Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first and most important step is recognizing the file path: `go/src/cmd/internal/obj/s390x/asmz.go`. This tells us we're dealing with assembly generation for the s390x architecture within the Go compiler toolchain. The `asmz.go` suffix strongly suggests it's the assembler part.

2. **Identify the Core Function:**  The primary function is `asmins(ctxt *Link, cursym *Symbol, p *Prog)`, which is called for each assembly instruction (`p`). This function is a large `switch` statement based on `p.As`, which represents the assembly opcode. This immediately suggests that the code's main purpose is to translate Go's intermediate representation of assembly instructions into actual machine code.

3. **Analyze the `switch` Cases:**  Go through the `switch` cases. Notice the consistent pattern:
    * **Opcode Identification:** Each case handles a specific range of opcodes (e.g., `case 119`, `case 120`).
    * **Argument Extraction:**  The code extracts operands from the `p` struct (e.g., `p.Reg`, `p.To.Reg`, `p.From.Reg`, `p.GetFrom3().Reg`, `p.From`). Pay attention to how different addressing modes are handled (registers, immediate values, memory offsets).
    * **Helper Function Calls:**  The code calls functions like `vop`, `singleElementMask`, `zVRRc`, `zVRRd`, `zRRE`, `zRRF`, etc. The `z` prefix strongly implies these are s390x-specific assembly encoding functions. The names often hint at the instruction format (e.g., `VRR` likely involves vector registers, `RRE` likely involves register-register-extended format).
    * **Error Handling:**  `c.ctxt.Diag` is used for reporting errors like unexpected opcodes or invalid register usage.

4. **Focus on Representative Cases:** It's not necessary to understand *every* single case in detail initially. Choose a few representative cases to analyze more deeply:
    * **Vector Instructions (Cases 119-123):** These cases involve `V` prefixed functions and multiple register operands. This confirms that the code handles vector instructions.
    * **Scalar Instructions (Cases 124-126):** These cases handle instructions like `AKM`, `AKMC`, `AKLMD`, `AKIMD`, `KDSA`, `AKMA`, and `AKMCTR`. Notice the checks for even registers and non-zero registers, suggesting constraints related to these specific instructions.

5. **Infer Functionality from Helper Functions:** Look at the helper functions defined later in the code:
    * **`vregoff`, `regoff`:** These likely calculate memory offsets.
    * **`isU12`:** Checks if a displacement fits within a 12-bit range, which is a common constraint in instruction encoding.
    * **`zopload12`, `zopload`, `zopstore12`, `zopstore`:** These functions map Go's generic load/store opcodes (`AFMOVD`, `AMOVD`, etc.) to specific s390x machine instructions (e.g., `op_LD`, `op_LG`, `op_STD`). The `12` suffix suggests handling of 12-bit displacements.
    * **`zoprre`, `zoprr`, `zopril`:** Similar mapping functions for other instruction types (compare instructions).
    * **`zE`, `zI`, `zMII`, `zRI`, `zRIE`, `zRIL`, `zRIS`, `zRR`, ... `zVRId`, `zVRIe`:** These are the core assembly encoding functions. The names clearly indicate the instruction formats (e.g., `zRI` for Register-Immediate, `zVRR` for Vector-Register-Register). They take the opcode and operands as input and append the encoded bytes to the `asm` slice.

6. **Connect the Dots:** Realize that `asmins` uses the opcode (`p.As`) to select the correct case, extracts the operands, and then calls the appropriate `z...` encoding function to generate the machine code bytes.

7. **Formulate the Functionality Summary:** Based on the analysis, summarize the code's purpose as generating s390x machine code from Go's assembly representation. Highlight the handling of various instruction formats (scalar and vector), load/store operations, and compare operations.

8. **Infer Go Language Feature Implementation (Key Insight):** The code manipulates vector registers and performs cryptographic operations (like `AKM`, `KDSA`, `KMA`). This strongly suggests the implementation of Go's **vector processing capabilities** and potentially **cryptographic primitives** for the s390x architecture.

9. **Provide Go Code Examples (Hypothetical):** Create simple Go code examples that would likely trigger the execution of the analyzed assembly instructions. Focus on vector operations and cryptographic functions. *Initially, I might not be 100% certain about the exact Go functions, but I can make educated guesses based on the assembly mnemonics.*

10. **Infer Input/Output:**  For the code examples, assume some input data (e.g., vector values, keys, data to be encrypted) and predict the output based on the operation being performed.

11. **Command-Line Arguments:** Since this is part of the compiler, mention that command-line arguments would influence the compilation process but are not directly handled within this specific code snippet.

12. **Common Mistakes:** Think about potential pitfalls when writing s390x assembly or using these features in Go. Register constraints (like even registers) are a common source of errors.

13. **Review and Refine:**  Read through the analysis, ensuring clarity, accuracy, and completeness. Make sure the explanation flows logically and addresses all parts of the prompt. For example, ensure the concluding summary ties back to the initial understanding of the code.

This iterative process of examining the code, identifying patterns, inferring functionality, and connecting the pieces allows for a comprehensive understanding of the provided Go assembly generation code.
这是 `go/src/cmd/internal/obj/s390x/asmz.go` 文件的一部分，主要负责将 Go 语言的汇编指令转换为 s390x 架构的机器码。

**功能归纳:**

这部分代码主要负责处理 s390x 架构中特定类型的汇编指令的编码工作，特别是涉及到向量寄存器 (VR) 操作和一些特殊指令（如加密相关的指令）。 它根据不同的指令类型，提取指令的操作数，并调用相应的编码函数将它们转换为机器码字节序列。

**具体功能分解:**

这段代码是 `asmins` 函数中的一部分 `switch` 语句，根据汇编指令 `p.As` 的不同值，执行不同的编码逻辑。 我们可以将它分解为以下几个主要功能：

1. **处理 VRR-c 类型的向量指令:**  这类指令通常是向量的移位、旋转、除法和减法操作，其中右侧的值在左侧（例如 `SLD`, `DIV` 等）。它会提取操作码、掩码信息以及参与运算的向量寄存器，并调用 `zVRRc` 函数进行编码。

2. **处理 VRR-d 类型的向量指令:** 这类指令涉及四个向量寄存器 `V1`, `V2`, `V3`, `V4` 的操作。它会提取操作码和所有相关的向量寄存器，并调用 `zVRRd` 函数进行编码。

3. **处理 VRR-e 类型的向量指令:**  类似于 VRR-d，但可能在掩码处理上有所不同。它提取操作码、掩码和向量寄存器，并调用 `zVRRe` 函数进行编码。

4. **处理 VRR-f 类型的向量指令:** 这种指令用于从通用寄存器 (GR) 加载向量寄存器 (VR)，且是分离的加载。它提取操作码和相关的寄存器，并调用 `zVRRf` 函数进行编码。

5. **处理 VPDI 类型的向量指令:**  这类指令可能涉及到将立即数与向量寄存器进行操作。它提取操作码、立即数偏移量和向量寄存器，并调用 `zVRRc` 函数进行编码。

6. **处理 AKM, AKMC, AKLMD, AKIMD 等指令:** 这些指令是与加密相关的指令。
   - `AKM`: 消息认证码生成指令。
   - `AKMC`: 消息认证码生成并校验指令。
   - `AKLMD`:  可能与加载密钥相关的指令。
   - `AKIMD`:  可能与使用立即数的密钥操作相关。
   这段代码会检查操作数的寄存器是否为 `R0` 以及是否为偶数寄存器，然后根据具体的指令调用 `zRRE` 函数进行编码。

7. **处理 KDSA 指令:**  这是数字签名和验证相关的指令。它也会检查目标寄存器是否为 `R0` 和偶数寄存器，并调用 `zRRE` 函数进行编码。

8. **处理 AKMA 和 AKMCTR 指令:**  这些也是与加密相关的指令。
   - `AKMA`:  带认证的消息加密指令。
   - `AKMCTR`: 带计数器的消息加密指令。
   这段代码会检查源寄存器、目标寄存器和第三个寄存器是否为 `R0` 以及是否为偶数寄存器，然后根据具体的指令调用 `zRRF` 函数进行编码。

**Go 语言功能推断及代码示例:**

根据这段代码对向量寄存器和加密指令的处理，我们可以推断它可能实现了 Go 语言的以下功能：

* **向量计算 (Vector Processing):**  `VRR-*` 和 `VPDI` 等指令暗示了 Go 语言支持 SIMD (Single Instruction, Multiple Data) 类型的向量运算，可以并行处理多个数据。
* **密码学原语 (Cryptographic Primitives):** `AKM`, `AKMC`, `AKLMD`, `AKIMD`, `KDSA`, `AKMA`, `AKMCTR` 等指令表明 Go 语言可能在 `crypto` 包或相关的内部包中提供了对 s390x 硬件加速的加密算法支持。

**Go 代码示例 (假设):**

```go
package main

import (
	"fmt"
	"unsafe"
)

// 假设的向量类型 (实际中可能使用更底层的类型或标准库)
type Vector128 [16]byte

func main() {
	// 向量加法 (假设的内联汇编或编译器优化)
	vec1 := Vector128{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	vec2 := Vector128{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	var result Vector128

	// 这里假设编译器会生成类似 VRR 指令的汇编代码
	for i := 0; i < len(vec1); i++ {
		result[i] = vec1[i] + vec2[i]
	}
	fmt.Println("向量加法结果:", result)

	// 消息认证码生成 (假设使用了硬件加速的加密函数)
	key := []byte("secret key")
	data := []byte("message to authenticate")
	// 假设的函数，实际可能在 crypto/hmac 或其他包中
	// mac := s390x_hmac_sha256(key, data)
	// fmt.Printf("HMAC-SHA256 MAC: %x\n", mac)
}
```

**假设的输入与输出:**

* **向量加法:**
    * **输入:** `vec1 = [1, 2, ..., 16]`, `vec2 = [16, 15, ..., 1]`
    * **输出:** `result = [17, 17, ..., 17]`
* **消息认证码生成:**
    * **输入:** `key = "secret key"`, `data = "message to authenticate"`
    * **输出:**  (输出会是 32 字节的 HMAC-SHA256 值，具体内容取决于 key 和 data)

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。 它是 Go 编译器的内部实现，当使用 `go build` 或 `go run` 等命令时，编译器会解析源代码并生成中间表示，然后 `asmz.go` 中的代码会将这些中间表示转换为目标平台的机器码。 命令行参数会影响编译过程的整体行为（例如选择目标架构、优化级别等），但不会直接传递到这段特定的汇编生成代码中。

**使用者易犯错的点 (基于代码推理):**

* **寄存器约束:**  对于加密相关的指令 (`AKM`, `KDSA`, `AKMA` 等)，代码中多次检查操作数寄存器是否为 `R0` 以及是否为偶数寄存器。 这意味着在使用这些指令时，必须遵守这些寄存器约束，否则汇编器会报错。  例如，尝试使用奇数寄存器作为 `AKM` 的操作数将会导致错误。

   ```go
   // 错误的用法，假设 R1 是奇数寄存器
   // _ "runtime/internal/sys"  // 假设的包
   // func ·HmacGo(ctxt *Link, cursym *Symbol, p *obj.Prog) {
   // 	p.As = AKM
   // 	p.From.Type = obj.TYPE_REG
   // 	p.From.Reg = REG_R1  // 错误：奇数寄存器
   // 	// ...
   // }
   ```

   **错误信息 (推测):** `input must be even register in ...` 或类似的错误。

**总结:**

这部分 `asmz.go` 代码是 Go 语言在 s390x 架构上实现向量计算和硬件加速的密码学功能的核心组成部分。 它负责将 Go 的汇编指令翻译成底层的机器码，并强制执行了特定指令的寄存器使用约束。 理解这段代码有助于深入了解 Go 语言在特定硬件架构上的底层实现原理。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/s390x/asmz.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共6部分，请归纳一下它的功能

"""
 asm)

	case 119: // VRR-c SHIFT/ROTATE/DIVIDE/SUB (rhs value on the left, like SLD, DIV etc.)
		op, m4, m6 := vop(p.As)
		m5 := singleElementMask(p.As)
		v2 := p.Reg
		if v2 == 0 {
			v2 = p.To.Reg
		}
		zVRRc(op, uint32(p.To.Reg), uint32(v2), uint32(p.From.Reg), m6, m5, m4, asm)

	case 120: // VRR-d
		op, m6, m5 := vop(p.As)
		v1 := uint32(p.To.Reg)
		v2 := uint32(p.From.Reg)
		v3 := uint32(p.Reg)
		v4 := uint32(p.GetFrom3().Reg)
		zVRRd(op, v1, v2, v3, m6, m5, v4, asm)

	case 121: // VRR-e
		op, m6, _ := vop(p.As)
		m5 := singleElementMask(p.As)
		v1 := uint32(p.To.Reg)
		v2 := uint32(p.From.Reg)
		v3 := uint32(p.Reg)
		v4 := uint32(p.GetFrom3().Reg)
		zVRRe(op, v1, v2, v3, m6, m5, v4, asm)

	case 122: // VRR-f LOAD VRS FROM GRS DISJOINT
		op, _, _ := vop(p.As)
		zVRRf(op, uint32(p.To.Reg), uint32(p.From.Reg), uint32(p.Reg), asm)

	case 123: // VPDI $m4, V2, V3, V1
		op, _, _ := vop(p.As)
		m4 := c.regoff(&p.From)
		zVRRc(op, uint32(p.To.Reg), uint32(p.Reg), uint32(p.GetFrom3().Reg), 0, 0, uint32(m4), asm)

	case 124:
		var opcode uint32
		switch p.As {
		default:
			c.ctxt.Diag("unexpected opcode %v", p.As)
		case AKM, AKMC, AKLMD:
			if p.From.Reg == REG_R0 {
				c.ctxt.Diag("input must not be R0 in %v", p)
			}
			if p.From.Reg&1 != 0 {
				c.ctxt.Diag("input must be even register in %v", p)
			}
			if p.To.Reg == REG_R0 {
				c.ctxt.Diag("second argument must not be R0 in %v", p)
			}
			if p.To.Reg&1 != 0 {
				c.ctxt.Diag("second argument must be even register in %v", p)
			}
			if p.As == AKM {
				opcode = op_KM
			} else if p.As == AKMC {
				opcode = op_KMC
			} else {
				opcode = op_KLMD
			}
		case AKIMD:
			if p.To.Reg == REG_R0 {
				c.ctxt.Diag("second argument must not be R0 in %v", p)
			}
			if p.To.Reg&1 != 0 {
				c.ctxt.Diag("second argument must be even register in %v", p)
			}
			opcode = op_KIMD
		}
		zRRE(opcode, uint32(p.From.Reg), uint32(p.To.Reg), asm)

	case 125: // KDSA sign and verify
		if p.To.Reg == REG_R0 {
			c.ctxt.Diag("second argument must not be R0 in %v", p)
		}
		if p.To.Reg&1 != 0 {
			c.ctxt.Diag("second argument must be an even register in %v", p)
		}
		zRRE(op_KDSA, uint32(p.From.Reg), uint32(p.To.Reg), asm)

	case 126: // KMA and KMCTR - CIPHER MESSAGE WITH AUTHENTICATION; CIPHER MESSAGE WITH COUNTER
		var opcode uint32
		switch p.As {
		default:
			c.ctxt.Diag("unexpected opcode %v", p.As)
		case AKMA, AKMCTR:
			if p.From.Reg == REG_R0 {
				c.ctxt.Diag("input argument must not be R0 in %v", p)
			}
			if p.From.Reg&1 != 0 {
				c.ctxt.Diag("input argument must be even register in %v", p)
			}
			if p.To.Reg == REG_R0 {
				c.ctxt.Diag("output argument must not be R0 in %v", p)
			}
			if p.To.Reg&1 != 0 {
				c.ctxt.Diag("output argument must be an even register in %v", p)
			}
			if p.Reg == REG_R0 {
				c.ctxt.Diag("third argument must not be R0 in %v", p)
			}
			if p.Reg&1 != 0 {
				c.ctxt.Diag("third argument must be even register in %v", p)
			}
			if p.As == AKMA {
				opcode = op_KMA
			} else if p.As == AKMCTR {
				opcode = op_KMCTR
			}
		}
		zRRF(opcode, uint32(p.Reg), 0, uint32(p.From.Reg), uint32(p.To.Reg), asm)
	}
}

func (c *ctxtz) vregoff(a *obj.Addr) int64 {
	c.instoffset = 0
	if a != nil {
		c.aclass(a)
	}
	return c.instoffset
}

func (c *ctxtz) regoff(a *obj.Addr) int32 {
	return int32(c.vregoff(a))
}

// find if the displacement is within 12 bit.
func isU12(displacement int32) bool {
	return displacement >= 0 && displacement < DISP12
}

// zopload12 returns the RX op with 12 bit displacement for the given load.
func (c *ctxtz) zopload12(a obj.As) (uint32, bool) {
	switch a {
	case AFMOVD:
		return op_LD, true
	case AFMOVS:
		return op_LE, true
	}
	return 0, false
}

// zopload returns the RXY op for the given load.
func (c *ctxtz) zopload(a obj.As) uint32 {
	switch a {
	// fixed point load
	case AMOVD:
		return op_LG
	case AMOVW:
		return op_LGF
	case AMOVWZ:
		return op_LLGF
	case AMOVH:
		return op_LGH
	case AMOVHZ:
		return op_LLGH
	case AMOVB:
		return op_LGB
	case AMOVBZ:
		return op_LLGC

	// floating point load
	case AFMOVD:
		return op_LDY
	case AFMOVS:
		return op_LEY

	// byte reversed load
	case AMOVDBR:
		return op_LRVG
	case AMOVWBR:
		return op_LRV
	case AMOVHBR:
		return op_LRVH
	}

	c.ctxt.Diag("unknown store opcode %v", a)
	return 0
}

// zopstore12 returns the RX op with 12 bit displacement for the given store.
func (c *ctxtz) zopstore12(a obj.As) (uint32, bool) {
	switch a {
	case AFMOVD:
		return op_STD, true
	case AFMOVS:
		return op_STE, true
	case AMOVW, AMOVWZ:
		return op_ST, true
	case AMOVH, AMOVHZ:
		return op_STH, true
	case AMOVB, AMOVBZ:
		return op_STC, true
	}
	return 0, false
}

// zopstore returns the RXY op for the given store.
func (c *ctxtz) zopstore(a obj.As) uint32 {
	switch a {
	// fixed point store
	case AMOVD:
		return op_STG
	case AMOVW, AMOVWZ:
		return op_STY
	case AMOVH, AMOVHZ:
		return op_STHY
	case AMOVB, AMOVBZ:
		return op_STCY

	// floating point store
	case AFMOVD:
		return op_STDY
	case AFMOVS:
		return op_STEY

	// byte reversed store
	case AMOVDBR:
		return op_STRVG
	case AMOVWBR:
		return op_STRV
	case AMOVHBR:
		return op_STRVH
	}

	c.ctxt.Diag("unknown store opcode %v", a)
	return 0
}

// zoprre returns the RRE op for the given a.
func (c *ctxtz) zoprre(a obj.As) uint32 {
	switch a {
	case ACMP:
		return op_CGR
	case ACMPU:
		return op_CLGR
	case AFCMPO: //ordered
		return op_KDBR
	case AFCMPU: //unordered
		return op_CDBR
	case ACEBR:
		return op_CEBR
	}
	c.ctxt.Diag("unknown rre opcode %v", a)
	return 0
}

// zoprr returns the RR op for the given a.
func (c *ctxtz) zoprr(a obj.As) uint32 {
	switch a {
	case ACMPW:
		return op_CR
	case ACMPWU:
		return op_CLR
	}
	c.ctxt.Diag("unknown rr opcode %v", a)
	return 0
}

// zopril returns the RIL op for the given a.
func (c *ctxtz) zopril(a obj.As) uint32 {
	switch a {
	case ACMP:
		return op_CGFI
	case ACMPU:
		return op_CLGFI
	case ACMPW:
		return op_CFI
	case ACMPWU:
		return op_CLFI
	}
	c.ctxt.Diag("unknown ril opcode %v", a)
	return 0
}

// z instructions sizes
const (
	sizeE    = 2
	sizeI    = 2
	sizeIE   = 4
	sizeMII  = 6
	sizeRI   = 4
	sizeRI1  = 4
	sizeRI2  = 4
	sizeRI3  = 4
	sizeRIE  = 6
	sizeRIE1 = 6
	sizeRIE2 = 6
	sizeRIE3 = 6
	sizeRIE4 = 6
	sizeRIE5 = 6
	sizeRIE6 = 6
	sizeRIL  = 6
	sizeRIL1 = 6
	sizeRIL2 = 6
	sizeRIL3 = 6
	sizeRIS  = 6
	sizeRR   = 2
	sizeRRD  = 4
	sizeRRE  = 4
	sizeRRF  = 4
	sizeRRF1 = 4
	sizeRRF2 = 4
	sizeRRF3 = 4
	sizeRRF4 = 4
	sizeRRF5 = 4
	sizeRRR  = 2
	sizeRRS  = 6
	sizeRS   = 4
	sizeRS1  = 4
	sizeRS2  = 4
	sizeRSI  = 4
	sizeRSL  = 6
	sizeRSY  = 6
	sizeRSY1 = 6
	sizeRSY2 = 6
	sizeRX   = 4
	sizeRX1  = 4
	sizeRX2  = 4
	sizeRXE  = 6
	sizeRXF  = 6
	sizeRXY  = 6
	sizeRXY1 = 6
	sizeRXY2 = 6
	sizeS    = 4
	sizeSI   = 4
	sizeSIL  = 6
	sizeSIY  = 6
	sizeSMI  = 6
	sizeSS   = 6
	sizeSS1  = 6
	sizeSS2  = 6
	sizeSS3  = 6
	sizeSS4  = 6
	sizeSS5  = 6
	sizeSS6  = 6
	sizeSSE  = 6
	sizeSSF  = 6
)

// instruction format variations
type form int

const (
	_a form = iota
	_b
	_c
	_d
	_e
	_f
)

func zE(op uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8), uint8(op))
}

func zI(op, i1 uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8), uint8(i1))
}

func zMII(op, m1, ri2, ri3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(m1)<<4)|uint8((ri2>>8)&0x0F),
		uint8(ri2),
		uint8(ri3>>16),
		uint8(ri3>>8),
		uint8(ri3))
}

func zRI(op, r1_m1, i2_ri2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1_m1)<<4)|(uint8(op)&0x0F),
		uint8(i2_ri2>>8),
		uint8(i2_ri2))
}

// Expected argument values for the instruction formats.
//
// Format    a1  a2   a3  a4  a5  a6  a7
// ------------------------------------
// a         r1,  0,  i2,  0,  0, m3,  0
// b         r1, r2, ri4,  0,  0, m3,  0
// c         r1, m3, ri4,  0,  0,  0, i2
// d         r1, r3,  i2,  0,  0,  0,  0
// e         r1, r3, ri2,  0,  0,  0,  0
// f         r1, r2,   0, i3, i4,  0, i5
// g         r1, m3,  i2,  0,  0,  0,  0
func zRIE(f form, op, r1, r2_m3_r3, i2_ri4_ri2, i3, i4, m3, i2_i5 uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8), uint8(r1)<<4|uint8(r2_m3_r3&0x0F))

	switch f {
	default:
		*asm = append(*asm, uint8(i2_ri4_ri2>>8), uint8(i2_ri4_ri2))
	case _f:
		*asm = append(*asm, uint8(i3), uint8(i4))
	}

	switch f {
	case _a, _b:
		*asm = append(*asm, uint8(m3)<<4)
	default:
		*asm = append(*asm, uint8(i2_i5))
	}

	*asm = append(*asm, uint8(op))
}

func zRIL(f form, op, r1_m1, i2_ri2 uint32, asm *[]byte) {
	if f == _a || f == _b {
		r1_m1 = r1_m1 - obj.RBaseS390X // this is a register base
	}
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1_m1)<<4)|(uint8(op)&0x0F),
		uint8(i2_ri2>>24),
		uint8(i2_ri2>>16),
		uint8(i2_ri2>>8),
		uint8(i2_ri2))
}

func zRIS(op, r1, m3, b4, d4, i2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(m3&0x0F),
		(uint8(b4)<<4)|(uint8(d4>>8)&0x0F),
		uint8(d4),
		uint8(i2),
		uint8(op))
}

func zRR(op, r1, r2 uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8), (uint8(r1)<<4)|uint8(r2&0x0F))
}

func zRRD(op, r1, r3, r2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		uint8(r1)<<4,
		(uint8(r3)<<4)|uint8(r2&0x0F))
}

func zRRE(op, r1, r2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		0,
		(uint8(r1)<<4)|uint8(r2&0x0F))
}

func zRRF(op, r3_m3, m4, r1, r2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		(uint8(r3_m3)<<4)|uint8(m4&0x0F),
		(uint8(r1)<<4)|uint8(r2&0x0F))
}

func zRRS(op, r1, r2, b4, d4, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(r2&0x0F),
		(uint8(b4)<<4)|uint8((d4>>8)&0x0F),
		uint8(d4),
		uint8(m3)<<4,
		uint8(op))
}

func zRS(op, r1, r3_m3, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(r3_m3&0x0F),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func zRSI(op, r1, r3, ri2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(r3&0x0F),
		uint8(ri2>>8),
		uint8(ri2))
}

func zRSL(op, l1, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(l1),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2),
		uint8(op))
}

func zRSY(op, r1, r3_m3, b2, d2 uint32, asm *[]byte) {
	dl2 := uint16(d2) & 0x0FFF
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(r3_m3&0x0F),
		(uint8(b2)<<4)|(uint8(dl2>>8)&0x0F),
		uint8(dl2),
		uint8(d2>>12),
		uint8(op))
}

func zRX(op, r1_m1, x2, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1_m1)<<4)|uint8(x2&0x0F),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func zRXE(op, r1, x2, b2, d2, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1)<<4)|uint8(x2&0x0F),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2),
		uint8(m3)<<4,
		uint8(op))
}

func zRXF(op, r3, x2, b2, d2, m1 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r3)<<4)|uint8(x2&0x0F),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2),
		uint8(m1)<<4,
		uint8(op))
}

func zRXY(op, r1_m1, x2, b2, d2 uint32, asm *[]byte) {
	dl2 := uint16(d2) & 0x0FFF
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r1_m1)<<4)|uint8(x2&0x0F),
		(uint8(b2)<<4)|(uint8(dl2>>8)&0x0F),
		uint8(dl2),
		uint8(d2>>12),
		uint8(op))
}

func zS(op, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func zSI(op, i2, b1, d1 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(i2),
		(uint8(b1)<<4)|uint8((d1>>8)&0x0F),
		uint8(d1))
}

func zSIL(op, b1, d1, i2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		(uint8(b1)<<4)|uint8((d1>>8)&0x0F),
		uint8(d1),
		uint8(i2>>8),
		uint8(i2))
}

func zSIY(op, i2, b1, d1 uint32, asm *[]byte) {
	dl1 := uint16(d1) & 0x0FFF
	*asm = append(*asm,
		uint8(op>>8),
		uint8(i2),
		(uint8(b1)<<4)|(uint8(dl1>>8)&0x0F),
		uint8(dl1),
		uint8(d1>>12),
		uint8(op))
}

func zSMI(op, m1, b3, d3, ri2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(m1)<<4,
		(uint8(b3)<<4)|uint8((d3>>8)&0x0F),
		uint8(d3),
		uint8(ri2>>8),
		uint8(ri2))
}

// Expected argument values for the instruction formats.
//
// Format    a1  a2  a3  a4  a5  a6
// -------------------------------
// a         l1,  0, b1, d1, b2, d2
// b         l1, l2, b1, d1, b2, d2
// c         l1, i3, b1, d1, b2, d2
// d         r1, r3, b1, d1, b2, d2
// e         r1, r3, b2, d2, b4, d4
// f          0, l2, b1, d1, b2, d2
func zSS(f form, op, l1_r1, l2_i3_r3, b1_b2, d1_d2, b2_b4, d2_d4 uint32, asm *[]byte) {
	*asm = append(*asm, uint8(op>>8))

	switch f {
	case _a:
		*asm = append(*asm, uint8(l1_r1))
	case _b, _c, _d, _e:
		*asm = append(*asm, (uint8(l1_r1)<<4)|uint8(l2_i3_r3&0x0F))
	case _f:
		*asm = append(*asm, uint8(l2_i3_r3))
	}

	*asm = append(*asm,
		(uint8(b1_b2)<<4)|uint8((d1_d2>>8)&0x0F),
		uint8(d1_d2),
		(uint8(b2_b4)<<4)|uint8((d2_d4>>8)&0x0F),
		uint8(d2_d4))
}

func zSSE(op, b1, d1, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(op),
		(uint8(b1)<<4)|uint8((d1>>8)&0x0F),
		uint8(d1),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func zSSF(op, r3, b1, d1, b2, d2 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(r3)<<4)|(uint8(op)&0x0F),
		(uint8(b1)<<4)|uint8((d1>>8)&0x0F),
		uint8(d1),
		(uint8(b2)<<4)|uint8((d2>>8)&0x0F),
		uint8(d2))
}

func rxb(va, vb, vc, vd uint32) uint8 {
	mask := uint8(0)
	if va >= REG_V16 && va <= REG_V31 {
		mask |= 0x8
	}
	if vb >= REG_V16 && vb <= REG_V31 {
		mask |= 0x4
	}
	if vc >= REG_V16 && vc <= REG_V31 {
		mask |= 0x2
	}
	if vd >= REG_V16 && vd <= REG_V31 {
		mask |= 0x1
	}
	return mask
}

func zVRX(op, v1, x2, b2, d2, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(x2)&0xf),
		(uint8(b2)<<4)|(uint8(d2>>8)&0xf),
		uint8(d2),
		(uint8(m3)<<4)|rxb(v1, 0, 0, 0),
		uint8(op))
}

func zVRV(op, v1, v2, b2, d2, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		(uint8(b2)<<4)|(uint8(d2>>8)&0xf),
		uint8(d2),
		(uint8(m3)<<4)|rxb(v1, v2, 0, 0),
		uint8(op))
}

func zVRS(op, v1, v3_r3, b2, d2, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v3_r3)&0xf),
		(uint8(b2)<<4)|(uint8(d2>>8)&0xf),
		uint8(d2),
		(uint8(m4)<<4)|rxb(v1, v3_r3, 0, 0),
		uint8(op))
}

func zVRRa(op, v1, v2, m5, m4, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		0,
		(uint8(m5)<<4)|(uint8(m4)&0xf),
		(uint8(m3)<<4)|rxb(v1, v2, 0, 0),
		uint8(op))
}

func zVRRb(op, v1, v2, v3, m5, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		uint8(v3)<<4,
		uint8(m5)<<4,
		(uint8(m4)<<4)|rxb(v1, v2, v3, 0),
		uint8(op))
}

func zVRRc(op, v1, v2, v3, m6, m5, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		uint8(v3)<<4,
		(uint8(m6)<<4)|(uint8(m5)&0xf),
		(uint8(m4)<<4)|rxb(v1, v2, v3, 0),
		uint8(op))
}

func zVRRd(op, v1, v2, v3, m5, m6, v4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		(uint8(v3)<<4)|(uint8(m5)&0xf),
		uint8(m6)<<4,
		(uint8(v4)<<4)|rxb(v1, v2, v3, v4),
		uint8(op))
}

func zVRRe(op, v1, v2, v3, m6, m5, v4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		(uint8(v3)<<4)|(uint8(m6)&0xf),
		uint8(m5),
		(uint8(v4)<<4)|rxb(v1, v2, v3, v4),
		uint8(op))
}

func zVRRf(op, v1, r2, r3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(r2)&0xf),
		uint8(r3)<<4,
		0,
		rxb(v1, 0, 0, 0),
		uint8(op))
}

func zVRIa(op, v1, i2, m3 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(v1)<<4,
		uint8(i2>>8),
		uint8(i2),
		(uint8(m3)<<4)|rxb(v1, 0, 0, 0),
		uint8(op))
}

func zVRIb(op, v1, i2, i3, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		uint8(v1)<<4,
		uint8(i2),
		uint8(i3),
		(uint8(m4)<<4)|rxb(v1, 0, 0, 0),
		uint8(op))
}

func zVRIc(op, v1, v3, i2, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v3)&0xf),
		uint8(i2>>8),
		uint8(i2),
		(uint8(m4)<<4)|rxb(v1, v3, 0, 0),
		uint8(op))
}

func zVRId(op, v1, v2, v3, i4, m5 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		uint8(v3)<<4,
		uint8(i4),
		(uint8(m5)<<4)|rxb(v1, v2, v3, 0),
		uint8(op))
}

func zVRIe(op, v1, v2, i3, m5, m4 uint32, asm *[]byte) {
	*asm = append(*asm,
		uint8(op>>8),
		(uint8(v1)<<4)|(uint8(v2)&0xf),
		uint8(i3>>4),
		(uint8(i3)<<4)|(uint8(m5)&0xf),
		(uint8(m4)<<4)|rxb(v1, v2, 0, 0),
		uint8(op))
}

"""




```