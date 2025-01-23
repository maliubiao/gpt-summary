Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteRISCV64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
// Code generated from _gen/RISCV64.rules using 'go generate'; DO NOT EDIT.

package ssa

import "internal/buildcfg"
import "math"
import "cmd/compile/internal/types"

func rewriteValueRISCV64(v *Value) bool {
	switch v.Op {
	case OpAbs:
		v.Op = OpRISCV64FABSD
		return true
	case OpAdd16:
		v.Op = OpRISCV64ADD
		return true
	case OpAdd32:
		v.Op = OpRISCV64ADD
		return true
	case OpAdd32F:
		v.Op = OpRISCV64FADDS
		return true
	case OpAdd64:
		v.Op = OpRISCV64ADD
		return true
	case OpAdd64F:
		v.Op = OpRISCV64FADDD
		return true
	case OpAdd8:
		v.Op = OpRISCV64ADD
		return true
	case OpAddPtr:
		v.Op = OpRISCV64ADD
		return true
	case OpAddr:
		return rewriteValueRISCV64_OpAddr(v)
	case OpAnd16:
		v.Op = OpRISCV64AND
		return true
	case OpAnd32:
		v.Op = OpRISCV64AND
		return true
	case OpAnd64:
		v.Op = OpRISCV64AND
		return true
	case OpAnd8:
		v.Op = OpRISCV64AND
		return true
	case OpAndB:
		v.Op = OpRISCV64AND
		return true
	case OpAtomicAdd32:
		v.Op = OpRISCV64LoweredAtomicAdd32
		return true
	case OpAtomicAdd64:
		v.Op = OpRISCV64LoweredAtomicAdd64
		return true
	case OpAtomicAnd32:
		v.Op = OpRISCV64LoweredAtomicAnd32
		return true
	case OpAtomicAnd8:
		return rewriteValueRISCV64_OpAtomicAnd8(v)
	case OpAtomicCompareAndSwap32:
		return rewriteValueRISCV64_OpAtomicCompareAndSwap32(v)
	case OpAtomicCompareAndSwap64:
		v.Op = OpRISCV64LoweredAtomicCas64
		return true
	case OpAtomicExchange32:
		v.Op = OpRISCV64LoweredAtomicExchange32
		return true
	case OpAtomicExchange64:
		v.Op = OpRISCV64LoweredAtomicExchange64
		return true
	case OpAtomicLoad32:
		v.Op = OpRISCV64LoweredAtomicLoad32
		return true
	case OpAtomicLoad64:
		v.Op = OpRISCV64LoweredAtomicLoad64
		return true
	case OpAtomicLoad8:
		v.Op = OpRISCV64LoweredAtomicLoad8
		return true
	case OpAtomicLoadPtr:
		v.Op = OpRISCV64LoweredAtomicLoad64
		return true
	case OpAtomicOr32:
		v.Op = OpRISCV64LoweredAtomicOr32
		return true
	case OpAtomicOr8:
		return rewriteValueRISCV64_OpAtomicOr8(v)
	case OpAtomicStore32:
		v.Op = OpRISCV64LoweredAtomicStore32
		return true
	case OpAtomicStore64:
		v.Op = OpRISCV64LoweredAtomicStore64
		return true
	case OpAtomicStore8:
		v.Op = OpRISCV64LoweredAtomicStore8
		return true
	case OpAtomicStorePtrNoWB:
		v.Op = OpRISCV64LoweredAtomicStore64
		return true
	case OpAvg64u:
		return rewriteValueRISCV64_OpAvg64u(v)
	case OpClosureCall:
		v.Op = OpRISCV64CALLclosure
		return true
	case OpCom16:
		v.Op = OpRISCV64NOT
		return true
	case OpCom32:
		v.Op = OpRISCV64NOT
		return true
	case OpCom64:
		v.Op = OpRISCV64NOT
		return true
	case OpCom8:
		v.Op = OpRISCV64NOT
		return true
	case OpConst16:
		return rewriteValueRISCV64_OpConst16(v)
	case OpConst32:
		return rewriteValueRISCV64_OpConst32(v)
	case OpConst32F:
		return rewriteValueRISCV64_OpConst32F(v)
	case OpConst64:
		return rewriteValueRISCV64_OpConst64(v)
	case OpConst64F:
		return rewriteValueRISCV64_OpConst64F(v)
	case OpConst8:
		return rewriteValueRISCV64_OpConst8(v)
	case OpConstBool:
		return rewriteValueRISCV64_OpConstBool(v)
	case OpConstNil:
		return rewriteValueRISCV64_OpConstNil(v)
	case OpCopysign:
		v.Op = OpRISCV64FSGNJD
		return true
	case OpCvt32Fto32:
		v.Op = OpRISCV64FCVTWS
		return true
	case OpCvt32Fto64:
		v.Op = OpRISCV64FCVTLS
		return true
	case OpCvt32Fto64F:
		v.Op = OpRISCV64FCVTDS
		return true
	case OpCvt32to32F:
		v.Op = OpRISCV64FCVTSW
		return true
	case OpCvt32to64F:
		v.Op = OpRISCV64FCVTDW
		return true
	case OpCvt64Fto32:
		v.Op = OpRISCV64FCVTWD
		return true
	case OpCvt64Fto32F:
		v.Op = OpRISCV64FCVTSD
		return true
	case OpCvt64Fto64:
		v.Op = OpRISCV64FCVTLD
		return true
	case OpCvt64to32F:
		v.Op = OpRISCV64FCVTSL
		return true
	case OpCvt64to64F:
		v.Op = OpRISCV64FCVTDL
		return true
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv16:
		return rewriteValueRISCV64_OpDiv16(v)
	case OpDiv16u:
		return rewriteValueRISCV64_OpDiv16u(v)
	case OpDiv32:
		return rewriteValueRISCV64_OpDiv32(v)
	case OpDiv32F:
		v.Op = OpRISCV64FDIVS
		return true
	case OpDiv32u:
		v.Op = OpRISCV64DIVUW
		return true
	case OpDiv64:
		return rewriteValueRISCV64_OpDiv64(v)
	case OpDiv64F:
		v.Op = OpRISCV64FDIVD
		return true
	case OpDiv64u:
		v.Op = OpRISCV64DIVU
		return true
	case OpDiv8:
		return rewriteValueRISCV64_OpDiv8(v)
	case OpDiv8u:
		return rewriteValueRISCV64_OpDiv8u(v)
	case OpEq16:
		return rewriteValueRISCV64_OpEq16(v)
	case OpEq32:
		return rewriteValueRISCV64_OpEq32(v)
	case OpEq32F:
		v.Op = OpRISCV64FEQS
		return true
	case OpEq64:
		return rewriteValueRISCV64_OpEq64(v)
	case OpEq64F:
		v.Op = OpRISCV64FEQD
		return true
	case OpEq8:
		return rewriteValueRISCV64_OpEq8(v)
	case OpEqB:
		return rewriteValueRISCV64_OpEqB(v)
	case OpEqPtr:
		return rewriteValueRISCV64_OpEqPtr(v)
	case OpFMA:
		v.Op = OpRISCV64FMADDD
		return true
	case OpGetCallerPC:
		v.Op = OpRISCV64LoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = OpRISCV64LoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = OpRISCV64LoweredGetClosurePtr
		return true
	case OpHmul32:
		return rewriteValueRISCV64_OpHmul32(v)
	case OpHmul32u:
		return rewriteValueRISCV64_OpHmul32u(v)
	case OpHmul64:
		v.Op = OpRISCV64MULH
		return true
	case OpHmul64u:
		v.Op = OpRISCV64MULHU
		return true
	case OpInterCall:
		v.Op = OpRISCV64CALLinter
		return true
	case OpIsInBounds:
		v.Op = OpLess64U
		return true
	case OpIsNonNil:
		v.Op = OpRISCV64SNEZ
		return true
	case OpIsSliceInBounds:
		v.Op = OpLeq64U
		return true
	case OpLeq16:
		return rewriteValueRISCV64_OpLeq16(v)
	case OpLeq16U:
		return rewriteValueRISCV64_OpLeq16U(v)
	case OpLeq32:
		return rewriteValueRISCV64_OpLeq32(v)
	case OpLeq32F:
		v.Op = OpRISCV64FLES
		return true
	case OpLeq32U:
		return rewriteValueRISCV64_OpLeq32U(v)
	case OpLeq64:
		return rewriteValueRISCV64_OpLeq64(v)
	case OpLeq64F:
		v.Op = OpRISCV64FLED
		return true
	case OpLeq64U:
		return rewriteValueRISCV64_OpLeq64U(v)
	case OpLeq8:
		return rewriteValueRISCV64_OpLeq8(v)
	case OpLeq8U:
		return rewriteValueRISCV64_OpLeq8U(v)
	case OpLess16:
		return rewriteValueRISCV64_OpLess16(v)
	case OpLess16U:
		return rewriteValueRISCV64_OpLess16U(v)
	case OpLess32:
		return rewriteValueRISCV64_OpLess32(v)
	case OpLess32F:
		v.Op = OpRISCV64FLTS
		return true
	case OpLess32U:
		return rewriteValueRISCV64_OpLess32U(v)
	case OpLess64:
		v.Op = OpRISCV64SLT
		return true
	case OpLess64F:
		v.Op = OpRISCV64FLTD
		return true
	case OpLess64U:
		v.Op = OpRISCV64SLTU
		return true
	case OpLess8:
		return rewriteValueRISCV64_OpLess8(v)
	case OpLess8U:
		return rewriteValueRISCV64_OpLess8U(v)
	case OpLoad:
		return rewriteValueRISCV64_OpLoad(v)
	case OpLocalAddr:
		return rewriteValueRISCV64_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValueRISCV64_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValueRISCV64_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValueRISCV64_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValueRISCV64_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValueRISCV64_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValueRISCV64_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValueRISCV64_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValueRISCV64_OpLsh32x8(v)
	case OpLsh64x16:
		return rewriteValueRISCV64_OpLsh64x16(v)
	case OpLsh64x32:
		return rewriteValueRISCV64_OpLsh64x32(v)
	case OpLsh64x64:
		return rewriteValueRISCV64_OpLsh64x64(v)
	case OpLsh64x8:
		return rewriteValueRISCV64_OpLsh64x8(v)
	case OpLsh8x16:
		return rewriteValueRISCV64_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValueRISCV64_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValueRISCV64_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValueRISCV64_OpLsh8x8(v)
	case OpMax32F:
		v.Op = OpRISCV64LoweredFMAXS
		return true
	case OpMax64:
		return rewriteValueRISCV64_OpMax64(v)
	case OpMax64F:
		v.Op = OpRISCV64LoweredFMAXD
		return true
	case OpMax64u:
		return rewriteValueRISCV64_OpMax64u(v)
	case OpMin32F:
		v.Op = OpRISCV64LoweredFMINS
		return true
	case OpMin64:
		return rewriteValueRISCV64_OpMin64(v)
	case OpMin64F:
		v.Op = OpRISCV64LoweredFMIND
		return true
	case OpMin64u:
		return rewriteValueRISCV64_OpMin64u(v)
	case OpMod16:
		return rewriteValueRISCV64_OpMod16(v)
	case OpMod16u:
		return rewriteValueRISCV64_OpMod16u(v)
	case OpMod32:
		return rewriteValueRISCV64_OpMod32(v)
	case OpMod32u:
		v.Op = OpRISCV64REMUW
		return true
	case OpMod64:
		return rewriteValueRISCV64_OpMod64(v)
	case OpMod64u:
		v.Op = OpRISCV64REMU
		return true
	case OpMod8:
		return rewriteValueRISCV64_OpMod8(v)
	case OpMod8u:
		return rewriteValueRISCV64_OpMod8u(v)
	case OpMove:
		return rewriteValueRISCV64_OpMove(v)
	case OpMul16:
		return rewriteValueRISCV64_OpMul16(v)
	case OpMul32:
		v.Op = OpRISCV64MULW
		return true
	case OpMul32F:
		v.Op = OpRISCV64FMULS
		return true
	case OpMul64:
		v.Op = OpRISCV64MUL
		return true
	case OpMul64F:
		v.Op = OpRISCV64FMULD
		return true
	case OpMul64uhilo:
		v.Op = OpRISCV64LoweredMuluhilo
		return true
	case OpMul64uover:
		v.Op = OpRISCV64LoweredMuluover
		return true
	case OpMul8:
		return rewriteValueRISCV64_OpMul8(v)
	case OpNeg16:
		v.Op = OpRISCV64NEG
		return true
	case OpNeg32:
		v.Op = OpRISCV64NEG
		return true
	case OpNeg32F:
		v.Op = OpRISCV64FNEGS
		return true
	case OpNeg64:
		v.Op = OpRISCV64NEG
		return true
	case OpNeg64F:
		v.Op = OpRISCV64FNEGD
		return true
	case OpNeg8:
		v.Op = OpRISCV64NEG
		return true
	case OpNeq16:
		return rewriteValueRISCV64_OpNeq16(v)
	case OpNeq32:
		return rewriteValueRISCV64_OpNeq32(v)
	case OpNeq32F:
		v.Op = OpRISCV64FNES
		return true
	case OpNeq64:
		return rewriteValueRISCV64_OpNeq64(v)
	case OpNeq64F:
		v.Op = OpRISCV64FNED
		return true
	case OpNeq8:
		return rewriteValueRISCV64_OpNeq8(v)
	case OpNeqB:
		return rewriteValueRISCV64_OpNeqB(v)
	case OpNeqPtr:
		return rewriteValueRISCV64_OpNeqPtr(v)
	case OpNilCheck:
		v.Op = OpRISCV64LoweredNilCheck
		return true
	case OpNot:
		v.Op = OpRISCV64SEQZ
		return true
	case OpOffPtr:
		return rewriteValueRISCV64_OpOffPtr(v)
	case OpOr16:
		v.Op = OpRISCV64OR
		return true
	case OpOr32:
		v.Op = OpRISCV64OR
		return true
	case OpOr64:
		v.Op = OpRISCV64OR
		return true
	case OpOr8:
		v.Op = OpRISCV64OR
		return true
	case OpOrB:
		v.Op = OpRISCV64OR
		return true
	case OpPanicBounds:
		return rewriteValueRISCV64_OpPanicBounds(v)
	case OpPubBarrier:
		v.Op = OpRISCV64LoweredPubBarrier
		return true
	case OpRISCV64ADD:
		return rewriteValueRISCV64_OpRISCV64ADD(v)
	case OpRISCV64ADDI:
		return rewriteValueRISCV64_OpRISCV64ADDI(v)
	case OpRISCV64AND:
		return rewriteValueRISCV64_OpRISCV64AND(v)
	case OpRISCV64ANDI:
		return rewriteValueRISCV64_OpRISCV64ANDI(v)
	case OpRISCV64FADDD:
		return rewriteValueRISCV64_OpRISCV64FADDD(v)
	case OpRISCV64FADDS:
		return rewriteValueRISCV64_OpRISCV64FADDS(v)
	case OpRISCV64FMADDD:
		return rewriteValueRISCV64_OpRISCV64FMADDD(v)
	case OpRISCV64FMADDS:
		return rewriteValueRISCV64_OpRISCV64FMADDS(v)
	case OpRISCV64FMSUBD:
		return rewriteValueRISCV64_OpRISCV64FMSUBD(v)
	case OpRISCV64FMSUBS:
		return rewriteValueRISCV64_OpRISCV64FMSUBS(v)
	case OpRISCV64FNMADDD:
		return rewriteValueRISCV64_OpRISCV64FNMADDD(v)
	case OpRISCV64FNMADDS:
		return rewriteValueRISCV64_OpRISCV64FNMADDS(v)
	case OpRISCV64FNMSUBD:
		return rewriteValueRISCV64_OpRISCV64FNMSUBD(v)
	case OpRISCV64FNMSUBS:
		return rewriteValueRISCV64_OpRISCV64FNMSUBS(v)
	case OpRISCV64FSUBD:
		return rewriteValueRISCV64_OpRISCV64FSUBD(v)
	case OpRISCV64FSUBS:
		return rewriteValueRISCV64_OpRISCV64FSUBS(v)
	case OpRISCV64MOVBUload:
		return rewriteValueRISCV64_OpRISCV64MOVBUload(v)
	case OpRISCV64MOVBUreg:
		return rewriteValueRISCV64_OpRISCV64MOVBUreg(v)
	case OpRISCV64MOVBload:
		return rewriteValueRISCV64_OpRISCV64MOVBload(v)
	case OpRISCV64MOVBreg:
		return rewriteValueRISCV64_OpRISCV64MOVBreg(v)
	case OpRISCV64MOVBstore:
		return rewriteValueRISCV64_OpRISCV64MOVBstore(v)
	case OpRISCV64MOVBstorezero:
		return rewriteValueRISCV64_OpRISCV64MOVBstorezero(v)
	case OpRISCV64MOVDload:
		return rewriteValueRISCV64_OpRISCV64MOVDload(v)
	case OpRISCV64MOVDnop:
		return rewriteValueRISCV64_OpRISCV64MOVDnop(v)
	case OpRISCV64MOVDreg:
		return rewriteValueRISCV64_OpRISCV64MOVDreg(v)
	case OpRISCV64MOVDstore:
		return rewriteValueRISCV64_OpRISCV64MOVDstore(v)
	case OpRISCV64MOVDstorezero:
		return rewriteValueRISCV64_OpRISCV64MOVDstorezero(v)
	case OpRISCV64MOVHUload:
		return rewriteValueRISCV64_OpRISCV64MOVHUload(v)
	case OpRISCV64MOVHUreg:
		return rewriteValueRISCV64_OpRISCV64MOVHUreg(v)
	case OpRISCV64MOVHload:
		return rewriteValueRISCV64_OpRISCV64MOVHload(v)
	case OpRISCV64MOVHreg:
		return rewriteValueRISCV64_OpRISCV64MOVHreg(v)
	case OpRISCV64MOVHstore:
		return rewriteValueRISCV64_OpRISCV64MOVHstore(v)
	case OpRISCV64MOVHstorezero:
		return rewriteValueRISCV64_OpRISCV64MOVHstorezero(v)
	case OpRISCV64MOVWUload:
		return rewriteValueRISCV64_OpRISCV64MOVWUload(v)
	case OpRISCV64MOVWUreg:
		return rewriteValueRISCV64_OpRISCV64MOVWUreg(v)
	case OpRISCV64MOVWload:
		return rewriteValueRISCV64_OpRISCV64MOVWload(v)
	case OpRISCV64MOVWreg:
		return rewriteValueRISCV64_OpRISCV64MOVWreg(v)
	case OpRISCV64MOVWstore:
		return rewriteValueRISCV64_OpRISCV64MOVWstore(v)
	case OpRISCV64MOVWstorezero:
		return rewriteValueRISCV64_OpRISCV64MOVWstorezero(v)
	case OpRISCV64NEG:
		return rewriteValueRISCV64_OpRISCV64NEG(v)
	case OpRISCV64NEGW:
		return rewriteValueRISCV64_OpRISCV64NEGW(v)
	case OpRISCV64OR:
		return rewriteValueRISCV64_OpRISCV64OR(v)
	case OpRISCV64ORI:
		return rewriteValueRISCV64_OpRISCV64ORI(v)
	case OpRISCV64ROL:
		return rewriteValueRISCV64_OpRISCV64ROL(v)
	case OpRISCV64ROLW:
		return rewriteValueRISCV64_OpRISCV64ROLW(v)
	case OpRISCV64ROR:
		return rewriteValueRISCV64_OpRISCV64ROR(v)
	case OpRISCV64RORW:
		return rewriteValueRISCV64_OpRISCV64RORW(v)
	case OpRISCV64SEQZ:
		return rewriteValueRISCV64_OpRISCV64SEQZ(v)
	case OpRISCV64SLL:
		return rewriteValueRISCV64_OpRISCV64SLL(v)
	case OpRISCV64SLLI:
		return rewriteValueRISCV64_OpRISCV64SLLI(v)
	case OpRISCV64SLLW:
		return rewriteValueRISCV64_OpRISCV64SLLW(v)
	case OpRISCV64SLT:
		return rewriteValueRISCV64_OpRISCV64SLT(v)
	case OpRISCV64SLTI:
		return rewriteValueRISCV64_OpRISCV64SLTI(v)
	case OpRISCV64SLTIU:
		return rewriteValueRISCV64_OpRISCV64SLTIU(v)
	case OpRISCV64SLTU:
		return rewriteValueRISCV64_OpRISCV64SLTU(v)
	case OpRISCV64SNEZ:
		return rewriteValueRISCV64_OpRISCV64SNEZ(v)
	case OpRISCV64SRA:
		return rewriteValueRISCV64_OpRISCV64SRA(v)
	case OpRISCV64SRAI:
		return rewriteValueRISCV64_OpRISCV64SRAI(v)
	case OpRISCV64SRAW:
		return rewriteValueRISCV64_OpRISCV64SRAW(v)
	case OpRISCV64SRL:
		return rewriteValueRISCV64_OpRISCV64SRL(v)
	case OpRISCV64SRLI:
		return rewriteValueRISCV64_OpRISCV64SRLI(v)
	case OpRISCV64SRLW:
		return rewriteValueRISCV64_OpRISCV64SRLW(v)
	case OpRISCV64SUB:
		return rewriteValueRISCV64_OpRISCV64SUB(v)
	case OpRISCV64SUBW:
		return rewriteValueRISCV64_OpRISCV64SUBW(v)
	case OpRISCV64XOR:
		return rewriteValueRISCV64_OpRISCV64XOR(v)
	case OpRotateLeft16:
		return rewriteValueRISCV64_OpRotateLeft16(v)
	case OpRotateLeft32:
		v.Op = OpRISCV64ROLW
		return true
	case OpRotateLeft64:
		v.Op = OpRISCV64ROL
		return true
	case OpRotateLeft8:
		return rewriteValueRISCV64_OpRotateLeft8(v)
	case OpRound32F:
		v.Op = OpRISCV64LoweredRound32F
		return true
	case OpRound64F:
		v.Op = OpRISCV64LoweredRound64F
		return true
	case OpRsh16Ux16:
		return rewriteValueRISCV64_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValueRISCV64_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValueRISCV64_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValueRISCV64_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValueRISCV64_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValueRISCV64_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValueRISCV64_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValueRISCV64_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValueRISCV64_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValueRISCV64_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValueRISCV64_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValueRISCV64_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValueRISCV64_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValueRISCV64_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValueRISCV64_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValueRISCV64_OpRsh32x8(v)
	case OpRsh64Ux16:
		return rewriteValueRISCV64_OpRsh64Ux16(v)
	case OpRsh64Ux32:
		return rewriteValueRISCV64_OpRsh64Ux32(v)
	case OpRsh64Ux64:
		return rewriteValueRISCV64_OpRsh64Ux64(v)
	case OpRsh64Ux8:
		return rewriteValueRISCV64_OpRsh64Ux8(v)
	case OpRsh64x16:
		return rewriteValueRISCV64_OpRsh64x16(v)
	case OpRsh64x32:
		return rewriteValueRISCV64_OpRsh64x32(v)
	case OpRsh64x64:
		return rewriteValueRISCV64_OpRsh64x64(v)
	case OpRsh64x8:
		return rewriteValueRISCV64_OpRsh64x8(v)
	case OpRsh8Ux16:
		return rewriteValueRISCV64_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValueRISCV64_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValueRISCV64_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValueRISCV64_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValueRISCV64_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValueRISCV64_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValueRISCV64_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValueRISCV64_OpRsh8x8(v)
	case OpSelect0:
		return rewriteValueRISCV64_OpSelect0(v)
	case OpSelect1:
		return rewriteValueRISCV64_OpSelect1(v)
	case OpSignExt16to32:
		v.Op = OpRISCV64MOVHreg
		return true
	case OpSignExt16to64:
		v.Op = OpRISCV64MOVHreg
		return true
	case OpSignExt32to64:
		v.Op = OpRISCV64MOVWreg
		return true
	case OpSignExt8to16:
		v.Op = OpRISCV64MOVBreg
		return true
	case OpSignExt8to32:
		v.Op = OpRISCV64MOVBreg
		return true
	case OpSignExt8to64:
		v.Op = OpRISCV64MOVBreg
		return true
	case OpSlicemask:
		return rewriteValueRISCV64_OpSlicemask(v)
	case OpSqrt:
		v.Op = OpRISCV64FSQRTD
		return true
	case OpSqrt32:
		v.Op = OpRISCV64FSQRTS
		return true
	case OpStaticCall:
		v.Op = OpRISCV64CALLstatic
		return true
	case OpStore:
		return rewriteValueRISCV64_OpStore(v)
	case OpSub16:
		v.Op = OpRISCV64SUB
		return true
	case OpSub32:
		v.Op = OpRISCV64SUB
		return true
	case OpSub32F:
		v.Op = OpRISCV64FSUBS
		return true
	case OpSub64:
		v.Op = OpRISCV64SUB
		return true
	case OpSub64F:
		v.Op = OpRISCV64FSUBD
		return true
	case OpSub8:
		v.Op = OpRISCV64SUB
		return true
	case OpSubPtr:
		v.Op = OpRISCV64SUB
		return true
	case OpTailCall:
		v.Op = OpRISCV64CALLtail
		return true
	case OpTrunc16to8:
		v.Op = OpCopy
		return true
	case OpTrunc32to16:
		v.Op = OpCopy
		return true
	case OpTrunc32to8:
		v.Op = OpCopy
		return true
	case OpTrunc64to16:
		v.Op = OpCopy
		return true
	case OpTrunc64to32:
		v.Op = OpCopy
		return true
	case OpTrunc64to8:
		v.Op = OpCopy
		return true
	case OpWB:
		v.Op = OpRISCV64LoweredWB
		return true
	case OpXor16:
		v.Op = OpRISCV64XOR
		return true
	case OpXor32:
		v.Op = OpRISCV64XOR
		return true
	case OpXor64:
		v.Op = OpRISCV64XOR
		return true
	case OpXor8:
		v.Op = OpRISCV64XOR
		return true
	case OpZero:
		return rewriteValueRISCV64_OpZero(v)
	case OpZeroExt16to32:
		v.Op = OpRISCV64MOVHUreg
		return true
	case OpZeroExt16to64:
		v.Op = OpRISCV64MOVHUreg
		return true
	case OpZeroExt32to64:
		v.Op = OpRISCV64MOVWUreg
		return true
	case OpZeroExt8to16:
		v.Op = OpRISCV64MOVBUreg
		return true
	case OpZeroExt8to32:
		v.Op = OpRISCV64MOVBUreg
		return true
	case OpZeroExt8to64:
		v.Op = OpRISCV64MOVBUreg
		return true
	}
	return false
}
func rewriteValueRISCV64_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVaddr {sym} [0] base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpRISCV64MOVaddr)
		v.AuxInt = int32ToAuxInt(0)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueRISCV64_OpAtomicAnd8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicAnd8 ptr val mem)
	// result: (LoweredAtomicAnd32 (ANDI <typ.Uintptr> [^3] ptr) (NOT <typ.UInt32> (SLL <typ.UInt32> (XORI <typ.UInt32> [0xff] (ZeroExt8to32 val)) (SLLI <typ.UInt64> [3] (ANDI <typ.UInt64> [3] ptr)))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpRISCV64LoweredAtomicAnd32)
		v0 := b.NewValue0(v.Pos, OpRISCV64ANDI, typ.Uintptr)
		v0.AuxInt = int64ToAuxInt(^3)
		v0.AddArg(ptr)
		v1 := b.NewValue0(v.Pos, OpRISCV64NOT, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLL, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpRISCV64XORI, typ.UInt32)
		v3.AuxInt = int64ToAuxInt(0xff)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v4.AddArg(val)
		v3.AddArg(v4)
		v5 := b.NewValue0(v.Pos, OpRISCV64SLLI, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(3)
		v6 := b.NewValue0(v.Pos, OpRISCV64ANDI, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(3)
		v6.AddArg(ptr)
		v5.AddArg(v6)
		v2.AddArg2(v3, v5)
		v1.AddArg(v2)
		v.AddArg3(v0, v1, mem)
		return true
	}
}
func rewriteValueRISCV64_OpAtomicCompareAndSwap32(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicCompareAndSwap32 ptr old new mem)
	// result: (LoweredAtomicCas32 ptr (SignExt32to64 old) new mem)
	for {
		ptr := v_0
		old := v_1
		new := v_2
		mem := v_3
		v.reset(OpRISCV64LoweredAtomicCas32)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(old)
		v.AddArg4(ptr, v0, new, mem)
		return true
	}
}
func rewriteValueRISCV64_OpAtomicOr8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicOr8 ptr val mem)
	// result: (LoweredAtomicOr32 (ANDI <typ.Uintptr> [^3] ptr) (SLL <typ.UInt32> (ZeroExt8to32 val) (SLLI <typ.UInt64> [3] (ANDI <typ.UInt64> [3] ptr))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpRISCV64LoweredAtomicOr32)
		v0 := b.NewValue0(v.Pos, OpRISCV64ANDI, typ.Uintptr)
		v0.AuxInt = int64ToAuxInt(^3)
		v0.AddArg(ptr)
		v1 := b.NewValue0(v.Pos, OpRISCV64SLL, typ.UInt32)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(val)
		v3 := b.NewValue0(v.Pos, OpRISCV64SLLI, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(3)
		v4 := b.NewValue0(v.Pos, OpRISCV64ANDI, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(3)
		v4.AddArg(ptr)
		v3.AddArg(v4)
		v1.AddArg2(v2, v3)
		v.AddArg3(v0, v1, mem)
		return true
	}
}
func rewriteValueRISCV64_OpAvg64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg64u <t> x y)
	// result: (ADD (ADD <t> (SRLI <t> [1] x) (SRLI <t> [1] y)) (ANDI <t> [1] (AND <t> x y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpRISCV64ADD)
		v0 := b.NewValue0(v.Pos, OpRISCV64ADD, t)
		v1 := b.NewValue0(v.Pos, OpRISCV64SRLI, t)
		v1.AuxInt = int64ToAuxInt(1)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpRISCV64SRLI, t)
		v2.AuxInt = int64ToAuxInt(1)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpRISCV64ANDI, t)
		v3.AuxInt = int64ToAuxInt(1)
		v4 := b.NewValue0(v.Pos, OpRISCV64AND, t)
		v4.AddArg2(x, y)
		v3.AddArg(v4)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueRISCV64_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueRISCV64_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueRISCV64_OpConst32F(v *Value) bool {
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Const32F [val])
	// result: (FMVSX (MOVDconst [int64(math.Float32bits(val))]))
	for {
		val := auxIntToFloat32(v.AuxInt)
		v.reset(OpRISCV64FMVSX)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(int64(math.Float32bits(val)))
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpConst64(v *Value) bool {
	// match: (Const64 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt64(v.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueRISCV64_OpConst64F(v *Value) bool {
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Const64F [val])
	// result: (FMVDX (MOVDconst [int64(math.Float64bits(val))]))
	for {
		val := auxIntToFloat64(v.AuxInt)
		v.reset(OpRISCV64FMVDX)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(int64(math.Float64bits(val)))
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueRISCV64_OpConstBool(v *Value) bool {
	// match: (ConstBool [val])
	// result: (MOVDconst [int64(b2i(val))])
	for {
		val := auxIntToBool(v.AuxInt)
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(b2i(val)))
		return true
	}
}
func rewriteValueRISCV64_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVDconst [0])
	for {
		v.reset(OpRISCV64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValueRISCV64_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 x y [false])
	// result: (DIVW (SignExt16to32 x) (SignExt16to32 y))
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpRISCV64DIVW)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (DIVUW (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64DIVUW)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div32 x y [false])
	// result: (DIVW x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpRISCV64DIVW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div64 x y [false])
	// result: (DIV x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpRISCV64DIV)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (DIVW (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64DIVW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (DIVUW (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64DIVUW)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (SEQZ (SUB <x.Type> (ZeroExt16to64 x) (ZeroExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SEQZ)
		v0 := b.NewValue0(v.Pos, OpRISCV64SUB, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq32 x y)
	// cond: x.Type.IsSigned()
	// result: (SEQZ (SUB <x.Type> (SignExt32to64 x) (SignExt32to64 y)))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			y := v_1
			if !(x.Type.IsSigned()) {
				continue
			}
			v.reset(OpRISCV64SEQZ)
			v0 := b.NewValue0(v.Pos, OpRISCV64SUB, x.Type)
			v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
			v1.AddArg(x)
			v2 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
			v2.AddArg(y)
			v0.AddArg2(v1, v2)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Eq32 x y)
	// cond: !x.Type.IsSigned()
	// result: (SEQZ (SUB <x.Type> (ZeroExt32to64 x) (ZeroExt32to64 y)))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			y := v_1
			if !(!x.Type.IsSigned()) {
				continue
			}
			v.reset(OpRISCV64SEQZ)
			v0 := b.NewValue0(v.Pos, OpRISCV64SUB, x.Type)
			v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
			v1.AddArg(x)
			v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
			v2.AddArg(y)
			v0.AddArg2(v1, v2)
			v.AddArg(v0)
			return true
		}
		break
	}
	return false
}
func rewriteValueRISCV64_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64 x y)
	// result: (SEQZ (SUB <x.Type> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SEQZ)
		v0 := b.NewValue0(v.Pos, OpRISCV64SUB, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (SEQZ (SUB <x.Type> (ZeroExt8to64 x) (ZeroExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SEQZ)
		v0 := b.NewValue0(v.Pos, OpRISCV64SUB, x.Type)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (SEQZ (SUB <typ.Bool> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SEQZ)
		v0 := b.NewValue0(v.Pos, OpRISCV64SUB, typ.Bool)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqPtr x y)
	// result: (SEQZ (SUB <typ.Uintptr> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SEQZ)
		v0 := b.NewValue0(v.Pos, OpRISCV64SUB, typ.Uintptr)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpHmul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32 x y)
	// result: (SRAI [32] (MUL (SignExt32to64 x) (SignExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SRAI)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpRISCV64MUL, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpHmul32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32u x y)
	// result: (SRLI [32] (MUL (ZeroExt32to64 x) (ZeroExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SRLI)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpRISCV64MUL, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (Not (Less16 y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpLess16, typ.Bool)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (Not (Less16U y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpLess16U, typ.Bool)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32 x y)
	// result: (Not (Less32 y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpLess32, typ.Bool)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32U x y)
	// result: (Not (Less32U y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpLess32U, typ.Bool)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpLeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64 x y)
	// result: (Not (Less64 y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpLess64, typ.Bool)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpLeq64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64U x y)
	// result: (Not (Less64U y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpLess64U, typ.Bool)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (Not (Less8 y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpLess8, typ.Bool)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (Not (Less8U y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpLess8U, typ.Bool)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueRISCV64_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (SLT (SignExt16to64 x) (SignExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SLT)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (SLTU (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SLTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32 x y)
	// result: (SLT (SignExt32to64 x) (SignExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SLT)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32U x y)
	// result: (SLTU (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SLTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (SLT (SignExt8to64 x) (SignExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SLT)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (SLTU (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64SLTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Load <t> ptr mem)
	// cond: t.IsBoolean()
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsBoolean()) {
			break
		}
		v.reset(OpRISCV64MOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: ( is8BitInt(t) && t.IsSigned())
	// result: (MOVBload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpRISCV64MOVBload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: ( is8BitInt(t) && !t.IsSigned())
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpRISCV64MOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && t.IsSigned())
	// result: (MOVHload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpRISCV64MOVHload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is16BitInt(t) && !t.IsSigned())
	// result: (MOVHUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpRISCV64MOVHUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) && t.IsSigned())
	// result: (MOVWload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpRISCV64MOVWload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is32BitInt(t) && !t.IsSigned())
	// result: (MOVWUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpRISCV64MOVWUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (MOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpRISCV64MOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (FMOVWload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpRISCV64FMOVWload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (FMOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpRISCV64FMOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpRISCV64MOVaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpRISCV64MOVaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg16 <t> (SLTIU <t> [64] (ZeroExt16to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg16, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh16x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg16 <t> (SLTIU <t> [64] (ZeroExt32to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg16, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh16x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh16x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg16 <t> (SLTIU <t> [64] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg16, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh16x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg16 <t> (SLTIU <t> [64] (ZeroExt8to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg16, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh16x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg32 <t> (SLTIU <t> [64] (ZeroExt16to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg32, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh32x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg32 <t> (SLTIU <t> [64] (ZeroExt32to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg32, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh32x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg32 <t> (SLTIU <t> [64] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg32, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh32x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg32 <t> (SLTIU <t> [64] (ZeroExt8to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg32, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh32x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg64 <t> (SLTIU <t> [64] (ZeroExt16to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg64, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh64x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg64 <t> (SLTIU <t> [64] (ZeroExt32to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg64, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh64x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh64x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg64 <t> (SLTIU <t> [64] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg64, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh64x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg64 <t> (SLTIU <t> [64] (ZeroExt8to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg64, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh64x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg8 <t> (SLTIU <t> [64] (ZeroExt16to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg8, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh8x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg8 <t> (SLTIU <t> [64] (ZeroExt32to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg8, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh8x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg8 <t> (SLTIU <t> [64] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg8, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh8x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (AND (SLL <t> x y) (Neg8 <t> (SLTIU <t> [64] (ZeroExt8to64 y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64AND)
		v0 := b.NewValue0(v.Pos, OpRISCV64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpNeg8, t)
		v2 := b.NewValue0(v.Pos, OpRISCV64SLTIU, t)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Lsh8x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLL x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpRISCV64SLL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpMax64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Max64 x y)
	// cond: buildcfg.GORISCV64 >= 22
	// result: (MAX x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GORISCV64 >= 22) {
			break
		}
		v.reset(OpRISCV64MAX)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpMax64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Max64u x y)
	// cond: buildcfg.GORISCV64 >= 22
	// result: (MAXU x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GORISCV64 >= 22) {
			break
		}
		v.reset(OpRISCV64MAXU)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpMin64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Min64 x y)
	// cond: buildcfg.GORISCV64 >= 22
	// result: (MIN x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GORISCV64 >= 22) {
			break
		}
		v.reset(OpRISCV64MIN)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpMin64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Min64u x y)
	// cond: buildcfg.GORISCV64 >= 22
	// result: (MINU x y)
	for {
		x := v_0
		y := v_1
		if !(buildcfg.GORISCV64 >= 22) {
			break
		}
		v.reset(OpRISCV64MINU)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y [false])
	// result: (REMW (SignExt16to32 x) (SignExt16to32 y))
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpRISCV64REMW)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (REMUW (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64REMUW)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod32 x y [false])
	// result: (REMW x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpRISCV64REMW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod64 x y [false])
	// result: (REM x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpRISCV64REM)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueRISCV64_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (REMW (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64REMW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (REMUW (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpRISCV64REMUW)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueRISCV64_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Move [0] _ _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.copyOf(mem)
		return true
	}
	// match: (Move [1] dst src mem)
	// result: (MOVBstore dst (MOVBload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore dst (MOVHload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpRISCV64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVBstore [1] dst (MOVBload [1] src mem) (MOVBstore dst (MOVBload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v0.AuxInt = int32ToAuxInt(1)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVBstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore dst (MOVWload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpRISCV64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVWload, typ.Int32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [2] dst (MOVHload [2] src mem) (MOVHstore dst (MOVHload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpRISCV64MOVHstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVBstore [3] dst (MOVBload [3] src mem) (MOVBstore [2] dst (MOVBload [2] src mem) (MOVBstore [1] dst (MOVBload [1] src mem) (MOVBstore dst (MOVBload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpRISCV64MOVBstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v2.AuxInt = int32ToAuxInt(2)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpRISCV64MOVBstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(1)
		v4 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v4.AuxInt = int32ToAuxInt(1)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpRISCV64MOVBstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpRISCV64MOVBload, typ.Int8)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] {t} dst src mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVDstore dst (MOVDload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpRISCV64MOVDstore)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVDload, typ.Int64)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [8] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [4] dst (MOVWload [4] src mem) (MOVWstore dst (MOVWload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpRISCV64MOVWstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVWload, typ.Int32)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVWload, typ.Int32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [6] dst (MOVHload [6] src mem) (MOVHstore [4] dst (MOVHload [4] src mem) (MOVHstore [2] dst (MOVHload [2] src mem) (MOVHstore dst (MOVHload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpRISCV64MOVHstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v0.AuxInt = int32ToAuxInt(6)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpRISCV64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v2.AuxInt = int32ToAuxInt(4)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpRISCV64MOVHstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(2)
		v4 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v4.AuxInt = int32ToAuxInt(2)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpRISCV64MOVHstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpRISCV64MOVHload, typ.Int16)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBload [2] src mem) (MOVBstore [1] dst (MOVBload [1] src mem) (MOVBstore dst (MOVBload src
```