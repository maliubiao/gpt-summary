Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共6部分，请归纳一下它的功能

"""
// Code generated from _gen/PPC64.rules using 'go generate'; DO NOT EDIT.

package ssa

import "internal/buildcfg"
import "math"
import "cmd/compile/internal/types"

func rewriteValuePPC64(v *Value) bool {
	switch v.Op {
	case OpAbs:
		v.Op = OpPPC64FABS
		return true
	case OpAdd16:
		v.Op = OpPPC64ADD
		return true
	case OpAdd32:
		v.Op = OpPPC64ADD
		return true
	case OpAdd32F:
		v.Op = OpPPC64FADDS
		return true
	case OpAdd64:
		v.Op = OpPPC64ADD
		return true
	case OpAdd64F:
		v.Op = OpPPC64FADD
		return true
	case OpAdd8:
		v.Op = OpPPC64ADD
		return true
	case OpAddPtr:
		v.Op = OpPPC64ADD
		return true
	case OpAddr:
		return rewriteValuePPC64_OpAddr(v)
	case OpAnd16:
		v.Op = OpPPC64AND
		return true
	case OpAnd32:
		v.Op = OpPPC64AND
		return true
	case OpAnd64:
		v.Op = OpPPC64AND
		return true
	case OpAnd8:
		v.Op = OpPPC64AND
		return true
	case OpAndB:
		v.Op = OpPPC64AND
		return true
	case OpAtomicAdd32:
		v.Op = OpPPC64LoweredAtomicAdd32
		return true
	case OpAtomicAdd64:
		v.Op = OpPPC64LoweredAtomicAdd64
		return true
	case OpAtomicAnd32:
		v.Op = OpPPC64LoweredAtomicAnd32
		return true
	case OpAtomicAnd8:
		v.Op = OpPPC64LoweredAtomicAnd8
		return true
	case OpAtomicCompareAndSwap32:
		return rewriteValuePPC64_OpAtomicCompareAndSwap32(v)
	case OpAtomicCompareAndSwap64:
		return rewriteValuePPC64_OpAtomicCompareAndSwap64(v)
	case OpAtomicCompareAndSwapRel32:
		return rewriteValuePPC64_OpAtomicCompareAndSwapRel32(v)
	case OpAtomicExchange32:
		v.Op = OpPPC64LoweredAtomicExchange32
		return true
	case OpAtomicExchange64:
		v.Op = OpPPC64LoweredAtomicExchange64
		return true
	case OpAtomicExchange8:
		v.Op = OpPPC64LoweredAtomicExchange8
		return true
	case OpAtomicLoad32:
		return rewriteValuePPC64_OpAtomicLoad32(v)
	case OpAtomicLoad64:
		return rewriteValuePPC64_OpAtomicLoad64(v)
	case OpAtomicLoad8:
		return rewriteValuePPC64_OpAtomicLoad8(v)
	case OpAtomicLoadAcq32:
		return rewriteValuePPC64_OpAtomicLoadAcq32(v)
	case OpAtomicLoadAcq64:
		return rewriteValuePPC64_OpAtomicLoadAcq64(v)
	case OpAtomicLoadPtr:
		return rewriteValuePPC64_OpAtomicLoadPtr(v)
	case OpAtomicOr32:
		v.Op = OpPPC64LoweredAtomicOr32
		return true
	case OpAtomicOr8:
		v.Op = OpPPC64LoweredAtomicOr8
		return true
	case OpAtomicStore32:
		return rewriteValuePPC64_OpAtomicStore32(v)
	case OpAtomicStore64:
		return rewriteValuePPC64_OpAtomicStore64(v)
	case OpAtomicStore8:
		return rewriteValuePPC64_OpAtomicStore8(v)
	case OpAtomicStoreRel32:
		return rewriteValuePPC64_OpAtomicStoreRel32(v)
	case OpAtomicStoreRel64:
		return rewriteValuePPC64_OpAtomicStoreRel64(v)
	case OpAvg64u:
		return rewriteValuePPC64_OpAvg64u(v)
	case OpBitLen32:
		return rewriteValuePPC64_OpBitLen32(v)
	case OpBitLen64:
		return rewriteValuePPC64_OpBitLen64(v)
	case OpBswap16:
		return rewriteValuePPC64_OpBswap16(v)
	case OpBswap32:
		return rewriteValuePPC64_OpBswap32(v)
	case OpBswap64:
		return rewriteValuePPC64_OpBswap64(v)
	case OpCeil:
		v.Op = OpPPC64FCEIL
		return true
	case OpClosureCall:
		v.Op = OpPPC64CALLclosure
		return true
	case OpCom16:
		return rewriteValuePPC64_OpCom16(v)
	case OpCom32:
		return rewriteValuePPC64_OpCom32(v)
	case OpCom64:
		return rewriteValuePPC64_OpCom64(v)
	case OpCom8:
		return rewriteValuePPC64_OpCom8(v)
	case OpCondSelect:
		return rewriteValuePPC64_OpCondSelect(v)
	case OpConst16:
		return rewriteValuePPC64_OpConst16(v)
	case OpConst32:
		return rewriteValuePPC64_OpConst32(v)
	case OpConst32F:
		v.Op = OpPPC64FMOVSconst
		return true
	case OpConst64:
		return rewriteValuePPC64_OpConst64(v)
	case OpConst64F:
		v.Op = OpPPC64FMOVDconst
		return true
	case OpConst8:
		return rewriteValuePPC64_OpConst8(v)
	case OpConstBool:
		return rewriteValuePPC64_OpConstBool(v)
	case OpConstNil:
		return rewriteValuePPC64_OpConstNil(v)
	case OpCopysign:
		return rewriteValuePPC64_OpCopysign(v)
	case OpCtz16:
		return rewriteValuePPC64_OpCtz16(v)
	case OpCtz32:
		return rewriteValuePPC64_OpCtz32(v)
	case OpCtz32NonZero:
		v.Op = OpCtz32
		return true
	case OpCtz64:
		return rewriteValuePPC64_OpCtz64(v)
	case OpCtz64NonZero:
		v.Op = OpCtz64
		return true
	case OpCtz8:
		return rewriteValuePPC64_OpCtz8(v)
	case OpCvt32Fto32:
		return rewriteValuePPC64_OpCvt32Fto32(v)
	case OpCvt32Fto64:
		return rewriteValuePPC64_OpCvt32Fto64(v)
	case OpCvt32Fto64F:
		v.Op = OpCopy
		return true
	case OpCvt32to32F:
		return rewriteValuePPC64_OpCvt32to32F(v)
	case OpCvt32to64F:
		return rewriteValuePPC64_OpCvt32to64F(v)
	case OpCvt64Fto32:
		return rewriteValuePPC64_OpCvt64Fto32(v)
	case OpCvt64Fto32F:
		v.Op = OpPPC64FRSP
		return true
	case OpCvt64Fto64:
		return rewriteValuePPC64_OpCvt64Fto64(v)
	case OpCvt64to32F:
		return rewriteValuePPC64_OpCvt64to32F(v)
	case OpCvt64to64F:
		return rewriteValuePPC64_OpCvt64to64F(v)
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv16:
		return rewriteValuePPC64_OpDiv16(v)
	case OpDiv16u:
		return rewriteValuePPC64_OpDiv16u(v)
	case OpDiv32:
		return rewriteValuePPC64_OpDiv32(v)
	case OpDiv32F:
		v.Op = OpPPC64FDIVS
		return true
	case OpDiv32u:
		v.Op = OpPPC64DIVWU
		return true
	case OpDiv64:
		return rewriteValuePPC64_OpDiv64(v)
	case OpDiv64F:
		v.Op = OpPPC64FDIV
		return true
	case OpDiv64u:
		v.Op = OpPPC64DIVDU
		return true
	case OpDiv8:
		return rewriteValuePPC64_OpDiv8(v)
	case OpDiv8u:
		return rewriteValuePPC64_OpDiv8u(v)
	case OpEq16:
		return rewriteValuePPC64_OpEq16(v)
	case OpEq32:
		return rewriteValuePPC64_OpEq32(v)
	case OpEq32F:
		return rewriteValuePPC64_OpEq32F(v)
	case OpEq64:
		return rewriteValuePPC64_OpEq64(v)
	case OpEq64F:
		return rewriteValuePPC64_OpEq64F(v)
	case OpEq8:
		return rewriteValuePPC64_OpEq8(v)
	case OpEqB:
		return rewriteValuePPC64_OpEqB(v)
	case OpEqPtr:
		return rewriteValuePPC64_OpEqPtr(v)
	case OpFMA:
		v.Op = OpPPC64FMADD
		return true
	case OpFloor:
		v.Op = OpPPC64FFLOOR
		return true
	case OpGetCallerPC:
		v.Op = OpPPC64LoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = OpPPC64LoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = OpPPC64LoweredGetClosurePtr
		return true
	case OpHmul32:
		v.Op = OpPPC64MULHW
		return true
	case OpHmul32u:
		v.Op = OpPPC64MULHWU
		return true
	case OpHmul64:
		v.Op = OpPPC64MULHD
		return true
	case OpHmul64u:
		v.Op = OpPPC64MULHDU
		return true
	case OpInterCall:
		v.Op = OpPPC64CALLinter
		return true
	case OpIsInBounds:
		return rewriteValuePPC64_OpIsInBounds(v)
	case OpIsNonNil:
		return rewriteValuePPC64_OpIsNonNil(v)
	case OpIsSliceInBounds:
		return rewriteValuePPC64_OpIsSliceInBounds(v)
	case OpLeq16:
		return rewriteValuePPC64_OpLeq16(v)
	case OpLeq16U:
		return rewriteValuePPC64_OpLeq16U(v)
	case OpLeq32:
		return rewriteValuePPC64_OpLeq32(v)
	case OpLeq32F:
		return rewriteValuePPC64_OpLeq32F(v)
	case OpLeq32U:
		return rewriteValuePPC64_OpLeq32U(v)
	case OpLeq64:
		return rewriteValuePPC64_OpLeq64(v)
	case OpLeq64F:
		return rewriteValuePPC64_OpLeq64F(v)
	case OpLeq64U:
		return rewriteValuePPC64_OpLeq64U(v)
	case OpLeq8:
		return rewriteValuePPC64_OpLeq8(v)
	case OpLeq8U:
		return rewriteValuePPC64_OpLeq8U(v)
	case OpLess16:
		return rewriteValuePPC64_OpLess16(v)
	case OpLess16U:
		return rewriteValuePPC64_OpLess16U(v)
	case OpLess32:
		return rewriteValuePPC64_OpLess32(v)
	case OpLess32F:
		return rewriteValuePPC64_OpLess32F(v)
	case OpLess32U:
		return rewriteValuePPC64_OpLess32U(v)
	case OpLess64:
		return rewriteValuePPC64_OpLess64(v)
	case OpLess64F:
		return rewriteValuePPC64_OpLess64F(v)
	case OpLess64U:
		return rewriteValuePPC64_OpLess64U(v)
	case OpLess8:
		return rewriteValuePPC64_OpLess8(v)
	case OpLess8U:
		return rewriteValuePPC64_OpLess8U(v)
	case OpLoad:
		return rewriteValuePPC64_OpLoad(v)
	case OpLocalAddr:
		return rewriteValuePPC64_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValuePPC64_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValuePPC64_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValuePPC64_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValuePPC64_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValuePPC64_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValuePPC64_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValuePPC64_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValuePPC64_OpLsh32x8(v)
	case OpLsh64x16:
		return rewriteValuePPC64_OpLsh64x16(v)
	case OpLsh64x32:
		return rewriteValuePPC64_OpLsh64x32(v)
	case OpLsh64x64:
		return rewriteValuePPC64_OpLsh64x64(v)
	case OpLsh64x8:
		return rewriteValuePPC64_OpLsh64x8(v)
	case OpLsh8x16:
		return rewriteValuePPC64_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValuePPC64_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValuePPC64_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValuePPC64_OpLsh8x8(v)
	case OpMax32F:
		return rewriteValuePPC64_OpMax32F(v)
	case OpMax64F:
		return rewriteValuePPC64_OpMax64F(v)
	case OpMin32F:
		return rewriteValuePPC64_OpMin32F(v)
	case OpMin64F:
		return rewriteValuePPC64_OpMin64F(v)
	case OpMod16:
		return rewriteValuePPC64_OpMod16(v)
	case OpMod16u:
		return rewriteValuePPC64_OpMod16u(v)
	case OpMod32:
		return rewriteValuePPC64_OpMod32(v)
	case OpMod32u:
		return rewriteValuePPC64_OpMod32u(v)
	case OpMod64:
		return rewriteValuePPC64_OpMod64(v)
	case OpMod64u:
		return rewriteValuePPC64_OpMod64u(v)
	case OpMod8:
		return rewriteValuePPC64_OpMod8(v)
	case OpMod8u:
		return rewriteValuePPC64_OpMod8u(v)
	case OpMove:
		return rewriteValuePPC64_OpMove(v)
	case OpMul16:
		v.Op = OpPPC64MULLW
		return true
	case OpMul32:
		v.Op = OpPPC64MULLW
		return true
	case OpMul32F:
		v.Op = OpPPC64FMULS
		return true
	case OpMul64:
		v.Op = OpPPC64MULLD
		return true
	case OpMul64F:
		v.Op = OpPPC64FMUL
		return true
	case OpMul8:
		v.Op = OpPPC64MULLW
		return true
	case OpNeg16:
		v.Op = OpPPC64NEG
		return true
	case OpNeg32:
		v.Op = OpPPC64NEG
		return true
	case OpNeg32F:
		v.Op = OpPPC64FNEG
		return true
	case OpNeg64:
		v.Op = OpPPC64NEG
		return true
	case OpNeg64F:
		v.Op = OpPPC64FNEG
		return true
	case OpNeg8:
		v.Op = OpPPC64NEG
		return true
	case OpNeq16:
		return rewriteValuePPC64_OpNeq16(v)
	case OpNeq32:
		return rewriteValuePPC64_OpNeq32(v)
	case OpNeq32F:
		return rewriteValuePPC64_OpNeq32F(v)
	case OpNeq64:
		return rewriteValuePPC64_OpNeq64(v)
	case OpNeq64F:
		return rewriteValuePPC64_OpNeq64F(v)
	case OpNeq8:
		return rewriteValuePPC64_OpNeq8(v)
	case OpNeqB:
		v.Op = OpPPC64XOR
		return true
	case OpNeqPtr:
		return rewriteValuePPC64_OpNeqPtr(v)
	case OpNilCheck:
		v.Op = OpPPC64LoweredNilCheck
		return true
	case OpNot:
		return rewriteValuePPC64_OpNot(v)
	case OpOffPtr:
		return rewriteValuePPC64_OpOffPtr(v)
	case OpOr16:
		v.Op = OpPPC64OR
		return true
	case OpOr32:
		v.Op = OpPPC64OR
		return true
	case OpOr64:
		v.Op = OpPPC64OR
		return true
	case OpOr8:
		v.Op = OpPPC64OR
		return true
	case OpOrB:
		v.Op = OpPPC64OR
		return true
	case OpPPC64ADD:
		return rewriteValuePPC64_OpPPC64ADD(v)
	case OpPPC64ADDC:
		return rewriteValuePPC64_OpPPC64ADDC(v)
	case OpPPC64ADDE:
		return rewriteValuePPC64_OpPPC64ADDE(v)
	case OpPPC64ADDconst:
		return rewriteValuePPC64_OpPPC64ADDconst(v)
	case OpPPC64AND:
		return rewriteValuePPC64_OpPPC64AND(v)
	case OpPPC64ANDN:
		return rewriteValuePPC64_OpPPC64ANDN(v)
	case OpPPC64ANDconst:
		return rewriteValuePPC64_OpPPC64ANDconst(v)
	case OpPPC64BRD:
		return rewriteValuePPC64_OpPPC64BRD(v)
	case OpPPC64BRH:
		return rewriteValuePPC64_OpPPC64BRH(v)
	case OpPPC64BRW:
		return rewriteValuePPC64_OpPPC64BRW(v)
	case OpPPC64CLRLSLDI:
		return rewriteValuePPC64_OpPPC64CLRLSLDI(v)
	case OpPPC64CMP:
		return rewriteValuePPC64_OpPPC64CMP(v)
	case OpPPC64CMPU:
		return rewriteValuePPC64_OpPPC64CMPU(v)
	case OpPPC64CMPUconst:
		return rewriteValuePPC64_OpPPC64CMPUconst(v)
	case OpPPC64CMPW:
		return rewriteValuePPC64_OpPPC64CMPW(v)
	case OpPPC64CMPWU:
		return rewriteValuePPC64_OpPPC64CMPWU(v)
	case OpPPC64CMPWUconst:
		return rewriteValuePPC64_OpPPC64CMPWUconst(v)
	case OpPPC64CMPWconst:
		return rewriteValuePPC64_OpPPC64CMPWconst(v)
	case OpPPC64CMPconst:
		return rewriteValuePPC64_OpPPC64CMPconst(v)
	case OpPPC64Equal:
		return rewriteValuePPC64_OpPPC64Equal(v)
	case OpPPC64FABS:
		return rewriteValuePPC64_OpPPC64FABS(v)
	case OpPPC64FADD:
		return rewriteValuePPC64_OpPPC64FADD(v)
	case OpPPC64FADDS:
		return rewriteValuePPC64_OpPPC64FADDS(v)
	case OpPPC64FCEIL:
		return rewriteValuePPC64_OpPPC64FCEIL(v)
	case OpPPC64FFLOOR:
		return rewriteValuePPC64_OpPPC64FFLOOR(v)
	case OpPPC64FGreaterEqual:
		return rewriteValuePPC64_OpPPC64FGreaterEqual(v)
	case OpPPC64FGreaterThan:
		return rewriteValuePPC64_OpPPC64FGreaterThan(v)
	case OpPPC64FLessEqual:
		return rewriteValuePPC64_OpPPC64FLessEqual(v)
	case OpPPC64FLessThan:
		return rewriteValuePPC64_OpPPC64FLessThan(v)
	case OpPPC64FMOVDload:
		return rewriteValuePPC64_OpPPC64FMOVDload(v)
	case OpPPC64FMOVDstore:
		return rewriteValuePPC64_OpPPC64FMOVDstore(v)
	case OpPPC64FMOVSload:
		return rewriteValuePPC64_OpPPC64FMOVSload(v)
	case OpPPC64FMOVSstore:
		return rewriteValuePPC64_OpPPC64FMOVSstore(v)
	case OpPPC64FNEG:
		return rewriteValuePPC64_OpPPC64FNEG(v)
	case OpPPC64FSQRT:
		return rewriteValuePPC64_OpPPC64FSQRT(v)
	case OpPPC64FSUB:
		return rewriteValuePPC64_OpPPC64FSUB(v)
	case OpPPC64FSUBS:
		return rewriteValuePPC64_OpPPC64FSUBS(v)
	case OpPPC64FTRUNC:
		return rewriteValuePPC64_OpPPC64FTRUNC(v)
	case OpPPC64GreaterEqual:
		return rewriteValuePPC64_OpPPC64GreaterEqual(v)
	case OpPPC64GreaterThan:
		return rewriteValuePPC64_OpPPC64GreaterThan(v)
	case OpPPC64ISEL:
		return rewriteValuePPC64_OpPPC64ISEL(v)
	case OpPPC64LessEqual:
		return rewriteValuePPC64_OpPPC64LessEqual(v)
	case OpPPC64LessThan:
		return rewriteValuePPC64_OpPPC64LessThan(v)
	case OpPPC64MFVSRD:
		return rewriteValuePPC64_OpPPC64MFVSRD(v)
	case OpPPC64MOVBZload:
		return rewriteValuePPC64_OpPPC64MOVBZload(v)
	case OpPPC64MOVBZloadidx:
		return rewriteValuePPC64_OpPPC64MOVBZloadidx(v)
	case OpPPC64MOVBZreg:
		return rewriteValuePPC64_OpPPC64MOVBZreg(v)
	case OpPPC64MOVBreg:
		return rewriteValuePPC64_OpPPC64MOVBreg(v)
	case OpPPC64MOVBstore:
		return rewriteValuePPC64_OpPPC64MOVBstore(v)
	case OpPPC64MOVBstoreidx:
		return rewriteValuePPC64_OpPPC64MOVBstoreidx(v)
	case OpPPC64MOVBstorezero:
		return rewriteValuePPC64_OpPPC64MOVBstorezero(v)
	case OpPPC64MOVDaddr:
		return rewriteValuePPC64_OpPPC64MOVDaddr(v)
	case OpPPC64MOVDload:
		return rewriteValuePPC64_OpPPC64MOVDload(v)
	case OpPPC64MOVDloadidx:
		return rewriteValuePPC64_OpPPC64MOVDloadidx(v)
	case OpPPC64MOVDstore:
		return rewriteValuePPC64_OpPPC64MOVDstore(v)
	case OpPPC64MOVDstoreidx:
		return rewriteValuePPC64_OpPPC64MOVDstoreidx(v)
	case OpPPC64MOVDstorezero:
		return rewriteValuePPC64_OpPPC64MOVDstorezero(v)
	case OpPPC64MOVHBRstore:
		return rewriteValuePPC64_OpPPC64MOVHBRstore(v)
	case OpPPC64MOVHZload:
		return rewriteValuePPC64_OpPPC64MOVHZload(v)
	case OpPPC64MOVHZloadidx:
		return rewriteValuePPC64_OpPPC64MOVHZloadidx(v)
	case OpPPC64MOVHZreg:
		return rewriteValuePPC64_OpPPC64MOVHZreg(v)
	case OpPPC64MOVHload:
		return rewriteValuePPC64_OpPPC64MOVHload(v)
	case OpPPC64MOVHloadidx:
		return rewriteValuePPC64_OpPPC64MOVHloadidx(v)
	case OpPPC64MOVHreg:
		return rewriteValuePPC64_OpPPC64MOVHreg(v)
	case OpPPC64MOVHstore:
		return rewriteValuePPC64_OpPPC64MOVHstore(v)
	case OpPPC64MOVHstoreidx:
		return rewriteValuePPC64_OpPPC64MOVHstoreidx(v)
	case OpPPC64MOVHstorezero:
		return rewriteValuePPC64_OpPPC64MOVHstorezero(v)
	case OpPPC64MOVWBRstore:
		return rewriteValuePPC64_OpPPC64MOVWBRstore(v)
	case OpPPC64MOVWZload:
		return rewriteValuePPC64_OpPPC64MOVWZload(v)
	case OpPPC64MOVWZloadidx:
		return rewriteValuePPC64_OpPPC64MOVWZloadidx(v)
	case OpPPC64MOVWZreg:
		return rewriteValuePPC64_OpPPC64MOVWZreg(v)
	case OpPPC64MOVWload:
		return rewriteValuePPC64_OpPPC64MOVWload(v)
	case OpPPC64MOVWloadidx:
		return rewriteValuePPC64_OpPPC64MOVWloadidx(v)
	case OpPPC64MOVWreg:
		return rewriteValuePPC64_OpPPC64MOVWreg(v)
	case OpPPC64MOVWstore:
		return rewriteValuePPC64_OpPPC64MOVWstore(v)
	case OpPPC64MOVWstoreidx:
		return rewriteValuePPC64_OpPPC64MOVWstoreidx(v)
	case OpPPC64MOVWstorezero:
		return rewriteValuePPC64_OpPPC64MOVWstorezero(v)
	case OpPPC64MTVSRD:
		return rewriteValuePPC64_OpPPC64MTVSRD(v)
	case OpPPC64MULLD:
		return rewriteValuePPC64_OpPPC64MULLD(v)
	case OpPPC64MULLW:
		return rewriteValuePPC64_OpPPC64MULLW(v)
	case OpPPC64NEG:
		return rewriteValuePPC64_OpPPC64NEG(v)
	case OpPPC64NOR:
		return rewriteValuePPC64_OpPPC64NOR(v)
	case OpPPC64NotEqual:
		return rewriteValuePPC64_OpPPC64NotEqual(v)
	case OpPPC64OR:
		return rewriteValuePPC64_OpPPC64OR(v)
	case OpPPC64ORN:
		return rewriteValuePPC64_OpPPC64ORN(v)
	case OpPPC64ORconst:
		return rewriteValuePPC64_OpPPC64ORconst(v)
	case OpPPC64RLWINM:
		return rewriteValuePPC64_OpPPC64RLWINM(v)
	case OpPPC64ROTL:
		return rewriteValuePPC64_OpPPC64ROTL(v)
	case OpPPC64ROTLW:
		return rewriteValuePPC64_OpPPC64ROTLW(v)
	case OpPPC64ROTLWconst:
		return rewriteValuePPC64_OpPPC64ROTLWconst(v)
	case OpPPC64SETBC:
		return rewriteValuePPC64_OpPPC64SETBC(v)
	case OpPPC64SETBCR:
		return rewriteValuePPC64_OpPPC64SETBCR(v)
	case OpPPC64SLD:
		return rewriteValuePPC64_OpPPC64SLD(v)
	case OpPPC64SLDconst:
		return rewriteValuePPC64_OpPPC64SLDconst(v)
	case OpPPC64SLW:
		return rewriteValuePPC64_OpPPC64SLW(v)
	case OpPPC64SLWconst:
		return rewriteValuePPC64_OpPPC64SLWconst(v)
	case OpPPC64SRAD:
		return rewriteValuePPC64_OpPPC64SRAD(v)
	case OpPPC64SRAW:
		return rewriteValuePPC64_OpPPC64SRAW(v)
	case OpPPC64SRD:
		return rewriteValuePPC64_OpPPC64SRD(v)
	case OpPPC64SRW:
		return rewriteValuePPC64_OpPPC64SRW(v)
	case OpPPC64SRWconst:
		return rewriteValuePPC64_OpPPC64SRWconst(v)
	case OpPPC64SUB:
		return rewriteValuePPC64_OpPPC64SUB(v)
	case OpPPC64SUBE:
		return rewriteValuePPC64_OpPPC64SUBE(v)
	case OpPPC64SUBFCconst:
		return rewriteValuePPC64_OpPPC64SUBFCconst(v)
	case OpPPC64XOR:
		return rewriteValuePPC64_OpPPC64XOR(v)
	case OpPPC64XORconst:
		return rewriteValuePPC64_OpPPC64XORconst(v)
	case OpPanicBounds:
		return rewriteValuePPC64_OpPanicBounds(v)
	case OpPopCount16:
		return rewriteValuePPC64_OpPopCount16(v)
	case OpPopCount32:
		return rewriteValuePPC64_OpPopCount32(v)
	case OpPopCount64:
		v.Op = OpPPC64POPCNTD
		return true
	case OpPopCount8:
		return rewriteValuePPC64_OpPopCount8(v)
	case OpPrefetchCache:
		return rewriteValuePPC64_OpPrefetchCache(v)
	case OpPrefetchCacheStreamed:
		return rewriteValuePPC64_OpPrefetchCacheStreamed(v)
	case OpPubBarrier:
		v.Op = OpPPC64LoweredPubBarrier
		return true
	case OpRotateLeft16:
		return rewriteValuePPC64_OpRotateLeft16(v)
	case OpRotateLeft32:
		v.Op = OpPPC64ROTLW
		return true
	case OpRotateLeft64:
		v.Op = OpPPC64ROTL
		return true
	case OpRotateLeft8:
		return rewriteValuePPC64_OpRotateLeft8(v)
	case OpRound:
		v.Op = OpPPC64FROUND
		return true
	case OpRound32F:
		v.Op = OpPPC64LoweredRound32F
		return true
	case OpRound64F:
		v.Op = OpPPC64LoweredRound64F
		return true
	case OpRsh16Ux16:
		return rewriteValuePPC64_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValuePPC64_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValuePPC64_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValuePPC64_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValuePPC64_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValuePPC64_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValuePPC64_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValuePPC64_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValuePPC64_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValuePPC64_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValuePPC64_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValuePPC64_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValuePPC64_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValuePPC64_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValuePPC64_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValuePPC64_OpRsh32x8(v)
	case OpRsh64Ux16:
		return rewriteValuePPC64_OpRsh64Ux16(v)
	case OpRsh64Ux32:
		return rewriteValuePPC64_OpRsh64Ux32(v)
	case OpRsh64Ux64:
		return rewriteValuePPC64_OpRsh64Ux64(v)
	case OpRsh64Ux8:
		return rewriteValuePPC64_OpRsh64Ux8(v)
	case OpRsh64x16:
		return rewriteValuePPC64_OpRsh64x16(v)
	case OpRsh64x32:
		return rewriteValuePPC64_OpRsh64x32(v)
	case OpRsh64x64:
		return rewriteValuePPC64_OpRsh64x64(v)
	case OpRsh64x8:
		return rewriteValuePPC64_OpRsh64x8(v)
	case OpRsh8Ux16:
		return rewriteValuePPC64_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValuePPC64_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValuePPC64_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValuePPC64_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValuePPC64_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValuePPC64_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValuePPC64_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValuePPC64_OpRsh8x8(v)
	case OpSelect0:
		return rewriteValuePPC64_OpSelect0(v)
	case OpSelect1:
		return rewriteValuePPC64_OpSelect1(v)
	case OpSelectN:
		return rewriteValuePPC64_OpSelectN(v)
	case OpSignExt16to32:
		v.Op = OpPPC64MOVHreg
		return true
	case OpSignExt16to64:
		v.Op = OpPPC64MOVHreg
		return true
	case OpSignExt32to64:
		v.Op = OpPPC64MOVWreg
		return true
	case OpSignExt8to16:
		v.Op = OpPPC64MOVBreg
		return true
	case OpSignExt8to32:
		v.Op = OpPPC64MOVBreg
		return true
	case OpSignExt8to64:
		v.Op = OpPPC64MOVBreg
		return true
	case OpSlicemask:
		return rewriteValuePPC64_OpSlicemask(v)
	case OpSqrt:
		v.Op = OpPPC64FSQRT
		return true
	case OpSqrt32:
		v.Op = OpPPC64FSQRTS
		return true
	case OpStaticCall:
		v.Op = OpPPC64CALLstatic
		return true
	case OpStore:
		return rewriteValuePPC64_OpStore(v)
	case OpSub16:
		v.Op = OpPPC64SUB
		return true
	case OpSub32:
		v.Op = OpPPC64SUB
		return true
	case OpSub32F:
		v.Op = OpPPC64FSUBS
		return true
	case OpSub64:
		v.Op = OpPPC64SUB
		return true
	case OpSub64F:
		v.Op = OpPPC64FSUB
		return true
	case OpSub8:
		v.Op = OpPPC64SUB
		return true
	case OpSubPtr:
		v.Op = OpPPC64SUB
		return true
	case OpTailCall:
		v.Op = OpPPC64CALLtail
		return true
	case OpTrunc:
		v.Op = OpPPC64FTRUNC
		return true
	case OpTrunc16to8:
		return rewriteValuePPC64_OpTrunc16to8(v)
	case OpTrunc32to16:
		return rewriteValuePPC64_OpTrunc32to16(v)
	case OpTrunc32to8:
		return rewriteValuePPC64_OpTrunc32to8(v)
	case OpTrunc64to16:
		return rewriteValuePPC64_OpTrunc64to16(v)
	case OpTrunc64to32:
		return rewriteValuePPC64_OpTrunc64to32(v)
	case OpTrunc64to8:
		return rewriteValuePPC64_OpTrunc64to8(v)
	case OpWB:
		v.Op = OpPPC64LoweredWB
		return true
	case OpXor16:
		v.Op = OpPPC64XOR
		return true
	case OpXor32:
		v.Op = OpPPC64XOR
		return true
	case OpXor64:
		v.Op = OpPPC64XOR
		return true
	case OpXor8:
		v.Op = OpPPC64XOR
		return true
	case OpZero:
		return rewriteValuePPC64_OpZero(v)
	case OpZeroExt16to32:
		v.Op = OpPPC64MOVHZreg
		return true
	case OpZeroExt16to64:
		v.Op = OpPPC64MOVHZreg
		return true
	case OpZeroExt32to64:
		v.Op = OpPPC64MOVWZreg
		return true
	case OpZeroExt8to16:
		v.Op = OpPPC64MOVBZreg
		return true
	case OpZeroExt8to32:
		v.Op = OpPPC64MOVBZreg
		return true
	case OpZeroExt8to64:
		v.Op = OpPPC64MOVBZreg
		return true
	}
	return false
}
func rewriteValuePPC64_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVDaddr {sym} [0] base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpPPC64MOVDaddr)
		v.AuxInt = int32ToAuxInt(0)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValuePPC64_OpAtomicCompareAndSwap32(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicCompareAndSwap32 ptr old new_ mem)
	// result: (LoweredAtomicCas32 [1] ptr old new_ mem)
	for {
		ptr := v_0
		old := v_1
		new_ := v_2
		mem := v_3
		v.reset(OpPPC64LoweredAtomicCas32)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicCompareAndSwap64(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicCompareAndSwap64 ptr old new_ mem)
	// result: (LoweredAtomicCas64 [1] ptr old new_ mem)
	for {
		ptr := v_0
		old := v_1
		new_ := v_2
		mem := v_3
		v.reset(OpPPC64LoweredAtomicCas64)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicCompareAndSwapRel32(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicCompareAndSwapRel32 ptr old new_ mem)
	// result: (LoweredAtomicCas32 [0] ptr old new_ mem)
	for {
		ptr := v_0
		old := v_1
		new_ := v_2
		mem := v_3
		v.reset(OpPPC64LoweredAtomicCas32)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicLoad32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad32 ptr mem)
	// result: (LoweredAtomicLoad32 [1] ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64LoweredAtomicLoad32)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicLoad64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad64 ptr mem)
	// result: (LoweredAtomicLoad64 [1] ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64LoweredAtomicLoad64)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicLoad8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad8 ptr mem)
	// result: (LoweredAtomicLoad8 [1] ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64LoweredAtomicLoad8)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicLoadAcq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoadAcq32 ptr mem)
	// result: (LoweredAtomicLoad32 [0] ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64LoweredAtomicLoad32)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicLoadAcq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoadAcq64 ptr mem)
	// result: (LoweredAtomicLoad64 [0] ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64LoweredAtomicLoad64)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicLoadPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoadPtr ptr mem)
	// result: (LoweredAtomicLoadPtr [1] ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpPPC64LoweredAtomicLoadPtr)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicStore32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicStore32 ptr val mem)
	// result: (LoweredAtomicStore32 [1] ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpPPC64LoweredAtomicStore32)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicStore64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicStore64 ptr val mem)
	// result: (LoweredAtomicStore64 [1] ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpPPC64LoweredAtomicStore64)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicStore8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicStore8 ptr val mem)
	// result: (LoweredAtomicStore8 [1] ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpPPC64LoweredAtomicStore8)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicStoreRel32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicStoreRel32 ptr val mem)
	// result: (LoweredAtomicStore32 [0] ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpPPC64LoweredAtomicStore32)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValuePPC64_OpAtomicStoreRel64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicStoreRel64 ptr val mem)
	// result: (LoweredAtomicStore64 [0] ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpPPC64LoweredAtomicStore64)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValuePPC64_OpAvg64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg64u <t> x y)
	// result: (ADD (SRDconst <t> (SUB <t> x y) [1]) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ADD)
		v0 := b.NewValue0(v.Pos, OpPPC64SRDconst, t)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpPPC64SUB, t)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValuePPC64_OpBitLen32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen32 x)
	// result: (SUBFCconst [32] (CNTLZW <typ.Int> x))
	for {
		x := v_0
		v.reset(OpPPC64SUBFCconst)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpPPC64CNTLZW, typ.Int)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpBitLen64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen64 x)
	// result: (SUBFCconst [64] (CNTLZD <typ.Int> x))
	for {
		x := v_0
		v.reset(OpPPC64SUBFCconst)
		v.AuxInt = int64ToAuxInt(64)
		v0 := b.NewValue0(v.Pos, OpPPC64CNTLZD, typ.Int)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpBswap16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Bswap16 x)
	// cond: buildcfg.GOPPC64>=10
	// result: (BRH x)
	for {
		x := v_0
		if !(buildcfg.GOPPC64 >= 10) {
			break
		}
		v.reset(OpPPC64BRH)
		v.AddArg(x)
		return true
	}
	// match: (Bswap16 x:(MOVHZload [off] {sym} ptr mem))
	// result: @x.Block (MOVHBRload (MOVDaddr <ptr.Type> [off] {sym} ptr) mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpPPC64MOVHBRload, typ.UInt16)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpPPC64MOVDaddr, ptr.Type)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (Bswap16 x:(MOVHZloadidx ptr idx mem))
	// result: @x.Block (MOVHBRloadidx ptr idx mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVHZloadidx {
			break
		}
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHBRloadidx, typ.Int16)
		v.copyOf(v0)
		v0.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpBswap32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Bswap32 x)
	// cond: buildcfg.GOPPC64>=10
	// result: (BRW x)
	for {
		x := v_0
		if !(buildcfg.GOPPC64 >= 10) {
			break
		}
		v.reset(OpPPC64BRW)
		v.AddArg(x)
		return true
	}
	// match: (Bswap32 x:(MOVWZload [off] {sym} ptr mem))
	// result: @x.Block (MOVWBRload (MOVDaddr <ptr.Type> [off] {sym} ptr) mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVWZload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpPPC64MOVWBRload, typ.UInt32)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpPPC64MOVDaddr, ptr.Type)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (Bswap32 x:(MOVWZloadidx ptr idx mem))
	// result: @x.Block (MOVWBRloadidx ptr idx mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVWZloadidx {
			break
		}
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWBRloadidx, typ.Int32)
		v.copyOf(v0)
		v0.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpBswap64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Bswap64 x)
	// cond: buildcfg.GOPPC64>=10
	// result: (BRD x)
	for {
		x := v_0
		if !(buildcfg.GOPPC64 >= 10) {
			break
		}
		v.reset(OpPPC64BRD)
		v.AddArg(x)
		return true
	}
	// match: (Bswap64 x:(MOVDload [off] {sym} ptr mem))
	// result: @x.Block (MOVDBRload (MOVDaddr <ptr.Type> [off] {sym} ptr) mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVDload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpPPC64MOVDBRload, typ.UInt64)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpPPC64MOVDaddr, ptr.Type)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (Bswap64 x:(MOVDloadidx ptr idx mem))
	// result: @x.Block (MOVDBRloadidx ptr idx mem)
	for {
		x := v_0
		if x.Op != OpPPC64MOVDloadidx {
			break
		}
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDBRloadidx, typ.Int64)
		v.copyOf(v0)
		v0.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpCom16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com16 x)
	// result: (NOR x x)
	for {
		x := v_0
		v.reset(OpPPC64NOR)
		v.AddArg2(x, x)
		return true
	}
}
func rewriteValuePPC64_OpCom32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com32 x)
	// result: (NOR x x)
	for {
		x := v_0
		v.reset(OpPPC64NOR)
		v.AddArg2(x, x)
		return true
	}
}
func rewriteValuePPC64_OpCom64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com64 x)
	// result: (NOR x x)
	for {
		x := v_0
		v.reset(OpPPC64NOR)
		v.AddArg2(x, x)
		return true
	}
}
func rewriteValuePPC64_OpCom8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Com8 x)
	// result: (NOR x x)
	for {
		x := v_0
		v.reset(OpPPC64NOR)
		v.AddArg2(x, x)
		return true
	}
}
func rewriteValuePPC64_OpCondSelect(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CondSelect x y (SETBC [a] cmp))
	// result: (ISEL [a] x y cmp)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64SETBC {
			break
		}
		a := auxIntToInt32(v_2.AuxInt)
		cmp := v_2.Args[0]
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(a)
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (CondSelect x y (SETBCR [a] cmp))
	// result: (ISEL [a+4] x y cmp)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpPPC64SETBCR {
			break
		}
		a := auxIntToInt32(v_2.AuxInt)
		cmp := v_2.Args[0]
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(a + 4)
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (CondSelect x y bool)
	// cond: flagArg(bool) == nil
	// result: (ISEL [6] x y (CMPconst [0] (ANDconst [1] bool)))
	for {
		x := v_0
		y := v_1
		bool := v_2
		if !(flagArg(bool) == nil) {
			break
		}
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v1.AuxInt = int64ToAuxInt(1)
		v1.AddArg(bool)
		v0.AddArg(v1)
		v.AddArg3(x, y, v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValuePPC64_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValuePPC64_OpConst64(v *Value) bool {
	// match: (Const64 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt64(v.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValuePPC64_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValuePPC64_OpConstBool(v *Value) bool {
	// match: (ConstBool [t])
	// result: (MOVDconst [b2i(t)])
	for {
		t := auxIntToBool(v.AuxInt)
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(t))
		return true
	}
}
func rewriteValuePPC64_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVDconst [0])
	for {
		v.reset(OpPPC64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValuePPC64_OpCopysign(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Copysign x y)
	// result: (FCPSGN y x)
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64FCPSGN)
		v.AddArg2(y, x)
		return true
	}
}
func rewriteValuePPC64_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz16 x)
	// result: (POPCNTW (MOVHZreg (ANDN <typ.Int16> (ADDconst <typ.Int16> [-1] x) x)))
	for {
		x := v_0
		v.reset(OpPPC64POPCNTW)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpPPC64ANDN, typ.Int16)
		v2 := b.NewValue0(v.Pos, OpPPC64ADDconst, typ.Int16)
		v2.AuxInt = int64ToAuxInt(-1)
		v2.AddArg(x)
		v1.AddArg2(v2, x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz32 x)
	// cond: buildcfg.GOPPC64<=8
	// result: (POPCNTW (MOVWZreg (ANDN <typ.Int> (ADDconst <typ.Int> [-1] x) x)))
	for {
		x := v_0
		if !(buildcfg.GOPPC64 <= 8) {
			break
		}
		v.reset(OpPPC64POPCNTW)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWZreg, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpPPC64ANDN, typ.Int)
		v2 := b.NewValue0(v.Pos, OpPPC64ADDconst, typ.Int)
		v2.AuxInt = int64ToAuxInt(-1)
		v2.AddArg(x)
		v1.AddArg2(v2, x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Ctz32 x)
	// result: (CNTTZW (MOVWZreg x))
	for {
		x := v_0
		v.reset(OpPPC64CNTTZW)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWZreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCtz64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz64 x)
	// cond: buildcfg.GOPPC64<=8
	// result: (POPCNTD (ANDN <typ.Int64> (ADDconst <typ.Int64> [-1] x) x))
	for {
		x := v_0
		if !(buildcfg.GOPPC64 <= 8) {
			break
		}
		v.reset(OpPPC64POPCNTD)
		v0 := b.NewValue0(v.Pos, OpPPC64ANDN, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpPPC64ADDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(-1)
		v1.AddArg(x)
		v0.AddArg2(v1, x)
		v.AddArg(v0)
		return true
	}
	// match: (Ctz64 x)
	// result: (CNTTZD x)
	for {
		x := v_0
		v.reset(OpPPC64CNTTZD)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz8 x)
	// result: (POPCNTB (MOVBZreg (ANDN <typ.UInt8> (ADDconst <typ.UInt8> [-1] x) x)))
	for {
		x := v_0
		v.reset(OpPPC64POPCNTB)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZreg, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpPPC64ANDN, typ.UInt8)
		v2 := b.NewValue0(v.Pos, OpPPC64ADDconst, typ.UInt8)
		v2.AuxInt = int64ToAuxInt(-1)
		v2.AddArg(x)
		v1.AddArg2(v2, x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCvt32Fto32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt32Fto32 x)
	// result: (MFVSRD (FCTIWZ x))
	for {
		x := v_0
		v.reset(OpPPC64MFVSRD)
		v0 := b.NewValue0(v.Pos, OpPPC64FCTIWZ, typ.Float64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCvt32Fto64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt32Fto64 x)
	// result: (MFVSRD (FCTIDZ x))
	for {
		x := v_0
		v.reset(OpPPC64MFVSRD)
		v0 := b.NewValue0(v.Pos, OpPPC64FCTIDZ, typ.Float64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCvt32to32F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt32to32F x)
	// result: (FCFIDS (MTVSRD (SignExt32to64 x)))
	for {
		x := v_0
		v.reset(OpPPC64FCFIDS)
		v0 := b.NewValue0(v.Pos, OpPPC64MTVSRD, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCvt32to64F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt32to64F x)
	// result: (FCFID (MTVSRD (SignExt32to64 x)))
	for {
		x := v_0
		v.reset(OpPPC64FCFID)
		v0 := b.NewValue0(v.Pos, OpPPC64MTVSRD, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCvt64Fto32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt64Fto32 x)
	// result: (MFVSRD (FCTIWZ x))
	for {
		x := v_0
		v.reset(OpPPC64MFVSRD)
		v0 := b.NewValue0(v.Pos, OpPPC64FCTIWZ, typ.Float64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCvt64Fto64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt64Fto64 x)
	// result: (MFVSRD (FCTIDZ x))
	for {
		x := v_0
		v.reset(OpPPC64MFVSRD)
		v0 := b.NewValue0(v.Pos, OpPPC64FCTIDZ, typ.Float64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCvt64to32F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt64to32F x)
	// result: (FCFIDS (MTVSRD x))
	for {
		x := v_0
		v.reset(OpPPC64FCFIDS)
		v0 := b.NewValue0(v.Pos, OpPPC64MTVSRD, typ.Float64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpCvt64to64F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt64to64F x)
	// result: (FCFID (MTVSRD x))
	for {
		x := v_0
		v.reset(OpPPC64FCFID)
		v0 := b.NewValue0(v.Pos, OpPPC64MTVSRD, typ.Float64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 [false] x y)
	// result: (DIVW (SignExt16to32 x) (SignExt16to32 y))
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpPPC64DIVW)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValuePPC64_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (DIVWU (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64DIVWU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuePPC64_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div32 [false] x y)
	// result: (DIVW x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpPPC64DIVW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValuePPC64_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div64 [false] x y)
	// result: (DIVD x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpPPC64DIVD)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValuePPC64_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (DIVW (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64DIVW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuePPC64_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (DIVWU (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64DIVWU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuePPC64_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// cond: x.Type.IsSigned() && y.Type.IsSigned()
	// result: (Equal (CMPW (SignExt16to32 x) (SignExt16to32 y)))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			y := v_1
			if !(x.Type.IsSigned() && y.Type.IsSigned()) {
				continue
			}
			v.reset(OpPPC64Equal)
			v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
			v1.AddArg(x)
			v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
			v2.AddArg(y)
			v0.AddArg2(v1, v2)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Eq16 x y)
	// result: (Equal (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64Equal)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32 x y)
	// result: (Equal (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64Equal)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (Equal (FCMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64Equal)
		v0 := b.NewValue0(v.Pos, OpPPC64FCMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64 x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64Equal)
		v0 := b.NewValue0(v.Pos, OpPPC64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (Equal (FCMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64Equal)
		v0 := b.NewValue0(v.Pos, OpPPC64FCMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// cond: x.Type.IsSigned() && y.Type.IsSigned()
	// result: (Equal (CMPW (SignExt8to32 x) (SignExt8to32 y)))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			y := v_1
			if !(x.Type.IsSigned() && y.Type.IsSigned()) {
				continue
			}
			v.reset(OpPPC64Equal)
			v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
			v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
			v1.AddArg(x)
			v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
			v2.AddArg(y)
			v0.AddArg2(v1, v2)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Eq8 x y)
	// result: (Equal (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64Equal)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (ANDconst [1] (EQV x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64ANDconst)
		v.AuxInt = int64ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpPPC64EQV, typ.Int64)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (EqPtr x y)
	// result: (Equal (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64Equal)
		v0 := b.NewValue0(v.Pos, OpPPC64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsInBounds idx len)
	// result: (LessThan (CMPU idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpPPC64LessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPU, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsNonNil ptr)
	// result: (NotEqual (CMPconst [0] ptr))
	for {
		ptr := v_0
		v.reset(OpPPC64NotEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(0)
		v0.AddArg(ptr)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (IsSliceInBounds idx len)
	// result: (LessEqual (CMPU idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpPPC64LessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPU, types.TypeFlags)
		v0.AddArg2(idx, len)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (LessEqual (CMPW (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (LessEqual (CMPWU (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPWU, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32 x y)
	// result: (LessEqual (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (FLessEqual (FCMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64FLessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64FCMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32U x y)
	// result: (LessEqual (CMPWU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPWU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64 x y)
	// result: (LessEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (FLessEqual (FCMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64FLessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64FCMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64U x y)
	// result: (LessEqual (CMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (LessEqual (CMPW (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (LessEqual (CMPWU (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessEqual)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPWU, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (LessThan (CMPW (SignExt16to32 x) (SignExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (LessThan (CMPWU (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPWU, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32 x y)
	// result: (LessThan (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (FLessThan (FCMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64FLessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64FCMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32U x y)
	// result: (LessThan (CMPWU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPWU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64 x y)
	// result: (LessThan (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (FLessThan (FCMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64FLessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64FCMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64U x y)
	// result: (LessThan (CMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPU, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (LessThan (CMPW (SignExt8to32 x) (SignExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (LessThan (CMPWU (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpPPC64LessThan)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPWU, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
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
		v.reset(OpPPC64MOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitInt(t) && t.IsSigned()
	// result: (MOVWload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVWload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitInt(t) && !t.IsSigned()
	// result: (MOVWZload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVWZload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is16BitInt(t) && t.IsSigned()
	// result: (MOVHload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVHload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is16BitInt(t) && !t.IsSigned()
	// result: (MOVHZload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is16BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVHZload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.IsBoolean()
	// result: (MOVBZload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsBoolean()) {
			break
		}
		v.reset(OpPPC64MOVBZload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is8BitInt(t) && t.IsSigned()
	// result: (MOVBreg (MOVBZload ptr mem))
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVBreg)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVBZload, typ.UInt8)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is8BitInt(t) && !t.IsSigned()
	// result: (MOVBZload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVBZload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (FMOVSload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpPPC64FMOVSload)
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
		v.reset(OpPPC64FMOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVDaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpPPC64MOVDaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVDaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpPPC64MOVDaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValuePPC64_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x16 <t> x y)
	// result: (ISEL [2] (SLD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0xFFF0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0xFFF0)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x32 <t> x y)
	// result: (ISEL [0] (SLD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPWUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPWUconst, types.TypeFlags)
		v3.AuxInt = int32ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x64 x (MOVDconst [c]))
	// cond: uint64(c) < 16
	// result: (SLWconst x [c])
	for {
		x := v_0
		if v_1.Op != OpPPC64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 16) {
			break
		}
		v.reset(OpPPC64SLWconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (Lsh16x64 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x64 <t> x y)
	// result: (ISEL [0] (SLD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPUconst y [16]))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPUconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(16)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 x y)
	// cond: shiftIsBounded(v)
	// result: (SLD x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpPPC64SLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh16x8 <t> x y)
	// result: (ISEL [2] (SLD <t> (MOVHZreg x) y) (MOVDconst [0]) (CMPconst [0] (ANDconst [0x00F0] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SLD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVHZreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDconst, typ.Int64)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		
"""




```