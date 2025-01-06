Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共7部分，请归纳一下它的功能

"""
// Code generated from _gen/S390X.rules using 'go generate'; DO NOT EDIT.

package ssa

import "math"
import "cmd/compile/internal/types"
import "cmd/internal/obj/s390x"

func rewriteValueS390X(v *Value) bool {
	switch v.Op {
	case OpAdd16:
		v.Op = OpS390XADDW
		return true
	case OpAdd32:
		v.Op = OpS390XADDW
		return true
	case OpAdd32F:
		return rewriteValueS390X_OpAdd32F(v)
	case OpAdd64:
		v.Op = OpS390XADD
		return true
	case OpAdd64F:
		return rewriteValueS390X_OpAdd64F(v)
	case OpAdd8:
		v.Op = OpS390XADDW
		return true
	case OpAddPtr:
		v.Op = OpS390XADD
		return true
	case OpAddr:
		return rewriteValueS390X_OpAddr(v)
	case OpAnd16:
		v.Op = OpS390XANDW
		return true
	case OpAnd32:
		v.Op = OpS390XANDW
		return true
	case OpAnd64:
		v.Op = OpS390XAND
		return true
	case OpAnd8:
		v.Op = OpS390XANDW
		return true
	case OpAndB:
		v.Op = OpS390XANDW
		return true
	case OpAtomicAdd32:
		return rewriteValueS390X_OpAtomicAdd32(v)
	case OpAtomicAdd64:
		return rewriteValueS390X_OpAtomicAdd64(v)
	case OpAtomicAnd32:
		v.Op = OpS390XLAN
		return true
	case OpAtomicAnd8:
		return rewriteValueS390X_OpAtomicAnd8(v)
	case OpAtomicCompareAndSwap32:
		return rewriteValueS390X_OpAtomicCompareAndSwap32(v)
	case OpAtomicCompareAndSwap64:
		return rewriteValueS390X_OpAtomicCompareAndSwap64(v)
	case OpAtomicExchange32:
		return rewriteValueS390X_OpAtomicExchange32(v)
	case OpAtomicExchange64:
		return rewriteValueS390X_OpAtomicExchange64(v)
	case OpAtomicLoad32:
		return rewriteValueS390X_OpAtomicLoad32(v)
	case OpAtomicLoad64:
		return rewriteValueS390X_OpAtomicLoad64(v)
	case OpAtomicLoad8:
		return rewriteValueS390X_OpAtomicLoad8(v)
	case OpAtomicLoadAcq32:
		return rewriteValueS390X_OpAtomicLoadAcq32(v)
	case OpAtomicLoadPtr:
		return rewriteValueS390X_OpAtomicLoadPtr(v)
	case OpAtomicOr32:
		v.Op = OpS390XLAO
		return true
	case OpAtomicOr8:
		return rewriteValueS390X_OpAtomicOr8(v)
	case OpAtomicStore32:
		return rewriteValueS390X_OpAtomicStore32(v)
	case OpAtomicStore64:
		return rewriteValueS390X_OpAtomicStore64(v)
	case OpAtomicStore8:
		return rewriteValueS390X_OpAtomicStore8(v)
	case OpAtomicStorePtrNoWB:
		return rewriteValueS390X_OpAtomicStorePtrNoWB(v)
	case OpAtomicStoreRel32:
		return rewriteValueS390X_OpAtomicStoreRel32(v)
	case OpAvg64u:
		return rewriteValueS390X_OpAvg64u(v)
	case OpBitLen64:
		return rewriteValueS390X_OpBitLen64(v)
	case OpBswap16:
		return rewriteValueS390X_OpBswap16(v)
	case OpBswap32:
		v.Op = OpS390XMOVWBR
		return true
	case OpBswap64:
		v.Op = OpS390XMOVDBR
		return true
	case OpCeil:
		return rewriteValueS390X_OpCeil(v)
	case OpClosureCall:
		v.Op = OpS390XCALLclosure
		return true
	case OpCom16:
		v.Op = OpS390XNOTW
		return true
	case OpCom32:
		v.Op = OpS390XNOTW
		return true
	case OpCom64:
		v.Op = OpS390XNOT
		return true
	case OpCom8:
		v.Op = OpS390XNOTW
		return true
	case OpConst16:
		return rewriteValueS390X_OpConst16(v)
	case OpConst32:
		return rewriteValueS390X_OpConst32(v)
	case OpConst32F:
		v.Op = OpS390XFMOVSconst
		return true
	case OpConst64:
		return rewriteValueS390X_OpConst64(v)
	case OpConst64F:
		v.Op = OpS390XFMOVDconst
		return true
	case OpConst8:
		return rewriteValueS390X_OpConst8(v)
	case OpConstBool:
		return rewriteValueS390X_OpConstBool(v)
	case OpConstNil:
		return rewriteValueS390X_OpConstNil(v)
	case OpCtz32:
		return rewriteValueS390X_OpCtz32(v)
	case OpCtz32NonZero:
		v.Op = OpCtz32
		return true
	case OpCtz64:
		return rewriteValueS390X_OpCtz64(v)
	case OpCtz64NonZero:
		v.Op = OpCtz64
		return true
	case OpCvt32Fto32:
		v.Op = OpS390XCFEBRA
		return true
	case OpCvt32Fto32U:
		v.Op = OpS390XCLFEBR
		return true
	case OpCvt32Fto64:
		v.Op = OpS390XCGEBRA
		return true
	case OpCvt32Fto64F:
		v.Op = OpS390XLDEBR
		return true
	case OpCvt32Fto64U:
		v.Op = OpS390XCLGEBR
		return true
	case OpCvt32Uto32F:
		v.Op = OpS390XCELFBR
		return true
	case OpCvt32Uto64F:
		v.Op = OpS390XCDLFBR
		return true
	case OpCvt32to32F:
		v.Op = OpS390XCEFBRA
		return true
	case OpCvt32to64F:
		v.Op = OpS390XCDFBRA
		return true
	case OpCvt64Fto32:
		v.Op = OpS390XCFDBRA
		return true
	case OpCvt64Fto32F:
		v.Op = OpS390XLEDBR
		return true
	case OpCvt64Fto32U:
		v.Op = OpS390XCLFDBR
		return true
	case OpCvt64Fto64:
		v.Op = OpS390XCGDBRA
		return true
	case OpCvt64Fto64U:
		v.Op = OpS390XCLGDBR
		return true
	case OpCvt64Uto32F:
		v.Op = OpS390XCELGBR
		return true
	case OpCvt64Uto64F:
		v.Op = OpS390XCDLGBR
		return true
	case OpCvt64to32F:
		v.Op = OpS390XCEGBRA
		return true
	case OpCvt64to64F:
		v.Op = OpS390XCDGBRA
		return true
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv16:
		return rewriteValueS390X_OpDiv16(v)
	case OpDiv16u:
		return rewriteValueS390X_OpDiv16u(v)
	case OpDiv32:
		return rewriteValueS390X_OpDiv32(v)
	case OpDiv32F:
		v.Op = OpS390XFDIVS
		return true
	case OpDiv32u:
		return rewriteValueS390X_OpDiv32u(v)
	case OpDiv64:
		return rewriteValueS390X_OpDiv64(v)
	case OpDiv64F:
		v.Op = OpS390XFDIV
		return true
	case OpDiv64u:
		v.Op = OpS390XDIVDU
		return true
	case OpDiv8:
		return rewriteValueS390X_OpDiv8(v)
	case OpDiv8u:
		return rewriteValueS390X_OpDiv8u(v)
	case OpEq16:
		return rewriteValueS390X_OpEq16(v)
	case OpEq32:
		return rewriteValueS390X_OpEq32(v)
	case OpEq32F:
		return rewriteValueS390X_OpEq32F(v)
	case OpEq64:
		return rewriteValueS390X_OpEq64(v)
	case OpEq64F:
		return rewriteValueS390X_OpEq64F(v)
	case OpEq8:
		return rewriteValueS390X_OpEq8(v)
	case OpEqB:
		return rewriteValueS390X_OpEqB(v)
	case OpEqPtr:
		return rewriteValueS390X_OpEqPtr(v)
	case OpFMA:
		return rewriteValueS390X_OpFMA(v)
	case OpFloor:
		return rewriteValueS390X_OpFloor(v)
	case OpGetCallerPC:
		v.Op = OpS390XLoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = OpS390XLoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = OpS390XLoweredGetClosurePtr
		return true
	case OpGetG:
		v.Op = OpS390XLoweredGetG
		return true
	case OpHmul32:
		return rewriteValueS390X_OpHmul32(v)
	case OpHmul32u:
		return rewriteValueS390X_OpHmul32u(v)
	case OpHmul64:
		v.Op = OpS390XMULHD
		return true
	case OpHmul64u:
		v.Op = OpS390XMULHDU
		return true
	case OpITab:
		return rewriteValueS390X_OpITab(v)
	case OpInterCall:
		v.Op = OpS390XCALLinter
		return true
	case OpIsInBounds:
		return rewriteValueS390X_OpIsInBounds(v)
	case OpIsNonNil:
		return rewriteValueS390X_OpIsNonNil(v)
	case OpIsSliceInBounds:
		return rewriteValueS390X_OpIsSliceInBounds(v)
	case OpLeq16:
		return rewriteValueS390X_OpLeq16(v)
	case OpLeq16U:
		return rewriteValueS390X_OpLeq16U(v)
	case OpLeq32:
		return rewriteValueS390X_OpLeq32(v)
	case OpLeq32F:
		return rewriteValueS390X_OpLeq32F(v)
	case OpLeq32U:
		return rewriteValueS390X_OpLeq32U(v)
	case OpLeq64:
		return rewriteValueS390X_OpLeq64(v)
	case OpLeq64F:
		return rewriteValueS390X_OpLeq64F(v)
	case OpLeq64U:
		return rewriteValueS390X_OpLeq64U(v)
	case OpLeq8:
		return rewriteValueS390X_OpLeq8(v)
	case OpLeq8U:
		return rewriteValueS390X_OpLeq8U(v)
	case OpLess16:
		return rewriteValueS390X_OpLess16(v)
	case OpLess16U:
		return rewriteValueS390X_OpLess16U(v)
	case OpLess32:
		return rewriteValueS390X_OpLess32(v)
	case OpLess32F:
		return rewriteValueS390X_OpLess32F(v)
	case OpLess32U:
		return rewriteValueS390X_OpLess32U(v)
	case OpLess64:
		return rewriteValueS390X_OpLess64(v)
	case OpLess64F:
		return rewriteValueS390X_OpLess64F(v)
	case OpLess64U:
		return rewriteValueS390X_OpLess64U(v)
	case OpLess8:
		return rewriteValueS390X_OpLess8(v)
	case OpLess8U:
		return rewriteValueS390X_OpLess8U(v)
	case OpLoad:
		return rewriteValueS390X_OpLoad(v)
	case OpLocalAddr:
		return rewriteValueS390X_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValueS390X_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValueS390X_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValueS390X_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValueS390X_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValueS390X_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValueS390X_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValueS390X_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValueS390X_OpLsh32x8(v)
	case OpLsh64x16:
		return rewriteValueS390X_OpLsh64x16(v)
	case OpLsh64x32:
		return rewriteValueS390X_OpLsh64x32(v)
	case OpLsh64x64:
		return rewriteValueS390X_OpLsh64x64(v)
	case OpLsh64x8:
		return rewriteValueS390X_OpLsh64x8(v)
	case OpLsh8x16:
		return rewriteValueS390X_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValueS390X_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValueS390X_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValueS390X_OpLsh8x8(v)
	case OpMod16:
		return rewriteValueS390X_OpMod16(v)
	case OpMod16u:
		return rewriteValueS390X_OpMod16u(v)
	case OpMod32:
		return rewriteValueS390X_OpMod32(v)
	case OpMod32u:
		return rewriteValueS390X_OpMod32u(v)
	case OpMod64:
		return rewriteValueS390X_OpMod64(v)
	case OpMod64u:
		v.Op = OpS390XMODDU
		return true
	case OpMod8:
		return rewriteValueS390X_OpMod8(v)
	case OpMod8u:
		return rewriteValueS390X_OpMod8u(v)
	case OpMove:
		return rewriteValueS390X_OpMove(v)
	case OpMul16:
		v.Op = OpS390XMULLW
		return true
	case OpMul32:
		v.Op = OpS390XMULLW
		return true
	case OpMul32F:
		v.Op = OpS390XFMULS
		return true
	case OpMul64:
		v.Op = OpS390XMULLD
		return true
	case OpMul64F:
		v.Op = OpS390XFMUL
		return true
	case OpMul64uhilo:
		v.Op = OpS390XMLGR
		return true
	case OpMul8:
		v.Op = OpS390XMULLW
		return true
	case OpNeg16:
		v.Op = OpS390XNEGW
		return true
	case OpNeg32:
		v.Op = OpS390XNEGW
		return true
	case OpNeg32F:
		v.Op = OpS390XFNEGS
		return true
	case OpNeg64:
		v.Op = OpS390XNEG
		return true
	case OpNeg64F:
		v.Op = OpS390XFNEG
		return true
	case OpNeg8:
		v.Op = OpS390XNEGW
		return true
	case OpNeq16:
		return rewriteValueS390X_OpNeq16(v)
	case OpNeq32:
		return rewriteValueS390X_OpNeq32(v)
	case OpNeq32F:
		return rewriteValueS390X_OpNeq32F(v)
	case OpNeq64:
		return rewriteValueS390X_OpNeq64(v)
	case OpNeq64F:
		return rewriteValueS390X_OpNeq64F(v)
	case OpNeq8:
		return rewriteValueS390X_OpNeq8(v)
	case OpNeqB:
		return rewriteValueS390X_OpNeqB(v)
	case OpNeqPtr:
		return rewriteValueS390X_OpNeqPtr(v)
	case OpNilCheck:
		v.Op = OpS390XLoweredNilCheck
		return true
	case OpNot:
		return rewriteValueS390X_OpNot(v)
	case OpOffPtr:
		return rewriteValueS390X_OpOffPtr(v)
	case OpOr16:
		v.Op = OpS390XORW
		return true
	case OpOr32:
		v.Op = OpS390XORW
		return true
	case OpOr64:
		v.Op = OpS390XOR
		return true
	case OpOr8:
		v.Op = OpS390XORW
		return true
	case OpOrB:
		v.Op = OpS390XORW
		return true
	case OpPanicBounds:
		return rewriteValueS390X_OpPanicBounds(v)
	case OpPopCount16:
		return rewriteValueS390X_OpPopCount16(v)
	case OpPopCount32:
		return rewriteValueS390X_OpPopCount32(v)
	case OpPopCount64:
		return rewriteValueS390X_OpPopCount64(v)
	case OpPopCount8:
		return rewriteValueS390X_OpPopCount8(v)
	case OpRotateLeft16:
		return rewriteValueS390X_OpRotateLeft16(v)
	case OpRotateLeft32:
		v.Op = OpS390XRLL
		return true
	case OpRotateLeft64:
		v.Op = OpS390XRLLG
		return true
	case OpRotateLeft8:
		return rewriteValueS390X_OpRotateLeft8(v)
	case OpRound:
		return rewriteValueS390X_OpRound(v)
	case OpRound32F:
		v.Op = OpS390XLoweredRound32F
		return true
	case OpRound64F:
		v.Op = OpS390XLoweredRound64F
		return true
	case OpRoundToEven:
		return rewriteValueS390X_OpRoundToEven(v)
	case OpRsh16Ux16:
		return rewriteValueS390X_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValueS390X_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValueS390X_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValueS390X_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValueS390X_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValueS390X_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValueS390X_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValueS390X_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValueS390X_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValueS390X_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValueS390X_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValueS390X_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValueS390X_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValueS390X_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValueS390X_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValueS390X_OpRsh32x8(v)
	case OpRsh64Ux16:
		return rewriteValueS390X_OpRsh64Ux16(v)
	case OpRsh64Ux32:
		return rewriteValueS390X_OpRsh64Ux32(v)
	case OpRsh64Ux64:
		return rewriteValueS390X_OpRsh64Ux64(v)
	case OpRsh64Ux8:
		return rewriteValueS390X_OpRsh64Ux8(v)
	case OpRsh64x16:
		return rewriteValueS390X_OpRsh64x16(v)
	case OpRsh64x32:
		return rewriteValueS390X_OpRsh64x32(v)
	case OpRsh64x64:
		return rewriteValueS390X_OpRsh64x64(v)
	case OpRsh64x8:
		return rewriteValueS390X_OpRsh64x8(v)
	case OpRsh8Ux16:
		return rewriteValueS390X_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValueS390X_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValueS390X_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValueS390X_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValueS390X_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValueS390X_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValueS390X_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValueS390X_OpRsh8x8(v)
	case OpS390XADD:
		return rewriteValueS390X_OpS390XADD(v)
	case OpS390XADDC:
		return rewriteValueS390X_OpS390XADDC(v)
	case OpS390XADDE:
		return rewriteValueS390X_OpS390XADDE(v)
	case OpS390XADDW:
		return rewriteValueS390X_OpS390XADDW(v)
	case OpS390XADDWconst:
		return rewriteValueS390X_OpS390XADDWconst(v)
	case OpS390XADDWload:
		return rewriteValueS390X_OpS390XADDWload(v)
	case OpS390XADDconst:
		return rewriteValueS390X_OpS390XADDconst(v)
	case OpS390XADDload:
		return rewriteValueS390X_OpS390XADDload(v)
	case OpS390XAND:
		return rewriteValueS390X_OpS390XAND(v)
	case OpS390XANDW:
		return rewriteValueS390X_OpS390XANDW(v)
	case OpS390XANDWconst:
		return rewriteValueS390X_OpS390XANDWconst(v)
	case OpS390XANDWload:
		return rewriteValueS390X_OpS390XANDWload(v)
	case OpS390XANDconst:
		return rewriteValueS390X_OpS390XANDconst(v)
	case OpS390XANDload:
		return rewriteValueS390X_OpS390XANDload(v)
	case OpS390XCMP:
		return rewriteValueS390X_OpS390XCMP(v)
	case OpS390XCMPU:
		return rewriteValueS390X_OpS390XCMPU(v)
	case OpS390XCMPUconst:
		return rewriteValueS390X_OpS390XCMPUconst(v)
	case OpS390XCMPW:
		return rewriteValueS390X_OpS390XCMPW(v)
	case OpS390XCMPWU:
		return rewriteValueS390X_OpS390XCMPWU(v)
	case OpS390XCMPWUconst:
		return rewriteValueS390X_OpS390XCMPWUconst(v)
	case OpS390XCMPWconst:
		return rewriteValueS390X_OpS390XCMPWconst(v)
	case OpS390XCMPconst:
		return rewriteValueS390X_OpS390XCMPconst(v)
	case OpS390XCPSDR:
		return rewriteValueS390X_OpS390XCPSDR(v)
	case OpS390XFCMP:
		return rewriteValueS390X_OpS390XFCMP(v)
	case OpS390XFCMPS:
		return rewriteValueS390X_OpS390XFCMPS(v)
	case OpS390XFMOVDload:
		return rewriteValueS390X_OpS390XFMOVDload(v)
	case OpS390XFMOVDstore:
		return rewriteValueS390X_OpS390XFMOVDstore(v)
	case OpS390XFMOVSload:
		return rewriteValueS390X_OpS390XFMOVSload(v)
	case OpS390XFMOVSstore:
		return rewriteValueS390X_OpS390XFMOVSstore(v)
	case OpS390XFNEG:
		return rewriteValueS390X_OpS390XFNEG(v)
	case OpS390XFNEGS:
		return rewriteValueS390X_OpS390XFNEGS(v)
	case OpS390XLDGR:
		return rewriteValueS390X_OpS390XLDGR(v)
	case OpS390XLEDBR:
		return rewriteValueS390X_OpS390XLEDBR(v)
	case OpS390XLGDR:
		return rewriteValueS390X_OpS390XLGDR(v)
	case OpS390XLOCGR:
		return rewriteValueS390X_OpS390XLOCGR(v)
	case OpS390XLTDBR:
		return rewriteValueS390X_OpS390XLTDBR(v)
	case OpS390XLTEBR:
		return rewriteValueS390X_OpS390XLTEBR(v)
	case OpS390XLoweredRound32F:
		return rewriteValueS390X_OpS390XLoweredRound32F(v)
	case OpS390XLoweredRound64F:
		return rewriteValueS390X_OpS390XLoweredRound64F(v)
	case OpS390XMOVBZload:
		return rewriteValueS390X_OpS390XMOVBZload(v)
	case OpS390XMOVBZreg:
		return rewriteValueS390X_OpS390XMOVBZreg(v)
	case OpS390XMOVBload:
		return rewriteValueS390X_OpS390XMOVBload(v)
	case OpS390XMOVBreg:
		return rewriteValueS390X_OpS390XMOVBreg(v)
	case OpS390XMOVBstore:
		return rewriteValueS390X_OpS390XMOVBstore(v)
	case OpS390XMOVBstoreconst:
		return rewriteValueS390X_OpS390XMOVBstoreconst(v)
	case OpS390XMOVDBR:
		return rewriteValueS390X_OpS390XMOVDBR(v)
	case OpS390XMOVDaddridx:
		return rewriteValueS390X_OpS390XMOVDaddridx(v)
	case OpS390XMOVDload:
		return rewriteValueS390X_OpS390XMOVDload(v)
	case OpS390XMOVDstore:
		return rewriteValueS390X_OpS390XMOVDstore(v)
	case OpS390XMOVDstoreconst:
		return rewriteValueS390X_OpS390XMOVDstoreconst(v)
	case OpS390XMOVDstoreidx:
		return rewriteValueS390X_OpS390XMOVDstoreidx(v)
	case OpS390XMOVHZload:
		return rewriteValueS390X_OpS390XMOVHZload(v)
	case OpS390XMOVHZreg:
		return rewriteValueS390X_OpS390XMOVHZreg(v)
	case OpS390XMOVHload:
		return rewriteValueS390X_OpS390XMOVHload(v)
	case OpS390XMOVHreg:
		return rewriteValueS390X_OpS390XMOVHreg(v)
	case OpS390XMOVHstore:
		return rewriteValueS390X_OpS390XMOVHstore(v)
	case OpS390XMOVHstoreconst:
		return rewriteValueS390X_OpS390XMOVHstoreconst(v)
	case OpS390XMOVHstoreidx:
		return rewriteValueS390X_OpS390XMOVHstoreidx(v)
	case OpS390XMOVWBR:
		return rewriteValueS390X_OpS390XMOVWBR(v)
	case OpS390XMOVWZload:
		return rewriteValueS390X_OpS390XMOVWZload(v)
	case OpS390XMOVWZreg:
		return rewriteValueS390X_OpS390XMOVWZreg(v)
	case OpS390XMOVWload:
		return rewriteValueS390X_OpS390XMOVWload(v)
	case OpS390XMOVWreg:
		return rewriteValueS390X_OpS390XMOVWreg(v)
	case OpS390XMOVWstore:
		return rewriteValueS390X_OpS390XMOVWstore(v)
	case OpS390XMOVWstoreconst:
		return rewriteValueS390X_OpS390XMOVWstoreconst(v)
	case OpS390XMOVWstoreidx:
		return rewriteValueS390X_OpS390XMOVWstoreidx(v)
	case OpS390XMULLD:
		return rewriteValueS390X_OpS390XMULLD(v)
	case OpS390XMULLDconst:
		return rewriteValueS390X_OpS390XMULLDconst(v)
	case OpS390XMULLDload:
		return rewriteValueS390X_OpS390XMULLDload(v)
	case OpS390XMULLW:
		return rewriteValueS390X_OpS390XMULLW(v)
	case OpS390XMULLWconst:
		return rewriteValueS390X_OpS390XMULLWconst(v)
	case OpS390XMULLWload:
		return rewriteValueS390X_OpS390XMULLWload(v)
	case OpS390XNEG:
		return rewriteValueS390X_OpS390XNEG(v)
	case OpS390XNEGW:
		return rewriteValueS390X_OpS390XNEGW(v)
	case OpS390XNOT:
		return rewriteValueS390X_OpS390XNOT(v)
	case OpS390XNOTW:
		return rewriteValueS390X_OpS390XNOTW(v)
	case OpS390XOR:
		return rewriteValueS390X_OpS390XOR(v)
	case OpS390XORW:
		return rewriteValueS390X_OpS390XORW(v)
	case OpS390XORWconst:
		return rewriteValueS390X_OpS390XORWconst(v)
	case OpS390XORWload:
		return rewriteValueS390X_OpS390XORWload(v)
	case OpS390XORconst:
		return rewriteValueS390X_OpS390XORconst(v)
	case OpS390XORload:
		return rewriteValueS390X_OpS390XORload(v)
	case OpS390XRISBGZ:
		return rewriteValueS390X_OpS390XRISBGZ(v)
	case OpS390XRLL:
		return rewriteValueS390X_OpS390XRLL(v)
	case OpS390XRLLG:
		return rewriteValueS390X_OpS390XRLLG(v)
	case OpS390XSLD:
		return rewriteValueS390X_OpS390XSLD(v)
	case OpS390XSLDconst:
		return rewriteValueS390X_OpS390XSLDconst(v)
	case OpS390XSLW:
		return rewriteValueS390X_OpS390XSLW(v)
	case OpS390XSLWconst:
		return rewriteValueS390X_OpS390XSLWconst(v)
	case OpS390XSRAD:
		return rewriteValueS390X_OpS390XSRAD(v)
	case OpS390XSRADconst:
		return rewriteValueS390X_OpS390XSRADconst(v)
	case OpS390XSRAW:
		return rewriteValueS390X_OpS390XSRAW(v)
	case OpS390XSRAWconst:
		return rewriteValueS390X_OpS390XSRAWconst(v)
	case OpS390XSRD:
		return rewriteValueS390X_OpS390XSRD(v)
	case OpS390XSRDconst:
		return rewriteValueS390X_OpS390XSRDconst(v)
	case OpS390XSRW:
		return rewriteValueS390X_OpS390XSRW(v)
	case OpS390XSRWconst:
		return rewriteValueS390X_OpS390XSRWconst(v)
	case OpS390XSTM2:
		return rewriteValueS390X_OpS390XSTM2(v)
	case OpS390XSTMG2:
		return rewriteValueS390X_OpS390XSTMG2(v)
	case OpS390XSUB:
		return rewriteValueS390X_OpS390XSUB(v)
	case OpS390XSUBE:
		return rewriteValueS390X_OpS390XSUBE(v)
	case OpS390XSUBW:
		return rewriteValueS390X_OpS390XSUBW(v)
	case OpS390XSUBWconst:
		return rewriteValueS390X_OpS390XSUBWconst(v)
	case OpS390XSUBWload:
		return rewriteValueS390X_OpS390XSUBWload(v)
	case OpS390XSUBconst:
		return rewriteValueS390X_OpS390XSUBconst(v)
	case OpS390XSUBload:
		return rewriteValueS390X_OpS390XSUBload(v)
	case OpS390XSumBytes2:
		return rewriteValueS390X_OpS390XSumBytes2(v)
	case OpS390XSumBytes4:
		return rewriteValueS390X_OpS390XSumBytes4(v)
	case OpS390XSumBytes8:
		return rewriteValueS390X_OpS390XSumBytes8(v)
	case OpS390XXOR:
		return rewriteValueS390X_OpS390XXOR(v)
	case OpS390XXORW:
		return rewriteValueS390X_OpS390XXORW(v)
	case OpS390XXORWconst:
		return rewriteValueS390X_OpS390XXORWconst(v)
	case OpS390XXORWload:
		return rewriteValueS390X_OpS390XXORWload(v)
	case OpS390XXORconst:
		return rewriteValueS390X_OpS390XXORconst(v)
	case OpS390XXORload:
		return rewriteValueS390X_OpS390XXORload(v)
	case OpSelect0:
		return rewriteValueS390X_OpSelect0(v)
	case OpSelect1:
		return rewriteValueS390X_OpSelect1(v)
	case OpSignExt16to32:
		v.Op = OpS390XMOVHreg
		return true
	case OpSignExt16to64:
		v.Op = OpS390XMOVHreg
		return true
	case OpSignExt32to64:
		v.Op = OpS390XMOVWreg
		return true
	case OpSignExt8to16:
		v.Op = OpS390XMOVBreg
		return true
	case OpSignExt8to32:
		v.Op = OpS390XMOVBreg
		return true
	case OpSignExt8to64:
		v.Op = OpS390XMOVBreg
		return true
	case OpSlicemask:
		return rewriteValueS390X_OpSlicemask(v)
	case OpSqrt:
		v.Op = OpS390XFSQRT
		return true
	case OpSqrt32:
		v.Op = OpS390XFSQRTS
		return true
	case OpStaticCall:
		v.Op = OpS390XCALLstatic
		return true
	case OpStore:
		return rewriteValueS390X_OpStore(v)
	case OpSub16:
		v.Op = OpS390XSUBW
		return true
	case OpSub32:
		v.Op = OpS390XSUBW
		return true
	case OpSub32F:
		return rewriteValueS390X_OpSub32F(v)
	case OpSub64:
		v.Op = OpS390XSUB
		return true
	case OpSub64F:
		return rewriteValueS390X_OpSub64F(v)
	case OpSub8:
		v.Op = OpS390XSUBW
		return true
	case OpSubPtr:
		v.Op = OpS390XSUB
		return true
	case OpTailCall:
		v.Op = OpS390XCALLtail
		return true
	case OpTrunc:
		return rewriteValueS390X_OpTrunc(v)
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
		v.Op = OpS390XLoweredWB
		return true
	case OpXor16:
		v.Op = OpS390XXORW
		return true
	case OpXor32:
		v.Op = OpS390XXORW
		return true
	case OpXor64:
		v.Op = OpS390XXOR
		return true
	case OpXor8:
		v.Op = OpS390XXORW
		return true
	case OpZero:
		return rewriteValueS390X_OpZero(v)
	case OpZeroExt16to32:
		v.Op = OpS390XMOVHZreg
		return true
	case OpZeroExt16to64:
		v.Op = OpS390XMOVHZreg
		return true
	case OpZeroExt32to64:
		v.Op = OpS390XMOVWZreg
		return true
	case OpZeroExt8to16:
		v.Op = OpS390XMOVBZreg
		return true
	case OpZeroExt8to32:
		v.Op = OpS390XMOVBZreg
		return true
	case OpZeroExt8to64:
		v.Op = OpS390XMOVBZreg
		return true
	}
	return false
}
func rewriteValueS390X_OpAdd32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Add32F x y)
	// result: (Select0 (FADDS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpS390XFADDS, types.NewTuple(typ.Float32, types.TypeFlags))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpAdd64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Add64F x y)
	// result: (Select0 (FADD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpS390XFADD, types.NewTuple(typ.Float64, types.TypeFlags))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVDaddr {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpS390XMOVDaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueS390X_OpAtomicAdd32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicAdd32 ptr val mem)
	// result: (AddTupleFirst32 val (LAA ptr val mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XAddTupleFirst32)
		v0 := b.NewValue0(v.Pos, OpS390XLAA, types.NewTuple(typ.UInt32, types.TypeMem))
		v0.AddArg3(ptr, val, mem)
		v.AddArg2(val, v0)
		return true
	}
}
func rewriteValueS390X_OpAtomicAdd64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicAdd64 ptr val mem)
	// result: (AddTupleFirst64 val (LAAG ptr val mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XAddTupleFirst64)
		v0 := b.NewValue0(v.Pos, OpS390XLAAG, types.NewTuple(typ.UInt64, types.TypeMem))
		v0.AddArg3(ptr, val, mem)
		v.AddArg2(val, v0)
		return true
	}
}
func rewriteValueS390X_OpAtomicAnd8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicAnd8 ptr val mem)
	// result: (LANfloor ptr (RLL <typ.UInt32> (ORWconst <typ.UInt32> val [-1<<8]) (RXSBG <typ.UInt32> {s390x.NewRotateParams(59, 60, 3)} (MOVDconst [3<<3]) ptr)) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XLANfloor)
		v0 := b.NewValue0(v.Pos, OpS390XRLL, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpS390XORWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(-1 << 8)
		v1.AddArg(val)
		v2 := b.NewValue0(v.Pos, OpS390XRXSBG, typ.UInt32)
		v2.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(59, 60, 3))
		v3 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(3 << 3)
		v2.AddArg2(v3, ptr)
		v0.AddArg2(v1, v2)
		v.AddArg3(ptr, v0, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicCompareAndSwap32(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicCompareAndSwap32 ptr old new_ mem)
	// result: (LoweredAtomicCas32 ptr old new_ mem)
	for {
		ptr := v_0
		old := v_1
		new_ := v_2
		mem := v_3
		v.reset(OpS390XLoweredAtomicCas32)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicCompareAndSwap64(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicCompareAndSwap64 ptr old new_ mem)
	// result: (LoweredAtomicCas64 ptr old new_ mem)
	for {
		ptr := v_0
		old := v_1
		new_ := v_2
		mem := v_3
		v.reset(OpS390XLoweredAtomicCas64)
		v.AddArg4(ptr, old, new_, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicExchange32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicExchange32 ptr val mem)
	// result: (LoweredAtomicExchange32 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XLoweredAtomicExchange32)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicExchange64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicExchange64 ptr val mem)
	// result: (LoweredAtomicExchange64 ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XLoweredAtomicExchange64)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicLoad32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad32 ptr mem)
	// result: (MOVWZatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpS390XMOVWZatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicLoad64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad64 ptr mem)
	// result: (MOVDatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpS390XMOVDatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicLoad8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoad8 ptr mem)
	// result: (MOVBZatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpS390XMOVBZatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicLoadAcq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoadAcq32 ptr mem)
	// result: (MOVWZatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpS390XMOVWZatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicLoadPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicLoadPtr ptr mem)
	// result: (MOVDatomicload ptr mem)
	for {
		ptr := v_0
		mem := v_1
		v.reset(OpS390XMOVDatomicload)
		v.AddArg2(ptr, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicOr8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (AtomicOr8 ptr val mem)
	// result: (LAOfloor ptr (SLW <typ.UInt32> (MOVBZreg <typ.UInt32> val) (RXSBG <typ.UInt32> {s390x.NewRotateParams(59, 60, 3)} (MOVDconst [3<<3]) ptr)) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XLAOfloor)
		v0 := b.NewValue0(v.Pos, OpS390XSLW, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt32)
		v1.AddArg(val)
		v2 := b.NewValue0(v.Pos, OpS390XRXSBG, typ.UInt32)
		v2.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(59, 60, 3))
		v3 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(3 << 3)
		v2.AddArg2(v3, ptr)
		v0.AddArg2(v1, v2)
		v.AddArg3(ptr, v0, mem)
		return true
	}
}
func rewriteValueS390X_OpAtomicStore32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (AtomicStore32 ptr val mem)
	// result: (SYNC (MOVWatomicstore ptr val mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XSYNC)
		v0 := b.NewValue0(v.Pos, OpS390XMOVWatomicstore, types.TypeMem)
		v0.AddArg3(ptr, val, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpAtomicStore64(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (AtomicStore64 ptr val mem)
	// result: (SYNC (MOVDatomicstore ptr val mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XSYNC)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDatomicstore, types.TypeMem)
		v0.AddArg3(ptr, val, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpAtomicStore8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (AtomicStore8 ptr val mem)
	// result: (SYNC (MOVBatomicstore ptr val mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XSYNC)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBatomicstore, types.TypeMem)
		v0.AddArg3(ptr, val, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpAtomicStorePtrNoWB(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (AtomicStorePtrNoWB ptr val mem)
	// result: (SYNC (MOVDatomicstore ptr val mem))
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XSYNC)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDatomicstore, types.TypeMem)
		v0.AddArg3(ptr, val, mem)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpAtomicStoreRel32(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AtomicStoreRel32 ptr val mem)
	// result: (MOVWatomicstore ptr val mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		v.reset(OpS390XMOVWatomicstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
}
func rewriteValueS390X_OpAvg64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg64u <t> x y)
	// result: (ADD (SRDconst <t> (SUB <t> x y) [1]) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpS390XADD)
		v0 := b.NewValue0(v.Pos, OpS390XSRDconst, t)
		v0.AuxInt = uint8ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpS390XSUB, t)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueS390X_OpBitLen64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen64 x)
	// result: (SUB (MOVDconst [64]) (FLOGR x))
	for {
		x := v_0
		v.reset(OpS390XSUB)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(64)
		v1 := b.NewValue0(v.Pos, OpS390XFLOGR, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpBswap16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Bswap16 x:(MOVHZload [off] {sym} ptr mem))
	// result: @x.Block (MOVHZreg (MOVHBRload [off] {sym} ptr mem))
	for {
		x := v_0
		if x.Op != OpS390XMOVHZload {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[1]
		ptr := x.Args[0]
		b = x.Block
		v0 := b.NewValue0(x.Pos, OpS390XMOVHZreg, typ.UInt64)
		v.copyOf(v0)
		v1 := b.NewValue0(x.Pos, OpS390XMOVHBRload, typ.UInt16)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg2(ptr, mem)
		v0.AddArg(v1)
		return true
	}
	// match: (Bswap16 x:(MOVHZloadidx [off] {sym} ptr idx mem))
	// result: @x.Block (MOVHZreg (MOVHBRloadidx [off] {sym} ptr idx mem))
	for {
		x := v_0
		if x.Op != OpS390XMOVHZloadidx {
			break
		}
		off := auxIntToInt32(x.AuxInt)
		sym := auxToSym(x.Aux)
		mem := x.Args[2]
		ptr := x.Args[0]
		idx := x.Args[1]
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHBRloadidx, typ.Int16)
		v1.AuxInt = int32ToAuxInt(off)
		v1.Aux = symToAux(sym)
		v1.AddArg3(ptr, idx, mem)
		v0.AddArg(v1)
		return true
	}
	return false
}
func rewriteValueS390X_OpCeil(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Ceil x)
	// result: (FIDBR [6] x)
	for {
		x := v_0
		v.reset(OpS390XFIDBR)
		v.AuxInt = int8ToAuxInt(6)
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueS390X_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueS390X_OpConst64(v *Value) bool {
	// match: (Const64 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt64(v.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueS390X_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVDconst [int64(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueS390X_OpConstBool(v *Value) bool {
	// match: (ConstBool [t])
	// result: (MOVDconst [b2i(t)])
	for {
		t := auxIntToBool(v.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(t))
		return true
	}
}
func rewriteValueS390X_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVDconst [0])
	for {
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValueS390X_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz32 <t> x)
	// result: (SUB (MOVDconst [64]) (FLOGR (MOVWZreg (ANDW <t> (SUBWconst <t> [1] x) (NOTW <t> x)))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpS390XSUB)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(64)
		v1 := b.NewValue0(v.Pos, OpS390XFLOGR, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpS390XMOVWZreg, typ.UInt64)
		v3 := b.NewValue0(v.Pos, OpS390XANDW, t)
		v4 := b.NewValue0(v.Pos, OpS390XSUBWconst, t)
		v4.AuxInt = int32ToAuxInt(1)
		v4.AddArg(x)
		v5 := b.NewValue0(v.Pos, OpS390XNOTW, t)
		v5.AddArg(x)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpCtz64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz64 <t> x)
	// result: (SUB (MOVDconst [64]) (FLOGR (AND <t> (SUBconst <t> [1] x) (NOT <t> x))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpS390XSUB)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(64)
		v1 := b.NewValue0(v.Pos, OpS390XFLOGR, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpS390XAND, t)
		v3 := b.NewValue0(v.Pos, OpS390XSUBconst, t)
		v3.AuxInt = int32ToAuxInt(1)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XNOT, t)
		v4.AddArg(x)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 x y)
	// result: (DIVW (MOVHreg x) (MOVHreg y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XDIVW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (DIVWU (MOVHZreg x) (MOVHZreg y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XDIVWU)
		v0 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32 x y)
	// result: (DIVW (MOVWreg x) y)
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XDIVW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVWreg, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueS390X_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32u x y)
	// result: (DIVWU (MOVWZreg x) y)
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XDIVWU)
		v0 := b.NewValue0(v.Pos, OpS390XMOVWZreg, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueS390X_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div64 x y)
	// result: (DIVD x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XDIVD)
		v.AddArg2(x, y)
		return true
	}
}
func rewriteValueS390X_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (DIVW (MOVBreg x) (MOVBreg y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XDIVW)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (DIVWU (MOVBZreg x) (MOVBZreg y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XDIVWU)
		v0 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueS390X_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (LOCGR {s390x.Equal} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVHreg x) (MOVHreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Equal)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq32 x y)
	// result: (LOCGR {s390x.Equal} (MOVDconst [0]) (MOVDconst [1]) (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Equal)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq32F x y)
	// result: (LOCGR {s390x.Equal} (MOVDconst [0]) (MOVDconst [1]) (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Equal)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XFCMPS, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq64 x y)
	// result: (LOCGR {s390x.Equal} (MOVDconst [0]) (MOVDconst [1]) (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Equal)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq64F x y)
	// result: (LOCGR {s390x.Equal} (MOVDconst [0]) (MOVDconst [1]) (FCMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Equal)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XFCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (LOCGR {s390x.Equal} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVBreg x) (MOVBreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Equal)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (LOCGR {s390x.Equal} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVBreg x) (MOVBreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Equal)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqPtr x y)
	// result: (LOCGR {s390x.Equal} (MOVDconst [0]) (MOVDconst [1]) (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Equal)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpFMA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMA x y z)
	// result: (FMADD z x y)
	for {
		x := v_0
		y := v_1
		z := v_2
		v.reset(OpS390XFMADD)
		v.AddArg3(z, x, y)
		return true
	}
}
func rewriteValueS390X_OpFloor(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Floor x)
	// result: (FIDBR [7] x)
	for {
		x := v_0
		v.reset(OpS390XFIDBR)
		v.AuxInt = int8ToAuxInt(7)
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpHmul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32 x y)
	// result: (SRDconst [32] (MULLD (MOVWreg x) (MOVWreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRDconst)
		v.AuxInt = uint8ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpS390XMULLD, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpS390XMOVWreg, typ.Int64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpS390XMOVWreg, typ.Int64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpHmul32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32u x y)
	// result: (SRDconst [32] (MULLD (MOVWZreg x) (MOVWZreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XSRDconst)
		v.AuxInt = uint8ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpS390XMULLD, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpS390XMOVWZreg, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpS390XMOVWZreg, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpITab(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ITab (Load ptr mem))
	// result: (MOVDload ptr mem)
	for {
		if v_0.Op != OpLoad {
			break
		}
		mem := v_0.Args[1]
		ptr := v_0.Args[0]
		v.reset(OpS390XMOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsInBounds idx len)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (CMPU idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPU, types.TypeFlags)
		v2.AddArg2(idx, len)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsNonNil p)
	// result: (LOCGR {s390x.NotEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPconst p [0]))
	for {
		p := v_0
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.NotEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPconst, types.TypeFlags)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg(p)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsSliceInBounds idx len)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPU idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPU, types.TypeFlags)
		v2.AddArg2(idx, len)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVHreg x) (MOVHreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPWU (MOVHZreg x) (MOVHZreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWU, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32 x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32F x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XFCMPS, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32U x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPWU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWU, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64 x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64F x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (FCMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XFCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64U x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPU, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVBreg x) (MOVBreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (LOCGR {s390x.LessOrEqual} (MOVDconst [0]) (MOVDconst [1]) (CMPWU (MOVBZreg x) (MOVBZreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.LessOrEqual)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWU, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVHreg x) (MOVHreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (CMPWU (MOVHZreg x) (MOVHZreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWU, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVHZreg, typ.UInt64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32 x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32F x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XFCMPS, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32U x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (CMPWU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWU, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less64 x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less64F x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (FCMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XFCMP, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less64U x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (CMPU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPU, types.TypeFlags)
		v2.AddArg2(x, y)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (CMPW (MOVBreg x) (MOVBreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPW, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBreg, typ.Int64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (LOCGR {s390x.Less} (MOVDconst [0]) (MOVDconst [1]) (CMPWU (MOVBZreg x) (MOVBZreg y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpS390XLOCGR)
		v.Aux = s390xCCMaskToAux(s390x.Less)
		v0 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpS390XMOVDconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpS390XCMPWU, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpS390XMOVBZreg, typ.UInt64)
		v4.AddArg(y)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueS390X_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
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
		v.reset(OpS390XMOVDload)
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
		v.reset(OpS390XMOVWload)
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
		v.reset(OpS390XMOVWZload)
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
		v.reset(OpS390XMOVHload)
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
		v.reset(OpS390XMOVHZload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is8BitInt(t) && t.IsSigned()
	// result: (MOVBload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpS390XMOVBload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (t.IsBoolean() || (is8BitInt(t) && !t.IsSigned()))
	// result: (MOVBZload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsBoolean() || (is8BitInt(t) && !t.IsSigned())) {
			break
		}
		v.reset(OpS390XMOVBZload)
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
		v.reset(OpS390XFMOVSload)
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
		v.reset(OpS390XFMOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpLocalAddr(v *Value) bool {
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
		v.reset(OpS390XMOVDaddr)
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
		if !(
"""




```