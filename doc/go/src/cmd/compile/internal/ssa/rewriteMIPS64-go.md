Response: 
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
// Code generated from _gen/MIPS64.rules using 'go generate'; DO NOT EDIT.

package ssa

import "cmd/compile/internal/types"

func rewriteValueMIPS64(v *Value) bool {
	switch v.Op {
	case OpAbs:
		v.Op = OpMIPS64ABSD
		return true
	case OpAdd16:
		v.Op = OpMIPS64ADDV
		return true
	case OpAdd32:
		v.Op = OpMIPS64ADDV
		return true
	case OpAdd32F:
		v.Op = OpMIPS64ADDF
		return true
	case OpAdd64:
		v.Op = OpMIPS64ADDV
		return true
	case OpAdd64F:
		v.Op = OpMIPS64ADDD
		return true
	case OpAdd8:
		v.Op = OpMIPS64ADDV
		return true
	case OpAddPtr:
		v.Op = OpMIPS64ADDV
		return true
	case OpAddr:
		return rewriteValueMIPS64_OpAddr(v)
	case OpAnd16:
		v.Op = OpMIPS64AND
		return true
	case OpAnd32:
		v.Op = OpMIPS64AND
		return true
	case OpAnd64:
		v.Op = OpMIPS64AND
		return true
	case OpAnd8:
		v.Op = OpMIPS64AND
		return true
	case OpAndB:
		v.Op = OpMIPS64AND
		return true
	case OpAtomicAdd32:
		v.Op = OpMIPS64LoweredAtomicAdd32
		return true
	case OpAtomicAdd64:
		v.Op = OpMIPS64LoweredAtomicAdd64
		return true
	case OpAtomicAnd32:
		v.Op = OpMIPS64LoweredAtomicAnd32
		return true
	case OpAtomicAnd8:
		return rewriteValueMIPS64_OpAtomicAnd8(v)
	case OpAtomicCompareAndSwap32:
		return rewriteValueMIPS64_OpAtomicCompareAndSwap32(v)
	case OpAtomicCompareAndSwap64:
		v.Op = OpMIPS64LoweredAtomicCas64
		return true
	case OpAtomicExchange32:
		v.Op = OpMIPS64LoweredAtomicExchange32
		return true
	case OpAtomicExchange64:
		v.Op = OpMIPS64LoweredAtomicExchange64
		return true
	case OpAtomicLoad32:
		v.Op = OpMIPS64LoweredAtomicLoad32
		return true
	case OpAtomicLoad64:
		v.Op = OpMIPS64LoweredAtomicLoad64
		return true
	case OpAtomicLoad8:
		v.Op = OpMIPS64LoweredAtomicLoad8
		return true
	case OpAtomicLoadPtr:
		v.Op = OpMIPS64LoweredAtomicLoad64
		return true
	case OpAtomicOr32:
		v.Op = OpMIPS64LoweredAtomicOr32
		return true
	case OpAtomicOr8:
		return rewriteValueMIPS64_OpAtomicOr8(v)
	case OpAtomicStore32:
		v.Op = OpMIPS64LoweredAtomicStore32
		return true
	case OpAtomicStore64:
		v.Op = OpMIPS64LoweredAtomicStore64
		return true
	case OpAtomicStore8:
		v.Op = OpMIPS64LoweredAtomicStore8
		return true
	case OpAtomicStorePtrNoWB:
		v.Op = OpMIPS64LoweredAtomicStore64
		return true
	case OpAvg64u:
		return rewriteValueMIPS64_OpAvg64u(v)
	case OpClosureCall:
		v.Op = OpMIPS64CALLclosure
		return true
	case OpCom16:
		return rewriteValueMIPS64_OpCom16(v)
	case OpCom32:
		return rewriteValueMIPS64_OpCom32(v)
	case OpCom64:
		return rewriteValueMIPS64_OpCom64(v)
	case OpCom8:
		return rewriteValueMIPS64_OpCom8(v)
	case OpConst16:
		return rewriteValueMIPS64_OpConst16(v)
	case OpConst32:
		return rewriteValueMIPS64_OpConst32(v)
	case OpConst32F:
		return rewriteValueMIPS64_OpConst32F(v)
	case OpConst64:
		return rewriteValueMIPS64_OpConst64(v)
	case OpConst64F:
		return rewriteValueMIPS64_OpConst64F(v)
	case OpConst8:
		return rewriteValueMIPS64_OpConst8(v)
	case OpConstBool:
		return rewriteValueMIPS64_OpConstBool(v)
	case OpConstNil:
		return rewriteValueMIPS64_OpConstNil(v)
	case OpCvt32Fto32:
		v.Op = OpMIPS64TRUNCFW
		return true
	case OpCvt32Fto64:
		v.Op = OpMIPS64TRUNCFV
		return true
	case OpCvt32Fto64F:
		v.Op = OpMIPS64MOVFD
		return true
	case OpCvt32to32F:
		v.Op = OpMIPS64MOVWF
		return true
	case OpCvt32to64F:
		v.Op = OpMIPS64MOVWD
		return true
	case OpCvt64Fto32:
		v.Op = OpMIPS64TRUNCDW
		return true
	case OpCvt64Fto32F:
		v.Op = OpMIPS64MOVDF
		return true
	case OpCvt64Fto64:
		v.Op = OpMIPS64TRUNCDV
		return true
	case OpCvt64to32F:
		v.Op = OpMIPS64MOVVF
		return true
	case OpCvt64to64F:
		v.Op = OpMIPS64MOVVD
		return true
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv16:
		return rewriteValueMIPS64_OpDiv16(v)
	case OpDiv16u:
		return rewriteValueMIPS64_OpDiv16u(v)
	case OpDiv32:
		return rewriteValueMIPS64_OpDiv32(v)
	case OpDiv32F:
		v.Op = OpMIPS64DIVF
		return true
	case OpDiv32u:
		return rewriteValueMIPS64_OpDiv32u(v)
	case OpDiv64:
		return rewriteValueMIPS64_OpDiv64(v)
	case OpDiv64F:
		v.Op = OpMIPS64DIVD
		return true
	case OpDiv64u:
		return rewriteValueMIPS64_OpDiv64u(v)
	case OpDiv8:
		return rewriteValueMIPS64_OpDiv8(v)
	case OpDiv8u:
		return rewriteValueMIPS64_OpDiv8u(v)
	case OpEq16:
		return rewriteValueMIPS64_OpEq16(v)
	case OpEq32:
		return rewriteValueMIPS64_OpEq32(v)
	case OpEq32F:
		return rewriteValueMIPS64_OpEq32F(v)
	case OpEq64:
		return rewriteValueMIPS64_OpEq64(v)
	case OpEq64F:
		return rewriteValueMIPS64_OpEq64F(v)
	case OpEq8:
		return rewriteValueMIPS64_OpEq8(v)
	case OpEqB:
		return rewriteValueMIPS64_OpEqB(v)
	case OpEqPtr:
		return rewriteValueMIPS64_OpEqPtr(v)
	case OpGetCallerPC:
		v.Op = OpMIPS64LoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = OpMIPS64LoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = OpMIPS64LoweredGetClosurePtr
		return true
	case OpHmul32:
		return rewriteValueMIPS64_OpHmul32(v)
	case OpHmul32u:
		return rewriteValueMIPS64_OpHmul32u(v)
	case OpHmul64:
		return rewriteValueMIPS64_OpHmul64(v)
	case OpHmul64u:
		return rewriteValueMIPS64_OpHmul64u(v)
	case OpInterCall:
		v.Op = OpMIPS64CALLinter
		return true
	case OpIsInBounds:
		return rewriteValueMIPS64_OpIsInBounds(v)
	case OpIsNonNil:
		return rewriteValueMIPS64_OpIsNonNil(v)
	case OpIsSliceInBounds:
		return rewriteValueMIPS64_OpIsSliceInBounds(v)
	case OpLeq16:
		return rewriteValueMIPS64_OpLeq16(v)
	case OpLeq16U:
		return rewriteValueMIPS64_OpLeq16U(v)
	case OpLeq32:
		return rewriteValueMIPS64_OpLeq32(v)
	case OpLeq32F:
		return rewriteValueMIPS64_OpLeq32F(v)
	case OpLeq32U:
		return rewriteValueMIPS64_OpLeq32U(v)
	case OpLeq64:
		return rewriteValueMIPS64_OpLeq64(v)
	case OpLeq64F:
		return rewriteValueMIPS64_OpLeq64F(v)
	case OpLeq64U:
		return rewriteValueMIPS64_OpLeq64U(v)
	case OpLeq8:
		return rewriteValueMIPS64_OpLeq8(v)
	case OpLeq8U:
		return rewriteValueMIPS64_OpLeq8U(v)
	case OpLess16:
		return rewriteValueMIPS64_OpLess16(v)
	case OpLess16U:
		return rewriteValueMIPS64_OpLess16U(v)
	case OpLess32:
		return rewriteValueMIPS64_OpLess32(v)
	case OpLess32F:
		return rewriteValueMIPS64_OpLess32F(v)
	case OpLess32U:
		return rewriteValueMIPS64_OpLess32U(v)
	case OpLess64:
		return rewriteValueMIPS64_OpLess64(v)
	case OpLess64F:
		return rewriteValueMIPS64_OpLess64F(v)
	case OpLess64U:
		return rewriteValueMIPS64_OpLess64U(v)
	case OpLess8:
		return rewriteValueMIPS64_OpLess8(v)
	case OpLess8U:
		return rewriteValueMIPS64_OpLess8U(v)
	case OpLoad:
		return rewriteValueMIPS64_OpLoad(v)
	case OpLocalAddr:
		return rewriteValueMIPS64_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValueMIPS64_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValueMIPS64_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValueMIPS64_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValueMIPS64_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValueMIPS64_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValueMIPS64_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValueMIPS64_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValueMIPS64_OpLsh32x8(v)
	case OpLsh64x16:
		return rewriteValueMIPS64_OpLsh64x16(v)
	case OpLsh64x32:
		return rewriteValueMIPS64_OpLsh64x32(v)
	case OpLsh64x64:
		return rewriteValueMIPS64_OpLsh64x64(v)
	case OpLsh64x8:
		return rewriteValueMIPS64_OpLsh64x8(v)
	case OpLsh8x16:
		return rewriteValueMIPS64_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValueMIPS64_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValueMIPS64_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValueMIPS64_OpLsh8x8(v)
	case OpMIPS64ADDV:
		return rewriteValueMIPS64_OpMIPS64ADDV(v)
	case OpMIPS64ADDVconst:
		return rewriteValueMIPS64_OpMIPS64ADDVconst(v)
	case OpMIPS64AND:
		return rewriteValueMIPS64_OpMIPS64AND(v)
	case OpMIPS64ANDconst:
		return rewriteValueMIPS64_OpMIPS64ANDconst(v)
	case OpMIPS64LoweredAtomicAdd32:
		return rewriteValueMIPS64_OpMIPS64LoweredAtomicAdd32(v)
	case OpMIPS64LoweredAtomicAdd64:
		return rewriteValueMIPS64_OpMIPS64LoweredAtomicAdd64(v)
	case OpMIPS64LoweredAtomicStore32:
		return rewriteValueMIPS64_OpMIPS64LoweredAtomicStore32(v)
	case OpMIPS64LoweredAtomicStore64:
		return rewriteValueMIPS64_OpMIPS64LoweredAtomicStore64(v)
	case OpMIPS64MOVBUload:
		return rewriteValueMIPS64_OpMIPS64MOVBUload(v)
	case OpMIPS64MOVBUreg:
		return rewriteValueMIPS64_OpMIPS64MOVBUreg(v)
	case OpMIPS64MOVBload:
		return rewriteValueMIPS64_OpMIPS64MOVBload(v)
	case OpMIPS64MOVBreg:
		return rewriteValueMIPS64_OpMIPS64MOVBreg(v)
	case OpMIPS64MOVBstore:
		return rewriteValueMIPS64_OpMIPS64MOVBstore(v)
	case OpMIPS64MOVBstorezero:
		return rewriteValueMIPS64_OpMIPS64MOVBstorezero(v)
	case OpMIPS64MOVDload:
		return rewriteValueMIPS64_OpMIPS64MOVDload(v)
	case OpMIPS64MOVDstore:
		return rewriteValueMIPS64_OpMIPS64MOVDstore(v)
	case OpMIPS64MOVFload:
		return rewriteValueMIPS64_OpMIPS64MOVFload(v)
	case OpMIPS64MOVFstore:
		return rewriteValueMIPS64_OpMIPS64MOVFstore(v)
	case OpMIPS64MOVHUload:
		return rewriteValueMIPS64_OpMIPS64MOVHUload(v)
	case OpMIPS64MOVHUreg:
		return rewriteValueMIPS64_OpMIPS64MOVHUreg(v)
	case OpMIPS64MOVHload:
		return rewriteValueMIPS64_OpMIPS64MOVHload(v)
	case OpMIPS64MOVHreg:
		return rewriteValueMIPS64_OpMIPS64MOVHreg(v)
	case OpMIPS64MOVHstore:
		return rewriteValueMIPS64_OpMIPS64MOVHstore(v)
	case OpMIPS64MOVHstorezero:
		return rewriteValueMIPS64_OpMIPS64MOVHstorezero(v)
	case OpMIPS64MOVVload:
		return rewriteValueMIPS64_OpMIPS64MOVVload(v)
	case OpMIPS64MOVVnop:
		return rewriteValueMIPS64_OpMIPS64MOVVnop(v)
	case OpMIPS64MOVVreg:
		return rewriteValueMIPS64_OpMIPS64MOVVreg(v)
	case OpMIPS64MOVVstore:
		return rewriteValueMIPS64_OpMIPS64MOVVstore(v)
	case OpMIPS64MOVVstorezero:
		return rewriteValueMIPS64_OpMIPS64MOVVstorezero(v)
	case OpMIPS64MOVWUload:
		return rewriteValueMIPS64_OpMIPS64MOVWUload(v)
	case OpMIPS64MOVWUreg:
		return rewriteValueMIPS64_OpMIPS64MOVWUreg(v)
	case OpMIPS64MOVWload:
		return rewriteValueMIPS64_OpMIPS64MOVWload(v)
	case OpMIPS64MOVWreg:
		return rewriteValueMIPS64_OpMIPS64MOVWreg(v)
	case OpMIPS64MOVWstore:
		return rewriteValueMIPS64_OpMIPS64MOVWstore(v)
	case OpMIPS64MOVWstorezero:
		return rewriteValueMIPS64_OpMIPS64MOVWstorezero(v)
	case OpMIPS64NEGV:
		return rewriteValueMIPS64_OpMIPS64NEGV(v)
	case OpMIPS64NOR:
		return rewriteValueMIPS64_OpMIPS64NOR(v)
	case OpMIPS64NORconst:
		return rewriteValueMIPS64_OpMIPS64NORconst(v)
	case OpMIPS64OR:
		return rewriteValueMIPS64_OpMIPS64OR(v)
	case OpMIPS64ORconst:
		return rewriteValueMIPS64_OpMIPS64ORconst(v)
	case OpMIPS64SGT:
		return rewriteValueMIPS64_OpMIPS64SGT(v)
	case OpMIPS64SGTU:
		return rewriteValueMIPS64_OpMIPS64SGTU(v)
	case OpMIPS64SGTUconst:
		return rewriteValueMIPS64_OpMIPS64SGTUconst(v)
	case OpMIPS64SGTconst:
		return rewriteValueMIPS64_OpMIPS64SGTconst(v)
	case OpMIPS64SLLV:
		return rewriteValueMIPS64_OpMIPS64SLLV(v)
	case OpMIPS64SLLVconst:
		return rewriteValueMIPS64_OpMIPS64SLLVconst(v)
	case OpMIPS64SRAV:
		return rewriteValueMIPS64_OpMIPS64SRAV(v)
	case OpMIPS64SRAVconst:
		return rewriteValueMIPS64_OpMIPS64SRAVconst(v)
	case OpMIPS64SRLV:
		return rewriteValueMIPS64_OpMIPS64SRLV(v)
	case OpMIPS64SRLVconst:
		return rewriteValueMIPS64_OpMIPS64SRLVconst(v)
	case OpMIPS64SUBV:
		return rewriteValueMIPS64_OpMIPS64SUBV(v)
	case OpMIPS64SUBVconst:
		return rewriteValueMIPS64_OpMIPS64SUBVconst(v)
	case OpMIPS64XOR:
		return rewriteValueMIPS64_OpMIPS64XOR(v)
	case OpMIPS64XORconst:
		return rewriteValueMIPS64_OpMIPS64XORconst(v)
	case OpMod16:
		return rewriteValueMIPS64_OpMod16(v)
	case OpMod16u:
		return rewriteValueMIPS64_OpMod16u(v)
	case OpMod32:
		return rewriteValueMIPS64_OpMod32(v)
	case OpMod32u:
		return rewriteValueMIPS64_OpMod32u(v)
	case OpMod64:
		return rewriteValueMIPS64_OpMod64(v)
	case OpMod64u:
		return rewriteValueMIPS64_OpMod64u(v)
	case OpMod8:
		return rewriteValueMIPS64_OpMod8(v)
	case OpMod8u:
		return rewriteValueMIPS64_OpMod8u(v)
	case OpMove:
		return rewriteValueMIPS64_OpMove(v)
	case OpMul16:
		return rewriteValueMIPS64_OpMul16(v)
	case OpMul32:
		return rewriteValueMIPS64_OpMul32(v)
	case OpMul32F:
		v.Op = OpMIPS64MULF
		return true
	case OpMul64:
		return rewriteValueMIPS64_OpMul64(v)
	case OpMul64F:
		v.Op = OpMIPS64MULD
		return true
	case OpMul64uhilo:
		v.Op = OpMIPS64MULVU
		return true
	case OpMul8:
		return rewriteValueMIPS64_OpMul8(v)
	case OpNeg16:
		v.Op = OpMIPS64NEGV
		return true
	case OpNeg32:
		v.Op = OpMIPS64NEGV
		return true
	case OpNeg32F:
		v.Op = OpMIPS64NEGF
		return true
	case OpNeg64:
		v.Op = OpMIPS64NEGV
		return true
	case OpNeg64F:
		v.Op = OpMIPS64NEGD
		return true
	case OpNeg8:
		v.Op = OpMIPS64NEGV
		return true
	case OpNeq16:
		return rewriteValueMIPS64_OpNeq16(v)
	case OpNeq32:
		return rewriteValueMIPS64_OpNeq32(v)
	case OpNeq32F:
		return rewriteValueMIPS64_OpNeq32F(v)
	case OpNeq64:
		return rewriteValueMIPS64_OpNeq64(v)
	case OpNeq64F:
		return rewriteValueMIPS64_OpNeq64F(v)
	case OpNeq8:
		return rewriteValueMIPS64_OpNeq8(v)
	case OpNeqB:
		v.Op = OpMIPS64XOR
		return true
	case OpNeqPtr:
		return rewriteValueMIPS64_OpNeqPtr(v)
	case OpNilCheck:
		v.Op = OpMIPS64LoweredNilCheck
		return true
	case OpNot:
		return rewriteValueMIPS64_OpNot(v)
	case OpOffPtr:
		return rewriteValueMIPS64_OpOffPtr(v)
	case OpOr16:
		v.Op = OpMIPS64OR
		return true
	case OpOr32:
		v.Op = OpMIPS64OR
		return true
	case OpOr64:
		v.Op = OpMIPS64OR
		return true
	case OpOr8:
		v.Op = OpMIPS64OR
		return true
	case OpOrB:
		v.Op = OpMIPS64OR
		return true
	case OpPanicBounds:
		return rewriteValueMIPS64_OpPanicBounds(v)
	case OpRotateLeft16:
		return rewriteValueMIPS64_OpRotateLeft16(v)
	case OpRotateLeft32:
		return rewriteValueMIPS64_OpRotateLeft32(v)
	case OpRotateLeft64:
		return rewriteValueMIPS64_OpRotateLeft64(v)
	case OpRotateLeft8:
		return rewriteValueMIPS64_OpRotateLeft8(v)
	case OpRound32F:
		v.Op = OpCopy
		return true
	case OpRound64F:
		v.Op = OpCopy
		return true
	case OpRsh16Ux16:
		return rewriteValueMIPS64_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValueMIPS64_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValueMIPS64_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValueMIPS64_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValueMIPS64_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValueMIPS64_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValueMIPS64_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValueMIPS64_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValueMIPS64_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValueMIPS64_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValueMIPS64_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValueMIPS64_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValueMIPS64_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValueMIPS64_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValueMIPS64_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValueMIPS64_OpRsh32x8(v)
	case OpRsh64Ux16:
		return rewriteValueMIPS64_OpRsh64Ux16(v)
	case OpRsh64Ux32:
		return rewriteValueMIPS64_OpRsh64Ux32(v)
	case OpRsh64Ux64:
		return rewriteValueMIPS64_OpRsh64Ux64(v)
	case OpRsh64Ux8:
		return rewriteValueMIPS64_OpRsh64Ux8(v)
	case OpRsh64x16:
		return rewriteValueMIPS64_OpRsh64x16(v)
	case OpRsh64x32:
		return rewriteValueMIPS64_OpRsh64x32(v)
	case OpRsh64x64:
		return rewriteValueMIPS64_OpRsh64x64(v)
	case OpRsh64x8:
		return rewriteValueMIPS64_OpRsh64x8(v)
	case OpRsh8Ux16:
		return rewriteValueMIPS64_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValueMIPS64_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValueMIPS64_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValueMIPS64_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValueMIPS64_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValueMIPS64_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValueMIPS64_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValueMIPS64_OpRsh8x8(v)
	case OpSelect0:
		return rewriteValueMIPS64_OpSelect0(v)
	case OpSelect1:
		return rewriteValueMIPS64_OpSelect1(v)
	case OpSignExt16to32:
		v.Op = OpMIPS64MOVHreg
		return true
	case OpSignExt16to64:
		v.Op = OpMIPS64MOVHreg
		return true
	case OpSignExt32to64:
		v.Op = OpMIPS64MOVWreg
		return true
	case OpSignExt8to16:
		v.Op = OpMIPS64MOVBreg
		return true
	case OpSignExt8to32:
		v.Op = OpMIPS64MOVBreg
		return true
	case OpSignExt8to64:
		v.Op = OpMIPS64MOVBreg
		return true
	case OpSlicemask:
		return rewriteValueMIPS64_OpSlicemask(v)
	case OpSqrt:
		v.Op = OpMIPS64SQRTD
		return true
	case OpSqrt32:
		v.Op = OpMIPS64SQRTF
		return true
	case OpStaticCall:
		v.Op = OpMIPS64CALLstatic
		return true
	case OpStore:
		return rewriteValueMIPS64_OpStore(v)
	case OpSub16:
		v.Op = OpMIPS64SUBV
		return true
	case OpSub32:
		v.Op = OpMIPS64SUBV
		return true
	case OpSub32F:
		v.Op = OpMIPS64SUBF
		return true
	case OpSub64:
		v.Op = OpMIPS64SUBV
		return true
	case OpSub64F:
		v.Op = OpMIPS64SUBD
		return true
	case OpSub8:
		v.Op = OpMIPS64SUBV
		return true
	case OpSubPtr:
		v.Op = OpMIPS64SUBV
		return true
	case OpTailCall:
		v.Op = OpMIPS64CALLtail
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
		v.Op = OpMIPS64LoweredWB
		return true
	case OpXor16:
		v.Op = OpMIPS64XOR
		return true
	case OpXor32:
		v.Op = OpMIPS64XOR
		return true
	case OpXor64:
		v.Op = OpMIPS64XOR
		return true
	case OpXor8:
		v.Op = OpMIPS64XOR
		return true
	case OpZero:
		return rewriteValueMIPS64_OpZero(v)
	case OpZeroExt16to32:
		v.Op = OpMIPS64MOVHUreg
		return true
	case OpZeroExt16to64:
		v.Op = OpMIPS64MOVHUreg
		return true
	case OpZeroExt32to64:
		v.Op = OpMIPS64MOVWUreg
		return true
	case OpZeroExt8to16:
		v.Op = OpMIPS64MOVBUreg
		return true
	case OpZeroExt8to32:
		v.Op = OpMIPS64MOVBUreg
		return true
	case OpZeroExt8to64:
		v.Op = OpMIPS64MOVBUreg
		return true
	}
	return false
}
func rewriteValueMIPS64_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (MOVVaddr {sym} base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpMIPS64MOVVaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueMIPS64_OpAtomicAnd8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (AtomicAnd8 ptr val mem)
	// cond: !config.BigEndian
	// result: (LoweredAtomicAnd32 (AND <typ.UInt32Ptr> (MOVVconst [^3]) ptr) (OR <typ.UInt64> (SLLV <typ.UInt32> (ZeroExt8to32 val) (SLLVconst <typ.UInt64> [3] (ANDconst <typ.UInt64> [3] ptr))) (NORconst [0] <typ.UInt64> (SLLV <typ.UInt64> (MOVVconst [0xff]) (SLLVconst <typ.UInt64> [3] (ANDconst <typ.UInt64> [3] ptr))))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		if !(!config.BigEndian) {
			break
		}
		v.reset(OpMIPS64LoweredAtomicAnd32)
		v0 := b.NewValue0(v.Pos, OpMIPS64AND, typ.UInt32Ptr)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpMIPS64OR, typ.UInt64)
		v3 := b.NewValue0(v.Pos, OpMIPS64SLLV, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v4.AddArg(val)
		v5 := b.NewValue0(v.Pos, OpMIPS64SLLVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(3)
		v6 := b.NewValue0(v.Pos, OpMIPS64ANDconst, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(3)
		v6.AddArg(ptr)
		v5.AddArg(v6)
		v3.AddArg2(v4, v5)
		v7 := b.NewValue0(v.Pos, OpMIPS64NORconst, typ.UInt64)
		v7.AuxInt = int64ToAuxInt(0)
		v8 := b.NewValue0(v.Pos, OpMIPS64SLLV, typ.UInt64)
		v9 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v9.AuxInt = int64ToAuxInt(0xff)
		v8.AddArg2(v9, v5)
		v7.AddArg(v8)
		v2.AddArg2(v3, v7)
		v.AddArg3(v0, v2, mem)
		return true
	}
	// match: (AtomicAnd8 ptr val mem)
	// cond: config.BigEndian
	// result: (LoweredAtomicAnd32 (AND <typ.UInt32Ptr> (MOVVconst [^3]) ptr) (OR <typ.UInt64> (SLLV <typ.UInt32> (ZeroExt8to32 val) (SLLVconst <typ.UInt64> [3] (ANDconst <typ.UInt64> [3] (XORconst <typ.UInt64> [3] ptr)))) (NORconst [0] <typ.UInt64> (SLLV <typ.UInt64> (MOVVconst [0xff]) (SLLVconst <typ.UInt64> [3] (ANDconst <typ.UInt64> [3] (XORconst <typ.UInt64> [3] ptr)))))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		if !(config.BigEndian) {
			break
		}
		v.reset(OpMIPS64LoweredAtomicAnd32)
		v0 := b.NewValue0(v.Pos, OpMIPS64AND, typ.UInt32Ptr)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpMIPS64OR, typ.UInt64)
		v3 := b.NewValue0(v.Pos, OpMIPS64SLLV, typ.UInt32)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v4.AddArg(val)
		v5 := b.NewValue0(v.Pos, OpMIPS64SLLVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(3)
		v6 := b.NewValue0(v.Pos, OpMIPS64ANDconst, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(3)
		v7 := b.NewValue0(v.Pos, OpMIPS64XORconst, typ.UInt64)
		v7.AuxInt = int64ToAuxInt(3)
		v7.AddArg(ptr)
		v6.AddArg(v7)
		v5.AddArg(v6)
		v3.AddArg2(v4, v5)
		v8 := b.NewValue0(v.Pos, OpMIPS64NORconst, typ.UInt64)
		v8.AuxInt = int64ToAuxInt(0)
		v9 := b.NewValue0(v.Pos, OpMIPS64SLLV, typ.UInt64)
		v10 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v10.AuxInt = int64ToAuxInt(0xff)
		v9.AddArg2(v10, v5)
		v8.AddArg(v9)
		v2.AddArg2(v3, v8)
		v.AddArg3(v0, v2, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpAtomicCompareAndSwap32(v *Value) bool {
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
		v.reset(OpMIPS64LoweredAtomicCas32)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(old)
		v.AddArg4(ptr, v0, new, mem)
		return true
	}
}
func rewriteValueMIPS64_OpAtomicOr8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (AtomicOr8 ptr val mem)
	// cond: !config.BigEndian
	// result: (LoweredAtomicOr32 (AND <typ.UInt32Ptr> (MOVVconst [^3]) ptr) (SLLV <typ.UInt32> (ZeroExt8to32 val) (SLLVconst <typ.UInt64> [3] (ANDconst <typ.UInt64> [3] ptr))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		if !(!config.BigEndian) {
			break
		}
		v.reset(OpMIPS64LoweredAtomicOr32)
		v0 := b.NewValue0(v.Pos, OpMIPS64AND, typ.UInt32Ptr)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpMIPS64SLLV, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v3.AddArg(val)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(3)
		v5 := b.NewValue0(v.Pos, OpMIPS64ANDconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(3)
		v5.AddArg(ptr)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v2, mem)
		return true
	}
	// match: (AtomicOr8 ptr val mem)
	// cond: config.BigEndian
	// result: (LoweredAtomicOr32 (AND <typ.UInt32Ptr> (MOVVconst [^3]) ptr) (SLLV <typ.UInt32> (ZeroExt8to32 val) (SLLVconst <typ.UInt64> [3] (ANDconst <typ.UInt64> [3] (XORconst <typ.UInt64> [3] ptr)))) mem)
	for {
		ptr := v_0
		val := v_1
		mem := v_2
		if !(config.BigEndian) {
			break
		}
		v.reset(OpMIPS64LoweredAtomicOr32)
		v0 := b.NewValue0(v.Pos, OpMIPS64AND, typ.UInt32Ptr)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(^3)
		v0.AddArg2(v1, ptr)
		v2 := b.NewValue0(v.Pos, OpMIPS64SLLV, typ.UInt32)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v3.AddArg(val)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(3)
		v5 := b.NewValue0(v.Pos, OpMIPS64ANDconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(3)
		v6 := b.NewValue0(v.Pos, OpMIPS64XORconst, typ.UInt64)
		v6.AuxInt = int64ToAuxInt(3)
		v6.AddArg(ptr)
		v5.AddArg(v6)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg3(v0, v2, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpAvg64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Avg64u <t> x y)
	// result: (ADDV (SRLVconst <t> (SUBV <t> x y) [1]) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64ADDV)
		v0 := b.NewValue0(v.Pos, OpMIPS64SRLVconst, t)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SUBV, t)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueMIPS64_OpCom16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com16 x)
	// result: (NOR (MOVVconst [0]) x)
	for {
		x := v_0
		v.reset(OpMIPS64NOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueMIPS64_OpCom32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com32 x)
	// result: (NOR (MOVVconst [0]) x)
	for {
		x := v_0
		v.reset(OpMIPS64NOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueMIPS64_OpCom64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com64 x)
	// result: (NOR (MOVVconst [0]) x)
	for {
		x := v_0
		v.reset(OpMIPS64NOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueMIPS64_OpCom8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com8 x)
	// result: (NOR (MOVVconst [0]) x)
	for {
		x := v_0
		v.reset(OpMIPS64NOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueMIPS64_OpConst16(v *Value) bool {
	// match: (Const16 [val])
	// result: (MOVVconst [int64(val)])
	for {
		val := auxIntToInt16(v.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueMIPS64_OpConst32(v *Value) bool {
	// match: (Const32 [val])
	// result: (MOVVconst [int64(val)])
	for {
		val := auxIntToInt32(v.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueMIPS64_OpConst32F(v *Value) bool {
	// match: (Const32F [val])
	// result: (MOVFconst [float64(val)])
	for {
		val := auxIntToFloat32(v.AuxInt)
		v.reset(OpMIPS64MOVFconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueMIPS64_OpConst64(v *Value) bool {
	// match: (Const64 [val])
	// result: (MOVVconst [int64(val)])
	for {
		val := auxIntToInt64(v.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueMIPS64_OpConst64F(v *Value) bool {
	// match: (Const64F [val])
	// result: (MOVDconst [float64(val)])
	for {
		val := auxIntToFloat64(v.AuxInt)
		v.reset(OpMIPS64MOVDconst)
		v.AuxInt = float64ToAuxInt(float64(val))
		return true
	}
}
func rewriteValueMIPS64_OpConst8(v *Value) bool {
	// match: (Const8 [val])
	// result: (MOVVconst [int64(val)])
	for {
		val := auxIntToInt8(v.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(val))
		return true
	}
}
func rewriteValueMIPS64_OpConstBool(v *Value) bool {
	// match: (ConstBool [t])
	// result: (MOVVconst [int64(b2i(t))])
	for {
		t := auxIntToBool(v.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(int64(b2i(t)))
		return true
	}
}
func rewriteValueMIPS64_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (MOVVconst [0])
	for {
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValueMIPS64_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 x y)
	// result: (Select1 (DIVV (SignExt16to64 x) (SignExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVV, types.NewTuple(typ.Int64, typ.Int64))
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (Select1 (DIVVU (ZeroExt16to64 x) (ZeroExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32 x y)
	// result: (Select1 (DIVV (SignExt32to64 x) (SignExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVV, types.NewTuple(typ.Int64, typ.Int64))
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32u x y)
	// result: (Select1 (DIVVU (ZeroExt32to64 x) (ZeroExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div64 x y)
	// result: (Select1 (DIVV x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVV, types.NewTuple(typ.Int64, typ.Int64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpDiv64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div64u x y)
	// result: (Select1 (DIVVU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (Select1 (DIVV (SignExt8to64 x) (SignExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVV, types.NewTuple(typ.Int64, typ.Int64))
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (Select1 (DIVVU (ZeroExt8to64 x) (ZeroExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (SGTU (MOVVconst [1]) (XOR (ZeroExt16to64 x) (ZeroExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq32 x y)
	// result: (SGTU (MOVVconst [1]) (XOR (ZeroExt32to64 x) (ZeroExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpEq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq32F x y)
	// result: (FPFlagTrue (CMPEQF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPS64CMPEQF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpEq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq64 x y)
	// result: (SGTU (MOVVconst [1]) (XOR x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpEq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Eq64F x y)
	// result: (FPFlagTrue (CMPEQD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPS64CMPEQD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (SGTU (MOVVconst [1]) (XOR (ZeroExt8to64 x) (ZeroExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpEqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqB x y)
	// result: (XOR (MOVVconst [1]) (XOR <typ.Bool> x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpEqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (EqPtr x y)
	// result: (SGTU (MOVVconst [1]) (XOR x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpHmul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32 x y)
	// result: (SRAVconst (Select1 <typ.Int64> (MULV (SignExt32to64 x) (SignExt32to64 y))) [32])
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SRAVconst)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpSelect1, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpMIPS64MULV, types.NewTuple(typ.Int64, typ.Int64))
		v2 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpHmul32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul32u x y)
	// result: (SRLVconst (Select1 <typ.UInt64> (MULVU (ZeroExt32to64 x) (ZeroExt32to64 y))) [32])
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SRLVconst)
		v.AuxInt = int64ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpMIPS64MULVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpHmul64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul64 x y)
	// result: (Select0 (MULV x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64MULV, types.NewTuple(typ.Int64, typ.Int64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpHmul64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Hmul64u x y)
	// result: (Select0 (MULVU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64MULVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpIsInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (IsInBounds idx len)
	// result: (SGTU len idx)
	for {
		idx := v_0
		len := v_1
		v.reset(OpMIPS64SGTU)
		v.AddArg2(len, idx)
		return true
	}
}
func rewriteValueMIPS64_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsNonNil ptr)
	// result: (SGTU ptr (MOVVconst [0]))
	for {
		ptr := v_0
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(ptr, v0)
		return true
	}
}
func rewriteValueMIPS64_OpIsSliceInBounds(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsSliceInBounds idx len)
	// result: (XOR (MOVVconst [1]) (SGTU idx len))
	for {
		idx := v_0
		len := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v1.AddArg2(idx, len)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (XOR (MOVVconst [1]) (SGT (SignExt16to64 x) (SignExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGT, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (XOR (MOVVconst [1]) (SGTU (ZeroExt16to64 x) (ZeroExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32 x y)
	// result: (XOR (MOVVconst [1]) (SGT (SignExt32to64 x) (SignExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGT, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq32F x y)
	// result: (FPFlagTrue (CMPGEF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPS64CMPGEF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32U x y)
	// result: (XOR (MOVVconst [1]) (SGTU (ZeroExt32to64 x) (ZeroExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64 x y)
	// result: (XOR (MOVVconst [1]) (SGT x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGT, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Leq64F x y)
	// result: (FPFlagTrue (CMPGED y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPS64CMPGED, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpLeq64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq64U x y)
	// result: (XOR (MOVVconst [1]) (SGTU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v1.AddArg2(x, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (XOR (MOVVconst [1]) (SGT (SignExt8to64 x) (SignExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGT, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (XOR (MOVVconst [1]) (SGTU (ZeroExt8to64 x) (ZeroExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64XOR)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(x)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (SGT (SignExt16to64 y) (SignExt16to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGT)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (SGTU (ZeroExt16to64 y) (ZeroExt16to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32 x y)
	// result: (SGT (SignExt32to64 y) (SignExt32to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGT)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLess32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less32F x y)
	// result: (FPFlagTrue (CMPGTF y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPS64CMPGTF, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32U x y)
	// result: (SGTU (ZeroExt32to64 y) (ZeroExt32to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLess64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less64 x y)
	// result: (SGT y x)
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGT)
		v.AddArg2(y, x)
		return true
	}
}
func rewriteValueMIPS64_OpLess64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Less64F x y)
	// result: (FPFlagTrue (CMPGTD y x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64FPFlagTrue)
		v0 := b.NewValue0(v.Pos, OpMIPS64CMPGTD, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpLess64U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Less64U x y)
	// result: (SGTU y x)
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v.AddArg2(y, x)
		return true
	}
}
func rewriteValueMIPS64_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (SGT (SignExt8to64 y) (SignExt8to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGT)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (SGTU (ZeroExt8to64 y) (ZeroExt8to64 x))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(y)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpLoad(v *Value) bool {
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
		v.reset(OpMIPS64MOVBUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && t.IsSigned())
	// result: (MOVBload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && t.IsSigned()) {
			break
		}
		v.reset(OpMIPS64MOVBload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is8BitInt(t) && !t.IsSigned())
	// result: (MOVBUload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is8BitInt(t) && !t.IsSigned()) {
			break
		}
		v.reset(OpMIPS64MOVBUload)
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
		v.reset(OpMIPS64MOVHload)
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
		v.reset(OpMIPS64MOVHUload)
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
		v.reset(OpMIPS64MOVWload)
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
		v.reset(OpMIPS64MOVWUload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: (is64BitInt(t) || isPtr(t))
	// result: (MOVVload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitInt(t) || isPtr(t)) {
			break
		}
		v.reset(OpMIPS64MOVVload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (MOVFload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpMIPS64MOVFload)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (MOVDload ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpMIPS64MOVDload)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (MOVVaddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpMIPS64MOVVaddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (MOVVaddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpMIPS64MOVVaddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y))) (SLLV <t> x (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y))) (SLLV <t> x (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x64 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) y)) (SLLV <t> x y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v0.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v3.AddArg2(x, y)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS64_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y))) (SLLV <t> x (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y))) (SLLV <t> x (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x32 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y))) (SLLV <t> x (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x64 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) y)) (SLLV <t> x y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v0.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v3.AddArg2(x, y)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS64_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y))) (SLLV <t> x (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x16 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y))) (SLLV <t> x (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x32 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y))) (SLLV <t> x (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x64 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) y)) (SLLV <t> x y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v0.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v3.AddArg2(x, y)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS64_OpLsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x8 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y))) (SLLV <t> x (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y))) (SLLV <t> x (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y))) (SLLV <t> x (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x64 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) y)) (SLLV <t> x y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v0.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v3.AddArg2(x, y)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS64_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y))) (SLLV <t> x (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SLLV, t)
		v4.AddArg2(x, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpMIPS64ADDV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDV x (MOVVconst <t> [c]))
	// cond: is32Bit(c) && !t.IsPtr()
	// result: (ADDVconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPS64MOVVconst {
				continue
			}
			t := v_1.Type
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c) && !t.IsPtr()) {
				continue
			}
			v.reset(OpMIPS64ADDVconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADDV x (NEGV y))
	// result: (SUBV x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPS64NEGV {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpMIPS64SUBV)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64ADDVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDVconst [off1] (MOVVaddr [off2] {sym} ptr))
	// cond: is32Bit(off1+int64(off2))
	// result: (MOVVaddr [int32(off1)+int32(off2)] {sym} ptr)
	for {
		off1 := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		if !(is32Bit(off1 + int64(off2))) {
			break
		}
		v.reset(OpMIPS64MOVVaddr)
		v.AuxInt = int32ToAuxInt(int32(off1) + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg(ptr)
		return true
	}
	// match: (ADDVconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ADDVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c+d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(c + d)
		return true
	}
	// match: (ADDVconst [c] (ADDVconst [d] x))
	// cond: is32Bit(c+d)
	// result: (ADDVconst [c+d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c + d)) {
			break
		}
		v.reset(OpMIPS64ADDVconst)
		v.AuxInt = int64ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (ADDVconst [c] (SUBVconst [d] x))
	// cond: is32Bit(c-d)
	// result: (ADDVconst [c-d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64SUBVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c - d)) {
			break
		}
		v.reset(OpMIPS64ADDVconst)
		v.AuxInt = int64ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64AND(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AND x (MOVVconst [c]))
	// cond:
```