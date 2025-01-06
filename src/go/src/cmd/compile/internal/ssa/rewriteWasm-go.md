Response: 
Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteWasm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能

"""
// Code generated from _gen/Wasm.rules using 'go generate'; DO NOT EDIT.

package ssa

import "internal/buildcfg"
import "math"
import "cmd/compile/internal/types"

func rewriteValueWasm(v *Value) bool {
	switch v.Op {
	case OpAbs:
		v.Op = OpWasmF64Abs
		return true
	case OpAdd16:
		v.Op = OpWasmI64Add
		return true
	case OpAdd32:
		v.Op = OpWasmI64Add
		return true
	case OpAdd32F:
		v.Op = OpWasmF32Add
		return true
	case OpAdd64:
		v.Op = OpWasmI64Add
		return true
	case OpAdd64F:
		v.Op = OpWasmF64Add
		return true
	case OpAdd8:
		v.Op = OpWasmI64Add
		return true
	case OpAddPtr:
		v.Op = OpWasmI64Add
		return true
	case OpAddr:
		return rewriteValueWasm_OpAddr(v)
	case OpAnd16:
		v.Op = OpWasmI64And
		return true
	case OpAnd32:
		v.Op = OpWasmI64And
		return true
	case OpAnd64:
		v.Op = OpWasmI64And
		return true
	case OpAnd8:
		v.Op = OpWasmI64And
		return true
	case OpAndB:
		v.Op = OpWasmI64And
		return true
	case OpBitLen64:
		return rewriteValueWasm_OpBitLen64(v)
	case OpCeil:
		v.Op = OpWasmF64Ceil
		return true
	case OpClosureCall:
		v.Op = OpWasmLoweredClosureCall
		return true
	case OpCom16:
		return rewriteValueWasm_OpCom16(v)
	case OpCom32:
		return rewriteValueWasm_OpCom32(v)
	case OpCom64:
		return rewriteValueWasm_OpCom64(v)
	case OpCom8:
		return rewriteValueWasm_OpCom8(v)
	case OpCondSelect:
		v.Op = OpWasmSelect
		return true
	case OpConst16:
		return rewriteValueWasm_OpConst16(v)
	case OpConst32:
		return rewriteValueWasm_OpConst32(v)
	case OpConst32F:
		v.Op = OpWasmF32Const
		return true
	case OpConst64:
		v.Op = OpWasmI64Const
		return true
	case OpConst64F:
		v.Op = OpWasmF64Const
		return true
	case OpConst8:
		return rewriteValueWasm_OpConst8(v)
	case OpConstBool:
		return rewriteValueWasm_OpConstBool(v)
	case OpConstNil:
		return rewriteValueWasm_OpConstNil(v)
	case OpConvert:
		v.Op = OpWasmLoweredConvert
		return true
	case OpCopysign:
		v.Op = OpWasmF64Copysign
		return true
	case OpCtz16:
		return rewriteValueWasm_OpCtz16(v)
	case OpCtz16NonZero:
		v.Op = OpWasmI64Ctz
		return true
	case OpCtz32:
		return rewriteValueWasm_OpCtz32(v)
	case OpCtz32NonZero:
		v.Op = OpWasmI64Ctz
		return true
	case OpCtz64:
		v.Op = OpWasmI64Ctz
		return true
	case OpCtz64NonZero:
		v.Op = OpWasmI64Ctz
		return true
	case OpCtz8:
		return rewriteValueWasm_OpCtz8(v)
	case OpCtz8NonZero:
		v.Op = OpWasmI64Ctz
		return true
	case OpCvt32Fto32:
		v.Op = OpWasmI64TruncSatF32S
		return true
	case OpCvt32Fto32U:
		v.Op = OpWasmI64TruncSatF32U
		return true
	case OpCvt32Fto64:
		v.Op = OpWasmI64TruncSatF32S
		return true
	case OpCvt32Fto64F:
		v.Op = OpWasmF64PromoteF32
		return true
	case OpCvt32Fto64U:
		v.Op = OpWasmI64TruncSatF32U
		return true
	case OpCvt32Uto32F:
		return rewriteValueWasm_OpCvt32Uto32F(v)
	case OpCvt32Uto64F:
		return rewriteValueWasm_OpCvt32Uto64F(v)
	case OpCvt32to32F:
		return rewriteValueWasm_OpCvt32to32F(v)
	case OpCvt32to64F:
		return rewriteValueWasm_OpCvt32to64F(v)
	case OpCvt64Fto32:
		v.Op = OpWasmI64TruncSatF64S
		return true
	case OpCvt64Fto32F:
		v.Op = OpWasmF32DemoteF64
		return true
	case OpCvt64Fto32U:
		v.Op = OpWasmI64TruncSatF64U
		return true
	case OpCvt64Fto64:
		v.Op = OpWasmI64TruncSatF64S
		return true
	case OpCvt64Fto64U:
		v.Op = OpWasmI64TruncSatF64U
		return true
	case OpCvt64Uto32F:
		v.Op = OpWasmF32ConvertI64U
		return true
	case OpCvt64Uto64F:
		v.Op = OpWasmF64ConvertI64U
		return true
	case OpCvt64to32F:
		v.Op = OpWasmF32ConvertI64S
		return true
	case OpCvt64to64F:
		v.Op = OpWasmF64ConvertI64S
		return true
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv16:
		return rewriteValueWasm_OpDiv16(v)
	case OpDiv16u:
		return rewriteValueWasm_OpDiv16u(v)
	case OpDiv32:
		return rewriteValueWasm_OpDiv32(v)
	case OpDiv32F:
		v.Op = OpWasmF32Div
		return true
	case OpDiv32u:
		return rewriteValueWasm_OpDiv32u(v)
	case OpDiv64:
		return rewriteValueWasm_OpDiv64(v)
	case OpDiv64F:
		v.Op = OpWasmF64Div
		return true
	case OpDiv64u:
		v.Op = OpWasmI64DivU
		return true
	case OpDiv8:
		return rewriteValueWasm_OpDiv8(v)
	case OpDiv8u:
		return rewriteValueWasm_OpDiv8u(v)
	case OpEq16:
		return rewriteValueWasm_OpEq16(v)
	case OpEq32:
		return rewriteValueWasm_OpEq32(v)
	case OpEq32F:
		v.Op = OpWasmF32Eq
		return true
	case OpEq64:
		v.Op = OpWasmI64Eq
		return true
	case OpEq64F:
		v.Op = OpWasmF64Eq
		return true
	case OpEq8:
		return rewriteValueWasm_OpEq8(v)
	case OpEqB:
		v.Op = OpWasmI64Eq
		return true
	case OpEqPtr:
		v.Op = OpWasmI64Eq
		return true
	case OpFloor:
		v.Op = OpWasmF64Floor
		return true
	case OpGetCallerPC:
		v.Op = OpWasmLoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = OpWasmLoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = OpWasmLoweredGetClosurePtr
		return true
	case OpInterCall:
		v.Op = OpWasmLoweredInterCall
		return true
	case OpIsInBounds:
		v.Op = OpWasmI64LtU
		return true
	case OpIsNonNil:
		return rewriteValueWasm_OpIsNonNil(v)
	case OpIsSliceInBounds:
		v.Op = OpWasmI64LeU
		return true
	case OpLeq16:
		return rewriteValueWasm_OpLeq16(v)
	case OpLeq16U:
		return rewriteValueWasm_OpLeq16U(v)
	case OpLeq32:
		return rewriteValueWasm_OpLeq32(v)
	case OpLeq32F:
		v.Op = OpWasmF32Le
		return true
	case OpLeq32U:
		return rewriteValueWasm_OpLeq32U(v)
	case OpLeq64:
		v.Op = OpWasmI64LeS
		return true
	case OpLeq64F:
		v.Op = OpWasmF64Le
		return true
	case OpLeq64U:
		v.Op = OpWasmI64LeU
		return true
	case OpLeq8:
		return rewriteValueWasm_OpLeq8(v)
	case OpLeq8U:
		return rewriteValueWasm_OpLeq8U(v)
	case OpLess16:
		return rewriteValueWasm_OpLess16(v)
	case OpLess16U:
		return rewriteValueWasm_OpLess16U(v)
	case OpLess32:
		return rewriteValueWasm_OpLess32(v)
	case OpLess32F:
		v.Op = OpWasmF32Lt
		return true
	case OpLess32U:
		return rewriteValueWasm_OpLess32U(v)
	case OpLess64:
		v.Op = OpWasmI64LtS
		return true
	case OpLess64F:
		v.Op = OpWasmF64Lt
		return true
	case OpLess64U:
		v.Op = OpWasmI64LtU
		return true
	case OpLess8:
		return rewriteValueWasm_OpLess8(v)
	case OpLess8U:
		return rewriteValueWasm_OpLess8U(v)
	case OpLoad:
		return rewriteValueWasm_OpLoad(v)
	case OpLocalAddr:
		return rewriteValueWasm_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValueWasm_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValueWasm_OpLsh16x32(v)
	case OpLsh16x64:
		v.Op = OpLsh64x64
		return true
	case OpLsh16x8:
		return rewriteValueWasm_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValueWasm_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValueWasm_OpLsh32x32(v)
	case OpLsh32x64:
		v.Op = OpLsh64x64
		return true
	case OpLsh32x8:
		return rewriteValueWasm_OpLsh32x8(v)
	case OpLsh64x16:
		return rewriteValueWasm_OpLsh64x16(v)
	case OpLsh64x32:
		return rewriteValueWasm_OpLsh64x32(v)
	case OpLsh64x64:
		return rewriteValueWasm_OpLsh64x64(v)
	case OpLsh64x8:
		return rewriteValueWasm_OpLsh64x8(v)
	case OpLsh8x16:
		return rewriteValueWasm_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValueWasm_OpLsh8x32(v)
	case OpLsh8x64:
		v.Op = OpLsh64x64
		return true
	case OpLsh8x8:
		return rewriteValueWasm_OpLsh8x8(v)
	case OpMod16:
		return rewriteValueWasm_OpMod16(v)
	case OpMod16u:
		return rewriteValueWasm_OpMod16u(v)
	case OpMod32:
		return rewriteValueWasm_OpMod32(v)
	case OpMod32u:
		return rewriteValueWasm_OpMod32u(v)
	case OpMod64:
		return rewriteValueWasm_OpMod64(v)
	case OpMod64u:
		v.Op = OpWasmI64RemU
		return true
	case OpMod8:
		return rewriteValueWasm_OpMod8(v)
	case OpMod8u:
		return rewriteValueWasm_OpMod8u(v)
	case OpMove:
		return rewriteValueWasm_OpMove(v)
	case OpMul16:
		v.Op = OpWasmI64Mul
		return true
	case OpMul32:
		v.Op = OpWasmI64Mul
		return true
	case OpMul32F:
		v.Op = OpWasmF32Mul
		return true
	case OpMul64:
		v.Op = OpWasmI64Mul
		return true
	case OpMul64F:
		v.Op = OpWasmF64Mul
		return true
	case OpMul8:
		v.Op = OpWasmI64Mul
		return true
	case OpNeg16:
		return rewriteValueWasm_OpNeg16(v)
	case OpNeg32:
		return rewriteValueWasm_OpNeg32(v)
	case OpNeg32F:
		v.Op = OpWasmF32Neg
		return true
	case OpNeg64:
		return rewriteValueWasm_OpNeg64(v)
	case OpNeg64F:
		v.Op = OpWasmF64Neg
		return true
	case OpNeg8:
		return rewriteValueWasm_OpNeg8(v)
	case OpNeq16:
		return rewriteValueWasm_OpNeq16(v)
	case OpNeq32:
		return rewriteValueWasm_OpNeq32(v)
	case OpNeq32F:
		v.Op = OpWasmF32Ne
		return true
	case OpNeq64:
		v.Op = OpWasmI64Ne
		return true
	case OpNeq64F:
		v.Op = OpWasmF64Ne
		return true
	case OpNeq8:
		return rewriteValueWasm_OpNeq8(v)
	case OpNeqB:
		v.Op = OpWasmI64Ne
		return true
	case OpNeqPtr:
		v.Op = OpWasmI64Ne
		return true
	case OpNilCheck:
		v.Op = OpWasmLoweredNilCheck
		return true
	case OpNot:
		v.Op = OpWasmI64Eqz
		return true
	case OpOffPtr:
		v.Op = OpWasmI64AddConst
		return true
	case OpOr16:
		v.Op = OpWasmI64Or
		return true
	case OpOr32:
		v.Op = OpWasmI64Or
		return true
	case OpOr64:
		v.Op = OpWasmI64Or
		return true
	case OpOr8:
		v.Op = OpWasmI64Or
		return true
	case OpOrB:
		v.Op = OpWasmI64Or
		return true
	case OpPopCount16:
		return rewriteValueWasm_OpPopCount16(v)
	case OpPopCount32:
		return rewriteValueWasm_OpPopCount32(v)
	case OpPopCount64:
		v.Op = OpWasmI64Popcnt
		return true
	case OpPopCount8:
		return rewriteValueWasm_OpPopCount8(v)
	case OpRotateLeft16:
		return rewriteValueWasm_OpRotateLeft16(v)
	case OpRotateLeft32:
		v.Op = OpWasmI32Rotl
		return true
	case OpRotateLeft64:
		v.Op = OpWasmI64Rotl
		return true
	case OpRotateLeft8:
		return rewriteValueWasm_OpRotateLeft8(v)
	case OpRound32F:
		v.Op = OpCopy
		return true
	case OpRound64F:
		v.Op = OpCopy
		return true
	case OpRoundToEven:
		v.Op = OpWasmF64Nearest
		return true
	case OpRsh16Ux16:
		return rewriteValueWasm_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValueWasm_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValueWasm_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValueWasm_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValueWasm_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValueWasm_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValueWasm_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValueWasm_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValueWasm_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValueWasm_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValueWasm_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValueWasm_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValueWasm_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValueWasm_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValueWasm_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValueWasm_OpRsh32x8(v)
	case OpRsh64Ux16:
		return rewriteValueWasm_OpRsh64Ux16(v)
	case OpRsh64Ux32:
		return rewriteValueWasm_OpRsh64Ux32(v)
	case OpRsh64Ux64:
		return rewriteValueWasm_OpRsh64Ux64(v)
	case OpRsh64Ux8:
		return rewriteValueWasm_OpRsh64Ux8(v)
	case OpRsh64x16:
		return rewriteValueWasm_OpRsh64x16(v)
	case OpRsh64x32:
		return rewriteValueWasm_OpRsh64x32(v)
	case OpRsh64x64:
		return rewriteValueWasm_OpRsh64x64(v)
	case OpRsh64x8:
		return rewriteValueWasm_OpRsh64x8(v)
	case OpRsh8Ux16:
		return rewriteValueWasm_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValueWasm_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValueWasm_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValueWasm_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValueWasm_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValueWasm_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValueWasm_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValueWasm_OpRsh8x8(v)
	case OpSignExt16to32:
		return rewriteValueWasm_OpSignExt16to32(v)
	case OpSignExt16to64:
		return rewriteValueWasm_OpSignExt16to64(v)
	case OpSignExt32to64:
		return rewriteValueWasm_OpSignExt32to64(v)
	case OpSignExt8to16:
		return rewriteValueWasm_OpSignExt8to16(v)
	case OpSignExt8to32:
		return rewriteValueWasm_OpSignExt8to32(v)
	case OpSignExt8to64:
		return rewriteValueWasm_OpSignExt8to64(v)
	case OpSlicemask:
		return rewriteValueWasm_OpSlicemask(v)
	case OpSqrt:
		v.Op = OpWasmF64Sqrt
		return true
	case OpSqrt32:
		v.Op = OpWasmF32Sqrt
		return true
	case OpStaticCall:
		v.Op = OpWasmLoweredStaticCall
		return true
	case OpStore:
		return rewriteValueWasm_OpStore(v)
	case OpSub16:
		v.Op = OpWasmI64Sub
		return true
	case OpSub32:
		v.Op = OpWasmI64Sub
		return true
	case OpSub32F:
		v.Op = OpWasmF32Sub
		return true
	case OpSub64:
		v.Op = OpWasmI64Sub
		return true
	case OpSub64F:
		v.Op = OpWasmF64Sub
		return true
	case OpSub8:
		v.Op = OpWasmI64Sub
		return true
	case OpSubPtr:
		v.Op = OpWasmI64Sub
		return true
	case OpTailCall:
		v.Op = OpWasmLoweredTailCall
		return true
	case OpTrunc:
		v.Op = OpWasmF64Trunc
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
		v.Op = OpWasmLoweredWB
		return true
	case OpWasmF64Add:
		return rewriteValueWasm_OpWasmF64Add(v)
	case OpWasmF64Mul:
		return rewriteValueWasm_OpWasmF64Mul(v)
	case OpWasmI64Add:
		return rewriteValueWasm_OpWasmI64Add(v)
	case OpWasmI64AddConst:
		return rewriteValueWasm_OpWasmI64AddConst(v)
	case OpWasmI64And:
		return rewriteValueWasm_OpWasmI64And(v)
	case OpWasmI64Eq:
		return rewriteValueWasm_OpWasmI64Eq(v)
	case OpWasmI64Eqz:
		return rewriteValueWasm_OpWasmI64Eqz(v)
	case OpWasmI64LeU:
		return rewriteValueWasm_OpWasmI64LeU(v)
	case OpWasmI64Load:
		return rewriteValueWasm_OpWasmI64Load(v)
	case OpWasmI64Load16S:
		return rewriteValueWasm_OpWasmI64Load16S(v)
	case OpWasmI64Load16U:
		return rewriteValueWasm_OpWasmI64Load16U(v)
	case OpWasmI64Load32S:
		return rewriteValueWasm_OpWasmI64Load32S(v)
	case OpWasmI64Load32U:
		return rewriteValueWasm_OpWasmI64Load32U(v)
	case OpWasmI64Load8S:
		return rewriteValueWasm_OpWasmI64Load8S(v)
	case OpWasmI64Load8U:
		return rewriteValueWasm_OpWasmI64Load8U(v)
	case OpWasmI64LtU:
		return rewriteValueWasm_OpWasmI64LtU(v)
	case OpWasmI64Mul:
		return rewriteValueWasm_OpWasmI64Mul(v)
	case OpWasmI64Ne:
		return rewriteValueWasm_OpWasmI64Ne(v)
	case OpWasmI64Or:
		return rewriteValueWasm_OpWasmI64Or(v)
	case OpWasmI64Shl:
		return rewriteValueWasm_OpWasmI64Shl(v)
	case OpWasmI64ShrS:
		return rewriteValueWasm_OpWasmI64ShrS(v)
	case OpWasmI64ShrU:
		return rewriteValueWasm_OpWasmI64ShrU(v)
	case OpWasmI64Store:
		return rewriteValueWasm_OpWasmI64Store(v)
	case OpWasmI64Store16:
		return rewriteValueWasm_OpWasmI64Store16(v)
	case OpWasmI64Store32:
		return rewriteValueWasm_OpWasmI64Store32(v)
	case OpWasmI64Store8:
		return rewriteValueWasm_OpWasmI64Store8(v)
	case OpWasmI64Xor:
		return rewriteValueWasm_OpWasmI64Xor(v)
	case OpXor16:
		v.Op = OpWasmI64Xor
		return true
	case OpXor32:
		v.Op = OpWasmI64Xor
		return true
	case OpXor64:
		v.Op = OpWasmI64Xor
		return true
	case OpXor8:
		v.Op = OpWasmI64Xor
		return true
	case OpZero:
		return rewriteValueWasm_OpZero(v)
	case OpZeroExt16to32:
		return rewriteValueWasm_OpZeroExt16to32(v)
	case OpZeroExt16to64:
		return rewriteValueWasm_OpZeroExt16to64(v)
	case OpZeroExt32to64:
		return rewriteValueWasm_OpZeroExt32to64(v)
	case OpZeroExt8to16:
		return rewriteValueWasm_OpZeroExt8to16(v)
	case OpZeroExt8to32:
		return rewriteValueWasm_OpZeroExt8to32(v)
	case OpZeroExt8to64:
		return rewriteValueWasm_OpZeroExt8to64(v)
	}
	return false
}
func rewriteValueWasm_OpAddr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Addr {sym} base)
	// result: (LoweredAddr {sym} [0] base)
	for {
		sym := auxToSym(v.Aux)
		base := v_0
		v.reset(OpWasmLoweredAddr)
		v.AuxInt = int32ToAuxInt(0)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
}
func rewriteValueWasm_OpBitLen64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (BitLen64 x)
	// result: (I64Sub (I64Const [64]) (I64Clz x))
	for {
		x := v_0
		v.reset(OpWasmI64Sub)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Clz, typ.Int64)
		v1.AddArg(x)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpCom16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com16 x)
	// result: (I64Xor x (I64Const [-1]))
	for {
		x := v_0
		v.reset(OpWasmI64Xor)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(-1)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpCom32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com32 x)
	// result: (I64Xor x (I64Const [-1]))
	for {
		x := v_0
		v.reset(OpWasmI64Xor)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(-1)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpCom64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com64 x)
	// result: (I64Xor x (I64Const [-1]))
	for {
		x := v_0
		v.reset(OpWasmI64Xor)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(-1)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpCom8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Com8 x)
	// result: (I64Xor x (I64Const [-1]))
	for {
		x := v_0
		v.reset(OpWasmI64Xor)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(-1)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpConst16(v *Value) bool {
	// match: (Const16 [c])
	// result: (I64Const [int64(c)])
	for {
		c := auxIntToInt16(v.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
}
func rewriteValueWasm_OpConst32(v *Value) bool {
	// match: (Const32 [c])
	// result: (I64Const [int64(c)])
	for {
		c := auxIntToInt32(v.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
}
func rewriteValueWasm_OpConst8(v *Value) bool {
	// match: (Const8 [c])
	// result: (I64Const [int64(c)])
	for {
		c := auxIntToInt8(v.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(int64(c))
		return true
	}
}
func rewriteValueWasm_OpConstBool(v *Value) bool {
	// match: (ConstBool [c])
	// result: (I64Const [b2i(c)])
	for {
		c := auxIntToBool(v.AuxInt)
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(b2i(c))
		return true
	}
}
func rewriteValueWasm_OpConstNil(v *Value) bool {
	// match: (ConstNil)
	// result: (I64Const [0])
	for {
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
}
func rewriteValueWasm_OpCtz16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz16 x)
	// result: (I64Ctz (I64Or x (I64Const [0x10000])))
	for {
		x := v_0
		v.reset(OpWasmI64Ctz)
		v0 := b.NewValue0(v.Pos, OpWasmI64Or, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0x10000)
		v0.AddArg2(x, v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpCtz32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz32 x)
	// result: (I64Ctz (I64Or x (I64Const [0x100000000])))
	for {
		x := v_0
		v.reset(OpWasmI64Ctz)
		v0 := b.NewValue0(v.Pos, OpWasmI64Or, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0x100000000)
		v0.AddArg2(x, v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpCtz8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Ctz8 x)
	// result: (I64Ctz (I64Or x (I64Const [0x100])))
	for {
		x := v_0
		v.reset(OpWasmI64Ctz)
		v0 := b.NewValue0(v.Pos, OpWasmI64Or, typ.Int64)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0x100)
		v0.AddArg2(x, v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpCvt32Uto32F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt32Uto32F x)
	// result: (F32ConvertI64U (ZeroExt32to64 x))
	for {
		x := v_0
		v.reset(OpWasmF32ConvertI64U)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpCvt32Uto64F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt32Uto64F x)
	// result: (F64ConvertI64U (ZeroExt32to64 x))
	for {
		x := v_0
		v.reset(OpWasmF64ConvertI64U)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpCvt32to32F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt32to32F x)
	// result: (F32ConvertI64S (SignExt32to64 x))
	for {
		x := v_0
		v.reset(OpWasmF32ConvertI64S)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpCvt32to64F(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Cvt32to64F x)
	// result: (F64ConvertI64S (SignExt32to64 x))
	for {
		x := v_0
		v.reset(OpWasmF64ConvertI64S)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpDiv16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16 [false] x y)
	// result: (I64DivS (SignExt16to64 x) (SignExt16to64 y))
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpWasmI64DivS)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueWasm_OpDiv16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div16u x y)
	// result: (I64DivU (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64DivU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpDiv32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32 [false] x y)
	// result: (I64DivS (SignExt32to64 x) (SignExt32to64 y))
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpWasmI64DivS)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueWasm_OpDiv32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div32u x y)
	// result: (I64DivU (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64DivU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpDiv64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Div64 [false] x y)
	// result: (I64DivS x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpWasmI64DivS)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueWasm_OpDiv8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8 x y)
	// result: (I64DivS (SignExt8to64 x) (SignExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64DivS)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpDiv8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Div8u x y)
	// result: (I64DivU (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64DivU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpEq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq16 x y)
	// result: (I64Eq (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64Eq)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpEq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq32 x y)
	// result: (I64Eq (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64Eq)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpEq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Eq8 x y)
	// result: (I64Eq (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64Eq)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpIsNonNil(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (IsNonNil p)
	// result: (I64Eqz (I64Eqz p))
	for {
		p := v_0
		v.reset(OpWasmI64Eqz)
		v0 := b.NewValue0(v.Pos, OpWasmI64Eqz, typ.Bool)
		v0.AddArg(p)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpLeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16 x y)
	// result: (I64LeS (SignExt16to64 x) (SignExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LeS)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLeq16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq16U x y)
	// result: (I64LeU (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LeU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32 x y)
	// result: (I64LeS (SignExt32to64 x) (SignExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LeS)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLeq32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq32U x y)
	// result: (I64LeU (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LeU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8 x y)
	// result: (I64LeS (SignExt8to64 x) (SignExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LeS)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLeq8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Leq8U x y)
	// result: (I64LeU (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LeU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLess16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16 x y)
	// result: (I64LtS (SignExt16to64 x) (SignExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LtS)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLess16U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less16U x y)
	// result: (I64LtU (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LtU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLess32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32 x y)
	// result: (I64LtS (SignExt32to64 x) (SignExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LtS)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLess32U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less32U x y)
	// result: (I64LtU (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LtU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLess8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8 x y)
	// result: (I64LtS (SignExt8to64 x) (SignExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LtS)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLess8U(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Less8U x y)
	// result: (I64LtU (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64LtU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Load <t> ptr mem)
	// cond: is32BitFloat(t)
	// result: (F32Load ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is32BitFloat(t)) {
			break
		}
		v.reset(OpWasmF32Load)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: is64BitFloat(t)
	// result: (F64Load ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(is64BitFloat(t)) {
			break
		}
		v.reset(OpWasmF64Load)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.Size() == 8
	// result: (I64Load ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.Size() == 8) {
			break
		}
		v.reset(OpWasmI64Load)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.Size() == 4 && !t.IsSigned()
	// result: (I64Load32U ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.Size() == 4 && !t.IsSigned()) {
			break
		}
		v.reset(OpWasmI64Load32U)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.Size() == 4 && t.IsSigned()
	// result: (I64Load32S ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.Size() == 4 && t.IsSigned()) {
			break
		}
		v.reset(OpWasmI64Load32S)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.Size() == 2 && !t.IsSigned()
	// result: (I64Load16U ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.Size() == 2 && !t.IsSigned()) {
			break
		}
		v.reset(OpWasmI64Load16U)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.Size() == 2 && t.IsSigned()
	// result: (I64Load16S ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.Size() == 2 && t.IsSigned()) {
			break
		}
		v.reset(OpWasmI64Load16S)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.Size() == 1 && !t.IsSigned()
	// result: (I64Load8U ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.Size() == 1 && !t.IsSigned()) {
			break
		}
		v.reset(OpWasmI64Load8U)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.Size() == 1 && t.IsSigned()
	// result: (I64Load8S ptr mem)
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.Size() == 1 && t.IsSigned()) {
			break
		}
		v.reset(OpWasmI64Load8S)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpLocalAddr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (LocalAddr <t> {sym} base mem)
	// cond: t.Elem().HasPointers()
	// result: (LoweredAddr {sym} (SPanchored base mem))
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		mem := v_1
		if !(t.Elem().HasPointers()) {
			break
		}
		v.reset(OpWasmLoweredAddr)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpSPanchored, typ.Uintptr)
		v0.AddArg2(base, mem)
		v.AddArg(v0)
		return true
	}
	// match: (LocalAddr <t> {sym} base _)
	// cond: !t.Elem().HasPointers()
	// result: (LoweredAddr {sym} base)
	for {
		t := v.Type
		sym := auxToSym(v.Aux)
		base := v_0
		if !(!t.Elem().HasPointers()) {
			break
		}
		v.reset(OpWasmLoweredAddr)
		v.Aux = symToAux(sym)
		v.AddArg(base)
		return true
	}
	return false
}
func rewriteValueWasm_OpLsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x16 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x32 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh16x8 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x16 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x32 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x16 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x32 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x64 x y)
	// cond: shiftIsBounded(v)
	// result: (I64Shl x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpWasmI64Shl)
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x64 x (I64Const [c]))
	// cond: uint64(c) < 64
	// result: (I64Shl x (I64Const [c]))
	for {
		x := v_0
		if v_1.Op != OpWasmI64Const {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 64) {
			break
		}
		v.reset(OpWasmI64Shl)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Lsh64x64 x (I64Const [c]))
	// cond: uint64(c) >= 64
	// result: (I64Const [0])
	for {
		if v_1.Op != OpWasmI64Const {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Lsh64x64 x y)
	// result: (Select (I64Shl x y) (I64Const [0]) (I64LtU y (I64Const [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmSelect)
		v0 := b.NewValue0(v.Pos, OpWasmI64Shl, typ.Int64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpWasmI64LtU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(y, v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueWasm_OpLsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x8 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 [c] x y)
	// result: (Lsh64x64 [c] x (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpLsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 [false] x y)
	// result: (I64RemS (SignExt16to64 x) (SignExt16to64 y))
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpWasmI64RemS)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueWasm_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (I64RemU (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64RemU)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32 [false] x y)
	// result: (I64RemS (SignExt32to64 x) (SignExt32to64 y))
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpWasmI64RemS)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueWasm_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32u x y)
	// result: (I64RemU (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64RemU)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod64 [false] x y)
	// result: (I64RemS x y)
	for {
		if auxIntToBool(v.AuxInt) != false {
			break
		}
		x := v_0
		y := v_1
		v.reset(OpWasmI64RemS)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueWasm_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (I64RemS (SignExt8to64 x) (SignExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64RemS)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (I64RemU (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64RemU)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
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
	// result: (I64Store8 dst (I64Load8U src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpWasmI64Store8)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load8U, typ.UInt8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (I64Store16 dst (I64Load16U src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpWasmI64Store16)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load16U, typ.UInt16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (I64Store32 dst (I64Load32U src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpWasmI64Store32)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load32U, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [8] dst src mem)
	// result: (I64Store dst (I64Load src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpWasmI64Store)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load, typ.UInt64)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [16] dst src mem)
	// result: (I64Store [8] dst (I64Load [8] src mem) (I64Store dst (I64Load src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpWasmI64Store)
		v.AuxInt = int64ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpWasmI64Load, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (I64Store8 [2] dst (I64Load8U [2] src mem) (I64Store16 dst (I64Load16U src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpWasmI64Store8)
		v.AuxInt = int64ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load8U, typ.UInt8)
		v0.AuxInt = int64ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store16, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpWasmI64Load16U, typ.UInt16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [5] dst src mem)
	// result: (I64Store8 [4] dst (I64Load8U [4] src mem) (I64Store32 dst (I64Load32U src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpWasmI64Store8)
		v.AuxInt = int64ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load8U, typ.UInt8)
		v0.AuxInt = int64ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store32, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpWasmI64Load32U, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [6] dst src mem)
	// result: (I64Store16 [4] dst (I64Load16U [4] src mem) (I64Store32 dst (I64Load32U src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpWasmI64Store16)
		v.AuxInt = int64ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load16U, typ.UInt16)
		v0.AuxInt = int64ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store32, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpWasmI64Load32U, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [7] dst src mem)
	// result: (I64Store32 [3] dst (I64Load32U [3] src mem) (I64Store32 dst (I64Load32U src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpWasmI64Store32)
		v.AuxInt = int64ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load32U, typ.UInt32)
		v0.AuxInt = int64ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store32, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpWasmI64Load32U, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 8 && s < 16
	// result: (I64Store [s-8] dst (I64Load [s-8] src mem) (I64Store dst (I64Load src mem) mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 8 && s < 16) {
			break
		}
		v.reset(OpWasmI64Store)
		v.AuxInt = int64ToAuxInt(s - 8)
		v0 := b.NewValue0(v.Pos, OpWasmI64Load, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(s - 8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpWasmI64Store, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpWasmI64Load, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: logLargeCopy(v, s)
	// result: (LoweredMove [s] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(logLargeCopy(v, s)) {
			break
		}
		v.reset(OpWasmLoweredMove)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg3(dst, src, mem)
		return true
	}
	return false
}
func rewriteValueWasm_OpNeg16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neg16 x)
	// result: (I64Sub (I64Const [0]) x)
	for {
		x := v_0
		v.reset(OpWasmI64Sub)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueWasm_OpNeg32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neg32 x)
	// result: (I64Sub (I64Const [0]) x)
	for {
		x := v_0
		v.reset(OpWasmI64Sub)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueWasm_OpNeg64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neg64 x)
	// result: (I64Sub (I64Const [0]) x)
	for {
		x := v_0
		v.reset(OpWasmI64Sub)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueWasm_OpNeg8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neg8 x)
	// result: (I64Sub (I64Const [0]) x)
	for {
		x := v_0
		v.reset(OpWasmI64Sub)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueWasm_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (I64Ne (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64Ne)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32 x y)
	// result: (I64Ne (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64Ne)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (I64Ne (ZeroExt8to64 x) (ZeroExt8to64 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmI64Ne)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpPopCount16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount16 x)
	// result: (I64Popcnt (ZeroExt16to64 x))
	for {
		x := v_0
		v.reset(OpWasmI64Popcnt)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpPopCount32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount32 x)
	// result: (I64Popcnt (ZeroExt32to64 x))
	for {
		x := v_0
		v.reset(OpWasmI64Popcnt)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpPopCount8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount8 x)
	// result: (I64Popcnt (ZeroExt8to64 x))
	for {
		x := v_0
		v.reset(OpWasmI64Popcnt)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueWasm_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (I64Const [c]))
	// result: (Or16 (Lsh16x64 <t> x (I64Const [c&15])) (Rsh16Ux64 <t> x (I64Const [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpWasmI64Const {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v3 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v3.AuxInt = int64ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueWasm_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (I64Const [c]))
	// result: (Or8 (Lsh8x64 <t> x (I64Const [c&7])) (Rsh8Ux64 <t> x (I64Const [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpWasmI64Const {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v3 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v3.AuxInt = int64ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueWasm_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt16to64 x) (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt16to64 x) (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt16to64 x) y)
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueWasm_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt16to64 x) (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 [c] x y)
	// result: (Rsh64x64 [c] (SignExt16to64 x) (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 [c] x y)
	// result: (Rsh64x64 [c] (SignExt16to64 x) (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 [c] x y)
	// result: (Rsh64x64 [c] (SignExt16to64 x) y)
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueWasm_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 [c] x y)
	// result: (Rsh64x64 [c] (SignExt16to64 x) (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt32to64 x) (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux32 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt32to64 x) (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt32to64 x) y)
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueWasm_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 [c] x y)
	// result: (Rsh64Ux64 [c] (ZeroExt32to64 x) (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 [c] x y)
	// result: (Rsh64x64 [c] (SignExt32to64 x) (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x32 [c] x y)
	// result: (Rsh64x64 [c] (SignExt32to64 x) (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x64 [c] x y)
	// result: (Rsh64x64 [c] (SignExt32to64 x) y)
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
}
func rewriteValueWasm_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 [c] x y)
	// result: (Rsh64x64 [c] (SignExt32to64 x) (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64x64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueWasm_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux16 [c] x y)
	// result: (Rsh64Ux64 [c] x (ZeroExt16to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux32 [c] x y)
	// result: (Rsh64Ux64 [c] x (ZeroExt32to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueWasm_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux64 x y)
	// cond: shiftIsBounded(v)
	// result: (I64ShrU x y)
	for {
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpWasmI64ShrU)
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64Ux64 x (I64Const [c]))
	// cond: uint64(c) < 64
	// result: (I64ShrU x (I64Const [c]))
	for {
		x := v_0
		if v_1.Op != OpWasmI64Const {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) < 64) {
			break
		}
		v.reset(OpWasmI64ShrU)
		v0 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	// match: (Rsh64Ux64 x (I64Const [c]))
	// cond: uint64(c) >= 64
	// result: (I64Const [0])
	for {
		if v_1.Op != OpWasmI64Const {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(uint64(c) >= 64) {
			break
		}
		v.reset(OpWasmI64Const)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Rsh64Ux64 x y)
	// result: (Select (I64ShrU x y) (I64Const [0]) (I64LtU y (I64Const [64])))
	for {
		x := v_0
		y := v_1
		v.reset(OpWasmSelect)
		v0 := b.NewValue0(v.Pos, OpWasmI64ShrU, typ.Int64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpWasmI64LtU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpWasmI64Const, typ.Int64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(y, v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
}
func rewriteValueWasm_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux8 [c] x y)
	// result: (Rsh64Ux64 [c] x (ZeroExt8to64 y))
	for {
		c := auxIntToBool(v.AuxInt)
		x := v_0
		y := v_1
		v.reset(OpRsh64Ux64)
		v.AuxInt = boolToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func re
"""




```