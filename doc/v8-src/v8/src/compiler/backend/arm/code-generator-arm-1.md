Response: The user wants a summary of the functionality of the provided C++ code snippet. This code seems to be part of a code generator for the ARM architecture within the V8 JavaScript engine. It appears to handle the compilation of various operations, including floating-point operations, stack manipulations, and SIMD (NEON) instructions.

To provide a good summary, I will go through the code block by block, identifying the type of operation each case handles. Then, I'll generalize the functionality.

If the code is related to JavaScript functionality, I need to provide a JavaScript example. This will likely involve showing how a particular JavaScript operation might be translated into one of the ARM instructions handled in this code.

Here's a breakdown of the cases and their likely functionality:

*   `kArmFloat32Min`, `kArmFloat64Min`:  Floating-point minimum operations.
*   `kArmFloat64SilenceNaN`: Handling of NaN (Not-a-Number) values.
*   `kArmPush`, `kArmPoke`, `kArmPeek`: Stack manipulation (pushing, writing, reading).
*   `kArmDmbIsh`, `kArmDsbIsb`: Memory barrier instructions.
*   `kArmVmullLow`, `kArmVmullHigh`, `kArmVpadal`, `kArmVpaddl`:  NEON vector multiplication and addition operations.
*   `kArmF64x2Splat`, `kArmF64x2ExtractLane`, `kArmF64x2ReplaceLane`, `kArmF64x2Abs`, `kArmF64x2Neg`, `kArmF64x2Sqrt`, `kArmF64x2Add`, `kArmF64x2Sub`, `kArmF64x2Mul`, `kArmF64x2Div`, `kArmF64x2Min`, `kArmF64x2Max`, `kArmF64x2Eq`, `kArmF64x2Ne`, `kArmF64x2Lt`, `kArmF64x2Le`, `kArmF64x2Pmin`, `kArmF64x2Pmax`, `kArmF64x2Qfma`, `kArmF64x2Qfms`, `kArmF64x2Ceil`, `kArmF64x2Floor`, `kArmF64x2Trunc`, `kArmF64x2NearestInt`, `kArmF64x2ConvertLowI32x4S`, `kArmF64x2ConvertLowI32x4U`, `kArmF64x2PromoteLowF32x4`:  NEON operations on pairs of 64-bit floating-point numbers.
*   `kArmI64x2SplatI32Pair`, `kArmI64x2ReplaceLaneI32Pair`, `kArmI64x2Add`, `kArmI64x2Sub`, `kArmI64x2Mul`, `kArmI64x2Abs`, `kArmI64x2Neg`, `kArmI64x2Shl`, `kArmI64x2ShrS`, `kArmI64x2ShrU`, `kArmI64x2BitMask`, `kArmI64x2SConvertI32x4Low`, `kArmI64x2SConvertI32x4High`, `kArmI64x2UConvertI32x4Low`, `kArmI64x2UConvertI32x4High`: NEON operations on pairs of 64-bit integers.
*   `kArmF32x4Splat`, `kArmF32x4ExtractLane`, `kArmF32x4ReplaceLane`, `kArmF32x4SConvertI32x4`, `kArmF32x4UConvertI32x4`, `kArmF32x4Abs`, `kArmF32x4Neg`, `kArmF32x4Sqrt`, `kArmF32x4Add`, `kArmF32x4Sub`, `kArmF32x4Mul`, `kArmF32x4Div`, `kArmF32x4Min`, `kArmF32x4Max`, `kArmF32x4Eq`, `kArmF32x4Ne`, `kArmF32x4Lt`, `kArmF32x4Le`, `kArmF32x4Pmin`, `kArmF32x4Pmax`, `kArmF32x4Qfma`, `kArmF32x4Qfms`, `kArmF32x4DemoteF64x2Zero`: NEON operations on vectors of four 32-bit floating-point numbers.
*   `kArmI32x4Splat`, `kArmI32x4ExtractLane`, `kArmI32x4ReplaceLane`, `kArmI32x4SConvertF32x4`, `kArmI32x4SConvertI16x8Low`, `kArmI32x4SConvertI16x8High`, `kArmI32x4Neg`, `kArmI32x4Shl`, `kArmI32x4ShrS`, `kArmI32x4Add`, `kArmI32x4Sub`, `kArmI32x4Mul`, `kArmI32x4MinS`, `kArmI32x4MaxS`, `kArmI64x2Eq`, `kArmI64x2Ne`, `kArmI64x2GtS`, `kArmI64x2GeS`, `kArmI32x4Eq`, `kArmI32x4Ne`, `kArmI32x4GtS`, `kArmI32x4GeS`, `kArmI32x4UConvertF32x4`, `kArmI32x4UConvertI16x8Low`, `kArmI32x4UConvertI16x8High`, `kArmI32x4ShrU`, `kArmI32x4MinU`, `kArmI32x4MaxU`, `kArmI32x4GtU`, `kArmI32x4GeU`, `kArmI32x4Abs`, `kArmI32x4BitMask`, `kArmI32x4DotI16x8S`, `kArmI16x8DotI8x16S`, `kArmI32x4DotI8x16AddS`, `kArmI32x4TruncSatF64x2SZero`, `kArmI32x4TruncSatF64x2UZero`: NEON operations on vectors of four 32-bit integers.
*   `kArmI16x8Splat`, `kArmI16x8ExtractLaneU`, `kArmI16x8ExtractLaneS`, `kArmI16x8ReplaceLane`, `kArmI16x8SConvertI8x16Low`, `kArmI16x8SConvertI8x16High`, `kArmI16x8Neg`, `kArmI16x8Shl`, `kArmI16x8ShrS`, `kArmI16x8SConvertI32x4`, `kArmI16x8Add`, `kArmI16x8AddSatS`, `kArmI16x8Sub`, `kArmI16x8SubSatS`, `kArmI16x8Mul`, `kArmI16x8MinS`, `kArmI16x8MaxS`, `kArmI16x8Eq`, `kArmI16x8Ne`, `kArmI16x8GtS`, `kArmI16x8GeS`, `kArmI16x8UConvertI8x16Low`, `kArmI16x8UConvertI8x16High`, `kArmI16x8ShrU`, `kArmI16x8UConvertI32x4`, `kArmI16x8AddSatU`, `kArmI16x8SubSatU`, `kArmI16x8MinU`, `kArmI16x8MaxU`, `kArmI16x8GtU`, `kArmI16x8GeU`, `kArmI16x8RoundingAverageU`, `kArmI16x8Abs`, `kArmI16x8BitMask`, `kArmI16x8Q15MulRSatS`: NEON operations on vectors of eight 16-bit integers.
*   `kArmI8x16Splat`, `kArmI8x16ExtractLaneU`, `kArmI8x16ExtractLaneS`, `kArmI8x16ReplaceLane`, `kArmI8x16Neg`, `kArmI8x16Shl`, `kArmI8x16ShrS`, `kArmI8x16SConvertI16x8`, `kArmI8x16Add`, `kArmI8x16AddSatS`, `kArmI8x16Sub`, `kArmI8x16SubSatS`, `kArmI8x16MinS`, `kArmI8x16MaxS`, `kArmI8x16Eq`, `kArmI8x16Ne`, `kArmI8x16GtS`, `kArmI8x16GeS`, `kArmI8x16ShrU`, `kArmI8x16UConvertI16x8`, `kArmI8x16AddSatU`, `kArmI8x16SubSatU`, `kArmI8x16MinU`, `kArmI8x16MaxU`, `kArmI8x16GtU`, `kArmI8x16GeU`, `kArmI8x16RoundingAverageU`, `kArmI8x16Abs`, `kArmI8x16BitMask`: NEON operations on vectors of sixteen 8-bit integers.
*   `kArmS128Const`, `kArmS128Zero`, `kArmS128AllOnes`, `kArmS128Dup`, `kArmS128And`, `kArmS128Or`, `kArmS128Xor`, `kArmS128Not`, `kArmS128Select`, `kArmS128AndNot`: General SIMD (vector) operations.
*   `kArmS32x4ZipLeft`, `kArmS32x4ZipRight`, `kArmS32x4UnzipLeft`, `kArmS32x4UnzipRight`, `kArmS32x4TransposeLeft`, `kArmS32x4Shuffle`, `kArmS32x4TransposeRight`: SIMD zip, unzip, transpose, and shuffle operations for 32-bit elements.
*   `kArmS16x8ZipLeft`, `kArmS16x8ZipRight`, `kArmS16x8UnzipLeft`, `kArmS16x8UnzipRight`, `kArmS16x8TransposeLeft`, `kArmS16x8TransposeRight`: SIMD zip, unzip, and transpose operations for 16-bit elements.
*   `kArmS8x16ZipLeft`, `kArmS8x16ZipRight`, `kArmS8x16UnzipLeft`, `kArmS8x16UnzipRight`, `kArmS8x16TransposeLeft`, `kArmS8x16TransposeRight`, `kArmS8x16Concat`, `kArmI8x16Swizzle`, `kArmI8x16Shuffle`: SIMD zip, unzip, transpose, concatenate, swizzle, and shuffle operations for 8-bit elements.
*   `kArmS32x2Reverse`, `kArmS16x4Reverse`, `kArmS16x2Reverse`, `kArmS8x8Reverse`, `kArmS8x4Reverse`, `kArmS8x2Reverse`: SIMD reverse operations on different element sizes.
*   `kArmV128AnyTrue`, `kArmI64x2AllTrue`, `kArmI32x4AllTrue`, `kArmI16x8AllTrue`, `kArmI8x16AllTrue`: SIMD "any true" and "all true" operations.
*   `kArmS128Load8Splat`, `kArmS128Load16Splat`, `kArmS128Load32Splat`, `kArmS128Load64Splat`, `kArmS128Load8x8S`, `kArmS128Load8x8U`, `kArmS128Load16x4S`, `kArmS128Load16x4U`, `kArmS128Load32x2S`, `kArmS128Load32x2U`, `kArmS128Load32Zero`, `kArmS128Load64Zero`, `kArmS128LoadLaneLow`, `kArmS128LoadLaneHigh`, `kArmS128StoreLaneLow`, `kArmS128StoreLaneHigh`: SIMD load and store operations.
*   `kAtomicLoadInt8`, `kAtomicLoadUint8`, `kAtomicLoadInt16`, `kAtomicLoadUint16`, `kAtomicLoadWord32`, `kAtomicStoreWord8`, `kAtomicStoreWord16`, `kAtomicStoreWord32`, `kAtomicExchangeInt8`, `kAtomicExchangeUint8`, `kAtomicExchangeInt16`, `kAtomicExchangeUint16`, `kAtomicExchangeWord32`, `kAtomicCompareExchangeInt8`, `kAtomicCompareExchangeUint8`, `kAtomicCompareExchangeInt16`: Atomic memory operations.
```cpp
putFloatRegister();
      SwVfpRegister left = i.InputFloatRegister(0);
      SwVfpRegister right = i.InputFloatRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat32Min>(this, result, left, right);
        __ FloatMin(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat64Min: {
      DwVfpRegister result = i.OutputDoubleRegister();
      DwVfpRegister left = i.InputDoubleRegister(0);
      DwVfpRegister right = i.InputDoubleRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat64Min>(this, result, left, right);
        __ FloatMin(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat64SilenceNaN: {
      DwVfpRegister value = i.InputDoubleRegister(0);
      DwVfpRegister result = i.OutputDoubleRegister();
      __ VFPCanonicalizeNaN(result, value);
      break;
    }
    case kArmPush: {
      int stack_decrement = i.InputInt32(0);
      int slots = stack_decrement / kSystemPointerSize;
      LocationOperand* op = LocationOperand::cast(instr->InputAt(1));
      MachineRepresentation rep = op->representation();
      int pushed_slots = ElementSizeInPointers(rep);
      // Slot-sized arguments are never padded but there may be a gap if
      // the slot allocator reclaimed other padding slots. Adjust the stack
      // here to skip any gap.
      __ AllocateStackSpace((slots - pushed_slots) * kSystemPointerSize);
      switch (rep) {
        case MachineRepresentation::kFloat32:
          __ vpush(i.InputFloatRegister(1));
          break;
        case MachineRepresentation::kFloat64:
          __ vpush(i.InputDoubleRegister(1));
          break;
        case MachineRepresentation::kSimd128:
          __ vpush(i.InputSimd128Register(1));
          break;
        default:
          __ push(i.InputRegister(1));
          break;
      }
      frame_access_state()->IncreaseSPDelta(slots);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmPoke: {
      int const slot = MiscField::decode(instr->opcode());
      __ str(i.InputRegister(0), MemOperand(sp, slot * kSystemPointerSize));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmPeek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ vldr(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ vldr(i.OutputFloatRegister(), MemOperand(fp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          UseScratchRegisterScope temps(masm());
          Register scratch = temps.Acquire();
          __ add(scratch, fp, Operand(offset));
          __ vld1(Neon8, NeonListOperand(i.OutputSimd128Register()),
                  NeonMemOperand(scratch));
        }
      } else {
        __ ldr(i.OutputRegister(), MemOperand(fp, offset));
      }
      break;
    }
    case kArmDmbIsh: {
      __ dmb(ISH);
      break;
    }
    case kArmDsbIsb: {
      __ dsb(SY);
      __ isb(SY);
      break;
    }
    case kArmVmullLow: {
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vmull(dt, i.OutputSimd128Register(), i.InputSimd128Register(0).low(),
               i.InputSimd128Register(1).low());
      break;
    }
    case kArmVmullHigh: {
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vmull(dt, i.OutputSimd128Register(), i.InputSimd128Register(0).high(),
               i.InputSimd128Register(1).high());
      break;
    }
    case kArmVpadal: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vpadal(dt, i.OutputSimd128Register(), i.InputSimd128Register(1));
      break;
    }
    case kArmVpaddl: {
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vpaddl(dt, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF64x2Splat: {
      Simd128Register dst = i.OutputSimd128Register();
      DoubleRegister src = i.InputDoubleRegister(0);
      __ Move(dst.low(), src);
      __ Move(dst.high(), src);
      break;
    }
    case kArmF64x2ExtractLane: {
      __ ExtractLane(i.OutputDoubleRegister(), i.InputSimd128Register(0),
                     i.InputInt8(1));
      break;
    }
    case kArmF64x2ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputDoubleRegister(2), i.InputInt8(1));
      break;
    }
    case kArmF64x2Abs: {
      __ vabs(i.OutputSimd128Register().low(), i.InputSimd128Register(0).low());
      __ vabs(i.OutputSimd128Register().high(),
              i.InputSimd128Register(0).high());
      break;
    }
    case kArmF64x2Neg: {
      __ vneg(i.OutputSimd128Register().low(), i.InputSimd128Register(0).low());
      __ vneg(i.OutputSimd128Register().high(),
              i.InputSimd128Register(0).high());
      break;
    }
    case kArmF64x2Sqrt: {
      __ vsqrt(i.OutputSimd128Register().low(),
               i.InputSimd128Register(0).low());
      __ vsqrt(i.OutputSimd128Register().high(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmF64x2Add: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vadd);
      break;
    }
    case kArmF64x2Sub: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vsub);
      break;
    }
    case kArmF64x2Mul: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vmul);
      break;
    }
    case kArmF64x2Div: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vdiv);
      break;
    }
    case kArmF64x2Min: {
      Simd128Register result = i.OutputSimd128Register();
      Simd128Register left = i.InputSimd128Register(0);
      Simd128Register right = i.InputSimd128Register(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool_low = zone()->New<OutOfLineFloat64Min>(
            this, result.low(), left.low(), right.low());
        auto ool_high = zone()->New<OutOfLineFloat64Min>(
            this, result.high(), left.high(), right.high());
        __ FloatMin(result.low(), left.low(), right.low(), ool_low->entry());
        __ bind(ool_low->exit());
        __ FloatMin(result.high(), left.high(), right.high(),
                    ool_high->entry());
        __ bind(ool_high->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmF64x2Max: {
      Simd128Register result = i.OutputSimd128Register();
      Simd128Register left = i.InputSimd128Register(0);
      Simd128Register right = i.InputSimd128Register(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool_low = zone()->New<OutOfLineFloat64Max>(
            this, result.low(), left.low(), right.low());
        auto ool_high = zone()->New<OutOfLineFloat64Max>(
            this, result.high(), left.high(), right.high());
        __ FloatMax(result.low(), left.low(), right.low(), ool_low->entry());
        __ bind(ool_low->exit());
        __ FloatMax(result.high(), left.high(), right.high(),
                    ool_high->entry());
        __ bind(ool_high->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
#undef ASSEMBLE_F64X2_ARITHMETIC_BINOP
    case kArmF64x2Eq: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(-1), LeaveCC, eq);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(-1), LeaveCC, eq);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Ne: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(-1), LeaveCC, ne);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(-1), LeaveCC, ne);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Lt: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(0), LeaveCC, cs);
      __ mov(scratch, Operand(-1), LeaveCC, mi);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(0), LeaveCC, cs);
      __ mov(scratch, Operand(-1), LeaveCC, mi);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Le: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(0), LeaveCC, hi);
      __ mov(scratch, Operand(-1), LeaveCC, ls);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(0), LeaveCC, hi);
      __ mov(scratch, Operand(-1), LeaveCC, ls);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Pmin: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_EQ(dst, lhs);

      // Move rhs only when rhs is strictly lesser (mi).
      __ VFPCompareAndSetFlags(rhs.low(), lhs.low());
      __ vmov(dst.low(), rhs.low(), mi);
      __ VFPCompareAndSetFlags(rhs.high(), lhs.high());
      __ vmov(dst.high(), rhs.high(), mi);
      break;
    }
    case kArmF64x2Pmax: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_EQ(dst, lhs);

      // Move rhs only when rhs is strictly greater (gt).
      __ VFPCompareAndSetFlags(rhs.low(), lhs.low());
      __ vmov(dst.low(), rhs.low(), gt);
      __ VFPCompareAndSetFlags(rhs.high(), lhs.high());
      __ vmov(dst.high(), rhs.high(), gt);
      break;
    }
    case kArmF64x2Qfma: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register src2 = i.InputSimd128Register(2);
      __ vmul(dst.low(), src0.low(), src1.low());
      __ vmul(dst.high(), src0.high(), src1.high());
      __ vadd(dst.low(), src2.low(), dst.low());
      __ vadd(dst.high(), src2.high(), dst.high());
      break;
    }
    case kArmF64x2Qfms: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register src2 = i.InputSimd128Register(2);
      __ vmul(dst.low(), src0.low(), src1.low());
      __ vmul(dst.high(), src0.high(), src1.high());
      __ vsub(dst.low(), src2.low(), dst.low());
      __ vsub(dst.high(), src2.high(), dst.high());
      break;
    }
    case kArmF64x2Ceil: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintp(dst.low(), src.low());
      __ vrintp(dst.high(), src.high());
      break;
    }
    case kArmF64x2Floor: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintm(dst.low(), src.low());
      __ vrintm(dst.high(), src.high());
      break;
    }
    case kArmF64x2Trunc: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintz(dst.low(), src.low());
      __ vrintz(dst.high(), src.high());
      break;
    }
    case kArmF64x2NearestInt: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintn(dst.low(), src.low());
      __ vrintn(dst.high(), src.high());
      break;
    }
    case kArmF64x2ConvertLowI32x4S: {
      __ F64x2ConvertLowI32x4S(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kArmF64x2ConvertLowI32x4U: {
      __ F64x2ConvertLowI32x4U(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kArmF64x2PromoteLowF32x4: {
      __ F64x2PromoteLowF32x4(i.OutputSimd128Register(),
                              i.InputSimd128Register(0));
      break;
    }
    case kArmI64x2SplatI32Pair: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vdup(Neon3
Prompt: 
```
这是目录为v8/src/compiler/backend/arm/code-generator-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
putFloatRegister();
      SwVfpRegister left = i.InputFloatRegister(0);
      SwVfpRegister right = i.InputFloatRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat32Min>(this, result, left, right);
        __ FloatMin(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat64Min: {
      DwVfpRegister result = i.OutputDoubleRegister();
      DwVfpRegister left = i.InputDoubleRegister(0);
      DwVfpRegister right = i.InputDoubleRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat64Min>(this, result, left, right);
        __ FloatMin(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat64SilenceNaN: {
      DwVfpRegister value = i.InputDoubleRegister(0);
      DwVfpRegister result = i.OutputDoubleRegister();
      __ VFPCanonicalizeNaN(result, value);
      break;
    }
    case kArmPush: {
      int stack_decrement = i.InputInt32(0);
      int slots = stack_decrement / kSystemPointerSize;
      LocationOperand* op = LocationOperand::cast(instr->InputAt(1));
      MachineRepresentation rep = op->representation();
      int pushed_slots = ElementSizeInPointers(rep);
      // Slot-sized arguments are never padded but there may be a gap if
      // the slot allocator reclaimed other padding slots. Adjust the stack
      // here to skip any gap.
      __ AllocateStackSpace((slots - pushed_slots) * kSystemPointerSize);
      switch (rep) {
        case MachineRepresentation::kFloat32:
          __ vpush(i.InputFloatRegister(1));
          break;
        case MachineRepresentation::kFloat64:
          __ vpush(i.InputDoubleRegister(1));
          break;
        case MachineRepresentation::kSimd128:
          __ vpush(i.InputSimd128Register(1));
          break;
        default:
          __ push(i.InputRegister(1));
          break;
      }
      frame_access_state()->IncreaseSPDelta(slots);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmPoke: {
      int const slot = MiscField::decode(instr->opcode());
      __ str(i.InputRegister(0), MemOperand(sp, slot * kSystemPointerSize));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmPeek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ vldr(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ vldr(i.OutputFloatRegister(), MemOperand(fp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          UseScratchRegisterScope temps(masm());
          Register scratch = temps.Acquire();
          __ add(scratch, fp, Operand(offset));
          __ vld1(Neon8, NeonListOperand(i.OutputSimd128Register()),
                  NeonMemOperand(scratch));
        }
      } else {
        __ ldr(i.OutputRegister(), MemOperand(fp, offset));
      }
      break;
    }
    case kArmDmbIsh: {
      __ dmb(ISH);
      break;
    }
    case kArmDsbIsb: {
      __ dsb(SY);
      __ isb(SY);
      break;
    }
    case kArmVmullLow: {
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vmull(dt, i.OutputSimd128Register(), i.InputSimd128Register(0).low(),
               i.InputSimd128Register(1).low());
      break;
    }
    case kArmVmullHigh: {
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vmull(dt, i.OutputSimd128Register(), i.InputSimd128Register(0).high(),
               i.InputSimd128Register(1).high());
      break;
    }
    case kArmVpadal: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vpadal(dt, i.OutputSimd128Register(), i.InputSimd128Register(1));
      break;
    }
    case kArmVpaddl: {
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vpaddl(dt, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF64x2Splat: {
      Simd128Register dst = i.OutputSimd128Register();
      DoubleRegister src = i.InputDoubleRegister(0);
      __ Move(dst.low(), src);
      __ Move(dst.high(), src);
      break;
    }
    case kArmF64x2ExtractLane: {
      __ ExtractLane(i.OutputDoubleRegister(), i.InputSimd128Register(0),
                     i.InputInt8(1));
      break;
    }
    case kArmF64x2ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputDoubleRegister(2), i.InputInt8(1));
      break;
    }
    case kArmF64x2Abs: {
      __ vabs(i.OutputSimd128Register().low(), i.InputSimd128Register(0).low());
      __ vabs(i.OutputSimd128Register().high(),
              i.InputSimd128Register(0).high());
      break;
    }
    case kArmF64x2Neg: {
      __ vneg(i.OutputSimd128Register().low(), i.InputSimd128Register(0).low());
      __ vneg(i.OutputSimd128Register().high(),
              i.InputSimd128Register(0).high());
      break;
    }
    case kArmF64x2Sqrt: {
      __ vsqrt(i.OutputSimd128Register().low(),
               i.InputSimd128Register(0).low());
      __ vsqrt(i.OutputSimd128Register().high(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmF64x2Add: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vadd);
      break;
    }
    case kArmF64x2Sub: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vsub);
      break;
    }
    case kArmF64x2Mul: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vmul);
      break;
    }
    case kArmF64x2Div: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vdiv);
      break;
    }
    case kArmF64x2Min: {
      Simd128Register result = i.OutputSimd128Register();
      Simd128Register left = i.InputSimd128Register(0);
      Simd128Register right = i.InputSimd128Register(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool_low = zone()->New<OutOfLineFloat64Min>(
            this, result.low(), left.low(), right.low());
        auto ool_high = zone()->New<OutOfLineFloat64Min>(
            this, result.high(), left.high(), right.high());
        __ FloatMin(result.low(), left.low(), right.low(), ool_low->entry());
        __ bind(ool_low->exit());
        __ FloatMin(result.high(), left.high(), right.high(),
                    ool_high->entry());
        __ bind(ool_high->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmF64x2Max: {
      Simd128Register result = i.OutputSimd128Register();
      Simd128Register left = i.InputSimd128Register(0);
      Simd128Register right = i.InputSimd128Register(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool_low = zone()->New<OutOfLineFloat64Max>(
            this, result.low(), left.low(), right.low());
        auto ool_high = zone()->New<OutOfLineFloat64Max>(
            this, result.high(), left.high(), right.high());
        __ FloatMax(result.low(), left.low(), right.low(), ool_low->entry());
        __ bind(ool_low->exit());
        __ FloatMax(result.high(), left.high(), right.high(),
                    ool_high->entry());
        __ bind(ool_high->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
#undef ASSEMBLE_F64X2_ARITHMETIC_BINOP
    case kArmF64x2Eq: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(-1), LeaveCC, eq);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(-1), LeaveCC, eq);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Ne: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(-1), LeaveCC, ne);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(-1), LeaveCC, ne);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Lt: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(0), LeaveCC, cs);
      __ mov(scratch, Operand(-1), LeaveCC, mi);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(0), LeaveCC, cs);
      __ mov(scratch, Operand(-1), LeaveCC, mi);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Le: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(0), LeaveCC, hi);
      __ mov(scratch, Operand(-1), LeaveCC, ls);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(0), LeaveCC, hi);
      __ mov(scratch, Operand(-1), LeaveCC, ls);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Pmin: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_EQ(dst, lhs);

      // Move rhs only when rhs is strictly lesser (mi).
      __ VFPCompareAndSetFlags(rhs.low(), lhs.low());
      __ vmov(dst.low(), rhs.low(), mi);
      __ VFPCompareAndSetFlags(rhs.high(), lhs.high());
      __ vmov(dst.high(), rhs.high(), mi);
      break;
    }
    case kArmF64x2Pmax: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_EQ(dst, lhs);

      // Move rhs only when rhs is strictly greater (gt).
      __ VFPCompareAndSetFlags(rhs.low(), lhs.low());
      __ vmov(dst.low(), rhs.low(), gt);
      __ VFPCompareAndSetFlags(rhs.high(), lhs.high());
      __ vmov(dst.high(), rhs.high(), gt);
      break;
    }
    case kArmF64x2Qfma: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register src2 = i.InputSimd128Register(2);
      __ vmul(dst.low(), src0.low(), src1.low());
      __ vmul(dst.high(), src0.high(), src1.high());
      __ vadd(dst.low(), src2.low(), dst.low());
      __ vadd(dst.high(), src2.high(), dst.high());
      break;
    }
    case kArmF64x2Qfms: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register src2 = i.InputSimd128Register(2);
      __ vmul(dst.low(), src0.low(), src1.low());
      __ vmul(dst.high(), src0.high(), src1.high());
      __ vsub(dst.low(), src2.low(), dst.low());
      __ vsub(dst.high(), src2.high(), dst.high());
      break;
    }
    case kArmF64x2Ceil: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintp(dst.low(), src.low());
      __ vrintp(dst.high(), src.high());
      break;
    }
    case kArmF64x2Floor: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintm(dst.low(), src.low());
      __ vrintm(dst.high(), src.high());
      break;
    }
    case kArmF64x2Trunc: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintz(dst.low(), src.low());
      __ vrintz(dst.high(), src.high());
      break;
    }
    case kArmF64x2NearestInt: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintn(dst.low(), src.low());
      __ vrintn(dst.high(), src.high());
      break;
    }
    case kArmF64x2ConvertLowI32x4S: {
      __ F64x2ConvertLowI32x4S(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kArmF64x2ConvertLowI32x4U: {
      __ F64x2ConvertLowI32x4U(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kArmF64x2PromoteLowF32x4: {
      __ F64x2PromoteLowF32x4(i.OutputSimd128Register(),
                              i.InputSimd128Register(0));
      break;
    }
    case kArmI64x2SplatI32Pair: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vdup(Neon32, dst, i.InputRegister(0));
      __ ReplaceLane(dst, dst, i.InputRegister(1), NeonS32, 1);
      __ ReplaceLane(dst, dst, i.InputRegister(1), NeonS32, 3);
      break;
    }
    case kArmI64x2ReplaceLaneI32Pair: {
      Simd128Register dst = i.OutputSimd128Register();
      int8_t lane = i.InputInt8(1);
      __ ReplaceLane(dst, dst, i.InputRegister(2), NeonS32, lane * 2);
      __ ReplaceLane(dst, dst, i.InputRegister(3), NeonS32, lane * 2 + 1);
      break;
    }
    case kArmI64x2Add: {
      __ vadd(Neon64, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2Sub: {
      __ vsub(Neon64, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2Mul: {
      UseScratchRegisterScope temps(masm());
      QwNeonRegister dst = i.OutputSimd128Register();
      QwNeonRegister left = i.InputSimd128Register(0);
      QwNeonRegister right = i.InputSimd128Register(1);
      QwNeonRegister tmp1 = i.TempSimd128Register(0);
      QwNeonRegister tmp2 = temps.AcquireQ();

      // This algorithm uses vector operations to perform 64-bit integer
      // multiplication by splitting it into a high and low 32-bit integers.
      // The tricky part is getting the low and high integers in the correct
      // place inside a NEON register, so that we can use as little vmull and
      // vmlal as possible.

      // Move left and right into temporaries, they will be modified by vtrn.
      __ vmov(tmp1, left);
      __ vmov(tmp2, right);

      // This diagram shows how the 64-bit integers fit into NEON registers.
      //
      //             [q.high()| q.low()]
      // left/tmp1:  [ a3, a2 | a1, a0 ]
      // right/tmp2: [ b3, b2 | b1, b0 ]
      //
      // We want to multiply the low 32 bits of left with high 32 bits of right,
      // for each lane, i.e. a2 * b3, a0 * b1. However, vmull takes two input d
      // registers, and multiply the corresponding low/high 32 bits, to get a
      // 64-bit integer: a1 * b1, a0 * b0. In order to make it work we transpose
      // the vectors, so that we get the low 32 bits of each 64-bit integer into
      // the same lane, similarly for high 32 bits.
      __ vtrn(Neon32, tmp1.low(), tmp1.high());
      // tmp1: [ a3, a1 | a2, a0 ]
      __ vtrn(Neon32, tmp2.low(), tmp2.high());
      // tmp2: [ b3, b1 | b2, b0 ]

      __ vmull(NeonU32, dst, tmp1.low(), tmp2.high());
      // dst: [ a2*b3 | a0*b1 ]
      __ vmlal(NeonU32, dst, tmp1.high(), tmp2.low());
      // dst: [ a2*b3 + a3*b2 | a0*b1 + a1*b0 ]
      __ vshl(NeonU64, dst, dst, 32);
      // dst: [ (a2*b3 + a3*b2) << 32 | (a0*b1 + a1*b0) << 32 ]

      __ vmlal(NeonU32, dst, tmp1.low(), tmp2.low());
      // dst: [ (a2*b3 + a3*b2)<<32 + (a2*b2) | (a0*b1 + a1*b0)<<32 + (a0*b0) ]
      break;
    }
    case kArmI64x2Abs: {
      __ I64x2Abs(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI64x2Neg: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vmov(dst, uint64_t{0});
      __ vsub(Neon64, dst, dst, i.InputSimd128Register(0));
      break;
    }
    case kArmI64x2Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(vshl, 6, Neon32, NeonS64);
      break;
    }
    case kArmI64x2ShrS: {
      // Only the least significant byte of each lane is used, so we can use
      // Neon32 as the size.
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 6, Neon32, NeonS64);
      break;
    }
    case kArmI64x2ShrU: {
      // Only the least significant byte of each lane is used, so we can use
      // Neon32 as the size.
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 6, Neon32, NeonU64);
      break;
    }
    case kArmI64x2BitMask: {
      __ I64x2BitMask(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kArmI64x2SConvertI32x4Low: {
      __ vmovl(NeonS32, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI64x2SConvertI32x4High: {
      __ vmovl(NeonS32, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmI64x2UConvertI32x4Low: {
      __ vmovl(NeonU32, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI64x2UConvertI32x4High: {
      __ vmovl(NeonU32, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmF32x4Splat: {
      int src_code = i.InputFloatRegister(0).code();
      __ vdup(Neon32, i.OutputSimd128Register(),
              DwVfpRegister::from_code(src_code / 2), src_code % 2);
      break;
    }
    case kArmF32x4ExtractLane: {
      __ ExtractLane(i.OutputFloatRegister(), i.InputSimd128Register(0),
                     i.InputInt8(1));
      break;
    }
    case kArmF32x4ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputFloatRegister(2), i.InputInt8(1));
      break;
    }
    case kArmF32x4SConvertI32x4: {
      __ vcvt_f32_s32(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4UConvertI32x4: {
      __ vcvt_f32_u32(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Abs: {
      __ vabs(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Neg: {
      __ vneg(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Sqrt: {
      QwNeonRegister dst = i.OutputSimd128Register();
      QwNeonRegister src1 = i.InputSimd128Register(0);
      DCHECK_EQ(dst, q0);
      DCHECK_EQ(src1, q0);
#define S_FROM_Q(reg, lane) SwVfpRegister::from_code(reg.code() * 4 + lane)
      __ vsqrt(S_FROM_Q(dst, 0), S_FROM_Q(src1, 0));
      __ vsqrt(S_FROM_Q(dst, 1), S_FROM_Q(src1, 1));
      __ vsqrt(S_FROM_Q(dst, 2), S_FROM_Q(src1, 2));
      __ vsqrt(S_FROM_Q(dst, 3), S_FROM_Q(src1, 3));
#undef S_FROM_Q
      break;
    }
    case kArmF32x4Add: {
      __ vadd(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Sub: {
      __ vsub(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Mul: {
      __ vmul(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Div: {
      QwNeonRegister dst = i.OutputSimd128Register();
      QwNeonRegister src1 = i.InputSimd128Register(0);
      QwNeonRegister src2 = i.InputSimd128Register(1);
      DCHECK_EQ(dst, q0);
      DCHECK_EQ(src1, q0);
      DCHECK_EQ(src2, q1);
#define S_FROM_Q(reg, lane) SwVfpRegister::from_code(reg.code() * 4 + lane)
      __ vdiv(S_FROM_Q(dst, 0), S_FROM_Q(src1, 0), S_FROM_Q(src2, 0));
      __ vdiv(S_FROM_Q(dst, 1), S_FROM_Q(src1, 1), S_FROM_Q(src2, 1));
      __ vdiv(S_FROM_Q(dst, 2), S_FROM_Q(src1, 2), S_FROM_Q(src2, 2));
      __ vdiv(S_FROM_Q(dst, 3), S_FROM_Q(src1, 3), S_FROM_Q(src2, 3));
#undef S_FROM_Q
      break;
    }
    case kArmF32x4Min: {
      __ vmin(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Max: {
      __ vmax(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Eq: {
      __ vceq(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Ne: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vceq(dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vmvn(dst, dst);
      break;
    }
    case kArmF32x4Lt: {
      __ vcgt(i.OutputSimd128Register(), i.InputSimd128Register(1),
              i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Le: {
      __ vcge(i.OutputSimd128Register(), i.InputSimd128Register(1),
              i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Pmin: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_NE(dst, lhs);
      DCHECK_NE(dst, rhs);

      // f32x4.pmin(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f32x4.lt(rhs, lhs))
      // = v128.bitselect(rhs, lhs, f32x4.gt(lhs, rhs))
      __ vcgt(dst, lhs, rhs);
      __ vbsl(dst, rhs, lhs);
      break;
    }
    case kArmF32x4Pmax: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_NE(dst, lhs);
      DCHECK_NE(dst, rhs);

      // f32x4.pmax(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f32x4.gt(rhs, lhs))
      __ vcgt(dst, rhs, lhs);
      __ vbsl(dst, rhs, lhs);
      break;
    }
    case kArmF32x4Qfma: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vmul(dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vadd(dst, i.InputSimd128Register(2), dst);
      break;
    }
    case kArmF32x4Qfms: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vmul(dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vsub(dst, i.InputSimd128Register(2), dst);
      break;
    }
    case kArmF32x4DemoteF64x2Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vcvt_f32_f64(SwVfpRegister::from_code(dst.code() * 4), src.low());
      __ vcvt_f32_f64(SwVfpRegister::from_code(dst.code() * 4 + 1), src.high());
      __ vmov(dst.high(), 0);
      break;
    }
    case kArmI32x4Splat: {
      __ vdup(Neon32, i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kArmI32x4ExtractLane: {
      __ ExtractLane(i.OutputRegister(), i.InputSimd128Register(0), NeonS32,
                     i.InputInt8(1));
      break;
    }
    case kArmI32x4ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputRegister(2), NeonS32, i.InputInt8(1));
      break;
    }
    case kArmI32x4SConvertF32x4: {
      __ vcvt_s32_f32(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI32x4SConvertI16x8Low: {
      __ vmovl(NeonS16, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI32x4SConvertI16x8High: {
      __ vmovl(NeonS16, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmI32x4Neg: {
      __ vneg(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI32x4Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(vshl, 5, Neon32, NeonS32);
      break;
    }
    case kArmI32x4ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 5, Neon32, NeonS32);
      break;
    }
    case kArmI32x4Add: {
      __ vadd(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Sub: {
      __ vsub(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Mul: {
      __ vmul(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4MinS: {
      __ vmin(NeonS32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4MaxS: {
      __ vmax(NeonS32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2Eq: {
      __ I64x2Eq(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2Ne: {
      __ I64x2Ne(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2GtS: {
      __ I64x2GtS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2GeS: {
      __ I64x2GeS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Eq: {
      __ vceq(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Ne: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vceq(Neon32, dst, i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      __ vmvn(dst, dst);
      break;
    }
    case kArmI32x4GtS: {
      __ vcgt(NeonS32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4GeS: {
      __ vcge(NeonS32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4UConvertF32x4: {
      __ vcvt_u32_f32(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI32x4UConvertI16x8Low: {
      __ vmovl(NeonU16, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI32x4UConvertI16x8High: {
      __ vmovl(NeonU16, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmI32x4ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 5, Neon32, NeonU32);
      break;
    }
    case kArmI32x4MinU: {
      __ vmin(NeonU32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4MaxU: {
      __ vmax(NeonU32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4GtU: {
      __ vcgt(NeonU32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4GeU: {
      __ vcge(NeonU32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Abs: {
      __ vabs(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI32x4BitMask: {
      Register dst = i.OutputRegister();
      UseScratchRegisterScope temps(masm());
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register tmp = temps.AcquireQ();
      Simd128Register mask = i.TempSimd128Register(0);

      __ vshr(NeonS32, tmp, src, 31);
      // Set i-th bit of each lane i. When AND with tmp, the lanes that
      // are signed will have i-th bit set, unsigned will be 0.
      __ vmov(mask.low(), base::Double(uint64_t{0x0000'0002'0000'0001}));
      __ vmov(mask.high(), base::Double(uint64_t{0x0000'0008'0000'0004}));
      __ vand(tmp, mask, tmp);
      __ vpadd(Neon32, tmp.low(), tmp.low(), tmp.high());
      __ vpadd(Neon32, tmp.low(), tmp.low(), kDoubleRegZero);
      __ VmovLow(dst, tmp.low());
      break;
    }
    case kArmI32x4DotI16x8S: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      __ vmull(NeonS16, scratch, lhs.low(), rhs.low());
      __ vpadd(Neon32, dst.low(), scratch.low(), scratch.high());
      __ vmull(NeonS16, scratch, lhs.high(), rhs.high());
      __ vpadd(Neon32, dst.high(), scratch.low(), scratch.high());
      break;
    }
    case kArmI16x8DotI8x16S: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      __ vmull(NeonS8, scratch, lhs.low(), rhs.low());
      __ vpadd(Neon16, dst.low(), scratch.low(), scratch.high());
      __ vmull(NeonS8, scratch, lhs.high(), rhs.high());
      __ vpadd(Neon16, dst.high(), scratch.low(), scratch.high());
      break;
    }
    case kArmI32x4DotI8x16AddS: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      Simd128Register tmp1 = i.TempSimd128Register(0);
      DCHECK_EQ(dst, i.InputSimd128Register(2));
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      __ vmull(NeonS8, scratch, lhs.low(), rhs.low());
      __ vpadd(Neon16, tmp1.low(), scratch.low(), scratch.high());
      __ vmull(NeonS8, scratch, lhs.high(), rhs.high());
      __ vpadd(Neon16, tmp1.high(), scratch.low(), scratch.high());
      __ vpadal(NeonS16, dst, tmp1);
      break;
    }
    case kArmI32x4TruncSatF64x2SZero: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vcvt_s32_f64(SwVfpRegister::from_code(dst.code() * 4), src.low());
      __ vcvt_s32_f64(SwVfpRegister::from_code(dst.code() * 4 + 1), src.high());
      __ vmov(dst.high(), 0);
      break;
    }
    case kArmI32x4TruncSatF64x2UZero: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vcvt_u32_f64(SwVfpRegister::from_code(dst.code() * 4), src.low());
      __ vcvt_u32_f64(SwVfpRegister::from_code(dst.code() * 4 + 1), src.high());
      __ vmov(dst.high(), 0);
      break;
    }
    case kArmI16x8Splat: {
      __ vdup(Neon16, i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kArmI16x8ExtractLaneU: {
      __ ExtractLane(i.OutputRegister(), i.InputSimd128Register(0), NeonU16,
                     i.InputInt8(1));
      break;
    }
    case kArmI16x8ExtractLaneS: {
      __ ExtractLane(i.OutputRegister(), i.InputSimd128Register(0), NeonS16,
                     i.InputInt8(1));
      break;
    }
    case kArmI16x8ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputRegister(2), NeonS16, i.InputInt8(1));
      break;
    }
    case kArmI16x8SConvertI8x16Low: {
      __ vmovl(NeonS8, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI16x8SConvertI8x16High: {
      __ vmovl(NeonS8, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmI16x8Neg: {
      __ vneg(Neon16, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI16x8Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(vshl, 4, Neon16, NeonS16);
      break;
    }
    case kArmI16x8ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 4, Neon16, NeonS16);
      break;
    }
    case kArmI16x8SConvertI32x4:
      ASSEMBLE_NEON_NARROWING_OP(NeonS16, NeonS16);
      break;
    case kArmI16x8Add: {
      __ vadd(Neon16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8AddSatS: {
      __ vqadd(NeonS16, i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8Sub: {
      __ vsub(Neon16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8SubSatS: {
      __ vqsub(NeonS16, i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8Mul: {
      __ vmul(Neon16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8MinS: {
      __ vmin(NeonS16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8MaxS: {
      __ vmax(NeonS16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8Eq: {
      __ vceq(Neon16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8Ne: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vceq(Neon16, dst, i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      __ vmvn(dst, dst);
      break;
    }
    case kArmI16x8GtS: {
      __ vcgt(NeonS16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8GeS: {
      __ vcge(NeonS16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8UConvertI8x16Low: {
      __ vmovl(NeonU8, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI16x8UConvertI8x16High: {
      __ vmovl(NeonU8, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmI16x8ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 4, Neon16, NeonU16);
      break;
    }
    case kArmI16x8UConvertI32x4:
      ASSEMBLE_NEON_NARROWING_OP(NeonU16, NeonS16);
      break;
    case kArmI16x8AddSatU: {
      __ vqadd(NeonU16, i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8SubSatU: {
      __ vqsub(NeonU16, i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8MinU: {
      __ vmin(NeonU16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8MaxU: {
      __ vmax(NeonU16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8GtU: {
      __ vcgt(NeonU16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8GeU: {
      __ vcge(NeonU16, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8RoundingAverageU: {
      __ vrhadd(NeonU16, i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kArmI16x8Abs: {
      __ vabs(Neon16, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI16x8BitMask: {
      UseScratchRegisterScope temps(masm());
      Register dst = i.OutputRegister();
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register tmp = temps.AcquireQ();
      Simd128Register mask = i.TempSimd128Register(0);

      __ vshr(NeonS16, tmp, src, 15);
      // Set i-th bit of each lane i. When AND with tmp, the lanes that
      // are signed will have i-th bit set, unsigned will be 0.
      __ vmov(mask.low(), base::Double(uint64_t{0x0008'0004'0002'0001}));
      __ vmov(mask.high(), base::Double(uint64_t{0x0080'0040'0020'0010}));
      __ vand(tmp, mask, tmp);
      __ vpadd(Neon16, tmp.low(), tmp.low(), tmp.high());
      __ vpadd(Neon16, tmp.low(), tmp.low(), tmp.low());
      __ vpadd(Neon16, tmp.low(), tmp.low(), tmp.low());
      __ vmov(NeonU16, dst, tmp.low(), 0);
      break;
    }
    case kArmI16x8Q15MulRSatS: {
      __ vqrdmulh(NeonS16, i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16Splat: {
      __ vdup(Neon8, i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kArmI8x16ExtractLaneU: {
      __ ExtractLane(i.OutputRegister(), i.InputSimd128Register(0), NeonU8,
                     i.InputInt8(1));
      break;
    }
    case kArmI8x16ExtractLaneS: {
      __ ExtractLane(i.OutputRegister(), i.InputSimd128Register(0), NeonS8,
                     i.InputInt8(1));
      break;
    }
    case kArmI8x16ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputRegister(2), NeonS8, i.InputInt8(1));
      break;
    }
    case kArmI8x16Neg: {
      __ vneg(Neon8, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI8x16Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(vshl, 3, Neon8, NeonS8);
      break;
    }
    case kArmI8x16ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 3, Neon8, NeonS8);
      break;
    }
    case kArmI8x16SConvertI16x8:
      ASSEMBLE_NEON_NARROWING_OP(NeonS8, NeonS8);
      break;
    case kArmI8x16Add: {
      __ vadd(Neon8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16AddSatS: {
      __ vqadd(NeonS8, i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16Sub: {
      __ vsub(Neon8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16SubSatS: {
      __ vqsub(NeonS8, i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16MinS: {
      __ vmin(NeonS8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16MaxS: {
      __ vmax(NeonS8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16Eq: {
      __ vceq(Neon8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16Ne: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vceq(Neon8, dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vmvn(dst, dst);
      break;
    }
    case kArmI8x16GtS: {
      __ vcgt(NeonS8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16GeS: {
      __ vcge(NeonS8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 3, Neon8, NeonU8);
      break;
    }
    case kArmI8x16UConvertI16x8:
      ASSEMBLE_NEON_NARROWING_OP(NeonU8, NeonS8);
      break;
    case kArmI8x16AddSatU: {
      __ vqadd(NeonU8, i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16SubSatU: {
      __ vqsub(NeonU8, i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16MinU: {
      __ vmin(NeonU8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16MaxU: {
      __ vmax(NeonU8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16GtU: {
      __ vcgt(NeonU8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16GeU: {
      __ vcge(NeonU8, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16RoundingAverageU: {
      __ vrhadd(NeonU8, i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kArmI8x16Abs: {
      __ vabs(Neon8, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI8x16BitMask: {
      UseScratchRegisterScope temps(masm());
      Register dst = i.OutputRegister();
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register tmp = temps.AcquireQ();
      Simd128Register mask = i.TempSimd128Register(0);

      __ vshr(NeonS8, tmp, src, 7);
      // Set i-th bit of each lane i. When AND with tmp, the lanes that
      // are signed will have i-th bit set, unsigned will be 0.
      __ vmov(mask.low(), base::Double(uint64_t{0x8040'2010'0804'0201}));
      __ vmov(mask.high(), base::Double(uint64_t{0x8040'2010'0804'0201}));
      __ vand(tmp, mask, tmp);
      __ vext(mask, tmp, tmp, 8);
      __ vzip(Neon8, mask, tmp);
      __ vpadd(Neon16, tmp.low(), tmp.low(), tmp.high());
      __ vpadd(Neon16, tmp.low(), tmp.low(), tmp.low());
      __ vpadd(Neon16, tmp.low(), tmp.low(), tmp.low());
      __ vmov(NeonU16, dst, tmp.low(), 0);
      break;
    }
    case kArmS128Const: {
      QwNeonRegister dst = i.OutputSimd128Register();
      uint64_t imm1 = make_uint64(i.InputUint32(1), i.InputUint32(0));
      uint64_t imm2 = make_uint64(i.InputUint32(3), i.InputUint32(2));
      __ vmov(dst.low(), base::Double(imm1));
      __ vmov(dst.high(), base::Double(imm2));
      break;
    }
    case kArmS128Zero: {
      __ veor(i.OutputSimd128Register(), i.OutputSimd128Register(),
              i.OutputSimd128Register());
      break;
    }
    case kArmS128AllOnes: {
      __ vmov(i.OutputSimd128Register(), uint64_t{0xffff'ffff'ffff'ffff});
      break;
    }
    case kArmS128Dup: {
      NeonSize size = static_cast<NeonSize>(i.InputInt32(1));
      int lanes = kSimd128Size >> size;
      int index = i.InputInt32(2);
      DCHECK(index < lanes);
      int d_lanes = lanes / 2;
      int src_d_index = index & (d_lanes - 1);
      int src_d_code = i.InputSimd128Register(0).low().code() + index / d_lanes;
      __ vdup(size, i.OutputSimd128Register(),
              DwVfpRegister::from_code(src_d_code), src_d_index);
      break;
    }
    case kArmS128And: {
      __ vand(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmS128Or: {
      __ vorr(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmS128Xor: {
      __ veor(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmS128Not: {
      __ vmvn(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmS128Select: {
      Simd128Register dst = i.OutputSimd128Register();
      DCHECK(dst == i.InputSimd128Register(0));
      __ vbsl(dst, i.InputSimd128Register(1), i.InputSimd128Register(2));
      break;
    }
    case kArmS128AndNot: {
      __ vbic(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmS32x4ZipLeft: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [0, 1, 2, 3], src1 = [4, 5, 6, 7]
      __ vmov(dst.high(), src1.low());         // dst = [0, 1, 4, 5]
      __ vtrn(Neon32, dst.low(), dst.high());  // dst = [0, 4, 1, 5]
      break;
    }
    case kArmS32x4ZipRight: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [4, 5, 6, 7], src1 = [0, 1, 2, 3] (flipped from ZipLeft).
      __ vmov(dst.low(), src1.high());         // dst = [2, 3, 6, 7]
      __ vtrn(Neon32, dst.low(), dst.high());  // dst = [2, 6, 3, 7]
      break;
    }
    case kArmS32x4UnzipLeft: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      DCHECK(dst == i.InputSimd128Register(0));
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      // src0 = [0, 1, 2, 3], src1 = [4, 5, 6, 7]
      __ vmov(scratch, src1);
      __ vuzp(Neon32, dst, scratch);  // dst = [0, 2, 4, 6]
      break;
    }
    case kArmS32x4UnzipRight: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      DCHECK(dst == i.InputSimd128Register(0));
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      // src0 = [4, 5, 6, 7], src1 = [0, 1, 2, 3] (flipped from UnzipLeft).
      __ vmov(scratch, src1);
      __ vuzp(Neon32, scratch, dst);  // dst = [1, 3, 5, 7]
      break;
    }
    case kArmS32x4TransposeLeft: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      DCHECK(dst == i.InputSimd128Register(0));
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      // src0 = [0, 1, 2, 3], src1 = [4, 5, 6, 7]
      __ vmov(scratch, src1);
      __ vtrn(Neon32, dst, scratch);  // dst = [0, 4, 2, 6]
      break;
    }
    case kArmS32x4Shuffle: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src0 = i.InputSimd128Register(0),
                      src1 = i.InputSimd128Register(1);
      DCHECK_NE(dst, src0);
      DCHECK_NE(dst, src1);
      // Perform shuffle as a vmov per lane.
      int dst_code = dst.code() * 4;
      int src0_code = src0.code() * 4;
      int src1_code = src1.code() * 4;
      int32_t shuffle = i.InputInt32(2);
      for (int i = 0; i < 4; i++) {
        int lane = shuffle & 0x7;
        int src_code = src0_code;
        if (lane >= 4) {
          src_code = src1_code;
          lane &= 0x3;
        }
        __ VmovExtended(dst_code + i, src_code + lane);
        shuffle >>= 8;
      }
      break;
    }
    case kArmS32x4TransposeRight: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [4, 5, 6, 7], src1 = [0, 1, 2, 3] (flipped from TransposeLeft).
      __ vmov(scratch, src1);
      __ vtrn(Neon32, scratch, dst);  // dst = [1, 5, 3, 7]
      break;
    }
    case kArmS16x8ZipLeft: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      // src0 = [0, 1, 2, 3, ... 7], src1 = [8, 9, 10, 11, ... 15]
      DCHECK(dst == i.InputSimd128Register(0));
      __ vmov(dst.high(), src1.low());         // dst = [0, 1, 2, 3, 8, ... 11]
      __ vzip(Neon16, dst.low(), dst.high());  // dst = [0, 8, 1, 9, ... 11]
      break;
    }
    case kArmS16x8ZipRight: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [8, 9, 10, 11, ... 15], src1 = [0, 1, 2, 3, ... 7] (flipped).
      __ vmov(dst.low(), src1.high());
      __ vzip(Neon16, dst.low(), dst.high());  // dst = [4, 12, 5, 13, ... 15]
      break;
    }
    case kArmS16x8UnzipLeft: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [0, 1, 2, 3, ... 7], src1 = [8, 9, 10, 11, ... 15]
      __ vmov(scratch, src1);
      __ vuzp(Neon16, dst, scratch);  // dst = [0, 2, 4, 6, ... 14]
      break;
    }
    case kArmS16x8UnzipRight: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [8, 9, 10, 11, ... 15], src1 = [0, 1, 2, 3, ... 7] (flipped).
      __ vmov(scratch, src1);
      __ vuzp(Neon16, scratch, dst);  // dst = [1, 3, 5, 7, ... 15]
      break;
    }
    case kArmS16x8TransposeLeft: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [0, 1, 2, 3, ... 7], src1 = [8, 9, 10, 11, ... 15]
      __ vmov(scratch, src1);
      __ vtrn(Neon16, dst, scratch);  // dst = [0, 8, 2, 10, ... 14]
      break;
    }
    case kArmS16x8TransposeRight: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [8, 9, 10, 11, ... 15], src1 = [0, 1, 2, 3, ... 7] (flipped).
      __ vmov(scratch, src1);
      __ vtrn(Neon16, scratch, dst);  // dst = [1, 9, 3, 11, ... 15]
      break;
    }
    case kArmS8x16ZipLeft: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [0, 1, 2, 3, ... 15], src1 = [16, 17, 18, 19, ... 31]
      __ vmov(dst.high(), src1.low());
      __ vzip(Neon8, dst.low(), dst.high());  // dst = [0, 16, 1, 17, ... 23]
      break;
    }
    case kArmS8x16ZipRight: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [16, 17, 18, 19, ... 31], src1 = [0, 1, 2, 3, ... 15] (flipped).
      __ vmov(dst.low(), src1.high());
      __ vzip(Neon8, dst.low(), dst.high());  // dst = [8, 24, 9, 25, ... 31]
      break;
    }
    case kArmS8x16UnzipLeft: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [0, 1, 2, 3, ... 15], src1 = [16, 17, 18, 19, ... 31]
      __ vmov(scratch, src1);
      __ vuzp(Neon8, dst, scratch);  // dst = [0, 2, 4, 6, ... 30]
      break;
    }
    case kArmS8x16UnzipRight: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [16, 17, 18, 19, ... 31], src1 = [0, 1, 2, 3, ... 15] (flipped).
      __ vmov(scratch, src1);
      __ vuzp(Neon8, scratch, dst);  // dst = [1, 3, 5, 7, ... 31]
      break;
    }
    case kArmS8x16TransposeLeft: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [0, 1, 2, 3, ... 15], src1 = [16, 17, 18, 19, ... 31]
      __ vmov(scratch, src1);
      __ vtrn(Neon8, dst, scratch);  // dst = [0, 16, 2, 18, ... 30]
      break;
    }
    case kArmS8x16TransposeRight: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      DCHECK(dst == i.InputSimd128Register(0));
      // src0 = [16, 17, 18, 19, ... 31], src1 = [0, 1, 2, 3, ... 15] (flipped).
      __ vmov(scratch, src1);
      __ vtrn(Neon8, scratch, dst);  // dst = [1, 17, 3, 19, ... 31]
      break;
    }
    case kArmS8x16Concat: {
      __ vext(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1), i.InputInt4(2));
      break;
    }
    case kArmI8x16Swizzle: {
      Simd128Register dst = i.OutputSimd128Register(),
                      tbl = i.InputSimd128Register(0),
                      src = i.InputSimd128Register(1);
      NeonListOperand table(tbl);
      __ vtbl(dst.low(), table, src.low());
      __ vtbl(dst.high(), table, src.high());
      break;
    }
    case kArmI8x16Shuffle: {
      Simd128Register dst = i.OutputSimd128Register(),
                      src0 = i.InputSimd128Register(0),
                      src1 = i.InputSimd128Register(1);
      DwVfpRegister table_base = src0.low();
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      // If unary shuffle, table is src0 (2 d-registers), otherwise src0 and
      // src1. They must be consecutive.
      int table_size = src0 == src1 ? 2 : 4;
      DCHECK_IMPLIES(src0 != src1, src0.code() + 1 == src1.code());
      // The shuffle lane mask is a byte mask, materialize in scratch.
      int scratch_s_base = scratch.code() * 4;
      for (int j = 0; j < 4; j++) {
        uint32_t four_lanes = i.InputUint32(2 + j);
        DCHECK_EQ(0, four_lanes & (table_size == 2 ? 0xF0F0F0F0 : 0xE0E0E0E0));
        __ vmov(SwVfpRegister::from_code(scratch_s_base + j),
                Float32::FromBits(four_lanes));
      }
      NeonListOperand table(table_base, table_size);
      if (dst != src0 && dst != src1) {
        __ vtbl(dst.low(), table, scratch.low());
        __ vtbl(dst.high(), table, scratch.high());
      } else {
        __ vtbl(scratch.low(), table, scratch.low());
        __ vtbl(scratch.high(), table, scratch.high());
        __ vmov(dst, scratch);
      }
      break;
    }
    case kArmS32x2Reverse: {
      __ vrev64(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmS16x4Reverse: {
      __ vrev64(Neon16, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmS16x2Reverse: {
      __ vrev32(Neon16, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmS8x8Reverse: {
      __ vrev64(Neon8, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmS8x4Reverse: {
      __ vrev32(Neon8, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmS8x2Reverse: {
      __ vrev16(Neon8, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmV128AnyTrue: {
      const QwNeonRegister& src = i.InputSimd128Register(0);
      UseScratchRegisterScope temps(masm());
      DwVfpRegister scratch = temps.AcquireD();
      __ vpmax(NeonU32, scratch, src.low(), src.high());
      __ vpmax(NeonU32, scratch, scratch, scratch);
      __ ExtractLane(i.OutputRegister(), scratch, NeonS32, 0);
      __ cmp(i.OutputRegister(), Operand(0));
      __ mov(i.OutputRegister(), Operand(1), LeaveCC, ne);
      break;
    }
    case kArmI64x2AllTrue: {
      __ I64x2AllTrue(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kArmI32x4AllTrue: {
      const QwNeonRegister& src = i.InputSimd128Register(0);
      UseScratchRegisterScope temps(masm());
      DwVfpRegister scratch = temps.AcquireD();
      __ vpmin(NeonU32, scratch, src.low(), src.high());
      __ vpmin(NeonU32, scratch, scratch, scratch);
      __ ExtractLane(i.OutputRegister(), scratch, NeonS32, 0);
      __ cmp(i.OutputRegister(), Operand(0));
      __ mov(i.OutputRegister(), Operand(1), LeaveCC, ne);
      break;
    }
    case kArmI16x8AllTrue: {
      const QwNeonRegister& src = i.InputSimd128Register(0);
      UseScratchRegisterScope temps(masm());
      DwVfpRegister scratch = temps.AcquireD();
      __ vpmin(NeonU16, scratch, src.low(), src.high());
      __ vpmin(NeonU16, scratch, scratch, scratch);
      __ vpmin(NeonU16, scratch, scratch, scratch);
      __ ExtractLane(i.OutputRegister(), scratch, NeonS16, 0);
      __ cmp(i.OutputRegister(), Operand(0));
      __ mov(i.OutputRegister(), Operand(1), LeaveCC, ne);
      break;
    }
    case kArmI8x16AllTrue: {
      const QwNeonRegister& src = i.InputSimd128Register(0);
      UseScratchRegisterScope temps(masm());
      DwVfpRegister scratch = temps.AcquireD();
      __ vpmin(NeonU8, scratch, src.low(), src.high());
      __ vpmin(NeonU8, scratch, scratch, scratch);
      __ vpmin(NeonU8, scratch, scratch, scratch);
      __ vpmin(NeonU8, scratch, scratch, scratch);
      __ ExtractLane(i.OutputRegister(), scratch, NeonS8, 0);
      __ cmp(i.OutputRegister(), Operand(0));
      __ mov(i.OutputRegister(), Operand(1), LeaveCC, ne);
      break;
    }
    case kArmS128Load8Splat: {
      __ vld1r(Neon8, NeonListOperand(i.OutputSimd128Register()),
               i.NeonInputOperand(0));
      break;
    }
    case kArmS128Load16Splat: {
      __ vld1r(Neon16, NeonListOperand(i.OutputSimd128Register()),
               i.NeonInputOperand(0));
      break;
    }
    case kArmS128Load32Splat: {
      __ vld1r(Neon32, NeonListOperand(i.OutputSimd128Register()),
               i.NeonInputOperand(0));
      break;
    }
    case kArmS128Load64Splat: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vld1(Neon32, NeonListOperand(dst.low()), i.NeonInputOperand(0));
      __ Move(dst.high(), dst.low());
      break;
    }
    case kArmS128Load8x8S: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vld1(Neon8, NeonListOperand(dst.low()), i.NeonInputOperand(0));
      __ vmovl(NeonS8, dst, dst.low());
      break;
    }
    case kArmS128Load8x8U: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vld1(Neon8, NeonListOperand(dst.low()), i.NeonInputOperand(0));
      __ vmovl(NeonU8, dst, dst.low());
      break;
    }
    case kArmS128Load16x4S: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vld1(Neon16, NeonListOperand(dst.low()), i.NeonInputOperand(0));
      __ vmovl(NeonS16, dst, dst.low());
      break;
    }
    case kArmS128Load16x4U: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vld1(Neon16, NeonListOperand(dst.low()), i.NeonInputOperand(0));
      __ vmovl(NeonU16, dst, dst.low());
      break;
    }
    case kArmS128Load32x2S: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vld1(Neon32, NeonListOperand(dst.low()), i.NeonInputOperand(0));
      __ vmovl(NeonS32, dst, dst.low());
      break;
    }
    case kArmS128Load32x2U: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vld1(Neon32, NeonListOperand(dst.low()), i.NeonInputOperand(0));
      __ vmovl(NeonU32, dst, dst.low());
      break;
    }
    case kArmS128Load32Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vmov(dst, 0);
      __ vld1s(Neon32, NeonListOperand(dst.low()), 0, i.NeonInputOperand(0));
      break;
    }
    case kArmS128Load64Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vmov(dst.high(), 0);
      __ vld1(Neon64, NeonListOperand(dst.low()), i.NeonInputOperand(0));
      break;
    }
    case kArmS128LoadLaneLow: {
      Simd128Register dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      auto sz = static_cast<NeonSize>(MiscField::decode(instr->opcode()));
      NeonListOperand dst_list = NeonListOperand(dst.low());
      __ LoadLane(sz, dst_list, i.InputUint8(1), i.NeonInputOperand(2));
      break;
    }
    case kArmS128LoadLaneHigh: {
      Simd128Register dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      auto sz = static_cast<NeonSize>(MiscField::decode(instr->opcode()));
      NeonListOperand dst_list = NeonListOperand(dst.high());
      __ LoadLane(sz, dst_list, i.InputUint8(1), i.NeonInputOperand(2));
      break;
    }
    case kArmS128StoreLaneLow: {
      Simd128Register src = i.InputSimd128Register(0);
      NeonListOperand src_list = NeonListOperand(src.low());
      auto sz = static_cast<NeonSize>(MiscField::decode(instr->opcode()));
      __ StoreLane(sz, src_list, i.InputUint8(1), i.NeonInputOperand(2));
      break;
    }
    case kArmS128StoreLaneHigh: {
      Simd128Register src = i.InputSimd128Register(0);
      NeonListOperand src_list = NeonListOperand(src.high());
      auto sz = static_cast<NeonSize>(MiscField::decode(instr->opcode()));
      __ StoreLane(sz, src_list, i.InputUint8(1), i.NeonInputOperand(2));
      break;
    }
    case kAtomicLoadInt8:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(ldrsb);
      break;
    case kAtomicLoadUint8:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(ldrb);
      break;
    case kAtomicLoadInt16:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(ldrsh);
      break;
    case kAtomicLoadUint16:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(ldrh);
      break;
    case kAtomicLoadWord32:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(ldr);
      break;
    case kAtomicStoreWord8:
      ASSEMBLE_ATOMIC_STORE_INTEGER(strb,
                                    AtomicMemoryOrderField::decode(opcode));
      break;
    case kAtomicStoreWord16:
      ASSEMBLE_ATOMIC_STORE_INTEGER(strh,
                                    AtomicMemoryOrderField::decode(opcode));
      break;
    case kAtomicStoreWord32:
      ASSEMBLE_ATOMIC_STORE_INTEGER(str,
                                    AtomicMemoryOrderField::decode(opcode));
      break;
    case kAtomicExchangeInt8:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(ldrexb, strexb);
      __ sxtb(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicExchangeUint8:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(ldrexb, strexb);
      break;
    case kAtomicExchangeInt16:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(ldrexh, strexh);
      __ sxth(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicExchangeUint16:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(ldrexh, strexh);
      break;
    case kAtomicExchangeWord32:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(ldrex, strex);
      break;
    case kAtomicCompareExchangeInt8:
      __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));
      __ uxtb(i.TempRegister(2), i.InputRegister(2));
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(ldrexb, strexb,
                                               i.TempRegister(2));
      __ sxtb(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicCompareExchangeUint8:
      __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));
      __ uxtb(i.TempRegister(2), i.InputRegister(2));
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(ldrexb, strexb,
                                               i.TempRegister(2));
      break;
    case kAtomicCompareExchangeInt16:
      __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));
      __ uxth(i.TempRegister(2), i.InputRegister(2));
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(ldrexh, strexh,
                                               i.TempRegister(2));
      __ sxth(i.OutputRegister(0), i.OutputRegister(0));
      break;
    case kAtomicCompareEx
"""


```