Response: The user wants to understand the functionality of the provided C++ code snippet, which is a part of a larger file for the S390 architecture within the V8 JavaScript engine.

**Plan:**

1. **Identify the purpose of the code:** Based on the file path and the structure of the code (a large `switch` statement), it's likely a code generator for S390 instructions.
2. **Summarize the core functionality:** Focus on what the code does in general terms.
3. **Explain the connection to JavaScript:** Highlight how this code enables JavaScript execution on S390.
4. **Provide a JavaScript example:** Demonstrate a simple JavaScript operation and how it might be translated (conceptually) into S390 instructions by this code.
这个C++代码文件（`code-generator-s390.cc` 的一部分）的主要功能是**为V8 JavaScript引擎在S390架构上生成机器码**。

更具体地说，这段代码处理了V8的中间表示（可能是Hydrogen或Lithium IR）中的各种操作码（`case kArch...`, `case kS390_...`, `case kIeee754...`, `case kAtomic...`, `case kSimd...`），并将这些操作码转换为对应的S390汇编指令。

**可以归纳为以下几点功能：**

1. **指令生成:**  针对不同的V8中间表示操作，生成相应的S390架构的机器指令。这包括算术运算（加减乘除、位运算等）、内存操作（加载、存储）、浮点运算、比较操作、类型转换、原子操作以及SIMD（单指令多数据）指令等。
2. **寄存器分配和使用:**  代码中使用了诸如 `i.OutputRegister()`, `i.InputRegister()`, `i.InputDoubleRegister()`, `i.OutputSimd128Register()` 等方法，表明它负责从中间表示中获取操作数，并将它们映射到S390架构的寄存器。
3. **内存操作处理:**  代码中包含了对栈操作 (`kArchStackCheckOffset`, `kArchStackSlot`, `kS390_Push`, `kS390_StoreToStackSlot`) 和堆内存操作 (`kArchStoreWithWriteBarrier`) 的处理。`kArchStoreWithWriteBarrier` 尤其重要，因为它涉及到垃圾回收的写屏障机制，用于跟踪堆对象的修改。
4. **类型转换:**  处理了JavaScript中常见的数值类型之间的转换，例如整数到浮点数，浮点数到整数，以及不同位宽整数之间的转换。
5. **原子操作支持:**  为多线程JavaScript环境提供了原子操作的支持，例如 `kAtomicExchangeInt8`, `kAtomicAddWord32` 等，这些操作保证了在并发环境下的数据一致性。
6. **SIMD指令支持:**  处理了SIMD相关的操作码，例如 `kS390_F64x2Add`, `kS390_I32x4Shl` 等，这允许JavaScript代码利用SIMD指令进行并行计算，提高性能。
7. **浮点运算支持:**  实现了JavaScript中各种浮点运算，包括基本的算术运算、数学函数（如 `sqrt`, `sin`, `cos` 等）以及 IEEE 754 标准的浮点运算。

**与JavaScript的功能关系以及JavaScript示例:**

这段C++代码是V8引擎将高级JavaScript代码转换为底层机器码的关键部分。当JavaScript代码在S390架构上运行时，V8会先将其解析成中间表示，然后 `code-generator-s390.cc` 中的代码就会将这些中间表示翻译成S390的机器指令，CPU最终执行的就是这些指令。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

**在V8内部，上述JavaScript代码的 `a + b` 操作可能会被翻译成以下S390汇编指令 (概念性示例):**

1. **加载操作数:** 将变量 `a` 和 `b` 的值从内存或寄存器加载到S390的通用寄存器中。
   ```assembly
   lg  r1, [address_of_a]  ; 加载 a 的值到寄存器 r1
   lg  r2, [address_of_b]  ; 加载 b 的值到寄存器 r2
   ```
2. **执行加法:** 使用S390的加法指令将寄存器中的值相加。
   ```assembly
   agr r0, r1, r2        ; 将 r1 和 r2 的值相加，结果存储到 r0
   ```
3. **存储结果:** 将结果存储回内存或寄存器。
   ```assembly
   stg [address_of_result], r0 ; 将 r0 中的结果存储到 result 变量的地址
   ```

**代码片段中与上述示例相关的部分可能包括:**

- `case kS390_Add64:`:  处理64位整数的加法操作，这对应了上述 `agr` 指令的生成。
- `case kS390_LoadWord64:`: 处理从内存加载64位字的操作，对应了上述 `lg` 指令的生成。
- `case kS390_StoreWord64:`: 处理将64位字存储到内存的操作，对应了上述 `stg` 指令的生成。

总而言之，`code-generator-s390.cc` 这个文件是V8引擎在S390架构上执行JavaScript代码的基石，它负责将高级的JavaScript操作转化为底层的硬件指令。

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/code-generator-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
lhs_register, sp, Operand(offset));
      }

      constexpr size_t kValueIndex = 0;
      DCHECK(instr->InputAt(kValueIndex)->IsRegister());
      __ CmpU64(lhs_register, i.InputRegister(kValueIndex));
      break;
    }
    case kArchStackCheckOffset:
      __ LoadSmiLiteral(i.OutputRegister(),
                        Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      break;
    case kArchStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&addressing_mode, &index);
      Register value = i.InputRegister(index);
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);

      if (v8_flags.debug_code) {
        // Checking that |value| is not a cleared weakref: our write barrier
        // does not support that for now.
        __ CmpS64(value, Operand(kClearedWeakHeapObjectLower32));
        __ Check(ne, AbortReason::kOperandIsCleared);
      }

      OutOfLineRecordWrite* ool = zone()->New<OutOfLineRecordWrite>(
          this, object, operand, value, scratch0, scratch1, mode,
          DetermineStubCallMode(), &unwinding_info_writer_);
      __ StoreTaggedField(value, operand);

      if (mode > RecordWriteMode::kValueIsPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, scratch0,
                       MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                       ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier:
      UNREACHABLE();
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      __ AddS64(i.OutputRegister(), offset.from_stack_pointer() ? sp : fp,
                Operand(offset.offset()));
      break;
    }
    case kS390_Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ LoadF64(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ LoadF32(i.OutputFloatRegister(), MemOperand(fp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ LoadV128(i.OutputSimd128Register(), MemOperand(fp, offset),
                      kScratchReg);
        }
      } else {
        __ LoadU64(i.OutputRegister(), MemOperand(fp, offset));
      }
      break;
    }
    case kS390_Abs32:
      // TODO(john.yan): zero-ext
      __ lpr(i.OutputRegister(0), i.InputRegister(0));
      break;
    case kS390_Abs64:
      __ lpgr(i.OutputRegister(0), i.InputRegister(0));
      break;
    case kS390_And32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(nrk), RM32Instr(And), RIInstr(nilf));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(nr), RM32Instr(And), RIInstr(nilf));
      }
      break;
    case kS390_And64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(ngrk), RM64Instr(ng), nullInstr);
      } else {
        ASSEMBLE_BIN_OP(RRInstr(ngr), RM64Instr(ng), nullInstr);
      }
      break;
    case kS390_Or32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(ork), RM32Instr(Or), RIInstr(oilf));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(or_z), RM32Instr(Or), RIInstr(oilf));
      }
      break;
    case kS390_Or64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(ogrk), RM64Instr(og), nullInstr);
      } else {
        ASSEMBLE_BIN_OP(RRInstr(ogr), RM64Instr(og), nullInstr);
      }
      break;
    case kS390_Xor32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(xrk), RM32Instr(Xor), RIInstr(xilf));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(xr), RM32Instr(Xor), RIInstr(xilf));
      }
      break;
    case kS390_Xor64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(xgrk), RM64Instr(xg), nullInstr);
      } else {
        ASSEMBLE_BIN_OP(RRInstr(xgr), RM64Instr(xg), nullInstr);
      }
      break;
    case kS390_ShiftLeft32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(ShiftLeftU32), nullInstr,
                          RRIInstr(ShiftLeftU32));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(sll), nullInstr, RIInstr(sll));
      }
      break;
    case kS390_ShiftLeft64:
      ASSEMBLE_BIN_OP(RRRInstr(sllg), nullInstr, RRIInstr(sllg));
      break;
    case kS390_ShiftRight32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(srlk), nullInstr, RRIInstr(srlk));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(srl), nullInstr, RIInstr(srl));
      }
      break;
    case kS390_ShiftRight64:
      ASSEMBLE_BIN_OP(RRRInstr(srlg), nullInstr, RRIInstr(srlg));
      break;
    case kS390_ShiftRightArith32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(srak), nullInstr, RRIInstr(srak));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(sra), nullInstr, RIInstr(sra));
      }
      break;
    case kS390_ShiftRightArith64:
      ASSEMBLE_BIN_OP(RRRInstr(srag), nullInstr, RRIInstr(srag));
      break;
    case kS390_RotRight32: {
      // zero-ext
      if (HasRegisterInput(instr, 1)) {
        __ lcgr(kScratchReg, i.InputRegister(1));
        __ rll(i.OutputRegister(), i.InputRegister(0), kScratchReg);
      } else {
        __ rll(i.OutputRegister(), i.InputRegister(0),
               Operand(32 - i.InputInt32(1)));
      }
      CHECK_AND_ZERO_EXT_OUTPUT(2);
      break;
    }
    case kS390_RotRight64:
      if (HasRegisterInput(instr, 1)) {
        __ lcgr(kScratchReg, i.InputRegister(1));
        __ rllg(i.OutputRegister(), i.InputRegister(0), kScratchReg);
      } else {
        DCHECK(HasImmediateInput(instr, 1));
        __ rllg(i.OutputRegister(), i.InputRegister(0),
                Operand(64 - i.InputInt32(1)));
      }
      break;
    // TODO(john.yan): clean up kS390_RotLeftAnd...
    case kS390_RotLeftAndClear64:
      if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
        int shiftAmount = i.InputInt32(1);
        int endBit = 63 - shiftAmount;
        int startBit = 63 - i.InputInt32(2);
        __ RotateInsertSelectBits(i.OutputRegister(), i.InputRegister(0),
                                  Operand(startBit), Operand(endBit),
                                  Operand(shiftAmount), true);
      } else {
        int shiftAmount = i.InputInt32(1);
        int clearBit = 63 - i.InputInt32(2);
        __ rllg(i.OutputRegister(), i.InputRegister(0), Operand(shiftAmount));
        __ sllg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
        __ srlg(i.OutputRegister(), i.OutputRegister(),
                Operand(clearBit + shiftAmount));
        __ sllg(i.OutputRegister(), i.OutputRegister(), Operand(shiftAmount));
      }
      break;
    case kS390_RotLeftAndClearLeft64:
      if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
        int shiftAmount = i.InputInt32(1);
        int endBit = 63;
        int startBit = 63 - i.InputInt32(2);
        __ RotateInsertSelectBits(i.OutputRegister(), i.InputRegister(0),
                                  Operand(startBit), Operand(endBit),
                                  Operand(shiftAmount), true);
      } else {
        int shiftAmount = i.InputInt32(1);
        int clearBit = 63 - i.InputInt32(2);
        __ rllg(i.OutputRegister(), i.InputRegister(0), Operand(shiftAmount));
        __ sllg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
        __ srlg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
      }
      break;
    case kS390_RotLeftAndClearRight64:
      if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
        int shiftAmount = i.InputInt32(1);
        int endBit = 63 - i.InputInt32(2);
        int startBit = 0;
        __ RotateInsertSelectBits(i.OutputRegister(), i.InputRegister(0),
                                  Operand(startBit), Operand(endBit),
                                  Operand(shiftAmount), true);
      } else {
        int shiftAmount = i.InputInt32(1);
        int clearBit = i.InputInt32(2);
        __ rllg(i.OutputRegister(), i.InputRegister(0), Operand(shiftAmount));
        __ srlg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
        __ sllg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
      }
      break;
    case kS390_Add32: {
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(ark), RM32Instr(AddS32), RRIInstr(AddS32));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(ar), RM32Instr(AddS32), RIInstr(AddS32));
      }
      break;
    }
    case kS390_Add64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(agrk), RM64Instr(ag), RRIInstr(AddS64));
      } else {
        ASSEMBLE_BIN_OP(RRInstr(agr), RM64Instr(ag), RIInstr(agfi));
      }
      break;
    case kS390_AddFloat:
      ASSEMBLE_BIN_OP(DDInstr(aebr), DMTInstr(AddFloat32), nullInstr);
      break;
    case kS390_AddDouble:
      ASSEMBLE_BIN_OP(DDInstr(adbr), DMTInstr(AddFloat64), nullInstr);
      break;
    case kS390_Sub32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(srk), RM32Instr(SubS32), RRIInstr(SubS32));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(sr), RM32Instr(SubS32), RIInstr(SubS32));
      }
      break;
    case kS390_Sub64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(sgrk), RM64Instr(sg), RRIInstr(SubS64));
      } else {
        ASSEMBLE_BIN_OP(RRInstr(sgr), RM64Instr(sg), RIInstr(SubS64));
      }
      break;
    case kS390_SubFloat:
      ASSEMBLE_BIN_OP(DDInstr(sebr), DMTInstr(SubFloat32), nullInstr);
      break;
    case kS390_SubDouble:
      ASSEMBLE_BIN_OP(DDInstr(sdbr), DMTInstr(SubFloat64), nullInstr);
      break;
    case kS390_Mul32:
      // zero-ext
      if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
        ASSEMBLE_BIN32_OP(RRRInstr(msrkc), RM32Instr(msc), RIInstr(MulS32));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(MulS32), RM32Instr(MulS32), RIInstr(MulS32));
      }
      break;
    case kS390_Mul32WithOverflow:
      // zero-ext
      ASSEMBLE_BIN32_OP(RRRInstr(Mul32WithOverflowIfCCUnequal),
                        RRM32Instr(Mul32WithOverflowIfCCUnequal),
                        RRIInstr(Mul32WithOverflowIfCCUnequal));
      break;
    case kS390_Mul64:
      ASSEMBLE_BIN_OP(RRInstr(MulS64), RM64Instr(MulS64), RIInstr(MulS64));
      break;
    case kS390_Mul64WithOverflow: {
      Register dst = i.OutputRegister(), src1 = i.InputRegister(0),
               src2 = i.InputRegister(1);
      CHECK(!AreAliased(dst, src1, src2));
      if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
        __ msgrkc(dst, src1, src2);
      } else {
        // Mul high.
        __ MulHighS64(r1, src1, src2);
        // Mul low.
        __ mov(dst, src1);
        __ MulS64(dst, src2);
        // Test whether {high} is a sign-extension of {result}.
        __ ShiftRightS64(r0, dst, Operand(63));
        __ CmpU64(r1, r0);
      }
      break;
    }
    case kS390_MulHigh32:
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(MulHighS32), RRM32Instr(MulHighS32),
                      RRIInstr(MulHighS32));
      break;
    case kS390_MulHighU32:
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(MulHighU32), RRM32Instr(MulHighU32),
                      RRIInstr(MulHighU32));
      break;
    case kS390_MulHighU64:
      ASSEMBLE_BIN_OP(RRRInstr(MulHighU64), nullInstr, nullInstr);
      break;
    case kS390_MulHighS64:
      ASSEMBLE_BIN_OP(RRRInstr(MulHighS64), nullInstr, nullInstr);
      break;
    case kS390_MulFloat:
      ASSEMBLE_BIN_OP(DDInstr(meebr), DMTInstr(MulFloat32), nullInstr);
      break;
    case kS390_MulDouble:
      ASSEMBLE_BIN_OP(DDInstr(mdbr), DMTInstr(MulFloat64), nullInstr);
      break;
    case kS390_Div64:
      ASSEMBLE_BIN_OP(RRRInstr(DivS64), RRM64Instr(DivS64), nullInstr);
      break;
    case kS390_Div32: {
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(DivS32), RRM32Instr(DivS32), nullInstr);
      break;
    }
    case kS390_DivU64:
      ASSEMBLE_BIN_OP(RRRInstr(DivU64), RRM64Instr(DivU64), nullInstr);
      break;
    case kS390_DivU32: {
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(DivU32), RRM32Instr(DivU32), nullInstr);
      break;
    }
    case kS390_DivFloat:
      ASSEMBLE_BIN_OP(DDInstr(debr), DMTInstr(DivFloat32), nullInstr);
      break;
    case kS390_DivDouble:
      ASSEMBLE_BIN_OP(DDInstr(ddbr), DMTInstr(DivFloat64), nullInstr);
      break;
    case kS390_Mod32:
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(ModS32), RRM32Instr(ModS32), nullInstr);
      break;
    case kS390_ModU32:
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(ModU32), RRM32Instr(ModU32), nullInstr);
      break;
    case kS390_Mod64:
      ASSEMBLE_BIN_OP(RRRInstr(ModS64), RRM64Instr(ModS64), nullInstr);
      break;
    case kS390_ModU64:
      ASSEMBLE_BIN_OP(RRRInstr(ModU64), RRM64Instr(ModU64), nullInstr);
      break;
    case kS390_AbsFloat:
      __ lpebr(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_SqrtFloat:
      ASSEMBLE_UNARY_OP(D_DInstr(sqebr), nullInstr, nullInstr);
      break;
    case kS390_SqrtDouble:
      ASSEMBLE_UNARY_OP(D_DInstr(sqdbr), nullInstr, nullInstr);
      break;
    case kS390_FloorFloat:
      __ FloorF32(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_CeilFloat:
      __ CeilF32(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_TruncateFloat:
      __ TruncF32(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    //  Double operations
    case kS390_ModDouble:
      ASSEMBLE_FLOAT_MODULO();
      break;
    case kIeee754Float64Acos:
      ASSEMBLE_IEEE754_UNOP(acos);
      break;
    case kIeee754Float64Acosh:
      ASSEMBLE_IEEE754_UNOP(acosh);
      break;
    case kIeee754Float64Asin:
      ASSEMBLE_IEEE754_UNOP(asin);
      break;
    case kIeee754Float64Asinh:
      ASSEMBLE_IEEE754_UNOP(asinh);
      break;
    case kIeee754Float64Atanh:
      ASSEMBLE_IEEE754_UNOP(atanh);
      break;
    case kIeee754Float64Atan:
      ASSEMBLE_IEEE754_UNOP(atan);
      break;
    case kIeee754Float64Atan2:
      ASSEMBLE_IEEE754_BINOP(atan2);
      break;
    case kIeee754Float64Tan:
      ASSEMBLE_IEEE754_UNOP(tan);
      break;
    case kIeee754Float64Tanh:
      ASSEMBLE_IEEE754_UNOP(tanh);
      break;
    case kIeee754Float64Cbrt:
      ASSEMBLE_IEEE754_UNOP(cbrt);
      break;
    case kIeee754Float64Sin:
      ASSEMBLE_IEEE754_UNOP(sin);
      break;
    case kIeee754Float64Sinh:
      ASSEMBLE_IEEE754_UNOP(sinh);
      break;
    case kIeee754Float64Cos:
      ASSEMBLE_IEEE754_UNOP(cos);
      break;
    case kIeee754Float64Cosh:
      ASSEMBLE_IEEE754_UNOP(cosh);
      break;
    case kIeee754Float64Exp:
      ASSEMBLE_IEEE754_UNOP(exp);
      break;
    case kIeee754Float64Expm1:
      ASSEMBLE_IEEE754_UNOP(expm1);
      break;
    case kIeee754Float64Log:
      ASSEMBLE_IEEE754_UNOP(log);
      break;
    case kIeee754Float64Log1p:
      ASSEMBLE_IEEE754_UNOP(log1p);
      break;
    case kIeee754Float64Log2:
      ASSEMBLE_IEEE754_UNOP(log2);
      break;
    case kIeee754Float64Log10:
      ASSEMBLE_IEEE754_UNOP(log10);
      break;
    case kIeee754Float64Pow:
      ASSEMBLE_IEEE754_BINOP(pow);
      break;
    case kS390_Neg32:
      __ lcr(i.OutputRegister(), i.InputRegister(0));
      CHECK_AND_ZERO_EXT_OUTPUT(1);
      break;
    case kS390_Neg64:
      __ lcgr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_MaxFloat:
      __ FloatMax(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                  i.InputDoubleRegister(1));
      break;
    case kS390_MaxDouble:
      __ DoubleMax(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                   i.InputDoubleRegister(1));
      break;
    case kS390_MinFloat:
      __ FloatMin(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                  i.InputDoubleRegister(1));
      break;
    case kS390_FloatNearestInt:
      __ NearestIntF32(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_MinDouble:
      __ DoubleMin(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                   i.InputDoubleRegister(1));
      break;
    case kS390_AbsDouble:
      __ lpdbr(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_FloorDouble:
      __ FloorF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_CeilDouble:
      __ CeilF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_TruncateDouble:
      __ TruncF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_RoundDouble:
      __ fidbra(ROUND_TO_NEAREST_AWAY_FROM_0, i.OutputDoubleRegister(),
                i.InputDoubleRegister(0));
      break;
    case kS390_DoubleNearestInt:
      __ NearestIntF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_NegFloat:
      ASSEMBLE_UNARY_OP(D_DInstr(lcebr), nullInstr, nullInstr);
      break;
    case kS390_NegDouble:
      ASSEMBLE_UNARY_OP(D_DInstr(lcdbr), nullInstr, nullInstr);
      break;
    case kS390_Cntlz32: {
      __ CountLeadingZerosU32(i.OutputRegister(), i.InputRegister(0), r0);
      break;
    }
    case kS390_Cntlz64: {
      __ CountLeadingZerosU64(i.OutputRegister(), i.InputRegister(0), r0);
      break;
    }
    case kS390_Popcnt32:
      __ Popcnt32(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_Popcnt64:
      __ Popcnt64(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_Cmp32:
      ASSEMBLE_COMPARE32(CmpS32, CmpU32);
      break;
    case kS390_Cmp64:
      ASSEMBLE_COMPARE(CmpS64, CmpU64);
      break;
    case kS390_CmpFloat:
      ASSEMBLE_FLOAT_COMPARE(cebr, ceb, ley);
      // __ cebr(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      break;
    case kS390_CmpDouble:
      ASSEMBLE_FLOAT_COMPARE(cdbr, cdb, ldy);
      // __ cdbr(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      break;
    case kS390_Tst32:
      if (HasRegisterInput(instr, 1)) {
        __ And(r0, i.InputRegister(0), i.InputRegister(1));
      } else {
        // detect tmlh/tmhl/tmhh case
        Operand opnd = i.InputImmediate(1);
        if (is_uint16(opnd.immediate())) {
          __ tmll(i.InputRegister(0), opnd);
        } else {
          __ lr(r0, i.InputRegister(0));
          __ nilf(r0, opnd);
        }
      }
      break;
    case kS390_Tst64:
      if (HasRegisterInput(instr, 1)) {
        __ AndP(r0, i.InputRegister(0), i.InputRegister(1));
      } else {
        Operand opnd = i.InputImmediate(1);
        if (is_uint16(opnd.immediate())) {
          __ tmll(i.InputRegister(0), opnd);
        } else {
          __ AndP(r0, i.InputRegister(0), opnd);
        }
      }
      break;
    case kS390_Float64SilenceNaN: {
      DoubleRegister value = i.InputDoubleRegister(0);
      DoubleRegister result = i.OutputDoubleRegister();
      __ CanonicalizeNaN(result, value);
      break;
    }
    case kS390_Push: {
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
          __ lay(sp, MemOperand(sp, -kSystemPointerSize));
          __ StoreF32(i.InputDoubleRegister(1), MemOperand(sp));
          break;
        case MachineRepresentation::kFloat64:
          __ lay(sp, MemOperand(sp, -kDoubleSize));
          __ StoreF64(i.InputDoubleRegister(1), MemOperand(sp));
          break;
        case MachineRepresentation::kSimd128:
          __ lay(sp, MemOperand(sp, -kSimd128Size));
          __ StoreV128(i.InputDoubleRegister(1), MemOperand(sp), kScratchReg);
          break;
        default:
          __ Push(i.InputRegister(1));
          break;
      }
      frame_access_state()->IncreaseSPDelta(slots);
      break;
    }
    case kS390_PushFrame: {
      int num_slots = i.InputInt32(1);
      __ lay(sp, MemOperand(sp, -num_slots * kSystemPointerSize));
      if (instr->InputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->InputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ StoreF64(i.InputDoubleRegister(0), MemOperand(sp));
        } else {
          DCHECK_EQ(MachineRepresentation::kFloat32, op->representation());
          __ StoreF32(i.InputDoubleRegister(0), MemOperand(sp));
        }
      } else {
        __ StoreU64(i.InputRegister(0), MemOperand(sp));
      }
      break;
    }
    case kS390_StoreToStackSlot: {
      int slot = i.InputInt32(1);
      if (instr->InputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->InputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ StoreF64(i.InputDoubleRegister(0),
                      MemOperand(sp, slot * kSystemPointerSize));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ StoreF32(i.InputDoubleRegister(0),
                      MemOperand(sp, slot * kSystemPointerSize));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ StoreV128(i.InputDoubleRegister(0),
                       MemOperand(sp, slot * kSystemPointerSize), kScratchReg);
        }
      } else {
        __ StoreU64(i.InputRegister(0),
                    MemOperand(sp, slot * kSystemPointerSize));
      }
      break;
    }
    case kS390_SignExtendWord8ToInt32:
      __ lbr(i.OutputRegister(), i.InputRegister(0));
      CHECK_AND_ZERO_EXT_OUTPUT(1);
      break;
    case kS390_SignExtendWord16ToInt32:
      __ lhr(i.OutputRegister(), i.InputRegister(0));
      CHECK_AND_ZERO_EXT_OUTPUT(1);
      break;
    case kS390_SignExtendWord8ToInt64:
      __ lgbr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_SignExtendWord16ToInt64:
      __ lghr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_SignExtendWord32ToInt64:
      __ lgfr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_Uint32ToUint64:
      // Zero extend
      __ llgfr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_Int64ToInt32:
      // sign extend
      __ lgfr(i.OutputRegister(), i.InputRegister(0));
      break;
    // Convert Fixed to Floating Point
    case kS390_Int64ToFloat32:
      __ ConvertInt64ToFloat(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_Int64ToDouble:
      __ ConvertInt64ToDouble(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_Uint64ToFloat32:
      __ ConvertUnsignedInt64ToFloat(i.OutputDoubleRegister(),
                                     i.InputRegister(0));
      break;
    case kS390_Uint64ToDouble:
      __ ConvertUnsignedInt64ToDouble(i.OutputDoubleRegister(),
                                      i.InputRegister(0));
      break;
    case kS390_Int32ToFloat32:
      __ ConvertIntToFloat(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_Int32ToDouble:
      __ ConvertIntToDouble(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_Uint32ToFloat32:
      __ ConvertUnsignedIntToFloat(i.OutputDoubleRegister(),
                                   i.InputRegister(0));
      break;
    case kS390_Uint32ToDouble:
      __ ConvertUnsignedIntToDouble(i.OutputDoubleRegister(),
                                    i.InputRegister(0));
      break;
    case kS390_DoubleToInt32: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertDoubleToInt32(i.OutputRegister(0), i.InputDoubleRegister(0),
                              kRoundToNearest);
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_DoubleToUint32: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertDoubleToUnsignedInt32(i.OutputRegister(0),
                                      i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_DoubleToInt64: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertDoubleToInt64(i.OutputRegister(0), i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_DoubleToUint64: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertDoubleToUnsignedInt64(i.OutputRegister(0),
                                      i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_Float32ToInt32: {
      Label done;
      __ ConvertFloat32ToInt32(i.OutputRegister(0), i.InputDoubleRegister(0),
                               kRoundToZero);
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_i32) {
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        __ b(Condition(0xE), &done, Label::kNear);  // normal case
        __ llilh(i.OutputRegister(0), Operand(0x8000));
      }
      __ bind(&done);
      break;
    }
    case kS390_Float32ToUint32: {
      Label done;
      __ ConvertFloat32ToUnsignedInt32(i.OutputRegister(0),
                                       i.InputDoubleRegister(0));
      bool set_overflow_to_min_u32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_u32) {
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        __ b(Condition(0xE), &done, Label::kNear);  // normal case
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_Float32ToUint64: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertFloat32ToUnsignedInt64(i.OutputRegister(0),
                                       i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_Float32ToInt64: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertFloat32ToInt64(i.OutputRegister(0), i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_DoubleToFloat32:
      ASSEMBLE_UNARY_OP(D_DInstr(ledbr), nullInstr, nullInstr);
      break;
    case kS390_Float32ToDouble:
      ASSEMBLE_UNARY_OP(D_DInstr(ldebr), D_MInstr(LoadF32AsF64), nullInstr);
      break;
    case kS390_DoubleExtractLowWord32:
      __ lgdr(i.OutputRegister(), i.InputDoubleRegister(0));
      __ llgfr(i.OutputRegister(), i.OutputRegister());
      break;
    case kS390_DoubleExtractHighWord32:
      __ lgdr(i.OutputRegister(), i.InputDoubleRegister(0));
      __ srlg(i.OutputRegister(), i.OutputRegister(), Operand(32));
      break;
    case kS390_DoubleFromWord32Pair:
      __ LoadU32(kScratchReg, i.InputRegister(1));
      __ ShiftLeftU64(i.TempRegister(0), i.InputRegister(0), Operand(32));
      __ OrP(i.TempRegister(0), i.TempRegister(0), kScratchReg);
      __ MovInt64ToDouble(i.OutputDoubleRegister(), i.TempRegister(0));
      break;
    case kS390_DoubleInsertLowWord32:
      __ lgdr(kScratchReg, i.InputDoubleRegister(0));
      __ lr(kScratchReg, i.InputRegister(1));
      __ ldgr(i.OutputDoubleRegister(), kScratchReg);
      break;
    case kS390_DoubleInsertHighWord32:
      __ sllg(kScratchReg, i.InputRegister(1), Operand(32));
      __ lgdr(r0, i.InputDoubleRegister(0));
      __ lr(kScratchReg, r0);
      __ ldgr(i.OutputDoubleRegister(), kScratchReg);
      break;
    case kS390_DoubleConstruct:
      __ sllg(kScratchReg, i.InputRegister(0), Operand(32));
      __ lr(kScratchReg, i.InputRegister(1));

      // Bitwise convert from GPR to FPR
      __ ldgr(i.OutputDoubleRegister(), kScratchReg);
      break;
    case kS390_LoadWordS8:
      ASSEMBLE_LOAD_INTEGER(LoadS8);
      break;
    case kS390_BitcastFloat32ToInt32:
      ASSEMBLE_UNARY_OP(R_DInstr(MovFloatToInt), R_MInstr(LoadU32), nullInstr);
      break;
    case kS390_BitcastInt32ToFloat32:
      __ MovIntToFloat(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_BitcastDoubleToInt64:
      __ MovDoubleToInt64(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_BitcastInt64ToDouble:
      __ MovInt64ToDouble(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_LoadWordU8:
      ASSEMBLE_LOAD_INTEGER(LoadU8);
      break;
    case kS390_LoadWordU16:
      ASSEMBLE_LOAD_INTEGER(LoadU16);
      break;
    case kS390_LoadWordS16:
      ASSEMBLE_LOAD_INTEGER(LoadS16);
      break;
    case kS390_LoadWordU32:
      ASSEMBLE_LOAD_INTEGER(LoadU32);
      break;
    case kS390_LoadWordS32:
      ASSEMBLE_LOAD_INTEGER(LoadS32);
      break;
    case kS390_LoadReverse16:
      ASSEMBLE_LOAD_INTEGER(lrvh);
      break;
    case kS390_LoadReverse32:
      ASSEMBLE_LOAD_INTEGER(lrv);
      break;
    case kS390_LoadReverse64:
      ASSEMBLE_LOAD_INTEGER(lrvg);
      break;
    case kS390_LoadReverse16RR:
      __ lrvr(i.OutputRegister(), i.InputRegister(0));
      __ rll(i.OutputRegister(), i.OutputRegister(), Operand(16));
      break;
    case kS390_LoadReverse32RR:
      __ lrvr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_LoadReverse64RR:
      __ lrvgr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_LoadReverseSimd128RR:
      __ vlgv(r0, i.InputSimd128Register(0), MemOperand(r0, 0), Condition(3));
      __ vlgv(r1, i.InputSimd128Register(0), MemOperand(r0, 1), Condition(3));
      __ lrvgr(r0, r0);
      __ lrvgr(r1, r1);
      __ vlvg(i.OutputSimd128Register(), r0, MemOperand(r0, 1), Condition(3));
      __ vlvg(i.OutputSimd128Register(), r1, MemOperand(r0, 0), Condition(3));
      break;
    case kS390_LoadReverseSimd128: {
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode);
      Simd128Register dst = i.OutputSimd128Register();
      if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
          is_uint12(operand.offset())) {
        __ vlbr(dst, operand, Condition(4));
      } else {
        __ lrvg(r0, operand);
        __ lrvg(r1, MemOperand(operand.rx(), operand.rb(),
                               operand.offset() + kSystemPointerSize));
        __ vlvgp(dst, r1, r0);
      }
      break;
    }
    case kS390_LoadWord64:
      ASSEMBLE_LOAD_INTEGER(lg);
      break;
    case kS390_LoadAndTestWord32: {
      ASSEMBLE_LOADANDTEST32(ltr, lt_z);
      break;
    }
    case kS390_LoadAndTestWord64: {
      ASSEMBLE_LOADANDTEST64(ltgr, ltg);
      break;
    }
    case kS390_LoadFloat32:
      ASSEMBLE_LOAD_FLOAT(LoadF32);
      break;
    case kS390_LoadDouble:
      ASSEMBLE_LOAD_FLOAT(LoadF64);
      break;
    case kS390_LoadSimd128: {
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode);
      __ vl(i.OutputSimd128Register(), operand, Condition(0));
      break;
    }
    case kS390_StoreWord8:
      ASSEMBLE_STORE_INTEGER(StoreU8);
      break;
    case kS390_StoreWord16:
      ASSEMBLE_STORE_INTEGER(StoreU16);
      break;
    case kS390_StoreWord32:
      ASSEMBLE_STORE_INTEGER(StoreU32);
      break;
    case kS390_StoreWord64:
      ASSEMBLE_STORE_INTEGER(StoreU64);
      break;
    case kS390_StoreReverse16:
      ASSEMBLE_STORE_INTEGER(strvh);
      break;
    case kS390_StoreReverse32:
      ASSEMBLE_STORE_INTEGER(strv);
      break;
    case kS390_StoreReverse64:
      ASSEMBLE_STORE_INTEGER(strvg);
      break;
    case kS390_StoreReverseSimd128: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode, &index);
      if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
          is_uint12(operand.offset())) {
        __ vstbr(i.InputSimd128Register(index), operand, Condition(4));
      } else {
        __ vlgv(r0, i.InputSimd128Register(index), MemOperand(r0, 1),
                Condition(3));
        __ vlgv(r1, i.InputSimd128Register(index), MemOperand(r0, 0),
                Condition(3));
        __ strvg(r0, operand);
        __ strvg(r1, MemOperand(operand.rx(), operand.rb(),
                                operand.offset() + kSystemPointerSize));
      }
      break;
    }
    case kS390_StoreFloat32:
      ASSEMBLE_STORE_FLOAT32();
      break;
    case kS390_StoreDouble:
      ASSEMBLE_STORE_DOUBLE();
      break;
    case kS390_StoreSimd128: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode, &index);
      __ vst(i.InputSimd128Register(index), operand, Condition(0));
      break;
    }
    case kS390_Lay: {
      MemOperand mem = i.MemoryOperand();
      if (!is_int20(mem.offset())) {
        // Add directly to the base register in case the index register (rx) is
        // r0.
        DCHECK(is_int32(mem.offset()));
        __ AddS64(ip, mem.rb(), Operand(mem.offset()));
        mem = MemOperand(mem.rx(), ip);
      }
      __ lay(i.OutputRegister(), mem);
      break;
    }
    case kAtomicExchangeInt8:
    case kAtomicExchangeUint8: {
      Register base = i.InputRegister(0);
      Register index = i.InputRegister(1);
      Register value = i.InputRegister(2);
      Register output = i.OutputRegister();
      __ la(r1, MemOperand(base, index));
      __ AtomicExchangeU8(r1, value, output, r0);
      if (opcode == kAtomicExchangeInt8) {
        __ LoadS8(output, output);
      } else {
        __ LoadU8(output, output);
      }
      break;
    }
    case kAtomicExchangeInt16:
    case kAtomicExchangeUint16: {
      Register base = i.InputRegister(0);
      Register index = i.InputRegister(1);
      Register value = i.InputRegister(2);
      Register output = i.OutputRegister();
      bool reverse_bytes = is_wasm_on_be(info());
      __ la(r1, MemOperand(base, index));
      Register value_ = value;
      if (reverse_bytes) {
        value_ = ip;
        __ lrvr(value_, value);
        __ ShiftRightU32(value_, value_, Operand(16));
      }
      __ AtomicExchangeU16(r1, value_, output, r0);
      if (reverse_bytes) {
        __ lrvr(output, output);
        __ ShiftRightU32(output, output, Operand(16));
      }
      if (opcode == kAtomicExchangeInt16) {
        __ lghr(output, output);
      } else {
        __ llghr(output, output);
      }
      break;
    }
    case kAtomicExchangeWord32: {
      Register base = i.InputRegister(0);
      Register index = i.InputRegister(1);
      Register value = i.InputRegister(2);
      Register output = i.OutputRegister();
      Label do_cs;
      bool reverse_bytes = is_wasm_on_be(info());
      __ lay(r1, MemOperand(base, index));
      Register value_ = value;
      if (reverse_bytes) {
        value_ = ip;
        __ lrvr(value_, value);
      }
      __ LoadU32(output, MemOperand(r1));
      __ bind(&do_cs);
      __ cs(output, value_, MemOperand(r1));
      __ bne(&do_cs, Label::kNear);
      if (reverse_bytes) {
        __ lrvr(output, output);
        __ LoadU32(output, output);
      }
      break;
    }
    case kAtomicCompareExchangeInt8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_BYTE(LoadS8);
      break;
    case kAtomicCompareExchangeUint8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_BYTE(LoadU8);
      break;
    case kAtomicCompareExchangeInt16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_HALFWORD(LoadS16);
      break;
    case kAtomicCompareExchangeUint16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_HALFWORD(LoadU16);
      break;
    case kAtomicCompareExchangeWord32:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_WORD();
      break;
#define ATOMIC_BINOP_CASE(op, inst)                                          \
  case kAtomic##op##Int8:                                                    \
    ASSEMBLE_ATOMIC_BINOP_BYTE(inst, [&]() {                                 \
      intptr_t shift_right = static_cast<intptr_t>(shift_amount);            \
      __ srlk(result, prev, Operand(shift_right));                           \
      __ LoadS8(result, result);                                             \
    });                                                                      \
    break;                                                                   \
  case kAtomic##op##Uint8:                                                   \
    ASSEMBLE_ATOMIC_BINOP_BYTE(inst, [&]() {                                 \
      int rotate_left = shift_amount == 0 ? 0 : 64 - shift_amount;           \
      __ RotateInsertSelectBits(result, prev, Operand(56), Operand(63),      \
                                Operand(static_cast<intptr_t>(rotate_left)), \
                                true);                                       \
    });                                                                      \
    break;                                                                   \
  case kAtomic##op##Int16:                                                   \
    ASSEMBLE_ATOMIC_BINOP_HALFWORD(inst, [&]() {                             \
      intptr_t shift_right = static_cast<intptr_t>(shift_amount);            \
      __ srlk(result, prev, Operand(shift_right));                           \
      if (is_wasm_on_be(info())) {                                           \
        __ lrvr(result, result);                                             \
        __ ShiftRightS32(result, result, Operand(16));                       \
      }                                                                      \
      __ LoadS16(result, result);                                            \
    });                                                                      \
    break;                                                                   \
  case kAtomic##op##Uint16:                                                  \
    ASSEMBLE_ATOMIC_BINOP_HALFWORD(inst, [&]() {                             \
      int rotate_left = shift_amount == 0 ? 0 : 64 - shift_amount;           \
      __ RotateInsertSelectBits(result, prev, Operand(48), Operand(63),      \
                                Operand(static_cast<intptr_t>(rotate_left)), \
                                true);                                       \
      if (is_wasm_on_be(info())) {                                           \
        __ lrvr(result, result);                                             \
        __ ShiftRightU32(result, result, Operand(16));                       \
      }                                                                      \
    });                                                                      \
    break;
      ATOMIC_BINOP_CASE(Add, AddS32)
      ATOMIC_BINOP_CASE(Sub, SubS32)
      ATOMIC_BINOP_CASE(And, And)
      ATOMIC_BINOP_CASE(Or, Or)
      ATOMIC_BINOP_CASE(Xor, Xor)
#undef ATOMIC_BINOP_CASE
    case kAtomicAddWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(laa, AddS32);
      break;
    case kAtomicSubWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(LoadAndSub32, SubS32);
      break;
    case kAtomicAndWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(lan, AndP);
      break;
    case kAtomicOrWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(lao, OrP);
      break;
    case kAtomicXorWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(lax, XorP);
      break;
    case kS390_Word64AtomicAddUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(laag, AddS64);
      break;
    case kS390_Word64AtomicSubUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(LoadAndSub64, SubS64);
      break;
    case kS390_Word64AtomicAndUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(lang, AndP);
      break;
    case kS390_Word64AtomicOrUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(laog, OrP);
      break;
    case kS390_Word64AtomicXorUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(laxg, XorP);
      break;
    case kS390_Word64AtomicExchangeUint64: {
      Register base = i.InputRegister(0);
      Register index = i.InputRegister(1);
      Register value = i.InputRegister(2);
      Register output = i.OutputRegister();
      bool reverse_bytes = is_wasm_on_be(info());
      Label do_cs;
      Register value_ = value;
      __ la(r1, MemOperand(base, index));
      if (reverse_bytes) {
        value_ = ip;
        __ lrvgr(value_, value);
      }
      __ lg(output, MemOperand(r1));
      __ bind(&do_cs);
      __ csg(output, value_, MemOperand(r1));
      __ bne(&do_cs, Label::kNear);
      if (reverse_bytes) {
        __ lrvgr(output, output);
      }
      break;
    }
    case kS390_Word64AtomicCompareExchangeUint64:
      ASSEMBLE_ATOMIC64_COMP_EXCHANGE_WORD64();
      break;
      // Simd Support.
#define SIMD_SHIFT_LIST(V) \
  V(I64x2Shl)              \
  V(I64x2ShrS)             \
  V(I64x2ShrU)             \
  V(I32x4Shl)              \
  V(I32x4ShrS)             \
  V(I32x4ShrU)             \
  V(I16x8Shl)              \
  V(I16x8ShrS)             \
  V(I16x8ShrU)             \
  V(I8x16Shl)              \
  V(I8x16ShrS)             \
  V(I8x16ShrU)

#define EMIT_SIMD_SHIFT(name)                                     \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputRegister(1), kScratchDoubleReg);               \
    break;                                                        \
  }
      SIMD_SHIFT_LIST(EMIT_SIMD_SHIFT)
#undef EMIT_SIMD_SHIFT
#undef SIMD_SHIFT_LIST

#define SIMD_BINOP_LIST(V) \
  V(F64x2Add)              \
  V(F64x2Sub)              \
  V(F64x2Mul)              \
  V(F64x2Div)              \
  V(F64x2Min)              \
  V(F64x2Max)              \
  V(F64x2Eq)               \
  V(F64x2Ne)               \
  V(F64x2Lt)               \
  V(F64x2Le)               \
  V(F64x2Pmin)             \
  V(F64x2Pmax)             \
  V(F32x4Add)              \
  V(F32x4Sub)              \
  V(F32x4Mul)              \
  V(F32x4Div)              \
  V(F32x4Min)              \
  V(F32x4Max)              \
  V(F32x4Eq)               \
  V(F32x4Ne)               \
  V(F32x4Lt)               \
  V(F32x4Le)               \
  V(F32x4Pmin)             \
  V(F32x4Pmax)             \
  V(I64x2Add)              \
  V(I64x2Sub)              \
  V(I64x2Eq)               \
  V(I64x2Ne)               \
  V(I64x2GtS)              \
  V(I64x2GeS)              \
  V(I32x4Add)              \
  V(I32x4Sub)              \
  V(I32x4Mul)              \
  V(I32x4Eq)               \
  V(I32x4Ne)               \
  V(I32x4GtS)              \
  V(I32x4GeS)              \
  V(I32x4GtU)              \
  V(I32x4MinS)             \
  V(I32x4MinU)             \
  V(I32x4MaxS)             \
  V(I32x4MaxU)             \
  V(I16x8Add)              \
  V(I16x8Sub)              \
  V(I16x8Mul)              \
  V(I16x8Eq)               \
  V(I16x8Ne)               \
  V(I16x8GtS)              \
  V(I16x8GeS)              \
  V(I16x8GtU)              \
  V(I16x8MinS)             \
  V(I16x8MinU)             \
  V(I16x8MaxS)             \
  V(I16x8MaxU)             \
  V(I16x8RoundingAverageU) \
  V(I8x16Add)              \
  V(I8x16Sub)              \
  V(I8x16Eq)               \
  V(I8x16Ne)               \
  V(I8x16GtS)              \
  V(I8x16GeS)              \
  V(I8x16GtU)              \
  V(I8x16MinS)             \
  V(I8x16MinU)             \
  V(I8x16MaxS)             \
  V(I8x16MaxU)             \
  V(I8x16RoundingAverageU) \
  V(S128And)               \
  V(S128Or)                \
  V(S128Xor)               \
  V(S128AndNot)

#define EMIT_SIMD_BINOP(name)                                     \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1));                           \
    break;                                                        \
  }
      SIMD_BINOP_LIST(EMIT_SIMD_BINOP)
#undef EMIT_SIMD_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_UNOP_LIST(V)                                     \
  V(F64x2Splat, Simd128Register, DoubleRegister)              \
  V(F64x2Abs, Simd128Register, Simd128Register)               \
  V(F64x2Neg, Simd128Register, Simd128Register)               \
  V(F64x2Sqrt, Simd128Register, Simd128Register)              \
  V(F64x2Ceil, Simd128Register, Simd128Register)              \
  V(F64x2Floor, Simd128Register, Simd128Register)             \
  V(F64x2Trunc, Simd128Register, Simd128Register)             \
  V(F64x2NearestInt, Simd128Register, Simd128Register)        \
  V(F32x4Splat, Simd128Register, DoubleRegister)              \
  V(F32x4Abs, Simd128Register, Simd128Register)               \
  V(F32x4Neg, Simd128Register, Simd128Register)               \
  V(F32x4Sqrt, Simd128Register, Simd128Register)              \
  V(F32x4Ceil, Simd128Register, Simd128Register)              \
  V(F32x4Floor, Simd128Register, Simd128Register)             \
  V(F32x4Trunc, Simd128Register, Simd128Register)             \
  V(F32x4NearestInt, Simd128Register, Simd128Register)        \
  V(I64x2Splat, Simd128Register, Register)                    \
  V(I64x2Abs, Simd128Register, Simd128Register)               \
  V(I64x2Neg, Simd128Register, Simd128Register)               \
  V(I64x2SConvertI32x4Low, Simd128Register, Simd128Register)  \
  V(I64x2SConvertI32x4High, Simd128Register, Simd128Register) \
  V(I64x2UConvertI32x4Low, Simd128Register, Simd128Register)  \
  V(I64x2UConvertI32x4High, Simd128Register, Simd128Register) \
  V(I32x4Splat, Simd128Register, Register)                    \
  V(I32x4Abs, Simd128Register, Simd128Register)               \
  V(I32x4Neg, Simd128Register, Simd128Register)               \
  V(I32x4SConvertI16x8Low, Simd128Register, Simd128Register)  \
  V(I32x4SConvertI16x8High, Simd128Register, Simd128Register) \
  V(I32x4UConvertI16x8Low, Simd128Register, Simd128Register)  \
  V(I32x4UConvertI16x8High, Simd128Register, Simd128Register) \
  V(I16x8Splat, Simd128Register, Register)                    \
  V(I16x8Abs, Simd128Register, Simd128Register)               \
  V(I16x8Neg, Simd128Register, Simd128Register)               \
  V(I16x8SConvertI8x16Low, Simd128Register, Simd128Register)  \
  V(I16x8SConvertI8x16High, Simd128Register, Simd128Register) \
  V(I16x8UConvertI8x16Low, Simd128Register, Simd128Register)  \
  V(I16x8UConvertI8x16High, Simd128Register, Simd128Register) \
  V(I8x16Splat, Simd128Register, Register)                    \
  V(I8x16Abs, Simd128Register, Simd128Register)               \
  V(I8x16Neg, Simd128Register, Simd128Register)               \
  V(S128Not, Simd128Register, Simd128Register)

#define EMIT_SIMD_UNOP(name, dtype, stype)         \
  case kS390_##name: {                             \
    __ name(i.Output##dtype(), i.Input##stype(0)); \
    break;                                         \
  }
      SIMD_UNOP_LIST(EMIT_SIMD_UNOP)
#undef EMIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_EXTRACT_LANE_LIST(V)     \
  V(F64x2ExtractLane, DoubleRegister) \
  V(F32x4ExtractLane, DoubleRegister) \
  V(I64x2ExtractLane, Register)       \
  V(I32x4ExtractLane, Register)       \
  V(I16x8ExtractLaneU, Register)      \
  V(I16x8ExtractLaneS, Register)      \
  V(I8x16ExtractLaneU, Register)      \
  V(I8x16ExtractLaneS, Register)

#define EMIT_SIMD_EXTRACT_LANE(name, dtype)                               \
  case kS390_##name: {                                                    \
    __ name(i.Output##dtype(), i.InputSimd128Register(0), i.InputInt8(1), \
            kScratchReg);                                                 \
    break;                                                                \
  }
      SIMD_EXTRACT_LANE_LIST(EMIT_SIMD_EXTRACT_LANE)
#undef EMIT_SIMD_EXTRACT_LANE
#undef SIMD_EXTRACT_LANE_LIST

#define SIMD_REPLACE_LANE_LIST(V)     \
  V(F64x2ReplaceLane, DoubleRegister) \
  V(F32x4ReplaceLane, DoubleRegister) \
  V(I64x2ReplaceLane, Register)       \
  V(I32x4ReplaceLane, Register)       \
  V(I16x8ReplaceLane, Register)       \
  V(I8x16ReplaceLane, Register)

#define EMIT_SIMD_REPLACE_LANE(name, stype)                       \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.Input##stype(2), i.InputInt8(1), kScratchReg);      \
    break;                                                        \
  }
      SIMD_REPLACE_LANE_LIST(EMIT_SIMD_REPLACE_LANE)
#undef EMIT_SIMD_REPLACE_LANE
#undef SIMD_REPLACE_LANE_LIST

#define SIMD_EXT_MUL_LIST(V) \
  V(I64x2ExtMulLowI32x4S)    \
  V(I64x2ExtMulHighI32x4S)   \
  V(I64x2ExtMulLowI32x4U)    \
  V(I64x2ExtMulHighI32x4U)   \
  V(I32x4ExtMulLowI16x8S)    \
  V(I32x4ExtMulHighI16x8S)   \
  V(I32x4ExtMulLowI16x8U)    \
  V(I32x4ExtMulHighI16x8U)   \
  V(I16x8ExtMulLowI8x16S)    \
  V(I16x8ExtMulHighI8x16S)   \
  V(I16x8ExtMulLowI8x16U)    \
  V(I16x8ExtMulHighI8x16U)

#define EMIT_SIMD_EXT_MUL(name)                                   \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1), kScratchDoubleReg);        \
    break;                                                        \
  }
      SIMD_EXT_MUL_LIST(EMIT_SIMD_EXT_MUL)
#undef EMIT_SIMD_EXT_MUL
#undef SIMD_EXT_MUL_LIST

#define SIMD_ALL_TRUE_LIST(V) \
  V(I64x2AllTrue)             \
  V(I32x4AllTrue)             \
  V(I16x8AllTrue)             \
  V(I8x16AllTrue)

#define EMIT_SIMD_ALL_TRUE(name)                                        \
  case kS390_##name: {                                                  \
    __ name(i.OutputRegister(), i.InputSimd128Register(0), kScratchReg, \
            kScratchDoubleReg);                                         \
    break;                                                              \
  }
      SIMD_ALL_TRUE_LIST(EMIT_SIMD_ALL_TRUE)
#undef EMIT_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_QFM_LIST(V) \
  V(F64x2Qfma)           \
  V(F64x2Qfms)           \
  V(F32x4Qfma)           \
  V(F32x4Qfms)

#define EMIT_SIMD_QFM(name)                                        \
  case kS390_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0),  \
            i.InputSimd128Register(1), i.InputSimd128Register(2)); \
    break;                                                         \
  }
      SIMD_QFM_LIST(EMIT_SIMD_QFM)
#undef EMIT_SIMD_QFM
#undef SIMD_QFM_LIST

#define SIMD_ADD_SUB_SAT_LIST(V) \
  V(I16x8AddSatS)                \
  V(I16x8SubSatS)                \
  V(I16x8AddSatU)                \
  V(I16x8SubSatU)                \
  V(I8x16AddSatS)                \
  V(I8x16SubSatS)                \
  V(I8x16AddSatU)                \
  V(I8x16SubSatU)

#define EMIT_SIMD_ADD_SUB_SAT(name)                               \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1), kScratchDoubleReg,         \
            i.ToSimd128Register(instr->TempAt(0)));               \
    break;                                                        \
  }
      SIMD_ADD_SUB_SAT_LIST(EMIT_SIMD_ADD_SUB_SAT)
#undef EMIT_SIMD_ADD_SUB_SAT
#undef SIMD_ADD_SUB_SAT_LIST

#define SIMD_EXT_ADD_PAIRWISE_LIST(V) \
  V(I32x4ExtAddPairwiseI16x8S)        \
  V(I32x4ExtAddPairwiseI16x8U)        \
  V(I16x8ExtAddPairwiseI8x16S)        \
  V(I16x8ExtAddPairwiseI8x16U)

#define EMIT_SIMD_EXT_ADD_PAIRWISE(name)                               \
  case kS390_##name: {                                                 \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0),      \
            kScratchDoubleReg, i.ToSimd128Register(instr->TempAt(0))); \
    break;                                                             \
  }
      SIMD_EXT_ADD_PAIRWISE_LIST(EMIT_SIMD_EXT_ADD_PAIRWISE)
#undef EMIT_SIMD_EXT_ADD_PAIRWISE
#undef SIMD_EXT_ADD_PAIRWISE_LIST

    case kS390_I64x2Mul: {
      __ I64x2Mul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), r0, r1, ip);
      break;
    }
    case kS390_I32x4GeU: {
      __ I32x4GeU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I16x8GeU: {
      __ I16x8GeU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I8x16GeU: {
      __ I8x16GeU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    // vector boolean unops
    case kS390_V128AnyTrue: {
      __ V128AnyTrue(i.OutputRegister(), i.InputSimd128Register(0),
                     kScratchReg);
      break;
    }
    // vector bitwise ops
    case kS390_S128Const: {
      uint64_t low = make_uint64(i.InputUint32(1), i.InputUint32(0));
      uint64_t high = make_uint64(i.InputUint32(3), i.InputUint32(2));
      __ S128Const(i.OutputSimd128Register(), high, low, r0, ip);
      break;
    }
    case kS390_S128Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ S128Zero(dst, dst);
      break;
    }
    case kS390_S128AllOnes: {
      Simd128Register dst = i.OutputSimd128Register();
      __ S128AllOnes(dst, dst);
      break;
    }
    case kS390_S128Select: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register mask = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register src2 = i.InputSimd128Register(2);
      __ S128Select(dst, src1, src2, mask);
      break;
    }
    // vector conversions
    case kS390_I32x4SConvertF32x4: {
      __ I32x4SConvertF32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchReg);
      break;
    }
    case kS390_I32x4UConvertF32x4: {
      __ I32x4UConvertF32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchReg);
      break;
    }
    case kS390_F32x4SConvertI32x4: {
      __ F32x4SConvertI32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchReg);
      break;
    }
    case kS390_F32x4UConvertI32x4: {
      __ F32x4UConvertI32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchReg);
      break;
    }
    case kS390_I16x8SConvertI32x4: {
      __ I16x8SConvertI32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0),
                            i.InputSimd128Register(1));
      break;
    }
    case kS390_I8x16SConvertI16x8: {
      __ I8x16SConvertI16x8(i.OutputSimd128Register(),
                            i.InputSimd128Register(0),
                            i.InputSimd128Register(1));
      break;
    }
    case kS390_I16x8UConvertI32x4: {
      __ I16x8UConvertI32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0),
                            i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I8x16UConvertI16x8: {
      __ I8x16UConvertI16x8(i.OutputSimd128Register(),
                            i.InputSimd128Register(0),
                            i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I8x16Shuffle: {
      uint64_t low = make_uint64(i.InputUint32(3), i.InputUint32(2));
      uint64_t high = make_uint64(i.InputUint32(5), i.InputUint32(4));
      __ I8x16Shuffle(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), high, low, r0, ip,
                      kScratchDoubleReg);
      break;
    }
    case kS390_I8x16Swizzle: {
      __ I8x16Swizzle(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), r0, r1, kScratchDoubleReg);
      break;
    }
    case kS390_I64x2BitMask: {
      __ I64x2BitMask(i.OutputRegister(), i.InputSimd128Register(0),
                      kScratchReg, kScratchDoubleReg);
      break;
    }
    case kS390_I32x4BitMask: {
      __ I32x4BitMask(i.OutputRegister(), i.InputSimd128Register(0),
                      kScratchReg, kScratchDoubleReg);
      break;
    }
    case kS390_I16x8BitMask: {
      __ I16x8BitMask(i.OutputRegister(), i.InputSimd128Register(0),
                      kScratchReg, kScratchDoubleReg);
      break;
    }
    case kS390_I8x16BitMask: {
      __ I8x16BitMask(i.OutputRegister(), i.InputSimd128Register(0), r0, ip,
                      kScratchDoubleReg);
      break;
    }
    case kS390_I32x4DotI16x8S: {
      __ I32x4DotI16x8S(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }

    case kS390_I16x8DotI8x16S: {
      __ I16x8DotI8x16S(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I32x4DotI8x16AddS: {
      __ I32x4DotI8x16AddS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                           i.InputSimd128Register(1), i.InputSimd128Register(2),
                           kScratchDoubleReg, i.TempSimd128Register(0));
      break;
    }
    case kS390_I16x8Q15MulRSatS: {
      __ I16x8Q15MulRSatS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg,
                          i.ToSimd128Register(instr->TempAt(0)),
                          i.ToSimd128Register(instr->TempAt(1)));
      break;
    }
    case kS390_I8x16Popcnt: {
      __ I8x16Popcnt(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kS390_F64x2ConvertLowI32x4S: {
      __ F64x2ConvertLowI32x4S(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kS390_F64x2ConvertLowI32x4U: {
      __ F64x2ConvertLowI32x4U(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kS390_F64x2PromoteLowF32x4: {
      __ F64x2PromoteLowF32x4(i.OutputSimd128Register(),
                              i.InputSimd128Register(0), kScratchDoubleReg, r0,
                              r1, ip);
      break;
    }
    case kS390_F32x4DemoteF64x2Zero: {
      __ F32x4DemoteF64x2Zero(i.OutputSimd128Register(),
                              i.InputSimd128Register(0), kScratchDoubleReg, r0,
                              r1, ip);
      break;
    }
    case kS390_I32x4TruncSatF64x2SZero: {
      __ I32x4TruncSatF64x2SZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kS390_I32x4TruncSatF64x2UZero: {
      __ I32x4TruncSatF64x2UZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
#define LOAD_SPLAT(type)                           \
  AddressingMode mode = kMode_None;                \
  MemOperand operand = i.MemoryOperand(&mode);     \
  Simd128Register dst = i.OutputSimd128Register(); \
  __ LoadAndSplat##type##LE(dst, operand, kScratchReg);
    case kS390_S128Load64Splat: {
      LOAD_SPLAT(64x2);
      break;
    }
    case kS390_S128Load32Splat: {
      LOAD_SPLAT(32x4);
      break;
    }
    case kS390_S128Load16Splat: {
      LOAD_SPLAT(16x8);
      break;
    }
    case kS390_S128Load8Splat: {
      LOAD_SPLAT(8x16);
      break;
    }
#undef LOAD_SPLAT
#define LOAD_EXTEND(type)                          \
  AddressingMode mode = kMode_None;                \
  MemOperand operand = i.MemoryOperand(&mode);     \
  Simd128Register dst = i.OutputSimd128Register(); \
  __ LoadAndExtend##type##LE(dst, operand, kScratchReg);
    case kS390_S128Load32x2U: {
      LOAD_EXTEND(32x2U);
      break;
    }
    case kS390_S128Load32x2S: {
      LOAD_EXTEND(32x2S);
      break;
    }
    case kS390_S128Load16x4U: {
      LOAD_EXTEND(16x4U);
      break;
    }
    case kS390_S128Load16x4S: {
      LOAD_EXTEND(16x4S);
      break;
    }
    case kS390_S128Load8x8U: {
      LOAD_EXTEND(8x8U);
      break;
    }
    case kS390_S128Load8x8S: {
      LOAD_EXTEND(8x8S);
      break;
    }
#undef LOAD_EXTEND
#define LOAD_AND_ZERO(type)                        \
  AddressingMode mode = kMode_None;                \
  MemOperand operand = i.MemoryOperand(&mode);     \
  Simd128Register dst = i.OutputSimd128Register(); \
  __ LoadV##type##ZeroLE(dst, operand, kScratchReg);
    case kS390_S128Load32Zero: {
      LOAD_AND_ZERO(32);
      break;
    }
    case kS390_S128Load64Zero: {
      LOAD_AND_ZERO(64);
      break;
    }
#undef LOAD_AND_ZERO
#undef LOAD_EXTEND
#define LOAD_LANE(type, lane)                          \
  AddressingMode mode = kMode_None;                    \
  size_t index = 2;                                    \
  MemOperand operand = i.MemoryOperand(&mode, &index); \
  Simd128Register dst = i.OutputSimd128Register();     \
  DCHECK_EQ(dst, i.InputSimd128Register(0));           \
  __ LoadLane##type##LE(dst, operand, lane, kScratchReg);
    case kS390_S128Load8Lane: {
      LOAD_LANE(8, 15 - i.InputUint8(1));
      break;
    }
    case kS390_S128Load16Lane: {
      LOAD_LANE(16, 7 - i.InputUint8(1));
      break;
    }
    case kS390_S128Load32Lane: {
      LOAD_LANE(32, 3 - i.InputUint8(1));
      break;
    }
    case kS390_S128Load64Lane: {
      LOAD_LANE(64, 1 - i.InputUint8(1));
      break;
    }
#undef LOAD_LANE
#define STORE_LANE(type, lane)                         \
  AddressingMode mode = kMode_None;                    \
  size_t index = 2;                                    \
  MemOperand operand = i.MemoryOperand(&mode, &index); \
  Simd128Register src = i.InputSimd128Register(0);     \
  __ StoreLane##type##LE(src, operand, lane, kScratchReg);
    case kS390_S128Store8Lane: {
      STORE_LANE(8, 15 - i.InputUint8(1));
      break;
    }
    case kS390_S128Store16Lane: {
      STORE_LANE(16, 7 - i.InputUint8(1));
      break;
    }
    case kS390_S128St
"""


```