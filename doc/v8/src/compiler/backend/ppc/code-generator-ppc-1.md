Response: The user wants me to summarize the functionality of the C++ code snippet provided, which is part of the `code-generator-ppc.cc` file in the V8 JavaScript engine. This is the second part of a three-part request. Since it's part 2, I should focus on the functionality within this specific snippet and not repeat information from the previous part (if any was given). I also need to illustrate the connection to JavaScript with an example.

The code primarily consists of a large `switch` statement handling different `kPPC_` cases. These cases represent specific PowerPC assembly instructions or higher-level operations within the V8 compiler's backend. The actions within each case involve emitting the corresponding assembly code using the `__` assembler object.

I'll go through the cases and group them based on their apparent function:

*   **Floating-point operations:** `kIeee754Float64Log10`, `kIeee754Float64Pow`, `kPPC_MaxDouble`, `kPPC_MinDouble`, `kPPC_AbsDouble`, `kPPC_SqrtDouble`, `kPPC_FloorDouble`, `kPPC_CeilDouble`, `kPPC_TruncateDouble`, `kPPC_RoundDouble`, `kPPC_NegDouble`. These clearly implement JavaScript math functions.
*   **Integer operations:** `kPPC_Neg`, `kPPC_Cntlz32`, `kPPC_Cntlz64`, `kPPC_Popcnt32`, `kPPC_Popcnt64`, `kPPC_ExtendSignWord8`, `kPPC_ExtendSignWord16`, `kPPC_ExtendSignWord32`, `kPPC_Uint32ToUint64`, `kPPC_Int64ToInt32`. These handle bitwise and arithmetic operations on integers.
*   **Comparison operations:** `kPPC_Cmp32`, `kPPC_Cmp64`, `kPPC_CmpDouble`, `kPPC_Tst32`, `kPPC_Tst64`. These are used for conditional logic.
*   **Stack manipulation:** `kPPC_Push`, `kPPC_PushFrame`, `kPPC_StoreToStackSlot`. These manage the call stack.
*   **Type conversions:** `kPPC_Int64ToFloat32`, `kPPC_Int64ToDouble`, `kPPC_Uint64ToFloat32`, `kPPC_Uint64ToDouble`, `kPPC_Int32ToFloat32`, `kPPC_Int32ToDouble`, `kPPC_Uint32ToFloat32`, `kPPC_Uint32ToDouble`, `kPPC_Float32ToInt32`, `kPPC_Float32ToUint32`, `kPPC_DoubleToInt32`, `kPPC_DoubleToUint32`, `kPPC_DoubleToInt64`, `kPPC_DoubleToUint64`, `kPPC_DoubleToFloat32`, `kPPC_Float32ToDouble`. These handle conversions between different numeric types.
*   **Double-precision floating-point manipulation:** `kPPC_DoubleExtractLowWord32`, `kPPC_DoubleExtractHighWord32`, `kPPC_DoubleFromWord32Pair`, `kPPC_DoubleInsertLowWord32`, `kPPC_DoubleInsertHighWord32`, `kPPC_DoubleConstruct`. These allow access to the underlying 32-bit parts of a 64-bit double.
*   **Bitcasting:** `kPPC_BitcastFloat32ToInt32`, `kPPC_BitcastInt32ToFloat32`, `kPPC_BitcastDoubleToInt64`, `kPPC_BitcastInt64ToDouble`. These reinterpret the bits of a value as a different type.
*   **Memory access (loads and stores):** `kPPC_LoadWordU8` to `kPPC_LoadDouble`, `kPPC_StoreWord8` to `kPPC_StoreDouble`. These read and write data from memory.
*   **SIMD (Single Instruction Multiple Data) operations:** A large block of `kPPC_` cases related to vector operations (e.g., `kPPC_F64x2Add`, `kPPC_I32x4Mul`). These are for optimizing parallel computations.
*   **Atomic operations:** `kPPC_AtomicExchangeInt8` to `kPPC_AtomicXorUint64`. These provide thread-safe memory access.
*   **Byte reversal:** `kPPC_ByteRev32`, `kPPC_LoadByteRev32`, `kPPC_StoreByteRev32`, `kPPC_ByteRev64`, `kPPC_LoadByteRev64`, `kPPC_StoreByteRev64`. These are used for handling different endianness.
*   **Specialized memory operations:** `kPPC_StoreCompressTagged`, `kPPC_StoreIndirectPointer`, `kPPC_LoadDecodeSandboxedPointer`, `kPPC_StoreEncodeSandboxedPointer`, `kPPC_LoadDecompressTaggedSigned`, `kPPC_LoadDecompressTagged`. These are likely related to V8's internal object representation and memory management.
*   **NaN handling:** `kPPC_Float64SilenceNaN`. This deals with the Not-a-Number value.

For the JavaScript example, I can choose a few representative cases.
该C++代码文件是V8 JavaScript引擎中PowerPC架构的代码生成器的第二部分。它主要负责将高级的、平台无关的中间表示（IR）指令转换为具体的PowerPC汇编指令。

延续第一部分的思路，这部分代码继续处理`Instruction`对象，并根据其`arch_opcode()`（架构相关的操作码）执行相应的汇编指令生成。

**具体功能归纳如下：**

1. **实现浮点运算指令:**  这部分代码处理了多种浮点数的运算，例如对数 (`kIeee754Float64Log10`)、指数 (`kIeee754Float64Pow`)、取最大值/最小值 (`kPPC_MaxDouble`, `kPPC_MinDouble`)、取绝对值 (`kPPC_AbsDouble`)、平方根 (`kPPC_SqrtDouble`)、取整 (`kPPC_FloorDouble`, `kPPC_CeilDouble`, `kPPC_TruncateDouble`, `kPPC_RoundDouble`) 和取反 (`kPPC_NegDouble`)。

2. **实现整数运算指令:**  包括取反 (`kPPC_Neg`)、计算前导零个数 (`kPPC_Cntlz32`, `kPPC_Cntlz64`)、计算人口数（设置位个数）(`kPPC_Popcnt32`, `kPPC_Popcnt64`) 等整数操作。

3. **实现比较指令:**  生成用于比较整数 (`kPPC_Cmp32`, `kPPC_Cmp64`) 和浮点数 (`kPPC_CmpDouble`) 的汇编指令，以及测试位 (`kPPC_Tst32`, `kPPC_Tst64`) 的指令。

4. **处理 NaN (Not-a-Number):**  提供了将浮点数 NaN 静默化的操作 (`kPPC_Float64SilenceNaN`)。

5. **实现栈操作指令:**  包括将数据压入栈 (`kPPC_Push`)、创建新的栈帧 (`kPPC_PushFrame`) 以及将数据存储到栈槽 (`kPPC_StoreToStackSlot`)。

6. **实现类型转换指令:**  涵盖了各种整型和浮点型之间的转换，例如有符号/无符号扩展 (`kPPC_ExtendSignWord8`, `kPPC_ExtendSignWord16`, `kPPC_ExtendSignWord32`, `kPPC_Uint32ToUint64`, `kPPC_Int64ToInt32`)，以及整数和浮点数之间的相互转换 (`kPPC_Int64ToFloat32`, `kPPC_Int64ToDouble` 等)。

7. **实现浮点数内部结构操作:**  允许提取双精度浮点数的低/高 32 位字 (`kPPC_DoubleExtractLowWord32`, `kPPC_DoubleExtractHighWord32`)，以及从两个 32 位字构建双精度浮点数 (`kPPC_DoubleFromWord32Pair`, `kPPC_DoubleConstruct`)。

8. **实现类型转换但不改变位表示的指令 (Bitcast):**  允许将浮点数的值解释为整数，反之亦然 (`kPPC_BitcastFloat32ToInt32`, `kPPC_BitcastInt32ToFloat32`, `kPPC_BitcastDoubleToInt64`, `kPPC_BitcastInt64ToDouble`)。

9. **实现内存加载和存储指令:**  提供了加载不同大小的整数 (`kPPC_LoadWordU8` 到 `kPPC_LoadWord64`) 和浮点数 (`kPPC_LoadFloat32`, `kPPC_LoadDouble`) 以及 SIMD 向量 (`kPPC_LoadSimd128`) 的指令，并支持原子加载。同时，也提供了相应的存储指令 (`kPPC_StoreWord8` 到 `kPPC_StoreDouble`, `kPPC_StoreSimd128`) 和原子存储。

10. **实现原子操作指令:**  支持各种原子操作，例如原子交换 (`kPPC_AtomicExchangeInt8` 等) 和原子比较交换 (`kPPC_AtomicCompareExchangeInt8` 等)，以及原子加、减、与、或、异或等操作。

11. **实现字节序反转指令:**  提供了 32 位和 64 位整数的字节序反转操作 (`kPPC_ByteRev32`, `kPPC_ByteRev64`)，以及相应的加载和存储指令。

12. **实现 SIMD (Single Instruction Multiple Data) 指令:**  处理了大量的 SIMD 指令，包括向量的加、减、乘、除、比较、逻辑运算、位移、绝对值、取反、平方根、类型转换、车道操作（提取、替换）、点积、shuffle 等等。这些指令用于加速并行计算。

13. **实现特殊的内存操作指令:**  例如压缩标记指针存储 (`kPPC_StoreCompressTagged`)、存储间接指针 (`kPPC_StoreIndirectPointer`)、加载/存储沙箱指针 (`kPPC_LoadDecodeSandboxedPointer`, `kPPC_StoreEncodeSandboxedPointer`) 以及加载解压缩的标记值 (`kPPC_LoadDecompressTaggedSigned`, `kPPC_LoadDecompressTagged`)。这些通常与 V8 的对象模型和内存管理有关。

**与 JavaScript 功能的关系 (举例说明):**

这部分代码直接参与了 JavaScript 代码的执行过程。当 V8 引擎执行 JavaScript 代码时，TurboFan 编译器会将 JavaScript 代码编译成机器码。 `code-generator-ppc.cc` 中的代码负责将中间表示转换为 PowerPC 架构的机器码。

例如，以下 JavaScript 代码会涉及到这部分代码的功能：

```javascript
function mathOperations(a, b) {
  console.log(Math.log10(a));
  console.log(Math.pow(a, b));
  return Math.max(a, b);
}

function bitwiseAnd(x, y) {
  return x & y;
}

function compareNumbers(n1, n2) {
  return n1 > n2;
}

function typeConversion(num) {
  return parseInt(num);
}

function simdOperation(arr1, arr2) {
  const v1 = Float64x2(arr1[0], arr1[1]);
  const v2 = Float64x2(arr2[0], arr2[1]);
  return v1.add(v2);
}
```

*   **`Math.log10(a)` 和 `Math.pow(a, b)`:**  当 TurboFan 编译 `mathOperations` 函数时，会生成 `kIeee754Float64Log10` 和 `kIeee754Float64Pow` 对应的指令，这部分代码会生成相应的 PowerPC 汇编指令来实现这些数学函数。
*   **`Math.max(a, b)`:**  会生成 `kPPC_MaxDouble` 指令。
*   **`x & y`:**  `bitwiseAnd` 函数中的按位与操作会生成 `kPPC_Tst32` 或 `kPPC_Tst64` 指令（取决于 `x` 和 `y` 的类型和大小）。
*   **`n1 > n2`:** `compareNumbers` 函数的比较操作会生成 `kPPC_Cmp32` 或 `kPPC_Cmp64` 指令。
*   **`parseInt(num)`:**  `typeConversion` 函数中的 `parseInt` 调用可能会导致生成各种类型转换指令，例如 `kPPC_DoubleToInt32` 或 `kPPC_Float32ToInt32`。
*   **SIMD 操作:**  `simdOperation` 函数中的 `Float64x2.add` 操作会直接对应到 `kPPC_F64x2Add` 这样的 SIMD 指令。

总而言之，这部分代码是 V8 引擎将 JavaScript 代码转换为可执行的机器码的关键组成部分，它负责将高级操作映射到具体的 PowerPC 汇编指令，从而保证 JavaScript 代码能够在 PowerPC 架构的处理器上高效运行。

### 提示词
```
这是目录为v8/src/compiler/backend/ppc/code-generator-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
case kIeee754Float64Log10:
      ASSEMBLE_IEEE754_UNOP(log10);
      break;
    case kIeee754Float64Pow:
      ASSEMBLE_IEEE754_BINOP(pow);
      break;
    case kPPC_Neg:
      __ neg(i.OutputRegister(), i.InputRegister(0), LeaveOE, i.OutputRCBit());
      break;
    case kPPC_MaxDouble:
      __ MaxF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1), kScratchDoubleReg);
      break;
    case kPPC_MinDouble:
      __ MinF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1), kScratchDoubleReg);
      break;
    case kPPC_AbsDouble:
      ASSEMBLE_FLOAT_UNOP_RC(fabs, 0);
      break;
    case kPPC_SqrtDouble:
      ASSEMBLE_FLOAT_UNOP_RC(fsqrt, MiscField::decode(instr->opcode()));
      break;
    case kPPC_FloorDouble:
      ASSEMBLE_FLOAT_UNOP_RC(frim, MiscField::decode(instr->opcode()));
      break;
    case kPPC_CeilDouble:
      ASSEMBLE_FLOAT_UNOP_RC(frip, MiscField::decode(instr->opcode()));
      break;
    case kPPC_TruncateDouble:
      ASSEMBLE_FLOAT_UNOP_RC(friz, MiscField::decode(instr->opcode()));
      break;
    case kPPC_RoundDouble:
      ASSEMBLE_FLOAT_UNOP_RC(frin, MiscField::decode(instr->opcode()));
      break;
    case kPPC_NegDouble:
      ASSEMBLE_FLOAT_UNOP_RC(fneg, 0);
      break;
    case kPPC_Cntlz32:
      __ cntlzw(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Cntlz64:
      __ cntlzd(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Popcnt32:
      __ Popcnt32(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Popcnt64:
      __ Popcnt64(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Cmp32:
      ASSEMBLE_COMPARE(cmpw, cmplw);
      break;
    case kPPC_Cmp64:
      ASSEMBLE_COMPARE(cmp, cmpl);
      break;
    case kPPC_CmpDouble:
      ASSEMBLE_FLOAT_COMPARE(fcmpu);
      break;
    case kPPC_Tst32:
      if (HasRegisterInput(instr, 1)) {
        __ and_(r0, i.InputRegister(0), i.InputRegister(1), i.OutputRCBit());
      } else {
        __ andi(r0, i.InputRegister(0), i.InputImmediate(1));
      }
      __ extsw(r0, r0, i.OutputRCBit());
      DCHECK_EQ(SetRC, i.OutputRCBit());
      break;
    case kPPC_Tst64:
      if (HasRegisterInput(instr, 1)) {
        __ and_(r0, i.InputRegister(0), i.InputRegister(1), i.OutputRCBit());
      } else {
        __ andi(r0, i.InputRegister(0), i.InputImmediate(1));
      }
      DCHECK_EQ(SetRC, i.OutputRCBit());
      break;
    case kPPC_Float64SilenceNaN: {
      DoubleRegister value = i.InputDoubleRegister(0);
      DoubleRegister result = i.OutputDoubleRegister();
      __ CanonicalizeNaN(result, value);
      break;
    }
    case kPPC_Push: {
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
          __ StoreF32WithUpdate(i.InputDoubleRegister(1),
                                MemOperand(sp, -kSystemPointerSize), r0);
          break;
        case MachineRepresentation::kFloat64:
          __ StoreF64WithUpdate(i.InputDoubleRegister(1),
                                MemOperand(sp, -kDoubleSize), r0);
          break;
        case MachineRepresentation::kSimd128:
          __ addi(sp, sp, Operand(-kSimd128Size));
          __ StoreSimd128(i.InputSimd128Register(1), MemOperand(r0, sp),
                          kScratchReg);
          break;
        default:
          __ StoreU64WithUpdate(i.InputRegister(1),
                                MemOperand(sp, -kSystemPointerSize), r0);
          break;
      }
      frame_access_state()->IncreaseSPDelta(slots);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_PushFrame: {
      int num_slots = i.InputInt32(1);
      if (instr->InputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->InputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ StoreF64WithUpdate(i.InputDoubleRegister(0),
                                MemOperand(sp, -num_slots * kSystemPointerSize),
                                r0);
        } else {
          DCHECK_EQ(MachineRepresentation::kFloat32, op->representation());
          __ StoreF32WithUpdate(i.InputDoubleRegister(0),
                                MemOperand(sp, -num_slots * kSystemPointerSize),
                                r0);
        }
      } else {
        __ StoreU64WithUpdate(i.InputRegister(0),
                              MemOperand(sp, -num_slots * kSystemPointerSize),
                              r0);
      }
      break;
    }
    case kPPC_StoreToStackSlot: {
      int slot = i.InputInt32(1);
      if (instr->InputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->InputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ StoreF64(i.InputDoubleRegister(0),
                      MemOperand(sp, slot * kSystemPointerSize), r0);
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ StoreF32(i.InputDoubleRegister(0),
                      MemOperand(sp, slot * kSystemPointerSize), r0);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ StoreSimd128(i.InputSimd128Register(0),
                          MemOperand(sp, slot * kSystemPointerSize),
                          kScratchReg);
        }
      } else {
        __ StoreU64(i.InputRegister(0),
                    MemOperand(sp, slot * kSystemPointerSize), r0);
      }
      break;
    }
    case kPPC_ExtendSignWord8:
      __ extsb(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_ExtendSignWord16:
      __ extsh(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_ExtendSignWord32:
      __ extsw(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint32ToUint64:
      // Zero extend
      __ clrldi(i.OutputRegister(), i.InputRegister(0), Operand(32));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int64ToInt32:
      __ extsw(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int64ToFloat32:
      __ ConvertInt64ToFloat(i.InputRegister(0), i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int64ToDouble:
      __ ConvertInt64ToDouble(i.InputRegister(0), i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint64ToFloat32:
      __ ConvertUnsignedInt64ToFloat(i.InputRegister(0),
                                     i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint64ToDouble:
      __ ConvertUnsignedInt64ToDouble(i.InputRegister(0),
                                      i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int32ToFloat32:
      __ ConvertIntToFloat(i.InputRegister(0), i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int32ToDouble:
      __ ConvertIntToDouble(i.InputRegister(0), i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint32ToFloat32:
      __ ConvertUnsignedIntToFloat(i.InputRegister(0),
                                   i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint32ToDouble:
      __ ConvertUnsignedIntToDouble(i.InputRegister(0),
                                    i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Float32ToInt32: {
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_i32) {
        __ mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      }
      __ fctiwz(kScratchDoubleReg, i.InputDoubleRegister(0));
      __ MovDoubleLowToInt(i.OutputRegister(), kScratchDoubleReg);
      if (set_overflow_to_min_i32) {
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        CRegister cr = cr7;
        int crbit = v8::internal::Assembler::encode_crbit(
            cr, static_cast<CRBit>(VXCVI % CRWIDTH));
        __ mcrfs(cr, VXCVI);  // extract FPSCR field containing VXCVI into cr7
        __ li(kScratchReg, Operand(1));
        __ ShiftLeftU64(kScratchReg, kScratchReg,
                        Operand(31));  // generate INT32_MIN.
        __ isel(i.OutputRegister(0), kScratchReg, i.OutputRegister(0), crbit);
      }
      break;
    }
    case kPPC_Float32ToUint32: {
      bool set_overflow_to_min_u32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_u32) {
        __ mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      }
      __ fctiwuz(kScratchDoubleReg, i.InputDoubleRegister(0));
      __ MovDoubleLowToInt(i.OutputRegister(), kScratchDoubleReg);
      if (set_overflow_to_min_u32) {
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        CRegister cr = cr7;
        int crbit = v8::internal::Assembler::encode_crbit(
            cr, static_cast<CRBit>(VXCVI % CRWIDTH));
        __ mcrfs(cr, VXCVI);  // extract FPSCR field containing VXCVI into cr7
        __ li(kScratchReg, Operand::Zero());
        __ isel(i.OutputRegister(0), kScratchReg, i.OutputRegister(0), crbit);
      }
      break;
    }
#define DOUBLE_TO_INT32(op)                                                \
  bool check_conversion = i.OutputCount() > 1;                             \
  CRegister cr = cr7;                                                      \
  FPSCRBit fps_bit = VXCVI;                                                \
  int cr_bit = v8::internal::Assembler::encode_crbit(                      \
      cr, static_cast<CRBit>(fps_bit % CRWIDTH));                          \
  __ mtfsb0(fps_bit); /* clear FPSCR:VXCVI bit */                          \
  __ op(kScratchDoubleReg, i.InputDoubleRegister(0));                      \
  __ MovDoubleLowToInt(i.OutputRegister(0), kScratchDoubleReg);            \
  __ mcrfs(cr, VXCVI); /* extract FPSCR field containing VXCVI into cr7 */ \
  if (check_conversion) {                                                  \
    __ li(i.OutputRegister(1), Operand(1));                                \
    __ isel(i.OutputRegister(1), r0, i.OutputRegister(1), cr_bit);         \
  } else {                                                                 \
    __ isel(i.OutputRegister(0), r0, i.OutputRegister(0), cr_bit);         \
  }
    case kPPC_DoubleToInt32: {
      DOUBLE_TO_INT32(fctiwz)
      break;
    }
    case kPPC_DoubleToUint32: {
      DOUBLE_TO_INT32(fctiwuz)
      break;
    }
#undef DOUBLE_TO_INT32
    case kPPC_DoubleToInt64: {
      bool check_conversion = i.OutputCount() > 1;
      __ mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      __ ConvertDoubleToInt64(i.InputDoubleRegister(0),
                              i.OutputRegister(0), kScratchDoubleReg);
      CRegister cr = cr7;
      int crbit = v8::internal::Assembler::encode_crbit(
          cr, static_cast<CRBit>(VXCVI % CRWIDTH));
      __ mcrfs(cr, VXCVI);  // extract FPSCR field containing VXCVI into cr7
      // Handle conversion failures (such as overflow).
      if (check_conversion) {
        __ li(i.OutputRegister(1), Operand(1));
        __ isel(i.OutputRegister(1), r0, i.OutputRegister(1), crbit);
      } else {
        __ isel(i.OutputRegister(0), r0, i.OutputRegister(0), crbit);
      }
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_DoubleToUint64: {
      bool check_conversion = (i.OutputCount() > 1);
      if (check_conversion) {
        __ mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      }
      __ ConvertDoubleToUnsignedInt64(i.InputDoubleRegister(0),
                                      i.OutputRegister(0), kScratchDoubleReg);
      if (check_conversion) {
        // Set 2nd output to zero if conversion fails.
        CRegister cr = cr7;
        int crbit = v8::internal::Assembler::encode_crbit(
            cr, static_cast<CRBit>(VXCVI % CRWIDTH));
        __ mcrfs(cr, VXCVI);  // extract FPSCR field containing VXCVI into cr7
        __ li(i.OutputRegister(1), Operand(1));
        __ isel(i.OutputRegister(1), r0, i.OutputRegister(1), crbit);
      }
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_DoubleToFloat32:
      ASSEMBLE_FLOAT_UNOP_RC(frsp, 0);
      break;
    case kPPC_Float32ToDouble:
      // Nothing to do.
      __ Move(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleExtractLowWord32:
      __ MovDoubleLowToInt(i.OutputRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleExtractHighWord32:
      __ MovDoubleHighToInt(i.OutputRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleFromWord32Pair:
      __ clrldi(kScratchReg, i.InputRegister(1), Operand(32));
      __ ShiftLeftU64(i.TempRegister(0), i.InputRegister(0), Operand(32));
      __ OrU64(i.TempRegister(0), i.TempRegister(0), kScratchReg);
      __ MovInt64ToDouble(i.OutputDoubleRegister(), i.TempRegister(0));
      break;
    case kPPC_DoubleInsertLowWord32:
      __ InsertDoubleLow(i.OutputDoubleRegister(), i.InputRegister(1), r0);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleInsertHighWord32:
      __ InsertDoubleHigh(i.OutputDoubleRegister(), i.InputRegister(1), r0);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleConstruct:
      __ MovInt64ComponentsToDouble(i.OutputDoubleRegister(),
                                    i.InputRegister(0), i.InputRegister(1), r0);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_BitcastFloat32ToInt32:
      __ MovFloatToInt(i.OutputRegister(), i.InputDoubleRegister(0),
                       kScratchDoubleReg);
      break;
    case kPPC_BitcastInt32ToFloat32:
      __ MovIntToFloat(i.OutputDoubleRegister(), i.InputRegister(0), ip);
      break;
    case kPPC_BitcastDoubleToInt64:
      __ MovDoubleToInt64(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kPPC_BitcastInt64ToDouble:
      __ MovInt64ToDouble(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kPPC_LoadWordU8:
      ASSEMBLE_LOAD_INTEGER(lbz, plbz, lbzx, false);
      break;
    case kPPC_LoadWordS8:
      ASSEMBLE_LOAD_INTEGER(lbz, plbz, lbzx, false);
      __ extsb(i.OutputRegister(), i.OutputRegister());
      break;
    case kPPC_LoadWordU16:
      ASSEMBLE_LOAD_INTEGER(lhz, plhz, lhzx, false);
      break;
    case kPPC_LoadWordS16:
      ASSEMBLE_LOAD_INTEGER(lha, plha, lhax, false);
      break;
    case kPPC_LoadWordU32:
      ASSEMBLE_LOAD_INTEGER(lwz, plwz, lwzx, false);
      break;
    case kPPC_LoadWordS32:
      ASSEMBLE_LOAD_INTEGER(lwa, plwa, lwax, true);
      break;
    case kPPC_LoadWord64:
      ASSEMBLE_LOAD_INTEGER(ld, pld, ldx, true);
      break;
    case kPPC_LoadFloat32:
      ASSEMBLE_LOAD_FLOAT(lfs, plfs, lfsx);
      break;
    case kPPC_LoadDouble:
      ASSEMBLE_LOAD_FLOAT(lfd, plfd, lfdx);
      break;
    case kPPC_LoadSimd128: {
      Simd128Register result = i.OutputSimd128Register();
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode);
      bool is_atomic = i.InputInt32(2);
      DCHECK_EQ(mode, kMode_MRR);
      __ LoadSimd128(result, operand, kScratchReg);
      if (is_atomic) __ lwsync();
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_LoadReverseSimd128RR: {
      __ xxbrq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kPPC_StoreWord8:
      ASSEMBLE_STORE_INTEGER(stb, pstb, stbx, false);
      break;
    case kPPC_StoreWord16:
      ASSEMBLE_STORE_INTEGER(sth, psth, sthx, false);
      break;
    case kPPC_StoreWord32:
      ASSEMBLE_STORE_INTEGER(stw, pstw, stwx, false);
      break;
    case kPPC_StoreWord64:
      ASSEMBLE_STORE_INTEGER(std, pstd, stdx, true);
      break;
    case kPPC_StoreFloat32:
      ASSEMBLE_STORE_FLOAT(stfs, pstfs, stfsx);
      break;
    case kPPC_StoreDouble:
      ASSEMBLE_STORE_FLOAT(stfd, pstfd, stfdx);
      break;
    case kPPC_StoreSimd128: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode, &index);
      Simd128Register value = i.InputSimd128Register(index);
      bool is_atomic = i.InputInt32(3);
      if (is_atomic) __ lwsync();
      DCHECK_EQ(mode, kMode_MRR);
      __ StoreSimd128(value, operand, kScratchReg);
      if (is_atomic) __ sync();
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kAtomicLoadInt8:
    case kAtomicLoadInt16:
      UNREACHABLE();
    case kAtomicExchangeInt8:
      __ AtomicExchange<int8_t>(
          MemOperand(i.InputRegister(0), i.InputRegister(1)),
          i.InputRegister(2), i.OutputRegister());
      break;
    case kPPC_AtomicExchangeUint8:
      __ AtomicExchange<uint8_t>(
          MemOperand(i.InputRegister(0), i.InputRegister(1)),
          i.InputRegister(2), i.OutputRegister());
      break;
    case kAtomicExchangeInt16: {
      ASSEMBLE_ATOMIC_EXCHANGE(int16_t, ByteReverseU16);
      __ extsh(i.OutputRegister(), i.OutputRegister());
      break;
    }
    case kPPC_AtomicExchangeUint16: {
      ASSEMBLE_ATOMIC_EXCHANGE(uint16_t, ByteReverseU16);
      break;
    }
    case kPPC_AtomicExchangeWord32: {
      ASSEMBLE_ATOMIC_EXCHANGE(uint32_t, ByteReverseU32);
      break;
    }
    case kPPC_AtomicExchangeWord64: {
      ASSEMBLE_ATOMIC_EXCHANGE(uint64_t, ByteReverseU64);
      break;
    }
    case kAtomicCompareExchangeInt8:
      __ AtomicCompareExchange<int8_t>(
          MemOperand(i.InputRegister(0), i.InputRegister(1)),
          i.InputRegister(2), i.InputRegister(3), i.OutputRegister(),
          kScratchReg);
      break;
    case kPPC_AtomicCompareExchangeUint8:
      __ AtomicCompareExchange<uint8_t>(
          MemOperand(i.InputRegister(0), i.InputRegister(1)),
          i.InputRegister(2), i.InputRegister(3), i.OutputRegister(),
          kScratchReg);
      break;
    case kAtomicCompareExchangeInt16: {
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE(int16_t, ByteReverseU16);
      __ extsh(i.OutputRegister(), i.OutputRegister());
      break;
    }
    case kPPC_AtomicCompareExchangeUint16: {
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE(uint16_t, ByteReverseU16);
      break;
    }
    case kPPC_AtomicCompareExchangeWord32: {
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE(uint32_t, ByteReverseU32);
      break;
    }
    case kPPC_AtomicCompareExchangeWord64: {
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE(uint64_t, ByteReverseU64);
    } break;

#define ATOMIC_BINOP_CASE(op, inst)                            \
  case kPPC_Atomic##op##Int8:                                  \
    ASSEMBLE_ATOMIC_BINOP_BYTE(inst, int8_t);                  \
    __ extsb(i.OutputRegister(), i.OutputRegister());          \
    break;                                                     \
  case kPPC_Atomic##op##Uint8:                                 \
    ASSEMBLE_ATOMIC_BINOP_BYTE(inst, uint8_t);                 \
    break;                                                     \
  case kPPC_Atomic##op##Int16:                                 \
    ASSEMBLE_ATOMIC_BINOP(inst, int16_t, ByteReverseU16, r0);  \
    __ extsh(i.OutputRegister(), i.OutputRegister());          \
    break;                                                     \
  case kPPC_Atomic##op##Uint16:                                \
    ASSEMBLE_ATOMIC_BINOP(inst, uint16_t, ByteReverseU16, r0); \
    break;                                                     \
  case kPPC_Atomic##op##Int32:                                 \
    ASSEMBLE_ATOMIC_BINOP(inst, int32_t, ByteReverseU32, r0);  \
    __ extsw(i.OutputRegister(), i.OutputRegister());          \
    break;                                                     \
  case kPPC_Atomic##op##Uint32:                                \
    ASSEMBLE_ATOMIC_BINOP(inst, uint32_t, ByteReverseU32, r0); \
    break;                                                     \
  case kPPC_Atomic##op##Int64:                                 \
  case kPPC_Atomic##op##Uint64:                                \
    ASSEMBLE_ATOMIC_BINOP(inst, uint64_t, ByteReverseU64, r0); \
    break;
      ATOMIC_BINOP_CASE(Add, add)
      ATOMIC_BINOP_CASE(Sub, sub)
      ATOMIC_BINOP_CASE(And, and_)
      ATOMIC_BINOP_CASE(Or, orx)
      ATOMIC_BINOP_CASE(Xor, xor_)
#undef ATOMIC_BINOP_CASE

    case kPPC_ByteRev32: {
      Register input = i.InputRegister(0);
      Register output = i.OutputRegister();
      Register temp1 = r0;
      if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
        __ brw(output, input);
        __ extsw(output, output);
        break;
      }
      __ rotlwi(temp1, input, 8);
      __ rlwimi(temp1, input, 24, 0, 7);
      __ rlwimi(temp1, input, 24, 16, 23);
      __ extsw(output, temp1);
      break;
    }
    case kPPC_LoadByteRev32: {
      ASSEMBLE_LOAD_INTEGER_RR(lwbrx);
      break;
    }
    case kPPC_StoreByteRev32: {
      ASSEMBLE_STORE_INTEGER_RR(stwbrx);
      break;
    }
    case kPPC_ByteRev64: {
      Register input = i.InputRegister(0);
      Register output = i.OutputRegister();
      Register temp1 = r0;
      Register temp2 = kScratchReg;
      Register temp3 = i.TempRegister(0);
      if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
        __ brd(output, input);
        break;
      }
      __ rldicl(temp1, input, 32, 32);
      __ rotlwi(temp2, input, 8);
      __ rlwimi(temp2, input, 24, 0, 7);
      __ rotlwi(temp3, temp1, 8);
      __ rlwimi(temp2, input, 24, 16, 23);
      __ rlwimi(temp3, temp1, 24, 0, 7);
      __ rlwimi(temp3, temp1, 24, 16, 23);
      __ rldicr(temp2, temp2, 32, 31);
      __ orx(output, temp2, temp3);
      break;
    }
    case kPPC_LoadByteRev64: {
      ASSEMBLE_LOAD_INTEGER_RR(ldbrx);
      break;
    }
    case kPPC_StoreByteRev64: {
      ASSEMBLE_STORE_INTEGER_RR(stdbrx);
      break;
    }
// Simd Support.
#define SIMD_BINOP_LIST(V) \
  V(F64x2Add)              \
  V(F64x2Sub)              \
  V(F64x2Mul)              \
  V(F64x2Div)              \
  V(F64x2Eq)               \
  V(F64x2Lt)               \
  V(F64x2Le)               \
  V(F32x4Add)              \
  V(F32x4Sub)              \
  V(F32x4Mul)              \
  V(F32x4Div)              \
  V(F32x4Min)              \
  V(F32x4Max)              \
  V(F32x4Eq)               \
  V(F32x4Lt)               \
  V(F32x4Le)               \
  V(I64x2Add)              \
  V(I64x2Sub)              \
  V(I64x2Eq)               \
  V(I64x2GtS)              \
  V(I32x4Add)              \
  V(I32x4Sub)              \
  V(I32x4Mul)              \
  V(I32x4MinS)             \
  V(I32x4MinU)             \
  V(I32x4MaxS)             \
  V(I32x4MaxU)             \
  V(I32x4Eq)               \
  V(I32x4GtS)              \
  V(I32x4GtU)              \
  V(I32x4DotI16x8S)        \
  V(I16x8Add)              \
  V(I16x8Sub)              \
  V(I16x8Mul)              \
  V(I16x8MinS)             \
  V(I16x8MinU)             \
  V(I16x8MaxS)             \
  V(I16x8MaxU)             \
  V(I16x8Eq)               \
  V(I16x8GtS)              \
  V(I16x8GtU)              \
  V(I16x8AddSatS)          \
  V(I16x8SubSatS)          \
  V(I16x8AddSatU)          \
  V(I16x8SubSatU)          \
  V(I16x8SConvertI32x4)    \
  V(I16x8UConvertI32x4)    \
  V(I16x8RoundingAverageU) \
  V(I16x8Q15MulRSatS)      \
  V(I8x16Add)              \
  V(I8x16Sub)              \
  V(I8x16MinS)             \
  V(I8x16MinU)             \
  V(I8x16MaxS)             \
  V(I8x16MaxU)             \
  V(I8x16Eq)               \
  V(I8x16GtS)              \
  V(I8x16GtU)              \
  V(I8x16AddSatS)          \
  V(I8x16SubSatS)          \
  V(I8x16AddSatU)          \
  V(I8x16SubSatU)          \
  V(I8x16SConvertI16x8)    \
  V(I8x16UConvertI16x8)    \
  V(I8x16RoundingAverageU) \
  V(S128And)               \
  V(S128Or)                \
  V(S128Xor)               \
  V(S128AndNot)

#define EMIT_SIMD_BINOP(name)                                     \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1));                           \
    break;                                                        \
  }
      SIMD_BINOP_LIST(EMIT_SIMD_BINOP)
#undef EMIT_SIMD_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_BINOP_WITH_SCRATCH_LIST(V) \
  V(F64x2Ne)                            \
  V(F64x2Pmin)                          \
  V(F64x2Pmax)                          \
  V(F32x4Ne)                            \
  V(F32x4Pmin)                          \
  V(F32x4Pmax)                          \
  V(I64x2Ne)                            \
  V(I64x2GeS)                           \
  V(I64x2ExtMulLowI32x4S)               \
  V(I64x2ExtMulHighI32x4S)              \
  V(I64x2ExtMulLowI32x4U)               \
  V(I64x2ExtMulHighI32x4U)              \
  V(I32x4Ne)                            \
  V(I32x4GeS)                           \
  V(I32x4GeU)                           \
  V(I32x4ExtMulLowI16x8S)               \
  V(I32x4ExtMulHighI16x8S)              \
  V(I32x4ExtMulLowI16x8U)               \
  V(I32x4ExtMulHighI16x8U)              \
  V(I16x8Ne)                            \
  V(I16x8GeS)                           \
  V(I16x8GeU)                           \
  V(I16x8ExtMulLowI8x16S)               \
  V(I16x8ExtMulHighI8x16S)              \
  V(I16x8ExtMulLowI8x16U)               \
  V(I16x8ExtMulHighI8x16U)              \
  V(I16x8DotI8x16S)                     \
  V(I8x16Ne)                            \
  V(I8x16GeS)                           \
  V(I8x16GeU)                           \
  V(I8x16Swizzle)

#define EMIT_SIMD_BINOP_WITH_SCRATCH(name)                        \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1), kScratchSimd128Reg);       \
    break;                                                        \
  }
      SIMD_BINOP_WITH_SCRATCH_LIST(EMIT_SIMD_BINOP_WITH_SCRATCH)
#undef EMIT_SIMD_BINOP_WITH_SCRATCH
#undef SIMD_BINOP_WITH_SCRATCH_LIST

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
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputRegister(1), kScratchSimd128Reg);              \
    break;                                                        \
  }
      SIMD_SHIFT_LIST(EMIT_SIMD_SHIFT)
#undef EMIT_SIMD_SHIFT
#undef SIMD_SHIFT_LIST

#define SIMD_UNOP_LIST(V)   \
  V(F64x2Abs)               \
  V(F64x2Neg)               \
  V(F64x2Sqrt)              \
  V(F64x2Ceil)              \
  V(F64x2Floor)             \
  V(F64x2Trunc)             \
  V(F64x2PromoteLowF32x4)   \
  V(F32x4Abs)               \
  V(F32x4Neg)               \
  V(F32x4SConvertI32x4)     \
  V(F32x4UConvertI32x4)     \
  V(I64x2Neg)               \
  V(I32x4Neg)               \
  V(F32x4Sqrt)              \
  V(F32x4Ceil)              \
  V(F32x4Floor)             \
  V(F32x4Trunc)             \
  V(F64x2ConvertLowI32x4S)  \
  V(I64x2SConvertI32x4Low)  \
  V(I64x2SConvertI32x4High) \
  V(I32x4SConvertI16x8Low)  \
  V(I32x4SConvertI16x8High) \
  V(I32x4UConvertF32x4)     \
  V(I16x8SConvertI8x16Low)  \
  V(I16x8SConvertI8x16High) \
  V(I8x16Popcnt)            \
  V(S128Not)

#define EMIT_SIMD_UNOP(name)                                       \
  case kPPC_##name: {                                              \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0)); \
    break;                                                         \
  }
      SIMD_UNOP_LIST(EMIT_SIMD_UNOP)
#undef EMIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_UNOP_WITH_SCRATCH_LIST(V) \
  V(F32x4DemoteF64x2Zero)              \
  V(I64x2Abs)                          \
  V(I32x4Abs)                          \
  V(I32x4SConvertF32x4)                \
  V(I32x4TruncSatF64x2SZero)           \
  V(I32x4TruncSatF64x2UZero)           \
  V(I16x8Abs)                          \
  V(I16x8Neg)                          \
  V(I8x16Abs)                          \
  V(I8x16Neg)

#define EMIT_SIMD_UNOP_WITH_SCRATCH(name)                         \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            kScratchSimd128Reg);                                  \
    break;                                                        \
  }
      SIMD_UNOP_WITH_SCRATCH_LIST(EMIT_SIMD_UNOP_WITH_SCRATCH)
#undef EMIT_SIMD_UNOP_WITH_SCRATCH
#undef SIMD_UNOP_WITH_SCRATCH_LIST

#define SIMD_ALL_TRUE_LIST(V) \
  V(I64x2AllTrue)             \
  V(I32x4AllTrue)             \
  V(I16x8AllTrue)             \
  V(I8x16AllTrue)
#define EMIT_SIMD_ALL_TRUE(name)                                   \
  case kPPC_##name: {                                              \
    __ name(i.OutputRegister(), i.InputSimd128Register(0), r0, ip, \
            kScratchSimd128Reg);                                   \
    break;                                                         \
  }
      SIMD_ALL_TRUE_LIST(EMIT_SIMD_ALL_TRUE)
#undef EMIT_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_QFM_LIST(V) \
  V(F64x2Qfma)           \
  V(F64x2Qfms)           \
  V(F32x4Qfma)           \
  V(F32x4Qfms)
#define EMIT_SIMD_QFM(name)                                       \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1), i.InputSimd128Register(2), \
            kScratchSimd128Reg);                                  \
    break;                                                        \
  }
      SIMD_QFM_LIST(EMIT_SIMD_QFM)
#undef EMIT_SIMD_QFM
#undef SIMD_QFM_LIST

#define SIMD_EXT_ADD_PAIRWISE_LIST(V) \
  V(I32x4ExtAddPairwiseI16x8S)        \
  V(I32x4ExtAddPairwiseI16x8U)        \
  V(I16x8ExtAddPairwiseI8x16S)        \
  V(I16x8ExtAddPairwiseI8x16U)
#define EMIT_SIMD_EXT_ADD_PAIRWISE(name)                          \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            kScratchSimd128Reg, kScratchSimd128Reg2);             \
    break;                                                        \
  }
      SIMD_EXT_ADD_PAIRWISE_LIST(EMIT_SIMD_EXT_ADD_PAIRWISE)
#undef EMIT_SIMD_EXT_ADD_PAIRWISE
#undef SIMD_EXT_ADD_PAIRWISE_LIST

#define SIMD_LOAD_LANE_LIST(V)    \
  V(S128Load64Lane, LoadLane64LE) \
  V(S128Load32Lane, LoadLane32LE) \
  V(S128Load16Lane, LoadLane16LE) \
  V(S128Load8Lane, LoadLane8LE)

#define EMIT_SIMD_LOAD_LANE(name, op)                                      \
  case kPPC_##name: {                                                      \
    Simd128Register dst = i.OutputSimd128Register();                       \
    DCHECK_EQ(dst, i.InputSimd128Register(0));                             \
    AddressingMode mode = kMode_None;                                      \
    size_t index = 1;                                                      \
    MemOperand operand = i.MemoryOperand(&mode, &index);                   \
    DCHECK_EQ(mode, kMode_MRR);                                            \
    __ op(dst, operand, i.InputUint8(3), kScratchReg, kScratchSimd128Reg); \
    break;                                                                 \
  }
      SIMD_LOAD_LANE_LIST(EMIT_SIMD_LOAD_LANE)
#undef EMIT_SIMD_LOAD_LANE
#undef SIMD_LOAD_LANE_LIST

#define SIMD_STORE_LANE_LIST(V)     \
  V(S128Store64Lane, StoreLane64LE) \
  V(S128Store32Lane, StoreLane32LE) \
  V(S128Store16Lane, StoreLane16LE) \
  V(S128Store8Lane, StoreLane8LE)

#define EMIT_SIMD_STORE_LANE(name, op)                                      \
  case kPPC_##name: {                                                       \
    AddressingMode mode = kMode_None;                                       \
    size_t index = 1;                                                       \
    MemOperand operand = i.MemoryOperand(&mode, &index);                    \
    DCHECK_EQ(mode, kMode_MRR);                                             \
    __ op(i.InputSimd128Register(0), operand, i.InputUint8(3), kScratchReg, \
          kScratchSimd128Reg);                                              \
    break;                                                                  \
  }
      SIMD_STORE_LANE_LIST(EMIT_SIMD_STORE_LANE)
#undef EMIT_SIMD_STORE_LANE
#undef SIMD_STORE_LANE_LIST

#define SIMD_LOAD_SPLAT(V)               \
  V(S128Load64Splat, LoadAndSplat64x2LE) \
  V(S128Load32Splat, LoadAndSplat32x4LE) \
  V(S128Load16Splat, LoadAndSplat16x8LE) \
  V(S128Load8Splat, LoadAndSplat8x16LE)

#define EMIT_SIMD_LOAD_SPLAT(name, op)                      \
  case kPPC_##name: {                                       \
    AddressingMode mode = kMode_None;                       \
    MemOperand operand = i.MemoryOperand(&mode);            \
    DCHECK_EQ(mode, kMode_MRR);                             \
    __ op(i.OutputSimd128Register(), operand, kScratchReg); \
    break;                                                  \
  }
      SIMD_LOAD_SPLAT(EMIT_SIMD_LOAD_SPLAT)
#undef EMIT_SIMD_LOAD_SPLAT
#undef SIMD_LOAD_SPLAT

    case kPPC_F64x2Splat: {
      __ F64x2Splat(i.OutputSimd128Register(), i.InputDoubleRegister(0),
                    kScratchReg);
      break;
    }
    case kPPC_F32x4Splat: {
      __ F32x4Splat(i.OutputSimd128Register(), i.InputDoubleRegister(0),
                    kScratchDoubleReg, kScratchReg);
      break;
    }
    case kPPC_I64x2Splat: {
      __ I64x2Splat(i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kPPC_I32x4Splat: {
      __ I32x4Splat(i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kPPC_I16x8Splat: {
      __ I16x8Splat(i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kPPC_I8x16Splat: {
      __ I8x16Splat(i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kPPC_FExtractLane: {
      int lane_size = LaneSizeField::decode(instr->opcode());
      switch (lane_size) {
        case 32: {
          __ F32x4ExtractLane(i.OutputDoubleRegister(),
                              i.InputSimd128Register(0), i.InputInt8(1),
                              kScratchSimd128Reg, kScratchReg, ip);
          break;
        }
        case 64: {
          __ F64x2ExtractLane(i.OutputDoubleRegister(),
                              i.InputSimd128Register(0), i.InputInt8(1),
                              kScratchSimd128Reg, kScratchReg);
          break;
        }
        default:
          UNREACHABLE();
      }
      break;
    }
    case kPPC_IExtractLane: {
      int lane_size = LaneSizeField::decode(instr->opcode());
      switch (lane_size) {
        case 32: {
          __ I32x4ExtractLane(i.OutputRegister(), i.InputSimd128Register(0),
                              i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        case 64: {
          __ I64x2ExtractLane(i.OutputRegister(), i.InputSimd128Register(0),
                              i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        default:
          UNREACHABLE();
      }
      break;
    }
    case kPPC_IExtractLaneU: {
      int lane_size = LaneSizeField::decode(instr->opcode());
      switch (lane_size) {
        case 8: {
          __ I8x16ExtractLaneU(i.OutputRegister(), i.InputSimd128Register(0),
                               i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        case 16: {
          __ I16x8ExtractLaneU(i.OutputRegister(), i.InputSimd128Register(0),
                               i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        default:
          UNREACHABLE();
      }
      break;
    }
    case kPPC_IExtractLaneS: {
      int lane_size = LaneSizeField::decode(instr->opcode());
      switch (lane_size) {
        case 8: {
          __ I8x16ExtractLaneS(i.OutputRegister(), i.InputSimd128Register(0),
                               i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        case 16: {
          __ I16x8ExtractLaneS(i.OutputRegister(), i.InputSimd128Register(0),
                               i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        default:
          UNREACHABLE();
      }
      break;
    }
    case kPPC_FReplaceLane: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      int lane_size = LaneSizeField::decode(instr->opcode());
      switch (lane_size) {
        case 32: {
          __ F32x4ReplaceLane(
              i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputDoubleRegister(2), i.InputInt8(1), kScratchReg,
              kScratchDoubleReg, kScratchSimd128Reg);
          break;
        }
        case 64: {
          __ F64x2ReplaceLane(i.OutputSimd128Register(),
                              i.InputSimd128Register(0),
                              i.InputDoubleRegister(2), i.InputInt8(1),
                              kScratchReg, kScratchSimd128Reg);
          break;
        }
        default:
          UNREACHABLE();
      }
      break;
    }
    case kPPC_IReplaceLane: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      int lane_size = LaneSizeField::decode(instr->opcode());
      switch (lane_size) {
        case 8: {
          __ I8x16ReplaceLane(i.OutputSimd128Register(),
                              i.InputSimd128Register(0), i.InputRegister(2),
                              i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        case 16: {
          __ I16x8ReplaceLane(i.OutputSimd128Register(),
                              i.InputSimd128Register(0), i.InputRegister(2),
                              i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        case 32: {
          __ I32x4ReplaceLane(i.OutputSimd128Register(),
                              i.InputSimd128Register(0), i.InputRegister(2),
                              i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        case 64: {
          __ I64x2ReplaceLane(i.OutputSimd128Register(),
                              i.InputSimd128Register(0), i.InputRegister(2),
                              i.InputInt8(1), kScratchSimd128Reg);
          break;
        }
        default:
          UNREACHABLE();
      }
      break;
    }
    case kPPC_I64x2Mul: {
      __ I64x2Mul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), ip, r0,
                  i.ToRegister(instr->TempAt(0)), kScratchSimd128Reg);
      break;
    }
    case kPPC_F64x2Min: {
      __ F64x2Min(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchSimd128Reg,
                  kScratchSimd128Reg2);
      break;
    }
    case kPPC_F64x2Max: {
      __ F64x2Max(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchSimd128Reg,
                  kScratchSimd128Reg2);
      break;
    }
    case kPPC_S128Const: {
      uint64_t low = make_uint64(i.InputUint32(1), i.InputUint32(0));
      uint64_t high = make_uint64(i.InputUint32(3), i.InputUint32(2));
      __ S128Const(i.OutputSimd128Register(), high, low, r0, ip);
      break;
    }
    case kPPC_S128Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vxor(dst, dst, dst);
      break;
    }
    case kPPC_S128AllOnes: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vcmpequb(dst, dst, dst);
      break;
    }
    case kPPC_S128Select: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register mask = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register src2 = i.InputSimd128Register(2);
      __ S128Select(dst, src1, src2, mask);
      break;
    }
    case kPPC_V128AnyTrue: {
      __ V128AnyTrue(i.OutputRegister(), i.InputSimd128Register(0), r0, ip,
                     kScratchSimd128Reg);
      break;
    }
    case kPPC_F64x2ConvertLowI32x4U: {
      __ F64x2ConvertLowI32x4U(i.OutputSimd128Register(),
                               i.InputSimd128Register(0), kScratchReg,
                               kScratchSimd128Reg);
      break;
    }
    case kPPC_I64x2UConvertI32x4Low: {
      __ I64x2UConvertI32x4Low(i.OutputSimd128Register(),
                               i.InputSimd128Register(0), kScratchReg,
                               kScratchSimd128Reg);
      break;
    }
    case kPPC_I64x2UConvertI32x4High: {
      __ I64x2UConvertI32x4High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchReg,
                                kScratchSimd128Reg);
      break;
    }
    case kPPC_I32x4UConvertI16x8Low: {
      __ I32x4UConvertI16x8Low(i.OutputSimd128Register(),
                               i.InputSimd128Register(0), kScratchReg,
                               kScratchSimd128Reg);
      break;
    }
    case kPPC_I32x4UConvertI16x8High: {
      __ I32x4UConvertI16x8High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchReg,
                                kScratchSimd128Reg);
      break;
    }
    case kPPC_I16x8UConvertI8x16Low: {
      __ I16x8UConvertI8x16Low(i.OutputSimd128Register(),
                               i.InputSimd128Register(0), kScratchReg,
                               kScratchSimd128Reg);
      break;
    }
    case kPPC_I16x8UConvertI8x16High: {
      __ I16x8UConvertI8x16High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchReg,
                                kScratchSimd128Reg);
      break;
    }
    case kPPC_I8x16Shuffle: {
      uint64_t low = make_uint64(i.InputUint32(3), i.InputUint32(2));
      uint64_t high = make_uint64(i.InputUint32(5), i.InputUint32(4));
      __ I8x16Shuffle(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), high, low, r0, ip,
                      kScratchSimd128Reg);
      break;
    }
    case kPPC_I64x2BitMask: {
      __ I64x2BitMask(i.OutputRegister(), i.InputSimd128Register(0),
                      kScratchReg, kScratchSimd128Reg);
      break;
    }
    case kPPC_I32x4BitMask: {
      __ I32x4BitMask(i.OutputRegister(), i.InputSimd128Register(0),
                      kScratchReg, kScratchSimd128Reg);
      break;
    }
    case kPPC_I16x8BitMask: {
      __ I16x8BitMask(i.OutputRegister(), i.InputSimd128Register(0),
                      kScratchReg, kScratchSimd128Reg);
      break;
    }
    case kPPC_I8x16BitMask: {
      __ I8x16BitMask(i.OutputRegister(), i.InputSimd128Register(0), r0, ip,
                      kScratchSimd128Reg);
      break;
    }
    case kPPC_I32x4DotI8x16AddS: {
      __ I32x4DotI8x16AddS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                           i.InputSimd128Register(1),
                           i.InputSimd128Register(2));
      break;
    }
#define PREP_LOAD_EXTEND()                     \
  AddressingMode mode = kMode_None;            \
  MemOperand operand = i.MemoryOperand(&mode); \
  DCHECK_EQ(mode, kMode_MRR);
    case kPPC_S128Load8x8S: {
      PREP_LOAD_EXTEND()
      __ LoadAndExtend8x8SLE(i.OutputSimd128Register(), operand, kScratchReg);
      break;
    }
    case kPPC_S128Load8x8U: {
      PREP_LOAD_EXTEND()
      __ LoadAndExtend8x8ULE(i.OutputSimd128Register(), operand, kScratchReg,
                             kScratchSimd128Reg);
      break;
    }
    case kPPC_S128Load16x4S: {
      PREP_LOAD_EXTEND()
      __ LoadAndExtend16x4SLE(i.OutputSimd128Register(), operand, kScratchReg);
      break;
    }
    case kPPC_S128Load16x4U: {
      PREP_LOAD_EXTEND()
      __ LoadAndExtend16x4ULE(i.OutputSimd128Register(), operand, kScratchReg,
                              kScratchSimd128Reg);
      break;
    }
    case kPPC_S128Load32x2S: {
      PREP_LOAD_EXTEND()
      __ LoadAndExtend32x2SLE(i.OutputSimd128Register(), operand, kScratchReg);
      break;
    }
    case kPPC_S128Load32x2U: {
      PREP_LOAD_EXTEND()
      __ LoadAndExtend32x2ULE(i.OutputSimd128Register(), operand, kScratchReg,
                              kScratchSimd128Reg);
      break;
    }
    case kPPC_S128Load32Zero: {
      PREP_LOAD_EXTEND()
      __ LoadV32ZeroLE(i.OutputSimd128Register(), operand, kScratchReg,
                       kScratchSimd128Reg);
      break;
    }
    case kPPC_S128Load64Zero: {
      PREP_LOAD_EXTEND()
      __ LoadV64ZeroLE(i.OutputSimd128Register(), operand, kScratchReg,
                       kScratchSimd128Reg);
      break;
    }
#undef PREP_LOAD_EXTEND
    case kPPC_StoreCompressTagged: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode, &index);
      Register value = i.InputRegister(index);
      bool is_atomic = i.InputInt32(index + 1);
      if (is_atomic) __ lwsync();
      __ StoreTaggedField(value, operand, r0);
      if (is_atomic) __ sync();
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_StoreIndirectPointer: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand mem = i.MemoryOperand(&mode, &index);
      Register value = i.InputRegister(index);
      bool is_atomic = i.InputInt32(index + 1);
      if (is_atomic) __ lwsync();
      __ StoreIndirectPointerField(value, mem, kScratchReg);
      if (is_atomic) __ sync();
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_LoadDecodeSandboxedPointer: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand mem = i.MemoryOperand(&mode, &index);
      bool is_atomic = i.InputInt32(index);
      __ LoadSandboxedPointerField(i.OutputRegister(), mem, kScratchReg);
      if (is_atomic) __ lwsync();
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_StoreEncodeSandboxedPointer: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand mem = i.MemoryOperand(&mode, &index);
      Register value = i.InputRegister(index);
      bool is_atomic = i.InputInt32(index + 1);
      if (is_atomic) __ lwsync();
      __ StoreSandboxedPointerField(value, mem, kScratchReg);
      if (is_atomic) __ sync();
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_LoadDecompressTaggedSigned: {
      CHECK(instr->HasOutput());
      ASSEMBLE_LOAD_INTEGER(lwz, plwz, lwzx, false);
      break;
    }
    case kPPC_LoadDecompressTagged: {
      CHECK(instr->HasOutput());
      ASSEMBLE_LOAD_INTEGER(lwz, plwz, lwzx, false);
      __ add(i.OutputRegister(), i.OutputRegister(), kPtrComprCageBaseRegister);
      break;
    }
    default:
      UNREACHABLE();
  }
  return kSuccess;
}

// Assembles branches after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  PPCOperandConverter i(this, instr);
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;
  ArchOpcode op = instr->arch_opcode();
  FlagsCondition condition = branch->condition;
  CRegister cr = cr0;

  Condition cond = FlagsConditionToCondition(condition, op);
  if (op == kPPC_CmpDouble) {
    // check for unordered if necessary
    if (cond == le) {
      __ bunordered(flabel, cr);
      // Unnecessary for eq/lt since only FU bit will be set.
    } else if (cond == gt) {
      __ bunordered(tlabel, cr);
      // Unnecessary for ne/ge since only FU bit will be set.
    }
  }
  __ b(cond, tlabel, cr);
  if (!branch->fallthru) __ b(flabel);  // no fallthru to flabel.
}

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ b(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  class OutOfLineTrap final : public OutOfLineCode {
   public:
    OutOfLineTrap(CodeGenerator* gen, Instruction* instr)
        : OutOfLineCode(gen), instr_(instr), gen_(gen) {}

    void Generate() final {
      PPCOperandConverter i(gen_, instr_);
      TrapId trap_id =
          static_cast<TrapId>(i.InputInt32(instr_->InputCount() - 1));
      GenerateCallToTrap(trap_id);
    }

   private:
    void GenerateCallToTrap(TrapId trap_id) {
      gen_->AssembleSourcePosition(instr_);
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ Call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
      ReferenceMap* reference_map =
          gen_->zone()->New<ReferenceMap>(gen_->zone());
      gen_->RecordSafepoint(reference_map);
      if (v8_flags.debug_code) {
        __ stop();
      }
    }

    Instruction* instr_;
    CodeGenerator* gen_;
  };
  auto ool = zone()->New<OutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  Label end;

  ArchOpcode op = instr->arch_opcode();
  CRegister cr = cr0;
  Condition cond = FlagsConditionToCondition(condition, op);
  if (op == kPPC_CmpDouble) {
    // check for unordered if necessary
    if (cond == le) {
      __ bunordered(&end, cr);
      // Unnecessary for eq/lt since only FU bit will be set.
    } else if (cond == gt) {
      __ bunordered(tlabel, cr);
      // Unnecessary for ne/ge since only FU bit will be set.
    }
  }
  __ b(cond, tlabel, cr);
  __ bind(&end);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  PPCOperandConverter i(this, instr);
  Label done;
  ArchOpcode op = instr->arch_opcode();
  CRegister cr = cr0;
  int reg_value = -1;

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Register reg = i.OutputRegister(instr->OutputCount() - 1);

  Condition cond = FlagsConditionToCondition(condition, op);
  if (op == kPPC_CmpDouble) {
    // check for unordered if necessary
    if (cond == le) {
      reg_value = 0;
      __ li(reg, Operand::Zero());
      __ bunordered(&done, cr);
    } else if (cond == gt) {
      reg_value = 1;
      __ li(reg, Operand(1));
      __ bunordered(&done, cr);
    }
    // Unnecessary for eq/lt & ne/ge since only FU bit will be set.
  }
  switch (cond) {
    case eq:
    case lt:
    case gt:
      if (reg_value != 1) __ li(reg, Operand(1));
      __ li(kScratchReg, Operand::Zero());
      __ isel(cond, reg, reg, kScratchReg, cr);
      break;
    case ne:
    case ge:
    case le:
      if (reg_value != 1) __ li(reg, Operand(1));
      // r0 implies logical zero in this form
      __ isel(NegateCondition(cond), reg, r0, reg, cr);
      break;
    default:
      UNREACHABLE();
  }
  __ bind(&done);
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  PPCOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  PPCOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  int32_t const case_count = static_cast<int32_t>(instr->InputCount() - 2);
  base::Vector<Label*> cases = zone()->AllocateVector<Label*>(case_count);
  for (int32_t index = 0; index < case_count; ++index) {
    cases[index] = GetLabel(i.InputRpo(index + 2));
  }
  Label* const table = AddJumpTable(cases);
  __ CmpU64(input, Operand(case_count), r0);
  __ bge(GetLabel(i.InputRpo(1)));
  __ mov_label_addr(kScratchReg, table);
  __ ShiftLeftU64(r0, input, Operand(kSystemPointerSizeLog2));
  __ LoadU64(kScratchReg, MemOperand(kScratchReg, r0));
  __ Jump(kScratchReg);
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  UNIMPLEMENTED();
}

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  const DoubleRegList double_saves = call_descriptor->CalleeSavedFPRegisters();

  // Save callee-saved Double registers.
  if (!double_saves.is_empty()) {
    frame->AlignSavedCalleeRegisterSlots();
    DCHECK_EQ(kNumCalleeSavedDoubles, double_saves.Count());
    frame->AllocateSavedCalleeRegisterSlots(kNumCalleeSavedDoubles *
                                            (kDoubleSize / kSystemPointerSize));
  }
  // Save callee-saved registers.
  const RegList saves =
      V8_EMBEDDED_CONSTANT_POOL_BOOL
          ? call_descriptor->CalleeSavedRegisters() - kConstantPoolRegister
          : call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    // register save area does not include the fp or constant pool pointer.
    const int num_saves =
        kNumCalleeSaved - 1 - (V8_EMBEDDED_CONSTANT_POOL_BOOL ? 1 : 0);
    frame->AllocateSavedCalleeRegisterSlots(num_saves);
  }
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  if (frame_access_state()->has_frame()) {
    if (call_descriptor->IsCFunctionCall()) {
#if V8_ENABLE_WEBASSEMBLY
      if (info()->GetOutputStackFrameType() == StackFrame::C_WASM_ENTRY) {
        __ StubPrologue(StackFrame::C_WASM_ENTRY);
        // Reserve stack space for saving the c_entry_fp later.
        __ addi(sp, sp, Operand(-kSystemPointerSize));
#else
      // For balance.
      if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
      } else {
        __ mflr(r0);
        if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
          __ Push(r0, fp, kConstantPoolRegister);
          // Adjust FP to point to saved FP.
          __ SubS64(fp, sp,
                    Operand(StandardFrameConstants::kConstantPoolOffset), r0);
        } else {
          __ Push(r0, fp);
          __ mr(fp, sp);
        }
      }
    } else if (call_descriptor->IsJSFunctionCall()) {
      __ Prologue();
    } else {
      StackFrame::Type type = info()->GetOutputStackFrameType();
      // TODO(mbrandy): Detect cases where ip is the entrypoint (for
      // efficient initialization of the constant pool pointer register).
      __ StubPrologue(type);
#if V8_ENABLE_WEBASSEMBLY
      if (call_descriptor->IsWasmFunctionCall() ||
          call_descriptor->IsWasmImportWrapper() ||
          call_descriptor->IsWasmCapiFunction()) {
        // For import wrappers and C-API functions, this stack slot is only used
        // for printing stack traces in V8. Also, it holds a WasmImportData
        // instead of the trusted instance data, which is taken care of in the
        // frames accessors.
        __ Push(kWasmImplicitArgRegister);
      }
      if (call_descriptor->IsWasmCapiFunction()) {
        // Reserve space for saving the PC later.
        __ addi(sp, sp, Operand(-kSystemPointerSize));
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }
    unwinding_info_writer_.MarkFrameConstructed(__ pc_offset());
  }

  int required_slots =
      frame()->GetTotalFrameSlotCount() - frame()->GetFixedSlotCount();
  if (info()->is_osr()) {
    // TurboFan OSR-compiled functions cannot be entered directly.
    __ Abort(AbortReason::kShouldNotDirectlyEnterOsrFunction);

    // Unoptimized code jumps directly to this entrypoint while the unoptimized
    // frame is still on the stack. Optimized code uses OSR values directly from
    // the unoptimized frame. Thus, all that needs to be done is to allocate the
    // remaining stack slots.
    __ RecordComment("-- OSR entrypoint --");
    osr_pc_offset_ = __ pc_offset();
    required_slots -= osr_helper()->UnoptimizedFrameSlots();
  }

  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();
  const RegList saves =
      V8_EMBEDDED_CONSTANT_POOL_BOOL
          ? call_descriptor->CalleeSavedRegisters() - kConstantPoolRegister
          : call_descriptor->CalleeSavedRegisters();

  if (required_slots > 0) {
#if V8_ENABLE_WEBASSEMBLY
    if (info()->IsWasm() && required_slots * kSystemPointerSize > 4 * KB) {
      // For WebAssembly functions with big frames we have to do the stack
      // overflow check before we construct the frame. Otherwise we may not
      // have enough space on the stack to call the runtime for the stack
      // overflow.
      Label done;

      // If the frame is bigger than the stack, we throw the stack overflow
      // exception unconditionally. Thereby we can avoid the integer overflow
      // check in the condition code.
      if (required_slots * kSystemPointerSize < v8_flags.stack_size * KB) {
        Register stack_limit = ip;
        __ LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit, r0);
        __ AddS64(stack_limit, stack_limit,
                  Operand(required_slots * kSystemPointerSize), r0);
        __ CmpU64(sp, stack_limit);
        __ bge(&done);
      }

      __ Call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
              RelocInfo::WASM_STUB_CALL);
      // The call does not return, hence we can ignore any references and just
      // define an empty safepoint.
      ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
      RecordSafepoint(reference_map);
      if (v8_flags.debug_code) __ stop();

      __ bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    // Skip callee-saved and return slots, which are pushed below.
    required_slots -= saves.Count();
    required_slots -= frame()->GetReturnSlotCount();
    required_slots -= (kDoubleSize / kSystemPointerSize) * saves_fp.Count();
    __ AddS64(sp, sp, Operand(-required_slots * kSystemPointerSize), r0);
  }

  // Save callee-saved Double registers.
  if (!saves_fp.is_empty()) {
    __ MultiPushDoubles(saves_fp);
    DCHECK_EQ(kNumCalleeSavedDoubles, saves_fp.Count());
  }

  // Save callee-saved registers.
  if (!saves.is_empty()) {
    __ MultiPush(saves);
    // register save area does not include the fp or constant pool pointer.
  }

  const int returns = frame()->GetReturnSlotCount();
  // Create space for returns.
  __ AllocateStackSpace(returns * kSystemPointerSize);

  if (!frame()->tagged_slots().IsEmpty()) {
    __ mov(kScratchReg, Operand(0));
    for (int spill_slot : frame()->tagged_slots()) {
      FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
      DCHECK(offset.from_frame_pointer());
      __ StoreU64(kScratchReg, MemOperand(fp, offset.offset()));
    }
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = frame()->GetReturnSlotCount();
  if (returns != 0) {
    // Create space for returns.
    __ AddS64(sp, sp, Operand(returns * kSystemPointerSize), r0);
  }

  // Restore registers.
  const RegList saves =
      V8_EMBEDDED_CONSTANT_POOL_BOOL
          ? call_descriptor->CalleeSavedRegisters() - kConstantPoolRegister
          : call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    __ MultiPop(saves);
  }

  // Restore double registers.
  const DoubleRegList double_saves = call_descriptor->CalleeSavedFPRegisters();
  if (!double_saves.is_empty()) {
    __ MultiPopDoubles(double_saves);
  }

  unwinding_info_writer_.MarkBlockWillExit();

  PPCOperandConverter g(this, nullptr);
  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ cmpi(g.ToRegister(additional_pop_count), Operand(0));
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue);
    }
  }

  Register argc_reg = r6;
  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.
  const bool drop_jsargs = parameter_slots != 0 &&
                           frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall();

  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    // Canonicalize JSFunction return sites for now unless they have an variable
    // number of stack slot pops
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ b(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count.
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
      __ LoadU64(argc_reg, MemOperand(fp, StandardFrameConstants::kArgCOffset));
    }
    AssembleDeconstructFrame();
  }
  // Constant pool is unavailable since the frame has been destructed
  ConstantPoolUnavailableScope constant_pool_unavailable(masm());
  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver).
    // The number of arguments without the receiver is
    // max(argc_reg, parameter_slots-1), and the receiver is added in
    // DropArguments().
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    if (parameter_slots > 1) {
      Label skip;
      __ CmpS64(argc_reg, Operand(parameter_slots), r0);
      __ bgt(&skip);
      __ mov(argc_reg, Operand(parameter_slots));
      __ bind(&skip);
    }
    __ DropArguments(argc_reg);
  } else if (additional_pop_count->IsImmediate()) {
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    __ Drop(parameter_slots + additional_count);
  } else if (parameter_slots == 0) {
    __ Drop(g.ToRegister(additional_pop_count));
  } else {
    // {additional_pop_count} is guaranteed to be zero if {parameter_slots !=
    // 0}. Check RawMachineAssembler::PopAndReturn.
    __ Drop(parameter_slots);
  }
  __ Ret();
}

void CodeGenerator::FinishCode() {}

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {
  int total_size = 0;
  for (DeoptimizationExit* exit : deoptimization_exits_) {
    total_size += (exit->kind() == DeoptimizeKind::kLazy)
                      ? Deoptimizer::kLazyDeoptExitSize
                      : Deoptimizer::kEagerDeoptExitSize;
  }

  __ CheckTrampolinePoolQuick(total_size);
}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  PPCOperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame
```