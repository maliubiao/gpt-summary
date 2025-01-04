Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a larger file `code-generator-mips64.cc`. This file seems to be responsible for generating MIPS64 assembly code from higher-level intermediate representation (IR) instructions within the V8 JavaScript engine.

The provided snippet appears to handle the generation of assembly code for specific IR instructions related to:

1. **Memory Access:** Loading and storing various data types (bytes, half-words, words, double-words) to and from memory. This includes both regular and unaligned accesses, and operations on floating-point registers.
2. **Stack Manipulation:** Pushing and popping values from the stack, claiming stack space, and storing values to specific stack slots.
3. **Bitwise Operations:** Byte swapping.
4. **SIMD (MSA) Operations:** A wide range of operations on 128-bit SIMD registers, including loading, storing, splatting, lane manipulation, arithmetic operations (add, subtract, multiply, divide), logical operations (and, or, xor, not), comparison operations, conversions between integer and floating-point types, and other specialized SIMD instructions.
5. **Atomic Operations:**  Atomic load, store, exchange, and compare-and-exchange operations on various integer sizes. Atomic binary operations (add, subtract, and, or, xor).
6. **Assertions:** Conditional assertions.

To illustrate the connection to JavaScript, I need to identify which JavaScript features would trigger these specific MIPS64 instructions. SIMD operations are directly related to the `SIMD` API in JavaScript. Memory access, stack manipulation, and atomic operations are fundamental to how JavaScript engines manage memory and execute code.

Let's break down the instructions and link them to JavaScript examples.
这是 `v8/src/compiler/backend/mips64/code-generator-mips64.cc` 文件的第二部分代码，它主要负责将 **中间表示 (IR) 指令** 转换为 **MIPS64 汇编代码**。这部分代码具体处理了各种类型的指令，涵盖了内存访问、栈操作、SIMD (MSA) 向量运算、原子操作以及一些辅助功能。

概括来说，这部分代码的功能是：**为多种中间表示指令生成对应的 MIPS64 汇编指令，以实现 V8 引擎的 JavaScript 执行。**

以下是一些主要的功能点：

* **内存访问指令:**  处理从内存加载数据到寄存器 (`Lhu`, `Lh`, `Lw`, `Lwu`, `Ld`, `Lwc1`, `Ldc1`) 和将寄存器数据存储到内存 (`Sh`, `Sw`, `Sd`, `Swc1`, `Sdc1`) 的操作。包括了对齐和非对齐的访问 (`U` 前缀)。
* **栈操作指令:**  实现将数据压入栈 (`Push`)、从栈中窥视数据 (`Peek`)、分配栈空间 (`StackClaim`) 和将数据存储到栈上的特定位置 (`StoreToStackSlot`)。
* **字节交换指令:**  支持 64 位和 32 位数据的字节交换 (`ByteSwap64`, `ByteSwap32`)。
* **SIMD (MSA) 向量操作指令:**  处理各种 SIMD 指令，这些指令允许对 128 位向量中的多个数据并行操作。涵盖了加载、存储、常量生成、零值填充、逻辑运算 (`S128And`, `S128Or`, `S128Xor`, `S128Not`)、选择 (`S128Select`)、算术运算（例如 `I32x4Add`, `F64x2Add` 等）、比较运算（例如 `F64x2Eq`, `I64x2GtS` 等）、类型转换（例如 `F64x2ConvertLowI32x4S`）、通道提取和替换、以及一些特定的 SIMD 功能（例如点积 `I32x4DotI16x8S`，绝对值，取反等）。这些指令的命名模式通常反映了操作的数据类型和操作本身（例如 `I32x4` 表示 4 个 32 位整数， `F64x2` 表示 2 个 64 位浮点数）。
* **原子操作指令:**  实现了原子加载 (`AtomicLoadInt8`, `AtomicLoadUint8` 等)、原子存储 (`AtomicStoreWord8`, `AtomicStoreWord16` 等)、原子交换 (`AtomicExchangeInt8`, `AtomicExchangeUint8` 等) 和原子比较并交换 (`AtomicCompareExchangeInt8`, `AtomicCompareExchangeUint8` 等) 操作。这些操作确保了在多线程环境中的数据一致性。
* **断言指令:**  支持在代码中插入断言 (`AssertEqual`)，用于调试和验证代码的正确性。
* **MSA 特定的加载和存储指令:**  提供了直接的 MSA 寄存器加载和存储指令 (`MsaLd`, `MsaSt`)。
* **向量元素全真判断指令:**  提供了判断向量中所有元素是否为真的指令 (`V128AnyTrue`, `I64x2AllTrue`, `I32x4AllTrue`, `I16x8AllTrue`, `I8x16AllTrue`)。

**与 JavaScript 的关系及示例**

这段代码的功能直接关系到 JavaScript 的执行效率，因为它负责将 JavaScript 的高级操作转换为底层的机器指令。

**示例 1: 内存访问**

在 JavaScript 中访问对象的属性会触发内存加载操作。

```javascript
const obj = { a: 10 };
const value = obj.a; // 这会触发类似 kMips64Ld 的指令来加载 'a' 的值
```

**示例 2: SIMD 向量操作**

JavaScript 的 `SIMD` API 允许进行向量化计算，这会直接对应到代码中的 MSA 指令。

```javascript
const a = SIMD.float32x4(1, 2, 3, 4);
const b = SIMD.float32x4(5, 6, 7, 8);
const sum = SIMD.float32x4.add(a, b); // 这会触发类似 kMips64F32x4Add 的指令
console.log(sum); // SIMD.float32x4(6, 8, 10, 12)
```

**示例 3: 原子操作**

JavaScript 的 `Atomics` API 允许在共享内存上进行原子操作，这会映射到代码中的原子操作指令。

```javascript
const buffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(buffer);

Atomics.add(view, 0, 5); // 这会触发类似 kAtomicAddWord32 的指令
console.log(view[0]); // 5
```

**示例 4: 栈操作**

函数调用和局部变量的存储涉及到栈操作。

```javascript
function foo(x) {
  const y = x + 1; // 局部变量 y 可能会被存储在栈上 (类似 kMips64StoreToStackSlot)
  return y;
}

foo(5); // 函数调用会涉及到栈的分配和参数传递
```

总而言之，这段 C++ 代码是 V8 引擎将 JavaScript 代码高效地转化为 MIPS64 架构机器码的关键组成部分，它针对不同的 JavaScript 语言特性和操作，生成了相应的底层指令。

Prompt: 
```
这是目录为v8/src/compiler/backend/mips64/code-generator-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
oryOperand());
      break;
    case kMips64Ulhu:
      __ Ulhu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Lh:
      __ Lh(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Ulh:
      __ Ulh(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Sh: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ Sh(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kMips64Ush: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ Ush(i.InputOrZeroRegister(index), mem, kScratchReg);
      break;
    }
    case kMips64Lw:
      __ Lw(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Ulw:
      __ Ulw(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Lwu:
      __ Lwu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Ulwu:
      __ Ulwu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Ld:
      __ Ld(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Uld:
      __ Uld(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Sw: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ Sw(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kMips64Usw: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ Usw(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kMips64Sd: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ Sd(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kMips64Usd: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ Usd(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kMips64Lwc1: {
      __ Lwc1(i.OutputSingleRegister(), i.MemoryOperand());
      break;
    }
    case kMips64Ulwc1: {
      __ Ulwc1(i.OutputSingleRegister(), i.MemoryOperand(), kScratchReg);
      break;
    }
    case kMips64Swc1: {
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&index);
      FPURegister ft = i.InputOrZeroSingleRegister(index);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }
      __ Swc1(ft, operand);
      break;
    }
    case kMips64Uswc1: {
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&index);
      FPURegister ft = i.InputOrZeroSingleRegister(index);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }
      __ Uswc1(ft, operand, kScratchReg);
      break;
    }
    case kMips64Ldc1:
      __ Ldc1(i.OutputDoubleRegister(), i.MemoryOperand());
      break;
    case kMips64Uldc1:
      __ Uldc1(i.OutputDoubleRegister(), i.MemoryOperand(), kScratchReg);
      break;
    case kMips64Sdc1: {
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&index);
      FPURegister ft = i.InputOrZeroDoubleRegister(index);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }
      __ Sdc1(ft, operand);
      break;
    }
    case kMips64Usdc1: {
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&index);
      FPURegister ft = i.InputOrZeroDoubleRegister(index);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }
      __ Usdc1(ft, operand, kScratchReg);
      break;
    }
    case kMips64Sync: {
      __ sync();
      break;
    }
    case kMips64Push:
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Sdc1(i.InputDoubleRegister(0), MemOperand(sp, -kDoubleSize));
        __ Subu(sp, sp, Operand(kDoubleSize));
        frame_access_state()->IncreaseSPDelta(kDoubleSize / kSystemPointerSize);
      } else {
        __ Push(i.InputRegister(0));
        frame_access_state()->IncreaseSPDelta(1);
      }
      break;
    case kMips64Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ Ldc1(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ Lwc1(
              i.OutputSingleRegister(0),
              MemOperand(fp, offset + kLessSignificantWordInDoublewordOffset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ ld_b(i.OutputSimd128Register(), MemOperand(fp, offset));
        }
      } else {
        __ Ld(i.OutputRegister(0), MemOperand(fp, offset));
      }
      break;
    }
    case kMips64StackClaim: {
      __ Dsubu(sp, sp, Operand(i.InputInt32(0)));
      frame_access_state()->IncreaseSPDelta(i.InputInt32(0) /
                                            kSystemPointerSize);
      break;
    }
    case kMips64StoreToStackSlot: {
      if (instr->InputAt(0)->IsFPRegister()) {
        if (instr->InputAt(0)->IsSimd128Register()) {
          CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
          __ st_b(i.InputSimd128Register(0), MemOperand(sp, i.InputInt32(1)));
        } else {
          __ Sdc1(i.InputDoubleRegister(0), MemOperand(sp, i.InputInt32(1)));
        }
      } else {
        __ Sd(i.InputRegister(0), MemOperand(sp, i.InputInt32(1)));
      }
      break;
    }
    case kMips64ByteSwap64: {
      __ ByteSwapSigned(i.OutputRegister(0), i.InputRegister(0), 8);
      break;
    }
    case kMips64ByteSwap32: {
      __ ByteSwapSigned(i.OutputRegister(0), i.InputRegister(0), 4);
      break;
    }
    case kMips64S128LoadSplat: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      auto sz = static_cast<MSASize>(MiscField::decode(instr->opcode()));
      __ LoadSplat(sz, i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kMips64S128Load8x8S: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register scratch = kSimd128ScratchReg;
      __ Ld(kScratchReg, i.MemoryOperand());
      __ fill_d(dst, kScratchReg);
      __ clti_s_b(scratch, dst, 0);
      __ ilvr_b(dst, scratch, dst);
      break;
    }
    case kMips64S128Load8x8U: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ Ld(kScratchReg, i.MemoryOperand());
      __ fill_d(dst, kScratchReg);
      __ ilvr_b(dst, kSimd128RegZero, dst);
      break;
    }
    case kMips64S128Load16x4S: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register scratch = kSimd128ScratchReg;
      __ Ld(kScratchReg, i.MemoryOperand());
      __ fill_d(dst, kScratchReg);
      __ clti_s_h(scratch, dst, 0);
      __ ilvr_h(dst, scratch, dst);
      break;
    }
    case kMips64S128Load16x4U: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ Ld(kScratchReg, i.MemoryOperand());
      __ fill_d(dst, kScratchReg);
      __ ilvr_h(dst, kSimd128RegZero, dst);
      break;
    }
    case kMips64S128Load32x2S: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register scratch = kSimd128ScratchReg;
      __ Ld(kScratchReg, i.MemoryOperand());
      __ fill_d(dst, kScratchReg);
      __ clti_s_w(scratch, dst, 0);
      __ ilvr_w(dst, scratch, dst);
      break;
    }
    case kMips64S128Load32x2U: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ Ld(kScratchReg, i.MemoryOperand());
      __ fill_d(dst, kScratchReg);
      __ ilvr_w(dst, kSimd128RegZero, dst);
      break;
    }
    case kMips64S128Load32Zero: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ xor_v(dst, dst, dst);
      __ Lwu(kScratchReg, i.MemoryOperand());
      __ insert_w(dst, 0, kScratchReg);
      break;
    }
    case kMips64S128Load64Zero: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ xor_v(dst, dst, dst);
      __ Ld(kScratchReg, i.MemoryOperand());
      __ insert_d(dst, 0, kScratchReg);
      break;
    }
    case kMips64S128LoadLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      auto sz = static_cast<MSASize>(MiscField::decode(instr->opcode()));
      __ LoadLane(sz, dst, i.InputUint8(1), i.MemoryOperand(2));
      break;
    }
    case kMips64S128StoreLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register src = i.InputSimd128Register(0);
      auto sz = static_cast<MSASize>(MiscField::decode(instr->opcode()));
      __ StoreLane(sz, src, i.InputUint8(1), i.MemoryOperand(2));
      break;
    }
    case kAtomicLoadInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Lb);
      break;
    case kAtomicLoadUint8:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Lbu);
      break;
    case kAtomicLoadInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Lh);
      break;
    case kAtomicLoadUint16:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Lhu);
      break;
    case kAtomicLoadWord32:
      if (AtomicWidthField::decode(opcode) == AtomicWidth::kWord32)
        ASSEMBLE_ATOMIC_LOAD_INTEGER(Lw);
      else
        ASSEMBLE_ATOMIC_LOAD_INTEGER(Lwu);
      break;
    case kMips64Word64AtomicLoadUint64:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld);
      break;
    case kAtomicStoreWord8:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Sb);
      break;
    case kAtomicStoreWord16:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Sh);
      break;
    case kAtomicStoreWord32:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Sw);
      break;
    case kMips64StoreCompressTagged:
    case kMips64Word64AtomicStoreWord64:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Sd);
      break;
    case kAtomicExchangeInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, true, 8, 32);
      break;
    case kAtomicExchangeUint8:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, false, 8, 32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 8, 64);
          break;
      }
      break;
    case kAtomicExchangeInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, true, 16, 32);
      break;
    case kAtomicExchangeUint16:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, false, 16, 32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 16, 64);
          break;
      }
      break;
    case kAtomicExchangeWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(Ll, Sc);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 32, 64);
          break;
      }
      break;
    case kMips64Word64AtomicExchangeUint64:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(Lld, Scd);
      break;
    case kAtomicCompareExchangeInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, true, 8, 32);
      break;
    case kAtomicCompareExchangeUint8:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, false, 8, 32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 8, 64);
          break;
      }
      break;
    case kAtomicCompareExchangeInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, true, 16, 32);
      break;
    case kAtomicCompareExchangeUint16:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, false, 16, 32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 16, 64);
          break;
      }
      break;
    case kAtomicCompareExchangeWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ sll(i.InputRegister(2), i.InputRegister(2), 0);
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Ll, Sc);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 32, 64);
          break;
      }
      break;
    case kMips64Word64AtomicCompareExchangeUint64:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Lld, Scd);
      break;
#define ATOMIC_BINOP_CASE(op, inst32, inst64)                          \
  case kAtomic##op##Int8:                                              \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, true, 8, inst32, 32);            \
    break;                                                             \
  case kAtomic##op##Uint8:                                             \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, false, 8, inst32, 32);       \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Lld, Scd, false, 8, inst64, 64);     \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Int16:                                             \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, true, 16, inst32, 32);           \
    break;                                                             \
  case kAtomic##op##Uint16:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, false, 16, inst32, 32);      \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Lld, Scd, false, 16, inst64, 64);    \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Word32:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP(Ll, Sc, inst32);                         \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Lld, Scd, false, 32, inst64, 64);    \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kMips64Word64Atomic##op##Uint64:                                \
    ASSEMBLE_ATOMIC_BINOP(Lld, Scd, inst64);                           \
    break;
      ATOMIC_BINOP_CASE(Add, Addu, Daddu)
      ATOMIC_BINOP_CASE(Sub, Subu, Dsubu)
      ATOMIC_BINOP_CASE(And, And, And)
      ATOMIC_BINOP_CASE(Or, Or, Or)
      ATOMIC_BINOP_CASE(Xor, Xor, Xor)
#undef ATOMIC_BINOP_CASE
    case kMips64AssertEqual:
      __ Assert(eq, static_cast<AbortReason>(i.InputOperand(2).immediate()),
                i.InputRegister(0), Operand(i.InputRegister(1)));
      break;
    case kMips64S128Const: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      uint64_t imm1 = make_uint64(i.InputUint32(1), i.InputUint32(0));
      uint64_t imm2 = make_uint64(i.InputUint32(3), i.InputUint32(2));
      __ li(kScratchReg, imm1);
      __ insert_d(dst, 0, kScratchReg);
      __ li(kScratchReg, imm2);
      __ insert_d(dst, 1, kScratchReg);
      break;
    }
    case kMips64S128Zero: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ xor_v(dst, dst, dst);
      break;
    }
    case kMips64S128AllOnes: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ ceq_d(dst, dst, dst);
      break;
    }
    case kMips64I32x4Splat: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fill_w(i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kMips64I32x4ExtractLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ copy_s_w(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputInt8(1));
      break;
    }
    case kMips64I32x4ReplaceLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      if (src != dst) {
        __ move_v(dst, src);
      }
      __ insert_w(dst, i.InputInt8(1), i.InputRegister(2));
      break;
    }
    case kMips64I32x4Add: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ addv_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I32x4Sub: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ subv_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F64x2Abs: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ bclri_d(i.OutputSimd128Register(), i.InputSimd128Register(0), 63);
      break;
    }
    case kMips64F64x2Neg: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ bnegi_d(i.OutputSimd128Register(), i.InputSimd128Register(0), 63);
      break;
    }
    case kMips64F64x2Sqrt: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fsqrt_d(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kMips64F64x2Add: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(fadd_d);
      break;
    }
    case kMips64F64x2Sub: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(fsub_d);
      break;
    }
    case kMips64F64x2Mul: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(fmul_d);
      break;
    }
    case kMips64F64x2Div: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(fdiv_d);
      break;
    }
    case kMips64F64x2Min: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register scratch0 = kSimd128RegZero;
      Simd128Register scratch1 = kSimd128ScratchReg;

      // If inputs are -0.0. and +0.0, then write -0.0 to scratch1.
      // scratch1 = (src0 == src1) ?  (src0 | src1) : (src1 | src1).
      __ fseq_d(scratch0, src0, src1);
      __ bsel_v(scratch0, src1, src0);
      __ or_v(scratch1, scratch0, src1);
      // scratch0 = isNaN(src0) ? src0 : scratch1.
      __ fseq_d(scratch0, src0, src0);
      __ bsel_v(scratch0, src0, scratch1);
      // scratch1 = (src0 < scratch0) ? src0 : scratch0.
      __ fslt_d(scratch1, src0, scratch0);
      __ bsel_v(scratch1, scratch0, src0);
      // Canonicalize the result.
      __ fmin_d(dst, scratch1, scratch1);
      break;
    }
    case kMips64F64x2Max: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register scratch0 = kSimd128RegZero;
      Simd128Register scratch1 = kSimd128ScratchReg;

      // If inputs are -0.0. and +0.0, then write +0.0 to scratch1.
      // scratch1 = (src0 == src1) ?  (src0 & src1) : (src1 & src1).
      __ fseq_d(scratch0, src0, src1);
      __ bsel_v(scratch0, src1, src0);
      __ and_v(scratch1, scratch0, src1);
      // scratch0 = isNaN(src0) ? src0 : scratch1.
      __ fseq_d(scratch0, src0, src0);
      __ bsel_v(scratch0, src0, scratch1);
      // scratch1 = (scratch0 < src0) ? src0 : scratch0.
      __ fslt_d(scratch1, scratch0, src0);
      __ bsel_v(scratch1, scratch0, src0);
      // Canonicalize the result.
      __ fmax_d(dst, scratch1, scratch1);
      break;
    }
    case kMips64F64x2Eq: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fceq_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F64x2Ne: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fcune_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64F64x2Lt: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fclt_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F64x2Le: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fcle_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F64x2Splat: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ Move(kScratchReg, i.InputDoubleRegister(0));
      __ fill_d(i.OutputSimd128Register(), kScratchReg);
      break;
    }
    case kMips64F64x2ExtractLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ copy_s_d(kScratchReg, i.InputSimd128Register(0), i.InputInt8(1));
      __ Move(i.OutputDoubleRegister(), kScratchReg);
      break;
    }
    case kMips64F64x2ReplaceLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ Move(kScratchReg, i.InputDoubleRegister(2));
      if (dst != src) {
        __ move_v(dst, src);
      }
      __ insert_d(dst, i.InputInt8(1), kScratchReg);
      break;
    }
    case kMips64I64x2Splat: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fill_d(i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kMips64I64x2ExtractLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ copy_s_d(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputInt8(1));
      break;
    }
    case kMips64F64x2Pmin: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      // dst = rhs < lhs ? rhs : lhs
      __ fclt_d(dst, rhs, lhs);
      __ bsel_v(dst, lhs, rhs);
      break;
    }
    case kMips64F64x2Pmax: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      // dst = lhs < rhs ? rhs : lhs
      __ fclt_d(dst, lhs, rhs);
      __ bsel_v(dst, lhs, rhs);
      break;
    }
    case kMips64F64x2Ceil: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ MSARoundD(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kRoundToPlusInf);
      break;
    }
    case kMips64F64x2Floor: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ MSARoundD(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kRoundToMinusInf);
      break;
    }
    case kMips64F64x2Trunc: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ MSARoundD(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kRoundToZero);
      break;
    }
    case kMips64F64x2NearestInt: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ MSARoundD(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kRoundToNearest);
      break;
    }
    case kMips64F64x2ConvertLowI32x4S: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ ilvr_w(kSimd128RegZero, kSimd128RegZero, i.InputSimd128Register(0));
      __ slli_d(kSimd128RegZero, kSimd128RegZero, 32);
      __ srai_d(kSimd128RegZero, kSimd128RegZero, 32);
      __ ffint_s_d(i.OutputSimd128Register(), kSimd128RegZero);
      break;
    }
    case kMips64F64x2ConvertLowI32x4U: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ ilvr_w(kSimd128RegZero, kSimd128RegZero, i.InputSimd128Register(0));
      __ ffint_u_d(i.OutputSimd128Register(), kSimd128RegZero);
      break;
    }
    case kMips64F64x2PromoteLowF32x4: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fexupr_d(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kMips64I64x2ReplaceLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      if (src != dst) {
        __ move_v(dst, src);
      }
      __ insert_d(dst, i.InputInt8(1), i.InputRegister(2));
      break;
    }
    case kMips64I64x2Add: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ addv_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I64x2Sub: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ subv_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I64x2Mul: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ mulv_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I64x2Neg: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ subv_d(i.OutputSimd128Register(), kSimd128RegZero,
                i.InputSimd128Register(0));
      break;
    }
    case kMips64I64x2Shl: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_d(kSimd128ScratchReg, i.InputRegister(1));
        __ sll_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ slli_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt6(1));
      }
      break;
    }
    case kMips64I64x2ShrS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_d(kSimd128ScratchReg, i.InputRegister(1));
        __ sra_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ srai_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt6(1));
      }
      break;
    }
    case kMips64I64x2ShrU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_d(kSimd128ScratchReg, i.InputRegister(1));
        __ srl_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ srli_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt6(1));
      }
      break;
    }
    case kMips64I64x2BitMask: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Register dst = i.OutputRegister();
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register scratch0 = kSimd128RegZero;
      Simd128Register scratch1 = kSimd128ScratchReg;
      __ srli_d(scratch0, src, 63);
      __ shf_w(scratch1, scratch0, 0x02);
      __ slli_d(scratch1, scratch1, 1);
      __ or_v(scratch0, scratch0, scratch1);
      __ copy_u_b(dst, scratch0, 0);
      break;
    }
    case kMips64I64x2Eq: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ceq_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kMips64I64x2Ne: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ceq_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      __ nor_v(i.OutputSimd128Register(), i.OutputSimd128Register(),
               i.OutputSimd128Register());
      break;
    }
    case kMips64I64x2GtS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ clt_s_d(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I64x2GeS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ cle_s_d(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I64x2Abs: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ add_a_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128RegZero);
      break;
    }
    case kMips64I64x2SConvertI32x4Low: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ ilvr_w(kSimd128ScratchReg, src, src);
      __ slli_d(dst, kSimd128ScratchReg, 32);
      __ srai_d(dst, dst, 32);
      break;
    }
    case kMips64I64x2SConvertI32x4High: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ ilvl_w(kSimd128ScratchReg, src, src);
      __ slli_d(dst, kSimd128ScratchReg, 32);
      __ srai_d(dst, dst, 32);
      break;
    }
    case kMips64I64x2UConvertI32x4Low: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ ilvr_w(i.OutputSimd128Register(), kSimd128RegZero,
                i.InputSimd128Register(0));
      break;
    }
    case kMips64I64x2UConvertI32x4High: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ ilvl_w(i.OutputSimd128Register(), kSimd128RegZero,
                i.InputSimd128Register(0));
      break;
    }
    case kMips64ExtMulLow: {
      auto dt = static_cast<MSADataType>(MiscField::decode(instr->opcode()));
      __ ExtMulLow(dt, i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1));
      break;
    }
    case kMips64ExtMulHigh: {
      auto dt = static_cast<MSADataType>(MiscField::decode(instr->opcode()));
      __ ExtMulHigh(dt, i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1));
      break;
    }
    case kMips64ExtAddPairwise: {
      auto dt = static_cast<MSADataType>(MiscField::decode(instr->opcode()));
      __ ExtAddPairwise(dt, i.OutputSimd128Register(),
                        i.InputSimd128Register(0));
      break;
    }
    case kMips64F32x4Splat: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ FmoveLow(kScratchReg, i.InputSingleRegister(0));
      __ fill_w(i.OutputSimd128Register(), kScratchReg);
      break;
    }
    case kMips64F32x4ExtractLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ copy_u_w(kScratchReg, i.InputSimd128Register(0), i.InputInt8(1));
      __ FmoveLow(i.OutputSingleRegister(), kScratchReg);
      break;
    }
    case kMips64F32x4ReplaceLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ FmoveLow(kScratchReg, i.InputSingleRegister(2));
      if (dst != src) {
        __ move_v(dst, src);
      }
      __ insert_w(dst, i.InputInt8(1), kScratchReg);
      break;
    }
    case kMips64F32x4SConvertI32x4: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ffint_s_w(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kMips64F32x4UConvertI32x4: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ffint_u_w(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kMips64I32x4Mul: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ mulv_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I32x4MaxS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ max_s_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I32x4MinS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ min_s_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I32x4Eq: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ceq_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kMips64I32x4Ne: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ ceq_w(dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ nor_v(dst, dst, dst);
      break;
    }
    case kMips64I32x4Shl: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_w(kSimd128ScratchReg, i.InputRegister(1));
        __ sll_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ slli_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt5(1));
      }
      break;
    }
    case kMips64I32x4ShrS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_w(kSimd128ScratchReg, i.InputRegister(1));
        __ sra_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ srai_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt5(1));
      }
      break;
    }
    case kMips64I32x4ShrU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_w(kSimd128ScratchReg, i.InputRegister(1));
        __ srl_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ srli_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt5(1));
      }
      break;
    }
    case kMips64I32x4MaxU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ max_u_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I32x4MinU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ min_u_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64S128Select: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      DCHECK(i.OutputSimd128Register() == i.InputSimd128Register(0));
      __ bsel_v(i.OutputSimd128Register(), i.InputSimd128Register(2),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64S128AndNot: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register scratch = kSimd128ScratchReg,
                      dst = i.OutputSimd128Register(),
                      src0 = i.InputSimd128Register(0),
                      src1 = i.InputSimd128Register(1);
      __ nor_v(scratch, src1, src1);
      __ and_v(dst, scratch, src0);
      break;
    }
    case kMips64F32x4Abs: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ bclri_w(i.OutputSimd128Register(), i.InputSimd128Register(0), 31);
      break;
    }
    case kMips64F32x4Neg: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ bnegi_w(i.OutputSimd128Register(), i.InputSimd128Register(0), 31);
      break;
    }
    case kMips64F32x4Add: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fadd_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F32x4Sub: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fsub_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F32x4Mul: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fmul_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F32x4Div: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fdiv_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F32x4Max: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register scratch0 = kSimd128RegZero;
      Simd128Register scratch1 = kSimd128ScratchReg;

      // If inputs are -0.0. and +0.0, then write +0.0 to scratch1.
      // scratch1 = (src0 == src1) ?  (src0 & src1) : (src1 & src1).
      __ fseq_w(scratch0, src0, src1);
      __ bsel_v(scratch0, src1, src0);
      __ and_v(scratch1, scratch0, src1);
      // scratch0 = isNaN(src0) ? src0 : scratch1.
      __ fseq_w(scratch0, src0, src0);
      __ bsel_v(scratch0, src0, scratch1);
      // scratch1 = (scratch0 < src0) ? src0 : scratch0.
      __ fslt_w(scratch1, scratch0, src0);
      __ bsel_v(scratch1, scratch0, src0);
      // Canonicalize the result.
      __ fmax_w(dst, scratch1, scratch1);
      break;
    }
    case kMips64F32x4Min: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register scratch0 = kSimd128RegZero;
      Simd128Register scratch1 = kSimd128ScratchReg;

      // If inputs are -0.0. and +0.0, then write -0.0 to scratch1.
      // scratch1 = (src0 == src1) ?  (src0 | src1) : (src1 | src1).
      __ fseq_w(scratch0, src0, src1);
      __ bsel_v(scratch0, src1, src0);
      __ or_v(scratch1, scratch0, src1);
      // scratch0 = isNaN(src0) ? src0 : scratch1.
      __ fseq_w(scratch0, src0, src0);
      __ bsel_v(scratch0, src0, scratch1);
      // scratch1 = (src0 < scratch0) ? src0 : scratch0.
      __ fslt_w(scratch1, src0, scratch0);
      __ bsel_v(scratch1, scratch0, src0);
      // Canonicalize the result.
      __ fmin_w(dst, scratch1, scratch1);
      break;
    }
    case kMips64F32x4Eq: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fceq_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F32x4Ne: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fcune_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64F32x4Lt: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fclt_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F32x4Le: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fcle_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64F32x4Pmin: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      // dst = rhs < lhs ? rhs : lhs
      __ fclt_w(dst, rhs, lhs);
      __ bsel_v(dst, lhs, rhs);
      break;
    }
    case kMips64F32x4Pmax: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      // dst = lhs < rhs ? rhs : lhs
      __ fclt_w(dst, lhs, rhs);
      __ bsel_v(dst, lhs, rhs);
      break;
    }
    case kMips64F32x4Ceil: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ MSARoundW(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kRoundToPlusInf);
      break;
    }
    case kMips64F32x4Floor: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ MSARoundW(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kRoundToMinusInf);
      break;
    }
    case kMips64F32x4Trunc: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ MSARoundW(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kRoundToZero);
      break;
    }
    case kMips64F32x4NearestInt: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ MSARoundW(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kRoundToNearest);
      break;
    }
    case kMips64F32x4DemoteF64x2Zero: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ fexdo_w(i.OutputSimd128Register(), kSimd128RegZero,
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I32x4SConvertF32x4: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ftrunc_s_w(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kMips64I32x4UConvertF32x4: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ftrunc_u_w(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kMips64F32x4Sqrt: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fsqrt_w(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kMips64I32x4Neg: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ subv_w(i.OutputSimd128Register(), kSimd128RegZero,
                i.InputSimd128Register(0));
      break;
    }
    case kMips64I32x4GtS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ clt_s_w(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I32x4GeS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ cle_s_w(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I32x4GtU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ clt_u_w(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I32x4GeU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ cle_u_w(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I32x4Abs: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ asub_s_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  kSimd128RegZero);
      break;
    }
    case kMips64I32x4BitMask: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Register dst = i.OutputRegister();
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register scratch0 = kSimd128RegZero;
      Simd128Register scratch1 = kSimd128ScratchReg;
      __ srli_w(scratch0, src, 31);
      __ srli_d(scratch1, scratch0, 31);
      __ or_v(scratch0, scratch0, scratch1);
      __ shf_w(scratch1, scratch0, 0x0E);
      __ slli_d(scratch1, scratch1, 2);
      __ or_v(scratch0, scratch0, scratch1);
      __ copy_u_b(dst, scratch0, 0);
      break;
    }
    case kMips64I32x4DotI16x8S: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ dotp_s_w(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I32x4TruncSatF64x2SZero: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ ftrunc_s_d(kSimd128ScratchReg, i.InputSimd128Register(0));
      __ sat_s_d(kSimd128ScratchReg, kSimd128ScratchReg, 31);
      __ pckev_w(i.OutputSimd128Register(), kSimd128RegZero,
                 kSimd128ScratchReg);
      break;
    }
    case kMips64I32x4TruncSatF64x2UZero: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ ftrunc_u_d(kSimd128ScratchReg, i.InputSimd128Register(0));
      __ sat_u_d(kSimd128ScratchReg, kSimd128ScratchReg, 31);
      __ pckev_w(i.OutputSimd128Register(), kSimd128RegZero,
                 kSimd128ScratchReg);
      break;
    }
    case kMips64I16x8Splat: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fill_h(i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kMips64I16x8ExtractLaneU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ copy_u_h(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputInt8(1));
      break;
    }
    case kMips64I16x8ExtractLaneS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ copy_s_h(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputInt8(1));
      break;
    }
    case kMips64I16x8ReplaceLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      if (src != dst) {
        __ move_v(dst, src);
      }
      __ insert_h(dst, i.InputInt8(1), i.InputRegister(2));
      break;
    }
    case kMips64I16x8Neg: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ subv_h(i.OutputSimd128Register(), kSimd128RegZero,
                i.InputSimd128Register(0));
      break;
    }
    case kMips64I16x8Shl: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_h(kSimd128ScratchReg, i.InputRegister(1));
        __ sll_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ slli_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt4(1));
      }
      break;
    }
    case kMips64I16x8ShrS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_h(kSimd128ScratchReg, i.InputRegister(1));
        __ sra_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ srai_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt4(1));
      }
      break;
    }
    case kMips64I16x8ShrU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_h(kSimd128ScratchReg, i.InputRegister(1));
        __ srl_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ srli_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt4(1));
      }
      break;
    }
    case kMips64I16x8Add: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ addv_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8AddSatS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ adds_s_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8Sub: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ subv_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8SubSatS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ subs_s_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8Mul: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ mulv_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8MaxS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ max_s_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8MinS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ min_s_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8Eq: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ceq_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8Ne: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ ceq_h(dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ nor_v(dst, dst, dst);
      break;
    }
    case kMips64I16x8GtS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ clt_s_h(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I16x8GeS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ cle_s_h(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I16x8AddSatU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ adds_u_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8SubSatU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ subs_u_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8MaxU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ max_u_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8MinU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ min_u_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I16x8GtU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ clt_u_h(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I16x8GeU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ cle_u_h(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I16x8RoundingAverageU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ aver_u_h(i.OutputSimd128Register(), i.InputSimd128Register(1),
                  i.InputSimd128Register(0));
      break;
    }
    case kMips64I16x8Abs: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ asub_s_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  kSimd128RegZero);
      break;
    }
    case kMips64I16x8BitMask: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Register dst = i.OutputRegister();
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register scratch0 = kSimd128RegZero;
      Simd128Register scratch1 = kSimd128ScratchReg;
      __ srli_h(scratch0, src, 15);
      __ srli_w(scratch1, scratch0, 15);
      __ or_v(scratch0, scratch0, scratch1);
      __ srli_d(scratch1, scratch0, 30);
      __ or_v(scratch0, scratch0, scratch1);
      __ shf_w(scratch1, scratch0, 0x0E);
      __ slli_d(scratch1, scratch1, 4);
      __ or_v(scratch0, scratch0, scratch1);
      __ copy_u_b(dst, scratch0, 0);
      break;
    }
    case kMips64I16x8Q15MulRSatS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ mulr_q_h(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16Splat: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ fill_b(i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kMips64I8x16ExtractLaneU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ copy_u_b(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputInt8(1));
      break;
    }
    case kMips64I8x16ExtractLaneS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ copy_s_b(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputInt8(1));
      break;
    }
    case kMips64I8x16ReplaceLane: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      if (src != dst) {
        __ move_v(dst, src);
      }
      __ insert_b(dst, i.InputInt8(1), i.InputRegister(2));
      break;
    }
    case kMips64I8x16Neg: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ subv_b(i.OutputSimd128Register(), kSimd128RegZero,
                i.InputSimd128Register(0));
      break;
    }
    case kMips64I8x16Shl: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_b(kSimd128ScratchReg, i.InputRegister(1));
        __ sll_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ slli_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt3(1));
      }
      break;
    }
    case kMips64I8x16ShrS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_b(kSimd128ScratchReg, i.InputRegister(1));
        __ sra_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ srai_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt3(1));
      }
      break;
    }
    case kMips64I8x16Add: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ addv_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16AddSatS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ adds_s_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16Sub: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ subv_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16SubSatS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ subs_s_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16MaxS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ max_s_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16MinS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ min_s_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16Eq: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ceq_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16Ne: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register();
      __ ceq_b(dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ nor_v(dst, dst, dst);
      break;
    }
    case kMips64I8x16GtS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ clt_s_b(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I8x16GeS: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ cle_s_b(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I8x16ShrU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (instr->InputAt(1)->IsRegister()) {
        __ fill_b(kSimd128ScratchReg, i.InputRegister(1));
        __ srl_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kSimd128ScratchReg);
      } else {
        __ srli_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt3(1));
      }
      break;
    }
    case kMips64I8x16AddSatU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ adds_u_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16SubSatU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ subs_u_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16MaxU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ max_u_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16MinU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ min_u_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kMips64I8x16GtU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ clt_u_b(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I8x16GeU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ cle_u_b(i.OutputSimd128Register(), i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      break;
    }
    case kMips64I8x16RoundingAverageU: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ aver_u_b(i.OutputSimd128Register(), i.InputSimd128Register(1),
                  i.InputSimd128Register(0));
      break;
    }
    case kMips64I8x16Abs: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      __ asub_s_b(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  kSimd128RegZero);
      break;
    }
    case kMips64I8x16Popcnt: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ pcnt_b(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kMips64I8x16BitMask: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Register dst = i.OutputRegister();
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register scratch0 = kSimd128RegZero;
      Simd128Register scratch1 = kSimd128ScratchReg;
      __ srli_b(scratch0, src, 7);
      __ srli_h(scratch1, scratch0, 7);
      __ or_v(scratch0, scratch0, scratch1);
      __ srli_w(scratch1, scratch0, 14);
      __ or_v(scratch0, scratch0, scratch1);
      __ srli_d(scratch1, scratch0, 28);
      __ or_v(scratch0, scratch0, scratch1);
      __ shf_w(scratch1, scratch0, 0x0E);
      __ ilvev_b(scratch0, scratch1, scratch0);
      __ copy_u_h(dst, scratch0, 0);
      break;
    }
    case kMips64S128And: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ and_v(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kMips64S128Or: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ or_v(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kMips64S128Xor: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ xor_v(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kMips64S128Not: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ nor_v(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(0));
      break;
    }
    case kMips64V128AnyTrue: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Register dst = i.OutputRegister();
      Label all_false;
      __ BranchMSA(&all_false, MSA_BRANCH_V, all_zero,
                   i.InputSimd128Register(0), USE_DELAY_SLOT);
      __ li(dst, 0l);  // branch delay slot
      __ li(dst, 1);
      __ bind(&all_false);
      break;
    }
    case kMips64I64x2AllTrue: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Register dst = i.OutputRegister();
      Label all_true;
      __ BranchMSA(&all_true, MSA_BRANCH_D, all_not_zero,
                   i.InputSimd128Register(0), USE_DELAY_SLOT);
      __ li(dst, 1);  // branch delay slot
      __ li(dst, 0l);
      __ bind(&all_true);
      break;
    }
    case kMips64I32x4AllTrue: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Register dst = i.OutputRegister();
      Label all_true;
      __ BranchMSA(&all_true, MSA_BRANCH_W, all_not_zero,
                   i.InputSimd128Register(0), USE_DELAY_SLOT);
      __ li(dst, 1);  // branch delay slot
      __ li(dst, 0l);
      __ bind(&all_true);
      break;
    }
    case kMips64I16x8AllTrue: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Register dst = i.OutputRegister();
      Label all_true;
      __ BranchMSA(&all_true, MSA_BRANCH_H, all_not_zero,
                   i.InputSimd128Register(0), USE_DELAY_SLOT);
      __ li(dst, 1);  // branch delay slot
      __ li(dst, 0l);
      __ bind(&all_true);
      break;
    }
    case kMips64I8x16AllTrue: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Register dst = i.OutputRegister();
      Label all_true;
      __ BranchMSA(&all_true, MSA_BRANCH_B, all_not_zero,
                   i.InputSimd128Register(0), USE_DELAY_SLOT);
      __ li(dst, 1);  // branch delay slot
      __ li(dst, 0l);
      __ bind(&all_true);
      break;
    }
    case kMips64MsaLd: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ ld_b(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kMips64MsaSt: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      __ st_b(i.InputSimd128Register(2), i.MemoryOperand());
      break;
    }
    case kMips64S32x4InterleaveRight: {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      Simd128Register dst = i.OutputSimd128Register(),
                      src0 = i.InputSimd128Re
"""


```