Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger file.
This is the third part of a four-part file.
The code seems to be related to low-level operations and potentially interacting with hardware features (like SIMD).
It defines functions within a `MacroAssembler` class, suggesting it's for generating machine code.
The function names like `LoadU32LE`, `StoreF64`, `AddF32`, and the use of registers indicate assembly-level operations.
The "LE" suffix likely stands for Little Endian.
It appears to handle loading, storing, and manipulating data of different sizes (8, 16, 32, 64, 128 bits) and types (integer, float, SIMD vectors).
There are also functions related to control flow (`JumpIfEqual`, `CallBuiltinByIndex`), deoptimization, and potentially atomic operations.
The presence of `#ifdef V8_TARGET_BIG_ENDIAN` suggests platform-specific handling.
The frequent use of `Condition` parameters in SIMD instructions hints at conditional execution based on vector element comparisons.
The file likely plays a crucial role in the V8 JavaScript engine by providing optimized, low-level implementations of various operations.

To illustrate the connection with JavaScript, I can create examples where these low-level operations would be essential for implementing JavaScript features.

Plan:
1. Summarize the functionalities present in the provided code snippet.
2. Identify if there is a connection with JavaScript functionality.
3. Provide JavaScript examples to demonstrate the connection.
这是 `v8/src/codegen/s390/macro-assembler-s390.cc` 文件的第三部分，主要负责实现以下功能：

**1. 内存加载和存储操作 (Load and Store Operations):**

*   **支持小端字节序 (Little-Endian - LE):**  提供了一系列带有 "LE" 后缀的函数，用于处理小端字节序的数据加载和存储。这包括加载和存储不同大小的无符号和有符号整数 (U64, S32, U32, U16, S16) 以及浮点数 (F64, F32) 和 128 位向量 (V128)。
*   **大端字节序 (Big-Endian):**  如果没有定义 `V8_TARGET_BIG_ENDIAN`，则会使用不带 "LE" 后缀的函数，这些函数通常假定是大端字节序或者平台默认的字节序。
*   **条件加载 (Load On Condition):** 提供了 `LoadOnConditionP` 用于基于条件码加载指针大小的数据。
*   **加载并测试 (Load And Test):**  提供 `LoadAndTest32` 和 `LoadAndTestP` 用于加载数据并设置条件码。

**2. 浮点数运算 (Floating-Point Operations):**

*   **基本的算术运算:**  提供了浮点数的加法 (`AddF32`, `AddF64`), 减法 (`SubF32`, `SubF64`), 乘法 (`MulF32`, `MulF64`), 和除法 (`DivF32`, `DivF64`) 操作，支持寄存器之间以及寄存器和内存之间的运算。
*   **类型转换:** 提供了将单精度浮点数加载并转换为双精度浮点数的功能 (`LoadF32AsF64`).

**3. 整数位运算 (Integer Bitwise Operations):**

*   **移位操作:**  提供了逻辑左移 (`ShiftLeftU32`, `ShiftLeftU64`) 和逻辑右移 (`ShiftRightU32`, `ShiftRightU64`) 以及算术右移 (`ShiftRightS32`, `ShiftRightS64`) 操作。
*   **清除位 (Clear Bits):**  提供了 `ClearRightImm` 用于清除最右边的指定数量的位。
*   **计算前导零和尾随零 (Count Leading/Trailing Zeros):** 提供了 `CountLeadingZerosU32`, `CountLeadingZerosU64`, `CountTrailingZerosU32`, `CountTrailingZerosU64` 用于计算整数的前导零和尾随零的个数。
*   **计算置位位数 (Popcount):** 提供了 `Popcnt32` 和 `Popcnt64` 用于计算 32 位和 64 位整数中置位的位数。

**4. 数据交换 (Data Swapping):**

*   提供了用于交换寄存器之间、寄存器和内存之间、以及内存之间的数据的函数，支持指针大小的数据、浮点数以及 128 位 SIMD 向量。

**5. 代码控制流 (Code Control Flow):**

*   **获取代码地址:** 提供了 `ComputeCodeStartAddress` 和 `LoadPC` 用于获取当前代码的起始地址和程序计数器 (PC) 的值。
*   **条件跳转:** 提供了 `JumpIfEqual` 和 `JumpIfLessThan` 用于基于条件跳转到指定的标签。
*   **调用内置函数 (Call Builtin Functions):**  提供了 `LoadEntryFromBuiltinIndex`, `CallBuiltinByIndex`, `LoadEntryFromBuiltin`, 和 `EntryFromBuiltinAsOperand` 用于加载和调用 V8 引擎的内置函数。
*   **调用和跳转代码对象 (Call and Jump Code Object):**  提供了 `LoadCodeInstructionStart`, `CallCodeObject`, 和 `JumpCodeObject` 用于加载和执行代码对象。
*   **调用 JavaScript 函数 (Call JavaScript Function):** 提供了 `CallJSFunction` 和 `JumpJSFunction` 用于调用 JavaScript 函数。
*   **与 C++ API 交互:** 提供了 `zosStoreReturnAddressAndCall` (在 `V8_OS_ZOS` 环境下) 和 `StoreReturnAddressAndCall` 用于调用 C++ API 函数并处理返回地址。
*   **处理去优化 (Deoptimization):**  提供了 `BailoutIfDeoptimized` 和 `CallForDeoptimization` 用于在代码需要去优化时跳转到相应的处理程序。
*   **陷阱和断点 (Trap and Debug Break):** 提供了 `Trap` 和 `DebugBreak` 用于插入陷阱指令或断点。

**6. 原子操作 (Atomic Operations):**

*   提供了原子比较并交换 (`AtomicCmpExchangeU8`, `AtomicCmpExchangeU16`) 和原子交换 (`AtomicExchangeU8`, `AtomicExchangeU16`) 操作，用于在多线程环境下安全地修改内存中的数据。

**7. SIMD (单指令多数据) 支持 (SIMD Support):**

*   提供了一整套用于操作 128 位 SIMD 寄存器的指令，包括：
    *   **创建 (Splat):**  将一个标量值复制到向量的所有元素 (`F64x2Splat`, `F32x4Splat`, `I64x2Splat`, `I32x4Splat`, `I16x8Splat`, `I8x16Splat`).
    *   **提取 (Extract Lane):** 从向量中提取指定索引的元素到标量寄存器 (`F64x2ExtractLane`, `F32x4ExtractLane`, `I64x2ExtractLane`, `I32x4ExtractLane`, `I16x8ExtractLaneU/S`, `I8x16ExtractLaneU/S`).
    *   **替换 (Replace Lane):** 将标量寄存器的值替换到向量的指定索引位置 (`F64x2ReplaceLane`, `F32x4ReplaceLane`, `I64x2ReplaceLane`, `I32x4ReplaceLane`, `I16x8ReplaceLane`, `I8x16ReplaceLane`).
    *   **逻辑运算 (Logical Operations):**  非 (`S128Not`), 与 (`S128And`), 或 (`S128Or`), 异或 (`S128Xor`), 与非 (`S128AndNot`), 以及创建全零 (`S128Zero`) 和全一 (`S128AllOnes`) 向量。
    *   **选择 (Select):**  根据掩码向量从两个源向量中选择元素 (`S128Select`).
    *   **一元运算 (Unary Operations):**  绝对值 (`F64x2Abs`, `F32x4Abs`, `I64x2Abs`, `I32x4Abs`, `I16x8Abs`, `I8x16Abs`), 取反 (`F64x2Neg`, `F32x4Neg`, `I64x2Neg`, `I32x4Neg`, `I16x8Neg`, `I8x16Neg`), 平方根 (`F64x2Sqrt`, `F32x4Sqrt`), Ceil, Floor, Trunc, Nearest Int, 以及符号扩展和零扩展转换。
    *   **二元比较运算 (Binary Comparison Operations):** 等于 (`I64x2Eq`, `I32x4Eq`, `I16x8Eq`, `I8x16Eq`, `F64x2Eq`, `F32x4Eq`), 大于 (`I64x2GtS`, `I32x4GtS/U`, `I16x8GtS/U`, `I8x16GtS/U`). 还提供了不等 (`F64x2Ne`, `F32x4Ne`, `I64x2Ne`, `I32x4Ne`, `I16x8Ne`, `I8x16Ne`), 小于 (`F64x2Lt`, `F32x4Lt`), 小于等于 (`F64x2Le`, `F32x4Le`), 大于等于 (`I64x2GeS`, `I32x4GeS/U`, `I16x8GeS/U`, `I8x16GeU`).
    *   **二元算术运算 (Binary Arithmetic Operations):** 加法 (`F64x2Add`, `F32x4Add`, `I64x2Add`, `I32x4Add`, `I16x8Add`, `I8x16Add`), 减法 (`F64x2Sub`, `F32x4Sub`, `I64x2Sub`, `I32x4Sub`, `I16x8Sub`, `I8x16Sub`), 乘法 (`F64x2Mul`, `F32x4Mul`, `I32x4Mul`, `I16x8Mul`, `I64x2Mul` - 使用标量寄存器辅助), 除法 (`F64x2Div`, `F32x4Div`), 最小值/最大值 (`F64x2Min/Max`, `F32x4Min/Max`, `I32x4MinS/U`, `I32x4MaxS/U`, `I16x8MinS/U`, `I16x8MaxS/U`, `I8x16MinS/U`, `I8x16MaxS/U`), 平均值 (`I16x8RoundingAverageU`, `I8x16RoundingAverageU`).
    *   **移位操作 (Shift Operations):**  左移 (`I64x2Shl`, `I32x4Shl`, `I16x8Shl`, `I8x16Shl`), 有符号右移 (`I64x2ShrS`, `I32x4ShrS`, `I16x8ShrS`, `I8x16ShrS`), 无符号右移 (`I64x2ShrU`, `I32x4ShrU`, `I16x8ShrU`, `I8x16ShrU`).
    *   **扩展乘法 (Extended Multiplication):**  将低位或高位的元素进行乘法 (`I64x2ExtMulLow/HighI32x4S/U`, `I32x4ExtMulLow/HighI16x8S/U`, `I16x8ExtMulLow/HighI8x16S/U`).
    *   **全真 (All True):** 检查向量的所有元素是否为真 (`I64x2AllTrue`, `I32x4AllTrue`, `I16x8AllTrue`, `I8x16AllTrue`).
    *   **融合乘加/减 (Fused Multiply-Add/Subtract):** `F64x2Qfma`, `F64x2Qfms`, `F32x4Qfma`, `F32x4Qfms`.
    *   **位掩码 (Bit Mask):**  将向量的每个元素的最高位提取到一个标量寄存器中 (`I64x2BitMask`, `I32x4BitMask`, `I16x8BitMask`, `I8x16BitMask`).
    *   **类型转换 (Conversions):** 将有符号和无符号 32 位整数转换为 64 位浮点数 (`F64x2ConvertLowI32x4S/U`), 以及将浮点数转换为有符号和无符号 32 位整数 (`I32x4SConvertF32x4`, `I32x4UConvertF32x4`).
    *   **任意真 (Any True):** 检查向量中是否有任何元素为真 (`V128AnyTrue`).

**与 JavaScript 的关系：**

这个文件中的代码直接用于实现 V8 JavaScript 引擎的底层操作。JavaScript 代码最终会被编译成机器码执行，而 `MacroAssembler` 正是用来生成这些机器码的工具。

**JavaScript 示例：**

1. **整数运算和内存访问:**

    ```javascript
    function add(a, b) {
      return a + b;
    }

    let x = 10;
    let y = 5;
    let result = add(x, y);
    // 在底层，`add` 函数的实现可能涉及到加载 `a` 和 `b` 的值到寄存器，
    // 然后执行加法指令，并将结果存储回内存或寄存器。
    ```

2. **浮点数运算:**

    ```javascript
    let pi = 3.14159;
    let radius = 5.0;
    let area = pi * radius * radius;
    // 计算 `area` 涉及到浮点数的乘法，这会使用 `MulF64` 或类似的指令。
    ```

3. **SIMD 操作 (用于 WebAssembly 或特定 JavaScript API):**

    ```javascript
    // WebAssembly SIMD
    const a = new Float64Array([1.0, 2.0]);
    const b = new Float64Array([3.0, 4.0]);
    const va = SIMD.float64x2(a[0], a[1]);
    const vb = SIMD.float64x2(b[0], b[1]);
    const vc = SIMD.float64x2.add(va, vb);
    // `SIMD.float64x2.add` 在底层可能会调用 `F64x2Add` 指令。
    ```

4. **内置函数调用:**

    ```javascript
    Math.sqrt(25);
    // `Math.sqrt` 是一个内置函数，调用它会使用类似 `CallBuiltinByIndex` 的机制来执行 V8 引擎预先编译好的代码。
    ```

5. **类型转换:**

    ```javascript
    let floatValue = 3.7;
    let intValue = Math.floor(floatValue);
    // `Math.floor` 的实现可能涉及到浮点数到整数的转换，底层会使用相应的指令。
    ```

总而言之，`macro-assembler-s390.cc` 文件的这一部分为 V8 JavaScript 引擎在 s390 架构上提供了执行 JavaScript 代码所需的各种底层操作指令的封装，涵盖了内存访问、算术运算、位操作、控制流、原子操作以及 SIMD 指令，是 V8 引擎高效运行的关键组成部分。

### 提示词
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
oadS32(dst, dst);
}

void MacroAssembler::LoadU32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  lrv(dst, opnd);
  LoadU32(dst, dst);
}

void MacroAssembler::LoadU16LE(Register dst, const MemOperand& opnd) {
  lrvh(dst, opnd);
  LoadU16(dst, dst);
}

void MacroAssembler::LoadS16LE(Register dst, const MemOperand& opnd) {
  lrvh(dst, opnd);
  LoadS16(dst, dst);
}

void MacroAssembler::LoadV128LE(DoubleRegister dst, const MemOperand& opnd,
                                Register scratch0, Register scratch1) {
  bool use_vlbr = CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
                  is_uint12(opnd.offset());
  if (use_vlbr) {
    vlbr(dst, opnd, Condition(4));
  } else {
    lrvg(scratch0, opnd);
    lrvg(scratch1,
         MemOperand(opnd.rx(), opnd.rb(), opnd.offset() + kSystemPointerSize));
    vlvgp(dst, scratch1, scratch0);
  }
}

void MacroAssembler::LoadF64LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  lrvg(scratch, opnd);
  ldgr(dst, scratch);
}

void MacroAssembler::LoadF32LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  lrv(scratch, opnd);
  ShiftLeftU64(scratch, scratch, Operand(32));
  ldgr(dst, scratch);
}

void MacroAssembler::StoreU64LE(Register src, const MemOperand& mem,
                                Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    strvg(src, MemOperand(mem.rb(), scratch));
  } else {
    strvg(src, mem);
  }
}

void MacroAssembler::StoreU32LE(Register src, const MemOperand& mem,
                                Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    strv(src, MemOperand(mem.rb(), scratch));
  } else {
    strv(src, mem);
  }
}

void MacroAssembler::StoreU16LE(Register src, const MemOperand& mem,
                                Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    strvh(src, MemOperand(mem.rb(), scratch));
  } else {
    strvh(src, mem);
  }
}

void MacroAssembler::StoreF64LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  DCHECK(is_uint12(opnd.offset()));
  lgdr(scratch, src);
  strvg(scratch, opnd);
}

void MacroAssembler::StoreF32LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  DCHECK(is_uint12(opnd.offset()));
  lgdr(scratch, src);
  ShiftRightU64(scratch, scratch, Operand(32));
  strv(scratch, opnd);
}

void MacroAssembler::StoreV128LE(Simd128Register src, const MemOperand& mem,
                                 Register scratch1, Register scratch2) {
  bool use_vstbr = CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
                   is_uint12(mem.offset());
  if (use_vstbr) {
    vstbr(src, mem, Condition(4));
  } else {
    vlgv(scratch1, src, MemOperand(r0, 1), Condition(3));
    vlgv(scratch2, src, MemOperand(r0, 0), Condition(3));
    strvg(scratch1, mem);
    strvg(scratch2,
          MemOperand(mem.rx(), mem.rb(), mem.offset() + kSystemPointerSize));
  }
}

#else
void MacroAssembler::LoadU64LE(Register dst, const MemOperand& mem,
                               Register scratch) {
  LoadU64(dst, mem, scratch);
}

void MacroAssembler::LoadS32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  LoadS32(dst, opnd, scratch);
}

void MacroAssembler::LoadU32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  LoadU32(dst, opnd, scratch);
}

void MacroAssembler::LoadU16LE(Register dst, const MemOperand& opnd) {
  LoadU16(dst, opnd);
}

void MacroAssembler::LoadS16LE(Register dst, const MemOperand& opnd) {
  LoadS16(dst, opnd);
}

void MacroAssembler::LoadV128LE(DoubleRegister dst, const MemOperand& opnd,
                                Register scratch0, Register scratch1) {
  USE(scratch1);
  LoadV128(dst, opnd, scratch0);
}

void MacroAssembler::LoadF64LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  USE(scratch);
  LoadF64(dst, opnd);
}

void MacroAssembler::LoadF32LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  USE(scratch);
  LoadF32(dst, opnd);
}

void MacroAssembler::StoreU64LE(Register src, const MemOperand& mem,
                                Register scratch) {
  StoreU64(src, mem, scratch);
}

void MacroAssembler::StoreU32LE(Register src, const MemOperand& mem,
                                Register scratch) {
  StoreU32(src, mem, scratch);
}

void MacroAssembler::StoreU16LE(Register src, const MemOperand& mem,
                                Register scratch) {
  StoreU16(src, mem, scratch);
}

void MacroAssembler::StoreF64LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  StoreF64(src, opnd);
}

void MacroAssembler::StoreF32LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  StoreF32(src, opnd);
}

void MacroAssembler::StoreV128LE(Simd128Register src, const MemOperand& mem,
                                 Register scratch1, Register scratch2) {
  StoreV128(src, mem, scratch1);
}

#endif

// Load And Test (Reg <- Reg)
void MacroAssembler::LoadAndTest32(Register dst, Register src) {
  ltr(dst, src);
}

// Load And Test Pointer Sized (Reg <- Reg)
void MacroAssembler::LoadAndTestP(Register dst, Register src) {
  ltgr(dst, src);
}

// Load And Test 32-bit (Reg <- Mem)
void MacroAssembler::LoadAndTest32(Register dst, const MemOperand& mem) {
  lt_z(dst, mem);
}

// Load And Test Pointer Sized (Reg <- Mem)
void MacroAssembler::LoadAndTestP(Register dst, const MemOperand& mem) {
  ltg(dst, mem);
}

// Load On Condition Pointer Sized (Reg <- Reg)
void MacroAssembler::LoadOnConditionP(Condition cond, Register dst,
                                      Register src) {
  locgr(cond, dst, src);
}

// Load Double Precision (64-bit) Floating Point number from memory
void MacroAssembler::LoadF64(DoubleRegister dst, const MemOperand& mem) {
  // for 32bit and 64bit we all use 64bit floating point regs
  if (is_uint12(mem.offset())) {
    ld(dst, mem);
  } else {
    ldy(dst, mem);
  }
}

// Load Single Precision (32-bit) Floating Point number from memory
void MacroAssembler::LoadF32(DoubleRegister dst, const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    le_z(dst, mem);
  } else {
    DCHECK(is_int20(mem.offset()));
    ley(dst, mem);
  }
}

void MacroAssembler::LoadV128(Simd128Register dst, const MemOperand& mem,
                              Register scratch) {
  DCHECK(scratch != r0);
  if (is_uint12(mem.offset())) {
    vl(dst, mem, Condition(0));
  } else {
    DCHECK(is_int20(mem.offset()));
    lay(scratch, mem);
    vl(dst, MemOperand(scratch), Condition(0));
  }
}

// Store Double Precision (64-bit) Floating Point number to memory
void MacroAssembler::StoreF64(DoubleRegister dst, const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    std(dst, mem);
  } else {
    stdy(dst, mem);
  }
}

// Store Single Precision (32-bit) Floating Point number to memory
void MacroAssembler::StoreF32(DoubleRegister src, const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    ste(src, mem);
  } else {
    stey(src, mem);
  }
}

void MacroAssembler::StoreV128(Simd128Register src, const MemOperand& mem,
                               Register scratch) {
  DCHECK(scratch != r0);
  if (is_uint12(mem.offset())) {
    vst(src, mem, Condition(0));
  } else {
    DCHECK(is_int20(mem.offset()));
    lay(scratch, mem);
    vst(src, MemOperand(scratch), Condition(0));
  }
}

void MacroAssembler::AddF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    aebr(dst, rhs);
  } else if (dst == rhs) {
    aebr(dst, lhs);
  } else {
    ler(dst, lhs);
    aebr(dst, rhs);
  }
}

void MacroAssembler::SubF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    sebr(dst, rhs);
  } else if (dst == rhs) {
    sebr(dst, lhs);
    lcebr(dst, dst);
  } else {
    ler(dst, lhs);
    sebr(dst, rhs);
  }
}

void MacroAssembler::MulF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    meebr(dst, rhs);
  } else if (dst == rhs) {
    meebr(dst, lhs);
  } else {
    ler(dst, lhs);
    meebr(dst, rhs);
  }
}

void MacroAssembler::DivF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    debr(dst, rhs);
  } else if (dst == rhs) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreF32(dst, MemOperand(sp));
    ler(dst, lhs);
    deb(dst, MemOperand(sp));
    la(sp, MemOperand(sp, kSystemPointerSize));
  } else {
    ler(dst, lhs);
    debr(dst, rhs);
  }
}

void MacroAssembler::AddF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    adbr(dst, rhs);
  } else if (dst == rhs) {
    adbr(dst, lhs);
  } else {
    ldr(dst, lhs);
    adbr(dst, rhs);
  }
}

void MacroAssembler::SubF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    sdbr(dst, rhs);
  } else if (dst == rhs) {
    sdbr(dst, lhs);
    lcdbr(dst, dst);
  } else {
    ldr(dst, lhs);
    sdbr(dst, rhs);
  }
}

void MacroAssembler::MulF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    mdbr(dst, rhs);
  } else if (dst == rhs) {
    mdbr(dst, lhs);
  } else {
    ldr(dst, lhs);
    mdbr(dst, rhs);
  }
}

void MacroAssembler::DivF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    ddbr(dst, rhs);
  } else if (dst == rhs) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreF64(dst, MemOperand(sp));
    ldr(dst, lhs);
    ddb(dst, MemOperand(sp));
    la(sp, MemOperand(sp, kSystemPointerSize));
  } else {
    ldr(dst, lhs);
    ddbr(dst, rhs);
  }
}

void MacroAssembler::AddFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    aeb(dst, opnd);
  } else {
    ley(scratch, opnd);
    aebr(dst, scratch);
  }
}

void MacroAssembler::AddFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    adb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    adbr(dst, scratch);
  }
}

void MacroAssembler::SubFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    seb(dst, opnd);
  } else {
    ley(scratch, opnd);
    sebr(dst, scratch);
  }
}

void MacroAssembler::SubFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    sdb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    sdbr(dst, scratch);
  }
}

void MacroAssembler::MulFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    meeb(dst, opnd);
  } else {
    ley(scratch, opnd);
    meebr(dst, scratch);
  }
}

void MacroAssembler::MulFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    mdb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    mdbr(dst, scratch);
  }
}

void MacroAssembler::DivFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    deb(dst, opnd);
  } else {
    ley(scratch, opnd);
    debr(dst, scratch);
  }
}

void MacroAssembler::DivFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    ddb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    ddbr(dst, scratch);
  }
}

void MacroAssembler::LoadF32AsF64(DoubleRegister dst, const MemOperand& opnd) {
  if (is_uint12(opnd.offset())) {
    ldeb(dst, opnd);
  } else {
    ley(dst, opnd);
    ldebr(dst, dst);
  }
}

// Variable length depending on whether offset fits into immediate field
// MemOperand of RX or RXY format
void MacroAssembler::StoreU32(Register src, const MemOperand& mem,
                              Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  bool use_RXform = false;
  bool use_RXYform = false;

  if (is_uint12(offset)) {
    // RX-format supports unsigned 12-bits offset.
    use_RXform = true;
  } else if (is_int20(offset)) {
    // RXY-format supports signed 20-bits offset.
    use_RXYform = true;
  } else if (scratch != no_reg) {
    // Materialize offset into scratch register.
    mov(scratch, Operand(offset));
  } else {
    // scratch is no_reg
    DCHECK(false);
  }

  if (use_RXform) {
    st(src, mem);
  } else if (use_RXYform) {
    sty(src, mem);
  } else {
    StoreU32(src, MemOperand(base, scratch));
  }
}

void MacroAssembler::LoadS16(Register dst, Register src) {
  lghr(dst, src);
}

// Loads 16-bits half-word value from memory and sign extends to pointer
// sized register
void MacroAssembler::LoadS16(Register dst, const MemOperand& mem,
                             Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (!is_int20(offset)) {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    lgh(dst, MemOperand(base, scratch));
  } else {
    lgh(dst, mem);
  }
}

// Variable length depending on whether offset fits into immediate field
// MemOperand current only supports d-form
void MacroAssembler::StoreU16(Register src, const MemOperand& mem,
                              Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (is_uint12(offset)) {
    sth(src, mem);
  } else if (is_int20(offset)) {
    sthy(src, mem);
  } else {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    sth(src, MemOperand(base, scratch));
  }
}

// Variable length depending on whether offset fits into immediate field
// MemOperand current only supports d-form
void MacroAssembler::StoreU8(Register src, const MemOperand& mem,
                             Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (is_uint12(offset)) {
    stc(src, mem);
  } else if (is_int20(offset)) {
    stcy(src, mem);
  } else {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    stc(src, MemOperand(base, scratch));
  }
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU32(Register dst, Register src,
                                  const Operand& val) {
  ShiftLeftU32(dst, src, r0, val);
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU32(Register dst, Register src, Register val,
                                  const Operand& val2) {
  if (dst == src) {
    sll(dst, val, val2);
  } else if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    sllk(dst, src, val, val2);
  } else {
    DCHECK(dst != val || val == r0);  // The lr/sll path clobbers val.
    lr(dst, src);
    sll(dst, val, val2);
  }
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU64(Register dst, Register src,
                                  const Operand& val) {
  ShiftLeftU64(dst, src, r0, val);
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU64(Register dst, Register src, Register val,
                                  const Operand& val2) {
  sllg(dst, src, val, val2);
}

// Shift right logical for 32-bit integer types.
void MacroAssembler::ShiftRightU32(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightU32(dst, src, r0, val);
}

// Shift right logical for 32-bit integer types.
void MacroAssembler::ShiftRightU32(Register dst, Register src, Register val,
                                   const Operand& val2) {
  if (dst == src) {
    srl(dst, val, val2);
  } else if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    srlk(dst, src, val, val2);
  } else {
    DCHECK(dst != val || val == r0);  // The lr/srl path clobbers val.
    lr(dst, src);
    srl(dst, val, val2);
  }
}

void MacroAssembler::ShiftRightU64(Register dst, Register src, Register val,
                                   const Operand& val2) {
  srlg(dst, src, val, val2);
}

// Shift right logical for 64-bit integer types.
void MacroAssembler::ShiftRightU64(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightU64(dst, src, r0, val);
}

// Shift right arithmetic for 32-bit integer types.
void MacroAssembler::ShiftRightS32(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightS32(dst, src, r0, val);
}

// Shift right arithmetic for 32-bit integer types.
void MacroAssembler::ShiftRightS32(Register dst, Register src, Register val,
                                   const Operand& val2) {
  if (dst == src) {
    sra(dst, val, val2);
  } else if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    srak(dst, src, val, val2);
  } else {
    DCHECK(dst != val || val == r0);  // The lr/sra path clobbers val.
    lr(dst, src);
    sra(dst, val, val2);
  }
}

// Shift right arithmetic for 64-bit integer types.
void MacroAssembler::ShiftRightS64(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightS64(dst, src, r0, val);
}

// Shift right arithmetic for 64-bit integer types.
void MacroAssembler::ShiftRightS64(Register dst, Register src, Register val,
                                   const Operand& val2) {
  srag(dst, src, val, val2);
}

// Clear right most # of bits
void MacroAssembler::ClearRightImm(Register dst, Register src,
                                   const Operand& val) {
  int numBitsToClear = val.immediate() % (kSystemPointerSize * 8);

  // Try to use RISBG if possible
  if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
    int endBit = 63 - numBitsToClear;
    RotateInsertSelectBits(dst, src, Operand::Zero(), Operand(endBit),
                           Operand::Zero(), true);
    return;
  }

  uint64_t hexMask = ~((1L << numBitsToClear) - 1);

  // S390 AND instr clobbers source.  Make a copy if necessary
  if (dst != src) mov(dst, src);

  if (numBitsToClear <= 16) {
    nill(dst, Operand(static_cast<uint16_t>(hexMask)));
  } else if (numBitsToClear <= 32) {
    nilf(dst, Operand(static_cast<uint32_t>(hexMask)));
  } else if (numBitsToClear <= 64) {
    nilf(dst, Operand(static_cast<intptr_t>(0)));
    nihf(dst, Operand(hexMask >> 32));
  }
}

void MacroAssembler::Popcnt32(Register dst, Register src) {
  DCHECK(src != r0);
  DCHECK(dst != r0);

  popcnt(dst, src);
  ShiftRightU32(r0, dst, Operand(16));
  ar(dst, r0);
  ShiftRightU32(r0, dst, Operand(8));
  ar(dst, r0);
  llgcr(dst, dst);
}

void MacroAssembler::Popcnt64(Register dst, Register src) {
  DCHECK(src != r0);
  DCHECK(dst != r0);

  popcnt(dst, src);
  ShiftRightU64(r0, dst, Operand(32));
  AddS64(dst, r0);
  ShiftRightU64(r0, dst, Operand(16));
  AddS64(dst, r0);
  ShiftRightU64(r0, dst, Operand(8));
  AddS64(dst, r0);
  LoadU8(dst, dst);
}

void MacroAssembler::SwapP(Register src, Register dst, Register scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  mov(scratch, src);
  mov(src, dst);
  mov(dst, scratch);
}

void MacroAssembler::SwapP(Register src, MemOperand dst, Register scratch) {
  if (dst.rx() != r0) DCHECK(!AreAliased(src, dst.rx(), scratch));
  if (dst.rb() != r0) DCHECK(!AreAliased(src, dst.rb(), scratch));
  DCHECK(!AreAliased(src, scratch));
  mov(scratch, src);
  LoadU64(src, dst);
  StoreU64(scratch, dst);
}

void MacroAssembler::SwapP(MemOperand src, MemOperand dst, Register scratch_0,
                           Register scratch_1) {
  if (src.rx() != r0) DCHECK(!AreAliased(src.rx(), scratch_0, scratch_1));
  if (src.rb() != r0) DCHECK(!AreAliased(src.rb(), scratch_0, scratch_1));
  if (dst.rx() != r0) DCHECK(!AreAliased(dst.rx(), scratch_0, scratch_1));
  if (dst.rb() != r0) DCHECK(!AreAliased(dst.rb(), scratch_0, scratch_1));
  DCHECK(!AreAliased(scratch_0, scratch_1));
  LoadU64(scratch_0, src);
  LoadU64(scratch_1, dst);
  StoreU64(scratch_0, dst);
  StoreU64(scratch_1, src);
}

void MacroAssembler::SwapFloat32(DoubleRegister src, DoubleRegister dst,
                                 DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  ldr(scratch, src);
  ldr(src, dst);
  ldr(dst, scratch);
}

void MacroAssembler::SwapFloat32(DoubleRegister src, MemOperand dst,
                                 DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  ldr(scratch, src);
  LoadF32(src, dst);
  StoreF32(scratch, dst);
}

void MacroAssembler::SwapFloat32(MemOperand src, MemOperand dst,
                                 DoubleRegister scratch) {
  // push d0, to be used as scratch
  lay(sp, MemOperand(sp, -kDoubleSize));
  StoreF64(d0, MemOperand(sp));
  LoadF32(scratch, src);
  LoadF32(d0, dst);
  StoreF32(scratch, dst);
  StoreF32(d0, src);
  // restore d0
  LoadF64(d0, MemOperand(sp));
  lay(sp, MemOperand(sp, kDoubleSize));
}

void MacroAssembler::SwapDouble(DoubleRegister src, DoubleRegister dst,
                                DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  ldr(scratch, src);
  ldr(src, dst);
  ldr(dst, scratch);
}

void MacroAssembler::SwapDouble(DoubleRegister src, MemOperand dst,
                                DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  ldr(scratch, src);
  LoadF64(src, dst);
  StoreF64(scratch, dst);
}

void MacroAssembler::SwapDouble(MemOperand src, MemOperand dst,
                                DoubleRegister scratch) {
  // push d0, to be used as scratch
  lay(sp, MemOperand(sp, -kDoubleSize));
  StoreF64(d0, MemOperand(sp));
  LoadF64(scratch, src);
  LoadF64(d0, dst);
  StoreF64(scratch, dst);
  StoreF64(d0, src);
  // restore d0
  LoadF64(d0, MemOperand(sp));
  lay(sp, MemOperand(sp, kDoubleSize));
}

void MacroAssembler::SwapSimd128(Simd128Register src, Simd128Register dst,
                                 Simd128Register scratch) {
  if (src == dst) return;
  vlr(scratch, src, Condition(0), Condition(0), Condition(0));
  vlr(src, dst, Condition(0), Condition(0), Condition(0));
  vlr(dst, scratch, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::SwapSimd128(Simd128Register src, MemOperand dst,
                                 Simd128Register scratch) {
  DCHECK(!AreAliased(src, scratch));
  vlr(scratch, src, Condition(0), Condition(0), Condition(0));
  LoadV128(src, dst, ip);
  StoreV128(scratch, dst, ip);
}

void MacroAssembler::SwapSimd128(MemOperand src, MemOperand dst,
                                 Simd128Register scratch) {
  // push d0, to be used as scratch
  lay(sp, MemOperand(sp, -kSimd128Size));
  StoreV128(d0, MemOperand(sp), ip);
  LoadV128(scratch, src, ip);
  LoadV128(d0, dst, ip);
  StoreV128(scratch, dst, ip);
  StoreV128(d0, src, ip);
  // restore d0
  LoadV128(d0, MemOperand(sp), ip);
  lay(sp, MemOperand(sp, kSimd128Size));
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  larl(dst, Operand(-pc_offset() / 2));
}

void MacroAssembler::LoadPC(Register dst) {
  Label current_pc;
  larl(dst, &current_pc);
  bind(&current_pc);
}

void MacroAssembler::JumpIfEqual(Register x, int32_t y, Label* dest) {
  CmpS32(x, Operand(y));
  beq(dest);
}

void MacroAssembler::JumpIfLessThan(Register x, int32_t y, Label* dest) {
  CmpS32(x, Operand(y));
  blt(dest);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  static_assert(kSystemPointerSize == 8);
  static_assert(kSmiTagSize == 1);
  static_assert(kSmiTag == 0);
  // The builtin_index register contains the builtin index as a Smi.
  if (SmiValuesAre32Bits()) {
    ShiftRightS64(target, builtin_index,
                  Operand(kSmiShift - kSystemPointerSizeLog2));
  } else {
    DCHECK(SmiValuesAre31Bits());
    ShiftLeftU64(target, builtin_index,
                 Operand(kSystemPointerSizeLog2 - kSmiShift));
  }
  LoadU64(target, MemOperand(kRootRegister, target,
                             IsolateData::builtin_entry_table_offset()));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  ASM_CODE_COMMENT(this);
  LoadU64(destination, EntryFromBuiltinAsOperand(builtin));
}

MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  LoadU64(destination,
          FieldMemOperand(code_object, Code::kInstructionStartOffset));
}

void MacroAssembler::CallCodeObject(Register code_object) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  DCHECK_WITH_MSG(!V8_ENABLE_LEAPTIERING_BOOL,
                  "argument_count is only used with Leaptiering");
  Register code = kJavaScriptCallCodeStartRegister;
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(code);
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
  Register code = kJavaScriptCallCodeStartRegister;
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, jump_mode);
}

#if V8_OS_ZOS
// Helper for CallApiFunctionAndReturn().
void MacroAssembler::zosStoreReturnAddressAndCall(Register target,
                                                  Register scratch) {
  DCHECK(target == r3 || target == r4);
  // Shuffle the arguments from Linux arg register to XPLINK arg regs
  mov(r1, r2);
  if (target == r3) {
    mov(r2, r3);
  } else {
    mov(r2, r3);
    mov(r3, r4);
  }

  // Update System Stack Pointer with the appropriate XPLINK stack bias.
  lay(r4, MemOperand(sp, -kStackPointerBias));

  // Preserve r7 by placing into callee-saved register r13
  mov(r13, r7);

  // Load function pointer from slot 1 of fn desc.
  LoadU64(ip, MemOperand(scratch, kSystemPointerSize));
  // Load environment from slot 0 of fn desc.
  LoadU64(r5, MemOperand(scratch));

  StoreReturnAddressAndCall(ip);

  // Restore r7 from r13
  mov(r7, r13);
}
#endif  // V8_OS_ZOS

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

#if V8_OS_ZOS
  Register ra = r7;
#else
  Register ra = r14;
#endif
  Label return_label;
  larl(ra, &return_label);  // Generate the return addr of call later.
#if V8_OS_ZOS
  // Mimic the XPLINK expected no-op (2-byte) instruction at the return point.
  // When the C call returns, the 2 bytes are skipped and then the proper
  // instruction is executed.
  lay(ra, MemOperand(ra, -2));
#endif
  StoreU64(ra, MemOperand(sp, kStackFrameRASlot * kSystemPointerSize));

  // zLinux ABI requires caller's frame to have sufficient space for callee
  // preserved regsiter save area.
  b(target);
  bind(&return_label);
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized(Register scratch) {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadTaggedField(scratch,
                  MemOperand(kJavaScriptCallCodeStartRegister, offset));
  TestCodeIsMarkedForDeoptimization(scratch, scratch);
  Jump(BUILTIN_CODE(isolate(), CompileLazyDeoptimizedCode),
       RelocInfo::CODE_TARGET, ne);
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  LoadU64(ip, MemOperand(kRootRegister,
                         IsolateData::BuiltinEntrySlotOffset(target)));
  Call(ip);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::CountLeadingZerosU32(Register dst, Register src,
                                          Register scratch_pair) {
  llgfr(dst, src);
  flogr(scratch_pair,
        dst);  // will modify a register pair scratch and scratch + 1
  AddS32(dst, scratch_pair, Operand(-32));
}

void MacroAssembler::CountLeadingZerosU64(Register dst, Register src,
                                          Register scratch_pair) {
  flogr(scratch_pair,
        src);  // will modify a register pair scratch and scratch + 1
  mov(dst, scratch_pair);
}

void MacroAssembler::CountTrailingZerosU32(Register dst, Register src,
                                           Register scratch_pair) {
  Register scratch0 = scratch_pair;
  Register scratch1 = Register::from_code(scratch_pair.code() + 1);
  DCHECK(!AreAliased(dst, scratch0, scratch1));
  DCHECK(!AreAliased(src, scratch0, scratch1));

  Label done;
  // Check if src is all zeros.
  ltr(scratch1, src);
  mov(dst, Operand(32));
  beq(&done);
  llgfr(scratch1, scratch1);
  lcgr(scratch0, scratch1);
  ngr(scratch1, scratch0);
  flogr(scratch0, scratch1);
  mov(dst, Operand(63));
  SubS64(dst, scratch0);
  bind(&done);
}

void MacroAssembler::CountTrailingZerosU64(Register dst, Register src,
                                           Register scratch_pair) {
  Register scratch0 = scratch_pair;
  Register scratch1 = Register::from_code(scratch_pair.code() + 1);
  DCHECK(!AreAliased(dst, scratch0, scratch1));
  DCHECK(!AreAliased(src, scratch0, scratch1));

  Label done;
  // Check if src is all zeros.
  ltgr(scratch1, src);
  mov(dst, Operand(64));
  beq(&done);
  lcgr(scratch0, scratch1);
  ngr(scratch0, scratch1);
  flogr(scratch0, scratch0);
  mov(dst, Operand(63));
  SubS64(dst, scratch0);
  bind(&done);
}

void MacroAssembler::AtomicCmpExchangeHelper(Register addr, Register output,
                                             Register old_value,
                                             Register new_value, int start,
                                             int end, int shift_amount,
                                             int offset, Register temp0,
                                             Register temp1) {
  LoadU32(temp0, MemOperand(addr, offset));
  llgfr(temp1, temp0);
  RotateInsertSelectBits(temp0, old_value, Operand(start), Operand(end),
                         Operand(shift_amount), false);
  RotateInsertSelectBits(temp1, new_value, Operand(start), Operand(end),
                         Operand(shift_amount), false);
  CmpAndSwap(temp0, temp1, MemOperand(addr, offset));
  RotateInsertSelectBits(output, temp0, Operand(start + shift_amount),
                         Operand(end + shift_amount),
                         Operand(64 - shift_amount), true);
}

void MacroAssembler::AtomicCmpExchangeU8(Register addr, Register output,
                                         Register old_value, Register new_value,
                                         Register temp0, Register temp1) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_COMP_EXCHANGE_BYTE(i)                                        \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 8 * idx;                                     \
    constexpr int end = start + 7;                                          \
    constexpr int shift_amount = (3 - idx) * 8;                             \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx, temp0, temp1);              \
  }
#else
#define ATOMIC_COMP_EXCHANGE_BYTE(i)                                        \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 8 * (3 - idx);                               \
    constexpr int end = start + 7;                                          \
    constexpr int shift_amount = idx * 8;                                   \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx, temp0, temp1);              \
  }
#endif

  Label one, two, three, done;
  tmll(addr, Operand(3));
  b(Condition(1), &three);
  b(Condition(2), &two);
  b(Condition(4), &one);
  /* ending with 0b00 */
  ATOMIC_COMP_EXCHANGE_BYTE(0);
  b(&done);
  /* ending with 0b01 */
  bind(&one);
  ATOMIC_COMP_EXCHANGE_BYTE(1);
  b(&done);
  /* ending with 0b10 */
  bind(&two);
  ATOMIC_COMP_EXCHANGE_BYTE(2);
  b(&done);
  /* ending with 0b11 */
  bind(&three);
  ATOMIC_COMP_EXCHANGE_BYTE(3);
  bind(&done);
}

void MacroAssembler::AtomicCmpExchangeU16(Register addr, Register output,
                                          Register old_value,
                                          Register new_value, Register temp0,
                                          Register temp1) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_COMP_EXCHANGE_HALFWORD(i)                                    \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 16 * idx;                                    \
    constexpr int end = start + 15;                                         \
    constexpr int shift_amount = (1 - idx) * 16;                            \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx * 2, temp0, temp1);          \
  }
#else
#define ATOMIC_COMP_EXCHANGE_HALFWORD(i)                                    \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 16 * (1 - idx);                              \
    constexpr int end = start + 15;                                         \
    constexpr int shift_amount = idx * 16;                                  \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx * 2, temp0, temp1);          \
  }
#endif

  Label two, done;
  tmll(addr, Operand(3));
  b(Condition(2), &two);
  ATOMIC_COMP_EXCHANGE_HALFWORD(0);
  b(&done);
  bind(&two);
  ATOMIC_COMP_EXCHANGE_HALFWORD(1);
  bind(&done);
}

void MacroAssembler::AtomicExchangeHelper(Register addr, Register value,
                                          Register output, int start, int end,
                                          int shift_amount, int offset,
                                          Register scratch) {
  Label do_cs;
  LoadU32(output, MemOperand(addr, offset));
  bind(&do_cs);
  llgfr(scratch, output);
  RotateInsertSelectBits(scratch, value, Operand(start), Operand(end),
                         Operand(shift_amount), false);
  csy(output, scratch, MemOperand(addr, offset));
  bne(&do_cs, Label::kNear);
  srl(output, Operand(shift_amount));
}

void MacroAssembler::AtomicExchangeU8(Register addr, Register value,
                                      Register output, Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_EXCHANGE_BYTE(i)                                               \
  {                                                                           \
    constexpr int idx = (i);                                                  \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");              \
    constexpr int start = 32 + 8 * idx;                                       \
    constexpr int end = start + 7;                                            \
    constexpr int shift_amount = (3 - idx) * 8;                               \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, -idx, \
                         scratch);                                            \
  }
#else
#define ATOMIC_EXCHANGE_BYTE(i)                                               \
  {                                                                           \
    constexpr int idx = (i);                                                  \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");              \
    constexpr int start = 32 + 8 * (3 - idx);                                 \
    constexpr int end = start + 7;                                            \
    constexpr int shift_amount = idx * 8;                                     \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, -idx, \
                         scratch);                                            \
  }
#endif
  Label three, two, one, done;
  tmll(addr, Operand(3));
  b(Condition(1), &three);
  b(Condition(2), &two);
  b(Condition(4), &one);

  // end with 0b00
  ATOMIC_EXCHANGE_BYTE(0);
  b(&done);

  // ending with 0b01
  bind(&one);
  ATOMIC_EXCHANGE_BYTE(1);
  b(&done);

  // ending with 0b10
  bind(&two);
  ATOMIC_EXCHANGE_BYTE(2);
  b(&done);

  // ending with 0b11
  bind(&three);
  ATOMIC_EXCHANGE_BYTE(3);

  bind(&done);
}

void MacroAssembler::AtomicExchangeU16(Register addr, Register value,
                                       Register output, Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_EXCHANGE_HALFWORD(i)                                     \
  {                                                                     \
    constexpr int idx = (i);                                            \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");        \
    constexpr int start = 32 + 16 * idx;                                \
    constexpr int end = start + 15;                                     \
    constexpr int shift_amount = (1 - idx) * 16;                        \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, \
                         -idx * 2, scratch);                            \
  }
#else
#define ATOMIC_EXCHANGE_HALFWORD(i)                                     \
  {                                                                     \
    constexpr int idx = (i);                                            \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");        \
    constexpr int start = 32 + 16 * (1 - idx);                          \
    constexpr int end = start + 15;                                     \
    constexpr int shift_amount = idx * 16;                              \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, \
                         -idx * 2, scratch);                            \
  }
#endif
  Label two, done;
  tmll(addr, Operand(3));
  b(Condition(2), &two);

  // end with 0b00
  ATOMIC_EXCHANGE_HALFWORD(0);
  b(&done);

  // ending with 0b10
  bind(&two);
  ATOMIC_EXCHANGE_HALFWORD(1);

  bind(&done);
}

// Simd Support.
void MacroAssembler::F64x2Splat(Simd128Register dst, Simd128Register src) {
  vrep(dst, src, Operand(0), Condition(3));
}

void MacroAssembler::F32x4Splat(Simd128Register dst, Simd128Register src) {
  vrep(dst, src, Operand(0), Condition(2));
}

void MacroAssembler::I64x2Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(3));
  vrep(dst, dst, Operand(0), Condition(3));
}

void MacroAssembler::I32x4Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(2));
  vrep(dst, dst, Operand(0), Condition(2));
}

void MacroAssembler::I16x8Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(1));
  vrep(dst, dst, Operand(0), Condition(1));
}

void MacroAssembler::I8x16Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(0));
  vrep(dst, dst, Operand(0), Condition(0));
}

void MacroAssembler::F64x2ExtractLane(DoubleRegister dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vrep(dst, src, Operand(1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::F32x4ExtractLane(DoubleRegister dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vrep(dst, src, Operand(3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I64x2ExtractLane(Register dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::I32x4ExtractLane(Register dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I16x8ExtractLaneU(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 7 - imm_lane_idx), Condition(1));
}

void MacroAssembler::I16x8ExtractLaneS(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register scratch) {
  vlgv(scratch, src, MemOperand(r0, 7 - imm_lane_idx), Condition(1));
  lghr(dst, scratch);
}

void MacroAssembler::I8x16ExtractLaneU(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 15 - imm_lane_idx), Condition(0));
}

void MacroAssembler::I8x16ExtractLaneS(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register scratch) {
  vlgv(scratch, src, MemOperand(r0, 15 - imm_lane_idx), Condition(0));
  lgbr(dst, scratch);
}

void MacroAssembler::F64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      DoubleRegister src2, uint8_t imm_lane_idx,
                                      Register scratch) {
  vlgv(scratch, src2, MemOperand(r0, 0), Condition(3));
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, scratch, MemOperand(r0, 1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::F32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      DoubleRegister src2, uint8_t imm_lane_idx,
                                      Register scratch) {
  vlgv(scratch, src2, MemOperand(r0, 0), Condition(2));
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, scratch, MemOperand(r0, 3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::I32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I16x8ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 7 - imm_lane_idx), Condition(1));
}

void MacroAssembler::I8x16ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 15 - imm_lane_idx), Condition(0));
}

void MacroAssembler::S128Not(Simd128Register dst, Simd128Register src) {
  vno(dst, src, src, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::S128Zero(Simd128Register dst, Simd128Register src) {
  vx(dst, src, src, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::S128AllOnes(Simd128Register dst, Simd128Register src) {
  vceq(dst, src, src, Condition(0), Condition(3));
}

void MacroAssembler::S128Select(Simd128Register dst, Simd128Register src1,
                                Simd128Register src2, Simd128Register mask) {
  vsel(dst, src1, src2, mask, Condition(0), Condition(0));
}

#define SIMD_UNOP_LIST_VRR_A(V)             \
  V(F64x2Abs, vfpso, 2, 0, 3)               \
  V(F64x2Neg, vfpso, 0, 0, 3)               \
  V(F64x2Sqrt, vfsq, 0, 0, 3)               \
  V(F64x2Ceil, vfi, 6, 0, 3)                \
  V(F64x2Floor, vfi, 7, 0, 3)               \
  V(F64x2Trunc, vfi, 5, 0, 3)               \
  V(F64x2NearestInt, vfi, 4, 0, 3)          \
  V(F32x4Abs, vfpso, 2, 0, 2)               \
  V(F32x4Neg, vfpso, 0, 0, 2)               \
  V(F32x4Sqrt, vfsq, 0, 0, 2)               \
  V(F32x4Ceil, vfi, 6, 0, 2)                \
  V(F32x4Floor, vfi, 7, 0, 2)               \
  V(F32x4Trunc, vfi, 5, 0, 2)               \
  V(F32x4NearestInt, vfi, 4, 0, 2)          \
  V(I64x2Abs, vlp, 0, 0, 3)                 \
  V(I64x2Neg, vlc, 0, 0, 3)                 \
  V(I64x2SConvertI32x4Low, vupl, 0, 0, 2)   \
  V(I64x2SConvertI32x4High, vuph, 0, 0, 2)  \
  V(I64x2UConvertI32x4Low, vupll, 0, 0, 2)  \
  V(I64x2UConvertI32x4High, vuplh, 0, 0, 2) \
  V(I32x4Abs, vlp, 0, 0, 2)                 \
  V(I32x4Neg, vlc, 0, 0, 2)                 \
  V(I32x4SConvertI16x8Low, vupl, 0, 0, 1)   \
  V(I32x4SConvertI16x8High, vuph, 0, 0, 1)  \
  V(I32x4UConvertI16x8Low, vupll, 0, 0, 1)  \
  V(I32x4UConvertI16x8High, vuplh, 0, 0, 1) \
  V(I16x8Abs, vlp, 0, 0, 1)                 \
  V(I16x8Neg, vlc, 0, 0, 1)                 \
  V(I16x8SConvertI8x16Low, vupl, 0, 0, 0)   \
  V(I16x8SConvertI8x16High, vuph, 0, 0, 0)  \
  V(I16x8UConvertI8x16Low, vupll, 0, 0, 0)  \
  V(I16x8UConvertI8x16High, vuplh, 0, 0, 0) \
  V(I8x16Abs, vlp, 0, 0, 0)                 \
  V(I8x16Neg, vlc, 0, 0, 0)                 \
  V(I8x16Popcnt, vpopct, 0, 0, 0)

#define EMIT_SIMD_UNOP_VRR_A(name, op, c1, c2, c3)                      \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src) { \
    op(dst, src, Condition(c1), Condition(c2), Condition(c3));          \
  }
SIMD_UNOP_LIST_VRR_A(EMIT_SIMD_UNOP_VRR_A)
#undef EMIT_SIMD_UNOP_VRR_A
#undef SIMD_UNOP_LIST_VRR_A

#define SIMD_BINOP_LIST_VRR_B(V) \
  V(I64x2Eq, vceq, 0, 3)         \
  V(I64x2GtS, vch, 0, 3)         \
  V(I32x4Eq, vceq, 0, 2)         \
  V(I32x4GtS, vch, 0, 2)         \
  V(I32x4GtU, vchl, 0, 2)        \
  V(I16x8Eq, vceq, 0, 1)         \
  V(I16x8GtS, vch, 0, 1)         \
  V(I16x8GtU, vchl, 0, 1)        \
  V(I8x16Eq, vceq, 0, 0)         \
  V(I8x16GtS, vch, 0, 0)         \
  V(I8x16GtU, vchl, 0, 0)

#define EMIT_SIMD_BINOP_VRR_B(name, op, c1, c2)                        \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            Simd128Register src2) {                    \
    op(dst, src1, src2, Condition(c1), Condition(c2));                 \
  }
SIMD_BINOP_LIST_VRR_B(EMIT_SIMD_BINOP_VRR_B)
#undef EMIT_SIMD_BINOP_VRR_B
#undef SIMD_BINOP_LIST_VRR_B

#define SIMD_BINOP_LIST_VRR_C(V)           \
  V(F64x2Add, vfa, 0, 0, 3)                \
  V(F64x2Sub, vfs, 0, 0, 3)                \
  V(F64x2Mul, vfm, 0, 0, 3)                \
  V(F64x2Div, vfd, 0, 0, 3)                \
  V(F64x2Min, vfmin, 1, 0, 3)              \
  V(F64x2Max, vfmax, 1, 0, 3)              \
  V(F64x2Eq, vfce, 0, 0, 3)                \
  V(F64x2Pmin, vfmin, 3, 0, 3)             \
  V(F64x2Pmax, vfmax, 3, 0, 3)             \
  V(F32x4Add, vfa, 0, 0, 2)                \
  V(F32x4Sub, vfs, 0, 0, 2)                \
  V(F32x4Mul, vfm, 0, 0, 2)                \
  V(F32x4Div, vfd, 0, 0, 2)                \
  V(F32x4Min, vfmin, 1, 0, 2)              \
  V(F32x4Max, vfmax, 1, 0, 2)              \
  V(F32x4Eq, vfce, 0, 0, 2)                \
  V(F32x4Pmin, vfmin, 3, 0, 2)             \
  V(F32x4Pmax, vfmax, 3, 0, 2)             \
  V(I64x2Add, va, 0, 0, 3)                 \
  V(I64x2Sub, vs, 0, 0, 3)                 \
  V(I32x4Add, va, 0, 0, 2)                 \
  V(I32x4Sub, vs, 0, 0, 2)                 \
  V(I32x4Mul, vml, 0, 0, 2)                \
  V(I32x4MinS, vmn, 0, 0, 2)               \
  V(I32x4MinU, vmnl, 0, 0, 2)              \
  V(I32x4MaxS, vmx, 0, 0, 2)               \
  V(I32x4MaxU, vmxl, 0, 0, 2)              \
  V(I16x8Add, va, 0, 0, 1)                 \
  V(I16x8Sub, vs, 0, 0, 1)                 \
  V(I16x8Mul, vml, 0, 0, 1)                \
  V(I16x8MinS, vmn, 0, 0, 1)               \
  V(I16x8MinU, vmnl, 0, 0, 1)              \
  V(I16x8MaxS, vmx, 0, 0, 1)               \
  V(I16x8MaxU, vmxl, 0, 0, 1)              \
  V(I16x8RoundingAverageU, vavgl, 0, 0, 1) \
  V(I8x16Add, va, 0, 0, 0)                 \
  V(I8x16Sub, vs, 0, 0, 0)                 \
  V(I8x16MinS, vmn, 0, 0, 0)               \
  V(I8x16MinU, vmnl, 0, 0, 0)              \
  V(I8x16MaxS, vmx, 0, 0, 0)               \
  V(I8x16MaxU, vmxl, 0, 0, 0)              \
  V(I8x16RoundingAverageU, vavgl, 0, 0, 0) \
  V(S128And, vn, 0, 0, 0)                  \
  V(S128Or, vo, 0, 0, 0)                   \
  V(S128Xor, vx, 0, 0, 0)                  \
  V(S128AndNot, vnc, 0, 0, 0)

#define EMIT_SIMD_BINOP_VRR_C(name, op, c1, c2, c3)                    \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            Simd128Register src2) {                    \
    op(dst, src1, src2, Condition(c1), Condition(c2), Condition(c3));  \
  }
SIMD_BINOP_LIST_VRR_C(EMIT_SIMD_BINOP_VRR_C)
#undef EMIT_SIMD_BINOP_VRR_C
#undef SIMD_BINOP_LIST_VRR_C

#define SIMD_SHIFT_LIST(V) \
  V(I64x2Shl, veslv, 3)    \
  V(I64x2ShrS, vesrav, 3)  \
  V(I64x2ShrU, vesrlv, 3)  \
  V(I32x4Shl, veslv, 2)    \
  V(I32x4ShrS, vesrav, 2)  \
  V(I32x4ShrU, vesrlv, 2)  \
  V(I16x8Shl, veslv, 1)    \
  V(I16x8ShrS, vesrav, 1)  \
  V(I16x8ShrU, vesrlv, 1)  \
  V(I8x16Shl, veslv, 0)    \
  V(I8x16ShrS, vesrav, 0)  \
  V(I8x16ShrU, vesrlv, 0)

#define EMIT_SIMD_SHIFT(name, op, c1)                                  \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            Register src2, Simd128Register scratch) {  \
    vlvg(scratch, src2, MemOperand(r0, 0), Condition(c1));             \
    vrep(scratch, scratch, Operand(0), Condition(c1));                 \
    op(dst, src1, scratch, Condition(0), Condition(0), Condition(c1)); \
  }                                                                    \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            const Operand& src2, Register scratch1,    \
                            Simd128Register scratch2) {                \
    mov(scratch1, src2);                                               \
    name(dst, src1, scratch1, scratch2);                               \
  }
SIMD_SHIFT_LIST(EMIT_SIMD_SHIFT)
#undef EMIT_SIMD_SHIFT
#undef SIMD_SHIFT_LIST

#define SIMD_EXT_MUL_LIST(V)                    \
  V(I64x2ExtMulLowI32x4S, vme, vmo, vmrl, 2)    \
  V(I64x2ExtMulHighI32x4S, vme, vmo, vmrh, 2)   \
  V(I64x2ExtMulLowI32x4U, vmle, vmlo, vmrl, 2)  \
  V(I64x2ExtMulHighI32x4U, vmle, vmlo, vmrh, 2) \
  V(I32x4ExtMulLowI16x8S, vme, vmo, vmrl, 1)    \
  V(I32x4ExtMulHighI16x8S, vme, vmo, vmrh, 1)   \
  V(I32x4ExtMulLowI16x8U, vmle, vmlo, vmrl, 1)  \
  V(I32x4ExtMulHighI16x8U, vmle, vmlo, vmrh, 1) \
  V(I16x8ExtMulLowI8x16S, vme, vmo, vmrl, 0)    \
  V(I16x8ExtMulHighI8x16S, vme, vmo, vmrh, 0)   \
  V(I16x8ExtMulLowI8x16U, vmle, vmlo, vmrl, 0)  \
  V(I16x8ExtMulHighI8x16U, vmle, vmlo, vmrh, 0)

#define EMIT_SIMD_EXT_MUL(name, mul_even, mul_odd, merge, mode)                \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1,         \
                            Simd128Register src2, Simd128Register scratch) {   \
    mul_even(scratch, src1, src2, Condition(0), Condition(0),                  \
             Condition(mode));                                                 \
    mul_odd(dst, src1, src2, Condition(0), Condition(0), Condition(mode));     \
    merge(dst, scratch, dst, Condition(0), Condition(0), Condition(mode + 1)); \
  }
SIMD_EXT_MUL_LIST(EMIT_SIMD_EXT_MUL)
#undef EMIT_SIMD_EXT_MUL
#undef SIMD_EXT_MUL_LIST

#define SIMD_ALL_TRUE_LIST(V) \
  V(I64x2AllTrue, 3)          \
  V(I32x4AllTrue, 2)          \
  V(I16x8AllTrue, 1)          \
  V(I8x16AllTrue, 0)

#define EMIT_SIMD_ALL_TRUE(name, mode)                                     \
  void MacroAssembler::name(Register dst, Simd128Register src,             \
                            Register scratch1, Simd128Register scratch2) { \
    mov(scratch1, Operand(1));                                             \
    xgr(dst, dst);                                                         \
    vx(scratch2, scratch2, scratch2, Condition(0), Condition(0),           \
       Condition(2));                                                      \
    vceq(scratch2, src, scratch2, Condition(0), Condition(mode));          \
    vtm(scratch2, scratch2, Condition(0), Condition(0), Condition(0));     \
    locgr(Condition(8), dst, scratch1);                                    \
  }
SIMD_ALL_TRUE_LIST(EMIT_SIMD_ALL_TRUE)
#undef EMIT_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_QFM_LIST(V) \
  V(F64x2Qfma, vfma, 3)  \
  V(F64x2Qfms, vfnms, 3) \
  V(F32x4Qfma, vfma, 2)  \
  V(F32x4Qfms, vfnms, 2)

#define EMIT_SIMD_QFM(name, op, c1)                                       \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1,    \
                            Simd128Register src2, Simd128Register src3) { \
    op(dst, src1, src2, src3, Condition(c1), Condition(0));               \
  }
SIMD_QFM_LIST(EMIT_SIMD_QFM)
#undef EMIT_SIMD_QFM
#undef SIMD_QFM_LIST

void MacroAssembler::I64x2Mul(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Register scratch1,
                              Register scratch2, Register scratch3) {
  Register scratch_1 = scratch1;
  Register scratch_2 = scratch2;
  for (int i = 0; i < 2; i++) {
    vlgv(scratch_1, src1, MemOperand(r0, i), Condition(3));
    vlgv(scratch_2, src2, MemOperand(r0, i), Condition(3));
    MulS64(scratch_1, scratch_2);
    scratch_1 = scratch2;
    scratch_2 = scratch3;
  }
  vlvgp(dst, scratch1, scratch2);
}

void MacroAssembler::F64x2Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfce(dst, src1, src2, Condition(0), Condition(0), Condition(3));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::F64x2Lt(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfch(dst, src2, src1, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::F64x2Le(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfche(dst, src2, src1, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::F32x4Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfce(dst, src1, src2, Condition(0), Condition(0), Condition(2));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::F32x4Lt(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfch(dst, src2, src1, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::F32x4Le(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfche(dst, src2, src1, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I64x2Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vceq(dst, src1, src2, Condition(0), Condition(3));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::I64x2GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2) {
  // Compute !(B > A) which is equal to A >= B.
  vch(dst, src2, src1, Condition(0), Condition(3));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::I32x4Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vceq(dst, src1, src2, Condition(0), Condition(2));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I32x4GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2) {
  // Compute !(B > A) which is equal to A >= B.
  vch(dst, src2, src1, Condition(0), Condition(2));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I32x4GeU(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vceq(scratch, src1, src2, Condition(0), Condition(2));
  vchl(dst, src1, src2, Condition(0), Condition(2));
  vo(dst, dst, scratch, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I16x8Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vceq(dst, src1, src2, Condition(0), Condition(1));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(1));
}

void MacroAssembler::I16x8GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2) {
  // Compute !(B > A) which is equal to A >= B.
  vch(dst, src2, src1, Condition(0), Condition(1));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(1));
}

void MacroAssembler::I16x8GeU(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vceq(scratch, src1, src2, Condition(0), Condition(1));
  vchl(dst, src1, src2, Condition(0), Condition(1));
  vo(dst, dst, scratch, Condition(0), Condition(0), Condition(1));
}

void MacroAssembler::I8x16Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vceq(dst, src1, src2, Condition(0), Condition(0));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::I8x16GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2) {
  // Compute !(B > A) which is equal to A >= B.
  vch(dst, src2, src1, Condition(0), Condition(0));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::I8x16GeU(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vceq(scratch, src1, src2, Condition(0), Condition(0));
  vchl(dst, src1, src2, Condition(0), Condition(0));
  vo(dst, dst, scratch, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::I64x2BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Simd128Register scratch2) {
  mov(scratch1, Operand(0x8080808080800040));
  vlvg(scratch2, scratch1, MemOperand(r0, 1), Condition(3));
  vbperm(scratch2, src, scratch2, Condition(0), Condition(0), Condition(0));
  vlgv(dst, scratch2, MemOperand(r0, 7), Condition(0));
}

void MacroAssembler::I32x4BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Simd128Register scratch2) {
  mov(scratch1, Operand(0x8080808000204060));
  vlvg(scratch2, scratch1, MemOperand(r0, 1), Condition(3));
  vbperm(scratch2, src, scratch2, Condition(0), Condition(0), Condition(0));
  vlgv(dst, scratch2, MemOperand(r0, 7), Condition(0));
}

void MacroAssembler::I16x8BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Simd128Register scratch2) {
  mov(scratch1, Operand(0x10203040506070));
  vlvg(scratch2, scratch1, MemOperand(r0, 1), Condition(3));
  vbperm(scratch2, src, scratch2, Condition(0), Condition(0), Condition(0));
  vlgv(dst, scratch2, MemOperand(r0, 7), Condition(0));
}

void MacroAssembler::F64x2ConvertLowI32x4S(Simd128Register dst,
                                           Simd128Register src) {
  vupl(dst, src, Condition(0), Condition(0), Condition(2));
  vcdg(dst, dst, Condition(4), Condition(0), Condition(3));
}

void MacroAssembler::F64x2ConvertLowI32x4U(Simd128Register dst,
                                           Simd128Register src) {
  vupll(dst, src, Condition(0), Condition(0), Condition(2));
  vcdlg(dst, dst, Condition(4), Condition(0), Condition(3));
}

void MacroAssembler::I8x16BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Register scratch2,
                                  Simd128Register scratch3) {
  mov(scratch1, Operand(0x4048505860687078));
  mov(scratch2, Operand(0x8101820283038));
  vlvgp(scratch3, scratch2, scratch1);
  vbperm(scratch3, src, scratch3, Condition(0), Condition(0), Condition(0));
  vlgv(dst, scratch3, MemOperand(r0, 3), Condition(1));
}

void MacroAssembler::V128AnyTrue(Register dst, Simd128Register src,
                                 Register scratch) {
  mov(dst, Operand(1));
  xgr(scratch, scratch);
  vtm(src, src, Condition(0), Condition(0), Condition(0));
  locgr(Condition(8), dst, scratch);
}

#define CONVERT_FLOAT_TO_INT32(convert, dst, src, scratch1, scratch2) \
  for (int index = 0; index < 4; index++) {                           \
    vlgv(scratch2, src, MemOperand(r0, index), Condition(2));         \
    MovIntToFloat(scratch1, scratch2);                                \
    convert(scratch2, scratch1, kRoundToZero);                        \
    vlvg(dst, scratch2, MemOperand(r0, index), Condition(2));         \
  }
void MacroAssembler::I32x4SConvertF32x4(Simd128Register dst,
                                        Simd128Register src,
                                        Simd128Register scratch1,
                                        Register scratch2) {
  // NaN to 0.
  vfce(scratch1, src, src, Condition(0), Condition(0), Condition(2));
  vn(dst, src, scratch1, Condition(0), Condition(0), Condition(0));
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)) {
    vcgd(dst, dst, Condition(5), Condition(0), Condition(2));
  } else {
    CONVERT_FLOAT_TO_INT32(ConvertFloat32ToInt32, dst, dst, scratch1, scratch2)
  }
}

void MacroAssembler::I32x4UConvertF32x4(Simd128Register dst,
                                        Simd128Register src,
                                        Simd128Register scratch1,
```