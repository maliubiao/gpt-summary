Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/x64/code-generator-x64.cc`. They have also provided some specific instructions:

1. **List the functionalities:** Describe what the code does.
2. **Torque Source:** Check if the filename ends with `.tq`. If it does, it's a Torque source.
3. **JavaScript Relation:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:**  If there's code logic, provide assumed inputs and outputs.
5. **Common Programming Errors:** Give examples of common programming errors related to the code.
6. **Summarize Functionality:** Based on the content, summarize the overall purpose of this specific part of the file.
7. **Part Number:** Acknowledge that this is part 8 of 10.

**Plan:**

1. **Analyze the Code:** Go through each `case` statement in the `switch` block and understand the corresponding x64 assembly instructions being generated. Focus on the overall purpose of each block.
2. **Functionality Listing:** Based on the analysis, create a list of functionalities. This will primarily involve SIMD (Single Instruction, Multiple Data) operations.
3. **Torque Check:**  Examine the filename.
4. **JavaScript Relation:** Determine if any of the operations directly correspond to JavaScript SIMD API calls or have a clear JavaScript equivalent. Provide examples where applicable.
5. **Code Logic Inference:** For specific code blocks with conditional logic or data manipulation (like shuffling, blending), provide example inputs and outputs for the involved registers.
6. **Common Programming Errors:** Think about potential errors developers might make when working with SIMD operations or low-level code generation. This could include incorrect lane indices, data type mismatches, or misunderstanding instruction behavior.
7. **Summarize:**  Synthesize the information to create a concise summary of this part of the code.
8. **Acknowledge Part Number:** Include a statement about this being part 8 of 10.
这是 `v8/src/compiler/backend/x64/code-generator-x64.cc` 文件中的一段代码，它负责为 V8 JavaScript 引擎在 x64 架构上生成机器码。 这段代码具体处理了多种 SIMD (Single Instruction, Multiple Data) 指令以及原子操作的生成。

**功能列举:**

这段代码的主要功能是根据中间表示 (Instruction) 生成对应的 x64 汇编指令。  它涵盖了以下 SIMD 和原子操作：

* **SIMD 数据重排和混洗:**
    * `kX64S8x16Shuffle`: 对 8 位整数的 128 位 SIMD 寄存器进行混洗。
    * `kX64S32x4Shuffle`: 对 32 位整数的 128 位 SIMD 寄存器进行混洗。
    * `kX64S16x8Blend`:  根据掩码混合两个 16 位整数的 128 位 SIMD 寄存器。
    * `kX64S16x8HalfShuffle1/2`:  对 16 位整数的 128 位 SIMD 寄存器进行半字混洗。
    * `kX64S8x16Alignr`:  将两个 128 位 SIMD 寄存器拼接后右移指定位数。
    * `kX64S16x8Dup/kX64S8x16Dup`: 复制 SIMD 寄存器中的某个元素到所有位置。
    * `kX64S64x2UnpackHigh/Low`, `kX64S32x4UnpackHigh/Low`, `kX64S16x8UnpackHigh/Low`, `kX64S8x16UnpackHigh/Low`:  解包 SIMD 寄存器的高位或低位元素。
    * `kX64S16x8UnzipHigh/Low`, `kX64S8x16UnzipHigh/Low`:  交错合并 SIMD 寄存器的高位或低位元素。
    * `kX64S8x16TransposeLow/High`:  转置 SIMD 寄存器的低位或高位字节。
    * `kX64S8x8Reverse/kX64S8x4Reverse/kX64S8x2Reverse`:  反转 SIMD 寄存器中的字节顺序。
    * `kX64Shufps`: 混洗单精度浮点数。
    * `kX64S32x4Rotate`: 循环移位 32 位整数。
    * `kX64S32x4Swizzle`: 调换 32 位整数的位置。

* **SIMD 数据加载:**
    * `kX64S128Load8Splat/kX64S128Load16Splat/kX64S128Load32Splat/kX64S128Load64Splat`: 从内存加载单个元素并复制到整个 SIMD 寄存器。
    * `kX64S128Load8x8S/U`, `kX64S128Load16x4S/U`, `kX64S128Load32x2S/U`: 从内存加载多个元素并进行符号/零扩展。
    * `kX64S256Load8Splat/kX64S256Load16Splat/kX64S256Load32Splat/kX64S256Load64Splat`:  与 128 位版本类似，但操作 256 位 SIMD 寄存器。
    * `kX64S256Load8x16S/U`, `kX64S256Load8x8U`, `kX64S256Load16x8S/U`, `kX64S256Load32x4S/U`:  与 128 位版本类似，但操作 256 位 SIMD 寄存器。
    * `kX64Movdqu256`: 加载或存储 256 位数据。

* **SIMD 数据存储:**
    * `kX64S128Store32Lane/kX64S128Store64Lane`: 将 SIMD 寄存器中的特定通道存储到内存。

* **SIMD 位操作和比较:**
    * `kX64I8x16Popcnt`: 计算 128 位 SIMD 寄存器中每个字节的 popcount (population count，即二进制表示中 1 的个数)。
    * `kX64V128AnyTrue`: 检查 128 位 SIMD 寄存器中是否有任何非零元素。
    * `kX64IAllTrue`: 检查 SIMD 寄存器中的所有元素是否都为真（非零）。

* **SIMD 融合操作:**
    * `kX64Blendvpd/kX64Blendvps`: 根据掩码从两个 SIMD 寄存器中选择元素。
    * `kX64Pblendvb`:  根据字节掩码混合两个 SIMD 寄存器。
    * `kX64I32x8DotI16x16S`:  计算两个 16 位整数向量的点积，并将结果累加到 32 位整数向量。

* **SIMD 类型转换:**
    * `kX64I32x4TruncF64x2UZero`: 将双精度浮点数截断为无符号 32 位整数。
    * `kX64I32x4TruncF32x4U`: 将单精度浮点数截断为无符号 32 位整数。
    * `kX64I32x8TruncF32x8U`: 将单精度浮点数截断为无符号 32 位整数 (256 位)。
    * `kX64Cvttps2dq/kX64Cvttpd2dq`: 将浮点数转换为整数，使用截断舍入。
    * `kX64I16x16SConvertI32x8/kX64I16x16UConvertI32x8`: 将 32 位整数压缩为有符号/无符号 16 位整数。
    * `kX64I8x32SConvertI16x16/kX64I8x32UConvertI16x16`: 将 16 位整数压缩为有符号/无符号 8 位整数。

* **SIMD 扩展乘法:**
    * `kX64I64x4ExtMulI32x4S/U`, `kX64I32x8ExtMulI16x8S/U`, `kX64I16x16ExtMulI8x16S/U`:  将低位元素相乘，并将结果扩展到更大的数据类型。

* **SIMD 常量加载:**
    * `kX64S256Const`: 加载 256 位常量。

* **SIMD 提取和插入:**
    * `kX64ExtractF128`: 从 256 位 SIMD 寄存器中提取 128 位。
    * `kX64InsertI128`: 将 128 位 SIMD 寄存器插入到 256 位 SIMD 寄存器的指定位置。

* **原子操作:**
    * `kAtomicStoreWord8/16/32`, `kX64Word64AtomicStoreWord64`: 原子存储操作。
    * `kAtomicExchangeInt8/Uint8/Int16/Uint16/Word32`, `kX64Word64AtomicExchangeUint64`: 原子交换操作。
    * `kAtomicCompareExchangeInt8/Uint8/Int16/Uint16/Word32`, `kX64Word64AtomicCompareExchangeUint64`: 原子比较并交换操作。
    * `kAtomicAddInt8/Uint8/Int16/Uint16/Word32`, `kX64Word64AtomicAddUint64`: 原子加法操作。
    * `kAtomicSubInt8/Uint8/Int16/Uint16/Word32`, `kX64Word64AtomicSubUint64`: 原子减法操作。
    * `kAtomicAndInt8/Uint8/Int16/Uint16/Word32`, `kX64Word64AtomicAndUint64`: 原子与操作。
    * `kAtomicOrInt8/Uint8/Int16/Uint16/Word32`, `kX64Word64AtomicOrUint64`: 原子或操作。
    * `kAtomicXorInt8/Uint8/Int16/Uint16/Word32`, `kX64Word64AtomicXorUint64`: 原子异或操作。

**Torque 源代码检查:**

`v8/src/compiler/backend/x64/code-generator-x64.cc` 以 `.cc` 结尾，**不是**以 `.tq` 结尾。 因此，它不是一个 V8 Torque 源代码。

**与 JavaScript 功能的关系和示例:**

这段代码生成的 SIMD 指令直接对应于 JavaScript 的 [WebAssembly SIMD](https://developer.mozilla.org/en-US/docs/WebAssembly/SIMD) 功能以及一些 JavaScript 引擎内部的优化。

例如，`kX64S32x4Shuffle` 可以用来实现 WebAssembly 的 `i32x4.shuffle` 指令。

```javascript
// JavaScript (WebAssembly)
const a = i32x4(1, 2, 3, 4);
const b = i32x4(5, 6, 7, 8);
const shuffled = i32x4.shuffle(a, b, 0, 5, 2, 7); // 索引对应 a 和 b 的元素
// shuffled 的结果可能是 i32x4(1, 6, 3, 8)
```

`kAtomicCompareExchangeWord32` 等原子操作则与 JavaScript 的 [SharedArrayBuffer](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer) 和 [Atomics](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Atomics) API 相关。

```javascript
// JavaScript
const sab = new SharedArrayBuffer(4);
const int32Array = new Int32Array(sab);
Atomics.compareExchange(int32Array, 0, 0, 10); // 如果索引 0 的值为 0，则设置为 10
```

**代码逻辑推理和假设输入输出:**

以 `kX64S32x4Shuffle` 为例：

**假设输入:**

* `i.OutputSimd128Register()`:  `xmm0`
* `i.InputSimd128Register(0)`: `xmm1` (假设包含值 [1, 2, 3, 4])
* `i.InputSimd128Register(1)`: `xmm2` (假设包含值 [5, 6, 7, 8])
* `i.InputUint8(2)`:  值为 `0b01'00'11'10` (十进制 230)。 这意味着从 `xmm1` 取索引 2 的元素，从 `xmm1` 取索引 0 的元素，从 `xmm2` 取索引 1 的元素，从 `xmm2` 取索引 0 的元素。
* `i.InputUint8(3)`: 值为 `0b00001111` (十进制 15)。这是一个 blend 掩码。

**输出:**

`xmm0` 将包含混洗和混合后的值。

1. `ASSEMBLE_SIMD_IMM_INSTR(Pshufd, kScratchDoubleReg, 1, shuffle);`  将 `xmm2` 的值根据 `shuffle` 混洗到 `kScratchDoubleReg` (例如 `xmm3`)。 如果 `shuffle` 是 230， 那么 `xmm3` 将包含 [7, 5, 8, 6]。
2. `ASSEMBLE_SIMD_IMM_INSTR(Pshufd, i.OutputSimd128Register(), 0, shuffle);` 将 `xmm1` 的值根据 `shuffle` 混洗到 `xmm0`。 如果 `shuffle` 是 230， 那么 `xmm0` 将包含 [3, 1, 4, 2]。
3. `__ Pblendw(i.OutputSimd128Register(), kScratchDoubleReg, i.InputUint8(3));`  根据掩码 `0b00001111` 混合 `xmm0` 和 `xmm3` 的 16 位字。由于掩码低 8 位全为 1， 高 8 位全为 0， 那么 `xmm0` 的低 8 字节将来自 `xmm3`， 高 8 字节将来自 `xmm0`。最终 `xmm0` 的值取决于具体的字节序，但会是 `xmm0` 和 `xmm3` 中元素的组合。

**用户常见的编程错误:**

* **SIMD 指令操作数类型不匹配:**  例如，将整数 SIMD 寄存器作为浮点 SIMD 指令的输入。
* **混洗或 blend 掩码错误:**  提供了超出范围的索引或者错误的掩码，导致程序行为不符合预期。
* **原子操作的内存对齐问题:**  某些原子操作可能要求操作的内存地址是对齐的。未对齐的访问可能导致崩溃或未定义的行为。
* **多线程环境下的原子操作使用不当:**  未能正确理解原子操作的内存顺序保证，可能导致数据竞争。
* **误解 SIMD 指令的行为:**  例如，不清楚 `pshufd` 指令是如何根据掩码选择元素的。

**归纳功能 (第 8 部分):**

这段代码是 `v8/src/compiler/backend/x64/code-generator-x64.cc` 文件的一部分，专门负责将高级的 SIMD 操作和原子操作转换为底层的 x64 汇编指令。它处理了各种 SIMD 数据的重排、加载、存储、位操作、类型转换、融合运算以及原子内存访问，是 V8 引擎实现高性能 JavaScript 执行的关键组成部分，特别是对于涉及 WebAssembly SIMD 和 SharedArrayBuffer 的代码。

Prompt: 
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/code-generator-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共10部分，请归纳一下它的功能

"""
nputAt(1)->IsSimd128Register()) {
          XMMRegister src1 = i.InputSimd128Register(1);
          if (src1 != dst) __ Movdqa(dst, src1);
        } else {
          __ Movdqu(dst, i.InputOperand(1));
        }
        for (int j = 5; j > 1; j--) {
          uint32_t lanes = i.InputUint32(j);
          for (int k = 0; k < 32; k += 8) {
            uint8_t lane = lanes >> k;
            mask2[j - 2] |= (lane >= kSimd128Size ? (lane & 0x0F) : 0x80) << k;
          }
        }
        SetupSimdImmediateInRegister(masm(), mask2, tmp_simd);
        __ Pshufb(dst, tmp_simd);
        __ Por(dst, kScratchDoubleReg);
      }
      break;
    }
    case kX64I8x16Popcnt: {
      __ I8x16Popcnt(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.TempSimd128Register(0), kScratchDoubleReg,
                     kScratchRegister);
      break;
    }
    case kX64S128Load8Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ S128Load8Splat(i.OutputSimd128Register(), i.MemoryOperand(),
                        kScratchDoubleReg);
      break;
    }
    case kX64S128Load16Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ S128Load16Splat(i.OutputSimd128Register(), i.MemoryOperand(),
                         kScratchDoubleReg);
      break;
    }
    case kX64S128Load32Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ S128Load32Splat(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load64Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Movddup(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load8x8S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovsxbw(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load8x8U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovzxbw(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load16x4S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovsxwd(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load16x4U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovzxwd(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load32x2S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovsxdq(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load32x2U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovzxdq(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Store32Lane: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      uint8_t lane = i.InputUint8(index + 1);
      __ S128Store32Lane(operand, i.InputSimd128Register(index), lane);
      break;
    }
    case kX64S128Store64Lane: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      uint8_t lane = i.InputUint8(index + 1);
      __ S128Store64Lane(operand, i.InputSimd128Register(index), lane);
      break;
    }
    case kX64Shufps: {
      if (instr->Output()->IsSimd128Register()) {
        __ Shufps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), i.InputUint8(2));
      } else {
        DCHECK(instr->Output()->IsSimd256Register());
        DCHECK(CpuFeatures::IsSupported(AVX));
        CpuFeatureScope scope(masm(), AVX);
        __ vshufps(i.OutputSimd256Register(), i.InputSimd256Register(0),
                   i.InputSimd256Register(1), i.InputUint8(2));
      }
      break;
    }
    case kX64S32x4Rotate: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      uint8_t mask = i.InputUint8(1);
      if (dst == src) {
        // 1-byte shorter encoding than pshufd.
        __ Shufps(dst, src, src, mask);
      } else {
        __ Pshufd(dst, src, mask);
      }
      break;
    }
    case kX64S32x4Swizzle: {
      DCHECK_EQ(2, instr->InputCount());
      ASSEMBLE_SIMD_IMM_INSTR(Pshufd, i.OutputSimd128Register(), 0,
                              i.InputUint8(1));
      break;
    }
    case kX64S32x4Shuffle: {
      DCHECK_EQ(4, instr->InputCount());  // Swizzles should be handled above.
      uint8_t shuffle = i.InputUint8(2);
      DCHECK_NE(0xe4, shuffle);  // A simple blend should be handled below.
      ASSEMBLE_SIMD_IMM_INSTR(Pshufd, kScratchDoubleReg, 1, shuffle);
      ASSEMBLE_SIMD_IMM_INSTR(Pshufd, i.OutputSimd128Register(), 0, shuffle);
      __ Pblendw(i.OutputSimd128Register(), kScratchDoubleReg, i.InputUint8(3));
      break;
    }
    case kX64S16x8Blend: {
      ASSEMBLE_SIMD_IMM_SHUFFLE(pblendw, i.InputUint8(2));
      break;
    }
    case kX64S16x8HalfShuffle1: {
      XMMRegister dst = i.OutputSimd128Register();
      uint8_t mask_lo = i.InputUint8(1);
      uint8_t mask_hi = i.InputUint8(2);
      if (mask_lo != 0xe4) {
        ASSEMBLE_SIMD_IMM_INSTR(Pshuflw, dst, 0, mask_lo);
        if (mask_hi != 0xe4) __ Pshufhw(dst, dst, mask_hi);
      } else {
        DCHECK_NE(mask_hi, 0xe4);
        ASSEMBLE_SIMD_IMM_INSTR(Pshufhw, dst, 0, mask_hi);
      }
      break;
    }
    case kX64S16x8HalfShuffle2: {
      XMMRegister dst = i.OutputSimd128Register();
      ASSEMBLE_SIMD_IMM_INSTR(Pshuflw, kScratchDoubleReg, 1, i.InputUint8(2));
      __ Pshufhw(kScratchDoubleReg, kScratchDoubleReg, i.InputUint8(3));
      ASSEMBLE_SIMD_IMM_INSTR(Pshuflw, dst, 0, i.InputUint8(2));
      __ Pshufhw(dst, dst, i.InputUint8(3));
      __ Pblendw(dst, kScratchDoubleReg, i.InputUint8(4));
      break;
    }
    case kX64S8x16Alignr: {
      ASSEMBLE_SIMD_IMM_SHUFFLE(palignr, i.InputUint8(2));
      break;
    }
    case kX64S16x8Dup: {
      XMMRegister dst = i.OutputSimd128Register();
      uint8_t lane = i.InputInt8(1) & 0x7;
      uint8_t lane4 = lane & 0x3;
      uint8_t half_dup = lane4 | (lane4 << 2) | (lane4 << 4) | (lane4 << 6);
      if (lane < 4) {
        ASSEMBLE_SIMD_IMM_INSTR(Pshuflw, dst, 0, half_dup);
        __ Punpcklqdq(dst, dst);
      } else {
        ASSEMBLE_SIMD_IMM_INSTR(Pshufhw, dst, 0, half_dup);
        __ Punpckhqdq(dst, dst);
      }
      break;
    }
    case kX64S8x16Dup: {
      XMMRegister dst = i.OutputSimd128Register();
      uint8_t lane = i.InputInt8(1) & 0xf;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (lane < 8) {
        __ Punpcklbw(dst, dst);
      } else {
        __ Punpckhbw(dst, dst);
      }
      lane &= 0x7;
      uint8_t lane4 = lane & 0x3;
      uint8_t half_dup = lane4 | (lane4 << 2) | (lane4 << 4) | (lane4 << 6);
      if (lane < 4) {
        __ Pshuflw(dst, dst, half_dup);
        __ Punpcklqdq(dst, dst);
      } else {
        __ Pshufhw(dst, dst, half_dup);
        __ Punpckhqdq(dst, dst);
      }
      break;
    }
    case kX64S64x2UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhqdq);
      break;
    case kX64S32x4UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhdq);
      break;
    case kX64S32x8UnpackHigh: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpunpckhdq(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64S16x8UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhwd);
      break;
    case kX64S8x16UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhbw);
      break;
    case kX64S64x2UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpcklqdq);
      break;
    case kX64S32x4UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckldq);
      break;
    case kX64S32x8UnpackLow: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpunpckldq(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64S16x8UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpcklwd);
      break;
    case kX64S8x16UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpcklbw);
      break;
    case kX64S16x8UnzipHigh: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (instr->InputCount() == 2) {
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psrld(kScratchDoubleReg, uint8_t{16});
        src2 = kScratchDoubleReg;
      }
      __ Psrld(dst, uint8_t{16});
      __ Packusdw(dst, src2);
      break;
    }
    case kX64S16x8UnzipLow: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      __ Pxor(kScratchDoubleReg, kScratchDoubleReg);
      if (instr->InputCount() == 2) {
        ASSEMBLE_SIMD_IMM_INSTR(Pblendw, kScratchDoubleReg, 1, uint8_t{0x55});
        src2 = kScratchDoubleReg;
      }
      __ Pblendw(dst, kScratchDoubleReg, uint8_t{0xaa});
      __ Packusdw(dst, src2);
      break;
    }
    case kX64S8x16UnzipHigh: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (instr->InputCount() == 2) {
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psrlw(kScratchDoubleReg, uint8_t{8});
        src2 = kScratchDoubleReg;
      }
      __ Psrlw(dst, uint8_t{8});
      __ Packuswb(dst, src2);
      break;
    }
    case kX64S8x16UnzipLow: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (instr->InputCount() == 2) {
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psllw(kScratchDoubleReg, uint8_t{8});
        __ Psrlw(kScratchDoubleReg, uint8_t{8});
        src2 = kScratchDoubleReg;
      }
      __ Psllw(dst, uint8_t{8});
      __ Psrlw(dst, uint8_t{8});
      __ Packuswb(dst, src2);
      break;
    }
    case kX64S8x16TransposeLow: {
      XMMRegister dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      __ Psllw(dst, uint8_t{8});
      if (instr->InputCount() == 1) {
        __ Movdqa(kScratchDoubleReg, dst);
      } else {
        DCHECK_EQ(2, instr->InputCount());
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psllw(kScratchDoubleReg, uint8_t{8});
      }
      __ Psrlw(dst, uint8_t{8});
      __ Por(dst, kScratchDoubleReg);
      break;
    }
    case kX64S8x16TransposeHigh: {
      XMMRegister dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      __ Psrlw(dst, uint8_t{8});
      if (instr->InputCount() == 1) {
        __ Movdqa(kScratchDoubleReg, dst);
      } else {
        DCHECK_EQ(2, instr->InputCount());
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psrlw(kScratchDoubleReg, uint8_t{8});
      }
      __ Psllw(kScratchDoubleReg, uint8_t{8});
      __ Por(dst, kScratchDoubleReg);
      break;
    }
    case kX64S8x8Reverse:
    case kX64S8x4Reverse:
    case kX64S8x2Reverse: {
      DCHECK_EQ(1, instr->InputCount());
      XMMRegister dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (arch_opcode != kX64S8x2Reverse) {
        // First shuffle words into position.
        uint8_t shuffle_mask = arch_opcode == kX64S8x4Reverse ? 0xB1 : 0x1B;
        __ Pshuflw(dst, dst, shuffle_mask);
        __ Pshufhw(dst, dst, shuffle_mask);
      }
      __ Movdqa(kScratchDoubleReg, dst);
      __ Psrlw(kScratchDoubleReg, uint8_t{8});
      __ Psllw(dst, uint8_t{8});
      __ Por(dst, kScratchDoubleReg);
      break;
    }
    case kX64V128AnyTrue: {
      Register dst = i.OutputRegister();
      XMMRegister src = i.InputSimd128Register(0);

      __ xorq(dst, dst);
      __ Ptest(src, src);
      __ setcc(not_equal, dst);
      break;
    }
    // Need to split up all the different lane structures because the
    // comparison instruction used matters, e.g. given 0xff00, pcmpeqb returns
    // 0x0011, pcmpeqw returns 0x0000, ptest will set ZF to 0 and 1
    // respectively.
    case kX64IAllTrue: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16AllTrue
            ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqb);
            break;
          }
          case kL16: {
            // I16x8AllTrue
            ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqw);
            break;
          }
          case kL32: {
            // I32x4AllTrue
            ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqd);
            break;
          }
          case kL64: {
            // I64x2AllTrue
            ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqq);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64Blendvpd: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        __ Blendvpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), i.InputSimd128Register(2));
      } else {
        DCHECK_EQ(vec_len, kV256);
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vblendvpd(i.OutputSimd256Register(), i.InputSimd256Register(0),
                     i.InputSimd256Register(1), i.InputSimd256Register(2));
      }
      break;
    }
    case kX64Blendvps: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        __ Blendvps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), i.InputSimd128Register(2));
      } else {
        DCHECK_EQ(vec_len, kV256);
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vblendvps(i.OutputSimd256Register(), i.InputSimd256Register(0),
                     i.InputSimd256Register(1), i.InputSimd256Register(2));
      }
      break;
    }
    case kX64Pblendvb: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        __ Pblendvb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), i.InputSimd128Register(2));
      } else {
        DCHECK_EQ(vec_len, kV256);
        CpuFeatureScope avx_scope(masm(), AVX2);
        __ vpblendvb(i.OutputSimd256Register(), i.InputSimd256Register(0),
                     i.InputSimd256Register(1), i.InputSimd256Register(2));
      }
      break;
    }
    case kX64I32x4TruncF64x2UZero: {
      __ I32x4TruncSatF64x2UZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg,
                                 kScratchRegister);
      break;
    }
    case kX64I32x4TruncF32x4U: {
      __ I32x4TruncF32x4U(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          kScratchDoubleReg, i.TempSimd128Register(0));
      break;
    }
    case kX64I32x8TruncF32x8U: {
      __ I32x8TruncF32x8U(i.OutputSimd256Register(), i.InputSimd256Register(0),
                          kScratchSimd256Reg, i.TempSimd256Register(0));
      break;
    }
    case kX64Cvttps2dq: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        __ Cvttps2dq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else {
        DCHECK_EQ(vec_len, kV256);
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vcvttps2dq(i.OutputSimd256Register(), i.InputSimd256Register(0));
      }
      break;
    }
    case kX64Cvttpd2dq: {
      __ Cvttpd2dq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kAtomicStoreWord8: {
      ASSEMBLE_SEQ_CST_STORE(MachineRepresentation::kWord8);
      break;
    }
    case kAtomicStoreWord16: {
      ASSEMBLE_SEQ_CST_STORE(MachineRepresentation::kWord16);
      break;
    }
    case kAtomicStoreWord32: {
      ASSEMBLE_SEQ_CST_STORE(MachineRepresentation::kWord32);
      break;
    }
    case kX64Word64AtomicStoreWord64: {
      ASSEMBLE_SEQ_CST_STORE(MachineRepresentation::kWord64);
      break;
    }
    case kAtomicExchangeInt8: {
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgb(i.InputRegister(0), i.MemoryOperand(1));
      __ movsxbl(i.InputRegister(0), i.InputRegister(0));
      break;
    }
    case kAtomicExchangeUint8: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgb(i.InputRegister(0), i.MemoryOperand(1));
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ movzxbl(i.InputRegister(0), i.InputRegister(0));
          break;
        case AtomicWidth::kWord64:
          __ movzxbq(i.InputRegister(0), i.InputRegister(0));
          break;
      }
      break;
    }
    case kAtomicExchangeInt16: {
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgw(i.InputRegister(0), i.MemoryOperand(1));
      __ movsxwl(i.InputRegister(0), i.InputRegister(0));
      break;
    }
    case kAtomicExchangeUint16: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgw(i.InputRegister(0), i.MemoryOperand(1));
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ movzxwl(i.InputRegister(0), i.InputRegister(0));
          break;
        case AtomicWidth::kWord64:
          __ movzxwq(i.InputRegister(0), i.InputRegister(0));
          break;
      }
      break;
    }
    case kAtomicExchangeWord32: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgl(i.InputRegister(0), i.MemoryOperand(1));
      break;
    }
    case kAtomicCompareExchangeInt8: {
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgb(i.MemoryOperand(2), i.InputRegister(1));
      __ movsxbl(rax, rax);
      break;
    }
    case kAtomicCompareExchangeUint8: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgb(i.MemoryOperand(2), i.InputRegister(1));
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ movzxbl(rax, rax);
          break;
        case AtomicWidth::kWord64:
          __ movzxbq(rax, rax);
          break;
      }
      break;
    }
    case kAtomicCompareExchangeInt16: {
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgw(i.MemoryOperand(2), i.InputRegister(1));
      __ movsxwl(rax, rax);
      break;
    }
    case kAtomicCompareExchangeUint16: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgw(i.MemoryOperand(2), i.InputRegister(1));
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ movzxwl(rax, rax);
          break;
        case AtomicWidth::kWord64:
          __ movzxwq(rax, rax);
          break;
      }
      break;
    }
    case kAtomicCompareExchangeWord32: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgl(i.MemoryOperand(2), i.InputRegister(1));
      if (AtomicWidthField::decode(opcode) == AtomicWidth::kWord64) {
        // Zero-extend the 32 bit value to 64 bit.
        __ movl(rax, rax);
      }
      break;
    }
    case kX64Word64AtomicExchangeUint64: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgq(i.InputRegister(0), i.MemoryOperand(1));
      break;
    }
    case kX64Word64AtomicCompareExchangeUint64: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgq(i.MemoryOperand(2), i.InputRegister(1));
      break;
    }
#define ATOMIC_BINOP_CASE(op, inst32, inst64)                          \
  case kAtomic##op##Int8:                                              \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP(inst32, movb, cmpxchgb);                     \
    __ movsxbl(rax, rax);                                              \
    break;                                                             \
  case kAtomic##op##Uint8:                                             \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP(inst32, movb, cmpxchgb);                 \
        __ movzxbl(rax, rax);                                          \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC64_BINOP(inst64, movb, cmpxchgb);               \
        __ movzxbq(rax, rax);                                          \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Int16:                                             \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP(inst32, movw, cmpxchgw);                     \
    __ movsxwl(rax, rax);                                              \
    break;                                                             \
  case kAtomic##op##Uint16:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP(inst32, movw, cmpxchgw);                 \
        __ movzxwl(rax, rax);                                          \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC64_BINOP(inst64, movw, cmpxchgw);               \
        __ movzxwq(rax, rax);                                          \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Word32:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP(inst32, movl, cmpxchgl);                 \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC64_BINOP(inst64, movl, cmpxchgl);               \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kX64Word64Atomic##op##Uint64:                                   \
    ASSEMBLE_ATOMIC64_BINOP(inst64, movq, cmpxchgq);                   \
    break;
      ATOMIC_BINOP_CASE(Add, addl, addq)
      ATOMIC_BINOP_CASE(Sub, subl, subq)
      ATOMIC_BINOP_CASE(And, andl, andq)
      ATOMIC_BINOP_CASE(Or, orl, orq)
      ATOMIC_BINOP_CASE(Xor, xorl, xorq)
#undef ATOMIC_BINOP_CASE

    case kAtomicLoadInt8:
    case kAtomicLoadUint8:
    case kAtomicLoadInt16:
    case kAtomicLoadUint16:
    case kAtomicLoadWord32:
      UNREACHABLE();  // Won't be generated by instruction selector.

    case kX64I32x8DotI16x16S: {
      ASSEMBLE_SIMD256_BINOP(pmaddwd, AVX2);
      break;
    }
    case kX64S256Load8Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpbroadcastb(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load16Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpbroadcastw(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load32Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vbroadcastss(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load64Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vbroadcastsd(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64Movdqu256: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx_scope(masm(), AVX);
      if (instr->HasOutput()) {
        __ vmovdqu(i.OutputSimd256Register(), i.MemoryOperand());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ vmovdqu(operand, i.InputSimd256Register(index));
      }
      break;
    }
    case kX64I16x16SConvertI32x8: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpackssdw(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64I16x16UConvertI32x8: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpackusdw(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64I8x32SConvertI16x16: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpacksswb(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64I8x32UConvertI16x16: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpackuswb(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64I64x4ExtMulI32x4S: {
      __ I64x4ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchSimd256Reg,
                     /*is_signed=*/true);
      break;
    }
    case kX64I64x4ExtMulI32x4U: {
      __ I64x4ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchSimd256Reg,
                     /*is_signed=*/false);
      break;
    }
    case kX64I32x8ExtMulI16x8S: {
      __ I32x8ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchSimd256Reg,
                     /*is_signed=*/true);
      break;
    }
    case kX64I32x8ExtMulI16x8U: {
      __ I32x8ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchSimd256Reg,
                     /*is_signed=*/false);
      break;
    }
    case kX64I16x16ExtMulI8x16S: {
      __ I16x16ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), kScratchSimd256Reg,
                      /*is_signed=*/true);
      break;
    }
    case kX64I16x16ExtMulI8x16U: {
      __ I16x16ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), kScratchSimd256Reg,
                      /*is_signed=*/false);
      break;
    }
    case kX64S256Load8x16S: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovsxbw(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load8x16U: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovzxbw(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load8x8U: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovzxbd(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load16x8S: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovsxwd(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load16x8U: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovzxwd(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load32x4S: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovsxdq(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load32x4U: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovzxdq(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Const: {
      // Emit code for generic constants as all zeros, or ones cases will be
      // handled separately by the selector.
      YMMRegister dst = i.OutputSimd256Register();
      uint32_t imm[8] = {};
      for (int j = 0; j < 8; j++) {
        imm[j] = i.InputUint32(j);
      }
      SetupSimd256ImmediateInRegister(masm(), imm, dst, kScratchDoubleReg);
      break;
    }
    case kX64ExtractF128: {
      CpuFeatureScope avx_scope(masm(), AVX);
      uint8_t lane = i.InputInt8(1);
      __ vextractf128(i.OutputSimd128Register(), i.InputSimd256Register(0),
                      lane);
      break;
    }
    case kX64InsertI128: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      uint8_t imm = i.InputInt8(2);
      InstructionOperand* input0 = instr->InputAt(0);
      if (input0->IsSimd128Register()) {
        __ vinserti128(i.OutputSimd256Register(),
                       YMMRegister::from_xmm(i.InputSimd128Register(0)),
                       i.InputSimd128Register(1), imm);
      } else {
        DCHECK(instr->InputAt(0)->IsSimd256Register());
        __ vinserti128(i.OutputSimd256Register(), i.InputSimd256Register(0),
                       i.InputSimd128Register(1), imm);
      }
      break;
    }
  }
  return kSuccess;
}  // NOLadability/fn_size)

#undef ASSEMBLE_PINSR
#undef ASSEMBLE_UNOP
#undef ASSEMBLE_BINOP
#undef ASSEMBLE_COMPARE
#undef ASSEMBLE_MULT
#undef ASSEMBLE_SHIFT
#undef ASSEMBLE_MOVX
#undef ASSEMBLE_SSE_BINOP
#undef ASSEMBLE_SSE_UNOP
#undef ASSEMBLE_AVX_BINOP
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC64_BINOP
#undef ASSEMBLE_SIMD_INSTR
#undef ASSEMBLE_SIMD_IMM_INSTR
#undef ASSEMBLE_SIMD_PUNPCK_SHUFFLE
#undef ASSEMBLE_SIMD_IMM_SHUFFLE
#undef ASSEMBLE_SIMD_ALL_TRUE
#undef ASSEMBLE_SIMD_SHIFT
#undef ASSEMBLE_SEQ_CST_STORE

namespace {

constexpr Condition FlagsConditionToCondition(FlagsCondition condition) {
  switch (condition) {
    case kUnorderedEqual:
    case kEqual:
      return equal;
    case kUnorderedNotEqual:
    case kNotEqual:
      return not_equal;
    case kSignedLessThan:
      return less;
    case kSignedGreaterThanOrEqual:
      return greater_equal;
    case kSignedLessThanOrEqual:
      return less_equal;
    case kSignedGreaterThan:
      return greater;
    case kUnsignedLessThan:
      return below;
    case kUnsignedGreaterThanOrEqual:
      return above_equal;
    case kUnsignedLessThanOrEqual:
      return below_equal;
    case kUnsignedGreaterThan:
      return above;
    case kOverflow:
      return overflow;
    case kNotOverflow:
      return no_overflow;
    case kIsNaN:
      return parity_even;
    case kIsNotNaN:
      return parity_odd;
    default:
      break;
  }
  UNREACHABLE();
}

}  // namespace

// Assembl
"""


```