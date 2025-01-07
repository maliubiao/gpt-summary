Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is part of the V8 JavaScript engine and resides in the `code-generator-ia32.cc` file.

Here's a plan to generate the response:

1. **Identify the primary purpose:** The code snippet seems to be handling the generation of IA-32 assembly instructions for various operations, particularly SIMD (Single Instruction, Multiple Data) operations.

2. **Check for Torque involvement:** The filename ends with `.cc`, not `.tq`, so it's not a Torque source file.

3. **Analyze the connection to JavaScript:**  V8 compiles JavaScript code into machine code. This file is part of that compilation process, specifically for the IA-32 architecture. The operations being handled likely correspond to JavaScript language features, especially those involving typed arrays or SIMD operations.

4. **Provide JavaScript examples:** For some of the operations, provide corresponding JavaScript examples to illustrate the connection.

5. **Look for code logic and provide examples:** Identify patterns or specific logic within the code and create hypothetical input/output scenarios.

6. **Identify potential programming errors:**  Based on the operations, highlight common errors a programmer might make when using the related JavaScript features.

7. **Summarize the functionality:** Based on the analysis, provide a concise summary of the code's purpose.
这是 V8 JavaScript 引擎中 `v8/src/compiler/backend/ia32/code-generator-ia32.cc` 文件的一部分代码，主要负责为 IA-32 架构生成机器码，特别是针对 SIMD (Single Instruction, Multiple Data) 操作。

**功能归纳:**

这段代码的功能是为 V8 的中间表示 (Instruction) 中的各种 SIMD 指令生成对应的 IA-32 汇编代码。它针对不同的 SIMD 操作（例如加法、减法、比较、位运算、数据重排等）和不同的数据类型（例如 8 位、16 位、32 位整数），生成相应的汇编指令，以利用 IA-32 架构的 SIMD 指令集（例如 SSE、SSE4.1、AVX）。

**关于文件类型:**

`v8/src/compiler/backend/ia32/code-generator-ia32.cc` 以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 V8 Torque 源代码。

**与 JavaScript 的关系及示例:**

这段代码与 JavaScript 的关系在于，当 JavaScript 代码中涉及到 SIMD 操作（例如使用 `Uint8ClampedArray` 或 `SIMD` API）时，V8 的编译器会生成对应的中间表示指令，然后 `code-generator-ia32.cc` 中的代码会将这些中间表示指令翻译成底层的 IA-32 汇编指令，从而在 CPU 上高效地执行这些 SIMD 操作。

**JavaScript 示例:**

```javascript
// 使用 Uint8ClampedArray 进行 SIMD 类似的按字节操作
const array1 = new Uint8ClampedArray([10, 20, 30, 40]);
const array2 = new Uint8ClampedArray([5, 10, 15, 20]);
const result = new Uint8ClampedArray(4);

for (let i = 0; i < array1.length; i++) {
  result[i] = array1[i] + array2[i]; // 编译器可能会利用 SIMD 指令优化这类操作
}

console.log(result); // 输出: Uint8ClampedArray [ 15, 30, 45, 60 ]

// 使用 SIMD API (如果浏览器支持)
// const a = SIMD.uint8x16(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
// const b = SIMD.uint8x16(16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1);
// const c = SIMD.uint8x16.add(a, b);
// console.log(c);
```

在后台，当 V8 编译这些 JavaScript 代码时，对于类似 `array1[i] + array2[i]` 的操作，或者 `SIMD.uint8x16.add(a, b)` 这样的 SIMD API 调用，`code-generator-ia32.cc` 中的代码会生成相应的 IA-32 SIMD 加法指令 (例如 `paddb`, `vpaddb` 等)。

**代码逻辑推理示例 (以 `kIA32I16x8Add` 为例):**

**假设输入:**

*   中间表示指令 `i` 代表一个 16 位整数向量加法操作 (`kIA32I16x8Add`)。
*   `i.OutputSimd128Register()` 返回 XMM 寄存器 `xmm0` 作为目标寄存器。
*   `i.InputSimd128Register(0)` 返回 XMM 寄存器 `xmm1` 作为第一个输入操作数。
*   `i.InputOperand(1)` 返回内存操作数 `[eax + 4]` 作为第二个输入操作数。

**输出的汇编代码:**

```assembly
paddw xmm0, [eax + 4]
```

**解释:** 这条 `paddw` 指令执行 16 位整数向量的加法，将 `xmm1` 中的值与内存地址 `[eax + 4]` 中的值相加，结果存储在 `xmm0` 中。

**用户常见的编程错误示例:**

在使用涉及 SIMD 操作的 JavaScript 时，常见的错误包括：

1. **数据类型不匹配:**  例如，尝试将浮点数数组与期望整数的 SIMD 操作混合使用，可能导致意外结果或错误。
    ```javascript
    const floatArray = new Float32Array([1.0, 2.0, 3.0, 4.0]);
    const intArray = new Int32Array([1, 2, 3, 4]);
    // 尝试对不同类型的数组进行按位运算，可能不会得到预期结果
    // 这种情况下，编译器可能不会直接使用整数 SIMD 指令
    for (let i = 0; i < floatArray.length; i++) {
      intArray[i] = floatArray[i] | intArray[i];
    }
    ```

2. **SIMD API 使用不当:**  如果使用 `SIMD` API，可能会错误地混合不同大小或类型的 SIMD 数据类型。
    ```javascript
    // 假设浏览器支持 SIMD
    // const a = SIMD.int32x4(1, 2, 3, 4);
    // const b = SIMD.float32x4(1.0, 2.0, 3.0, 4.0);
    // 错误地尝试将 int32x4 和 float32x4 相加，通常需要先进行类型转换
    // const c = SIMD.int32x4.add(a, b); // 这会导致类型错误
    ```

3. **对齐问题 (底层优化相关):** 虽然 JavaScript 层面不直接暴露，但在底层，SIMD 指令通常对内存对齐有要求。如果 V8 在进行优化时未能正确处理对齐，可能会导致性能下降或在某些架构上出现错误。这通常是 V8 团队需要处理的问题，但开发者理解这一点有助于理解为什么某些看似简单的操作在底层会比较复杂。

**第 4 部分功能归纳:**

作为代码生成器的第四部分，这段代码专门负责处理 SIMD 相关的指令生成。它涵盖了多种 SIMD 操作，包括算术运算、位运算、比较运算、数据转换、数据重排等，并针对 IA-32 架构的不同 SIMD 指令集（SSE、SSE4.1、AVX）生成相应的汇编代码。其核心目标是将 V8 的高级中间表示转换为可以在 IA-32 处理器上高效执行的机器码，从而加速 JavaScript 中涉及向量化计算的部分。

Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/code-generator-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/code-generator-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
asm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pminuw(dst, src);
      __ pcmpeqw(dst, src);
      break;
    }
    case kAVXI16x8GeU: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpminuw(kScratchDoubleReg, src1, src2);
      __ vpcmpeqw(i.OutputSimd128Register(), kScratchDoubleReg, src2);
      break;
    }
    case kIA32I16x8RoundingAverageU: {
      __ Pavgw(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I16x8Abs: {
      __ Pabsw(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I16x8BitMask: {
      Register dst = i.OutputRegister();
      XMMRegister tmp = i.TempSimd128Register(0);
      __ Packsswb(tmp, i.InputSimd128Register(0));
      __ Pmovmskb(dst, tmp);
      __ shr(dst, 8);
      break;
    }
    case kIA32I8x16Splat: {
      if (instr->InputAt(0)->IsRegister()) {
        __ I8x16Splat(i.OutputSimd128Register(), i.InputRegister(0),
                      kScratchDoubleReg);
      } else {
        __ I8x16Splat(i.OutputSimd128Register(), i.InputOperand(0),
                      kScratchDoubleReg);
      }
      break;
    }
    case kIA32I8x16ExtractLaneS: {
      Register dst = i.OutputRegister();
      __ Pextrb(dst, i.InputSimd128Register(0), i.InputUint8(1));
      __ movsx_b(dst, dst);
      break;
    }
    case kIA32Pinsrb: {
      ASSEMBLE_SIMD_PINSR(pinsrb, SSE4_1);
      break;
    }
    case kIA32Pinsrw: {
      ASSEMBLE_SIMD_PINSR(pinsrw, SSE4_1);
      break;
    }
    case kIA32Pinsrd: {
      ASSEMBLE_SIMD_PINSR(pinsrd, SSE4_1);
      break;
    }
    case kIA32Movlps: {
      if (instr->HasOutput()) {
        __ Movlps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.MemoryOperand(2));
      } else {
        size_t index = 0;
        Operand dst = i.MemoryOperand(&index);
        __ Movlps(dst, i.InputSimd128Register(index));
      }
      break;
    }
    case kIA32Movhps: {
      if (instr->HasOutput()) {
        __ Movhps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.MemoryOperand(2));
      } else {
        size_t index = 0;
        Operand dst = i.MemoryOperand(&index);
        __ Movhps(dst, i.InputSimd128Register(index));
      }
      break;
    }
    case kIA32Pextrb: {
      if (HasAddressingMode(instr)) {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ Pextrb(operand, i.InputSimd128Register(index),
                  i.InputUint8(index + 1));
      } else {
        Register dst = i.OutputRegister();
        __ Pextrb(dst, i.InputSimd128Register(0), i.InputUint8(1));
      }
      break;
    }
    case kIA32Pextrw: {
      if (HasAddressingMode(instr)) {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ Pextrw(operand, i.InputSimd128Register(index),
                  i.InputUint8(index + 1));
      } else {
        Register dst = i.OutputRegister();
        __ Pextrw(dst, i.InputSimd128Register(0), i.InputUint8(1));
      }
      break;
    }
    case kIA32S128Store32Lane: {
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      uint8_t laneidx = i.InputUint8(index + 1);
      __ S128Store32Lane(operand, i.InputSimd128Register(index), laneidx);
      break;
    }
    case kIA32I8x16SConvertI16x8: {
      __ Packsswb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      break;
    }
    case kIA32I8x16Neg: {
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(0);
      if (src.is_reg(dst)) {
        __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
        __ Psignb(dst, kScratchDoubleReg);
      } else {
        __ Pxor(dst, dst);
        __ Psubb(dst, src);
      }
      break;
    }
    case kIA32I8x16Shl: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      DCHECK_IMPLIES(!CpuFeatures::IsSupported(AVX), dst == src);
      Register tmp = i.TempRegister(0);

      if (HasImmediateInput(instr, 1)) {
        __ I8x16Shl(dst, src, i.InputInt3(1), tmp, kScratchDoubleReg);
      } else {
        XMMRegister tmp_simd = i.TempSimd128Register(1);
        __ I8x16Shl(dst, src, i.InputRegister(1), tmp, kScratchDoubleReg,
                    tmp_simd);
      }
      break;
    }
    case kIA32I8x16ShrS: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      DCHECK_IMPLIES(!CpuFeatures::IsSupported(AVX), dst == src);

      if (HasImmediateInput(instr, 1)) {
        __ I8x16ShrS(dst, src, i.InputInt3(1), kScratchDoubleReg);
      } else {
        __ I8x16ShrS(dst, src, i.InputRegister(1), i.TempRegister(0),
                     kScratchDoubleReg, i.TempSimd128Register(1));
      }
      break;
    }
    case kIA32I8x16Add: {
      __ Paddb(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I8x16AddSatS: {
      __ Paddsb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I8x16Sub: {
      __ Psubb(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I8x16SubSatS: {
      __ Psubsb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I8x16MinS: {
      __ Pminsb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I8x16MaxS: {
      __ Pmaxsb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I8x16Eq: {
      __ Pcmpeqb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kSSEI8x16Ne: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ pcmpeqb(i.OutputSimd128Register(), i.InputOperand(1));
      __ pcmpeqb(kScratchDoubleReg, kScratchDoubleReg);
      __ xorps(i.OutputSimd128Register(), kScratchDoubleReg);
      break;
    }
    case kAVXI8x16Ne: {
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vpcmpeqb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      __ vpcmpeqb(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpxor(i.OutputSimd128Register(), i.OutputSimd128Register(),
               kScratchDoubleReg);
      break;
    }
    case kIA32I8x16GtS: {
      __ Pcmpgtb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kSSEI8x16GeS: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pminsb(dst, src);
      __ pcmpeqb(dst, src);
      break;
    }
    case kAVXI8x16GeS: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpminsb(kScratchDoubleReg, src1, src2);
      __ vpcmpeqb(i.OutputSimd128Register(), kScratchDoubleReg, src2);
      break;
    }
    case kIA32I8x16UConvertI16x8: {
      __ Packuswb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kIA32I8x16AddSatU: {
      __ Paddusb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I8x16SubSatU: {
      __ Psubusb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I8x16ShrU: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      DCHECK_IMPLIES(!CpuFeatures::IsSupported(AVX), dst == src);
      Register tmp = i.TempRegister(0);

      if (HasImmediateInput(instr, 1)) {
        __ I8x16ShrU(dst, src, i.InputInt3(1), tmp, kScratchDoubleReg);
      } else {
        __ I8x16ShrU(dst, src, i.InputRegister(1), tmp, kScratchDoubleReg,
                     i.TempSimd128Register(1));
      }

      break;
    }
    case kIA32I8x16MinU: {
      __ Pminub(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I8x16MaxU: {
      __ Pmaxub(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kSSEI8x16GtU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pmaxub(dst, src);
      __ pcmpeqb(dst, src);
      __ pcmpeqb(kScratchDoubleReg, kScratchDoubleReg);
      __ xorps(dst, kScratchDoubleReg);
      break;
    }
    case kAVXI8x16GtU: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpmaxub(kScratchDoubleReg, src1, src2);
      __ vpcmpeqb(dst, kScratchDoubleReg, src2);
      __ vpcmpeqb(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpxor(dst, dst, kScratchDoubleReg);
      break;
    }
    case kSSEI8x16GeU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pminub(dst, src);
      __ pcmpeqb(dst, src);
      break;
    }
    case kAVXI8x16GeU: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpminub(kScratchDoubleReg, src1, src2);
      __ vpcmpeqb(i.OutputSimd128Register(), kScratchDoubleReg, src2);
      break;
    }
    case kIA32I8x16RoundingAverageU: {
      __ Pavgb(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I8x16Abs: {
      __ Pabsb(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I8x16BitMask: {
      __ Pmovmskb(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I8x16Popcnt: {
      __ I8x16Popcnt(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchDoubleReg, i.TempSimd128Register(0),
                     i.TempRegister(1));
      break;
    }
    case kIA32S128Const: {
      XMMRegister dst = i.OutputSimd128Register();
      Register tmp = i.TempRegister(0);
      uint64_t low_qword = make_uint64(i.InputUint32(1), i.InputUint32(0));
      __ Move(dst, low_qword);
      __ Move(tmp, Immediate(i.InputUint32(2)));
      __ Pinsrd(dst, tmp, 2);
      __ Move(tmp, Immediate(i.InputUint32(3)));
      __ Pinsrd(dst, tmp, 3);
      break;
    }
    case kIA32S128Zero: {
      XMMRegister dst = i.OutputSimd128Register();
      __ Pxor(dst, dst);
      break;
    }
    case kIA32S128AllOnes: {
      XMMRegister dst = i.OutputSimd128Register();
      __ Pcmpeqd(dst, dst);
      break;
    }
    case kIA32S128Not: {
      __ S128Not(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchDoubleReg);
      break;
    }
    case kIA32S128And: {
      __ Pand(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputOperand(1));
      break;
    }
    case kIA32S128Or: {
      __ Por(i.OutputSimd128Register(), i.InputSimd128Register(0),
             i.InputOperand(1));
      break;
    }
    case kIA32S128Xor: {
      __ Pxor(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputOperand(1));
      break;
    }
    case kIA32S128Select: {
      __ S128Select(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), i.InputSimd128Register(2),
                    kScratchDoubleReg);
      break;
    }
    case kIA32S128AndNot: {
      // The inputs have been inverted by instruction selector, so we can call
      // andnps here without any modifications.
      __ Andnps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputSimd128Register(1));
      break;
    }
    case kIA32I8x16Swizzle: {
      __ I8x16Swizzle(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), kScratchDoubleReg,
                      i.TempRegister(0), MiscField::decode(instr->opcode()));
      break;
    }
    case kIA32I8x16Shuffle: {
      XMMRegister dst = i.OutputSimd128Register();
      Operand src0 = i.InputOperand(0);
      Register tmp = i.TempRegister(0);
      // Prepare 16 byte aligned buffer for shuffle control mask
      __ mov(tmp, esp);
      __ and_(esp, -16);
      if (instr->InputCount() == 5) {  // only one input operand
        DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
        for (int j = 4; j > 0; j--) {
          uint32_t mask = i.InputUint32(j);
          __ push(Immediate(mask));
        }
        __ Pshufb(dst, Operand(esp, 0));
      } else {  // two input operands
        DCHECK_EQ(6, instr->InputCount());
        __ Movups(kScratchDoubleReg, src0);
        for (int j = 5; j > 1; j--) {
          uint32_t lanes = i.InputUint32(j);
          uint32_t mask = 0;
          for (int k = 0; k < 32; k += 8) {
            uint8_t lane = lanes >> k;
            mask |= (lane < kSimd128Size ? lane : 0x80) << k;
          }
          __ push(Immediate(mask));
        }
        __ Pshufb(kScratchDoubleReg, Operand(esp, 0));
        Operand src1 = i.InputOperand(1);
        if (!src1.is_reg(dst)) __ Movups(dst, src1);
        for (int j = 5; j > 1; j--) {
          uint32_t lanes = i.InputUint32(j);
          uint32_t mask = 0;
          for (int k = 0; k < 32; k += 8) {
            uint8_t lane = lanes >> k;
            mask |= (lane >= kSimd128Size ? (lane & 0xF) : 0x80) << k;
          }
          __ push(Immediate(mask));
        }
        __ Pshufb(dst, Operand(esp, 0));
        __ por(dst, kScratchDoubleReg);
      }
      __ mov(esp, tmp);
      break;
    }
    case kIA32S128Load8Splat: {
      __ S128Load8Splat(i.OutputSimd128Register(), i.MemoryOperand(),
                        kScratchDoubleReg);
      break;
    }
    case kIA32S128Load16Splat: {
      __ S128Load16Splat(i.OutputSimd128Register(), i.MemoryOperand(),
                         kScratchDoubleReg);
      break;
    }
    case kIA32S128Load32Splat: {
      __ S128Load32Splat(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kIA32S128Load64Splat: {
      __ Movddup(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kIA32S128Load8x8S: {
      __ Pmovsxbw(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kIA32S128Load8x8U: {
      __ Pmovzxbw(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kIA32S128Load16x4S: {
      __ Pmovsxwd(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kIA32S128Load16x4U: {
      __ Pmovzxwd(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kIA32S128Load32x2S: {
      __ Pmovsxdq(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kIA32S128Load32x2U: {
      __ Pmovzxdq(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kIA32S32x4Rotate: {
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
    case kIA32S32x4Swizzle: {
      DCHECK_EQ(2, instr->InputCount());
      __ Pshufd(i.OutputSimd128Register(), i.InputOperand(0), i.InputUint8(1));
      break;
    }
    case kIA32S32x4Shuffle: {
      DCHECK_EQ(4, instr->InputCount());  // Swizzles should be handled above.
      uint8_t shuffle = i.InputUint8(2);
      DCHECK_NE(0xe4, shuffle);  // A simple blend should be handled below.
      __ Pshufd(kScratchDoubleReg, i.InputOperand(1), shuffle);
      __ Pshufd(i.OutputSimd128Register(), i.InputOperand(0), shuffle);
      __ Pblendw(i.OutputSimd128Register(), kScratchDoubleReg, i.InputUint8(3));
      break;
    }
    case kIA32S16x8Blend:
      ASSEMBLE_SIMD_IMM_SHUFFLE(pblendw, SSE4_1, i.InputInt8(2));
      break;
    case kIA32S16x8HalfShuffle1: {
      XMMRegister dst = i.OutputSimd128Register();
      __ Pshuflw(dst, i.InputOperand(0), i.InputUint8(1));
      __ Pshufhw(dst, dst, i.InputUint8(2));
      break;
    }
    case kIA32S16x8HalfShuffle2: {
      XMMRegister dst = i.OutputSimd128Register();
      __ Pshuflw(kScratchDoubleReg, i.InputOperand(1), i.InputUint8(2));
      __ Pshufhw(kScratchDoubleReg, kScratchDoubleReg, i.InputUint8(3));
      __ Pshuflw(dst, i.InputOperand(0), i.InputUint8(2));
      __ Pshufhw(dst, dst, i.InputUint8(3));
      __ Pblendw(dst, kScratchDoubleReg, i.InputUint8(4));
      break;
    }
    case kIA32S8x16Alignr:
      ASSEMBLE_SIMD_IMM_SHUFFLE(palignr, SSSE3, i.InputInt8(2));
      break;
    case kIA32S16x8Dup: {
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(0);
      uint8_t lane = i.InputUint8(1) & 0x7;
      uint8_t lane4 = lane & 0x3;
      uint8_t half_dup = lane4 | (lane4 << 2) | (lane4 << 4) | (lane4 << 6);
      if (lane < 4) {
        __ Pshuflw(dst, src, half_dup);
        __ Punpcklqdq(dst, dst);
      } else {
        __ Pshufhw(dst, src, half_dup);
        __ Punpckhqdq(dst, dst);
      }
      break;
    }
    case kIA32S8x16Dup: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      uint8_t lane = i.InputUint8(1) & 0xf;
      if (CpuFeatures::IsSupported(AVX)) {
        CpuFeatureScope avx_scope(masm(), AVX);
        if (lane < 8) {
          __ vpunpcklbw(dst, src, src);
        } else {
          __ vpunpckhbw(dst, src, src);
        }
      } else {
        DCHECK_EQ(dst, src);
        if (lane < 8) {
          __ punpcklbw(dst, dst);
        } else {
          __ punpckhbw(dst, dst);
        }
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
    case kIA32S64x2UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhqdq);
      break;
    case kIA32S32x4UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhdq);
      break;
    case kIA32S16x8UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhwd);
      break;
    case kIA32S8x16UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhbw);
      break;
    case kIA32S64x2UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpcklqdq);
      break;
    case kIA32S32x4UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckldq);
      break;
    case kIA32S16x8UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpcklwd);
      break;
    case kIA32S8x16UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpcklbw);
      break;
    case kSSES16x8UnzipHigh: {
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (instr->InputCount() == 2) {
        __ movups(kScratchDoubleReg, i.InputOperand(1));
        __ psrld(kScratchDoubleReg, 16);
        src2 = kScratchDoubleReg;
      }
      __ psrld(dst, 16);
      __ packusdw(dst, src2);
      break;
    }
    case kAVXS16x8UnzipHigh: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      if (instr->InputCount() == 2) {
        __ vpsrld(kScratchDoubleReg, i.InputSimd128Register(1), 16);
        src2 = kScratchDoubleReg;
      }
      __ vpsrld(dst, i.InputSimd128Register(0), 16);
      __ vpackusdw(dst, dst, src2);
      break;
    }
    case kSSES16x8UnzipLow: {
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      __ xorps(kScratchDoubleReg, kScratchDoubleReg);
      if (instr->InputCount() == 2) {
        __ pblendw(kScratchDoubleReg, i.InputOperand(1), 0x55);
        src2 = kScratchDoubleReg;
      }
      __ pblendw(dst, kScratchDoubleReg, 0xaa);
      __ packusdw(dst, src2);
      break;
    }
    case kAVXS16x8UnzipLow: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      __ vpxor(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      if (instr->InputCount() == 2) {
        __ vpblendw(kScratchDoubleReg, kScratchDoubleReg, i.InputOperand(1),
                    0x55);
        src2 = kScratchDoubleReg;
      }
      __ vpblendw(dst, kScratchDoubleReg, i.InputSimd128Register(0), 0x55);
      __ vpackusdw(dst, dst, src2);
      break;
    }
    case kSSES8x16UnzipHigh: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (instr->InputCount() == 2) {
        __ movups(kScratchDoubleReg, i.InputOperand(1));
        __ psrlw(kScratchDoubleReg, 8);
        src2 = kScratchDoubleReg;
      }
      __ psrlw(dst, 8);
      __ packuswb(dst, src2);
      break;
    }
    case kAVXS8x16UnzipHigh: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      if (instr->InputCount() == 2) {
        __ vpsrlw(kScratchDoubleReg, i.InputSimd128Register(1), 8);
        src2 = kScratchDoubleReg;
      }
      __ vpsrlw(dst, i.InputSimd128Register(0), 8);
      __ vpackuswb(dst, dst, src2);
      break;
    }
    case kSSES8x16UnzipLow: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (instr->InputCount() == 2) {
        __ movups(kScratchDoubleReg, i.InputOperand(1));
        __ psllw(kScratchDoubleReg, 8);
        __ psrlw(kScratchDoubleReg, 8);
        src2 = kScratchDoubleReg;
      }
      __ psllw(dst, 8);
      __ psrlw(dst, 8);
      __ packuswb(dst, src2);
      break;
    }
    case kAVXS8x16UnzipLow: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      if (instr->InputCount() == 2) {
        __ vpsllw(kScratchDoubleReg, i.InputSimd128Register(1), 8);
        __ vpsrlw(kScratchDoubleReg, kScratchDoubleReg, 8);
        src2 = kScratchDoubleReg;
      }
      __ vpsllw(dst, i.InputSimd128Register(0), 8);
      __ vpsrlw(dst, dst, 8);
      __ vpackuswb(dst, dst, src2);
      break;
    }
    case kSSES8x16TransposeLow: {
      XMMRegister dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      __ psllw(dst, 8);
      if (instr->InputCount() == 1) {
        __ movups(kScratchDoubleReg, dst);
      } else {
        DCHECK_EQ(2, instr->InputCount());
        __ movups(kScratchDoubleReg, i.InputOperand(1));
        __ psllw(kScratchDoubleReg, 8);
      }
      __ psrlw(dst, 8);
      __ orps(dst, kScratchDoubleReg);
      break;
    }
    case kAVXS8x16TransposeLow: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      if (instr->InputCount() == 1) {
        __ vpsllw(kScratchDoubleReg, i.InputSimd128Register(0), 8);
        __ vpsrlw(dst, kScratchDoubleReg, 8);
      } else {
        DCHECK_EQ(2, instr->InputCount());
        __ vpsllw(kScratchDoubleReg, i.InputSimd128Register(1), 8);
        __ vpsllw(dst, i.InputSimd128Register(0), 8);
        __ vpsrlw(dst, dst, 8);
      }
      __ vpor(dst, dst, kScratchDoubleReg);
      break;
    }
    case kSSES8x16TransposeHigh: {
      XMMRegister dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      __ psrlw(dst, 8);
      if (instr->InputCount() == 1) {
        __ movups(kScratchDoubleReg, dst);
      } else {
        DCHECK_EQ(2, instr->InputCount());
        __ movups(kScratchDoubleReg, i.InputOperand(1));
        __ psrlw(kScratchDoubleReg, 8);
      }
      __ psllw(kScratchDoubleReg, 8);
      __ orps(dst, kScratchDoubleReg);
      break;
    }
    case kAVXS8x16TransposeHigh: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      if (instr->InputCount() == 1) {
        __ vpsrlw(dst, i.InputSimd128Register(0), 8);
        __ vpsllw(kScratchDoubleReg, dst, 8);
      } else {
        DCHECK_EQ(2, instr->InputCount());
        __ vpsrlw(kScratchDoubleReg, i.InputSimd128Register(1), 8);
        __ vpsrlw(dst, i.InputSimd128Register(0), 8);
        __ vpsllw(kScratchDoubleReg, kScratchDoubleReg, 8);
      }
      __ vpor(dst, dst, kScratchDoubleReg);
      break;
    }
    case kSSES8x8Reverse:
    case kSSES8x4Reverse:
    case kSSES8x2Reverse: {
      DCHECK_EQ(1, instr->InputCount());
      XMMRegister dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (arch_opcode != kSSES8x2Reverse) {
        // First shuffle words into position.
        int8_t shuffle_mask = arch_opcode == kSSES8x4Reverse ? 0xB1 : 0x1B;
        __ pshuflw(dst, dst, shuffle_mask);
        __ pshufhw(dst, dst, shuffle_mask);
      }
      __ movaps(kScratchDoubleReg, dst);
      __ psrlw(kScratchDoubleReg, 8);
      __ psllw(dst, 8);
      __ orps(dst, kScratchDoubleReg);
      break;
    }
    case kAVXS8x2Reverse:
    case kAVXS8x4Reverse:
    case kAVXS8x8Reverse: {
      DCHECK_EQ(1, instr->InputCount());
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = dst;
      if (arch_opcode != kAVXS8x2Reverse) {
        // First shuffle words into position.
        int8_t shuffle_mask = arch_opcode == kAVXS8x4Reverse ? 0xB1 : 0x1B;
        __ vpshuflw(dst, i.InputOperand(0), shuffle_mask);
        __ vpshufhw(dst, dst, shuffle_mask);
      } else {
        src = i.InputSimd128Register(0);
      }
      // Reverse each 16 bit lane.
      __ vpsrlw(kScratchDoubleReg, src, 8);
      __ vpsllw(dst, src, 8);
      __ vpor(dst, dst, kScratchDoubleReg);
      break;
    }
    case kIA32S128AnyTrue: {
      Register dst = i.OutputRegister();
      XMMRegister src = i.InputSimd128Register(0);
      Register tmp = i.TempRegister(0);
      __ xor_(tmp, tmp);
      __ mov(dst, Immediate(1));
      __ Ptest(src, src);
      __ cmov(zero, dst, tmp);
      break;
    }
    // Need to split up all the different lane structures because the
    // comparison instruction used matters, e.g. given 0xff00, pcmpeqb returns
    // 0x0011, pcmpeqw returns 0x0000, ptest will set ZF to 0 and 1
    // respectively.
    case kIA32I64x2AllTrue:
      ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqq);
      break;
    case kIA32I32x4AllTrue:
      ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqd);
      break;
    case kIA32I16x8AllTrue:
      ASSEMBLE_SIMD_ALL_TRUE(pcmpeqw);
      break;
    case kIA32I8x16AllTrue: {
      ASSEMBLE_SIMD_ALL_TRUE(pcmpeqb);
      break;
    }
    case kIA32Blendvpd: {
      __ Blendvpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), i.InputSimd128Register(2));
      break;
    }
    case kIA32Blendvps: {
      __ Blendvps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), i.InputSimd128Register(2));
      break;
    }
    case kIA32Pblendvb: {
      __ Pblendvb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), i.InputSimd128Register(2));
      break;
    }
    case kIA32I32x4TruncF64x2UZero: {
      __ I32x4TruncSatF64x2UZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg,
                                 i.TempRegister(0));
      break;
    }
    case kIA32I32x4TruncF32x4U: {
      __ I32x4TruncF32x4U(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          kScratchDoubleReg, i.TempSimd128Register(0));
      break;
    }
    case kIA32Cvttps2dq: {
      __ Cvttps2dq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32Cvttpd2dq: {
      __ Cvttpd2dq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32Word32AtomicPairLoad: {
      __ movq(kScratchDoubleReg, i.MemoryOperand());
      __ Pextrd(i.OutputRegister(0), kScratchDoubleReg, 0);
      __ Pextrd(i.OutputRegister(1), kScratchDoubleReg, 1);
      break;
    }
    case kIA32Word32ReleasePairStore: {
      __ push(ebx);
      i.MoveInstructionOperandToRegister(ebx, instr->InputAt(1));
      __ push(ebx);
      i.MoveInstructionOperandToRegister(ebx, instr->InputAt(0));
      __ push(ebx);
      frame_access_state()->IncreaseSPDelta(3);
      __ movq(kScratchDoubleReg, MemOperand(esp, 0));
      __ pop(ebx);
      __ pop(ebx);
      __ pop(ebx);
      frame_access_state()->IncreaseSPDelta(-3);
      __ movq(i.MemoryOperand(2), kScratchDoubleReg);
      break;
    }
    case kIA32Word32SeqCstPairStore: {
      Label store;
      __ bind(&store);
      __ mov(eax, i.MemoryOperand(2));
      __ mov(edx, i.NextMemoryOperand(2));
      __ push(ebx);
      frame_access_state()->IncreaseSPDelta(1);
      i.MoveInstructionOperandToRegister(ebx, instr->InputAt(0));
      __ lock();
      __ cmpxchg8b(i.MemoryOperand(2));
      __ pop(ebx);
      frame_access_state()->IncreaseSPDelta(-1);
      __ j(not_equal, &store);
      break;
    }
    case kAtomicExchangeInt8: {
      __ xchg_b(i.InputRegister(0), i.MemoryOperand(1));
      __ movsx_b(i.InputRegister(0), i.InputRegister(0));
      break;
    }
    case kAtomicExchangeUint8: {
      __ xchg_b(i.InputRegister(0), i.MemoryOperand(1));
      __ movzx_b(i.InputRegister(0), i.InputRegister(0));
      break;
    }
    case kAtomicExchangeInt16: {
      __ xchg_w(i.InputRegister(0), i.MemoryOperand(1));
      __ movsx_w(i.InputRegister(0), i.InputRegister(0));
      break;
    }
    case kAtomicExchangeUint16: {
      __ xchg_w(i.InputRegister(0), i.MemoryOperand(1));
      __ movzx_w(i.InputRegister(0), i.InputRegister(0));
      break;
    }
    case kAtomicExchangeWord32: {
      __ xchg(i.InputRegister(0), i.MemoryOperand(1));
      break;
    }
    case kIA32Word32AtomicPairExchange: {
      DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr));
      Label exchange;
      __ bind(&exchange);
      __ mov(eax, i.MemoryOperand(2));
      __ mov(edx, i.NextMemoryOperand(2));
      __ push(ebx);
      frame_access_state()->IncreaseSPDelta(1);
      i.MoveInstructionOperandToRegister(ebx, instr->InputAt(0));
      __ lock();
      __ cmpxchg8b(i.MemoryOperand(2));
      __ pop(ebx);
      frame_access_state()->IncreaseSPDelta(-1);
      __ j(not_equal, &exchange);
      break;
    }
    case kAtomicCompareExchangeInt8: {
      __ lock();
      __ cmpxchg_b(i.MemoryOperand(2), i.InputRegister(1));
      __ movsx_b(eax, eax);
      break;
    }
    case kAtomicCompareExchangeUint8: {
      __ lock();
      __ cmpxchg_b(i.MemoryOperand(2), i.InputRegister(1));
      __ movzx_b(eax, eax);
      break;
    }
    case kAtomicCompareExchangeInt16: {
      __ lock();
      __ cmpxchg_w(i.MemoryOperand(2), i.InputRegister(1));
      __ movsx_w(eax, eax);
      break;
    }
    case kAtomicCompareExchangeUint16: {
      __ lock();
      __ cmpxchg_w(i.MemoryOperand(2), i.InputRegister(1));
      __ movzx_w(eax, eax);
      break;
    }
    case kAtomicCompareExchangeWord32: {
      __ lock();
      __ cmpxchg(i.MemoryOperand(2), i.InputRegister(1));
      break;
    }
    case kIA32Word32AtomicPairCompareExchange: {
      __ push(ebx);
      frame_access_state()->IncreaseSPDelta(1);
      i.MoveInstructionOperandToRegister(ebx, instr->InputAt(2));
      __ lock();
      __ cmpxchg8b(i.MemoryOperand(4));
      __ pop(ebx);
      frame_access_state()->IncreaseSPDelta(-1);
      break;
    }
#define ATOMIC_BINOP_CASE(op, inst)             
"""


```