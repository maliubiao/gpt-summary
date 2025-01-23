Response: The user wants a summary of the functionality of the provided C++ code snippet. This is part 2 of 3. The code seems to be related to code generation for the IA32 architecture within the V8 JavaScript engine. It appears to handle various low-level operations, including stack manipulation, SIMD (Single Instruction, Multiple Data) operations, and atomic operations. Since this is part 2, I should avoid repeating any information I might have gleaned from part 1 (if I had seen it). I will focus on the operations present in this specific snippet. I need to identify the different instruction types (cases) and briefly describe what each does. If any of these operations are directly related to how JavaScript works, I should provide a simple JavaScript example.

Based on the keywords like `kIA32Poke`, `kIA32Peek`, and the various `kIA32F64x2...`, `kIA32F32x4...`, `kIA32I32x4...` etc. cases, it looks like this code is responsible for translating higher-level intermediate representation (IR) instructions into actual IA32 assembly instructions. The SIMD instructions strongly suggest a connection to optimizing array operations or similar data-parallel tasks, which are common in JavaScript. The atomic operations are relevant for concurrent programming scenarios.

**Plan:**

1. **Identify the core functionality:** Code generation for IA32 architecture within V8.
2. **Categorize the operations:**  Stack operations, floating-point SIMD, integer SIMD, atomic operations, memory access.
3. **Summarize each operation category.**
4. **Find connections to JavaScript and provide examples.**  Focus on how these low-level operations enable features in JavaScript, particularly around typed arrays and concurrency (although explicit concurrency is limited in single-threaded JS).
这是 `v8/src/compiler/backend/ia32/code-generator-ia32.cc` 文件的一部分，主要负责将中间代码（可能是由 V8 的其他编译器阶段生成的）转换为针对 IA32 架构的机器码。

**功能归纳：**

这部分代码主要负责处理以下类型的操作：

1. **栈操作:**  `kIA32Poke` 和 `kIA32Peek` 用于在当前栈帧上写入和读取数据。`kIA32StackClaim` 用于在栈上分配空间。
2. **SIMD (Single Instruction, Multiple Data) 浮点运算 (双精度和单精度):**  处理 `F64x2` (双精度 128 位 SIMD) 和 `F32x4` (单精度 128 位 SIMD) 向量的各种运算，例如 splat（复制单个值到所有通道）、提取通道、替换通道、平方根、加减乘除、最小值、最大值、比较（相等、不等、小于、小于等于）、融合乘加/减、以及类型转换等。
3. **SIMD 整数运算 (64位, 32位, 16位, 8位):**  处理 `I64x2`, `I32x4`, `I16x8`, `I8x16` 向量的各种运算，例如 splat、提取通道、替换通道、绝对值、取反、移位（左移、有符号右移、无符号右移）、加减乘、最小值、最大值、比较（相等、不等、大于、大于等于）、类型转换、点积、饱和运算、平均值、位掩码等。
4. **SIMD 通用操作:**  例如 `kIA32Insertps` (插入单精度浮点数)、`kIA32Movlps`/`kIA32Movhps` (移动低/高位单精度浮点数)、`kIA32Pextrb`/`kIA32Pextrw` (提取字节/字)、`kIA32S128Store32Lane` (存储 128 位 SIMD 寄存器中的 32 位数据到指定通道) 等。
5. **SIMD 常量和逻辑操作:**  加载常量 (`kIA32S128Const`)、零 (`kIA32S128Zero`)、全一 (`kIA32S128AllOnes`)，以及按位非 (`kIA32S128Not`)、与 (`kIA32S128And`)、或 (`kIA32S128Or`)、异或 (`kIA32S128Xor`)、选择 (`kIA32S128Select`)、与非 (`kIA32S128AndNot`)。
6. **SIMD 重排和混洗操作:**  `kIA32I8x16Swizzle`、`kIA32I8x16Shuffle`、`kIA32S32x4Rotate`、`kIA32S32x4Swizzle`、`kIA32S32x4Shuffle`、`kIA32S16x8Blend`、`kIA32S16x8HalfShuffle1/2`、`kIA32S8x16Alignr`、`kIA32S16x8Dup`、`kIA32S8x16Dup` 以及各种 `Unpack` 操作等，用于重新排列 SIMD 向量中的元素。
7. **SIMD 加载操作:** 从内存加载不同大小的数据到 SIMD 寄存器，例如 `kIA32S128Load8Splat`、`kIA32S128Load16Splat`、`kIA32S128Load32Splat`、`kIA32S128Load64Splat` 以及有符号和无符号的扩展加载 (`kIA32S128Load8x8S/U`, `kIA32S128Load16x4S/U`, `kIA32S128Load32x2S/U`)。
8. **SIMD 是否全为真判断:**  `kIA32S128AnyTrue`, `kIA32I64x2AllTrue`, `kIA32I32x4AllTrue`, `kIA32I16x8AllTrue`, `kIA32I8x16AllTrue` 用于检查 SIMD 向量中的元素是否都满足特定条件（通常用于条件分支）。
9. **SIMD 选择性混合:**  `kIA32Blendvpd`, `kIA32Blendvps`, `kIA32Pblendvb` 根据掩码从两个 SIMD 向量中选择元素进行混合。
10. **原子操作:**  `kIA32Word32AtomicPairLoad`, `kIA32Word32ReleasePairStore`, `kIA32Word32SeqCstPairStore`, `kAtomicExchangeInt8/Uint8/Int16/Uint16/Word32`, `kIA32Word32AtomicPairExchange`, `kAtomicCompareExchangeInt8/Uint8/Int16/Uint16/Word32`, `kIA32Word32AtomicPairCompareExchange` 等，用于在多线程环境中安全地访问和修改共享内存。

**与 JavaScript 的关系及示例:**

这些低级操作与 JavaScript 的功能息息相关，特别是在以下几个方面：

* **Typed Arrays (类型化数组):**  JavaScript 的 `TypedArray` (例如 `Int32Array`, `Float64Array`) 允许对二进制数据进行高效的操作。SIMD 指令 (`F64x2`, `F32x4`, `I32x4` 等) 可以极大地加速对这些类型化数组的数学运算和数据处理。

```javascript
const floatArray = new Float32Array([1.0, 2.0, 3.0, 4.0]);

// 假设 V8 内部使用 SIMD 指令来加速类似的操作
for (let i = 0; i < floatArray.length; i++) {
  floatArray[i] *= 2.0;
}

console.log(floatArray); // 输出: Float32Array [ 2, 4, 6, 8 ]
```

* **WebAssembly (Wasm):** WebAssembly 允许以接近原生的性能运行代码。Wasm 中定义的 SIMD 指令与这里看到的 `kIA32F64x2...`, `kIA32I32x4...` 等操作有直接的对应关系。V8 需要能够将这些 Wasm SIMD 指令翻译成 IA32 机器码。

```javascript
// 假设一个 WebAssembly 模块导出了一个使用 SIMD 的函数
const wasmCode = `
  (module
    (func $add_vectors (param $v1 v128) (param $v2 v128) (result v128)
      local.get $v1
      local.get $v2
      f32x4.add
    )
    (export "add_vectors" (func $add_vectors))
  )
`;

const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule);
const addVectors = wasmInstance.exports.add_vectors;

const vector1 = new Float32Array([1, 2, 3, 4]);
const vector2 = new Float32Array([5, 6, 7, 8]);

// 在 V8 内部，调用 addVectors 可能会使用类似 kIA32F32x4Add 的指令
const resultVector = addVectors(vector1, vector2);
console.log(resultVector); // 输出类似: v128 { f32x4: [ 6, 8, 10, 12 ] }
```

* **原子操作与 SharedArrayBuffer:** JavaScript 的 `SharedArrayBuffer` 允许在多个 Worker 之间共享内存。为了安全地访问和修改共享内存，需要使用原子操作，例如 `Atomics.add()`, `Atomics.compareExchange()` 等。  这里看到的 `kAtomicCompareExchangeWord32` 等操作就对应了这些 JavaScript 原子操作的底层实现。

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const i32a = new Int32Array(sab);

// 在一个 Worker 中
Atomics.add(i32a, 0, 5);

// 在另一个 Worker 中
const oldValue = Atomics.compareExchange(i32a, 0, 5, 10);
console.log(oldValue); // 输出 5 (如果值仍然是 5)
```

总而言之，这部分代码是 V8 引擎将高级 JavaScript 或 WebAssembly 代码转换为可以在 IA32 架构上执行的低级机器码的关键组成部分，尤其是在处理数值计算、多媒体处理和并发等性能敏感的场景中。

### 提示词
```
这是目录为v8/src/compiler/backend/ia32/code-generator-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
ckSlot() || input->IsFloatStackSlot()) {
          __ AllocateStackSpace(stack_decrement - kSystemPointerSize);
          __ push(i.InputOperand(1));
        } else if (input->IsDoubleStackSlot()) {
          DCHECK_GE(stack_decrement, kDoubleSize);
          __ Movsd(kScratchDoubleReg, i.InputOperand(1));
          __ AllocateStackSpace(stack_decrement);
          __ Movsd(Operand(esp, 0), kScratchDoubleReg);
        } else {
          DCHECK(input->IsSimd128StackSlot());
          DCHECK_GE(stack_decrement, kSimd128Size);
          // TODO(bbudge) Use Movaps when slots are aligned.
          __ Movups(kScratchDoubleReg, i.InputOperand(1));
          __ AllocateStackSpace(stack_decrement);
          __ Movups(Operand(esp, 0), kScratchDoubleReg);
        }
      }
      frame_access_state()->IncreaseSPDelta(slots);
      break;
    }
    case kIA32Poke: {
      int slot = MiscField::decode(instr->opcode());
      if (HasImmediateInput(instr, 0)) {
        __ mov(Operand(esp, slot * kSystemPointerSize), i.InputImmediate(0));
      } else {
        __ mov(Operand(esp, slot * kSystemPointerSize), i.InputRegister(0));
      }
      break;
    }
    case kIA32Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ Movsd(i.OutputDoubleRegister(), Operand(ebp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ Movss(i.OutputFloatRegister(), Operand(ebp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ Movdqu(i.OutputSimd128Register(), Operand(ebp, offset));
        }
      } else {
        __ mov(i.OutputRegister(), Operand(ebp, offset));
      }
      break;
    }
    case kIA32F64x2Splat: {
      __ Movddup(i.OutputSimd128Register(), i.InputDoubleRegister(0));
      break;
    }
    case kIA32F64x2ExtractLane: {
      __ F64x2ExtractLane(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                          i.InputUint8(1));
      break;
    }
    case kIA32F64x2ReplaceLane: {
      __ F64x2ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputDoubleRegister(2), i.InputInt8(1));
      break;
    }
    case kIA32F64x2Sqrt: {
      __ Sqrtpd(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32F64x2Add: {
      __ Addpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F64x2Sub: {
      __ Subpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F64x2Mul: {
      __ Mulpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F64x2Div: {
      __ Divpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F64x2Min: {
      __ F64x2Min(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32F64x2Max: {
      __ F64x2Max(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32F64x2Eq: {
      __ Cmpeqpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F64x2Ne: {
      __ Cmpneqpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      break;
    }
    case kIA32F64x2Lt: {
      __ Cmpltpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F64x2Le: {
      __ Cmplepd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F64x2Qfma: {
      __ F64x2Qfma(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kIA32F64x2Qfms: {
      __ F64x2Qfms(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kIA32Minpd: {
      __ Minpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kIA32Maxpd: {
      __ Maxpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kIA32F64x2Round: {
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundpd(i.OutputSimd128Register(), i.InputDoubleRegister(0), mode);
      break;
    }
    case kIA32F64x2PromoteLowF32x4: {
      if (HasAddressingMode(instr)) {
        __ Cvtps2pd(i.OutputSimd128Register(), i.MemoryOperand());
      } else {
        __ Cvtps2pd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      }
      break;
    }
    case kIA32F32x4DemoteF64x2Zero: {
      __ Cvtpd2ps(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I32x4TruncSatF64x2SZero: {
      __ I32x4TruncSatF64x2SZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg,
                                 i.TempRegister(0));
      break;
    }
    case kIA32I32x4TruncSatF64x2UZero: {
      __ I32x4TruncSatF64x2UZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg,
                                 i.TempRegister(0));
      break;
    }
    case kIA32F64x2ConvertLowI32x4S: {
      __ Cvtdq2pd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32F64x2ConvertLowI32x4U: {
      __ F64x2ConvertLowI32x4U(i.OutputSimd128Register(),
                               i.InputSimd128Register(0), i.TempRegister(0));
      break;
    }
    case kIA32I64x2ExtMulLowI32x4S: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true, /*is_signed=*/true);
      break;
    }
    case kIA32I64x2ExtMulHighI32x4S: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false, /*is_signed=*/true);
      break;
    }
    case kIA32I64x2ExtMulLowI32x4U: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true, /*is_signed=*/false);
      break;
    }
    case kIA32I64x2ExtMulHighI32x4U: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false, /*is_signed=*/false);
      break;
    }
    case kIA32I32x4ExtMulLowI16x8S: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true, /*is_signed=*/true);
      break;
    }
    case kIA32I32x4ExtMulHighI16x8S: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false, /*is_signed=*/true);
      break;
    }
    case kIA32I32x4ExtMulLowI16x8U: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true, /*is_signed=*/false);
      break;
    }
    case kIA32I32x4ExtMulHighI16x8U: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false, /*is_signed=*/false);
      break;
    }
    case kIA32I16x8ExtMulLowI8x16S: {
      __ I16x8ExtMulLow(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg,
                        /*is_signed=*/true);
      break;
    }
    case kIA32I16x8ExtMulHighI8x16S: {
      __ I16x8ExtMulHighS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I16x8ExtMulLowI8x16U: {
      __ I16x8ExtMulLow(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg,
                        /*is_signed=*/false);
      break;
    }
    case kIA32I16x8ExtMulHighI8x16U: {
      __ I16x8ExtMulHighU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I64x2SplatI32Pair: {
      XMMRegister dst = i.OutputSimd128Register();
      __ Pinsrd(dst, i.InputRegister(0), 0);
      __ Pinsrd(dst, i.InputOperand(1), 1);
      __ Pshufd(dst, dst, uint8_t{0x44});
      break;
    }
    case kIA32I64x2ReplaceLaneI32Pair: {
      int8_t lane = i.InputInt8(1);
      __ Pinsrd(i.OutputSimd128Register(), i.InputOperand(2), lane * 2);
      __ Pinsrd(i.OutputSimd128Register(), i.InputOperand(3), lane * 2 + 1);
      break;
    }
    case kIA32I64x2Abs: {
      __ I64x2Abs(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  kScratchDoubleReg);
      break;
    }
    case kIA32I64x2Neg: {
      __ I64x2Neg(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  kScratchDoubleReg);
      break;
    }
    case kIA32I64x2Shl: {
      ASSEMBLE_SIMD_SHIFT(Psllq, 6);
      break;
    }
    case kIA32I64x2ShrS: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      if (HasImmediateInput(instr, 1)) {
        __ I64x2ShrS(dst, src, i.InputInt6(1), kScratchDoubleReg);
      } else {
        __ I64x2ShrS(dst, src, i.InputRegister(1), kScratchDoubleReg,
                     i.TempSimd128Register(0), i.TempRegister(1));
      }
      break;
    }
    case kIA32I64x2Add: {
      __ Paddq(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I64x2Sub: {
      __ Psubq(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I64x2Mul: {
      __ I64x2Mul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), i.TempSimd128Register(0),
                  i.TempSimd128Register(1));
      break;
    }
    case kIA32I64x2ShrU: {
      ASSEMBLE_SIMD_SHIFT(Psrlq, 6);
      break;
    }
    case kIA32I64x2BitMask: {
      __ Movmskpd(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I64x2Eq: {
      __ Pcmpeqq(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I64x2Ne: {
      __ Pcmpeqq(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      __ Pcmpeqq(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ Pxor(i.OutputSimd128Register(), kScratchDoubleReg);
      break;
    }
    case kIA32I64x2GtS: {
      __ I64x2GtS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I64x2GeS: {
      __ I64x2GeS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I64x2SConvertI32x4Low: {
      __ Pmovsxdq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I64x2SConvertI32x4High: {
      __ I64x2SConvertI32x4High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kIA32I64x2UConvertI32x4Low: {
      __ Pmovzxdq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I64x2UConvertI32x4High: {
      __ I64x2UConvertI32x4High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kIA32I32x4ExtAddPairwiseI16x8S: {
      __ I32x4ExtAddPairwiseI16x8S(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0),
                                   i.TempRegister(0));
      break;
    }
    case kIA32I32x4ExtAddPairwiseI16x8U: {
      __ I32x4ExtAddPairwiseI16x8U(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0),
                                   kScratchDoubleReg);
      break;
    }
    case kIA32I16x8ExtAddPairwiseI8x16S: {
      __ I16x8ExtAddPairwiseI8x16S(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0), kScratchDoubleReg,
                                   i.TempRegister(0));
      break;
    }
    case kIA32I16x8ExtAddPairwiseI8x16U: {
      __ I16x8ExtAddPairwiseI8x16U(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0),
                                   i.TempRegister(0));
      break;
    }
    case kIA32I16x8Q15MulRSatS: {
      __ I16x8Q15MulRSatS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I16x8RelaxedQ15MulRS: {
      __ Pmulhrsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kIA32I16x8DotI8x16I7x16S: {
      __ I16x8DotI8x16I7x16S(i.OutputSimd128Register(),
                             i.InputSimd128Register(0),
                             i.InputSimd128Register(1));
      break;
    }
    case kIA32I32x4DotI8x16I7x16AddS: {
      __ I32x4DotI8x16I7x16AddS(
          i.OutputSimd128Register(), i.InputSimd128Register(0),
          i.InputSimd128Register(1), i.InputSimd128Register(2),
          kScratchDoubleReg, i.TempSimd128Register(0));
      break;
    }
    case kIA32F32x4Splat: {
      __ F32x4Splat(i.OutputSimd128Register(), i.InputDoubleRegister(0));
      break;
    }
    case kIA32F32x4ExtractLane: {
      __ F32x4ExtractLane(i.OutputFloatRegister(), i.InputSimd128Register(0),
                          i.InputUint8(1));
      break;
    }
    case kIA32Insertps: {
      if (CpuFeatures::IsSupported(AVX)) {
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vinsertps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputOperand(2), i.InputInt8(1) << 4);
      } else {
        DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
        CpuFeatureScope sse_scope(masm(), SSE4_1);
        __ insertps(i.OutputSimd128Register(), i.InputOperand(2),
                    i.InputInt8(1) << 4);
      }
      break;
    }
    case kIA32F32x4SConvertI32x4: {
      __ Cvtdq2ps(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32F32x4UConvertI32x4: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      __ Pxor(kScratchDoubleReg, kScratchDoubleReg);      // zeros
      __ Pblendw(kScratchDoubleReg, src, uint8_t{0x55});  // get lo 16 bits
      __ Psubd(dst, src, kScratchDoubleReg);              // get hi 16 bits
      __ Cvtdq2ps(kScratchDoubleReg, kScratchDoubleReg);  // convert lo exactly
      __ Psrld(dst, dst, uint8_t{1});  // divide by 2 to get in unsigned range
      __ Cvtdq2ps(dst, dst);    // convert hi exactly
      __ Addps(dst, dst, dst);  // double hi, exactly
      __ Addps(dst, dst, kScratchDoubleReg);  // add hi and lo, may round.
      break;
    }
    case kIA32F32x4Sqrt: {
      __ Sqrtps(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32F32x4Add: {
      __ Addps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    };
    case kIA32F32x4Sub: {
      __ Subps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F32x4Mul: {
      __ Mulps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F32x4Div: {
      __ Divps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F32x4Min: {
      __ F32x4Min(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32F32x4Max: {
      __ F32x4Max(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32F32x4Eq: {
      __ Cmpeqps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F32x4Ne: {
      __ Cmpneqps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      break;
    }
    case kIA32F32x4Lt: {
      __ Cmpltps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F32x4Le: {
      __ Cmpleps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F32x4Qfma: {
      __ F32x4Qfma(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kIA32F32x4Qfms: {
      __ F32x4Qfms(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kIA32Minps: {
      __ Minps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kIA32Maxps: {
      __ Maxps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kIA32F32x4Round: {
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundps(i.OutputSimd128Register(), i.InputDoubleRegister(0), mode);
      break;
    }
    case kIA32I32x4Splat: {
      XMMRegister dst = i.OutputSimd128Register();
      __ Movd(dst, i.InputOperand(0));
      __ Pshufd(dst, dst, uint8_t{0x0});
      break;
    }
    case kIA32I32x4ExtractLane: {
      __ Pextrd(i.OutputRegister(), i.InputSimd128Register(0), i.InputInt8(1));
      break;
    }
    case kIA32I32x4SConvertF32x4: {
      __ I32x4SConvertF32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            i.TempRegister(0));
      break;
    }
    case kIA32I32x4SConvertI16x8Low: {
      __ Pmovsxwd(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32I32x4SConvertI16x8High: {
      __ I32x4SConvertI16x8High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kIA32I32x4Neg: {
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(0);
      if (src.is_reg(dst)) {
        __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
        __ Psignd(dst, kScratchDoubleReg);
      } else {
        __ Pxor(dst, dst);
        __ Psubd(dst, src);
      }
      break;
    }
    case kIA32I32x4Shl: {
      ASSEMBLE_SIMD_SHIFT(Pslld, 5);
      break;
    }
    case kIA32I32x4ShrS: {
      ASSEMBLE_SIMD_SHIFT(Psrad, 5);
      break;
    }
    case kIA32I32x4Add: {
      __ Paddd(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I32x4Sub: {
      __ Psubd(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I32x4Mul: {
      __ Pmulld(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I32x4MinS: {
      __ Pminsd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I32x4MaxS: {
      __ Pmaxsd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I32x4Eq: {
      __ Pcmpeqd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I32x4Ne: {
      __ Pcmpeqd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ Pxor(i.OutputSimd128Register(), i.OutputSimd128Register(),
              kScratchDoubleReg);
      break;
    }
    case kIA32I32x4GtS: {
      __ Pcmpgtd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I32x4GeS: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src1 = i.InputSimd128Register(0);
      XMMRegister src2 = i.InputSimd128Register(1);
      if (CpuFeatures::IsSupported(AVX)) {
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vpminsd(kScratchDoubleReg, src1, src2);
        __ vpcmpeqd(dst, kScratchDoubleReg, src2);
      } else {
        DCHECK_EQ(dst, src1);
        CpuFeatureScope sse_scope(masm(), SSE4_1);
        __ pminsd(dst, src2);
        __ pcmpeqd(dst, src2);
      }
      break;
    }
    case kSSEI32x4UConvertF32x4: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister tmp = i.TempSimd128Register(0);
      XMMRegister tmp2 = i.TempSimd128Register(1);
      __ I32x4TruncF32x4U(dst, dst, tmp, tmp2);
      break;
    }
    case kAVXI32x4UConvertF32x4: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister tmp = i.TempSimd128Register(0);
      // NAN->0, negative->0
      __ vpxor(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vmaxps(dst, dst, kScratchDoubleReg);
      // scratch: float representation of max_signed
      __ vpcmpeqd(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpsrld(kScratchDoubleReg, kScratchDoubleReg, 1);  // 0x7fffffff
      __ vcvtdq2ps(kScratchDoubleReg, kScratchDoubleReg);  // 0x4f000000
      // tmp: convert (src-max_signed).
      // Positive overflow lanes -> 0x7FFFFFFF
      // Negative lanes -> 0
      __ vsubps(tmp, dst, kScratchDoubleReg);
      __ vcmpleps(kScratchDoubleReg, kScratchDoubleReg, tmp);
      __ vcvttps2dq(tmp, tmp);
      __ vpxor(tmp, tmp, kScratchDoubleReg);
      __ vpxor(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpmaxsd(tmp, tmp, kScratchDoubleReg);
      // convert. Overflow lanes above max_signed will be 0x80000000
      __ vcvttps2dq(dst, dst);
      // Add (src-max_signed) for overflow lanes.
      __ vpaddd(dst, dst, tmp);
      break;
    }
    case kIA32I32x4UConvertI16x8Low: {
      __ Pmovzxwd(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32I32x4UConvertI16x8High: {
      __ I32x4UConvertI16x8High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kIA32I32x4ShrU: {
      ASSEMBLE_SIMD_SHIFT(Psrld, 5);
      break;
    }
    case kIA32I32x4MinU: {
      __ Pminud(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I32x4MaxU: {
      __ Pmaxud(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kSSEI32x4GtU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pmaxud(dst, src);
      __ pcmpeqd(dst, src);
      __ pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
      __ xorps(dst, kScratchDoubleReg);
      break;
    }
    case kAVXI32x4GtU: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpmaxud(kScratchDoubleReg, src1, src2);
      __ vpcmpeqd(dst, kScratchDoubleReg, src2);
      __ vpcmpeqd(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpxor(dst, dst, kScratchDoubleReg);
      break;
    }
    case kSSEI32x4GeU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pminud(dst, src);
      __ pcmpeqd(dst, src);
      break;
    }
    case kAVXI32x4GeU: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpminud(kScratchDoubleReg, src1, src2);
      __ vpcmpeqd(i.OutputSimd128Register(), kScratchDoubleReg, src2);
      break;
    }
    case kIA32I32x4Abs: {
      __ Pabsd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I32x4BitMask: {
      __ Movmskps(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I32x4DotI16x8S: {
      __ Pmaddwd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I16x8Splat: {
      if (instr->InputAt(0)->IsRegister()) {
        __ I16x8Splat(i.OutputSimd128Register(), i.InputRegister(0));
      } else {
        __ I16x8Splat(i.OutputSimd128Register(), i.InputOperand(0));
      }
      break;
    }
    case kIA32I16x8ExtractLaneS: {
      Register dst = i.OutputRegister();
      __ Pextrw(dst, i.InputSimd128Register(0), i.InputUint8(1));
      __ movsx_w(dst, dst);
      break;
    }
    case kIA32I16x8SConvertI8x16Low: {
      __ Pmovsxbw(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32I16x8SConvertI8x16High: {
      __ I16x8SConvertI8x16High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kIA32I16x8Neg: {
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(0);
      if (src.is_reg(dst)) {
        __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
        __ Psignw(dst, kScratchDoubleReg);
      } else {
        __ Pxor(dst, dst);
        __ Psubw(dst, src);
      }
      break;
    }
    case kIA32I16x8Shl: {
      ASSEMBLE_SIMD_SHIFT(Psllw, 4);
      break;
    }
    case kIA32I16x8ShrS: {
      ASSEMBLE_SIMD_SHIFT(Psraw, 4);
      break;
    }
    case kIA32I16x8SConvertI32x4: {
      __ Packssdw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      break;
    }
    case kIA32I16x8Add: {
      __ Paddw(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I16x8AddSatS: {
      __ Paddsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8Sub: {
      __ Psubw(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I16x8SubSatS: {
      __ Psubsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8Mul: {
      __ Pmullw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8MinS: {
      __ Pminsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8MaxS: {
      __ Pmaxsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8Eq: {
      __ Pcmpeqw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kSSEI16x8Ne: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ pcmpeqw(i.OutputSimd128Register(), i.InputOperand(1));
      __ pcmpeqw(kScratchDoubleReg, kScratchDoubleReg);
      __ xorps(i.OutputSimd128Register(), kScratchDoubleReg);
      break;
    }
    case kAVXI16x8Ne: {
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vpcmpeqw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      __ vpcmpeqw(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpxor(i.OutputSimd128Register(), i.OutputSimd128Register(),
               kScratchDoubleReg);
      break;
    }
    case kIA32I16x8GtS: {
      __ Pcmpgtw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kSSEI16x8GeS: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pminsw(dst, src);
      __ pcmpeqw(dst, src);
      break;
    }
    case kAVXI16x8GeS: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpminsw(kScratchDoubleReg, src1, src2);
      __ vpcmpeqw(i.OutputSimd128Register(), kScratchDoubleReg, src2);
      break;
    }
    case kIA32I16x8UConvertI8x16Low: {
      __ Pmovzxbw(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32I16x8UConvertI8x16High: {
      __ I16x8UConvertI8x16High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kIA32I16x8ShrU: {
      ASSEMBLE_SIMD_SHIFT(Psrlw, 4);
      break;
    }
    case kIA32I16x8UConvertI32x4: {
      __ Packusdw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kIA32I16x8AddSatU: {
      __ Paddusw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I16x8SubSatU: {
      __ Psubusw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I16x8MinU: {
      __ Pminuw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8MaxU: {
      __ Pmaxuw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kSSEI16x8GtU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pmaxuw(dst, src);
      __ pcmpeqw(dst, src);
      __ pcmpeqw(kScratchDoubleReg, kScratchDoubleReg);
      __ xorps(dst, kScratchDoubleReg);
      break;
    }
    case kAVXI16x8GtU: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpmaxuw(kScratchDoubleReg, src1, src2);
      __ vpcmpeqw(dst, kScratchDoubleReg, src2);
      __ vpcmpeqw(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpxor(dst, dst, kScratchDoubleReg);
      break;
    }
    case kSSEI16x8GeU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
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
```