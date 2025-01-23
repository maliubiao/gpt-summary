Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/mips64/code-generator-mips64.cc`. They have specific questions about its purpose, relationship to JavaScript, potential use of Torque, illustrative examples, and common programming errors. This is part 3 of 6, so a concise summary of the current part is needed.

Here's a breakdown of the thinking process:

1. **Identify the core functionality:** The code consists of a large `switch` statement. Each `case` corresponds to a specific `ArchOpcode` (likely an instruction in the MIPS64 architecture). The code within each `case` appears to be generating the corresponding MIPS64 assembly instructions using the `__` assembler object.

2. **Determine the overall purpose:**  Given that it's in `v8/src/compiler/backend/mips64`, this file is responsible for the *code generation* phase of the V8 compiler for the MIPS64 architecture. It translates intermediate representation (likely from the TurboFan compiler) into actual machine code.

3. **Address the Torque question:** The file extension is `.cc`, not `.tq`. Therefore, it's not a Torque file.

4. **Relate to JavaScript:**  Since this is a backend code generator, it directly enables the execution of JavaScript on MIPS64 by producing the necessary machine code. Think of a simple JavaScript operation and how it might be translated down to machine instructions. For example, adding two numbers in JavaScript will eventually require an addition instruction at the machine level.

5. **Provide a JavaScript example:**  A basic arithmetic operation is a good starting point to illustrate the connection. `const sum = a + b;` would conceptually involve loading the values of `a` and `b` into registers and then performing an addition. The provided C++ code handles the low-level details of generating those load and add instructions.

6. **Consider code logic and examples:**  The `switch` statement itself represents the core logic. Pick a few representative `case` statements and explain what they do. Focus on instructions related to memory access (load/store) and SIMD operations as those are prominent in the provided snippet.

7. **Think about potential programming errors:**  Common errors in assembly/low-level programming often involve incorrect memory access, register usage, or assumptions about data types. An example could be loading or storing the wrong number of bytes, leading to data corruption. Another could be not handling the zero register correctly in certain floating-point operations.

8. **Summarize the current part:** The provided snippet primarily deals with memory access (loads and stores), stack manipulation, atomic operations, and SIMD instructions. It's a portion of the code generation logic focused on translating specific IR operations into their MIPS64 equivalents.

9. **Structure the answer:** Organize the findings into clear sections addressing each of the user's points. Use headings and code blocks for better readability.
这是v8源代码文件 `v8/src/compiler/backend/mips64/code-generator-mips64.cc` 的一部分，它负责 **将中间代码（可能是TurboFan IR）翻译成 MIPS64 架构的机器码**。

**功能归纳 (针对提供的代码片段):**

这段代码主要负责处理各种 **内存访问**、**栈操作**、**原子操作** 和 **SIMD (MSA) 指令** 的生成。具体来说，它根据不同的 `ArchOpcode` (架构操作码) 生成对应的 MIPS64 汇编指令。

**详细功能列表:**

* **内存加载指令 (Load):**
    * `kMips64Lbu`, `kMips64Ulbu`: 加载无符号字节
    * `kMips64Lh`, `kMips64Ulh`: 加载有符号和无符号半字
    * `kMips64Lw`, `kMips64Ulw`, `kMips64Lwu`, `kMips64Ulwu`: 加载字 (32位)
    * `kMips64Ld`, `kMips64Uld`: 加载双字 (64位)
    * `kMips64Lwc1`, `kMips64Ulwc1`: 加载单精度浮点数
    * `kMips64Ldc1`, `kMips64Uldc1`: 加载双精度浮点数
    * `kMips64S128LoadSplat`: 加载并复制到整个 128 位 SIMD 寄存器
    * `kMips64S128Load8x8S`, `kMips64S128Load8x8U`, `kMips64S128Load16x4S`, `kMips64S128Load16x4U`, `kMips64S128Load32x2S`, `kMips64S128Load32x2U`: 加载并进行符号/零扩展的 SIMD 元素加载
    * `kMips64S128Load32Zero`, `kMips64S128Load64Zero`: 加载并部分清零的 SIMD 加载
    * `kMips64S128LoadLane`: 加载 SIMD 向量的指定通道
* **内存存储指令 (Store):**
    * `kMips64Sb`, `kMips64Usb`: 存储字节
    * `kMips64Sh`, `kMips64Ush`: 存储半字
    * `kMips64Sw`, `kMips64Usw`: 存储字
    * `kMips64Sd`, `kMips64Usd`: 存储双字
    * `kMips64Swc1`, `kMips64Uswc1`: 存储单精度浮点数
    * `kMips64Sdc1`, `kMips64Usdc1`: 存储双精度浮点数
    * `kMips64S128StoreLane`: 存储 SIMD 向量的指定通道
    * `kMips64StoreToStackSlot`: 将数据存储到栈槽
    * `kMips64StoreCompressTagged`: 存储压缩的标签值 (可能与垃圾回收有关)
* **栈操作指令:**
    * `kMips64Push`: 将数据压入栈
    * `kMips64Peek`: 从栈中窥视数据
    * `kMips64StackClaim`: 在栈上申请空间
* **原子操作指令:**
    * `kAtomicLoadInt8`, `kAtomicLoadUint8`, `kAtomicLoadInt16`, `kAtomicLoadUint16`, `kAtomicLoadWord32`, `kMips64Word64AtomicLoadUint64`: 原子加载各种大小的整数
    * `kAtomicStoreWord8`, `kAtomicStoreWord16`, `kAtomicStoreWord32`, `kMips64Word64AtomicStoreWord64`: 原子存储各种大小的整数
    * `kAtomicExchangeInt8`, `kAtomicExchangeUint8`, `kAtomicExchangeInt16`, `kAtomicExchangeUint16`, `kAtomicExchangeWord32`, `kMips64Word64AtomicExchangeUint64`: 原子交换
    * `kAtomicCompareExchangeInt8`, `kAtomicCompareExchangeUint8`, `kAtomicCompareExchangeInt16`, `kAtomicCompareExchangeUint16`, `kAtomicCompareExchangeWord32`, `kMips64Word64AtomicCompareExchangeUint64`: 原子比较并交换
    * `kAtomicAddInt8`, `kAtomicAddUint8`, `kAtomicAddInt16`, `kAtomicAddUint16`, `kAtomicAddWord32`, `kMips64Word64AtomicAddUint64`: 原子加法
    * `kAtomicSubInt8`, `kAtomicSubUint8`, `kAtomicSubInt16`, `kAtomicSubUint16`, `kAtomicSubWord32`, `kMips64Word64AtomicSubUint64`: 原子减法
    * `kAtomicAndInt8`, `kAtomicAndUint8`, `kAtomicAndInt16`, `kAtomicAndUint16`, `kAtomicAndWord32`, `kMips64Word64AtomicAndUint64`: 原子与
    * `kAtomicOrInt8`, `kAtomicOrUint8`, `kAtomicOrInt16`, `kAtomicOrUint16`, `kAtomicOrWord32`, `kMips64Word64AtomicOrUint64`: 原子或
    * `kAtomicXorInt8`, `kAtomicXorUint8`, `kAtomicXorInt16`, `kAtomicXorUint16`, `kAtomicXorWord32`, `kMips64Word64AtomicXorUint64`: 原子异或
* **SIMD (MSA) 指令:**
    * `kMips64S128Const`: 加载常量到 SIMD 寄存器
    * `kMips64S128Zero`: 将 SIMD 寄存器置零
    * `kMips64S128AllOnes`: 将 SIMD 寄存器设置为全 1
    * `kMips64I32x4Splat`, `kMips64I64x2Splat`, `kMips64F64x2Splat`: 将标量值复制到 SIMD 寄存器的所有通道
    * `kMips64I32x4ExtractLane`, `kMips64I64x2ExtractLane`, `kMips64F64x2ExtractLane`: 提取 SIMD 寄存器的指定通道
    * `kMips64I32x4ReplaceLane`, `kMips64I64x2ReplaceLane`, `kMips64F64x2ReplaceLane`: 替换 SIMD 寄存器的指定通道
    * `kMips64I32x4Add`, `kMips64I32x4Sub`, `kMips64I64x2Add`, `kMips64I64x2Sub`, `kMips64I64x2Mul`: SIMD 整数加减乘
    * `kMips64F64x2Abs`, `kMips64F64x2Neg`, `kMips64F64x2Sqrt`, `kMips64F64x2Add`, `kMips64F64x2Sub`, `kMips64F64x2Mul`, `kMips64F64x2Div`, `kMips64F64x2Min`, `kMips64F64x2Max`, `kMips64F64x2Eq`, `kMips64F64x2Ne`, `kMips64F64x2Lt`, `kMips64F64x2Le`: SIMD 双精度浮点数运算
    * `kMips64F64x2Pmin`, `kMips64F64x2Pmax`, `kMips64F64x2Ceil`, `kMips64F64x2Floor`, `kMips64F64x2Trunc`, `kMips64F64x2NearestInt`: SIMD 双精度浮点数特殊运算
    * `kMips64F64x2ConvertLowI32x4S`, `kMips64F64x2ConvertLowI32x4U`, `kMips64F64x2PromoteLowF32x4`: SIMD 类型转换
    * `kMips64I64x2Neg`, `kMips64I64x2Shl`, `kMips64I64x2ShrS`, `kMips64I64x2ShrU`, `kMips64I64x2BitMask`, `kMips64I64x2Eq`, `kMips64I64x2Ne`, `kMips64I64x2GtS`, `kMips64I64x2GeS`, `kMips64I64x2Abs`, `kMips64I64x2SConvertI32x4Low`, `kMips64I64x2SConvertI32x4High`, `kMips64I64x2UConvertI32x4Low`, `kMips64I64x2UConvertI32x4High`: SIMD 64位整数运算
    * `kMips64ExtMulLow`, `kMips64ExtMulHigh`: SIMD 扩展乘法
* **其他指令:**
    * `kMips64Sync`: 生成 `sync` 指令，用于内存屏障
    * `kMips64ByteSwap64`, `kMips64ByteSwap32`: 字节交换
    * `kMips64AssertEqual`: 断言两个寄存器值相等

**关于文件类型:**

`v8/src/compiler/backend/mips64/code-generator-mips64.cc` **不是**以 `.tq` 结尾，因此它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。

**与 JavaScript 的关系 (举例):**

这段代码直接参与了 JavaScript 代码的执行过程。当 V8 编译 JavaScript 代码时，对于需要在 MIPS64 架构上执行的操作，最终会调用到这里的代码来生成相应的机器码。

例如，考虑以下简单的 JavaScript 代码:

```javascript
let a = 10;
let b = 5;
let sum = a + b;
```

在 V8 的编译过程中，对于 `a + b` 这个加法操作，编译器可能会生成一个中间表示，然后 `code-generator-mips64.cc` 中的代码（很可能涉及到算术运算相关的 `case`）会将这个中间表示翻译成 MIPS64 的加法指令，例如 `daddiu` (带立即数的 64 位加法)。

再比如，对于以下 JavaScript 代码的内存访问：

```javascript
let arr = [1, 2, 3];
let firstElement = arr[0];
```

编译器会生成加载数组元素的中间表示，然后 `code-generator-mips64.cc` 中 `kMips64Ld` 或类似的加载指令的 `case` 会被调用，生成从内存中加载 `arr[0]` 值的 MIPS64 指令。

对于 SIMD 操作，JavaScript 中可以使用 Typed Arrays 或 WebAssembly SIMD 指令：

```javascript
const a = new Float64Array([1.0, 2.0]);
const b = new Float64Array([3.0, 4.0]);
const c = new Float64Array(2);
c[0] = a[0] + b[0];
c[1] = a[1] + b[1];
```

或者使用 WebAssembly SIMD:

```wasm
;; ...
local.get 0 ;; load vector a
local.get 1 ;; load vector b
f64x2.add  ;; perform vector addition
local.set 2 ;; store the result
```

在这些情况下，`code-generator-mips64.cc` 中以 `kMips64F64x2Add` 开头的 `case` 语句会生成 MIPS64 MSA 指令 (例如 `fadd_d`) 来执行 SIMD 加法。

**代码逻辑推理 (假设输入与输出):**

假设输入的 `instr->opcode()` 是 `kMips64Lw`，并且 `i.OutputRegister()` 返回寄存器 `t0`，`i.MemoryOperand()` 返回内存操作数 `(s0)` (表示寄存器 s0 指向的内存地址)。

**假设输入:**
* `instr->opcode()`: `kMips64Lw`
* `i.OutputRegister()`: `t0`
* `i.MemoryOperand()`: `MemOperand(s0)`

**代码逻辑:**
```c++
case kMips64Lw:
  __ Lw(i.OutputRegister(), i.MemoryOperand());
  break;
```

**预期输出 (生成的汇编指令):**
```assembly
lw t0, (s0)
```
这条 MIPS64 汇编指令会将寄存器 `s0` 指向的内存地址中的一个字 (32位) 加载到寄存器 `t0` 中。

**用户常见的编程错误 (与此代码相关联):**

虽然开发者不会直接编写这个 C++ 代码，但理解其背后的逻辑有助于避免在编写 JavaScript 或 WebAssembly 时引入可能导致低效或错误机器码生成的问题。

一个与内存访问相关的常见错误是 **类型不匹配** 或 **越界访问**。 例如：

**JavaScript 示例 (可能导致生成错误的内存访问指令):**

```javascript
let arr = new Uint8Array(10);
let val = arr[15]; // 越界访问
```

或者

```javascript
let num = 10.5; // JavaScript 数字是双精度浮点数
let intArr = new Int32Array(1);
intArr[0] = num; // 精度丢失，可能生成截断存储指令
```

在这些情况下，编译器最终生成的机器码可能尝试访问超出分配范围的内存，或者存储了错误大小或类型的数值，而 `code-generator-mips64.cc` 中的加载/存储指令生成部分需要正确处理这些情况，但这取决于编译器的其他部分的分析和优化。

另一个常见的错误与 **原子操作** 有关，例如 **缺乏同步** 或 **错误地使用原子操作**。

**JavaScript 示例 (需要原子操作但可能没有正确使用):**

```javascript
let counter = 0;

function increment() {
  // 在多线程环境下，这可能不是线程安全的
  counter++;
}
```

如果需要线程安全地增加计数器，应该使用原子操作。`code-generator-mips64.cc` 中 `kAtomicAddWord32` 等指令的生成就与这种场景相关。如果开发者没有在 JavaScript 或更底层的代码中正确地使用原子操作 API，那么生成的非原子指令可能会导致竞争条件。

对于 **SIMD 操作**，常见的错误包括 **数据类型不匹配**、**通道索引错误** 或 **对齐问题**。

**JavaScript 示例 (使用 Typed Array 可能出错的情况):**

```javascript
const a = new Float32Array([1, 2, 3, 4]);
const b = new Float64Array(a.buffer); // 类型不匹配的视图

// 对 b 的操作可能产生意想不到的结果，因为数据被解释为不同的类型
console.log(b[0]);
```

或者在 SIMD 操作中使用了错误的通道索引，导致访问了错误的数据。

**总结:**

这段 `code-generator-mips64.cc` 的代码片段是 V8 编译器后端的重要组成部分，专门负责将中间代码转换为 MIPS64 架构的机器码，尤其关注内存访问、栈操作、原子操作和 SIMD 指令的生成。虽然开发者通常不直接修改此代码，但理解其功能有助于理解 JavaScript 代码的执行原理，并避免编写可能导致低效或错误机器码的程序。

### 提示词
```
这是目录为v8/src/compiler/backend/mips64/code-generator-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/code-generator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                    i.InputSimd
```