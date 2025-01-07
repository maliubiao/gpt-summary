Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/riscv/code-generator-riscv.cc`. The request has several constraints:

1. **List Functionality:** Describe what the code does.
2. **Torque Check:** Determine if the file is a Torque file based on its extension.
3. **JavaScript Relation:** If related to JavaScript, provide a JavaScript example.
4. **Logic Inference:** If there's code logic, give an example with inputs and outputs.
5. **Common Errors:**  Illustrate potential programming mistakes related to the code.
6. **Part of Series:** Acknowledge that this is part 4 of 6.
7. **Summarize Functionality:** Provide a concise summary of the code's purpose.

Let's break down the code snippet and address each point.

**Code Analysis:**

The code consists of a large `switch` statement based on `opcode`. Each `case` handles a specific RISC-V instruction or a higher-level operation that translates to a sequence of RISC-V instructions. Many of these cases involve:

* **Memory Operations:** Loading and storing data from memory. There are tagged, compressed, sandboxed, and protected variants.
* **Atomic Operations:** Performing atomic read-modify-write operations on memory.
* **SIMD (Vector) Operations:** Utilizing RISC-V Vector Extension (RVV) instructions for parallel processing of 128-bit data. These include arithmetic, logical, comparison, lane manipulation, and type conversion operations.
* **Assertions:** Checking conditions and potentially aborting if they are not met.

**Addressing the Constraints:**

1. **Functionality:** The code generates RISC-V machine code for various operations, especially those involving memory access, atomic operations, and SIMD (RVV) instructions. It acts as a backend for the V8 compiler, translating intermediate representations of code into architecture-specific instructions.

2. **Torque Check:** The filename ends in `.cc`, not `.tq`. Therefore, it's not a Torque source file.

3. **JavaScript Relation:**  Many of the operations, especially the SIMD instructions (prefixed with `kRiscvS128` or `kRiscvFxx`), directly correspond to JavaScript's WebAssembly (Wasm) SIMD instructions. The memory operations are fundamental to any JavaScript execution involving object access and data manipulation.

4. **Logic Inference:** Consider the `kRiscvI32x4ShrU` case (32-bit integer vector right shift unsigned):
    * **Assumption:** The input `i` represents an instruction with operands.
    * **Input:** Let `i.InputSimd128Register(0)` hold the vector `[8, 16, 24, 32]` and `i.InputInt5(1)` be `2`.
    * **Output:** The generated RISC-V code will perform a right shift by 2 bits on each element. The resulting vector in `i.OutputSimd128Register()` will be `[2, 4, 6, 8]`.

5. **Common Errors:** A common error related to SIMD operations is incorrect lane indexing or size specification. For example, in the `kRiscvI8x16ExtractLaneU` case, if the `i.InputInt8(1)` (the lane index) is out of bounds (0-15 for a 16-byte vector), the behavior is undefined and could lead to crashes or incorrect results.

6. **Part of Series:** Acknowledged.

7. **Summarize Functionality:** This section of `code-generator-riscv.cc` focuses on generating RISC-V assembly code for memory access, atomic operations, and, most significantly, SIMD (RVV) instructions used in WebAssembly, including arithmetic, logical, bitwise, and lane manipulation operations. It bridges the gap between V8's internal representation of code and the actual machine instructions executed by a RISC-V processor.
这是一个V8源代码文件，位于 `v8/src/compiler/backend/riscv/` 目录下，名为 `code-generator-riscv.cc`。 从其名称和路径来看，它属于 V8 编译器的后端部分，专门负责为 RISC-V 架构生成机器码。

**功能归纳:**

这个代码片段的主要功能是处理中间代码（可能是 Hydrogen IR 或 Machine IR）中的特定 RISC-V 指令节点，并将其转换为实际的 RISC-V 汇编指令。  具体来说，这段代码涵盖了以下几类操作：

1. **原子操作:**  实现了 RISC-V 的原子操作指令，例如原子加、减、与、或、异或等。这对于多线程环境下的数据同步至关重要。
2. **断言:**  生成断言指令，用于在运行时检查条件是否满足，如果不满足则触发程序中止。
3. **Tagged 指针处理:**  针对 V8 中 Tagged 指针的压缩和解压缩操作。Tagged 指针是 V8 用来区分对象类型的一种技术，将类型信息编码在指针的低位。
4. **Sandboxed 指针处理:**  处理沙箱环境下的指针编码和解码。
5. **Indirect 指针存储:**  存储间接指针。
6. **RISC-V Vector Extension (RVV) 指令:**  这是该代码片段的核心部分，大量处理了 RVV 指令，用于 SIMD (单指令多数据) 并行计算。这些指令涵盖了：
    * **加载和存储:** `kRiscvRvvSt`, `kRiscvRvvLd` 用于加载和存储向量数据。
    * **向量零初始化:** `kRiscvS128Zero` 用于将向量寄存器置零。
    * **向量加载并部分置零:** `kRiscvS128Load32Zero`, `kRiscvS128Load64Zero` 从内存加载数据，并将向量的其余部分置零。
    * **向量通道操作:** `kRiscvS128LoadLane`, `kRiscvS128StoreLane`, `kRiscvI8x16ExtractLaneU/S` 等用于加载、存储和提取向量的特定通道。
    * **向量扩展:** `kRiscvS128Load64ExtendS/U` 用于将加载的 64 位值扩展到 128 位向量。
    * **向量 Splat:** `kRiscvS128LoadSplat` 用于将内存中的单个值复制到整个向量。
    * **向量全 1:** `kRiscvS128AllOnes` 用于生成一个所有位都为 1 的向量。
    * **向量选择:** `kRiscvS128Select` 用于根据掩码选择两个向量的元素。
    * **向量取反:** `kRiscvVnot` 用于按位取反向量。
    * **向量常量:** `kRiscvS128Const` 用于加载向量常量。
    * **向量 Gather:** `kRiscvVrgather` 用于根据索引从向量中收集元素。
    * **向量 Slide Down:** `kRiscvVslidedown` 用于将向量元素向下移动。
    * **向量位移:** `kRiscvI8x16ShrU/S`, `kRiscvI16x8ShrU/S`, `kRiscvI32x4ShrU/S`, `kRiscvI64x2ShrU/S`, `kRiscvI8x16Shl`, `kRiscvI16x8Shl`, `kRiscvI32x4Shl`, `kRiscvI64x2Shl` 用于执行向量的逻辑和算术右移以及左移操作。
    * **向量截断饱和转换:** `kRiscvI32x4TruncSatF64x2SZero`, `kRiscvI32x4TruncSatF64x2UZero` 用于将浮点数转换为整数并进行饱和处理。
    * **向量绝对值:** `kRiscvVAbs` 用于计算向量元素的绝对值。
    * **向量通道替换:** `kRiscvI8x16ReplaceLane`, `kRiscvI16x8ReplaceLane`, `kRiscvI64x2ReplaceLane`, `kRiscvI32x4ReplaceLane` 用于替换向量中的特定通道。
    * **向量 Any True / All True:** `kRiscvV128AnyTrue`, `kRiscvVAllTrue` 用于检查向量中是否有任何或所有元素为真。
    * **向量 Shuffle:** `kRiscvI8x16Shuffle` 用于重新排列向量中的字节。
    * **向量 Popcnt:** `kRiscvI8x16Popcnt` 用于计算向量中每个字节的置位位数。
    * **浮点向量操作:**  `kRiscvF64x2NearestInt`, `kRiscvF64x2Trunc`, `kRiscvF64x2Sqrt`, `kRiscvF64x2Abs`, `kRiscvF64x2Ceil`, `kRiscvF64x2Floor`, `kRiscvF64x2ReplaceLane`, `kRiscvF64x2Pmax`, `kRiscvF64x2Pmin`, `kRiscvF64x2ExtractLane`, `kRiscvF64x2PromoteLowF32x4`, `kRiscvF64x2ConvertLowI32x4S/U`, `kRiscvF64x2Qfma/Qfms`, `kRiscvF32x4ExtractLane`, `kRiscvF32x4Trunc`, `kRiscvF32x4NearestInt`, `kRiscvF32x4DemoteF64x2Zero`, `kRiscvF32x4Abs`, `kRiscvF32x4Ceil`, `kRiscvF32x4Floor`, `kRiscvF32x4UConvertI32x4`, `kRiscvF32x4SConvertI32x4`, `kRiscvF32x4ReplaceLane`, `kRiscvF32x4Pmax/Pmin`, `kRiscvF32x4Sqrt`, `kRiscvF32x4Qfma/Qfms` 等，涵盖了双精度和单精度浮点向量的各种运算，包括取整、截断、平方根、绝对值、ceil、floor、通道替换、最大/最小值、类型转换和融合乘加/减。
    * **整数向量类型转换:** `kRiscvI64x2SConvertI32x4Low/High`, `kRiscvI64x2UConvertI32x4Low/High` 用于将 32 位整数向量转换为 64 位整数向量。

**关于文件类型:**

`v8/src/compiler/backend/riscv/code-generator-riscv.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 的关系:**

这段代码与 JavaScript 的功能有密切关系，主要体现在 **WebAssembly (Wasm)** 的支持上。  V8 是一个 JavaScript 引擎，它也负责执行 WebAssembly 代码。

许多以 `kRiscvS128` 或 `kRiscvFxx` 开头的指令都直接对应于 WebAssembly 的 SIMD 指令集。 例如：

* `kRiscvS128Load32Zero` 对应于 Wasm 的 `v128.load32_zero` 指令。
* `kRiscvI32x4Shl` 对应于 Wasm 的 `i32x4.shl` 指令。
* `kRiscvF64x2Add` (虽然这段代码中没有直接展示 `Add`，但可以推断存在类似的指令) 对应于 Wasm 的 `f64x2.add` 指令。

**JavaScript 示例:**

以下 JavaScript 示例展示了如何使用 WebAssembly 的 SIMD 功能，这些功能最终会通过 V8 的代码生成器（包括 `code-generator-riscv.cc`）转换为 RISC-V 汇编代码：

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
const buffer = new Uint8Array(memory.buffer);

// 创建一个包含 SIMD 指令的 WebAssembly 模块
const module = new WebAssembly.Module(Uint8Array.from([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x04,
  0x01, 0x7e, 0x6b, 0x03, 0x01, 0x01, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64,
  0x00, 0x00, 0x0a, 0x08, 0x01, 0x06, 0x00, 0x20, 0x20, 0xfd, 0x0b, 0x0b
]));

const instance = new WebAssembly.Instance(module, { mem: memory });
const wasmVec = new Float64Array(memory.buffer, 0, 2);
wasmVec[0] = 1.5;
wasmVec[1] = 2.5;

// 调用 WebAssembly 导出函数，该函数可能使用了 SIMD 指令
const result = instance.exports.add(1.0, 2.0);
console.log(result); // 输出可能是 SIMD 运算的结果
```

**代码逻辑推理示例:**

**假设输入:**

* `opcode` 为 `kRiscvI32x4Shl` (32位整数向量左移)
* `i.InputSimd128Register(0)` 包含向量 `[1, 2, 3, 4]`
* `i.InputInt5(1)` 的值为 `2` (左移位数)

**输出:**

生成的 RISC-V 汇编代码将执行以下操作：

1. 设置向量单元大小为 32 位 (`__ VU.set(kScratchReg, E32, m1);`).
2. 执行向量左移指令 `vsll.vi v[output_register], v[input_register_0], 2`,  其中 `v[output_register]` 是输出向量寄存器，`v[input_register_0]` 是输入向量寄存器，`2` 是左移的立即数。

最终，`i.OutputSimd128Register()` 将包含向量 `[4, 8, 12, 16]`。

**用户常见的编程错误示例:**

在使用 SIMD 指令时，用户可能会犯以下错误：

1. **类型不匹配:**  例如，尝试将浮点向量作为整数向量进行操作，或者将位数不匹配的向量进行运算。
   ```c++
   // 假设在 JavaScript (Wasm) 中定义了 f32x4 类型的向量
   // 错误地尝试将其作为 i32x4 进行左移
   // 对应的 code-generator-riscv.cc 中的处理可能会出错或产生未预期结果
   case kRiscvI32x4Shl: {
       // ... 但是输入实际上是浮点向量
   }
   ```
2. **越界访问:**  在进行 `ExtractLane` 或 `ReplaceLane` 操作时，使用超出向量边界的索引。
   ```c++
   case kRiscvI8x16ExtractLaneU: {
       // 假设 i.InputInt8(1) 的值大于 15 (对于 16 字节的向量)
       __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                        i.InputInt8(1)); // 索引越界
       // ...
   }
   ```
3. **位移量过大:**  对于位移操作，使用超过数据类型大小的位移量。例如，对 32 位整数左移 32 位或更多。虽然 RISC-V 的向量位移指令通常会取模，但理解其行为至关重要。
   ```c++
   case kRiscvI32x4Shl: {
       // 如果 i.InputInt5(1) 的值是 32 或更大
       __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputInt5(1) % 32); // 实际位移量会取模
       // 用户可能期望的是全部变为 0
   }
   ```

**第 4 部分功能归纳:**

作为第 4 部分，这个代码片段主要集中在为 RISC-V 架构生成 **向量 (SIMD) 指令** 的机器码，尤其是针对 WebAssembly 的支持。它还涵盖了一些基本的原子操作、断言以及 Tagged 和 Sandboxed 指针的处理。 核心功能是利用 RISC-V 的向量扩展指令集 (RVV) 来实现高效的并行计算。

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/code-generator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/code-generator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
      i.InputRegister(2));                                      \
    break;
      ATOMIC_BINOP_CASE(Add, Add32, Add64, amoadd_w)  // todo: delete 64
      ATOMIC_BINOP_CASE(Sub, Sub32, Sub64, Amosub_w)  // todo: delete 64
      ATOMIC_BINOP_CASE(And, And, And, amoand_w)
      ATOMIC_BINOP_CASE(Or, Or, Or, amoor_w)
      ATOMIC_BINOP_CASE(Xor, Xor, Xor, amoxor_w)
#undef ATOMIC_BINOP_CASE
#endif
    case kRiscvAssertEqual:
      __ Assert(eq, static_cast<AbortReason>(i.InputOperand(2).immediate()),
                i.InputRegister(0), Operand(i.InputRegister(1)));
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvStoreCompressTagged: {
      MemOperand mem = i.MemoryOperand(1);
      __ StoreTaggedField(i.InputOrZeroRegister(0), mem);
      break;
    }
    case kRiscvLoadDecompressTaggedSigned: {
      CHECK(instr->HasOutput());
      Register result = i.OutputRegister();
      MemOperand operand = i.MemoryOperand();
      __ DecompressTaggedSigned(result, operand);
      break;
    }
    case kRiscvLoadDecompressTagged: {
      CHECK(instr->HasOutput());
      Register result = i.OutputRegister();
      MemOperand operand = i.MemoryOperand();
      __ DecompressTagged(result, operand);
      break;
    }
    case kRiscvLoadDecodeSandboxedPointer:
      __ LoadSandboxedPointerField(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvStoreEncodeSandboxedPointer: {
      MemOperand mem = i.MemoryOperand(1);
      __ StoreSandboxedPointerField(i.InputOrZeroRegister(0), mem);
      break;
    }
    case kRiscvStoreIndirectPointer: {
      MemOperand mem = i.MemoryOperand(1);
      __ StoreIndirectPointerField(i.InputOrZeroRegister(0), mem);
      break;
    }
    case kRiscvAtomicLoadDecompressTaggedSigned:
      __ AtomicDecompressTaggedSigned(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvAtomicLoadDecompressTagged:
      __ AtomicDecompressTagged(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvAtomicStoreCompressTagged: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ AtomicStoreTaggedField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kRiscvLoadDecompressProtected: {
      __ DecompressProtected(i.OutputRegister(), i.MemoryOperand(), trapper);
      break;
    }
#endif
    case kRiscvRvvSt: {
      (__ VU).set(kScratchReg, VSew::E8, Vlmul::m1);
      auto memOperand = i.MemoryOperand(1);
      Register dst = memOperand.offset() == 0 ? memOperand.rm() : kScratchReg;
      if (memOperand.offset() != 0) {
        __ AddWord(dst, memOperand.rm(), memOperand.offset());
      }
      trapper(__ pc_offset());
      __ vs(i.InputSimd128Register(0), dst, 0, VSew::E8);
      break;
    }
    case kRiscvRvvLd: {
      (__ VU).set(kScratchReg, VSew::E8, Vlmul::m1);
      Register src = i.MemoryOperand().offset() == 0 ? i.MemoryOperand().rm()
                                                     : kScratchReg;
      if (i.MemoryOperand().offset() != 0) {
        __ AddWord(src, i.MemoryOperand().rm(), i.MemoryOperand().offset());
      }
      trapper(__ pc_offset());
      __ vl(i.OutputSimd128Register(), src, 0, VSew::E8);
      break;
    }
    case kRiscvS128Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E8, m1);
      __ vmv_vx(dst, zero_reg);
      break;
    }
    case kRiscvS128Load32Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E32, m1);
      __ Load32U(kScratchReg, i.MemoryOperand(), trapper);
      __ vmv_sx(dst, kScratchReg);
      break;
    }
    case kRiscvS128Load64Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E64, m1);
#if V8_TARGET_ARCH_RISCV64
      __ LoadWord(kScratchReg, i.MemoryOperand(), trapper);
      __ vmv_sx(dst, kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
      __ LoadDouble(kScratchDoubleReg, i.MemoryOperand(), trapper);
      __ vfmv_sf(dst, kScratchDoubleReg);
#endif
      break;
    }
    case kRiscvS128LoadLane: {
      Simd128Register dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      auto sz = LaneSizeField::decode(opcode);
      __ LoadLane(sz, dst, i.InputUint8(1), i.MemoryOperand(2), trapper);
      break;
    }
    case kRiscvS128StoreLane: {
      Simd128Register src = i.InputSimd128Register(0);
      DCHECK_EQ(src, i.InputSimd128Register(0));
      auto sz = LaneSizeField::decode(opcode);
      __ StoreLane(sz, src, i.InputUint8(1), i.MemoryOperand(2), trapper);
      break;
    }
    case kRiscvS128Load64ExtendS: {
      __ VU.set(kScratchReg, E64, m1);
#if V8_TARGET_ARCH_RISCV64
      __ LoadWord(kScratchReg, i.MemoryOperand(), trapper);
      __ vmv_vx(kSimd128ScratchReg, kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
      __ LoadDouble(kScratchDoubleReg, i.MemoryOperand(), trapper);
      __ vfmv_vf(kSimd128ScratchReg, kScratchDoubleReg);
#endif
      __ VU.set(kScratchReg, i.InputInt8(2), m1);
      __ vsext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvS128Load64ExtendU: {
      __ VU.set(kScratchReg, E64, m1);
#if V8_TARGET_ARCH_RISCV64
      __ LoadWord(kScratchReg, i.MemoryOperand(), trapper);
      __ vmv_vx(kSimd128ScratchReg, kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
      __ LoadDouble(kScratchDoubleReg, i.MemoryOperand(), trapper);
      __ vfmv_vf(kSimd128ScratchReg, kScratchDoubleReg);
#endif
      __ VU.set(kScratchReg, i.InputInt8(2), m1);
      __ vzext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvS128LoadSplat: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      switch (i.InputInt8(2)) {
        case E8:
          __ Lb(kScratchReg, i.MemoryOperand(), trapper);
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
          break;
        case E16:
          __ Lh(kScratchReg, i.MemoryOperand(), trapper);
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
          break;
        case E32:
          __ Lw(kScratchReg, i.MemoryOperand(), trapper);
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
          break;
        case E64:
#if V8_TARGET_ARCH_RISCV64
          __ LoadWord(kScratchReg, i.MemoryOperand(), trapper);
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
          __ LoadDouble(kScratchDoubleReg, i.MemoryOperand(), trapper);
          __ vfmv_vf(i.OutputSimd128Register(), kScratchDoubleReg);
#endif
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kRiscvS128AllOnes: {
      __ VU.set(kScratchReg, E8, m1);
      __ vmv_vx(i.OutputSimd128Register(), zero_reg);
      __ vnot_vv(i.OutputSimd128Register(), i.OutputSimd128Register());
      break;
    }
    case kRiscvS128Select: {
      __ VU.set(kScratchReg, E8, m1);
      __ vand_vv(kSimd128ScratchReg, i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      __ vnot_vv(kSimd128ScratchReg2, i.InputSimd128Register(0));
      __ vand_vv(kSimd128ScratchReg2, i.InputSimd128Register(2),
                 kSimd128ScratchReg2);
      __ vor_vv(i.OutputSimd128Register(), kSimd128ScratchReg,
                kSimd128ScratchReg2);
      break;
    }
    case kRiscvVnot: {
      (__ VU).set(kScratchReg, VSew::E8, Vlmul::m1);
      __ vnot_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvS128Const: {
      Simd128Register dst = i.OutputSimd128Register();
      uint8_t imm[16];
      *reinterpret_cast<uint64_t*>(imm) =
          make_uint64(i.InputUint32(1), i.InputUint32(0));
      *(reinterpret_cast<uint64_t*>(imm) + 1) =
          make_uint64(i.InputUint32(3), i.InputUint32(2));
      __ WasmRvvS128const(dst, imm);
      break;
    }
    case kRiscvVrgather: {
      Simd128Register index = i.InputSimd128Register(0);
      if (!(instr->InputAt(1)->IsImmediate())) {
        index = i.InputSimd128Register(1);
      } else {
#if V8_TARGET_ARCH_RISCV64
        __ VU.set(kScratchReg, E64, m1);
        __ li(kScratchReg, i.InputInt64(1));
        __ vmv_vi(kSimd128ScratchReg3, -1);
        __ vmv_sx(kSimd128ScratchReg3, kScratchReg);
        index = kSimd128ScratchReg3;
#elif V8_TARGET_ARCH_RISCV32
        int64_t intput_int64 = i.InputInt64(1);
        int32_t input_int32[2];
        memcpy(input_int32, &intput_int64, sizeof(intput_int64));
        __ VU.set(kScratchReg, E32, m1);
        __ li(kScratchReg, input_int32[1]);
        __ vmv_vx(kSimd128ScratchReg3, kScratchReg);
        __ li(kScratchReg, input_int32[0]);
        __ vmv_sx(kSimd128ScratchReg3, kScratchReg);
        index = kSimd128ScratchReg3;
#endif
      }
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (i.OutputSimd128Register() == i.InputSimd128Register(0)) {
        __ vrgather_vv(kSimd128ScratchReg, i.InputSimd128Register(0), index);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      } else {
        __ vrgather_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                       index);
      }
      break;
    }
    case kRiscvVslidedown: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsImmediate()) {
        DCHECK(is_uint5(i.InputInt32(1)));
        __ vslidedown_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                         i.InputInt5(1));
      } else {
        __ vslidedown_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                         i.InputRegister(1));
      }
      break;
    }
    case kRiscvI8x16ExtractLaneU: {
      __ VU.set(kScratchReg, E8, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vmv_xs(i.OutputRegister(), kSimd128ScratchReg);
      __ slli(i.OutputRegister(), i.OutputRegister(), sizeof(void*) * 8 - 8);
      __ srli(i.OutputRegister(), i.OutputRegister(), sizeof(void*) * 8 - 8);
      break;
    }
    case kRiscvI8x16ExtractLaneS: {
      __ VU.set(kScratchReg, E8, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vmv_xs(i.OutputRegister(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI16x8ExtractLaneU: {
      __ VU.set(kScratchReg, E16, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vmv_xs(i.OutputRegister(), kSimd128ScratchReg);
      __ slli(i.OutputRegister(), i.OutputRegister(), sizeof(void*) * 8 - 16);
      __ srli(i.OutputRegister(), i.OutputRegister(), sizeof(void*) * 8 - 16);
      break;
    }
    case kRiscvI16x8ExtractLaneS: {
      __ VU.set(kScratchReg, E16, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vmv_xs(i.OutputRegister(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI8x16ShrU: {
      __ VU.set(kScratchReg, E8, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ andi(i.InputRegister(1), i.InputRegister(1), 8 - 1);
        __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsrl_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 8);
      }
      break;
    }
    case kRiscvI16x8ShrU: {
      __ VU.set(kScratchReg, E16, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ andi(i.InputRegister(1), i.InputRegister(1), 16 - 1);
        __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsrl_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 16);
      }
      break;
    }
    case kRiscvI32x4TruncSatF64x2SZero: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmv_vx(kSimd128ScratchReg, zero_reg);
      __ vmfeq_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(0));
      __ vmv_vv(kSimd128ScratchReg3, i.InputSimd128Register(0));
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vfncvt_x_f_w(kSimd128ScratchReg, kSimd128ScratchReg3, MaskType::Mask);
      __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI32x4TruncSatF64x2UZero: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmv_vx(kSimd128ScratchReg, zero_reg);
      __ vmfeq_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(0));
      __ vmv_vv(kSimd128ScratchReg3, i.InputSimd128Register(0));
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vfncvt_xu_f_w(kSimd128ScratchReg, kSimd128ScratchReg3, MaskType::Mask);
      __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI32x4ShrU: {
      __ VU.set(kScratchReg, E32, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsrl_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 32);
      }
      break;
    }
    case kRiscvI64x2ShrU: {
      __ VU.set(kScratchReg, E64, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        if (is_uint5(i.InputInt6(1) % 64)) {
          __ vsrl_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt6(1) % 64);
        } else {
          __ li(kScratchReg, i.InputInt6(1) % 64);
          __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
        }
      }
      break;
    }
    case kRiscvI8x16ShrS: {
      __ VU.set(kScratchReg, E8, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsra_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 8);
      }
      break;
    }
    case kRiscvI16x8ShrS: {
      __ VU.set(kScratchReg, E16, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsra_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 16);
      }
      break;
    }
    case kRiscvI32x4ShrS: {
      __ VU.set(kScratchReg, E32, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsra_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 32);
      }
      break;
    }
    case kRiscvI64x2ShrS: {
      __ VU.set(kScratchReg, E64, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        if (is_uint5(i.InputInt6(1) % 64)) {
          __ vsra_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt6(1) % 64);
        } else {
          __ li(kScratchReg, i.InputInt6(1) % 64);
          __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
        }
      }
      break;
    }
    case kRiscvI32x4ExtractLane: {
      __ WasmRvvExtractLane(i.OutputRegister(), i.InputSimd128Register(0),
                            i.InputInt8(1), E32, m1);
      break;
    }
    case kRiscvVAbs: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ vmslt_vx(v0, i.InputSimd128Register(0), zero_reg);
      __ vneg_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 MaskType::Mask);
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case kRiscvI64x2ExtractLane: {
      __ WasmRvvExtractLane(i.OutputRegister(), i.InputSimd128Register(0),
                            i.InputInt8(1), E64, m1);
      break;
    }
#elif V8_TARGET_ARCH_RISCV32
    case kRiscvI64x2ExtractLane: {
      uint8_t imm_lane_idx = i.InputInt8(1);
      __ VU.set(kScratchReg, E32, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       (imm_lane_idx << 0x1) + 1);
      __ vmv_xs(i.OutputRegister(1), kSimd128ScratchReg);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       (imm_lane_idx << 0x1));
      __ vmv_xs(i.OutputRegister(0), kSimd128ScratchReg);
      break;
    }
#endif
    case kRiscvI8x16Shl: {
      __ VU.set(kScratchReg, E8, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 8);
      }
      break;
    }
    case kRiscvI16x8Shl: {
      __ VU.set(kScratchReg, E16, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 16);
      }
      break;
    }
    case kRiscvI32x4Shl: {
      __ VU.set(kScratchReg, E32, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 32);
      }
      break;
    }
    case kRiscvI64x2Shl: {
      __ VU.set(kScratchReg, E64, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        if (is_int5(i.InputInt6(1) % 64)) {
          __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt6(1) % 64);
        } else {
          __ li(kScratchReg, i.InputInt6(1) % 64);
          __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
        }
      }
      break;
    }
    case kRiscvI8x16ReplaceLane: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E64, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ VU.set(kScratchReg, E8, m1);
      __ vmerge_vx(dst, i.InputRegister(2), src);
      break;
    }
    case kRiscvI16x8ReplaceLane: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E16, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vmerge_vx(dst, i.InputRegister(2), src);
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case kRiscvI64x2ReplaceLane: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E64, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vmerge_vx(dst, i.InputRegister(2), src);
      break;
    }
#elif V8_TARGET_ARCH_RISCV32
    case kRiscvI64x2ReplaceLaneI32Pair: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      Register int64_low = i.InputRegister(2);
      Register int64_high = i.InputRegister(3);
      __ VU.set(kScratchReg, E32, m1);
      __ vmv_vx(kSimd128ScratchReg, int64_high);
      __ vmv_sx(kSimd128ScratchReg, int64_low);
      __ VU.set(kScratchReg, E64, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vfmv_fs(kScratchDoubleReg, kSimd128ScratchReg);
      __ vfmerge_vf(dst, kScratchDoubleReg, src);
      break;
    }
#endif
    case kRiscvI32x4ReplaceLane: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E32, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vmerge_vx(dst, i.InputRegister(2), src);
      break;
    }
    case kRiscvV128AnyTrue: {
      __ VU.set(kScratchReg, E8, m1);
      Register dst = i.OutputRegister();
      Label t;
      __ vmv_sx(kSimd128ScratchReg, zero_reg);
      __ vredmaxu_vs(kSimd128ScratchReg, i.InputSimd128Register(0),
                     kSimd128ScratchReg);
      __ vmv_xs(dst, kSimd128ScratchReg);
      __ beq(dst, zero_reg, &t);
      __ li(dst, 1);
      __ bind(&t);
      break;
    }
    case kRiscvVAllTrue: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      Register dst = i.OutputRegister();
      Label notalltrue;
      __ vmv_vi(kSimd128ScratchReg, -1);
      __ vredminu_vs(kSimd128ScratchReg, i.InputSimd128Register(0),
                     kSimd128ScratchReg);
      __ vmv_xs(dst, kSimd128ScratchReg);
      __ beqz(dst, &notalltrue);
      __ li(dst, 1);
      __ bind(&notalltrue);
      break;
    }
    case kRiscvI8x16Shuffle: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);

#if V8_TARGET_ARCH_RISCV64
      int64_t imm1 = make_uint64(i.InputInt32(3), i.InputInt32(2));
      int64_t imm2 = make_uint64(i.InputInt32(5), i.InputInt32(4));
      __ VU.set(kScratchReg, VSew::E64, Vlmul::m1);
      __ li(kScratchReg, imm2);
      __ vmv_sx(kSimd128ScratchReg2, kScratchReg);
      __ vslideup_vi(kSimd128ScratchReg, kSimd128ScratchReg2, 1);
      __ li(kScratchReg, imm1);
      __ vmv_sx(kSimd128ScratchReg, kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
      __ VU.set(kScratchReg, VSew::E32, Vlmul::m1);
      __ li(kScratchReg, i.InputInt32(5));
      __ vmv_vx(kSimd128ScratchReg2, kScratchReg);
      __ li(kScratchReg, i.InputInt32(4));
      __ vmv_sx(kSimd128ScratchReg2, kScratchReg);
      __ li(kScratchReg, i.InputInt32(3));
      __ vmv_vx(kSimd128ScratchReg, kScratchReg);
      __ li(kScratchReg, i.InputInt32(2));
      __ vmv_sx(kSimd128ScratchReg, kScratchReg);
      __ vslideup_vi(kSimd128ScratchReg, kSimd128ScratchReg2, 2);
#endif

      __ VU.set(kScratchReg, E8, m1);
      if (dst == src0) {
        __ vmv_vv(kSimd128ScratchReg2, src0);
        src0 = kSimd128ScratchReg2;
      } else if (dst == src1) {
        __ vmv_vv(kSimd128ScratchReg2, src1);
        src1 = kSimd128ScratchReg2;
      }
      __ vrgather_vv(dst, src0, kSimd128ScratchReg);
      __ vadd_vi(kSimd128ScratchReg, kSimd128ScratchReg, -16);
      __ vrgather_vv(kSimd128ScratchReg3, src1, kSimd128ScratchReg);
      __ vor_vv(dst, dst, kSimd128ScratchReg3);
      break;
    }
    case kRiscvI8x16Popcnt: {
      VRegister dst = i.OutputSimd128Register(),
                src = i.InputSimd128Register(0);
      Label t;

      __ VU.set(kScratchReg, E8, m1);
      __ vmv_vv(kSimd128ScratchReg, src);
      __ vmv_vv(dst, kSimd128RegZero);

      __ bind(&t);
      __ vmsne_vv(v0, kSimd128ScratchReg, kSimd128RegZero);
      __ vadd_vi(dst, dst, 1, Mask);
      __ vadd_vi(kSimd128ScratchReg2, kSimd128ScratchReg, -1, Mask);
      __ vand_vv(kSimd128ScratchReg, kSimd128ScratchReg, kSimd128ScratchReg2);
      // kScratchReg = -1 if kSimd128ScratchReg == 0 i.e. no active element
      __ vfirst_m(kScratchReg, kSimd128ScratchReg);
      __ bgez(kScratchReg, &t);
      break;
    }
    case kRiscvF64x2NearestInt: {
      __ Round_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2Trunc: {
      __ Trunc_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2Sqrt: {
      __ VU.set(kScratchReg, E64, m1);
      __ vfsqrt_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Abs: {
      __ VU.set(kScratchReg, VSew::E64, Vlmul::m1);
      __ vfabs_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Ceil: {
      __ Ceil_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2Floor: {
      __ Floor_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2ReplaceLane: {
      __ VU.set(kScratchReg, E64, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vfmerge_vf(i.OutputSimd128Register(), i.InputSingleRegister(2),
                    i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Pmax: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmflt_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vmerge_vv(i.OutputSimd128Register(), i.InputSimd128Register(1),
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Pmin: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmflt_vv(v0, i.InputSimd128Register(1), i.InputSimd128Register(0));
      __ vmerge_vv(i.OutputSimd128Register(), i.InputSimd128Register(1),
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2ExtractLane: {
      __ VU.set(kScratchReg, E64, m1);
      if (is_uint5(i.InputInt8(1))) {
        __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                         i.InputInt8(1));
      } else {
        __ li(kScratchReg, i.InputInt8(1));
        __ vslidedown_vx(kSimd128ScratchReg, i.InputSimd128Register(0),
                         kScratchReg);
      }
      __ vfmv_fs(i.OutputDoubleRegister(), kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2PromoteLowF32x4: {
      __ VU.set(kScratchReg, E32, mf2);
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vfwcvt_f_f_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else {
        __ vfwcvt_f_f_v(kSimd128ScratchReg3, i.InputSimd128Register(0));
        __ VU.set(kScratchReg, E64, m1);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg3);
      }
      break;
    }
    case kRiscvF64x2ConvertLowI32x4S: {
      __ VU.set(kScratchReg, E32, mf2);
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vfwcvt_f_x_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else {
        __ vfwcvt_f_x_v(kSimd128ScratchReg3, i.InputSimd128Register(0));
        __ VU.set(kScratchReg, E64, m1);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg3);
      }
      break;
    }
    case kRiscvF64x2ConvertLowI32x4U: {
      __ VU.set(kScratchReg, E32, mf2);
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vfwcvt_f_xu_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else {
        __ vfwcvt_f_xu_v(kSimd128ScratchReg3, i.InputSimd128Register(0));
        __ VU.set(kScratchReg, E64, m1);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg3);
      }
      break;
    }
    case kRiscvF64x2Qfma: {
      __ VU.set(kScratchReg, E64, m1);
      __ vfmadd_vv(i.InputSimd128Register(0), i.InputSimd128Register(1),
                   i.InputSimd128Register(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Qfms: {
      __ VU.set(kScratchReg, E64, m1);
      __ vfnmsub_vv(i.InputSimd128Register(0), i.InputSimd128Register(1),
                    i.InputSimd128Register(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4ExtractLane: {
      __ VU.set(kScratchReg, E32, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vfmv_fs(i.OutputDoubleRegister(), kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4Trunc: {
      __ Trunc_f(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4NearestInt: {
      __ Round_f(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4DemoteF64x2Zero: {
      __ VU.set(kScratchReg, E32, mf2);
      __ vfncvt_f_f_w(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ VU.set(kScratchReg, E32, m1);
      __ vmv_vi(v0, 12);
      __ vmerge_vx(i.OutputSimd128Register(), zero_reg,
                   i.OutputSimd128Register());
      break;
    }
    case kRiscvF32x4Abs: {
      __ VU.set(kScratchReg, VSew::E32, Vlmul::m1);
      __ vfabs_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Ceil: {
      __ Ceil_f(i.OutputSimd128Register(), i.InputSimd128Register(0),
                kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4Floor: {
      __ Floor_f(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4UConvertI32x4: {
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vfcvt_f_xu_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4SConvertI32x4: {
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vfcvt_f_x_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4ReplaceLane: {
      __ VU.set(kScratchReg, E32, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ fmv_x_w(kScratchReg, i.InputSingleRegister(2));
      __ vmerge_vx(i.OutputSimd128Register(), kScratchReg,
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Pmax: {
      __ VU.set(kScratchReg, E32, m1);
      __ vmflt_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vmerge_vv(i.OutputSimd128Register(), i.InputSimd128Register(1),
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Pmin: {
      __ VU.set(kScratchReg, E32, m1);
      __ vmflt_vv(v0, i.InputSimd128Register(1), i.InputSimd128Register(0));
      __ vmerge_vv(i.OutputSimd128Register(), i.InputSimd128Register(1),
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Sqrt: {
      __ VU.set(kScratchReg, E32, m1);
      __ vfsqrt_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Qfma: {
      __ VU.set(kScratchReg, E32, m1);
      __ vfmadd_vv(i.InputSimd128Register(0), i.InputSimd128Register(1),
                   i.InputSimd128Register(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Qfms: {
      __ VU.set(kScratchReg, E32, m1);
      __ vfnmsub_vv(i.InputSimd128Register(0), i.InputSimd128Register(1),
                    i.InputSimd128Register(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvI64x2SConvertI32x4Low: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmv_vv(kSimd128ScratchReg, i.InputSimd128Register(0));
      __ vsext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);

      break;
    }
    case kRiscvI64x2SConvertI32x4High: {
      __ VU.set(kScratchReg, E32, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0), 2);
      __ VU.set(kScratchReg, E64, m1);
      __ vsext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI64x2UConvertI32x4Low: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmv_vv(kSimd128ScratchReg, i.InputSimd128Register(0));
      __ vzext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI64x2UConvertI32x4High: {
      __ VU.set(kScratchReg, E32, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0), 2);
      __ VU.set(kScratchReg, E64, m1);
      __ vzext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
  
"""


```