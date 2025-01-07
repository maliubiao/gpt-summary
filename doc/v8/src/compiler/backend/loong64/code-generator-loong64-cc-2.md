Response:
My goal is to analyze the provided C++ code snippet and fulfill the user's request. Here's a breakdown of my thought process:

1. **Understanding the Context:** The user explicitly states this is a part of `v8/src/compiler/backend/loong64/code-generator-loong64.cc`. This immediately tells me it's related to V8's code generation for the LoongArch 64-bit architecture. The mention of "part 3 of 4" suggests a larger file, and this section likely focuses on a specific aspect of code generation.

2. **Identifying the Core Functionality:**  The code consists of a large `switch` statement within the `AssembleArchInstruction` function. This function takes an `Instruction*` as input, which represents a higher-level instruction from V8's intermediate representation. The `switch` statement dispatches based on the `arch_opcode()` of the instruction, which are specific to the LoongArch backend (e.g., `kLoong64Float64ToUint32`, `kLoong64Ld_w`, etc.).

3. **Analyzing Individual Cases:** I began examining the different `case` blocks within the `switch`. Each case corresponds to a specific LoongArch instruction or a higher-level operation that needs to be translated into LoongArch assembly. I observed patterns:
    * **Direct Assembly Emission:** Many cases directly emit LoongArch assembly instructions using the `__` macro (which seems to be an alias for methods of the `MacroAssembler`). Examples include `__ movfcsr2gr`, `__ And`, `__ Ld_w`, `__ St_b`, etc.
    * **Operand Conversion:** The `Loong64OperandConverter` class (`i`) is used to extract operands (registers, memory locations, immediates) from the V8 instruction in a LoongArch-specific way.
    * **Helper Functions:**  Some cases call helper functions like `RecordTrapInfoIfNeeded`, `SignExtend`, and `AssembleBranchToLabels`. These encapsulate more complex logic.
    * **Floating-Point Operations:**  Cases with `kLoong64Float...` prefixes deal with floating-point conversions and manipulations, often using specific FPU registers.
    * **Memory Access:**  Cases like `kLoong64Ld_*` and `kLoong64St_*` handle loading and storing data from memory.
    * **Atomic Operations:** Cases with `kAtomic...` prefixes implement atomic memory operations.
    * **Stack Manipulation:** Cases like `kLoong64Push`, `kLoong64Peek`, and `kLoong64StackClaim` manage the stack.
    * **Bit Manipulation:**  Cases like `kLoong64ByteSwap*` perform bitwise operations.

4. **Inferring Overall Function:** Based on the individual cases, I concluded that the primary function of this code is to *translate V8's machine-independent intermediate representation (IR) instructions into concrete LoongArch assembly code*. It acts as the "backend" for the LoongArch architecture within V8's compiler pipeline.

5. **Addressing Specific User Questions:**

    * **Functionality Listing:** I systematically listed the key functionalities observed in the code, such as integer and floating-point arithmetic, memory access, atomic operations, stack manipulation, and bit manipulation.
    * **Torque Source:** I checked the file extension (`.cc`) and correctly identified it as a C++ source file, not a Torque file.
    * **JavaScript Relationship:** I focused on the cases involving type conversions (e.g., `Float64ToUint32`) and explained how these relate to JavaScript's dynamic typing and number handling. I provided a JavaScript example demonstrating a potential overflow during such a conversion.
    * **Code Logic Inference:** I selected the `kLoong64Float64ToUint32` case as a good example of code logic and provided a step-by-step explanation with hypothetical input and output, highlighting the overflow check.
    * **Common Programming Errors:** I identified potential errors related to integer overflows during type conversions based on the code's overflow handling mechanisms. I gave a JavaScript example of an overflow scenario.
    * **Part Summary:** I summarized the overall function based on my earlier analysis, emphasizing its role as the instruction selector and code emitter for the LoongArch architecture.

6. **Refinement and Organization:**  I organized the information logically, grouping related functionalities together. I used clear headings and bullet points to make the explanation easy to read. I also made sure to connect the low-level C++ code to higher-level JavaScript concepts where applicable.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on listing individual assembly instructions. I realized the user needed a higher-level understanding of the *functionality* provided by the code.
* I considered if any cases were related to garbage collection or other V8-specific mechanisms, but the provided snippet mainly focused on core instruction execution.
* I ensured the JavaScript examples were relevant and clearly illustrated the concepts being discussed in the C++ code.
* I made sure to explicitly address each point in the user's request.

By following this process of examining the code, understanding its context, and connecting it to the user's questions, I was able to generate a comprehensive and accurate response.
好的，让我们来分析一下这段 `v8/src/compiler/backend/loong64/code-generator-loong64.cc` 代码的功能。

**核心功能总结：**

这段代码是 V8 JavaScript 引擎中针对 LoongArch 64 位架构的代码生成器的核心部分。 它的主要功能是将 V8 的中间表示 (IR) 指令转换为 LoongArch 汇编指令。  具体来说，这段代码实现了 `AssembleArchInstruction` 函数中的一个巨大的 `switch` 语句，该语句根据不同的 V8 IR 指令 (`instr->arch_opcode()`)，生成相应的 LoongArch 汇编代码。

**详细功能分解：**

以下是这段代码中各个 `case` 分支的主要功能：

* **整数和浮点数转换：**
    * `kLoong64Float64ToInt32`, `kLoong64Float64ToUint32`, `kLoong64Float32ToInt32`, `kLoong64Float32ToUint32`, `kLoong64Float32ToInt64`, `kLoong64Float64ToUint64`:  处理浮点数到不同大小和符号的整数的转换。 代码中包含对溢出和 NaN 的处理。
* **位运算：**
    * `kLoong64BitcastDL`, `kLoong64BitcastLD`:  在浮点数和整数寄存器之间进行位级别的转换。
    * `kLoong64Float64ExtractLowWord32`, `kLoong64Float64ExtractHighWord32`, `kLoong64Float64FromWord32Pair`, `kLoong64Float64InsertLowWord32`, `kLoong64Float64InsertHighWord32`:  用于操作双精度浮点数的低 32 位和高 32 位。
    * `kLoong64Ext_w_b`, `kLoong64Ext_w_h`:  对字节或半字进行符号扩展到 32 位。
    * `kLoong64ByteSwap64`, `kLoong64ByteSwap32`:  进行字节序反转。
* **内存操作：**
    * `kLoong64Ld_bu`, `kLoong64Ld_b`, `kLoong64St_b`, `kLoong64Ld_hu`, `kLoong64Ld_h`, `kLoong64St_h`, `kLoong64Ld_w`, `kLoong64Ld_wu`, `kLoong64Ld_d`, `kLoong64St_w`, `kLoong64St_d`:  加载和存储不同大小的数据（字节、半字、字、双字）到内存。 `RecordTrapInfoIfNeeded` 可能用于记录潜在的陷阱信息。
    * `kLoong64LoadDecompressTaggedSigned`, `kLoong64LoadDecompressTagged`, `kLoong64LoadDecompressProtected`, `kLoong64StoreCompressTagged`:  处理 V8 中压缩标记指针的加载和存储。
    * `kLoong64LoadDecodeSandboxedPointer`, `kLoong64StoreEncodeSandboxedPointer`, `kLoong64StoreIndirectPointer`:  处理沙箱指针的加载和存储。
    * `kLoong64Fld_s`, `kLoong64Fst_s`, `kLoong64Fld_d`, `kLoong64Fst_d`:  加载和存储单精度和双精度浮点数到内存。
* **原子操作：**
    * `kLoong64AtomicLoadDecompressTaggedSigned`, `kLoong64AtomicLoadDecompressTagged`, `kLoong64AtomicStoreCompressTagged`:  原子地加载和存储压缩标记指针。
    * `kAtomicLoadInt8`, `kAtomicLoadUint8`, `kAtomicLoadInt16`, `kAtomicLoadUint16`, `kAtomicLoadWord32`, `kLoong64Word64AtomicLoadUint32`, `kLoong64Word64AtomicLoadUint64`:  原子地加载不同大小的整数。
    * `kAtomicStoreWord8`, `kAtomicStoreWord16`, `kAtomicStoreWord32`, `kLoong64Word64AtomicStoreWord64`:  原子地存储不同大小的整数。
    * `kAtomicExchangeInt8`, `kAtomicExchangeUint8`, `kAtomicExchangeInt16`, `kAtomicExchangeUint16`, `kAtomicExchangeWord32`, `kLoong64Word64AtomicExchangeUint64`:  原子地交换内存中的值。
    * `kAtomicCompareExchangeInt8`, `kAtomicCompareExchangeUint8`, `kAtomicCompareExchangeInt16`, `kAtomicCompareExchangeUint16`, `kAtomicCompareExchangeWord32`, `kLoong64Word64AtomicCompareExchangeUint64`:  原子地比较并交换内存中的值。
    * `kAtomicAddWord32`, `kAtomicSubWord32`, `kAtomicAndWord32`, `kAtomicOrWord32`, `kAtomicXorWord32`, `kLoong64Word64AtomicAddUint64`, `kLoong64Word64AtomicSubUint64`, `kLoong64Word64AtomicAndUint64`, `kLoong64Word64AtomicOrUint64`, `kLoong64Word64AtomicXorUint64`:  原子地进行算术和逻辑运算。
* **栈操作：**
    * `kLoong64Push`:  将数据压入栈。
    * `kLoong64Peek`:  从栈中窥视数据。
    * `kLoong64StackClaim`:  在栈上分配空间。
    * `kLoong64Poke`:  将数据写入栈的指定偏移量。
* **其他指令：**
    * `kLoong64Dbar`:  数据屏障指令。

**关于文件类型和 JavaScript 关系：**

* **文件类型：**  `v8/src/compiler/backend/loong64/code-generator-loong64.cc` 的 `.cc` 扩展名表明它是一个 **C++ 源文件**，而不是 Torque 源文件 (`.tq`)。
* **JavaScript 关系：**  这段代码直接参与了将 JavaScript 代码编译成机器码的过程。  许多指令都与 JavaScript 中常见的操作有关，例如：

**JavaScript 示例 (与类型转换相关):**

```javascript
let floatValue = 123.45;
let int32Value = floatValue | 0; // 将浮点数转换为 32 位整数 (相当于 floor)
let uint32Value = floatValue >>> 0; // 将浮点数转换为无符号 32 位整数

// 可能会发生溢出的情况
let largeFloat = 999999999999.99;
let overflowInt = largeFloat | 0; // 结果可能不符合预期
let overflowUint = largeFloat >>> 0; // 结果可能不符合预期
```

这段 C++ 代码中的 `kLoong64Float64ToInt32` 和 `kLoong64Float64ToUint32` 等 `case` 就是负责生成执行类似 JavaScript 类型转换操作的机器码。  代码中的溢出检查部分对应于 JavaScript 运行时可能发生的超出整数范围的情况。

**代码逻辑推理和假设输入/输出 (以 `kLoong64Float64ToUint32` 为例):**

**假设输入:**

* `instr` 代表一个 `kLoong64Float64ToUint32` 指令。
* `i.InputDoubleRegister(0)`  包含一个双精度浮点数，例如 `10.5`。
* `i.OutputRegister(0)` 是用于存储转换后无符号 32 位整数的寄存器。
* `instr->OutputCount() > 1`  表示还需要输出一个标志位，指示是否发生溢出。

**代码逻辑:**

1. `__ Ftintrz_uw_d(i.OutputRegister(), i.InputDoubleRegister(0), scratch);`:  使用浮点指令将双精度浮点数截断转换为无符号 32 位整数，结果存储在 `i.OutputRegister()` 中。
2. `if (instr->OutputCount() > 1)`: 如果需要输出溢出标志。
3. `__ li(i.OutputRegister(1), 1);`:  初始化溢出标志为 1 (假设发生溢出)。
4. 一系列浮点比较和条件加载指令检查输入浮点数是否小于 0 或大于 `UINT32_MAX`。
5. 如果浮点数在有效范围内，则通过条件加载指令将溢出标志 `i.OutputRegister(1)` 修改为 0。

**假设输出:**

* 如果输入浮点数为 `10.5`，则 `i.OutputRegister(0)` 将包含 `10`，如果 `instr->OutputCount() > 1`，则 `i.OutputRegister(1)` 将包含 `0` (未溢出)。
* 如果输入浮点数为 `-1.0`，则 `i.OutputRegister(0)` 的结果取决于 `Ftintrz_uw_d` 的具体实现 (可能是 0 或其他值)，如果 `instr->OutputCount() > 1`，则 `i.OutputRegister(1)` 将包含 `1` (溢出)。
* 如果输入浮点数为 `4294967296.0` (大于 `UINT32_MAX`)，则 `i.OutputRegister(0)` 的结果取决于 `Ftintrz_uw_d` 的具体实现，如果 `instr->OutputCount() > 1`，则 `i.OutputRegister(1)` 将包含 `1` (溢出)。

**用户常见的编程错误 (与类型转换相关):**

* **整数溢出：**  将一个超出目标整数类型范围的浮点数或大整数转换为较小的整数类型，导致数据丢失或意外的结果。
    ```javascript
    let bigNumber = 2**32;
    let intValue = bigNumber | 0; // 错误：intValue 的值不是预期的 2**32
    console.log(intValue); // 输出 0 或其他意想不到的值
    ```
* **浮点数精度丢失：**  将一个无法精确表示为整数的浮点数转换为整数，导致精度丢失（截断）。
    ```javascript
    let pi = 3.14159;
    let intPi = pi | 0; // 结果是 3，小数部分被截断
    console.log(intPi);
    ```
* **未处理 NaN 或 Infinity：**  将 NaN (非数字) 或 Infinity 转换为整数，通常会得到 0 或其他不期望的结果。
    ```javascript
    let notANumber = NaN;
    let intNaN = notANumber | 0; // 结果是 0
    console.log(intNaN);
    ```

**归纳一下它的功能 (第 3 部分):**

作为整个代码生成器的一部分，这段代码主要负责处理 V8 IR 指令集中的 **算术运算、类型转换、内存访问、原子操作和栈操作** 等核心功能。 它针对 LoongArch 64 位架构的特性，将这些高级指令翻译成可以直接在该架构上执行的汇编代码。  这段代码是 V8 将 JavaScript 代码高效地编译为 LoongArch 机器码的关键组成部分。它体现了编译器后端的重要职责：指令选择和代码生成。

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/code-generator-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/loong64/code-generator-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
     __ movfcsr2gr(output2, FCSR2);
        // Check for overflow and NaNs.
        __ And(output2, output2,
               kFCSROverflowCauseMask | kFCSRInvalidOpCauseMask);
        __ Slt(output2, zero_reg, output2);
        __ xori(output2, output2, 1);
      }
      if (set_overflow_to_min_i64) {
        // Avoid INT64_MAX as an overflow indicator and use INT64_MIN instead,
        // because INT64_MIN allows easier out-of-bounds detection.
        __ addi_d(scratch, i.OutputRegister(), 1);
        __ slt(scratch, scratch, i.OutputRegister());
        __ add_d(i.OutputRegister(), i.OutputRegister(), scratch);
      }
      break;
    }
    case kLoong64Float64ToUint32: {
      FPURegister scratch = kScratchDoubleReg;
      __ Ftintrz_uw_d(i.OutputRegister(), i.InputDoubleRegister(0), scratch);
      if (instr->OutputCount() > 1) {
        __ li(i.OutputRegister(1), 1);
        __ Move(scratch, static_cast<double>(-1.0));
        __ CompareF64(scratch, i.InputDoubleRegister(0), CLT);
        __ LoadZeroIfNotFPUCondition(i.OutputRegister(1));
        __ Move(scratch, static_cast<double>(UINT32_MAX) + 1);
        __ CompareF64(scratch, i.InputDoubleRegister(0), CLE);
        __ LoadZeroIfFPUCondition(i.OutputRegister(1));
      }
      break;
    }
    case kLoong64Float32ToUint32: {
      FPURegister scratch = kScratchDoubleReg;
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      __ Ftintrz_uw_s(i.OutputRegister(), i.InputDoubleRegister(0), scratch);
      if (set_overflow_to_min_i32) {
        UseScratchRegisterScope temps(masm());
        Register scratch = temps.Acquire();
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        __ addi_w(scratch, i.OutputRegister(), 1);
        __ Movz(i.OutputRegister(), zero_reg, scratch);
      }
      break;
    }
    case kLoong64Float32ToUint64: {
      FPURegister scratch = kScratchDoubleReg;
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Ftintrz_ul_s(i.OutputRegister(), i.InputDoubleRegister(0), scratch,
                      result);
      break;
    }
    case kLoong64Float64ToUint64: {
      FPURegister scratch = kScratchDoubleReg;
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Ftintrz_ul_d(i.OutputRegister(0), i.InputDoubleRegister(0), scratch,
                      result);
      break;
    }
    case kLoong64BitcastDL:
      __ movfr2gr_d(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64BitcastLD:
      __ movgr2fr_d(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kLoong64Float64ExtractLowWord32:
      __ FmoveLow(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64ExtractHighWord32:
      __ movfrh2gr_s(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64FromWord32Pair:
      __ movgr2fr_w(i.OutputDoubleRegister(), i.InputRegister(1));
      __ movgr2frh_w(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kLoong64Float64InsertLowWord32:
      __ FmoveLow(i.OutputDoubleRegister(), i.InputRegister(1));
      break;
    case kLoong64Float64InsertHighWord32:
      __ movgr2frh_w(i.OutputDoubleRegister(), i.InputRegister(1));
      break;
      // ... more basic instructions ...

    case kLoong64Ext_w_b:
      __ ext_w_b(i.OutputRegister(), i.InputRegister(0));
      break;
    case kLoong64Ext_w_h:
      __ ext_w_h(i.OutputRegister(), i.InputRegister(0));
      break;
    case kLoong64Ld_bu:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_bu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64Ld_b:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_b(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64St_b: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ St_b(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64Ld_hu:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_hu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64Ld_h:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_h(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64St_h: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ St_h(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64Ld_w:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_w(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64Ld_wu:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_wu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64Ld_d:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_d(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64St_w: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ St_w(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64St_d: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ St_d(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64LoadDecompressTaggedSigned:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ DecompressTaggedSigned(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64LoadDecompressTagged:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ DecompressTagged(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64LoadDecompressProtected:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ DecompressProtected(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64StoreCompressTagged: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ StoreTaggedField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64LoadDecodeSandboxedPointer:
      __ LoadSandboxedPointerField(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64StoreEncodeSandboxedPointer: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ StoreSandboxedPointerField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64StoreIndirectPointer: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ StoreIndirectPointerField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64AtomicLoadDecompressTaggedSigned:
      __ AtomicDecompressTaggedSigned(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64AtomicLoadDecompressTagged:
      __ AtomicDecompressTagged(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64AtomicStoreCompressTagged: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ AtomicStoreTaggedField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64Fld_s: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Fld_s(i.OutputSingleRegister(), i.MemoryOperand());
      break;
    }
    case kLoong64Fst_s: {
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&index);
      FPURegister ft = i.InputOrZeroSingleRegister(index);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Fst_s(ft, operand);
      break;
    }
    case kLoong64Fld_d:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Fld_d(i.OutputDoubleRegister(), i.MemoryOperand());
      break;
    case kLoong64Fst_d: {
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&index);
      FPURegister ft = i.InputOrZeroDoubleRegister(index);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Fst_d(ft, operand);
      break;
    }
    case kLoong64Dbar: {
      __ dbar(0);
      break;
    }
    case kLoong64Push:
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Fst_d(i.InputDoubleRegister(0), MemOperand(sp, -kDoubleSize));
        __ Sub_d(sp, sp, Operand(kDoubleSize));
        frame_access_state()->IncreaseSPDelta(kDoubleSize / kSystemPointerSize);
      } else {
        __ Push(i.InputRegister(0));
        frame_access_state()->IncreaseSPDelta(1);
      }
      break;
    case kLoong64Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ Fld_d(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ Fld_s(i.OutputSingleRegister(0), MemOperand(fp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          abort();
        }
      } else {
        __ Ld_d(i.OutputRegister(0), MemOperand(fp, offset));
      }
      break;
    }
    case kLoong64StackClaim: {
      __ Sub_d(sp, sp, Operand(i.InputInt32(0)));
      frame_access_state()->IncreaseSPDelta(i.InputInt32(0) /
                                            kSystemPointerSize);
      break;
    }
    case kLoong64Poke: {
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Fst_d(i.InputDoubleRegister(0), MemOperand(sp, i.InputInt32(1)));
      } else {
        __ St_d(i.InputRegister(0), MemOperand(sp, i.InputInt32(1)));
      }
      break;
    }
    case kLoong64ByteSwap64: {
      __ ByteSwap(i.OutputRegister(0), i.InputRegister(0), 8);
      break;
    }
    case kLoong64ByteSwap32: {
      __ ByteSwap(i.OutputRegister(0), i.InputRegister(0), 4);
      break;
    }
    case kAtomicLoadInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_b);
      break;
    case kAtomicLoadUint8:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_bu);
      break;
    case kAtomicLoadInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_h);
      break;
    case kAtomicLoadUint16:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_hu);
      break;
    case kAtomicLoadWord32:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_w);
      break;
    case kLoong64Word64AtomicLoadUint32:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_wu);
      break;
    case kLoong64Word64AtomicLoadUint64:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_d);
      break;
    case kAtomicStoreWord8:
      ASSEMBLE_ATOMIC_STORE_INTEGER(St_b);
      break;
    case kAtomicStoreWord16:
      ASSEMBLE_ATOMIC_STORE_INTEGER(St_h);
      break;
    case kAtomicStoreWord32:
      ASSEMBLE_ATOMIC_STORE_INTEGER(St_w);
      break;
    case kLoong64Word64AtomicStoreWord64:
      ASSEMBLE_ATOMIC_STORE_INTEGER(St_d);
      break;
    case kAtomicExchangeInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, true, 8, 32);
      break;
    case kAtomicExchangeUint8:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, false, 8, 32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 8, 64);
          break;
      }
      break;
    case kAtomicExchangeInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, true, 16, 32);
      break;
    case kAtomicExchangeUint16:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, false, 16, 32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 16, 64);
          break;
      }
      break;
    case kAtomicExchangeWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amswap_db_w(i.OutputRegister(0), i.InputRegister(2),
                         i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 32, 64);
          break;
      }
      break;
    case kLoong64Word64AtomicExchangeUint64:
      __ add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amswap_db_d(i.OutputRegister(0), i.InputRegister(2),
                     i.TempRegister(0));
      break;
    case kAtomicCompareExchangeInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, true, 8, 32);
      break;
    case kAtomicCompareExchangeUint8:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, false, 8,
                                                       32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 8,
                                                       64);
          break;
      }
      break;
    case kAtomicCompareExchangeInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, true, 16, 32);
      break;
    case kAtomicCompareExchangeUint16:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, false, 16,
                                                       32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 16,
                                                       64);
          break;
      }
      break;
    case kAtomicCompareExchangeWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ slli_w(i.InputRegister(2), i.InputRegister(2), 0);
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Ll_w, Sc_w);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 32,
                                                       64);
          break;
      }
      break;
    case kLoong64Word64AtomicCompareExchangeUint64:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Ll_d, Sc_d);
      break;
    case kAtomicAddWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amadd_db_w(i.OutputRegister(0), i.InputRegister(2),
                        i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, Add_d, 64);
          break;
      }
      break;
    case kAtomicSubWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_BINOP(Ll_w, Sc_w, Sub_w);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, Sub_d, 64);
          break;
      }
      break;
    case kAtomicAndWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amand_db_w(i.OutputRegister(0), i.InputRegister(2),
                        i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, And, 64);
          break;
      }
      break;
    case kAtomicOrWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amor_db_w(i.OutputRegister(0), i.InputRegister(2),
                       i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, Or, 64);
          break;
      }
      break;
    case kAtomicXorWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amxor_db_w(i.OutputRegister(0), i.InputRegister(2),
                        i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, Xor, 64);
          break;
      }
      break;
#define ATOMIC_BINOP_CASE(op, inst32, inst64)                          \
  case kAtomic##op##Int8:                                              \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, true, 8, inst32, 32);        \
    break;                                                             \
  case kAtomic##op##Uint8:                                             \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, false, 8, inst32, 32);   \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 8, inst64, 64);   \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Int16:                                             \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, true, 16, inst32, 32);       \
    break;                                                             \
  case kAtomic##op##Uint16:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, false, 16, inst32, 32);  \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 16, inst64, 64);  \
        break;                                                         \
    }                                                                  \
    break;
      ATOMIC_BINOP_CASE(Add, Add_w, Add_d)
      ATOMIC_BINOP_CASE(Sub, Sub_w, Sub_d)
      ATOMIC_BINOP_CASE(And, And, And)
      ATOMIC_BINOP_CASE(Or, Or, Or)
      ATOMIC_BINOP_CASE(Xor, Xor, Xor)
#undef ATOMIC_BINOP_CASE

    case kLoong64Word64AtomicAddUint64:
      __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amadd_db_d(i.OutputRegister(0), i.InputRegister(2), i.TempRegister(0));
      break;
    case kLoong64Word64AtomicSubUint64:
      ASSEMBLE_ATOMIC_BINOP(Ll_d, Sc_d, Sub_d);
      break;
    case kLoong64Word64AtomicAndUint64:
      __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amand_db_d(i.OutputRegister(0), i.InputRegister(2), i.TempRegister(0));
      break;
    case kLoong64Word64AtomicOrUint64:
      __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amor_db_d(i.OutputRegister(0), i.InputRegister(2), i.TempRegister(0));
      break;
    case kLoong64Word64AtomicXorUint64:
      __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amxor_db_d(i.OutputRegister(0), i.InputRegister(2), i.TempRegister(0));
      break;
#undef ATOMIC_BINOP_CASE
    case kLoong64S128Const:
    case kLoong64S128Zero:
    case kLoong64I32x4Splat:
    case kLoong64I32x4ExtractLane:
    case kLoong64I32x4Add:
    case kLoong64I32x4ReplaceLane:
    case kLoong64I32x4Sub:
    case kLoong64F64x2Abs:
    default:
      break;
  }
  return kSuccess;
}

#define UNSUPPORTED_COND(opcode, condition)                                    \
  StdoutStream{} << "Unsupported " << #opcode << " condition: \"" << condition \
                 << "\"";                                                      \
  UNIMPLEMENTED();

void SignExtend(MacroAssembler* masm, Instruction* instr, Register* left,
                Operand* right, Register* temp0, Register* temp1) {
  bool need_signed = false;
  MachineRepresentation rep_left =
      LocationOperand::cast(instr->InputAt(0))->representation();
  need_signed = IsAnyTagged(rep_left) || IsAnyCompressed(rep_left) ||
                rep_left == MachineRepresentation::kWord64;
  if (need_signed) {
    masm->slli_w(*temp0, *left, 0);
    *left = *temp0;
  }

  if (instr->InputAt(1)->IsAnyLocationOperand()) {
    MachineRepresentation rep_right =
        LocationOperand::cast(instr->InputAt(1))->representation();
    need_signed = IsAnyTagged(rep_right) || IsAnyCompressed(rep_right) ||
                  rep_right == MachineRepresentation::kWord64;
    if (need_signed && right->is_reg()) {
      DCHECK(*temp1 != no_reg);
      masm->slli_w(*temp1, right->rm(), 0);
      *right = Operand(*temp1);
    }
  }
}

void AssembleBranchToLabels(CodeGenerator* gen, MacroAssembler* masm,
                            Instruction* instr, FlagsCondition condition,
                            Label* tlabel, Label* flabel, bool fallthru) {
#undef __
#define __ masm->
  Loong64OperandConverter i(gen, instr);

  // LOONG64 does not have condition code flags, so compare and branch are
  // implemented differently than on the other arch's. The compare operations
  // emit loong64 pseudo-instructions, which are handled here by branch
  // instructions that do the actual comparison. Essential that the input
  // registers to compare pseudo-op are not modified before this branch op, as
  // they are tested here.

  if (instr->arch_opcode() == kLoong64Tst) {
    Condition cc = FlagsConditionToConditionTst(condition);
    __ Branch(tlabel, cc, t8, Operand(zero_reg));
  } else if (instr->arch_opcode() == kLoong64Add_d ||
             instr->arch_opcode() == kLoong64Sub_d) {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Register scratch2 = temps.Acquire();
    Condition cc = FlagsConditionToConditionOvf(condition);
    __ srai_d(scratch, i.OutputRegister(), 32);
    __ srai_w(scratch2, i.OutputRegister(), 31);
    __ Branch(tlabel, cc, scratch2, Operand(scratch));
  } else if (instr->arch_opcode() == kLoong64AddOvf_d ||
             instr->arch_opcode() == kLoong64SubOvf_d) {
    switch (condition) {
      // Overflow occurs if overflow register is negative
      case kOverflow:
        __ Branch(tlabel, lt, t8, Operand(zero_reg));
        break;
      case kNotOverflow:
        __ Branch(tlabel, ge, t8, Operand(zero_reg));
        break;
      default:
        UNSUPPORTED_COND(instr->arch_opcode(), condition);
    }
  } else if (instr->arch_opcode() == kLoong64MulOvf_w ||
             instr->arch_opcode() == kLoong64MulOvf_d) {
    // Overflow occurs if overflow register is not zero
    switch (condition) {
      case kOverflow:
        __ Branch(tlabel, ne, t8, Operand(zero_reg));
        break;
      case kNotOverflow:
        __ Branch(tlabel, eq, t8, Operand(zero_reg));
        break;
      default:
        UNSUPPORTED_COND(instr->arch_opcode(), condition);
    }
  } else if (instr->arch_opcode() == kLoong64Cmp32 ||
             instr->arch_opcode() == kLoong64Cmp64) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register left = i.InputRegister(0);
    Operand right = i.InputOperand(1);
    // Word32Compare has two temp registers.
    if (COMPRESS_POINTERS_BOOL && (instr->arch_opcode() == kLoong64Cmp32)) {
      Register temp0 = i.TempRegister(0);
      Register temp1 = right.is_reg() ? i.TempRegister(1) : no_reg;
      SignExtend(masm, instr, &left, &right, &temp0, &temp1);
    }
    __ Branch(tlabel, cc, left, right);
  } else if (instr->arch_opcode() == kArchStackPointerGreaterThan) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    DCHECK((cc == ls) || (cc == hi));
    if (cc == ls) {
      __ xori(i.TempRegister(0), i.TempRegister(0), 1);
    }
    __ Branch(tlabel, ne, i.TempRegister(0), Operand(zero_reg));
  } else if (instr->arch_opcode() == kLoong64Float32Cmp ||
             instr->arch_opcode() == kLoong64Float64Cmp) {
    bool predicate;
    FlagsConditionToConditionCmpFPU(&predicate, condition);
    if (predicate) {
      __ BranchTrueF(tlabel);
    } else {
      __ BranchFalseF(tlabel);
    }
  } else {
    PrintF("AssembleArchBranch Unimplemented arch_opcode: %d\n",
           instr->arch_opcode());
    UNIMPLEMENTED();
  }
  if (!fallthru) __ Branch(flabel);  // no fallthru to flabel.
#undef __
#define __ masm()->
}

// Assembles branches after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;

  AssembleBranchToLabels(this, masm(), instr, branch->condition, tlabel, flabel,
                         branch->fallthru);
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

#undef UNSUPPORTED_COND

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ Branch(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  auto ool = zone()->New<WasmOutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  AssembleBranchToLabels(this, masm(), instr, condition, tlabel, nullptr, true);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  Loong64OperandConverter i(this, instr);

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Register result = i.OutputRegister(instr->OutputCount() - 1);
  // Loong64 does not have condition code flags, so compare and branch are
  // implemented differently than on the other arch's. The compare operations
  // emit loong64 pseudo-instructions, which are checked and handled here.

  if (instr->arch_opcode() == kLoong64Tst) {
    Condition cc = FlagsConditionToConditionTst(condition);
    if (cc == eq) {
      __ Sltu(result, t8, 1);
    } else {
      __ Sltu(result, zero_reg, t8);
    }
    return;
  } else if (instr->arch_opcode() == kLoong64Add_d ||
             instr->arch_opcode() == kLoong64Sub_d) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    Condition cc = FlagsConditionToConditionOvf(condition);
    // Check for overflow creates 1 or 0 for result.
    __ srli_d(scratch, i.OutputRegister(), 63);
    __ srli_w(result, i.OutputRegister(), 31);
    __ xor_(result, scratch, result);
    if (cc == eq)  // Toggle result for not overflow.
      __ xori(result, result, 1);
    return;
  } else if (instr->arch_opcode() == kLoong64AddOvf_d ||
             instr->arch_opcode() == kLoong64SubOvf_d) {
    // Overflow occurs if overflow register is negative
    __ slt(result, t8, zero_reg);
  } else if (instr->arch_opcode() == kLoong64MulOvf_w ||
             instr->arch_opcode() == kLoong64MulOvf_d) {
    // Overflow occurs if overflow register is not zero
    __ Sgtu(result, t8, zero_reg);
  } else if (instr->arch_opcode() == kLoong64Cmp32 ||
             instr->arch_opcode() == kLoong64Cmp64) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register left = i.InputRegister(0);
    Operand right = i.InputOperand(1);
    if (COMPRESS_POINTERS_BOOL && (instr->arch_opcode() == kLoong64Cmp32)) {
      Register temp0 = i.TempRegister(0);
      Register temp1 = right.is_reg() ? i.TempRegister(1) : no_reg;
      SignExtend(masm(), instr, &left, &right, &temp0, &temp1);
    }
    __ CompareWord(cc, result, left, right);
    return;
  } else if (instr->arch_opcode() == kLoong64Float64Cmp ||
             instr->arch_opcode() == kLoong64Float32Cmp) {
    FPURegister left = i.InputOrZeroDoubleRegister(0);
    FPURegister right = i.InputOrZeroDoubleRegister(1);
    if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
        !__ IsDoubleZeroRegSet()) {
      __ Move(kDoubleRegZero, 0.0);
    }
    bool predicate;
    FlagsConditionToConditionCmpFPU(&predicate, condition);
    {
      __ movcf2gr(result, FCC0);
      if (!predicate) {
        __ xori(result, result, 1);
      }
    }
    return;
  } else if (instr->arch_opcode() == kArchStackPointerGreaterThan) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    DCHECK((cc == ls) || (cc == hi));
    if (cc == ls) {
      __ xori(i.OutputRegister(), i.TempRegister(0), 1);
    }
    return;
  } else {
    PrintF("AssembleArchBranch Unimplemented arch_opcode is : %d\n",
           instr->arch_opcode());
    TRACE("UNIMPLEMENTED code_generator_loong64: %s at line %d\n", __FUNCTION__,
          __LINE__);
    UNIMPLEMENTED();
  }
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  Loong64OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }

  UseScratchRegisterScope temps(masm());
  Register scratch = temps.Acquire();
  // The input register may contains dirty data in upper 32 bits, explicitly
  // sign-extend it here.
  __ slli_w(scratch, input, 0);
  AssembleArchBinarySearchSwitchRange(scratch, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  Loong64OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  size_t const case_count = instr->InputCount() - 2;

  UseScratchRegisterScope temps(masm());
  Register scratch = temps.Acquire();
  // The input register may contains dirty data in upper 32 bits, explicitly
  // sign-extend it here.
 
"""


```