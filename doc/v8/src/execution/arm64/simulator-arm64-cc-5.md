Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/execution/arm64/simulator-arm64.cc`.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The code consists of several `VisitNEON...` methods within the `Simulator` class. The "NEON" prefix strongly suggests it's related to ARM's NEON instruction set, which is used for Single Instruction Multiple Data (SIMD) operations. The `Simulator` class implies this code is part of a simulator that executes ARM64 instructions.

2. **Analyze Individual `VisitNEON...` Methods:**  Go through each method and determine its purpose based on its name and the operations it performs. Look for keywords like "Load," "Store," "Copy," "Extract," "Multiply," "Add," "Subtract," "Shift," etc.

3. **Categorize the Functionality:** Group the methods based on the type of NEON instruction they handle. Common categories include:
    * Arithmetic/Logical operations (e.g., multiplication, addition, comparison)
    * Data movement (e.g., copy, extract, duplicate)
    * Load/Store operations (moving data between registers and memory)
    * Shift operations

4. **Identify Data Types and Formats:**  Notice the use of `VectorFormat` and functions like `NEONFormatDecoder`. This indicates the code deals with different data types (bytes, half-words, words, double-words) and arrangements within the NEON registers.

5. **Look for Specific Operations:** Within each method, pay attention to calls to functions like `fmul`, `fmla`, `ld1`, `st1`, `shl`, etc. These represent the actual NEON instructions being simulated.

6. **Address Specific User Questions:**
    * **.tq extension:** The code snippet is C++, not Torque, so this condition is false.
    * **Relationship to JavaScript:**  NEON instructions are used to optimize performance-critical parts of JavaScript execution. Think of array manipulation, graphics, or other computationally intensive tasks. A simple example involving array multiplication would be relevant.
    * **Code logic inference:** Choose a relatively straightforward `VisitNEON...` method and provide a hypothetical input state (register values) and the expected output state after the simulated instruction executes.
    * **Common programming errors:**  Focus on errors related to memory access (alignment, bounds) and data type mismatches, as these are common when working with SIMD instructions and manual memory management (which the simulator does).

7. **Synthesize a Summary:** Combine the information gathered into a concise summary of the file's purpose, highlighting its role in simulating ARM64 NEON instructions.

8. **Address the "Part 6 of 7" aspect:**  Acknowledge that this is a component of a larger system.

**Self-Correction/Refinement during the thought process:**

* Initially, I might just list the methods without grouping them. Realizing that grouping provides a better overview leads to the categorization step.
* I need to ensure the JavaScript example is simple and illustrates the benefit of SIMD operations.
* For the code logic example, choosing a complex instruction would make it harder to understand. A simpler data movement or arithmetic operation is better.
* When discussing programming errors, avoid overly technical details and focus on common pitfalls.

By following this structured approach, I can generate a comprehensive and accurate summary that addresses all the user's requirements.
目录 `v8/src/execution/arm64/simulator-arm64.cc` 是 V8 JavaScript 引擎中用于模拟 ARM64 架构指令执行的 C++ 代码。

**功能归纳 (基于提供的代码片段):**

这个代码片段主要负责模拟 ARM64 架构中 NEON (Advanced SIMD) 指令的执行。NEON 是一组用于并行处理向量数据的指令，可以显著提升在音频、视频处理以及其他数据密集型任务中的性能。

具体来说，这个代码片段中的函数（以 `VisitNEON...` 开头）对应于不同的 NEON 指令类型，并模拟这些指令在 V8 虚拟机中的行为。

以下是根据代码片段推断出的功能点：

* **模拟 NEON 向量运算:**  代码中出现了大量的 NEON 指令助记符，例如 `FMUL` (浮点乘法), `FMLA` (浮点乘加), `FMLS` (浮点乘减), `ADD` (加法), `SUB` (减法), `SHL` (左移), `USHR` (无符号右移) 等。这些函数模拟了这些指令对 NEON 寄存器中的向量数据进行操作。
* **模拟按元素的 NEON 运算:**  `VisitNEONByIndexedElement` 和 `VisitNEONScalarByIndexedElement` 模拟了 NEON 指令，这些指令使用一个向量寄存器中的特定元素与另一个向量或标量寄存器进行运算。
* **模拟 NEON 数据复制和提取:** `VisitNEONCopy` 和 `VisitNEONExtract` 模拟了在 NEON 寄存器之间复制数据、将标量值插入向量、从向量中提取标量值等操作。
* **模拟 NEON 加载和存储指令:** `VisitNEONLoadStoreMultiStruct`, `VisitNEONLoadStoreMultiStructPostIndex`, `VisitNEONLoadStoreSingleStruct`, `VisitNEONLoadStoreSingleStructPostIndex` 模拟了将多个或单个 NEON 寄存器的数据加载到内存或从内存存储的操作。这些函数还处理不同的寻址模式 (偏移寻址和后索引寻址)。
* **模拟 NEON 常数加载:** `VisitNEONModifiedImmediate` 模拟了将特定的立即数值加载到 NEON 寄存器的操作。
* **模拟 NEON 标量运算:**  `VisitNEONScalar2RegMisc`, `VisitNEONScalar3Diff`, `VisitNEONScalar3Same`, `VisitNEONScalarPairwise`, `VisitNEONScalarShiftImmediate` 等函数模拟了对 NEON 标量寄存器进行各种运算，包括算术、比较、类型转换和移位操作。
* **处理不同的数据格式:** 代码中使用了 `VectorFormat` 和 `NEONFormatDecoder`，表明该模拟器能够处理不同大小和类型的向量元素 (例如，字节、半字、字、双字，以及浮点数)。
* **内存访问模拟:** 代码中包含对内存读写操作的模拟 (`ld1`, `st1`, `ld2`, `st2` 等) 以及内存访问探测 (`ProbeMemory`).
* **日志记录:**  代码中包含 `LogVRead` 和 `LogVWrite` 函数调用，表明模拟器可以记录 NEON 寄存器的读写操作，这对于调试和分析很有用。
* **处理饱和运算:** 代码中出现 `.SignedSaturate()` 和 `.UnsignedSaturate()`，说明模拟器也处理了 NEON 指令中的饱和运算，即结果超出范围时会被限制在最大或最小值。
* **浮点运算:** 代码中大量出现了以 `f` 开头的 NEON 指令，表明它支持浮点运算，并能处理不同的浮点舍入模式。

**关于代码的特性:**

* **不是 Torque 代码:**  根据您的描述，如果文件名以 `.tq` 结尾才是 Torque 代码。`simulator-arm64.cc` 以 `.cc` 结尾，因此是标准的 C++ 代码。

**与 JavaScript 的关系 (示例):**

NEON 指令通常用于加速 JavaScript 中处理数组或进行数值计算的场景。例如，当 JavaScript 代码执行以下操作时，V8 引擎可能会利用 NEON 指令：

```javascript
// 假设有一个很大的数组
const array1 = [1.0, 2.0, 3.0, 4.0];
const array2 = [5.0, 6.0, 7.0, 8.0];
const result = [];

// 将两个数组的对应元素相加
for (let i = 0; i < array1.length; i++) {
  result.push(array1[i] + array2[i]);
}

console.log(result); // 输出 [6, 8, 10, 12]
```

在 V8 内部，对于这种循环操作，如果条件允许，它可能会将多个加法操作打包成一个 NEON 的向量加法指令来执行，例如 `FADD` 或其变体，一次处理多个浮点数，从而提高性能。 `simulator-arm64.cc` 中的 `VisitNEONAdd` (或其他类似的加法指令模拟函数) 就负责模拟这种指令的行为。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 NEON 指令需要模拟（对应 `VisitNEONAdd` 函数中的 `add` 操作）：

指令： `ADD V0.4S, V1.4S, V2.4S`

含义： 将 NEON 寄存器 V1 和 V2 中的四个单精度浮点数对应相加，结果存储到 V0。

**假设输入:**

* NEON 寄存器 V1 的值为: `[1.0, 2.0, 3.0, 4.0]`
* NEON 寄存器 V2 的值为: `[5.0, 6.0, 7.0, 8.0]`

**预期输出:**

* NEON 寄存器 V0 的值将会是: `[6.0, 8.0, 10.0, 12.0]`

`VisitNEONAdd` 函数会读取 V1 和 V2 的值，执行向量加法操作，并将结果写入 V0。

**用户常见的编程错误 (与 NEON 指令相关):**

当直接编写汇编代码或使用编译器 intrinsic 函数操作 NEON 指令时，用户容易犯以下错误：

1. **数据类型不匹配:**  NEON 指令对操作数的数据类型有严格的要求。例如，试图将浮点数向量与整数向量相加会导致错误。
   ```c++
   // 假设 v0 是 float32x4_t， v1 是 int32x4_t
   // 错误: 数据类型不匹配
   // vaddq_f32(v0, v0, v1);
   ```

2. **向量长度不匹配:** 某些 NEON 指令要求操作数的向量长度一致。
   ```c++
   // 假设 v0 是 float32x4_t， v1 是 float32x2_t
   // 错误: 向量长度不匹配
   // vaddq_f32(v0, v0, v1);
   ```

3. **内存对齐问题:**  NEON 加载和存储指令通常对内存地址的对齐有要求。如果访问未对齐的内存地址，可能导致性能下降或程序崩溃。
   ```c++
   float data[5];
   float *ptr = &data[1]; // 未对齐的地址
   float32x4_t v;
   // 错误或性能问题: 尝试加载未对齐的数据
   // vld1q_f32(ptr);
   ```

4. **越界访问:**  在按元素操作时，如果索引超出向量的边界，会导致未定义的行为。

5. **误解指令的行为:**  仔细阅读指令的文档非常重要。例如，某些移位指令的行为可能与直觉不符，或者某些饱和指令在溢出时的处理方式需要注意。

**这是第 6 部分，共 7 部分，请归纳一下它的功能:**

作为第 6 部分，这个代码片段专注于模拟 ARM64 架构中**NEON 和 Advanced SIMD 扩展的指令执行**。它涵盖了向量和标量的算术运算、逻辑运算、数据移动、加载存储以及立即数加载等多种 NEON 指令类型。这部分代码是 V8 引擎模拟 ARM64 架构处理器行为的关键组成部分，使得 V8 能够在非 ARM64 平台上运行和测试，并为在 ARM64 平台上执行 JavaScript 代码提供底层的指令执行能力。

### 提示词
```
这是目录为v8/src/execution/arm64/simulator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
tVectorFormat(nfd.FPFormatMap());

      switch (instr->Mask(NEONByIndexedElementFPMask)) {
        case NEON_FMUL_byelement:
          Op = &Simulator::fmul;
          break;
        case NEON_FMLA_byelement:
          Op = &Simulator::fmla;
          break;
        case NEON_FMLS_byelement:
          Op = &Simulator::fmls;
          break;
        case NEON_FMULX_byelement:
          Op = &Simulator::fmulx;
          break;
        default:
          UNIMPLEMENTED();
      }
  }

  (this->*Op)(vf, rd, rn, vreg(rm_reg), index);
}

void Simulator::VisitNEONCopy(Instruction* instr) {
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::TriangularFormatMap());
  VectorFormat vf = nfd.GetVectorFormat();

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  int imm5 = instr->ImmNEON5();
  int lsb = LowestSetBitPosition(imm5);
  int reg_index = imm5 >> lsb;

  if (instr->Mask(NEONCopyInsElementMask) == NEON_INS_ELEMENT) {
    int imm4 = instr->ImmNEON4();
    DCHECK_GE(lsb, 1);
    int rn_index = imm4 >> (lsb - 1);
    ins_element(vf, rd, reg_index, rn, rn_index);
  } else if (instr->Mask(NEONCopyInsGeneralMask) == NEON_INS_GENERAL) {
    ins_immediate(vf, rd, reg_index, xreg(instr->Rn()));
  } else if (instr->Mask(NEONCopyUmovMask) == NEON_UMOV) {
    uint64_t value = LogicVRegister(rn).Uint(vf, reg_index);
    value &= MaxUintFromFormat(vf);
    set_xreg(instr->Rd(), value);
  } else if (instr->Mask(NEONCopyUmovMask) == NEON_SMOV) {
    int64_t value = LogicVRegister(rn).Int(vf, reg_index);
    if (instr->NEONQ()) {
      set_xreg(instr->Rd(), value);
    } else {
      DCHECK(is_int32(value));
      set_wreg(instr->Rd(), static_cast<int32_t>(value));
    }
  } else if (instr->Mask(NEONCopyDupElementMask) == NEON_DUP_ELEMENT) {
    dup_element(vf, rd, rn, reg_index);
  } else if (instr->Mask(NEONCopyDupGeneralMask) == NEON_DUP_GENERAL) {
    dup_immediate(vf, rd, xreg(instr->Rn()));
  } else {
    UNIMPLEMENTED();
  }
}

void Simulator::VisitNEONExtract(Instruction* instr) {
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LogicalFormatMap());
  VectorFormat vf = nfd.GetVectorFormat();
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  SimVRegister& rm = vreg(instr->Rm());
  if (instr->Mask(NEONExtractMask) == NEON_EXT) {
    int index = instr->ImmNEONExt();
    ext(vf, rd, rn, rm, index);
  } else {
    UNIMPLEMENTED();
  }
}

void Simulator::NEONLoadStoreMultiStructHelper(const Instruction* instr,
                                               AddrMode addr_mode) {
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LoadStoreFormatMap());
  VectorFormat vf = nfd.GetVectorFormat();

  uint64_t addr_base = xreg(instr->Rn(), Reg31IsStackPointer);
  int reg_size = RegisterSizeInBytesFromFormat(vf);

  int reg[4];
  uint64_t addr[4];
  for (int i = 0; i < 4; i++) {
    reg[i] = (instr->Rt() + i) % kNumberOfVRegisters;
    addr[i] = addr_base + (i * reg_size);
  }
  int count = 1;
  bool log_read = true;

  // Bit 23 determines whether this is an offset or post-index addressing mode.
  // In offset mode, bits 20 to 16 should be zero; these bits encode the
  // register of immediate in post-index mode.
  if ((instr->Bit(23) == 0) && (instr->Bits(20, 16) != 0)) {
    UNREACHABLE();
  }

  // We use the PostIndex mask here, as it works in this case for both Offset
  // and PostIndex addressing.
  switch (instr->Mask(NEONLoadStoreMultiStructPostIndexMask)) {
    case NEON_LD1_4v:
    case NEON_LD1_4v_post:
      ld1(vf, vreg(reg[3]), addr[3]);
      count++;
      [[fallthrough]];
    case NEON_LD1_3v:
    case NEON_LD1_3v_post:
      ld1(vf, vreg(reg[2]), addr[2]);
      count++;
      [[fallthrough]];
    case NEON_LD1_2v:
    case NEON_LD1_2v_post:
      ld1(vf, vreg(reg[1]), addr[1]);
      count++;
      [[fallthrough]];
    case NEON_LD1_1v:
    case NEON_LD1_1v_post:
      ld1(vf, vreg(reg[0]), addr[0]);
      break;
    case NEON_ST1_4v:
    case NEON_ST1_4v_post:
      st1(vf, vreg(reg[3]), addr[3]);
      count++;
      [[fallthrough]];
    case NEON_ST1_3v:
    case NEON_ST1_3v_post:
      st1(vf, vreg(reg[2]), addr[2]);
      count++;
      [[fallthrough]];
    case NEON_ST1_2v:
    case NEON_ST1_2v_post:
      st1(vf, vreg(reg[1]), addr[1]);
      count++;
      [[fallthrough]];
    case NEON_ST1_1v:
    case NEON_ST1_1v_post:
      st1(vf, vreg(reg[0]), addr[0]);
      log_read = false;
      break;
    case NEON_LD2_post:
    case NEON_LD2:
      ld2(vf, vreg(reg[0]), vreg(reg[1]), addr[0]);
      count = 2;
      break;
    case NEON_ST2:
    case NEON_ST2_post:
      st2(vf, vreg(reg[0]), vreg(reg[1]), addr[0]);
      count = 2;
      log_read = false;
      break;
    case NEON_LD3_post:
    case NEON_LD3:
      ld3(vf, vreg(reg[0]), vreg(reg[1]), vreg(reg[2]), addr[0]);
      count = 3;
      break;
    case NEON_ST3:
    case NEON_ST3_post:
      st3(vf, vreg(reg[0]), vreg(reg[1]), vreg(reg[2]), addr[0]);
      count = 3;
      log_read = false;
      break;
    case NEON_LD4_post:
    case NEON_LD4:
      ld4(vf, vreg(reg[0]), vreg(reg[1]), vreg(reg[2]), vreg(reg[3]), addr[0]);
      count = 4;
      break;
    case NEON_ST4:
    case NEON_ST4_post:
      st4(vf, vreg(reg[0]), vreg(reg[1]), vreg(reg[2]), vreg(reg[3]), addr[0]);
      count = 4;
      log_read = false;
      break;
    default:
      UNIMPLEMENTED();
  }

  {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    if (log_read) {
      local_monitor_.NotifyLoad();
    } else {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_processor_);
    }
  }

  // Explicitly log the register update whilst we have type information.
  for (int i = 0; i < count; i++) {
    // For de-interleaving loads, only print the base address.
    int lane_size = LaneSizeInBytesFromFormat(vf);
    PrintRegisterFormat format = GetPrintRegisterFormatTryFP(
        GetPrintRegisterFormatForSize(reg_size, lane_size));
    if (log_read) {
      LogVRead(addr_base, reg[i], format);
    } else {
      LogVWrite(addr_base, reg[i], format);
    }
  }

  if (addr_mode == PostIndex) {
    int rm = instr->Rm();
    // The immediate post index addressing mode is indicated by rm = 31.
    // The immediate is implied by the number of vector registers used.
    addr_base +=
        (rm == 31) ? RegisterSizeInBytesFromFormat(vf) * count : xreg(rm);
    set_xreg(instr->Rn(), addr_base);
  } else {
    DCHECK_EQ(addr_mode, Offset);
  }
}

void Simulator::VisitNEONLoadStoreMultiStruct(Instruction* instr) {
  NEONLoadStoreMultiStructHelper(instr, Offset);
}

void Simulator::VisitNEONLoadStoreMultiStructPostIndex(Instruction* instr) {
  NEONLoadStoreMultiStructHelper(instr, PostIndex);
}

void Simulator::NEONLoadStoreSingleStructHelper(const Instruction* instr,
                                                AddrMode addr_mode) {
  uint64_t addr = xreg(instr->Rn(), Reg31IsStackPointer);
  int rt = instr->Rt();

  // Bit 23 determines whether this is an offset or post-index addressing mode.
  // In offset mode, bits 20 to 16 should be zero; these bits encode the
  // register of immediate in post-index mode.
  DCHECK_IMPLIES(instr->Bit(23) == 0, instr->Bits(20, 16) == 0);

  bool do_load = false;

  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LoadStoreFormatMap());
  VectorFormat vf_t = nfd.GetVectorFormat();

  VectorFormat vf = kFormat16B;
  // We use the PostIndex mask here, as it works in this case for both Offset
  // and PostIndex addressing.
  switch (instr->Mask(NEONLoadStoreSingleStructPostIndexMask)) {
    case NEON_LD1_b:
    case NEON_LD1_b_post:
    case NEON_LD2_b:
    case NEON_LD2_b_post:
    case NEON_LD3_b:
    case NEON_LD3_b_post:
    case NEON_LD4_b:
    case NEON_LD4_b_post:
      do_load = true;
      [[fallthrough]];
    case NEON_ST1_b:
    case NEON_ST1_b_post:
    case NEON_ST2_b:
    case NEON_ST2_b_post:
    case NEON_ST3_b:
    case NEON_ST3_b_post:
    case NEON_ST4_b:
    case NEON_ST4_b_post:
      break;

    case NEON_LD1_h:
    case NEON_LD1_h_post:
    case NEON_LD2_h:
    case NEON_LD2_h_post:
    case NEON_LD3_h:
    case NEON_LD3_h_post:
    case NEON_LD4_h:
    case NEON_LD4_h_post:
      do_load = true;
      [[fallthrough]];
    case NEON_ST1_h:
    case NEON_ST1_h_post:
    case NEON_ST2_h:
    case NEON_ST2_h_post:
    case NEON_ST3_h:
    case NEON_ST3_h_post:
    case NEON_ST4_h:
    case NEON_ST4_h_post:
      vf = kFormat8H;
      break;

    case NEON_LD1_s:
    case NEON_LD1_s_post:
    case NEON_LD2_s:
    case NEON_LD2_s_post:
    case NEON_LD3_s:
    case NEON_LD3_s_post:
    case NEON_LD4_s:
    case NEON_LD4_s_post:
      do_load = true;
      [[fallthrough]];
    case NEON_ST1_s:
    case NEON_ST1_s_post:
    case NEON_ST2_s:
    case NEON_ST2_s_post:
    case NEON_ST3_s:
    case NEON_ST3_s_post:
    case NEON_ST4_s:
    case NEON_ST4_s_post: {
      static_assert((NEON_LD1_s | (1 << NEONLSSize_offset)) == NEON_LD1_d,
                    "LSB of size distinguishes S and D registers.");
      static_assert(
          (NEON_LD1_s_post | (1 << NEONLSSize_offset)) == NEON_LD1_d_post,
          "LSB of size distinguishes S and D registers.");
      static_assert((NEON_ST1_s | (1 << NEONLSSize_offset)) == NEON_ST1_d,
                    "LSB of size distinguishes S and D registers.");
      static_assert(
          (NEON_ST1_s_post | (1 << NEONLSSize_offset)) == NEON_ST1_d_post,
          "LSB of size distinguishes S and D registers.");
      vf = ((instr->NEONLSSize() & 1) == 0) ? kFormat4S : kFormat2D;
      break;
    }

    case NEON_LD1R:
    case NEON_LD1R_post: {
      vf = vf_t;
      if (!ProbeMemory(addr, LaneSizeInBytesFromFormat(vf))) return;
      ld1r(vf, vreg(rt), addr);
      do_load = true;
      break;
    }

    case NEON_LD2R:
    case NEON_LD2R_post: {
      vf = vf_t;
      if (!ProbeMemory(addr, 2 * LaneSizeInBytesFromFormat(vf))) return;
      int rt2 = (rt + 1) % kNumberOfVRegisters;
      ld2r(vf, vreg(rt), vreg(rt2), addr);
      do_load = true;
      break;
    }

    case NEON_LD3R:
    case NEON_LD3R_post: {
      vf = vf_t;
      if (!ProbeMemory(addr, 3 * LaneSizeInBytesFromFormat(vf))) return;
      int rt2 = (rt + 1) % kNumberOfVRegisters;
      int rt3 = (rt2 + 1) % kNumberOfVRegisters;
      ld3r(vf, vreg(rt), vreg(rt2), vreg(rt3), addr);
      do_load = true;
      break;
    }

    case NEON_LD4R:
    case NEON_LD4R_post: {
      vf = vf_t;
      if (!ProbeMemory(addr, 4 * LaneSizeInBytesFromFormat(vf))) return;
      int rt2 = (rt + 1) % kNumberOfVRegisters;
      int rt3 = (rt2 + 1) % kNumberOfVRegisters;
      int rt4 = (rt3 + 1) % kNumberOfVRegisters;
      ld4r(vf, vreg(rt), vreg(rt2), vreg(rt3), vreg(rt4), addr);
      do_load = true;
      break;
    }
    default:
      UNIMPLEMENTED();
  }

  PrintRegisterFormat print_format =
      GetPrintRegisterFormatTryFP(GetPrintRegisterFormat(vf));
  // Make sure that the print_format only includes a single lane.
  print_format =
      static_cast<PrintRegisterFormat>(print_format & ~kPrintRegAsVectorMask);

  int esize = LaneSizeInBytesFromFormat(vf);
  int index_shift = LaneSizeInBytesLog2FromFormat(vf);
  int lane = instr->NEONLSIndex(index_shift);
  int scale = 0;
  int rt2 = (rt + 1) % kNumberOfVRegisters;
  int rt3 = (rt2 + 1) % kNumberOfVRegisters;
  int rt4 = (rt3 + 1) % kNumberOfVRegisters;
  switch (instr->Mask(NEONLoadStoreSingleLenMask)) {
    case NEONLoadStoreSingle1:
      scale = 1;
      if (!ProbeMemory(addr, scale * esize)) return;
      if (do_load) {
        ld1(vf, vreg(rt), lane, addr);
        LogVRead(addr, rt, print_format, lane);
      } else {
        st1(vf, vreg(rt), lane, addr);
        LogVWrite(addr, rt, print_format, lane);
      }
      break;
    case NEONLoadStoreSingle2:
      scale = 2;
      if (!ProbeMemory(addr, scale * esize)) return;
      if (do_load) {
        ld2(vf, vreg(rt), vreg(rt2), lane, addr);
        LogVRead(addr, rt, print_format, lane);
        LogVRead(addr + esize, rt2, print_format, lane);
      } else {
        st2(vf, vreg(rt), vreg(rt2), lane, addr);
        LogVWrite(addr, rt, print_format, lane);
        LogVWrite(addr + esize, rt2, print_format, lane);
      }
      break;
    case NEONLoadStoreSingle3:
      scale = 3;
      if (!ProbeMemory(addr, scale * esize)) return;
      if (do_load) {
        ld3(vf, vreg(rt), vreg(rt2), vreg(rt3), lane, addr);
        LogVRead(addr, rt, print_format, lane);
        LogVRead(addr + esize, rt2, print_format, lane);
        LogVRead(addr + (2 * esize), rt3, print_format, lane);
      } else {
        st3(vf, vreg(rt), vreg(rt2), vreg(rt3), lane, addr);
        LogVWrite(addr, rt, print_format, lane);
        LogVWrite(addr + esize, rt2, print_format, lane);
        LogVWrite(addr + (2 * esize), rt3, print_format, lane);
      }
      break;
    case NEONLoadStoreSingle4:
      scale = 4;
      if (!ProbeMemory(addr, scale * esize)) return;
      if (do_load) {
        ld4(vf, vreg(rt), vreg(rt2), vreg(rt3), vreg(rt4), lane, addr);
        LogVRead(addr, rt, print_format, lane);
        LogVRead(addr + esize, rt2, print_format, lane);
        LogVRead(addr + (2 * esize), rt3, print_format, lane);
        LogVRead(addr + (3 * esize), rt4, print_format, lane);
      } else {
        st4(vf, vreg(rt), vreg(rt2), vreg(rt3), vreg(rt4), lane, addr);
        LogVWrite(addr, rt, print_format, lane);
        LogVWrite(addr + esize, rt2, print_format, lane);
        LogVWrite(addr + (2 * esize), rt3, print_format, lane);
        LogVWrite(addr + (3 * esize), rt4, print_format, lane);
      }
      break;
    default:
      UNIMPLEMENTED();
  }

  {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    if (do_load) {
      local_monitor_.NotifyLoad();
    } else {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_processor_);
    }
  }

  if (addr_mode == PostIndex) {
    int rm = instr->Rm();
    int lane_size = LaneSizeInBytesFromFormat(vf);
    set_xreg(instr->Rn(), addr + ((rm == 31) ? (scale * lane_size) : xreg(rm)));
  }
}

void Simulator::VisitNEONLoadStoreSingleStruct(Instruction* instr) {
  NEONLoadStoreSingleStructHelper(instr, Offset);
}

void Simulator::VisitNEONLoadStoreSingleStructPostIndex(Instruction* instr) {
  NEONLoadStoreSingleStructHelper(instr, PostIndex);
}

void Simulator::VisitNEONModifiedImmediate(Instruction* instr) {
  SimVRegister& rd = vreg(instr->Rd());
  int cmode = instr->NEONCmode();
  int cmode_3_1 = (cmode >> 1) & 7;
  int cmode_3 = (cmode >> 3) & 1;
  int cmode_2 = (cmode >> 2) & 1;
  int cmode_1 = (cmode >> 1) & 1;
  int cmode_0 = cmode & 1;
  int q = instr->NEONQ();
  int op_bit = instr->NEONModImmOp();
  uint64_t imm8 = instr->ImmNEONabcdefgh();

  // Find the format and immediate value
  uint64_t imm = 0;
  VectorFormat vform = kFormatUndefined;
  switch (cmode_3_1) {
    case 0x0:
    case 0x1:
    case 0x2:
    case 0x3:
      vform = (q == 1) ? kFormat4S : kFormat2S;
      imm = imm8 << (8 * cmode_3_1);
      break;
    case 0x4:
    case 0x5:
      vform = (q == 1) ? kFormat8H : kFormat4H;
      imm = imm8 << (8 * cmode_1);
      break;
    case 0x6:
      vform = (q == 1) ? kFormat4S : kFormat2S;
      if (cmode_0 == 0) {
        imm = imm8 << 8 | 0x000000FF;
      } else {
        imm = imm8 << 16 | 0x0000FFFF;
      }
      break;
    case 0x7:
      if (cmode_0 == 0 && op_bit == 0) {
        vform = q ? kFormat16B : kFormat8B;
        imm = imm8;
      } else if (cmode_0 == 0 && op_bit == 1) {
        vform = q ? kFormat2D : kFormat1D;
        imm = 0;
        for (int i = 0; i < 8; ++i) {
          if (imm8 & (1ULL << i)) {
            imm |= (UINT64_C(0xFF) << (8 * i));
          }
        }
      } else {  // cmode_0 == 1, cmode == 0xF.
        if (op_bit == 0) {
          vform = q ? kFormat4S : kFormat2S;
          imm = base::bit_cast<uint32_t>(instr->ImmNEONFP32());
        } else if (q == 1) {
          vform = kFormat2D;
          imm = base::bit_cast<uint64_t>(instr->ImmNEONFP64());
        } else {
          DCHECK((q == 0) && (op_bit == 1) && (cmode == 0xF));
          VisitUnallocated(instr);
        }
      }
      break;
    default:
      UNREACHABLE();
  }

  // Find the operation.
  NEONModifiedImmediateOp op;
  if (cmode_3 == 0) {
    if (cmode_0 == 0) {
      op = op_bit ? NEONModifiedImmediate_MVNI : NEONModifiedImmediate_MOVI;
    } else {  // cmode<0> == '1'
      op = op_bit ? NEONModifiedImmediate_BIC : NEONModifiedImmediate_ORR;
    }
  } else {  // cmode<3> == '1'
    if (cmode_2 == 0) {
      if (cmode_0 == 0) {
        op = op_bit ? NEONModifiedImmediate_MVNI : NEONModifiedImmediate_MOVI;
      } else {  // cmode<0> == '1'
        op = op_bit ? NEONModifiedImmediate_BIC : NEONModifiedImmediate_ORR;
      }
    } else {  // cmode<2> == '1'
      if (cmode_1 == 0) {
        op = op_bit ? NEONModifiedImmediate_MVNI : NEONModifiedImmediate_MOVI;
      } else {  // cmode<1> == '1'
        if (cmode_0 == 0) {
          op = NEONModifiedImmediate_MOVI;
        } else {  // cmode<0> == '1'
          op = NEONModifiedImmediate_MOVI;
        }
      }
    }
  }

  // Call the logic function.
  switch (op) {
    case NEONModifiedImmediate_ORR:
      orr(vform, rd, rd, imm);
      break;
    case NEONModifiedImmediate_BIC:
      bic(vform, rd, rd, imm);
      break;
    case NEONModifiedImmediate_MOVI:
      movi(vform, rd, imm);
      break;
    case NEONModifiedImmediate_MVNI:
      mvni(vform, rd, imm);
      break;
    default:
      VisitUnimplemented(instr);
  }
}

void Simulator::VisitNEONScalar2RegMisc(Instruction* instr) {
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::ScalarFormatMap());
  VectorFormat vf = nfd.GetVectorFormat();

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());

  if (instr->Mask(NEON2RegMiscOpcode) <= NEON_NEG_scalar_opcode) {
    // These instructions all use a two bit size field, except NOT and RBIT,
    // which use the field to encode the operation.
    switch (instr->Mask(NEONScalar2RegMiscMask)) {
      case NEON_CMEQ_zero_scalar:
        cmp(vf, rd, rn, 0, eq);
        break;
      case NEON_CMGE_zero_scalar:
        cmp(vf, rd, rn, 0, ge);
        break;
      case NEON_CMGT_zero_scalar:
        cmp(vf, rd, rn, 0, gt);
        break;
      case NEON_CMLT_zero_scalar:
        cmp(vf, rd, rn, 0, lt);
        break;
      case NEON_CMLE_zero_scalar:
        cmp(vf, rd, rn, 0, le);
        break;
      case NEON_ABS_scalar:
        abs(vf, rd, rn);
        break;
      case NEON_SQABS_scalar:
        abs(vf, rd, rn).SignedSaturate(vf);
        break;
      case NEON_NEG_scalar:
        neg(vf, rd, rn);
        break;
      case NEON_SQNEG_scalar:
        neg(vf, rd, rn).SignedSaturate(vf);
        break;
      case NEON_SUQADD_scalar:
        suqadd(vf, rd, rn);
        break;
      case NEON_USQADD_scalar:
        usqadd(vf, rd, rn);
        break;
      default:
        UNIMPLEMENTED();
    }
  } else {
    VectorFormat fpf = nfd.GetVectorFormat(nfd.FPScalarFormatMap());
    FPRounding fpcr_rounding = static_cast<FPRounding>(fpcr().RMode());

    // These instructions all use a one bit size field, except SQXTUN, SQXTN
    // and UQXTN, which use a two bit size field.
    switch (instr->Mask(NEONScalar2RegMiscFPMask)) {
      case NEON_FRECPE_scalar:
        frecpe(fpf, rd, rn, fpcr_rounding);
        break;
      case NEON_FRECPX_scalar:
        frecpx(fpf, rd, rn);
        break;
      case NEON_FRSQRTE_scalar:
        frsqrte(fpf, rd, rn);
        break;
      case NEON_FCMGT_zero_scalar:
        fcmp_zero(fpf, rd, rn, gt);
        break;
      case NEON_FCMGE_zero_scalar:
        fcmp_zero(fpf, rd, rn, ge);
        break;
      case NEON_FCMEQ_zero_scalar:
        fcmp_zero(fpf, rd, rn, eq);
        break;
      case NEON_FCMLE_zero_scalar:
        fcmp_zero(fpf, rd, rn, le);
        break;
      case NEON_FCMLT_zero_scalar:
        fcmp_zero(fpf, rd, rn, lt);
        break;
      case NEON_SCVTF_scalar:
        scvtf(fpf, rd, rn, 0, fpcr_rounding);
        break;
      case NEON_UCVTF_scalar:
        ucvtf(fpf, rd, rn, 0, fpcr_rounding);
        break;
      case NEON_FCVTNS_scalar:
        fcvts(fpf, rd, rn, FPTieEven);
        break;
      case NEON_FCVTNU_scalar:
        fcvtu(fpf, rd, rn, FPTieEven);
        break;
      case NEON_FCVTPS_scalar:
        fcvts(fpf, rd, rn, FPPositiveInfinity);
        break;
      case NEON_FCVTPU_scalar:
        fcvtu(fpf, rd, rn, FPPositiveInfinity);
        break;
      case NEON_FCVTMS_scalar:
        fcvts(fpf, rd, rn, FPNegativeInfinity);
        break;
      case NEON_FCVTMU_scalar:
        fcvtu(fpf, rd, rn, FPNegativeInfinity);
        break;
      case NEON_FCVTZS_scalar:
        fcvts(fpf, rd, rn, FPZero);
        break;
      case NEON_FCVTZU_scalar:
        fcvtu(fpf, rd, rn, FPZero);
        break;
      case NEON_FCVTAS_scalar:
        fcvts(fpf, rd, rn, FPTieAway);
        break;
      case NEON_FCVTAU_scalar:
        fcvtu(fpf, rd, rn, FPTieAway);
        break;
      case NEON_FCVTXN_scalar:
        // Unlike all of the other FP instructions above, fcvtxn encodes dest
        // size S as size<0>=1. There's only one case, so we ignore the form.
        DCHECK_EQ(instr->Bit(22), 1);
        fcvtxn(kFormatS, rd, rn);
        break;
      default:
        switch (instr->Mask(NEONScalar2RegMiscMask)) {
          case NEON_SQXTN_scalar:
            sqxtn(vf, rd, rn);
            break;
          case NEON_UQXTN_scalar:
            uqxtn(vf, rd, rn);
            break;
          case NEON_SQXTUN_scalar:
            sqxtun(vf, rd, rn);
            break;
          default:
            UNIMPLEMENTED();
        }
    }
  }
}

void Simulator::VisitNEONScalar3Diff(Instruction* instr) {
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LongScalarFormatMap());
  VectorFormat vf = nfd.GetVectorFormat();

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  SimVRegister& rm = vreg(instr->Rm());
  switch (instr->Mask(NEONScalar3DiffMask)) {
    case NEON_SQDMLAL_scalar:
      sqdmlal(vf, rd, rn, rm);
      break;
    case NEON_SQDMLSL_scalar:
      sqdmlsl(vf, rd, rn, rm);
      break;
    case NEON_SQDMULL_scalar:
      sqdmull(vf, rd, rn, rm);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitNEONScalar3Same(Instruction* instr) {
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::ScalarFormatMap());
  VectorFormat vf = nfd.GetVectorFormat();

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  SimVRegister& rm = vreg(instr->Rm());

  if (instr->Mask(NEONScalar3SameFPFMask) == NEONScalar3SameFPFixed) {
    vf = nfd.GetVectorFormat(nfd.FPScalarFormatMap());
    switch (instr->Mask(NEONScalar3SameFPMask)) {
      case NEON_FMULX_scalar:
        fmulx(vf, rd, rn, rm);
        break;
      case NEON_FACGE_scalar:
        fabscmp(vf, rd, rn, rm, ge);
        break;
      case NEON_FACGT_scalar:
        fabscmp(vf, rd, rn, rm, gt);
        break;
      case NEON_FCMEQ_scalar:
        fcmp(vf, rd, rn, rm, eq);
        break;
      case NEON_FCMGE_scalar:
        fcmp(vf, rd, rn, rm, ge);
        break;
      case NEON_FCMGT_scalar:
        fcmp(vf, rd, rn, rm, gt);
        break;
      case NEON_FRECPS_scalar:
        frecps(vf, rd, rn, rm);
        break;
      case NEON_FRSQRTS_scalar:
        frsqrts(vf, rd, rn, rm);
        break;
      case NEON_FABD_scalar:
        fabd(vf, rd, rn, rm);
        break;
      default:
        UNIMPLEMENTED();
    }
  } else {
    switch (instr->Mask(NEONScalar3SameMask)) {
      case NEON_ADD_scalar:
        add(vf, rd, rn, rm);
        break;
      case NEON_SUB_scalar:
        sub(vf, rd, rn, rm);
        break;
      case NEON_CMEQ_scalar:
        cmp(vf, rd, rn, rm, eq);
        break;
      case NEON_CMGE_scalar:
        cmp(vf, rd, rn, rm, ge);
        break;
      case NEON_CMGT_scalar:
        cmp(vf, rd, rn, rm, gt);
        break;
      case NEON_CMHI_scalar:
        cmp(vf, rd, rn, rm, hi);
        break;
      case NEON_CMHS_scalar:
        cmp(vf, rd, rn, rm, hs);
        break;
      case NEON_CMTST_scalar:
        cmptst(vf, rd, rn, rm);
        break;
      case NEON_USHL_scalar:
        ushl(vf, rd, rn, rm);
        break;
      case NEON_SSHL_scalar:
        sshl(vf, rd, rn, rm);
        break;
      case NEON_SQDMULH_scalar:
        sqdmulh(vf, rd, rn, rm);
        break;
      case NEON_SQRDMULH_scalar:
        sqrdmulh(vf, rd, rn, rm);
        break;
      case NEON_UQADD_scalar:
        add(vf, rd, rn, rm).UnsignedSaturate(vf);
        break;
      case NEON_SQADD_scalar:
        add(vf, rd, rn, rm).SignedSaturate(vf);
        break;
      case NEON_UQSUB_scalar:
        sub(vf, rd, rn, rm).UnsignedSaturate(vf);
        break;
      case NEON_SQSUB_scalar:
        sub(vf, rd, rn, rm).SignedSaturate(vf);
        break;
      case NEON_UQSHL_scalar:
        ushl(vf, rd, rn, rm).UnsignedSaturate(vf);
        break;
      case NEON_SQSHL_scalar:
        sshl(vf, rd, rn, rm).SignedSaturate(vf);
        break;
      case NEON_URSHL_scalar:
        ushl(vf, rd, rn, rm).Round(vf);
        break;
      case NEON_SRSHL_scalar:
        sshl(vf, rd, rn, rm).Round(vf);
        break;
      case NEON_UQRSHL_scalar:
        ushl(vf, rd, rn, rm).Round(vf).UnsignedSaturate(vf);
        break;
      case NEON_SQRSHL_scalar:
        sshl(vf, rd, rn, rm).Round(vf).SignedSaturate(vf);
        break;
      default:
        UNIMPLEMENTED();
    }
  }
}

void Simulator::VisitNEONScalarByIndexedElement(Instruction* instr) {
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LongScalarFormatMap());
  VectorFormat vf = nfd.GetVectorFormat();
  VectorFormat vf_r = nfd.GetVectorFormat(nfd.ScalarFormatMap());

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  ByElementOp Op = nullptr;

  int rm_reg = instr->Rm();
  int index = (instr->NEONH() << 1) | instr->NEONL();
  if (instr->NEONSize() == 1) {
    rm_reg &= 0xF;
    index = (index << 1) | instr->NEONM();
  }

  switch (instr->Mask(NEONScalarByIndexedElementMask)) {
    case NEON_SQDMULL_byelement_scalar:
      Op = &Simulator::sqdmull;
      break;
    case NEON_SQDMLAL_byelement_scalar:
      Op = &Simulator::sqdmlal;
      break;
    case NEON_SQDMLSL_byelement_scalar:
      Op = &Simulator::sqdmlsl;
      break;
    case NEON_SQDMULH_byelement_scalar:
      Op = &Simulator::sqdmulh;
      vf = vf_r;
      break;
    case NEON_SQRDMULH_byelement_scalar:
      Op = &Simulator::sqrdmulh;
      vf = vf_r;
      break;
    default:
      vf = nfd.GetVectorFormat(nfd.FPScalarFormatMap());
      index = instr->NEONH();
      if ((instr->FPType() & 1) == 0) {
        index = (index << 1) | instr->NEONL();
      }
      switch (instr->Mask(NEONScalarByIndexedElementFPMask)) {
        case NEON_FMUL_byelement_scalar:
          Op = &Simulator::fmul;
          break;
        case NEON_FMLA_byelement_scalar:
          Op = &Simulator::fmla;
          break;
        case NEON_FMLS_byelement_scalar:
          Op = &Simulator::fmls;
          break;
        case NEON_FMULX_byelement_scalar:
          Op = &Simulator::fmulx;
          break;
        default:
          UNIMPLEMENTED();
      }
  }

  (this->*Op)(vf, rd, rn, vreg(rm_reg), index);
}

void Simulator::VisitNEONScalarCopy(Instruction* instr) {
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::TriangularScalarFormatMap());
  VectorFormat vf = nfd.GetVectorFormat();

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());

  if (instr->Mask(NEONScalarCopyMask) == NEON_DUP_ELEMENT_scalar) {
    int imm5 = instr->ImmNEON5();
    int lsb = LowestSetBitPosition(imm5);
    int rn_index = imm5 >> lsb;
    dup_element(vf, rd, rn, rn_index);
  } else {
    UNIMPLEMENTED();
  }
}

void Simulator::VisitNEONScalarPairwise(Instruction* instr) {
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::FPScalarFormatMap());
  VectorFormat vf = nfd.GetVectorFormat();

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  switch (instr->Mask(NEONScalarPairwiseMask)) {
    case NEON_ADDP_scalar:
      addp(vf, rd, rn);
      break;
    case NEON_FADDP_scalar:
      faddp(vf, rd, rn);
      break;
    case NEON_FMAXP_scalar:
      fmaxp(vf, rd, rn);
      break;
    case NEON_FMAXNMP_scalar:
      fmaxnmp(vf, rd, rn);
      break;
    case NEON_FMINP_scalar:
      fminp(vf, rd, rn);
      break;
    case NEON_FMINNMP_scalar:
      fminnmp(vf, rd, rn);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitNEONScalarShiftImmediate(Instruction* instr) {
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  FPRounding fpcr_rounding = static_cast<FPRounding>(fpcr().RMode());

  static const NEONFormatMap map = {
      {22, 21, 20, 19},
      {NF_UNDEF, NF_B, NF_H, NF_H, NF_S, NF_S, NF_S, NF_S, NF_D, NF_D, NF_D,
       NF_D, NF_D, NF_D, NF_D, NF_D}};
  NEONFormatDecoder nfd(instr, &map);
  VectorFormat vf = nfd.GetVectorFormat();

  int highestSetBit = HighestSetBitPosition(instr->ImmNEONImmh());
  int immhimmb = instr->ImmNEONImmhImmb();
  int right_shift = (16 << highestSetBit) - immhimmb;
  int left_shift = immhimmb - (8 << highestSetBit);
  switch (instr->Mask(NEONScalarShiftImmediateMask)) {
    case NEON_SHL_scalar:
      shl(vf, rd, rn, left_shift);
      break;
    case NEON_SLI_scalar:
      sli(vf, rd, rn, left_shift);
      break;
    case NEON_SQSHL_imm_scalar:
      sqshl(vf, rd, rn, left_shift);
      break;
    case NEON_UQSHL_imm_scalar:
      uqshl(vf, rd, rn, left_shift);
      break;
    case NEON_SQSHLU_scalar:
      sqshlu(vf, rd, rn, left_shift);
      break;
    case NEON_SRI_scalar:
      sri(vf, rd, rn, right_shift);
      break;
    case NEON_SSHR_scalar:
      sshr(vf, rd, rn, right_shift);
      break;
    case NEON_USHR_scalar:
      ushr(vf, rd, rn, right_shift);
      break;
    case NEON_SRSHR_scalar:
      sshr(vf, rd, rn, right_shift).Round(vf);
      break;
    case NEON_URSHR_scalar:
      ushr(vf, rd, rn, right_shift).Round(vf);
      break;
    case NEON_SSRA_scalar:
      ssra(vf, rd, rn, right_shift);
      break;
    case NEON_USRA_scalar:
      usra(vf, rd, rn, right_shift);
      break;
    case NEON_SRSRA_scalar:
      srsra(vf, rd, rn, right_shift);
      break;
    case NEON_URSRA_scalar:
      ursra(vf, rd, rn, right_shift);
      break;
    case NEON_UQSHRN_scalar:
      uqshrn(vf, rd, rn, right_shift);
      break;
    case NEON_UQRSHRN_scalar:
      uqrshrn(vf, rd, rn, right_shift);
      break;
    case NEON_SQSHRN_scalar:
      sqshrn(vf, rd, rn, right_shift);
      break;
    case NEON_SQRSHRN_scalar:
      sqrshrn(vf, rd, rn, right_shift);
      break;
    case NEON_SQSHRUN_scalar:
      sqshrun(vf, rd, rn, right_shift);
      break;
    case NEON_SQRSHRUN_scalar:
      sqrshrun(vf, rd, rn, right_shift);
      break;
    case NEON_FCVTZS_imm_scalar:
      fcvts(vf, rd, rn, FPZero, right_shift);
      break;
    case NEON_FCVTZU_imm_scalar:
      fcvtu(vf, rd, rn, FPZero, right_shift);
      break;
    case NEON_SCVTF_imm_scalar:
      scvtf(vf, rd, rn, right_shift, fpcr_rounding);
      break;
    case NEON_UCVTF_imm_scalar:
      ucvtf(vf, rd, rn, right_shift, fpcr_rounding);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitNEONShiftImmediate(Instruction* instr) {
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  FPRounding fpcr_rounding = static_cast<FPRounding>(fpcr().RMode());

  // 00010->8B, 00011->16B, 001x0->4H, 001x1->8H,
  // 01xx0->2S, 01xx1->4S, 1xxx1->2D, all others undefined.
  static const NEONFormatMap map = {
      {22, 21, 20, 19, 30},
      {NF_UNDEF, NF_UNDEF, NF_8B,    NF_16B, NF_4H,    NF_8H, NF_4H,    NF_8H,
       NF_2S,    NF_4S,    NF_2S,    NF_4S,  NF_2S,    NF_4S, NF_2S,    NF_4S,
       NF_UNDEF, NF_2D,    NF_UNDEF, NF_2D,  NF_UNDEF, NF_2D, NF_UNDEF, NF_2D,
       NF_UNDEF, NF_2D,    NF_UNDEF, NF_2D,  NF_UNDEF, NF_2D, NF_UNDEF, NF_2D}};
  NEONFormatDecoder nfd(instr, &map);
  VectorFormat vf = nfd.GetVectorFormat();

  // 0001->8H, 001x->4S, 01xx->2D, all others undefined.
  static const NEONFormatMap map_l = {
      {22, 21, 20, 19},
      {NF_UNDEF, NF_8H, NF_4S, NF_4S, NF_2D, NF_2D, NF_2D, NF_2D}};
  VectorFormat vf_l = nfd.GetVectorFormat(&map_l);

  int highestSetBit = HighestSetBitPosition(instr->ImmNEONImmh());
  int immhimmb = instr->ImmNEONImmhImmb();
  int right_shift = (16 << highestSetBit) - immhimmb;
  int left_shift = immhimmb - (8 << highestSetBit);

  switch (instr->Mask(NEONShiftImmediateMask)) {
    case NEON_SHL:
      shl(vf, rd, rn, left_shift);
```