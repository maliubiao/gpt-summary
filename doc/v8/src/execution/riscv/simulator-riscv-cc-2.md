Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/execution/riscv/simulator-riscv.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The filename `simulator-riscv.cc` strongly suggests this code is part of a simulator for the RISC-V architecture within the V8 JavaScript engine.

2. **Analyze the code snippets:** Examine the provided code blocks for key functionalities. Look for patterns, macros, and function definitions.

3. **Group related functionalities:**  Notice the repetitive patterns in the macros like `RVV_VI_VFP_LOOP`, `RVV_VN_CLIPU_VI_LOOP`, `RVV_VN_CLIP_VI_LOOP`, and `RVV_VI_VIE_x_LOOP`. These seem to be related to RISC-V Vector (RVV) instructions.

4. **Focus on the macros:** The macros are doing something repetitive with different data sizes (E8, E16, E32, E64). The names suggest operations like "Vector Integer Floating-Point Loop," "Vector Narrow Clip Unsigned," and "Vector Integer Extend." The `CHECK` macros indicate assertions and validation.

5. **Examine utility functions:**  Identify functions like `get_round`, `signed_saturation`, and `unsigned_saturation`. These are helper functions for specific operations, like rounding and clamping values within a certain range.

6. **Recognize the debugger:** The `RiscvDebugger` class and its methods (`Debug`, `PrintRegs`, `PrintAllRegs`, etc.) clearly indicate debugging capabilities within the simulator. The commands it handles (like `si`, `c`, `p`, `stack`, `break`) are standard debugger commands.

7. **Address the file extension and JavaScript relationship:** The prompt specifically asks about `.tq` files and JavaScript relevance. The code is `.cc`, so it's C++. The simulator's purpose is to *execute* JavaScript code on a simulated RISC-V architecture, so the relationship is indirect but fundamental.

8. **Consider code logic and assumptions:** The macros involving loops and data sizes suggest operations on arrays or vectors. The saturation functions imply handling potential overflows or underflows. The rounding function is clearly for implementing different rounding modes.

9. **Identify potential programming errors:** The saturation and rounding functions hint at potential issues with integer overflow, data type conversion, and the nuances of floating-point arithmetic.

10. **Structure the response:** Organize the findings into clear sections based on the prompt's requirements: file type, functionality, JavaScript relation, code logic, common errors, and a summary.

11. **Elaborate with examples (especially JavaScript):** While the core code is C++, demonstrate the *effect* of the simulated instructions in a JavaScript context. This helps the user connect the low-level simulation with the high-level language. For example, show how array manipulations or math operations in JavaScript might utilize these simulated vector instructions under the hood.

12. **Provide concrete examples for code logic and errors:**  Illustrate the behavior of rounding and saturation with specific input values and expected outputs. Show examples of JavaScript code that could lead to the simulated errors (like exceeding integer limits).

13. **Summarize the core function:**  Concisely restate the main purpose of the code – simulating RISC-V instructions, especially vector instructions, within V8 for debugging and testing.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on the individual macros without recognizing the overarching theme of RVV simulation. Stepping back and looking for patterns helped identify the core functionality.
* I needed to be careful to distinguish between the *C++ code of the simulator* and the *JavaScript code it simulates*. The JavaScript examples demonstrate the *purpose* of the simulated instructions, not the C++ code itself.
* The prompt emphasizes the `.tq` extension. It's crucial to explicitly state that this file is `.cc` and therefore C++, not Torque.

By following these steps and refining the response, I could generate a comprehensive and accurate explanation of the provided code snippet.
这是 `v8/src/execution/riscv/simulator-riscv.cc` 源代码的第三部分。根据您提供的信息，我们可以归纳出以下功能：

**核心功能归纳：RISC-V 向量（RVV）指令的模拟执行**

这部分代码主要集中在模拟 RISC-V 向量扩展（RVV）指令的执行，特别是涉及到浮点运算和整数运算的向量操作。 它定义了用于处理不同向量元素宽度 (SEW) 的循环宏，以及一些辅助的内联函数用于舍入和饱和运算。

**详细功能列表:**

1. **向量浮点循环宏 (`RVV_VI_VFP_LOOP`)**:
   - 定义了针对向量和立即数进行浮点运算的循环结构。
   - 根据不同的向量元素宽度 (E8, E16, E32) 执行相应的操作。
   - 包括了边界检查 (`CHECK8`, `CHECK16`, `CHECK32`) 和跟踪 (`rvv_trace_vd()`)。
   - 宏内部调用 `VI_VFP_LOOP_SCALE_BASE`，这可能负责处理向量长度和跨步。
   - `BODY8`, `BODY16`, `BODY32` 是占位符，代表实际的浮点运算逻辑。

2. **获取舍入值的函数 (`get_round`)**:
   -  根据 RISC-V 的舍入模式 (`vxrm`) 和移位位数，计算舍入所需的比特位。
   -  支持多种舍入模式：
      -  `round-to-nearest-up` (四舍五入)
      -  `round-to-nearest-even` (向偶数舍入)
      -  `round-to-odd` (向奇数舍入，也称为 "jam")
      -  `round-down` (向下舍入，截断)

3. **有符号饱和函数 (`signed_saturation`)**:
   - 将输入值 `v` 饱和到一个有符号的 `n` 位整数范围内。
   - 如果 `v` 大于最大值，则返回最大值；如果小于最小值，则返回最小值。

4. **无符号饱和函数 (`unsigned_saturation`)**:
   - 将输入值 `v` 饱和到一个无符号的 `n` 位整数范围内。
   - 如果 `v` 大于最大值，则返回最大值；如果小于 0，则返回 0。

5. **向量无符号裁剪循环宏 (`RVV_VN_CLIPU_VI_LOOP`)**:
   - 定义了将向量 `vs2` 的元素进行右移 (`uimm5`)，加上舍入值后，进行无符号饱和的循环。
   - 根据不同的向量元素宽度 (E8, E16, E32) 使用不同的饱和位数 (8, 16, 32)。
   - `VN_UPARAMS` 可能是用于设置向量操作的参数。

6. **向量有符号裁剪循环宏 (`RVV_VN_CLIP_VI_LOOP`)**:
   - 定义了将向量 `vs2` 的元素进行右移 (`uimm5`)，加上舍入值后，进行有符号饱和的循环。
   - 同样根据不同的向量元素宽度 (E8, E16, E32) 使用不同的饱和位数 (8, 16, 32)。
   - `VN_PARAMS` 可能是用于设置向量操作的参数。

7. **扩展检查宏 (`CHECK_EXT`)**:
   - 用于检查扩展指令的先决条件。
   - 确保目标寄存器和源寄存器不同。
   - 检查元素宽度和向量长度乘数 (`vflmul`) 的兼容性。
   - 检查寄存器地址的对齐要求。
   - 检查是否会发生寄存器溢出。

8. **向量立即数扩展循环宏 (`RVV_VI_VIE_8_LOOP`, `RVV_VI_VIE_4_LOOP`, `RVV_VI_VIE_2_LOOP`)**:
   - 定义了将立即数扩展到向量的循环。
   - `RVV_VI_VIE_8_LOOP` 将 8 位立即数扩展到 64 位向量元素。
   - `RVV_VI_VIE_4_LOOP` 将 4 位立即数扩展到 32 或 64 位向量元素。
   - `RVV_VI_VIE_2_LOOP` 将 2 位立即数扩展到 16, 32 或 64 位向量元素。
   - `signed` 参数指示是否进行有符号扩展。
   - `VI_VIE_PARAMS` 和 `VI_VIE_UPARAMS` 可能用于设置向量操作的参数，并指定源和目标元素的宽度。

**关于文件类型和 JavaScript 关系:**

-  `v8/src/execution/riscv/simulator-riscv.cc`  **不是**以 `.tq` 结尾，因此它是一个 **C++ 源代码文件**，而不是 v8 Torque 源代码。
-  它与 JavaScript 的功能有密切关系。 这个文件是 V8 JavaScript 引擎中 RISC-V 架构的模拟器代码的一部分。当 V8 需要在没有实际 RISC-V 硬件的平台上运行或进行调试时，它会使用这个模拟器来执行 RISC-V 的指令。JavaScript 代码最终会被 V8 编译成 RISC-V 的机器码（或者中间表示，然后被模拟器执行）。

**JavaScript 示例 (说明关系):**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它可以模拟执行由 V8 为 RISC-V 架构生成的、与 JavaScript 操作相关的指令。例如，以下 JavaScript 代码：

```javascript
function addArrays(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] + b[i]);
  }
  return result;
}

const arr1 = [1, 2, 3, 4];
const arr2 = [5, 6, 7, 8];
const sum = addArrays(arr1, arr2);
console.log(sum); // 输出 [6, 8, 10, 12]
```

当 V8 将 `addArrays` 函数编译成 RISC-V 机器码，并假定启用了向量扩展时，可能会生成类似于由 `RVV_VI_VFP_LOOP` 宏模拟的向量加法指令。模拟器会执行这些指令，从而实现 JavaScript 中数组的加法操作。

**代码逻辑推理和假设输入/输出:**

**假设输入 (`get_round`):**

- `vxrm`: 1 (round-to-nearest-even)
- `v`:  `0b1011` (十进制 11)
- `shift`: 2

**推理:**

- `shift` 是 2，所以我们关注从右往左数第 2 位（值为 1）和第 1 位（值为 1）。
- `d` (第 2 位) = 1
- `d1` (第 1 位) = 1
- `D2` (第 0 位) = 1
- 因为 `vxrm` 是 1 (round-to-nearest-even)，且 `D2` 不为 0，所以返回 `d1 & 1`，即 1。

**输出:** 1

**假设输入 (`signed_saturation`):**

- `v`: 150
- `n`: 7 (有符号 7 位整数范围是 -64 到 63)

**推理:**

- 最大有符号 7 位整数是 63。
- `v` (150) 大于 63。

**输出:** 63

**假设输入 (`unsigned_saturation`):**

- `v`: -10
- `n`: 4 (无符号 4 位整数范围是 0 到 15)

**推理:**

- `v` (-10) 小于 0。

**输出:** 0

**用户常见的编程错误举例:**

1. **整数溢出**:  在 JavaScript 中进行数值计算时，如果结果超出了 JavaScript Number 类型的安全整数范围，可能会导致精度丢失。在模拟器层面，`signed_saturation` 和 `unsigned_saturation` 宏模拟了硬件层面的饱和行为，这与 JavaScript 的默认行为不同。

   ```javascript
   let maxSafeInteger = Number.MAX_SAFE_INTEGER;
   console.log(maxSafeInteger + 1); // 输出 9007199254740992，可能不是期望的结果
   ```

2. **浮点数精度问题**: 浮点运算在计算机中通常是近似的。模拟器中的浮点循环宏 (`RVV_VI_VFP_LOOP`) 旨在模拟 RISC-V 硬件的浮点运算，这有助于开发者理解和调试在 V8 中执行的 JavaScript 浮点运算可能出现的精度问题。

   ```javascript
   let a = 0.1;
   let b = 0.2;
   console.log(a + b); // 输出 0.30000000000000004，而不是精确的 0.3
   ```

3. **不理解饱和运算**:  开发者可能期望数值运算会像 JavaScript 那样自动扩展范围，而没有意识到在某些底层操作中，数值会被饱和到一个固定的范围内。

   ```javascript
   // 假设 JavaScript 代码最终映射到需要饱和运算的底层指令
   function saturate(value) {
       // ... 模拟饱和行为
       if (value > 127) return 127;
       if (value < -128) return -128;
       return value;
   }
   console.log(saturate(150)); // 输出 127
   ```

**总结 `v8/src/execution/riscv/simulator-riscv.cc` (第 3 部分) 的功能:**

这部分代码是 V8 引擎中 RISC-V 模拟器的核心组成部分，专注于模拟 RISC-V 向量扩展指令的执行，特别是浮点和整数运算中的循环、舍入和饱和操作。它为在非 RISC-V 平台上运行或调试 JavaScript 代码提供了必要的基础设施，并有助于理解底层硬件行为对 JavaScript 代码执行的影响。

### 提示词
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/riscv/simulator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
_check);                                                           \
  switch (rvv_vsew()) {                                                       \
    case E8: {                                                                \
      CHECK8                                                                  \
      VI_VFP_LOOP_SCALE_BASE                                                  \
      BODY8 /*set_fp_exceptions*/;                                            \
      RVV_VI_VFP_LOOP_END                                                     \
    } break;                                                                  \
    case E16: {                                                               \
      CHECK16                                                                 \
      VI_VFP_LOOP_SCALE_BASE                                                  \
      BODY16 /*set_fp_exceptions*/;                                           \
      RVV_VI_VFP_LOOP_END                                                     \
    } break;                                                                  \
    case E32: {                                                               \
      CHECK32                                                                 \
      VI_VFP_LOOP_SCALE_BASE                                                  \
      BODY32 /*set_fp_exceptions*/;                                           \
      RVV_VI_VFP_LOOP_END                                                     \
    } break;                                                                  \
    default:                                                                  \
      require(0);                                                             \
      break;                                                                  \
  }                                                                           \
  rvv_trace_vd();

// calculate the value of r used in rounding
static inline uint8_t get_round(int vxrm, uint64_t v, uint8_t shift) {
  uint8_t d = v8::internal::unsigned_bitextract_64(shift, shift, v);
  uint8_t d1;
  uint64_t D1, D2;

  if (shift == 0 || shift > 64) {
    return 0;
  }

  d1 = v8::internal::unsigned_bitextract_64(shift - 1, shift - 1, v);
  D1 = v8::internal::unsigned_bitextract_64(shift - 1, 0, v);
  if (vxrm == 0) { /* round-to-nearest-up (add +0.5 LSB) */
    return d1;
  } else if (vxrm == 1) { /* round-to-nearest-even */
    if (shift > 1) {
      D2 = v8::internal::unsigned_bitextract_64(shift - 2, 0, v);
      return d1 & ((D2 != 0) | d);
    } else {
      return d1 & d;
    }
  } else if (vxrm == 3) { /* round-to-odd (OR bits into LSB, aka "jam") */
    return !d & (D1 != 0);
  }
  return 0; /* round-down (truncate) */
}

template <typename Src, typename Dst>
inline Dst signed_saturation(Src v, uint n) {
  Dst smax = (Dst)(INTPTR_MAX >> (sizeof(intptr_t) * 8 - n));
  Dst smin = (Dst)(INTPTR_MIN >> (sizeof(intptr_t) * 8 - n));
  return (v > smax) ? smax : ((v < smin) ? smin : (Dst)v);
}

template <typename Src, typename Dst>
inline Dst unsigned_saturation(Src v, uint n) {
  Dst umax = (Dst)(UINTPTR_MAX >> (sizeof(uintptr_t) * 8 - n));
  return (v > umax) ? umax : ((v < 0) ? 0 : (Dst)v);
}

#define RVV_VN_CLIPU_VI_LOOP()                                   \
  RVV_VI_GENERAL_LOOP_BASE                                       \
  RVV_VI_LOOP_MASK_SKIP()                                        \
  if (rvv_vsew() == E8) {                                        \
    VN_UPARAMS(16);                                              \
    vd = unsigned_saturation<uint16_t, uint8_t>(                 \
        (static_cast<uint16_t>(vs2) >> uimm5) +                  \
            get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        8);                                                      \
  } else if (rvv_vsew() == E16) {                                \
    VN_UPARAMS(32);                                              \
    vd = unsigned_saturation<uint32_t, uint16_t>(                \
        (static_cast<uint32_t>(vs2) >> uimm5) +                  \
            get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        16);                                                     \
  } else if (rvv_vsew() == E32) {                                \
    VN_UPARAMS(64);                                              \
    vd = unsigned_saturation<uint64_t, uint32_t>(                \
        (static_cast<uint64_t>(vs2) >> uimm5) +                  \
            get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        32);                                                     \
  } else if (rvv_vsew() == E64) {                                \
    UNREACHABLE();                                               \
  } else {                                                       \
    UNREACHABLE();                                               \
  }                                                              \
  RVV_VI_LOOP_END                                                \
  rvv_trace_vd();

#define RVV_VN_CLIP_VI_LOOP()                                                 \
  RVV_VI_GENERAL_LOOP_BASE                                                    \
  RVV_VI_LOOP_MASK_SKIP()                                                     \
  if (rvv_vsew() == E8) {                                                     \
    VN_PARAMS(16);                                                            \
    vd = signed_saturation<int16_t, int8_t>(                                  \
        (vs2 >> uimm5) + get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        8);                                                                   \
  } else if (rvv_vsew() == E16) {                                             \
    VN_PARAMS(32);                                                            \
    vd = signed_saturation<int32_t, int16_t>(                                 \
        (vs2 >> uimm5) + get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        16);                                                                  \
  } else if (rvv_vsew() == E32) {                                             \
    VN_PARAMS(64);                                                            \
    vd = signed_saturation<int64_t, int32_t>(                                 \
        (vs2 >> uimm5) + get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        32);                                                                  \
  } else if (rvv_vsew() == E64) {                                             \
    UNREACHABLE();                                                            \
  } else {                                                                    \
    UNREACHABLE();                                                            \
  }                                                                           \
  RVV_VI_LOOP_END                                                             \
  rvv_trace_vd();

#define CHECK_EXT(div)                                              \
  CHECK_NE(rvv_vd_reg(), rvv_vs2_reg());                            \
  reg_t from = rvv_vsew() / div;                                    \
  CHECK(from >= E8 && from <= E64);                                 \
  CHECK_GE((float)rvv_vflmul() / div, 0.125);                       \
  CHECK_LE((float)rvv_vflmul() / div, 8);                           \
  require_align(rvv_vd_reg(), rvv_vflmul());                        \
  require_align(rvv_vs2_reg(), rvv_vflmul() / div);                 \
  if ((rvv_vflmul() / div) < 1) {                                   \
    require_noover(rvv_vd_reg(), rvv_vflmul(), rvv_vs2_reg(),       \
                   rvv_vflmul() / div);                             \
  } else {                                                          \
    require_noover_widen(rvv_vd_reg(), rvv_vflmul(), rvv_vs2_reg(), \
                         rvv_vflmul() / div);                       \
  }

#define RVV_VI_VIE_8_LOOP(signed)      \
  CHECK_EXT(8)                         \
  RVV_VI_GENERAL_LOOP_BASE             \
  RVV_VI_LOOP_MASK_SKIP()              \
  if (rvv_vsew() == E64) {             \
    if (signed) {                      \
      VI_VIE_PARAMS(64, 8);            \
      vd = static_cast<int64_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(64, 8);           \
      vd = static_cast<uint64_t>(vs2); \
    }                                  \
  } else {                             \
    UNREACHABLE();                     \
  }                                    \
  RVV_VI_LOOP_END                      \
  rvv_trace_vd();

#define RVV_VI_VIE_4_LOOP(signed)      \
  CHECK_EXT(4)                         \
  RVV_VI_GENERAL_LOOP_BASE             \
  RVV_VI_LOOP_MASK_SKIP()              \
  if (rvv_vsew() == E32) {             \
    if (signed) {                      \
      VI_VIE_PARAMS(32, 4);            \
      vd = static_cast<int32_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(32, 4);           \
      vd = static_cast<uint32_t>(vs2); \
    }                                  \
  } else if (rvv_vsew() == E64) {      \
    if (signed) {                      \
      VI_VIE_PARAMS(64, 4);            \
      vd = static_cast<int64_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(64, 4);           \
      vd = static_cast<uint64_t>(vs2); \
    }                                  \
  } else {                             \
    UNREACHABLE();                     \
  }                                    \
  RVV_VI_LOOP_END                      \
  rvv_trace_vd();

#define RVV_VI_VIE_2_LOOP(signed)      \
  CHECK_EXT(2)                         \
  RVV_VI_GENERAL_LOOP_BASE             \
  RVV_VI_LOOP_MASK_SKIP()              \
  if (rvv_vsew() == E16) {             \
    if (signed) {                      \
      VI_VIE_PARAMS(16, 2);            \
      vd = static_cast<int16_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(16, 2);           \
      vd = static_cast<uint16_t>(vs2); \
    }                                  \
  } else if (rvv_vsew() == E32) {      \
    if (signed) {                      \
      VI_VIE_PARAMS(32, 2);            \
      vd = static_cast<int32_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(32, 2);           \
      vd = static_cast<uint32_t>(vs2); \
    }                                  \
  } else if (rvv_vsew() == E64) {      \
    if (signed) {                      \
      VI_VIE_PARAMS(64, 2);            \
      vd = static_cast<int64_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(64, 2);           \
      vd = static_cast<uint64_t>(vs2); \
    }                                  \
  } else {                             \
    UNREACHABLE();                     \
  }                                    \
  RVV_VI_LOOP_END                      \
  rvv_trace_vd();
#endif

namespace v8 {
namespace internal {

DEFINE_LAZY_LEAKY_OBJECT_GETTER(Simulator::GlobalMonitor,
                                Simulator::GlobalMonitor::Get)

// Util functions.
inline bool HaveSameSign(int64_t a, int64_t b) { return ((a ^ b) >= 0); }

uint32_t get_fcsr_condition_bit(uint32_t cc) {
  if (cc == 0) {
    return 23;
  } else {
    return 24 + cc;
  }
}

// Generated by Assembler::break_()/stop(), ebreak code is passed as immediate
// field of a subsequent LUI instruction; otherwise returns -1
static inline int32_t get_ebreak_code(Instruction* instr) {
  DCHECK(instr->InstructionBits() == kBreakInstr);
  uint8_t* cur = reinterpret_cast<uint8_t*>(instr);
  Instruction* next_instr = reinterpret_cast<Instruction*>(cur + kInstrSize);
  if (next_instr->BaseOpcodeFieldRaw() == LUI)
    return (next_instr->Imm20UValue());
  else
    return -1;
}

// This macro provides a platform independent use of sscanf. The reason for
// SScanF not being implemented in a platform independent was through
// ::v8::internal::OS in the same way as SNPrintF is that the Windows C Run-Time
// Library does not provide vsscanf.
#define SScanF sscanf

// The RiscvDebugger class is used by the simulator while debugging simulated
// code.
class RiscvDebugger {
 public:
  explicit RiscvDebugger(Simulator* sim) : sim_(sim) {}

  void Debug();
  // Print all registers with a nice formatting.
  void PrintRegs(char name_prefix, int start_index, int end_index);
  void PrintAllRegs();
  void PrintAllRegsIncludingFPU();

  static const Instr kNopInstr = 0x0;

 private:
  Simulator* sim_;

  sreg_t GetRegisterValue(int regnum);
  int64_t GetFPURegisterValue(int regnum);
  float GetFPURegisterValueFloat(int regnum);
  double GetFPURegisterValueDouble(int regnum);
#ifdef CAN_USE_RVV_INSTRUCTIONS
  __int128_t GetVRegisterValue(int regnum);
#endif
  bool GetValue(const char* desc, sreg_t* value);
};

#define UNSUPPORTED()                                                  \
  v8::base::EmbeddedVector<char, 256> buffer;                          \
  disasm::NameConverter converter;                                     \
  disasm::Disassembler dasm(converter);                                \
  dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_)); \
  printf("Sim: Unsupported inst. Func:%s Line:%d PC:0x%" REGIx_FORMAT, \
         __FUNCTION__, __LINE__, get_pc());                            \
  PrintF(" %-44s\n", buffer.begin());                                  \
  base::OS::Abort();

sreg_t RiscvDebugger::GetRegisterValue(int regnum) {
  if (regnum == kNumSimuRegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_register(regnum);
  }
}

int64_t RiscvDebugger::GetFPURegisterValue(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register(regnum);
  }
}

float RiscvDebugger::GetFPURegisterValueFloat(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register_float(regnum);
  }
}

double RiscvDebugger::GetFPURegisterValueDouble(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register_double(regnum);
  }
}

#ifdef CAN_USE_RVV_INSTRUCTIONS
__int128_t RiscvDebugger::GetVRegisterValue(int regnum) {
  if (regnum == kNumVRegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_vregister(regnum);
  }
}
#endif

bool RiscvDebugger::GetValue(const char* desc, sreg_t* value) {
  int regnum = Registers::Number(desc);
  int fpuregnum = FPURegisters::Number(desc);

  if (regnum != kInvalidRegister) {
    *value = GetRegisterValue(regnum);
    return true;
  } else if (fpuregnum != kInvalidFPURegister) {
    *value = GetFPURegisterValue(fpuregnum);
    return true;
  } else if (strncmp(desc, "0x", 2) == 0) {
#if V8_TARGET_ARCH_RISCV64
    return SScanF(desc + 2, "%" SCNx64, reinterpret_cast<reg_t*>(value)) == 1;
#elif V8_TARGET_ARCH_RISCV32
    return SScanF(desc + 2, "%" SCNx32, reinterpret_cast<reg_t*>(value)) == 1;
#endif
  } else {
#if V8_TARGET_ARCH_RISCV64
    return SScanF(desc, "%" SCNu64, reinterpret_cast<reg_t*>(value)) == 1;
#elif V8_TARGET_ARCH_RISCV32
    return SScanF(desc, "%" SCNu32, reinterpret_cast<reg_t*>(value)) == 1;
#endif
  }
}

#define REG_INFO(name)                             \
  name, GetRegisterValue(Registers::Number(name)), \
      GetRegisterValue(Registers::Number(name))

void RiscvDebugger::PrintRegs(char name_prefix, int start_index,
                              int end_index) {
  base::EmbeddedVector<char, 10> name1, name2;
  DCHECK(name_prefix == 'a' || name_prefix == 't' || name_prefix == 's');
  DCHECK(start_index >= 0 && end_index <= 99);
  int num_registers = (end_index - start_index) + 1;
  for (int i = 0; i < num_registers / 2; i++) {
    SNPrintF(name1, "%c%d", name_prefix, start_index + 2 * i);
    SNPrintF(name2, "%c%d", name_prefix, start_index + 2 * i + 1);
    PrintF("%3s: 0x%016" REGIx_FORMAT "  %14" REGId_FORMAT
           " \t%3s: 0x%016" REGIx_FORMAT "  %14" REGId_FORMAT " \n",
           REG_INFO(name1.begin()), REG_INFO(name2.begin()));
  }
  if (num_registers % 2 == 1) {
    SNPrintF(name1, "%c%d", name_prefix, end_index);
    PrintF("%3s: 0x%016" REGIx_FORMAT "  %14" REGId_FORMAT " \n",
           REG_INFO(name1.begin()));
  }
}

void RiscvDebugger::PrintAllRegs() {
  PrintF("\n");
  // ra, sp, gp
  PrintF("%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT
         "\t%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT
         "\t%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT "\n",
         REG_INFO("ra"), REG_INFO("sp"), REG_INFO("gp"));

  // tp, fp, pc
  PrintF("%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT
         "\t%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT
         "\t%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT "\n",
         REG_INFO("tp"), REG_INFO("fp"), REG_INFO("pc"));

  // print register a0, .., a7
  PrintRegs('a', 0, 7);
  // print registers s1, ..., s11
  PrintRegs('s', 1, 11);
  // print registers t0, ..., t6
  PrintRegs('t', 0, 6);
}

#undef REG_INFO

void RiscvDebugger::PrintAllRegsIncludingFPU() {
#define FPU_REG_INFO(n) \
  FPURegisters::Name(n), GetFPURegisterValue(n), GetFPURegisterValueDouble(n)

  PrintAllRegs();

  PrintF("\n\n");
  // f0, f1, f2, ... f31.
  DCHECK_EQ(kNumFPURegisters % 2, 0);
  for (int i = 0; i < kNumFPURegisters; i += 2)
    PrintF("%3s: 0x%016" PRIx64 "  %16.4e \t%3s: 0x%016" PRIx64 "  %16.4e\n",
           FPU_REG_INFO(i), FPU_REG_INFO(i + 1));
#undef FPU_REG_INFO
}

void RiscvDebugger::Debug() {
  intptr_t last_pc = -1;
  bool done = false;

#define COMMAND_SIZE 63
#define ARG_SIZE 255

#define STR(a) #a
#define XSTR(a) STR(a)

  char cmd[COMMAND_SIZE + 1];
  char arg1[ARG_SIZE + 1];
  char arg2[ARG_SIZE + 1];
  char* argv[3] = {cmd, arg1, arg2};

  // Make sure to have a proper terminating character if reaching the limit.
  cmd[COMMAND_SIZE] = 0;
  arg1[ARG_SIZE] = 0;
  arg2[ARG_SIZE] = 0;

  while (!done && (sim_->get_pc() != Simulator::end_sim_pc)) {
    if (last_pc != sim_->get_pc()) {
      disasm::NameConverter converter;
      disasm::Disassembler dasm(converter);
      // Use a reasonably large buffer.
      v8::base::EmbeddedVector<char, 256> buffer;
      const char* name = sim_->builtins_.Lookup((Address)sim_->get_pc());
      if (name != nullptr) {
        PrintF("Call builtin:  %s\n", name);
      }
      dasm.InstructionDecode(buffer,
                             reinterpret_cast<uint8_t*>(sim_->get_pc()));
      PrintF("  0x%016" REGIx_FORMAT "   %s\n", sim_->get_pc(), buffer.begin());
      last_pc = sim_->get_pc();
    }
    char* line = ReadLine("sim> ");
    if (line == nullptr) {
      break;
    } else {
      char* last_input = sim_->last_debugger_input();
      if (strcmp(line, "\n") == 0 && last_input != nullptr) {
        line = last_input;
      } else {
        // Ownership is transferred to sim_;
        sim_->set_last_debugger_input(line);
      }
      // Use sscanf to parse the individual parts of the command line. At the
      // moment no command expects more than two parameters.
      int argc = SScanF(
            line,
            "%" XSTR(COMMAND_SIZE) "s "
            "%" XSTR(ARG_SIZE) "s "
            "%" XSTR(ARG_SIZE) "s",
            cmd, arg1, arg2);
      if ((strcmp(cmd, "si") == 0) || (strcmp(cmd, "stepi") == 0)) {
        Instruction* instr = reinterpret_cast<Instruction*>(sim_->get_pc());
        if (!(instr->IsTrap()) ||
            instr->InstructionBits() == rtCallRedirInstr) {
          sim_->icount_++;
          sim_->InstructionDecode(
              reinterpret_cast<Instruction*>(sim_->get_pc()));
        } else {
          // Allow si to jump over generated breakpoints.
          PrintF("/!\\ Jumping over generated breakpoint.\n");
          sim_->set_pc(sim_->get_pc() + kInstrSize);
        }
      } else if ((strcmp(cmd, "c") == 0) || (strcmp(cmd, "cont") == 0)) {
        // Execute the one instruction we broke at with breakpoints disabled.
        sim_->InstructionDecode(reinterpret_cast<Instruction*>(sim_->get_pc()));
        // Leave the debugger shell.
        done = true;
      } else if ((strcmp(cmd, "p") == 0) || (strcmp(cmd, "print") == 0)) {
        if (argc == 2) {
          sreg_t value;
          int64_t fvalue;
          double dvalue;
          if (strcmp(arg1, "all") == 0) {
            PrintAllRegs();
          } else if (strcmp(arg1, "allf") == 0) {
            PrintAllRegsIncludingFPU();
          } else {
            int regnum = Registers::Number(arg1);
            int fpuregnum = FPURegisters::Number(arg1);
#ifdef CAN_USE_RVV_INSTRUCTIONS
            int vregnum = VRegisters::Number(arg1);
#endif
            if (regnum != kInvalidRegister) {
              value = GetRegisterValue(regnum);
              PrintF("%s: 0x%08" REGIx_FORMAT "  %" REGId_FORMAT "  \n", arg1,
                     value, value);
            } else if (fpuregnum != kInvalidFPURegister) {
              fvalue = GetFPURegisterValue(fpuregnum);
              dvalue = GetFPURegisterValueDouble(fpuregnum);
              PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n",
                     FPURegisters::Name(fpuregnum), fvalue, dvalue);
#ifdef CAN_USE_RVV_INSTRUCTIONS
            } else if (vregnum != kInvalidVRegister) {
              __int128_t v = GetVRegisterValue(vregnum);
              PrintF("\t%s:0x%016" PRIx64 "%016" PRIx64 "\n",
                     VRegisters::Name(vregnum), (uint64_t)(v >> 64),
                     (uint64_t)v);
#endif
            } else {
              PrintF("%s unrecognized\n", arg1);
            }
          }
        } else {
          if (argc == 3) {
            if (strcmp(arg2, "single") == 0) {
              int64_t value;
              float fvalue;
              int fpuregnum = FPURegisters::Number(arg1);

              if (fpuregnum != kInvalidFPURegister) {
                value = GetFPURegisterValue(fpuregnum);
                value &= 0xFFFFFFFFUL;
                fvalue = GetFPURegisterValueFloat(fpuregnum);
                PrintF("%s: 0x%08" PRIx64 "  %11.4e\n", arg1, value, fvalue);
              } else {
                PrintF("%s unrecognized\n", arg1);
              }
            } else {
              PrintF("print <fpu register> single\n");
            }
          } else {
            PrintF("print <register> or print <fpu register> single\n");
          }
        }
      } else if ((strcmp(cmd, "po") == 0) ||
                 (strcmp(cmd, "printobject") == 0)) {
        if (argc == 2) {
          sreg_t value;
          StdoutStream os;
          if (GetValue(arg1, &value)) {
            Tagged<Object> obj(value);
            os << arg1 << ": \n";
#ifdef DEBUG
            Print(obj, os);
            os << "\n";
#else
            os << Brief(obj) << "\n";
#endif
          } else {
            os << arg1 << " unrecognized\n";
          }
        } else {
          PrintF("printobject <value>\n");
        }
      } else if (strcmp(cmd, "stack") == 0 || strcmp(cmd, "mem") == 0) {
        sreg_t* cur = nullptr;
        sreg_t* end = nullptr;
        int next_arg = 1;

        if (strcmp(cmd, "stack") == 0) {
          cur = reinterpret_cast<sreg_t*>(sim_->get_register(Simulator::sp));
        } else {  // Command "mem".
          if (argc < 2) {
            PrintF("Need to specify <address> to mem command\n");
            continue;
          }
          sreg_t value;
          if (!GetValue(arg1, &value)) {
            PrintF("%s unrecognized\n", arg1);
            continue;
          }
          cur = reinterpret_cast<sreg_t*>(value);
          next_arg++;
        }

        sreg_t words;
        if (argc == next_arg) {
          words = 10;
        } else {
          if (!GetValue(argv[next_arg], &words)) {
            words = 10;
          }
        }
        end = cur + words;

        while (cur < end) {
          PrintF("  0x%012" PRIxPTR " :  0x%016" REGIx_FORMAT
                 "  %14" REGId_FORMAT " ",
                 reinterpret_cast<intptr_t>(cur), *cur, *cur);
          // Tagged<Object> obj(*cur);
          // Heap* current_heap = sim_->isolate_->heap();
          // if (IsSmi(obj) ||
          //     IsValidHeapObject(current_heap, Cast<HeapObject>(obj))) {
          //   PrintF(" (");
          //   if (IsSmi(obj)) {
          //     PrintF("smi %d", Smi::ToInt(obj));
          //   }
          //   PrintF(")");
          // }
          PrintF("\n");
          cur++;
        }
      } else if (strcmp(cmd, "memhex") == 0) {
        sreg_t* cur = nullptr;
        sreg_t* end = nullptr;
        int next_arg = 1;
        if (argc < 2) {
          PrintF("Need to specify <address> to memhex command\n");
          continue;
        }
        sreg_t value;
        if (!GetValue(arg1, &value)) {
          PrintF("%s unrecognized\n", arg1);
          continue;
        }
        cur = reinterpret_cast<sreg_t*>(value);
        next_arg++;

        sreg_t words;
        if (argc == next_arg) {
          words = 10;
        } else {
          if (!GetValue(argv[next_arg], &words)) {
            words = 10;
          }
        }
        end = cur + words;

        while (cur < end) {
          PrintF("  0x%012" PRIxPTR " :  0x%016" REGIx_FORMAT
                 "  %14" REGId_FORMAT " ",
                 reinterpret_cast<intptr_t>(cur), *cur, *cur);
          PrintF("\n");
          cur++;
        }
      } else if ((strcmp(cmd, "watch") == 0)) {
        if (argc < 2) {
          PrintF("Need to specify <address> to mem command\n");
          continue;
        }
        sreg_t value;
        if (!GetValue(arg1, &value)) {
          PrintF("%s unrecognized\n", arg1);
          continue;
        }
        sim_->watch_address_ = reinterpret_cast<sreg_t*>(value);
        sim_->watch_value_ = *(sim_->watch_address_);
      } else if ((strcmp(cmd, "disasm") == 0) || (strcmp(cmd, "dpc") == 0) ||
                 (strcmp(cmd, "di") == 0)) {
        disasm::NameConverter converter;
        disasm::Disassembler dasm(converter);
        // Use a reasonably large buffer.
        v8::base::EmbeddedVector<char, 256> buffer;

        uint8_t* cur = nullptr;
        uint8_t* end = nullptr;

        if (argc == 1) {
          cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
          end = cur + (10 * kInstrSize);
        } else if (argc == 2) {
          int regnum = Registers::Number(arg1);
          if (regnum != kInvalidRegister || strncmp(arg1, "0x", 2) == 0) {
            // The argument is an address or a register name.
            sreg_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(value);
              // Disassemble 10 instructions at <arg1>.
              end = cur + (10 * kInstrSize);
            }
          } else {
            // The argument is the number of instructions.
            sreg_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
              // Disassemble <arg1> instructions.
              end = cur + (value * kInstrSize);
            }
          }
        } else {
          sreg_t value1;
          sreg_t value2;
          if (GetValue(arg1, &value1) && GetValue(arg2, &value2)) {
            cur = reinterpret_cast<uint8_t*>(value1);
            end = cur + (value2 * kInstrSize);
          }
        }

        while (cur < end) {
          dasm.InstructionDecode(buffer, cur);
          PrintF("  0x%08" PRIxPTR "   %s\n", reinterpret_cast<intptr_t>(cur),
                 buffer.begin());
          cur += kInstrSize;
        }
      } else if (strcmp(cmd, "gdb") == 0) {
        PrintF("relinquishing control to gdb\n");
        v8::base::OS::DebugBreak();
        PrintF("regaining control from gdb\n");
      } else if (strcmp(cmd, "trace") == 0) {
        PrintF("enable trace sim\n");
        v8_flags.trace_sim = true;
      } else if (strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0 ||
                 strcmp(cmd, "tbreak") == 0) {
        bool is_tbreak = strcmp(cmd, "tbreak") == 0;
        if (argc == 2) {
          sreg_t value;
          if (GetValue(arg1, &value)) {
            sim_->SetBreakpoint(reinterpret_cast<Instruction*>(value),
                                is_tbreak);
          } else {
            PrintF("%s unrecognized\n", arg1);
          }
        } else {
          sim_->ListBreakpoints();
          PrintF("Use `break <address>` to set or disable a breakpoint\n");
          PrintF(
              "Use `tbreak <address>` to set or disable a temporary "
              "breakpoint\n");
        }
      } else if (strcmp(cmd, "flags") == 0) {
        PrintF("No flags on RISC-V !\n");
      } else if (strcmp(cmd, "stop") == 0) {
        sreg_t value;
        if (argc == 3) {
          // Print information about all/the specified breakpoint(s).
          if (strcmp(arg1, "info") == 0) {
            if (strcmp(arg2, "all") == 0) {
              PrintF("Stop information:\n");
              for (uint32_t i = kMaxWatchpointCode + 1; i <= kMaxStopCode;
                   i++) {
                sim_->PrintStopInfo(i);
              }
            } else if (GetValue(arg2, &value)) {
              sim_->PrintStopInfo(value);
            } else {
              PrintF("Unrecognized argument.\n");
            }
          } else if (strcmp(arg1, "enable") == 0) {
            // Enable all/the specified breakpoint(s).
            if (strcmp(arg2, "all") == 0) {
              for (uint32_t i = kMaxWatchpointCode + 1; i <= kMaxStopCode;
                   i++) {
                sim_->EnableStop(i);
              }
            } else if (GetValue(arg2, &value)) {
              sim_->EnableStop(value);
            } else {
              PrintF("Unrecognized argument.\n");
            }
          } else if (strcmp(arg1, "disable") == 0) {
            // Disable all/the specified breakpoint(s).
            if (strcmp(arg2, "all") == 0) {
              for (uint32_t i = kMaxWatchpointCode + 1; i <= kMaxStopCode;
                   i++) {
                sim_->DisableStop(i);
              }
            } else if (GetValue(arg2, &value)) {
              sim_->DisableStop(value);
            } else {
              PrintF("Unrecognized argument.\n");
            }
          }
        } else {
          PrintF("Wrong usage. Use help command for more information.\n");
        }
      } else if ((strcmp(cmd, "stat") == 0) || (strcmp(cmd, "st") == 0)) {
        // Print registers and disassemble.
        PrintAllRegs();
        PrintF("\n");

        disasm::NameConverter converter;
        disasm::Disassembler dasm(converter);
        // Use a reasonably large buffer.
        v8::base::EmbeddedVector<char, 256> buffer;

        uint8_t* cur = nullptr;
        uint8_t* end = nullptr;

        if (argc == 1) {
          cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
          end = cur + (10 * kInstrSize);
        } else if (argc == 2) {
          sreg_t value;
          if (GetValue(arg1, &value)) {
            cur = reinterpret_cast<uint8_t*>(value);
            // no length parameter passed, assume 10 instructions
            end = cur + (10 * kInstrSize);
          }
        } else {
          sreg_t value1;
          sreg_t value2;
          if (GetValue(arg1, &value1) && GetValue(arg2, &value2)) {
            cur = reinterpret_cast<uint8_t*>(value1);
            end = cur + (value2 * kInstrSize);
          }
        }

        while (cur < end) {
          dasm.InstructionDecode(buffer, cur);
          PrintF("  0x%08" PRIxPTR "   %s\n", reinterpret_cast<intptr_t>(cur),
                 buffer.begin());
          cur += kInstrSize;
        }
      } else if ((strcmp(cmd, "h") == 0) || (strcmp(cmd, "help") == 0)) {
        PrintF("cont (alias 'c')\n");
        PrintF("  Continue execution\n");
        PrintF("stepi (alias 'si')\n");
        PrintF("  Step one instruction\n");
        PrintF("print (alias 'p')\n");
        PrintF("  print <register>\n");
        PrintF("  Print register content\n");
        PrintF("  Use register name 'all' to print all GPRs\n");
        PrintF("  Use register name 'allf' to print all GPRs and FPRs\n");
        PrintF("printobject (alias 'po')\n");
        PrintF("  printobject <register>\n");
        PrintF("  Print an object from a register\n");
        PrintF("stack\n");
        PrintF("  stack [<words>]\n");
        PrintF("  Dump stack content, default dump 10 words)\n");
        PrintF("mem\n");
        PrintF("  mem <address> [<words>]\n");
        PrintF("  Dump memory content, default dump 10 words)\n");
        PrintF("watch\n");
        PrintF("  watch <address> \n");
        PrintF("  watch memory content.
```