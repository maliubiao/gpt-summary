Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/arm/macro-assembler-arm.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The filename suggests this is related to code generation for the ARM architecture within the V8 JavaScript engine. The "MacroAssembler" part hints at a low-level interface for emitting machine code instructions.

2. **Analyze Function Categories:**  Scan the function names and their arguments to identify logical groupings of operations. Common patterns emerge:
    * **Floating-Point Operations (VFP):**  Functions like `VFPCompareAndSetFlags`, `VFPCompareAndLoadFlags`, `VmovHigh`, `VmovLow`, `VmovExtended`. These clearly deal with ARM's Vector Floating-Point unit.
    * **NEON Instructions:** Functions like `ExtractLane`, `ReplaceLane`, `LoadLane`, `StoreLane` involving `QwNeonRegister` and `NeonDataType`. This points to operations using ARM's NEON SIMD extensions.
    * **Bitwise Shift Operations (Pairs):**  Functions like `LslPair`, `LsrPair`, `AsrPair`. These manipulate pairs of registers as a 64-bit value.
    * **Stack Frame Management:** Functions like `StubPrologue`, `Prologue`, `DropArguments`, `EnterFrame`, `LeaveFrame`, `AllocateStackSpace`, `EnterExitFrame`, `LeaveExitFrame`. These are fundamental for function call setup and teardown.
    * **Function Invocation:** Functions like `InvokePrologue`, `CallDebugOnFunctionCall`, `InvokeFunctionCode`, `InvokeFunctionWithNewTarget`, `InvokeFunction`. These handle calling JavaScript functions.
    * **Exception Handling:** Functions like `PushStackHandler`, `PopStackHandler`. These manage the stack of exception handlers.
    * **Object Type Checks:** Functions like `CompareObjectType`, `CompareObjectTypeRange`, `CompareInstanceType`, `CompareInstanceTypeRange`. These are used for verifying the type of JavaScript objects.
    * **Root Object Comparisons:** Functions like `CompareTaggedRoot`, `CompareRoot`. These compare registers with predefined root objects in the V8 heap.
    * **Utility/Helper Functions:**  Functions like `MovFromFloatResult`, `MovFromFloatParameter`, `LoadStackLimit`, `StackOverflowCheck`. These perform specific, often low-level tasks.

3. **Synthesize Functionality Descriptions:** For each category, describe the overall purpose and provide specific examples of what the functions do. Use clear and concise language.

4. **Address Specific Constraints:**
    * **`.tq` extension:** Explicitly state that this file is `.cc` and not `.tq`, so it's C++ code, not Torque.
    * **Relationship to JavaScript:**  Explain how these low-level operations are used to implement higher-level JavaScript features (e.g., arithmetic, function calls, object manipulation). Provide illustrative JavaScript examples that would rely on these underlying mechanisms.
    * **Code Logic Reasoning:** For functions with clear input-output behavior (like the bitwise shift pairs), create simple examples with assumed inputs and their expected outputs.
    * **Common Programming Errors:** Think about common errors related to the operations performed by these functions (e.g., incorrect floating-point comparisons, stack overflow, type mismatches). Provide simple code snippets demonstrating these errors.

5. **Structure the Summary:** Organize the information logically using headings and bullet points for readability.

6. **Review and Refine:** Read through the generated summary to ensure accuracy, clarity, and completeness. Check that all parts of the code snippet have been covered and the constraints have been addressed. For example, ensure that the provided JavaScript examples are relevant to the C++ code's function.

By following this systematic approach, we can create a comprehensive and informative summary of the `macro-assembler-arm.cc` code snippet, addressing all the user's requirements.
这是 `v8/src/codegen/arm/macro-assembler-arm.cc` 文件代码片段的第二部分，延续了第一部分的功能，主要提供了用于生成 ARM 架构机器码的宏汇编器接口。  这一部分集中在以下功能：

**核心功能延续:**

* **浮点运算 (VFP/NEON):** 提供了执行浮点数比较、加载 FPSCR 标志、在 VFP 寄存器和通用寄存器之间移动数据（包括高低位）、以及扩展移动数据的指令。也包括了使用 NEON 指令进行 SIMD 操作，例如提取和替换 NEON 寄存器中的 lane。
* **内存操作 (Load/Store):** 提供了从内存加载数据到 NEON 寄存器和将 NEON 寄存器数据存储到内存的指令，包括针对特定 lane 的操作。
* **位操作 (Shift):** 提供了对寄存器对进行逻辑左移、逻辑右移和算术右移的指令。这些操作通常用于处理 64 位值。
* **栈帧管理:** 提供了用于创建和销毁栈帧的指令，包括标准栈帧、Stub 栈帧和 Exit 栈帧。也提供了分配和释放栈空间的操作。
* **函数调用:** 提供了用于调用 JavaScript 函数的指令，包括设置参数、处理参数数量不匹配的情况、以及在调试模式下的处理。
* **异常处理:** 提供了用于压入和弹出栈处理器的指令，用于管理异常处理流程。
* **对象类型检查:** 提供了用于比较对象的类型和实例类型的指令，常用于运行时类型检查。
* **根对象比较:** 提供了用于比较寄存器值与预定义的根对象的指令。

**具体功能归纳:**

1. **精确的浮点比较和标志设置:**  `VFPCompareAndSetFlags` 和 `VFPCompareAndLoadFlags` 系列函数用于比较 VFP 寄存器中的浮点数或浮点数与立即数，并将比较结果反映到 CPU 的条件标志或 FPSCR 寄存器中。

2. **VFP 寄存器数据移动:** `VmovHigh` 和 `VmovLow` 函数用于在通用寄存器和 VFP 双精度寄存器的高低 32 位之间移动数据。 `VmovExtended` 提供了一种在不同 VFP 寄存器（包括单精度和双精度）之间移动数据的方式，并处理了当 VFP 寄存器数量为 16 或 32 时的不同情况。

3. **NEON SIMD 操作:** `ExtractLane` 函数用于从 NEON 寄存器中提取特定 lane 的数据到通用寄存器或 VFP 寄存器。 `ReplaceLane` 函数用于将通用寄存器或 VFP 寄存器的值替换到 NEON 寄存器的特定 lane 中。 `LoadLane` 和 `StoreLane` 用于加载和存储 NEON 寄存器的特定 lane 到内存。

4. **64 位移位操作:** `LslPair`, `LsrPair`, `AsrPair` 函数用于对两个寄存器组成的 64 位值进行左移、逻辑右移和算术右移操作。 它们考虑了移位量大于 32 位的情况。

5. **栈帧的建立和销毁:** `StubPrologue` 用于创建特定类型的 Stub 栈帧。 `Prologue` 用于创建标准栈帧。 `DropArguments` 用于调整栈指针以移除函数参数。 `EnterFrame` 用于创建新的栈帧，并可选地加载常量池指针。 `LeaveFrame` 用于销毁栈帧。 `AllocateStackSpace` 用于在栈上分配空间，尤其在 Windows 平台上会确保触及每一页内存。 `EnterExitFrame` 和 `LeaveExitFrame` 用于处理从 JavaScript 代码到 C++ 代码的调用边界。

6. **从浮点运算结果/参数中获取值:** `MovFromFloatResult` 和 `MovFromFloatParameter` 用于从浮点运算的结果寄存器（通常是 `d0`）或者参数寄存器中获取浮点数值。

7. **栈溢出检查:** `LoadStackLimit` 用于加载栈顶限制。 `StackOverflowCheck` 用于检查函数调用是否会导致栈溢出。

8. **函数调用的准备和执行:** `InvokePrologue` 用于在函数调用前进行参数数量检查和栈空间调整。 `CallDebugOnFunctionCall` 用于在调试模式下触发函数调用钩子。 `InvokeFunctionCode` 是实际执行函数调用的核心，它会根据调用类型（Call 或 Jump）调用相应的 JSFunction。 `InvokeFunctionWithNewTarget` 和 `InvokeFunction` 是 `InvokeFunctionCode` 的高层封装，用于处理带有 `new.target` 的调用和普通调用。

9. **栈处理器管理:** `PushStackHandler` 用于将当前的栈处理器压入栈中。 `PopStackHandler` 用于弹出栈处理器。

10. **对象类型和根对象比较:** `CompareObjectType` 和 `CompareObjectTypeRange` 用于比较对象的类型是否在指定的范围内。 `CompareInstanceType` 和 `CompareInstanceTypeRange` 用于比较实例类型。 `CompareTaggedRoot` 和 `CompareRoot` 用于比较寄存器中的值是否与特定的根对象相等。

**关于代码逻辑推理的例子:**

假设输入：
* `dst_low` 和 `dst_high` 是目标寄存器，例如 `r0`, `r1`
* `src_low` 和 `src_high` 是源寄存器，例如 `r2`, `r3`
* `shift` 是立即数 5

对于 `LslPair(r0, r1, r2, r3, 5)`：

* **假设输入:** `r2` 的值为 `0xAAAAAAA`, `r3` 的值为 `0xBBBBBBB`
* **预期输出:**
    * `r0` 的值为 `0x55555540` ( `0xAAAAAAA` 左移 5 位)
    * `r1` 的值为 `0x0000001D` ( `0xBBBBBBB` 左移 5 位，加上 `0xAAAAAAA` 移出的高位)
    * 实现了将由 `r3:r2` 表示的 64 位值左移 5 位，结果存入 `r1:r0`。

**与 JavaScript 功能的关系示例:**

很多这里的底层指令都支撑着 JavaScript 的各种操作。例如：

```javascript
function add(a, b) {
  return a + b;
}

add(1.5, 2.5);
```

当执行这段 JavaScript 代码时，V8 会生成机器码。`MacroAssembler` 中提供的浮点运算指令（如 `vadd`，虽然此片段未展示，但在同一个文件中可能存在）会被用来实现 `1.5 + 2.5` 的加法运算。`MovFromFloatParameter` 可能被用于将 JavaScript 传递的浮点数参数加载到 VFP 寄存器中。

再比如：

```javascript
function shiftLeft(x) {
  return x << 5;
}

shiftLeft(0xAAAAAAA);
```

对于 32 位整数的左移，ARM 的 `lsl` 指令就可以处理。但如果 JavaScript 中的数值超过 32 位，`LslPair` 这样的指令就会被用到，将 JavaScript 的大整数表示在两个寄存器中进行移位操作。

**用户常见的编程错误示例:**

* **错误的浮点数比较:**  直接使用 `==` 比较浮点数可能由于精度问题导致错误。 `VFPCompareAndSetFlags` 这样的指令虽然在底层，但它反映了浮点比较的复杂性。 程序员在编写涉及到浮点数比较的 JavaScript 代码时，应该注意使用适当的容差或者专门的比较函数。

```javascript
let a = 0.1 + 0.2;
let b = 0.3;
console.log(a == b); // 输出 false，因为浮点数精度问题
```

* **栈溢出:** 递归调用过深的函数会导致栈溢出。 `StackOverflowCheck` 这样的底层检查可以防止程序崩溃，并抛出错误。 JavaScript 程序员应该避免无限递归或创建过大的局部变量。

```javascript
function recursiveFn() {
  recursiveFn();
}
recursiveFn(); // 可能导致栈溢出错误
```

* **类型错误:** JavaScript 是动态类型的，但很多 V8 的底层操作都依赖于类型信息。 如果 JavaScript 代码传递了错误的类型，即使底层指令可以执行，也可能产生非预期的结果或导致错误。 `CompareObjectType` 等指令用于在运行时进行类型检查，确保操作的有效性。

```javascript
function onlyAcceptsNumbers(num) {
  return num + 1;
}
onlyAcceptsNumbers("hello"); // JavaScript 不会报错，但结果可能不是预期的
```

**总结一下，这部分 `v8/src/codegen/arm/macro-assembler-arm.cc` 代码片段的功能是:**

提供了一组用于在 ARM 架构上生成高效机器码的低级接口，专注于浮点运算、NEON SIMD 操作、64 位位操作、栈帧管理、函数调用和类型检查等核心功能，这些功能是 V8 引擎执行 JavaScript 代码的基础。它抽象了底层的 ARM 指令，为 V8 的其他代码生成模块提供了便利。

Prompt: 
```
这是目录为v8/src/codegen/arm/macro-assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm/macro-assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
nalling NaNs, which
  // become quiet NaNs. We use vsub rather than vadd because vsub preserves -0.0
  // inputs: -0.0 + 0.0 = 0.0, but -0.0 - 0.0 = -0.0.
  vsub(dst, src, kDoubleRegZero, cond);
}

void MacroAssembler::VFPCompareAndSetFlags(const SwVfpRegister src1,
                                           const SwVfpRegister src2,
                                           const Condition cond) {
  // Compare and move FPSCR flags to the normal condition flags.
  VFPCompareAndLoadFlags(src1, src2, pc, cond);
}

void MacroAssembler::VFPCompareAndSetFlags(const SwVfpRegister src1,
                                           const float src2,
                                           const Condition cond) {
  // Compare and move FPSCR flags to the normal condition flags.
  VFPCompareAndLoadFlags(src1, src2, pc, cond);
}

void MacroAssembler::VFPCompareAndSetFlags(const DwVfpRegister src1,
                                           const DwVfpRegister src2,
                                           const Condition cond) {
  // Compare and move FPSCR flags to the normal condition flags.
  VFPCompareAndLoadFlags(src1, src2, pc, cond);
}

void MacroAssembler::VFPCompareAndSetFlags(const DwVfpRegister src1,
                                           const double src2,
                                           const Condition cond) {
  // Compare and move FPSCR flags to the normal condition flags.
  VFPCompareAndLoadFlags(src1, src2, pc, cond);
}

void MacroAssembler::VFPCompareAndLoadFlags(const SwVfpRegister src1,
                                            const SwVfpRegister src2,
                                            const Register fpscr_flags,
                                            const Condition cond) {
  // Compare and load FPSCR.
  vcmp(src1, src2, cond);
  vmrs(fpscr_flags, cond);
}

void MacroAssembler::VFPCompareAndLoadFlags(const SwVfpRegister src1,
                                            const float src2,
                                            const Register fpscr_flags,
                                            const Condition cond) {
  // Compare and load FPSCR.
  vcmp(src1, src2, cond);
  vmrs(fpscr_flags, cond);
}

void MacroAssembler::VFPCompareAndLoadFlags(const DwVfpRegister src1,
                                            const DwVfpRegister src2,
                                            const Register fpscr_flags,
                                            const Condition cond) {
  // Compare and load FPSCR.
  vcmp(src1, src2, cond);
  vmrs(fpscr_flags, cond);
}

void MacroAssembler::VFPCompareAndLoadFlags(const DwVfpRegister src1,
                                            const double src2,
                                            const Register fpscr_flags,
                                            const Condition cond) {
  // Compare and load FPSCR.
  vcmp(src1, src2, cond);
  vmrs(fpscr_flags, cond);
}

void MacroAssembler::VmovHigh(Register dst, DwVfpRegister src) {
  if (src.code() < 16) {
    const LowDwVfpRegister loc = LowDwVfpRegister::from_code(src.code());
    vmov(dst, loc.high());
  } else {
    vmov(NeonS32, dst, src, 1);
  }
}

void MacroAssembler::VmovHigh(DwVfpRegister dst, Register src) {
  if (dst.code() < 16) {
    const LowDwVfpRegister loc = LowDwVfpRegister::from_code(dst.code());
    vmov(loc.high(), src);
  } else {
    vmov(NeonS32, dst, 1, src);
  }
}

void MacroAssembler::VmovLow(Register dst, DwVfpRegister src) {
  if (src.code() < 16) {
    const LowDwVfpRegister loc = LowDwVfpRegister::from_code(src.code());
    vmov(dst, loc.low());
  } else {
    vmov(NeonS32, dst, src, 0);
  }
}

void MacroAssembler::VmovLow(DwVfpRegister dst, Register src) {
  if (dst.code() < 16) {
    const LowDwVfpRegister loc = LowDwVfpRegister::from_code(dst.code());
    vmov(loc.low(), src);
  } else {
    vmov(NeonS32, dst, 0, src);
  }
}

void MacroAssembler::VmovExtended(Register dst, int src_code) {
  DCHECK_LE(SwVfpRegister::kNumRegisters, src_code);
  DCHECK_GT(SwVfpRegister::kNumRegisters * 2, src_code);
  if (src_code & 0x1) {
    VmovHigh(dst, DwVfpRegister::from_code(src_code / 2));
  } else {
    VmovLow(dst, DwVfpRegister::from_code(src_code / 2));
  }
}

void MacroAssembler::VmovExtended(int dst_code, Register src) {
  DCHECK_LE(SwVfpRegister::kNumRegisters, dst_code);
  DCHECK_GT(SwVfpRegister::kNumRegisters * 2, dst_code);
  if (dst_code & 0x1) {
    VmovHigh(DwVfpRegister::from_code(dst_code / 2), src);
  } else {
    VmovLow(DwVfpRegister::from_code(dst_code / 2), src);
  }
}

void MacroAssembler::VmovExtended(int dst_code, int src_code) {
  if (src_code == dst_code) return;

  if (src_code < SwVfpRegister::kNumRegisters &&
      dst_code < SwVfpRegister::kNumRegisters) {
    // src and dst are both s-registers.
    vmov(SwVfpRegister::from_code(dst_code),
         SwVfpRegister::from_code(src_code));
    return;
  }
  DwVfpRegister dst_d_reg = DwVfpRegister::from_code(dst_code / 2);
  DwVfpRegister src_d_reg = DwVfpRegister::from_code(src_code / 2);
  int dst_offset = dst_code & 1;
  int src_offset = src_code & 1;
  if (CpuFeatures::IsSupported(NEON)) {
    UseScratchRegisterScope temps(this);
    DwVfpRegister scratch = temps.AcquireD();
    // On Neon we can shift and insert from d-registers.
    if (src_offset == dst_offset) {
      // Offsets are the same, use vdup to copy the source to the opposite lane.
      vdup(Neon32, scratch, src_d_reg, src_offset);
      // Here we are extending the lifetime of scratch.
      src_d_reg = scratch;
      src_offset = dst_offset ^ 1;
    }
    if (dst_offset) {
      if (dst_d_reg == src_d_reg) {
        vdup(Neon32, dst_d_reg, src_d_reg, 0);
      } else {
        vsli(Neon64, dst_d_reg, src_d_reg, 32);
      }
    } else {
      if (dst_d_reg == src_d_reg) {
        vdup(Neon32, dst_d_reg, src_d_reg, 1);
      } else {
        vsri(Neon64, dst_d_reg, src_d_reg, 32);
      }
    }
    return;
  }

  // Without Neon, use the scratch registers to move src and/or dst into
  // s-registers.
  UseScratchRegisterScope temps(this);
  LowDwVfpRegister d_scratch = temps.AcquireLowD();
  LowDwVfpRegister d_scratch2 = temps.AcquireLowD();
  int s_scratch_code = d_scratch.low().code();
  int s_scratch_code2 = d_scratch2.low().code();
  if (src_code < SwVfpRegister::kNumRegisters) {
    // src is an s-register, dst is not.
    vmov(d_scratch, dst_d_reg);
    vmov(SwVfpRegister::from_code(s_scratch_code + dst_offset),
         SwVfpRegister::from_code(src_code));
    vmov(dst_d_reg, d_scratch);
  } else if (dst_code < SwVfpRegister::kNumRegisters) {
    // dst is an s-register, src is not.
    vmov(d_scratch, src_d_reg);
    vmov(SwVfpRegister::from_code(dst_code),
         SwVfpRegister::from_code(s_scratch_code + src_offset));
  } else {
    // Neither src or dst are s-registers. Both scratch double registers are
    // available when there are 32 VFP registers.
    vmov(d_scratch, src_d_reg);
    vmov(d_scratch2, dst_d_reg);
    vmov(SwVfpRegister::from_code(s_scratch_code + dst_offset),
         SwVfpRegister::from_code(s_scratch_code2 + src_offset));
    vmov(dst_d_reg, d_scratch2);
  }
}

void MacroAssembler::VmovExtended(int dst_code, const MemOperand& src) {
  if (dst_code < SwVfpRegister::kNumRegisters) {
    vldr(SwVfpRegister::from_code(dst_code), src);
  } else {
    UseScratchRegisterScope temps(this);
    LowDwVfpRegister scratch = temps.AcquireLowD();
    // TODO(bbudge) If Neon supported, use load single lane form of vld1.
    int dst_s_code = scratch.low().code() + (dst_code & 1);
    vmov(scratch, DwVfpRegister::from_code(dst_code / 2));
    vldr(SwVfpRegister::from_code(dst_s_code), src);
    vmov(DwVfpRegister::from_code(dst_code / 2), scratch);
  }
}

void MacroAssembler::VmovExtended(const MemOperand& dst, int src_code) {
  if (src_code < SwVfpRegister::kNumRegisters) {
    vstr(SwVfpRegister::from_code(src_code), dst);
  } else {
    // TODO(bbudge) If Neon supported, use store single lane form of vst1.
    UseScratchRegisterScope temps(this);
    LowDwVfpRegister scratch = temps.AcquireLowD();
    int src_s_code = scratch.low().code() + (src_code & 1);
    vmov(scratch, DwVfpRegister::from_code(src_code / 2));
    vstr(SwVfpRegister::from_code(src_s_code), dst);
  }
}

void MacroAssembler::ExtractLane(Register dst, QwNeonRegister src,
                                 NeonDataType dt, int lane) {
  int size = NeonSz(dt);  // 0, 1, 2
  int byte = lane << size;
  int double_word = byte >> kDoubleSizeLog2;
  int double_byte = byte & (kDoubleSize - 1);
  int double_lane = double_byte >> size;
  DwVfpRegister double_source =
      DwVfpRegister::from_code(src.code() * 2 + double_word);
  vmov(dt, dst, double_source, double_lane);
}

void MacroAssembler::ExtractLane(Register dst, DwVfpRegister src,
                                 NeonDataType dt, int lane) {
  int size = NeonSz(dt);  // 0, 1, 2
  int byte = lane << size;
  int double_byte = byte & (kDoubleSize - 1);
  int double_lane = double_byte >> size;
  vmov(dt, dst, src, double_lane);
}

void MacroAssembler::ExtractLane(SwVfpRegister dst, QwNeonRegister src,
                                 int lane) {
  int s_code = src.code() * 4 + lane;
  VmovExtended(dst.code(), s_code);
}

void MacroAssembler::ExtractLane(DwVfpRegister dst, QwNeonRegister src,
                                 int lane) {
  DwVfpRegister double_dst = DwVfpRegister::from_code(src.code() * 2 + lane);
  vmov(dst, double_dst);
}

void MacroAssembler::ReplaceLane(QwNeonRegister dst, QwNeonRegister src,
                                 Register src_lane, NeonDataType dt, int lane) {
  Move(dst, src);
  int size = NeonSz(dt);  // 0, 1, 2
  int byte = lane << size;
  int double_word = byte >> kDoubleSizeLog2;
  int double_byte = byte & (kDoubleSize - 1);
  int double_lane = double_byte >> size;
  DwVfpRegister double_dst =
      DwVfpRegister::from_code(dst.code() * 2 + double_word);
  vmov(dt, double_dst, double_lane, src_lane);
}

void MacroAssembler::ReplaceLane(QwNeonRegister dst, QwNeonRegister src,
                                 SwVfpRegister src_lane, int lane) {
  Move(dst, src);
  int s_code = dst.code() * 4 + lane;
  VmovExtended(s_code, src_lane.code());
}

void MacroAssembler::ReplaceLane(QwNeonRegister dst, QwNeonRegister src,
                                 DwVfpRegister src_lane, int lane) {
  Move(dst, src);
  DwVfpRegister double_dst = DwVfpRegister::from_code(dst.code() * 2 + lane);
  vmov(double_dst, src_lane);
}

void MacroAssembler::LoadLane(NeonSize sz, NeonListOperand dst_list,
                              uint8_t lane, NeonMemOperand src) {
  if (sz == Neon64) {
    // vld1s is not valid for Neon64.
    vld1(Neon64, dst_list, src);
  } else {
    vld1s(sz, dst_list, lane, src);
  }
}

void MacroAssembler::StoreLane(NeonSize sz, NeonListOperand src_list,
                               uint8_t lane, NeonMemOperand dst) {
  if (sz == Neon64) {
    // vst1s is not valid for Neon64.
    vst1(Neon64, src_list, dst);
  } else {
    vst1s(sz, src_list, lane, dst);
  }
}

void MacroAssembler::LslPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift) {
  DCHECK(!AreAliased(dst_high, src_low));
  DCHECK(!AreAliased(dst_high, shift));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  Label less_than_32;
  Label done;
  rsb(scratch, shift, Operand(32), SetCC);
  b(gt, &less_than_32);
  // If shift >= 32
  and_(scratch, shift, Operand(0x1F));
  lsl(dst_high, src_low, Operand(scratch));
  mov(dst_low, Operand(0));
  jmp(&done);
  bind(&less_than_32);
  // If shift < 32
  lsl(dst_high, src_high, Operand(shift));
  orr(dst_high, dst_high, Operand(src_low, LSR, scratch));
  lsl(dst_low, src_low, Operand(shift));
  bind(&done);
}

void MacroAssembler::LslPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             uint32_t shift) {
  DCHECK_GE(63, shift);
  DCHECK(!AreAliased(dst_high, src_low));

  if (shift == 0) {
    Move(dst_high, src_high);
    Move(dst_low, src_low);
  } else if (shift == 32) {
    Move(dst_high, src_low);
    Move(dst_low, Operand(0));
  } else if (shift >= 32) {
    shift &= 0x1F;
    lsl(dst_high, src_low, Operand(shift));
    mov(dst_low, Operand(0));
  } else {
    lsl(dst_high, src_high, Operand(shift));
    orr(dst_high, dst_high, Operand(src_low, LSR, 32 - shift));
    lsl(dst_low, src_low, Operand(shift));
  }
}

void MacroAssembler::LsrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift) {
  DCHECK(!AreAliased(dst_low, src_high));
  DCHECK(!AreAliased(dst_low, shift));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  Label less_than_32;
  Label done;
  rsb(scratch, shift, Operand(32), SetCC);
  b(gt, &less_than_32);
  // If shift >= 32
  and_(scratch, shift, Operand(0x1F));
  lsr(dst_low, src_high, Operand(scratch));
  mov(dst_high, Operand(0));
  jmp(&done);
  bind(&less_than_32);
  // If shift < 32

  lsr(dst_low, src_low, Operand(shift));
  orr(dst_low, dst_low, Operand(src_high, LSL, scratch));
  lsr(dst_high, src_high, Operand(shift));
  bind(&done);
}

void MacroAssembler::LsrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             uint32_t shift) {
  DCHECK_GE(63, shift);
  DCHECK(!AreAliased(dst_low, src_high));

  if (shift == 32) {
    mov(dst_low, src_high);
    mov(dst_high, Operand(0));
  } else if (shift > 32) {
    shift &= 0x1F;
    lsr(dst_low, src_high, Operand(shift));
    mov(dst_high, Operand(0));
  } else if (shift == 0) {
    Move(dst_low, src_low);
    Move(dst_high, src_high);
  } else {
    lsr(dst_low, src_low, Operand(shift));
    orr(dst_low, dst_low, Operand(src_high, LSL, 32 - shift));
    lsr(dst_high, src_high, Operand(shift));
  }
}

void MacroAssembler::AsrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift) {
  DCHECK(!AreAliased(dst_low, src_high));
  DCHECK(!AreAliased(dst_low, shift));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  Label less_than_32;
  Label done;
  rsb(scratch, shift, Operand(32), SetCC);
  b(gt, &less_than_32);
  // If shift >= 32
  and_(scratch, shift, Operand(0x1F));
  asr(dst_low, src_high, Operand(scratch));
  asr(dst_high, src_high, Operand(31));
  jmp(&done);
  bind(&less_than_32);
  // If shift < 32
  lsr(dst_low, src_low, Operand(shift));
  orr(dst_low, dst_low, Operand(src_high, LSL, scratch));
  asr(dst_high, src_high, Operand(shift));
  bind(&done);
}

void MacroAssembler::AsrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             uint32_t shift) {
  DCHECK_GE(63, shift);
  DCHECK(!AreAliased(dst_low, src_high));

  if (shift == 32) {
    mov(dst_low, src_high);
    asr(dst_high, src_high, Operand(31));
  } else if (shift > 32) {
    shift &= 0x1F;
    asr(dst_low, src_high, Operand(shift));
    asr(dst_high, src_high, Operand(31));
  } else if (shift == 0) {
    Move(dst_low, src_low);
    Move(dst_high, src_high);
  } else {
    lsr(dst_low, src_low, Operand(shift));
    orr(dst_low, dst_low, Operand(src_high, LSL, 32 - shift));
    asr(dst_high, src_high, Operand(shift));
  }
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  mov(scratch, Operand(StackFrame::TypeToMarker(type)));
  PushCommonFrame(scratch);
}

void MacroAssembler::Prologue() { PushStandardFrame(r1); }

void MacroAssembler::DropArguments(Register count) {
  add(sp, sp, Operand(count, LSL, kPointerSizeLog2), LeaveCC);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

void MacroAssembler::EnterFrame(StackFrame::Type type,
                                bool load_constant_pool_pointer_reg) {
  ASM_CODE_COMMENT(this);
  // r0-r3: preserved
  UseScratchRegisterScope temps(this);
  Register scratch = no_reg;
  if (!StackFrame::IsJavaScript(type)) {
    scratch = temps.Acquire();
    mov(scratch, Operand(StackFrame::TypeToMarker(type)));
  }
  PushCommonFrame(scratch);
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM) Push(kWasmImplicitArgRegister);
#endif  // V8_ENABLE_WEBASSEMBLY
}

int MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  // r0: preserved
  // r1: preserved
  // r2: preserved

  // Drop the execution stack down to the frame pointer and restore
  // the caller frame pointer and return address.
  mov(sp, fp);
  int frame_ends = pc_offset();
  ldm(ia_w, sp, {fp, lr});
  return frame_ends;
}

#ifdef V8_OS_WIN
void MacroAssembler::AllocateStackSpace(Register bytes_scratch) {
  // "Functions that allocate 4 KB or more on the stack must ensure that each
  // page prior to the final page is touched in order." Source:
  // https://docs.microsoft.com/en-us/cpp/build/overview-of-arm-abi-conventions?view=vs-2019#stack
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  DwVfpRegister scratch = temps.AcquireD();
  Label check_offset;
  Label touch_next_page;
  jmp(&check_offset);
  bind(&touch_next_page);
  sub(sp, sp, Operand(kStackPageSize));
  // Just to touch the page, before we increment further.
  vldr(scratch, MemOperand(sp));
  sub(bytes_scratch, bytes_scratch, Operand(kStackPageSize));

  bind(&check_offset);
  cmp(bytes_scratch, Operand(kStackPageSize));
  b(gt, &touch_next_page);

  sub(sp, sp, bytes_scratch);
}

void MacroAssembler::AllocateStackSpace(int bytes) {
  ASM_CODE_COMMENT(this);
  DCHECK_GE(bytes, 0);
  UseScratchRegisterScope temps(this);
  DwVfpRegister scratch = no_dreg;
  while (bytes > kStackPageSize) {
    if (scratch == no_dreg) {
      scratch = temps.AcquireD();
    }
    sub(sp, sp, Operand(kStackPageSize));
    vldr(scratch, MemOperand(sp));
    bytes -= kStackPageSize;
  }
  if (bytes == 0) return;
  sub(sp, sp, Operand(bytes));
}
#endif

void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  using ER = ExternalReference;

  // Set up the frame structure on the stack.
  DCHECK_EQ(2 * kPointerSize, ExitFrameConstants::kCallerSPDisplacement);
  DCHECK_EQ(1 * kPointerSize, ExitFrameConstants::kCallerPCOffset);
  DCHECK_EQ(0 * kPointerSize, ExitFrameConstants::kCallerFPOffset);
  mov(scratch, Operand(StackFrame::TypeToMarker(frame_type)));
  PushCommonFrame(scratch);
  // Reserve room for saved entry sp.
  sub(sp, fp, Operand(ExitFrameConstants::kFixedFrameSizeFromFp));
  if (v8_flags.debug_code) {
    mov(scratch, Operand::Zero());
    str(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  str(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  str(cp, ExternalReferenceAsOperand(context_address, no_reg));

  // Reserve place for the return address and stack space and align the frame
  // preparing for calling the runtime function.
  AllocateStackSpace((stack_space + 1) * kPointerSize);
  EnforceStackAlignment();

  // Set the exit frame sp value to point just before the return address
  // location.
  add(scratch, sp, Operand(kPointerSize));
  str(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

int MacroAssembler::ActivationFrameAlignment() {
#if V8_HOST_ARCH_ARM
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one ARM
  // platform for another ARM platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else   // V8_HOST_ARCH_ARM
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif  // V8_HOST_ARCH_ARM
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ASM_CODE_COMMENT(this);
  ConstantPoolUnavailableScope constant_pool_unavailable(this);

  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  ldr(cp, ExternalReferenceAsOperand(context_address, no_reg));
#ifdef DEBUG
  mov(scratch, Operand(Context::kInvalidContext));
  str(scratch, ExternalReferenceAsOperand(context_address, no_reg));
#endif

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  mov(scratch, Operand::Zero());
  str(scratch, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Tear down the exit frame, pop the arguments, and return.
  mov(sp, Operand(fp));
  ldm(ia_w, sp, {fp, lr});
}

void MacroAssembler::MovFromFloatResult(const DwVfpRegister dst) {
  if (use_eabi_hardfloat()) {
    Move(dst, d0);
  } else {
    vmov(dst, r0, r1);
  }
}

// On ARM this is just a synonym to make the purpose clear.
void MacroAssembler::MovFromFloatParameter(DwVfpRegister dst) {
  MovFromFloatResult(dst);
}

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();
  CHECK(is_int32(offset));
  ldr(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch,
                                        Label* stack_overflow) {
  ASM_CODE_COMMENT(this);
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  LoadStackLimit(scratch, StackLimitKind::kRealStackLimit);
  // Make scratch the space we have left. The stack might already be overflowed
  // here which will cause scratch to become negative.
  sub(scratch, sp, scratch);
  // Check if the arguments will overflow the stack.
  cmp(scratch, Operand(num_args, LSL, kPointerSizeLog2));
  b(le, stack_overflow);  // Signed comparison.
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  ASM_CODE_COMMENT(this);
  Label regular_invoke;
  //  r0: actual arguments count
  //  r1: function (passed through to callee)
  //  r2: expected arguments count
  DCHECK_EQ(actual_parameter_count, r0);
  DCHECK_EQ(expected_parameter_count, r2);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  sub(expected_parameter_count, expected_parameter_count,
      actual_parameter_count, SetCC);
  b(le, &regular_invoke);

  Label stack_overflow;
  Register scratch = r4;
  StackOverflowCheck(expected_parameter_count, scratch, &stack_overflow);

  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy, check;
    Register num = r5, src = r6, dest = r9;  // r7 and r8 are context and root.
    mov(src, sp);
    // Update stack pointer.
    lsl(scratch, expected_parameter_count, Operand(kSystemPointerSizeLog2));
    AllocateStackSpace(scratch);
    mov(dest, sp);
    mov(num, actual_parameter_count);
    b(&check);
    bind(&copy);
    ldr(scratch, MemOperand(src, kSystemPointerSize, PostIndex));
    str(scratch, MemOperand(dest, kSystemPointerSize, PostIndex));
    sub(num, num, Operand(1), SetCC);
    bind(&check);
    b(gt, &copy);
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(scratch, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    str(scratch, MemOperand(r9, kSystemPointerSize, PostIndex));
    sub(expected_parameter_count, expected_parameter_count, Operand(1), SetCC);
    b(gt, &loop);
  }
  b(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    bkpt(0);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CallDebugOnFunctionCall(Register fun, Register new_target,
                                             Register expected_parameter_count,
                                             Register actual_parameter_count) {
  ASM_CODE_COMMENT(this);
  // Load receiver to pass it later to DebugOnFunctionCall hook.
  ldr(r4, ReceiverOperand());
  FrameScope frame(
      this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

  SmiTag(expected_parameter_count);
  Push(expected_parameter_count);

  SmiTag(actual_parameter_count);
  Push(actual_parameter_count);

  if (new_target.is_valid()) {
    Push(new_target);
  }
  Push(fun);
  Push(fun);
  Push(r4);
  CallRuntime(Runtime::kDebugOnFunctionCall);
  Pop(fun);
  if (new_target.is_valid()) {
    Pop(new_target);
  }

  Pop(actual_parameter_count);
  SmiUntag(actual_parameter_count);

  Pop(expected_parameter_count);
  SmiUntag(expected_parameter_count);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, r1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == r3);

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    ExternalReference debug_hook_active =
        ExternalReference::debug_hook_on_function_call_address(isolate());
    Move(r4, debug_hook_active);
    ldrsb(r4, MemOperand(r4));
    cmp(r4, Operand(0));
    b(ne, &debug_hook);
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(r3, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }
  b(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, expected_parameter_count,
                          actual_parameter_count);
  b(&continue_after_hook);

  // Continue here if InvokePrologue does handle the invocation due to
  // mismatched parameter counts.
  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register fun, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r1.
  DCHECK_EQ(fun, r1);

  Register expected_reg = r2;
  Register temp_reg = r4;

  ldr(temp_reg, FieldMemOperand(r1, JSFunction::kSharedFunctionInfoOffset));
  ldr(cp, FieldMemOperand(r1, JSFunction::kContextOffset));
  ldrh(expected_reg,
       FieldMemOperand(temp_reg,
                       SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(fun, new_target, expected_reg, actual_parameter_count,
                     type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r1.
  DCHECK_EQ(function, r1);

  // Get the function and setup the context.
  ldr(cp, FieldMemOperand(r1, JSFunction::kContextOffset));

  InvokeFunctionCode(r1, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::PushStackHandler() {
  ASM_CODE_COMMENT(this);
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kPointerSize);

  Push(Smi::zero());  // Padding.
  // Link the current handler as the next handler.
  Move(r6,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  ldr(r5, MemOperand(r6));
  push(r5);
  // Set this new handler as the current one.
  str(sp, MemOperand(r6));
}

void MacroAssembler::PopStackHandler() {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  static_assert(StackHandlerConstants::kNextOffset == 0);
  pop(r1);
  Move(scratch,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  str(r1, MemOperand(scratch));
  add(sp, sp, Operand(StackHandlerConstants::kSize - kPointerSize));
}

void MacroAssembler::CompareObjectType(Register object, Register map,
                                       Register type_reg, InstanceType type) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  const Register temp = type_reg == no_reg ? temps.Acquire() : type_reg;

  LoadMap(map, object);
  CompareInstanceType(map, temp, type);
}

void MacroAssembler::CompareObjectTypeRange(Register object, Register map,
                                            Register type_reg, Register scratch,
                                            InstanceType lower_limit,
                                            InstanceType upper_limit) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, object);
  CompareInstanceTypeRange(map, type_reg, scratch, lower_limit, upper_limit);
}

void MacroAssembler::CompareInstanceType(Register map, Register type_reg,
                                         InstanceType type) {
  ldrh(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  cmp(type_reg, Operand(type));
}

void MacroAssembler::CompareRange(Register value, Register scratch,
                                  unsigned lower_limit, unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    sub(scratch, value, Operand(lower_limit));
    cmp(scratch, Operand(higher_limit - lower_limit));
  } else {
    cmp(value, Operand(higher_limit));
  }
}
void MacroAssembler::CompareInstanceTypeRange(Register map, Register type_reg,
                                              Register scratch,
                                              InstanceType lower_limit,
                                              InstanceType higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  ldrh(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  CompareRange(type_reg, scratch, lower_limit, higher_limit);
}

void MacroAssembler::CompareTaggedRoot(Register obj, RootIndex index) {
  CompareRoot(obj, index);
}

void MacroAssembler::CompareRoot(Register obj, RootIndex index) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  DCHECK(obj != scratch);
  LoadRoot(scratch, index);
  cmp(obj, scratch);
}

void MacroAssembler::Ju
"""


```