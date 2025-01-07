Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `macro-assembler-arm64-inl.h` file. They've asked for a breakdown of its functions, considerations for Torque, relevance to JavaScript, examples with hypothetical inputs and outputs, common programming errors, and a final summary of its purpose.

Here's a plan to address each point:

1. **List Functionality:** Go through each function in the snippet and describe its purpose in generating ARM64 assembly instructions. Focus on what operation each function performs (e.g., bitwise operations, arithmetic, memory access, conditional jumps).

2. **Torque Consideration:**  Check the filename extension. Since it's `.h`, it's not a Torque file. State this explicitly.

3. **JavaScript Relationship:**  Explain that `MacroAssembler` is a low-level component used by V8 to generate machine code, which is the final output of compiling JavaScript. Provide a simplified JavaScript example that would *indirectly* lead to the use of some of these functions during compilation (e.g., a simple addition that might involve the `Add` function). Emphasize that developers don't directly interact with `MacroAssembler`.

4. **Code Logic and Examples:** For a few representative functions (like `SmiTag`, `SmiUntag`, `JumpIfSmi`, `Add`), create hypothetical input register values and show the expected output register value after the function executes. This demonstrates the low-level transformations happening.

5. **Common Programming Errors:** Think about potential errors that could arise when *using* a `MacroAssembler` (if a developer were to do so directly, which is uncommon). This might include incorrect register usage, miscalculating offsets, or using the wrong instructions for a given task. Since this is a low-level API, the errors are generally around correctness of the generated assembly.

6. **Summary of Functionality:**  Provide a concise overview of the role of this code, highlighting that it's a set of building blocks for generating ARM64 assembly within the V8 JavaScript engine.

Planning complete. Proceeding with response generation.
这是 V8 JavaScript 引擎中 `v8/src/codegen/arm64/macro-assembler-arm64-inl.h` 文件的一部分，它定义了 `MacroAssembler` 类的内联函数。`MacroAssembler` 类是 V8 中用于生成 ARM64 汇编代码的核心组件。

**功能列举:**

这个代码片段定义了一系列内联函数，用于生成各种 ARM64 指令。这些指令可以大致分为以下几类：

* **位域操作:**
    * `Sbfiz`:  带符号位域插入零 (Signed Bitfield Insert in Zero)。从源寄存器提取一个带符号的位域，并将其插入到目标寄存器中，其余位清零。
    * `Ubfx`: 无符号位域提取 (Unsigned Bitfield Extract)。从源寄存器提取一个无符号的位域。

* **类型转换:**
    * `Ucvtf`: 无符号整数转换为浮点数 (Unsigned Convert to Float)。将无符号整数寄存器的值转换为浮点数。

* **算术运算:**
    * `Udiv`: 无符号除法 (Unsigned Divide)。执行无符号整数除法。
    * `Umaddl`: 无符号乘加长 (Unsigned Multiply-Add Long)。执行两个 32 位无符号整数的乘法，并将结果与一个 64 位累加器相加。
    * `Umsubl`: 无符号乘减长 (Unsigned Multiply-Subtract Long)。执行两个 32 位无符号整数的乘法，并从一个 64 位累加器中减去结果。

* **零扩展:**
    * `Uxtb`: 无符号扩展字节 (Unsigned Extend Byte)。将 8 位值零扩展到 64 位。
    * `Uxth`: 无符号扩展半字 (Unsigned Extend Halfword)。将 16 位值零扩展到 64 位。
    * `Uxtw`: 无符号扩展字 (Unsigned Extend Word)。将 32 位值零扩展到 64 位。

* **初始化:**
    * `InitializeRootRegister`: 初始化根寄存器 (通常用于存储 Isolate 的根地址) 和浮点零寄存器。

* **Smi (Small Integer) 操作:**
    * `SmiTag`: 将一个普通整数标记为 Smi。通过左移操作实现。
    * `SmiUntag`: 从 Smi 中提取原始整数值。通过右移或带符号位域提取实现。
    * `SmiToInt32`: 将 Smi 转换为 32 位整数。

* **条件跳转:**
    * `JumpIfSmi`: 如果寄存器包含 Smi，则跳转到指定标签。
    * `JumpIfNotSmi`: 如果寄存器不包含 Smi，则跳转到指定标签。
    * `JumpIfEqual`: 如果寄存器等于一个立即数，则跳转。
    * `JumpIfLessThan`: 如果寄存器小于一个立即数，则跳转。
    * `JumpIfUnsignedLessThan`: 如果寄存器无符号小于一个立即数，则跳转。
    * `CompareAndBranch`: 比较两个操作数，并根据条件跳转。
    * `CompareTaggedAndBranch`: 比较两个标记的值，并根据条件跳转。
    * `TestAndBranchIfAnySet`: 如果寄存器中任何指定的位被设置，则跳转。
    * `TestAndBranchIfAllClear`: 如果寄存器中所有指定的位都未设置，则跳转。

* **无条件跳转:**
    * `jmp`: 无条件跳转到指定标签。

* **栈操作 (Push/Pop):**
    * `Push`: 将多个寄存器压入栈。
    * `Pop`: 从栈中弹出多个值到寄存器。
    * `Poke`: 将一个寄存器的值存储到栈上的指定偏移量。
    * `Peek`: 从栈上的指定偏移量加载值到寄存器。
    * `Claim`: 在栈上分配指定大小的空间。
    * `Drop`: 释放栈上指定大小的空间。
    * `DropArguments`: 释放函数参数占用的栈空间。
    * `DropSlots`: 释放指定数量的栈槽。
    * `PushArgument`: 将参数压入栈 (通常用于函数调用)。

**Torque 源代码:**

`v8/src/codegen/arm64/macro-assembler-arm64-inl.h` 文件以 `.h` 结尾，而不是 `.tq`。因此，它不是一个 V8 Torque 源代码文件。 Torque 文件通常用于定义更高级的、类型安全的汇编代码生成器。 `macro-assembler-arm64-inl.h` 提供了更底层的汇编指令操作。

**与 JavaScript 的关系 (示例):**

`MacroAssembler` 的功能与 JavaScript 的执行密切相关。当 V8 编译 JavaScript 代码时，它会将 JavaScript 源代码转换为机器码。`MacroAssembler` 类及其内联函数就是在这个过程中被用来生成 ARM64 架构的机器码指令的。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 编译 `add` 函数时，它可能会使用 `MacroAssembler::Add` 函数来生成执行加法操作的 ARM64 指令。具体来说，它可能将 `a` 和 `b` 的值加载到寄存器中，然后调用 `Add` 函数生成加法指令，并将结果存储到另一个寄存器中。

**代码逻辑推理 (假设输入与输出):**

以 `SmiTag` 函数为例：

**假设输入:**

* `dst` 寄存器：x0 (目标寄存器)
* `src` 寄存器：x1 (源寄存器)，其值为 10 (十进制)

**执行的指令:** `Lsl(x0, x1, kSmiShift)`

假设 `kSmiShift` 的值为 1 (V8 中 Smi 标记位占一位)。

**输出:**

* `dst` 寄存器 x0 的值将是 20 (十进制)，二进制表示为 `...00010100`。  原始值 10 的二进制 `...00001010` 左移一位，相当于乘以 2。Smi 标记通常会将最低位作为标记位。

以 `JumpIfSmi` 函数为例：

**假设输入:**

* `value` 寄存器：x2
* 场景 1: x2 的值为 8 (十进制)，二进制 `...00001000` (假设是 Smi，最低位为 0)
* 场景 2: x2 的值为 9 (十进制)，二进制 `...00001001` (假设不是 Smi，最低位为 1)
* `smi_label`:  指向代码中某个标签 L1
* `not_smi_label`: 指向代码中某个标签 L2

**执行的指令:** `Tbz(value, 0, smi_label)`

**输出:**

* 场景 1: 由于 `x2` 的最低位是 0，条件满足，程序跳转到标签 `L1`。
* 场景 2: 由于 `x2` 的最低位是 1，条件不满足，程序继续执行 `Tbz` 指令后的代码（如果提供了 `not_smi_label`，则会执行后续的 `B(not_smi_label)` 指令，跳转到 `L2`）。

**涉及用户常见的编程错误 (示例):**

尽管开发者通常不会直接编写 `MacroAssembler` 代码，但在更底层的编程中，类似的汇编操作容易出现错误。

* **错误的寄存器使用:**  例如，错误地使用了已经存储了重要数据的寄存器，导致数据被覆盖。
    ```c++
    // 错误示例：假设 x0 存储了重要的返回值
    Mov(x1, 5);
    Add(x0, x1, 10); // 期望 x0 = 15，但可能覆盖了之前的返回值
    ```

* **栈操作不匹配:**  `Push` 和 `Pop` 的数量或寄存器类型不匹配，导致栈指针错误，程序崩溃。
    ```c++
    Push(x0, x1);
    // ... 一些操作 ...
    Pop(x0); // 错误：只 Pop 了一个寄存器，栈不平衡
    ```

* **条件跳转逻辑错误:**  条件判断错误，导致程序执行流程不符合预期。
    ```c++
    Cmp(x0, 10);
    B(lt, &some_label); // 意图是如果 x0 < 10 则跳转，但可能逻辑有误
    ```

* **Smi 标记/取消标记错误:**  在需要 Smi 和普通整数之间转换时，忘记或错误地进行 `SmiTag` 或 `SmiUntag` 操作，导致类型错误。例如，直接对未取消标记的 Smi 进行算术运算可能会得到错误的结果。

**归纳一下它的功能 (第 2 部分总结):**

这部分 `macro-assembler-arm64-inl.h` 代码定义了 `MacroAssembler` 类的关键组成部分，提供了一组内联函数，用于生成各种基本的 ARM64 汇编指令。这些函数涵盖了位操作、类型转换、算术运算、栈管理、条件和无条件跳转等核心功能。它们是 V8 JavaScript 引擎将 JavaScript 代码编译为高效机器码的基础构建块。`MacroAssembler` 提供了一个抽象层，使得 V8 的编译器可以更容易地生成正确的 ARM64 汇编代码，而无需手动编写复杂的汇编指令。 这些函数的设计考虑了性能和代码生成效率，通过内联的方式减少了函数调用的开销。

Prompt: 
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  sbfiz(rd, rn, lsb, width);
}

void MacroAssembler::Ubfx(const Register& rd, const Register& rn, unsigned lsb,
                          unsigned width) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  ubfx(rd, rn, lsb, width);
}

void MacroAssembler::Ucvtf(const VRegister& fd, const Register& rn,
                           unsigned fbits) {
  DCHECK(allow_macro_instructions());
  ucvtf(fd, rn, fbits);
}

void MacroAssembler::Udiv(const Register& rd, const Register& rn,
                          const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  udiv(rd, rn, rm);
}

void MacroAssembler::Umaddl(const Register& rd, const Register& rn,
                            const Register& rm, const Register& ra) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  umaddl(rd, rn, rm, ra);
}

void MacroAssembler::Umsubl(const Register& rd, const Register& rn,
                            const Register& rm, const Register& ra) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  umsubl(rd, rn, rm, ra);
}

void MacroAssembler::Uxtb(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  uxtb(rd, rn);
}

void MacroAssembler::Uxth(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  uxth(rd, rn);
}

void MacroAssembler::Uxtw(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  uxtw(rd, rn);
}

void MacroAssembler::InitializeRootRegister() {
  ExternalReference isolate_root = ExternalReference::isolate_root(isolate());
  Mov(kRootRegister, Operand(isolate_root));
  Fmov(fp_zero, 0.0);

#ifdef V8_COMPRESS_POINTERS
  LoadRootRelative(kPtrComprCageBaseRegister, IsolateData::cage_base_offset());
#endif
}

void MacroAssembler::SmiTag(Register dst, Register src) {
  DCHECK(dst.Is64Bits() && src.Is64Bits());
  DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
  Lsl(dst, src, kSmiShift);
}

void MacroAssembler::SmiTag(Register smi) { SmiTag(smi, smi); }

void MacroAssembler::SmiUntag(Register dst, Register src) {
  DCHECK(dst.Is64Bits() && src.Is64Bits());
  if (v8_flags.enable_slow_asserts) {
    AssertSmi(src);
  }
  DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
  if (COMPRESS_POINTERS_BOOL) {
    Sbfx(dst, src.W(), kSmiShift, kSmiValueSize);
  } else {
    Asr(dst, src, kSmiShift);
  }
}

void MacroAssembler::SmiUntag(Register dst, const MemOperand& src) {
  DCHECK(dst.Is64Bits());
  if (SmiValuesAre32Bits()) {
    if (src.IsImmediateOffset() && src.shift_amount() == 0) {
      // Load value directly from the upper half-word.
      // Assumes that Smis are shifted by 32 bits and little endianness.
      DCHECK_EQ(kSmiShift, 32);
      Ldrsw(dst,
            MemOperand(src.base(), src.offset() + (kSmiShift / kBitsPerByte),
                       src.addrmode()));

    } else {
      Ldr(dst, src);
      SmiUntag(dst);
    }
  } else {
    DCHECK(SmiValuesAre31Bits());
    if (COMPRESS_POINTERS_BOOL) {
      Ldr(dst.W(), src);
    } else {
      Ldr(dst, src);
    }
    SmiUntag(dst);
  }
}

void MacroAssembler::SmiUntag(Register smi) { SmiUntag(smi, smi); }

void MacroAssembler::SmiToInt32(Register smi) { SmiToInt32(smi, smi); }

void MacroAssembler::SmiToInt32(Register dst, Register smi) {
  DCHECK(dst.Is64Bits());
  if (v8_flags.enable_slow_asserts) {
    AssertSmi(smi);
  }
  DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
  if (COMPRESS_POINTERS_BOOL) {
    Asr(dst.W(), smi.W(), kSmiShift);
  } else {
    Lsr(dst, smi, kSmiShift);
  }
}

void MacroAssembler::JumpIfSmi(Register value, Label* smi_label,
                               Label* not_smi_label) {
  static_assert((kSmiTagSize == 1) && (kSmiTag == 0));
  // Check if the tag bit is set.
  if (smi_label) {
    Tbz(value, 0, smi_label);
    if (not_smi_label) {
      B(not_smi_label);
    }
  } else {
    DCHECK(not_smi_label);
    Tbnz(value, 0, not_smi_label);
  }
}

void MacroAssembler::JumpIfEqual(Register x, int32_t y, Label* dest) {
  CompareAndBranch(x, y, eq, dest);
}

void MacroAssembler::JumpIfLessThan(Register x, int32_t y, Label* dest) {
  CompareAndBranch(x, y, lt, dest);
}

void MacroAssembler::JumpIfUnsignedLessThan(Register x, int32_t y,
                                            Label* dest) {
  CompareAndBranch(x, y, lo, dest);
}

void MacroAssembler::JumpIfNotSmi(Register value, Label* not_smi_label) {
  JumpIfSmi(value, nullptr, not_smi_label);
}

inline void MacroAssembler::AssertFeedbackVector(Register object) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  AssertFeedbackVector(object, scratch);
}

void MacroAssembler::jmp(Label* L) { B(L); }

template <MacroAssembler::StoreLRMode lr_mode>
void MacroAssembler::Push(const CPURegister& src0, const CPURegister& src1,
                          const CPURegister& src2, const CPURegister& src3) {
  DCHECK(AreSameSizeAndType(src0, src1, src2, src3));
  DCHECK_IMPLIES((lr_mode == kSignLR), ((src0 == lr) || (src1 == lr) ||
                                        (src2 == lr) || (src3 == lr)));
  DCHECK_IMPLIES((lr_mode == kDontStoreLR), ((src0 != lr) && (src1 != lr) &&
                                             (src2 != lr) && (src3 != lr)));

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  if (lr_mode == kSignLR) {
    Pacibsp();
  }
#endif

  int count = 1 + src1.is_valid() + src2.is_valid() + src3.is_valid();
  int size = src0.SizeInBytes();
  DCHECK_EQ(0, (size * count) % 16);

  PushHelper(count, size, src0, src1, src2, src3);
}

template <MacroAssembler::StoreLRMode lr_mode>
void MacroAssembler::Push(const Register& src0, const VRegister& src1) {
  DCHECK_IMPLIES((lr_mode == kSignLR), ((src0 == lr) || (src1 == lr)));
  DCHECK_IMPLIES((lr_mode == kDontStoreLR), ((src0 != lr) && (src1 != lr)));
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  if (lr_mode == kSignLR) {
    Pacibsp();
  }
#endif

  int size = src0.SizeInBytes() + src1.SizeInBytes();
  DCHECK_EQ(0, size % 16);

  // Reserve room for src0 and push src1.
  str(src1, MemOperand(sp, -size, PreIndex));
  // Fill the gap with src0.
  str(src0, MemOperand(sp, src1.SizeInBytes()));
}

template <MacroAssembler::LoadLRMode lr_mode>
void MacroAssembler::Pop(const CPURegister& dst0, const CPURegister& dst1,
                         const CPURegister& dst2, const CPURegister& dst3) {
  // It is not valid to pop into the same register more than once in one
  // instruction, not even into the zero register.
  DCHECK(!AreAliased(dst0, dst1, dst2, dst3));
  DCHECK(AreSameSizeAndType(dst0, dst1, dst2, dst3));
  DCHECK(dst0.is_valid());

  int count = 1 + dst1.is_valid() + dst2.is_valid() + dst3.is_valid();
  int size = dst0.SizeInBytes();
  DCHECK_EQ(0, (size * count) % 16);

  PopHelper(count, size, dst0, dst1, dst2, dst3);

  DCHECK_IMPLIES((lr_mode == kAuthLR), ((dst0 == lr) || (dst1 == lr) ||
                                        (dst2 == lr) || (dst3 == lr)));
  DCHECK_IMPLIES((lr_mode == kDontLoadLR), ((dst0 != lr) && (dst1 != lr)) &&
                                               (dst2 != lr) && (dst3 != lr));

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  if (lr_mode == kAuthLR) {
    Autibsp();
  }
#endif
}

template <MacroAssembler::StoreLRMode lr_mode>
void MacroAssembler::Poke(const CPURegister& src, const Operand& offset) {
  DCHECK_IMPLIES((lr_mode == kSignLR), (src == lr));
  DCHECK_IMPLIES((lr_mode == kDontStoreLR), (src != lr));
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  if (lr_mode == kSignLR) {
    Pacibsp();
  }
#endif

  if (offset.IsImmediate()) {
    DCHECK_GE(offset.ImmediateValue(), 0);
  } else if (v8_flags.debug_code) {
    Cmp(xzr, offset);
    Check(le, AbortReason::kStackAccessBelowStackPointer);
  }

  Str(src, MemOperand(sp, offset));
}

template <MacroAssembler::LoadLRMode lr_mode>
void MacroAssembler::Peek(const CPURegister& dst, const Operand& offset) {
  if (offset.IsImmediate()) {
    DCHECK_GE(offset.ImmediateValue(), 0);
  } else if (v8_flags.debug_code) {
    Cmp(xzr, offset);
    Check(le, AbortReason::kStackAccessBelowStackPointer);
  }

  Ldr(dst, MemOperand(sp, offset));

  DCHECK_IMPLIES((lr_mode == kAuthLR), (dst == lr));
  DCHECK_IMPLIES((lr_mode == kDontLoadLR), (dst != lr));
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  if (lr_mode == kAuthLR) {
    Autibsp();
  }
#endif
}

void MacroAssembler::Claim(int64_t count, uint64_t unit_size) {
  DCHECK_GE(count, 0);
  uint64_t size = count * unit_size;

  if (size == 0) {
    return;
  }
  DCHECK_EQ(size % 16, 0);
#ifdef V8_TARGET_OS_WIN
  while (size > kStackPageSize) {
    Sub(sp, sp, kStackPageSize);
    Str(xzr, MemOperand(sp));
    size -= kStackPageSize;
  }
#endif
  Sub(sp, sp, size);
}

void MacroAssembler::Claim(const Register& count, uint64_t unit_size,
                           bool assume_sp_aligned) {
  if (unit_size == 0) return;
  DCHECK(base::bits::IsPowerOfTwo(unit_size));

  const int shift = base::bits::CountTrailingZeros(unit_size);
  const Operand size(count, LSL, shift);

  if (size.IsZero()) {
    return;
  }
  AssertPositiveOrZero(count);

#ifdef V8_TARGET_OS_WIN
  // "Functions that allocate 4k or more worth of stack must ensure that each
  // page prior to the final page is touched in order." Source:
  // https://docs.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions?view=vs-2019#stack

  // Callers expect count register to not be clobbered, so copy it.
  UseScratchRegisterScope temps(this);
  Register bytes_scratch = temps.AcquireX();
  Mov(bytes_scratch, size);

  Label check_offset;
  Label touch_next_page;
  B(&check_offset);
  Bind(&touch_next_page);
  Sub(sp, sp, kStackPageSize);
  // Just to touch the page, before we increment further.
  if (assume_sp_aligned) {
    Str(xzr, MemOperand(sp));
  } else {
    Register sp_copy = temps.AcquireX();
    Mov(sp_copy, sp);
    Str(xzr, MemOperand(sp_copy));
  }
  Sub(bytes_scratch, bytes_scratch, kStackPageSize);

  Bind(&check_offset);
  Cmp(bytes_scratch, kStackPageSize);
  B(gt, &touch_next_page);

  Sub(sp, sp, bytes_scratch);
#else
  Sub(sp, sp, size);
#endif
}

void MacroAssembler::Drop(int64_t count, uint64_t unit_size) {
  DCHECK_GE(count, 0);
  uint64_t size = count * unit_size;

  if (size == 0) {
    return;
  }

  Add(sp, sp, size);
  DCHECK_EQ(size % 16, 0);
}

void MacroAssembler::Drop(const Register& count, uint64_t unit_size) {
  if (unit_size == 0) return;
  DCHECK(base::bits::IsPowerOfTwo(unit_size));

  const int shift = base::bits::CountTrailingZeros(unit_size);
  const Operand size(count, LSL, shift);

  if (size.IsZero()) {
    return;
  }

  AssertPositiveOrZero(count);
  Add(sp, sp, size);
}

void MacroAssembler::DropArguments(const Register& count, int extra_slots) {
  UseScratchRegisterScope temps(this);
  Register tmp = temps.AcquireX();
  Add(tmp, count, extra_slots + 1);  // +1 is for rounding the count up to 2.
  Bic(tmp, tmp, 1);
  Drop(tmp, kXRegSize);
}

void MacroAssembler::DropArguments(int64_t count) {
  Drop(RoundUp(count, 2), kXRegSize);
}

void MacroAssembler::DropSlots(int64_t count) {
  Drop(RoundUp(count, 2), kXRegSize);
}

void MacroAssembler::PushArgument(const Register& arg) { Push(padreg, arg); }

void MacroAssembler::CompareAndBranch(const Register& lhs, const Operand& rhs,
                                      Condition cond, Label* label) {
  if (rhs.IsImmediate() && (rhs.ImmediateValue() == 0)) {
    switch (cond) {
      case eq:
      case ls:
        Cbz(lhs, label);
        return;
      case lt:
        Tbnz(lhs, lhs.SizeInBits() - 1, label);
        return;
      case ge:
        Tbz(lhs, lhs.SizeInBits() - 1, label);
        return;
      case ne:
      case hi:
        Cbnz(lhs, label);
        return;
      default:
        break;
    }
  }
  Cmp(lhs, rhs);
  B(cond, label);
}

void MacroAssembler::CompareTaggedAndBranch(const Register& lhs,
                                            const Operand& rhs, Condition cond,
                                            Label* label) {
  if (COMPRESS_POINTERS_BOOL) {
    CompareAndBranch(lhs.W(), rhs.ToW(), cond, label);
  } else {
    CompareAndBranch(lhs, rhs, cond, label);
  }
}

void MacroAssembler::TestAndBranchIfAnySet(const Register& reg,
                                           const uint64_t bit_pattern,
                                           Label* label) {
  int bits = reg.SizeInBits();
  DCHECK_GT(CountSetBits(bit_pattern, bits), 0);
  if (CountSetBits(bit_pattern, bits) == 1) {
    Tbnz(reg, MaskToBit(bit_pattern), label);
  } else {
    Tst(reg, bit_pattern);
    B(ne, label);
  }
}

void MacroAssembler::TestAndBranchIfAllClear(const Register& reg,
                                             const uint64_t bit_pattern,
                                             Label* label) {
  int bits = reg.SizeInBits();
  DCHECK_GT(CountSetBits(bit_pattern, bits), 0);
  if (CountSetBits(bit_pattern, bits) == 1) {
    Tbz(reg, MaskToBit(bit_pattern), label);
  } else {
    Tst(reg, bit_pattern);
    B(eq, label);
  }
}

}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_INL_H_

"""


```