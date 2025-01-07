Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The filename `liftoff-assembler-loong64-inl.h` immediately suggests assembly code generation for the LoongArch64 architecture within the Liftoff tier of the V8 WebAssembly engine. The `.inl.h` suffix indicates inline function definitions, likely for performance.

2. **High-Level Structure Scan:**  A quick skim reveals:
    * Header guards (`#ifndef`, `#define`, `#endif`): Standard C++ practice.
    * Includes: Various V8 headers related to codegen, machine types, heap management, and WebAssembly. This confirms its role within the V8 ecosystem.
    * Namespaces: `v8::internal::wasm::liftoff`. This clearly situates the code within the WebAssembly Liftoff implementation.
    * Stack Frame Layout:  A detailed comment describing the Liftoff stack frame structure. This is crucial for understanding memory access patterns.
    * Inline Functions: A series of inline functions for common assembly operations (getting stack slots, memory operations, loads, stores, pushes).
    * `LiftoffAssembler` class methods:  Functions for preparing and patching stack frames, handling tail calls, managing code generation, and various load/store/atomic operations.

3. **Detailed Analysis of Key Sections:**

    * **Stack Frame Layout:**  Recognize the importance of this. It dictates how parameters, local variables, and metadata are arranged on the stack. Note the specific offsets for instance data, feedback vector, return address, etc. The alignment requirement (16-byte) is a common performance optimization.

    * **`GetStackSlot` and `GetInstanceDataOperand`:** These are simple helper functions for accessing specific locations within the stack frame, based on the defined layout.

    * **`GetMemOp`:** This function is more complex. It's responsible for generating `MemOperand` objects, which represent memory addresses. Notice the handling of:
        * Base register (`addr`).
        * Optional offset register (`offset`).
        * Immediate offset (`offset_imm`).
        * 64-bit offsets.
        * Shift amounts for pointer scaling.
        * Handling both small and large immediate offsets. This is a key optimization to avoid loading large immediates into registers.

    * **`Load` and `Store` (basic):** These functions provide a type-safe interface for loading and storing values of different kinds (integers, floats, references). The `switch` statement based on `ValueKind` is central to this. The `UNREACHABLE()` cases indicate that some types (like `kS128`) are not handled by these basic functions, likely requiring specialized instructions.

    * **`push`:**  Handles pushing values onto the stack, considering different data types and their sizes.

    * **`StoreToMemory`:**  A higher-level store function that can handle values in registers, constants, or on the stack. This demonstrates the abstraction provided by the `LiftoffAssembler`.

    * **`LiftoffAssembler::PrepareStackFrame` and `PatchPrepareStackFrame`:**  These are critical for function prologue generation. The `PatchPrepareStackFrame` function handles the complexities of large stack frames and stack overflow checks, demonstrating a more involved code generation process. The use of a `MacroAssembler` for patching is an important detail.

    * **`LiftoffAssembler::CallFrameSetupStub` and `PrepareTailCall`:** These functions deal with function calls, setting up the necessary stack frame and handling tail call optimizations.

    * **Load/Store with Offsets:**  Functions like `Load(LiftoffRegister dst, Register src_addr, ...)` and `Store(Register dst_addr, ...)` showcase how memory access with base registers, offset registers, and immediate offsets is implemented. Pay attention to the `LoadType` and `StoreType` enums, which specify the size and signedness of the memory access.

    * **Atomic Operations:** The `AtomicLoad`, `AtomicStore`, and `Atomic*` functions implement atomic memory operations, crucial for concurrent programming. The use of LL/SC (Load-Linked/Store-Conditional) instructions and memory barriers (`dbar`) is characteristic of implementing atomic primitives on architectures like LoongArch64. The macros `ASSEMBLE_ATOMIC_BINOP_EXT` and `ATOMIC_BINOP_CASE` show a pattern for generating atomic read-modify-write operations.

4. **Relate to JavaScript (If Applicable):**  Consider how the generated assembly code would be used to execute JavaScript code, specifically WebAssembly. Think about memory access patterns, function calls, and data representation.

5. **Identify Potential Programming Errors:** Based on the functionality, consider common mistakes developers might make when dealing with assembly or low-level memory manipulation (e.g., incorrect stack offsets, type mismatches in loads/stores, race conditions in atomic operations).

6. **Structure the Output:** Organize the analysis into clear sections:
    * Overall functionality.
    * Explanation of key components (stack frame, memory operations, loads/stores, atomics).
    * Connection to JavaScript (if any).
    * Code logic examples (inputs and outputs for specific functions).
    * Common programming errors.
    * Summary of functionality.

7. **Iterative Refinement:** After the initial pass, review the analysis for accuracy, completeness, and clarity. Ensure the examples are relevant and easy to understand. For instance, initially, I might not have focused enough on the significance of `PatchPrepareStackFrame` and its handling of large frames, but a second review would highlight its importance.

By following these steps, one can systematically analyze a complex source code file and extract its key functionalities and implications. The process involves understanding the context (V8, WebAssembly, LoongArch64), dissecting the code structure, and relating it to higher-level concepts and potential pitfalls.
这是v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h的第1部分，它是一个V8源代码文件，主要为WebAssembly的Liftoff编译器在LoongArch64架构上提供内联的汇编器功能。以下是它的功能归纳：

**核心功能：为LoongArch64架构上的Liftoff编译器提供底层的汇编指令生成能力。**

具体来说，这个头文件定义了一些内联函数和 `LiftoffAssembler` 类的方法，用于执行以下操作：

1. **定义Liftoff栈帧结构:**
   - 详细描述了Liftoff在LoongArch64上的栈帧布局，包括参数、返回地址、帧指针、实例数据、反馈向量和局部变量的存储位置。
   - 定义了访问栈帧中特定元素的便捷方法，如 `GetStackSlot` 和 `GetInstanceDataOperand`。

2. **提供内存操作的抽象:**
   - 提供了 `GetMemOp` 模板函数，用于生成各种形式的内存操作数，支持基址寄存器、偏移寄存器和立即数偏移，以及偏移的移位操作。
   - 提供了类型安全的 `Load` 和 `Store` 内联函数，根据 `ValueKind` (数据类型) 生成相应的加载和存储指令 (如 `Ld_h`, `Ld_w`, `Ld_d`, `Fld_s`, `Fld_d` 和 `St_h`, `St_w`, `St_d`, `Fst_s`, `Fst_d`)。
   - 提供了 `push` 内联函数，用于将寄存器值推入栈中，并根据数据类型选择合适的指令。
   - 提供了 `StoreToMemory` 函数，可以将寄存器、常量或栈上的值存储到内存中。

3. **管理函数调用和栈帧:**
   - `PrepareStackFrame`:  预留栈帧空间。
   - `CallFrameSetupStub`: 调用内置函数 `kWasmLiftoffFrameSetup` 来设置栈帧。
   - `PrepareTailCall`:  为尾调用优化做准备，调整栈帧。
   - `AlignFrameSize`:  对齐栈帧大小（目前为空操作）。
   - `PatchPrepareStackFrame`:  在代码生成后，回填实际的栈帧大小，并处理大栈帧的情况，可能需要进行栈溢出检查。

4. **提供常量加载功能:**
   - `LoadConstant`: 将常量值加载到寄存器中。

5. **访问Wasm实例数据:**
   - `LoadInstanceDataFromFrame`: 从栈帧中加载Wasm实例数据指针。
   - `SpillInstanceData`: 将实例数据指针写回栈帧。
   - `LoadTrustedPointer`, `LoadFromInstance`, `LoadTaggedPointerFromInstance`:  从实例数据中加载不同类型的指针和数据。

6. **支持OSR (On-Stack Replacement):**
   - `ResetOSRTarget`:  目前为空操作，可能与OSR优化相关。

7. **处理Tagged指针:**
   - `LoadTaggedPointer`:  加载Tagged指针，可能涉及到指针压缩。
   - `LoadProtectedPointer`: 加载受保护的指针。
   - `LoadFullPointer`: 加载完整的指针。
   - `StoreTaggedPointer`: 存储Tagged指针，并包含写屏障逻辑。

8. **支持不同类型的Load和Store操作:**
   - 提供了更细粒度的 `Load` 和 `Store` 函数，可以指定加载/存储的类型 (如 `LoadType::kI32Load8U`, `StoreType::kI64Store`)，并处理对齐和符号扩展。

9. **支持原子操作:**
   - 提供了 `AtomicLoad` 和 `AtomicStore` 函数，用于执行原子加载和存储操作。
   - 提供了 `AtomicAdd`, `AtomicAnd`, `AtomicOr`, `AtomicXor`, `AtomicSub` 等函数，用于执行原子读-修改-写操作，使用 LL/SC (Load-Linked/Store-Conditional) 指令实现。

10. **栈增长和收缩 (与实验性的可增长栈相关):**
    - `LoadOldFramePointer`:  加载旧的帧指针，用于支持栈增长。
    - `CheckStackShrink`:  检查是否需要收缩栈。
    - `CheckTierUp`: 检查是否需要进行分层编译（Tier-Up）。

**与JavaScript的关系 (间接):**

这个头文件本身不包含直接的JavaScript代码，但它是V8引擎的一部分，负责将WebAssembly代码编译成机器码。当JavaScript执行WebAssembly模块时，Liftoff编译器会使用这些内联函数来生成LoongArch64架构的汇编指令，从而执行WebAssembly代码。

**代码逻辑推理示例:**

假设我们有一个Wasm函数，需要将一个32位整数局部变量存储到栈上的某个位置。

**假设输入:**
- `assm`: 一个 `LiftoffAssembler` 实例。
- `dst_offset`: 局部变量在栈上的偏移量 (例如 8)。
- `src_reg`: 包含要存储的32位整数的 `LiftoffRegister` (例如 `r3`)。
- `kind`: `kI32`。

**代码:**
```c++
liftoff::Store(assm, liftoff::GetStackSlot(dst_offset), src_reg, kind);
```

**输出 (生成的汇编指令可能类似于):**
```assembly
  st.w r3, [fp, #-8]  // 将寄存器 r3 的低 32 位存储到相对于帧指针 fp 偏移 -8 的内存位置
```

**用户常见的编程错误示例:**

在使用与汇编器相关的API时，用户（通常是V8的开发者或WebAssembly引擎的贡献者）可能会犯以下错误：

1. **错误的栈偏移量:**  计算栈帧中变量的偏移量时出现错误，导致读写到错误的内存位置，可能导致程序崩溃或数据损坏。
   ```c++
   // 错误地使用了正偏移量，应该使用负偏移量访问局部变量
   liftoff::GetStackSlot(8);
   ```

2. **数据类型不匹配:**  使用错误的 `ValueKind` 进行加载或存储，例如将一个64位的值当作32位的值来处理，可能导致数据截断或类型错误。
   ```c++
   LiftoffRegister reg; // 假设 reg 中存储的是一个 64 位整数
   liftoff::Store(assm, liftoff::GetStackSlot(0), reg, kI32); // 错误地使用了 kI32
   ```

3. **寄存器分配错误:**  在手动管理寄存器时，可能会错误地使用或覆盖正在使用的寄存器，导致数据丢失或逻辑错误。  Liftoff通常会帮助管理寄存器，但直接使用汇编器时需要注意。

4. **原子操作使用不当:**  在多线程环境中，如果原子操作使用不当，例如缺少必要的内存屏障，可能导致数据竞争和未定义的行为。

**功能归纳 (第1部分):**

这个头文件的第1部分主要关注于 **定义Liftoff栈帧结构、提供基本的内存操作抽象（加载、存储、推送）、管理基本的函数调用和栈帧的准备工作**。它为后续更复杂的汇编指令生成和优化奠定了基础。 涉及到了访问实例数据、加载常量以及一些与Tagged指针相关的操作。 此外，初步涉及了栈增长和收缩的机制以及分层编译的检查。  它不包含完整的原子操作或复杂的控制流逻辑，这些很可能会在后续的部分中出现。

Prompt: 
```
这是目录为v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_LOONG64_LIFTOFF_ASSEMBLER_LOONG64_INL_H_
#define V8_WASM_BASELINE_LOONG64_LIFTOFF_ASSEMBLER_LOONG64_INL_H_

#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/loong64/assembler-loong64-inl.h"
#include "src/codegen/machine-type.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/parallel-move-inl.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"

namespace v8::internal::wasm {

namespace liftoff {

// Liftoff Frames.
//
//  slot      Frame
//       +--------------------+---------------------------
//  n+4  | optional padding slot to keep the stack 16 byte aligned.
//  n+3  |   parameter n      |
//  ...  |       ...          |
//   4   |   parameter 1      | or parameter 2
//   3   |   parameter 0      | or parameter 1
//   2   |  (result address)  | or parameter 0
//  -----+--------------------+---------------------------
//   1   | return addr (ra)   |
//   0   | previous frame (fp)|
//  -----+--------------------+  <-- frame ptr (fp)
//  -1   | StackFrame::WASM   |
//  -2   |     instance       |
//  -3   |     feedback vector|
//  -----+--------------------+---------------------------
//  -4   |     slot 0         |   ^
//  -5   |     slot 1         |   |
//       |                    | Frame slots
//       |                    |   |
//       |                    |   v
//       | optional padding slot to keep the stack 16 byte aligned.
//  -----+--------------------+  <-- stack ptr (sp)
//

inline MemOperand GetStackSlot(int offset) { return MemOperand(fp, -offset); }

inline MemOperand GetInstanceDataOperand() {
  return GetStackSlot(WasmLiftoffFrameConstants::kInstanceDataOffset);
}

template <typename T>
inline MemOperand GetMemOp(LiftoffAssembler* assm, Register addr,
                           Register offset, T offset_imm,
                           bool i64_offset = false, unsigned shift_amount = 0) {
  if (offset != no_reg) {
    if (!i64_offset) {
      assm->bstrpick_d(kScratchReg, offset, 31, 0);
      offset = kScratchReg;
    }
    if (shift_amount != 0) {
      assm->alsl_d(kScratchReg, offset, addr, shift_amount);
    } else {
      assm->add_d(kScratchReg, offset, addr);
    }
    addr = kScratchReg;
  }
  if (is_int31(offset_imm)) {
    int32_t offset_imm32 = static_cast<int32_t>(offset_imm);
    return MemOperand(addr, offset_imm32);
  } else {
    assm->li(kScratchReg2, Operand(offset_imm));
    assm->add_d(kScratchReg2, addr, kScratchReg2);
    return MemOperand(kScratchReg2, 0);
  }
}

inline void Load(LiftoffAssembler* assm, LiftoffRegister dst, MemOperand src,
                 ValueKind kind) {
  switch (kind) {
    case kI16:
      assm->Ld_h(dst.gp(), src);
      break;
    case kI32:
      assm->Ld_w(dst.gp(), src);
      break;
    case kI64:
    case kRef:
    case kRefNull:
    case kRtt:
      assm->Ld_d(dst.gp(), src);
      break;
    case kF32:
      assm->Fld_s(dst.fp(), src);
      break;
    case kF64:
      assm->Fld_d(dst.fp(), src);
      break;
    case kS128:
      UNREACHABLE();
      break;
    default:
      UNREACHABLE();
  }
}

inline void Store(LiftoffAssembler* assm, MemOperand dst, LiftoffRegister src,
                  ValueKind kind) {
  switch (kind) {
    case kI16:
      assm->St_h(src.gp(), dst);
      break;
    case kI32:
      assm->St_w(src.gp(), dst);
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->St_d(src.gp(), dst);
      break;
    case kF32:
      assm->Fst_s(src.fp(), dst);
      break;
    case kF64:
      assm->Fst_d(src.fp(), dst);
      break;
    default:
      UNREACHABLE();
  }
}

inline void Store(LiftoffAssembler* assm, Register base, int32_t offset,
                  LiftoffRegister src, ValueKind kind) {
  MemOperand dst(base, offset);
  Store(assm, dst, src, kind);
}

inline void push(LiftoffAssembler* assm, LiftoffRegister reg, ValueKind kind) {
  switch (kind) {
    case kI32:
      assm->addi_d(sp, sp, -kSystemPointerSize);
      assm->St_w(reg.gp(), MemOperand(sp, 0));
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->Push(reg.gp());
      break;
    case kF32:
      assm->addi_d(sp, sp, -kSystemPointerSize);
      assm->Fst_s(reg.fp(), MemOperand(sp, 0));
      break;
    case kF64:
      assm->addi_d(sp, sp, -kSystemPointerSize);
      assm->Fst_d(reg.fp(), MemOperand(sp, 0));
      break;
    case kS128:
      UNREACHABLE();
      break;
    default:
      UNREACHABLE();
  }
}

inline void StoreToMemory(LiftoffAssembler* assm, MemOperand dst,
                          const LiftoffAssembler::VarState& src) {
  if (src.is_reg()) {
    Store(assm, dst, src.reg(), src.kind());
    return;
  }

  UseScratchRegisterScope temps(assm);
  Register temp = temps.Acquire();
  if (src.is_const()) {
    if (src.i32_const() == 0) {
      temp = zero_reg;
    } else {
      assm->li(temp, static_cast<int64_t>(src.i32_const()));
    }
  } else {
    DCHECK(src.is_stack());
    if (value_kind_size(src.kind()) == 4) {
      assm->Ld_w(temp, liftoff::GetStackSlot(src.offset()));
    } else {
      assm->Ld_d(temp, liftoff::GetStackSlot(src.offset()));
    }
  }

  if (value_kind_size(src.kind()) == 4) {
    assm->St_w(temp, dst);
  } else {
    DCHECK_EQ(8, value_kind_size(src.kind()));
    assm->St_d(temp, dst);
  }
}

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  int offset = pc_offset();
  // When constant that represents size of stack frame can't be represented
  // as 16bit we need three instructions to add it to sp, so we reserve space
  // for this case.
  addi_d(sp, sp, 0);
  nop();
  nop();
  return offset;
}

void LiftoffAssembler::CallFrameSetupStub(int declared_function_index) {
// The standard library used by gcc tryjobs does not consider `std::find` to be
// `constexpr`, so wrap it in a `#ifdef __clang__` block.
#ifdef __clang__
  static_assert(std::find(std::begin(wasm::kGpParamRegisters),
                          std::end(wasm::kGpParamRegisters),
                          kLiftoffFrameSetupFunctionReg) ==
                std::end(wasm::kGpParamRegisters));
#endif

  // On LOONG64, we must push at least {ra} before calling the stub, otherwise
  // it would get clobbered with no possibility to recover it. So just set
  // up the frame here.
  EnterFrame(StackFrame::WASM);
  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

void LiftoffAssembler::PrepareTailCall(int num_callee_stack_params,
                                       int stack_param_delta) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  // Push the return address and frame pointer to complete the stack frame.
  Ld_d(scratch, MemOperand(fp, 8));
  Push(scratch);
  Ld_d(scratch, MemOperand(fp, 0));
  Push(scratch);

  // Shift the whole frame upwards.
  int slot_count = num_callee_stack_params + 2;
  for (int i = slot_count - 1; i >= 0; --i) {
    Ld_d(scratch, MemOperand(sp, i * 8));
    St_d(scratch, MemOperand(fp, (i - stack_param_delta) * 8));
  }

  // Set the new stack and frame pointer.
  addi_d(sp, fp, -stack_param_delta * 8);
  Pop(ra, fp);
}

void LiftoffAssembler::AlignFrameSize() {}

void LiftoffAssembler::PatchPrepareStackFrame(
    int offset, SafepointTableBuilder* safepoint_table_builder,
    bool feedback_vector_slot, size_t stack_param_slots) {
  // The frame_size includes the frame marker and the instance slot. Both are
  // pushed as part of frame construction, so we don't need to allocate memory
  // for them anymore.
  int frame_size = GetTotalFrameSize() - 2 * kSystemPointerSize;
  // The frame setup builtin also pushes the feedback vector.
  if (feedback_vector_slot) {
    frame_size -= kSystemPointerSize;
  }

  // We can't run out of space, just pass anything big enough to not cause the
  // assembler to try to grow the buffer.
  constexpr int kAvailableSpace = 256;
  MacroAssembler patching_assembler(
      nullptr, AssemblerOptions{}, CodeObjectRequired::kNo,
      ExternalAssemblerBuffer(buffer_start_ + offset, kAvailableSpace));

  if (V8_LIKELY(frame_size < 4 * KB)) {
    // This is the standard case for small frames: just subtract from SP and be
    // done with it.
    patching_assembler.Add_d(sp, sp, Operand(-frame_size));
    return;
  }

  // The frame size is bigger than 4KB, so we might overflow the available stack
  // space if we first allocate the frame and then do the stack check (we will
  // need some remaining stack space for throwing the exception). That's why we
  // check the available stack space before we allocate the frame. To do this we
  // replace the {__ Add_d(sp, sp, -frame_size)} with a jump to OOL code that
  // does this "extended stack check".
  //
  // The OOL code can simply be generated here with the normal assembler,
  // because all other code generation, including OOL code, has already finished
  // when {PatchPrepareStackFrame} is called. The function prologue then jumps
  // to the current {pc_offset()} to execute the OOL code for allocating the
  // large frame.
  // Emit the unconditional branch in the function prologue (from {offset} to
  // {pc_offset()}).

  int imm32 = pc_offset() - offset;
  CHECK(is_int26(imm32));
  patching_assembler.b(imm32 >> 2);

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    Register stack_limit = kScratchReg;
    LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
    Add_d(stack_limit, stack_limit, Operand(frame_size));
    Branch(&continuation, uge, sp, Operand(stack_limit));
  }

  if (v8_flags.experimental_wasm_growable_stacks) {
    LiftoffRegList regs_to_save;
    regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
    regs_to_save.set(WasmHandleStackOverflowDescriptor::FrameBaseRegister());
    for (auto reg : kGpParamRegisters) regs_to_save.set(reg);
    PushRegisters(regs_to_save);
    li(WasmHandleStackOverflowDescriptor::GapRegister(), frame_size);
    Add_d(WasmHandleStackOverflowDescriptor::FrameBaseRegister(), fp,
          Operand(stack_param_slots * kStackSlotSize +
                  CommonFrameConstants::kFixedFrameSizeAboveFp));
    CallBuiltin(Builtin::kWasmHandleStackOverflow);
    PopRegisters(regs_to_save);
  } else {
    Call(static_cast<Address>(Builtin::kWasmStackOverflow),
         RelocInfo::WASM_STUB_CALL);
    // The call will not return; just define an empty safepoint.
    safepoint_table_builder->DefineSafepoint(this);
    if (v8_flags.debug_code) stop();
  }

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP;
  Add_d(sp, sp, Operand(-frame_size));

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ Add_d(sp, sp, -framesize)}
  // (which is a Branch now).
  int func_start_offset = offset + 3 * kInstrSize;
  imm32 = func_start_offset - pc_offset();
  CHECK(is_int26(imm32));
  b(imm32 >> 2);
}

void LiftoffAssembler::FinishCode() {}

void LiftoffAssembler::AbortCompilation() {}

// static
constexpr int LiftoffAssembler::StaticStackFrameSize() {
  return WasmLiftoffFrameConstants::kFeedbackVectorOffset;
}

int LiftoffAssembler::SlotSizeForType(ValueKind kind) {
  switch (kind) {
    case kS128:
      return value_kind_size(kind);
    default:
      return kStackSlotSize;
  }
}

bool LiftoffAssembler::NeedsAlignment(ValueKind kind) {
  return kind == kS128 || is_reference(kind);
}

void LiftoffAssembler::CheckTierUp(int declared_func_index, int budget_used,
                                   Label* ool_label,
                                   const FreezeCacheState& frozen) {
  Register budget_array = kScratchReg;

  Register instance_data = cache_state_.cached_instance_data;
  if (instance_data == no_reg) {
    instance_data = budget_array;  // Reuse the scratch register.
    LoadInstanceDataFromFrame(instance_data);
  }

  constexpr int kArrayOffset = wasm::ObjectAccess::ToTagged(
      WasmTrustedInstanceData::kTieringBudgetArrayOffset);
  Ld_d(budget_array, MemOperand(instance_data, kArrayOffset));

  int budget_arr_offset = kInt32Size * declared_func_index;

  Register budget = kScratchReg2;
  MemOperand budget_addr(budget_array, budget_arr_offset);
  Ld_w(budget, budget_addr);
  Sub_w(budget, budget, budget_used);
  St_w(budget, budget_addr);

  Branch(ool_label, less, budget, Operand(zero_reg));
}

Register LiftoffAssembler::LoadOldFramePointer() {
  if (!v8_flags.experimental_wasm_growable_stacks) {
    return fp;
  }

  LiftoffRegister old_fp = GetUnusedRegister(RegClass::kGpReg, {});
  Label done, call_runtime;
  Ld_d(old_fp.gp(), MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  BranchShort(
      &call_runtime, eq, old_fp.gp(),
      Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  mov(old_fp.gp(), fp);
  jmp(&done);

  bind(&call_runtime);
  LiftoffRegList regs_to_save = cache_state()->used_registers;
  PushRegisters(regs_to_save);
  li(kCArgRegs[0], ExternalReference::isolate_address());
  PrepareCallCFunction(1, kScratchReg);
  CallCFunction(ExternalReference::wasm_load_old_fp(), 1);
  if (old_fp.gp() != kReturnRegister0) {
    mov(old_fp.gp(), kReturnRegister0);
  }
  PopRegisters(regs_to_save);

  bind(&done);
  return old_fp.gp();
}

void LiftoffAssembler::CheckStackShrink() {
  Label done;
  {
    UseScratchRegisterScope temps{this};
    Register scratch = temps.Acquire();
    Ld_d(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
    BranchShort(
        &done, ne, scratch,
        Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  }
  LiftoffRegList regs_to_save;
  for (auto reg : kGpReturnRegisters) regs_to_save.set(reg);
  PushRegisters(regs_to_save);
  li(kCArgRegs[0], ExternalReference::isolate_address());
  PrepareCallCFunction(1, kScratchReg);
  CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
  mov(fp, kReturnRegister0);
  PopRegisters(regs_to_save);
  bind(&done);
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      MacroAssembler::li(reg.gp(), Operand(value.to_i32()));
      break;
    case kI64:
      MacroAssembler::li(reg.gp(), Operand(value.to_i64()));
      break;
    case kF32:
      MacroAssembler::Move(reg.fp(), value.to_f32_boxed().get_bits());
      break;
    case kF64:
      MacroAssembler::Move(reg.fp(), value.to_f64_boxed().get_bits());
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadInstanceDataFromFrame(Register dst) {
  Ld_d(dst, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  MemOperand src{src_addr, offset};
  LoadTrustedPointerField(dst, src, tag);
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  switch (size) {
    case 1:
      Ld_b(dst, MemOperand(instance, offset));
      break;
    case 4:
      Ld_w(dst, MemOperand(instance, offset));
      break;
    case 8:
      Ld_d(dst, MemOperand(instance, offset));
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int32_t offset) {
  LoadTaggedField(dst, MemOperand(instance, offset));
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  St_d(instance, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::ResetOSRTarget() {}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  unsigned shift_amount = !needs_shift ? 0 : COMPRESS_POINTERS_BOOL ? 2 : 3;
  MemOperand src_op = liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm,
                                        false, shift_amount);
  LoadTaggedField(dst, src_op);

  // Since LoadTaggedField might start with an instruction loading an immediate
  // argument to a register, we have to compute the {protected_load_pc} after
  // calling it.
  // In case of compressed pointers, there is an additional instruction
  // (pointer decompression) after the load.
  uint8_t protected_instruction_offset_bias =
      COMPRESS_POINTERS_BOOL ? 2 * kInstrSize : kInstrSize;
  if (protected_load_pc) {
    *protected_load_pc = pc_offset() - protected_instruction_offset_bias;
  }
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset_imm) {
  LoadProtectedPointerField(dst, MemOperand{src_addr, offset_imm});
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  MemOperand src_op = liftoff::GetMemOp(this, src_addr, no_reg, offset_imm);
  Ld_d(dst, src_op);
}

#ifdef V8_ENABLE_SANDBOX
void LiftoffAssembler::LoadCodeEntrypointViaCodePointer(Register dst,
                                                        Register src_addr,
                                                        int32_t offset_imm) {
  MemOperand src_op = liftoff::GetMemOp(this, src_addr, no_reg, offset_imm);
  MacroAssembler::LoadCodeEntrypointViaCodePointer(dst, src_op,
                                                   kWasmEntrypointTag);
}
#endif

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList pinned,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  UseScratchRegisterScope temps(this);
  Operand offset_op =
      offset_reg.is_valid() ? Operand(offset_reg) : Operand(offset_imm);
  // For the write barrier (below), we cannot have both an offset register and
  // an immediate offset. Add them to a 32-bit offset initially, but in a 64-bit
  // register, because that's needed in the MemOperand below.
  if (offset_reg.is_valid() && offset_imm) {
    Register effective_offset = temps.Acquire();
    Add_d(effective_offset, offset_reg, Operand(offset_imm));
    offset_op = Operand(effective_offset);
  }

  if (offset_op.is_reg()) {
    StoreTaggedField(src, MemOperand(dst_addr, offset_op.rm()));
  } else {
    StoreTaggedField(src, MemOperand(dst_addr, offset_imm));
  }

  // Since StoreTaggedField might start with an instruction loading an immediate
  // argument to a register, we have to compute the {protected_load_pc} after
  // calling it.
  if (protected_store_pc) {
    *protected_store_pc = pc_offset() - kInstrSize;
  }

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  Label exit;
  CheckPageFlag(dst_addr, MemoryChunk::kPointersFromHereAreInterestingMask,
                kZero, &exit);
  JumpIfSmi(src, &exit);
  CheckPageFlag(src, MemoryChunk::kPointersToHereAreInterestingMask, eq, &exit);
  CallRecordWriteStubSaveRegisters(dst_addr, offset_op, SaveFPRegsMode::kSave,
                                   StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uintptr_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool is_load_mem, bool i64_offset,
                            bool needs_shift) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  unsigned shift_amount = needs_shift ? type.size_log_2() : 0;
  MemOperand src_op = liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm,
                                        i64_offset, shift_amount);

  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U:
      Ld_bu(dst.gp(), src_op);
      break;
    case LoadType::kI32Load8S:
    case LoadType::kI64Load8S:
      Ld_b(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      MacroAssembler::Ld_hu(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16S:
    case LoadType::kI64Load16S:
      MacroAssembler::Ld_h(dst.gp(), src_op);
      break;
    case LoadType::kI64Load32U:
      MacroAssembler::Ld_wu(dst.gp(), src_op);
      break;
    case LoadType::kI32Load:
    case LoadType::kI64Load32S:
      MacroAssembler::Ld_w(dst.gp(), src_op);
      break;
    case LoadType::kI64Load:
      MacroAssembler::Ld_d(dst.gp(), src_op);
      break;
    case LoadType::kF32Load:
      MacroAssembler::Fld_s(dst.fp(), src_op);
      break;
    case LoadType::kF32LoadF16:
      UNIMPLEMENTED();
      break;
    case LoadType::kF64Load:
      MacroAssembler::Fld_d(dst.fp(), src_op);
      break;
    case LoadType::kS128Load:
      UNREACHABLE();
      break;
    default:
      UNREACHABLE();
  }
  // protected_load_pc should be the address of the load/store instruction.
  // The MacroAssembler load/store may contain some instructions for adjusting
  // MemOperand, so use pc_offset - kInstrSize to locate.
  if (protected_load_pc) *protected_load_pc = pc_offset() - kInstrSize;
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList pinned,
                             uint32_t* protected_store_pc, bool is_store_mem,
                             bool i64_offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset);

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      St_b(src.gp(), dst_op);
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      MacroAssembler::St_h(src.gp(), dst_op);
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      MacroAssembler::St_w(src.gp(), dst_op);
      break;
    case StoreType::kI64Store:
      MacroAssembler::St_d(src.gp(), dst_op);
      break;
    case StoreType::kF32Store:
      MacroAssembler::Fst_s(src.fp(), dst_op);
      break;
    case StoreType::kF32StoreF16:
      UNIMPLEMENTED();
      break;
    case StoreType::kF64Store:
      MacroAssembler::Fst_d(src.fp(), dst_op);
      break;
    case StoreType::kS128Store:
      UNREACHABLE();
      break;
    default:
      UNREACHABLE();
  }
  // protected_store_pc should be the address of the load/store instruction.
  // The MacroAssembler load/store may contain some instructions for adjusting
  // MemOperand, so use pc_offset - kInstrSize to locate.
  if (protected_store_pc) *protected_store_pc = pc_offset() - kInstrSize;
}

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uintptr_t offset_imm,
                                  LoadType type, LiftoffRegList pinned,
                                  bool i64_offset) {
  UseScratchRegisterScope temps(this);
  MemOperand src_op =
      liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm, i64_offset);
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U: {
      Ld_bu(dst.gp(), src_op);
      dbar(0);
      return;
    }
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U: {
      Ld_hu(dst.gp(), src_op);
      dbar(0);
      return;
    }
    case LoadType::kI32Load: {
      Ld_w(dst.gp(), src_op);
      dbar(0);
      return;
    }
    case LoadType::kI64Load32U: {
      Ld_wu(dst.gp(), src_op);
      dbar(0);
      return;
    }
    case LoadType::kI64Load: {
      Ld_d(dst.gp(), src_op);
      dbar(0);
      return;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uintptr_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList pinned,
                                   bool i64_offset) {
  UseScratchRegisterScope temps(this);
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset);
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8: {
      dbar(0);
      St_b(src.gp(), dst_op);
      return;
    }
    case StoreType::kI64Store16:
    case StoreType::kI32Store16: {
      dbar(0);
      St_h(src.gp(), dst_op);
      return;
    }
    case StoreType::kI64Store32:
    case StoreType::kI32Store: {
      dbar(0);
      St_w(src.gp(), dst_op);
      return;
    }
    case StoreType::kI64Store: {
      dbar(0);
      St_d(src.gp(), dst_op);
      return;
    }
    default:
      UNREACHABLE();
  }
}

#define ASSEMBLE_ATOMIC_BINOP_EXT(load_linked, store_conditional, size, \
                                  bin_instr, aligned)                   \
  do {                                                                  \
    Label binop;                                                        \
    andi(temp3, temp0, aligned);                                        \
    Sub_d(temp0, temp0, Operand(temp3));                                \
    slli_w(temp3, temp3, 3);                                            \
    dbar(0);                                                            \
    bind(&binop);                                                       \
    load_linked(temp1, MemOperand(temp0, 0));                           \
    ExtractBits(result.gp(), temp1, temp3, size, false);                \
    bin_instr(temp2, result.gp(), Operand(value.gp()));                 \
    InsertBits(temp1, temp2, temp3, size);                              \
    store_conditional(temp1, MemOperand(temp0, 0));                     \
    BranchShort(&binop, eq, temp1, Operand(zero_reg));                  \
    dbar(0);                                                            \
  } while (0)

#define ATOMIC_BINOP_CASE(name, inst32, inst64, opcode)                        \
  void LiftoffAssembler::Atomic##name(                                         \
      Register dst_addr, Register offset_reg, uintptr_t offset_imm,            \
      LiftoffRegister value, LiftoffRegister result, StoreType type,           \
      bool i64_offset) {                                                       \
    LiftoffRegList pinned{dst_addr, value, result};                            \
    if (offset_reg != no_reg) pinned.set(offset_reg);                          \
    Register temp0 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();       \
    Register temp1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();       \
    Register temp2 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();       \
    Register temp3 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();       \
    MemOperand dst_op =                                                        \
        liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset); \
    Add_d(temp0, dst_op.base(), dst_op.offset());                              \
    switch (type.value()) {                                                    \
      case StoreType::kI64Store8:                                              \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, 8, inst64, 7);                   \
        break;                                                                 \
      case StoreType::kI32Store8:                                              \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, 8, inst32, 3);                   \
        break;                                                                 \
      case StoreType::kI64Store16:                                             \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, 16, inst64, 7);                  \
        break;                                                                 \
      case StoreType::kI32Store16:                                             \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, 16, inst32, 3);                  \
        break;                                                                 \
      case StoreType::kI64Store32:                                             \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, 32, inst64, 7);                  \
        break;                                                                 \
      case StoreType::kI32Store:                                               \
        am##opcode##_db_w(result.gp(), value.gp(), temp0);                     \
        break;                                                                 \
      case StoreType::kI64Store:                                               \
        am##opcode##_db_d(result.gp(), value.gp(), temp0);                     \
        break;                                                                 \
      default:                                                                 \
        UNREACHABLE();                                                         \
    }                                                                          \
  }

ATOMIC_BINOP_CASE(Add, Add_w, Add_d, add)
ATOMIC_BINOP_CASE(And, And, And, and)
ATOMIC_BINOP_CASE(Or, Or, Or, or)
ATOMIC_BINOP_CASE(Xor, Xor, Xor, xor)

#define ASSEMBLE_ATOMIC_BINOP(load_linked, store_conditional, bin_instr) \
  do {                                                                   \
    Label binop;                                                         \
    dbar(0);                                                             \
    bind(&binop);                                                        \
    load_linked(result.gp(), MemOperand(temp0, 0));                      \
    bin_instr(temp1, result.gp(), Operand(value.gp()));                  \
    store_conditional(temp1, MemOperand(temp0, 0));                      \
    BranchShort(&binop, eq, temp1, Operand(zero_reg));                   \
    dbar(0);                                                             \
  } while (0)

void LiftoffAssembler::AtomicSub(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  LiftoffRegList pinned{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register temp0 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp2 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp3 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset);
  Add_d(temp0, dst_op.base(), dst_op.offset());
  switch (type.value()) {
    case StoreType::kI64Store8:
      ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, 8, Sub_d, 7);
      break;
    case StoreType::kI32Store8:
      ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, 8, Sub_w, 3);
      break;
    case StoreType::kI64Store16:
      ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, 16, Sub_d, 7);
      break;
    case StoreType::kI32Store16:
      ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, 16, Sub_w, 3);
      break;
    case StoreType::kI64Store32:
      ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, 32, Sub_d, 7);
      break;
    case StoreType::kI32Store:
      ASSEMBLE_ATOMIC_BINOP(Ll_w, Sc_w, Sub_w);
      break;
    case StoreType::kI64Store:
      ASSEMBLE_ATOMIC_BINOP(Ll_d, Sc_d, Sub_d);
      break;
    default:
      UNREACHABLE();
  }
}
#undef ASSEMBLE_ATOMIC_BINOP
#un
"""


```