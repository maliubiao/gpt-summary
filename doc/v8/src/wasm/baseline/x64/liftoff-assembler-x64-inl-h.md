Response:
The user wants to understand the functionality of the provided C++ header file `v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h`. I need to analyze the code and identify its purpose.

The file seems to be part of the Liftoff compiler for WebAssembly in the V8 JavaScript engine, specifically for the x64 architecture. The "inl.h" suffix suggests it contains inline function definitions.

Here's a breakdown of the functionalities I can identify:

1. **Register definitions:** Defines scratch registers (`kScratchRegister`, `kScratchRegister2`, `kScratchDoubleReg`, `kScratchDoubleReg2`) for temporary calculations.
2. **Stack manipulation:** Provides functions and constants for accessing stack slots (`GetStackSlot`), instance data (`kInstanceDataOperand`), and OSR target slot (`kOSRTargetSlot`).
3. **Memory access:** Offers functions for loading and storing data to memory (`GetMemOp`, `LoadFromStack`, `StoreToMemory`).
4. **Function calls:** Includes functions for preparing stack frames (`PrepareStackFrame`), setting up call frames (`CallFrameSetupStub`), handling tail calls (`PrepareTailCall`), and aligning frame size (`AlignFrameSize`).
5. **Code patching:** Implements a mechanism to patch the stack frame preparation instruction (`PatchPrepareStackFrame`), especially for large frames.
6. **Tier-up mechanism:** Contains a function (`CheckTierUp`) to check if a function should be tiered up to a more optimized compiler.
7. **Stack shrinking:** Provides functions (`LoadOldFramePointer`, `CheckStackShrink`) related to dynamically shrinking the stack in growable stacks scenarios.
8. **Constant loading:** Offers a function to load constant values into registers (`LoadConstant`).
9. **Instance data access:** Includes functions to load and spill instance data (`LoadInstanceDataFromFrame`, `SpillInstanceData`).
10. **Tagged pointer handling:**  Provides functions for loading and storing tagged pointers, potentially involving write barriers for garbage collection (`LoadTaggedPointer`, `StoreTaggedPointer`).
11. **Atomic operations:** Implements atomic load, store, add, subtract, and other binary operations (`AtomicLoad`, `Store`, `AtomicAdd`, `AtomicSub`, `AtomicAnd`, `AtomicOr`, `AtomicXor`, `AtomicExchange`).
12. **Load and Store instructions:** Offers general load and store instructions with different sizes and signedness (`Load`, `Store`).

Based on this analysis, I can formulate a summary of the file's functionality. Since the user explicitly mentioned checking for ".tq" suffix and Javascript relation, I need to address those points even though this is clearly a C++ header file. The file doesn't end in ".tq", so it's not a Torque file. While it's low-level code, its purpose is to support the execution of Javascript by efficiently running WebAssembly code. I can illustrate this connection with a simple Javascript example that might trigger the use of this code indirectly.

For the code logic推理, I can take a simple function like `GetMemOp` and demonstrate how it calculates the memory operand based on inputs.

Regarding common programming errors, this file deals with low-level memory operations, so typical errors would be related to incorrect offsets, sizes, or register usage, potentially leading to crashes or memory corruption.
这个C++头文件 `v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h` 是V8 JavaScript引擎中为WebAssembly设计的Liftoff编译器在x64架构下的内联汇编器实现。它提供了一系列用于生成x64汇编指令的内联函数和常量，这些指令用于实现WebAssembly代码的基本执行。

**功能归纳:**

1. **定义了汇编器使用的常量和寄存器:** 例如，定义了用于临时存储的寄存器 `kScratchRegister` 和 `kScratchRegister2`，以及用于浮点数的 `kScratchDoubleReg` 和 `kScratchDoubleReg2`。
2. **提供了访问栈空间的工具函数:**  `GetStackSlot` 函数用于计算栈上的偏移地址，方便访问局部变量、函数参数等。定义了访问特定栈位置的常量，如 `kInstanceDataOperand` 和 `kOSRTargetSlot`。
3. **实现了内存操作的内联函数:**
    - `GetMemOp` 函数用于根据基地址、偏移寄存器和立即数偏移量计算内存操作数。
    - `LoadFromStack` 函数用于从栈上加载不同类型的数据到寄存器。
    - `StoreToMemory` 函数用于将寄存器中的数据存储到内存中。
4. **提供了处理函数调用栈帧的函数:**
    - `PrepareStackFrame` 函数用于在函数入口处预留栈空间。
    - `CallFrameSetupStub` 函数用于调用内置函数来设置调用帧。
    - `PrepareTailCall` 函数用于准备尾调用。
    - `AlignFrameSize` 函数用于对齐栈帧大小。
    - `PatchPrepareStackFrame` 函数用于在代码生成后，根据实际栈帧大小修补栈空间分配指令，特别处理了栈帧过大的情况。
5. **支持代码优化和分层编译:** `CheckTierUp` 函数用于检查是否需要将函数提升到更高级的编译器进行优化。
6. **实现了栈收缩功能 (与可增长栈相关):** `LoadOldFramePointer` 和 `CheckStackShrink` 函数用于在支持动态栈大小调整的情况下处理栈的收缩。
7. **提供了加载常量的函数:** `LoadConstant` 函数用于将常量值加载到寄存器中。
8. **提供了访问WebAssembly实例数据的函数:** `LoadInstanceDataFromFrame` 和 `SpillInstanceData` 函数用于加载和保存当前WebAssembly实例的数据指针。
9. **提供了加载和存储各种类型指针的函数:** 包括加载受保护的指针、带偏移的指针等，以及对应的存储操作。
10. **实现了原子操作的函数:**  `AtomicLoad`, `AtomicStore`, `AtomicAdd`, `AtomicSub`, `AtomicAnd`, `AtomicOr`, `AtomicXor`, `AtomicExchange` 等函数用于执行原子内存操作，保证在多线程环境下的数据一致性。
11. **提供了基本的加载和存储指令的封装:** `Load` 和 `Store` 函数用于加载和存储不同大小和类型的内存数据。

**关于文件后缀和 Torque:**

文件 `v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h` 的确是以 `.h` 结尾，因此它是一个 C++ 头文件，而不是以 `.tq` 结尾的 V8 Torque 源代码。Torque 是一种用于定义 V8 内部函数的领域特定语言。

**与 JavaScript 的关系:**

虽然此文件是 C++ 代码，但它直接服务于 JavaScript 的执行。当 JavaScript 代码调用 WebAssembly 模块时，V8 引擎会使用 Liftoff 编译器（在某些情况下）将 WebAssembly 代码编译成本地机器码。这个头文件中定义的汇编器就负责生成这些机器码，这些机器码会被 CPU 执行，从而实现 WebAssembly 的功能，最终影响 JavaScript 的行为。

**JavaScript 示例:**

```javascript
// 假设有一个简单的 WebAssembly 模块，它导出一个函数 add
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60,
  0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01,
  0x03, 0x61, 0x64, 0x64, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20,
  0x00, 0x20, 0x01, 0x6a, 0x0b
]);

WebAssembly.instantiate(wasmCode).then(wasmInstance => {
  const addFunction = wasmInstance.instance.exports.add;
  const result = addFunction(5, 3); // 调用 WebAssembly 导出的 add 函数
  console.log(result); // 输出 8
});
```

在这个例子中，当 `addFunction(5, 3)` 被调用时，如果 V8 的 Liftoff 编译器被用于编译 `add` 函数，那么 `liftoff-assembler-x64-inl.h` 中定义的函数就会被用来生成 x64 汇编代码，执行加法操作并返回结果。例如，`LoadConstant` 可能会被用来加载常量 5 和 3 到寄存器，然后使用汇编指令执行加法，并将结果存储回寄存器或栈上。

**代码逻辑推理示例:**

**假设输入:**

- `assm`: 一个 `LiftoffAssembler` 实例。
- `addr`: 寄存器 `rax`，包含基地址 `0x1000`.
- `offset_reg`: 寄存器 `rbx`，包含偏移量 `0x8`.
- `offset_imm`: 立即数偏移量 `0x10`.
- `scale_factor`: `times_8`.

**执行 `GetMemOp(assm, addr, offset_reg, offset_imm, scale_factor)`:**

1. `is_uint31(offset_imm)` 为真 (0x10 小于 2^31)。
2. `offset_imm32` 被赋值为 `0x10`。
3. 由于 `offset_reg` 不是 `no_reg`，返回 `Operand(addr, offset_reg, scale_factor, offset_imm32)`。

**输出:**  一个表示内存操作数的 `Operand` 对象，它将被编码为访问地址 `rax + rbx * 8 + 0x10` 处的内存。

**用户常见的编程错误示例:**

由于这个头文件是 V8 内部实现，普通 JavaScript 开发者不会直接编写或修改这些代码。然而，理解其背后的概念有助于理解 WebAssembly 和 JavaScript 引擎的底层工作原理。

与这类底层汇编器相关的常见编程错误（如果用户需要直接操作类似的接口）包括：

1. **错误的偏移量计算:** 在 `GetMemOp` 或手动构建 `Operand` 时，使用了不正确的偏移量，导致访问了错误的内存地址，可能导致程序崩溃或数据损坏。
   ```c++
   // 错误示例：假设需要访问数组的第三个元素（假设每个元素大小为 4 字节）
   Operand wrong_offset(addr_reg, 3); // 缺少乘以元素大小
   Operand correct_offset(addr_reg, 3 * 4);
   ```
2. **寄存器冲突:** 错误地使用了已经被占用的寄存器，导致数据被意外覆盖。例如，在调用 `GetMemOp` 后，如果立即覆盖了可能被 `GetMemOp` 使用的 `kScratchRegister2`，可能会导致后续使用该 `Operand` 时出错。
   ```c++
   LiftoffAssembler assm;
   Register addr_reg = r8;
   Register offset_reg = r9;
   assm.Move(kScratchRegister2, Immediate(10)); // 假设 GetMemOp 可能会用 kScratchRegister2
   Operand mem_op = GetMemOp(&assm, addr_reg, offset_reg, 10);
   assm.Move(kScratchRegister2, Immediate(20)); // 错误：可能在 mem_op 使用 kScratchRegister2 之前覆盖了它
   assm.movq(kScratchRegister, mem_op); // 此时 mem_op 可能会计算错误
   ```
3. **类型不匹配:** 在 `LoadFromStack` 或 `StoreToMemory` 时，指定的 `ValueKind` 与实际存储的数据类型不符，可能导致数据截断或错误解释。
   ```c++
   LiftoffAssembler assm;
   LiftoffRegister reg(r10);
   int stack_offset = 8;
   int32_t value = 0x12345678;
   assm.pushq(Immediate(value)); // 将 int32_t 推入栈，占用 8 字节
   LoadFromStack(&assm, reg, GetStackSlot(stack_offset), kI16); // 错误：尝试以 kI16 (2 字节) 加载
   ```

总而言之，`v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h` 是 V8 引擎中 Liftoff 编译器的核心组成部分，它提供了在 x64 架构下生成高效 WebAssembly 执行代码的基础工具。虽然普通 JavaScript 开发者不需要直接接触这些代码，但理解其功能有助于深入了解 JavaScript 引擎的工作原理。

### 提示词
```
这是目录为v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_X64_LIFTOFF_ASSEMBLER_X64_INL_H_
#define V8_WASM_BASELINE_X64_LIFTOFF_ASSEMBLER_X64_INL_H_

#include <optional>

#include "src/codegen/assembler.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/x64/assembler-x64.h"
#include "src/codegen/x64/register-x64.h"
#include "src/flags/flags.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/parallel-move-inl.h"
#include "src/wasm/baseline/parallel-move.h"
#include "src/wasm/object-access.h"
#include "src/wasm/simd-shuffle.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"

namespace v8::internal::wasm {

#define RETURN_FALSE_IF_MISSING_CPU_FEATURE(name)    \
  if (!CpuFeatures::IsSupported(name)) return false; \
  CpuFeatureScope feature(this, name);

namespace liftoff {

constexpr Register kScratchRegister2 = r11;
static_assert(kScratchRegister != kScratchRegister2, "collision");
static_assert((kLiftoffAssemblerGpCacheRegs &
               RegList{kScratchRegister, kScratchRegister2})
                  .is_empty(),
              "scratch registers must not be used as cache registers");

constexpr DoubleRegister kScratchDoubleReg2 = xmm14;
static_assert(kScratchDoubleReg != kScratchDoubleReg2, "collision");
static_assert((kLiftoffAssemblerFpCacheRegs &
               DoubleRegList{kScratchDoubleReg, kScratchDoubleReg2})
                  .is_empty(),
              "scratch registers must not be used as cache registers");

inline constexpr Operand GetStackSlot(int offset) {
  return Operand(rbp, -offset);
}

constexpr Operand kInstanceDataOperand =
    GetStackSlot(WasmLiftoffFrameConstants::kInstanceDataOffset);

constexpr Operand kOSRTargetSlot = GetStackSlot(kOSRTargetOffset);

// Note: The returned Operand might contain {kScratchRegister2}; make sure not
// to clobber that until after the last use of the Operand.
inline Operand GetMemOp(LiftoffAssembler* assm, Register addr,
                        Register offset_reg, uintptr_t offset_imm,
                        ScaleFactor scale_factor = times_1) {
  if (is_uint31(offset_imm)) {
    int32_t offset_imm32 = static_cast<int32_t>(offset_imm);
    return offset_reg == no_reg
               ? Operand(addr, offset_imm32)
               : Operand(addr, offset_reg, scale_factor, offset_imm32);
  }
  // Offset immediate does not fit in 31 bits.
  Register scratch = kScratchRegister2;
  assm->MacroAssembler::Move(scratch, offset_imm);
  if (offset_reg != no_reg) assm->addq(scratch, offset_reg);
  return Operand(addr, scratch, scale_factor, 0);
}

inline void LoadFromStack(LiftoffAssembler* assm, LiftoffRegister dst,
                          Operand src, ValueKind kind) {
  switch (kind) {
    case kI16:
      assm->movw(dst.gp(), src);
      break;
    case kI32:
      assm->movl(dst.gp(), src);
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
      // Stack slots are uncompressed even when heap pointers are compressed.
      assm->movq(dst.gp(), src);
      break;
    case kF32:
      assm->Movss(dst.fp(), src);
      break;
    case kF64:
      assm->Movsd(dst.fp(), src);
      break;
    case kS128:
      assm->Movdqu(dst.fp(), src);
      break;
    default:
      UNREACHABLE();
  }
}

inline void StoreToMemory(LiftoffAssembler* assm, Operand dst,
                          LiftoffRegister src, ValueKind kind) {
  switch (kind) {
    case kI16:
      assm->movw(dst, src.gp());
      break;
    case kI32:
      assm->movl(dst, src.gp());
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
      // Stack slots are uncompressed even when heap pointers are compressed.
      assm->movq(dst, src.gp());
      break;
    case kF32:
      assm->Movss(dst, src.fp());
      break;
    case kF64:
      assm->Movsd(dst, src.fp());
      break;
    case kS128:
      assm->Movdqu(dst, src.fp());
      break;
    default:
      UNREACHABLE();
  }
}

inline void StoreToMemory(LiftoffAssembler* assm, Operand dst,
                          const LiftoffAssembler::VarState& src) {
  if (src.is_reg()) {
    liftoff::StoreToMemory(assm, dst, src.reg(), src.kind());
  } else if (src.is_const()) {
    if (src.kind() == kI32) {
      assm->movl(dst, Immediate(src.i32_const()));
    } else {
      assm->MacroAssembler::Move(dst, static_cast<int64_t>(src.i32_const()));
    }
  } else if (value_kind_size(src.kind()) == 4) {
    DCHECK(src.is_stack());
    assm->movl(kScratchRegister, liftoff::GetStackSlot(src.offset()));
    assm->movl(dst, kScratchRegister);
  } else {
    DCHECK(src.is_stack());
    DCHECK_EQ(8, value_kind_size(src.kind()));
    assm->movq(kScratchRegister, liftoff::GetStackSlot(src.offset()));
    assm->movq(dst, kScratchRegister);
  }
}

inline void push(LiftoffAssembler* assm, LiftoffRegister reg, ValueKind kind,
                 int padding = 0) {
  switch (kind) {
    case kI32:
    case kI64:
    case kRef:
    case kRefNull:
    case kRtt:
      assm->AllocateStackSpace(padding);
      assm->pushq(reg.gp());
      break;
    case kF32:
      assm->AllocateStackSpace(kSystemPointerSize + padding);
      assm->Movss(Operand(rsp, 0), reg.fp());
      break;
    case kF64:
      assm->AllocateStackSpace(kSystemPointerSize + padding);
      assm->Movsd(Operand(rsp, 0), reg.fp());
      break;
    case kS128:
      assm->AllocateStackSpace(kSystemPointerSize * 2 + padding);
      assm->Movdqu(Operand(rsp, 0), reg.fp());
      break;
    default:
      UNREACHABLE();
  }
}

constexpr int kSubSpSize = 7;  // 7 bytes for "subq rsp, <imm32>"

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  int offset = pc_offset();
  // Next we reserve the memory for the whole stack frame. We do not know yet
  // how big the stack frame will be so we just emit a placeholder instruction.
  // PatchPrepareStackFrame will patch this in order to increase the stack
  // appropriately.
  sub_sp_32(0);
  DCHECK_EQ(liftoff::kSubSpSize, pc_offset() - offset);
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

  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

void LiftoffAssembler::PrepareTailCall(int num_callee_stack_params,
                                       int stack_param_delta) {
  // Push the return address and frame pointer to complete the stack frame.
  pushq(Operand(rbp, 8));
  pushq(Operand(rbp, 0));

  // Shift the whole frame upwards.
  const int slot_count = num_callee_stack_params + 2;
  for (int i = slot_count - 1; i >= 0; --i) {
    movq(kScratchRegister, Operand(rsp, i * 8));
    movq(Operand(rbp, (i - stack_param_delta) * 8), kScratchRegister);
  }

  // Set the new stack and frame pointer.
  leaq(rsp, Operand(rbp, -stack_param_delta * 8));
  popq(rbp);
}

void LiftoffAssembler::AlignFrameSize() {
  max_used_spill_offset_ = RoundUp(max_used_spill_offset_, kSystemPointerSize);
}

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
  DCHECK_EQ(0, frame_size % kSystemPointerSize);

  // We can't run out of space when patching, just pass anything big enough to
  // not cause the assembler to try to grow the buffer.
  constexpr int kAvailableSpace = 64;
  Assembler patching_assembler(
      AssemblerOptions{},
      ExternalAssemblerBuffer(buffer_start_ + offset, kAvailableSpace));

  if (V8_LIKELY(frame_size < 4 * KB)) {
    // This is the standard case for small frames: just subtract from SP and be
    // done with it.
    patching_assembler.sub_sp_32(frame_size);
    DCHECK_EQ(liftoff::kSubSpSize, patching_assembler.pc_offset());
    return;
  }

  // The frame size is bigger than 4KB, so we might overflow the available stack
  // space if we first allocate the frame and then do the stack check (we will
  // need some remaining stack space for throwing the exception). That's why we
  // check the available stack space before we allocate the frame. To do this we
  // replace the {__ sub(sp, framesize)} with a jump to OOL code that does this
  // "extended stack check".
  //
  // The OOL code can simply be generated here with the normal assembler,
  // because all other code generation, including OOL code, has already finished
  // when {PatchPrepareStackFrame} is called. The function prologue then jumps
  // to the current {pc_offset()} to execute the OOL code for allocating the
  // large frame.

  // Emit the unconditional branch in the function prologue (from {offset} to
  // {pc_offset()}).
  patching_assembler.jmp_rel(pc_offset() - offset);
  DCHECK_GE(liftoff::kSubSpSize, patching_assembler.pc_offset());
  patching_assembler.Nop(liftoff::kSubSpSize - patching_assembler.pc_offset());

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    movq(kScratchRegister,
         StackLimitAsOperand(StackLimitKind::kRealStackLimit));
    addq(kScratchRegister, Immediate(frame_size));
    cmpq(rsp, kScratchRegister);
    j(above_equal, &continuation, Label::kNear);
  }

  if (v8_flags.experimental_wasm_growable_stacks) {
    LiftoffRegList regs_to_save;
    regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
    regs_to_save.set(WasmHandleStackOverflowDescriptor::FrameBaseRegister());
    for (auto reg : kGpParamRegisters) regs_to_save.set(reg);
    PushRegisters(regs_to_save);
    movq(WasmHandleStackOverflowDescriptor::GapRegister(),
         Immediate(frame_size));
    movq(WasmHandleStackOverflowDescriptor::FrameBaseRegister(), rbp);
    addq(WasmHandleStackOverflowDescriptor::FrameBaseRegister(),
         Immediate(static_cast<int32_t>(
             stack_param_slots * kStackSlotSize +
             CommonFrameConstants::kFixedFrameSizeAboveFp)));
    CallBuiltin(Builtin::kWasmHandleStackOverflow);
    PopRegisters(regs_to_save);
  } else {
    near_call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
              RelocInfo::WASM_STUB_CALL);
    // The call will not return; just define an empty safepoint.
    safepoint_table_builder->DefineSafepoint(this);
    AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
  }

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP; consult {MacroAssembler::AllocateStackSpace}.
  AllocateStackSpace(frame_size);

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ sub(sp, sp, framesize)} (which
  // is a branch now).
  int func_start_offset = offset + liftoff::kSubSpSize;
  jmp_rel(func_start_offset - pc_offset());
}

void LiftoffAssembler::FinishCode() {}

void LiftoffAssembler::AbortCompilation() {}

// static
constexpr int LiftoffAssembler::StaticStackFrameSize() {
  return kOSRTargetOffset;
}

int LiftoffAssembler::SlotSizeForType(ValueKind kind) {
  return value_kind_full_size(kind);
}

bool LiftoffAssembler::NeedsAlignment(ValueKind kind) {
  return is_reference(kind);
}

void LiftoffAssembler::CheckTierUp(int declared_func_index, int budget_used,
                                   Label* ool_label,
                                   const FreezeCacheState& frozen) {
  Register instance_data = cache_state_.cached_instance_data;
  if (instance_data == no_reg) {
    instance_data = kScratchRegister;
    LoadInstanceDataFromFrame(instance_data);
  }

  Register budget_array = kScratchRegister;  // Overwriting {instance_data}.
  constexpr int kArrayOffset = wasm::ObjectAccess::ToTagged(
      WasmTrustedInstanceData::kTieringBudgetArrayOffset);
  movq(budget_array, Operand{instance_data, kArrayOffset});

  int offset = kInt32Size * declared_func_index;
  subl(Operand{budget_array, offset}, Immediate(budget_used));
  j(negative, ool_label);
}

Register LiftoffAssembler::LoadOldFramePointer() {
  if (!v8_flags.experimental_wasm_growable_stacks) {
    return rbp;
  }
  LiftoffRegister old_fp = GetUnusedRegister(RegClass::kGpReg, {});
  Label done, call_runtime;
  movq(old_fp.gp(), MemOperand(rbp, TypedFrameConstants::kFrameTypeOffset));
  cmpq(old_fp.gp(),
       Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  j(equal, &call_runtime);
  movq(old_fp.gp(), rbp);
  jmp(&done);

  bind(&call_runtime);
  LiftoffRegList regs_to_save = cache_state()->used_registers;
  PushRegisters(regs_to_save);
  PrepareCallCFunction(1);
  LoadAddress(kCArgRegs[0], ExternalReference::isolate_address());
  CallCFunction(ExternalReference::wasm_load_old_fp(), 1);
  if (old_fp.gp() != kReturnRegister0) {
    movq(old_fp.gp(), kReturnRegister0);
  }
  PopRegisters(regs_to_save);

  bind(&done);
  return old_fp.gp();
}

void LiftoffAssembler::CheckStackShrink() {
  movq(kScratchRegister,
       MemOperand(rbp, TypedFrameConstants::kFrameTypeOffset));
  cmpq(kScratchRegister,
       Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  Label done;
  j(not_equal, &done);
  LiftoffRegList regs_to_save;
  for (auto reg : kGpReturnRegisters) regs_to_save.set(reg);
  PushRegisters(regs_to_save);
  PrepareCallCFunction(1);
  LoadAddress(kCArgRegs[0], ExternalReference::isolate_address());
  CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
  // Restore old FP. We don't need to restore old SP explicitly, because
  // it will be restored from FP in LeaveFrame before return.
  movq(rbp, kReturnRegister0);
  PopRegisters(regs_to_save);
  bind(&done);
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      if (value.to_i32() == 0) {
        xorl(reg.gp(), reg.gp());
      } else {
        movl(reg.gp(), Immediate(value.to_i32()));
      }
      break;
    case kI64:
      MacroAssembler::Move(reg.gp(), value.to_i64());
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
  movq(dst, liftoff::kInstanceDataOperand);
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  LoadTrustedPointerField(dst, Operand{src_addr, offset}, tag,
                          kScratchRegister);
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  Operand src{instance, offset};
  switch (size) {
    case 1:
      movzxbl(dst, src);
      break;
    case 4:
      movl(dst, src);
      break;
    case 8:
      movq(dst, src);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int offset) {
  DCHECK_LE(0, offset);
  LoadTaggedField(dst, Operand(instance, offset));
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  movq(liftoff::kInstanceDataOperand, instance);
}

void LiftoffAssembler::ResetOSRTarget() {
  movq(liftoff::kOSRTargetSlot, Immediate(0));
}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  DCHECK_GE(offset_imm, 0);
  if (offset_reg != no_reg) AssertZeroExtended(offset_reg);
  ScaleFactor scale_factor = !needs_shift             ? times_1
                             : COMPRESS_POINTERS_BOOL ? times_4
                                                      : times_8;
  Operand src_op =
      liftoff::GetMemOp(this, src_addr, offset_reg,
                        static_cast<uint32_t>(offset_imm), scale_factor);
  if (protected_load_pc) *protected_load_pc = pc_offset();
  LoadTaggedField(dst, src_op);
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset_imm) {
  DCHECK_LE(0, offset_imm);
  LoadProtectedPointerField(dst, Operand{src_addr, offset_imm});
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  Operand src_op = liftoff::GetMemOp(this, src_addr, no_reg,
                                     static_cast<uint32_t>(offset_imm));
  movq(dst, src_op);
}

#ifdef V8_ENABLE_SANDBOX
void LiftoffAssembler::LoadCodeEntrypointViaCodePointer(Register dst,
                                                        Register src_addr,
                                                        int offset_imm) {
  Operand src_op = liftoff::GetMemOp(this, src_addr, no_reg,
                                     static_cast<uint32_t>(offset_imm));
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
  DCHECK_GE(offset_imm, 0);
  Operand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg,
                                     static_cast<uint32_t>(offset_imm));
  if (protected_store_pc) *protected_store_pc = pc_offset();
  StoreTaggedField(dst_op, src);

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  // None of the code below uses the {kScratchRegister} (in particular the
  // {CallRecordWriteStubSaveRegisters} just emits a near call). Hence we can
  // use it as scratch register here.
  Label exit;
  CheckPageFlag(dst_addr, kScratchRegister,
                MemoryChunk::kPointersFromHereAreInterestingMask, zero, &exit,
                Label::kNear);
  JumpIfSmi(src, &exit, Label::kNear);
  CheckPageFlag(src, kScratchRegister,
                MemoryChunk::kPointersToHereAreInterestingMask, zero, &exit,
                Label::kNear);
  leaq(kScratchRegister, dst_op);

  CallRecordWriteStubSaveRegisters(dst_addr, kScratchRegister,
                                   SaveFPRegsMode::kSave,
                                   StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uintptr_t offset_imm,
                                  LoadType type, LiftoffRegList /* pinned */,
                                  bool i64_offset) {
  Load(dst, src_addr, offset_reg, offset_imm, type, nullptr, true, i64_offset);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uintptr_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool /* is_load_mem */, bool i64_offset,
                            bool needs_shift) {
  if (offset_reg != no_reg && !i64_offset) AssertZeroExtended(offset_reg);
  static_assert(times_4 == 2);
  ScaleFactor scale_factor =
      needs_shift ? static_cast<ScaleFactor>(type.size_log_2()) : times_1;
  Operand src_op =
      liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm, scale_factor);
  if (protected_load_pc) *protected_load_pc = pc_offset();
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U:
      movzxbl(dst.gp(), src_op);
      break;
    case LoadType::kI32Load8S:
      movsxbl(dst.gp(), src_op);
      break;
    case LoadType::kI64Load8S:
      movsxbq(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      movzxwl(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16S:
      movsxwl(dst.gp(), src_op);
      break;
    case LoadType::kI64Load16S:
      movsxwq(dst.gp(), src_op);
      break;
    case LoadType::kI32Load:
    case LoadType::kI64Load32U:
      movl(dst.gp(), src_op);
      break;
    case LoadType::kI64Load32S:
      movsxlq(dst.gp(), src_op);
      break;
    case LoadType::kI64Load:
      movq(dst.gp(), src_op);
      break;
    case LoadType::kF32Load:
      Movss(dst.fp(), src_op);
      break;
    case LoadType::kF32LoadF16: {
      CpuFeatureScope f16c_scope(this, F16C);
      CpuFeatureScope avx2_scope(this, AVX2);
      vpbroadcastw(dst.fp(), src_op);
      vcvtph2ps(dst.fp(), dst.fp());
      break;
    }
    case LoadType::kF64Load:
      Movsd(dst.fp(), src_op);
      break;
    case LoadType::kS128Load:
      Movdqu(dst.fp(), src_op);
      break;
  }
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList /* pinned */,
                             uint32_t* protected_store_pc,
                             bool /* is_store_mem */, bool i64_offset) {
  if (offset_reg != no_reg && !i64_offset) AssertZeroExtended(offset_reg);
  Operand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      movb(dst_op, src.gp());
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      movw(dst_op, src.gp());
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      movl(dst_op, src.gp());
      break;
    case StoreType::kI64Store:
      movq(dst_op, src.gp());
      break;
    case StoreType::kF32Store:
      Movss(dst_op, src.fp());
      break;
    case StoreType::kF32StoreF16: {
      CpuFeatureScope fscope(this, F16C);
      vcvtps2ph(kScratchDoubleReg, src.fp(), 0);
      Pextrw(dst_op, kScratchDoubleReg, static_cast<uint8_t>(0));
      break;
    }
    case StoreType::kF64Store:
      Movsd(dst_op, src.fp());
      break;
    case StoreType::kS128Store:
      Movdqu(dst_op, src.fp());
      break;
  }
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uintptr_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList /* pinned */,
                                   bool i64_offset) {
  if (offset_reg != no_reg && !i64_offset) AssertZeroExtended(offset_reg);
  Operand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);
  Register src_reg = src.gp();
  if (cache_state()->is_used(src)) {
    movq(kScratchRegister, src_reg);
    src_reg = kScratchRegister;
  }
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      xchgb(src_reg, dst_op);
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      xchgw(src_reg, dst_op);
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      xchgl(src_reg, dst_op);
      break;
    case StoreType::kI64Store:
      xchgq(src_reg, dst_op);
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicAdd(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  if (offset_reg != no_reg && !i64_offset) AssertZeroExtended(offset_reg);
  DCHECK(!cache_state()->is_used(result));
  if (cache_state()->is_used(value)) {
    // We cannot overwrite {value}, but the {value} register is changed in the
    // code we generate. Therefore we copy {value} to {result} and use the
    // {result} register in the code below.
    movq(result.gp(), value.gp());
    value = result;
  }
  Operand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);
  lock();
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      xaddb(dst_op, value.gp());
      movzxbq(result.gp(), value.gp());
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      xaddw(dst_op, value.gp());
      movzxwq(result.gp(), value.gp());
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      xaddl(dst_op, value.gp());
      if (value != result) {
        movq(result.gp(), value.gp());
      }
      break;
    case StoreType::kI64Store:
      xaddq(dst_op, value.gp());
      if (value != result) {
        movq(result.gp(), value.gp());
      }
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicSub(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  if (offset_reg != no_reg && !i64_offset) AssertZeroExtended(offset_reg);
  LiftoffRegList dont_overwrite =
      cache_state()->used_registers | LiftoffRegList{dst_addr};
  if (offset_reg != no_reg) dont_overwrite.set(offset_reg);
  DCHECK(!dont_overwrite.has(result));
  if (dont_overwrite.has(value)) {
    // We cannot overwrite {value}, but the {value} register is changed in the
    // code we generate. Therefore we copy {value} to {result} and use the
    // {result} register in the code below.
    movq(result.gp(), value.gp());
    value = result;
  }
  Operand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      negb(value.gp());
      lock();
      xaddb(dst_op, value.gp());
      movzxbq(result.gp(), value.gp());
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      negw(value.gp());
      lock();
      xaddw(dst_op, value.gp());
      movzxwq(result.gp(), value.gp());
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      negl(value.gp());
      lock();
      xaddl(dst_op, value.gp());
      if (value != result) {
        movq(result.gp(), value.gp());
      }
      break;
    case StoreType::kI64Store:
      negq(value.gp());
      lock();
      xaddq(dst_op, value.gp());
      if (value != result) {
        movq(result.gp(), value.gp());
      }
      break;
    default:
      UNREACHABLE();
  }
}

namespace liftoff {
#define __ lasm->

inline void AtomicBinop(LiftoffAssembler* lasm,
                        void (Assembler::*opl)(Register, Register),
                        void (Assembler::*opq)(Register, Register),
                        Register dst_addr, Register offset_reg,
                        uintptr_t offset_imm, LiftoffRegister value,
                        LiftoffRegister result, StoreType type,
                        bool i64_offset) {
  if (offset_reg != no_reg && !i64_offset) __ AssertZeroExtended(offset_reg);
  DCHECK(!__ cache_state()->is_used(result));
  Register value_reg = value.gp();
  // The cmpxchg instruction uses rax to store the old value of the
  // compare-exchange primitive. Therefore we have to spill the register and
  // move any use to another register.
  LiftoffRegList pinned = LiftoffRegList{dst_addr, value_reg};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  __ ClearRegister(rax, {&dst_addr, &offset_reg, &value_reg}, pinned);
  Operand dst_op = liftoff::GetMemOp(lasm, dst_addr, offset_reg, offset_imm);

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      Label binop;
      __ xorq(rax, rax);
      __ movb(rax, dst_op);
      __ bind(&binop);
      __ movl(kScratchRegister, rax);
      (lasm->*opl)(kScratchRegister, value_reg);
      __ lock();
      __ cmpxchgb(dst_op, kScratchRegister);
      __ j(not_equal, &binop);
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      Label binop;
      __ xorq(rax, rax);
      __ movw(rax, dst_op);
      __ bind(&binop);
      __ movl(kScratchRegister, rax);
      (lasm->*opl)(kScratchRegister, value_reg);
      __ lock();
      __ cmpxchgw(dst_op, kScratchRegister);
      __ j(not_equal, &binop);
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      Label binop;
      __ movl(rax, dst_op);
      __ bind(&binop);
      __ movl(kScratchRegister, rax);
      (lasm->*opl)(kScratchRegister, value_reg);
      __ lock();
      __ cmpxchgl(dst_op, kScratchRegister);
      __ j(not_equal, &binop);
      break;
    }
    case StoreType::kI64Store: {
      Label binop;
      __ movq(rax, dst_op);
      __ bind(&binop);
      __ movq(kScratchRegister, rax);
      (lasm->*opq)(kScratchRegister, value_reg);
      __ lock();
      __ cmpxchgq(dst_op, kScratchRegister);
      __ j(not_equal, &binop);
      break;
    }
    default:
      UNREACHABLE();
  }

  if (result.gp() != rax) {
    __ movq(result.gp(), rax);
  }
}
#undef __
}  // namespace liftoff

void LiftoffAssembler::AtomicAnd(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  liftoff::AtomicBinop(this, &Assembler::andl, &Assembler::andq, dst_addr,
                       offset_reg, offset_imm, value, result, type, i64_offset);
}

void LiftoffAssembler::AtomicOr(Register dst_addr, Register offset_reg,
                                uintptr_t offset_imm, LiftoffRegister value,
                                LiftoffRegister result, StoreType type,
                                bool i64_offset) {
  liftoff::AtomicBinop(this, &Assembler::orl, &Assembler::orq, dst_addr,
                       offset_reg, offset_imm, value, result, type, i64_offset);
}

void LiftoffAssembler::AtomicXor(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  liftoff::AtomicBinop(this, &Assembler::xorl, &Assembler::xorq, dst_addr,
                       offset_reg, offset_imm, value, result, type, i64_offset);
}

void LiftoffAssembler::AtomicExchange(Register dst_addr, Register offset_reg,
                                      uintptr_t offset_imm,
                                      LiftoffRegister value,
                                      LiftoffRegister result, StoreType type,
                                      bool i64_offset) {
  if (offset_reg != no_reg && !i64_offset) AssertZeroExtended(offset_reg);
  DCHECK(!cache_state()->is_used(result));
  if (cache_state()->is_used(value)) {
    // We cannot overwrite {value}, but the {value} register is changed in the
    // code we generate. Therefore we copy {value} to {result} and use the
    // {re
```