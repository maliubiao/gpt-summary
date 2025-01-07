Response:
My thinking process to analyze the given C++ header file and provide a summary goes like this:

1. **Identify the Core Purpose:** The filename `liftoff-assembler-arm64-inl.h` immediately suggests this file defines inline functions related to the Liftoff assembler for the ARM64 architecture within the V8 JavaScript engine. The `.inl.h` convention signifies inline implementations.

2. **Scan for Key Components and Concepts:** I quickly scanned the file for prominent elements:
    * **Includes:** These reveal dependencies. `macro-assembler-arm64-inl.h`, `liftoff-assembler.h`, `parallel-move-inl.h`, `wasm-objects.h` are important clues. They indicate the file interacts with lower-level ARM64 assembly, the general Liftoff assembler framework, parallel register moves, and WebAssembly object representations.
    * **Namespaces:** `v8::internal::wasm::liftoff` confirms the context is the WebAssembly Liftoff tier within V8.
    * **Frame Structure:** The detailed comment block describing the Liftoff frame layout is crucial. It explains how data is organized on the stack during function calls.
    * **Inline Functions:**  The majority of the file consists of `inline` functions. This means their code is likely substituted directly at the call site for performance.
    * **`GetStackSlot`, `GetInstanceDataOperand`:** These strongly suggest managing data within the function's stack frame.
    * **`GetRegFromType`:** This points to mapping WebAssembly value types (like `i32`, `f64`) to specific ARM64 register types.
    * **`AcquireByType`:**  Indicates a mechanism for obtaining temporary registers based on value type.
    * **`GetMemOp`, `GetEffectiveAddress`:** These are clearly about calculating memory addresses, a fundamental part of assembly.
    * **`EmitSimdShift`:** Signals support for SIMD (Single Instruction, Multiple Data) operations.
    * **`LoadToRegister`, `StoreToMemory`:** Core operations for moving data between memory and registers.
    * **`PrepareStackFrame`, `CallFrameSetupStub`, `PrepareTailCall`:** Functions related to the setup and management of function call frames.
    * **`PatchPrepareStackFrame`:**  Suggests late modification or optimization of the stack frame setup.
    * **`CheckTierUp`, `CheckStackShrink`:**  Features related to dynamic optimization and stack management.
    * **`LoadConstant`, `LoadInstanceDataFromFrame`:**  Loading specific types of data.
    * **`LoadTaggedPointer`, `StoreTaggedPointer`:** Handling tagged pointers, which are used in V8's object model.
    * **`Load`, `Store`:** Generic load and store operations with various data types and sizes.
    * **Atomic Operations (`AtomicBinop`):** Support for thread-safe operations on memory.

3. **Group Functionalities:**  Based on the scanned elements, I started grouping the functionalities:
    * **Stack Frame Management:**  Functions related to setting up, managing, and accessing data within the Liftoff stack frame (e.g., `GetStackSlot`, `PrepareStackFrame`).
    * **Register Management:** Functions for obtaining and using registers based on data types (e.g., `GetRegFromType`, `AcquireByType`).
    * **Memory Access:** Functions for calculating memory addresses and loading/storing data of various types (e.g., `GetMemOp`, `Load`, `Store`).
    * **Function Call Handling:** Functions for preparing for function calls, including tail calls (e.g., `CallFrameSetupStub`, `PrepareTailCall`).
    * **Optimization and Runtime Features:**  Functions related to dynamic optimization (`CheckTierUp`) and stack adjustments (`CheckStackShrink`).
    * **Data Loading:** Functions for loading constants, instance data, and tagged pointers.
    * **SIMD Support:** Functions for performing SIMD operations (`EmitSimdShift`).
    * **Atomic Operations:** Functions for performing atomic memory operations.

4. **Synthesize a High-Level Summary:**  Using the grouped functionalities, I formulated a concise summary highlighting the main purpose of the file: providing inline assembly utilities for the Liftoff compiler on ARM64, focusing on stack management, register allocation, memory access, and function call handling.

5. **Address Specific Questions:** I then revisited the prompt's specific questions:
    * **Filename ending with `.tq`:**  Confirmed it's not a Torque file.
    * **Relationship to JavaScript:** Explained that this code is part of V8, which executes JavaScript, and the Liftoff compiler generates machine code from the WebAssembly bytecode produced by compiling JavaScript (or directly from WebAssembly). Provided a JavaScript example that *could* lead to this code being executed (though the connection is indirect).
    * **Code Logic Inference:** Selected a simple function (`GetStackSlot`) and provided example inputs and outputs to illustrate its functionality.
    * **Common Programming Errors:** Focused on stack overflow as a potential consequence of improper stack frame management, which this file helps implement correctly.
    * **Overall Functionality (Part 1):**  This was covered in the high-level summary.

6. **Refine and Organize:** I reviewed the entire response, ensuring clarity, accuracy, and logical flow. I used bullet points and clear headings to organize the information effectively. I made sure to connect the technical details back to the broader context of V8 and JavaScript where appropriate.
这是V8 JavaScript引擎中用于ARM64架构的Liftoff基线编译器的汇编器头文件（内联实现）。它定义了在生成ARM64汇编代码时使用的各种内联函数，这些函数是Liftoff编译器将WebAssembly代码转换为机器码的关键组成部分。

**功能归纳 (第1部分):**

这个头文件 `v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h` 的主要功能是提供一组**内联函数**，作为ARM64架构上Liftoff编译器的汇编指令构建块。  它封装了底层的ARM64汇编指令，并提供了更高级别的抽象，使得Liftoff编译器更容易生成正确且高效的机器码。

更具体地说，它涉及以下几个方面：

* **栈帧管理:** 定义了Liftoff函数调用的栈帧布局，并提供了访问栈帧中不同位置（例如参数、局部变量、实例数据）的内联函数，如 `GetStackSlot` 和 `GetInstanceDataOperand`。
* **寄存器操作:** 提供了根据WebAssembly值类型（如 `i32`, `f64`）获取对应的ARM64寄存器的函数，如 `GetRegFromType`。还包含了处理寄存器列表的函数，如 `PadRegList` 和 `PadVRegList`。
* **内存访问:** 提供了生成内存操作指令的函数，例如计算有效地址的 `GetMemOp` 和 `GetEffectiveAddress`，以及加载和存储数据的 `LoadToRegister` 和 `StoreToMemory`。
* **SIMD支持:** 包含用于生成SIMD（单指令多数据）操作指令的函数，如 `EmitSimdShift` 和 `EmitSimdShiftRightImmediate`。
* **条件判断:** 提供了生成用于检查向量中所有或任意元素是否为真的指令的函数，如 `EmitAnyTrue` 和 `EmitAllTrue`。
* **代码生成辅助:** 提供了诸如准备栈帧、设置调用帧、准备尾调用等高级操作的函数。
* **优化相关:**  包含与代码优化相关的函数，例如 `CheckTierUp` 用于检查是否需要将函数提升到更高级的编译器。
* **常量加载:** 提供了加载常量的函数 `LoadConstant`。
* **实例数据访问:** 提供了加载Wasm实例数据的函数 `LoadInstanceDataFromFrame`。
* **类型相关的操作:** 提供了根据类型确定槽大小和是否需要对齐的函数 `SlotSizeForType` 和 `NeedsAlignment`。

**关于文件类型和 JavaScript 功能的关系:**

* **文件名以 `.tq` 结尾？**  根据您的描述，`v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h` 以 `.h` 结尾，而不是 `.tq`。因此，它是一个**C++头文件**，而不是V8的Torque源代码。 Torque是一种V8内部使用的类型化汇编语言，用于生成V8的内置函数。

* **与 JavaScript 的功能关系？**  这个头文件中的代码是V8引擎的核心组成部分，它直接影响着**WebAssembly 代码的执行效率**。 当 JavaScript 代码中调用 WebAssembly 模块时，V8 的 Liftoff 编译器会使用这里的函数将 WebAssembly 指令转换为底层的 ARM64 机器码。

**JavaScript 举例说明:**

虽然这个头文件本身不是 JavaScript 代码，但它的功能是为执行 WebAssembly 代码提供支持。以下是一个简单的 JavaScript 例子，当执行其中的 WebAssembly 代码时，V8 的 Liftoff 编译器可能会用到 `liftoff-assembler-arm64-inl.h` 中定义的函数：

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01,
  0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x04,
  0x04, 0x01, 0x70, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20,
  0x00, 0x20, 0x01, 0x6a, 0x0b
]);

WebAssembly.instantiate(wasmCode).then(instance => {
  const add = instance.instance.exports.add;
  const result = add(5, 10); // 调用 WebAssembly 函数
  console.log(result); // 输出 15
});
```

在这个例子中，当 `add(5, 10)` 被调用时，V8 的 Liftoff 编译器会负责将 WebAssembly 的加法指令 (`0x6a`) 转换为 ARM64 机器码。 `liftoff-assembler-arm64-inl.h` 中定义的函数，例如用于加载参数、执行加法运算、存储结果的函数，会在这个过程中被使用。

**代码逻辑推理示例:**

以 `GetStackSlot` 函数为例：

**假设输入:** `offset = 8`

**代码:**

```c++
inline MemOperand GetStackSlot(int offset) { return MemOperand(fp, -offset); }
```

**推理:**  该函数返回一个 `MemOperand` 对象，表示内存操作数。它使用帧指针寄存器 `fp` 作为基地址，并将提供的 `offset` 取负数作为偏移量。在 ARM64 的 Liftoff 栈帧布局中，正偏移量通常指向帧指针之下的区域（旧的栈帧），负偏移量指向帧指针之上的区域（当前栈帧的局部变量和参数）。

**输出:**  返回一个表示内存地址 `fp - 8` 的 `MemOperand` 对象。这意味着它访问的是当前栈帧中相对于帧指针偏移 8 个字节的位置。根据栈帧布局的注释，这可能是参数或局部变量。

**用户常见的编程错误示例:**

虽然用户通常不会直接编写或修改这个头文件，但理解其背后的概念可以帮助理解与 WebAssembly 和内存管理相关的常见错误。

一个相关的常见错误是**栈溢出**。 如果 WebAssembly 函数调用层级过深或者局部变量占用过多栈空间，就可能导致栈指针超出分配的范围，覆盖其他内存区域，从而引发程序崩溃或其他不可预测的行为。  `liftoff-assembler-arm64-inl.h` 中的栈帧管理相关代码的正确性对于防止这类错误至关重要。 如果编译器生成的代码错误地分配或访问栈空间，就可能导致栈溢出。

例如，如果 Liftoff 编译器在生成代码时，错误地计算了所需的栈帧大小，并使用了过小的偏移量访问局部变量，就可能导致访问到栈帧之外的内存。

**总结:**

`v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h` 是 V8 引擎中一个关键的 C++ 头文件，它为 ARM64 架构上的 Liftoff 基线编译器提供了构建汇编指令的内联函数。它抽象了底层的 ARM64 指令，并提供了用于栈帧管理、寄存器操作、内存访问、SIMD 支持和代码生成辅助等功能，是 V8 执行 WebAssembly 代码的重要组成部分。理解这个文件的功能有助于理解 V8 如何将 WebAssembly 代码转换为机器码并执行。

Prompt: 
```
这是目录为v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_ARM64_LIFTOFF_ASSEMBLER_ARM64_INL_H_
#define V8_WASM_BASELINE_ARM64_LIFTOFF_ASSEMBLER_ARM64_INL_H_

#include "src/codegen/arm64/macro-assembler-arm64-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
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
//   1   | return addr (lr)   |
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

inline CPURegister GetRegFromType(const LiftoffRegister& reg, ValueKind kind) {
  switch (kind) {
    case kI32:
      return reg.gp().W();
    case kI64:
    case kRef:
    case kRefNull:
    case kRtt:
      return reg.gp().X();
    case kF32:
      return reg.fp().S();
    case kF64:
      return reg.fp().D();
    case kS128:
      return reg.fp().Q();
    default:
      UNREACHABLE();
  }
}

inline CPURegList PadRegList(RegList list) {
  if ((list.Count() & 1) != 0) list.set(padreg);
  return CPURegList(kXRegSizeInBits, list);
}

inline CPURegList PadVRegList(DoubleRegList list) {
  if ((list.Count() & 1) != 0) list.set(fp_scratch);
  return CPURegList(kQRegSizeInBits, list);
}

inline CPURegister AcquireByType(UseScratchRegisterScope* temps,
                                 ValueKind kind) {
  switch (kind) {
    case kI32:
      return temps->AcquireW();
    case kI64:
    case kRef:
    case kRefNull:
      return temps->AcquireX();
    case kF32:
      return temps->AcquireS();
    case kF64:
      return temps->AcquireD();
    case kS128:
      return temps->AcquireQ();
    default:
      UNREACHABLE();
  }
}

template <typename T>
inline MemOperand GetMemOp(LiftoffAssembler* assm,
                           UseScratchRegisterScope* temps, Register addr,
                           Register offset, T offset_imm,
                           bool i64_offset = false, unsigned shift_amount = 0) {
  if (!offset.is_valid()) return MemOperand(addr.X(), offset_imm);
  Register effective_addr = addr.X();
  if (offset_imm) {
    effective_addr = temps->AcquireX();
    assm->Add(effective_addr, addr.X(), offset_imm);
  }
  return i64_offset
             ? MemOperand(effective_addr, offset.X(), LSL, shift_amount)
             : MemOperand(effective_addr, offset.W(), UXTW, shift_amount);
}

// Compute the effective address (sum of |addr|, |offset| (if given) and
// |offset_imm|) into a temporary register. This is needed for certain load
// instructions that do not support an offset (register or immediate).
// Returns |addr| if both |offset| and |offset_imm| are zero.
inline Register GetEffectiveAddress(LiftoffAssembler* assm,
                                    UseScratchRegisterScope* temps,
                                    Register addr, Register offset,
                                    uintptr_t offset_imm,
                                    bool i64_offset = false) {
  if (!offset.is_valid() && offset_imm == 0) return addr;
  Register tmp = temps->AcquireX();
  if (offset.is_valid()) {
    assm->Add(tmp, addr, i64_offset ? Operand(offset) : Operand(offset, UXTW));
    addr = tmp;
  }
  if (offset_imm != 0) assm->Add(tmp, addr, offset_imm);
  return tmp;
}

enum class ShiftDirection : bool { kLeft, kRight };

enum class ShiftSign : bool { kSigned, kUnsigned };

template <ShiftDirection dir, ShiftSign sign = ShiftSign::kSigned>
inline void EmitSimdShift(LiftoffAssembler* assm, VRegister dst, VRegister lhs,
                          Register rhs, VectorFormat format) {
  DCHECK_IMPLIES(dir == ShiftDirection::kLeft, sign == ShiftSign::kSigned);
  DCHECK(dst.IsSameFormat(lhs));
  DCHECK_EQ(dst.LaneCount(), LaneCountFromFormat(format));

  UseScratchRegisterScope temps(assm);
  VRegister tmp = temps.AcquireV(format);
  Register shift = dst.Is2D() ? temps.AcquireX() : temps.AcquireW();
  int mask = LaneSizeInBitsFromFormat(format) - 1;
  assm->And(shift, rhs, mask);
  assm->Dup(tmp, shift);

  if (dir == ShiftDirection::kRight) {
    assm->Neg(tmp, tmp);
  }

  if (sign == ShiftSign::kSigned) {
    assm->Sshl(dst, lhs, tmp);
  } else {
    assm->Ushl(dst, lhs, tmp);
  }
}

template <VectorFormat format, ShiftSign sign>
inline void EmitSimdShiftRightImmediate(LiftoffAssembler* assm, VRegister dst,
                                        VRegister lhs, int32_t rhs) {
  // Sshr and Ushr does not allow shifts to be 0, so check for that here.
  int mask = LaneSizeInBitsFromFormat(format) - 1;
  int32_t shift = rhs & mask;
  if (!shift) {
    if (dst != lhs) {
      assm->Mov(dst, lhs);
    }
    return;
  }

  if (sign == ShiftSign::kSigned) {
    assm->Sshr(dst, lhs, rhs & mask);
  } else {
    assm->Ushr(dst, lhs, rhs & mask);
  }
}

inline void EmitAnyTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src) {
  // AnyTrue does not depend on the number of lanes, so we can use V4S for all.
  UseScratchRegisterScope scope(assm);
  VRegister temp = scope.AcquireV(kFormat4S);
  assm->Umaxp(temp, src.fp().V4S(), src.fp().V4S());
  assm->Fmov(dst.gp().X(), temp.D());
  assm->Cmp(dst.gp().X(), 0);
  assm->Cset(dst.gp().W(), ne);
}

inline void EmitAllTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src, VectorFormat format) {
  UseScratchRegisterScope scope(assm);
  VRegister temp = scope.AcquireV(ScalarFormatFromFormat(format));
  assm->Uminv(temp, VRegister::Create(src.fp().code(), format));
  assm->Umov(dst.gp().W(), temp, 0);
  assm->Cmp(dst.gp().W(), 0);
  assm->Cset(dst.gp().W(), ne);
}

inline CPURegister LoadToRegister(LiftoffAssembler* assm,
                                  UseScratchRegisterScope* temps,
                                  const LiftoffAssembler::VarState& src) {
  if (src.is_reg()) {
    return GetRegFromType(src.reg(), src.kind());
  }
  if (src.is_const()) {
    if (src.kind() == kI32) {
      if (src.i32_const() == 0) return wzr;
      Register temp = temps->AcquireW();
      assm->Mov(temp, src.i32_const());
      return temp;
    }
    DCHECK_EQ(kI64, src.kind());
    if (src.i32_const() == 0) return xzr;
    Register temp = temps->AcquireX();
    assm->Mov(temp, static_cast<int64_t>(src.i32_const()));
    return temp;
  }
  DCHECK(src.is_stack());
  CPURegister temp = AcquireByType(temps, src.kind());
  assm->Ldr(temp, GetStackSlot(src.offset()));
  return temp;
}

inline void StoreToMemory(LiftoffAssembler* assm, MemOperand dst,
                          const LiftoffAssembler::VarState& src) {
  if (src.kind() == kI16) {
    DCHECK(src.is_reg());
    assm->Strh(src.reg().gp(), dst);
    return;
  }
  UseScratchRegisterScope temps{assm};
  CPURegister src_reg = LoadToRegister(assm, &temps, src);
  assm->Str(src_reg, dst);
}

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  int offset = pc_offset();
  InstructionAccurateScope scope(this, 1);
  // Next we reserve the memory for the whole stack frame. We do not know yet
  // how big the stack frame will be so we just emit a placeholder instruction.
  // PatchPrepareStackFrame will patch this in order to increase the stack
  // appropriately.
  sub(sp, sp, 0);
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

  // On ARM64, we must push at least {lr} before calling the stub, otherwise
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
  temps.Exclude(x16, x17);

  // This is the previous stack pointer value (before we push the lr and the
  // fp). We need to keep it to autenticate the lr and adjust the new stack
  // pointer afterwards.
  Add(x16, fp, 16);

  // Load the fp and lr of the old frame, they will be pushed in the new frame
  // during the actual call.
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Ldp(fp, x17, MemOperand(fp));
  Autib1716();
  Mov(lr, x17);
#else
  Ldp(fp, lr, MemOperand(fp));
#endif

  temps.Include(x17);

  Register scratch = temps.AcquireX();

  // Shift the whole frame upwards, except for fp and lr.
  // Adjust x16 to be the new stack pointer first, so that {str} doesn't need
  // a temp register to materialize the offset.
  Sub(x16, x16, stack_param_delta * 8);
  int slot_count = num_callee_stack_params;
  for (int i = slot_count - 1; i >= 0; --i) {
    ldr(scratch, MemOperand(sp, i * 8));
    str(scratch, MemOperand(x16, i * 8));
  }

  // Set the new stack pointer.
  mov(sp, x16);
}

void LiftoffAssembler::AlignFrameSize() {
  // The frame_size includes the frame marker. The frame marker has already been
  // pushed on the stack though, so we don't need to allocate memory for it
  // anymore.
  int frame_size = GetTotalFrameSize() - 2 * kSystemPointerSize;

  static_assert(kStackSlotSize == kXRegSize,
                "kStackSlotSize must equal kXRegSize");

  // The stack pointer is required to be quadword aligned.
  // Misalignment will cause a stack alignment fault.
  int misalignment = frame_size % kQuadWordSizeInBytes;
  if (misalignment) {
    int padding = kQuadWordSizeInBytes - misalignment;
    frame_size += padding;
    max_used_spill_offset_ += padding;
  }
}

void LiftoffAssembler::PatchPrepareStackFrame(
    int offset, SafepointTableBuilder* safepoint_table_builder,
    bool feedback_vector_slot, size_t stack_param_slots) {
  // The frame_size includes the frame marker and the instance slot. Both are
  // pushed as part of frame construction, so we don't need to allocate memory
  // for them anymore.
  int frame_size = GetTotalFrameSize() - 2 * kSystemPointerSize;
  // The frame setup builtin also pushes the feedback vector, and an unused
  // slot for alignment.
  if (feedback_vector_slot) {
    frame_size = std::max(frame_size - 2 * kSystemPointerSize, 0);
  }

  // The stack pointer is required to be quadword aligned.
  // Misalignment will cause a stack alignment fault.
  DCHECK_EQ(frame_size, RoundUp(frame_size, kQuadWordSizeInBytes));

  PatchingAssembler patching_assembler(zone(), AssemblerOptions{},
                                       buffer_start_ + offset, 1);

  if (V8_LIKELY(frame_size < 4 * KB)) {
    // This is the standard case for small frames: just subtract from SP and be
    // done with it.
    DCHECK(IsImmAddSub(frame_size));
    patching_assembler.PatchSubSp(frame_size);
    return;
  }

  // The frame size is bigger than 4KB, so we might overflow the available stack
  // space if we first allocate the frame and then do the stack check (we will
  // need some remaining stack space for throwing the exception). That's why we
  // check the available stack space before we allocate the frame. To do this we
  // replace the {__ sub(sp, sp, framesize)} with a jump to OOL code that does
  // this "extended stack check".
  //
  // The OOL code can simply be generated here with the normal assembler,
  // because all other code generation, including OOL code, has already finished
  // when {PatchPrepareStackFrame} is called. The function prologue then jumps
  // to the current {pc_offset()} to execute the OOL code for allocating the
  // large frame.

  // Emit the unconditional branch in the function prologue (from {offset} to
  // {pc_offset()}).
  patching_assembler.b((pc_offset() - offset) >> kInstrSizeLog2);

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    UseScratchRegisterScope temps(this);
    Register stack_limit = temps.AcquireX();
    LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
    Add(stack_limit, stack_limit, Operand(frame_size));
    Cmp(sp, stack_limit);
    B(hs /* higher or same */, &continuation);
  }

  if (v8_flags.experimental_wasm_growable_stacks) {
    LiftoffRegList regs_to_save;
    regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
    regs_to_save.set(WasmHandleStackOverflowDescriptor::FrameBaseRegister());
    for (auto reg : kGpParamRegisters) regs_to_save.set(reg);
    PushRegisters(regs_to_save);
    Mov(WasmHandleStackOverflowDescriptor::GapRegister(), frame_size);
    Add(WasmHandleStackOverflowDescriptor::FrameBaseRegister(), fp,
        Operand(stack_param_slots * kStackSlotSize +
                CommonFrameConstants::kFixedFrameSizeAboveFp));
    CallBuiltin(Builtin::kWasmHandleStackOverflow);
    PopRegisters(regs_to_save);
  } else {
    Call(static_cast<Address>(Builtin::kWasmStackOverflow),
         RelocInfo::WASM_STUB_CALL);
    // The call will not return; just define an empty safepoint.
    safepoint_table_builder->DefineSafepoint(this);
    if (v8_flags.debug_code) Brk(0);
  }

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP; consult {MacroAssembler::Claim}.
  Claim(frame_size, 1);

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ sub(sp, sp, framesize)} (which
  // is a branch now).
  int func_start_offset = offset + kInstrSize;
  b((func_start_offset - pc_offset()) >> kInstrSizeLog2);
}

void LiftoffAssembler::FinishCode() { ForceConstantPoolEmissionWithoutJump(); }

void LiftoffAssembler::AbortCompilation() { AbortedCodeGeneration(); }

// static
constexpr int LiftoffAssembler::StaticStackFrameSize() {
  return WasmLiftoffFrameConstants::kFeedbackVectorOffset;
}

int LiftoffAssembler::SlotSizeForType(ValueKind kind) {
  // TODO(zhin): Unaligned access typically take additional cycles, we should do
  // some performance testing to see how big an effect it will take.
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
  UseScratchRegisterScope temps{this};
  Register budget_array = temps.AcquireX();

  Register instance_data = cache_state_.cached_instance_data;
  if (instance_data == no_reg) {
    instance_data = budget_array;  // Reuse the temp register.
    LoadInstanceDataFromFrame(instance_data);
  }

  constexpr int kArrayOffset = wasm::ObjectAccess::ToTagged(
      WasmTrustedInstanceData::kTieringBudgetArrayOffset);
  ldr(budget_array, MemOperand{instance_data, kArrayOffset});

  int budget_arr_offset = kInt32Size * declared_func_index;
  // If the offset cannot be used in the operand directly, add it once to the
  // budget_array to avoid doing that two times below.
  if (!IsImmLSScaled(budget_arr_offset, 2 /* log2(sizeof(i32)) */) &&
      !IsImmLSUnscaled(budget_arr_offset)) {
    Add(budget_array, budget_array, budget_arr_offset);
    budget_arr_offset = 0;
  }

  Register budget = temps.AcquireW();
  MemOperand budget_addr{budget_array, budget_arr_offset};
  ldr(budget, budget_addr);
  // Make sure that the {budget_used} can be used as an immediate for SUB.
  if (budget_used > 0xFFF000) {
    budget_used = 0xFFF000;  // 16'773'120
  } else if (budget_used > 0xFFF) {
    budget_used &= 0xFFF000;
  }
  DCHECK(IsImmAddSub(budget_used));
  AddSub(budget, budget, Operand{budget_used}, SetFlags, SUB);
  str(budget, budget_addr);
  B(ool_label, mi);
}

Register LiftoffAssembler::LoadOldFramePointer() {
  if (!v8_flags.experimental_wasm_growable_stacks) {
    return fp;
  }
  LiftoffRegister old_fp = GetUnusedRegister(RegClass::kGpReg, {});
  Label done, call_runtime;
  Ldr(old_fp.gp(), MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  Cmp(old_fp.gp(),
      Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  B(eq, &call_runtime);
  Mov(old_fp.gp(), fp);
  jmp(&done);

  bind(&call_runtime);
  LiftoffRegList regs_to_save = cache_state()->used_registers;
  PushRegisters(regs_to_save);
  Mov(kCArgRegs[0], ExternalReference::isolate_address());
  CallCFunction(ExternalReference::wasm_load_old_fp(), 1);
  if (old_fp.gp() != kReturnRegister0) {
    Mov(old_fp.gp(), kReturnRegister0);
  }
  PopRegisters(regs_to_save);

  bind(&done);
  return old_fp.gp();
}

void LiftoffAssembler::CheckStackShrink() {
  {
    UseScratchRegisterScope temps{this};
    Register scratch = temps.AcquireX();
    Ldr(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
    Cmp(scratch,
        Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  }
  Label done;
  B(ne, &done);
  LiftoffRegList regs_to_save;
  for (auto reg : kGpReturnRegisters) regs_to_save.set(reg);
  PushRegisters(regs_to_save);
  Mov(kCArgRegs[0], ExternalReference::isolate_address());
  CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
  Mov(fp, kReturnRegister0);
  PopRegisters(regs_to_save);
  if (options().enable_simulator_code) {
    // The next instruction after shrinking stack is leaving the frame.
    // So SP will be set to old FP there. Switch simulator stack limit here.
    UseScratchRegisterScope temps{this};
    temps.Exclude(x16);
    LoadStackLimit(x16, StackLimitKind::kRealStackLimit);
    hlt(kImmExceptionIsSwitchStackLimit);
  }
  bind(&done);
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      Mov(reg.gp().W(), value.to_i32());
      break;
    case kI64:
      Mov(reg.gp().X(), value.to_i64());
      break;
    case kF32:
      Fmov(reg.fp().S(), value.to_f32());
      break;
    case kF64:
      Fmov(reg.fp().D(), value.to_f64());
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadInstanceDataFromFrame(Register dst) {
  Ldr(dst, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  MemOperand src{src_addr, offset};
  LoadTrustedPointerField(dst, src, tag);
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  MemOperand src{instance, offset};
  switch (size) {
    case 1:
      Ldrb(dst.W(), src);
      break;
    case 4:
      Ldr(dst.W(), src);
      break;
    case 8:
      Ldr(dst, src);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int offset) {
  DCHECK_LE(0, offset);
  LoadTaggedField(dst, MemOperand{instance, offset});
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  Str(instance, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::ResetOSRTarget() {}

enum class LoadOrStore : bool { kLoad, kStore };

// The purpose of this class is to reconstruct the PC offset of a protected
// instruction (load or store) that has just been emitted. We cannot simply
// record the current PC offset before emitting the instruction, because the
// respective helper function we call might emit more than one instruction
// (e.g. to load an immediate into a register, or to get a constant pool
// out of the way).
//
// Template arguments:
// kLoadOrStore:
//    DCHECK that the detected protected instruction has the right type.
// kExtraEmittedInstructions:
//    By default, we assume that when the destructor runs, the PC is right
//    behind the protected instruction. If additional instructions are expected
//    to have been emitted (such as a pointer decompression), specify their
//    number here.
template <LoadOrStore kLoadOrStore, uint8_t kExtraEmittedInstructions = 0>
class GetProtectedInstruction {
 public:
  GetProtectedInstruction(LiftoffAssembler* assm,
                          uint32_t* protected_instruction_pc)
      : assm_(assm),
        protected_instruction_pc_(protected_instruction_pc),
        // First emit any required pools...
        blocked_pools_scope_(assm, kReservedInstructions * kInstrSize),
        // ...then record the PC offset before the relevant instruction
        // sequence.
        previous_pc_offset_(assm->pc_offset()) {}

  ~GetProtectedInstruction() {
    if (!protected_instruction_pc_) return;
    *protected_instruction_pc_ =
        assm_->pc_offset() - kInstrSize * (1 + kExtraEmittedInstructions);
    if constexpr (kLoadOrStore == LoadOrStore::kLoad) {
      DCHECK(assm_->InstructionAt(*protected_instruction_pc_)->IsLoad());
    } else {
      DCHECK(assm_->InstructionAt(*protected_instruction_pc_)->IsStore());
    }
    // Make sure {kReservedInstructions} was large enough.
    DCHECK_LE(assm_->pc_offset() - previous_pc_offset_,
              kReservedInstructions * kInstrSize);
    USE(previous_pc_offset_);
  }

 private:
  // For simplicity, we hard-code this value. We could make it a template
  // argument if we needed more flexibility. It must be at least the maximum
  // length of the instruction sequence emitted by the {LoadTaggedField} etc.
  // helper functions below.
  static constexpr int kReservedInstructions = 4;

  LiftoffAssembler* assm_;
  uint32_t* protected_instruction_pc_;
  MacroAssembler::BlockPoolsScope blocked_pools_scope_;
  int previous_pc_offset_;
};

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  UseScratchRegisterScope temps(this);
  unsigned shift_amount = !needs_shift ? 0 : COMPRESS_POINTERS_BOOL ? 2 : 3;
  MemOperand src_op = liftoff::GetMemOp(this, &temps, src_addr, offset_reg,
                                        offset_imm, false, shift_amount);
  DCHECK(!src_op.IsPostIndex());  // See MacroAssembler::LoadStoreMacroComplex.
  constexpr uint8_t kDecompressionInstruction = COMPRESS_POINTERS_BOOL ? 1 : 0;
  GetProtectedInstruction<LoadOrStore::kLoad, kDecompressionInstruction>
      collect_protected_load(this, protected_load_pc);
  LoadTaggedField(dst, src_op);
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset_imm) {
  LoadProtectedPointerField(dst, MemOperand{src_addr, offset_imm});
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  UseScratchRegisterScope temps(this);
  MemOperand src_op =
      liftoff::GetMemOp(this, &temps, src_addr, no_reg, offset_imm);
  Ldr(dst.X(), src_op);
}

#ifdef V8_ENABLE_SANDBOX
void LiftoffAssembler::LoadCodeEntrypointViaCodePointer(Register dst,
                                                        Register src_addr,
                                                        int32_t offset_imm) {
  UseScratchRegisterScope temps(this);
  MemOperand src_op =
      liftoff::GetMemOp(this, &temps, src_addr, no_reg, offset_imm);
  MacroAssembler::LoadCodeEntrypointViaCodePointer(dst, src_op,
                                                   kWasmEntrypointTag);
}
#endif

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList /* pinned */,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  UseScratchRegisterScope temps(this);
  Operand offset_op = offset_reg.is_valid() ? Operand(offset_reg.W(), UXTW)
                                            : Operand(offset_imm);
  // This is similar to {liftoff::GetMemOp}, but leaves {dst_addr} alone, and
  // gives us a combined {offset_op}, which we need for the write barrier
  // below. The 32-bit addition is okay because on-heap offsets don't get
  // bigger than that.
  if (offset_reg.is_valid() && offset_imm) {
    Register effective_offset = temps.AcquireX();
    Add(effective_offset.W(), offset_reg.W(), offset_imm);
    offset_op = effective_offset;
  }
  {
    GetProtectedInstruction<LoadOrStore::kStore> collect_protected_store(
        this, protected_store_pc);
    StoreTaggedField(src, MemOperand(dst_addr.X(), offset_op));
  }

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  // The write barrier.
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
                            bool /* is_load_mem */, bool i64_offset,
                            bool needs_shift) {
  UseScratchRegisterScope temps(this);
  unsigned shift_amount = needs_shift ? type.size_log_2() : 0;
  MemOperand src_op = liftoff::GetMemOp(this, &temps, src_addr, offset_reg,
                                        offset_imm, i64_offset, shift_amount);
  DCHECK(!src_op.IsPostIndex());  // See MacroAssembler::LoadStoreMacroComplex.
  GetProtectedInstruction<LoadOrStore::kLoad> collect_protected_load(
      this, protected_load_pc);
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U:
      Ldrb(dst.gp().W(), src_op);
      break;
    case LoadType::kI32Load8S:
      Ldrsb(dst.gp().W(), src_op);
      break;
    case LoadType::kI64Load8S:
      Ldrsb(dst.gp().X(), src_op);
      break;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      Ldrh(dst.gp().W(), src_op);
      break;
    case LoadType::kI32Load16S:
      Ldrsh(dst.gp().W(), src_op);
      break;
    case LoadType::kI64Load16S:
      Ldrsh(dst.gp().X(), src_op);
      break;
    case LoadType::kI32Load:
    case LoadType::kI64Load32U:
      Ldr(dst.gp().W(), src_op);
      break;
    case LoadType::kI64Load32S:
      Ldrsw(dst.gp().X(), src_op);
      break;
    case LoadType::kI64Load:
      Ldr(dst.gp().X(), src_op);
      break;
    case LoadType::kF32Load:
      Ldr(dst.fp().S(), src_op);
      break;
    case LoadType::kF32LoadF16: {
      CpuFeatureScope scope(this, FP16);
      Ldr(dst.fp().H(), src_op);
      Fcvt(dst.fp().S(), dst.fp().H());
      break;
    }
    case LoadType::kF64Load:
      Ldr(dst.fp().D(), src_op);
      break;
    case LoadType::kS128Load:
      Ldr(dst.fp().Q(), src_op);
      break;
  }
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList /* pinned */,
                             uint32_t* protected_store_pc,
                             bool /* is_store_mem */, bool i64_offset) {
  UseScratchRegisterScope temps(this);
  MemOperand dst_op = liftoff::GetMemOp(this, &temps, dst_addr, offset_reg,
                                        offset_imm, i64_offset);
  DCHECK(!dst_op.IsPostIndex());  // See MacroAssembler::LoadStoreMacroComplex.
  GetProtectedInstruction<LoadOrStore::kStore> collect_protected_store(
      this, protected_store_pc);
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      Strb(src.gp().W(), dst_op);
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      Strh(src.gp().W(), dst_op);
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      Str(src.gp().W(), dst_op);
      break;
    case StoreType::kI64Store:
      Str(src.gp().X(), dst_op);
      break;
    case StoreType::kF32StoreF16: {
      CpuFeatureScope scope(this, FP16);
      Fcvt(src.fp().H(), src.fp().S());
      Str(src.fp().H(), dst_op);
      break;
    }
    case StoreType::kF32Store:
      Str(src.fp().S(), dst_op);
      break;
    case StoreType::kF64Store:
      Str(src.fp().D(), dst_op);
      break;
    case StoreType::kS128Store:
      Str(src.fp().Q(), dst_op);
      break;
  }
}

namespace liftoff {
#define __ lasm->

inline Register CalculateActualAddress(LiftoffAssembler* lasm,
                                       UseScratchRegisterScope& temps,
                                       Register addr_reg, Register offset_reg,
                                       uintptr_t offset_imm) {
  DCHECK_NE(addr_reg, no_reg);
  if (offset_reg == no_reg && offset_imm == 0) return addr_reg;
  Register result = temps.AcquireX();
  if (offset_reg == no_reg) {
    __ Add(result, addr_reg, Operand(offset_imm));
  } else {
    __ Add(result, addr_reg, Operand(offset_reg));
    if (offset_imm != 0) __ Add(result, result, Operand(offset_imm));
  }
  return result;
}

enum class Binop { kAdd, kSub, kAnd, kOr, kXor, kExchange };

inline void AtomicBinop(LiftoffAssembler* lasm, Register dst_addr,
                        Register offset_reg, uintptr_t offset_imm,
                        LiftoffRegister value, LiftoffRegister result,
                        StoreType type, Binop op) {
  LiftoffRegList pinned{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register store_result = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();

  // {LiftoffCompiler::AtomicBinop} ensures that {result} is unique.
  DCHECK(result.gp() != value.gp() && result.gp() != dst_addr &&
         result.gp() != offset_reg);

  UseScratchRegisterScope temps(lasm);
  Register actual_addr = liftoff::CalculateActualAddress(
      lasm, temps, dst_addr, offset_reg, offset_imm);

  if (CpuFeatures::IsSupported(LSE)) {
    CpuFeatureScope scope(lasm, LSE);
    switch (op) {
      case Binop::kAnd:
        switch (type.value()) {
          case StoreType::kI64Store8:
          case StoreType::kI32Store8: {
            UseScratchRegisterScope temps(lasm);
            Register temp = temps.AcquireW();
            __ mvn(temp, value.gp().W());
            __ ldclr
"""


```