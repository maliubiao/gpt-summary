Response:
Let's break down the thought process for analyzing the provided C++ header file and generating the response.

1. **Understand the Request:** The core request is to analyze a V8 source file (`liftoff-assembler-ppc-inl.h`) and describe its functionality. Specific points to address include:
    * General purpose.
    * Checking for Torque (based on file extension).
    * Relationship to JavaScript (with examples).
    * Code logic inference (with input/output).
    * Common programming errors.
    * Summarizing the functionality (for part 1 of 4).

2. **Initial File Scan and Identification:**  The first step is to quickly read through the file to get a high-level understanding. Keywords like `assembler`, `wasm`, `liftoff`, `PPC`, `MemOperand`, `Store`, `Load`, `Call`, and the stack frame layout diagram immediately jump out. This suggests the file deals with code generation for WebAssembly on the PPC architecture, specifically within the Liftoff tier of the V8 engine. The `.inl.h` suffix indicates it's an inline header file, likely containing implementations of functions declared elsewhere.

3. **Deconstruct the File by Sections:** Break down the file into logical parts:
    * **Copyright and Includes:** Standard header information. Note the included headers, which provide further clues (e.g., `assembler.h`, `liftoff-assembler.h`, `wasm-objects.h`).
    * **Namespace:** The `v8::internal::wasm::liftoff` namespace confirms the context.
    * **Stack Frame Layout:**  This is crucial. Carefully analyze the diagram. Identify the different parts of the stack frame: parameters, return address, frame pointer, constant pool, instance data, etc. Understand the relative offsets.
    * **`GetMemOp` Function:**  This function clearly constructs memory operands. Note the handling of offsets (immediate and register-based), potential shifting, and scratch registers.
    * **`GetStackSlot` Function:**  A simple helper for accessing stack slots relative to the frame pointer.
    * **`GetInstanceDataOperand` Function:**  Specifically retrieves the memory operand for the instance data.
    * **`StoreToMemory` Function:** This function is responsible for writing values from various sources (registers, constants, stack) to memory. Note the type handling (kI32, kI64, kF32, etc.).
    * **`LiftoffAssembler` Class Methods:** The bulk of the file. Analyze each method individually:
        * **Frame Setup/Teardown:**  `PrepareStackFrame`, `CallFrameSetupStub`, `PrepareTailCall`, `AlignFrameSize`, `PatchPrepareStackFrame`, `FinishCode`, `AbortCompilation`. These are about managing the function call stack. The `PatchPrepareStackFrame` logic for large frames is complex and deserves attention.
        * **Constant Loading:** `LoadConstant`.
        * **Instance Data Access:** `LoadInstanceDataFromFrame`, `LoadTrustedPointer`, `LoadFromInstance`, `LoadTaggedPointerFromInstance`, `SpillInstanceData`.
        * **Tiering Up:** `CheckTierUp`. This relates to optimizing code execution.
        * **Stack Checks:** `CheckStackShrink`.
        * **Memory Access (Load/Store):**  `LoadTaggedPointer`, `LoadProtectedPointer`, `LoadFullPointer`, `StoreTaggedPointer`, `Load`, `Store`. Pay attention to different load/store types (size, signedness).
        * **Atomic Operations:** `AtomicLoad`, `AtomicStore`, `AtomicAdd`, `AtomicSub`, etc. These are for thread-safe memory access.

4. **Address Specific Points from the Request:**

    * **Functionality:**  Based on the breakdown, the primary function is to provide a low-level code generation interface for the Liftoff compiler targeting PPC. It handles stack management, memory access (loads, stores, atomics), function calls, and interaction with the V8 runtime.

    * **Torque:** Check the file extension. Since it's `.inl.h` and *not* `.tq`, it's not a Torque file.

    * **JavaScript Relationship:** Consider how the generated code relates to JavaScript. Wasm code executes within the V8 engine, which also runs JavaScript. The generated code interacts with the V8 runtime (e.g., for stack overflow checks, write barriers). Think about scenarios where JavaScript calls Wasm functions, and vice versa. Examples involve passing data (parameters, return values) and memory access.

    * **Code Logic Inference:** Select a few representative functions for deeper analysis. `GetMemOp` is a good choice because it involves conditional logic and calculations. Create simple hypothetical input values and trace the execution to determine the output `MemOperand`.

    * **Common Programming Errors:**  Think about typical mistakes when working with low-level code or memory: incorrect offsets, type mismatches, forgetting write barriers, race conditions in atomic operations.

5. **Structure the Response:** Organize the information logically according to the request's points. Use clear headings and bullet points for readability.

6. **Refine and Elaborate:** Review the initial draft and add more detail where needed. For example, explain *why* certain registers are used in specific functions. Provide more concrete examples for the JavaScript relationship.

7. **Summary (Part 1):**  Focus on the core functionality identified in the initial analysis. Emphasize the role of the file in the Liftoff compilation process for WebAssembly on PPC.

**Self-Correction/Refinement Example During the Process:**

* **Initial Thought:**  "The stack frame layout is just a diagram; I don't need to analyze it deeply."
* **Correction:** "Wait, the offsets in the diagram are used by functions like `GetStackSlot` and `GetInstanceDataOperand`. Understanding the layout is crucial for understanding how these functions work and how data is accessed on the stack."

* **Initial Thought:** "I'll just say `GetMemOp` calculates memory addresses."
* **Correction:** "That's too vague. I need to explain *how* it calculates the address, including handling immediate offsets, register offsets, and shifts. The conditional logic based on the size of the immediate offset is important."

By following these steps, including a process of deconstruction, analysis, and refinement, you can generate a comprehensive and accurate response to the given request.
This is the first part of a four-part analysis of the V8 source code file `v8/src/wasm/baseline/ppc/liftoff-assembler-ppc-inl.h`.

**Functionality of `v8/src/wasm/baseline/ppc/liftoff-assembler-ppc-inl.h`:**

This header file defines **inline implementations** for the `LiftoffAssembler` class, specifically targeting the **PowerPC (PPC)** architecture within the V8 JavaScript engine. The `LiftoffAssembler` is a crucial component of the **Liftoff tier**, which is a baseline compiler for WebAssembly. Its primary function is to **generate machine code** for WebAssembly instructions on PPC.

Here's a breakdown of its key functionalities:

1. **Stack Frame Management:**
   - It defines the structure and layout of the stack frame used by WebAssembly functions compiled by Liftoff on PPC. The comments clearly illustrate the organization of parameters, return addresses, frame pointers, instance data, and local variables (slots) on the stack.
   - It provides functions like `PrepareStackFrame`, `CallFrameSetupStub`, `PrepareTailCall`, and `PatchPrepareStackFrame` to manipulate and set up the stack frame for function calls and returns. This includes allocating stack space, saving/restoring registers, and handling potential stack overflows.

2. **Memory Access Operations:**
   - It offers inline functions like `GetMemOp` and `GetStackSlot` to calculate memory addresses and access stack slots. `GetMemOp` handles different ways of specifying memory addresses (base register, offset register, immediate offset).
   - It provides `StoreToMemory` to write data from registers, constants, or stack slots to memory.
   - It includes functions like `Load`, `Store`, `AtomicLoad`, and `AtomicStore` for loading and storing different data types (integers, floats, SIMD vectors) from and to memory. These functions handle endianness (byte order) and can generate appropriate PPC instructions.

3. **Constant Loading:**
   - The `LoadConstant` function facilitates loading immediate values (constants) into registers.

4. **Interaction with the V8 Runtime:**
   - Functions like `CallFrameSetupStub` and calls to builtins (`kWasmLiftoffFrameSetup`, `kWasmStackOverflow`) demonstrate how the generated code interacts with the V8 runtime environment for tasks like setting up function calls and handling errors.
   - `LoadInstanceDataFromFrame` and related functions handle accessing the WebAssembly instance data, which contains information about the module being executed.
   - `CheckTierUp` allows the Liftoff compiler to potentially trigger a transition to a more optimizing compiler (TurboFan) based on execution counts.

5. **Atomic Operations:**
   - The file includes functions for atomic memory operations like `AtomicAdd`, `AtomicSub`, `AtomicAnd`, `AtomicOr`, `AtomicXor`, and `AtomicExchange`. These are essential for supporting WebAssembly's shared memory feature, enabling safe concurrent access to memory.

6. **Tagged Pointer Handling:**
   - Functions like `LoadTaggedPointer` and `StoreTaggedPointer` deal with V8's tagged pointers, which are used to represent JavaScript objects and other heap-allocated data. This is necessary when WebAssembly interacts with JavaScript objects.

**Is it a Torque file?**

The filename ends with `.inl.h`, **not** `.tq`. Therefore, it is **not** a V8 Torque source code file. Torque files use the `.tq` extension.

**Relationship to JavaScript and Examples:**

This file is deeply related to JavaScript because WebAssembly is executed within a JavaScript engine (like V8). The code generated by `LiftoffAssembler` directly executes when a WebAssembly module is run in a JavaScript environment.

**Example:** Imagine a simple WebAssembly function that adds two numbers:

```wasm
(module
  (func $add (param $p0 i32) (param $p1 i32) (result i32)
    local.get $p0
    local.get $p1
    i32.add
  )
  (export "add" (func $add))
)
```

When V8 compiles this WebAssembly module using the Liftoff compiler on PPC, the `LiftoffAssemblerPPC` (using the definitions in this header file) would generate PPC machine code that:

1. **Pulls the parameters `$p0` and `$p1` from the stack.** The `GetStackSlot` function would be used to calculate the memory locations of these parameters relative to the frame pointer. Instructions like `LoadS32` would be generated using the `Load` function.

2. **Performs the `i32.add` operation.** This would involve generating PPC addition instructions (e.g., `addw`) on the registers holding the loaded values.

3. **Pushes the result back onto the stack or into a register for the caller.** The `Store` function might be used to write the result back to the appropriate location.

**JavaScript Example:**

```javascript
const wasmCode = `
  (module
    (func $add (param $p0 i32) (param $p1 i32) (result i32)
      local.get $p0
      local.get $p1
      i32.add
    )
    (export "add" (func $add))
  )
`;

const wasmModule = new WebAssembly.Module(new TextEncoder().encode(wasmCode));
const wasmInstance = new WebAssembly.Instance(wasmModule);

const result = wasmInstance.exports.add(5, 10); // Calling the WebAssembly function
console.log(result); // Output: 15
```

When `wasmInstance.exports.add(5, 10)` is called, the V8 engine will execute the PPC machine code generated by the `LiftoffAssemblerPPC` (using the logic from this header file) for the `$add` function.

**Code Logic Inference (Example: `GetMemOp`)**

**Hypothetical Input:**

- `assm`: A pointer to a `LiftoffAssembler` instance.
- `addr`: Register `r3` (base address).
- `offset`: Register `r4` (offset).
- `offset_imm`: `0` (immediate offset).
- `scratch`: Register `r5` (scratch register).
- `i64_offset`: `false`.
- `shift_amount`: `2`.

**Code Logic:**

```c++
inline MemOperand GetMemOp(LiftoffAssembler* assm, Register addr,
                           Register offset, uintptr_t offset_imm,
                           Register scratch, bool i64_offset = false,
                           unsigned shift_amount = 0) {
  Register kScratchReg2 = scratch; // kScratchReg2 will be r5
  DCHECK_NE(addr, kScratchReg2); // r3 != r5 (true)
  DCHECK_NE(offset, kScratchReg2); // r4 != r5 (true)
  if (offset != no_reg) { // r4 != no_reg (true)
    if (!i64_offset) { // !false (true)
      // extract least significant 32 bits without sign extend
      assm->ExtractBitRange(kScratchReg2, offset, 31, 0, LeaveRC, false);
      // Assuming r4 initially holds 0xFFFFFFFF0000000A, after ExtractBitRange, r5 will hold 0x0000000A.
      offset = kScratchReg2; // offset now becomes r5
    }
    if (shift_amount != 0) { // 2 != 0 (true)
      assm->ShiftLeftU64(kScratchReg2, offset, Operand(shift_amount));
      // Shift left r5 (0x0000000A) by 2 bits. r5 becomes 0x00000028.
    }
    assm->AddS64(kScratchReg2, offset, addr);
    // Add the (potentially shifted) offset (r5 = 0x00000028) to the base address (r3).
    // Assuming r3 initially holds 0x1000, kScratchReg2 (r5) becomes 0x1028.
    addr = kScratchReg2; // addr now becomes r5
  }
  if (is_int31(offset_imm)) { // is_int31(0) (true)
    int32_t offset_imm32 = static_cast<int32_t>(offset_imm); // offset_imm32 = 0
    return MemOperand(addr, offset_imm32); // Returns MemOperand(r5, 0)
  } else {
    // ... (This branch won't be executed in this case)
  }
}
```

**Output:**

The function will return a `MemOperand` representing the memory address calculated as the value in register `r5` with an immediate offset of `0`. If `r3` initially held `0x1000` and `r4` held `0xFFFFFFFF0000000A`, the resulting memory address would correspond to `0x1028`.

**Common Programming Errors (Illustrative Examples):**

1. **Incorrect Stack Offset:**
   - **Error:** Calculating the wrong offset when accessing parameters or local variables on the stack.
   - **Example:**  Accessing a parameter at `GetStackSlot(8)` when it's actually at `GetStackSlot(12)`. This can lead to reading incorrect data or crashing the program.

2. **Type Mismatch in Memory Access:**
   - **Error:** Using the wrong load/store instruction for the data type being accessed.
   - **Example:**  Using `StoreU32` to store a 64-bit value, potentially truncating the data. Or using `LoadS8` to load an unsigned byte, which could lead to incorrect sign extension.

3. **Forgetting Write Barriers:**
   - **Error:** When storing a pointer to an object in the V8 heap, failing to inform the garbage collector about the change.
   - **Example:**  Storing a pointer to a JavaScript object without calling `StoreTaggedPointer`. This can lead to the garbage collector prematurely freeing the object, causing crashes or memory corruption.

4. **Incorrect Use of Atomic Operations:**
   - **Error:** Using atomic operations without understanding their semantics or when they are not necessary.
   - **Example:**  Using `AtomicAdd` when a simple addition would suffice, potentially introducing unnecessary overhead. Or, failing to use atomic operations when concurrent access to shared memory requires it, leading to race conditions and unpredictable behavior.

**Summary of Functionality (Part 1):**

The header file `v8/src/wasm/baseline/ppc/liftoff-assembler-ppc-inl.h` is a core component of V8's Liftoff compiler for WebAssembly on the PowerPC architecture. It provides the building blocks for generating low-level PPC machine code. This includes defining the stack frame layout, providing functions for memory access (loads, stores, atomics), managing function calls, interacting with the V8 runtime, and handling tagged pointers. It enables the efficient execution of WebAssembly code within the V8 JavaScript engine. This part focuses primarily on the foundational aspects of code generation and memory management within the Liftoff assembler for PPC.

### 提示词
```
这是目录为v8/src/wasm/baseline/ppc/liftoff-assembler-ppc-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/ppc/liftoff-assembler-ppc-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_PPC_LIFTOFF_ASSEMBLER_PPC_INL_H_
#define V8_WASM_BASELINE_PPC_LIFTOFF_ASSEMBLER_PPC_INL_H_

#include "src/codegen/assembler.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/parallel-move-inl.h"
#include "src/wasm/object-access.h"
#include "src/wasm/simd-shuffle.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"

namespace v8::internal::wasm {

namespace liftoff {

//  half
//  slot        Frame
//  -----+--------------------+---------------------------
//  n+3  |   parameter n      |
//  ...  |       ...          |
//   4   |   parameter 1      | or parameter 2
//   3   |   parameter 0      | or parameter 1
//   2   |  (result address)  | or parameter 0
//  -----+--------------------+---------------------------
//   2   | return addr (lr)   |
//   1   | previous frame (fp)|
//   0   | const pool (r28)   | if const pool is enabled
//  -----+--------------------+  <-- frame ptr (fp) or cp
//  -1   | StackFrame::WASM   |
//  -2   |    instance        |
//  -3   |    feedback vector |
//  -4   |    tiering budget  |
//  -----+--------------------+---------------------------
//  -5   |    slot 0 (high)   |   ^
//  -6   |    slot 0 (low)    |   |
//  -7   |    slot 1 (high)   | Frame slots
//  -8   |    slot 1 (low)    |   |
//       |                    |   v
//  -----+--------------------+  <-- stack ptr (sp)
//
//


// TODO(tpearson): Much of this logic is already implemented in
// the MacroAssembler GenerateMemoryOperationWithAlignPrefixed()
// macro. Deduplicate this code using that macro where possible.
inline MemOperand GetMemOp(LiftoffAssembler* assm, Register addr,
                           Register offset, uintptr_t offset_imm,
                           Register scratch, bool i64_offset = false,
                           unsigned shift_amount = 0) {
  Register kScratchReg2 = scratch;
  DCHECK_NE(addr, kScratchReg2);
  DCHECK_NE(offset, kScratchReg2);
  if (offset != no_reg) {
    if (!i64_offset) {
      // extract least significant 32 bits without sign extend
      assm->ExtractBitRange(kScratchReg2, offset, 31, 0, LeaveRC, false);
      offset = kScratchReg2;
    }
    if (shift_amount != 0) {
      assm->ShiftLeftU64(kScratchReg2, offset, Operand(shift_amount));
    }
    assm->AddS64(kScratchReg2, offset, addr);
    addr = kScratchReg2;
  }
  if (is_int31(offset_imm)) {
    int32_t offset_imm32 = static_cast<int32_t>(offset_imm);
    return MemOperand(addr, offset_imm32);
  } else {
    // Offset immediate does not fit in 31 bits.
    assm->mov(kScratchReg2, Operand(offset_imm));
    assm->AddS64(kScratchReg2, addr, kScratchReg2);
    return MemOperand(kScratchReg2, 0);
  }
}

inline MemOperand GetStackSlot(uint32_t offset) {
  return MemOperand(fp, -static_cast<int32_t>(offset));
}

inline MemOperand GetInstanceDataOperand() {
  return GetStackSlot(WasmLiftoffFrameConstants::kInstanceDataOffset);
}

inline void StoreToMemory(LiftoffAssembler* assm, MemOperand dst,
                          const LiftoffAssembler::VarState& src,
                          Register scratch1, Register scratch2) {
  if (src.is_reg()) {
    switch (src.kind()) {
      case kI16:
        assm->StoreU16(src.reg().gp(), dst, scratch1);
        break;
      case kI32:
        assm->StoreU32(src.reg().gp(), dst, scratch1);
        break;
      case kI64:
        assm->StoreU64(src.reg().gp(), dst, scratch1);
        break;
      case kF32:
        assm->StoreF32(src.reg().fp(), dst, scratch1);
        break;
      case kF64:
        assm->StoreF64(src.reg().fp(), dst, scratch1);
        break;
      case kS128:
        assm->StoreSimd128(src.reg().fp().toSimd(), dst, scratch1);
        break;
      default:
        UNREACHABLE();
    }
  } else if (src.is_const()) {
    if (src.kind() == kI32) {
      assm->mov(scratch2, Operand(src.i32_const()));
      assm->StoreU32(scratch2, dst, scratch1);
    } else {
      assm->mov(scratch2, Operand(static_cast<int64_t>(src.i32_const())));
      assm->StoreU64(scratch2, dst, scratch1);
    }
  } else if (value_kind_size(src.kind()) == 4) {
    assm->LoadU32(scratch2, liftoff::GetStackSlot(src.offset()), scratch1);
    assm->StoreU32(scratch2, dst, scratch1);
  } else {
    DCHECK_EQ(8, value_kind_size(src.kind()));
    assm->LoadU64(scratch2, liftoff::GetStackSlot(src.offset()), scratch1);
    assm->StoreU64(scratch2, dst, scratch1);
  }
}

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  int offset = pc_offset();
  addi(sp, sp, Operand::Zero());
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

  Register scratch = ip;
  mov(scratch, Operand(StackFrame::TypeToMarker(StackFrame::WASM)));
  PushCommonFrame(scratch);
  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

void LiftoffAssembler::PrepareTailCall(int num_callee_stack_params,
                                       int stack_param_delta) {
  Register scratch = ip;
  // Push the return address and frame pointer to complete the stack frame.
  AddS64(sp, sp, Operand(-2 * kSystemPointerSize), r0);
  LoadU64(scratch, MemOperand(fp, kSystemPointerSize), r0);
  StoreU64(scratch, MemOperand(sp, kSystemPointerSize), r0);
  LoadU64(scratch, MemOperand(fp), r0);
  StoreU64(scratch, MemOperand(sp), r0);

  // Shift the whole frame upwards.
  int slot_count = num_callee_stack_params + 2;
  for (int i = slot_count - 1; i >= 0; --i) {
    LoadU64(scratch, MemOperand(sp, i * kSystemPointerSize), r0);
    StoreU64(scratch,
             MemOperand(fp, (i - stack_param_delta) * kSystemPointerSize), r0);
  }

  // Set the new stack and frame pointer.
  AddS64(sp, fp, Operand(-stack_param_delta * kSystemPointerSize), r0);
  Pop(r0, fp);
  mtlr(r0);
}

void LiftoffAssembler::AlignFrameSize() {}

void LiftoffAssembler::PatchPrepareStackFrame(
    int offset, SafepointTableBuilder* safepoint_table_builder,
    bool feedback_vector_slot, size_t stack_param_slots) {
  int frame_size =
      GetTotalFrameSize() -
      (V8_EMBEDDED_CONSTANT_POOL_BOOL ? 3 : 2) * kSystemPointerSize;
  // The frame setup builtin also pushes the feedback vector.
  if (feedback_vector_slot) {
    frame_size -= kSystemPointerSize;
  }

  Assembler patching_assembler(
      AssemblerOptions{},
      ExternalAssemblerBuffer(buffer_start_ + offset, kInstrSize + kGap));

  if (V8_LIKELY(frame_size < 4 * KB)) {
    patching_assembler.addi(sp, sp, Operand(-frame_size));
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

  int jump_offset = pc_offset() - offset;
  if (!is_int26(jump_offset)) {
    bailout(kUnsupportedArchitecture, "branch offset overflow");
    return;
  }
  patching_assembler.b(jump_offset, LeaveLK);

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    Register stack_limit = ip;
    LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit, r0);
    AddS64(stack_limit, stack_limit, Operand(frame_size), r0);
    CmpU64(sp, stack_limit);
    bge(&continuation);
  }

  Call(static_cast<Address>(Builtin::kWasmStackOverflow),
       RelocInfo::WASM_STUB_CALL);
  // The call will not return; just define an empty safepoint.
  safepoint_table_builder->DefineSafepoint(this);
  if (v8_flags.debug_code) stop();

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP; consult {MacroAssembler::AllocateStackSpace}.
  SubS64(sp, sp, Operand(frame_size), r0);

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ sub(sp, sp, framesize)} (which
  // is a branch now).
  jump_offset = offset - pc_offset() + kInstrSize;
  if (!is_int26(jump_offset)) {
    bailout(kUnsupportedArchitecture, "branch offset overflow");
    return;
  }
  b(jump_offset, LeaveLK);
}

void LiftoffAssembler::FinishCode() { EmitConstantPool(); }

void LiftoffAssembler::AbortCompilation() { FinishCode(); }

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
  return (kind == kS128 || is_reference(kind));
}

void LiftoffAssembler::CheckTierUp(int declared_func_index, int budget_used,
                                   Label* ool_label,
                                   const FreezeCacheState& frozen) {
  Register budget_array = ip;
  Register instance_data = cache_state_.cached_instance_data;

  if (instance_data == no_reg) {
    instance_data = budget_array;  // Reuse the temp register.
    LoadInstanceDataFromFrame(instance_data);
  }

  constexpr int kArrayOffset = wasm::ObjectAccess::ToTagged(
      WasmTrustedInstanceData::kTieringBudgetArrayOffset);
  LoadU64(budget_array, MemOperand(instance_data, kArrayOffset), r0);

  int budget_arr_offset = kInt32Size * declared_func_index;
  // Pick a random register from kLiftoffAssemblerGpCacheRegs.
  // TODO(miladfarca): Use ScratchRegisterScope when available.
  Register budget = r15;
  push(budget);
  MemOperand budget_addr(budget_array, budget_arr_offset);
  LoadS32(budget, budget_addr, r0);
  mov(r0, Operand(budget_used));
  sub(budget, budget, r0, LeaveOE, SetRC);
  StoreU32(budget, budget_addr, r0);
  pop(budget);
  blt(ool_label, cr0);
}

Register LiftoffAssembler::LoadOldFramePointer() { return fp; }

void LiftoffAssembler::CheckStackShrink() {
  // TODO(irezvov): 42202153
  UNIMPLEMENTED();
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      mov(reg.gp(), Operand(value.to_i32()));
      break;
    case kI64:
      mov(reg.gp(), Operand(value.to_i64()));
      break;
    case kF32: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      mov(scratch, Operand(value.to_f32_boxed().get_bits()));
      MovIntToFloat(reg.fp(), scratch, ip);
      break;
    }
    case kF64: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      mov(scratch, Operand(value.to_f64_boxed().get_bits()));
      MovInt64ToDouble(reg.fp(), scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadInstanceDataFromFrame(Register dst) {
  LoadU64(dst, liftoff::GetInstanceDataOperand(), r0);
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  MemOperand src{src_addr, offset};
  LoadTrustedPointerField(dst, src, tag, r0);
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  switch (size) {
    case 1:
      LoadU8(dst, MemOperand(instance, offset), r0);
      break;
    case 4:
      LoadU32(dst, MemOperand(instance, offset), r0);
      break;
    case 8:
      LoadU64(dst, MemOperand(instance, offset), r0);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int offset) {
  LoadTaggedField(dst, MemOperand(instance, offset), r0);
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  StoreU64(instance, liftoff::GetInstanceDataOperand(), r0);
}

void LiftoffAssembler::ResetOSRTarget() {}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  unsigned shift_amount = !needs_shift ? 0 : COMPRESS_POINTERS_BOOL ? 2 : 3;
  if (offset_reg != no_reg && shift_amount != 0) {
    ShiftLeftU64(ip, offset_reg, Operand(shift_amount));
    offset_reg = ip;
  }
  if (protected_load_pc) *protected_load_pc = pc_offset();
  LoadTaggedField(dst, MemOperand(src_addr, offset_reg, offset_imm), r0);
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  LoadTaggedPointer(dst, src_addr, no_reg, offset);
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  LoadU64(dst, MemOperand(src_addr, offset_imm), r0);
}

#ifdef V8_ENABLE_SANDBOX
void LiftoffAssembler::LoadCodeEntrypointViaCodePointer(Register dst,
                                                        Register src_addr,
                                                        int32_t offset_imm) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  MemOperand src_op =
      liftoff::GetMemOp(this, src_addr, no_reg, offset_imm, scratch);
  MacroAssembler::LoadCodeEntrypointViaCodePointer(dst, src_op, scratch);
}
#endif

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList /* pinned */,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  MemOperand dst_op = MemOperand(dst_addr, offset_reg, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();
  StoreTaggedField(src, dst_op, r0);

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  Label exit;
  // NOTE: to_condition(kZero) is the equality condition (eq)
  // This line verifies the masked address is equal to dst_addr,
  // not that it is zero!
  CheckPageFlag(dst_addr, ip, MemoryChunk::kPointersFromHereAreInterestingMask,
                to_condition(kZero), &exit);
  JumpIfSmi(src, &exit);
  CheckPageFlag(src, ip, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                &exit);
  mov(ip, Operand(offset_imm));
  add(ip, ip, dst_addr);
  if (offset_reg != no_reg) {
    add(ip, ip, offset_reg);
  }
  CallRecordWriteStubSaveRegisters(dst_addr, ip, SaveFPRegsMode::kSave,
                                   StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uintptr_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool is_load_mem, bool i64_offset,
                            bool needs_shift) {
  if (!i64_offset && offset_reg != no_reg) {
    ZeroExtWord32(ip, offset_reg);
    offset_reg = ip;
  }
  unsigned shift_amount = needs_shift ? type.size_log_2() : 0;
  if (offset_reg != no_reg && shift_amount != 0) {
    ShiftLeftU64(ip, offset_reg, Operand(shift_amount));
    offset_reg = ip;
  }
  MemOperand src_op = MemOperand(src_addr, offset_reg, offset_imm);
  if (protected_load_pc) *protected_load_pc = pc_offset();
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U:
      LoadU8(dst.gp(), src_op, r0);
      break;
    case LoadType::kI32Load8S:
    case LoadType::kI64Load8S:
      LoadS8(dst.gp(), src_op, r0);
      break;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      if (is_load_mem) {
        LoadU16LE(dst.gp(), src_op, r0);
      } else {
        LoadU16(dst.gp(), src_op, r0);
      }
      break;
    case LoadType::kI32Load16S:
    case LoadType::kI64Load16S:
      if (is_load_mem) {
        LoadS16LE(dst.gp(), src_op, r0);
      } else {
        LoadS16(dst.gp(), src_op, r0);
      }
      break;
    case LoadType::kI64Load32U:
      if (is_load_mem) {
        LoadU32LE(dst.gp(), src_op, r0);
      } else {
        LoadU32(dst.gp(), src_op, r0);
      }
      break;
    case LoadType::kI32Load:
    case LoadType::kI64Load32S:
      if (is_load_mem) {
        LoadS32LE(dst.gp(), src_op, r0);
      } else {
        LoadS32(dst.gp(), src_op, r0);
      }
      break;
    case LoadType::kI64Load:
      if (is_load_mem) {
        LoadU64LE(dst.gp(), src_op, r0);
      } else {
        LoadU64(dst.gp(), src_op, r0);
      }
      break;
    case LoadType::kF32Load:
      if (is_load_mem) {
        // `ip` could be used as offset_reg.
        Register scratch = ip;
        if (offset_reg == ip) {
          scratch = GetRegisterThatIsNotOneOf(src_addr);
          push(scratch);
        }
        LoadF32LE(dst.fp(), src_op, r0, scratch);
        if (offset_reg == ip) {
          pop(scratch);
        }
      } else {
        LoadF32(dst.fp(), src_op, r0);
      }
      break;
    case LoadType::kF64Load:
      if (is_load_mem) {
        // `ip` could be used as offset_reg.
        Register scratch = ip;
        if (offset_reg == ip) {
          scratch = GetRegisterThatIsNotOneOf(src_addr);
          push(scratch);
        }
        LoadF64LE(dst.fp(), src_op, r0, scratch);
        if (offset_reg == ip) {
          pop(scratch);
        }
      } else {
        LoadF64(dst.fp(), src_op, r0);
      }
      break;
    case LoadType::kS128Load:
      if (is_load_mem) {
        LoadSimd128LE(dst.fp().toSimd(), src_op, r0);
      } else {
        LoadSimd128(dst.fp().toSimd(), src_op, r0);
      }
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList pinned,
                             uint32_t* protected_store_pc, bool is_store_mem,
                             bool i64_offset) {
  if (!i64_offset && offset_reg != no_reg) {
    ZeroExtWord32(ip, offset_reg);
    offset_reg = ip;
  }
  MemOperand dst_op = MemOperand(dst_addr, offset_reg, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      StoreU8(src.gp(), dst_op, r0);
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      if (is_store_mem) {
        StoreU16LE(src.gp(), dst_op, r0);
      } else {
        StoreU16(src.gp(), dst_op, r0);
      }
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      if (is_store_mem) {
        StoreU32LE(src.gp(), dst_op, r0);
      } else {
        StoreU32(src.gp(), dst_op, r0);
      }
      break;
    case StoreType::kI64Store:
      if (is_store_mem) {
        StoreU64LE(src.gp(), dst_op, r0);
      } else {
        StoreU64(src.gp(), dst_op, r0);
      }
      break;
    case StoreType::kF32Store:
      if (is_store_mem) {
        Register scratch2 = GetUnusedRegister(kGpReg, pinned).gp();
        StoreF32LE(src.fp(), dst_op, r0, scratch2);
      } else {
        StoreF32(src.fp(), dst_op, r0);
      }
      break;
    case StoreType::kF64Store:
      if (is_store_mem) {
        Register scratch2 = GetUnusedRegister(kGpReg, pinned).gp();
        StoreF64LE(src.fp(), dst_op, r0, scratch2);
      } else {
        StoreF64(src.fp(), dst_op, r0);
      }
      break;
    case StoreType::kS128Store: {
      if (is_store_mem) {
        StoreSimd128LE(src.fp().toSimd(), dst_op, r0, kScratchSimd128Reg);
      } else {
        StoreSimd128(src.fp().toSimd(), dst_op, r0);
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uintptr_t offset_imm,
                                  LoadType type, LiftoffRegList /* pinned */,
                                  bool i64_offset) {
  Load(dst, src_addr, offset_reg, offset_imm, type, nullptr, true, i64_offset);
  lwsync();
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uintptr_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList pinned,
                                   bool i64_offset) {
  lwsync();
  Store(dst_addr, offset_reg, offset_imm, src, type, pinned, nullptr, true,
        i64_offset);
  sync();
}

#ifdef V8_TARGET_BIG_ENDIAN
constexpr bool is_be = true;
#else
constexpr bool is_be = false;
#endif

#define ATOMIC_OP(instr)                                                 \
  {                                                                      \
    if (!i64_offset && offset_reg != no_reg) {                           \
      ZeroExtWord32(ip, offset_reg);                                     \
      offset_reg = ip;                                                   \
    }                                                                    \
                                                                         \
    Register offset = r0;                                                \
    if (offset_imm != 0) {                                               \
      mov(offset, Operand(offset_imm));                                  \
      if (offset_reg != no_reg) add(offset, offset, offset_reg);         \
      mr(ip, offset);                                                    \
      offset = ip;                                                       \
    } else if (offset_reg != no_reg) {                                   \
      offset = offset_reg;                                               \
    }                                                                    \
                                                                         \
    MemOperand dst = MemOperand(offset, dst_addr);                       \
                                                                         \
    switch (type.value()) {                                              \
      case StoreType::kI32Store8:                                        \
      case StoreType::kI64Store8: {                                      \
        auto op_func = [&](Register dst, Register lhs, Register rhs) {   \
          instr(dst, lhs, rhs);                                          \
        };                                                               \
        AtomicOps<uint8_t>(dst, value.gp(), result.gp(), r0, op_func);   \
        break;                                                           \
      }                                                                  \
      case StoreType::kI32Store16:                                       \
      case StoreType::kI64Store16: {                                     \
        auto op_func = [&](Register dst, Register lhs, Register rhs) {   \
          if (is_be) {                                                   \
            Register scratch = GetRegisterThatIsNotOneOf(lhs, rhs, dst); \
            push(scratch);                                               \
            ByteReverseU16(dst, lhs, scratch);                           \
            instr(dst, dst, rhs);                                        \
            ByteReverseU16(dst, dst, scratch);                           \
            pop(scratch);                                                \
          } else {                                                       \
            instr(dst, lhs, rhs);                                        \
          }                                                              \
        };                                                               \
        AtomicOps<uint16_t>(dst, value.gp(), result.gp(), r0, op_func);  \
        if (is_be) {                                                     \
          ByteReverseU16(result.gp(), result.gp(), ip);                  \
        }                                                                \
        break;                                                           \
      }                                                                  \
      case StoreType::kI32Store:                                         \
      case StoreType::kI64Store32: {                                     \
        auto op_func = [&](Register dst, Register lhs, Register rhs) {   \
          if (is_be) {                                                   \
            Register scratch = GetRegisterThatIsNotOneOf(lhs, rhs, dst); \
            push(scratch);                                               \
            ByteReverseU32(dst, lhs, scratch);                           \
            instr(dst, dst, rhs);                                        \
            ByteReverseU32(dst, dst, scratch);                           \
            pop(scratch);                                                \
          } else {                                                       \
            instr(dst, lhs, rhs);                                        \
          }                                                              \
        };                                                               \
        AtomicOps<uint32_t>(dst, value.gp(), result.gp(), r0, op_func);  \
        if (is_be) {                                                     \
          ByteReverseU32(result.gp(), result.gp(), ip);                  \
        }                                                                \
        break;                                                           \
      }                                                                  \
      case StoreType::kI64Store: {                                       \
        auto op_func = [&](Register dst, Register lhs, Register rhs) {   \
          if (is_be) {                                                   \
            ByteReverseU64(dst, lhs);                                    \
            instr(dst, dst, rhs);                                        \
            ByteReverseU64(dst, dst);                                    \
          } else {                                                       \
            instr(dst, lhs, rhs);                                        \
          }                                                              \
        };                                                               \
        AtomicOps<uint64_t>(dst, value.gp(), result.gp(), r0, op_func);  \
        if (is_be) {                                                     \
          ByteReverseU64(result.gp(), result.gp());                      \
        }                                                                \
        break;                                                           \
      }                                                                  \
      default:                                                           \
        UNREACHABLE();                                                   \
    }                                                                    \
  }

void LiftoffAssembler::AtomicAdd(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  ATOMIC_OP(add);
}

void LiftoffAssembler::AtomicSub(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  ATOMIC_OP(sub);
}

void LiftoffAssembler::AtomicAnd(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  ATOMIC_OP(and_);
}

void LiftoffAssembler::AtomicOr(Register dst_addr, Register offset_reg,
                                uintptr_t offset_imm, LiftoffRegister value,
                                LiftoffRegister result, StoreType type,
                                bool i64_offset) {
  ATOMIC_OP(orx);
}

void LiftoffAssembler::AtomicXor(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  ATOMIC_OP(xor_);
}

void LiftoffAssembler::AtomicExchange(Register dst_addr, Register offset_reg,
                                      uintptr_t offset_imm,
                                      LiftoffRegister value,
                                      LiftoffRegister result, StoreType type,
                                      bool i64_offset) {
  if (!i64_offset && offset_reg != no_reg) {
    ZeroExtWord32(ip, offset_reg);
    offset_reg = ip;
  }

  Register offset = r0;
  if (offset_imm != 0) {
    mov(offset, Operand(offset_imm));
    if (offset_reg != no_reg) add(offset, offset, offset_reg);
    mr(ip, offset);
    offset = ip;
  } else if (offset_reg != no_reg) {
    offset = offset_reg;
  }
  MemOperand dst = MemOperand(offset, dst_addr);
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      MacroAssembler::AtomicExchange<uint8_t>(dst, value.gp(), result.gp());
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      if (is_be) {
        Register scratch = GetRegisterThatIsNotOneOf(value.gp(), result.gp());
        push(scratch);
        ByteReverseU16(r0, value.gp(), scratch);
        pop(scratch);
        MacroAssembler::AtomicExchange<uint16_t>(dst, r0, result.gp());
        ByteReverseU16(result.gp(), result.gp(), ip);
      } else {
        MacroAssembler::AtomicExchange<uint16_t>(dst, value.gp(), result.gp());
      }
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      if (is_be) {
        Register scratch = GetRegisterThatIsNotOneOf(value.gp(), result.gp());
        push(scratch);
        ByteReverseU32(r0, value.gp(), scratch);
        pop(scratch);
        MacroAssembler::AtomicExchange<uint32_t>(dst, r0, result.gp());
        ByteReverseU32(result.gp(), result.gp(), ip);
      } else {
        MacroAssembler::AtomicExchange<uint32_t>(dst, value.gp(), result.gp());
      }
      break;
    }
    case StoreType::kI64Store: {
      if (is_be) {
        ByteReverseU64(r0, value.gp());
        MacroAssembler::AtomicExchange<uint64_t>(dst, r0, result.gp());
        ByteReverseU64(result.gp(), result.gp());
      } else {
        MacroAssembler::AtomicExchange<uint64_t>(dst, value.gp(), result.gp());
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void L
```