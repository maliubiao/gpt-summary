Response:
Let's break down the thought process for analyzing the provided C++ header file.

**1. Initial Understanding: What is this?**

The first lines are crucial:

```c++
// Copyright 2012 the V8 project authors. All rights reserved.
// ...
#include "src/codegen/assembler.h"
#include "src/codegen/mips64/assembler-mips64.h"
```

This immediately tells us:

* **V8 Project:**  It's part of the V8 JavaScript engine.
* **Code Generation:** The `codegen` directory suggests it's involved in turning JavaScript into machine code.
* **MIPS64 Architecture:** The `mips64` directory specifies the target architecture.
* **`macro-assembler`:** This hints at a higher-level abstraction over the raw assembler instructions, providing convenience functions.
* **Header File (`.h`):** This means it declares interfaces (classes, functions, enums) that will be implemented elsewhere.

**2. Identifying the Core Class:**

The most important element is the `MacroAssembler` class declaration. This will be the focus of the functional analysis.

**3. Analyzing Key Sections and Features:**

Now, we go through the code section by section, looking for patterns and purpose. It's like reading a technical document, paying attention to keywords and comments.

* **Reserved Registers:** The comment about `t8`, `t9`, and `at` being reserved is important for understanding how the `MacroAssembler` uses registers internally.
* **Enums (`BranchDelaySlot`, `LiFlags`, `RAStatus`):** These define options and states relevant to the assembly process, like how to handle branch delay slots and different ways to load constants.
* **Helper Functions (`GetRegisterThatIsNotOneOf`, `FieldMemOperand`, `CFunctionArgumentOperand`):** These are utility functions to make common operations easier, like getting an unused register or creating memory operands.
* **Activation Support (`EnterFrame`, `LeaveFrame`, `AllocateStackSpace`):**  These functions deal with setting up and tearing down function call frames on the stack. This is fundamental for function execution.
* **Prologue/Epilogue (`StubPrologue`, `Prologue`):** Standard function setup code.
* **Debugging (`Trap`, `DebugBreak`, `Assert`, `Check`, `Abort`):**  Tools for debugging generated code.
* **Branching (`Branch`, `BranchAndLink`, `BranchShort`, etc.):** A core function of any assembler – controlling the flow of execution. Note the different conditional and unconditional branches.
* **Floating-Point Operations (`CompareF32`, `CompareF64`, `BranchTrueF`, etc.):** Handling floating-point numbers, which are crucial for JavaScript.
* **Constant Loading (`LiLower32BitHelper`, `li`, `LoadFromConstantsTable`, `LoadRootRelative`):** Efficient ways to load constant values into registers.
* **Function Calls (`Jump`, `Call`, `Ret`, `TailCallBuiltin`, `CallJSFunction`):** Mechanisms for calling other functions (C++, JavaScript, built-ins).
* **Stack Manipulation (`push`, `Push`, `pop`, `Pop`, `Drop`, `DropArguments`):**  Essential for managing function arguments, local variables, and return addresses.
* **Register Operations (`Addu`, `Daddu`, `Subu`, `Dsubu`, `And`, `Or`, `Xor`, etc.):** Basic arithmetic and logical operations on registers.
* **Smi Handling (`SmiTag`, `SmiUntag`, `SmiToInt32`, `AssertSmi`):** Dealing with Small Integers, a common optimization in V8.
* **C Function Interface (`PrepareCallCFunction`, `CallCFunction`, `MovToFloatParameter`, etc.):**  How V8's generated code interacts with C++ code.
* **Floating-Point Conversion (`TruncateDoubleToI`):** Converting floating-point numbers to integers.
* **Conditional Moves (`Movz`, `Movn`, `Movt`, `Movf`):**  Efficient conditional assignment.
* **Bit Manipulation (`Clz`, `Dclz`, `Ctz`, `Dctz`, `Popcnt`, `Dpopcnt`, `Ext`, `Dext`, `Ins`, `Dins`, `ExtractBits`, `InsertBits`):** Lower-level bit manipulation operations.
* **Endianness Handling (`ByteSwapSigned`, `ByteSwapUnsigned`):**  Important for cross-platform compatibility.
* **Load/Store Instructions (`Ld`, `Sd`, `Lb`, `Sb`, `Lw`, `Sw`, `Ldc1`, `Sdc1`, etc.):** Moving data between registers and memory.
* **Floating-Point Min/Max (`Float32Max`, `Float32Min`, `Float64Max`, `Float64Min`):**  Implementing the `Math.max` and `Math.min` functions.
* **Moves (`mov`, `Move`):**  Copying values between registers.
* **Overflow Detection (`DaddOverflow`, `DsubOverflow`, `MulOverflow`, `DMulOverflow`):** Checking for arithmetic overflow.
* **Switch Tables (`GenerateSwitchTable`):**  Efficiently handling switch statements.
* **Root Table Access (`LoadRoot`):** Accessing global objects and constants.
* **Map and Feedback Vector Loading (`LoadMap`, `LoadFeedbackVector`):** Operations specific to V8's object model and optimization.

**4. Synthesizing the Functionality:**

After analyzing the sections, we can start to summarize the overall functionality. The key is to identify the main purpose and the supporting features. The `MacroAssembler` is clearly about *generating machine code for the MIPS64 architecture*. The other features are all in service of this goal.

**5. Addressing the Specific Questions:**

Finally, we address the specific questions in the prompt:

* **Listing Functionality:** This involves summarizing the points identified in step 3 and 4.
* **`.tq` Extension:**  Checking the file extension is straightforward.
* **Relationship to JavaScript:** This requires understanding how the assembly code relates to JavaScript concepts (function calls, object access, data types, etc.). The examples in the header (like `CallJSFunction` and Smi operations) are clues. Thinking about the JavaScript code that would *require* these low-level operations is key.
* **Code Logic Reasoning:** This involves selecting a simple function (like `Push`) and explaining its operation based on the assembly instructions it uses. Defining example input and output clarifies the process.
* **Common Programming Errors:** Thinking about what can go wrong when working with assembly or lower-level code (stack corruption, register misuse) is important.
* **Overall Function Summary:** This is a concise recap of the core purpose of the header file.

**Self-Correction/Refinement:**

During the process, I might realize I've missed a significant category of functions or misinterpreted something. For example, I might initially focus too much on arithmetic operations and forget the crucial role of stack manipulation. Reviewing the section headers and comments can help correct such oversights. Also, considering the context of V8 – a JavaScript engine – helps prioritize features related to object manipulation, function calls, and dynamic typing.
Let's break down the functionality of the `v8/src/codegen/mips64/macro-assembler-mips64.h` header file.

**Core Functionality:**

This header file defines the `MacroAssembler` class for the MIPS64 architecture within the V8 JavaScript engine. The `MacroAssembler` acts as a high-level interface for generating MIPS64 assembly instructions. It provides a set of convenient methods that abstract away the complexities of raw assembly, allowing developers to generate machine code in a more readable and maintainable way.

**Key Functionality Areas:**

* **Code Generation Abstraction:** It provides methods like `li` (load immediate), `Ld` (load doubleword), `Sd` (store doubleword), `Branch`, `Call`, `Ret`, etc., which correspond to common MIPS64 assembly instructions. These methods often handle details like instruction encoding and operand formatting.

* **Stack Management:**  It offers functions to manage the call stack, including:
    * `EnterFrame`/`LeaveFrame`: Setting up and tearing down stack frames for function calls.
    * `AllocateStackSpace`:  Reserving space on the stack.
    * `Push`/`Pop`: Pushing and popping values from the stack.
    * `Drop`: Discarding values from the stack.

* **Function Calls and Jumps:** It provides methods for:
    * Unconditional and conditional jumps (`jmp`, `Branch`).
    * Direct and indirect calls to functions (`Call`).
    * Returning from functions (`Ret`).
    * Calling C functions from generated code (`CallCFunction`).
    * Calling built-in V8 functions (`CallBuiltin`, `TailCallBuiltin`).
    * Calling JavaScript functions (`CallJSFunction`, `JumpJSFunction`).

* **Register Handling:** It implicitly manages certain reserved registers (`t8`, `t9`, `at`) and provides utilities like `GetRegisterThatIsNotOneOf` to find available registers.

* **Constant Loading:**  It offers various ways to load constant values into registers, optimizing for size or patchability (`li` with different `LiFlags`). It also includes functions to load constants from the V8 root table or constants table.

* **Debugging and Assertions:** It includes methods for debugging generated code:
    * `Trap`, `DebugBreak`: Inserting breakpoints.
    * `Assert`, `Check`:  Conditionally aborting execution if a condition is false.
    * `Abort`:  Terminating execution with a message.

* **Floating-Point Operations:** It provides methods for performing floating-point comparisons (`CompareF32`, `CompareF64`), branches based on floating-point conditions (`BranchTrueF`, `BranchFalseF`), and basic floating-point arithmetic (though the provided snippet doesn't show many arithmetic operations directly).

* **Smi (Small Integer) Handling:** It includes functions to tag and untag Smi values (`SmiTag`, `SmiUntag`), which are a common optimization in V8.

* **Object and Memory Access:** It provides utilities for accessing object fields (`FieldMemOperand`) and external references (`ExternalReferenceAsOperand`).

* **Interfacing with C++:** It includes functions to prepare for and call C++ functions, handling argument passing conventions.

* **Conditional Execution (Emulated):** On MIPS, conditional execution is often achieved through conditional branches. The `MacroAssembler` provides methods like `Branch(Label* L, Condition cond, ...)` to implement this.

* **Atomic Operations:**  It includes methods for load-linked and store-conditional operations (`Ll`, `Sc`, `Lld`, `Scd`) which are crucial for implementing synchronization primitives.

**Regarding the `.tq` extension:**

The comment within the code snippet states:

```c++
#ifndef INCLUDED_FROM_MACRO_ASSEMBLER_H
#error This header must be included via macro-assembler.h
#endif
```

This tells us that `macro-assembler-mips64.h` is intended to be included by another header file, likely `macro-assembler.h`. The snippet itself doesn't provide enough information to determine if a file named `v8/src/codegen/mips64/macro-assembler-mips64.tq` exists.

**If `v8/src/codegen/mips64/macro-assembler-mips64.h` ended with `.tq`, it would indeed indicate a V8 Torque source file.** Torque is V8's domain-specific language for generating efficient built-in functions. Torque files are then compiled into C++ code.

**Relationship to JavaScript and Examples:**

The `MacroAssembler` plays a crucial role in how V8 executes JavaScript code. When V8 compiles JavaScript code (either at runtime for interpreted code or ahead-of-time for optimized code), it uses the `MacroAssembler` to generate the actual machine instructions that the CPU will execute.

Here are some examples of how the functionality in this header relates to JavaScript features:

* **Function Calls:** When you call a JavaScript function, the `CallJSFunction` method (or similar) in the `MacroAssembler` will be used to generate the assembly instructions to set up the new stack frame, pass arguments, and jump to the function's code.

  ```javascript
  function myFunction(a, b) {
    return a + b;
  }

  myFunction(5, 10); // This function call would involve code generated by MacroAssembler
  ```

* **Object Property Access:** When you access a property of a JavaScript object, the `MacroAssembler` might generate code using `Ld` with a `FieldMemOperand` to load the value of that property from memory.

  ```javascript
  const myObject = { x: 42 };
  const value = myObject.x; // Accessing the 'x' property
  ```

* **Arithmetic Operations:** When you perform arithmetic operations in JavaScript, the `MacroAssembler` will generate corresponding MIPS64 instructions like `Addu` (add unsigned) or `Daddu` (doubleword add unsigned).

  ```javascript
  const sum = 5 + 3; // The '+' operation will translate to assembly instructions
  ```

* **Conditional Statements:** `if` statements in JavaScript translate to conditional branches in assembly using methods like `Branch` with appropriate condition codes.

  ```javascript
  const x = 10;
  if (x > 5) {
    console.log("x is greater than 5");
  }
  ```

**Code Logic Reasoning Example:**

Let's consider the `Push(Register src)` function:

```c++
void push(Register src) {
  Daddu(sp, sp, Operand(-kPointerSize));
  Sd(src, MemOperand(sp, 0));
}
void Push(Register src) { push(src); }
```

**Assumption:** `kPointerSize` is 8 (for MIPS64), `sp` is the stack pointer register.

**Input:**  `src` is a register holding a 64-bit value (e.g., `a0` holding the value 0x1234567890ABCDEF). Assume the stack pointer `sp` currently holds the address 0x7FFFFFF000.

**Logic:**

1. `Daddu(sp, sp, Operand(-kPointerSize));`: This instruction subtracts `kPointerSize` (8) from the stack pointer `sp`.
   * **Input `sp`:** 0x7FFFFFF000
   * **`Operand(-kPointerSize)`:** -8
   * **Output `sp`:** 0x7FFFFFF000 - 8 = 0x7FFFFFF000 - 0x8 = 0x7FFFFFEFF8

2. `Sd(src, MemOperand(sp, 0));`: This instruction stores the contents of the `src` register to the memory location pointed to by `sp` plus an offset of 0.
   * **Input `src`:** 0x1234567890ABCDEF
   * **Input `sp`:** 0x7FFFFFEFF8
   * **Memory Location:** 0x7FFFFFEFF8 + 0 = 0x7FFFFFEFF8
   * **Output:** The value 0x1234567890ABCDEF is written to memory address 0x7FFFFFEFF8.

**Output:**

* The stack pointer `sp` is now 0x7FFFFFEFF8.
* The memory location at address 0x7FFFFFEFF8 contains the value 0x1234567890ABCDEF.

**Common User Programming Errors (If someone were manually writing assembly or extending this):**

* **Stack Overflow/Underflow:** Incorrectly managing the stack pointer by pushing too much without popping, or popping from an empty stack. For example, calling `Push` repeatedly without corresponding `Pop` operations.
* **Register Clobbering:** Using reserved registers (`t8`, `t9`, `at`) for other purposes, leading to unpredictable behavior when the `MacroAssembler` uses them.
* **Incorrect Operand Sizes:** Using instructions with operands of the wrong size (e.g., using a 32-bit store instruction when a 64-bit store is needed).
* **Branching to Wrong Addresses:** Calculating branch targets incorrectly, leading to crashes or unexpected code execution.
* **Forgetting Branch Delay Slots:** On older MIPS architectures (and sometimes for optimization reasons even on newer ones), some instructions execute in the "branch delay slot."  Forgetting to place a valid instruction in this slot or placing an instruction that has unwanted side effects can cause issues. The `MacroAssembler` often handles this, but manual assembly requires careful attention.
* **Incorrectly Handling Function Call Conventions:** Not setting up arguments correctly when calling other functions, or not preserving caller-saved registers.

**Summary of Functionality (Part 1):**

The `v8/src/codegen/mips64/macro-assembler-mips64.h` header file defines the `MacroAssembler` class for the MIPS64 architecture in V8. It provides a high-level C++ interface for generating MIPS64 assembly instructions, abstracting away low-level details. This includes functionalities for stack management, function calls, register handling, constant loading, debugging, floating-point operations, Smi handling, object access, and interfacing with C++. It is a crucial component for V8's code generation process, enabling the engine to execute JavaScript code efficiently on MIPS64 systems.

Prompt: 
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/macro-assembler-mips64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDED_FROM_MACRO_ASSEMBLER_H
#error This header must be included via macro-assembler.h
#endif

#ifndef V8_CODEGEN_MIPS64_MACRO_ASSEMBLER_MIPS64_H_
#define V8_CODEGEN_MIPS64_MACRO_ASSEMBLER_MIPS64_H_

#include <optional>

#include "src/codegen/assembler.h"
#include "src/codegen/mips64/assembler-mips64.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/objects/tagged-index.h"

namespace v8 {
namespace internal {

// Forward declarations.
enum class AbortReason : uint8_t;

// Reserved Register Usage Summary.
//
// Registers t8, t9, and at are reserved for use by the MacroAssembler.
//
// The programmer should know that the MacroAssembler may clobber these three,
// but won't touch other registers except in special cases.
//
// Per the MIPS ABI, register t9 must be used for indirect function call
// via 'jalr t9' or 'jr t9' instructions. This is relied upon by gcc when
// trying to update gp register for position-independent-code. Whenever
// MIPS generated code calls C code, it must be via t9 register.

// Allow programmer to use Branch Delay Slot of Branches, Jumps, Calls.
enum BranchDelaySlot { USE_DELAY_SLOT, PROTECT };

// Flags used for the li macro-assembler function.
enum LiFlags {
  // If the constant value can be represented in just 16 bits, then
  // optimize the li to use a single instruction, rather than lui/ori/dsll
  // sequence. A number of other optimizations that emits less than
  // maximum number of instructions exists.
  OPTIMIZE_SIZE = 0,
  // Always use 6 instructions (lui/ori/dsll sequence) for release 2 or 4
  // instructions for release 6 (lui/ori/dahi/dati), even if the constant
  // could be loaded with just one, so that this value is patchable later.
  CONSTANT_SIZE = 1,
  // For address loads only 4 instruction are required. Used to mark
  // constant load that will be used as address without relocation
  // information. It ensures predictable code size, so specific sites
  // in code are patchable.
  ADDRESS_LOAD = 2
};

enum RAStatus { kRAHasNotBeenSaved, kRAHasBeenSaved };

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2 = no_reg,
                                   Register reg3 = no_reg,
                                   Register reg4 = no_reg,
                                   Register reg5 = no_reg,
                                   Register reg6 = no_reg);

// -----------------------------------------------------------------------------
// Static helper functions.

#if defined(V8_TARGET_LITTLE_ENDIAN)
#define SmiWordOffset(offset) (offset + kPointerSize / 2)
#else
#define SmiWordOffset(offset) offset
#endif

// Generate a MemOperand for loading a field from an object.
inline MemOperand FieldMemOperand(Register object, int offset) {
  return MemOperand(object, offset - kHeapObjectTag);
}

// Generate a MemOperand for storing arguments 5..N on the stack
// when calling CallCFunction().
// TODO(plind): Currently ONLY used for O32. Should be fixed for
//              n64, and used in RegExp code, and other places
//              with more than 8 arguments.
inline MemOperand CFunctionArgumentOperand(int index) {
  DCHECK_GT(index, kCArgSlotCount);
  // Argument 5 takes the slot just past the four Arg-slots.
  int offset = (index - 5) * kPointerSize + kCArgsSlotsSize;
  return MemOperand(sp, offset);
}

class V8_EXPORT_PRIVATE MacroAssembler : public MacroAssemblerBase {
 public:
  using MacroAssemblerBase::MacroAssemblerBase;

  // Activation support.
  void EnterFrame(StackFrame::Type type);
  void EnterFrame(StackFrame::Type type, bool load_constant_pool_pointer_reg) {
    // Out-of-line constant pool not implemented on mips.
    UNREACHABLE();
  }
  void LeaveFrame(StackFrame::Type type);

  void AllocateStackSpace(Register bytes) { Dsubu(sp, sp, bytes); }

  void AllocateStackSpace(int bytes) {
    DCHECK_GE(bytes, 0);
    if (bytes == 0) return;
    Dsubu(sp, sp, Operand(bytes));
  }

  // Generates function and stub prologue code.
  void StubPrologue(StackFrame::Type type);
  void Prologue();

  void InitializeRootRegister() {
    ExternalReference isolate_root = ExternalReference::isolate_root(isolate());
    li(kRootRegister, Operand(isolate_root));
  }

  // Jump unconditionally to given label.
  // We NEED a nop in the branch delay slot, as it used by v8, for example in
  // CodeGenerator::ProcessDeferred().
  // Currently the branch delay slot is filled by the MacroAssembler.
  // Use rather b(Label) for code generation.
  void jmp(Label* L) { Branch(L); }

  // -------------------------------------------------------------------------
  // Debugging.

  void Trap();
  void DebugBreak();

  // Calls Abort(msg) if the condition cc is not satisfied.
  // Use --debug_code to enable.
  void Assert(Condition cc, AbortReason reason, Register rs,
              Operand rt) NOOP_UNLESS_DEBUG_CODE;

  void AssertJSAny(Register object, Register map_tmp, Register tmp,
                   AbortReason abort_reason) NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but always enabled.
  void Check(Condition cc, AbortReason reason, Register rs, Operand rt);

  // Print a message to stdout and abort execution.
  void Abort(AbortReason msg);

  // Arguments macros.
#define COND_TYPED_ARGS Condition cond, Register r1, const Operand &r2
#define COND_ARGS cond, r1, r2

  // Cases when relocation is not needed.
#define DECLARE_NORELOC_PROTOTYPE(Name, target_type)                          \
  void Name(target_type target, BranchDelaySlot bd = PROTECT);                \
  inline void Name(BranchDelaySlot bd, target_type target) {                  \
    Name(target, bd);                                                         \
  }                                                                           \
  void Name(target_type target, COND_TYPED_ARGS,                              \
            BranchDelaySlot bd = PROTECT);                                    \
  inline void Name(BranchDelaySlot bd, target_type target, COND_TYPED_ARGS) { \
    Name(target, COND_ARGS, bd);                                              \
  }

#define DECLARE_BRANCH_PROTOTYPES(Name)   \
  DECLARE_NORELOC_PROTOTYPE(Name, Label*) \
  DECLARE_NORELOC_PROTOTYPE(Name, int32_t)

  DECLARE_BRANCH_PROTOTYPES(Branch)
  DECLARE_BRANCH_PROTOTYPES(BranchAndLink)
  DECLARE_BRANCH_PROTOTYPES(BranchShort)

#undef DECLARE_BRANCH_PROTOTYPES
#undef COND_TYPED_ARGS
#undef COND_ARGS

  // Floating point branches
  void CompareF32(FPUCondition cc, FPURegister cmp1, FPURegister cmp2) {
    CompareF(S, cc, cmp1, cmp2);
  }

  void CompareIsNanF32(FPURegister cmp1, FPURegister cmp2) {
    CompareIsNanF(S, cmp1, cmp2);
  }

  void CompareF64(FPUCondition cc, FPURegister cmp1, FPURegister cmp2) {
    CompareF(D, cc, cmp1, cmp2);
  }

  void CompareIsNanF64(FPURegister cmp1, FPURegister cmp2) {
    CompareIsNanF(D, cmp1, cmp2);
  }

  void BranchTrueShortF(Label* target, BranchDelaySlot bd = PROTECT);
  void BranchFalseShortF(Label* target, BranchDelaySlot bd = PROTECT);

  void BranchTrueF(Label* target, BranchDelaySlot bd = PROTECT);
  void BranchFalseF(Label* target, BranchDelaySlot bd = PROTECT);

  // MSA branches
  void BranchMSA(Label* target, MSABranchDF df, MSABranchCondition cond,
                 MSARegister wt, BranchDelaySlot bd = PROTECT);

  void CompareWord(Condition cond, Register dst, Register lhs,
                   const Operand& rhs);

  void BranchLong(int32_t offset, BranchDelaySlot bdslot = PROTECT);
  void Branch(Label* L, Condition cond, Register rs, RootIndex index,
              BranchDelaySlot bdslot = PROTECT);

  static int InstrCountForLi64Bit(int64_t value);
  inline void LiLower32BitHelper(Register rd, Operand j);
  void li_optimized(Register rd, Operand j, LiFlags mode = OPTIMIZE_SIZE);
  // Load int32 in the rd register.
  void li(Register rd, Operand j, LiFlags mode = OPTIMIZE_SIZE);
  inline void li(Register rd, int64_t j, LiFlags mode = OPTIMIZE_SIZE) {
    li(rd, Operand(j), mode);
  }
  // inline void li(Register rd, int32_t j, LiFlags mode = OPTIMIZE_SIZE) {
  //   li(rd, Operand(static_cast<int64_t>(j)), mode);
  // }
  void li(Register dst, Handle<HeapObject> value, LiFlags mode = OPTIMIZE_SIZE);
  void li(Register dst, ExternalReference value, LiFlags mode = OPTIMIZE_SIZE);

  void LoadFromConstantsTable(Register destination, int constant_index) final;
  void LoadRootRegisterOffset(Register destination, intptr_t offset) final;
  void LoadRootRelative(Register destination, int32_t offset) final;
  void StoreRootRelative(int32_t offset, Register value) final;

  // Operand pointing to an external reference.
  // May emit code to set up the scratch register. The operand is
  // only guaranteed to be correct as long as the scratch register
  // isn't changed.
  // If the operand is used more than once, use a scratch register
  // that is guaranteed not to be clobbered.
  MemOperand ExternalReferenceAsOperand(ExternalReference reference,
                                        Register scratch);
  MemOperand ExternalReferenceAsOperand(IsolateFieldId id) {
    return ExternalReferenceAsOperand(ExternalReference::Create(id), no_reg);
  }

  inline void Move(Register output, MemOperand operand) { Ld(output, operand); }

// Jump, Call, and Ret pseudo instructions implementing inter-working.
#define COND_ARGS                                  \
  Condition cond = al, Register rs = zero_reg,     \
            const Operand &rt = Operand(zero_reg), \
            BranchDelaySlot bd = PROTECT

  void Jump(Register target, COND_ARGS);
  void Jump(intptr_t target, RelocInfo::Mode rmode, COND_ARGS);
  void Jump(Address target, RelocInfo::Mode rmode, COND_ARGS);
  // Deffer from li, this method save target to the memory, and then load
  // it to register use ld, it can be used in wasm jump table for concurrent
  // patching.
  void PatchAndJump(Address target);
  void Jump(Handle<Code> code, RelocInfo::Mode rmode, COND_ARGS);
  void Jump(const ExternalReference& reference);
  void Call(Register target, COND_ARGS);
  void Call(Address target, RelocInfo::Mode rmode, COND_ARGS);
  void Call(Handle<Code> code, RelocInfo::Mode rmode = RelocInfo::CODE_TARGET,
            COND_ARGS);
  void Call(Label* target);
  void LoadAddress(Register dst, Label* target);
  void LoadAddressPCRelative(Register dst, Label* target);

  // Load the builtin given by the Smi in |builtin_index| into |target|.
  void LoadEntryFromBuiltinIndex(Register builtin_index, Register target);
  void LoadEntryFromBuiltin(Builtin builtin, Register destination);
  MemOperand EntryFromBuiltinAsOperand(Builtin builtin);

  void CallBuiltinByIndex(Register builtin_index, Register target);
  void CallBuiltin(Builtin builtin);
  void TailCallBuiltin(Builtin builtin);
  void TailCallBuiltin(Builtin builtin, Condition cond, Register type,
                       Operand range);

  // Load the code entry point from the Code object.
  void LoadCodeInstructionStart(Register destination,
                                Register code_data_container_object,
                                CodeEntrypointTag tag);
  void CallCodeObject(Register code_data_container_object,
                      CodeEntrypointTag tag);
  void JumpCodeObject(Register code_data_container_object,
                      CodeEntrypointTag tag,
                      JumpMode jump_mode = JumpMode::kJump);

  // Convenience functions to call/jmp to the code of a JSFunction object.
  void CallJSFunction(Register function_object);
  void JumpJSFunction(Register function_object,
                      JumpMode jump_mode = JumpMode::kJump);

  // Generates an instruction sequence s.t. the return address points to the
  // instruction following the call.
  // The return address on the stack is used by frame iteration.
  void StoreReturnAddressAndCall(Register target);

  void CallForDeoptimization(Builtin target, int deopt_id, Label* exit,
                             DeoptimizeKind kind, Label* ret,
                             Label* jump_deoptimization_entry_label);

  void Ret(COND_ARGS);
  inline void Ret(BranchDelaySlot bd, Condition cond = al,
                  Register rs = zero_reg,
                  const Operand& rt = Operand(zero_reg)) {
    Ret(cond, rs, rt, bd);
  }

  // Emit code to discard a non-negative number of pointer-sized elements
  // from the stack, clobbering only the sp register.
  void Drop(int count, Condition cond = cc_always, Register reg = no_reg,
            const Operand& op = Operand(no_reg));

  void DropArguments(Register count);
  void DropArgumentsAndPushNewReceiver(Register argc, Register receiver);

  // Trivial case of DropAndRet that utilizes the delay slot.
  void DropAndRet(int drop);

  void DropAndRet(int drop, Condition cond, Register reg, const Operand& op);

  void Ld(Register rd, const MemOperand& rs);
  void Sd(Register rd, const MemOperand& rs);

  void push(Register src) {
    Daddu(sp, sp, Operand(-kPointerSize));
    Sd(src, MemOperand(sp, 0));
  }
  void Push(Register src) { push(src); }
  void Push(Handle<HeapObject> handle);
  void Push(Tagged<Smi> smi);

  // Push two registers. Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2) {
    Dsubu(sp, sp, Operand(2 * kPointerSize));
    Sd(src1, MemOperand(sp, 1 * kPointerSize));
    Sd(src2, MemOperand(sp, 0 * kPointerSize));
  }

  // Push three registers. Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2, Register src3) {
    Dsubu(sp, sp, Operand(3 * kPointerSize));
    Sd(src1, MemOperand(sp, 2 * kPointerSize));
    Sd(src2, MemOperand(sp, 1 * kPointerSize));
    Sd(src3, MemOperand(sp, 0 * kPointerSize));
  }

  // Push four registers. Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2, Register src3, Register src4) {
    Dsubu(sp, sp, Operand(4 * kPointerSize));
    Sd(src1, MemOperand(sp, 3 * kPointerSize));
    Sd(src2, MemOperand(sp, 2 * kPointerSize));
    Sd(src3, MemOperand(sp, 1 * kPointerSize));
    Sd(src4, MemOperand(sp, 0 * kPointerSize));
  }

  // Push five registers. Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2, Register src3, Register src4,
            Register src5) {
    Dsubu(sp, sp, Operand(5 * kPointerSize));
    Sd(src1, MemOperand(sp, 4 * kPointerSize));
    Sd(src2, MemOperand(sp, 3 * kPointerSize));
    Sd(src3, MemOperand(sp, 2 * kPointerSize));
    Sd(src4, MemOperand(sp, 1 * kPointerSize));
    Sd(src5, MemOperand(sp, 0 * kPointerSize));
  }

  void Push(Register src, Condition cond, Register tst1, Register tst2) {
    // Since we don't have conditional execution we use a Branch.
    Branch(3, cond, tst1, Operand(tst2));
    Dsubu(sp, sp, Operand(kPointerSize));
    Sd(src, MemOperand(sp, 0));
  }

  enum PushArrayOrder { kNormal, kReverse };
  void PushArray(Register array, Register size, Register scratch,
                 Register scratch2, PushArrayOrder order = kNormal);

  void MaybeSaveRegisters(RegList registers);
  void MaybeRestoreRegisters(RegList registers);

  void CallEphemeronKeyBarrier(Register object, Register slot_address,
                               SaveFPRegsMode fp_mode);

  void CallRecordWriteStubSaveRegisters(
      Register object, Register slot_address, SaveFPRegsMode fp_mode,
      StubCallMode mode = StubCallMode::kCallBuiltinPointer);
  void CallRecordWriteStub(
      Register object, Register slot_address, SaveFPRegsMode fp_mode,
      StubCallMode mode = StubCallMode::kCallBuiltinPointer);

  // Push multiple registers on the stack.
  // Registers are saved in numerical order, with higher numbered registers
  // saved in higher memory addresses.
  void MultiPush(RegList regs);
  void MultiPushFPU(DoubleRegList regs);
  void MultiPushMSA(DoubleRegList regs);

  // Calculate how much stack space (in bytes) are required to store caller
  // registers excluding those specified in the arguments.
  int RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                      Register exclusion1 = no_reg,
                                      Register exclusion2 = no_reg,
                                      Register exclusion3 = no_reg) const;

  // Push caller saved registers on the stack, and return the number of bytes
  // stack pointer is adjusted.
  int PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1 = no_reg,
                      Register exclusion2 = no_reg,
                      Register exclusion3 = no_reg);
  // Restore caller saved registers from the stack, and return the number of
  // bytes stack pointer is adjusted.
  int PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1 = no_reg,
                     Register exclusion2 = no_reg,
                     Register exclusion3 = no_reg);

  void pop(Register dst) {
    Ld(dst, MemOperand(sp, 0));
    Daddu(sp, sp, Operand(kPointerSize));
  }
  void Pop(Register dst) { pop(dst); }

  // Pop two registers. Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2) {
    DCHECK(src1 != src2);
    Ld(src2, MemOperand(sp, 0 * kPointerSize));
    Ld(src1, MemOperand(sp, 1 * kPointerSize));
    Daddu(sp, sp, 2 * kPointerSize);
  }

  // Pop three registers. Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2, Register src3) {
    Ld(src3, MemOperand(sp, 0 * kPointerSize));
    Ld(src2, MemOperand(sp, 1 * kPointerSize));
    Ld(src1, MemOperand(sp, 2 * kPointerSize));
    Daddu(sp, sp, 3 * kPointerSize);
  }

  void Pop(uint32_t count = 1) { Daddu(sp, sp, Operand(count * kPointerSize)); }

  // Pops multiple values from the stack and load them in the
  // registers specified in regs. Pop order is the opposite as in MultiPush.
  void MultiPop(RegList regs);
  void MultiPopFPU(DoubleRegList regs);
  void MultiPopMSA(DoubleRegList regs);

#define DEFINE_INSTRUCTION(instr)                          \
  void instr(Register rd, Register rs, const Operand& rt); \
  void instr(Register rd, Register rs, Register rt) {      \
    instr(rd, rs, Operand(rt));                            \
  }                                                        \
  void instr(Register rs, Register rt, int32_t j) { instr(rs, rt, Operand(j)); }

#define DEFINE_INSTRUCTION2(instr)                                 \
  void instr(Register rs, const Operand& rt);                      \
  void instr(Register rs, Register rt) { instr(rs, Operand(rt)); } \
  void instr(Register rs, int32_t j) { instr(rs, Operand(j)); }

  DEFINE_INSTRUCTION(Addu)
  DEFINE_INSTRUCTION(Daddu)
  DEFINE_INSTRUCTION(Div)
  DEFINE_INSTRUCTION(Divu)
  DEFINE_INSTRUCTION(Ddivu)
  DEFINE_INSTRUCTION(Mod)
  DEFINE_INSTRUCTION(Modu)
  DEFINE_INSTRUCTION(Ddiv)
  DEFINE_INSTRUCTION(Subu)
  DEFINE_INSTRUCTION(Dsubu)
  DEFINE_INSTRUCTION(Dmod)
  DEFINE_INSTRUCTION(Dmodu)
  DEFINE_INSTRUCTION(Mul)
  DEFINE_INSTRUCTION(Mulh)
  DEFINE_INSTRUCTION(Mulhu)
  DEFINE_INSTRUCTION(Dmul)
  DEFINE_INSTRUCTION(Dmulh)
  DEFINE_INSTRUCTION(Dmulhu)
  DEFINE_INSTRUCTION2(Mult)
  DEFINE_INSTRUCTION2(Dmult)
  DEFINE_INSTRUCTION2(Multu)
  DEFINE_INSTRUCTION2(Dmultu)
  DEFINE_INSTRUCTION2(Div)
  DEFINE_INSTRUCTION2(Ddiv)
  DEFINE_INSTRUCTION2(Divu)
  DEFINE_INSTRUCTION2(Ddivu)

  DEFINE_INSTRUCTION(And)
  DEFINE_INSTRUCTION(Or)
  DEFINE_INSTRUCTION(Xor)
  DEFINE_INSTRUCTION(Nor)
  DEFINE_INSTRUCTION2(Neg)

  DEFINE_INSTRUCTION(Slt)
  DEFINE_INSTRUCTION(Sltu)
  DEFINE_INSTRUCTION(Sle)
  DEFINE_INSTRUCTION(Sleu)
  DEFINE_INSTRUCTION(Sgt)
  DEFINE_INSTRUCTION(Sgtu)
  DEFINE_INSTRUCTION(Sge)
  DEFINE_INSTRUCTION(Sgeu)

  // MIPS32 R2 instruction macro.
  DEFINE_INSTRUCTION(Ror)
  DEFINE_INSTRUCTION(Dror)

#undef DEFINE_INSTRUCTION
#undef DEFINE_INSTRUCTION2
#undef DEFINE_INSTRUCTION3

  void SmiTag(Register dst, Register src) {
    static_assert(kSmiTag == 0);
    if (SmiValuesAre32Bits()) {
      dsll32(dst, src, 0);
    } else {
      DCHECK(SmiValuesAre31Bits());
      Addu(dst, src, src);
    }
  }

  void SmiTag(Register reg) { SmiTag(reg, reg); }

  void SmiUntag(Register dst, const MemOperand& src);
  void SmiUntag(Register dst, Register src) {
    if (SmiValuesAre32Bits()) {
      dsra32(dst, src, kSmiShift - 32);
    } else {
      DCHECK(SmiValuesAre31Bits());
      sra(dst, src, kSmiShift);
    }
  }

  void SmiUntag(Register reg) { SmiUntag(reg, reg); }

  // Left-shifted from int32 equivalent of Smi.
  void SmiScale(Register dst, Register src, int scale) {
    if (SmiValuesAre32Bits()) {
      // The int portion is upper 32-bits of 64-bit word.
      dsra(dst, src, kSmiShift - scale);
    } else {
      DCHECK(SmiValuesAre31Bits());
      DCHECK_GE(scale, kSmiTagSize);
      sll(dst, src, scale - kSmiTagSize);
    }
  }

  // On MIPS64, we should sign-extend 32-bit values.
  void SmiToInt32(Register smi) {
    if (v8_flags.enable_slow_asserts) {
      AssertSmi(smi);
    }
    DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
    SmiUntag(smi);
  }

  // Abort execution if argument is a smi, enabled via --debug-code.
  void AssertNotSmi(Register object) NOOP_UNLESS_DEBUG_CODE;
  void AssertSmi(Register object) NOOP_UNLESS_DEBUG_CODE;

  int CalculateStackPassedWords(int num_reg_arguments,
                                int num_double_arguments);

  // Before calling a C-function from generated code, align arguments on stack
  // and add space for the four mips argument slots.
  // After aligning the frame, non-register arguments must be stored on the
  // stack, after the argument-slots using helper: CFunctionArgumentOperand().
  // The argument count assumes all arguments are word sized.
  // Some compilers/platforms require the stack to be aligned when calling
  // C++ code.
  // Needs a scratch register to do some arithmetic. This register will be
  // trashed.
  void PrepareCallCFunction(int num_reg_arguments, int num_double_registers,
                            Register scratch);
  void PrepareCallCFunction(int num_reg_arguments, Register scratch);

  // Arguments 1-4 are placed in registers a0 through a3 respectively.
  // Arguments 5..n are stored to stack using following:
  //  Sw(a4, CFunctionArgumentOperand(5));

  // Calls a C function and cleans up the space for arguments allocated
  // by PrepareCallCFunction. The called function is not allowed to trigger a
  // garbage collection, since that might move the code and invalidate the
  // return address (unless this is somehow accounted for by the called
  // function).
  int CallCFunction(
      ExternalReference function, int num_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);
  int CallCFunction(
      Register function, int num_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);
  int CallCFunction(
      ExternalReference function, int num_reg_arguments,
      int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);
  int CallCFunction(
      Register function, int num_reg_arguments, int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);
  void MovFromFloatResult(DoubleRegister dst);
  void MovFromFloatParameter(DoubleRegister dst);

  // There are two ways of passing double arguments on MIPS, depending on
  // whether soft or hard floating point ABI is used. These functions
  // abstract parameter passing for the three different ways we call
  // C functions from generated code.
  void MovToFloatParameter(DoubleRegister src);
  void MovToFloatParameters(DoubleRegister src1, DoubleRegister src2);
  void MovToFloatResult(DoubleRegister src);

  // See comments at the beginning of Builtins::Generate_CEntry.
  inline void PrepareCEntryArgs(int num_args) { li(a0, num_args); }
  inline void PrepareCEntryFunction(const ExternalReference& ref) {
    li(a1, ref);
  }

  void CheckPageFlag(Register object, Register scratch, int mask, Condition cc,
                     Label* condition_met);
#undef COND_ARGS

  // Performs a truncating conversion of a floating point number as used by
  // the JS bitwise operations. See ECMA-262 9.5: ToInt32.
  // Exits with 'result' holding the answer.
  void TruncateDoubleToI(Isolate* isolate, Zone* zone, Register result,
                         DoubleRegister double_input, StubCallMode stub_mode);

  // Conditional move.
  void Movz(Register rd, Register rs, Register rt);
  void Movn(Register rd, Register rs, Register rt);
  void Movt(Register rd, Register rs, uint16_t cc = 0);
  void Movf(Register rd, Register rs, uint16_t cc = 0);

  void LoadZeroIfFPUCondition(Register dest);
  void LoadZeroIfNotFPUCondition(Register dest);

  void LoadZeroIfConditionNotZero(Register dest, Register condition);
  void LoadZeroIfConditionZero(Register dest, Register condition);

  void Clz(Register rd, Register rs);
  void Dclz(Register rd, Register rs);
  void Ctz(Register rd, Register rs);
  void Dctz(Register rd, Register rs);
  void Popcnt(Register rd, Register rs);
  void Dpopcnt(Register rd, Register rs);

  // MIPS64 R2 instruction macro.
  void Ext(Register rt, Register rs, uint16_t pos, uint16_t size);
  void Dext(Register rt, Register rs, uint16_t pos, uint16_t size);
  void Ins(Register rt, Register rs, uint16_t pos, uint16_t size);
  void Dins(Register rt, Register rs, uint16_t pos, uint16_t size);
  void ExtractBits(Register dest, Register source, Register pos, int size,
                   bool sign_extend = false);
  void InsertBits(Register dest, Register source, Register pos, int size);
  void Neg_s(FPURegister fd, FPURegister fs);
  void Neg_d(FPURegister fd, FPURegister fs);

  // MIPS64 R6 instruction macros.
  void Bovc(Register rt, Register rs, Label* L);
  void Bnvc(Register rt, Register rs, Label* L);

  // Convert single to unsigned word.
  void Trunc_uw_s(FPURegister fd, FPURegister fs, FPURegister scratch);
  void Trunc_uw_s(Register rd, FPURegister fs, FPURegister scratch);

  // Change endianness
  void ByteSwapSigned(Register dest, Register src, int operand_size);
  void ByteSwapUnsigned(Register dest, Register src, int operand_size);

  void Ulh(Register rd, const MemOperand& rs);
  void Ulhu(Register rd, const MemOperand& rs);
  void Ush(Register rd, const MemOperand& rs, Register scratch);

  void Ulw(Register rd, const MemOperand& rs);
  void Ulwu(Register rd, const MemOperand& rs);
  void Usw(Register rd, const MemOperand& rs);

  void Uld(Register rd, const MemOperand& rs);
  void Usd(Register rd, const MemOperand& rs);

  void Ulwc1(FPURegister fd, const MemOperand& rs, Register scratch);
  void Uswc1(FPURegister fd, const MemOperand& rs, Register scratch);

  void Uldc1(FPURegister fd, const MemOperand& rs, Register scratch);
  void Usdc1(FPURegister fd, const MemOperand& rs, Register scratch);

  void Lb(Register rd, const MemOperand& rs);
  void Lbu(Register rd, const MemOperand& rs);
  void Sb(Register rd, const MemOperand& rs);

  void Lh(Register rd, const MemOperand& rs);
  void Lhu(Register rd, const MemOperand& rs);
  void Sh(Register rd, const MemOperand& rs);

  void Lw(Register rd, const MemOperand& rs);
  void Lwu(Register rd, const MemOperand& rs);
  void Sw(Register rd, const MemOperand& rs);

  void Lwc1(FPURegister fd, const MemOperand& src);
  void Swc1(FPURegister fs, const MemOperand& dst);

  void Ldc1(FPURegister fd, const MemOperand& src);
  void Sdc1(FPURegister fs, const MemOperand& dst);

  void Ll(Register rd, const MemOperand& rs);
  void Sc(Register rd, const MemOperand& rs);

  void Lld(Register rd, const MemOperand& rs);
  void Scd(Register rd, const MemOperand& rs);

  // Perform a floating-point min or max operation with the
  // (IEEE-754-compatible) semantics of MIPS32's Release 6 MIN.fmt/MAX.fmt.
  // Some cases, typically NaNs or +/-0.0, are expected to be rare and are
  // handled in out-of-line code. The specific behaviour depends on supported
  // instructions.
  //
  // These functions assume (and assert) that src1!=src2. It is permitted
  // for the result to alias either input register.
  void Float32Max(FPURegister dst, FPURegister src1, FPURegister src2,
                  Label* out_of_line);
  void Float32Min(FPURegister dst, FPURegister src1, FPURegister src2,
                  Label* out_of_line);
  void Float64Max(FPURegister dst, FPURegister src1, FPURegister src2,
                  Label* out_of_line);
  void Float64Min(FPURegister dst, FPURegister src1, FPURegister src2,
                  Label* out_of_line);

  // Generate out-of-line cases for the macros above.
  void Float32MaxOutOfLine(FPURegister dst, FPURegister src1, FPURegister src2);
  void Float32MinOutOfLine(FPURegister dst, FPURegister src1, FPURegister src2);
  void Float64MaxOutOfLine(FPURegister dst, FPURegister src1, FPURegister src2);
  void Float64MinOutOfLine(FPURegister dst, FPURegister src1, FPURegister src2);

  bool IsDoubleZeroRegSet() { return has_double_zero_reg_set_; }

  void LoadIsolateField(Register dst, IsolateFieldId id);

  void mov(Register rd, Register rt) { or_(rd, rt, zero_reg); }

  inline void Move(Register dst, Handle<HeapObject> handle) { li(dst, handle); }
  inline void Move(Register dst, Tagged<Smi> value) { li(dst, Operand(value)); }

  inline void Move(Register dst, Register src) {
    if (dst != src) {
      mov(dst, src);
    }
  }

  inline void Move(FPURegister dst, FPURegister src) { Move_d(dst, src); }

  inline void Move(Register dst_low, Register dst_high, FPURegister src) {
    mfc1(dst_low, src);
    mfhc1(dst_high, src);
  }

  inline void Move(Register dst, FPURegister src) { dmfc1(dst, src); }

  inline void Move(FPURegister dst, Register src) { dmtc1(src, dst); }

  inline void FmoveHigh(Register dst_high, FPURegister src) {
    mfhc1(dst_high, src);
  }

  inline void FmoveHigh(FPURegister dst, Register src_high) {
    mthc1(src_high, dst);
  }

  inline void FmoveLow(Register dst_low, FPURegister src) {
    mfc1(dst_low, src);
  }

  void FmoveLow(FPURegister dst, Register src_low);

  inline void Move(FPURegister dst, Register src_low, Register src_high) {
    mtc1(src_low, dst);
    mthc1(src_high, dst);
  }

  inline void Move_d(FPURegister dst, FPURegister src) {
    if (dst != src) {
      mov_d(dst, src);
    }
  }

  inline void Move_s(FPURegister dst, FPURegister src) {
    if (dst != src) {
      mov_s(dst, src);
    }
  }

  void Move(FPURegister dst, float imm) {
    Move(dst, base::bit_cast<uint32_t>(imm));
  }
  void Move(FPURegister dst, double imm) {
    Move(dst, base::bit_cast<uint64_t>(imm));
  }
  void Move(FPURegister dst, uint32_t src);
  void Move(FPURegister dst, uint64_t src);

  // DaddOverflow sets overflow register to a negative value if
  // overflow occured, otherwise it is zero or positive
  void DaddOverflow(Register dst, Register left, const Operand& right,
                    Register overflow);
  // DsubOverflow sets overflow register to a negative value if
  // overflow occured, otherwise it is zero or positive
  void DsubOverflow(Register dst, Register left, const Operand& right,
                    Register overflow);
  // [D]MulOverflow set overflow register to zero if no overflow occured
  void MulOverflow(Register dst, Register left, const Operand& right,
                   Register overflow);
  void DMulOverflow(Register dst, Register left, const Operand& right,
                    Register overflow);

// Number of instructions needed for calculation of switch table entry address
#ifdef _MIPS_ARCH_MIPS64R6
  static const int kSwitchTablePrologueSize = 6;
#else
  static const int kSwitchTablePrologueSize = 11;
#endif

  // GetLabelFunction must be lambda '[](size_t index) -> Label*' or a
  // functor/function with 'Label *func(size_t index)' declaration.
  template <typename Func>
  void GenerateSwitchTable(Register index, size_t case_count,
                           Func GetLabelFunction);

  // Load an object from the root table.
  void LoadRoot(Register destination, RootIndex index) final;
  void LoadRoot(Register destination, RootIndex index, Condition cond,
                Register src1, const Operand& src2);

  void LoadMap(Register destination, Register object);

  void LoadFeedbackVector(Register dst, Register closure, Register scratch,
                          Label* fbv_undef);

  // If the value is a NaN, canonical
"""


```