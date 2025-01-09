Response:
Let's break down the thought process for analyzing this V8 header file.

1. **Identify the Core Purpose:** The filename `baseline-assembler-s390-inl.h` immediately tells us this is an *inline header* for the *baseline assembler* targeting the *s390 architecture*. The "baseline" part suggests it's related to V8's baseline compiler (Sparkplug).

2. **Header Guard and Includes:**  The `#ifndef`, `#define`, and `#endif` lines are a standard header guard, preventing multiple inclusions. The `#include` directives tell us this file relies on other V8 components:
    * `baseline-assembler.h`:  Likely defines the base `BaselineAssembler` class.
    * `interface-descriptors.h`: Probably defines structures for describing function interfaces (arguments, return values).
    * `s390/assembler-s390-inl.h`:  Provides the low-level s390 assembly instructions.
    * `literal-objects-inl.h`:  Deals with inline representations of literal objects.

3. **Namespace Structure:** The code is within `v8::internal::baseline`, indicating its role within V8's internal architecture and specifically within the baseline compiler.

4. **Scratch Registers:** The `detail::kScratchRegisters` array and the `ScratchRegisterScope` class clearly manage temporary registers for intermediate calculations. This is a common optimization technique in assemblers. The `AcquireScratch()` method suggests a mechanism for borrowing these temporary registers.

5. **Assembler Macros:** The `#define __ assm->` and `#define __ masm_->` are common tricks in V8's codebase to shorten assembler instruction prefixes. `assm` likely refers to the base `BaselineAssembler`, while `masm_` is the underlying `MacroAssembler` (from the s390-specific includes). The `#undef __` is used to clean up the macro definition later.

6. **Key Functionalities - Scan for Verbs and Nouns:**  Now, the real work begins: looking at the methods of the `BaselineAssembler` class. Focus on verbs and the nouns they act upon. Common patterns emerge:
    * **`JumpIf...`:**  These methods implement conditional jumps based on various criteria (roots, SMIs, object types, comparisons). They take conditions (`cc`), operands (registers, immediate values, memory locations), and target labels.
    * **`Move...`:**  These methods move data between registers, memory locations, and immediate values. Note the variations like `MoveMaybeSmi` and `MoveSmi`.
    * **`Load...`:**  Methods for loading data from memory into registers (tagged fields, signed fields, bytes, words).
    * **`Store...`:** Methods for storing data from registers into memory (tagged fields, with/without write barriers). The write barrier is crucial for garbage collection.
    * **`Push...` and `Pop...`:**  Stack manipulation.
    * **`Bind(Label*)`:**  Defines a label in the generated code.
    * **`TryLoadOptimizedOsrCode`:**  Likely related to on-stack replacement (OSR) optimization.
    * **`AddToInterruptBudget...`:**  Deals with managing execution time and triggering interrupts.
    * **`LdaContextSlot`, `StaContextSlot`, `LdaModuleVariable`, `StaModuleVariable`:**  Accessing variables in different scopes (context, module).
    * **`IncrementSmi`:**  Incrementing a Small Integer (Smi) in memory.
    * **`Word32And`:** Bitwise AND operation.
    * **`Switch`:**  Implementing a switch statement.
    * **`EmitReturn`:** Handling function returns.

7. **Specific Details and Considerations:**  As you go through the methods:
    * **Memory Operands:** Pay attention to how memory operands are constructed (`MemOperand(fp, ...)`). `fp` likely refers to the frame pointer. The constants like `kSystemPointerSize` and `BaselineFrameConstants::kFeedbackVectorFromFp` give hints about the frame layout.
    * **Tagged Values and Smis:** Notice the frequent references to "Tagged" and "Smi." This is central to V8's object representation. `Smi` is a special compact representation for small integers.
    * **Write Barriers:** Understand the purpose of write barriers in garbage collection.
    * **Scratch Register Usage:** Observe how `ScratchRegisterScope` is used to acquire and release temporary registers.
    * **Endianness:** The `#ifdef V8_TARGET_BIG_ENDIAN` block shows platform-specific adjustments (stack bias).
    * **Compression Pointers:** The `COMPRESS_POINTERS_BOOL` checks indicate an optimization where pointers are sometimes compressed.

8. **Torque Check:**  The prompt asks about `.tq` files. A quick scan confirms the file *doesn't* end in `.tq`, so it's not a Torque file.

9. **JavaScript Relevance:** Consider how these assembler operations relate to JavaScript concepts:
    * **Variable access:** `LdaContextSlot`, `StaContextSlot`, `LdaModuleVariable`, `StaModuleVariable` are directly related to how JavaScript variables are stored and accessed.
    * **Function calls and returns:** `EmitReturn`, stack manipulation (`Push`, `Pop`).
    * **Control flow:** `JumpIf...`, `Switch`.
    * **Object manipulation:**  Loading and storing tagged fields, checking object types.
    * **Arithmetic operations:** `IncrementSmi`, `Word32And`.

10. **Example Generation (JavaScript, Logic, Errors):**  Once you understand the functionalities, you can create examples to illustrate them. Think about simple JavaScript code snippets that would trigger these low-level operations. For logic examples, choose specific input values and trace the expected behavior. For common errors, think about mistakes developers make that would lead to issues in the underlying assembly.

11. **Refine and Organize:**  Finally, organize your findings logically, grouping related functionalities and providing clear explanations for each point. Use formatting (like headings and bullet points) to improve readability.

Self-Correction/Refinement during the process:

* **Initial Oversimplification:**  I might initially think a `JumpIf` is just a simple branch. Realizing it involves comparisons and different operand types requires closer inspection.
* **Missing the "Why":**  Just listing the functions isn't enough. Understanding *why* these functions exist in the context of a baseline compiler is crucial. For instance, understanding the interrupt budget helps explain why that code is present.
* **Vague Explanations:** Initially, my explanations might be too generic. I need to be more specific about V8's terminology (Tagged, Smi, Context, etc.).
* **Forgetting Edge Cases:** When generating examples, remember to consider edge cases or less obvious scenarios.

By following this structured approach, I can systematically analyze the header file and extract its key functionalities and relevance.
This header file, `v8/src/baseline/s390/baseline-assembler-s390-inl.h`, provides inline implementations for the `BaselineAssembler` class specifically targeting the s390 architecture in V8's baseline compiler (Sparkplug). Let's break down its functionalities:

**Core Functionality:**

The primary function of this file is to offer a higher-level abstraction over the raw s390 assembly instructions provided by `src/codegen/s390/assembler-s390-inl.h`. It helps in generating s390 machine code for the baseline compiler by providing convenient methods for common operations.

**Key Features and Functionalities:**

1. **Scratch Register Management:**
   - Defines a set of scratch registers (`kScratchRegisters`) that can be used for temporary values during code generation.
   - Provides the `ScratchRegisterScope` class to manage the allocation and deallocation of these scratch registers, ensuring they are not inadvertently clobbered.

2. **Assembler Macros:**
   - Defines macros like `__` to simplify writing s390 assembly instructions. It essentially redirects `__` to call methods on the underlying `MacroAssembler` (`masm_`).

3. **Register Frame Operations:**
   - `RegisterFrameOperand`: Calculates the memory operand for accessing a specific interpreter register within the current function's frame.
   - `RegisterFrameAddress`: Calculates the memory address of a specific interpreter register in the frame and stores it in a scratch register.
   - `FeedbackVectorOperand`, `FeedbackCellOperand`: Provides access to the feedback vector and feedback cell, which are used for collecting runtime type information for optimizations.

4. **Control Flow:**
   - `Bind`: Defines a label in the generated code.
   - `Jump`, `JumpIfRoot`, `JumpIfNotRoot`, `JumpIfSmi`, `JumpIfNotSmi`, `JumpIfImmediate`: Provides methods for unconditional and conditional jumps based on various conditions (root values, Smi checks, immediate values).
   - `TestAndBranch`: Performs a bitwise AND and jumps based on the result.
   - `JumpIf`:  Performs a comparison and jumps based on the condition.
   - `JumpIfObjectType`, `JumpIfInstanceType`:  Checks the type of an object and jumps accordingly.
   - `JumpIfPointer`, `JumpIfTagged`, `JumpIfByte`:  Provides conditional jumps based on comparing pointers, tagged values, and byte values.
   - `Switch`: Implements a switch statement using a jump table.

5. **Data Movement:**
   - `Move`: Provides methods to move data between registers, memory locations, and immediate values (including tagged values, external references, and handles).
   - `MoveMaybeSmi`, `MoveSmi`: Specific methods for moving potentially or definitely Smi values.

6. **Stack Operations:**
   - `Push`, `PushReverse`, `Pop`: Methods for pushing and popping values onto/from the stack.

7. **Memory Access:**
   - `LoadTaggedField`, `LoadTaggedSignedField`, `LoadTaggedSignedFieldAndUntag`:  Methods for loading tagged values (pointers to objects or Smis) and signed values from object fields.
   - `LoadWord16FieldZeroExtend`, `LoadWord8Field`:  Methods for loading 16-bit and 8-bit values from object fields.
   - `StoreTaggedSignedField`, `StoreTaggedFieldWithWriteBarrier`, `StoreTaggedFieldNoWriteBarrier`: Methods for storing tagged values into object fields, with or without triggering a write barrier (important for garbage collection).

8. **Optimization Hints:**
   - `TryLoadOptimizedOsrCode`:  Attempts to load optimized code for on-stack replacement (OSR).

9. **Interrupt Handling:**
   - `AddToInterruptBudgetAndJumpIfNotExceeded`:  Manages an interrupt budget to prevent long-running JavaScript code from blocking the main thread.

10. **Context and Scope Access:**
   - `LdaContextSlot`, `StaContextSlot`:  Loads and stores values from specific slots in the current execution context.
   - `LdaModuleVariable`, `StaModuleVariable`:  Loads and stores values from module variables.

11. **Smi Operations:**
   - `IncrementSmi`: Increments a Small Integer (Smi) stored in memory.

12. **Bitwise Operations:**
   - `Word32And`: Performs a bitwise AND operation.

13. **Return Sequence:**
   - `EmitReturn`: Generates the necessary code to return from a baseline-compiled function, including updating the interrupt budget and leaving the stack frame.

**Is it a Torque file?**

The filename ends with `.h`, not `.tq`. Therefore, `v8/src/baseline/s390/baseline-assembler-s390-inl.h` is **not** a V8 Torque source code file. It's a standard C++ header file containing inline function definitions.

**Relationship to JavaScript Functionality:**

This file is directly involved in the execution of JavaScript code. The `BaselineAssembler` is responsible for generating the actual machine code that executes the bytecode produced by V8's interpreter. Many of the methods in this file directly correspond to common JavaScript operations:

* **Variable Access:** `LdaContextSlot`, `StaContextSlot`, `LdaModuleVariable`, `StaModuleVariable` are used when accessing and modifying JavaScript variables in different scopes.
* **Function Calls and Returns:** `EmitReturn` is crucial for function returns. The stack manipulation methods (`Push`, `Pop`) are used during function calls.
* **Control Flow Statements:**  The `JumpIf...` and `Switch` methods implement the underlying logic for `if`, `else`, `for`, `while`, and `switch` statements in JavaScript.
* **Object and Property Access:** `LoadTaggedField`, `StoreTaggedFieldWithWriteBarrier` are used when accessing and modifying properties of JavaScript objects.
* **Type Checks:** `JumpIfSmi`, `JumpIfObjectType`, `JumpIfInstanceType` are used to perform type checks on JavaScript values.
* **Arithmetic Operations:** `IncrementSmi` is used for incrementing integer values.

**JavaScript Example:**

```javascript
function add(a, b) {
  return a + b;
}

let x = 5;
let y = 10;
let sum = add(x, y);
```

When the V8 baseline compiler compiles this JavaScript code for the s390 architecture, the `BaselineAssembler` (using methods from this header file) would generate s390 assembly instructions to:

* **Load the values of `a` and `b` (which might be Smis) into registers.**  Methods like `MoveSmi` or `LoadTaggedField` (if they are not Smis) would be used.
* **Perform the addition.**  This might involve low-level s390 arithmetic instructions.
* **Store the result in a register.**
* **Return the result.** The `EmitReturn` method would be used to generate the return sequence.
* **When accessing `x`, `y`, and `sum`, methods like `LdaContextSlot` or `LdaModuleVariable` would be used to load their values from memory.**

**Code Logic Reasoning (Hypothetical Example):**

Let's consider the `JumpIfSmi` function:

**Hypothetical Input:**

* `value` register contains a tagged value (could be a Smi or a pointer to an object).
* `target` is a label representing the jump destination.

**Code Logic (Simplified):**

The `JumpIfSmi` method internally uses the s390 `TestAndBranch` instruction (or similar) to check if the least significant bit of the `value` register is 0. In V8, Smi values have their least significant bit set to 0.

**Hypothetical Output:**

* If the least significant bit of `value` is 0 (indicating a Smi), the program execution will jump to the `target` label.
* Otherwise, execution will continue to the next instruction after the `JumpIfSmi` call.

**User-Common Programming Errors:**

While developers don't directly interact with this assembly-level code, understanding its purpose can help diagnose performance issues and understand the underlying behavior of JavaScript. Common programming errors that might indirectly relate to the code generated by this assembler include:

1. **Type Mismatches:** Performing operations on values of unexpected types can lead to deoptimizations and slower execution. For example, trying to perform arithmetic on a non-Smi value might trigger more complex code paths.

   ```javascript
   function multiply(a, b) {
     return a * b;
   }

   let result = multiply("5", 10); // "5" is a string, not a number
   ```

   In this case, the baseline compiler might initially generate code assuming `a` and `b` are numbers (potentially Smis). When it encounters a string, it might need to deoptimize and switch to a more general (and slower) code path.

2. **Excessive Object Property Access:** Frequent access to object properties can lead to increased memory loads and stores, impacting performance. The `LoadTaggedField` and `StoreTaggedFieldWithWriteBarrier` methods are invoked during property access.

   ```javascript
   let obj = { x: 1, y: 2, z: 3 };
   let sum = 0;
   for (let i = 0; i < 1000; i++) {
     sum += obj.x + obj.y + obj.z;
   }
   ```

   The loop will repeatedly use `LoadTaggedField` to access the `x`, `y`, and `z` properties. Optimizing object layouts can help improve the efficiency of these operations.

3. **Creating Too Many Short-Lived Objects:** Frequent creation and destruction of objects can put pressure on the garbage collector. The write barriers involved in storing object properties (using `StoreTaggedFieldWithWriteBarrier`) are part of the garbage collection mechanism.

   ```javascript
   function createPoint(x, y) {
     return { x: x, y: y };
   }

   for (let i = 0; i < 1000; i++) {
     let p = createPoint(i, i * 2); // Creates a new object in each iteration
     // ... some operation with p ...
   }
   ```

In summary, `v8/src/baseline/s390/baseline-assembler-s390-inl.h` is a crucial part of V8's baseline compiler for the s390 architecture. It provides the building blocks for generating efficient machine code to execute JavaScript, and understanding its functionalities provides insight into the low-level operations that underpin JavaScript execution.

Prompt: 
```
这是目录为v8/src/baseline/s390/baseline-assembler-s390-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/baseline/s390/baseline-assembler-s390-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BASELINE_S390_BASELINE_ASSEMBLER_S390_INL_H_
#define V8_BASELINE_S390_BASELINE_ASSEMBLER_S390_INL_H_

#include "src/baseline/baseline-assembler.h"
#include "src/codegen/interface-descriptors.h"
#include "src/codegen/s390/assembler-s390-inl.h"
#include "src/objects/literal-objects-inl.h"

namespace v8 {
namespace internal {
namespace baseline {

namespace detail {

static constexpr Register kScratchRegisters[] = {r8, ip, r1};
static constexpr int kNumScratchRegisters = arraysize(kScratchRegisters);

#ifdef DEBUG
inline bool Clobbers(Register target, MemOperand op) {
  return op.rb() == target || op.rx() == target;
}
#endif
}  // namespace detail

class BaselineAssembler::ScratchRegisterScope {
 public:
  explicit ScratchRegisterScope(BaselineAssembler* assembler)
      : assembler_(assembler),
        prev_scope_(assembler->scratch_register_scope_),
        registers_used_(prev_scope_ == nullptr ? 0
                                               : prev_scope_->registers_used_) {
    assembler_->scratch_register_scope_ = this;
  }
  ~ScratchRegisterScope() { assembler_->scratch_register_scope_ = prev_scope_; }

  Register AcquireScratch() {
    DCHECK_LT(registers_used_, detail::kNumScratchRegisters);
    return detail::kScratchRegisters[registers_used_++];
  }

 private:
  BaselineAssembler* assembler_;
  ScratchRegisterScope* prev_scope_;
  int registers_used_;
};

#define __ assm->
// s390x helper
template <int width = 64>
static void JumpIfHelper(MacroAssembler* assm, Condition cc, Register lhs,
                         Register rhs, Label* target) {
  static_assert(width == 64 || width == 32,
                "only support 64 and 32 bit compare");
  if (width == 64) {
    if (is_signed(cc)) {
      __ CmpS64(lhs, rhs);
    } else {
      __ CmpU64(lhs, rhs);
    }
  } else {
    if (is_signed(cc)) {
      __ CmpS32(lhs, rhs);
    } else {
      __ CmpU32(lhs, rhs);
    }
  }
  __ b(to_condition(cc), target);
}

#undef __

#define __ masm_->

MemOperand BaselineAssembler::RegisterFrameOperand(
    interpreter::Register interpreter_register) {
  return MemOperand(fp, interpreter_register.ToOperand() * kSystemPointerSize);
}
void BaselineAssembler::RegisterFrameAddress(
    interpreter::Register interpreter_register, Register rscratch) {
  return __ AddS64(rscratch, fp,
                   interpreter_register.ToOperand() * kSystemPointerSize);
}
MemOperand BaselineAssembler::FeedbackVectorOperand() {
  return MemOperand(fp, BaselineFrameConstants::kFeedbackVectorFromFp);
}
MemOperand BaselineAssembler::FeedbackCellOperand() {
  return MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp);
}

void BaselineAssembler::Bind(Label* label) { __ bind(label); }

void BaselineAssembler::JumpTarget() {
  // NOP on arm.
}

void BaselineAssembler::Jump(Label* target, Label::Distance distance) {
  ASM_CODE_COMMENT(masm_);
  __ b(target);
}

void BaselineAssembler::JumpIfRoot(Register value, RootIndex index,
                                   Label* target, Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  __ JumpIfRoot(value, index, target);
}

void BaselineAssembler::JumpIfNotRoot(Register value, RootIndex index,
                                      Label* target, Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  __ JumpIfNotRoot(value, index, target);
}

void BaselineAssembler::JumpIfSmi(Register value, Label* target,
                                  Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  __ JumpIfSmi(value, target);
}

void BaselineAssembler::JumpIfImmediate(Condition cc, Register left, int right,
                                        Label* target,
                                        Label::Distance distance) {
  ASM_CODE_COMMENT(masm_);
  JumpIf(cc, left, Operand(right), target, distance);
}

void BaselineAssembler::JumpIfNotSmi(Register value, Label* target,
                                     Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  __ JumpIfNotSmi(value, target);
}

void BaselineAssembler::TestAndBranch(Register value, int mask, Condition cc,
                                      Label* target, Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  __ AndP(r0, value, Operand(mask));
  __ b(to_condition(cc), target);
}

void BaselineAssembler::JumpIf(Condition cc, Register lhs, const Operand& rhs,
                               Label* target, Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  if (is_signed(cc)) {
    __ CmpS64(lhs, rhs);
  } else {
    __ CmpU64(lhs, rhs);
  }
  __ b(to_condition(cc), target);
}

void BaselineAssembler::JumpIfObjectTypeFast(Condition cc, Register object,
                                             InstanceType instance_type,
                                             Label* target,
                                             Label::Distance distance) {
  ScratchRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  JumpIfObjectType(cc, object, instance_type, scratch, target, distance);
}

void BaselineAssembler::JumpIfObjectType(Condition cc, Register object,
                                         InstanceType instance_type,
                                         Register map, Label* target,
                                         Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  ScratchRegisterScope temps(this);
  Register type = temps.AcquireScratch();
  __ LoadMap(map, object);
  __ LoadU16(type, FieldMemOperand(map, Map::kInstanceTypeOffset));
  JumpIf(cc, type, Operand(instance_type), target);
}

void BaselineAssembler::JumpIfInstanceType(Condition cc, Register map,
                                           InstanceType instance_type,
                                           Label* target, Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  ScratchRegisterScope temps(this);
  Register type = temps.AcquireScratch();
  if (v8_flags.debug_code) {
    __ AssertNotSmi(map);
    __ CompareObjectType(map, type, type, MAP_TYPE);
    __ Assert(eq, AbortReason::kUnexpectedValue);
  }
  __ LoadU16(type, FieldMemOperand(map, Map::kInstanceTypeOffset));
  JumpIf(cc, type, Operand(instance_type), target);
}

void BaselineAssembler::JumpIfPointer(Condition cc, Register value,
                                      MemOperand operand, Label* target,
                                      Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  ScratchRegisterScope temps(this);
  Register tmp = temps.AcquireScratch();
  __ LoadU64(tmp, operand);
  JumpIfHelper(masm_, cc, value, tmp, target);
}

void BaselineAssembler::JumpIfSmi(Condition cc, Register value, Tagged<Smi> smi,
                                  Label* target, Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  __ AssertSmi(value);
  __ LoadSmiLiteral(r0, smi);
  JumpIfHelper(masm_, cc, value, r0, target);
}

void BaselineAssembler::JumpIfSmi(Condition cc, Register lhs, Register rhs,
                                  Label* target, Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  __ AssertSmi(lhs);
  __ AssertSmi(rhs);
  JumpIfHelper(masm_, cc, lhs, rhs, target);
}

#ifdef V8_TARGET_BIG_ENDIAN
constexpr static int stack_bias = 4;
#else
constexpr static int stack_bias = 0;
#endif

void BaselineAssembler::JumpIfTagged(Condition cc, Register value,
                                     MemOperand operand, Label* target,
                                     Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  DCHECK(operand.rb() == fp || operand.rx() == fp);
  if (COMPRESS_POINTERS_BOOL) {
    MemOperand addr =
        MemOperand(operand.rx(), operand.rb(), operand.offset() + stack_bias);
    __ LoadTaggedField(ip, addr, r0);
  } else {
    __ LoadTaggedField(ip, operand, r0);
  }
  JumpIfHelper<COMPRESS_POINTERS_BOOL ? 32 : 64>(masm_, cc, value, ip, target);
}

void BaselineAssembler::JumpIfTagged(Condition cc, MemOperand operand,
                                     Register value, Label* target,
                                     Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  DCHECK(operand.rb() == fp || operand.rx() == fp);
  if (COMPRESS_POINTERS_BOOL) {
    MemOperand addr =
        MemOperand(operand.rx(), operand.rb(), operand.offset() + stack_bias);
    __ LoadTaggedField(ip, addr, r0);
  } else {
    __ LoadTaggedField(ip, operand, r0);
  }
  JumpIfHelper<COMPRESS_POINTERS_BOOL ? 32 : 64>(masm_, cc, ip, value, target);
}
void BaselineAssembler::JumpIfByte(Condition cc, Register value, int32_t byte,
                                   Label* target, Label::Distance) {
  ASM_CODE_COMMENT(masm_);
  JumpIf(cc, value, Operand(byte), target);
}

void BaselineAssembler::Move(interpreter::Register output, Register source) {
  Move(RegisterFrameOperand(output), source);
}

void BaselineAssembler::Move(Register output, Tagged<TaggedIndex> value) {
  ASM_CODE_COMMENT(masm_);
  __ mov(output, Operand(value.ptr()));
}

void BaselineAssembler::Move(MemOperand output, Register source) {
  ASM_CODE_COMMENT(masm_);
  __ StoreU64(source, output);
}

void BaselineAssembler::Move(Register output, ExternalReference reference) {
  ASM_CODE_COMMENT(masm_);
  __ Move(output, reference);
}

void BaselineAssembler::Move(Register output, Handle<HeapObject> value) {
  ASM_CODE_COMMENT(masm_);
  __ Move(output, value);
}

void BaselineAssembler::Move(Register output, int32_t value) {
  ASM_CODE_COMMENT(masm_);
  __ mov(output, Operand(value));
}

void BaselineAssembler::MoveMaybeSmi(Register output, Register source) {
  ASM_CODE_COMMENT(masm_);
  __ mov(output, source);
}

void BaselineAssembler::MoveSmi(Register output, Register source) {
  ASM_CODE_COMMENT(masm_);
  __ mov(output, source);
}

namespace detail {

template <typename Arg>
inline Register ToRegister(BaselineAssembler* basm,
                           BaselineAssembler::ScratchRegisterScope* scope,
                           Arg arg) {
  Register reg = scope->AcquireScratch();
  basm->Move(reg, arg);
  return reg;
}
inline Register ToRegister(BaselineAssembler* basm,
                           BaselineAssembler::ScratchRegisterScope* scope,
                           Register reg) {
  return reg;
}

template <typename... Args>
struct PushAllHelper;
template <>
struct PushAllHelper<> {
  static int Push(BaselineAssembler* basm) { return 0; }
  static int PushReverse(BaselineAssembler* basm) { return 0; }
};
// TODO(ishell): try to pack sequence of pushes into one instruction by
// looking at regiser codes. For example, Push(r1, r2, r5, r0, r3, r4)
// could be generated as two pushes: Push(r1, r2, r5) and Push(r0, r3, r4).
template <typename Arg>
struct PushAllHelper<Arg> {
  static int Push(BaselineAssembler* basm, Arg arg) {
    BaselineAssembler::ScratchRegisterScope scope(basm);
    basm->masm()->Push(ToRegister(basm, &scope, arg));
    return 1;
  }
  static int PushReverse(BaselineAssembler* basm, Arg arg) {
    return Push(basm, arg);
  }
};
// TODO(ishell): try to pack sequence of pushes into one instruction by
// looking at regiser codes. For example, Push(r1, r2, r5, r0, r3, r4)
// could be generated as two pushes: Push(r1, r2, r5) and Push(r0, r3, r4).
template <typename Arg, typename... Args>
struct PushAllHelper<Arg, Args...> {
  static int Push(BaselineAssembler* basm, Arg arg, Args... args) {
    PushAllHelper<Arg>::Push(basm, arg);
    return 1 + PushAllHelper<Args...>::Push(basm, args...);
  }
  static int PushReverse(BaselineAssembler* basm, Arg arg, Args... args) {
    int nargs = PushAllHelper<Args...>::PushReverse(basm, args...);
    PushAllHelper<Arg>::Push(basm, arg);
    return nargs + 1;
  }
};
template <>
struct PushAllHelper<interpreter::RegisterList> {
  static int Push(BaselineAssembler* basm, interpreter::RegisterList list) {
    for (int reg_index = 0; reg_index < list.register_count(); ++reg_index) {
      PushAllHelper<interpreter::Register>::Push(basm, list[reg_index]);
    }
    return list.register_count();
  }
  static int PushReverse(BaselineAssembler* basm,
                         interpreter::RegisterList list) {
    for (int reg_index = list.register_count() - 1; reg_index >= 0;
         --reg_index) {
      PushAllHelper<interpreter::Register>::Push(basm, list[reg_index]);
    }
    return list.register_count();
  }
};

template <typename... T>
struct PopAllHelper;
template <>
struct PopAllHelper<> {
  static void Pop(BaselineAssembler* basm) {}
};
// TODO(ishell): try to pack sequence of pops into one instruction by
// looking at regiser codes. For example, Pop(r1, r2, r5, r0, r3, r4)
// could be generated as two pops: Pop(r1, r2, r5) and Pop(r0, r3, r4).
template <>
struct PopAllHelper<Register> {
  static void Pop(BaselineAssembler* basm, Register reg) {
    basm->masm()->Pop(reg);
  }
};
template <typename... T>
struct PopAllHelper<Register, T...> {
  static void Pop(BaselineAssembler* basm, Register reg, T... tail) {
    PopAllHelper<Register>::Pop(basm, reg);
    PopAllHelper<T...>::Pop(basm, tail...);
  }
};

}  // namespace detail

template <typename... T>
int BaselineAssembler::Push(T... vals) {
  return detail::PushAllHelper<T...>::Push(this, vals...);
}

template <typename... T>
void BaselineAssembler::PushReverse(T... vals) {
  detail::PushAllHelper<T...>::PushReverse(this, vals...);
}

template <typename... T>
void BaselineAssembler::Pop(T... registers) {
  detail::PopAllHelper<T...>::Pop(this, registers...);
}

void BaselineAssembler::LoadTaggedField(Register output, Register source,
                                        int offset) {
  ASM_CODE_COMMENT(masm_);
  __ LoadTaggedField(output, FieldMemOperand(source, offset), r0);
}

void BaselineAssembler::LoadTaggedSignedField(Register output, Register source,
                                              int offset) {
  ASM_CODE_COMMENT(masm_);
  __ LoadTaggedSignedField(output, FieldMemOperand(source, offset));
}

void BaselineAssembler::LoadTaggedSignedFieldAndUntag(Register output,
                                                      Register source,
                                                      int offset) {
  LoadTaggedSignedField(output, source, offset);
  SmiUntag(output);
}

void BaselineAssembler::LoadWord16FieldZeroExtend(Register output,
                                                  Register source, int offset) {
  ASM_CODE_COMMENT(masm_);
  __ LoadU16(output, FieldMemOperand(source, offset));
}

void BaselineAssembler::LoadWord8Field(Register output, Register source,
                                       int offset) {
  ASM_CODE_COMMENT(masm_);
  __ LoadU8(output, FieldMemOperand(source, offset));
}

void BaselineAssembler::StoreTaggedSignedField(Register target, int offset,
                                               Tagged<Smi> value) {
  ASM_CODE_COMMENT(masm_);
  ScratchRegisterScope temps(this);
  Register tmp = temps.AcquireScratch();
  __ LoadSmiLiteral(tmp, value);
  __ StoreTaggedField(tmp, FieldMemOperand(target, offset), r0);
}

void BaselineAssembler::StoreTaggedFieldWithWriteBarrier(Register target,
                                                         int offset,
                                                         Register value) {
  ASM_CODE_COMMENT(masm_);
  Register scratch = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(target, value, scratch));
  __ StoreTaggedField(value, FieldMemOperand(target, offset), r0);
  __ RecordWriteField(target, offset, value, scratch, kLRHasNotBeenSaved,
                      SaveFPRegsMode::kIgnore);
}

void BaselineAssembler::StoreTaggedFieldNoWriteBarrier(Register target,
                                                       int offset,
                                                       Register value) {
  __ StoreTaggedField(value, FieldMemOperand(target, offset), r0);
}

void BaselineAssembler::TryLoadOptimizedOsrCode(Register scratch_and_result,
                                                Register feedback_vector,
                                                FeedbackSlot slot,
                                                Label* on_result,
                                                Label::Distance) {
  Label fallthrough;
  LoadTaggedField(scratch_and_result, feedback_vector,
                  FeedbackVector::OffsetOfElementAt(slot.ToInt()));
  __ LoadWeakValue(scratch_and_result, scratch_and_result, &fallthrough);

  // Is it marked_for_deoptimization? If yes, clear the slot.
  {
    ScratchRegisterScope temps(this);

    // The entry references a CodeWrapper object. Unwrap it now.
    __ LoadTaggedField(
        scratch_and_result,
        FieldMemOperand(scratch_and_result, CodeWrapper::kCodeOffset));

    Register scratch = temps.AcquireScratch();
    __ TestCodeIsMarkedForDeoptimization(scratch_and_result, scratch);
    __ beq(on_result);
    __ mov(scratch, __ ClearedValue());
    StoreTaggedFieldNoWriteBarrier(
        feedback_vector, FeedbackVector::OffsetOfElementAt(slot.ToInt()),
        scratch);
  }

  __ bind(&fallthrough);
  Move(scratch_and_result, 0);
}

void BaselineAssembler::AddToInterruptBudgetAndJumpIfNotExceeded(
    int32_t weight, Label* skip_interrupt_label) {
  ASM_CODE_COMMENT(masm_);
  ScratchRegisterScope scratch_scope(this);
  Register feedback_cell = scratch_scope.AcquireScratch();
  LoadFeedbackCell(feedback_cell);

  Register interrupt_budget = scratch_scope.AcquireScratch();
  __ LoadU32(
      interrupt_budget,
      FieldMemOperand(feedback_cell, FeedbackCell::kInterruptBudgetOffset));
  // Remember to set flags as part of the add!
  __ AddS32(interrupt_budget, Operand(weight));
  __ StoreU32(
      interrupt_budget,
      FieldMemOperand(feedback_cell, FeedbackCell::kInterruptBudgetOffset), r0);
  if (skip_interrupt_label) {
    // Use compare flags set by add
    DCHECK_LT(weight, 0);
    __ b(ge, skip_interrupt_label);
  }
}

void BaselineAssembler::AddToInterruptBudgetAndJumpIfNotExceeded(
    Register weight, Label* skip_interrupt_label) {
  ASM_CODE_COMMENT(masm_);
  ScratchRegisterScope scratch_scope(this);
  Register feedback_cell = scratch_scope.AcquireScratch();
  LoadFeedbackCell(feedback_cell);

  Register interrupt_budget = scratch_scope.AcquireScratch();
  __ LoadU32(
      interrupt_budget,
      FieldMemOperand(feedback_cell, FeedbackCell::kInterruptBudgetOffset));
  // Remember to set flags as part of the add!
  __ AddS32(interrupt_budget, interrupt_budget, weight);
  __ StoreU32(
      interrupt_budget,
      FieldMemOperand(feedback_cell, FeedbackCell::kInterruptBudgetOffset));
  if (skip_interrupt_label) __ b(ge, skip_interrupt_label);
}

void BaselineAssembler::LdaContextSlot(Register context, uint32_t index,
                                       uint32_t depth,
                                       CompressionMode compression_mode) {
  for (; depth > 0; --depth) {
    LoadTaggedField(context, context, Context::kPreviousOffset);
  }
  LoadTaggedField(kInterpreterAccumulatorRegister, context,
                  Context::OffsetOfElementAt(index));
}

void BaselineAssembler::StaContextSlot(Register context, Register value,
                                       uint32_t index, uint32_t depth) {
  for (; depth > 0; --depth) {
    LoadTaggedField(context, context, Context::kPreviousOffset);
  }
  StoreTaggedFieldWithWriteBarrier(context, Context::OffsetOfElementAt(index),
                                   value);
}

void BaselineAssembler::LdaModuleVariable(Register context, int cell_index,
                                          uint32_t depth) {
  for (; depth > 0; --depth) {
    LoadTaggedField(context, context, Context::kPreviousOffset);
  }
  LoadTaggedField(context, context, Context::kExtensionOffset);
  if (cell_index > 0) {
    LoadTaggedField(context, context, SourceTextModule::kRegularExportsOffset);
    // The actual array index is (cell_index - 1).
    cell_index -= 1;
  } else {
    LoadTaggedField(context, context, SourceTextModule::kRegularImportsOffset);
    // The actual array index is (-cell_index - 1).
    cell_index = -cell_index - 1;
  }
  LoadFixedArrayElement(context, context, cell_index);
  LoadTaggedField(kInterpreterAccumulatorRegister, context, Cell::kValueOffset);
}

void BaselineAssembler::StaModuleVariable(Register context, Register value,
                                          int cell_index, uint32_t depth) {
  for (; depth > 0; --depth) {
    LoadTaggedField(context, context, Context::kPreviousOffset);
  }
  LoadTaggedField(context, context, Context::kExtensionOffset);
  LoadTaggedField(context, context, SourceTextModule::kRegularExportsOffset);

  // The actual array index is (cell_index - 1).
  cell_index -= 1;
  LoadFixedArrayElement(context, context, cell_index);
  StoreTaggedFieldWithWriteBarrier(context, Cell::kValueOffset, value);
}

void BaselineAssembler::IncrementSmi(MemOperand lhs) {
  Register scratch = ip;
  if (SmiValuesAre31Bits()) {
    DCHECK(COMPRESS_POINTERS_BOOL);
    DCHECK(lhs.rb() == fp || lhs.rx() == fp);
    MemOperand addr = MemOperand(lhs.rx(), lhs.rb(), lhs.offset() + stack_bias);
    __ LoadS32(scratch, addr);
    __ AddU32(scratch, Operand(Smi::FromInt(1)));
    __ StoreU32(scratch, addr);
  } else {
    __ SmiUntag(scratch, lhs);
    __ AddU64(scratch, Operand(1));
    __ SmiTag(scratch);
    __ StoreU64(scratch, lhs);
  }
}

void BaselineAssembler::Word32And(Register output, Register lhs, int rhs) {
  __ AndP(output, lhs, Operand(rhs));
}

void BaselineAssembler::Switch(Register reg, int case_value_base,
                               Label** labels, int num_labels) {
  ASM_CODE_COMMENT(masm_);
  Label fallthrough, jump_table;
  if (case_value_base != 0) {
    __ AddS64(reg, Operand(-case_value_base));
  }

  // Mostly copied from code-generator-arm.cc
  ScratchRegisterScope scope(this);
  JumpIf(kUnsignedGreaterThanEqual, reg, Operand(num_labels), &fallthrough);
  // Ensure to emit the constant pool first if necessary.
  int entry_size_log2 = 3;
  __ ShiftLeftU32(reg, reg, Operand(entry_size_log2));
  __ larl(r1, &jump_table);
  __ lay(reg, MemOperand(reg, r1));
  __ b(reg);
  __ b(&fallthrough);
  __ bind(&jump_table);
  for (int i = 0; i < num_labels; ++i) {
    __ b(labels[i], Label::kFar);
    __ nop();
  }
  __ bind(&fallthrough);
}

#undef __

#define __ basm.

void BaselineAssembler::EmitReturn(MacroAssembler* masm) {
  ASM_CODE_COMMENT(masm);
  BaselineAssembler basm(masm);

  Register weight = BaselineLeaveFrameDescriptor::WeightRegister();
  Register params_size = BaselineLeaveFrameDescriptor::ParamsSizeRegister();

  {
    ASM_CODE_COMMENT_STRING(masm, "Update Interrupt Budget");

    Label skip_interrupt_label;
    __ AddToInterruptBudgetAndJumpIfNotExceeded(weight, &skip_interrupt_label);
    {
      __ masm()->SmiTag(params_size);
      __ Push(params_size, kInterpreterAccumulatorRegister);

      __ LoadContext(kContextRegister);
      __ LoadFunction(kJSFunctionRegister);
      __ Push(kJSFunctionRegister);
      __ CallRuntime(Runtime::kBytecodeBudgetInterrupt_Sparkplug, 1);

      __ Pop(kInterpreterAccumulatorRegister, params_size);
      __ masm()->SmiUntag(params_size);
    }

    __ Bind(&skip_interrupt_label);
  }

  BaselineAssembler::ScratchRegisterScope temps(&basm);
  Register actual_params_size = temps.AcquireScratch();
  // Compute the size of the actual parameters + receiver.
  __ Move(actual_params_size,
          MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  Label corrected_args_count;
  JumpIfHelper(__ masm(), kGreaterThanEqual, params_size, actual_params_size,
               &corrected_args_count);
  __ masm()->mov(params_size, actual_params_size);
  __ Bind(&corrected_args_count);

  // Leave the frame (also dropping the register file).
  __ masm()->LeaveFrame(StackFrame::BASELINE);

  // Drop receiver + arguments.
  __ masm() -> DropArguments(params_size);
  __ masm()->Ret();
}

#undef __

inline void EnsureAccumulatorPreservedScope::AssertEqualToAccumulator(
    Register reg) {
  if (COMPRESS_POINTERS_BOOL) {
    assembler_->masm()->CmpU32(reg, kInterpreterAccumulatorRegister);
  } else {
    assembler_->masm()->CmpU64(reg, kInterpreterAccumulatorRegister);
  }
  assembler_->masm()->Assert(eq, AbortReason::kAccumulatorClobbered);
}

}  // namespace baseline
}  // namespace internal
}  // namespace v8

#endif  // V8_BASELINE_S390_BASELINE_ASSEMBLER_S390_INL_H_

"""

```