Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/mips64/macro-assembler-mips64.cc`. The summary should cover:

1. **General Functionality**: What does this code do?
2. **Torque Source**: Is it a Torque file (ends with `.tq`)?
3. **JavaScript Relationship**: How does it relate to JavaScript (with examples)?
4. **Code Logic Inference**:  Provide an example of input/output for a code snippet.
5. **Common Programming Errors**:  Illustrate potential errors users might make.
6. **Overall Function Summary**:  A concise summary of its purpose.

Let's break down the code snippet and address each point:

* **Memory Access (`Load`, `Store`, `MemOperand`)**:  The code has functions to load and store data from memory, constructing memory operands.
* **Control Flow (`Jump`, `Call`, `Ret`, `Branch`)**:  It contains functions for unconditional and conditional jumps, calls, returns, and branches, including long jumps.
* **Builtin Calls (`CallBuiltin`, `TailCallBuiltin`)**: It has mechanisms to call built-in V8 functions.
* **Stack Manipulation (`Push`, `Pop`, `DropArguments`)**:  Functions to manipulate the stack, including pushing arguments, popping values, and dropping arguments.
* **Exception Handling (`PushStackHandler`, `PopStackHandler`)**:  Code for setting up and tearing down stack handlers for exception management.
* **Floating-Point Operations (`FPUCanonicalizeNaN`, `MovFromFloatResult`, etc.)**: Functions for handling floating-point values, especially related to calling conventions.
* **JavaScript Invocation (`InvokePrologue`, `InvokeFunctionCode`, etc.)**:  Complex logic for invoking JavaScript functions, handling argument counts, and debugger hooks.
* **Runtime Calls (`CallRuntime`, `TailCallRuntime`)**:  Functions to call into the V8 runtime.
* **Specific Instructions (`li`, `mov`, `add`, `sub`, etc.)**:  Low-level MIPS64 instructions are used throughout.

Now let's formulate the answers for each point:

1. **General Functionality**: The code defines a `MacroAssembler` class for the MIPS64 architecture in V8. It provides an abstraction layer over raw assembly instructions, offering higher-level functions for common code generation tasks.

2. **Torque Source**: The filename ends with `.cc`, not `.tq`, so it's C++.

3. **JavaScript Relationship**: This code is crucial for executing JavaScript. When V8 compiles JavaScript code, it uses the `MacroAssembler` to generate the actual machine code that runs on the MIPS64 processor. The `InvokeFunction` family of functions directly relates to how JavaScript function calls are handled.

4. **Code Logic Inference**:  Consider the `JumpIfIsInRange` function. We can provide example inputs and the expected output based on its logic.

5. **Common Programming Errors**:  The usage of stack manipulation functions can lead to errors if not managed correctly.

6. **Overall Function Summary**: This part of the `MacroAssembler` for MIPS64 in V8 focuses on providing high-level abstractions for generating machine code related to function calls, control flow, memory access, and interaction with the V8 runtime, which are all fundamental to executing JavaScript.
This code snippet is a part of the `MacroAssembler` class implementation for the MIPS64 architecture within the V8 JavaScript engine. It provides higher-level building blocks for generating MIPS64 assembly instructions, making it easier for V8's compiler to produce efficient machine code.

Here's a breakdown of its functionalities within this specific snippet:

**General Functionality:**

* **Loading Constants:**  The `LoadConstant` family of functions provides ways to load various types of constants (handles, external references, integers) into registers, potentially using scratch registers for intermediate steps.
* **Jumping and Calling:** The `Jump` and `Call` families of functions implement different ways to transfer control flow. This includes:
    * **Direct Jumps/Calls:** Jumping or calling to a register, immediate address, or a label within the current code.
    * **Conditional Jumps/Calls:**  Executing jumps or calls based on the result of a condition.
    * **Tail Calls:**  Optimized calls that don't require a new stack frame.
    * **Calls to Built-ins:**  Specialized functions for calling V8's built-in JavaScript functions.
* **Branching:**  The `Branch` and `BranchLong` functions provide mechanisms for conditional jumps based on comparisons between registers and operands.
* **Stack Manipulation:** Functions like `Push`, `Pop`, `DropArguments`, and `DropAndRet` manage the call stack by pushing and popping values and adjusting the stack pointer.
* **Exception Handling:** The `PushStackHandler` and `PopStackHandler` functions are used to set up and tear down stack frames for handling exceptions.
* **Floating-Point Support:**  Functions like `FPUCanonicalizeNaN`, `MovFromFloatResult`, `MovToFloatParameter`, etc., handle the movement and manipulation of floating-point values, especially in the context of function calls and returns.
* **JavaScript Invocation:**  The `InvokePrologue`, `InvokeFunctionCode`, `InvokeFunctionWithNewTarget`, and `InvokeFunction` functions encapsulate the complex logic for calling JavaScript functions, including argument handling, debugger hooks, and handling different call types.
* **Runtime Calls:** The `CallRuntime` and `TailCallRuntime` functions provide a way to call into V8's runtime system for operations that cannot be directly implemented in assembly.
* **Overflow Checking:**  Functions like `DaddOverflow`, `DsubOverflow`, `MulOverflow`, and `DMulOverflow` perform arithmetic operations and detect potential overflow conditions.

**Is it a Torque Source?**

No, `v8/src/codegen/mips64/macro-assembler-mips64.cc` ends with `.cc`, indicating it's a **C++** source file, not a Torque (`.tq`) file. Torque is a higher-level language used within V8 for generating code, and often results in C++ code like this.

**Relationship with JavaScript and Examples:**

This code directly enables the execution of JavaScript code. When V8 compiles JavaScript, it uses the `MacroAssembler` to generate the low-level MIPS64 instructions that the processor can understand.

Here are some examples of how the functions in this snippet relate to JavaScript functionality:

* **Function Calls:**  The `InvokeFunction` family of functions is directly responsible for executing JavaScript function calls. For example, when you call a function in JavaScript:

   ```javascript
   function myFunction(a, b) {
     return a + b;
   }
   myFunction(5, 10);
   ```

   V8's compiler will use functions like `InvokeFunction` in the `MacroAssembler` to generate the MIPS64 instructions to:
    * Set up the stack frame.
    * Pass arguments (`5` and `10`).
    * Call the compiled code for `myFunction`.
    * Handle the return value.

* **Arithmetic Operations:** When JavaScript performs arithmetic operations like `a + b`, the compiler might use functions like `DaddOverflow` to generate the MIPS64 instructions for addition, while also checking for potential integer overflow.

* **Control Flow (if/else, loops):**  JavaScript's `if` statements and loops are translated into conditional jumps and branches using functions like `Branch` and `Jump`.

   ```javascript
   let x = 5;
   if (x > 0) {
     console.log("Positive");
   }
   ```

   The `if (x > 0)` condition would likely involve a comparison instruction and a conditional jump instruction generated using `Branch`.

* **Built-in Functions:** When you call a built-in JavaScript function like `Math.abs(-5)`, the `CallBuiltin` function in the `MacroAssembler` is used to call the pre-compiled code for that built-in function.

**Code Logic Inference (Example):**

Let's consider the `JumpIfIsInRange` function:

```c++
void MacroAssembler::JumpIfIsInRange(Register value, unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  ASM_CODE_COMMENT(this);
  if (lower_limit != 0) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Dsubu(scratch, value, Operand(lower_limit));
    Branch(on_in_range, ls, scratch, Operand(higher_limit - lower_limit));
  } else {
    Branch(on_in_range, ls, value, Operand(higher_limit - lower_limit));
  }
}
```

**Assumptions:**

* `value` register holds an unsigned integer.
* `lower_limit` and `higher_limit` are unsigned integer constants.
* `on_in_range` is a label to jump to if `value` is within the inclusive range [`lower_limit`, `higher_limit`].

**Scenario 1: `lower_limit` is not 0**

* **Input:**
    * `value` register contains the value `10`.
    * `lower_limit` is `5`.
    * `higher_limit` is `15`.
* **Output:** The code will:
    1. Subtract `lower_limit` (5) from `value` (10) and store the result (5) in a scratch register.
    2. Compare the scratch register (5) with `higher_limit - lower_limit` (15 - 5 = 10) using the "less than or same" (`ls`) condition.
    3. Since 5 is less than or the same as 10, the code will **jump** to the `on_in_range` label.

**Scenario 2: `lower_limit` is 0**

* **Input:**
    * `value` register contains the value `8`.
    * `lower_limit` is `0`.
    * `higher_limit` is `12`.
* **Output:** The code will:
    1. Directly compare `value` (8) with `higher_limit - lower_limit` (12 - 0 = 12) using the "less than or same" (`ls`) condition.
    2. Since 8 is less than or the same as 12, the code will **jump** to the `on_in_range` label.

**Common Programming Errors (Illustrative):**

* **Incorrect Stack Management:**  Manually manipulating the stack (using `Push`, `Pop`, `DropArguments`) requires careful attention. Forgetting to pop values or dropping too many arguments can lead to stack corruption and crashes.

   ```c++
   // Example of a potential error:
   void MyIncorrectFunction(MacroAssembler* masm) {
     Register arg1 = a0;
     Register temp = t0;
     masm->push(arg1); // Push an argument onto the stack
     // ... some operations ...
     // Forgot to pop the value before returning!
     masm->Ret();
   }
   ```
   This would leave an extra value on the stack, potentially causing issues for the caller.

* **Incorrect Register Usage:**  Many MIPS64 instructions have specific register requirements or conventions. Using the wrong register for an operation can lead to unexpected results.

* **Off-by-One Errors in Loops:** When pushing or popping multiple values in a loop, incorrect loop bounds can lead to pushing/popping the wrong number of elements.

* **Condition Code Errors:** Using the wrong condition code in a `Branch` instruction will cause the jump to occur under incorrect circumstances. For instance, using `eq` (equal) when you intended `ne` (not equal).

**归纳一下它的功能 (Summary of Functionality):**

This portion of `v8/src/codegen/mips64/macro-assembler-mips64.cc` provides the building blocks for generating MIPS64 assembly code within the V8 engine. It offers abstractions for common tasks like loading constants, controlling program flow (jumps, calls, branches), managing the stack, handling exceptions, supporting floating-point operations, and, crucially, implementing the complex logic required for invoking JavaScript functions and interacting with the V8 runtime environment. It's a fundamental component in enabling the execution of JavaScript code on MIPS64 architectures.

### 提示词
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
RootRegisterOffsetForExternalReferenceTableEntry(
                                   isolate(), reference)));
        return MemOperand(scratch, 0);
      }
    }
  }
  DCHECK(scratch.is_valid());
  li(scratch, reference);
  return MemOperand(scratch, 0);
}

void MacroAssembler::Jump(Register target, Condition cond, Register rs,
                          const Operand& rt, BranchDelaySlot bd) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (kArchVariant == kMips64r6 && bd == PROTECT) {
    if (cond == cc_always) {
      jic(target, 0);
    } else {
      BRANCH_ARGS_CHECK(cond, rs, rt);
      Branch(2, NegateCondition(cond), rs, rt);
      jic(target, 0);
    }
  } else {
    if (cond == cc_always) {
      jr(target);
    } else {
      BRANCH_ARGS_CHECK(cond, rs, rt);
      Branch(2, NegateCondition(cond), rs, rt);
      jr(target);
    }
    // Emit a nop in the branch delay slot if required.
    if (bd == PROTECT) nop();
  }
}

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond, Register rs, const Operand& rt,
                          BranchDelaySlot bd) {
  Label skip;
  if (cond != cc_always) {
    Branch(USE_DELAY_SLOT, &skip, NegateCondition(cond), rs, rt);
  }
  // The first instruction of 'li' may be placed in the delay slot.
  // This is not an issue, t9 is expected to be clobbered anyway.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    li(t9, Operand(target, rmode));
    Jump(t9, al, zero_reg, Operand(zero_reg), bd);
    bind(&skip);
  }
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode, Condition cond,
                          Register rs, const Operand& rt, BranchDelaySlot bd) {
  DCHECK(!RelocInfo::IsCodeTarget(rmode));
  Jump(static_cast<intptr_t>(target), rmode, cond, rs, rt, bd);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, Register rs, const Operand& rt,
                          BranchDelaySlot bd) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Label skip;
  if (cond != cc_always) {
    BranchShort(&skip, NegateCondition(cond), rs, rt);
  }

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    TailCallBuiltin(builtin);
    bind(&skip);
    return;
  }

  Jump(static_cast<intptr_t>(code.address()), rmode, cc_always, rs, rt, bd);
  bind(&skip);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  li(t9, reference);
  Jump(t9);
}

// Note: To call gcc-compiled C code on mips, you must call through t9.
void MacroAssembler::Call(Register target, Condition cond, Register rs,
                          const Operand& rt, BranchDelaySlot bd) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (kArchVariant == kMips64r6 && bd == PROTECT) {
    if (cond == cc_always) {
      jialc(target, 0);
    } else {
      BRANCH_ARGS_CHECK(cond, rs, rt);
      Branch(2, NegateCondition(cond), rs, rt);
      jialc(target, 0);
    }
  } else {
    if (cond == cc_always) {
      jalr(target);
    } else {
      BRANCH_ARGS_CHECK(cond, rs, rt);
      Branch(2, NegateCondition(cond), rs, rt);
      jalr(target);
    }
    // Emit a nop in the branch delay slot if required.
    if (bd == PROTECT) nop();
  }
  set_pc_for_safepoint();
}

void MacroAssembler::JumpIfIsInRange(Register value, unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  ASM_CODE_COMMENT(this);
  if (lower_limit != 0) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Dsubu(scratch, value, Operand(lower_limit));
    Branch(on_in_range, ls, scratch, Operand(higher_limit - lower_limit));
  } else {
    Branch(on_in_range, ls, value, Operand(higher_limit - lower_limit));
  }
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode, Condition cond,
                          Register rs, const Operand& rt, BranchDelaySlot bd) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  li(t9, Operand(static_cast<int64_t>(target), rmode), ADDRESS_LOAD);
  Call(t9, cond, rs, rt, bd);
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, Register rs, const Operand& rt,
                          BranchDelaySlot bd) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  Call(code.address(), rmode, cond, rs, rt, bd);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  ASM_CODE_COMMENT(this);
  static_assert(kSystemPointerSize == 8);
  static_assert(kSmiTagSize == 1);
  static_assert(kSmiTag == 0);

  // The builtin_index register contains the builtin index as a Smi.
  SmiUntag(target, builtin_index);
  Dlsa(target, kRootRegister, target, kSystemPointerSizeLog2);
  Ld(target, MemOperand(target, IsolateData::builtin_entry_table_offset()));
}
void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  Ld(destination, EntryFromBuiltinAsOperand(builtin));
}
MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  ASM_CODE_COMMENT(this);
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}
void MacroAssembler::CallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  Register temp = t9;
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(temp);
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Call(temp);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      IndirectLoadConstant(temp, code);
      CallCodeObject(temp, kJSEntrypointTag);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      // Short builtin calls is unsupported in mips64.
      UNREACHABLE();
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond,
                                     Register type, Operand range) {
  if (cond != cc_always) {
    Label done;
    Branch(&done, NegateCondition(cond), type, range);
    TailCallBuiltin(builtin);
    bind(&done);
  } else {
    TailCallBuiltin(builtin);
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  Register temp = t9;

  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Jump(temp);
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Jump(temp);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      IndirectLoadConstant(temp, code);
      JumpCodeObject(temp, kJSEntrypointTag);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
  }
}

void MacroAssembler::PatchAndJump(Address target) {
  if (kArchVariant != kMips64r6) {
    ASM_CODE_COMMENT(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    mov(scratch, ra);
    bal(1);                                  // jump to ld
    nop();                                   // in the delay slot
    ld(t9, MemOperand(ra, kInstrSize * 3));  // ra == pc_
    jr(t9);
    mov(ra, scratch);  // in delay slot
    DCHECK_EQ(reinterpret_cast<uint64_t>(pc_) % 8, 0);
    *reinterpret_cast<uint64_t*>(pc_) = target;  // pc_ should be align.
    pc_ += sizeof(uint64_t);
  } else {
    // TODO(mips r6): Implement.
    UNIMPLEMENTED();
  }
}

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  ASM_CODE_COMMENT(this);
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

  // Compute the return address in lr to return to after the jump below. The pc
  // is already at '+ 8' from the current instruction; but return is after three
  // instructions, so add another 4 to pc to get the return address.

  Assembler::BlockTrampolinePoolScope block_trampoline_pool(this);
  static constexpr int kNumInstructionsToJump = 4;
  Label find_ra;
  // Adjust the value in ra to point to the correct return location, 2nd
  // instruction past the real call into C code (the jalr(t9)), and push it.
  // This is the return address of the exit frame.
  if (kArchVariant >= kMips64r6) {
    addiupc(ra, kNumInstructionsToJump + 1);
  } else {
    // This no-op-and-link sequence saves PC + 8 in ra register on pre-r6 MIPS
    nal();  // nal has branch delay slot.
    Daddu(ra, ra, kNumInstructionsToJump * kInstrSize);
  }
  bind(&find_ra);

  // This spot was reserved in EnterExitFrame.
  Sd(ra, MemOperand(sp));
  // Stack space reservation moved to the branch delay slot below.
  // Stack is still aligned.

  // Call the C routine.
  mov(t9, target);  // Function pointer to t9 to conform to ABI for PIC.
  jalr(t9);
  // Set up sp in the delay slot.
  daddiu(sp, sp, -kCArgsSlotsSize);
  // Make sure the stored 'ra' points to this position.
  DCHECK_EQ(kNumInstructionsToJump, InstructionsGeneratedSince(&find_ra));
}

void MacroAssembler::Ret(Condition cond, Register rs, const Operand& rt,
                         BranchDelaySlot bd) {
  Jump(ra, cond, rs, rt, bd);
}

void MacroAssembler::BranchLong(Label* L, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT &&
      (!L->is_bound() || is_near_r6(L))) {
    BranchShortHelperR6(0, L);
  } else {
    // Generate position independent long branch.
    BlockTrampolinePoolScope block_trampoline_pool(this);
    int64_t imm64 = branch_long_offset(L);
    DCHECK(is_int32(imm64));
    int32_t imm32 = static_cast<int32_t>(imm64);
    or_(t8, ra, zero_reg);
    nal();                                        // Read PC into ra register.
    lui(t9, (imm32 & kHiMaskOf32) >> kLuiShift);  // Branch delay slot.
    ori(t9, t9, (imm32 & kImm16Mask));
    daddu(t9, ra, t9);
    if (bdslot == USE_DELAY_SLOT) {
      or_(ra, t8, zero_reg);
    }
    jr(t9);
    // Emit a or_ in the branch delay slot if it's protected.
    if (bdslot == PROTECT) or_(ra, t8, zero_reg);
  }
}

void MacroAssembler::BranchLong(int32_t offset, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT && (is_int26(offset))) {
    BranchShortHelperR6(offset, nullptr);
  } else {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    or_(t8, ra, zero_reg);
    nal();                                         // Read PC into ra register.
    lui(t9, (offset & kHiMaskOf32) >> kLuiShift);  // Branch delay slot.
    ori(t9, t9, (offset & kImm16Mask));
    daddu(t9, ra, t9);
    if (bdslot == USE_DELAY_SLOT) {
      or_(ra, t8, zero_reg);
    }
    jr(t9);
    // Emit a or_ in the branch delay slot if it's protected.
    if (bdslot == PROTECT) or_(ra, t8, zero_reg);
  }
}

void MacroAssembler::BranchAndLinkLong(Label* L, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT &&
      (!L->is_bound() || is_near_r6(L))) {
    BranchAndLinkShortHelperR6(0, L);
  } else {
    // Generate position independent long branch and link.
    BlockTrampolinePoolScope block_trampoline_pool(this);
    int64_t imm64 = branch_long_offset(L);
    DCHECK(is_int32(imm64));
    int32_t imm32 = static_cast<int32_t>(imm64);
    lui(t8, (imm32 & kHiMaskOf32) >> kLuiShift);
    nal();                              // Read PC into ra register.
    ori(t8, t8, (imm32 & kImm16Mask));  // Branch delay slot.
    daddu(t8, ra, t8);
    jalr(t8);
    // Emit a nop in the branch delay slot if required.
    if (bdslot == PROTECT) nop();
  }
}

void MacroAssembler::DropArguments(Register count) {
  Dlsa(sp, sp, count, kPointerSizeLog2);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

void MacroAssembler::DropAndRet(int drop) {
  int32_t drop_size = drop * kSystemPointerSize;
  DCHECK(is_int31(drop_size));

  if (is_int16(drop_size)) {
    Ret(USE_DELAY_SLOT);
    daddiu(sp, sp, drop_size);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, drop_size);
    Ret(USE_DELAY_SLOT);
    daddu(sp, sp, scratch);
  }
}

void MacroAssembler::DropAndRet(int drop, Condition cond, Register r1,
                                const Operand& r2) {
  // Both Drop and Ret need to be conditional.
  Label skip;
  if (cond != cc_always) {
    Branch(&skip, NegateCondition(cond), r1, r2);
  }

  Drop(drop);
  Ret();

  if (cond != cc_always) {
    bind(&skip);
  }
}

void MacroAssembler::Drop(int count, Condition cond, Register reg,
                          const Operand& op) {
  if (count <= 0) {
    return;
  }

  Label skip;

  if (cond != al) {
    Branch(&skip, NegateCondition(cond), reg, op);
  }

  Daddu(sp, sp, Operand(count * kPointerSize));

  if (cond != al) {
    bind(&skip);
  }
}

void MacroAssembler::Swap(Register reg1, Register reg2, Register scratch) {
  if (scratch == no_reg) {
    Xor(reg1, reg1, Operand(reg2));
    Xor(reg2, reg2, Operand(reg1));
    Xor(reg1, reg1, Operand(reg2));
  } else {
    mov(scratch, reg1);
    mov(reg1, reg2);
    mov(reg2, scratch);
  }
}

void MacroAssembler::Call(Label* target) { BranchAndLink(target); }

void MacroAssembler::LoadAddress(Register dst, Label* target) {
  uint64_t address = jump_address(target);
  li(dst, address);
}

void MacroAssembler::LoadAddressPCRelative(Register dst, Label* target) {
  ASM_CODE_COMMENT(this);
  nal();
  // daddiu could handle 16-bit pc offset.
  int32_t offset = branch_offset_helper(target, OffsetSize::kOffset16);
  DCHECK(is_int16(offset));
  mov(t8, ra);
  daddiu(dst, ra, offset);
  mov(ra, t8);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(smi));
  push(scratch);
}

void MacroAssembler::Push(Handle<HeapObject> handle) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(handle));
  push(scratch);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               Register scratch2, PushArrayOrder order) {
  DCHECK(!AreAliased(array, size, scratch, scratch2));
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    mov(scratch, zero_reg);
    jmp(&entry);
    bind(&loop);
    Dlsa(scratch2, array, scratch, kPointerSizeLog2);
    Ld(scratch2, MemOperand(scratch2));
    push(scratch2);
    Daddu(scratch, scratch, Operand(1));
    bind(&entry);
    Branch(&loop, less, scratch, Operand(size));
  } else {
    mov(scratch, size);
    jmp(&entry);
    bind(&loop);
    Dlsa(scratch2, array, scratch, kPointerSizeLog2);
    Ld(scratch2, MemOperand(scratch2));
    push(scratch2);
    bind(&entry);
    Daddu(scratch, scratch, Operand(-1));
    Branch(&loop, greater_equal, scratch, Operand(zero_reg));
  }
}

// ---------------------------------------------------------------------------
// Exception handling.

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kPointerSize);

  Push(Smi::zero());  // Padding.

  // Link the current handler as the next handler.
  li(t2,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  Ld(t1, MemOperand(t2));
  push(t1);

  // Set this new handler as the current one.
  Sd(sp, MemOperand(t2));
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kNextOffset == 0);
  pop(a1);
  Daddu(sp, sp,
        Operand(
            static_cast<int64_t>(StackHandlerConstants::kSize - kPointerSize)));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  Sd(a1, MemOperand(scratch));
}

void MacroAssembler::FPUCanonicalizeNaN(const DoubleRegister dst,
                                        const DoubleRegister src) {
  sub_d(dst, src, kDoubleRegZero);
}

void MacroAssembler::MovFromFloatResult(const DoubleRegister dst) {
  if (IsMipsSoftFloatABI) {
    if (kArchEndian == kLittle) {
      Move(dst, v0, v1);
    } else {
      Move(dst, v1, v0);
    }
  } else {
    Move(dst, f0);  // Reg f0 is o32 ABI FP return value.
  }
}

void MacroAssembler::MovFromFloatParameter(const DoubleRegister dst) {
  if (IsMipsSoftFloatABI) {
    if (kArchEndian == kLittle) {
      Move(dst, a0, a1);
    } else {
      Move(dst, a1, a0);
    }
  } else {
    Move(dst, f12);  // Reg f12 is n64 ABI FP first argument value.
  }
}

void MacroAssembler::MovToFloatParameter(DoubleRegister src) {
  if (!IsMipsSoftFloatABI) {
    Move(f12, src);
  } else {
    if (kArchEndian == kLittle) {
      Move(a0, a1, src);
    } else {
      Move(a1, a0, src);
    }
  }
}

void MacroAssembler::MovToFloatResult(DoubleRegister src) {
  if (!IsMipsSoftFloatABI) {
    Move(f0, src);
  } else {
    if (kArchEndian == kLittle) {
      Move(v0, v1, src);
    } else {
      Move(v1, v0, src);
    }
  }
}

void MacroAssembler::MovToFloatParameters(DoubleRegister src1,
                                          DoubleRegister src2) {
  if (!IsMipsSoftFloatABI) {
    const DoubleRegister fparg2 = f13;
    if (src2 == f12) {
      DCHECK(src1 != fparg2);
      Move(fparg2, src2);
      Move(f12, src1);
    } else {
      Move(f12, src1);
      Move(fparg2, src2);
    }
  } else {
    if (kArchEndian == kLittle) {
      Move(a0, a1, src1);
      Move(a2, a3, src2);
    } else {
      Move(a1, a0, src1);
      Move(a3, a2, src2);
    }
  }
}

// -----------------------------------------------------------------------------
// JavaScript invokes.

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();

  Ld(destination, MemOperand(kRootRegister, static_cast<int32_t>(offset)));
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch1,
                                        Register scratch2,
                                        Label* stack_overflow) {
  ASM_CODE_COMMENT(this);
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.

  LoadStackLimit(scratch1, StackLimitKind::kRealStackLimit);
  // Make scratch1 the space we have left. The stack might already be overflowed
  // here which will cause scratch1 to become negative.
  dsubu(scratch1, sp, scratch1);
  // Check if the arguments will overflow the stack.
  dsll(scratch2, num_args, kPointerSizeLog2);
  // Signed comparison.
  Branch(stack_overflow, le, scratch1, Operand(scratch2));
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadCodeEntrypointFromJSDispatchTable(
    Register destination, MemOperand field_operand) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  DCHECK(!AreAliased(destination, scratch));
  DCHECK_EQ(JSDispatchEntry::kEntrypointOffset, 0);

  li(scratch, ExternalReference::js_dispatch_table_address());
  Lwu(destination, field_operand);
  dsrl(destination, destination, kJSDispatchHandleShift);
  dsll(destination, destination, kJSDispatchTableEntrySizeLog2);
  Ld(destination, MemOperand(scratch, destination));
}
#endif

void MacroAssembler::TestCodeIsMarkedForDeoptimizationAndJump(
    Register code_data_container, Register scratch, Condition cond,
    Label* target) {
  Lwu(scratch, FieldMemOperand(code_data_container, Code::kFlagsOffset));
  And(scratch, scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
  Branch(target, cond, scratch, Operand(zero_reg));
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  ASM_CODE_COMMENT(this);
  Label regular_invoke;

  //  a0: actual arguments count
  //  a1: function (passed through to callee)
  //  a2: expected arguments count

  DCHECK_EQ(actual_parameter_count, a0);
  DCHECK_EQ(expected_parameter_count, a2);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  Dsubu(expected_parameter_count, expected_parameter_count,
        actual_parameter_count);
  Branch(&regular_invoke, le, expected_parameter_count, Operand(zero_reg));

  Label stack_overflow;
  StackOverflowCheck(expected_parameter_count, t0, t1, &stack_overflow);
  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy;
    Register src = a6, dest = a7;
    mov(src, sp);
    dsll(t0, expected_parameter_count, kSystemPointerSizeLog2);
    Dsubu(sp, sp, Operand(t0));
    // Update stack pointer.
    mov(dest, sp);
    mov(t0, actual_parameter_count);
    bind(&copy);
    Ld(t1, MemOperand(src, 0));
    Sd(t1, MemOperand(dest, 0));
    Dsubu(t0, t0, Operand(1));
    Daddu(src, src, Operand(kSystemPointerSize));
    Daddu(dest, dest, Operand(kSystemPointerSize));
    Branch(&copy, gt, t0, Operand(zero_reg));
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(t0, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    Sd(t0, MemOperand(a7, 0));
    Dsubu(expected_parameter_count, expected_parameter_count, Operand(1));
    Daddu(a7, a7, Operand(kSystemPointerSize));
    Branch(&loop, gt, expected_parameter_count, Operand(zero_reg));
  }
  b(&regular_invoke);
  nop();

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    break_(0xCC);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CheckDebugHook(Register fun, Register new_target,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count) {
  Label skip_hook;

  li(t0, ExternalReference::debug_hook_on_function_call_address(isolate()));
  Lb(t0, MemOperand(t0));
  Branch(&skip_hook, eq, t0, Operand(zero_reg));

  {
    // Load receiver to pass it later to DebugOnFunctionCall hook.
    LoadReceiver(t0);

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
    Push(t0);
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
  bind(&skip_hook);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, a1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == a3);

  // On function call, call into the debugger if necessary.
  CheckDebugHook(function, new_target, expected_parameter_count,
                 actual_parameter_count);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(a3, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }

  // Continue here if InvokePrologue does handle the invocation due to
  // mismatched parameter counts.
  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);
  Register expected_parameter_count = a2;
  Register temp_reg = t0;
  Ld(temp_reg, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  Ld(cp, FieldMemOperand(a1, JSFunction::kContextOffset));
  // The argument count is stored as uint16_t
  Lhu(expected_parameter_count,
      FieldMemOperand(temp_reg,
                      SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(a1, new_target, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);

  // Get the function and setup the context.
  Ld(cp, FieldMemOperand(a1, JSFunction::kContextOffset));

  InvokeFunctionCode(a1, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}

// ---------------------------------------------------------------------------
// Support functions.

void MacroAssembler::GetObjectType(Register object, Register map,
                                   Register type_reg) {
  LoadMap(map, object);
  Lhu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
}

void MacroAssembler::GetInstanceTypeRange(Register map, Register type_reg,
                                          InstanceType lower_limit,
                                          Register range) {
  Lhu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  Dsubu(range, type_reg, Operand(lower_limit));
}

// -----------------------------------------------------------------------------
// Runtime calls.

void MacroAssembler::DaddOverflow(Register dst, Register left,
                                  const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = t8;
  if (!right.is_reg()) {
    li(at, Operand(right));
    right_reg = at;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch && right_reg != scratch && dst != scratch &&
         overflow != scratch);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    daddu(scratch, left, right_reg);
    xor_(overflow, scratch, left);
    xor_(at, scratch, right_reg);
    and_(overflow, overflow, at);
    mov(dst, scratch);
  } else {
    daddu(dst, left, right_reg);
    xor_(overflow, dst, left);
    xor_(at, dst, right_reg);
    and_(overflow, overflow, at);
  }
}

void MacroAssembler::DsubOverflow(Register dst, Register left,
                                  const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = t8;
  if (!right.is_reg()) {
    li(at, Operand(right));
    right_reg = at;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch && right_reg != scratch && dst != scratch &&
         overflow != scratch);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    dsubu(scratch, left, right_reg);
    xor_(overflow, left, scratch);
    xor_(at, left, right_reg);
    and_(overflow, overflow, at);
    mov(dst, scratch);
  } else {
    dsubu(dst, left, right_reg);
    xor_(overflow, left, dst);
    xor_(at, left, right_reg);
    and_(overflow, overflow, at);
  }
}

void MacroAssembler::MulOverflow(Register dst, Register left,
                                 const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = t8;
  if (!right.is_reg()) {
    li(at, Operand(right));
    right_reg = at;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch && right_reg != scratch && dst != scratch &&
         overflow != scratch);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Mul(scratch, left, right_reg);
    Mulh(overflow, left, right_reg);
    mov(dst, scratch);
  } else {
    Mul(dst, left, right_reg);
    Mulh(overflow, left, right_reg);
  }

  dsra32(scratch, dst, 0);
  xor_(overflow, overflow, scratch);
}

void MacroAssembler::DMulOverflow(Register dst, Register left,
                                  const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = t8;
  if (!right.is_reg()) {
    li(at, Operand(right));
    right_reg = at;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch && right_reg != scratch && dst != scratch &&
         overflow != scratch);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Dmul(scratch, left, right_reg);
    Dmulh(overflow, left, right_reg);
    mov(dst, scratch);
  } else {
    Dmul(dst, left, right_reg);
    Dmulh(overflow, left, right_reg);
  }

  dsra32(scratch, dst, 31);
  xor_(overflow, overflow, scratch);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // All parameters are on the stack. v0 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  PrepareCEntryArgs(num_arguments);
  PrepareCEntryFunction(ExternalReference::Create(f));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  ASM_CODE_COMMENT(this);
  cons
```