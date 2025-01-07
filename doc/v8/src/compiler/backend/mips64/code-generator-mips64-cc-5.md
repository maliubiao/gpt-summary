Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Context:** The first step is to recognize the file path: `v8/src/compiler/backend/mips64/code-generator-mips64.cc`. This immediately tells us we're dealing with the code generation phase of the V8 compiler, specifically for the MIPS64 architecture. The `.cc` extension confirms it's C++ code.

2. **Identify the Core Class:** The code clearly defines methods within the `CodeGenerator` class. This is the central entity we need to focus on.

3. **Analyze Method by Method (High-Level):**  Go through the provided code, identifying the purpose of each function based on its name and the operations it performs. Look for keywords and common patterns:

    * `AssembleReturn`:  Likely handles the function return process.
    * `Push`, `Pop`:  Related to stack manipulation.
    * `Move`, `Swap`:  Operations for data transfer.
    * `AssembleDeconstructFrame`:  Deals with tearing down the call frame.
    * `SetPendingMove`, `MoveToTempLocation`, `MoveTempLocationTo`: Suggest strategies for handling data movement, potentially involving temporary storage.
    * `AssembleJumpTable`:  Handles jump tables (less relevant in this specific snippet, but good to note).

4. **Deep Dive into Key Methods (Focus on Logic):**  Select the most significant methods and examine their internal workings:

    * **`AssembleReturn`:**  Notice the steps: adjusting the stack pointer for return values, restoring saved registers (both general-purpose and floating-point), and handling argument popping. The logic for `additional_pop_count` and the distinction between JS and C function calls are important details.

    * **`Push` and `Pop`:** Observe how they modify the stack pointer (`sp`) and how they handle different operand types (register, stack slot). The use of `frame_access_state_` is a key element for managing stack frame information.

    * **`AssembleMove`:** This function has a lot of branching based on the source and destination operand types. The handling of constants, registers, and stack slots for both integer and floating-point values needs to be considered. The special cases for 32-bit moves are also worth noting.

5. **Infer Overall Functionality:**  Based on the analysis of individual methods, synthesize the high-level purpose of the `code-generator-mips64.cc` file. It's clearly responsible for generating MIPS64 assembly code from a higher-level representation of the program. It manages registers, the stack, and performs data transfers.

6. **Address Specific Questions from the Prompt:**

    * **Functionality Listing:**  Systematically list the identified functionalities.
    * **Torque:** Check the file extension. It's `.cc`, not `.tq`.
    * **Relationship to JavaScript:**  Recognize that this code generator is part of the V8 JavaScript engine. Its purpose is to translate JavaScript code into machine code. Provide a simple JavaScript example and explain how the code generator would be involved in compiling it (e.g., function calls, variable assignments).
    * **Code Logic Reasoning (Hypothetical Input/Output):**  For a simple case like `AssembleMove`, devise a concrete example with specific registers and values to illustrate the expected assembly output.
    * **Common Programming Errors:** Think about the types of errors that could occur if this code generation process is flawed. Stack overflows (related to `Push`/`Pop`), incorrect data movement leading to wrong results, and register corruption are potential issues.
    * **Overall Function Summary (Part 6):**  Reiterate the main purpose of the code in a concise summary.

7. **Refine and Organize:** Review the generated information for clarity, accuracy, and completeness. Organize the points logically, using headings and bullet points for readability. Ensure the language is precise and avoids jargon where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about moving data around."  **Correction:** Realize it's more than just moving data. It's about the *semantics* of operations within a function call context (return, arguments), and the specific constraints of the MIPS64 architecture (register usage, instruction formats).
* **Focusing too much on individual instructions:** **Correction:** Step back and consider the higher-level goals of the methods. For example, `AssembleReturn` isn't just about the `Ret` instruction; it's about the entire process of cleaning up and returning from a function.
* **Forgetting the "why":** **Correction:**  Always connect the technical details back to the overall purpose of a code generator – translating higher-level code into executable machine instructions.

By following this structured thought process, we can effectively analyze and understand the functionality of the provided C++ code snippet.
This C++ code snippet is a part of the `code-generator-mips64.cc` file within the V8 JavaScript engine, specifically for the MIPS64 architecture. It focuses on the implementation of various code generation tasks necessary for compiling JavaScript code down to MIPS64 assembly instructions.

Here's a breakdown of its functionalities:

**1. Function Prologue and Epilogue (`AssembleReturn`):**

* **Stack Management during Return:**  It handles the necessary stack adjustments when a function returns, including popping return values and managing the stack pointer (`sp`).
* **Restoring Callee-Saved Registers:**  It restores the values of registers that the current function was responsible for preserving (callee-saved registers). This ensures that the calling function's state is not corrupted. It handles both general-purpose registers and floating-point registers.
* **Handling Argument Popping:** It deals with removing arguments from the stack after a function call. It differentiates between regular JavaScript function calls and built-in function calls with special argument handling.
* **Deconstructing the Frame:**  It calls `AssembleDeconstructFrame()` to unwind the function's stack frame.
* **Optimization for Return Sites:** It includes an optimization where it jumps to a pre-defined `return_label_` if available, avoiding redundant frame deconstruction in certain cases.

**2. Stack Manipulation (`Push`, `Pop`, `PopTempStackSlots`):**

* **`Push`:** Implements pushing values onto the stack. It handles different operand types (registers, stack slots) and updates the stack pointer accordingly. It also keeps track of temporary stack slots used during code generation.
* **`Pop`:** Implements popping values from the stack into a destination operand (register or stack slot). It updates the stack pointer and handles different operand types.
* **`PopTempStackSlots`:**  Cleans up any temporary stack slots that were used during code generation.

**3. Data Movement (`AssembleMove`, `AssembleSwap`, `MoveToTempLocation`, `MoveTempLocationTo`, `SetPendingMove`):**

* **`AssembleMove`:**  Generates MIPS64 instructions to move data between different locations (registers, stack slots, constants). It handles various data types (integers, floats, pointers) and optimizes for 32-bit moves when possible. It also handles loading constants from different sources (immediate values, embedded numbers, external references, heap objects, root entries).
* **`AssembleSwap`:** Generates instructions to swap the contents of two operands (registers or stack slots). It handles both general-purpose registers and floating-point registers.
* **`MoveToTempLocation`:**  Moves a value from a source operand to a temporary location (either a register or the stack). This is used to break dependencies in instruction scheduling.
* **`MoveTempLocationTo`:** Moves a value from a temporary location to a destination operand.
* **`SetPendingMove`:**  Marks a move operation as pending and can reserve scratch registers if needed, especially for moves involving stack slots or constant to FP register moves. This is likely part of a more complex move scheduling or register allocation strategy to avoid conflicts.

**4. Jump Tables (`AssembleJumpTable`):**

* This section indicates support for jump tables, although the provided code states that on 64-bit MIPS, jump tables are emitted inline, meaning a separate jump table structure isn't explicitly created here.

**5. Atomic Operations and IEEE754 Operations (Placeholders):**

* The code includes `#undef` directives for macros related to atomic operations and IEEE754 floating-point operations. This suggests that the implementations for these operations are likely defined elsewhere in the codebase and might be included or generated based on the specific needs.

**6. Deoptimization (`PrepareForDeoptimizationExits`):**

* This function is a placeholder that is likely used to prepare for deoptimization exits, which are mechanisms for reverting to interpreted execution if certain assumptions made during compilation are invalidated.

**If `v8/src/compiler/backend/mips64/code-generator-mips64.cc` ended with `.tq`, it would be a V8 Torque source code.** Torque is a domain-specific language used within V8 to generate C++ code for runtime functions and compiler intrinsics. Since it ends with `.cc`, it's a regular C++ source file.

**Relationship to JavaScript and Examples:**

This code directly enables the execution of JavaScript code on MIPS64 architectures. Here are a few JavaScript examples and how this code generator would be involved:

**Example 1: Function Call**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

The `AssembleReturn` function would be crucial when compiling the `add` function. It would handle:
* Popping the return value (the sum of `a` and `b`) onto the stack or into a register.
* Restoring any callee-saved registers used within the `add` function.
* Adjusting the stack pointer to clean up the function's stack frame.

**Example 2: Variable Assignment**

```javascript
let x = 20;
let y = x;
```

The `AssembleMove` function would be used to compile the assignment `let y = x;`. If `x` was stored in a register, `AssembleMove` would generate a MIPS64 `mov` instruction to copy the value from the register holding `x` to the register allocated for `y`. If `x` was on the stack, it would generate instructions to load the value from the stack into a register and then potentially move it to the location of `y`.

**Example 3: Simple Arithmetic**

```javascript
let a = 5;
let b = 10;
let sum = a + b;
```

While the core arithmetic operation (`+`) might be handled by other parts of the code generator, `AssembleMove` would be used to move the initial values of `a` and `b` into registers, and potentially to move the final `sum` to its designated location (register or stack).

**Code Logic Reasoning (Hypothetical Input and Output):**

**Scenario:** Compiling the JavaScript code `let x = 10;` where `x` is assigned to register `t1`.

**Hypothetical Input:** An `InstructionOperand` representing the constant value `10` and an `InstructionOperand` representing the register `t1`.

**Code Flow in `AssembleMove`:**

1. The code would enter the `else if (source->IsConstant())` block.
2. It would extract the constant value `10`.
3. Since the destination is a register, it would enter the `if (destination->IsRegister())` block.
4. It would generate a MIPS64 `li` (load immediate) instruction: `__ li(t1, Operand(10));`

**Hypothetical Output (MIPS64 Assembly):**

```assembly
li t1, 10
```

**User-Common Programming Errors and How This Code Helps Prevent/Handle Them:**

* **Stack Overflow:** Incorrect stack management in `Push`, `Pop`, and `AssembleReturn` could lead to stack overflows. This code carefully manages the stack pointer to ensure proper allocation and deallocation of stack space.
* **Register Corruption:** Failing to save and restore callee-saved registers in `AssembleReturn` would corrupt the state of the calling function. This code explicitly handles the saving and restoring of these registers.
* **Incorrect Data Values:** Errors in `AssembleMove` could lead to incorrect values being moved between locations, resulting in wrong program behavior. The careful handling of different operand types and constant loading helps prevent this.
* **Type Mismatches:** While not directly evident in this snippet, the code generator as a whole must ensure that operations are performed on compatible data types. Incorrectly moving a floating-point value to an integer register (or vice-versa without proper conversion) would be a common error that the type system and code generation logic must prevent.

**Part 6 Summary (Overall Functionality):**

This part of `v8/src/compiler/backend/mips64/code-generator-mips64.cc` focuses on the low-level details of generating MIPS64 assembly code for fundamental operations like function returns, stack manipulation, and data movement. It ensures that JavaScript code is translated into efficient and correct machine instructions for the MIPS64 architecture, handling register management, stack frame setup and teardown, and various data types. It plays a crucial role in the overall compilation pipeline of the V8 JavaScript engine.

Prompt: 
```
这是目录为v8/src/compiler/backend/mips64/code-generator-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/code-generator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
_access_state()->GetFrameOffset(spill_slot);
    DCHECK(offset.from_frame_pointer());
    __ Sd(zero_reg, MemOperand(fp, offset.offset()));
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = frame()->GetReturnSlotCount();
  if (returns != 0) {
    __ Daddu(sp, sp, Operand(returns * kSystemPointerSize));
  }

  // Restore GP registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    __ MultiPop(saves);
  }

  // Restore FPU registers.
  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fpu.is_empty()) {
    __ MultiPopFPU(saves_fpu);
  }

  MipsOperandConverter g(this, nullptr);

  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue,
                g.ToRegister(additional_pop_count),
                Operand(static_cast<int64_t>(0)));
    }
  }

  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.
  const bool drop_jsargs = frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall() &&
                           parameter_slots != 0;

  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    // Canonicalize JSFunction return sites for now unless they have an variable
    // number of stack slot pops.
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ Branch(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count
      __ Ld(t0, MemOperand(fp, StandardFrameConstants::kArgCOffset));
    }
    AssembleDeconstructFrame();
  }
  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver). This
    // number of arguments is given by max(1 + argc_reg, parameter_slots).
    if (parameter_slots > 1) {
      __ li(kScratchReg, parameter_slots);
      __ slt(kScratchReg2, t0, kScratchReg);
      __ movn(t0, kScratchReg, kScratchReg2);
    }
    __ Dlsa(sp, sp, t0, kSystemPointerSizeLog2);
  } else if (additional_pop_count->IsImmediate()) {
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    __ Drop(parameter_slots + additional_count);
  } else {
    Register pop_reg = g.ToRegister(additional_pop_count);
    __ Drop(parameter_slots);
    __ Dlsa(sp, sp, pop_reg, kSystemPointerSizeLog2);
  }
  __ Ret();
}

void CodeGenerator::FinishCode() {}

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  MipsOperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ Push(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ Ld(scratch, g.ToMemOperand(source));
    __ Push(scratch);
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ Dsubu(sp, sp, Operand(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  MipsOperandConverter g(this, nullptr);
  int dropped_slots = ElementSizeInPointers(rep);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Pop(g.ToRegister(dest));
  } else if (dest->IsStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ Pop(scratch);
    __ Sd(scratch, g.ToMemOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Daddu(sp, sp, Operand(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ Daddu(sp, sp, Operand(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  DCHECK(!source->IsImmediate());
  move_cycle_.temps.emplace(masm());
  auto& temps = *move_cycle_.temps;
  // Temporarily exclude the reserved scratch registers while we pick one to
  // resolve the move cycle. Re-include them immediately afterwards as they
  // might be needed for the move to the temp location.
  temps.Exclude(move_cycle_.scratch_regs);
  if (!IsFloatingPoint(rep)) {
    if (temps.hasAvailable()) {
      Register scratch = move_cycle_.temps->Acquire();
      move_cycle_.scratch_reg.emplace(scratch);
    }
  }

  temps.Include(move_cycle_.scratch_regs);

  if (move_cycle_.scratch_reg.has_value()) {
    // A scratch register is available for this rep.
    // auto& scratch_reg = *move_cycle_.scratch_reg;
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(source, &scratch);
  } else {
    // The scratch registers are blocked by pending moves. Use the stack
    // instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  if (move_cycle_.scratch_reg.has_value()) {
    // auto& scratch_reg = *move_cycle_.scratch_reg;
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(&scratch, dest);
  } else {
    Pop(dest, rep);
  }
  // Restore the default state to release the {UseScratchRegisterScope} and to
  // prepare for the next cycle.
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  InstructionOperand* src = &move->source();
  InstructionOperand* dst = &move->destination();
  UseScratchRegisterScope temps(masm());
  if (src->IsConstant() && dst->IsFPLocationOperand()) {
    Register temp = temps.Acquire();
    move_cycle_.scratch_regs.set(temp);
  } else if (src->IsAnyStackSlot() || dst->IsAnyStackSlot()) {
    MipsOperandConverter g(this, nullptr);
    bool src_need_scratch = false;
    bool dst_need_scratch = false;
    if (src->IsAnyStackSlot()) {
      MemOperand src_mem = g.ToMemOperand(src);
      src_need_scratch =
          (!is_int16(src_mem.offset())) || (((src_mem.offset() & 0b111) != 0) &&
                                            !is_int16(src_mem.offset() + 4));
    }
    if (dst->IsAnyStackSlot()) {
      MemOperand dst_mem = g.ToMemOperand(dst);
      dst_need_scratch =
          (!is_int16(dst_mem.offset())) || (((dst_mem.offset() & 0b111) != 0) &&
                                            !is_int16(dst_mem.offset() + 4));
    }
    if (src_need_scratch || dst_need_scratch) {
      Register temp = temps.Acquire();
      move_cycle_.scratch_regs.set(temp);
    }
  }
}

namespace {

bool Is32BitOperand(InstructionOperand* operand) {
  DCHECK(operand->IsStackSlot() || operand->IsRegister());
  MachineRepresentation mr = LocationOperand::cast(operand)->representation();
  return mr == MachineRepresentation::kWord32 ||
         mr == MachineRepresentation::kCompressed ||
         mr == MachineRepresentation::kCompressedPointer;
}

// When we need only 32 bits, move only 32 bits, otherwise the destination
// register' upper 32 bits may contain dirty data.
bool Use32BitMove(InstructionOperand* source, InstructionOperand* destination) {
  return Is32BitOperand(source) && Is32BitOperand(destination);
}

}  // namespace

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  MipsOperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  if (source->IsRegister()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      __ mov(g.ToRegister(destination), src);
    } else {
      __ Sd(src, g.ToMemOperand(destination));
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    MemOperand src = g.ToMemOperand(source);
    if (destination->IsRegister()) {
      if (Use32BitMove(source, destination)) {
        __ Lw(g.ToRegister(destination), src);
      } else {
        __ Ld(g.ToRegister(destination), src);
      }
    } else {
      Register temp = kScratchReg;
      __ Ld(temp, src);
      __ Sd(temp, g.ToMemOperand(destination));
    }
  } else if (source->IsConstant()) {
    Constant src = g.ToConstant(source);
    if (destination->IsRegister() || destination->IsStackSlot()) {
      Register dst =
          destination->IsRegister() ? g.ToRegister(destination) : kScratchReg;
      switch (src.type()) {
        case Constant::kInt32:
          __ li(dst, Operand(src.ToInt32(), src.rmode()));
          break;
        case Constant::kFloat32:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat32()));
          break;
        case Constant::kInt64:
          __ li(dst, Operand(src.ToInt64(), src.rmode()));
          break;
        case Constant::kFloat64:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat64().value()));
          break;
        case Constant::kExternalReference:
          __ li(dst, src.ToExternalReference());
          break;
        case Constant::kHeapObject: {
          Handle<HeapObject> src_object = src.ToHeapObject();
          RootIndex index;
          if (IsMaterializableFromRoot(src_object, &index)) {
            __ LoadRoot(dst, index);
          } else {
            __ li(dst, src_object);
          }
          break;
        }
        case Constant::kCompressedHeapObject:
          UNREACHABLE();
        case Constant::kRpoNumber:
          UNREACHABLE();  // TODO(titzer): loading RPO numbers on mips64.
      }
      if (destination->IsStackSlot()) __ Sd(dst, g.ToMemOperand(destination));
    } else if (src.type() == Constant::kFloat32) {
      if (destination->IsFPStackSlot()) {
        MemOperand dst = g.ToMemOperand(destination);
        if (base::bit_cast<int32_t>(src.ToFloat32()) == 0) {
          __ Sd(zero_reg, dst);
        } else {
          __ li(kScratchReg, Operand(base::bit_cast<int32_t>(src.ToFloat32())));
          __ Sd(kScratchReg, dst);
        }
      } else {
        DCHECK(destination->IsFPRegister());
        FloatRegister dst = g.ToSingleRegister(destination);
        __ Move(dst, src.ToFloat32());
      }
    } else {
      DCHECK_EQ(Constant::kFloat64, src.type());
      DoubleRegister dst = destination->IsFPRegister()
                               ? g.ToDoubleRegister(destination)
                               : kScratchDoubleReg;
      __ Move(dst, src.ToFloat64().value());
      if (destination->IsFPStackSlot()) {
        __ Sdc1(dst, g.ToMemOperand(destination));
      }
    }
  } else if (source->IsFPRegister()) {
    MachineRepresentation rep = LocationOperand::cast(source)->representation();
    if (rep == MachineRepresentation::kSimd128) {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      MSARegister src = g.ToSimd128Register(source);
      if (destination->IsSimd128Register()) {
        MSARegister dst = g.ToSimd128Register(destination);
        __ move_v(dst, src);
      } else {
        DCHECK(destination->IsSimd128StackSlot());
        __ st_b(src, g.ToMemOperand(destination));
      }
    } else {
      FPURegister src = g.ToDoubleRegister(source);
      if (destination->IsFPRegister()) {
        FPURegister dst = g.ToDoubleRegister(destination);
        __ Move(dst, src);
      } else {
        DCHECK(destination->IsFPStackSlot());
        __ Sdc1(src, g.ToMemOperand(destination));
      }
    }
  } else if (source->IsFPStackSlot()) {
    DCHECK(destination->IsFPRegister() || destination->IsFPStackSlot());
    MemOperand src = g.ToMemOperand(source);
    MachineRepresentation rep = LocationOperand::cast(source)->representation();
    if (rep == MachineRepresentation::kSimd128) {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      if (destination->IsSimd128Register()) {
        __ ld_b(g.ToSimd128Register(destination), src);
      } else {
        DCHECK(destination->IsSimd128StackSlot());
        MSARegister temp = kSimd128ScratchReg;
        __ ld_b(temp, src);
        __ st_b(temp, g.ToMemOperand(destination));
      }
    } else {
      if (destination->IsFPRegister()) {
        __ Ldc1(g.ToDoubleRegister(destination), src);
      } else {
        DCHECK(destination->IsFPStackSlot());
        FPURegister temp = kScratchDoubleReg;
        __ Ldc1(temp, src);
        __ Sdc1(temp, g.ToMemOperand(destination));
      }
    }
  } else {
    UNREACHABLE();
  }
}

void CodeGenerator::AssembleSwap(InstructionOperand* source,
                                 InstructionOperand* destination) {
  MipsOperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  if (source->IsRegister()) {
    // Register-register.
    Register temp = kScratchReg;
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      Register dst = g.ToRegister(destination);
      __ Move(temp, src);
      __ Move(src, dst);
      __ Move(dst, temp);
    } else {
      DCHECK(destination->IsStackSlot());
      MemOperand dst = g.ToMemOperand(destination);
      __ mov(temp, src);
      __ Ld(src, dst);
      __ Sd(temp, dst);
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsStackSlot());
    Register temp_0 = kScratchReg;
    Register temp_1 = kScratchReg2;
    MemOperand src = g.ToMemOperand(source);
    MemOperand dst = g.ToMemOperand(destination);
    __ Ld(temp_0, src);
    __ Ld(temp_1, dst);
    __ Sd(temp_0, dst);
    __ Sd(temp_1, src);
  } else if (source->IsFPRegister()) {
    MachineRepresentation rep = LocationOperand::cast(source)->representation();
    if (rep == MachineRepresentation::kSimd128) {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      MSARegister temp = kSimd128ScratchReg;
      MSARegister src = g.ToSimd128Register(source);
      if (destination->IsSimd128Register()) {
        MSARegister dst = g.ToSimd128Register(destination);
        __ move_v(temp, src);
        __ move_v(src, dst);
        __ move_v(dst, temp);
      } else {
        DCHECK(destination->IsSimd128StackSlot());
        MemOperand dst = g.ToMemOperand(destination);
        __ move_v(temp, src);
        __ ld_b(src, dst);
        __ st_b(temp, dst);
      }
    } else {
      FPURegister temp = kScratchDoubleReg;
      FPURegister src = g.ToDoubleRegister(source);
      if (destination->IsFPRegister()) {
        FPURegister dst = g.ToDoubleRegister(destination);
        __ Move(temp, src);
        __ Move(src, dst);
        __ Move(dst, temp);
      } else {
        DCHECK(destination->IsFPStackSlot());
        MemOperand dst = g.ToMemOperand(destination);
        __ Move(temp, src);
        __ Ldc1(src, dst);
        __ Sdc1(temp, dst);
      }
    }
  } else if (source->IsFPStackSlot()) {
    DCHECK(destination->IsFPStackSlot());
    Register temp_0 = kScratchReg;
    MemOperand src0 = g.ToMemOperand(source);
    MemOperand src1(src0.rm(), src0.offset() + kInt64Size);
    MemOperand dst0 = g.ToMemOperand(destination);
    MemOperand dst1(dst0.rm(), dst0.offset() + kInt64Size);
    MachineRepresentation rep = LocationOperand::cast(source)->representation();
    if (rep == MachineRepresentation::kSimd128) {
      CpuFeatureScope msa_scope(masm(), MIPS_SIMD);
      MSARegister temp_1 = kSimd128ScratchReg;
      __ ld_b(temp_1, dst0);  // Save destination in temp_1.
      __ Ld(temp_0, src0);    // Then use temp_0 to copy source to destination.
      __ Sd(temp_0, dst0);
      __ Ld(temp_0, src1);
      __ Sd(temp_0, dst1);
      __ st_b(temp_1, src0);
    } else {
      FPURegister temp_1 = kScratchDoubleReg;
      __ Ldc1(temp_1, dst0);  // Save destination in temp_1.
      __ Ld(temp_0, src0);    // Then use temp_0 to copy source to destination.
      __ Sdc1(temp_1, src0);
      __ Sd(temp_0, dst0);
    }
  } else {
    // No other combinations are possible.
    UNREACHABLE();
  }
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
  // On 64-bit MIPS we emit the jump tables inline.
  UNREACHABLE();
}

#undef ASSEMBLE_ATOMIC_LOAD_INTEGER
#undef ASSEMBLE_ATOMIC_STORE_INTEGER
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC_BINOP_EXT
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP
#undef ASSEMBLE_F64X2_ARITHMETIC_BINOP

#undef TRACE
#undef __

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```