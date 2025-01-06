Response: The user wants to understand the functionality of the provided C++ code snippet, which is part of the `code-generator-ia32.cc` file in the V8 JavaScript engine. This is the third and final part of the file.

Here's a breakdown of the thought process to summarize the code's function and its relation to JavaScript:

1. **Identify the Core Purpose:** The filename "code-generator-ia32.cc" strongly suggests this code is responsible for generating machine code for the IA32 architecture. This means it translates higher-level instructions into the specific assembly instructions that an IA32 processor can execute.

2. **Examine the Content - Focus on Key Sections:**  Quickly scan the provided code for recurring patterns and important function names. Notice:
    * **Macros:** `ATOMIC_BINOP_CASE`, `ASSEMBLE_ATOMIC_BINOP`, `ASSEMBLE_I64ATOMIC_BINOP`. These relate to atomic operations, which are important for concurrent programming.
    * **`case` statements within a larger `switch`:** This suggests handling different kinds of operations or instructions. The `kAtomic...` and `kIA32Word32AtomicPair...` cases confirm the atomic operation focus.
    * **`CodeGenerator` class methods:** Functions like `AssembleArchBranch`, `AssembleArchDeoptBranch`, `AssembleArchJumpRegardlessOfAssemblyOrder`, `AssembleArchTrap`, `AssembleArchBoolean`, `AssembleConstructFrame`, `AssembleReturn`, `AssembleMove`, `AssembleSwap`, `AssembleJumpTable`. These clearly relate to code generation for control flow, function calls, data movement, and other architectural features.
    * **WebAssembly conditionals:**  The `#if V8_ENABLE_WEBASSEMBLY` sections highlight the code's role in supporting WebAssembly within V8.
    * **Frame management:**  Sections dealing with `ConstructFrame` and `Return` indicate responsibility for setting up and tearing down function call stacks.
    * **Register usage:** Mentions of registers like `eax`, `edx`, `ebp`, `esp`, and XMM registers.
    * **Operand handling:**  The `IA32OperandConverter` class is used to manage different types of operands (registers, stack slots, immediates).

3. **Group Functionality:** Based on the observations, categorize the code's responsibilities:
    * **Atomic Operations:** Handling atomic reads, writes, and binary operations on different data sizes.
    * **Control Flow:**  Generating code for branches, jumps, conditional execution, and traps (especially for WebAssembly).
    * **Function Calls:**  Managing the setup and teardown of function call frames, argument passing, and return values (including distinctions between JS functions, runtime functions, and C++ functions).
    * **Data Movement:** Implementing `move` and `swap` operations between registers, stack slots, and constants.
    * **WebAssembly Support:**  Specific code generation for WebAssembly features like traps and stack management.
    * **Optimization/Deoptimization:** Handling deoptimization branches.
    * **Switch Statements:**  Generating code for `switch` statements using binary search and jump tables.

4. **Connect to JavaScript:**  Consider how these low-level operations relate to JavaScript's features:
    * **Atomic Operations:** Directly map to JavaScript's `Atomics` object and its methods for shared memory concurrency.
    * **Control Flow:**  JavaScript's `if`, `else`, `for`, `while`, `switch` statements are all implemented using branching and jumping at the machine code level. Function calls in JavaScript trigger the frame setup and teardown routines.
    * **Data Movement:**  Assigning values to variables, passing arguments to functions, and returning values all involve moving data between registers and memory.
    * **WebAssembly:** The integration directly supports running WebAssembly code within the JavaScript engine.
    * **Optimization/Deoptimization:** When the JavaScript engine optimizes code, it might generate IA32 code using these functions. If assumptions made during optimization become invalid, deoptimization code (generated here) handles the fallback to less optimized code.
    * **Switch Statements:** JavaScript's `switch` statement benefits from the optimized binary search and jump table implementations.

5. **Create JavaScript Examples:**  Craft simple JavaScript code snippets that illustrate the use of the features whose underlying implementation is handled by the C++ code. Focus on clear and concise examples.

6. **Structure the Summary:** Organize the findings into a coherent summary that covers the key responsibilities and the connection to JavaScript. Start with a high-level overview and then provide more specific details. Use bullet points or numbered lists for readability.

7. **Refine and Verify:** Review the summary for accuracy and completeness. Ensure that the JavaScript examples are relevant and illustrate the intended concepts. Double-check for any technical inaccuracies. For example, explicitly mention the different calling conventions handled.
Based on the provided C++ code snippet from `v8/src/compiler/backend/ia32/code-generator-ia32.cc`, this part of the code generator focuses on the implementation of **atomic operations**, **control flow instructions**, and **function call/return sequences** for the IA32 architecture within the V8 JavaScript engine. It also includes specific handling for **WebAssembly traps** and **boolean materialization**.

Here's a breakdown of the functionalities:

**1. Atomic Operations:**

* **Implementation of various atomic binary operations:** The code defines macros (`ATOMIC_BINOP_CASE`, `ASSEMBLE_ATOMIC_BINOP`, `ASSEMBLE_I64ATOMIC_BINOP`) to generate assembly code for atomic addition, subtraction, bitwise AND, OR, and XOR operations on different integer sizes (8-bit, 16-bit, and 32-bit).
* **Atomic compare-and-exchange:** The `cmpxchg` instruction is used within the atomic binary operations to ensure atomicity.
* **Special handling for 64-bit atomic operations:**  The `ASSEMBLE_I64ATOMIC_BINOP` macro and the specific `kIA32Word32AtomicPairSub` case handle atomic operations on 64-bit values using pairs of 32-bit registers.
* **Note on unimplemented load/store:**  The code explicitly marks atomic load and store instructions as `UNREACHABLE()`, indicating they are not generated by the instruction selector in this architecture.

**2. Control Flow Instructions:**

* **Generating branch instructions:** The `AssembleArchBranch` function takes an instruction and branch information to generate conditional jump instructions based on the flags set by previous operations. It handles various condition codes (equal, not equal, less than, greater than, etc.).
* **Generating deoptimization branches:** `AssembleArchDeoptBranch` simply calls `AssembleArchBranch`, suggesting that deoptimization is implemented using standard branching mechanisms.
* **Generating unconditional jumps:** `AssembleArchJumpRegardlessOfAssemblyOrder` generates simple unconditional jump instructions.
* **WebAssembly trap handling:** The `AssembleArchTrap` function generates code to handle WebAssembly traps. It uses an `OutOfLineTrap` helper class to generate a call to a runtime stub, recording safepoint information and asserting that the call should not return.
* **Boolean materialization:** `AssembleArchBoolean` generates code to materialize boolean values (0 or 1) in a register based on the result of a previous comparison.
* **Conditional boolean and branch (not implemented):**  `AssembleArchConditionalBoolean` and `AssembleArchConditionalBranch` are marked as `UNREACHABLE()`, indicating that these specific forms of conditional operations might be handled differently or not directly generated on IA32.
* **Switch statement implementation:**
    * `AssembleArchBinarySearchSwitch`: Implements a `switch` statement using a binary search approach.
    * `AssembleArchTableSwitch`: Implements a `switch` statement using a jump table for more efficient dispatch when the case values are dense.

**3. Function Call and Return Sequences:**

* **Detailed explanation of calling conventions:** The code provides extensive comments explaining the register usage and stack layout during JavaScript function calls and runtime calls on IA32.
* **Frame construction (`AssembleConstructFrame`):** This function generates the assembly code to set up a function's stack frame, including pushing the frame pointer, saving callee-saved registers, and allocating space for local variables. It also handles specific cases for OSR (On-Stack Replacement) entry and WebAssembly functions.
* **Frame finalization (`FinishFrame`):**  Allocates slots for saving callee-saved registers.
* **Return instruction generation (`AssembleReturn`):** This function generates the code to restore the stack frame, pop callee-saved registers, and execute the `ret` instruction. It handles different calling conventions and potentially pops arguments from the stack.
* **Deconstructing the frame (`AssembleDeconstructFrame` called within `AssembleReturn`):** This reverses the actions of frame construction, restoring `esp` to `ebp` and popping `ebp`.

**4. Data Movement (Move and Swap):**

* **`AssembleMove`:** This function generates assembly instructions to move data between registers, stack slots, and immediate values. It handles different data types (integers, floats, SIMD vectors) and optimizes based on the source and destination operand types.
* **`AssembleSwap`:** This function generates assembly instructions to swap the contents of two operands (registers or stack slots). It also handles different data types and uses a scratch register when necessary.

**5. Temporary Stack Slots:**

* **`Push` and `Pop`:** These functions manage a temporary area on the stack for holding intermediate values during code generation.
* **`PopTempStackSlots`:** Cleans up the temporary stack area.
* **`MoveToTempLocation` and `MoveTempLocationTo`:**  Facilitate moving values to and from the temporary stack area or a designated scratch register.

**Connection to JavaScript:**

This C++ code is a crucial part of the V8 engine that directly enables the execution of JavaScript code on IA32 processors. Here are some examples of how the functionalities relate to JavaScript:

* **Atomic Operations:** The atomic operations implemented here are the foundation for JavaScript's `Atomics` object, which allows for concurrent operations on shared memory.

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
   const view = new Int32Array(sab);
   Atomics.add(view, 0, 5); // This operation would be implemented using the atomic instructions generated here.
   ```

* **Control Flow:** JavaScript's control flow statements (`if`, `else`, `for`, `while`, `switch`) are translated into the branch and jump instructions generated by functions like `AssembleArchBranch`, `AssembleArchJumpRegardlessOfAssemblyOrder`, and the `AssembleArch*Switch` functions.

   ```javascript
   let x = 10;
   if (x > 5) { // This 'if' statement would be translated into a conditional branch.
       console.log("x is greater than 5");
   }

   switch (x) { // This 'switch' statement might be translated using binary search or a jump table.
       case 10:
           console.log("x is 10");
           break;
       default:
           console.log("x is not 10");
   }
   ```

* **Function Calls:** When a JavaScript function is called, the `AssembleConstructFrame` function (or similar mechanisms) sets up the stack frame. When the function returns, `AssembleReturn` is used to clean up the stack.

   ```javascript
   function myFunction(a, b) { // Calling this function involves frame setup.
       return a + b; // Returning from the function involves frame teardown.
   }
   let result = myFunction(2, 3);
   ```

* **WebAssembly:** The WebAssembly trap handling directly supports running WebAssembly code within the V8 engine. When a WebAssembly trap occurs, the code generated by `AssembleArchTrap` is executed.

* **Boolean Materialization:**  Comparison operations in JavaScript that result in boolean values rely on the code generated by `AssembleArchBoolean`.

   ```javascript
   let isEven = (10 % 2 === 0); // The result of the comparison (true/false) is materialized as 1 or 0.
   ```

* **Data Movement:**  Assigning values to variables and passing arguments involves the move operations implemented by `AssembleMove`.

   ```javascript
   let y = x; // This assignment involves moving the value of x to y.
   function anotherFunction(val) {
       console.log(val); // Passing 'x' as an argument involves moving its value.
   }
   anotherFunction(x);
   ```

In summary, this part of `code-generator-ia32.cc` is responsible for translating higher-level operations and control flow structures in the V8 engine's intermediate representation into the actual IA32 assembly instructions that the processor will execute. It's a fundamental component that bridges the gap between JavaScript code and the underlying hardware.

Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/code-generator-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
   \
  case kAtomic##op##Int8: {                        \
    ASSEMBLE_ATOMIC_BINOP(inst, mov_b, cmpxchg_b); \
    __ movsx_b(eax, eax);                          \
    break;                                         \
  }                                                \
  case kAtomic##op##Uint8: {                       \
    ASSEMBLE_ATOMIC_BINOP(inst, mov_b, cmpxchg_b); \
    __ movzx_b(eax, eax);                          \
    break;                                         \
  }                                                \
  case kAtomic##op##Int16: {                       \
    ASSEMBLE_ATOMIC_BINOP(inst, mov_w, cmpxchg_w); \
    __ movsx_w(eax, eax);                          \
    break;                                         \
  }                                                \
  case kAtomic##op##Uint16: {                      \
    ASSEMBLE_ATOMIC_BINOP(inst, mov_w, cmpxchg_w); \
    __ movzx_w(eax, eax);                          \
    break;                                         \
  }                                                \
  case kAtomic##op##Word32: {                      \
    ASSEMBLE_ATOMIC_BINOP(inst, mov, cmpxchg);     \
    break;                                         \
  }
      ATOMIC_BINOP_CASE(Add, add)
      ATOMIC_BINOP_CASE(Sub, sub)
      ATOMIC_BINOP_CASE(And, and_)
      ATOMIC_BINOP_CASE(Or, or_)
      ATOMIC_BINOP_CASE(Xor, xor_)
#undef ATOMIC_BINOP_CASE
#define ATOMIC_BINOP_CASE(op, instr1, instr2)         \
  case kIA32Word32AtomicPair##op: {                   \
    DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr)); \
    ASSEMBLE_I64ATOMIC_BINOP(instr1, instr2)          \
    break;                                            \
  }
      ATOMIC_BINOP_CASE(Add, add, adc)
      ATOMIC_BINOP_CASE(And, and_, and_)
      ATOMIC_BINOP_CASE(Or, or_, or_)
      ATOMIC_BINOP_CASE(Xor, xor_, xor_)
#undef ATOMIC_BINOP_CASE
    case kIA32Word32AtomicPairSub: {
      DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr));
      Label binop;
      __ bind(&binop);
      // Move memory operand into edx:eax
      __ mov(eax, i.MemoryOperand(2));
      __ mov(edx, i.NextMemoryOperand(2));
      // Save input registers temporarily on the stack.
      __ push(ebx);
      frame_access_state()->IncreaseSPDelta(1);
      i.MoveInstructionOperandToRegister(ebx, instr->InputAt(0));
      __ push(i.InputRegister(1));
      // Negate input in place
      __ neg(ebx);
      __ adc(i.InputRegister(1), 0);
      __ neg(i.InputRegister(1));
      // Add memory operand, negated input.
      __ add(ebx, eax);
      __ adc(i.InputRegister(1), edx);
      __ lock();
      __ cmpxchg8b(i.MemoryOperand(2));
      // Restore input registers
      __ pop(i.InputRegister(1));
      __ pop(ebx);
      frame_access_state()->IncreaseSPDelta(-1);
      __ j(not_equal, &binop);
      break;
    }
    case kAtomicLoadInt8:
    case kAtomicLoadUint8:
    case kAtomicLoadInt16:
    case kAtomicLoadUint16:
    case kAtomicLoadWord32:
    case kAtomicStoreWord8:
    case kAtomicStoreWord16:
    case kAtomicStoreWord32:
      UNREACHABLE();  // Won't be generated by instruction selector.
  }
  return kSuccess;
}

static Condition FlagsConditionToCondition(FlagsCondition condition) {
  switch (condition) {
    case kUnorderedEqual:
    case kEqual:
      return equal;
    case kUnorderedNotEqual:
    case kNotEqual:
      return not_equal;
    case kSignedLessThan:
      return less;
    case kSignedGreaterThanOrEqual:
      return greater_equal;
    case kSignedLessThanOrEqual:
      return less_equal;
    case kSignedGreaterThan:
      return greater;
    case kUnsignedLessThan:
      return below;
    case kUnsignedGreaterThanOrEqual:
      return above_equal;
    case kUnsignedLessThanOrEqual:
      return below_equal;
    case kUnsignedGreaterThan:
      return above;
    case kOverflow:
      return overflow;
    case kNotOverflow:
      return no_overflow;
    default:
      UNREACHABLE();
  }
}

// Assembles a branch after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  Label::Distance flabel_distance =
      branch->fallthru ? Label::kNear : Label::kFar;
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;
  if (branch->condition == kUnorderedEqual) {
    __ j(parity_even, flabel, flabel_distance);
  } else if (branch->condition == kUnorderedNotEqual) {
    __ j(parity_even, tlabel);
  }
  __ j(FlagsConditionToCondition(branch->condition), tlabel);

  // Add a jump if not falling through to the next block.
  if (!branch->fallthru) __ jmp(flabel);
}

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ jmp(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  class OutOfLineTrap final : public OutOfLineCode {
   public:
    OutOfLineTrap(CodeGenerator* gen, Instruction* instr)
        : OutOfLineCode(gen), instr_(instr), gen_(gen) {}

    void Generate() final {
      IA32OperandConverter i(gen_, instr_);
      TrapId trap_id =
          static_cast<TrapId>(i.InputInt32(instr_->InputCount() - 1));
      GenerateCallToTrap(trap_id);
    }

   private:
    void GenerateCallToTrap(TrapId trap_id) {
      gen_->AssembleSourcePosition(instr_);
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ wasm_call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
      ReferenceMap* reference_map =
          gen_->zone()->New<ReferenceMap>(gen_->zone());
      gen_->RecordSafepoint(reference_map);
      __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
    }

    Instruction* instr_;
    CodeGenerator* gen_;
  };
  auto ool = zone()->New<OutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  Label end;
  if (condition == kUnorderedEqual) {
    __ j(parity_even, &end, Label::kNear);
  } else if (condition == kUnorderedNotEqual) {
    __ j(parity_even, tlabel);
  }
  __ j(FlagsConditionToCondition(condition), tlabel);
  __ bind(&end);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  IA32OperandConverter i(this, instr);
  Label done;

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  Label check;
  DCHECK_NE(0u, instr->OutputCount());
  Register reg = i.OutputRegister(instr->OutputCount() - 1);
  if (condition == kUnorderedEqual) {
    __ j(parity_odd, &check, Label::kNear);
    __ Move(reg, Immediate(0));
    __ jmp(&done, Label::kNear);
  } else if (condition == kUnorderedNotEqual) {
    __ j(parity_odd, &check, Label::kNear);
    __ mov(reg, Immediate(1));
    __ jmp(&done, Label::kNear);
  }
  Condition cc = FlagsConditionToCondition(condition);

  __ bind(&check);
  if (reg.is_byte_register()) {
    // setcc for byte registers (al, bl, cl, dl).
    __ setcc(cc, reg);
    __ movzx_b(reg, reg);
  } else {
    // Emit a branch to set a register to either 1 or 0.
    Label set;
    __ j(cc, &set, Label::kNear);
    __ Move(reg, Immediate(0));
    __ jmp(&done, Label::kNear);
    __ bind(&set);
    __ mov(reg, Immediate(1));
  }
  __ bind(&done);
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  IA32OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  IA32OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  size_t const case_count = instr->InputCount() - 2;
  base::Vector<Label*> cases = zone()->AllocateVector<Label*>(case_count);
  for (size_t index = 0; index < case_count; ++index) {
    cases[index] = GetLabel(i.InputRpo(index + 2));
  }
  Label* const table = AddJumpTable(cases);
  __ cmp(input, Immediate(case_count));
  __ j(above_equal, GetLabel(i.InputRpo(1)));
  __ jmp(Operand::JumpTable(input, times_system_pointer_size, table));
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  UNIMPLEMENTED();
}

// The calling convention for JSFunctions on IA32 passes arguments on the
// stack and the JSFunction and context in EDI and ESI, respectively, thus
// the steps of the call look as follows:

// --{ before the call instruction }--------------------------------------------
//                                                         |  caller frame |
//                                                         ^ esp           ^ ebp

// --{ push arguments and setup ESI, EDI }--------------------------------------
//                                       | args + receiver |  caller frame |
//                                       ^ esp                             ^ ebp
//                 [edi = JSFunction, esi = context]

// --{ call [edi + kCodeEntryOffset] }------------------------------------------
//                                 | RET | args + receiver |  caller frame |
//                                 ^ esp                                   ^ ebp

// =={ prologue of called function }============================================
// --{ push ebp }---------------------------------------------------------------
//                            | FP | RET | args + receiver |  caller frame |
//                            ^ esp                                        ^ ebp

// --{ mov ebp, esp }-----------------------------------------------------------
//                            | FP | RET | args + receiver |  caller frame |
//                            ^ ebp,esp

// --{ push esi }---------------------------------------------------------------
//                      | CTX | FP | RET | args + receiver |  caller frame |
//                      ^esp  ^ ebp

// --{ push edi }---------------------------------------------------------------
//                | FNC | CTX | FP | RET | args + receiver |  caller frame |
//                ^esp        ^ ebp

// --{ subi esp, #N }-----------------------------------------------------------
// | callee frame | FNC | CTX | FP | RET | args + receiver |  caller frame |
// ^esp                       ^ ebp

// =={ body of called function }================================================

// =={ epilogue of called function }============================================
// --{ mov esp, ebp }-----------------------------------------------------------
//                            | FP | RET | args + receiver |  caller frame |
//                            ^ esp,ebp

// --{ pop ebp }-----------------------------------------------------------
// |                               | RET | args + receiver |  caller frame |
//                                 ^ esp                                   ^ ebp

// --{ ret #A+1 }-----------------------------------------------------------
// |                                                       |  caller frame |
//                                                         ^ esp           ^ ebp

// Runtime function calls are accomplished by doing a stub call to the
// CEntry (a real code object). On IA32 passes arguments on the
// stack, the number of arguments in EAX, the address of the runtime function
// in EBX, and the context in ESI.

// --{ before the call instruction }--------------------------------------------
//                                                         |  caller frame |
//                                                         ^ esp           ^ ebp

// --{ push arguments and setup EAX, EBX, and ESI }-----------------------------
//                                       | args + receiver |  caller frame |
//                                       ^ esp                             ^ ebp
//              [eax = #args, ebx = runtime function, esi = context]

// --{ call #CEntry }-----------------------------------------------------------
//                                 | RET | args + receiver |  caller frame |
//                                 ^ esp                                   ^ ebp

// =={ body of runtime function }===============================================

// --{ runtime returns }--------------------------------------------------------
//                                                         |  caller frame |
//                                                         ^ esp           ^ ebp

// Other custom linkages (e.g. for calling directly into and out of C++) may
// need to save callee-saved registers on the stack, which is done in the
// function prologue of generated code.

// --{ before the call instruction }--------------------------------------------
//                                                         |  caller frame |
//                                                         ^ esp           ^ ebp

// --{ set up arguments in registers on stack }---------------------------------
//                                                  | args |  caller frame |
//                                                  ^ esp                  ^ ebp
//                  [r0 = arg0, r1 = arg1, ...]

// --{ call code }--------------------------------------------------------------
//                                            | RET | args |  caller frame |
//                                            ^ esp                        ^ ebp

// =={ prologue of called function }============================================
// --{ push ebp }---------------------------------------------------------------
//                                       | FP | RET | args |  caller frame |
//                                       ^ esp                             ^ ebp

// --{ mov ebp, esp }-----------------------------------------------------------
//                                       | FP | RET | args |  caller frame |
//                                       ^ ebp,esp

// --{ save registers }---------------------------------------------------------
//                                | regs | FP | RET | args |  caller frame |
//                                ^ esp  ^ ebp

// --{ subi esp, #N }-----------------------------------------------------------
//                 | callee frame | regs | FP | RET | args |  caller frame |
//                 ^esp                  ^ ebp

// =={ body of called function }================================================

// =={ epilogue of called function }============================================
// --{ restore registers }------------------------------------------------------
//                                | regs | FP | RET | args |  caller frame |
//                                ^ esp  ^ ebp

// --{ mov esp, ebp }-----------------------------------------------------------
//                                       | FP | RET | args |  caller frame |
//                                       ^ esp,ebp

// --{ pop ebp }----------------------------------------------------------------
//                                            | RET | args |  caller frame |
//                                            ^ esp                        ^ ebp

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {  // Save callee-saved registers.
    DCHECK(!info()->is_osr());
    frame->AllocateSavedCalleeRegisterSlots(saves.Count());
  }
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  if (frame_access_state()->has_frame()) {
    if (call_descriptor->IsCFunctionCall()) {
      __ push(ebp);
      __ mov(ebp, esp);
#if V8_ENABLE_WEBASSEMBLY
      if (info()->GetOutputStackFrameType() == StackFrame::C_WASM_ENTRY) {
        __ Push(Immediate(StackFrame::TypeToMarker(StackFrame::C_WASM_ENTRY)));
        // Reserve stack space for saving the c_entry_fp later.
        __ AllocateStackSpace(kSystemPointerSize);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    } else if (call_descriptor->IsJSFunctionCall()) {
      __ Prologue();
    } else {
      __ StubPrologue(info()->GetOutputStackFrameType());
#if V8_ENABLE_WEBASSEMBLY
      if (call_descriptor->IsWasmFunctionCall() ||
          call_descriptor->IsWasmImportWrapper() ||
          call_descriptor->IsWasmCapiFunction()) {
        // For import wrappers and C-API functions, this stack slot is only used
        // for printing stack traces in V8. Also, it holds a WasmImportData
        // instead of the trusted instance data, which is taken care of in the
        // frames accessors.
        __ push(kWasmImplicitArgRegister);
      }
      if (call_descriptor->IsWasmCapiFunction()) {
        // Reserve space for saving the PC later.
        __ AllocateStackSpace(kSystemPointerSize);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }
  }

  int required_slots =
      frame()->GetTotalFrameSlotCount() - frame()->GetFixedSlotCount();

  if (info()->is_osr()) {
    // TurboFan OSR-compiled functions cannot be entered directly.
    __ Abort(AbortReason::kShouldNotDirectlyEnterOsrFunction);

    // Unoptimized code jumps directly to this entrypoint while the unoptimized
    // frame is still on the stack. Optimized code uses OSR values directly from
    // the unoptimized frame. Thus, all that needs to be done is to allocate the
    // remaining stack slots.
    __ RecordComment("-- OSR entrypoint --");
    osr_pc_offset_ = __ pc_offset();
    required_slots -= osr_helper()->UnoptimizedFrameSlots();
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (required_slots > 0) {
    DCHECK(frame_access_state()->has_frame());
#if V8_ENABLE_WEBASSEMBLY
    if (info()->IsWasm() && required_slots * kSystemPointerSize > 4 * KB) {
      // For WebAssembly functions with big frames we have to do the stack
      // overflow check before we construct the frame. Otherwise we may not
      // have enough space on the stack to call the runtime for the stack
      // overflow.
      Label done;

      // If the frame is bigger than the stack, we throw the stack overflow
      // exception unconditionally. Thereby we can avoid the integer overflow
      // check in the condition code.
      if (required_slots * kSystemPointerSize < v8_flags.stack_size * KB) {
        Register scratch = esi;
        __ push(scratch);
        __ mov(scratch, esp);
        __ sub(scratch, Immediate(required_slots * kSystemPointerSize));
        __ CompareStackLimit(scratch, StackLimitKind::kRealStackLimit);
        __ pop(scratch);
        __ j(above_equal, &done, Label::kNear);
      }

      if (v8_flags.experimental_wasm_growable_stacks) {
        RegList regs_to_save;
        regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
        regs_to_save.set(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister());
        for (auto reg : wasm::kGpParamRegisters) regs_to_save.set(reg);
        for (Register reg : base::Reversed(regs_to_save)) {
          __ push(reg);
        }
        __ mov(WasmHandleStackOverflowDescriptor::GapRegister(),
               Immediate(required_slots * kSystemPointerSize));
        __ mov(WasmHandleStackOverflowDescriptor::FrameBaseRegister(), ebp);
        __ add(WasmHandleStackOverflowDescriptor::FrameBaseRegister(),
               Immediate(static_cast<int32_t>(
                   call_descriptor->ParameterSlotCount() * kSystemPointerSize +
                   CommonFrameConstants::kFixedFrameSizeAboveFp)));
        __ CallBuiltin(Builtin::kWasmHandleStackOverflow);
        for (Register reg : regs_to_save) {
          __ pop(reg);
        }
      } else {
        __ wasm_call(static_cast<Address>(Builtin::kWasmStackOverflow),
                     RelocInfo::WASM_STUB_CALL);
        // The call does not return, hence we can ignore any references and just
        // define an empty safepoint.
        ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
        RecordSafepoint(reference_map);
        __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
      }
      __ bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    // Skip callee-saved and return slots, which are created below.
    required_slots -= saves.Count();
    required_slots -= frame()->GetReturnSlotCount();
    if (required_slots > 0) {
      __ AllocateStackSpace(required_slots * kSystemPointerSize);
    }
  }

  if (!saves.is_empty()) {  // Save callee-saved registers.
    DCHECK(!info()->is_osr());
    for (Register reg : base::Reversed(saves)) {
      __ push(reg);
    }
  }

  // Allocate return slots (located after callee-saved).
  if (frame()->GetReturnSlotCount() > 0) {
    __ AllocateStackSpace(frame()->GetReturnSlotCount() * kSystemPointerSize);
  }

  for (int spill_slot : frame()->tagged_slots()) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
    DCHECK(offset.from_frame_pointer());
    __ mov(Operand(ebp, offset.offset()), Immediate(0));
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  // Restore registers.
  if (!saves.is_empty()) {
    const int returns = frame()->GetReturnSlotCount();
    if (returns != 0) {
      __ add(esp, Immediate(returns * kSystemPointerSize));
    }
    for (Register reg : saves) {
      __ pop(reg);
    }
  }

  IA32OperandConverter g(this, nullptr);
  int parameter_slots = static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ cmp(g.ToRegister(additional_pop_count), Immediate(0));
      __ Assert(equal, AbortReason::kUnexpectedAdditionalPopValue);
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  if (call_descriptor->IsWasmFunctionCall() &&
      v8_flags.experimental_wasm_growable_stacks) {
    Register tmp = ecx;
    __ mov(tmp, MemOperand(ebp, TypedFrameConstants::kFrameTypeOffset));
    __ cmp(tmp,
           Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
    Label done;
    __ j(not_equal, &done);
    for (Register reg : base::Reversed(wasm::kGpReturnRegisters)) {
      __ push(reg);
    }
    __ PrepareCallCFunction(1, kReturnRegister0);
    __ Move(Operand(esp, 0 * kSystemPointerSize),
            Immediate(ExternalReference::isolate_address()));
    __ CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
    // Restore old ebp. We don't need to restore old esp explicitly, because
    // it will be restored from ebp in LeaveFrame before return.
    __ mov(ebp, kReturnRegister0);
    for (Register reg : wasm::kGpReturnRegisters) {
      __ pop(reg);
    }
    __ bind(&done);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  Register argc_reg = ecx;
  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.

  const bool drop_jsargs = parameter_slots != 0 &&
                           frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall();
  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    // Canonicalize JSFunction return sites for now if they always have the same
    // number of return args.
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ jmp(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count.
      __ mov(argc_reg, Operand(ebp, StandardFrameConstants::kArgCOffset));
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    }
    AssembleDeconstructFrame();
  }

  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver).
    // The number of arguments without the receiver is
    // max(argc_reg, parameter_slots-1), and the receiver is added in
    // DropArguments().
    Label mismatch_return;
    Register scratch_reg = edx;
    DCHECK_NE(argc_reg, scratch_reg);
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(scratch_reg));
    __ cmp(argc_reg, Immediate(parameter_slots));
    __ j(greater, &mismatch_return, Label::kNear);
    __ Ret(parameter_slots * kSystemPointerSize, scratch_reg);
    __ bind(&mismatch_return);
    __ DropArguments(argc_reg, scratch_reg);
    // We use a return instead of a jump for better return address prediction.
    __ Ret();
  } else if (additional_pop_count->IsImmediate()) {
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    size_t pop_size = (parameter_slots + additional_count) * kSystemPointerSize;
    if (is_uint16(pop_size)) {
      // Avoid the additional scratch register, it might clobber the
      // CalleeSavedRegisters.
      __ ret(static_cast<int>(pop_size));
    } else {
      Register scratch_reg = ecx;
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(scratch_reg));
      CHECK_LE(pop_size, static_cast<size_t>(std::numeric_limits<int>::max()));
      __ Ret(static_cast<int>(pop_size), scratch_reg);
    }
  } else {
    Register pop_reg = g.ToRegister(additional_pop_count);
    Register scratch_reg = pop_reg == ecx ? edi : ecx;
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(scratch_reg));
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(pop_reg));
    int pop_size = static_cast<int>(parameter_slots * kSystemPointerSize);
    __ PopReturnAddressTo(scratch_reg);
    __ lea(esp, Operand(esp, pop_reg, times_system_pointer_size,
                        static_cast<int>(pop_size)));
    __ PushReturnAddressFrom(scratch_reg);
    __ Ret();
  }
}

void CodeGenerator::FinishCode() {}

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  IA32OperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ push(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot() || source->IsFloatStackSlot()) {
    __ push(g.ToOperand(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ sub(esp, Immediate(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  IA32OperandConverter g(this, nullptr);
  int dropped_slots = ElementSizeInPointers(rep);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ pop(g.ToRegister(dest));
  } else if (dest->IsStackSlot() || dest->IsFloatStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ pop(g.ToOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ add(esp, Immediate(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ add(esp, Immediate(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  DCHECK(!source->IsImmediate());
  if ((IsFloatingPoint(rep) &&
       !move_cycle_.pending_double_scratch_register_use)) {
    // The scratch double register is available.
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             kScratchDoubleReg.code());
    AssembleMove(source, &scratch);
  } else {
    // The scratch register blocked by pending moves. Use the stack instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  if (IsFloatingPoint(rep) &&
      !move_cycle_.pending_double_scratch_register_use) {
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             kScratchDoubleReg.code());
    AssembleMove(&scratch, dest);
  } else {
    Pop(dest, rep);
  }
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  InstructionOperand* source = &move->source();
  InstructionOperand* destination = &move->destination();
  MoveType::Type move_type = MoveType::InferMove(source, destination);
  if (move_type == MoveType::kStackToStack) {
    if (!source->IsStackSlot()) {
      move_cycle_.pending_double_scratch_register_use = true;
    }
    return;
  }
}

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  IA32OperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.
  switch (MoveType::InferMove(source, destination)) {
    case MoveType::kRegisterToRegister:
      if (source->IsRegister()) {
        __ mov(g.ToRegister(destination), g.ToRegister(source));
      } else {
        DCHECK(source->IsFPRegister());
        __ Movaps(g.ToDoubleRegister(destination), g.ToDoubleRegister(source));
      }
      return;
    case MoveType::kRegisterToStack: {
      Operand dst = g.ToOperand(destination);
      if (source->IsRegister()) {
        __ mov(dst, g.ToRegister(source));
      } else {
        DCHECK(source->IsFPRegister());
        XMMRegister src = g.ToDoubleRegister(source);
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kFloat32) {
          __ Movss(dst, src);
        } else if (rep == MachineRepresentation::kFloat64) {
          __ Movsd(dst, src);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, rep);
          __ Movups(dst, src);
        }
      }
      return;
    }
    case MoveType::kStackToRegister: {
      Operand src = g.ToOperand(source);
      if (source->IsStackSlot()) {
        __ mov(g.ToRegister(destination), src);
      } else {
        DCHECK(source->IsFPStackSlot());
        XMMRegister dst = g.ToDoubleRegister(destination);
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kFloat32) {
          __ Movss(dst, src);
        } else if (rep == MachineRepresentation::kFloat64) {
          __ Movsd(dst, src);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, rep);
          __ Movups(dst, src);
        }
      }
      return;
    }
    case MoveType::kStackToStack: {
      Operand src = g.ToOperand(source);
      Operand dst = g.ToOperand(destination);
      if (source->IsStackSlot()) {
        __ push(src);
        __ pop(dst);
      } else {
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kFloat32) {
          __ Movss(kScratchDoubleReg, src);
          __ Movss(dst, kScratchDoubleReg);
        } else if (rep == MachineRepresentation::kFloat64) {
          __ Movsd(kScratchDoubleReg, src);
          __ Movsd(dst, kScratchDoubleReg);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, rep);
          __ Movups(kScratchDoubleReg, src);
          __ Movups(dst, kScratchDoubleReg);
        }
      }
      return;
    }
    case MoveType::kConstantToRegister: {
      Constant src = g.ToConstant(source);
      if (destination->IsRegister()) {
        Register dst = g.ToRegister(destination);
        if (src.type() == Constant::kHeapObject) {
          __ Move(dst, src.ToHeapObject());
        } else if (src.type() == Constant::kExternalReference) {
          __ Move(dst, Immediate(src.ToExternalReference()));
        } else {
          __ Move(dst, g.ToImmediate(source));
        }
      } else {
        DCHECK(destination->IsFPRegister());
        XMMRegister dst = g.ToDoubleRegister(destination);
        if (src.type() == Constant::kFloat32) {
          // TODO(turbofan): Can we do better here?
          __ Move(dst, src.ToFloat32AsInt());
        } else {
          DCHECK_EQ(src.type(), Constant::kFloat64);
          __ Move(dst, src.ToFloat64().AsUint64());
        }
      }
      return;
    }
    case MoveType::kConstantToStack: {
      Constant src = g.ToConstant(source);
      Operand dst = g.ToOperand(destination);
      if (destination->IsStackSlot()) {
        __ Move(dst, g.ToImmediate(source));
      } else {
        DCHECK(destination->IsFPStackSlot());
        if (src.type() == Constant::kFloat32) {
          __ Move(dst, Immediate(src.ToFloat32AsInt()));
        } else {
          DCHECK_EQ(src.type(), Constant::kFloat64);
          uint64_t constant_value = src.ToFloat64().AsUint64();
          uint32_t lower = static_cast<uint32_t>(constant_value);
          uint32_t upper = static_cast<uint32_t>(constant_value >> 32);
          Operand dst0 = dst;
          Operand dst1 = g.ToOperand(destination, kSystemPointerSize);
          __ Move(dst0, Immediate(lower));
          __ Move(dst1, Immediate(upper));
        }
      }
      return;
    }
  }
  UNREACHABLE();
}

void CodeGenerator::AssembleSwap(InstructionOperand* source,
                                 InstructionOperand* destination) {
  IA32OperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  switch (MoveType::InferSwap(source, destination)) {
    case MoveType::kRegisterToRegister: {
      if (source->IsRegister()) {
        Register src = g.ToRegister(source);
        Register dst = g.ToRegister(destination);
        __ push(src);
        __ mov(src, dst);
        __ pop(dst);
      } else {
        DCHECK(source->IsFPRegister());
        XMMRegister src = g.ToDoubleRegister(source);
        XMMRegister dst = g.ToDoubleRegister(destination);
        __ Movaps(kScratchDoubleReg, src);
        __ Movaps(src, dst);
        __ Movaps(dst, kScratchDoubleReg);
      }
      return;
    }
    case MoveType::kRegisterToStack: {
      if (source->IsRegister()) {
        Register src = g.ToRegister(source);
        __ push(src);
        frame_access_state()->IncreaseSPDelta(1);
        Operand dst = g.ToOperand(destination);
        __ mov(src, dst);
        frame_access_state()->IncreaseSPDelta(-1);
        dst = g.ToOperand(destination);
        __ pop(dst);
      } else {
        DCHECK(source->IsFPRegister());
        XMMRegister src = g.ToDoubleRegister(source);
        Operand dst = g.ToOperand(destination);
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kFloat32) {
          __ Movss(kScratchDoubleReg, dst);
          __ Movss(dst, src);
          __ Movaps(src, kScratchDoubleReg);
        } else if (rep == MachineRepresentation::kFloat64) {
          __ Movsd(kScratchDoubleReg, dst);
          __ Movsd(dst, src);
          __ Movaps(src, kScratchDoubleReg);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, rep);
          __ Movups(kScratchDoubleReg, dst);
          __ Movups(dst, src);
          __ Movups(src, kScratchDoubleReg);
        }
      }
      return;
    }
    case MoveType::kStackToStack: {
      if (source->IsStackSlot()) {
        Operand dst1 = g.ToOperand(destination);
        __ push(dst1);
        frame_access_state()->IncreaseSPDelta(1);
        Operand src1 = g.ToOperand(source);
        __ push(src1);
        Operand dst2 = g.ToOperand(destination);
        __ pop(dst2);
        frame_access_state()->IncreaseSPDelta(-1);
        Operand src2 = g.ToOperand(source);
        __ pop(src2);
      } else {
        DCHECK(source->IsFPStackSlot());
        Operand src0 = g.ToOperand(source);
        Operand dst0 = g.ToOperand(destination);
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kFloat32) {
          __ Movss(kScratchDoubleReg, dst0);  // Save dst in scratch register.
          __ push(src0);  // Then use stack to copy src to destination.
          __ pop(dst0);
          __ Movss(src0, kScratchDoubleReg);
        } else if (rep == MachineRepresentation::kFloat64) {
          __ Movsd(kScratchDoubleReg, dst0);  // Save dst in scratch register.
          __ push(src0);  // Then use stack to copy src to destination.
          __ pop(dst0);
          __ push(g.ToOperand(source, kSystemPointerSize));
          __ pop(g.ToOperand(destination, kSystemPointerSize));
          __ Movsd(src0, kScratchDoubleReg);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, rep);
          __ Movups(kScratchDoubleReg, dst0);  // Save dst in scratch register.
          __ push(src0);  // Then use stack to copy src to destination.
          __ pop(dst0);
          __ push(g.ToOperand(source, kSystemPointerSize));
          __ pop(g.ToOperand(destination, kSystemPointerSize));
          __ push(g.ToOperand(source, 2 * kSystemPointerSize));
          __ pop(g.ToOperand(destination, 2 * kSystemPointerSize));
          __ push(g.ToOperand(source, 3 * kSystemPointerSize));
          __ pop(g.ToOperand(destination, 3 * kSystemPointerSize));
          __ Movups(src0, kScratchDoubleReg);
        }
      }
      return;
    }
    default:
      UNREACHABLE();
  }
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
  for (auto target : targets) {
    __ dd(target);
  }
}

#undef __
#undef kScratchDoubleReg
#undef ASSEMBLE_COMPARE
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP
#undef ASSEMBLE_BINOP
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_I64ATOMIC_BINOP
#undef ASSEMBLE_MOVX
#undef ASSEMBLE_SIMD_PUNPCK_SHUFFLE
#undef ASSEMBLE_SIMD_IMM_SHUFFLE
#undef ASSEMBLE_SIMD_ALL_TRUE
#undef ASSEMBLE_SIMD_SHIFT
#undef ASSEMBLE_SIMD_PINSR

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```