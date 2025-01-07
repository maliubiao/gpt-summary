Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of the V8 JavaScript engine, specifically the instruction selector for the LoongArch64 architecture.

Here's a breakdown of the code's key functions:

1. **Function Signatures and Templates:** The code defines template functions within the `InstructionSelectorT` class, parameterized by an `Adapter`. This suggests a strategy pattern or a way to abstract across different phases of compilation (like Turbofan and Turboshaft).

2. **`EmitPrepareArguments`:** Handles setting up arguments for function calls. It distinguishes between C function calls and regular JavaScript calls. For C calls, it prepares registers and pokes arguments onto the stack. For JavaScript calls, it allocates stack space and moves arguments onto the stack.

3. **`EmitPrepareResults`:**  Handles retrieving results from function calls. It looks for results stored in the caller's frame and moves them into registers.

4. **`VisitUnalignedLoad` and `VisitUnalignedStore`:** These functions are marked as `UNREACHABLE()`, indicating that the LoongArch64 architecture doesn't directly support unaligned memory access in this context, or that this functionality is handled differently.

5. **`VisitCompare` (and related `VisitFloat32Compare`, `VisitFloat64Compare`, `VisitWordCompare`, `VisitWord32Compare`, `VisitWord64Compare`):**  These functions deal with generating instructions for comparison operations. They handle various data types (integers, floats) and immediate values, and they integrate with a `FlagsContinuationT` object to manage conditional branching.

6. **Atomic Operations (`VisitAtomicLoad`, `VisitAtomicStore`, `VisitAtomicExchange`, `VisitAtomicCompareExchange`, `VisitAtomicBinop`):** These functions generate instructions for atomic memory operations. They handle different data sizes and memory ordering (though the comments indicate memory order is currently ignored). They also account for write barriers for tagged pointers and compressed pointers.

7. **`VisitStackPointerGreaterThan`:** Generates instructions to check if the stack pointer is greater than a certain limit, typically used for stack overflow checks.

8. **`VisitWordCompareZero`:**  Optimizes comparisons against zero. It attempts to combine the comparison with earlier comparison operations if possible, improving code efficiency. It handles various comparison opcodes and data types.

Based on these observations, the core function of `instruction-selector-loong64.cc` is to **translate high-level intermediate representation (IR) operations into low-level LoongArch64 machine instructions.**  It handles function calls, comparisons, and atomic operations, taking into account the specifics of the LoongArch64 architecture and the requirements of the V8 runtime.

Now, let's address the specific questions in the prompt:

*   **Functionality:** As summarized above, it translates IR to LoongArch64 instructions.
*   **`.tq` extension:** The code does *not* end with `.tq`, so it's not a Torque source file.
*   **Relationship to JavaScript:**  This code is crucial for executing JavaScript. When V8 compiles JavaScript code, this file is responsible for generating the actual machine code that the LoongArch64 processor will execute.
*   **JavaScript example:**  Comparisons and function calls in JavaScript directly translate into the kinds of operations handled in this code.
*   **Code logic inference (with assumptions):**
    *   **Assumption:**  A JavaScript function call `foo(a, b)` is being compiled.
    *   **Input:**  The IR representing this call, with nodes representing `foo`, `a`, and `b`.
    *   **Output (from `EmitPrepareArguments`):**  LoongArch64 instructions that move the values of `a` and `b` into registers or onto the stack in preparation for calling `foo`. The specific instructions would depend on the calling convention.
*   **User programming errors:**  While this code itself doesn't directly prevent user errors, it plays a role in how V8 handles them. For instance, if a JavaScript program attempts an unaligned memory access (which is generally not allowed), this code might generate a trap or an exception based on the architecture's behavior. However, the `UNREACHABLE()` in `VisitUnalignedLoad` and `VisitUnalignedStore` suggests this is handled at a higher level or through different mechanisms on LoongArch64. A common error this *indirectly* relates to is stack overflow, which `VisitStackPointerGreaterThan` helps detect.
    *   **Example:** A recursive function without a proper base case can lead to a stack overflow.
        ```javascript
        function recursiveFunction(n) {
          recursiveFunction(n + 1); // Missing base case
        }
        recursiveFunction(0);
        ```
*   **Part 4 of 6:**  This section focuses on argument/result preparation, comparisons, and atomic operations.

**Final Summary of Functionality (Part 4):**

This section of `instruction-selector-loong64.cc` is responsible for generating LoongArch64 assembly instructions for:

*   Preparing arguments and retrieving results for both C and JavaScript function calls.
*   Performing comparison operations on various data types (integers and floating-point numbers), including optimizations for comparisons with zero.
*   Executing atomic memory operations (load, store, exchange, compare-and-exchange, and other binary operations), handling write barriers for garbage collection.
*   Performing stack overflow checks.
Based on the provided code snippet from `v8/src/compiler/backend/loong64/instruction-selector-loong64.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code is responsible for a part of the **instruction selection** phase in the V8 compiler's backend for the **LoongArch64 (loong64)** architecture. Instruction selection is the process of converting high-level, machine-independent intermediate representation (IR) instructions into concrete, low-level machine instructions specific to the target architecture.

**Specific functionalities in this part:**

1. **Preparing Arguments for Function Calls (`EmitPrepareArguments`):**
    *   It handles setting up the necessary data for calling functions, distinguishing between calling C functions and other types of functions (likely JavaScript functions or runtime stubs).
    *   For C function calls, it prepares registers and potentially pushes arguments onto the stack. It uses the `CallDescriptor` to determine the number of general-purpose (GP) and floating-point (FP) parameters.
    *   For non-C function calls, it calculates the required stack space for arguments and then "pokes" (writes) the arguments onto the stack.

2. **Preparing for Results of Function Calls (`EmitPrepareResults`):**
    *   This function deals with retrieving the results of a function call.
    *   It iterates through the expected results and, if a result is located in the caller's frame (on the stack), it "peeks" (reads) the value from the stack into a register.
    *   It also marks the result nodes with the appropriate machine type (Float32, Float64) if they are located in specific stack slots.

3. **Handling Unaligned Memory Access (Currently Disabled):**
    *   The functions `VisitUnalignedLoad` and `VisitUnalignedStore` are present but contain `UNREACHABLE()`. This indicates that unaligned memory accesses are either not directly supported or handled in a different way on the LoongArch64 architecture within V8's current implementation.

4. **Implementing Comparison Operations (`VisitCompare`, `VisitFloat32Compare`, `VisitFloat64Compare`, `VisitWordCompare`, `VisitWord32Compare`, `VisitWord64Compare`):**
    *   These functions generate LoongArch64 instructions for various comparison operations.
    *   They handle comparisons between registers and immediates.
    *   They utilize `FlagsContinuationT` to manage the conditional flags resulting from the comparisons for subsequent conditional branches or other flag-dependent instructions.
    *   Specific functions handle floating-point (single and double precision) and integer (32-bit and 64-bit) comparisons.
    *   There's specific logic for optimizing 32-bit comparisons, potentially using 64-bit compare instructions due to how values are represented in registers.

5. **Implementing Atomic Memory Operations (`VisitAtomicLoad`, `VisitAtomicStore`, `VisitAtomicExchange`, `VisitAtomicCompareExchange`, `VisitAtomicBinop`):**
    *   These functions generate LoongArch64 instructions for atomic operations, which are crucial for concurrent programming to ensure data integrity.
    *   They handle atomic loads, stores, exchange (swap), compare-and-exchange, and binary operations (like add, and, or) on memory locations.
    *   They consider the data size (atomic width) and memory access kind (e.g., protected).
    *   For atomic stores of tagged pointers, they potentially include write barriers for garbage collection.

6. **Checking Stack Pointer (`VisitStackPointerGreaterThan`):**
    *   This function generates instructions to check if the current stack pointer is greater than a certain limit. This is typically used for stack overflow detection.

7. **Optimizing Comparisons with Zero (`VisitWordCompareZero`):**
    *   This function provides an optimized way to handle comparisons where one of the operands is zero.
    *   It attempts to combine the comparison with previous operations (like inverting the condition if comparing against the result of an equality check).
    *   It handles various comparison opcodes (equality, less than, etc.) for both 32-bit and 64-bit integers and floats.
    *   It also looks for overflow projections from arithmetic operations to potentially combine the overflow check with the comparison.

**Regarding your specific questions:**

*   **`.tq` extension:** The provided code does not end with `.tq`. Therefore, it is **not** a V8 Torque source code file. Torque files are used for a more declarative way of defining compiler intrinsics and code generation patterns in V8.

*   **Relationship to JavaScript and Example:** This code is directly related to the execution of JavaScript. When V8 compiles JavaScript code for the LoongArch64 architecture, this code is responsible for selecting the appropriate low-level instructions.

    **JavaScript Example:**

    ```javascript
    function add(a, b) {
      return a + b;
    }

    let result = add(5, 10);

    if (result > 12) {
      console.log("Result is greater than 12");
    }
    ```

    *   The call to `add(5, 10)` would involve `EmitPrepareArguments` to set up the arguments `5` and `10` for the function call.
    *   The comparison `result > 12` would be handled by one of the `VisitWordCompare` functions, generating LoongArch64 comparison instructions and using `FlagsContinuationT` to potentially branch based on the result.

*   **Code Logic Inference (with assumptions):**

    *   **Assumption:** We are compiling the JavaScript code `if (x < 10) { ... }` where `x` is a 32-bit integer.
    *   **Input:** An IR node representing the `x < 10` comparison.
    *   **Output (from `VisitWord32Compare` or `VisitWordCompareZero`):** LoongArch64 instructions that perform the comparison. This might involve a `CMP` instruction comparing the register holding `x` with the immediate value `10`, followed by setting the appropriate flags. The `FlagsContinuationT` object would then be used to generate a conditional branch instruction based on the flags (e.g., a branch if less than).

*   **User Programming Errors:** While this code doesn't directly *cause* user programming errors, it plays a role in how V8 handles them. For instance:

    *   **Stack Overflow:** If a JavaScript program has excessive recursion, leading to a stack overflow, the code generated by `VisitStackPointerGreaterThan` (or similar stack checking mechanisms) will detect this and likely throw a `StackOverflowError`.
    *   **Incorrect Comparisons:** If a user makes a logical error in their JavaScript comparison (e.g., using `>` instead of `<`), this code will faithfully generate the corresponding (but logically incorrect) LoongArch64 comparison instruction.

*   **Summary of Functionality (Part 4 of 6):**

    This specific part of `instruction-selector-loong64.cc` focuses on:

    *   **Function call setup and result retrieval.**
    *   **Generating comparison instructions for various data types and handling conditional execution.**
    *   **Implementing atomic memory operations for concurrency.**
    *   **Stack overflow detection.**
    *   **Optimizing comparisons with zero.**

It acts as a crucial bridge between the architecture-independent IR and the concrete machine code for the LoongArch64 processor within the V8 JavaScript engine.

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/instruction-selector-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/loong64/instruction-selector-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
PushParameter>* arguments, const CallDescriptor* call_descriptor,
    node_t node) {
    Loong64OperandGeneratorT<Adapter> g(this);

    // Prepare for C function call.
    if (call_descriptor->IsCFunctionCall()) {
      int gp_param_count =
          static_cast<int>(call_descriptor->GPParameterCount());
      int fp_param_count =
          static_cast<int>(call_descriptor->FPParameterCount());
      Emit(kArchPrepareCallCFunction | ParamField::encode(gp_param_count) |
               FPParamField::encode(fp_param_count),
           0, nullptr, 0, nullptr);

      // Poke any stack arguments.
      int slot = 0;
      for (PushParameter input : (*arguments)) {
        Emit(kLoong64Poke, g.NoOutput(), g.UseRegister(input.node),
             g.TempImmediate(slot << kSystemPointerSizeLog2));
        ++slot;
      }
    } else {
      int push_count = static_cast<int>(call_descriptor->ParameterSlotCount());
      if (push_count > 0) {
        // Calculate needed space
        int stack_size = 0;
        for (PushParameter input : (*arguments)) {
          if (this->valid(input.node)) {
            stack_size += input.location.GetSizeInPointers();
          }
        }
        Emit(kLoong64StackClaim, g.NoOutput(),
             g.TempImmediate(stack_size << kSystemPointerSizeLog2));
      }
      for (size_t n = 0; n < arguments->size(); ++n) {
        PushParameter input = (*arguments)[n];
        if (this->valid(input.node)) {
          Emit(kLoong64Poke, g.NoOutput(), g.UseRegister(input.node),
               g.TempImmediate(static_cast<int>(n << kSystemPointerSizeLog2)));
        }
      }
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);

  for (PushParameter output : *results) {
    if (!output.location.IsCallerFrameSlot()) continue;
    // Skip any alignment holes in nodes.
    if (this->valid(output.node)) {
      DCHECK(!call_descriptor->IsCFunctionCall());
      if (output.location.GetType() == MachineType::Float32()) {
        MarkAsFloat32(output.node);
      } else if (output.location.GetType() == MachineType::Float64()) {
        MarkAsFloat64(output.node);
      } else if (output.location.GetType() == MachineType::Simd128()) {
        abort();
      }
      int offset = call_descriptor->GetOffsetToReturns();
      int reverse_slot = -output.location.GetLocation() - offset;
      Emit(kLoong64Peek, g.DefineAsRegister(output.node),
           g.UseImmediate(reverse_slot));
    }
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return false;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  UNREACHABLE();
}

namespace {

// Shared routine for multiple compare operations.
template <typename Adapter>
static Instruction* VisitCompare(InstructionSelectorT<Adapter>* selector,
                                 InstructionCode opcode,
                                 InstructionOperand left,
                                 InstructionOperand right,
                                 FlagsContinuationT<Adapter>* cont) {
#ifdef V8_COMPRESS_POINTERS
  if (opcode == kLoong64Cmp32) {
    Loong64OperandGeneratorT<Adapter> g(selector);
    InstructionOperand inputs[] = {left, right};
    if (right.IsImmediate()) {
      InstructionOperand temps[1] = {g.TempRegister()};
      return selector->EmitWithContinuation(opcode, 0, nullptr,
                                            arraysize(inputs), inputs,
                                            arraysize(temps), temps, cont);
    } else {
      InstructionOperand temps[2] = {g.TempRegister(), g.TempRegister()};
      return selector->EmitWithContinuation(opcode, 0, nullptr,
                                            arraysize(inputs), inputs,
                                            arraysize(temps), temps, cont);
    }
  }
#endif
  return selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple float32 compare operations.
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& op = selector->Get(node).template Cast<ComparisonOp>();
    OpIndex left = op.left();
    OpIndex right = op.right();
    InstructionOperand lhs, rhs;

    lhs =
        selector->MatchZero(left) ? g.UseImmediate(left) : g.UseRegister(left);
    rhs = selector->MatchZero(right) ? g.UseImmediate(right)
                                     : g.UseRegister(right);
    VisitCompare(selector, kLoong64Float32Cmp, lhs, rhs, cont);
  } else {
    Float32BinopMatcher m(node);
    InstructionOperand lhs, rhs;

    lhs = m.left().IsZero() ? g.UseImmediate(m.left().node())
                            : g.UseRegister(m.left().node());
    rhs = m.right().IsZero() ? g.UseImmediate(m.right().node())
                             : g.UseRegister(m.right().node());
    VisitCompare(selector, kLoong64Float32Cmp, lhs, rhs, cont);
  }
}

// Shared routine for multiple float64 compare operations.
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    Loong64OperandGeneratorT<Adapter> g(selector);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& compare = selector->Get(node);
    DCHECK(compare.Is<ComparisonOp>());
    OpIndex lhs = compare.input(0);
    OpIndex rhs = compare.input(1);
    if (selector->MatchZero(rhs)) {
      VisitCompare(selector, kLoong64Float64Cmp, g.UseRegister(lhs),
                   g.UseImmediate(rhs), cont);
    } else if (selector->MatchZero(lhs)) {
      VisitCompare(selector, kLoong64Float64Cmp, g.UseImmediate(lhs),
                   g.UseRegister(rhs), cont);
    } else {
      VisitCompare(selector, kLoong64Float64Cmp, g.UseRegister(lhs),
                   g.UseRegister(rhs), cont);
    }
  } else {
    Loong64OperandGeneratorT<Adapter> g(selector);
    Float64BinopMatcher m(node);
    InstructionOperand lhs, rhs;

    lhs = m.left().IsZero() ? g.UseImmediate(m.left().node())
                            : g.UseRegister(m.left().node());
    rhs = m.right().IsZero() ? g.UseImmediate(m.right().node())
                             : g.UseRegister(m.right().node());
    VisitCompare(selector, kLoong64Float64Cmp, lhs, rhs, cont);
  }
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont, bool commutative) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  // Match immediates on left or right side of comparison.
  if (g.CanBeImmediate(right, opcode)) {
    if (opcode == kLoong64Tst) {
      if constexpr (Adapter::IsTurbofan) {
        if (left->opcode() == IrOpcode::kTruncateInt64ToInt32) {
          VisitCompare(selector, opcode,
                       g.UseRegister(selector->input_at(left, 0)),
                       g.UseImmediate(right), cont);
          return;
        }
      }

      VisitCompare(selector, opcode, g.UseRegister(left), g.UseImmediate(right),
                   cont);
    } else {
      switch (cont->condition()) {
        case kEqual:
        case kNotEqual:
          if (cont->IsSet()) {
            VisitCompare(selector, opcode, g.UseUniqueRegister(left),
                         g.UseImmediate(right), cont);
          } else {
            VisitCompare(selector, opcode, g.UseUniqueRegister(left),
                         g.UseImmediate(right), cont);
          }
          break;
        case kSignedLessThan:
        case kSignedGreaterThanOrEqual:
        case kSignedLessThanOrEqual:
        case kSignedGreaterThan:
        case kUnsignedLessThan:
        case kUnsignedGreaterThanOrEqual:
        case kUnsignedLessThanOrEqual:
        case kUnsignedGreaterThan:
          VisitCompare(selector, opcode, g.UseUniqueRegister(left),
                       g.UseImmediate(right), cont);
          break;
        default:
          UNREACHABLE();
      }
    }
  } else if (g.CanBeImmediate(left, opcode)) {
    if (!commutative) cont->Commute();
    if (opcode == kLoong64Tst) {
      VisitCompare(selector, opcode, g.UseRegister(right), g.UseImmediate(left),
                   cont);
    } else {
      switch (cont->condition()) {
        case kEqual:
        case kNotEqual:
          if (cont->IsSet()) {
            VisitCompare(selector, opcode, g.UseUniqueRegister(right),
                         g.UseImmediate(left), cont);
          } else {
            VisitCompare(selector, opcode, g.UseUniqueRegister(right),
                         g.UseImmediate(left), cont);
          }
          break;
        case kSignedLessThan:
        case kSignedGreaterThanOrEqual:
        case kSignedLessThanOrEqual:
        case kSignedGreaterThan:
        case kUnsignedLessThan:
        case kUnsignedGreaterThanOrEqual:
        case kUnsignedLessThanOrEqual:
        case kUnsignedGreaterThan:
          VisitCompare(selector, opcode, g.UseUniqueRegister(right),
                       g.UseImmediate(left), cont);
          break;
        default:
          UNREACHABLE();
      }
    }
  } else {
    VisitCompare(selector, opcode, g.UseUniqueRegister(left),
                 g.UseUniqueRegister(right), cont);
  }
}

template <typename Adapter>
void VisitOptimizedWord32Compare(InstructionSelectorT<Adapter>* selector,
                                 Node* node, InstructionCode opcode,
                                 FlagsContinuationT<Adapter>* cont) {
  // TODO(LOONG_dev): LOONG64 Add check for debug mode
  VisitWordCompare(selector, node, opcode, cont, false);
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitFullWord32Compare(InstructionSelectorT<Adapter>* selector,
                            typename Adapter::node_t node,
                            InstructionCode opcode,
                            FlagsContinuationT<Adapter>* cont) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  InstructionOperand leftOp = g.TempRegister();
  InstructionOperand rightOp = g.TempRegister();

  selector->Emit(kLoong64Sll_d, leftOp,
                 g.UseRegister(selector->input_at(node, 0)),
                 g.TempImmediate(32));
  selector->Emit(kLoong64Sll_d, rightOp,
                 g.UseRegister(selector->input_at(node, 1)),
                 g.TempImmediate(32));

  Instruction* instr = VisitCompare(selector, opcode, leftOp, rightOp, cont);
  if constexpr (Adapter::IsTurboshaft) {
    selector->UpdateSourcePosition(instr, node);
  }
}

template <typename Adapter>
void VisitWord32Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitFullWord32Compare(selector, node, kLoong64Cmp64, cont);
  } else {
    // LOONG64 doesn't support Word32 compare instructions. Instead it relies
    // that the values in registers are correctly sign-extended and uses
    // Word64 comparison instead.
#ifdef USE_SIMULATOR
    // When call to a host function in simulator, if the function return a
    // int32 value, the simulator do not sign-extended to int64 because in
    // simulator we do not know the function whether return an int32 or int64.
    // so we need do a full word32 compare in this case.
    if (node->InputAt(0)->opcode() == IrOpcode::kCall ||
        node->InputAt(1)->opcode() == IrOpcode::kCall) {
      VisitFullWord32Compare(selector, node, kLoong64Cmp64, cont);
      return;
    }
#endif
    VisitOptimizedWord32Compare(selector, node, kLoong64Cmp32, cont);
  }
}

template <typename Adapter>
void VisitWord64Compare(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node,
                        FlagsContinuationT<Adapter>* cont) {
  VisitWordCompare(selector, node, kLoong64Cmp64, cont, false);
}

template <typename Adapter>
void VisitAtomicLoad(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto load = selector->load_view(node);
  node_t base = load.base();
  node_t index = load.index();

  // The memory order is ignored.
  LoadRepresentation load_rep = load.loaded_rep();
  InstructionCode code;
  switch (load_rep.representation()) {
    case MachineRepresentation::kWord8:
      DCHECK_IMPLIES(load_rep.IsSigned(), width == AtomicWidth::kWord32);
      code = load_rep.IsSigned() ? kAtomicLoadInt8 : kAtomicLoadUint8;
      break;
    case MachineRepresentation::kWord16:
      DCHECK_IMPLIES(load_rep.IsSigned(), width == AtomicWidth::kWord32);
      code = load_rep.IsSigned() ? kAtomicLoadInt16 : kAtomicLoadUint16;
      break;
    case MachineRepresentation::kWord32:
      code = (width == AtomicWidth::kWord32) ? kAtomicLoadWord32
                                             : kLoong64Word64AtomicLoadUint32;
      break;
    case MachineRepresentation::kWord64:
      code = kLoong64Word64AtomicLoadUint64;
      break;
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      code = kLoong64AtomicLoadDecompressTaggedSigned;
      break;
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      code = kLoong64AtomicLoadDecompressTagged;
      break;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
      code = kLoong64Word64AtomicLoadUint64;
      break;
#endif
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
      DCHECK(COMPRESS_POINTERS_BOOL);
      code = kLoong64Word64AtomicLoadUint32;
      break;
    default:
      UNREACHABLE();
  }

  bool traps_on_null;
  if (load.is_protected(&traps_on_null)) {
    // Atomic loads and null dereference are mutually exclusive. This might
    // change with multi-threaded wasm-gc in which case the access mode should
    // probably be kMemoryAccessProtectedNullDereference.
    DCHECK(!traps_on_null);
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  if (g.CanBeImmediate(index, code)) {
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(index));
  } else {
    selector->Emit(code | AddressingModeField::encode(kMode_MRR) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseRegister(index));
  }
}

template <typename Adapter>
AtomicStoreParameters AtomicStoreParametersOf(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node) {
  auto store = selector->store_view(node);
  return AtomicStoreParameters(store.stored_rep().representation(),
                               store.stored_rep().write_barrier_kind(),
                               store.memory_order().value(),
                               store.access_kind());
}

template <typename Adapter>
void VisitAtomicStore(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto store = selector->store_view(node);
  node_t base = store.base();
  node_t index = selector->value(store.index());
  node_t value = store.value();
  DCHECK_EQ(store.displacement(), 0);

  // The memory order is ignored.
  AtomicStoreParameters store_params = AtomicStoreParametersOf(selector, node);
  WriteBarrierKind write_barrier_kind = store_params.write_barrier_kind();
  MachineRepresentation rep = store_params.representation();

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  InstructionCode code;

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedPointer(rep));
    DCHECK_EQ(kTaggedSize, 8);

    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    code = kArchAtomicStoreWithWriteBarrier;
    code |= RecordWriteModeField::encode(record_write_mode);
  } else {
    switch (rep) {
      case MachineRepresentation::kWord8:
        code = kAtomicStoreWord8;
        break;
      case MachineRepresentation::kWord16:
        code = kAtomicStoreWord16;
        break;
      case MachineRepresentation::kWord32:
        code = kAtomicStoreWord32;
        break;
      case MachineRepresentation::kWord64:
        DCHECK_EQ(width, AtomicWidth::kWord64);
        code = kLoong64Word64AtomicStoreWord64;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
        DCHECK_EQ(AtomicWidthSize(width), kTaggedSize);
        code = kLoong64AtomicStoreCompressTagged;
        break;
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
        DCHECK(COMPRESS_POINTERS_BOOL);
        DCHECK_EQ(width, AtomicWidth::kWord32);
        code = kLoong64AtomicStoreCompressTagged;
        break;
      default:
        UNREACHABLE();
    }
  }

  if (store_params.kind() == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  if (g.CanBeImmediate(index, code)) {
    selector->Emit(code | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.NoOutput(), g.UseRegister(base), g.UseImmediate(index),
                   g.UseRegisterOrImmediateZero(value));
  } else {
    selector->Emit(code | AddressingModeField::encode(kMode_MRR) |
                       AtomicWidthField::encode(width),
                   g.NoOutput(), g.UseRegister(base), g.UseRegister(index),
                   g.UseRegisterOrImmediateZero(value));
  }
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         AtomicWidth width, MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temp[3];
  temp[0] = g.TempRegister();
  temp[1] = g.TempRegister();
  temp[2] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
}

template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode, AtomicWidth width,
                                MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[4];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(old_value);
  inputs[input_count++] = g.UseUniqueRegister(new_value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temp[3];
  temp[0] = g.TempRegister();
  temp[1] = g.TempRegister();
  temp[2] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
}

template <typename Adapter>
void VisitAtomicBinop(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      AtomicWidth width, MemoryAccessKind access_kind) {
  using node_t = typename Adapter::node_t;
  Loong64OperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temps[4];
  temps[0] = g.TempRegister();
  temps[1] = g.TempRegister();
  temps[2] = g.TempRegister();
  temps[3] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, 1, outputs, input_count, inputs, 4, temps);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuationT<Adapter>* cont) {
  StackCheckKind kind;
  node_t value;
  if constexpr (Adapter::IsTurboshaft) {
    const auto& op =
        this->turboshaft_graph()
            ->Get(node)
            .template Cast<turboshaft::StackPointerGreaterThanOp>();
    kind = op.kind;
    value = op.stack_limit();
  } else {
    kind = StackCheckKindOf(node->op());
    value = node->InputAt(0);
  }
  InstructionCode opcode =
      kArchStackPointerGreaterThan | MiscField::encode(static_cast<int>(kind));

  Loong64OperandGeneratorT<Adapter> g(this);

  // No outputs.
  InstructionOperand* const outputs = nullptr;
  const int output_count = 0;

  // TempRegister(0) is used to store the comparison result.
  // Applying an offset to this stack check requires a temp register. Offsets
  // are only applied to the first stack check. If applying an offset, we must
  // ensure the input and temp registers do not alias, thus kUniqueRegister.
  InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
  const int temp_count = (kind == StackCheckKind::kJSFunctionEntry ? 2 : 1);
  const auto register_mode = (kind == StackCheckKind::kJSFunctionEntry)
                                 ? OperandGenerator::kUniqueRegister
                                 : OperandGenerator::kRegister;

  InstructionOperand inputs[] = {g.UseRegisterWithMode(value, register_mode)};
  static constexpr int input_count = arraysize(inputs);

  EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                       temp_count, temps, cont);
}

// Shared routine for word comparisons against zero.
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    // Try to combine with comparisons against 0 by simply inverting the branch.
    while (value->opcode() == IrOpcode::kWord32Equal && CanCover(user, value)) {
      Int32BinopMatcher m(value);
      if (!m.right().Is(0)) break;
      user = value;
      value = m.left().node();
      cont->Negate();
    }

    if (CanCover(user, value)) {
      switch (value->opcode()) {
        case IrOpcode::kWord32Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kInt32LessThan:
          cont->OverwriteAndNegateIfEqual(kSignedLessThan);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kInt32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kUint32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kUint32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitWord32Compare(this, value, cont);
        case IrOpcode::kWord64Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kInt64LessThan:
          cont->OverwriteAndNegateIfEqual(kSignedLessThan);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kInt64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kUint64LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kUint64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitWord64Compare(this, value, cont);
        case IrOpcode::kFloat32Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat64Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kProjection:
          // Check if this is the overflow output projection of an
          // <Operation>WithOverflow node.
          if (ProjectionIndexOf(value->op()) == 1u) {
            // We cannot combine the <Operation>WithOverflow with this branch
            // unless the 0th projection (the use of the actual value of the
            // <Operation> is either nullptr, which means there's no use of the
            // actual value, or was already defined, which means it is scheduled
            // *AFTER* this branch).
            Node* const node = value->InputAt(0);
            Node* const result = NodeProperties::FindProjection(node, 0);
            if (result == nullptr || IsDefined(result)) {
              switch (node->opcode()) {
                case IrOpcode::kInt32AddWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64Add_d, cont);
                case IrOpcode::kInt32SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64Sub_d, cont);
                case IrOpcode::kInt32MulWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64MulOvf_w, cont);
                case IrOpcode::kInt64MulWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64MulOvf_d, cont);
                case IrOpcode::kInt64AddWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64AddOvf_d, cont);
                case IrOpcode::kInt64SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kLoong64SubOvf_d, cont);
                default:
                  break;
              }
            }
          }
          break;
        case IrOpcode::kWord32And:
        case IrOpcode::kWord64And:
          return VisitWordCompare(this, value, kLoong64Tst, cont, true);
        case IrOpcode::kStackPointerGreaterThan:
          cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
          return VisitStackPointerGreaterThan(value, cont);
        default:
          break;
      }
    }

    // Continuation could not be combined with a compare, emit compare against
    // 0.
    VisitCompare(this, kLoong64Cmp32, g.UseRegister(value), g.TempImmediate(0),
                 cont);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    Loong64OperandGeneratorT<TurboshaftAdapter> g(this);
    // Try to combine with comparisons against 0 by simply inverting the branch.
    while (const ComparisonOp* equal =
               this->TryCast<Opmask::kWord32Equal>(value)) {
      if (!CanCover(user, value)) break;
      if (!MatchIntegralZero(equal->right())) break;
      user = value;
      value = equal->left();
      cont->Negate();
    }

    const Operation& value_op = Get(value);
    if (CanCover(user, value)) {
      if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
        switch (comparison->rep.value()) {
          case RegisterRepresentation::Word32():
            cont->OverwriteAndNegateIfEqual(
                GetComparisonFlagCondition(*comparison));
            return VisitWord32Compare(this, value, cont);

          case RegisterRepresentation::Word64():
            cont->OverwriteAndNegateIfEqual(
                GetComparisonFlagCondition(*comparison));
            return VisitWord64Compare(this, value, cont);

          case RegisterRepresentation::Float32():
            switch (comparison->kind) {
              case ComparisonOp::Kind::kEqual:
                cont->OverwriteAndNegateIfEqual(kEqual);
                return VisitFloat32Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThan:
                cont->OverwriteAndNegateIfEqual(kFloatLessThan);
                return VisitFloat32Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThanOrEqual:
                cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
                return VisitFloat32Compare(this, value, cont);
              default:
                UNREACHABLE();
            }
"""


```