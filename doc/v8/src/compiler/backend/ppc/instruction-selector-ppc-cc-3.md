Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc`. I need to analyze the code and summarize its purpose within the V8 compiler.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the core purpose:** The filename `instruction-selector-ppc.cc` strongly suggests this code is responsible for selecting specific PowerPC (PPC) instructions based on higher-level intermediate representations (IR) of code. This is a crucial step in the compilation process where abstract operations are translated into concrete machine instructions.

2. **Analyze the code structure:** The code is filled with `case` statements within `switch` blocks. These `switch` statements operate on `IrOpcode` enums. This confirms the initial hypothesis: the code is mapping IR operations to PPC instructions.

3. **Examine specific `case` blocks:**  Let's look at some examples:
    * `IrOpcode::kFloat64LessThan`: This handles a floating-point less-than comparison. The code calls `VisitFloat64Compare`. This suggests a separate helper function handles the actual instruction emission for floating-point comparisons. The `cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);` line implies the condition codes need manipulation based on the specific comparison type.
    * `IrOpcode::kProjection`: This handles projections, often related to multi-output operations like those that can overflow. The code checks for `kInt32AddWithOverflow`, `kInt32SubWithOverflow`, etc. This confirms the code handles operations that produce both a result and an overflow flag. It emits instructions like `kPPC_AddWithOverflow32`.
    * `IrOpcode::kInt32Sub`, `IrOpcode::kWord32And`, `IrOpcode::kInt64Sub`, `IrOpcode::kWord64And`: These handle integer and bitwise operations. They call functions like `VisitWord32Compare` and `VisitWordCompare`, again indicating a pattern of delegating to specialized handlers.
    * `IrOpcode::kStackPointerGreaterThan`: This handles stack pointer comparisons and seems to directly manipulate condition codes.

4. **Look for patterns and common themes:**
    * **`Visit...` functions:**  The repeated use of `Visit...` functions (e.g., `VisitFloat64Compare`, `VisitWord32Compare`) suggests a strategy of breaking down the instruction selection process into smaller, manageable parts based on the type of operation.
    * **`FlagsContinuation`:** This class appears to manage the setting and manipulation of processor flags based on the comparison results. The `OverwriteAndNegateIfEqual` method is used to adjust the condition code for branching.
    * **Operand generation:** The `PPCOperandGeneratorT` class is used to create operands for the PPC instructions, handling register allocation and immediate values.
    * **Overflow handling:**  A significant portion of the code deals with operations that can overflow and how to check for and handle these cases.

5. **Address the specific user questions:**
    * **Functionality:**  Based on the analysis, the primary function is instruction selection for the PowerPC architecture in the V8 compiler's backend.
    * **Torque:** The code snippet is clearly C++, not Torque. The user's statement about `.tq` is a conditional check.
    * **JavaScript relationship:** The code translates JavaScript operations into machine code. Comparisons, arithmetic, and bitwise operations in JavaScript will eventually be processed by this code.
    * **JavaScript example:** Provide a simple JavaScript example that uses comparisons and arithmetic to illustrate how these high-level concepts map to the low-level operations handled by this C++ code.
    * **Code logic reasoning (input/output):** Choose a simple case, like `IrOpcode::kInt32Sub` within a conditional branch. Demonstrate how the input IR node representing the subtraction is processed and how the `FlagsContinuation` influences the emitted comparison instruction. This requires making assumptions about the structure of the IR.
    * **Common programming errors:**  Overflow errors in integer arithmetic are a direct consequence of the operations handled here. Provide a JavaScript example of integer overflow.
    * **Summary:**  Synthesize the findings into a concise summary of the code's role.

6. **Refine the answer:** Ensure the language is clear, concise, and uses the correct terminology (e.g., IR, instruction selection, condition codes). Double-check the examples for correctness and clarity. Acknowledge the "part 4 of 5" context.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
Based on the provided C++ code snippet from `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code snippet is a part of the **Instruction Selector** for the PowerPC (PPC) architecture within the V8 JavaScript engine's optimizing compiler (TurboFan or Turboshaft). Its primary function is to **translate intermediate representation (IR) nodes representing operations into specific PowerPC machine instructions**.

**Key Operations and Concepts Demonstrated in the Snippet:**

* **Handling Comparison Operations:** The code heavily focuses on handling various comparison operations (less than, less than or equal to, equal) for different data types (float32, float64, int32, int64). It uses the `FlagsContinuation` class to manage how the results of these comparisons (processor flags) are used for conditional branching.
* **Combining Comparisons with Branches:** The code attempts to optimize branching by combining comparison operations directly with branch instructions. For example, if a branch depends on the result of `kFloat64LessThan`, it tries to emit a single PPC instruction that performs the comparison and branches based on the result.
* **Handling Overflow Checks:**  It specifically handles operations that can potentially overflow (like `kInt32AddWithOverflow`, `kInt32MulWithOverflow`). It checks for the overflow projection of these operations and emits appropriate PPC instructions (e.g., `kPPC_AddWithOverflow32`) and conditional branches based on the overflow flag.
* **Bitwise Operations:** It handles bitwise AND operations (`kWord32And`, `kWord64And`) using the `kPPC_Tst32` and `kPPC_Tst64` instructions for testing bits. It notes opportunities for potential optimization with instructions like `rlwinm` and `rldic` (rotate and mask instructions).
* **Stack Pointer Comparisons:** It handles comparisons with the stack pointer (`kStackPointerGreaterThan`).
* **Switch Statements:** It implements logic for selecting the best strategy for compiling switch statements, choosing between a jump table (`ArchTableSwitch`) and a binary search tree (`ArchBinarySearchSwitch`) based on the number of cases and the range of values.
* **Handling Constants:** It has specific logic for comparing against root handles (constants stored in the V8 heap), potentially optimizing by using immediate values in the comparison if the root is read-only.
* **Atomic Operations:** The latter part of the snippet deals with atomic operations (load, store, exchange, compare exchange) for both 32-bit and 64-bit values. It selects appropriate PowerPC atomic instructions based on the data type and the specific atomic operation.

**If `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc` ended with `.tq`:**

The comment within the code explicitly states: "如果v8/src/compiler/backend/ppc/instruction-selector-ppc.cc以.tq结尾，那它是个v8 torque源代码". This means **if the file ended with `.tq`, it would be a V8 Torque source file.** Torque is V8's internal language for defining built-in functions and some compiler components. Since the file ends with `.cc`, it's a standard C++ source file.

**Relationship with JavaScript and Example:**

This code directly translates JavaScript operations into low-level machine instructions. For example, a JavaScript comparison like:

```javascript
let a = 10;
let b = 5;
if (a > b) {
  console.log("a is greater than b");
}
```

The `a > b` comparison would eventually be represented as an IR node (likely `kInt32GreaterThan` or similar if `a` and `b` are integers). The code in `instruction-selector-ppc.cc` would be responsible for selecting the appropriate PPC comparison instruction to evaluate this condition and set the processor flags, which would then be used by the branch instruction corresponding to the `if` statement.

**Code Logic Reasoning (Hypothetical Input and Output):**

**Hypothetical Input:** An IR node representing the operation `a - b` where `a` and `b` are 32-bit integers, within the context of a conditional branch checking if the result is less than 0.

**Processing:** The `VisitWordCompareZero` function would be called (since we're branching based on whether the result is zero). It would identify the input node as `kInt32Sub`. The `VisitWord32Compare` function would likely be called.

**Hypothetical Output:**  The instruction selector might emit the following PPC instructions (simplified representation):

```assembly
sub  rX, rY, rZ  // Subtract the register holding 'b' (rY) from the register holding 'a' (rX), store in rZ.
cmplwi rZ, 0     // Compare the value in rZ with the immediate value 0.
blt  target_label // Branch to 'target_label' if the Less Than flag is set (meaning rZ < 0).
```

**Assumptions:**
* `rX` holds the value of `a`.
* `rY` holds the value of `b`.
* `rZ` is a temporary register.
* `target_label` is the address of the code to execute if `a - b < 0`.

**Common Programming Errors:**

This code helps prevent certain errors at the compilation level by correctly handling operations. However, common programming errors related to the operations it handles include:

* **Integer Overflow:**  Performing arithmetic operations that exceed the maximum or minimum value representable by the integer type.

   ```javascript
   let maxInt = 2147483647;
   let result = maxInt + 1; // Integer overflow
   console.log(result); // Output might be a negative number due to wrapping.
   ```
   The `kInt32AddWithOverflow` handling in the C++ code is directly related to detecting and potentially throwing exceptions for such overflows (depending on the JavaScript semantics of the operation).

* **Floating-Point Precision Errors:**  Comparisons involving floating-point numbers can sometimes lead to unexpected results due to the limitations of representing real numbers in binary.

   ```javascript
   let x = 0.1 + 0.2;
   let y = 0.3;
   if (x === y) { // This might evaluate to false due to precision issues.
       console.log("Equal");
   } else {
       console.log("Not equal"); // Likely output
   }
   ```
   The `VisitFloat32Equal` and `VisitFloat64Equal` functions in the C++ code translate these floating-point comparisons into PPC instructions, but the inherent precision limitations remain.

**归纳一下它的功能 (Summarize its Functionality):**

This part of the `instruction-selector-ppc.cc` file is responsible for the **core logic of translating comparison operations, overflow-checked arithmetic, bitwise operations, stack pointer comparisons, and switch statements from V8's intermediate representation into specific PowerPC machine instructions.** It plays a crucial role in the code generation pipeline, ensuring that JavaScript code is efficiently translated into executable PPC assembly. It also includes handling for atomic operations.

Prompt: 
```
这是目录为v8/src/compiler/backend/ppc/instruction-selector-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ppc/instruction-selector-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
);
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
                return VisitBinop<Adapter>(this, node, kPPC_AddWithOverflow32,
                                           kInt16Imm, cont);
              case IrOpcode::kInt32SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<Adapter>(this, node, kPPC_SubWithOverflow32,
                                           kInt16Imm_Negate, cont);
              case IrOpcode::kInt32MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kNotEqual);
                return EmitInt32MulWithOverflow(this, node, cont);
              case IrOpcode::kInt64AddWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<Adapter>(this, node, kPPC_Add64, kInt16Imm,
                                           cont);
              case IrOpcode::kInt64SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<Adapter>(this, node, kPPC_Sub,
                                           kInt16Imm_Negate, cont);
              case IrOpcode::kInt64MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kNotEqual);
                return EmitInt64MulWithOverflow(this, node, cont);
              default:
                break;
            }
          }
        }
        break;
      case IrOpcode::kInt32Sub:
        return VisitWord32Compare(this, value, cont);
      case IrOpcode::kWord32And:
        // TODO(mbandy): opportunity for rlwinm?
        return VisitWordCompare(this, value, kPPC_Tst32, cont, true,
                                kInt16Imm_Unsigned);
// TODO(mbrandy): Handle?
// case IrOpcode::kInt32Add:
// case IrOpcode::kWord32Or:
// case IrOpcode::kWord32Xor:
// case IrOpcode::kWord32Sar:
// case IrOpcode::kWord32Shl:
// case IrOpcode::kWord32Shr:
// case IrOpcode::kWord32Ror:
      case IrOpcode::kInt64Sub:
        return VisitWord64Compare(this, value, cont);
      case IrOpcode::kWord64And:
        // TODO(mbandy): opportunity for rldic?
        return VisitWordCompare(this, value, kPPC_Tst64, cont, true,
                                kInt16Imm_Unsigned);
// TODO(mbrandy): Handle?
// case IrOpcode::kInt64Add:
// case IrOpcode::kWord64Or:
// case IrOpcode::kWord64Xor:
// case IrOpcode::kWord64Sar:
// case IrOpcode::kWord64Shl:
// case IrOpcode::kWord64Shr:
// case IrOpcode::kWord64Ror:
      case IrOpcode::kStackPointerGreaterThan:
        cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
        return VisitStackPointerGreaterThan(value, cont);
      default:
        break;
      }
    }

  // Branch could not be combined with a compare, emit compare against 0.
  PPCOperandGeneratorT<Adapter> g(this);
  VisitCompare(this, kPPC_Cmp32, g.UseRegister(value), g.TempImmediate(0),
               cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  // Try to combine with comparisons against 0 by simply inverting the branch.
  ConsumeEqualZero(&user, &value, cont);

  if (CanCover(user, value)) {
    const Operation& value_op = Get(value);
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      switch (comparison->rep.MapTaggedToWord().value()) {
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
              cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
              return VisitFloat32Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        case RegisterRepresentation::Float64():
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kEqual);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
              return VisitFloat64Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        default:
          break;
      }
    } else if (const ProjectionOp* projection =
                   value_op.TryCast<ProjectionOp>()) {
      // Check if this is the overflow output projection of an
      // <Operation>WithOverflow node.
      if (projection->index == 1u) {
        // We cannot combine the <Operation>WithOverflow with this branch
        // unless the 0th projection (the use of the actual value of the
        // <Operation> is either nullptr, which means there's no use of the
        // actual value, or was already defined, which means it is scheduled
        // *AFTER* this branch).
        OpIndex node = projection->input();
        OpIndex result = FindProjection(node, 0);
        if (!result.valid() || IsDefined(result)) {
          if (const OverflowCheckedBinopOp* binop =
                  TryCast<OverflowCheckedBinopOp>(node)) {
            const bool is64 = binop->rep == WordRepresentation::Word64();
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node,
                                  is64 ? kPPC_Add64 : kPPC_AddWithOverflow32,
                                  kInt16Imm, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node,
                                  is64 ? kPPC_Sub : kPPC_SubWithOverflow32,
                                  kInt16Imm_Negate, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                if (is64) {
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt64MulWithOverflow(this, node, cont);
                } else {
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt32MulWithOverflow(this, node, cont);
                }
            }
          }
        }
      }
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWord32Compare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      return VisitWordCompare(this, value, kPPC_Tst32, cont, true,
                              kInt16Imm_Unsigned);
    } else if (value_op.Is<Opmask::kWord64Sub>()) {
      return VisitWord64Compare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord64BitwiseAnd>()) {
      return VisitWordCompare(this, value, kPPC_Tst64, cont, true,
                              kInt16Imm_Unsigned);
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }

  // Branch could not be combined with a compare, emit compare against 0.
  PPCOperandGeneratorT<TurboshaftAdapter> g(this);
  VisitCompare(this, kPPC_Cmp32, g.UseRegister(value), g.TempImmediate(0),
               cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  PPCOperandGeneratorT<Adapter> g(this);
  InstructionOperand value_operand = g.UseRegister(this->input_at(node, 0));

  // Emit either ArchTableSwitch or ArchBinarySearchSwitch.
  if (enable_switch_jump_table_ ==
      InstructionSelector::kEnableSwitchJumpTable) {
  static const size_t kMaxTableSwitchValueRange = 2 << 16;
  size_t table_space_cost = 4 + sw.value_range();
  size_t table_time_cost = 3;
  size_t lookup_space_cost = 3 + 2 * sw.case_count();
  size_t lookup_time_cost = sw.case_count();
  if (sw.case_count() > 0 &&
      table_space_cost + 3 * table_time_cost <=
          lookup_space_cost + 3 * lookup_time_cost &&
      sw.min_value() > std::numeric_limits<int32_t>::min() &&
      sw.value_range() <= kMaxTableSwitchValueRange) {
      InstructionOperand index_operand = value_operand;
      if (sw.min_value()) {
      index_operand = g.TempRegister();
      Emit(kPPC_Sub, index_operand, value_operand,
           g.TempImmediate(sw.min_value()));
      }
      // Zero extend, because we use it as 64-bit index into the jump table.
      InstructionOperand index_operand_zero_ext = g.TempRegister();
      Emit(kPPC_Uint32ToUint64, index_operand_zero_ext, index_operand);
      index_operand = index_operand_zero_ext;
      // Generate a table lookup.
      return EmitTableSwitch(sw, index_operand);
  }
  }

  // Generate a tree of conditional jumps.
  return EmitBinarySearchSwitch(sw, value_operand);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Equal(
    node_t const node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                    (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
    PPCOperandGeneratorT<TurbofanAdapter> g(this);
    const RootsTable& roots_table = isolate()->roots_table();
    RootIndex root_index;
    Node* left = nullptr;
    Handle<HeapObject> right;
    // HeapConstants and CompressedHeapConstants can be treated the same when
    // using them as an input to a 32-bit comparison. Check whether either is
    // present.
    {
      CompressedHeapObjectBinopMatcher m(node);
      if (m.right().HasResolvedValue()) {
      left = m.left().node();
      right = m.right().ResolvedValue();
      } else {
      HeapObjectBinopMatcher m2(node);
      if (m2.right().HasResolvedValue()) {
          left = m2.left().node();
          right = m2.right().ResolvedValue();
      }
      }
    }
  if (!right.is_null() && roots_table.IsRootHandle(right, &root_index)) {
      DCHECK_NE(left, nullptr);
      if (RootsTable::IsReadOnly(root_index)) {
      Tagged_t ptr = MacroAssemblerBase::ReadOnlyRootPtr(root_index, isolate());
      if (g.CanBeImmediate(ptr, kInt16Imm)) {
          return VisitCompare(this, kPPC_Cmp32, g.UseRegister(left),
                              g.TempImmediate(ptr), &cont);
      }
      }
  }
  }
  VisitWord32Compare(this, node, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Equal(
    node_t const node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& equal = Get(node);
  DCHECK(equal.Is<ComparisonOp>());
  OpIndex left = equal.input(0);
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                    (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
    PPCOperandGeneratorT<TurboshaftAdapter> g(this);
    const RootsTable& roots_table = isolate()->roots_table();
    RootIndex root_index;
    Handle<HeapObject> right;
    // HeapConstants and CompressedHeapConstants can be treated the same when
    // using them as an input to a 32-bit comparison. Check whether either is
    // present.
    if (MatchHeapConstant(node, &right) && !right.is_null() &&
        roots_table.IsRootHandle(right, &root_index)) {
      if (RootsTable::IsReadOnly(root_index)) {
        Tagged_t ptr =
            MacroAssemblerBase::ReadOnlyRootPtr(root_index, isolate());
        if (g.CanBeImmediate(ptr, kInt16Imm)) {
          return VisitCompare(this, kPPC_Cmp32, g.UseRegister(left),
                              g.TempImmediate(ptr), &cont);
        }
      }
    }
  }
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWord32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Equal(node_t const node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWord64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kNotEqual, ovf);
    return EmitInt32MulWithOverflow(this, node, &cont);
  }
  FlagsContinuation cont;
  EmitInt32MulWithOverflow(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveParamToFPR(node_t node, int index) {
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveFPRToParam(
    InstructionOperand* op, LinkageLocation location) {}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareArguments(
    ZoneVector<PushParameter>* arguments, const CallDescriptor* call_descriptor,
    node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);

  // Prepare for C function call.
  if (call_descriptor->IsCFunctionCall()) {
    Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                         call_descriptor->ParameterCount())),
         0, nullptr, 0, nullptr);

    // Poke any stack arguments.
    int slot = kStackFrameExtraParamSlot;
    for (PushParameter input : (*arguments)) {
      if (!this->valid(input.node)) continue;
      Emit(kPPC_StoreToStackSlot, g.NoOutput(), g.UseRegister(input.node),
           g.TempImmediate(slot));
      ++slot;
    }
  } else {
    // Push any stack arguments.
    int stack_decrement = 0;
    for (PushParameter input : base::Reversed(*arguments)) {
      stack_decrement += kSystemPointerSize;
      // Skip any alignment holes in pushed nodes.
      if (!this->valid(input.node)) continue;
      InstructionOperand decrement = g.UseImmediate(stack_decrement);
      stack_decrement = 0;
      Emit(kPPC_Push, g.NoOutput(), decrement, g.UseRegister(input.node));
    }
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return false;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64ExtractLowWord32(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  Emit(kPPC_DoubleExtractLowWord32, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64ExtractHighWord32(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  Emit(kPPC_DoubleExtractHighWord32, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  PPCOperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast = this->Cast<BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();

  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kPPC_DoubleFromWord32Pair, g.DefineAsRegister(node), g.UseRegister(hi),
       g.UseRegister(lo), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
  UNIMPLEMENTED();
  } else {
  PPCOperandGeneratorT<Adapter> g(this);
  Node* left = node->InputAt(0);
  Node* right = node->InputAt(1);
  if (left->opcode() == IrOpcode::kFloat64InsertHighWord32 &&
      CanCover(node, left)) {
    left = left->InputAt(1);
    Emit(kPPC_DoubleConstruct, g.DefineAsRegister(node), g.UseRegister(left),
         g.UseRegister(right));
    return;
  }
  Emit(kPPC_DoubleInsertLowWord32, g.DefineSameAsFirst(node),
       g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
  UNIMPLEMENTED();
  } else {
  PPCOperandGeneratorT<Adapter> g(this);
  Node* left = node->InputAt(0);
  Node* right = node->InputAt(1);
  if (left->opcode() == IrOpcode::kFloat64InsertLowWord32 &&
      CanCover(node, left)) {
    left = left->InputAt(1);
    Emit(kPPC_DoubleConstruct, g.DefineAsRegister(node), g.UseRegister(right),
         g.UseRegister(left));
    return;
  }
  Emit(kPPC_DoubleInsertHighWord32, g.DefineSameAsFirst(node),
       g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  Emit(kPPC_Sync, g.NoOutput());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  auto load_view = this->load_view(node);
  ImmediateMode mode;
  InstructionCode opcode = SelectLoadOpcode(load_view.loaded_rep(), &mode);
  VisitLoadCommon(this, node, mode, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicLoad(node_t node) {
  auto load_view = this->load_view(node);
  ImmediateMode mode;
  InstructionCode opcode = SelectLoadOpcode(load_view.loaded_rep(), &mode);
  VisitLoadCommon(this, node, mode, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  auto store = this->store_view(node);
  AtomicStoreParameters store_params(store.stored_rep().representation(),
                                     store.stored_rep().write_barrier_kind(),
                                     store.memory_order().value(),
                                     store.access_kind());
  VisitStoreCommon(this, node, store_params.store_representation(),
                   store_params.order());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicStore(node_t node) {
  auto store = this->store_view(node);
  AtomicStoreParameters store_params(store.stored_rep().representation(),
                                     store.stored_rep().write_barrier_kind(),
                                     store.memory_order().value(),
                                     store.access_kind());
  VisitStoreCommon(this, node, store_params.store_representation(),
                   store_params.order());
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode) {
  using node_t = typename Adapter::node_t;
  PPCOperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRR;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  selector->Emit(code, 1, outputs, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicExchange(node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = kAtomicExchangeInt8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kPPC_AtomicExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = kAtomicExchangeInt16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kPPC_AtomicExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
               atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kPPC_AtomicExchangeWord32;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = kAtomicExchangeInt8;
    } else if (type == MachineType::Uint8()) {
      opcode = kPPC_AtomicExchangeUint8;
    } else if (type == MachineType::Int16()) {
      opcode = kAtomicExchangeInt16;
    } else if (type == MachineType::Uint16()) {
      opcode = kPPC_AtomicExchangeUint16;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = kPPC_AtomicExchangeWord32;
    } else {
      UNREACHABLE();
    }
  }
  VisitAtomicExchange(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicExchange(node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kPPC_AtomicExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kPPC_AtomicExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kPPC_AtomicExchangeWord32;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
      opcode = kPPC_AtomicExchangeWord64;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Uint8()) {
      opcode = kPPC_AtomicExchangeUint8;
    } else if (type == MachineType::Uint16()) {
      opcode = kPPC_AtomicExchangeUint16;
    } else if (type == MachineType::Uint32()) {
      opcode = kPPC_AtomicExchangeWord32;
    } else if (type == MachineType::Uint64()) {
      opcode = kPPC_AtomicExchangeWord64;
    } else {
      UNREACHABLE();
    }
  }
  VisitAtomicExchange(this, node, opcode);
}

template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode) {
  using node_t = typename Adapter::node_t;
  PPCOperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRR;
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);

  InstructionOperand inputs[4];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(old_value);
  inputs[input_count++] = g.UseUniqueRegister(new_value);

  InstructionOperand outputs[1];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  selector->Emit(code, output_count, outputs, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = kAtomicCompareExchangeInt8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kPPC_AtomicCompareExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = kAtomicCompareExchangeInt16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kPPC_AtomicCompareExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
               atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kPPC_AtomicCompareExchangeWord32;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = kAtomicCompareExchangeInt8;
    } else if (type == MachineType::Uint8()) {
      opcode = kPPC_AtomicCompareExchangeUint8;
    } else if (type == MachineType::Int16()) {
      opcode = kAtomicCompareExchangeInt16;
    } else if (type == MachineType::Uint16()) {
      opcode = kPPC_AtomicCompareExchangeUint16;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = kPPC_AtomicCompareExchangeWord32;
    } else {
      UNREACHABLE();
    }
  }
  VisitAtomicCompareExchange(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicCompareExchange(
    node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kPPC_AtomicCompareExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kPPC_AtomicCompareExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kPPC_AtomicCompareExchangeWord32;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
      opcode = kPPC_AtomicCompareExchangeWord64;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Uint8()) {
      opcode = kPPC_AtomicCompareExchangeUint8;
    } else if (type == MachineType::Uint16()) {
      opcode = kPPC_AtomicCompareExchangeUint16;
    } else if (type == MachineType::Uint32()) {
      opcode = kPPC_AtomicCompareExchangeWord32;
    } else if (type == MachineType::Uint64()) {
      opcode = kPPC_AtomicCompareExchangeWord64;
    } else {
      UNREACHABLE();
    }
  }
  VisitAtomicCompareExchange(this, node, opcode);
}

template <typename Adapter>
void VisitAtomicBinaryOperation(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode int8_op, ArchOpcode uint8_op,
                                ArchOpcode int16_op, ArchOpcode uint16_op,
                                ArchOpcode int32_op, ArchOpcode uint32_op,
                                ArchOpcode int64_op, ArchOpcode uint64_op) {
  using node_t = typename Adapter::node_t;
  PPCOperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op =
        selector->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = int8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = uint8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = int16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = uint16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32()) {
      opcode = int32_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = uint32_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int64()) {
      opcode = int64_op;
    } else if (atomic_op.memory_rep == Memor
"""


```