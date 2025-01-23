Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/x64/instruction-selector-x64.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Function:** The file name and the code itself heavily suggest this file is responsible for *instruction selection* in the V8 compiler backend for the x64 architecture. This means it takes high-level operations and translates them into specific x64 machine instructions.

2. **Analyze Key Functions and Templates:**  Look for the prominent functions and template structures. The code contains functions like `TryNarrowOpcodeSize`, `RemoveUnnecessaryWordAnd`, `VisitWordCompare`, `VisitWord32EqualImpl`, `VisitWord64EqualImpl`, `VisitCompareZero`, `VisitFloat32Compare`, `VisitFloat64Compare`, and `VisitAtomicBinop`/`VisitAtomicCompareExchange`. These names clearly indicate their purpose: selecting the right instruction variant based on operand types and optimizing comparisons. The template structure `<typename Adapter>` suggests the code is designed to be used by different instruction selection "adapters," likely for Turbofan and Turboshaft, V8's optimizing compilers.

3. **Examine Specific Optimizations:** Notice the `RemoveUnnecessaryWordAnd` function. This is a concrete optimization, where redundant bitwise AND operations can be eliminated if a subsequent comparison effectively masks the same bits. This demonstrates a focus on code size and performance.

4. **Focus on Comparison Logic:** The majority of the code deals with comparisons (`VisitWordCompare`, `VisitWord32EqualImpl`, `VisitWord64EqualImpl`, `VisitCompareZero`, `VisitFloat32Compare`, `VisitFloat64Compare`). Pay close attention to how different comparison opcodes (like `kX64Cmp`, `kX64Test`) are chosen based on the types of operands and the desired outcome. The logic around `FlagsContinuationT` is also crucial, indicating how comparison results are used for branching.

5. **Consider Different Data Types:** The code handles `Word32`, `Word64`, `Float32`, and `Float64` comparisons. This highlights the need for type-specific instruction selection.

6. **Look for Architecture-Specific Details:**  The code mentions AVX and SSE instructions, which are x64 instruction set extensions for optimized floating-point operations. The handling of root handles (`kMode_Root`) and pointer compression (`V8_COMPRESS_POINTERS`) are also architecture-specific optimizations.

7. **Infer the Role of `FlagsContinuationT`:**  The repeated use of `FlagsContinuationT` and methods like `OverwriteUnsignedIfSigned`, `Commute`, and `Negate` indicates this object manages how comparison results (flags) are used for subsequent conditional branches. This is a core part of instruction selection for control flow.

8. **Address the Specific Questions in the Prompt:**
    * **Functionality:** Summarize the core purpose as instruction selection and optimization for comparisons on x64.
    * **.tq extension:** State that this file is `.cc`, so it's not Torque.
    * **Relationship to JavaScript:** Explain that while directly C++, it's crucial for efficient execution of JavaScript. Provide a simple JavaScript example of a comparison that would involve this code during compilation.
    * **Code Logic/Assumptions:**  Choose a simple function like `TryNarrowOpcodeSize` and create a hypothetical input and output to illustrate its behavior.
    * **Common Programming Errors:** Focus on type mismatches in comparisons, as this is directly related to the code's function of selecting the correct comparison instruction based on type.
    * **Part of a Larger System:** Acknowledge that this is one piece of a larger compiler backend.

9. **Structure the Answer:** Organize the findings logically, starting with the main functionality, then addressing the specific points from the prompt. Use clear and concise language.

10. **Review and Refine:** Read through the answer to ensure accuracy, completeness, and clarity. Make sure the examples are relevant and easy to understand. For instance, initially, I might have only focused on individual function descriptions. However, the request asks for an *overall* understanding, so I should synthesize the information to describe the broader functionality. Also ensure that the provided JavaScript example is simple and directly relates to the concepts discussed in the C++ code.
Based on the provided C++ code snippet from `v8/src/compiler/backend/x64/instruction-selector-x64.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code is a part of the **instruction selection** phase within the V8 JavaScript engine's optimizing compiler (likely Turbofan or Turboshaft) for the **x64 architecture**. Its primary role is to take higher-level, architecture-independent intermediate representation (IR) nodes representing operations and **select the most appropriate and efficient x64 machine instructions** to implement them. Specifically, this snippet focuses heavily on **selecting instructions for comparison operations**.

**Key Functionalities Detailed:**

* **Narrowing Opcode Size (`TryNarrowOpcodeSize`):** This function attempts to optimize comparison instructions by using smaller operand sizes (8-bit, 16-bit, or 32-bit) when possible, instead of always using the full 64-bit size. It checks the types of the operands and the target instruction to determine if a narrower instruction can be used without loss of information. This can lead to smaller and potentially faster code.
* **Removing Unnecessary WordAnd (`RemoveUnnecessaryWordAnd`):**  This optimization identifies cases where a bitwise AND operation with a mask is performed just before a comparison. If the comparison instruction effectively already masks the relevant bits (e.g., comparing with an 8-bit value), the explicit AND operation can be removed.
* **Handling Word Comparisons (`VisitWordCompare`, `VisitWord32EqualImpl`, `VisitWord64EqualImpl`):** These functions handle the selection of comparison instructions for integer (word) values. They consider factors like:
    * **Operand Types:** Whether operands are registers, immediates (constants), or memory locations.
    * **Immediate Placement:**  Ensuring immediates are often placed on the right side of the comparison instruction.
    * **Memory Operands:**  Prioritizing memory operands on the left side in some cases.
    * **Root Handles:** Optimizing comparisons against specific pre-defined values (root handles) used within V8.
    * **Pointer Compression:**  Adjusting comparison instructions when pointer compression is enabled.
* **Handling Comparisons with Zero (`VisitCompareZero`):** This function specializes in selecting efficient instructions for comparing a value against zero. It attempts to combine the comparison with preceding operations (like addition, subtraction, bitwise operations, and shifts) if the result of that operation is only used for this comparison and a subsequent branch.
* **Handling Floating-Point Comparisons (`VisitFloat32Compare`, `VisitFloat64Compare`):** These functions select the appropriate SSE or AVX comparison instructions for single-precision (float32) and double-precision (float64) floating-point numbers.
* **Handling Atomic Operations (`VisitAtomicBinop`, `VisitAtomicCompareExchange`):** These functions handle the selection of instructions for atomic read-modify-write operations and compare-and-exchange operations, which are crucial for concurrent programming.

**Relation to JavaScript and Examples:**

Yes, this code is directly related to the performance of JavaScript. When the V8 engine compiles your JavaScript code, this instruction selector plays a vital role in translating your high-level logic into efficient machine code.

**JavaScript Example:**

```javascript
function compareNumbers(a, b) {
  if (a < b) {
    console.log("a is less than b");
  } else if (a === 0) {
    console.log("a is zero");
  }
}

compareNumbers(5, 10);
compareNumbers(0, 5);
```

When V8 compiles this `compareNumbers` function for the x64 architecture, the code in `instruction-selector-x64.cc` (specifically the parts shown) would be involved in selecting the appropriate x64 instructions for the `<` and `===` comparisons. For instance:

* The `a < b` comparison might involve `VisitWordCompare` selecting a `kX64Cmp` instruction.
* The `a === 0` comparison might involve `VisitCompareZero` selecting a `kX64Test` or `kX64Cmp` instruction optimized for comparing against zero.

**Code Logic Inference (Example with `TryNarrowOpcodeSize`):**

**Hypothetical Input:**

* `selector`: An `InstructionSelectorT` instance.
* `opcode`: `kX64Cmp` (a generic compare instruction).
* `left`: A node representing a variable of type `int8_t` (8-bit integer).
* `right`: A node representing a constant value of `10` (which fits within an 8-bit integer).
* `cont`: A `FlagsContinuationT` instance.

**Assumed Logic in `TryNarrowOpcodeSize`:**

The function would check the `MachineType` of `left` and `right`. Seeing that both can be represented as 8-bit integers, and the `opcode` is a generic compare, it would likely return `kX64Cmp8`.

**Output:**

* `kX64Cmp8`

**Explanation:** The function determined that an 8-bit compare instruction is sufficient because both operands fit within 8 bits, leading to a more efficient instruction.

**Common Programming Errors:**

This code doesn't directly *cause* user programming errors, but it helps optimize code generated from potentially flawed JavaScript. However, understanding its logic can indirectly shed light on performance implications of certain JavaScript patterns.

One common error that relates to the concepts here is **unnecessary type conversions or comparisons involving different types**. For example:

```javascript
let a = 10;
let b = "10";

if (a == b) { // Loose equality (==) triggers type coercion
  console.log("They are equal");
}

if (a === parseInt(b)) { // Strict equality (===) after explicit conversion
  console.log("They are strictly equal");
}
```

In the first `if` statement, JavaScript performs type coercion before comparison. While it might work, the generated machine code might not be as efficient as a direct comparison between numbers. The instruction selector might need to handle these type differences. The second `if` demonstrates a more explicit and potentially more performant comparison after ensuring both operands are numbers.

**Part 6 of 10 - Summary of Functionality:**

As the 6th part of a larger instruction selection process, this specific section of `instruction-selector-x64.cc` focuses on the crucial task of **optimizing comparison operations** for the x64 architecture. It analyzes operand types, existing operations, and target instruction characteristics to select the most efficient x64 instructions for comparing values. This includes using narrower instructions when possible, removing redundant operations, and handling comparisons against specific values like zero and root handles. This optimization directly contributes to the overall performance of executed JavaScript code.

### 提示词
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/instruction-selector-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
entations don't match, both operands will be
    // zero/sign-extended to 32bit.
    left_type = MachineTypeForNarrow(selector, left, right);
    right_type = MachineTypeForNarrow(selector, right, left);
  }
  if (left_type == right_type) {
    switch (left_type.representation()) {
      case MachineRepresentation::kBit:
      case MachineRepresentation::kWord8: {
        if (opcode == kX64Test || opcode == kX64Test32) return kX64Test8;
        if (opcode == kX64Cmp || opcode == kX64Cmp32) {
          if (left_type.semantic() == MachineSemantic::kUint32) {
            cont->OverwriteUnsignedIfSigned();
          } else {
            CHECK_EQ(MachineSemantic::kInt32, left_type.semantic());
          }
          return kX64Cmp8;
        }
        break;
      }
      // Cmp16/Test16 may introduce LCP(Length-Changing-Prefixes) stall, use
      // Cmp32/Test32 instead.
      case MachineRepresentation::kWord16:  // Fall through.
      case MachineRepresentation::kWord32:
        if (opcode == kX64Test) return kX64Test32;
        if (opcode == kX64Cmp) {
          if (left_type.semantic() == MachineSemantic::kUint32) {
            cont->OverwriteUnsignedIfSigned();
          } else {
            CHECK_EQ(MachineSemantic::kInt32, left_type.semantic());
          }
          return kX64Cmp32;
        }
        break;
#ifdef V8_COMPRESS_POINTERS
      case MachineRepresentation::kTaggedSigned:
      case MachineRepresentation::kTaggedPointer:
      case MachineRepresentation::kTagged:
        // When pointer compression is enabled the lower 32-bits uniquely
        // identify tagged value.
        if (opcode == kX64Cmp) return kX64Cmp32;
        break;
#endif
      default:
        break;
    }
  }
  return opcode;
}

/*
Remove unnecessary WordAnd
For example:
33:  IfFalse(31)
517: Int32Constant[65535]
518: Word32And(18, 517)
36:  Int32Constant[266]
37:  Int32LessThanOrEqual(36, 518)
38:  Branch[None]

If Int32LessThanOrEqual select cmp16, the above Word32And can be removed:
33:  IfFalse(31)
36:  Int32Constant[266]
37:  Int32LessThanOrEqual(36, 18)
38:  Branch[None]
*/
template <typename Adapter>
typename Adapter::node_t RemoveUnnecessaryWordAnd(
    InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
    typename Adapter::node_t and_node) {
  int64_t mask = 0;

  if (opcode == kX64Cmp32 || opcode == kX64Test32) {
    mask = std::numeric_limits<uint32_t>::max();
  } else if (opcode == kX64Cmp16 || opcode == kX64Test16) {
    mask = std::numeric_limits<uint16_t>::max();
  } else if (opcode == kX64Cmp8 || opcode == kX64Test8) {
    mask = std::numeric_limits<uint8_t>::max();
  } else {
    return and_node;
  }

  DCHECK_EQ(selector->value_input_count(and_node), 2);
  auto and_left = selector->input_at(and_node, 0);
  auto and_right = selector->input_at(and_node, 1);
  auto and_constant_node = typename Adapter::node_t{};
  auto and_other_node = typename Adapter::node_t{};
  if (IsIntConstant(selector, and_left)) {
    and_constant_node = and_left;
    and_other_node = and_right;
  } else if (IsIntConstant(selector, and_right)) {
    and_constant_node = and_right;
    and_other_node = and_left;
  }

  if (Adapter::valid(and_constant_node)) {
    int64_t and_constant = selector->integer_constant(and_constant_node);
    if (and_constant == mask) return and_other_node;
  }
  return and_node;
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  // The 32-bit comparisons automatically truncate Word64
  // values to Word32 range, no need to do that explicitly.
  if (opcode == kX64Cmp32 || opcode == kX64Test32) {
    if (selector->is_truncate_word64_to_word32(left)) {
      left = selector->input_at(left, 0);
    }
    if (selector->is_truncate_word64_to_word32(right)) {
      right = selector->input_at(right, 0);
    }
  }

  opcode = TryNarrowOpcodeSize(selector, opcode, left, right, cont);

  // If one of the two inputs is an immediate, make sure it's on the right, or
  // if one of the two inputs is a memory operand, make sure it's on the left.
  int effect_level = selector->GetEffectLevel(node, cont);

  if ((!g.CanBeImmediate(right) && g.CanBeImmediate(left)) ||
      (g.CanBeMemoryOperand(opcode, node, right, effect_level) &&
       !g.CanBeMemoryOperand(opcode, node, left, effect_level))) {
    if (!selector->IsCommutative(node)) cont->Commute();
    std::swap(left, right);
  }

  if (IsWordAnd(selector, left)) {
    left = RemoveUnnecessaryWordAnd(selector, opcode, left);
  }

  // Match immediates on right side of comparison.
  if (g.CanBeImmediate(right)) {
    if (g.CanBeMemoryOperand(opcode, node, left, effect_level)) {
      return VisitCompareWithMemoryOperand(selector, opcode, left,
                                           g.UseImmediate(right), cont);
    }
    return VisitCompare(selector, opcode, g.Use(left), g.UseImmediate(right),
                        cont);
  }

  // Match memory operands on left side of comparison.
  if (g.CanBeMemoryOperand(opcode, node, left, effect_level)) {
    return VisitCompareWithMemoryOperand(selector, opcode, left,
                                         g.UseRegister(right), cont);
  }

  return VisitCompare(selector, opcode, left, right, cont,
                      selector->IsCommutative(node));
}

template <typename Adapter>
void VisitWord64EqualImpl(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node,
                          FlagsContinuationT<Adapter>* cont) {
  if (selector->CanUseRootsRegister()) {
    X64OperandGeneratorT<Adapter> g(selector);
    const RootsTable& roots_table = selector->isolate()->roots_table();
    RootIndex root_index;
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const ComparisonOp& equal =
          selector->Get(node).template Cast<ComparisonOp>();
      DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
      Handle<HeapObject> object;
      if (equal.rep == RegisterRepresentation::Tagged() &&
          selector->MatchHeapConstant(equal.right(), &object)) {
        if (roots_table.IsRootHandle(object, &root_index)) {
          InstructionCode opcode =
              kX64Cmp | AddressingModeField::encode(kMode_Root);
          return VisitCompare(
              selector, opcode,
              g.TempImmediate(
                  MacroAssemblerBase::RootRegisterOffsetForRootIndex(
                      root_index)),
              g.UseRegister(equal.left()), cont);
        }
      }
    } else {
      HeapObjectBinopMatcher m(node);
      if (m.right().HasResolvedValue() &&
          roots_table.IsRootHandle(m.right().ResolvedValue(), &root_index)) {
        InstructionCode opcode =
            kX64Cmp | AddressingModeField::encode(kMode_Root);
        return VisitCompare(
            selector, opcode,
            g.TempImmediate(
                MacroAssemblerBase::RootRegisterOffsetForRootIndex(root_index)),
            g.UseRegister(m.left().node()), cont);
      }
    }
  }
  VisitWordCompare(selector, node, kX64Cmp, cont);
}

bool MatchHeapObjectEqual(InstructionSelectorT<TurbofanAdapter>* selector,
                          Node* node, Node** left, Handle<HeapObject>* right) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWord32Equal);
  CompressedHeapObjectBinopMatcher m(node);
  if (m.right().HasResolvedValue()) {
    *left = m.left().node();
    *right = m.right().ResolvedValue();
    return true;
  }
  HeapObjectBinopMatcher m2(node);
  if (m2.right().HasResolvedValue()) {
    *left = m2.left().node();
    *right = m2.right().ResolvedValue();
    return true;
  }
  return false;
}

bool MatchHeapObjectEqual(InstructionSelectorT<TurboshaftAdapter>* selector,
                          turboshaft::OpIndex node, turboshaft::OpIndex* left,
                          Handle<HeapObject>* right) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ComparisonOp& equal = selector->Get(node).Cast<ComparisonOp>();
  DCHECK_EQ(equal.kind, ComparisonOp::Kind::kEqual);
  if (selector->MatchHeapConstant(equal.right(), right)) {
    *left = equal.left();
    return true;
  }
  return false;
}

template <typename Adapter>
void VisitWord32EqualImpl(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node,
                          FlagsContinuationT<Adapter>* cont) {
  if (COMPRESS_POINTERS_BOOL && selector->isolate()) {
    X64OperandGeneratorT<Adapter> g(selector);
    const RootsTable& roots_table = selector->isolate()->roots_table();
    RootIndex root_index;
    typename Adapter::node_t left;
    Handle<HeapObject> right;
    // HeapConstants and CompressedHeapConstants can be treated the same when
    // using them as an input to a 32-bit comparison. Check whether either is
    // present.
    if (MatchHeapObjectEqual(selector, node, &left, &right)) {
      if (roots_table.IsRootHandle(right, &root_index)) {
        DCHECK(Adapter::valid(left));
        if (RootsTable::IsReadOnly(root_index) &&
            (V8_STATIC_ROOTS_BOOL || !selector->isolate()->bootstrapper())) {
          return VisitCompare(
              selector, kX64Cmp32, g.UseRegister(left),
              g.TempImmediate(MacroAssemblerBase::ReadOnlyRootPtr(
                  root_index, selector->isolate())),
              cont);
        }
        if (selector->CanUseRootsRegister()) {
          InstructionCode opcode =
              kX64Cmp32 | AddressingModeField::encode(kMode_Root);
          return VisitCompare(
              selector, opcode,
              g.TempImmediate(
                  MacroAssemblerBase::RootRegisterOffsetForRootIndex(
                      root_index)),
              g.UseRegister(left), cont);
        }
      }
    }
  }
  VisitWordCompare(selector, node, kX64Cmp32, cont);
}

void VisitCompareZero(InstructionSelectorT<TurboshaftAdapter>* selector,
                      turboshaft::OpIndex user, turboshaft::OpIndex node,
                      InstructionCode opcode,
                      FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  X64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const Operation& op = selector->turboshaft_graph()->Get(node);
  if (cont->IsBranch() &&
      (cont->condition() == kNotEqual || cont->condition() == kEqual)) {
    if (const WordBinopOp* binop = op.TryCast<WordBinopOp>()) {
      if (selector->IsOnlyUserOfNodeInSameBlock(user, node)) {
        const bool is64 = binop->rep == WordRepresentation::Word64();
        switch (binop->kind) {
          case WordBinopOp::Kind::kAdd:
            return VisitBinop(selector, node, is64 ? kX64Add : kX64Add32, cont);
          case WordBinopOp::Kind::kSub:
            return VisitBinop(selector, node, is64 ? kX64Sub : kX64Sub32, cont);
          case WordBinopOp::Kind::kBitwiseAnd:
            return VisitBinop(selector, node, is64 ? kX64And : kX64And32, cont);
          case WordBinopOp::Kind::kBitwiseOr:
            return VisitBinop(selector, node, is64 ? kX64Or : kX64Or32, cont);
          default:
            break;
        }
      }
    } else if (const ShiftOp* shift = op.TryCast<ShiftOp>()) {
      if (selector->IsOnlyUserOfNodeInSameBlock(user, node)) {
        const bool is64 = shift->rep == WordRepresentation::Word64();
        switch (shift->kind) {
          case ShiftOp::Kind::kShiftLeft:
            if (TryVisitWordShift(selector, node, is64 ? 64 : 32,
                                  is64 ? kX64Shl : kX64Shl32, cont)) {
              return;
            }
            break;
          case ShiftOp::Kind::kShiftRightLogical:
            if (TryVisitWordShift(selector, node, is64 ? 64 : 32,
                                  is64 ? kX64Shr : kX64Shr32, cont)) {
              return;
            }
            break;
          default:
            break;
        }
      }
    }
  }

  int effect_level = selector->GetEffectLevel(node, cont);
  if (const auto load = op.TryCast<turboshaft::LoadOp>()) {
    if (load->loaded_rep == turboshaft::MemoryRepresentation::Int8() ||
        load->loaded_rep == turboshaft::MemoryRepresentation::Uint8()) {
      if (opcode == kX64Cmp32) {
        opcode = kX64Cmp8;
      } else if (opcode == kX64Test32) {
        opcode = kX64Test8;
      }
    } else if (load->loaded_rep == turboshaft::MemoryRepresentation::Int16() ||
               load->loaded_rep == turboshaft::MemoryRepresentation::Uint16()) {
      if (opcode == kX64Cmp32) {
        opcode = kX64Cmp16;
      } else if (opcode == kX64Test32) {
        opcode = kX64Test16;
      }
    }
  }
  if (g.CanBeMemoryOperand(opcode, user, node, effect_level)) {
    VisitCompareWithMemoryOperand(selector, opcode, node, g.TempImmediate(0),
                                  cont);
  } else {
    VisitCompare(selector, opcode, g.Use(node), g.TempImmediate(0), cont);
  }
}

// Shared routine for comparison with zero.
void VisitCompareZero(InstructionSelectorT<TurbofanAdapter>* selector,
                      Node* user, Node* node, InstructionCode opcode,
                      FlagsContinuationT<TurbofanAdapter>* cont) {
  X64OperandGeneratorT<TurbofanAdapter> g(selector);
  if (cont->IsBranch() &&
      (cont->condition() == kNotEqual || cont->condition() == kEqual)) {
    switch (node->opcode()) {
#define FLAGS_SET_BINOP_LIST(V)        \
  V(kInt32Add, VisitBinop, kX64Add32)  \
  V(kInt32Sub, VisitBinop, kX64Sub32)  \
  V(kWord32And, VisitBinop, kX64And32) \
  V(kWord32Or, VisitBinop, kX64Or32)   \
  V(kInt64Add, VisitBinop, kX64Add)    \
  V(kInt64Sub, VisitBinop, kX64Sub)    \
  V(kWord64And, VisitBinop, kX64And)   \
  V(kWord64Or, VisitBinop, kX64Or)
#define FLAGS_SET_BINOP(opcode, Visit, archOpcode)           \
  case IrOpcode::opcode:                                     \
    if (selector->IsOnlyUserOfNodeInSameBlock(user, node)) { \
      return Visit(selector, node, archOpcode, cont);        \
    }                                                        \
    break;
      FLAGS_SET_BINOP_LIST(FLAGS_SET_BINOP)
#undef FLAGS_SET_BINOP_LIST
#undef FLAGS_SET_BINOP

// Skip Word64Sar/Word32Sar since no instruction reduction in most cases.
#define FLAGS_SET_SHIFT_LIST(V) \
  V(kWord32Shl, 32, kX64Shl32)  \
  V(kWord32Shr, 32, kX64Shr32)  \
  V(kWord64Shl, 64, kX64Shl)    \
  V(kWord64Shr, 64, kX64Shr)
#define FLAGS_SET_SHIFT(opcode, bits, archOpcode)                            \
  case IrOpcode::opcode:                                                     \
    if (selector->IsOnlyUserOfNodeInSameBlock(user, node)) {                 \
      if (TryVisitWordShift(selector, node, bits, archOpcode, cont)) return; \
    }                                                                        \
    break;
      FLAGS_SET_SHIFT_LIST(FLAGS_SET_SHIFT)
#undef TRY_VISIT_WORD32_SHIFT
#undef TRY_VISIT_WORD64_SHIFT
#undef FLAGS_SET_SHIFT_LIST
#undef FLAGS_SET_SHIFT
      default:
        break;
    }
  }
  int effect_level = selector->GetEffectLevel(node, cont);
  if (node->opcode() == IrOpcode::kLoad ||
      node->opcode() == IrOpcode::kLoadImmutable) {
    switch (LoadRepresentationOf(node->op()).representation()) {
      case MachineRepresentation::kWord8:
        if (opcode == kX64Cmp32) {
          opcode = kX64Cmp8;
        } else if (opcode == kX64Test32) {
          opcode = kX64Test8;
        }
        break;
      case MachineRepresentation::kWord16:
        if (opcode == kX64Cmp32) {
          opcode = kX64Cmp16;
        } else if (opcode == kX64Test32) {
          opcode = kX64Test16;
        }
        break;
      default:
        break;
    }
  }
  if (g.CanBeMemoryOperand(opcode, user, node, effect_level)) {
    VisitCompareWithMemoryOperand(selector, opcode, node, g.TempImmediate(0),
                                  cont);
  } else {
    VisitCompare(selector, opcode, g.Use(node), g.TempImmediate(0), cont);
  }
}

// Shared routine for multiple float32 compare operations (inputs commuted).
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  InstructionCode const opcode =
      selector->IsSupported(AVX) ? kAVXFloat32Cmp : kSSEFloat32Cmp;
  VisitCompare(selector, opcode, right, left, cont, false);
}

// Shared routine for multiple float64 compare operations (inputs commuted).
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  InstructionCode const opcode =
      selector->IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
  VisitCompare(selector, opcode, right, left, cont, false);
}

// Shared routine for Word32/Word64 Atomic Binops
template <typename Adapter>
void VisitAtomicBinop(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      AtomicWidth width, MemoryAccessKind access_kind) {
  auto atomic_op = selector->atomic_rmw_view(node);
  X64OperandGeneratorT<Adapter> g(selector);
  AddressingMode addressing_mode;
  InstructionOperand inputs[] = {
      g.UseUniqueRegister(atomic_op.value()),
      g.UseUniqueRegister(atomic_op.base()),
      g.GetEffectiveIndexOperand(atomic_op.index(), &addressing_mode)};
  InstructionOperand outputs[] = {g.DefineAsFixed(node, rax)};
  InstructionOperand temps[] = {g.TempRegister()};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                 arraysize(temps), temps);
}

// Shared routine for Word32/Word64 Atomic CmpExchg
template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode, AtomicWidth width,
                                MemoryAccessKind access_kind) {
  auto atomic_op = selector->atomic_rmw_view(node);
  X64OperandGeneratorT<Adapter> g(selector);
  AddressingMode addressing_mode;
  InstructionOperand inputs[] = {
      g.UseFixed(atomic_op.expected(), rax),
      g.UseUniqueRegister(atomic_op.value()),
      g.UseUniqueRegister(atomic_op.base()),
      g.GetEffectiveIndexOperand(atomic_op.index(), &addressing_mode)};
  InstructionOperand outputs[] = {g.DefineAsFixed(node, rax)};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs);
}

}  // namespace

// Shared routine for word comparison against zero.
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  // Try to combine with comparisons against 0 by simply inverting the branch.
  ConsumeEqualZero(&user, &value, cont);

  if (CanCover(user, value)) {
    const Operation& value_op = this->Get(value);
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      if (comparison->kind == ComparisonOp::Kind::kEqual) {
        switch (comparison->rep.MapTaggedToWord().value()) {
          case RegisterRepresentation::Word32():
            cont->OverwriteAndNegateIfEqual(kEqual);
            return VisitWord32EqualImpl(this, value, cont);
          case RegisterRepresentation::Word64(): {
            cont->OverwriteAndNegateIfEqual(kEqual);
            if (this->MatchIntegralZero(comparison->right())) {
              // Try to combine the branch with a comparison.
              if (CanCover(value, comparison->left())) {
                const Operation& left_op = this->Get(comparison->left());
                if (left_op.Is<Opmask::kWord64Sub>()) {
                  return VisitWordCompare(this, comparison->left(), kX64Cmp,
                                          cont);
                } else if (left_op.Is<Opmask::kWord64BitwiseAnd>()) {
                  return VisitWordCompare(this, comparison->left(), kX64Test,
                                          cont);
                }
              }
              return VisitCompareZero(this, value, comparison->left(), kX64Cmp,
                                      cont);
            }
            return VisitWord64EqualImpl(this, value, cont);
          }
          case RegisterRepresentation::Float32():
            cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
            return VisitFloat32Compare(this, value, cont);
          case RegisterRepresentation::Float64(): {
            bool is_self_compare =
                this->input_at(value, 0) == this->input_at(value, 1);
            cont->OverwriteAndNegateIfEqual(is_self_compare ? kIsNotNaN
                                                            : kUnorderedEqual);
            return VisitFloat64Compare(this, value, cont);
          }
          default:
            break;
        }
      } else {
        switch (comparison->rep.MapTaggedToWord().value()) {
          case RegisterRepresentation::Word32(): {
            cont->OverwriteAndNegateIfEqual(
                GetComparisonFlagCondition(*comparison));
            return VisitWordCompare(this, value, kX64Cmp32, cont);
          }
          case RegisterRepresentation::Word64(): {
            cont->OverwriteAndNegateIfEqual(
                GetComparisonFlagCondition(*comparison));
            return VisitWordCompare(this, value, kX64Cmp, cont);
          }
          case RegisterRepresentation::Float32():
            if (comparison->kind == ComparisonOp::Kind::kSignedLessThan) {
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
              return VisitFloat32Compare(this, value, cont);
            } else {
              DCHECK_EQ(comparison->kind,
                        ComparisonOp::Kind::kSignedLessThanOrEqual);
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
              return VisitFloat32Compare(this, value, cont);
            }
          case RegisterRepresentation::Float64():
            if (comparison->kind == ComparisonOp::Kind::kSignedLessThan) {
              if (MatchZero(comparison->left())) {
                const Operation& right = this->Get(comparison->right());
                if (right.Is<Opmask::kFloat64Abs>()) {
                  // This matches the pattern
                  //
                  //   Float64LessThan(#0.0, Float64Abs(x))
                  //
                  // which TurboFan generates for NumberToBoolean in the general
                  // case, and which evaluates to false if x is 0, -0 or NaN. We
                  // can compile this to a simple (v)ucomisd using not_equal
                  // flags condition, which avoids the costly Float64Abs.
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  InstructionCode const opcode =
                      IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
                  return VisitCompare(this, opcode, comparison->left(),
                                      right.Cast<FloatUnaryOp>().input(), cont,
                                      false);
                }
              }
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
              return VisitFloat64Compare(this, value, cont);
            } else {
              DCHECK_EQ(comparison->kind,
                        ComparisonOp::Kind::kSignedLessThanOrEqual);
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
              return VisitFloat64Compare(this, value, cont);
            }
          default:
            break;
        }
      }
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWordCompare(this, value, kX64Cmp32, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      return VisitWordCompare(this, value, kX64Test32, cont);
    } else if (const ProjectionOp* projection =
                   value_op.TryCast<ProjectionOp>()) {
      // Check if this is the overflow output projection of an
      // OverflowCheckedBinop operation.
      if (projection->index == 1u) {
        // We cannot combine the OverflowCheckedBinop operation with this branch
        // unless the 0th projection (the use of the actual value of the
        // operation is either {OpIndex::Invalid()}, which means there's no use
        // of the actual value, or was already defined, which means it is
        // scheduled *AFTER* this branch).
        OpIndex node = projection->input();
        OpIndex result = FindProjection(node, 0);
        if (!result.valid() || IsDefined(result)) {
          if (const OverflowCheckedBinopOp* binop =
                  this->TryCast<OverflowCheckedBinopOp>(node)) {
            const bool is64 = binop->rep == WordRepresentation::Word64();
            cont->OverwriteAndNegateIfEqual(kOverflow);
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                return VisitBinop(this, node, is64 ? kX64Add : kX64Add32, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                return VisitBinop(this, node, is64 ? kX64Sub : kX64Sub32, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                return VisitBinop(this, node, is64 ? kX64Imul : kX64Imul32,
                                  cont);
            }
            UNREACHABLE();
          }
        }
      }
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }

  // Branch could not be combined with a compare, emit compare against 0.
  VisitCompareZero(this, user, value, kX64Cmp32, cont);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWordCompareZero(
    Node* user, Node* value, FlagsContinuation* cont) {
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
        return VisitWord32EqualImpl(this, value, cont);
      case IrOpcode::kInt32LessThan:
        cont->OverwriteAndNegateIfEqual(kSignedLessThan);
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kInt32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kUint32LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kUint32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitWordCompare(this, value, kX64Cmp32, cont);
      case IrOpcode::kWord64Equal: {
        cont->OverwriteAndNegateIfEqual(kEqual);
        Int64BinopMatcher m(value);
        if (m.right().Is(0)) {
          // Try to combine the branch with a comparison.
          Node* const eq_user = m.node();
          Node* const eq_value = m.left().node();
          if (CanCover(eq_user, eq_value)) {
            switch (eq_value->opcode()) {
              case IrOpcode::kInt64Sub:
                return VisitWordCompare(this, eq_value, kX64Cmp, cont);
              case IrOpcode::kWord64And:
                return VisitWordCompare(this, eq_value, kX64Test, cont);
              default:
                break;
            }
          }
          return VisitCompareZero(this, eq_user, eq_value, kX64Cmp, cont);
        }
        return VisitWord64EqualImpl(this, value, cont);
      }
      case IrOpcode::kInt64LessThan:
        cont->OverwriteAndNegateIfEqual(kSignedLessThan);
        return VisitWordCompare(this, value, kX64Cmp, cont);
      case IrOpcode::kInt64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
        return VisitWordCompare(this, value, kX64Cmp, cont);
      case IrOpcode::kUint64LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitWordCompare(this, value, kX64Cmp, cont);
      case IrOpcode::kUint64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitWordCompare(this, value, kX64Cmp, cont);
      case IrOpcode::kFloat32Equal:
        cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat32LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat64Equal: {
        bool is_self_compare =
            this->input_at(value, 0) == this->input_at(value, 1);
        cont->OverwriteAndNegateIfEqual(is_self_compare ? kIsNotNaN
                                                        : kUnorderedEqual);
        return VisitFloat64Compare(this, value, cont);
      }
      case IrOpcode::kFloat64LessThan: {
        Float64BinopMatcher m(value);
        if (m.left().Is(0.0) && m.right().IsFloat64Abs()) {
          // This matches the pattern
          //
          //   Float64LessThan(#0.0, Float64Abs(x))
          //
          // which TurboFan generates for NumberToBoolean in the general case,
          // and which evaluates to false if x is 0, -0 or NaN. We can compile
          // this to a simple (v)ucomisd using not_equal flags condition, which
          // avoids the costly Float64Abs.
          cont->OverwriteAndNegateIfEqual(kNotEqual);
          InstructionCode const opcode =
              IsSupported(AVX) ? kAVXFloat64Cmp : kSSEFloat64Cmp;
          return VisitCompare(this, opcode, m.left().node(),
                              m.right().InputAt(0), cont, false);
        }
        cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
        return VisitFloat64Compare(this, value, cont);
      }
      case IrOpcode::kFloat64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
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
                return VisitBinop(this, node, kX64Add32, cont);
              case IrOpcode::kInt32SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kX64Sub32, cont);
```