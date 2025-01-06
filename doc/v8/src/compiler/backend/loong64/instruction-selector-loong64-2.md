Response: The user wants a summary of the provided C++ code snippet, which is part 3 of a larger file. The file is related to the instruction selection phase of the V8 JavaScript engine's compiler for the LoongArch64 architecture. The summary should describe the functionality of the code. If the functionality relates to JavaScript, the user wants an example.

**Plan:**

1. **Identify the main purpose of the code:** The code consists of template specializations of the `InstructionSelectorT` class for the LoongArch64 architecture. This class is responsible for selecting machine instructions based on the intermediate representation of the code.
2. **Analyze the code blocks:** Each code block corresponds to the implementation of a specific operation or a group of related operations. Pay attention to the operations being handled (e.g., comparisons, arithmetic, SIMD operations, atomic operations).
3. **Group related functionalities:**  Combine the descriptions of similar operations to create a more concise summary.
4. **Identify connections to JavaScript:**  Consider how the described low-level operations relate to higher-level JavaScript concepts.
5. **Construct JavaScript examples:**  For functionalities related to JavaScript, create illustrative examples.
This C++ code snippet is the third part of the `instruction-selector-loong64.cc` file, which is responsible for the **instruction selection** phase in the V8 JavaScript engine's compiler for the LoongArch64 architecture. Specifically, this part continues to define how various intermediate representation (IR) nodes are translated into specific LoongArch64 machine instructions.

Here's a breakdown of the functionalities covered in this part:

**1. Handling Comparison Operations and Conditional Jumps:**

*   It defines how to handle `VisitSwitch` statements, which are used for implementing `switch` statements in JavaScript. It decides whether to use a jump table or a binary search for efficiency.
*   It implements `VisitWord32Equal`, `VisitInt32LessThan`, `VisitInt32LessThanOrEqual`, `VisitUint32LessThan`, `VisitUint32LessThanOrEqual`, `VisitWord64Equal`, `VisitInt64LessThan`, `VisitInt64LessThanOrEqual`, `VisitUint64LessThan`, `VisitUint64LessThanOrEqual`, `VisitFloat32Equal`, `VisitFloat32LessThan`, `VisitFloat32LessThanOrEqual`, `VisitFloat64Equal`, `VisitFloat64LessThan`, `VisitFloat64LessThanOrEqual`. These functions translate comparison operations in the IR to corresponding LoongArch64 compare instructions, setting the processor flags.
*   It includes optimizations for comparing against zero and for comparing against constant values from the V8's read-only root table.

**2. Handling Arithmetic Operations with Overflow Checks:**

*   It defines how to handle arithmetic operations that need to check for overflow: `VisitInt32AddWithOverflow`, `VisitInt32SubWithOverflow`, `VisitInt32MulWithOverflow`, `VisitInt64MulWithOverflow`, `VisitInt64AddWithOverflow`, `VisitInt64SubWithOverflow`. These functions generate LoongArch64 instructions that perform the arithmetic and set the overflow flag if necessary.

**3. Handling Floating-Point Operations:**

*   It implements functions for extracting and inserting the low and high 32-bit words of a 64-bit floating-point number: `VisitFloat64ExtractLowWord32`, `VisitFloat64ExtractHighWord32`, `VisitFloat64InsertLowWord32`, `VisitFloat64InsertHighWord32`.
*   It handles bitcasting a pair of 32-bit words to a 64-bit float: `VisitBitcastWord32PairToFloat64`.
*   It defines how to silence NaN values for float64: `VisitFloat64SilenceNaN`.

**4. Handling Memory Barriers:**

*   It implements `VisitMemoryBarrier`, which generates the necessary instruction to ensure memory ordering.

**5. Handling Atomic Operations:**

*   It defines how to handle various atomic load, store, exchange, and compare-exchange operations for both 32-bit and 64-bit integers: `VisitWord32AtomicLoad`, `VisitWord32AtomicStore`, `VisitWord64AtomicLoad`, `VisitWord64AtomicStore`, `VisitWord32AtomicExchange`, `VisitWord64AtomicExchange`, `VisitWord32AtomicCompareExchange`, `VisitWord64AtomicCompareExchange`.
*   It also implements atomic binary operations like add, subtract, and, or, and xor: `VisitWord32AtomicAdd`, `VisitWord32AtomicSub`, `VisitWord32AtomicAnd`, `VisitWord32AtomicOr`, `VisitWord32AtomicXor`, `VisitWord64AtomicAdd`, `VisitWord64AtomicSub`, `VisitWord64AtomicAnd`, `VisitWord64AtomicOr`, `VisitWord64AtomicXor`.

**6. Handling SIMD (Single Instruction, Multiple Data) Operations:**

*   This section covers a wide range of SIMD operations for different data types (F64x2, F32x4, I64x2, I32x4, I16x8, I8x16).
*   It includes operations like:
    *   **Constants and Zeroing:** `VisitS128Const`, `VisitS128Zero`
    *   **Lane Splatting:** `VisitF64x2Splat`, `VisitF32x4Splat`, etc.
    *   **Lane Extraction:** `VisitF64x2ExtractLane`, `VisitI32x4ExtractLaneS`, etc.
    *   **Lane Replacement:** `VisitF64x2ReplaceLane`, `VisitI32x4ReplaceLane`, etc.
    *   **Unary Operations:** `VisitF64x2Abs`, `VisitI32x4Neg`, `VisitS128Not`, etc.
    *   **Shift Operations:** `VisitI64x2Shl`, `VisitI32x4ShrS`, etc.
    *   **Binary Operations:** `VisitF64x2Add`, `VisitI32x4Mul`, `VisitS128And`, etc.
    *   **Lane Selection (Shuffle):** `VisitI8x16Shuffle`, including optimizations for common shuffle patterns.
    *   **Swizzle:** `VisitI8x16Swizzle`
    *   **Select:** `VisitS128Select`
    *   **Packed Min/Max:** `VisitF32x4Pmin`, `VisitI16x8MaxS`, etc.
    *   **Extended Multiplication:** `VisitI64x2ExtMulLowI32x4S`, etc.
    *   **Pairwise Addition:** `VisitI16x8ExtAddPairwiseI8x16S`, etc.
*   It also marks some SIMD operations as unimplemented.

**7. Other Machine Operations:**

*   It handles `VisitSetStackPointer`, which sets the stack pointer register.
*   It defines how to perform sign extension for different word sizes: `VisitSignExtendWord8ToInt32`, `VisitSignExtendWord16ToInt32`, `VisitSignExtendWord8ToInt64`, `VisitSignExtendWord16ToInt64`, `VisitSignExtendWord32ToInt64`.

**Relationship to JavaScript and Examples:**

Many of the operations in this code directly correspond to JavaScript language features and built-in functions.

*   **Comparison Operators:**  JavaScript's `<`, `>`, `<=`, `>=`, `==`, `!=` operators are ultimately translated into the comparison instructions handled here.

    ```javascript
    let a = 5;
    let b = 10;
    if (a < b) { // This will involve a comparison instruction
      console.log("a is less than b");
    }
    ```

*   **Arithmetic Operators:** JavaScript's `+`, `-`, `*` operators, including those that might overflow, are handled.

    ```javascript
    let x = 2147483647; // Maximum 32-bit signed integer
    let y = 1;
    let sum = x + y; // May trigger an overflow check
    ```

*   **`switch` Statements:** JavaScript's `switch` statement uses the `VisitSwitch` functionality.

    ```javascript
    let day = 2;
    switch (day) {
      case 1:
        console.log("Monday");
        break;
      case 2:
        console.log("Tuesday"); // This case might be implemented using a jump table
        break;
      // ... other cases
      default:
        console.log("Weekend");
    }
    ```

*   **Floating-Point Operations:**  JavaScript's number type is based on double-precision floating-point numbers, so operations on numbers involve these instructions.

    ```javascript
    let pi = 3.14159;
    let roundedPi = Math.floor(pi); // Floor operation
    ```

*   **Atomic Operations:** JavaScript's `Atomics` object provides methods for performing atomic operations on shared memory.

    ```javascript
    const buffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
    const view = new Int32Array(buffer);
    Atomics.add(view, 0, 5); // Atomic addition
    ```

*   **SIMD Operations:** The WebAssembly SIMD proposal introduces SIMD types and operations that directly map to the SIMD instructions handled here. While not direct JavaScript syntax, they are used in WebAssembly modules that can be run in JavaScript environments.

    ```javascript
    // Example of WebAssembly SIMD (conceptual - actual syntax is different)
    let a = f32x4(1.0, 2.0, 3.0, 4.0);
    let b = f32x4(0.5, 1.0, 1.5, 2.0);
    let sum = a + b; // SIMD addition (hypothetical)
    ```

*   **Memory Barriers:** While not directly exposed in typical JavaScript, memory barriers are crucial for ensuring correct behavior in multi-threaded scenarios, especially when dealing with shared memory and Web Workers.

*   **Sign Extension:** This is often used when dealing with data from lower-level sources (like byte arrays or external libraries) where you need to interpret smaller integer types as larger ones while preserving their sign.

    ```javascript
    // Imagine reading a signed 8-bit integer from a buffer
    let byteValue = -10; // Represented as a byte
    // Internally, the engine might need to sign-extend this to a 32-bit integer
    let intValue = byteValue; // Implicit conversion might involve sign extension
    ```

In summary, this code is a crucial part of the V8 compiler that bridges the gap between the high-level semantics of JavaScript and the low-level instructions that the LoongArch64 processor can execute. It optimizes code execution by selecting the most appropriate and efficient machine instructions for various JavaScript operations.

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/instruction-selector-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""


          case RegisterRepresentation::Float64():
            switch (comparison->kind) {
              case ComparisonOp::Kind::kEqual:
                cont->OverwriteAndNegateIfEqual(kEqual);
                return VisitFloat64Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThan:
                cont->OverwriteAndNegateIfEqual(kFloatLessThan);
                return VisitFloat64Compare(this, value, cont);
              case ComparisonOp::Kind::kSignedLessThanOrEqual:
                cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
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
                                    is64 ? kLoong64AddOvf_d : kLoong64Add_d,
                                    cont);
                case OverflowCheckedBinopOp::Kind::kSignedSub:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node,
                                    is64 ? kLoong64SubOvf_d : kLoong64Sub_d,
                                    cont);
                case OverflowCheckedBinopOp::Kind::kSignedMul:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node,
                                    is64 ? kLoong64MulOvf_d : kLoong64MulOvf_w,
                                    cont);
              }
            }
          }
        }
      } else if (value_op.Is<Opmask::kWord32BitwiseAnd>() ||
                 value_op.Is<Opmask::kWord64BitwiseAnd>()) {
        return VisitWordCompare(this, value, kLoong64Tst, cont, true);
      } else if (value_op.Is<StackPointerGreaterThanOp>()) {
        cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
        return VisitStackPointerGreaterThan(value, cont);
      }
    }

    // Continuation could not be combined with a compare, emit compare against
    // 0.
    VisitCompare(this, kLoong64Cmp32, g.UseRegister(value), g.TempImmediate(0),
                 cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  Loong64OperandGeneratorT<Adapter> g(this);
  InstructionOperand value_operand = g.UseRegister(this->input_at(node, 0));

  // Emit either ArchTableSwitch or ArchBinarySearchSwitch.
  if (enable_switch_jump_table_ ==
      InstructionSelector::kEnableSwitchJumpTable) {
    static const size_t kMaxTableSwitchValueRange = 2 << 16;
    size_t table_space_cost = 10 + 2 * sw.value_range();
    size_t table_time_cost = 3;
    size_t lookup_space_cost = 2 + 2 * sw.case_count();
    size_t lookup_time_cost = sw.case_count();
    if (sw.case_count() > 0 &&
        table_space_cost + 3 * table_time_cost <=
            lookup_space_cost + 3 * lookup_time_cost &&
        sw.min_value() > std::numeric_limits<int32_t>::min() &&
        sw.value_range() <= kMaxTableSwitchValueRange) {
      InstructionOperand index_operand = value_operand;
      if (sw.min_value()) {
        index_operand = g.TempRegister();
        Emit(kLoong64Sub_w, index_operand, value_operand,
             g.TempImmediate(sw.min_value()));
      }
      // Generate a table lookup.
      return EmitTableSwitch(sw, index_operand);
    }
  }

  // Generate a tree of conditional jumps.
  return EmitBinarySearchSwitch(sw, value_operand);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  Int32BinopMatcher m(node);
  if (m.right().Is(0)) {
    return VisitWordCompareZero(m.node(), m.left().node(), &cont);
  }
  if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                    (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
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
        Tagged_t ptr =
            MacroAssemblerBase::ReadOnlyRootPtr(root_index, isolate());
        if (g.CanBeImmediate(ptr, kLoong64Cmp32)) {
          VisitCompare(this, kLoong64Cmp32, g.UseRegister(left),
                       g.TempImmediate(ptr), &cont);
          return;
        }
      }
    }
  }
  VisitWord32Compare(this, node, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Equal(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& equal = Get(node);
  DCHECK(equal.Is<ComparisonOp>());
  OpIndex left = equal.input(0);
  OpIndex right = equal.input(1);
  OpIndex user = node;
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);

  if (MatchZero(right)) {
    return VisitWordCompareZero(user, left, &cont);
  }

  if (isolate() && (V8_STATIC_ROOTS_BOOL ||
                    (COMPRESS_POINTERS_BOOL && !isolate()->bootstrapper()))) {
    Loong64OperandGeneratorT<TurboshaftAdapter> g(this);
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
        if (g.CanBeImmediate(ptr, kLoong64Cmp32)) {
          VisitCompare(this, kLoong64Cmp32, g.UseRegister(left),
                       g.TempImmediate(int32_t(ptr)), &cont);
          return;
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
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid() && IsUsed(ovf)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64Add_d, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64Add_d, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kLoong64Add_d, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64Sub_d, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64Sub_d, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kLoong64Sub_d, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64MulOvf_w, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64MulOvf_w, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kLoong64MulOvf_w, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64MulOvf_d, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64MulOvf_d, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kLoong64MulOvf_d, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AddWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64AddOvf_d, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64AddOvf_d, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kLoong64AddOvf_d, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64SubWithOverflow(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    OpIndex ovf = FindProjection(node, 1);
    if (ovf.valid()) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64SubOvf_d, &cont);
    }
  } else {
    if (Node* ovf = NodeProperties::FindProjection(node, 1)) {
      FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
      return VisitBinop(this, node, kLoong64SubOvf_d, &cont);
    }
  }

  FlagsContinuation cont;
  VisitBinop(this, node, kLoong64SubOvf_d, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Equal(node_t node) {
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
void InstructionSelectorT<Adapter>::VisitFloat64ExtractLowWord32(node_t node) {
  VisitRR(this, kLoong64Float64ExtractLowWord32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64ExtractHighWord32(node_t node) {
  VisitRR(this, kLoong64Float64ExtractHighWord32, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Loong64OperandGeneratorT<TurboshaftAdapter> g(this);
  const auto& bitcast = this->Cast<BitcastWord32PairToFloat64Op>(node);
  node_t hi = bitcast.high_word32();
  node_t lo = bitcast.low_word32();

  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kLoong64Float64FromWord32Pair, g.DefineAsRegister(node), g.Use(hi),
       g.Use(lo), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64SilenceNaN(node_t node) {
  VisitRR(this, kLoong64Float64SilenceNaN, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Emit(kLoong64Float64InsertLowWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Emit(kLoong64Float64InsertHighWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.UseRegister(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  Emit(kLoong64Dbar, g.NoOutput());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  VisitAtomicLoad(this, node, AtomicWidth::kWord32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  VisitAtomicStore(this, node, AtomicWidth::kWord32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicLoad(node_t node) {
  VisitAtomicLoad(this, node, AtomicWidth::kWord64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicStore(node_t node) {
  VisitAtomicStore(this, node, AtomicWidth::kWord64);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32,
                      atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Int32() ||
             params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }

  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32, params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = kLoong64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64,
                      atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kLoong64Word64AtomicExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord64, params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
             atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32,
                             atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32AtomicCompareExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Int32() ||
             params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }

  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32,
                             params.kind());
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64AtomicCompareExchange(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
  ArchOpcode opcode;
  if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
    opcode = kLoong64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             atomic_op.memory_access_kind);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64AtomicCompareExchange(
    Node* node) {
  ArchOpcode opcode;
  AtomicOpParameters params = AtomicOpParametersOf(node->op());
  if (params.type() == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (params.type() == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (params.type() == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else if (params.type() == MachineType::Uint64()) {
    opcode = kLoong64Word64AtomicCompareExchangeUint64;
  } else {
    UNREACHABLE();
  }
  VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord64,
                             params.kind());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    ArchOpcode opcode;
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = int8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = uint8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = int16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = uint16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
               atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = word32_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32,
                     atomic_op.memory_access_kind);
  } else {
    ArchOpcode opcode;
    AtomicOpParameters params = AtomicOpParametersOf(node->op());
    if (params.type() == MachineType::Int8()) {
      opcode = int8_op;
    } else if (params.type() == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (params.type() == MachineType::Int16()) {
      opcode = int16_op;
    } else if (params.type() == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (params.type() == MachineType::Int32() ||
               params.type() == MachineType::Uint32()) {
      opcode = word32_op;
    } else {
      UNREACHABLE();
    }

    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord32, params.kind());
  }
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) { \
    VisitWord32AtomicBinaryOperation(                                      \
        node, kAtomic##op##Int8, kAtomic##op##Uint8, kAtomic##op##Int16,   \
        kAtomic##op##Uint16, kAtomic##op##Word32);                         \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64AtomicBinaryOperation(
    node_t node, ArchOpcode uint8_op, ArchOpcode uint16_op,
    ArchOpcode uint32_op, ArchOpcode uint64_op) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    ArchOpcode opcode;
    if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = uint8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = uint16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = uint32_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint64()) {
      opcode = uint64_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64,
                     atomic_op.memory_access_kind);
  } else {
    ArchOpcode opcode;
    AtomicOpParameters params = AtomicOpParametersOf(node->op());
    if (params.type() == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (params.type() == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (params.type() == MachineType::Uint32()) {
      opcode = uint32_op;
    } else if (params.type() == MachineType::Uint64()) {
      opcode = uint64_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinop(this, node, opcode, AtomicWidth::kWord64, params.kind());
  }
}

#define VISIT_ATOMIC_BINOP(op)                                                 \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::VisitWord64Atomic##op(node_t node) {     \
    VisitWord64AtomicBinaryOperation(node, kAtomic##op##Uint8,                 \
                                     kAtomic##op##Uint16, kAtomic##op##Word32, \
                                     kLoong64Word64Atomic##op##Uint64);        \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

#define SIMD_TYPE_LIST(V) \
  V(F64x2)                \
  V(F32x4)                \
  V(I64x2)                \
  V(I32x4)                \
  V(I16x8)                \
  V(I8x16)

#define SIMD_UNOP_LIST(V)                                             \
  V(F64x2Abs, kLoong64F64x2Abs)                                       \
  V(F64x2Neg, kLoong64F64x2Neg)                                       \
  V(F64x2Sqrt, kLoong64F64x2Sqrt)                                     \
  V(F64x2Ceil, kLoong64F64x2Ceil)                                     \
  V(F64x2Floor, kLoong64F64x2Floor)                                   \
  V(F64x2Trunc, kLoong64F64x2Trunc)                                   \
  V(F64x2NearestInt, kLoong64F64x2NearestInt)                         \
  V(I64x2Neg, kLoong64I64x2Neg)                                       \
  V(I64x2BitMask, kLoong64I64x2BitMask)                               \
  V(F64x2ConvertLowI32x4S, kLoong64F64x2ConvertLowI32x4S)             \
  V(F64x2ConvertLowI32x4U, kLoong64F64x2ConvertLowI32x4U)             \
  V(F64x2PromoteLowF32x4, kLoong64F64x2PromoteLowF32x4)               \
  V(F32x4SConvertI32x4, kLoong64F32x4SConvertI32x4)                   \
  V(F32x4UConvertI32x4, kLoong64F32x4UConvertI32x4)                   \
  V(F32x4Abs, kLoong64F32x4Abs)                                       \
  V(F32x4Neg, kLoong64F32x4Neg)                                       \
  V(F32x4Sqrt, kLoong64F32x4Sqrt)                                     \
  V(F32x4Ceil, kLoong64F32x4Ceil)                                     \
  V(F32x4Floor, kLoong64F32x4Floor)                                   \
  V(F32x4Trunc, kLoong64F32x4Trunc)                                   \
  V(F32x4NearestInt, kLoong64F32x4NearestInt)                         \
  V(F32x4DemoteF64x2Zero, kLoong64F32x4DemoteF64x2Zero)               \
  V(I64x2Abs, kLoong64I64x2Abs)                                       \
  V(I64x2SConvertI32x4Low, kLoong64I64x2SConvertI32x4Low)             \
  V(I64x2SConvertI32x4High, kLoong64I64x2SConvertI32x4High)           \
  V(I64x2UConvertI32x4Low, kLoong64I64x2UConvertI32x4Low)             \
  V(I64x2UConvertI32x4High, kLoong64I64x2UConvertI32x4High)           \
  V(I32x4SConvertF32x4, kLoong64I32x4SConvertF32x4)                   \
  V(I32x4UConvertF32x4, kLoong64I32x4UConvertF32x4)                   \
  V(I32x4Neg, kLoong64I32x4Neg)                                       \
  V(I32x4SConvertI16x8Low, kLoong64I32x4SConvertI16x8Low)             \
  V(I32x4SConvertI16x8High, kLoong64I32x4SConvertI16x8High)           \
  V(I32x4UConvertI16x8Low, kLoong64I32x4UConvertI16x8Low)             \
  V(I32x4UConvertI16x8High, kLoong64I32x4UConvertI16x8High)           \
  V(I32x4Abs, kLoong64I32x4Abs)                                       \
  V(I32x4BitMask, kLoong64I32x4BitMask)                               \
  V(I32x4TruncSatF64x2SZero, kLoong64I32x4TruncSatF64x2SZero)         \
  V(I32x4TruncSatF64x2UZero, kLoong64I32x4TruncSatF64x2UZero)         \
  V(I32x4RelaxedTruncF32x4S, kLoong64I32x4RelaxedTruncF32x4S)         \
  V(I32x4RelaxedTruncF32x4U, kLoong64I32x4RelaxedTruncF32x4U)         \
  V(I32x4RelaxedTruncF64x2SZero, kLoong64I32x4RelaxedTruncF64x2SZero) \
  V(I32x4RelaxedTruncF64x2UZero, kLoong64I32x4RelaxedTruncF64x2UZero) \
  V(I16x8Neg, kLoong64I16x8Neg)                                       \
  V(I16x8SConvertI8x16Low, kLoong64I16x8SConvertI8x16Low)             \
  V(I16x8SConvertI8x16High, kLoong64I16x8SConvertI8x16High)           \
  V(I16x8UConvertI8x16Low, kLoong64I16x8UConvertI8x16Low)             \
  V(I16x8UConvertI8x16High, kLoong64I16x8UConvertI8x16High)           \
  V(I16x8Abs, kLoong64I16x8Abs)                                       \
  V(I16x8BitMask, kLoong64I16x8BitMask)                               \
  V(I8x16Neg, kLoong64I8x16Neg)                                       \
  V(I8x16Abs, kLoong64I8x16Abs)                                       \
  V(I8x16Popcnt, kLoong64I8x16Popcnt)                                 \
  V(I8x16BitMask, kLoong64I8x16BitMask)                               \
  V(S128Not, kLoong64S128Not)                                         \
  V(I64x2AllTrue, kLoong64I64x2AllTrue)                               \
  V(I32x4AllTrue, kLoong64I32x4AllTrue)                               \
  V(I16x8AllTrue, kLoong64I16x8AllTrue)                               \
  V(I8x16AllTrue, kLoong64I8x16AllTrue)                               \
  V(V128AnyTrue, kLoong64V128AnyTrue)

#define SIMD_SHIFT_OP_LIST(V) \
  V(I64x2Shl)                 \
  V(I64x2ShrS)                \
  V(I64x2ShrU)                \
  V(I32x4Shl)                 \
  V(I32x4ShrS)                \
  V(I32x4ShrU)                \
  V(I16x8Shl)                 \
  V(I16x8ShrS)                \
  V(I16x8ShrU)                \
  V(I8x16Shl)                 \
  V(I8x16ShrS)                \
  V(I8x16ShrU)

#define SIMD_BINOP_LIST(V)                                \
  V(F64x2Add, kLoong64F64x2Add)                           \
  V(F64x2Sub, kLoong64F64x2Sub)                           \
  V(F64x2Mul, kLoong64F64x2Mul)                           \
  V(F64x2Div, kLoong64F64x2Div)                           \
  V(F64x2Min, kLoong64F64x2Min)                           \
  V(F64x2Max, kLoong64F64x2Max)                           \
  V(F64x2Eq, kLoong64F64x2Eq)                             \
  V(F64x2Ne, kLoong64F64x2Ne)                             \
  V(F64x2Lt, kLoong64F64x2Lt)                             \
  V(F64x2Le, kLoong64F64x2Le)                             \
  V(F64x2RelaxedMin, kLoong64F64x2RelaxedMin)             \
  V(F64x2RelaxedMax, kLoong64F64x2RelaxedMax)             \
  V(I64x2Eq, kLoong64I64x2Eq)                             \
  V(I64x2Ne, kLoong64I64x2Ne)                             \
  V(I64x2Add, kLoong64I64x2Add)                           \
  V(I64x2Sub, kLoong64I64x2Sub)                           \
  V(I64x2Mul, kLoong64I64x2Mul)                           \
  V(I64x2GtS, kLoong64I64x2GtS)                           \
  V(I64x2GeS, kLoong64I64x2GeS)                           \
  V(F32x4Add, kLoong64F32x4Add)                           \
  V(F32x4Sub, kLoong64F32x4Sub)                           \
  V(F32x4Mul, kLoong64F32x4Mul)                           \
  V(F32x4Div, kLoong64F32x4Div)                           \
  V(F32x4Max, kLoong64F32x4Max)                           \
  V(F32x4Min, kLoong64F32x4Min)                           \
  V(F32x4Eq, kLoong64F32x4Eq)                             \
  V(F32x4Ne, kLoong64F32x4Ne)                             \
  V(F32x4Lt, kLoong64F32x4Lt)                             \
  V(F32x4Le, kLoong64F32x4Le)                             \
  V(F32x4RelaxedMin, kLoong64F32x4RelaxedMin)             \
  V(F32x4RelaxedMax, kLoong64F32x4RelaxedMax)             \
  V(I32x4Add, kLoong64I32x4Add)                           \
  V(I32x4Sub, kLoong64I32x4Sub)                           \
  V(I32x4Mul, kLoong64I32x4Mul)                           \
  V(I32x4MaxS, kLoong64I32x4MaxS)                         \
  V(I32x4MinS, kLoong64I32x4MinS)                         \
  V(I32x4MaxU, kLoong64I32x4MaxU)                         \
  V(I32x4MinU, kLoong64I32x4MinU)                         \
  V(I32x4Eq, kLoong64I32x4Eq)                             \
  V(I32x4Ne, kLoong64I32x4Ne)                             \
  V(I32x4GtS, kLoong64I32x4GtS)                           \
  V(I32x4GeS, kLoong64I32x4GeS)                           \
  V(I32x4GtU, kLoong64I32x4GtU)                           \
  V(I32x4GeU, kLoong64I32x4GeU)                           \
  V(I32x4DotI16x8S, kLoong64I32x4DotI16x8S)               \
  V(I16x8Add, kLoong64I16x8Add)                           \
  V(I16x8AddSatS, kLoong64I16x8AddSatS)                   \
  V(I16x8AddSatU, kLoong64I16x8AddSatU)                   \
  V(I16x8Sub, kLoong64I16x8Sub)                           \
  V(I16x8SubSatS, kLoong64I16x8SubSatS)                   \
  V(I16x8SubSatU, kLoong64I16x8SubSatU)                   \
  V(I16x8Mul, kLoong64I16x8Mul)                           \
  V(I16x8MaxS, kLoong64I16x8MaxS)                         \
  V(I16x8MinS, kLoong64I16x8MinS)                         \
  V(I16x8MaxU, kLoong64I16x8MaxU)                         \
  V(I16x8MinU, kLoong64I16x8MinU)                         \
  V(I16x8Eq, kLoong64I16x8Eq)                             \
  V(I16x8Ne, kLoong64I16x8Ne)                             \
  V(I16x8GtS, kLoong64I16x8GtS)                           \
  V(I16x8GeS, kLoong64I16x8GeS)                           \
  V(I16x8GtU, kLoong64I16x8GtU)                           \
  V(I16x8GeU, kLoong64I16x8GeU)                           \
  V(I16x8RoundingAverageU, kLoong64I16x8RoundingAverageU) \
  V(I16x8SConvertI32x4, kLoong64I16x8SConvertI32x4)       \
  V(I16x8UConvertI32x4, kLoong64I16x8UConvertI32x4)       \
  V(I16x8Q15MulRSatS, kLoong64I16x8Q15MulRSatS)           \
  V(I16x8RelaxedQ15MulRS, kLoong64I16x8RelaxedQ15MulRS)   \
  V(I8x16Add, kLoong64I8x16Add)                           \
  V(I8x16AddSatS, kLoong64I8x16AddSatS)                   \
  V(I8x16AddSatU, kLoong64I8x16AddSatU)                   \
  V(I8x16Sub, kLoong64I8x16Sub)                           \
  V(I8x16SubSatS, kLoong64I8x16SubSatS)                   \
  V(I8x16SubSatU, kLoong64I8x16SubSatU)                   \
  V(I8x16MaxS, kLoong64I8x16MaxS)                         \
  V(I8x16MinS, kLoong64I8x16MinS)                         \
  V(I8x16MaxU, kLoong64I8x16MaxU)                         \
  V(I8x16MinU, kLoong64I8x16MinU)                         \
  V(I8x16Eq, kLoong64I8x16Eq)                             \
  V(I8x16Ne, kLoong64I8x16Ne)                             \
  V(I8x16GtS, kLoong64I8x16GtS)                           \
  V(I8x16GeS, kLoong64I8x16GeS)                           \
  V(I8x16GtU, kLoong64I8x16GtU)                           \
  V(I8x16GeU, kLoong64I8x16GeU)                           \
  V(I8x16RoundingAverageU, kLoong64I8x16RoundingAverageU) \
  V(I8x16SConvertI16x8, kLoong64I8x16SConvertI16x8)       \
  V(I8x16UConvertI16x8, kLoong64I8x16UConvertI16x8)       \
  V(S128And, kLoong64S128And)                             \
  V(S128Or, kLoong64S128Or)                               \
  V(S128Xor, kLoong64S128Xor)                             \
  V(S128AndNot, kLoong64S128AndNot)

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitS128Const(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitS128Const(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  static const int kUint32Immediates = kSimd128Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kLoong64S128Zero, dst);
  } else if (all_ones) {
    Emit(kLoong64S128AllOnes, dst);
  } else {
    Emit(kLoong64S128Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    Emit(kLoong64S128Zero, g.DefineAsRegister(node));
  }
}

#define SIMD_VISIT_SPLAT(Type)                                          \
  template <typename Adapter>                                           \
  void InstructionSelectorT<Adapter>::Visit##Type##Splat(node_t node) { \
    VisitRR(this, kLoong64##Type##Splat, node);                         \
  }
SIMD_TYPE_LIST(SIMD_VISIT_SPLAT)
#undef SIMD_VISIT_SPLAT

#define SIMD_VISIT_EXTRACT_LANE(Type, Sign)                           \
  template <typename Adapter>                                         \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign( \
      node_t node) {                                                  \
    VisitRRI(this, kLoong64##Type##ExtractLane##Sign, node);          \
  }
SIMD_VISIT_EXTRACT_LANE(F64x2, )
SIMD_VISIT_EXTRACT_LANE(F32x4, )
SIMD_VISIT_EXTRACT_LANE(I64x2, )
SIMD_VISIT_EXTRACT_LANE(I32x4, )
SIMD_VISIT_EXTRACT_LANE(I16x8, U)
SIMD_VISIT_EXTRACT_LANE(I16x8, S)
SIMD_VISIT_EXTRACT_LANE(I8x16, U)
SIMD_VISIT_EXTRACT_LANE(I8x16, S)
#undef SIMD_VISIT_EXTRACT_LANE

#define SIMD_VISIT_REPLACE_LANE(Type)                                         \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Type##ReplaceLane(node_t node) { \
    VisitRRIR(this, kLoong64##Type##ReplaceLane, node);                       \
  }
SIMD_TYPE_LIST(SIMD_VISIT_REPLACE_LANE)
#undef SIMD_VISIT_REPLACE_LANE

#define SIMD_VISIT_UNOP(Name, instruction)                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, instruction, node);                            \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP

#define SIMD_VISIT_SHIFT_OP(Name)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitSimdShift(this, kLoong64##Name, node);                  \
  }
SIMD_SHIFT_OP_LIST(SIMD_VISIT_SHIFT_OP)
#undef SIMD_VISIT_SHIFT_OP

#define SIMD_VISIT_BINOP(Name, instruction)                      \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, instruction, node);                           \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP)
#undef SIMD_VISIT_BINOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  VisitRRRR(this, kLoong64S128Select, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

#define SIMD_UNIMP_OP_LIST(V) \
  V(F64x2Qfma)                \
  V(F64x2Qfms)                \
  V(F32x4Qfma)                \
  V(F32x4Qfms)                \
  V(I16x8DotI8x16I7x16S)      \
  V(I32x4DotI8x16I7x16AddS)

#define SIMD_VISIT_UNIMP_OP(Name)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }
SIMD_UNIMP_OP_LIST(SIMD_VISIT_UNIMP_OP)

#undef SIMD_VISIT_UNIMP_OP
#undef SIMD_UNIMP_OP_LIST

#define UNIMPLEMENTED_SIMD_FP16_OP_LIST(V) \
  V(F16x8Splat)                            \
  V(F16x8ExtractLane)                      \
  V(F16x8ReplaceLane)                      \
  V(F16x8Abs)                              \
  V(F16x8Neg)                              \
  V(F16x8Sqrt)                             \
  V(F16x8Floor)                            \
  V(F16x8Ceil)                             \
  V(F16x8Trunc)                            \
  V(F16x8NearestInt)                       \
  V(F16x8Add)                              \
  V(F16x8Sub)                              \
  V(F16x8Mul)                              \
  V(F16x8Div)                              \
  V(F16x8Min)                              \
  V(F16x8Max)                              \
  V(F16x8Pmin)                             \
  V(F16x8Pmax)                             \
  V(F16x8Eq)                               \
  V(F16x8Ne)                               \
  V(F16x8Lt)                               \
  V(F16x8Le)                               \
  V(F16x8SConvertI16x8)                    \
  V(F16x8UConvertI16x8)                    \
  V(I16x8SConvertF16x8)                    \
  V(I16x8UConvertF16x8)                    \
  V(F32x4PromoteLowF16x8)                  \
  V(F16x8DemoteF32x4Zero)                  \
  V(F16x8DemoteF64x2Zero)                  \
  V(F16x8Qfma)                             \
  V(F16x8Qfms)

#define SIMD_VISIT_UNIMPL_FP16_OP(Name)                          \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_FP16_OP_LIST(SIMD_VISIT_UNIMPL_FP16_OP)
#undef SIMD_VISIT_UNIMPL_FP16_OP
#undef UNIMPLEMENTED_SIMD_FP16_OP_LIST

#if V8_ENABLE_WEBASSEMBLY
namespace {

struct ShuffleEntry {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode opcode;
};

static const ShuffleEntry arch_shuffles[] = {
    {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
     kLoong64S32x4InterleaveRight},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kLoong64S32x4InterleaveLeft},
    {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27},
     kLoong64S32x4PackEven},
    {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31},
     kLoong64S32x4PackOdd},
    {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27},
     kLoong64S32x4InterleaveEven},
    {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31},
     kLoong64S32x4InterleaveOdd},

    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kLoong64S16x8InterleaveRight},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kLoong64S16x8InterleaveLeft},
    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kLoong64S16x8PackEven},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kLoong64S16x8PackOdd},
    {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29},
     kLoong64S16x8InterleaveEven},
    {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31},
     kLoong64S16x8InterleaveOdd},
    {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9},
     kLoong64S16x4Reverse},
    {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13},
     kLoong64S16x2Reverse},

    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kLoong64S8x16InterleaveRight},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kLoong64S8x16InterleaveLeft},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kLoong64S8x16PackEven},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kLoong64S8x16PackOdd},
    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kLoong64S8x16InterleaveEven},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kLoong64S8x16InterleaveOdd},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8},
     kLoong64S8x8Reverse},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
     kLoong64S8x4Reverse},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
     kLoong64S8x2Reverse}};

bool TryMatchArchShuffle(const uint8_t* shuffle, const ShuffleEntry* table,
                         size_t num_entries, bool is_swizzle,
                         ArchOpcode* opcode) {
  uint8_t mask = is_swizzle ? kSimd128Size - 1 : 2 * kSimd128Size - 1;
  for (size_t i = 0; i < num_entries; ++i) {
    const ShuffleEntry& entry = table[i];
    int j = 0;
    for (; j < kSimd128Size; ++j) {
      if ((entry.shuffle[j] & mask) != (shuffle[j] & mask)) {
        break;
      }
    }
    if (j == kSimd128Size) {
      *opcode = entry.opcode;
      return true;
    }
  }
  return false;
}

}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI8x16Shuffle(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI8x16Shuffle(Node* node) {
  uint8_t shuffle[kSimd128Size];
  bool is_swizzle;
  // TODO(LOONG_dev): Properly use view here once Turboshaft support is
  // implemented.
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle(view, shuffle, &is_swizzle);
  uint8_t shuffle32x4[4];
  ArchOpcode opcode;
  if (TryMatchArchShuffle(shuffle, arch_shuffles, arraysize(arch_shuffles),
                          is_swizzle, &opcode)) {
    VisitRRR(this, opcode, node);
    return;
  }
  Node* input0 = node->InputAt(0);
  Node* input1 = node->InputAt(1);
  uint8_t offset;
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    Emit(kLoong64S8x16Concat, g.DefineSameAsFirst(node), g.UseRegister(input1),
         g.UseRegister(input0), g.UseImmediate(offset));
    return;
  }
  if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    Emit(kLoong64S32x4Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle32x4)));
    return;
  }
  Emit(kLoong64I8x16Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
       g.UseRegister(input1),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 4)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 8)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 12)));
}
#else
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  UNREACHABLE();
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    // We don't want input 0 or input 1 to be the same as output, since we will
    // modify output before do the calculation.
    Emit(kLoong64I8x16Swizzle, g.DefineAsRegister(node),
         g.UseUniqueRegister(node->InputAt(0)),
         g.UseUniqueRegister(node->InputAt(1)), arraysize(temps), temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt32(node_t node) {
  VisitRR(this, kLoong64Ext_w_b, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
  VisitRR(this, kLoong64Ext_w_h, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt64(node_t node) {
  VisitRR(this, kLoong64Ext_w_b, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt64(node_t node) {
  VisitRR(this, kLoong64Ext_w_h, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Emit(kLoong64Sll_w, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)), g.TempImmediate(0));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitUniqueRRR(this, kLoong64F32x4Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitUniqueRRR(this, kLoong64F32x4Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitUniqueRRR(this, kLoong64F64x2Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitUniqueRRR(this, kLoong64F64x2Pmax, node);
}

#define VISIT_EXT_MUL(OPCODE1, OPCODE2)                                    \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulLow##OPCODE2(  \
      node_t node) {}                                                      \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulHigh##OPCODE2( \
      node_t node) {}

VISIT_EXT_MUL(I64x2, I32x4S)
VISIT_EXT_MUL(I64x2, I32x4U)
VISIT_EXT_MUL(I32x4, I16x8S)
VISIT_EXT_MUL(I32x4, I16x8U)
VISIT_EXT_MUL(I16x8, I8x16S)
VISIT_EXT_MUL(I16x8, I8x16U)
#undef VISIT_EXT_MUL

#define VISIT_EXTADD_PAIRWISE(OPCODE)                              \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) { \
    if constexpr (Adapter::IsTurboshaft) {                         \
      UNIMPLEMENTED();                                             \
    } else {                                                       \
      Loong64OperandGeneratorT<Adapter> g(this);                   \
      Emit(kLoong64ExtAddPairwise, g.DefineAsRegister(node),       \
           g.UseRegister(node->InputAt(0)));                       \
    }                                                              \
  }
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16S)
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16U)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8S)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8U)
#undef VISIT_EXTADD_PAIRWISE

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
  UNREACHABLE();
}

// static
MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  MachineOperatorBuilder::Flags flags = MachineOperatorBuilder::kNoFlags;
  return flags | MachineOperatorBuilder::kWord32ShiftIsSafe |
         MachineOperatorBuilder::kInt32DivIsSafe |
         MachineOperatorBuilder::kUint32DivIsSafe |
         MachineOperatorBuilder::kFloat64RoundDown |
         MachineOperatorBuilder::kFloat32RoundDown |
         MachineOperatorBuilder::kFloat64RoundUp |
         MachineOperatorBuilder::kFloat32RoundUp |
         MachineOperatorBuilder::kFloat64RoundTruncate |
         MachineOperatorBuilder::kFloat32RoundTruncate |
         MachineOperatorBuilder::kFloat64RoundTiesEven |
         MachineOperatorBuilder::kFloat32RoundTiesEven;
}

// static
MachineOperatorBuilder::AlignmentRequirements
InstructionSelector::AlignmentRequirements() {
  return MachineOperatorBuilder::AlignmentRequirements::
      FullUnalignedAccessSupport();
}

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurbofanAdapter>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurboshaftAdapter>;

#undef SIMD_BINOP_LIST
#undef SIMD_SHIFT_OP_LIST
#undef SIMD_UNOP_LIST
#undef SIMD_TYPE_LIST
#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```