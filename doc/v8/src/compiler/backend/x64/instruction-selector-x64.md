Response: The user wants a summary of the C++ source code file `v8/src/compiler/backend/x64/instruction-selector-x64.cc`.
The request also asks to illustrate the file's relation to JavaScript using a JavaScript example.
The provided code snippet is the first part of a larger file.

Based on the file path and the included headers, this file is likely responsible for:

1. **Instruction Selection:**  Choosing the appropriate x64 machine instructions to implement the operations defined in the intermediate representation (IR) of the V8 JavaScript engine.
2. **Backend for x64:** This file is specifically for the x64 architecture.
3. **Compiler Backend:**  It's part of the compiler's backend, which translates the IR into machine code.

Key elements in the provided code snippet:

* **Includes:** Various V8 internal headers related to compilation, code generation, and architecture specifics.
* **Namespaces:**  `v8::internal::compiler`.
* **Helper Functions:**
    * `IsCompressed`: Checks if a node represents a compressed value (related to pointer compression).
    * `ValueFitsIntoImmediate`, `CanBeImmediate`, `GetImmediateIntegerValue`:  Deal with immediate values in instructions.
    * `TryMatchScaledIndex`, `TryMatchBaseWithScaledIndexAndDisplacement`:  Help in identifying memory access patterns that can be optimized using x64 addressing modes (base + index * scale + displacement).
* **Operand Generator (`X64OperandGeneratorT`):** A class to generate machine operands, handling specifics of the x64 architecture like addressing modes.
* **Helper Functions for Opcode Selection:** `GetLoadOpcode`, `GetStoreOpcode` - determine the specific x64 instruction for load and store operations based on data types.
* **Instruction Selection Visitors:** Functions like `VisitTraceInstruction`, `VisitStackSlot`, `VisitLoadLane`, `VisitLoadTransform`, etc., are responsible for handling specific IR nodes and emitting corresponding x64 instructions. These functions use the operand generator to create the instruction operands.

**Relationship to JavaScript:**

This file is a crucial part of V8's compilation pipeline. When JavaScript code is executed, V8's compiler (TurboFan or Crankshaft, though this file seems more aligned with TurboFan due to the presence of "turboshaft" in the code) translates the JavaScript into an internal representation. Then, the instruction selector, using files like this one, converts that representation into actual x64 machine code that the CPU can execute.

**Summary of Part 1's Functionality:**

This first part of the `instruction-selector-x64.cc` file lays the foundation for selecting x64 instructions. It provides:

1. **Basic infrastructure:** Includes, namespaces, and helper functions for common tasks.
2. **Mechanisms for handling immediate values:** Determining if a value can be represented as an immediate and retrieving its integer representation.
3. **Logic for recognizing and decomposing memory access patterns:** Identifying base registers, index registers, scaling factors, and displacements to utilize efficient x64 addressing modes.
4. **An operand generator tailored for the x64 architecture:** This generator knows how to create the correct operands for x64 instructions, including handling different addressing modes.
5. **Initial implementations of instruction selection for certain operations:**  Examples include handling trace instructions, stack slots, and some WebAssembly-related instructions (`LoadLane`, `LoadTransform`). It also includes helpers for determining the correct load and store opcodes based on data types.

**JavaScript Example (Illustrative):**

Consider the following JavaScript code:

```javascript
function add(a, b) {
  return a + b;
}

let x = 5;
let y = 10;
let result = add(x, y);
console.log(result); // Output: 15
```

When V8 compiles the `add` function and the subsequent code, the `instruction-selector-x64.cc` file (along with other parts of the compiler) would be involved in generating the x64 instructions for:

* **Loading the values of `a` and `b` into registers.**  The `VisitLoad` function (defined later but conceptually introduced here with `GetLoadOpcode`) and the operand generator would be involved.
* **Performing the addition.**  A `VisitAdd` function (likely in the subsequent parts of the file) would select an x64 addition instruction (e.g., `ADD`).
* **Storing the result.** A `VisitStore` function (and `GetStoreOpcode`) would generate the instruction to store the sum.
* **Potentially, accessing memory for the `console.log` call.**  The memory access logic in this file would be relevant.

For instance, the memory access pattern matching could be used if you are accessing elements in an array:

```javascript
let myArray = [1, 2, 3, 4];
let index = 2;
let value = myArray[index]; // Accessing myArray[2]
```

The compiler might recognize this as a base address (`myArray`'s starting address) plus an index (`index`) potentially scaled by the size of the array elements. The functions like `TryMatchScaledIndex` would be involved in this process.
This is the first part of the `instruction-selector-x64.cc` file, which is a crucial component in V8's compiler for the x64 architecture. Its primary function is **instruction selection**, which is the process of choosing the appropriate x64 machine instructions to implement the operations defined in V8's intermediate representation (IR).

Here's a breakdown of the functionalities provided in this first part:

1. **Setup and Includes:** It includes necessary header files for V8's internal data structures, code generation, and x64 architecture specifics. This sets up the environment for instruction selection.

2. **Helper Functions for Node Analysis:** It defines various helper functions to analyze the IR nodes:
    * **`IsCompressed(Node* const node)` and `IsCompressed(InstructionSelectorT<Adapter>* selector, turboshaft::OpIndex node)`:** These functions determine if a given node represents a compressed value or pointer, which is relevant for pointer compression optimizations.
    * **`LhsIsNotOnlyConstant` (DEBUG only):**  A debugging assertion to ensure that commutative binary operations have constants on the right side, as part of graph normalization.
    * **`ValueFitsIntoImmediate`:** Checks if an integer value can be represented as an immediate operand in an x64 instruction.
    * **`CanBeImmediate`:**  Determines if a given IR node represents a constant value that can be used as an immediate operand. It handles different constant types (integers, heap objects).
    * **`GetImmediateIntegerValue`:** Retrieves the integer value of a constant node, assuming it can be used as an immediate.
    * **`TryMatchScaledIndex`:** Attempts to recognize patterns like `base + index * scale` in memory access operations. This helps in utilizing efficient x64 addressing modes.
    * **`TryMatchBaseWithScaledIndexAndDisplacement`:**  Extends the scaled index matching to include a base register and a displacement, allowing for recognition of more complex memory access patterns like `base + index * scale + displacement`.

3. **Operand Generator (`X64OperandGeneratorT`):** This template class is responsible for generating the actual operands for the x64 instructions. It provides methods like:
    * **`CanBeImmediate` and `GetImmediateIntegerValue`:**  Wrappers around the global helper functions.
    * **`CanBeMemoryOperand`:** Checks if a given node can be used as a memory operand for a specific instruction, considering data types and pointer compression.
    * **`IsZeroIntConstant`:** Checks if a node represents an integer constant with the value zero.
    * **`GenerateMemoryOperandInputs`:**  A crucial function that takes components of a memory address (index, scale, base, displacement) and generates the appropriate `InstructionOperand` objects for the x64 instruction, handling different addressing modes.
    * **`GetEffectiveAddressMemoryOperand`:**  A higher-level function that tries to match complex memory access patterns and generate the most efficient memory operand.

4. **Helper Functions for Opcode Determination:**
    * **`GetLoadOpcode`:** Determines the specific x64 instruction opcode for a load operation based on the data type being loaded (e.g., `kX64Movl` for a 32-bit load, `kX64Movq` for a 64-bit load). It handles both `LoadRepresentation` (Turbofan) and `MemoryRepresentation` (Turboshaft).
    * **`GetStoreOpcode`:** Similar to `GetLoadOpcode`, but for store operations.
    * **`GetSeqCstStoreOpcode`:**  Gets the opcode for sequentially consistent store operations.

5. **Instruction Selection "Visitor" Functions (Partial):** The snippet includes the beginning of several `Visit...` functions, which are the core of the instruction selection process. These functions are called for different types of IR nodes. In this part, we see examples like:
    * **`VisitTraceInstruction`:** Handles nodes representing debugging trace instructions.
    * **`VisitStackSlot`:** Handles the allocation and access of stack slots.
    * **`VisitAbortCSADcheck`:** Handles a specific check related to Code Sandboxing Across Domains (CSAD).
    * **`VisitLoadLane`, `VisitLoadTransform`, `VisitS256Const`, `VisitS256Zero`, `VisitSimd256LoadTransform`, `VisitF32x8RelaxedMin`, `VisitF32x8RelaxedMax`, `VisitF64x4RelaxedMin`, `VisitF64x4RelaxedMax`, `VisitSimd256Shufd`, `VisitSimd256Shufps`, `VisitSimd256Unpack`, `VisitSimdPack128To256`:** These functions handle specific WebAssembly SIMD (Single Instruction, Multiple Data) operations, demonstrating the file's role in supporting WebAssembly.

**Relationship to JavaScript (with Examples):**

This file directly translates the operations defined in the optimized JavaScript code (represented as IR) into low-level x64 instructions. Here's how it relates with examples:

* **Basic Arithmetic:** When you perform `a + b` in JavaScript, after optimization, the IR will have an "Add" node. The `VisitAdd` function (likely in later parts) in this file would select the `kX64Add` instruction to perform the addition on x64 registers.

* **Memory Access (Array Access):**  Consider `myArray[i]`. The IR will represent this memory access. The `TryMatchScaledIndex` and `TryMatchBaseWithScaledIndexAndDisplacement` functions would recognize the pattern (base address of `myArray` + index `i` * size of element). The `GenerateMemoryOperandInputs` function would then generate the appropriate addressing mode for the x64 `MOV` instruction to load the value.

   ```javascript
   let myArray = [10, 20, 30];
   let index = 1;
   let value = myArray[index]; // Accessing myArray[1]
   ```

   The compiler might generate an x64 instruction like `movl (%rax,%rcx,4), %rdx`  (assuming `%rax` holds the base address of `myArray`, `%rcx` holds the index, and we're loading a 32-bit integer into `%rdx`). This file is responsible for selecting this specific instruction and its operands.

* **WebAssembly SIMD:** The `VisitLoadLane`, `VisitLoadTransform`, etc., functions directly handle WebAssembly SIMD instructions. For example, a WebAssembly instruction to load a specific lane from a SIMD vector would be translated by `VisitLoadLane` into an x64 instruction like `pinsrd` (insert dword).

   ```javascript
   // Example WebAssembly (conceptual, actual syntax is different)
   // %v is a v128 vector, load byte at index 2 into register %r
   // load_lane.i8 2, %v
   ```

   The `VisitLoadLane` function would generate the corresponding `kX64Pinsrb` instruction.

In essence, this file is the bridge between the high-level operations in the optimized JavaScript code and the concrete instructions that the x64 processor can understand and execute. It makes crucial decisions about which x64 instructions to use for optimal performance.

### 提示词
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>

#include "src/base/bounds.h"
#include "src/base/iterator.h"
#include "src/base/logging.h"
#include "src/base/overflowing-math.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/machine-type.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/backend/instruction-selector-adapter.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/backend/instruction.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/turboshaft/load-store-simplification-reducer.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/handles/handles-inl.h"
#include "src/objects/slots-inl.h"
#include "src/roots/roots-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/simd-shuffle.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

namespace {

bool IsCompressed(Node* const node) {
  if (node == nullptr) return false;
  const IrOpcode::Value opcode = node->opcode();
  if (opcode == IrOpcode::kLoad || opcode == IrOpcode::kProtectedLoad ||
      opcode == IrOpcode::kLoadTrapOnNull ||
      opcode == IrOpcode::kUnalignedLoad ||
      opcode == IrOpcode::kLoadImmutable) {
    LoadRepresentation load_rep = LoadRepresentationOf(node->op());
    return load_rep.IsCompressed();
  } else if (node->opcode() == IrOpcode::kPhi) {
    MachineRepresentation phi_rep = PhiRepresentationOf(node->op());
    return phi_rep == MachineRepresentation::kCompressed ||
           phi_rep == MachineRepresentation::kCompressedPointer;
  }
  return false;
}

template <typename Adapter>
bool IsCompressed(InstructionSelectorT<Adapter>* selector,
                  turboshaft::OpIndex node) {
  if (!node.valid()) return false;
  if (selector->is_load(node)) {
    auto load = selector->load_view(node);
    return load.loaded_rep().IsCompressed();
  } else if (selector->IsPhi(node)) {
    MachineRepresentation phi_rep = selector->phi_representation_of(node);
    return phi_rep == MachineRepresentation::kCompressed ||
           phi_rep == MachineRepresentation::kCompressedPointer;
  }
  return false;
}

#ifdef DEBUG
// {left_idx} and {right_idx} are assumed to be the inputs of a commutative
// binop. This function checks that {left_idx} is not the only constant input of
// this binop (since the graph should have been normalized before, putting
// constants on the right input of binops when possible).
bool LhsIsNotOnlyConstant(turboshaft::Graph* graph,
                          turboshaft::OpIndex left_idx,
                          turboshaft::OpIndex right_idx) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  const Operation& left = graph->Get(left_idx);
  const Operation& right = graph->Get(right_idx);

  if (right.Is<ConstantOp>()) {
    // There is a constant on the right.
    return true;
  }
  if (left.Is<ConstantOp>()) {
    // Constant on the left but not on the right.
    return false;
  }

  // Left is not a constant
  return true;
}

#endif

}  // namespace

bool ValueFitsIntoImmediate(int64_t value) {
  // int32_t min will overflow if displacement mode is kNegativeDisplacement.
  constexpr int64_t kImmediateMin = std::numeric_limits<int32_t>::min() + 1;
  constexpr int64_t kImmediateMax = std::numeric_limits<int32_t>::max();
  static_assert(kImmediateMin ==
                turboshaft::LoadStoreSimplificationConfiguration::kMinOffset);
  static_assert(kImmediateMax ==
                turboshaft::LoadStoreSimplificationConfiguration::kMaxOffset);
  return kImmediateMin <= value && value <= kImmediateMax;
}

template <typename Adapter>
bool CanBeImmediate(InstructionSelectorT<Adapter>* selector,
                    typename Adapter::node_t node) {
  // TODO(dmercadier): this is not in sync with GetImmediateIntegerValue, which
  // is surprising because we often use the pattern
  // `if (CanBeImmediate()) { GetImmediateIntegerValue }`. We should make sure
  // that both functions are in sync.
  if (!selector->is_constant(node)) return false;
  auto constant = selector->constant_view(node);
  if (constant.is_compressed_heap_object()) {
    if (!COMPRESS_POINTERS_BOOL) return false;
    // For builtin code we need static roots
    if (selector->isolate()->bootstrapper() && !V8_STATIC_ROOTS_BOOL) {
      return false;
    }
    const RootsTable& roots_table = selector->isolate()->roots_table();
    RootIndex root_index;
    Handle<HeapObject> value = constant.heap_object_value();
    if (roots_table.IsRootHandle(value, &root_index)) {
      return RootsTable::IsReadOnly(root_index);
    }
    return false;
  }
  if (constant.is_int32() || constant.is_relocatable_int32()) {
    const int32_t value = constant.int32_value();
    // int32_t min will overflow if displacement mode is
    // kNegativeDisplacement.
    return value != std::numeric_limits<int32_t>::min();
  }
  if (constant.is_int64()) {
    const int64_t value = constant.int64_value();
    return ValueFitsIntoImmediate(value);
  }
  if (constant.is_number_zero()) {
    return true;
  }
  return false;
}

template <typename Adapter>
int32_t GetImmediateIntegerValue(InstructionSelectorT<Adapter>* selector,
                                 typename Adapter::node_t node) {
  DCHECK(CanBeImmediate(selector, node));
  auto constant = selector->constant_view(node);
  if (constant.is_int32()) return constant.int32_value();
  if (constant.is_int64()) {
    return static_cast<int32_t>(constant.int64_value());
  }
  DCHECK(constant.is_number_zero());
  return 0;
}

template <typename Adapter>
struct ScaledIndexMatch {
  using node_t = typename Adapter::node_t;

  node_t base;
  node_t index;
  int scale;
};

template <typename ScaleMatcher>
std::optional<ScaledIndexMatch<TurbofanAdapter>> TryMatchScaledIndex(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
    bool allow_power_of_two_plus_one) {
  ScaleMatcher m(node, allow_power_of_two_plus_one);
  if (!m.matches()) return std::nullopt;
  ScaledIndexMatch<TurbofanAdapter> match;
  match.index = node->InputAt(0);
  match.base = m.power_of_two_plus_one() ? match.index : nullptr;
  match.scale = m.scale();
  return match;
}

std::optional<ScaledIndexMatch<TurbofanAdapter>> TryMatchScaledIndex32(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
    bool allow_power_of_two_plus_one) {
  return TryMatchScaledIndex<Int32ScaleMatcher>(selector, node,
                                                allow_power_of_two_plus_one);
}

std::optional<ScaledIndexMatch<TurbofanAdapter>> TryMatchScaledIndex64(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
    bool allow_power_of_two_plus_one) {
  return TryMatchScaledIndex<Int64ScaleMatcher>(selector, node,
                                                allow_power_of_two_plus_one);
}

bool MatchScaledIndex(InstructionSelectorT<TurboshaftAdapter>* selector,
                      turboshaft::OpIndex node, turboshaft::OpIndex* index,
                      int* scale, bool* power_of_two_plus_one) {
  DCHECK_NOT_NULL(index);
  DCHECK_NOT_NULL(scale);
  using namespace turboshaft;  // NOLINT(build/namespaces)

  auto MatchScaleConstant = [](const Operation& op, int& scale,
                               bool* plus_one) {
    const ConstantOp* constant = op.TryCast<ConstantOp>();
    if (constant == nullptr) return false;
    if (constant->kind != ConstantOp::Kind::kWord32 &&
        constant->kind != ConstantOp::Kind::kWord64) {
      return false;
    }
    uint64_t value = constant->integral();
    if (plus_one) *plus_one = false;
    if (value == 1) return (scale = 0), true;
    if (value == 2) return (scale = 1), true;
    if (value == 4) return (scale = 2), true;
    if (value == 8) return (scale = 3), true;
    if (plus_one == nullptr) return false;
    *plus_one = true;
    if (value == 3) return (scale = 1), true;
    if (value == 5) return (scale = 2), true;
    if (value == 9) return (scale = 3), true;
    return false;
  };

  const Operation& op = selector->Get(node);
  if (const WordBinopOp* binop = op.TryCast<WordBinopOp>()) {
    if (binop->kind != WordBinopOp::Kind::kMul) return false;
    if (MatchScaleConstant(selector->Get(binop->right()), *scale,
                           power_of_two_plus_one)) {
      *index = binop->left();
      return true;
    }
    if (MatchScaleConstant(selector->Get(binop->left()), *scale,
                           power_of_two_plus_one)) {
      *index = binop->right();
      return true;
    }
    return false;
  } else if (const ShiftOp* shift = op.TryCast<ShiftOp>()) {
    if (shift->kind != ShiftOp::Kind::kShiftLeft) return false;
    int64_t scale_value;
    if (selector->MatchSignedIntegralConstant(shift->right(), &scale_value)) {
      if (scale_value < 0 || scale_value > 3) return false;
      *index = shift->left();
      *scale = static_cast<int>(scale_value);
      if (power_of_two_plus_one) *power_of_two_plus_one = false;
      return true;
    }
  }
  return false;
}

std::optional<ScaledIndexMatch<TurboshaftAdapter>> TryMatchScaledIndex(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex node,
    bool allow_power_of_two_plus_one) {
  ScaledIndexMatch<TurboshaftAdapter> match;
  bool plus_one = false;
  if (MatchScaledIndex(selector, node, &match.index, &match.scale,
                       allow_power_of_two_plus_one ? &plus_one : nullptr)) {
    match.base = plus_one ? match.index : turboshaft::OpIndex{};
    return match;
  }
  return std::nullopt;
}

std::optional<ScaledIndexMatch<TurboshaftAdapter>> TryMatchScaledIndex32(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex node,
    bool allow_power_of_two_plus_one) {
  return TryMatchScaledIndex(selector, node, allow_power_of_two_plus_one);
}

std::optional<ScaledIndexMatch<TurboshaftAdapter>> TryMatchScaledIndex64(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex node,
    bool allow_power_of_two_plus_one) {
  return TryMatchScaledIndex(selector, node, allow_power_of_two_plus_one);
}

template <typename Adapter>
struct BaseWithScaledIndexAndDisplacementMatch {
  using node_t = typename Adapter::node_t;

  node_t base = {};
  node_t index = {};
  int scale = 0;
  int64_t displacement = 0;
  DisplacementMode displacement_mode = kPositiveDisplacement;
};

template <typename BaseWithIndexAndDisplacementMatcher>
std::optional<BaseWithScaledIndexAndDisplacementMatch<TurbofanAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node) {
  BaseWithScaledIndexAndDisplacementMatch<TurbofanAdapter> result;
  BaseWithIndexAndDisplacementMatcher m(node);
  if (m.matches()) {
    result.base = m.base();
    result.index = m.index();
    result.scale = m.scale();
    if (m.displacement() == nullptr) {
      result.displacement = 0;
    } else {
      if (m.displacement()->opcode() == IrOpcode::kInt64Constant) {
        result.displacement = OpParameter<int64_t>(m.displacement()->op());
      } else {
        DCHECK_EQ(m.displacement()->opcode(), IrOpcode::kInt32Constant);
        result.displacement = OpParameter<int32_t>(m.displacement()->op());
      }
    }
    result.displacement_mode = m.displacement_mode();
    return result;
  }
  return std::nullopt;
}

std::optional<BaseWithScaledIndexAndDisplacementMatch<TurbofanAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement64(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node) {
  return TryMatchBaseWithScaledIndexAndDisplacement<
      BaseWithIndexAndDisplacement64Matcher>(selector, node);
}

std::optional<BaseWithScaledIndexAndDisplacementMatch<TurbofanAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement32(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node) {
  return TryMatchBaseWithScaledIndexAndDisplacement<
      BaseWithIndexAndDisplacement32Matcher>(selector, node);
}

std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement64ForWordBinop(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex left,
    turboshaft::OpIndex right, bool is_commutative);

std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement64(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  // The BaseWithIndexAndDisplacementMatcher canonicalizes the order of
  // displacements and scale factors that are used as inputs, so instead of
  // enumerating all possible patterns by brute force, checking for node
  // clusters using the following templates in the following order suffices
  // to find all of the interesting cases (S = index * scale, B = base
  // input, D = displacement input):
  //
  // (S + (B + D))
  // (S + (B + B))
  // (S + D)
  // (S + B)
  // ((S + D) + B)
  // ((S + B) + D)
  // ((B + D) + B)
  // ((B + B) + D)
  // (B + D)
  // (B + B)
  BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter> result;
  result.displacement_mode = kPositiveDisplacement;

  const Operation& op = selector->Get(node);
  if (const LoadOp* load = op.TryCast<LoadOp>()) {
    result.base = load->base();
    result.index = load->index().value_or_invalid();
    result.scale = load->element_size_log2;
    result.displacement = load->offset;
    if (load->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (const StoreOp* store = op.TryCast<StoreOp>()) {
    result.base = store->base();
    result.index = store->index().value_or_invalid();
    result.scale = store->element_size_log2;
    result.displacement = store->offset;
    if (store->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (op.Is<WordBinopOp>()) {
    // Nothing to do here, fall into the case below.
#ifdef V8_ENABLE_WEBASSEMBLY
  } else if (const Simd128LaneMemoryOp* lane_op =
                 op.TryCast<Simd128LaneMemoryOp>()) {
    result.base = lane_op->base();
    result.index = lane_op->index();
    result.scale = 0;
    result.displacement = 0;
    if (lane_op->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (const Simd128LoadTransformOp* load_transform =
                 op.TryCast<Simd128LoadTransformOp>()) {
    result.base = load_transform->base();
    DCHECK_EQ(load_transform->offset, 0);

    if (CanBeImmediate(selector, load_transform->index())) {
      result.index = {};
      result.displacement =
          GetImmediateIntegerValue(selector, load_transform->index());
    } else {
      result.index = load_transform->index();
      result.displacement = 0;
    }

    result.scale = 0;
    DCHECK(!load_transform->load_kind.tagged_base);
    return result;
#if V8_ENABLE_WASM_SIMD256_REVEC
  } else if (const Simd256LoadTransformOp* load_transform =
                 op.TryCast<Simd256LoadTransformOp>()) {
    result.base = load_transform->base();
    result.index = load_transform->index();
    DCHECK_EQ(load_transform->offset, 0);
    result.scale = 0;
    result.displacement = 0;
    DCHECK(!load_transform->load_kind.tagged_base);
    return result;
#endif  // V8_ENABLE_WASM_SIMD256_REVEC
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    return std::nullopt;
  }

  const WordBinopOp& binop = op.Cast<WordBinopOp>();
  OpIndex left = binop.left();
  OpIndex right = binop.right();
  return TryMatchBaseWithScaledIndexAndDisplacement64ForWordBinop(
      selector, left, right, binop.IsCommutative());
}

std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement64ForWordBinop(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex left,
    turboshaft::OpIndex right, bool is_commutative) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  // In the comments of this function, the following letters have the following
  // meaning:
  //
  //   S: scaled index. That is, "OpIndex * constant" or "OpIndex << constant",
  //      where "constant" is a small power of 2 (1, 2, 4, 8 for the
  //      multiplication, 0, 1, 2 or 3 for the shift). The "constant" is called
  //      "scale" in the BaseWithScaledIndexAndDisplacementMatch struct that is
  //      returned.
  //
  //   B: base. Just a regular OpIndex.
  //
  //   D: displacement. An integral constant.

  // Helper to check (S + ...)
  auto match_S_plus = [&selector](OpIndex left, OpIndex right)
      -> std::optional<
          BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>> {
    BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter> result;
    result.displacement_mode = kPositiveDisplacement;

    // Check (S + ...)
    if (MatchScaledIndex(selector, left, &result.index, &result.scale,
                         nullptr)) {
      result.displacement_mode = kPositiveDisplacement;

      // Check (S + (... binop ...))
      if (const WordBinopOp* right_binop =
              selector->Get(right).TryCast<WordBinopOp>()) {
        // Check (S + (B - D))
        if (right_binop->kind == WordBinopOp::Kind::kSub) {
          if (!selector->MatchSignedIntegralConstant(right_binop->right(),
                                                     &result.displacement)) {
            return std::nullopt;
          }
          result.base = right_binop->left();
          result.displacement_mode = kNegativeDisplacement;
          return result;
        }
        // Check (S + (... + ...))
        if (right_binop->kind == WordBinopOp::Kind::kAdd) {
          if (selector->MatchSignedIntegralConstant(right_binop->right(),
                                                    &result.displacement)) {
            // (S + (B + D))
            result.base = right_binop->left();
          } else if (selector->MatchSignedIntegralConstant(
                         right_binop->left(), &result.displacement)) {
            // (S + (D + B))
            result.base = right_binop->right();
          } else {
            // Treat it as (S + B)
            result.base = right;
            result.displacement = 0;
          }
          return result;
        }
      }

      // Check (S + D)
      if (selector->MatchSignedIntegralConstant(right, &result.displacement)) {
        result.base = OpIndex{};
        return result;
      }

      // Treat it as (S + B)
      result.base = right;
      result.displacement = 0;
      return result;
    }

    return std::nullopt;
  };

  // Helper to check ((S + ...) + ...)
  auto match_S_plus_plus = [&selector](turboshaft::OpIndex left,
                                       turboshaft::OpIndex right,
                                       turboshaft::OpIndex left_add_left,
                                       turboshaft::OpIndex left_add_right)
      -> std::optional<
          BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>> {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    DCHECK_EQ(selector->Get(left).Cast<WordBinopOp>().kind,
              WordBinopOp::Kind::kAdd);

    BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter> result;
    result.displacement_mode = kPositiveDisplacement;

    if (MatchScaledIndex(selector, left_add_left, &result.index, &result.scale,
                         nullptr)) {
      result.displacement_mode = kPositiveDisplacement;
      // Check ((S + D) + B)
      if (selector->MatchSignedIntegralConstant(left_add_right,
                                                &result.displacement)) {
        result.base = right;
        return result;
      }
      // Check ((S + B) + D)
      if (selector->MatchSignedIntegralConstant(right, &result.displacement)) {
        result.base = left_add_right;
        return result;
      }
      // Treat it as (B + B) and use index as right B.
      result.base = left;
      result.index = right;
      result.scale = 0;
      DCHECK_EQ(result.displacement, 0);
      return result;
    }
    return std::nullopt;
  };

  // Helper to check ((... + ...) + ...)
  auto match_plus_plus = [&selector, &match_S_plus_plus](OpIndex left,
                                                         OpIndex right)
      -> std::optional<
          BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>> {
    BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter> result;
    result.displacement_mode = kPositiveDisplacement;

    // Check ((... + ...) + ...)
    if (const WordBinopOp* left_add =
            selector->Get(left).TryCast<WordBinopOp>();
        left_add && left_add->kind == WordBinopOp::Kind::kAdd) {
      // Check ((S + ...) + ...)
      auto maybe_res =
          match_S_plus_plus(left, right, left_add->left(), left_add->right());
      if (maybe_res) return maybe_res;
      // Check ((... + S) + ...)
      maybe_res =
          match_S_plus_plus(left, right, left_add->right(), left_add->left());
      if (maybe_res) return maybe_res;
    }

    return std::nullopt;
  };

  // Check (S + ...)
  auto maybe_res = match_S_plus(left, right);
  if (maybe_res) return maybe_res;

  if (is_commutative) {
    // Check (... + S)
    maybe_res = match_S_plus(right, left);
    if (maybe_res) {
      return maybe_res;
    }
  }

  // Check ((... + ...) + ...)
  maybe_res = match_plus_plus(left, right);
  if (maybe_res) return maybe_res;

  if (is_commutative) {
    // Check (... + (... + ...))
    maybe_res = match_plus_plus(right, left);
    if (maybe_res) {
      return maybe_res;
    }
  }

  BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter> result;
  result.displacement_mode = kPositiveDisplacement;

  // Check (B + D)
  if (selector->MatchSignedIntegralConstant(right, &result.displacement)) {
    result.base = left;
    return result;
  }

  // Treat as (B + B) and use index as left B.
  result.index = left;
  result.base = right;
  return result;
}

std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement32(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    turboshaft::OpIndex node) {
  return TryMatchBaseWithScaledIndexAndDisplacement64(selector, node);
}

// Adds X64-specific methods for generating operands.
template <typename Adapter>
class X64OperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit X64OperandGeneratorT(InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  template <typename T>
  bool CanBeImmediate(T*) {
    UNREACHABLE(/*REMOVE*/);
  }

  bool CanBeImmediate(node_t node) {
    return compiler::CanBeImmediate(this->selector(), node);
  }

  int32_t GetImmediateIntegerValue(node_t node) {
    return compiler::GetImmediateIntegerValue(this->selector(), node);
  }

  bool CanBeMemoryOperand(InstructionCode opcode, node_t node, node_t input,
                          int effect_level) {
    if (!this->IsLoadOrLoadImmutable(input)) return false;
    if (!selector()->CanCover(node, input)) return false;

    if (effect_level != selector()->GetEffectLevel(input)) {
      return false;
    }

    MachineRepresentation rep =
        this->load_view(input).loaded_rep().representation();
    switch (opcode) {
      case kX64And:
      case kX64Or:
      case kX64Xor:
      case kX64Add:
      case kX64Sub:
      case kX64Push:
      case kX64Cmp:
      case kX64Test:
        // When pointer compression is enabled 64-bit memory operands can't be
        // used for tagged values.
        return rep == MachineRepresentation::kWord64 ||
               (!COMPRESS_POINTERS_BOOL && IsAnyTagged(rep));
      case kX64And32:
      case kX64Or32:
      case kX64Xor32:
      case kX64Add32:
      case kX64Sub32:
      case kX64Cmp32:
      case kX64Test32:
        // When pointer compression is enabled 32-bit memory operands can be
        // used for tagged values.
        return rep == MachineRepresentation::kWord32 ||
               (COMPRESS_POINTERS_BOOL &&
                (IsAnyTagged(rep) || IsAnyCompressed(rep)));
      case kAVXFloat64Add:
      case kAVXFloat64Sub:
      case kAVXFloat64Mul:
        DCHECK_EQ(MachineRepresentation::kFloat64, rep);
        return true;
      case kAVXFloat32Add:
      case kAVXFloat32Sub:
      case kAVXFloat32Mul:
        DCHECK_EQ(MachineRepresentation::kFloat32, rep);
        return true;
      case kX64Cmp16:
      case kX64Test16:
        return rep == MachineRepresentation::kWord16;
      case kX64Cmp8:
      case kX64Test8:
        return rep == MachineRepresentation::kWord8;
      default:
        break;
    }
    return false;
  }

  bool IsZeroIntConstant(node_t node) const {
    if constexpr (Adapter::IsTurboshaft) {
      if (turboshaft::ConstantOp* op =
              this->turboshaft_graph()
                  ->Get(node)
                  .template TryCast<turboshaft::ConstantOp>()) {
        switch (op->kind) {
          case turboshaft::ConstantOp::Kind::kWord32:
            return op->word32() == 0;
          case turboshaft::ConstantOp::Kind::kWord64:
            return op->word64() == 0;
          default:
            break;
        }
      }
      return false;
    } else {
      if (node->opcode() == IrOpcode::kInt32Constant) {
        return OpParameter<int32_t>(node->op()) == 0;
      } else if (node->opcode() == IrOpcode::kInt64Constant) {
        return OpParameter<int64_t>(node->op()) == 0;
      }
      return false;
    }
  }

  AddressingMode GenerateMemoryOperandInputs(
      optional_node_t index, int scale_exponent, node_t base,
      int64_t displacement, DisplacementMode displacement_mode,
      InstructionOperand inputs[], size_t* input_count,
      RegisterUseKind reg_kind = RegisterUseKind::kUseRegister) {
    AddressingMode mode = kMode_MRI;
    node_t base_before_folding = base;
    bool fold_base_into_displacement = false;
    int64_t fold_value = 0;
    if (this->valid(base) && (this->valid(index) || displacement != 0)) {
      if (CanBeImmediate(base) && this->valid(index) &&
          ValueFitsIntoImmediate(displacement)) {
        fold_value = GetImmediateIntegerValue(base);
        if (displacement_mode == kNegativeDisplacement) {
          fold_value -= displacement;
        } else {
          fold_value += displacement;
        }
        if (V8_UNLIKELY(fold_value == 0)) {
          base = node_t{};
          displacement = 0;
        } else if (ValueFitsIntoImmediate(fold_value)) {
          base = node_t{};
          fold_base_into_displacement = true;
        }
      } else if (IsZeroIntConstant(base)) {
        base = node_t{};
      }
    }
    if (this->valid(base)) {
      inputs[(*input_count)++] = UseRegister(base, reg_kind);
      if (this->valid(index)) {
        DCHECK(scale_exponent >= 0 && scale_exponent <= 3);
        inputs[(*input_count)++] = UseRegister(this->value(index), reg_kind);
        if (displacement != 0) {
          inputs[(*input_count)++] = UseImmediate64(
              displacement_mode == kNegativeDisplacement ? -displacement
                                                         : displacement);
          static const AddressingMode kMRnI_modes[] = {kMode_MR1I, kMode_MR2I,
                                                       kMode_MR4I, kMode_MR8I};
          mode = kMRnI_modes[scale_exponent];
        } else {
          static const AddressingMode kMRn_modes[] = {kMode_MR1, kMode_MR2,
                                                      kMode_MR4, kMode_MR8};
          mode = kMRn_modes[scale_exponent];
        }
      } else {
        if (displacement == 0) {
          mode = kMode_MR;
        } else {
          inputs[(*input_count)++] = UseImmediate64(
              displacement_mode == kNegativeDisplacement ? -displacement
                                                         : displacement);
          mode = kMode_MRI;
        }
      }
    } else {
      DCHECK(scale_exponent >= 0 && scale_exponent <= 3);
      if (fold_base_into_displacement) {
        DCHECK(!this->valid(base));
        DCHECK(this->valid(index));
        inputs[(*input_count)++] = UseRegister(this->value(index), reg_kind);
        inputs[(*input_count)++] = UseImmediate(static_cast<int>(fold_value));
        static const AddressingMode kMnI_modes[] = {kMode_MRI, kMode_M2I,
                                                    kMode_M4I, kMode_M8I};
        mode = kMnI_modes[scale_exponent];
      } else if (displacement != 0) {
        if (!this->valid(index)) {
          // This seems to only occur in (0 + k) cases, but we don't have an
          // addressing mode for a simple constant, so we use the base in a
          // register for kMode_MRI.
          CHECK(IsZeroIntConstant(base_before_folding));
          inputs[(*input_count)++] = UseRegister(base_before_folding, reg_kind);
          inputs[(*input_count)++] = UseImmediate64(
              displacement_mode == kNegativeDisplacement ? -displacement
                                                         : displacement);
          mode = kMode_MRI;
        } else {
          inputs[(*input_count)++] = UseRegister(this->value(index), reg_kind);
          inputs[(*input_count)++] = UseImmediate64(
              displacement_mode == kNegativeDisplacement ? -displacement
                                                         : displacement);
          static const AddressingMode kMnI_modes[] = {kMode_MRI, kMode_M2I,
                                                      kMode_M4I, kMode_M8I};
          mode = kMnI_modes[scale_exponent];
        }
      } else {
        DCHECK(this->valid(index));
        inputs[(*input_count)++] = UseRegister(this->value(index), reg_kind);
        static const AddressingMode kMn_modes[] = {kMode_MR, kMode_MR1,
                                                   kMode_M4, kMode_M8};
        mode = kMn_modes[scale_exponent];
        if (mode == kMode_MR1) {
          // [%r1 + %r1*1] has a smaller encoding than [%r1*2+0]
          inputs[(*input_count)++] = UseRegister(this->value(index), reg_kind);
        }
      }
    }
    return mode;
  }

  AddressingMode GenerateMemoryOperandInputs(
      Node* index, int scale_exponent, Node* base, Node* displacement,
      DisplacementMode displacement_mode, InstructionOperand inputs[],
      size_t* input_count,
      RegisterUseKind reg_kind = RegisterUseKind::kUseRegister) {
    if constexpr (Adapter::IsTurboshaft) {
      // Turboshaft is not using this overload.
      UNREACHABLE();
    } else {
      int64_t displacement_value;
      if (displacement == nullptr) {
        displacement_value = 0;
      } else if (displacement->opcode() == IrOpcode::kInt32Constant) {
        displacement_value = OpParameter<int32_t>(displacement->op());
      } else if (displacement->opcode() == IrOpcode::kInt64Constant) {
        displacement_value = OpParameter<int64_t>(displacement->op());
      } else {
        UNREACHABLE();
      }
      return GenerateMemoryOperandInputs(index, scale_exponent, base,
                                         displacement_value, displacement_mode,
                                         inputs, input_count, reg_kind);
    }
  }

  AddressingMode GetEffectiveAddressMemoryOperand(
      node_t operand, InstructionOperand inputs[], size_t* input_count,
      RegisterUseKind reg_kind = RegisterUseKind::kUseRegister);

  InstructionOperand GetEffectiveIndexOperand(node_t index,
                                              AddressingMode* mode) {
    if (CanBeImmediate(index)) {
      *mode = kMode_MRI;
      return UseImmediate(index);
    } else {
      *mode = kMode_MR1;
      return UseUniqueRegister(index);
    }
  }

  bool CanBeBetterLeftOperand(node_t node) const {
    return !selector()->IsReallyLive(node);
  }
};

namespace {

struct LoadStoreView {
  explicit LoadStoreView(const turboshaft::Operation& op) {
    DCHECK(op.Is<turboshaft::LoadOp>() || op.Is<turboshaft::StoreOp>());
    if (const turboshaft::LoadOp* load = op.TryCast<turboshaft::LoadOp>()) {
      base = load->base();
      index = load->index();
      offset = load->offset;
    } else {
      DCHECK(op.Is<turboshaft::StoreOp>());
      const turboshaft::StoreOp& store = op.Cast<turboshaft::StoreOp>();
      base = store.base();
      index = store.index();
      offset = store.offset;
    }
  }
  turboshaft::OpIndex base;
  turboshaft::OptionalOpIndex index;
  int32_t offset;
};

}  // namespace

template <>
AddressingMode
X64OperandGeneratorT<TurboshaftAdapter>::GetEffectiveAddressMemoryOperand(
    turboshaft::OpIndex operand, InstructionOperand inputs[],
    size_t* input_count, RegisterUseKind reg_kind) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  const Operation& op = Get(operand);
  if (op.Is<LoadOp>() || op.Is<StoreOp>()) {
    LoadStoreView load_or_store(op);
    if (ExternalReference reference;
        MatchExternalConstant(load_or_store.base, &reference) &&
        !load_or_store.index.valid()) {
      if (selector()->CanAddressRelativeToRootsRegister(reference)) {
        const ptrdiff_t delta =
            load_or_store.offset +
            MacroAssemblerBase::RootRegisterOffsetForExternalReference(
                selector()->isolate(), reference);
        if (is_int32(delta)) {
          inputs[(*input_count)++] = TempImmediate(static_cast<int32_t>(delta));
          return kMode_Root;
        }
      }
    }
  }

  auto m = TryMatchBaseWithScaledIndexAndDisplacement64(selector(), operand);
  DCHECK(m.has_value());
  if (IsCompressed(selector(), m->base)) {
    DCHECK(!m->index.valid());
    DCHECK(m->displacement == 0 || ValueFitsIntoImmediate(m->displacement));
    AddressingMode mode = kMode_MCR;
    inputs[(*input_count)++] = UseRegister(m->base, reg_kind);
    if (m->displacement != 0) {
      inputs[(*input_count)++] =
          m->displacement_mode == kNegativeDisplacement
              ? UseImmediate(static_cast<int>(-m->displacement))
              : UseImmediate(static_cast<int>(m->displacement));
      mode = kMode_MCRI;
    }
    return mode;
  }
  if (TurboshaftAdapter::valid(m->base) &&
      this->Get(m->base).Is<turboshaft::LoadRootRegisterOp>()) {
    DCHECK(!this->valid(m->index));
    DCHECK_EQ(m->scale, 0);
    DCHECK(ValueFitsIntoImmediate(m->displacement));
    inputs[(*input_count)++] = UseImmediate(static_cast<int>(m->displacement));
    return kMode_Root;
  } else if (ValueFitsIntoImmediate(m->displacement)) {
    return GenerateMemoryOperandInputs(m->index, m->scale, m->base,
                                       m->displacement, m->displacement_mode,
                                       inputs, input_count, reg_kind);
  } else if (!TurboshaftAdapter::valid(m->base) &&
             m->displacement_mode == kPositiveDisplacement) {
    // The displacement cannot be an immediate, but we can use the
    // displacement as base instead and still benefit from addressing
    // modes for the scale.
    UNIMPLEMENTED();
  } else {
    // TODO(nicohartmann@): Turn this into a `DCHECK` once we have some
    // coverage.
    CHECK_EQ(m->displacement, 0);
    inputs[(*input_count)++] = UseRegister(m->base, reg_kind);
    inputs[(*input_count)++] = UseRegister(m->index, reg_kind);
    return kMode_MR1;
  }
}

template <>
AddressingMode
X64OperandGeneratorT<TurbofanAdapter>::GetEffectiveAddressMemoryOperand(
    node_t operand, InstructionOperand inputs[], size_t* input_count,
    RegisterUseKind reg_kind) {
  {
    LoadMatcher<ExternalReferenceMatcher> m(operand);
    if (m.index().HasResolvedValue() && m.object().HasResolvedValue() &&
        selector()->CanAddressRelativeToRootsRegister(
            m.object().ResolvedValue())) {
      ptrdiff_t const delta =
          m.index().ResolvedValue() +
          MacroAssemblerBase::RootRegisterOffsetForExternalReference(
              selector()->isolate(), m.object().ResolvedValue());
      if (is_int32(delta)) {
        inputs[(*input_count)++] = TempImmediate(static_cast<int32_t>(delta));
        return kMode_Root;
      }
    }
  }
  BaseWithIndexAndDisplacement64Matcher m(operand, AddressOption::kAllowAll);
  DCHECK(m.matches());
  // Decompress pointer by complex addressing mode.
  if (IsCompressed(m.base())) {
    DCHECK(m.index() == nullptr);
    DCHECK(m.displacement() == nullptr || CanBeImmediate(m.displacement()));
    AddressingMode mode = kMode_MCR;
    inputs[(*input_count)++] = UseRegister(m.base(), reg_kind);
    if (m.displacement() != nullptr) {
      inputs[(*input_count)++] = m.displacement_mode() == kNegativeDisplacement
                                     ? UseNegatedImmediate(m.displacement())
                                     : UseImmediate(m.displacement());
      mode = kMode_MCRI;
    }
    return mode;
  }
  if (m.base() != nullptr &&
      m.base()->opcode() == IrOpcode::kLoadRootRegister) {
    DCHECK_EQ(m.index(), nullptr);
    DCHECK_EQ(m.scale(), 0);
    inputs[(*input_count)++] = UseImmediate(m.displacement());
    return kMode_Root;
  } else if (m.displacement() == nullptr || CanBeImmediate(m.displacement())) {
    return GenerateMemoryOperandInputs(m.index(), m.scale(), m.base(),
                                       m.displacement(), m.displacement_mode(),
                                       inputs, input_count, reg_kind);
  } else if (m.base() == nullptr &&
             m.displacement_mode() == kPositiveDisplacement) {
    // The displacement cannot be an immediate, but we can use the
    // displacement as base instead and still benefit from addressing
    // modes for the scale.
    return GenerateMemoryOperandInputs(m.index(), m.scale(), m.displacement(),
                                       nullptr, m.displacement_mode(), inputs,
                                       input_count, reg_kind);
  } else {
    inputs[(*input_count)++] = UseRegister(operand->InputAt(0), reg_kind);
    inputs[(*input_count)++] = UseRegister(operand->InputAt(1), reg_kind);
    return kMode_MR1;
  }
}

namespace {

ArchOpcode GetLoadOpcode(turboshaft::MemoryRepresentation loaded_rep,
                         turboshaft::RegisterRepresentation result_rep) {
  // NOTE: The meaning of `loaded_rep` = `MemoryRepresentation::AnyTagged()` is
  // we are loading a compressed tagged field, while `result_rep` =
  // `RegisterRepresentation::Tagged()` refers to an uncompressed tagged value.
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (loaded_rep) {
    case MemoryRepresentation::Int8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movsxbl;
    case MemoryRepresentation::Uint8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movzxbl;
    case MemoryRepresentation::Int16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movsxwl;
    case MemoryRepresentation::Uint16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movzxwl;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kX64Movl;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word64());
      return kX64Movq;
    case MemoryRepresentation::Float16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return kX64Movsh;
    case MemoryRepresentation::Float32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return kX64Movss;
    case MemoryRepresentation::Float64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float64());
      return kX64Movsd;
#ifdef V8_COMPRESS_POINTERS
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kX64Movl;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kX64MovqDecompressTagged;
    case MemoryRepresentation::TaggedSigned():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kX64Movl;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kX64MovqDecompressTaggedSigned;
#else
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kX64Movq;
#endif
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kX64Movq;
    case MemoryRepresentation::ProtectedPointer():
      CHECK(V8_ENABLE_SANDBOX_BOOL);
      return kX64MovqDecompressProtected;
    case MemoryRepresentation::IndirectPointer():
      UNREACHABLE();
    case MemoryRepresentation::SandboxedPointer():
      return kX64MovqDecodeSandboxedPointer;
    case MemoryRepresentation::Simd128():
      DCHECK_EQ(result_rep, RegisterRepresentation::Simd128());
      return kX64Movdqu;
    case MemoryRepresentation::Simd256():
      DCHECK_EQ(result_rep, RegisterRepresentation::Simd256());
      return kX64Movdqu256;
  }
}

ArchOpcode GetLoadOpcode(LoadRepresentation load_rep) {
  ArchOpcode opcode;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat16:
      opcode = kX64Movsh;
      break;
    case MachineRepresentation::kFloat32:
      opcode = kX64Movss;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kX64Movsd;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsSigned() ? kX64Movsxbl : kX64Movzxbl;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsSigned() ? kX64Movsxwl : kX64Movzxwl;
      break;
    case MachineRepresentation::kWord32:
      opcode = kX64Movl;
      break;
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      opcode = kX64Movl;
      break;
#else
      UNREACHABLE();
#endif
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      opcode = kX64MovqDecompressTaggedSigned;
      break;
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      opcode = kX64MovqDecompressTagged;
      break;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
#endif
    case MachineRepresentation::kWord64:
      opcode = kX64Movq;
      break;
    case MachineRepresentation::kProtectedPointer:
      CHECK(V8_ENABLE_SANDBOX_BOOL);
      opcode = kX64MovqDecompressProtected;
      break;
    case MachineRepresentation::kSandboxedPointer:
      opcode = kX64MovqDecodeSandboxedPointer;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kX64Movdqu;
      break;
    case MachineRepresentation::kSimd256:  // Fall through.
      opcode = kX64Movdqu256;
      break;
    case MachineRepresentation::kNone:     // Fall through.
    case MachineRepresentation::kMapWord:  // Fall through.
    case MachineRepresentation::kIndirectPointer:  // Fall through.
      UNREACHABLE();
  }
  return opcode;
}

ArchOpcode GetStoreOpcode(turboshaft::MemoryRepresentation stored_rep) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (stored_rep) {
    case MemoryRepresentation::Int8():
    case MemoryRepresentation::Uint8():
      return kX64Movb;
    case MemoryRepresentation::Int16():
    case MemoryRepresentation::Uint16():
      return kX64Movw;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      return kX64Movl;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      return kX64Movq;
    case MemoryRepresentation::Float16():
      return kX64Movsh;
    case MemoryRepresentation::Float32():
      return kX64Movss;
    case MemoryRepresentation::Float64():
      return kX64Movsd;
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      return kX64MovqCompressTagged;
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      return kX64Movq;
    case MemoryRepresentation::ProtectedPointer():
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
    case MemoryRepresentation::IndirectPointer():
      return kX64MovqStoreIndirectPointer;
    case MemoryRepresentation::SandboxedPointer():
      return kX64MovqEncodeSandboxedPointer;
    case MemoryRepresentation::Simd128():
      return kX64Movdqu;
    case MemoryRepresentation::Simd256():
      return kX64Movdqu256;
  }
}

ArchOpcode GetStoreOpcode(StoreRepresentation store_rep) {
  switch (store_rep.representation()) {
    case MachineRepresentation::kFloat16:
      return kX64Movsh;
    case MachineRepresentation::kFloat32:
      return kX64Movss;
    case MachineRepresentation::kFloat64:
      return kX64Movsd;
    case MachineRepresentation::kBit:
    case MachineRepresentation::kWord8:
      return kX64Movb;
    case MachineRepresentation::kWord16:
      return kX64Movw;
    case MachineRepresentation::kWord32:
      return kX64Movl;
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      return kX64MovqCompressTagged;
#else
      UNREACHABLE();
#endif
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      return kX64MovqCompressTagged;
    case MachineRepresentation::kWord64:
      return kX64Movq;
    case MachineRepresentation::kIndirectPointer:
      return kX64MovqStoreIndirectPointer;
    case MachineRepresentation::kSandboxedPointer:
      return kX64MovqEncodeSandboxedPointer;
    case MachineRepresentation::kSimd128:
      return kX64Movdqu;
    case MachineRepresentation::kSimd256:
      return kX64Movdqu256;
    case MachineRepresentation::kNone:
    case MachineRepresentation::kMapWord:
    case MachineRepresentation::kProtectedPointer:
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
  }
}

ArchOpcode GetSeqCstStoreOpcode(StoreRepresentation store_rep) {
  switch (store_rep.representation()) {
    case MachineRepresentation::kWord8:
      return kAtomicStoreWord8;
    case MachineRepresentation::kWord16:
      return kAtomicStoreWord16;
    case MachineRepresentation::kWord32:
      return kAtomicStoreWord32;
    case MachineRepresentation::kWord64:
      return kX64Word64AtomicStoreWord64;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
      if (COMPRESS_POINTERS_BOOL) return kAtomicStoreWord32;
      return kX64Word64AtomicStoreWord64;
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
      CHECK(COMPRESS_POINTERS_BOOL);
      return kAtomicStoreWord32;
    default:
      UNREACHABLE();
  }
}

// Used for pmin/pmax and relaxed min/max.
template <typename Adapter, VectorLength vec_len>
void VisitMinOrMax(InstructionSelectorT<Adapter>* selector,
                   typename Adapter::node_t node, ArchOpcode opcode,
                   bool flip_inputs) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  InstructionOperand dst = selector->IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  InstructionCode instr_code = opcode | VectorLengthField::encode(vec_len);
  if (flip_inputs) {
    // Due to the way minps/minpd work, we want the dst to be same as the second
    // input: b = pmin(a, b) directly maps to minps b a.
    selector->Emit(instr_code, dst, g.UseRegister(selector->input_at(node, 1)),
                   g.UseRegister(selector->input_at(node, 0)));
  } else {
    selector->Emit(instr_code, dst, g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 1)));
  }
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTraceInstruction(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // Currently not used by Turboshaft.
    UNIMPLEMENTED();
  } else {
    X64OperandGeneratorT<Adapter> g(this);
    uint32_t markid = OpParameter<uint32_t>(node->op());
    Emit(kX64TraceInstruction, g.Use(node), g.UseImmediate(markid));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackSlot(node_t node) {
  StackSlotRepresentation rep = this->stack_slot_representation_of(node);
  int slot =
      frame_->AllocateSpillSlot(rep.size(), rep.alignment(), rep.is_tagged());
  OperandGenerator g(this);

  Emit(kArchStackSlot, g.DefineAsRegister(node),
       sequence()->AddImmediate(Constant(slot)), 0, nullptr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitAbortCSADcheck(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kArchAbortCSADcheck, g.NoOutput(),
       g.UseFixed(this->input_at(node, 0), rdx));
}

#ifdef V8_ENABLE_WEBASSEMBLY
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& load = this->Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kArchNop;
  switch (load.lane_kind) {
    case Simd128LaneMemoryOp::LaneKind::k8:
      opcode = kX64Pinsrb;
      break;
    case Simd128LaneMemoryOp::LaneKind::k16:
      opcode = kX64Pinsrw;
      break;
    case Simd128LaneMemoryOp::LaneKind::k32:
      opcode = kX64Pinsrd;
      break;
    case Simd128LaneMemoryOp::LaneKind::k64:
      opcode = kX64Pinsrq;
      break;
  }

  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  // Input 0 is value node, 1 is lane idx, and GetEffectiveAddressMemoryOperand
  // uses up to 3 inputs. This ordering is consistent with other operations that
  // use the same opcode.
  InstructionOperand inputs[5];
  size_t input_count = 0;

  inputs[input_count++] = g.UseRegister(load.value());
  inputs[input_count++] = g.UseImmediate(load.lane);

  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(mode);

  DCHECK_GE(5, input_count);

  // x64 supports unaligned loads.
  DCHECK(!load.kind.maybe_unaligned);
  if (load.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  Emit(opcode, 1, outputs, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  InstructionCode opcode = kArchNop;
  if (params.rep == MachineType::Int8()) {
    opcode = kX64Pinsrb;
  } else if (params.rep == MachineType::Int16()) {
    opcode = kX64Pinsrw;
  } else if (params.rep == MachineType::Int32()) {
    opcode = kX64Pinsrd;
  } else if (params.rep == MachineType::Int64()) {
    opcode = kX64Pinsrq;
  } else {
    UNREACHABLE();
  }

  X64OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  // Input 0 is value node, 1 is lane idx, and GetEffectiveAddressMemoryOperand
  // uses up to 3 inputs. This ordering is consistent with other operations that
  // use the same opcode.
  InstructionOperand inputs[5];
  size_t input_count = 0;

  inputs[input_count++] = g.UseRegister(node->InputAt(2));
  inputs[input_count++] = g.UseImmediate(params.laneidx);

  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(mode);

  DCHECK_GE(5, input_count);

  // x64 supports unaligned loads.
  DCHECK_NE(params.kind, MemoryAccessKind::kUnaligned);
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  Emit(opcode, 1, outputs, input_count, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LoadTransformOp& op =
      this->Get(node).Cast<Simd128LoadTransformOp>();
  ArchOpcode opcode;
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8x8S:
      opcode = kX64S128Load8x8S;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8U:
      opcode = kX64S128Load8x8U;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4S:
      opcode = kX64S128Load16x4S;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4U:
      opcode = kX64S128Load16x4U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2S:
      opcode = kX64S128Load32x2S;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      opcode = kX64S128Load32x2U;
      break;
    case Simd128LoadTransformOp::TransformKind::k8Splat:
      opcode = kX64S128Load8Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k16Splat:
      opcode = kX64S128Load16Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Splat:
      opcode = kX64S128Load32Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      opcode = kX64S128Load64Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Zero:
      opcode = kX64Movss;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Zero:
      opcode = kX64Movsd;
      break;
  }

  // x64 supports unaligned loads
  DCHECK(!op.load_kind.maybe_unaligned);
  InstructionCode code = opcode;
  if (op.load_kind.with_trap_handler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  VisitLoad(node, node, code);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());
  ArchOpcode opcode;
  switch (params.transformation) {
    case LoadTransformation::kS128Load8Splat:
      opcode = kX64S128Load8Splat;
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kX64S128Load16Splat;
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kX64S128Load32Splat;
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kX64S128Load64Splat;
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kX64S128Load8x8S;
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kX64S128Load8x8U;
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kX64S128Load16x4S;
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kX64S128Load16x4U;
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kX64S128Load32x2S;
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kX64S128Load32x2U;
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kX64Movss;
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kX64Movsd;
      break;
    // Simd256
    case LoadTransformation::kS256Load8Splat:
      opcode = kX64S256Load8Splat;
      break;
    case LoadTransformation::kS256Load16Splat:
      opcode = kX64S256Load16Splat;
      break;
    case LoadTransformation::kS256Load32Splat:
      opcode = kX64S256Load32Splat;
      break;
    case LoadTransformation::kS256Load64Splat:
      opcode = kX64S256Load64Splat;
      break;
    case LoadTransformation::kS256Load8x16S:
      opcode = kX64S256Load8x16S;
      break;
    case LoadTransformation::kS256Load8x16U:
      opcode = kX64S256Load8x16U;
      break;
    case LoadTransformation::kS256Load16x8S:
      opcode = kX64S256Load16x8S;
      break;
    case LoadTransformation::kS256Load16x8U:
      opcode = kX64S256Load16x8U;
      break;
    case LoadTransformation::kS256Load32x4S:
      opcode = kX64S256Load32x4S;
      break;
    case LoadTransformation::kS256Load32x4U:
      opcode = kX64S256Load32x4U;
      break;
    default:
      UNREACHABLE();
  }
  // x64 supports unaligned loads
  DCHECK_NE(params.kind, MemoryAccessKind::kUnaligned);
  InstructionCode code = opcode;
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  VisitLoad(node, node, code);
}

#if V8_ENABLE_WASM_SIMD256_REVEC
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS256Const(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  static const int kUint32Immediates = kSimd256Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd256ConstantOp& constant =
        this->Get(node).template Cast<turboshaft::Simd256ConstantOp>();
    memcpy(val, constant.value, kSimd256Size);
  } else {
    memcpy(val, S256ImmediateParameterOf(node->op()).data(), kSimd256Size);
  }
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = std::all_of(std::begin(val), std::end(val),
                               [](uint32_t v) { return v == 0; });
  // It's should not happen for Turboshaft, IsZero is checked earlier in
  // instruction selector
  DCHECK_IMPLIES(Adapter::IsTurboshaft, !all_zeros);
  bool all_ones = std::all_of(std::begin(val), std::end(val),
                              [](uint32_t v) { return v == UINT32_MAX; });
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kX64SZero | VectorLengthField::encode(kV256), dst);
  } else if (all_ones) {
    Emit(kX64SAllOnes | VectorLengthField::encode(kV256), dst);
  } else {
    Emit(kX64S256Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]), g.UseImmediate(val[4]),
         g.UseImmediate(val[5]), g.UseImmediate(val[6]),
         g.UseImmediate(val[7]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS256Zero(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  Emit(kX64SZero | VectorLengthField::encode(kV256), g.DefineAsRegister(node));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimd256LoadTransform(
    Node* node) {
  // For Turbofan, VisitLoadTransform should be called instead.
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimd256LoadTransform(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd256LoadTransformOp& op =
      this->Get(node).Cast<Simd256LoadTransformOp>();
  ArchOpcode opcode;
  switch (op.transform_kind) {
    case Simd256LoadTransformOp::TransformKind::k8x16S:
      opcode = kX64S256Load8x16S;
      break;
    case Simd256LoadTransformOp::TransformKind::k8x16U:
      opcode = kX64S256Load8x16U;
      break;
    case Simd256LoadTransformOp::TransformKind::k8x8U:
      opcode = kX64S256Load8x8U;
      break;
    case Simd256LoadTransformOp::TransformKind::k16x8S:
      opcode = kX64S256Load16x8S;
      break;
    case Simd256LoadTransformOp::TransformKind::k16x8U:
      opcode = kX64S256Load16x8U;
      break;
    case Simd256LoadTransformOp::TransformKind::k32x4S:
      opcode = kX64S256Load32x4S;
      break;
    case Simd256LoadTransformOp::TransformKind::k32x4U:
      opcode = kX64S256Load32x4U;
      break;
    case Simd256LoadTransformOp::TransformKind::k8Splat:
      opcode = kX64S256Load8Splat;
      break;
    case Simd256LoadTransformOp::TransformKind::k16Splat:
      opcode = kX64S256Load16Splat;
      break;
    case Simd256LoadTransformOp::TransformKind::k32Splat:
      opcode = kX64S256Load32Splat;
      break;
    case Simd256LoadTransformOp::TransformKind::k64Splat:
      opcode = kX64S256Load64Splat;
      break;
  }

  // x64 supports unaligned loads
  DCHECK(!op.load_kind.maybe_unaligned);
  InstructionCode code = opcode;
  if (op.load_kind.with_trap_handler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  VisitLoad(node, node, code);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF32x8RelaxedMin(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF32x8RelaxedMax(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF64x4RelaxedMin(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitF64x4RelaxedMax(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF32x8RelaxedMin(
    node_t node) {
  VisitMinOrMax<TurboshaftAdapter, kV256>(this, node, kX64Minps, false);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF32x8RelaxedMax(
    node_t node) {
  VisitMinOrMax<TurboshaftAdapter, kV256>(this, node, kX64Maxps, false);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF64x4RelaxedMin(
    node_t node) {
  VisitMinOrMax<TurboshaftAdapter, kV256>(this, node, kX64Minpd, false);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitF64x4RelaxedMax(
    node_t node) {
  VisitMinOrMax<TurboshaftAdapter, kV256>(this, node, kX64Maxpd, false);
}

#ifdef V8_TARGET_ARCH_X64
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimd256Shufd(Node* node) {
  UNIMPLEMENTED();
}
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimd256Shufps(Node* node) {
  UNIMPLEMENTED();
}
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimd256Unpack(Node* node) {
  UNIMPLEMENTED();
}
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitSimdPack128To256(Node* node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimd256Shufd(node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const turboshaft::Simd256ShufdOp& shufd =
      Get(node).Cast<turboshaft::Simd256ShufdOp>();
  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionOperand src = g.UseUniqueRegister(shufd.input());
  InstructionOperand imm = g.UseImmediate(shufd.control);
  InstructionOperand inputs[] = {src, imm};
  Emit(kX64Vpshufd, 1, &dst, 2, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimd256Shufps(node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const turboshaft::Simd256ShufpsOp& shufps =
      Get(node).Cast<turboshaft::Simd256ShufpsOp>();
  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionOperand src1 = g.UseUniqueRegister(shufps.left());
  InstructionOperand src2 = g.UseUniqueRegister(shufps.right());
  InstructionOperand imm = g.UseImmediate(shufps.control);
  InstructionOperand inputs[] = {src1, src2, imm};
  Emit(kX64Shufps, 1, &dst, 3, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimd256Unpack(node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const turboshaft::Simd256UnpackOp& unpack =
      Get(node).Cast<turboshaft::Simd256UnpackOp>();
  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionOperand src1 = g.UseUniqueRegister(unpack.left());
  InstructionOperand src2 = g.UseUniqueRegister(unpack.right());
  InstructionOperand inputs[] = {src1, src2};
  ArchOpcode code;
  switch (unpack.kind) {
    case turboshaft::Simd256UnpackOp::Kind::k32x8High:
      code = kX64S32x8UnpackHigh;
      break;
    case turboshaft::Simd256UnpackOp::Kind::k32x8Low:
      code = kX64S32x8UnpackLow;
      break;
    default:
      UNIMPLEMENTED();
  }
  Emit(code, 1, &dst, 2, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitSimdPack128To256(
    node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);

  const turboshaft::SimdPack128To256Op& op =
      Get(node).Cast<turboshaft::SimdPack128To256Op>();

  turboshaft::OpIndex input0 = op.input(0);
  turboshaft::OpIndex input1 = op.input(1);
  constexpr int kHighLaneIndex = 1;

  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionOperand src0 = g.UseUniqueRegister(input0);
  InstructionOperand src1 = g.UseUniqueRegister(input1);
  InstructionOperand imm = g.UseImmediate(kHighLaneIndex);

  InstructionOperand inputs[] = {src0, src1, imm};

  Emit(kX6
```