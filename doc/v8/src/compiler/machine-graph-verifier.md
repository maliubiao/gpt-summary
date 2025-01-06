Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The primary goal is to understand what the C++ code does and how it relates to JavaScript. This means identifying its core functionality within the V8 compiler and then demonstrating a connection (if one exists) to JavaScript's behavior.

2. **Initial Skim and Keywords:**  First, I'd quickly skim the code, looking for prominent keywords and class names. Things that jump out are:
    * `MachineGraphVerifier` (the main class)
    * `MachineRepresentation` (appears frequently)
    * `Schedule`, `Graph`, `Linkage`, `Node` (compiler-related concepts)
    * `IrOpcode` (Intermediate Representation Opcodes)
    * `Check` (indicating verification logic)
    * `Call`, `Return`, `Parameter` (function/code structure)
    * Data types like `Word32`, `Word64`, `Float32`, `Float64`, `Tagged`

3. **Identify the Core Functionality:**  Based on the keywords and structure, it seems the code is involved in:
    * **Verifying** something related to a "machine graph."
    * Focusing on the **representation** of data within this graph.
    * Doing this within the context of the V8 compiler (due to the `v8::internal::compiler` namespace).

4. **Analyze `MachineRepresentationInferrer`:**  This class looks like it figures out the `MachineRepresentation` of each `Node` in the graph. It iterates through the blocks and nodes in the `Schedule`. The `switch` statement based on `IrOpcode` is key. It assigns representations based on the operation being performed (e.g., `kParameter` gets its representation from the linkage, `kLoad` gets its representation from the load operator, etc.).

5. **Analyze `MachineRepresentationChecker`:** This class appears to use the information from the `Inferrer` to **check** if the representations are consistent and valid. It also iterates through the graph. The `CHECK_EQ` and custom `CheckValueInput...` methods suggest it's enforcing rules about how data is used in different operations. For example, it checks if the inputs to an `Add` operation are both `Word32`.

6. **Connect to Compiler Principles:**  At this point, I'd connect this to general compiler knowledge. Compilers need to understand the types and sizes of data to generate correct machine code. "Machine Representation" likely refers to how data is stored and manipulated at the machine level (e.g., as a 32-bit integer, a 64-bit float, a pointer).

7. **Infer the Purpose of Verification:**  The verification step likely helps catch errors early in the compilation process. If the compiler tries to perform an operation on data with an incompatible representation, this verifier will flag it. This prevents the generation of incorrect or potentially crashing machine code.

8. **Identify the Link to JavaScript (the Tricky Part):** The prompt specifically asks about the connection to JavaScript. This requires understanding *why* V8 needs this kind of verification.

    * **JavaScript's Dynamic Nature:** JavaScript is dynamically typed. Variables don't have fixed types declared upfront. V8's compiler (Turbofan) performs optimizations based on *inferred* types.
    * **Internal Representations:** Even though JavaScript is dynamic, V8 internally needs to represent values in a way that the machine understands. This is where `MachineRepresentation` comes in. A JavaScript number might be represented internally as a 64-bit float, a 32-bit integer, or even a "tagged" value that indicates its type.
    * **The Connection:** The `MachineGraphVerifier` ensures that the compiler's internal understanding of the data's representation is consistent as it builds the optimized machine code. This is crucial for correctly handling JavaScript's dynamic types. If the compiler *thinks* a value is an integer but it's actually a float, operations will fail.

9. **Construct the JavaScript Example:** The example needs to demonstrate how JavaScript's dynamic nature leads to V8 having different internal representations.

    * **Simple Operations:** Start with basic arithmetic.
    * **Type Changes:** Show how the *same* JavaScript variable can have different internal representations. The example of `x = 10; x = 10.5;` is perfect because `10` can be an integer representation, while `10.5` requires a floating-point representation.
    * **The Role of the Verifier (Conceptual):** Explain that the verifier ensures V8 handles these transitions correctly. It makes sure that when `x` changes from an integer to a float, subsequent machine code operations are appropriate for a float.

10. **Refine the Summary:**  Based on the analysis, construct a concise summary that highlights:
    * The core function: verifying the machine graph.
    * The key concept: `MachineRepresentation`.
    * The purpose: ensuring consistency and correctness during compilation.
    * The link to JavaScript: handling dynamic types and ensuring correct machine code generation.

11. **Review and Iterate:**  Finally, review the summary and example for clarity, accuracy, and completeness. Make sure the language is accessible and explains the connection to JavaScript effectively. For instance, initially, I might have focused too much on the low-level details of the C++ code. The key is to bridge the gap to the higher-level concept of JavaScript's dynamic typing.
这个C++源代码文件 `machine-graph-verifier.cc` 的主要功能是**在 V8 编译器的机器图（Machine Graph）构建完成后，对其进行验证，以确保图的结构和数据类型的一致性**。更具体地说，它检查机器图中每个节点（操作）的输入和输出的机器表示（Machine Representation）是否符合预期，从而尽早发现编译过程中的错误。

**核心功能归纳:**

1. **机器表示推断 (Machine Representation Inference):**
   - `MachineRepresentationInferrer` 类负责遍历机器图，并根据每个节点的操作码（`IrOpcode`）和上下文信息，推断出该节点代表的值的机器表示。
   - 机器表示描述了数据在底层机器级别的存储和处理方式，例如：`kWord32` (32位整数), `kWord64` (64位整数), `kFloat64` (64位浮点数), `kTagged` (V8的标记指针，可以指向各种JavaScript对象) 等。
   - 推断过程会考虑参数类型、返回值类型、加载/存储操作的表示、Phi节点的表示等。

2. **机器表示检查 (Machine Representation Checking):**
   - `MachineRepresentationChecker` 类利用 `MachineRepresentationInferrer` 推断出的信息，再次遍历机器图，并检查每个节点的操作是否使用了与其输入和输出的预期机器表示相符的值。
   - 例如，如果一个加法操作（例如 `kWord32Add`）的输入被推断为 `kFloat64`，则会触发一个错误，因为整数加法操作不应该接受浮点数作为输入。
   - 检查过程涵盖了各种操作码，包括算术运算、位运算、比较运算、加载/存储操作、函数调用等。
   - 针对不同的操作码，会进行特定的检查，例如：
     - `kCall`: 检查调用输入的类型是否与调用描述符 (Call Descriptor) 中定义的参数类型匹配。
     - `kLoad`: 检查加载地址是否为指针类型，加载结果的类型是否与加载表示一致。
     - `kStore`: 检查存储地址是否为指针类型，存储的值的类型是否与存储表示一致。
     - `kPhi`: 检查 Phi 节点的所有输入是否具有相同的机器表示。

3. **错误报告:**
   - 如果在检查过程中发现不一致的情况，`MachineRepresentationChecker` 会生成详细的错误信息，包括出错的节点 ID、操作码、以及类型不匹配的输入节点等。
   - 这些错误信息有助于 V8 开发人员调试编译器，确保生成的机器代码的正确性。

**与 JavaScript 的关系 (通过示例说明):**

虽然 `machine-graph-verifier.cc` 是一个纯粹的 C++ 文件，位于 V8 编译器的内部，但它的功能直接关系到 JavaScript 代码的执行效率和正确性。V8 使用 Turbofan 编译器将 JavaScript 代码编译成优化的机器码。在这个编译过程中，会构建机器图来表示程序的执行流程。`machine-graph-verifier.cc` 确保了这个机器图的正确性，这最终保证了生成的机器码能够正确地执行 JavaScript 代码。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10); // 整数相加
add(3.14, 2.71); // 浮点数相加
add(5, 2.5); // 整数和浮点数相加
```

**解释:**

1. **整数相加 (`add(5, 10)`)**: 当 V8 编译 `add(5, 10)` 时，Turbofan 可能会在机器图中生成 `kWord32Add` 操作，并且 `machine-graph-verifier.cc` 会验证该操作的输入是否都是 `kWord32` 表示的整数。

2. **浮点数相加 (`add(3.14, 2.71)`)**: 当 V8 编译 `add(3.14, 2.71)` 时，Turbofan 可能会生成 `kFloat64Add` 操作，`machine-graph-verifier.cc` 会验证输入是否都是 `kFloat64` 表示的浮点数。

3. **整数和浮点数相加 (`add(5, 2.5)`)**:  这种情况稍微复杂。JavaScript 是动态类型的，V8 在编译时可能需要进行类型转换。
   - Turbofan 可能会生成一些中间操作来将整数 `5` 转换为浮点数，然后再进行浮点数加法 (`kFloat64Add`)。
   - `machine-graph-verifier.cc` 会确保类型转换操作的输出类型与后续的浮点数加法操作的输入类型一致。例如，转换操作的输出应该是 `kFloat64`，以便 `kFloat64Add` 可以正确地处理。

**如果缺少 `machine-graph-verifier.cc` 或其功能失效，可能会导致以下问题:**

- **生成的机器码不正确:** 例如，可能会尝试用整数加法操作来处理浮点数，导致计算结果错误。
- **程序崩溃:** 在某些情况下，类型不匹配的机器操作可能会导致程序崩溃。
- **安全漏洞:** 错误的类型处理有时可能被利用来绕过安全检查。

总而言之，`machine-graph-verifier.cc` 在 V8 编译器的优化过程中扮演着至关重要的角色，它通过静态分析机器图的数据类型一致性，保证了最终生成的机器码能够正确且高效地执行 JavaScript 代码。它就像一个严格的“类型检查器”，在编译的底层机器表示层面工作，确保了 JavaScript 动态类型在底层实现中的一致性。

Prompt: 
```
这是目录为v8/src/compiler/machine-graph-verifier.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/machine-graph-verifier.h"

#include "src/compiler/common-operator.h"
#include "src/compiler/linkage.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/schedule.h"
#include "src/compiler/turbofan-graph.h"
#include "src/zone/zone.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {

class MachineRepresentationInferrer {
 public:
  MachineRepresentationInferrer(Schedule const* schedule, Graph const* graph,
                                Linkage* linkage, Zone* zone)
      : schedule_(schedule),
        linkage_(linkage),
        representation_vector_(graph->NodeCount(), MachineRepresentation::kNone,
                               zone) {
    Run();
  }

  CallDescriptor* call_descriptor() const {
    return linkage_->GetIncomingDescriptor();
  }

  MachineRepresentation GetRepresentation(Node const* node) const {
    return representation_vector_.at(node->id());
  }

 private:
  MachineRepresentation PromoteRepresentation(MachineRepresentation rep) {
    switch (rep) {
      case MachineRepresentation::kWord8:
      case MachineRepresentation::kWord16:
      case MachineRepresentation::kWord32:
        return MachineRepresentation::kWord32;
      case MachineRepresentation::kSandboxedPointer:
        // A sandboxed pointer is a Word64 that uses an encoded representation
        // when stored on the heap.
        return MachineRepresentation::kWord64;
      default:
        break;
    }
    return rep;
  }

  void Run() {
    auto blocks = schedule_->all_blocks();
    for (BasicBlock* block : *blocks) {
      current_block_ = block;
      for (size_t i = 0; i <= block->NodeCount(); ++i) {
        Node const* node =
            i < block->NodeCount() ? block->NodeAt(i) : block->control_input();
        if (node == nullptr) {
          DCHECK_EQ(block->NodeCount(), i);
          break;
        }
        switch (node->opcode()) {
          case IrOpcode::kParameter:
            representation_vector_[node->id()] =
                linkage_->GetParameterType(ParameterIndexOf(node->op()))
                    .representation();
            break;
          case IrOpcode::kReturn: {
            representation_vector_[node->id()] = PromoteRepresentation(
                linkage_->GetReturnType().representation());
            break;
          }
          case IrOpcode::kProjection: {
            representation_vector_[node->id()] =
                NodeProperties::GetProjectionType(node);
          } break;
          case IrOpcode::kTypedStateValues:
            representation_vector_[node->id()] = MachineRepresentation::kNone;
            break;
          case IrOpcode::kWord32AtomicLoad:
          case IrOpcode::kWord64AtomicLoad:
            representation_vector_[node->id()] =
                PromoteRepresentation(AtomicLoadParametersOf(node->op())
                                          .representation()
                                          .representation());
            break;
          case IrOpcode::kLoad:
          case IrOpcode::kLoadImmutable:
          case IrOpcode::kProtectedLoad:
          case IrOpcode::kLoadTrapOnNull:
            representation_vector_[node->id()] = PromoteRepresentation(
                LoadRepresentationOf(node->op()).representation());
            break;
          case IrOpcode::kLoadFramePointer:
          case IrOpcode::kLoadParentFramePointer:
          case IrOpcode::kStackSlot:
          case IrOpcode::kLoadRootRegister:
#if V8_ENABLE_WEBASSEMBLY
          case IrOpcode::kLoadStackPointer:
#endif  // V8_ENABLE_WEBASSEMBLY
            representation_vector_[node->id()] =
                MachineType::PointerRepresentation();
            break;
          case IrOpcode::kUnalignedLoad:
            representation_vector_[node->id()] = PromoteRepresentation(
                LoadRepresentationOf(node->op()).representation());
            break;
          case IrOpcode::kPhi:
            representation_vector_[node->id()] =
                PhiRepresentationOf(node->op());
            break;
          case IrOpcode::kCall: {
            auto call_descriptor = CallDescriptorOf(node->op());
            if (call_descriptor->ReturnCount() > 0) {
              representation_vector_[node->id()] =
                  call_descriptor->GetReturnType(0).representation();
            } else {
              representation_vector_[node->id()] =
                  MachineRepresentation::kTagged;
            }
            break;
          }
          case IrOpcode::kWord32AtomicStore:
          case IrOpcode::kWord64AtomicStore:
            representation_vector_[node->id()] = PromoteRepresentation(
                AtomicStoreParametersOf(node->op()).representation());
            break;
          case IrOpcode::kWord32AtomicPairLoad:
          case IrOpcode::kWord32AtomicPairStore:
          case IrOpcode::kWord32AtomicPairAdd:
          case IrOpcode::kWord32AtomicPairSub:
          case IrOpcode::kWord32AtomicPairAnd:
          case IrOpcode::kWord32AtomicPairOr:
          case IrOpcode::kWord32AtomicPairXor:
          case IrOpcode::kWord32AtomicPairExchange:
          case IrOpcode::kWord32AtomicPairCompareExchange:
            representation_vector_[node->id()] = MachineRepresentation::kWord32;
            break;
          case IrOpcode::kWord32AtomicExchange:
          case IrOpcode::kWord32AtomicCompareExchange:
          case IrOpcode::kWord32AtomicAdd:
          case IrOpcode::kWord32AtomicSub:
          case IrOpcode::kWord32AtomicAnd:
          case IrOpcode::kWord32AtomicOr:
          case IrOpcode::kWord32AtomicXor:
          case IrOpcode::kWord64AtomicExchange:
          case IrOpcode::kWord64AtomicCompareExchange:
          case IrOpcode::kWord64AtomicAdd:
          case IrOpcode::kWord64AtomicSub:
          case IrOpcode::kWord64AtomicAnd:
          case IrOpcode::kWord64AtomicOr:
          case IrOpcode::kWord64AtomicXor:
            representation_vector_[node->id()] = PromoteRepresentation(
                AtomicOpType(node->op()).representation());
            break;
          case IrOpcode::kStore:
          case IrOpcode::kProtectedStore:
          case IrOpcode::kStoreTrapOnNull:
          case IrOpcode::kStoreIndirectPointer:
            representation_vector_[node->id()] = PromoteRepresentation(
                StoreRepresentationOf(node->op()).representation());
            break;
          case IrOpcode::kUnalignedStore:
            representation_vector_[node->id()] = PromoteRepresentation(
                UnalignedStoreRepresentationOf(node->op()));
            break;
          case IrOpcode::kHeapConstant:
            representation_vector_[node->id()] =
                MachineRepresentation::kTaggedPointer;
            break;
          case IrOpcode::kNumberConstant:
          case IrOpcode::kChangeBitToTagged:
          case IrOpcode::kIfException:
          case IrOpcode::kOsrValue:
          case IrOpcode::kChangeInt32ToTagged:
          case IrOpcode::kChangeUint32ToTagged:
          case IrOpcode::kBitcastWordToTagged:
          case IrOpcode::kTaggedIndexConstant:
            representation_vector_[node->id()] = MachineRepresentation::kTagged;
            break;
          case IrOpcode::kCompressedHeapConstant:
            representation_vector_[node->id()] =
                MachineRepresentation::kCompressedPointer;
            break;
          case IrOpcode::kExternalConstant:
            representation_vector_[node->id()] =
                MachineType::PointerRepresentation();
            break;
          case IrOpcode::kBitcastTaggedToWord:
          case IrOpcode::kBitcastTaggedToWordForTagAndSmiBits:
            representation_vector_[node->id()] =
                MachineType::PointerRepresentation();
            break;
          case IrOpcode::kBitcastWordToTaggedSigned:
            representation_vector_[node->id()] =
                MachineRepresentation::kTaggedSigned;
            break;
          case IrOpcode::kWord32Equal:
          case IrOpcode::kInt32LessThan:
          case IrOpcode::kInt32LessThanOrEqual:
          case IrOpcode::kUint32LessThan:
          case IrOpcode::kUint32LessThanOrEqual:
          case IrOpcode::kWord64Equal:
          case IrOpcode::kInt64LessThan:
          case IrOpcode::kInt64LessThanOrEqual:
          case IrOpcode::kUint64LessThan:
          case IrOpcode::kUint64LessThanOrEqual:
          case IrOpcode::kFloat32Equal:
          case IrOpcode::kFloat32LessThan:
          case IrOpcode::kFloat32LessThanOrEqual:
          case IrOpcode::kFloat64Equal:
          case IrOpcode::kFloat64LessThan:
          case IrOpcode::kFloat64LessThanOrEqual:
          case IrOpcode::kChangeTaggedToBit:
          case IrOpcode::kStackPointerGreaterThan:
            representation_vector_[node->id()] = MachineRepresentation::kBit;
            break;
#define LABEL(opcode) case IrOpcode::k##opcode:
          case IrOpcode::kTruncateInt64ToInt32:
          case IrOpcode::kTruncateFloat32ToInt32:
          case IrOpcode::kTruncateFloat32ToUint32:
          case IrOpcode::kBitcastFloat32ToInt32:
#if V8_ENABLE_WEBASSEMBLY
          case IrOpcode::kI32x4ExtractLane:
          case IrOpcode::kI16x8ExtractLaneU:
          case IrOpcode::kI16x8ExtractLaneS:
          case IrOpcode::kI8x16ExtractLaneU:
          case IrOpcode::kI8x16ExtractLaneS:
          case IrOpcode::kI8x16BitMask:
#endif  // V8_ENABLE_WEBASSEMBLY
          case IrOpcode::kInt32Constant:
          case IrOpcode::kRelocatableInt32Constant:
          case IrOpcode::kTruncateFloat64ToWord32:
          case IrOpcode::kTruncateFloat64ToUint32:
          case IrOpcode::kChangeFloat64ToInt32:
          case IrOpcode::kChangeFloat64ToUint32:
          case IrOpcode::kRoundFloat64ToInt32:
          case IrOpcode::kFloat64ExtractLowWord32:
          case IrOpcode::kFloat64ExtractHighWord32:
          case IrOpcode::kWord32Popcnt:
            MACHINE_UNOP_32_LIST(LABEL)
            MACHINE_BINOP_32_LIST(LABEL) {
              representation_vector_[node->id()] =
                  MachineRepresentation::kWord32;
            }
            break;
          case IrOpcode::kChangeInt32ToInt64:
          case IrOpcode::kChangeUint32ToUint64:
          case IrOpcode::kBitcastWord32ToWord64:
          case IrOpcode::kInt64Constant:
          case IrOpcode::kRelocatableInt64Constant:
          case IrOpcode::kBitcastFloat64ToInt64:
          case IrOpcode::kChangeFloat64ToInt64:
          case IrOpcode::kChangeFloat64ToUint64:
          case IrOpcode::kTruncateFloat64ToInt64:
          case IrOpcode::kWord64Popcnt:
          case IrOpcode::kWord64Ctz:
          case IrOpcode::kWord64Clz:
            MACHINE_BINOP_64_LIST(LABEL) {
              representation_vector_[node->id()] =
                  MachineRepresentation::kWord64;
            }
            break;
          case IrOpcode::kRoundInt32ToFloat32:
          case IrOpcode::kRoundUint32ToFloat32:
          case IrOpcode::kRoundInt64ToFloat32:
          case IrOpcode::kRoundUint64ToFloat32:
          case IrOpcode::kBitcastInt32ToFloat32:
          case IrOpcode::kFloat32Constant:
          case IrOpcode::kTruncateFloat64ToFloat32:
            MACHINE_FLOAT32_BINOP_LIST(LABEL)
            MACHINE_FLOAT32_UNOP_LIST(LABEL) {
              representation_vector_[node->id()] =
                  MachineRepresentation::kFloat32;
            }
            break;
          case IrOpcode::kRoundInt64ToFloat64:
          case IrOpcode::kRoundUint64ToFloat64:
          case IrOpcode::kBitcastInt64ToFloat64:
          case IrOpcode::kChangeFloat32ToFloat64:
          case IrOpcode::kChangeInt32ToFloat64:
          case IrOpcode::kChangeUint32ToFloat64:
          case IrOpcode::kFloat64InsertLowWord32:
          case IrOpcode::kFloat64InsertHighWord32:
          case IrOpcode::kFloat64Constant:
          case IrOpcode::kFloat64SilenceNaN:
            MACHINE_FLOAT64_BINOP_LIST(LABEL)
            MACHINE_FLOAT64_UNOP_LIST(LABEL) {
              representation_vector_[node->id()] =
                  MachineRepresentation::kFloat64;
            }
            break;
#if V8_ENABLE_WEBASSEMBLY
          case IrOpcode::kI32x4ReplaceLane:
          case IrOpcode::kI32x4Splat:
          case IrOpcode::kI8x16Splat:
          case IrOpcode::kI8x16Eq:
            representation_vector_[node->id()] =
                MachineRepresentation::kSimd128;
            break;
#endif  // V8_ENABLE_WEBASSEMBLY
#undef LABEL
          default:
            break;
        }
      }
    }
  }

  Schedule const* const schedule_;
  Linkage const* const linkage_;
  ZoneVector<MachineRepresentation> representation_vector_;
  BasicBlock* current_block_;
};

class MachineRepresentationChecker {
 public:
  MachineRepresentationChecker(
      Schedule const* const schedule,
      MachineRepresentationInferrer const* const inferrer, bool is_stub,
      const char* name)
      : schedule_(schedule),
        inferrer_(inferrer),
        is_stub_(is_stub),
        name_(name),
        current_block_(nullptr) {}

  void Run() {
    BasicBlockVector const* blocks = schedule_->all_blocks();
    for (BasicBlock* block : *blocks) {
      current_block_ = block;
      for (size_t i = 0; i <= block->NodeCount(); ++i) {
        Node const* node =
            i < block->NodeCount() ? block->NodeAt(i) : block->control_input();
        if (node == nullptr) {
          DCHECK_EQ(block->NodeCount(), i);
          break;
        }
        switch (node->opcode()) {
          case IrOpcode::kCall:
          case IrOpcode::kTailCall:
            CheckCallInputs(node);
            break;
          case IrOpcode::kChangeBitToTagged:
            CHECK_EQ(MachineRepresentation::kBit,
                     inferrer_->GetRepresentation(node->InputAt(0)));
            break;
          case IrOpcode::kChangeTaggedToBit:
            CHECK_EQ(MachineRepresentation::kTagged,
                     inferrer_->GetRepresentation(node->InputAt(0)));
            break;
          case IrOpcode::kRoundInt64ToFloat64:
          case IrOpcode::kRoundUint64ToFloat64:
          case IrOpcode::kRoundInt64ToFloat32:
          case IrOpcode::kRoundUint64ToFloat32:
          case IrOpcode::kTruncateInt64ToInt32:
          case IrOpcode::kBitcastInt64ToFloat64:
          case IrOpcode::kWord64Ctz:
          case IrOpcode::kWord64Clz:
          case IrOpcode::kWord64Popcnt:
            CheckValueInputForInt64Op(node, 0);
            break;
          case IrOpcode::kBitcastWordToTagged:
          case IrOpcode::kBitcastWordToTaggedSigned:
            CheckValueInputRepresentationIs(
                node, 0, MachineType::PointerRepresentation());
            break;
          case IrOpcode::kBitcastTaggedToWord:
          case IrOpcode::kBitcastTaggedToWordForTagAndSmiBits:
            if (COMPRESS_POINTERS_BOOL) {
              CheckValueInputIsCompressedOrTagged(node, 0);
            } else {
              CheckValueInputIsTagged(node, 0);
            }
            break;
          case IrOpcode::kTruncateFloat64ToWord32:
          case IrOpcode::kTruncateFloat64ToUint32:
          case IrOpcode::kTruncateFloat64ToFloat32:
          case IrOpcode::kChangeFloat64ToInt32:
          case IrOpcode::kChangeFloat64ToUint32:
          case IrOpcode::kRoundFloat64ToInt32:
          case IrOpcode::kFloat64ExtractLowWord32:
          case IrOpcode::kFloat64ExtractHighWord32:
          case IrOpcode::kBitcastFloat64ToInt64:
          case IrOpcode::kTryTruncateFloat64ToInt64:
          case IrOpcode::kTryTruncateFloat64ToInt32:
          case IrOpcode::kTryTruncateFloat64ToUint32:
            CheckValueInputForFloat64Op(node, 0);
            break;
          case IrOpcode::kWord64Equal:
            if (Is64() && !COMPRESS_POINTERS_BOOL) {
              CheckValueInputIsTaggedOrPointer(node, 0);
              CheckValueInputIsTaggedOrPointer(node, 1);
              if (!is_stub_) {
                CheckValueInputRepresentationIs(
                    node, 1, inferrer_->GetRepresentation(node->InputAt(0)));
              }
            } else {
              CheckValueInputForInt64Op(node, 0);
              CheckValueInputForInt64Op(node, 1);
            }
            break;
          case IrOpcode::kInt64LessThan:
          case IrOpcode::kInt64LessThanOrEqual:
          case IrOpcode::kUint64LessThan:
          case IrOpcode::kUint64LessThanOrEqual:
            CheckValueInputForInt64Op(node, 0);
            CheckValueInputForInt64Op(node, 1);
            break;
#if V8_ENABLE_WEBASSEMBLY
          case IrOpcode::kI32x4ExtractLane:
          case IrOpcode::kI16x8ExtractLaneU:
          case IrOpcode::kI16x8ExtractLaneS:
          case IrOpcode::kI8x16BitMask:
          case IrOpcode::kI8x16ExtractLaneU:
          case IrOpcode::kI8x16ExtractLaneS:
            CheckValueInputRepresentationIs(node, 0,
                                            MachineRepresentation::kSimd128);
            break;
          case IrOpcode::kI32x4ReplaceLane:
            CheckValueInputRepresentationIs(node, 0,
                                            MachineRepresentation::kSimd128);
            CheckValueInputForInt32Op(node, 1);
            break;
          case IrOpcode::kI32x4Splat:
          case IrOpcode::kI8x16Splat:
            CheckValueInputForInt32Op(node, 0);
            break;
          case IrOpcode::kI8x16Eq:
            CheckValueInputRepresentationIs(node, 0,
                                            MachineRepresentation::kSimd128);
            CheckValueInputRepresentationIs(node, 1,
                                            MachineRepresentation::kSimd128);
            break;
#endif  // V8_ENABLE_WEBASSEMBLY

#define LABEL(opcode) case IrOpcode::k##opcode:
          case IrOpcode::kChangeInt32ToTagged:
          case IrOpcode::kChangeUint32ToTagged:
          case IrOpcode::kChangeInt32ToFloat64:
          case IrOpcode::kChangeUint32ToFloat64:
          case IrOpcode::kRoundInt32ToFloat32:
          case IrOpcode::kRoundUint32ToFloat32:
          case IrOpcode::kBitcastInt32ToFloat32:
          case IrOpcode::kBitcastWord32ToWord64:
          case IrOpcode::kChangeInt32ToInt64:
          case IrOpcode::kChangeUint32ToUint64:
          case IrOpcode::kWord32Popcnt:
            MACHINE_UNOP_32_LIST(LABEL) { CheckValueInputForInt32Op(node, 0); }
            break;
          // Allow tagged pointers to be compared directly, and range checked.
          case IrOpcode::kWord32Equal:
          case IrOpcode::kUint32LessThan:
          case IrOpcode::kUint32LessThanOrEqual:
            if (Is32()) {
              CheckValueInputIsTaggedOrPointer(node, 0);
              CheckValueInputIsTaggedOrPointer(node, 1);
              if (!is_stub_) {
                CheckValueInputRepresentationIs(
                    node, 1, inferrer_->GetRepresentation(node->InputAt(0)));
              }
            } else {
              if (COMPRESS_POINTERS_BOOL) {
                CheckValueInputIsCompressedOrTaggedOrInt32(node, 0);
                CheckValueInputIsCompressedOrTaggedOrInt32(node, 1);
              } else {
                CheckValueIsTaggedOrInt32(node, 0);
                CheckValueIsTaggedOrInt32(node, 1);
              }
            }
            break;

          case IrOpcode::kInt32LessThan:
          case IrOpcode::kInt32LessThanOrEqual:
            MACHINE_BINOP_32_LIST(LABEL) {
              CheckValueInputForInt32Op(node, 0);
              CheckValueInputForInt32Op(node, 1);
            }
            break;
            MACHINE_BINOP_64_LIST(LABEL) {
              CheckValueInputForInt64Op(node, 0);
              CheckValueInputForInt64Op(node, 1);
            }
            break;
          case IrOpcode::kFloat32Equal:
          case IrOpcode::kFloat32LessThan:
          case IrOpcode::kFloat32LessThanOrEqual:
            MACHINE_FLOAT32_BINOP_LIST(LABEL) {
              CheckValueInputForFloat32Op(node, 0);
              CheckValueInputForFloat32Op(node, 1);
            }
            break;
          case IrOpcode::kChangeFloat32ToFloat64:
          case IrOpcode::kTruncateFloat32ToInt32:
          case IrOpcode::kTruncateFloat32ToUint32:
          case IrOpcode::kBitcastFloat32ToInt32:
            MACHINE_FLOAT32_UNOP_LIST(LABEL) {
              CheckValueInputForFloat32Op(node, 0);
            }
            break;
          case IrOpcode::kFloat64Equal:
          case IrOpcode::kFloat64LessThan:
          case IrOpcode::kFloat64LessThanOrEqual:
            MACHINE_FLOAT64_BINOP_LIST(LABEL) {
              CheckValueInputForFloat64Op(node, 0);
              CheckValueInputForFloat64Op(node, 1);
            }
            break;
          case IrOpcode::kFloat64SilenceNaN:
          case IrOpcode::kChangeFloat64ToInt64:
          case IrOpcode::kChangeFloat64ToUint64:
          case IrOpcode::kTruncateFloat64ToInt64:
            MACHINE_FLOAT64_UNOP_LIST(LABEL) {
              CheckValueInputForFloat64Op(node, 0);
            }
            break;
#undef LABEL
          case IrOpcode::kFloat64InsertLowWord32:
          case IrOpcode::kFloat64InsertHighWord32:
            CheckValueInputForFloat64Op(node, 0);
            CheckValueInputForInt32Op(node, 1);
            break;
          case IrOpcode::kInt32PairAdd:
          case IrOpcode::kInt32PairSub:
            for (int j = 0; j < node->op()->ValueInputCount(); ++j) {
              CheckValueInputForInt32Op(node, j);
            }
            break;
          case IrOpcode::kParameter:
          case IrOpcode::kProjection:
            break;
          case IrOpcode::kAbortCSADcheck:
            CheckValueInputIsTagged(node, 0);
            break;
          case IrOpcode::kLoad:
          case IrOpcode::kUnalignedLoad:
          case IrOpcode::kLoadImmutable:
          case IrOpcode::kWord32AtomicLoad:
          case IrOpcode::kWord32AtomicPairLoad:
          case IrOpcode::kWord64AtomicLoad:
            CheckValueInputIsTaggedOrPointer(node, 0);
            CheckValueInputRepresentationIs(
                node, 1, MachineType::PointerRepresentation());
            break;
          case IrOpcode::kWord32AtomicPairAdd:
          case IrOpcode::kWord32AtomicPairSub:
          case IrOpcode::kWord32AtomicPairAnd:
          case IrOpcode::kWord32AtomicPairOr:
          case IrOpcode::kWord32AtomicPairXor:
          case IrOpcode::kWord32AtomicPairStore:
          case IrOpcode::kWord32AtomicPairExchange:
            CheckValueInputRepresentationIs(node, 3,
                                            MachineRepresentation::kWord32);
            [[fallthrough]];
          case IrOpcode::kStore:
          case IrOpcode::kStoreIndirectPointer:
          case IrOpcode::kUnalignedStore:
          case IrOpcode::kWord32AtomicStore:
          case IrOpcode::kWord32AtomicExchange:
          case IrOpcode::kWord32AtomicAdd:
          case IrOpcode::kWord32AtomicSub:
          case IrOpcode::kWord32AtomicAnd:
          case IrOpcode::kWord32AtomicOr:
          case IrOpcode::kWord32AtomicXor:
          case IrOpcode::kWord64AtomicStore:
          case IrOpcode::kWord64AtomicExchange:
          case IrOpcode::kWord64AtomicAdd:
          case IrOpcode::kWord64AtomicSub:
          case IrOpcode::kWord64AtomicAnd:
          case IrOpcode::kWord64AtomicOr:
          case IrOpcode::kWord64AtomicXor:
            CheckValueInputIsTaggedOrPointer(node, 0);
            CheckValueInputRepresentationIs(
                node, 1, MachineType::PointerRepresentation());
            switch (inferrer_->GetRepresentation(node)) {
              case MachineRepresentation::kTagged:
              case MachineRepresentation::kTaggedPointer:
              case MachineRepresentation::kTaggedSigned:
              case MachineRepresentation::kIndirectPointer:
                if (COMPRESS_POINTERS_BOOL &&
                    ((node->opcode() == IrOpcode::kStore &&
                      IsAnyTagged(StoreRepresentationOf(node->op())
                                      .representation())) ||
                     (node->opcode() == IrOpcode::kWord32AtomicStore &&
                      IsAnyTagged(AtomicStoreParametersOf(node->op())
                                      .representation())))) {
                  CheckValueInputIsCompressedOrTagged(node, 2);
                } else {
                  CheckValueInputIsTagged(node, 2);
                }
                break;
              default:
                CheckValueInputRepresentationIs(
                    node, 2, inferrer_->GetRepresentation(node));
            }
            break;
          case IrOpcode::kStorePair: {
            CheckValueInputIsTaggedOrPointer(node, 0);
            CheckValueInputRepresentationIs(
                node, 1, MachineType::PointerRepresentation());
            auto CheckInput = [&](MachineRepresentation rep, int input) {
              switch (rep) {
                case MachineRepresentation::kTagged:
                case MachineRepresentation::kTaggedPointer:
                case MachineRepresentation::kTaggedSigned:
                case MachineRepresentation::kIndirectPointer:
                  if (COMPRESS_POINTERS_BOOL) {
                    CheckValueInputIsCompressedOrTagged(node, input);
                  } else {
                    CheckValueInputIsTagged(node, input);
                  }
                  break;
                default:
                  CheckValueInputRepresentationIs(node, input, rep);
              }
            };
            auto rep = StorePairRepresentationOf(node->op());
            CHECK_GE(ElementSizeLog2Of(rep.first.representation()), 2);
            CHECK_EQ(ElementSizeLog2Of(rep.first.representation()),
                     ElementSizeLog2Of(rep.second.representation()));
            CheckInput(rep.first.representation(), 2);
            CheckInput(rep.second.representation(), 3);
            break;
          }
          case IrOpcode::kWord32AtomicPairCompareExchange:
            CheckValueInputRepresentationIs(node, 4,
                                            MachineRepresentation::kWord32);
            CheckValueInputRepresentationIs(node, 5,
                                            MachineRepresentation::kWord32);
            [[fallthrough]];
          case IrOpcode::kWord32AtomicCompareExchange:
          case IrOpcode::kWord64AtomicCompareExchange:
            CheckValueInputIsTaggedOrPointer(node, 0);
            CheckValueInputRepresentationIs(
                node, 1, MachineType::PointerRepresentation());
            switch (inferrer_->GetRepresentation(node)) {
              case MachineRepresentation::kTagged:
              case MachineRepresentation::kTaggedPointer:
              case MachineRepresentation::kTaggedSigned:
                CheckValueInputIsTagged(node, 2);
                CheckValueInputIsTagged(node, 3);
                break;
              default:
                CheckValueInputRepresentationIs(
                    node, 2, inferrer_->GetRepresentation(node));
                CheckValueInputRepresentationIs(
                    node, 3, inferrer_->GetRepresentation(node));
            }
            break;
          case IrOpcode::kPhi:
            switch (inferrer_->GetRepresentation(node)) {
              case MachineRepresentation::kTagged:
              case MachineRepresentation::kTaggedPointer:
                for (int j = 0; j < node->op()->ValueInputCount(); ++j) {
                  CheckValueInputIsTagged(node, j);
                }
                break;
              case MachineRepresentation::kTaggedSigned:
                for (int j = 0; j < node->op()->ValueInputCount(); ++j) {
                  if (COMPRESS_POINTERS_BOOL) {
                    CheckValueInputIsCompressedOrTagged(node, j);
                  } else {
                    CheckValueInputIsTagged(node, j);
                  }
                }
                break;
              case MachineRepresentation::kCompressed:
              case MachineRepresentation::kCompressedPointer:
                for (int j = 0; j < node->op()->ValueInputCount(); ++j) {
                  CheckValueInputIsCompressedOrTagged(node, j);
                }
                break;
              case MachineRepresentation::kWord32:
                for (int j = 0; j < node->op()->ValueInputCount(); ++j) {
                  CheckValueInputForInt32Op(node, j);
                }
                break;
              default:
                for (int j = 0; j < node->op()->ValueInputCount(); ++j) {
                  CheckValueInputRepresentationIs(
                      node, j, inferrer_->GetRepresentation(node));
                }
                break;
            }
            break;
          case IrOpcode::kBranch:
          case IrOpcode::kSwitch:
            CheckValueInputForInt32Op(node, 0);
            break;
          case IrOpcode::kReturn: {
            // TODO(ishell): enable once the pop count parameter type becomes
            // MachineType::PointerRepresentation(). Currently it's int32 or
            // word-size.
            // CheckValueInputRepresentationIs(
            //     node, 0, MachineType::PointerRepresentation());  // Pop count
            size_t return_count = inferrer_->call_descriptor()->ReturnCount();
            for (size_t j = 0; j < return_count; j++) {
              MachineType type = inferrer_->call_descriptor()->GetReturnType(j);
              int input_index = static_cast<int>(j + 1);
              switch (type.representation()) {
                case MachineRepresentation::kTagged:
                case MachineRepresentation::kTaggedPointer:
                case MachineRepresentation::kTaggedSigned:
                  CheckValueInputIsTagged(node, input_index);
                  break;
                case MachineRepresentation::kWord32:
                  CheckValueInputForInt32Op(node, input_index);
                  break;
                default:
                  CheckValueInputRepresentationIs(node, input_index,
                                                  type.representation());
                  break;
              }
            }
            break;
          }
#if V8_ENABLE_WEBASSEMBLY
          case IrOpcode::kSetStackPointer:
#endif  // V8_ENABLE_WEBASSEMBLY
          case IrOpcode::kStackPointerGreaterThan:
            CheckValueInputRepresentationIs(
                node, 0, MachineType::PointerRepresentation());
            break;
          case IrOpcode::kThrow:
          case IrOpcode::kTypedStateValues:
          case IrOpcode::kFrameState:
          case IrOpcode::kStaticAssert:
            break;
          default:
            if (node->op()->ValueInputCount() != 0) {
              std::stringstream str;
              str << "Node #" << node->id() << ":" << *node->op()
                  << " in the machine graph is not being checked.";
              PrintDebugHelp(str, node);
              FATAL("%s", str.str().c_str());
            }
            break;
        }
      }
    }
  }

 private:
  static bool Is32() {
    return MachineType::PointerRepresentation() ==
           MachineRepresentation::kWord32;
  }
  static bool Is64() {
    return MachineType::PointerRepresentation() ==
           MachineRepresentation::kWord64;
  }

  void CheckValueInputRepresentationIs(Node const* node, int index,
                                       MachineRepresentation representation) {
    Node const* input = node->InputAt(index);
    MachineRepresentation input_representation =
        inferrer_->GetRepresentation(input);
    if (input_representation != representation) {
      std::stringstream str;
      str << "TypeError: node #" << node->id() << ":" << *node->op()
          << " uses node #" << input->id() << ":" << *input->op() << ":"
          << input_representation << " which doesn't have a " << representation
          << " representation.";
      PrintDebugHelp(str, node);
      FATAL("%s", str.str().c_str());
    }
  }

  void CheckValueInputIsTagged(Node const* node, int index) {
    Node const* input = node->InputAt(index);
    switch (inferrer_->GetRepresentation(input)) {
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kTaggedPointer:
      case MachineRepresentation::kTaggedSigned:
        return;
      default:
        break;
    }
    std::ostringstream str;
    str << "TypeError: node #" << node->id() << ":" << *node->op()
        << " uses node #" << input->id() << ":" << *input->op()
        << " which doesn't have a tagged representation.";
    PrintDebugHelp(str, node);
    FATAL("%s", str.str().c_str());
  }

  void CheckValueInputIsCompressedOrTagged(Node const* node, int index) {
    Node const* input = node->InputAt(index);
    switch (inferrer_->GetRepresentation(input)) {
      case MachineRepresentation::kCompressed:
      case MachineRepresentation::kCompressedPointer:
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kTaggedPointer:
      case MachineRepresentation::kTaggedSigned:
        return;
      default:
        break;
    }
    std::ostringstream str;
    str << "TypeError: node #" << node->id() << ":" << *node->op()
        << " uses node #" << input->id() << ":" << *input->op()
        << " which doesn't have a compressed or tagged representation.";
    PrintDebugHelp(str, node);
    FATAL("%s", str.str().c_str());
  }

  void CheckValueInputIsCompressedOrTaggedOrInt32(Node const* node, int index) {
    Node const* input = node->InputAt(index);
    switch (inferrer_->GetRepresentation(input)) {
      case MachineRepresentation::kCompressed:
      case MachineRepresentation::kCompressedPointer:
        return;
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kTaggedPointer:
      case MachineRepresentation::kTaggedSigned:
        return;
      case MachineRepresentation::kBit:
      case MachineRepresentation::kWord8:
      case MachineRepresentation::kWord16:
      case MachineRepresentation::kWord32:
        return;
      default:
        break;
    }
    std::ostringstream str;
    str << "TypeError: node #" << node->id() << ":" << *node->op()
        << " uses node #" << input->id() << ":" << *input->op()
        << " which doesn't have a compressed, tagged, or int32 representation.";
    PrintDebugHelp(str, node);
    FATAL("%s", str.str().c_str());
  }

  void CheckValueInputIsTaggedOrPointer(Node const* node, int index) {
    Node const* input = node->InputAt(index);
    MachineRepresentation rep = inferrer_->GetRepresentation(input);
    switch (rep) {
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kTaggedPointer:
      case MachineRepresentation::kTaggedSigned:
        return;
      case MachineRepresentation::kBit:
      case MachineRepresentation::kWord8:
      case MachineRepresentation::kWord16:
      case MachineRepresentation::kWord32:
        if (Is32()) {
          return;
        }
        break;
      case MachineRepresentation::kWord64:
        if (Is64()) {
          return;
        }
        break;
      default:
        break;
    }
    switch (node->opcode()) {
      case IrOpcode::kLoad:
      case IrOpcode::kProtectedLoad:
      case IrOpcode::kLoadTrapOnNull:
      case IrOpcode::kUnalignedLoad:
      case IrOpcode::kLoadImmutable:
        if (rep == MachineRepresentation::kCompressed ||
            rep == MachineRepresentation::kCompressedPointer) {
          if (DECOMPRESS_POINTER_BY_ADDRESSING_MODE && index == 0) {
            return;
          }
        }
        break;
      default:
        break;
    }
    if (inferrer_->GetRepresentation(input) !=
        MachineType::PointerRepresentation()) {
      std::ostringstream str;
      str << "TypeError: node #" << node->id() << ":" << *node->op()
          << " uses node #" << input->id() << ":" << *input->op()
          << " which doesn't have a tagged or pointer representation.";
      PrintDebugHelp(str, node);
      FATAL("%s", str.str().c_str());
    }
  }

  void CheckValueInputForInt32Op(Node const* node, int index) {
    Node const* input = node->InputAt(index);
    switch (inferrer_->GetRepresentation(input)) {
      case MachineRepresentation::kBit:
      case MachineRepresentation::kWord8:
      case MachineRepresentation::kWord16:
      case MachineRepresentation::kWord32:
        return;
      case MachineRepresentation::kNone: {
        std::ostringstream str;
        str << "TypeError: node #" << input->id() << ":" << *input->op()
            << " is untyped.";
        PrintDebugHelp(str, node);
        FATAL("%s", str.str().c_str());
      }
      default:
        break;
    }
    std::ostringstream str;
    str << "TypeError: node #" << node->id() << ":" << *node->op()
        << " uses node #" << input->id() << ":" << *input->op()
        << " which doesn't have an int32-compatible representation.";
    PrintDebugHelp(str, node);
    FATAL("%s", str.str().c_str());
  }

  void CheckValueIsTaggedOrInt32(Node const* node, int index) {
    Node const* input = node->InputAt(index);
    switch (inferrer_->GetRepresentation(input)) {
      case MachineRepresentation::kBit:
      case MachineRepresentation::kWord8:
      case MachineRepresentation::kWord16:
      case MachineRepresentation::kWord32:
        return;
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kTaggedPointer:
        return;
      default:
        break;
    }
    std::ostringstream str;
    str << "TypeError: node #" << node->id() << ":" << *node->op()
        << " uses node #" << input->id() << ":" << *input->op()
        << " which doesn't have a tagged or int32-compatible "
           "representation.";
    PrintDebugHelp(str, node);
    FATAL("%s", str.str().c_str());
  }

  void CheckValueInputForInt64Op(Node const* node, int index) {
    Node const* input = node->InputAt(index);
    MachineRepresentation input_representation =
        inferrer_->GetRepresentation(input);
    switch (input_representation) {
      case MachineRepresentation::kWord64:
        return;
      case MachineRepresentation::kNone: {
        std::ostringstream str;
        str << "TypeError: node #" << input->id() << ":" << *input->op()
            << " is untyped.";
        PrintDebugHelp(str, node);
        FATAL("%s", str.str().c_str());
      }

      default:
        break;
    }
    std::ostringstream str;
    str << "TypeError: node #" << node->id() << ":" << *node->op()
        << " uses node #" << input->id() << ":" << *input->op() << ":"
        << input_representation
        << " which doesn't have a kWord64 representation.";
    PrintDebugHelp(str, node);
    FATAL("%s", str.str().c_str());
  }

  void CheckValueInputForFloat32Op(Node const* node, int index) {
    Node const* input = node->InputAt(index);
    if (MachineRepresentation::kFloat32 ==
        inferrer_->GetRepresentation(input)) {
      return;
    }
    std::ostringstream str;
    str << "TypeError: node #" << node->id() << ":" << *node->op()
        << " uses node #" << input->id() << ":" << *input->op()
        << " which doesn't have a kFloat32 representation.";
    PrintDebugHelp(str, node);
    FATAL("%s", str.str().c_str());
  }

  void CheckValueInputForFloat64Op(Node const* node, int index) {
    Node const* input = node->InputAt(index);
    if (MachineRepresentation::kFloat64 ==
        inferrer_->GetRepresentation(input)) {
      return;
    }
    std::ostringstream str;
    str << "TypeError: node #" << node->id() << ":" << *node->op()
        << " uses node #" << input->id() << ":" << *input->op()
        << " which doesn't have a kFloat64 representation.";
    PrintDebugHelp(str, node);
    FATAL("%s", str.str().c_str());
  }

  void CheckCallInputs(Node const* node) {
    auto call_descriptor = CallDescriptorOf(node->op());
    std::ostringstream str;
    bool should_log_error = false;
    for (size_t i = 0; i < call_descriptor->InputCount(); ++i) {
      Node const* input = node->InputAt(static_cast<int>(i));
      MachineRepresentation const input_type =
          inferrer_->GetRepresentation(input);
      MachineRepresentation const expected_input_type =
          call_descriptor->GetInputType(i).representation();
      if (!IsCompatible(expected_input_type, input_type)) {
        if (!should_log_error) {
          should_log_error = true;
          str << "TypeError: node #" << node->id() << ":" << *node->op()
              << " has wrong type for:" << std::endl;
        } else {
          str << std::endl;
        }
        str << " * input " << i << " (" << input->id() << ":" << *input->op()
            << ") has a " << input_type
            << " representation (expected: " << expected_input_type << ").";
      }
    }
    if (should_log_error) {
      PrintDebugHelp(str, node);
      FATAL("%s", str.str().c_str());
    }
  }

  bool IsCompatible(MachineRepresentation expected,
                    MachineRepresentation actual) {
    switch (expected) {
      case MachineRepresentation::kTagged:
        return IsAnyTagged(actual);
      case MachineRepresentation::kCompressed:
        return IsAnyCompressed(actual);
      case MachineRepresentation::kMapWord:
      case MachineRepresentation::kTaggedSigned:
      case MachineRepresentation::kTaggedPointer:
        // TODO(turbofan): At the moment, the machine graph doesn't contain
        // reliable information if a node is kTaggedSigned, kTaggedPointer or
        // kTagged, and often this is context-dependent. We should at least
        // check for obvious violations: kTaggedSigned where we expect
        // kTaggedPointer and the other way around, but at the moment, this
        // happens in dead code.
        return IsAnyTagged(actual);
      case MachineRepresentation::kCompressedPointer:
      case MachineRepresentation::kProtectedPointer:
      case MachineRepresentation::kIndirectPointer:
      case MachineRepresentation::kSandboxedPointer:
      case MachineRepresentation::kFloat16:
      case MachineRepresentation::kFloat32:
      case MachineRepresentation::kFloat64:
      case MachineRepresentation::kSimd128:
      case MachineRepresentation::kSimd256:
      case MachineRepresentation::kBit:
      case MachineRepresentation::kWord8:
      case MachineRepresentation::kWord16:
      case MachineRepresentation::kWord64:
        return expected == actual;
      case MachineRepresentation::kWord32:
        return (actual == MachineRepresentation::kBit ||
                actual == MachineRepresentation::kWord8 ||
                actual == MachineRepresentation::kWord16 ||
                actual == MachineRepresentation::kWord32);
      case MachineRepresentation::kNone:
        UNREACHABLE();
    }
    return false;
  }

  void PrintDebugHelp(std::ostream& out, Node const* node) {
    if (DEBUG_BOOL) {
      out << "\n#     Current block: " << *current_block_;
      out << "\n#\n#     Specify option --csa-trap-on-node=" << name_ << ","
          << node->id() << " for debugging.";
    }
  }

  Schedule const* const schedule_;
  MachineRepresentationInferrer const* const inferrer_;
  bool is_stub_;
  const char* name_;
  BasicBlock* current_block_;
};

}  // namespace

void MachineGraphVerifier::Run(Graph* graph, Schedule const* const schedule,
                               Linkage* linkage, bool is_stub, const char* name,
                               Zone* temp_zone) {
  MachineRepresentationInferrer representation_inferrer(schedule, graph,
                                                        linkage, temp_zone);
  MachineRepresentationChecker checker(schedule, &representation_inferrer,
                                       is_stub, name);
  checker.Run();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```