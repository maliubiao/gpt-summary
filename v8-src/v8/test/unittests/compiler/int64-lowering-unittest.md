Response: Let's break down the thought process to arrive at the summary of the C++ code.

1. **Identify the Core Purpose:** The filename itself, `int64-lowering-unittest.cc`, strongly suggests this code is testing a process called "Int64 Lowering". The `unittest` part indicates it's about testing, not the actual implementation.

2. **Scan the Includes:** The `#include` directives provide crucial context:
    * `"src/compiler/int64-lowering.h"`: This confirms the core purpose is testing the `Int64Lowering` class.
    * Other includes like `codegen/`, `compiler/`, `wasm/`, and `test/unittests/compiler/` point to the relevant areas of the V8 codebase. This suggests the `Int64Lowering` is part of the compiler pipeline, likely involved in handling 64-bit integer operations, potentially related to WebAssembly.
    * `testing/gmock-support.h`: This confirms the use of Google Mock for writing the tests.

3. **Examine the Class Definition:** The `Int64LoweringTest` class is where the actual tests reside. Key observations:
    * Inheritance from `GraphTest`: This indicates the tests operate on a graph representation, a common structure in compilers.
    * Member variables `machine_` and `simplified_`: These likely represent different operator builders for machine-level and simplified intermediate representations, respectively. This hints at the lowering process involving a transformation between these representations.
    * `value_` array:  This holds test data for 64-bit integers.
    * `LowerGraph` methods:  These are the core testing functions. They take a `Node` (representing an operation) and potentially a `Signature` (describing function parameters and returns). The name "LowerGraph" directly relates to the "lowering" concept.
    * Helper functions like `low_word_value`, `high_word_value`, and `TestComparison`: These simplify the assertion process by breaking down 64-bit values into their 32-bit parts.

4. **Analyze the Test Cases (the `TEST_F` blocks):**  This is where the specific functionalities being tested become clear. Look for patterns and the types of operations being tested:
    * `Int64Constant`: Testing how 64-bit constants are represented after lowering.
    * `Int64Load`, `Int64Store`, `UnalignedInt64Load`, etc.: Testing the lowering of memory access operations for 64-bit integers. The "unaligned" variant suggests handling cases where the memory address isn't a multiple of the data size.
    * `Int64And`, `TruncateInt64ToInt32`, `Parameter`, `CallI64Return`, `CallI64Parameter`, `Int64Add`, `I64Clz`, `I64Ctz`, `I64Ror`, `Int64Sub`, `Int64Mul`, `Int64Ior`, `Int64Xor`, `Int64Shl`, `Int64ShrU`, `Int64ShrS`, `Int64Eq`, `Int64LtS`, `Int64LeS`, `Int64LtU`, `Int64LeU`, `I32ConvertI64`, `I64SConvertI32`, `I64UConvertI32`, `F64ReinterpretI64`, `I64ReinterpretF64`, `I64Popcnt`, `I64PhiWord64`, `I64ReverseBytes`:  These test the lowering of various 64-bit arithmetic, bitwise, and conversion operations. The "I64" and "Int64" prefixes consistently indicate 64-bit integer operations.
    * `EffectPhiLoop`, `LoopCycle`, `LoopExitValue`:  These test the lowering of 64-bit values within control flow structures like loops.

5. **Infer the "Lowering" Process:** Based on the tests, "lowering" likely involves transforming 64-bit integer operations into sequences of 32-bit integer operations. This is particularly evident in tests involving arithmetic and bitwise operations, where the expected results involve separate operations on the low and high 32-bit words. The tests target a 32-bit architecture (`#if V8_TARGET_ARCH_32_BIT`), which reinforces this idea.

6. **Consider the JavaScript Connection:**  The presence of `wasm/` includes and test cases like `CallI64Return` and `CallI64Parameter` strongly suggest a connection to WebAssembly. WebAssembly supports 64-bit integers, and V8 needs to handle these when running WebAssembly code. The "lowering" likely happens when WebAssembly code with 64-bit operations is compiled for a 32-bit architecture.

7. **Construct the Summary:** Combine the observations to create a concise summary. Start with the core purpose (testing Int64 lowering), then elaborate on the context (V8 compiler, 32-bit architecture), the nature of the tests (different 64-bit operations), and the likely mechanism of lowering (into 32-bit operations). Finally, connect it to JavaScript via WebAssembly.

8. **Create the JavaScript Example:**  Choose a simple JavaScript/WebAssembly example that demonstrates a 64-bit integer operation that would trigger the lowering process on a 32-bit system. A basic arithmetic operation or a WebAssembly function call with a 64-bit parameter or return value serves well.

**(Self-Correction/Refinement):** Initially, one might focus solely on the C++ aspects. However, the WebAssembly includes and test names are strong indicators of a JavaScript connection. Ensuring this connection is explicitly mentioned in the summary makes it more complete. Also, initially, the explanation of "lowering" might be too abstract. Grounding it with the observation of 64-bit operations being broken down into 32-bit operations makes it more concrete.
这个C++源代码文件 `v8/test/unittests/compiler/int64-lowering-unittest.cc` 是V8 JavaScript引擎中编译器组件的一个单元测试文件。它的主要功能是 **测试 `Int64Lowering` 类的正确性**。

`Int64Lowering` 类的作用是将图（Graph）中表示 64 位整数（int64_t）的操作转换为可以在目标架构上执行的等效操作序列。  在 32 位架构上，原生不支持 64 位整数运算，因此 `Int64Lowering` 需要将这些 64 位操作分解为多个 32 位操作。

**具体来说，这个单元测试文件测试了 `Int64Lowering` 类对以下 64 位整数操作的处理：**

* **常量 (Constant):**  将 64 位常量分解为两个 32 位常量（低位和高位）。
* **加载 (Load):** 将加载 64 位整数的操作转换为加载两个 32 位整数的操作。
* **存储 (Store):** 将存储 64 位整数的操作转换为存储两个 32 位整数的操作。
* **算术运算 (Arithmetic Operations):** 例如加法 (`Int64Add`)、减法 (`Int64Sub`)、乘法 (`Int64Mul`) 等，将 64 位运算转换为使用 32 位运算的组合。
* **位运算 (Bitwise Operations):** 例如与 (`Int64And`)、或 (`Int64Ior`)、异或 (`Int64Xor`)、左移 (`Int64Shl`)、右移 (`Int64ShrU`, `Int64ShrS`) 等，将 64 位位运算转换为 32 位位运算的组合。
* **比较运算 (Comparison Operations):** 例如等于 (`Int64Eq`)、小于 (`Int64LtS`, `Int64LtU`)、小于等于 (`Int64LeS`, `Int64LeU`) 等，将 64 位比较转换为基于 32 位比较的逻辑组合。
* **类型转换 (Type Conversions):** 例如将 64 位整数截断为 32 位整数 (`TruncateInt64ToInt32`)，将 32 位整数转换为 64 位整数 (`ChangeInt32ToInt64`, `ChangeUint32ToUint64`)。
* **参数 (Parameter):** 处理函数参数中的 64 位整数。
* **函数调用 (Call):** 处理带有 64 位整数参数或返回值的函数调用，特别是涉及到 WebAssembly 的调用。
* **其他操作:** 例如计算前导零的数量 (`I64Clz`)、尾部零的数量 (`I64Ctz`)、循环右移 (`I64Ror`)、字节反转 (`I64ReverseBytes`)、计算置位位数 (`I64Popcnt`) 等。
* **控制流 (Control Flow):** 测试在循环 (`EffectPhiLoop`, `LoopCycle`, `LoopExitValue`) 和条件分支中如何处理 64 位整数。
* **重新解释 (Reinterpret):** 将 64 位整数重新解释为双精度浮点数 (`F64ReinterpretI64`)，反之亦然 (`I64ReinterpretF64`)。
* **Phi 节点 (Phi Node):**  测试在控制流汇合点处理 64 位整数的情况。

**与 JavaScript 的关系 (以及 JavaScript 例子):**

这个文件与 JavaScript 的功能密切相关，因为它测试的是 V8 引擎的编译器部分，而编译器负责将 JavaScript 代码（以及 WebAssembly 代码）转换为机器码执行。

当 JavaScript 代码中使用了超出 32 位整数范围的整数时，V8 内部会将其表示为 64 位整数。 例如：

```javascript
const largeNumber = 9007199254740991n + 1n; // 使用 BigInt 表示大于 Number.MAX_SAFE_INTEGER 的整数
console.log(largeNumber); // 输出 9007199254740992n
```

在 V8 内部，对于 32 位架构，当执行涉及 `largeNumber` 的操作时，`Int64Lowering` 就会发挥作用。例如，如果执行加法操作：

```javascript
const a = 9007199254740991n;
const b = 1n;
const sum = a + b;
```

在编译 `a + b` 这个操作时，`Int64Lowering` 会将这个 64 位加法操作转换为一系列 32 位加法和进位操作。

**WebAssembly 的例子:**

WebAssembly 本身就支持 64 位整数类型 (`i64`)。当在 JavaScript 中调用 WebAssembly 模块中的函数，并且该函数接受或返回 `i64` 类型的值时，`Int64Lowering` 也会参与其中，确保这些 64 位值能够正确地在 JavaScript 和 WebAssembly 之间传递和操作，尤其是在 32 位系统上。

例如，如果有一个 WebAssembly 函数：

```wasm
(module
  (func $add_i64 (param $a i64) (param $b i64) (result i64)
    local.get $a
    local.get $b
    i64.add
  )
  (export "add_i64" (func $add_i64))
)
```

在 JavaScript 中调用它：

```javascript
const wasmCode = // ... 上面的 wasm 代码的字节表示
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);
const add_i64 = wasmInstance.exports.add_i64;

const result = add_i64(9007199254740991n, 1n);
console.log(result); // 输出 9007199254740992n
```

在 V8 内部，当编译和执行 `add_i64` 这个 WebAssembly 函数时，如果是在 32 位架构上，`Int64Lowering` 会将 `i64.add` 操作转换为相应的 32 位操作序列。

总而言之，`int64-lowering-unittest.cc` 这个文件确保了 V8 引擎在处理 64 位整数时（无论是在 JavaScript 的 BigInt 中还是在 WebAssembly 中）的正确性，尤其是在那些原生不支持 64 位整数运算的 32 位架构上。

Prompt: 
```
这是目录为v8/test/unittests/compiler/int64-lowering-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/int64-lowering.h"

#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/signature.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/linkage.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/wasm-compiler.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/compiler/node-test-utils.h"
#include "testing/gmock-support.h"

#if V8_TARGET_ARCH_32_BIT

using testing::AllOf;
using testing::Capture;
using testing::CaptureEq;

namespace v8 {
namespace internal {
namespace compiler {

class Int64LoweringTest : public GraphTest {
 public:
  Int64LoweringTest()
      : GraphTest(),
        machine_(zone(), MachineRepresentation::kWord32,
                 MachineOperatorBuilder::Flag::kAllOptionalOps),
        simplified_(zone()) {
    value_[0] = 0x1234567890ABCDEF;
    value_[1] = 0x1EDCBA098765432F;
    value_[2] = 0x1133557799886644;
  }

  MachineOperatorBuilder* machine() { return &machine_; }
  SimplifiedOperatorBuilder* simplified() { return &simplified_; }

  void LowerGraph(Node* node, Signature<MachineRepresentation>* signature) {
    Node* zero = graph()->NewNode(common()->Int32Constant(0));
    Node* ret = graph()->NewNode(common()->Return(), zero, node,
                                 graph()->start(), graph()->start());
    NodeProperties::MergeControlToEnd(graph(), common(), ret);

    Int64Lowering lowering(graph(), machine(), common(), simplified(), zone(),
                           signature);
    lowering.LowerGraph();
  }

  void LowerGraphWithSpecialCase(Node* node, MachineRepresentation rep) {
    Node* zero = graph()->NewNode(common()->Int32Constant(0));
    Node* ret = graph()->NewNode(common()->Return(), zero, node,
                                 graph()->start(), graph()->start());
    NodeProperties::MergeControlToEnd(graph(), common(), ret);

    // Create a signature for the outer wasm<>js call; for these tests we focus
    // on lowering the special cases rather than the wrapper node at the
    // JavaScript boundaries.
    Signature<MachineRepresentation>::Builder sig_builder(zone(), 1, 0);
    sig_builder.AddReturn(rep);

    Int64Lowering lowering(graph(), machine(), common(), simplified(), zone(),
                           sig_builder.Get());
    lowering.LowerGraph();
  }

  void LowerGraph(Node* node, MachineRepresentation return_type,
                  MachineRepresentation rep = MachineRepresentation::kWord32,
                  int num_params = 0) {
    Signature<MachineRepresentation>::Builder sig_builder(zone(), 1,
                                                          num_params);
    sig_builder.AddReturn(return_type);
    for (int i = 0; i < num_params; i++) {
      sig_builder.AddParam(rep);
    }
    LowerGraph(node, sig_builder.Get());
  }

  void CompareCallDescriptors(const CallDescriptor* lhs,
                              const CallDescriptor* rhs) {
    EXPECT_THAT(lhs->CalleeSavedFPRegisters(), rhs->CalleeSavedFPRegisters());
    EXPECT_THAT(lhs->CalleeSavedRegisters(), rhs->CalleeSavedRegisters());
    EXPECT_THAT(lhs->FrameStateCount(), rhs->FrameStateCount());
    EXPECT_THAT(lhs->InputCount(), rhs->InputCount());
    for (size_t i = 0; i < lhs->InputCount(); i++) {
      EXPECT_THAT(lhs->GetInputLocation(i), rhs->GetInputLocation(i));
      EXPECT_THAT(lhs->GetInputType(i), rhs->GetInputType(i));
    }
    EXPECT_THAT(lhs->ReturnCount(), rhs->ReturnCount());
    for (size_t i = 0; i < lhs->ReturnCount(); i++) {
      EXPECT_THAT(lhs->GetReturnLocation(i), rhs->GetReturnLocation(i));
      EXPECT_THAT(lhs->GetReturnType(i), rhs->GetReturnType(i));
    }
    EXPECT_THAT(lhs->flags(), rhs->flags());
    EXPECT_THAT(lhs->kind(), rhs->kind());
  }

  int64_t value(int i) { return value_[i]; }

  int32_t low_word_value(int i) {
    return static_cast<int32_t>(value_[i] & 0xFFFFFFFF);
  }

  int32_t high_word_value(int i) {
    return static_cast<int32_t>(value_[i] >> 32);
  }

  void TestComparison(
      const Operator* op,
      Matcher<Node*> (*high_word_matcher)(const Matcher<Node*>& lhs_matcher,
                                          const Matcher<Node*>& rhs_matcher),
      Matcher<Node*> (*low_word_matcher)(const Matcher<Node*>& lhs_matcher,
                                         const Matcher<Node*>& rhs_matcher)) {
    LowerGraph(
        graph()->NewNode(op, Int64Constant(value(0)), Int64Constant(value(1))),
        MachineRepresentation::kWord32);
    EXPECT_THAT(
        graph()->end()->InputAt(1),
        IsReturn(IsWord32Or(
                     high_word_matcher(IsInt32Constant(high_word_value(0)),
                                       IsInt32Constant(high_word_value(1))),
                     IsWord32And(
                         IsWord32Equal(IsInt32Constant(high_word_value(0)),
                                       IsInt32Constant(high_word_value(1))),
                         low_word_matcher(IsInt32Constant(low_word_value(0)),
                                          IsInt32Constant(low_word_value(1))))),
                 start(), start()));
  }

 private:
  MachineOperatorBuilder machine_;
  SimplifiedOperatorBuilder simplified_;
  int64_t value_[3];
};

TEST_F(Int64LoweringTest, Int64Constant) {
  LowerGraph(Int64Constant(value(0)), MachineRepresentation::kWord64);
  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsInt32Constant(low_word_value(0)),
                        IsInt32Constant(high_word_value(0)), start(), start()));
}

#if defined(V8_TARGET_LITTLE_ENDIAN)
#define LOAD_VERIFY(kLoad)                                                     \
  Matcher<Node*> high_word_load_matcher =                                      \
      Is##kLoad(MachineType::Int32(), IsInt32Constant(base),                   \
                IsInt32Constant(index + 4), start(), start());                 \
                                                                               \
  EXPECT_THAT(                                                                 \
      graph()->end()->InputAt(1),                                              \
      IsReturn2(                                                               \
          Is##kLoad(MachineType::Int32(), IsInt32Constant(base),               \
                    IsInt32Constant(index),                                    \
                    AllOf(CaptureEq(&high_word_load), high_word_load_matcher), \
                    start()),                                                  \
          AllOf(CaptureEq(&high_word_load), high_word_load_matcher), start(),  \
          start()));
#elif defined(V8_TARGET_BIG_ENDIAN)
#define LOAD_VERIFY(kLoad)                                                     \
  Matcher<Node*> high_word_load_matcher =                                      \
      Is##kLoad(MachineType::Int32(), IsInt32Constant(base),                   \
                IsInt32Constant(index), start(), start());                     \
                                                                               \
  EXPECT_THAT(                                                                 \
      graph()->end()->InputAt(1),                                              \
      IsReturn2(                                                               \
          Is##kLoad(MachineType::Int32(), IsInt32Constant(base),               \
                    IsInt32Constant(index + 4),                                \
                    AllOf(CaptureEq(&high_word_load), high_word_load_matcher), \
                    start()),                                                  \
          AllOf(CaptureEq(&high_word_load), high_word_load_matcher), start(),  \
          start()));
#endif

#define INT64_LOAD_LOWERING(kLoad, param, builder)                          \
  int32_t base = 0x1234;                                                    \
  int32_t index = 0x5678;                                                   \
                                                                            \
  LowerGraph(graph()->NewNode(builder()->kLoad(param), Int32Constant(base), \
                              Int32Constant(index), start(), start()),      \
             MachineRepresentation::kWord64);                               \
                                                                            \
  Capture<Node*> high_word_load;                                            \
  LOAD_VERIFY(kLoad)

TEST_F(Int64LoweringTest, Int64Load) {
  INT64_LOAD_LOWERING(Load, MachineType::Int64(), machine);
}

TEST_F(Int64LoweringTest, UnalignedInt64Load) {
  INT64_LOAD_LOWERING(UnalignedLoad, MachineType::Int64(), machine);
}

TEST_F(Int64LoweringTest, Int64LoadFromObject) {
  INT64_LOAD_LOWERING(LoadFromObject,
                      ObjectAccess(MachineType::Int64(), kNoWriteBarrier),
                      simplified);
}

TEST_F(Int64LoweringTest, Int64LoadImmutable) {
  int32_t base = 0x1234;
  int32_t index = 0x5678;

  LowerGraph(graph()->NewNode(machine()->LoadImmutable(MachineType::Int64()),
                              Int32Constant(base), Int32Constant(index)),
             MachineRepresentation::kWord64);

  Capture<Node*> high_word_load;

#if defined(V8_TARGET_LITTLE_ENDIAN)
  Matcher<Node*> high_word_load_matcher = IsLoadImmutable(
      MachineType::Int32(), IsInt32Constant(base), IsInt32Constant(index + 4));

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(IsLoadImmutable(MachineType::Int32(), IsInt32Constant(base),
                                IsInt32Constant(index)),
                AllOf(CaptureEq(&high_word_load), high_word_load_matcher),
                start(), start()));
#elif defined(V8_TARGET_BIG_ENDIAN)
  Matcher<Node*> high_word_load_matcher = IsLoadImmutable(
      MachineType::Int32(), IsInt32Constant(base), IsInt32Constant(index));

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(IsLoadImmutable(MachineType::Int32(), IsInt32Constant(base),
                                IsInt32Constant(index + 4)),
                AllOf(CaptureEq(&high_word_load), high_word_load_matcher),
                start(), start()));
#endif
}

#if defined(V8_TARGET_LITTLE_ENDIAN)
#define STORE_VERIFY(kStore, kRep)                                             \
  EXPECT_THAT(                                                                 \
      graph()->end()->InputAt(1),                                              \
      IsReturn(IsInt32Constant(return_value),                                  \
               Is##kStore(kRep, IsInt32Constant(base), IsInt32Constant(index), \
                          IsInt32Constant(low_word_value(0)),                  \
                          Is##kStore(kRep, IsInt32Constant(base),              \
                                     IsInt32Constant(index + 4),               \
                                     IsInt32Constant(high_word_value(0)),      \
                                     start(), start()),                        \
                          start()),                                            \
               start()));
#elif defined(V8_TARGET_BIG_ENDIAN)
#define STORE_VERIFY(kStore, kRep)                                             \
  EXPECT_THAT(                                                                 \
      graph()->end()->InputAt(1),                                              \
      IsReturn(IsInt32Constant(return_value),                                  \
               Is##kStore(                                                     \
                   kRep, IsInt32Constant(base), IsInt32Constant(index + 4),    \
                   IsInt32Constant(low_word_value(0)),                         \
                   Is##kStore(                                                 \
                       kRep, IsInt32Constant(base), IsInt32Constant(index),    \
                       IsInt32Constant(high_word_value(0)), start(), start()), \
                   start()),                                                   \
               start()));
#endif

#define INT64_STORE_LOWERING(kStore, kRep32, kRep64, builder)                \
  int32_t base = 1111;                                                       \
  int32_t index = 2222;                                                      \
  int32_t return_value = 0x5555;                                             \
                                                                             \
  Signature<MachineRepresentation>::Builder sig_builder(zone(), 1, 0);       \
  sig_builder.AddReturn(MachineRepresentation::kWord32);                     \
                                                                             \
  Node* store = graph()->NewNode(builder()->kStore(kRep64),                  \
                                 Int32Constant(base), Int32Constant(index),  \
                                 Int64Constant(value(0)), start(), start()); \
                                                                             \
  Node* zero = graph()->NewNode(common()->Int32Constant(0));                 \
  Node* ret = graph()->NewNode(common()->Return(), zero,                     \
                               Int32Constant(return_value), store, start()); \
                                                                             \
  NodeProperties::MergeControlToEnd(graph(), common(), ret);                 \
                                                                             \
  Int64Lowering lowering(graph(), machine(), common(), simplified(), zone(), \
                         sig_builder.Get());                                 \
  lowering.LowerGraph();                                                     \
                                                                             \
  STORE_VERIFY(kStore, kRep32)

TEST_F(Int64LoweringTest, Int64Store) {
  const StoreRepresentation rep64(MachineRepresentation::kWord64,
                                  WriteBarrierKind::kNoWriteBarrier);
  const StoreRepresentation rep32(MachineRepresentation::kWord32,
                                  WriteBarrierKind::kNoWriteBarrier);
  INT64_STORE_LOWERING(Store, rep32, rep64, machine);
}

TEST_F(Int64LoweringTest, Int32Store) {
  const StoreRepresentation rep32(MachineRepresentation::kWord32,
                                  WriteBarrierKind::kNoWriteBarrier);
  int32_t base = 1111;
  int32_t index = 2222;
  int32_t return_value = 0x5555;

  Signature<MachineRepresentation>::Builder sig_builder(zone(), 1, 0);
  sig_builder.AddReturn(MachineRepresentation::kWord32);

  Node* store = graph()->NewNode(machine()->Store(rep32), Int32Constant(base),
                                 Int32Constant(index), Int64Constant(value(0)),
                                 start(), start());

  Node* zero = graph()->NewNode(common()->Int32Constant(0));
  Node* ret = graph()->NewNode(common()->Return(), zero,
                               Int32Constant(return_value), store, start());

  NodeProperties::MergeControlToEnd(graph(), common(), ret);

  Int64Lowering lowering(graph(), machine(), common(), simplified(), zone(),
                         sig_builder.Get());
  lowering.LowerGraph();

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn(IsInt32Constant(return_value),
               IsStore(rep32, IsInt32Constant(base), IsInt32Constant(index),
                       IsInt32Constant(low_word_value(0)), start(), start()),
               start()));
}

TEST_F(Int64LoweringTest, Int64UnalignedStore) {
  const UnalignedStoreRepresentation rep64(MachineRepresentation::kWord64);
  const UnalignedStoreRepresentation rep32(MachineRepresentation::kWord32);
  INT64_STORE_LOWERING(UnalignedStore, rep32, rep64, machine);
}

TEST_F(Int64LoweringTest, Int64StoreToObject) {
  const ObjectAccess access64(MachineType::Int64(), kNoWriteBarrier);
  const ObjectAccess access32(MachineType::Int32(), kNoWriteBarrier);
  INT64_STORE_LOWERING(StoreToObject, access32, access64, simplified);
}

TEST_F(Int64LoweringTest, Int64And) {
  LowerGraph(graph()->NewNode(machine()->Word64And(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord64);
  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsWord32And(IsInt32Constant(low_word_value(0)),
                                    IsInt32Constant(low_word_value(1))),
                        IsWord32And(IsInt32Constant(high_word_value(0)),
                                    IsInt32Constant(high_word_value(1))),
                        start(), start()));
}

TEST_F(Int64LoweringTest, TruncateInt64ToInt32) {
  LowerGraph(graph()->NewNode(machine()->TruncateInt64ToInt32(),
                              Int64Constant(value(0))),
             MachineRepresentation::kWord32);
  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn(IsInt32Constant(low_word_value(0)), start(), start()));
}

TEST_F(Int64LoweringTest, Parameter) {
  LowerGraph(Parameter(1), MachineRepresentation::kWord64,
             MachineRepresentation::kWord64, 1);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsParameter(1), IsParameter(2), start(), start()));
}

TEST_F(Int64LoweringTest, Parameter2) {
  Signature<MachineRepresentation>::Builder sig_builder(zone(), 1, 5);
  sig_builder.AddReturn(MachineRepresentation::kWord32);

  sig_builder.AddParam(MachineRepresentation::kWord32);
  sig_builder.AddParam(MachineRepresentation::kWord64);
  sig_builder.AddParam(MachineRepresentation::kFloat64);
  sig_builder.AddParam(MachineRepresentation::kWord64);
  sig_builder.AddParam(MachineRepresentation::kWord32);

  int start_parameter = start()->op()->ValueOutputCount();
  LowerGraph(Parameter(5), sig_builder.Get());

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn(IsParameter(7), start(), start()));
  // The parameter of the start node should increase by 2, because we lowered
  // two parameter nodes.
  EXPECT_THAT(start()->op()->ValueOutputCount(), start_parameter + 2);
}

TEST_F(Int64LoweringTest, ParameterWithJSContextParam) {
  Signature<MachineRepresentation>::Builder sig_builder(zone(), 0, 2);
  sig_builder.AddParam(MachineRepresentation::kWord64);
  sig_builder.AddParam(MachineRepresentation::kWord64);

  auto sig = sig_builder.Get();

  Node* js_context = graph()->NewNode(
      common()->Parameter(Linkage::GetJSCallContextParamIndex(
                              static_cast<int>(sig->parameter_count()) + 1),
                          "%context"),
      start());
  LowerGraph(js_context, sig);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn(js_context, start(), start()));
}

TEST_F(Int64LoweringTest, ParameterWithJSClosureParam) {
  Signature<MachineRepresentation>::Builder sig_builder(zone(), 0, 2);
  sig_builder.AddParam(MachineRepresentation::kWord64);
  sig_builder.AddParam(MachineRepresentation::kWord64);

  auto sig = sig_builder.Get();

  Node* js_closure = graph()->NewNode(
      common()->Parameter(Linkage::kJSCallClosureParamIndex, "%closure"),
      start());
  LowerGraph(js_closure, sig);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn(js_closure, start(), start()));
}

// The following tests are only valid in 32-bit platforms, due to one of these
// two assumptions:
// - Pointers are 32 bit and therefore pointers do not get lowered.
// - 64-bit rol/ror/clz/ctz instructions have a control input.
TEST_F(Int64LoweringTest, CallI64Return) {
  int32_t function = 0x9999;
  Node* context_address = Int32Constant(0);

  wasm::FunctionSig::Builder sig_builder(zone(), 1, 0);
  sig_builder.AddReturn(wasm::kWasmI64);

  auto call_descriptor =
      compiler::GetWasmCallDescriptor(zone(), sig_builder.Get());

  LowerGraph(
      graph()->NewNode(common()->Call(call_descriptor), Int32Constant(function),
                       context_address, start(), start()),
      MachineRepresentation::kWord64);

  Capture<Node*> call;
  Matcher<Node*> call_matcher =
      IsCall(testing::_, IsInt32Constant(function), start(), start());

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsProjection(0, AllOf(CaptureEq(&call), call_matcher)),
                        IsProjection(1, AllOf(CaptureEq(&call), call_matcher)),
                        start(), start()));

  CompareCallDescriptors(
      CallDescriptorOf(
          graph()->end()->InputAt(1)->InputAt(1)->InputAt(0)->op()),
      compiler::GetI32WasmCallDescriptor(zone(), call_descriptor));
}

TEST_F(Int64LoweringTest, CallI64Parameter) {
  int32_t function = 0x9999;
  Node* context_address = Int32Constant(0);

  wasm::FunctionSig::Builder sig_builder(zone(), 1, 3);
  sig_builder.AddReturn(wasm::kWasmI32);
  sig_builder.AddParam(wasm::kWasmI64);
  sig_builder.AddParam(wasm::kWasmI32);
  sig_builder.AddParam(wasm::kWasmI64);

  auto call_descriptor =
      compiler::GetWasmCallDescriptor(zone(), sig_builder.Get());

  LowerGraph(
      graph()->NewNode(common()->Call(call_descriptor), Int32Constant(function),
                       context_address, Int64Constant(value(0)),
                       Int32Constant(low_word_value(1)),
                       Int64Constant(value(2)), start(), start()),
      MachineRepresentation::kWord32);

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn(IsCall(testing::_, IsInt32Constant(function), context_address,
                      IsInt32Constant(low_word_value(0)),
                      IsInt32Constant(high_word_value(0)),
                      IsInt32Constant(low_word_value(1)),
                      IsInt32Constant(low_word_value(2)),
                      IsInt32Constant(high_word_value(2)), start(), start()),
               start(), start()));

  CompareCallDescriptors(
      CallDescriptorOf(graph()->end()->InputAt(1)->InputAt(1)->op()),
      compiler::GetI32WasmCallDescriptor(zone(), call_descriptor));
}

TEST_F(Int64LoweringTest, Int64Add) {
  LowerGraph(graph()->NewNode(machine()->Int64Add(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord64);

  Capture<Node*> add;
  Matcher<Node*> add_matcher = IsInt32PairAdd(
      IsInt32Constant(low_word_value(0)), IsInt32Constant(high_word_value(0)),
      IsInt32Constant(low_word_value(1)), IsInt32Constant(high_word_value(1)));

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsProjection(0, AllOf(CaptureEq(&add), add_matcher)),
                        IsProjection(1, AllOf(CaptureEq(&add), add_matcher)),
                        start(), start()));
}

TEST_F(Int64LoweringTest, I64Clz) {
  LowerGraph(graph()->NewNode(machine()->Word64ClzLowerable(),
                              Int64Constant(value(0)), graph()->start()),
             MachineRepresentation::kWord64);

  Capture<Node*> branch_capture;
  Matcher<Node*> branch_matcher = IsBranch(
      IsWord32Equal(IsInt32Constant(high_word_value(0)), IsInt32Constant(0)),
      start());

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(
          IsPhi(MachineRepresentation::kWord32,
                IsInt32Add(IsWord32Clz(IsInt32Constant(low_word_value(0))),
                           IsInt32Constant(32)),
                IsWord32Clz(IsInt32Constant(high_word_value(0))),
                IsMerge(
                    IsIfTrue(AllOf(CaptureEq(&branch_capture), branch_matcher)),
                    IsIfFalse(
                        AllOf(CaptureEq(&branch_capture), branch_matcher)))),
          IsInt32Constant(0), start(), start()));
}

TEST_F(Int64LoweringTest, I64Ctz) {
  LowerGraph(graph()->NewNode(machine()->Word64CtzLowerable().placeholder(),
                              Int64Constant(value(0)), graph()->start()),
             MachineRepresentation::kWord64);
  Capture<Node*> branch_capture;
  Matcher<Node*> branch_matcher = IsBranch(
      IsWord32Equal(IsInt32Constant(low_word_value(0)), IsInt32Constant(0)),
      start());
  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(
          IsPhi(MachineRepresentation::kWord32,
                IsInt32Add(IsWord32Ctz(IsInt32Constant(high_word_value(0))),
                           IsInt32Constant(32)),
                IsWord32Ctz(IsInt32Constant(low_word_value(0))),
                IsMerge(
                    IsIfTrue(AllOf(CaptureEq(&branch_capture), branch_matcher)),
                    IsIfFalse(
                        AllOf(CaptureEq(&branch_capture), branch_matcher)))),
          IsInt32Constant(0), start(), start()));
}

TEST_F(Int64LoweringTest, I64Ror) {
  LowerGraph(
      graph()->NewNode(machine()->Word64RorLowerable(), Int64Constant(value(0)),
                       Parameter(0), graph()->start()),
      MachineRepresentation::kWord64, MachineRepresentation::kWord64, 1);

  Matcher<Node*> branch_lt32_matcher =
      IsBranch(IsInt32LessThan(IsParameter(0), IsInt32Constant(32)), start());

  Matcher<Node*> low_input_matcher = IsPhi(
      MachineRepresentation::kWord32, IsInt32Constant(low_word_value(0)),
      IsInt32Constant(high_word_value(0)),
      IsMerge(IsIfTrue(branch_lt32_matcher), IsIfFalse(branch_lt32_matcher)));

  Matcher<Node*> high_input_matcher = IsPhi(
      MachineRepresentation::kWord32, IsInt32Constant(high_word_value(0)),
      IsInt32Constant(low_word_value(0)),
      IsMerge(IsIfTrue(branch_lt32_matcher), IsIfFalse(branch_lt32_matcher)));

  Matcher<Node*> shift_matcher =
      IsWord32And(IsParameter(0), IsInt32Constant(0x1F));

  Matcher<Node*> bit_mask_matcher = IsWord32Xor(
      IsWord32Shr(IsInt32Constant(-1), shift_matcher), IsInt32Constant(-1));

  Matcher<Node*> inv_mask_matcher =
      IsWord32Xor(bit_mask_matcher, IsInt32Constant(-1));

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(
          IsWord32Or(IsWord32And(IsWord32Ror(low_input_matcher, shift_matcher),
                                 inv_mask_matcher),
                     IsWord32And(IsWord32Ror(high_input_matcher, shift_matcher),
                                 bit_mask_matcher)),
          IsWord32Or(IsWord32And(IsWord32Ror(high_input_matcher, shift_matcher),
                                 inv_mask_matcher),
                     IsWord32And(IsWord32Ror(low_input_matcher, shift_matcher),
                                 bit_mask_matcher)),
          start(), start()));
}

TEST_F(Int64LoweringTest, I64Ror_0) {
  LowerGraph(
      graph()->NewNode(machine()->Word64RorLowerable(), Int64Constant(value(0)),
                       Int32Constant(0), graph()->start()),
      MachineRepresentation::kWord64);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsInt32Constant(low_word_value(0)),
                        IsInt32Constant(high_word_value(0)), start(), start()));
}

TEST_F(Int64LoweringTest, I64Ror_32) {
  LowerGraph(
      graph()->NewNode(machine()->Word64RorLowerable(), Int64Constant(value(0)),
                       Int32Constant(32), graph()->start()),
      MachineRepresentation::kWord64);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsInt32Constant(high_word_value(0)),
                        IsInt32Constant(low_word_value(0)), start(), start()));
}

TEST_F(Int64LoweringTest, I64Ror_11) {
  LowerGraph(
      graph()->NewNode(machine()->Word64RorLowerable(), Int64Constant(value(0)),
                       Int32Constant(11), graph()->start()),
      MachineRepresentation::kWord64);

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(IsWord32Or(IsWord32Shr(IsInt32Constant(low_word_value(0)),
                                       IsInt32Constant(11)),
                           IsWord32Shl(IsInt32Constant(high_word_value(0)),
                                       IsInt32Constant(21))),
                IsWord32Or(IsWord32Shr(IsInt32Constant(high_word_value(0)),
                                       IsInt32Constant(11)),
                           IsWord32Shl(IsInt32Constant(low_word_value(0)),
                                       IsInt32Constant(21))),
                start(), start()));
}

TEST_F(Int64LoweringTest, I64Ror_43) {
  LowerGraph(
      graph()->NewNode(machine()->Word64RorLowerable(), Int64Constant(value(0)),
                       Int32Constant(43), graph()->start()),
      MachineRepresentation::kWord64);

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(IsWord32Or(IsWord32Shr(IsInt32Constant(high_word_value(0)),
                                       IsInt32Constant(11)),
                           IsWord32Shl(IsInt32Constant(low_word_value(0)),
                                       IsInt32Constant(21))),
                IsWord32Or(IsWord32Shr(IsInt32Constant(low_word_value(0)),
                                       IsInt32Constant(11)),
                           IsWord32Shl(IsInt32Constant(high_word_value(0)),
                                       IsInt32Constant(21))),
                start(), start()));
}

TEST_F(Int64LoweringTest, Int64Sub) {
  LowerGraph(graph()->NewNode(machine()->Int64Sub(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord64);

  Capture<Node*> sub;
  Matcher<Node*> sub_matcher = IsInt32PairSub(
      IsInt32Constant(low_word_value(0)), IsInt32Constant(high_word_value(0)),
      IsInt32Constant(low_word_value(1)), IsInt32Constant(high_word_value(1)));

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsProjection(0, AllOf(CaptureEq(&sub), sub_matcher)),
                        IsProjection(1, AllOf(CaptureEq(&sub), sub_matcher)),
                        start(), start()));
}

TEST_F(Int64LoweringTest, Int64Mul) {
  LowerGraph(graph()->NewNode(machine()->Int64Mul(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord64);

  Capture<Node*> mul_capture;
  Matcher<Node*> mul_matcher = IsInt32PairMul(
      IsInt32Constant(low_word_value(0)), IsInt32Constant(high_word_value(0)),
      IsInt32Constant(low_word_value(1)), IsInt32Constant(high_word_value(1)));

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(IsProjection(0, AllOf(CaptureEq(&mul_capture), mul_matcher)),
                IsProjection(1, AllOf(CaptureEq(&mul_capture), mul_matcher)),
                start(), start()));
}

TEST_F(Int64LoweringTest, Int64Ior) {
  LowerGraph(graph()->NewNode(machine()->Word64Or(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord64);
  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsWord32Or(IsInt32Constant(low_word_value(0)),
                                   IsInt32Constant(low_word_value(1))),
                        IsWord32Or(IsInt32Constant(high_word_value(0)),
                                   IsInt32Constant(high_word_value(1))),
                        start(), start()));
}

TEST_F(Int64LoweringTest, Int64Xor) {
  LowerGraph(graph()->NewNode(machine()->Word64Xor(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord64);
  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsWord32Xor(IsInt32Constant(low_word_value(0)),
                                    IsInt32Constant(low_word_value(1))),
                        IsWord32Xor(IsInt32Constant(high_word_value(0)),
                                    IsInt32Constant(high_word_value(1))),
                        start(), start()));
}

TEST_F(Int64LoweringTest, Int64Shl) {
  LowerGraph(graph()->NewNode(machine()->Word64Shl(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord64);

  Capture<Node*> shl;
  Matcher<Node*> shl_matcher = IsWord32PairShl(
      IsInt32Constant(low_word_value(0)), IsInt32Constant(high_word_value(0)),
      IsInt32Constant(low_word_value(1)));

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsProjection(0, AllOf(CaptureEq(&shl), shl_matcher)),
                        IsProjection(1, AllOf(CaptureEq(&shl), shl_matcher)),
                        start(), start()));
}

TEST_F(Int64LoweringTest, Int64ShrU) {
  LowerGraph(graph()->NewNode(machine()->Word64Shr(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord64);

  Capture<Node*> shr;
  Matcher<Node*> shr_matcher = IsWord32PairShr(
      IsInt32Constant(low_word_value(0)), IsInt32Constant(high_word_value(0)),
      IsInt32Constant(low_word_value(1)));

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsProjection(0, AllOf(CaptureEq(&shr), shr_matcher)),
                        IsProjection(1, AllOf(CaptureEq(&shr), shr_matcher)),
                        start(), start()));
}

TEST_F(Int64LoweringTest, Int64ShrS) {
  LowerGraph(graph()->NewNode(machine()->Word64Sar(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord64);

  Capture<Node*> sar;
  Matcher<Node*> sar_matcher = IsWord32PairSar(
      IsInt32Constant(low_word_value(0)), IsInt32Constant(high_word_value(0)),
      IsInt32Constant(low_word_value(1)));

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsProjection(0, AllOf(CaptureEq(&sar), sar_matcher)),
                        IsProjection(1, AllOf(CaptureEq(&sar), sar_matcher)),
                        start(), start()));
}

TEST_F(Int64LoweringTest, Int64Eq) {
  LowerGraph(graph()->NewNode(machine()->Word64Equal(), Int64Constant(value(0)),
                              Int64Constant(value(1))),
             MachineRepresentation::kWord32);
  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn(IsWord32Equal(
                   IsWord32Or(IsWord32Xor(IsInt32Constant(low_word_value(0)),
                                          IsInt32Constant(low_word_value(1))),
                              IsWord32Xor(IsInt32Constant(high_word_value(0)),
                                          IsInt32Constant(high_word_value(1)))),
                   IsInt32Constant(0)),
               start(), start()));
}

TEST_F(Int64LoweringTest, Int64LtS) {
  TestComparison(machine()->Int64LessThan(), IsInt32LessThan, IsUint32LessThan);
}

TEST_F(Int64LoweringTest, Int64LeS) {
  TestComparison(machine()->Int64LessThanOrEqual(), IsInt32LessThan,
                 IsUint32LessThanOrEqual);
}

TEST_F(Int64LoweringTest, Int64LtU) {
  TestComparison(machine()->Uint64LessThan(), IsUint32LessThan,
                 IsUint32LessThan);
}

TEST_F(Int64LoweringTest, Int64LeU) {
  TestComparison(machine()->Uint64LessThanOrEqual(), IsUint32LessThan,
                 IsUint32LessThanOrEqual);
}

TEST_F(Int64LoweringTest, I32ConvertI64) {
  LowerGraph(graph()->NewNode(machine()->TruncateInt64ToInt32(),
                              Int64Constant(value(0))),
             MachineRepresentation::kWord32);
  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn(IsInt32Constant(low_word_value(0)), start(), start()));
}

TEST_F(Int64LoweringTest, I64SConvertI32) {
  LowerGraph(graph()->NewNode(machine()->ChangeInt32ToInt64(),
                              Int32Constant(low_word_value(0))),
             MachineRepresentation::kWord64);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsInt32Constant(low_word_value(0)),
                        IsWord32Sar(IsInt32Constant(low_word_value(0)),
                                    IsInt32Constant(31)),
                        start(), start()));
}

TEST_F(Int64LoweringTest, I64SConvertI32_2) {
  LowerGraph(
      graph()->NewNode(machine()->ChangeInt32ToInt64(),
                       graph()->NewNode(machine()->TruncateInt64ToInt32(),
                                        Int64Constant(value(0)))),
      MachineRepresentation::kWord64);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsInt32Constant(low_word_value(0)),
                        IsWord32Sar(IsInt32Constant(low_word_value(0)),
                                    IsInt32Constant(31)),
                        start(), start()));
}

TEST_F(Int64LoweringTest, I64UConvertI32) {
  LowerGraph(graph()->NewNode(machine()->ChangeUint32ToUint64(),
                              Int32Constant(low_word_value(0))),
             MachineRepresentation::kWord64);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsInt32Constant(low_word_value(0)), IsInt32Constant(0),
                        start(), start()));
}

TEST_F(Int64LoweringTest, I64UConvertI32_2) {
  LowerGraph(
      graph()->NewNode(machine()->ChangeUint32ToUint64(),
                       graph()->NewNode(machine()->TruncateInt64ToInt32(),
                                        Int64Constant(value(0)))),
      MachineRepresentation::kWord64);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsInt32Constant(low_word_value(0)), IsInt32Constant(0),
                        start(), start()));
}

TEST_F(Int64LoweringTest, F64ReinterpretI64) {
  int64_t value = 0x0123456789abcdef;
  LowerGraph(graph()->NewNode(machine()->BitcastInt64ToFloat64(),
                              Int64Constant(value)),
             MachineRepresentation::kFloat64);
  Node* ret = graph()->end()->InputAt(1);
  EXPECT_EQ(ret->opcode(), IrOpcode::kReturn);
  Node* ret_value = ret->InputAt(1);
  EXPECT_EQ(ret_value->opcode(), IrOpcode::kFloat64InsertLowWord32);
  Node* high_half = ret_value->InputAt(0);
  EXPECT_EQ(high_half->opcode(), IrOpcode::kFloat64InsertHighWord32);
  Node* low_half_bits = ret_value->InputAt(1);
  Int32Matcher m1(low_half_bits);
  EXPECT_TRUE(m1.Is(static_cast<int32_t>(value & 0xFFFFFFFF)));
  Node* high_half_bits = high_half->InputAt(1);
  Int32Matcher m2(high_half_bits);
  EXPECT_TRUE(m2.Is(static_cast<int32_t>(value >> 32)));
}

TEST_F(Int64LoweringTest, I64ReinterpretF64) {
  double value = 1234.5678;
  LowerGraph(graph()->NewNode(machine()->BitcastFloat64ToInt64(),
                              Float64Constant(value)),
             MachineRepresentation::kWord64);
  Node* ret = graph()->end()->InputAt(1);
  EXPECT_EQ(ret->opcode(), IrOpcode::kReturn);
  Node* ret_value_low = ret->InputAt(1);
  EXPECT_EQ(ret_value_low->opcode(), IrOpcode::kFloat64ExtractLowWord32);
  Node* ret_value_high = ret->InputAt(2);
  EXPECT_EQ(ret_value_high->opcode(), IrOpcode::kFloat64ExtractHighWord32);
}

TEST_F(Int64LoweringTest, Dfs) {
  Node* common = Int64Constant(value(0));
  LowerGraph(graph()->NewNode(machine()->Word64And(), common,
                              graph()->NewNode(machine()->Word64And(), common,
                                               Int64Constant(value(1)))),
             MachineRepresentation::kWord64);

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(IsWord32And(IsInt32Constant(low_word_value(0)),
                            IsWord32And(IsInt32Constant(low_word_value(0)),
                                        IsInt32Constant(low_word_value(1)))),
                IsWord32And(IsInt32Constant(high_word_value(0)),
                            IsWord32And(IsInt32Constant(high_word_value(0)),
                                        IsInt32Constant(high_word_value(1)))),
                start(), start()));
}

TEST_F(Int64LoweringTest, I64Popcnt) {
  LowerGraph(graph()->NewNode(machine()->Word64Popcnt().placeholder(),
                              Int64Constant(value(0))),
             MachineRepresentation::kWord64);

  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(IsInt32Add(IsWord32Popcnt(IsInt32Constant(low_word_value(0))),
                           IsWord32Popcnt(IsInt32Constant(high_word_value(0)))),
                IsInt32Constant(0), start(), start()));
}

TEST_F(Int64LoweringTest, I64PhiWord64) {
  LowerGraph(graph()->NewNode(common()->Phi(MachineRepresentation::kWord64, 2),
                              Int64Constant(value(0)), Int64Constant(value(1)),
                              start()),
             MachineRepresentation::kWord64);

  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsPhi(MachineRepresentation::kWord32,
                              IsInt32Constant(low_word_value(0)),
                              IsInt32Constant(low_word_value(1)), start()),
                        IsPhi(MachineRepresentation::kWord32,
                              IsInt32Constant(high_word_value(0)),
                              IsInt32Constant(high_word_value(1)), start()),
                        start(), start()));
}

void TestPhi(Int64LoweringTest* test, MachineRepresentation rep, Node* v1,
             Node* v2) {
  test->LowerGraph(test->graph()->NewNode(test->common()->Phi(rep, 2), v1, v2,
                                          test->start()),
                   rep);

  EXPECT_THAT(test->graph()->end()->InputAt(1),
              IsReturn(IsPhi(rep, v1, v2, test->start()), test->start(),
                       test->start()));
}

TEST_F(Int64LoweringTest, I64PhiFloat32) {
  TestPhi(this, MachineRepresentation::kFloat32, Float32Constant(1.5),
          Float32Constant(2.5));
}

TEST_F(Int64LoweringTest, I64PhiFloat64) {
  TestPhi(this, MachineRepresentation::kFloat64, Float32Constant(1.5),
          Float32Constant(2.5));
}

TEST_F(Int64LoweringTest, I64PhiWord32) {
  TestPhi(this, MachineRepresentation::kWord32, Float32Constant(1),
          Float32Constant(2));
}

TEST_F(Int64LoweringTest, I64ReverseBytes) {
  LowerGraph(graph()->NewNode(machine()->Word64ReverseBytes(),
                              Int64Constant(value(0))),
             MachineRepresentation::kWord64);
  EXPECT_THAT(
      graph()->end()->InputAt(1),
      IsReturn2(IsWord32ReverseBytes(IsInt32Constant(high_word_value(0))),
                IsWord32ReverseBytes(IsInt32Constant(low_word_value(0))),
                start(), start()));
}

TEST_F(Int64LoweringTest, EffectPhiLoop) {
  // Construct a cycle consisting of an EffectPhi, a Store, and a Load.
  Node* eff_phi = graph()->NewNode(common()->EffectPhi(1), graph()->start(),
                                   graph()->start());

  StoreRepresentation store_rep(MachineRepresentation::kWord64,
                                WriteBarrierKind::kNoWriteBarrier);
  LoadRepresentation load_rep(MachineType::Int64());

  Node* load =
      graph()->NewNode(machine()->Load(load_rep), Int64Constant(value(0)),
                       Int64Constant(value(1)), eff_phi, graph()->start());

  Node* store =
      graph()->NewNode(machine()->Store(store_rep), Int64Constant(value(0)),
                       Int64Constant(value(1)), load, load, graph()->start());

  eff_phi->InsertInput(zone(), 1, store);
  NodeProperties::ChangeOp(eff_phi,
                           common()->ResizeMergeOrPhi(eff_phi->op(), 2));

  LowerGraph(load, MachineRepresentation::kWord64);
}

TEST_F(Int64LoweringTest, LoopCycle) {
  // New node with two placeholders.
  Node* compare = graph()->NewNode(machine()->Word64Equal(), Int64Constant(0),
                                   Int64Constant(value(0)));

  Node* load = graph()->NewNode(
      machine()->Load(MachineType::Int64()), Int64Constant(value(1)),
      Int64Constant(value(2)), graph()->start(),
      graph()->NewNode(
          common()->Loop(2), graph()->start(),
          graph()->NewNode(common()->IfFalse(),
                           graph()->NewNode(common()->Branch(), compare,
                                            graph()->start()))));

  NodeProperties::ReplaceValueInput(compare, load, 0);

  LowerGraph(load, MachineRepresentation::kWord64);
}

TEST_F(Int64LoweringTest, LoopExitValue) {
  Node* loop_header = graph()->NewNode(common()->Loop(1), graph()->start());
  Node* loop_exit =
      graph()->NewNode(common()->LoopExit(), loop_header, loop_header);
  Node* exit =
      graph()->NewNode(common()->LoopExitValue(MachineRepresentation::kWord64),
                       Int64Constant(value(2)), loop_exit);
  LowerGraph(exit, MachineRepresentation::kWord64);
  EXPECT_THAT(graph()->end()->InputAt(1),
              IsReturn2(IsLoopExitValue(MachineRepresentation::kWord32,
                                        IsInt32Constant(low_word_value(2))),
                        IsLoopExitValue(MachineRepresentation::kWord32,
                                        IsInt32Constant(high_word_value(2))),
                        start(), start()));
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_32_BIT

"""

```