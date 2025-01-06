Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Understanding the Goal:**

The first step is to understand *why* this file exists. The filename `int64-lowering-unittest.cc` and the directory `v8/test/unittests/compiler/` immediately suggest this is a unit test for a compiler component that deals with 64-bit integers. The "lowering" part hints at a process of transforming or simplifying 64-bit operations into something more basic, likely for architectures that don't natively support 64-bit operations efficiently.

**2. Identifying Key Components:**

Next, scan the `#include` directives. These tell us the major players involved:

* `src/compiler/int64-lowering.h`:  This is the header file for the code being tested. It confirms our initial guess about the file's purpose.
* `src/codegen/...`:  These headers relate to code generation, suggesting the "lowering" process is about preparing 64-bit operations for actual machine instructions.
* `src/compiler/...`:  These headers point to other compiler infrastructure components, like the graph representation (`node.h`, `node-properties.h`), operators (`common-operator.h`, `machine-operator.h`), and possibly intermediate representations.
* `src/wasm/...`:  The presence of WASM-related headers indicates that 64-bit integer handling is also relevant to WebAssembly compilation within V8.
* `test/unittests/compiler/...` and `testing/gmock-support.h`: These confirm that this is indeed a unit test file using Google Mock for assertions.

**3. Examining the Test Fixture:**

The `Int64LoweringTest` class, derived from `GraphTest`, is the core of the test setup. Key observations:

* `MachineOperatorBuilder machine_;` and `SimplifiedOperatorBuilder simplified_;`:  These likely represent different levels of abstraction in the compiler's intermediate representation.
* `value_`: An array of `int64_t` values. These are the test inputs.
* `LowerGraph` methods:  These are the central functions for triggering the 64-bit lowering process on a given node in the graph. The different overloads suggest variations in how the lowering is tested (e.g., with or without specific signatures).
* Helper functions like `low_word_value`, `high_word_value`, and `TestComparison`: These simplify the process of creating and verifying expected outputs after the lowering.

**4. Analyzing Individual Test Cases:**

Now, delve into the `TEST_F` macros. Each test case focuses on a specific 64-bit operation or scenario:

* `Int64Constant`: Tests lowering a 64-bit constant. Expectation: it's split into two 32-bit constants.
* `Int64Load`, `UnalignedInt64Load`, `Int64LoadFromObject`, `Int64LoadImmutable`: Test lowering different types of memory loads of 64-bit values. Expectation: they are translated into two 32-bit loads. The `LOAD_VERIFY` macro handles platform-specific byte ordering.
* `Int64Store`, `Int32Store`, `Int64UnalignedStore`, `Int64StoreToObject`: Test lowering different types of 64-bit stores. Expectation: They are translated into two 32-bit stores. The `STORE_VERIFY` macro handles platform-specific byte ordering.
* `Int64And`, `TruncateInt64ToInt32`, `Parameter`, `Parameter2`, `ParameterWithJSContextParam`, `ParameterWithJSClosureParam`: Test lowering bitwise AND, truncation, and parameter passing for 64-bit values.
* `CallI64Return`, `CallI64Parameter`: Test lowering function calls that involve 64-bit return values and parameters.
* Arithmetic operations (`Int64Add`, `Int64Sub`, `Int64Mul`): Test lowering addition, subtraction, and multiplication. Expectation: They are translated into pairs of 32-bit operations with carry handling.
* Bitwise operations (`I64Clz`, `I64Ctz`, `I64Ror`, `Int64Ior`, `Int64Xor`, `Int64Shl`, `Int64ShrU`, `Int64ShrS`): Test lowering various bitwise operations (count leading zeros, count trailing zeros, rotate right, OR, XOR, left shift, unsigned right shift, signed right shift). These often involve more complex logic to simulate 64-bit behavior using 32-bit operations.
* Comparisons (`Int64Equal`, `Int64NotEqual`, `Int64LessThan`, `Int64LessThanOrEqual`, `Int64GreaterThan`, `Int64GreaterThanOrEqual`): Test lowering comparison operations. Expectation: They involve comparing the high and low 32-bit words.

**5. Identifying Patterns and Logic:**

A key pattern emerges:  On 32-bit architectures, 64-bit operations are generally lowered into pairs of 32-bit operations. This involves:

* **Splitting:** 64-bit values are split into their lower and higher 32-bit words.
* **Pairing:** 64-bit operations are often translated into sequences of two 32-bit operations, carefully managing carries and borrows.
* **Conditional Logic:** For some operations (like CLZ, CTZ, ROR), conditional branches are used to handle different cases based on the values of the high and low words.

**6. Connecting to JavaScript:**

While the code is C++, it's crucial to consider its connection to JavaScript. JavaScript's `Number` type can represent integers beyond the 32-bit range. The `Int64Lowering` pass is essential for making these operations efficient on platforms where native 64-bit support is limited or unavailable. Examples of relevant JavaScript operations include:

* Bitwise operations on large integers (e.g., `(BigInt(0x1234567890ABCDEF) & BigInt(0x1)).toString(16)`).
* Arithmetic operations on large integers.
* Comparisons of large integers.

**7. Inferring Common Errors:**

Based on the tested scenarios, we can infer potential programming errors that this lowering pass helps to avoid or handle correctly:

* **Assuming native 64-bit support:** Developers might write code that implicitly relies on 64-bit operations, which would be inefficient or incorrect on 32-bit platforms without this lowering.
* **Incorrectly handling high and low words:** Manually implementing 64-bit operations using 32-bit types is error-prone. This lowering pass automates this process.
* **Endianness issues:** The `LOAD_VERIFY` and `STORE_VERIFY` macros highlight the importance of considering byte order when working with multi-word values.

**8. Summarization:**

Finally, synthesize the findings into a concise summary, focusing on the core functionality and its purpose within the V8 JavaScript engine. Highlight the target architecture (32-bit), the key transformation (64-bit to 32-bit operations), and the connection to JavaScript's ability to handle large integers.
好的，让我们来分析一下 `v8/test/unittests/compiler/int64-lowering-unittest.cc` 这个文件的功能。

**核心功能归纳：**

`v8/test/unittests/compiler/int64-lowering-unittest.cc` 是 V8 JavaScript 引擎中 **编译器 (compiler)** 的一个 **单元测试 (unittest)** 文件，专门用于测试 **Int64Lowering** 这个编译阶段的功能。

**Int64Lowering 的功能：**

`Int64Lowering` 的主要目标是将 64 位整数 (int64) 相关的操作 **降低 (lowering)**  为可以在目标架构上高效执行的指令。  这在 **32 位架构** 上尤其重要，因为 32 位架构本身不直接支持 64 位整数运算。`Int64Lowering` 会将 64 位操作分解为一系列 32 位操作。

**文件内容的功能细节：**

这个单元测试文件通过创建各种不同的 **图节点 (graph nodes)** 来模拟 64 位整数的运算，然后调用 `Int64Lowering` 过程来转换这些节点。  测试会断言转换后的图结构是否符合预期，即 64 位操作是否被正确地转换为了等价的 32 位操作序列。

**具体测试的场景包括：**

* **常量 (Constant):** 测试 64 位常量如何被表示为两个 32 位常量。
* **加载 (Load):** 测试从内存中加载 64 位整数如何被转换为加载两个 32 位整数。
* **存储 (Store):** 测试将 64 位整数存储到内存中如何被转换为存储两个 32 位整数。
* **算术运算 (Arithmetic Operations):** 测试 64 位整数的加法、减法、乘法等运算如何被转换为 32 位运算，并处理进位和借位。
* **位运算 (Bitwise Operations):** 测试 64 位整数的与、或、异或、移位、循环移位等运算如何被转换为 32 位运算。
* **比较运算 (Comparison Operations):** 测试 64 位整数的比较运算如何被转换为 32 位比较运算。
* **函数调用 (Call):** 测试当函数参数或返回值是 64 位整数时，如何进行处理。
* **参数 (Parameter):** 测试函数参数为 64 位整数时，如何在内部表示。
* **类型转换 (Truncate):** 测试将 64 位整数截断为 32 位整数。

**关于文件名后缀 .tq：**

你提到的 `.tq` 后缀，通常用于 V8 的 **Torque** 语言编写的源代码。 Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。  但是，`v8/test/unittests/compiler/int64-lowering-unittest.cc`  **不是** 以 `.tq` 结尾，它是一个标准的 **C++** 源文件。 因此，它不是 Torque 代码。

**与 JavaScript 功能的关系及示例：**

`Int64Lowering` 与 JavaScript 的功能密切相关，因为它使得 JavaScript 能够正确且高效地处理超出 32 位安全整数范围的整数。  虽然 JavaScript 的 `Number` 类型可以表示这些值，但在底层，V8 需要将这些操作转换为机器可以执行的指令。

**JavaScript 示例：**

```javascript
// JavaScript 可以处理超出 32 位范围的整数
const largeNumber1 = 9007199254740991n; // 使用 BigInt 表示
const largeNumber2 = 1n;

const sum = largeNumber1 + largeNumber2;
console.log(sum); // 输出 9007199254741000n

const bitwiseAnd = largeNumber1 & largeNumber2;
console.log(bitwiseAnd); // 输出 1n
```

当 V8 执行这些 JavaScript 代码时，特别是当运行在 32 位架构上时，`Int64Lowering` 这样的编译阶段会将对 `largeNumber1` 和 `largeNumber2` 的 64 位操作转换为一系列 32 位操作，以确保结果的正确性。

**代码逻辑推理 (假设输入与输出):**

**假设输入：**  一个表示 64 位整数加法的图节点，操作数为两个 64 位常量 `0x1234567890ABCDEF` 和 `0xFEDCBA0987654321`。

**预期输出 (在 32 位架构上经过 Int64Lowering 后):**

一系列新的图节点，表示以下 32 位操作：

1. **低 32 位加法:** 将 `0x90ABCDEF` 和 `0x87654321` 相加。
2. **进位计算:**  检查低 32 位加法是否产生进位。
3. **高 32 位加法:** 将 `0x12345678` 和 `0xFEDCBA09` 相加，并加上来自低 32 位加法的进位 (如果有)。
4. **结果表示:**  将高 32 位和低 32 位的结果组合起来，表示 64 位加法的最终结果。

**涉及用户常见的编程错误 (以 C++ 为例，模拟底层操作):**

```c++
#include <iostream>

int main() {
  uint32_t low1 = 0x90ABCDEF;
  uint32_t high1 = 0x12345678;
  uint32_t low2 = 0x87654321;
  uint32_t high2 = 0xFEDCBA09;

  // 尝试直接进行 64 位运算 (如果平台支持)
  uint64_t num1 = ((uint64_t)high1 << 32) | low1;
  uint64_t num2 = ((uint64_t)high2 << 32) | low2;
  uint64_t sum_64 = num1 + num2;
  std::cout << "64-bit sum: " << std::hex << sum_64 << std::endl;

  // 手动模拟 32 位加法处理进位 (容易出错)
  uint32_t low_sum = low1 + low2;
  uint32_t carry = (low_sum < low1); // 检查是否溢出
  uint32_t high_sum = high1 + high2 + carry;
  uint64_t manual_sum = ((uint64_t)high_sum << 32) | low_sum;
  std::cout << "Manual 32-bit sum: " << std::hex << manual_sum << std::endl;

  return 0;
}
```

**常见的编程错误：**

* **忽略进位/借位:**  在手动实现 64 位算术运算时，很容易忘记处理低位运算产生的进位或借位，导致高位计算错误。
* **类型溢出:**  在 32 位环境中进行运算时，如果不注意类型转换，可能会发生意外的溢出。
* **字节序问题:**  在处理 64 位数据的内存表示时，可能会遇到字节序 (endianness) 问题，导致高低位数据错乱。

`Int64Lowering` 的作用就是确保在 V8 内部正确处理这些细节，避免这些常见的编程错误影响 JavaScript 代码的执行。

**总结：**

`v8/test/unittests/compiler/int64-lowering-unittest.cc` 是一个关键的单元测试文件，用于验证 V8 编译器中 `Int64Lowering` 组件的功能。 该组件负责将 64 位整数操作转换为可以在目标架构上高效执行的指令序列，尤其在 32 位架构上至关重要。 它确保了 JavaScript 能够正确处理超出 32 位范围的整数运算，避免了手动实现这些操作时容易出现的错误。

这就是对 `v8/test/unittests/compiler/int64-lowering-unittest.cc` 文件功能的归纳。

Prompt: 
```
这是目录为v8/test/unittests/compiler/int64-lowering-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/int64-lowering-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

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
  LowerGraph(graph()->NewNode(machine()->Word64Shr(), Int64Constant(val
"""


```