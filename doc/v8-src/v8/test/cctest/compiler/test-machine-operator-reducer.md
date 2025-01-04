Response: Let's break down the thought process for analyzing this C++ code and connecting it to JavaScript.

1. **Understand the Core Purpose:** The file name `test-machine-operator-reducer.cc` immediately suggests this is a *test* file. The terms "machine operator" and "reducer" hint at compiler optimizations within a virtual machine. Specifically, it likely tests how certain operations are simplified or transformed.

2. **Identify Key Classes and Concepts:**
    * `MachineOperatorReducer`: This is the central piece. It's responsible for *reducing* machine-level operations. Reduction means finding simpler or more efficient ways to represent the same computation.
    * `ReducerTester`: This appears to be a helper class for setting up and running tests on the `MachineOperatorReducer`. It provides utilities for creating nodes in a graph, representing constants, and checking the results of reductions.
    * `Graph`: This likely represents the intermediate representation of code being compiled, often a directed graph of operations.
    * `Node`: Individual operations within the `Graph`.
    * `Operator`:  Represents the type of operation (e.g., addition, subtraction, bitwise AND).
    * `MachineOperatorBuilder`:  Used to create machine-level operators.
    * `CommonOperatorBuilder`: Used to create common operators (like constants).
    * `JSGraph`: Seems to integrate JavaScript-specific concepts into the graph representation.
    * Templates (`template <typename T> ...`): Indicate the code works with different data types (int32, int64, float, double).

3. **Analyze the Test Structure (`ReducerTester`):**
    * The constructor sets up the necessary components for testing (graph, operators, etc.).
    * `Constant<T>`:  A convenient way to create constant nodes of various types.
    * `ValueOf<T>`:  Extracts the value from a constant node.
    * `CheckFoldBinop`: This is the core assertion mechanism. It creates a binary operation node (`CreateBinopNode`), runs the `MachineOperatorReducer`, and checks if the result matches the expected value or node. There are multiple overloads for different scenarios (constant operands, node operands, checking for specific operator types). The name "Fold" suggests constant folding, a common compiler optimization.
    * `CheckBinop`: Similar to `CheckFoldBinop`, but checks if the entire resulting *node* is the expected node, not just the value.
    * `CheckPutConstantOnRight`/`CheckDontPutConstantOnRight`: These test a specific reduction rule related to commutative operators and placing constants on the right-hand side.
    * `Parameter`: Creates input parameters for the graph.

4. **Examine Individual Test Cases (e.g., `TEST(ReduceWord32And)`):**
    * Each `TEST` function focuses on a specific machine operation (e.g., `Word32And`, `Word32Or`, `Int32Add`).
    * It instantiates `ReducerTester`.
    * It sets the `binop` member of the `ReducerTester` to the relevant machine operator.
    * It uses loops (`FOR_INT32_INPUTS`) to test the operator with various constant inputs using `CheckFoldBinop`. This tests constant folding.
    * It uses `CheckPutConstantOnRight`/`CheckDontPutConstantOnRight` to test constant placement rules.
    * It creates parameter nodes and constant nodes and uses `CheckBinop` to test more complex reduction scenarios involving variables.

5. **Connect to JavaScript (The "Aha!" Moment):**  The key is understanding that this C++ code is part of the V8 JavaScript engine. The "machine operators" being reduced are the low-level operations that JavaScript code gets compiled down to.

    * **Constant Folding:** When JavaScript code performs operations on constants, the compiler can often calculate the result at compile time. The `CheckFoldBinop` tests directly verify this. For example, `1 + 2` can be reduced to `3` during compilation.
    * **Algebraic Simplification:**  The tests also show simplification rules like `x & 0 => 0`, `x + 0 => x`. These are algebraic identities that can be applied to optimize the generated machine code.
    * **Machine-Specific Optimizations:**  The `ReduceJsShifts` test highlights optimizations related to how shift operations are implemented on the target architecture. If the hardware automatically masks the shift amount, the compiler can take advantage of that.

6. **Construct JavaScript Examples:**  Based on the C++ tests, create JavaScript snippets that would trigger the corresponding reductions. Focus on the *intent* of the C++ tests.

    * For `ReduceWord32And`: Show examples of bitwise AND operations, including cases with zero and -1.
    * For `ReduceInt32Add`: Demonstrate addition with zero.
    * For `ReduceInt32Mul`: Show multiplication by zero, one, and powers of two.
    * For the shift operations:  Illustrate how shifts with constants and the masking behavior are handled.

7. **Refine and Explain:** Review the JavaScript examples and explanations to ensure they clearly illustrate the connection to the C++ code and the optimization being tested. Explain *why* these reductions are beneficial (performance improvements).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this is just about generic operator overloading.
* **Correction:** The file path and the class names (`MachineOperatorReducer`, `JSGraph`) clearly indicate this is specific to the V8 JavaScript engine's compilation pipeline.
* **Initial thought:** Focus only on constant folding.
* **Correction:**  Realize the tests cover a broader range of algebraic simplifications and machine-specific optimizations.
* **Initial thought:**  Provide very technical JavaScript examples related to Typed Arrays.
* **Correction:**  Start with simpler, more common JavaScript examples to make the connection clearer and then potentially mention Typed Arrays as a more concrete use case for some of these low-level operations.
这个C++源代码文件 `test-machine-operator-reducer.cc` 是 **V8 JavaScript 引擎** 的一部分，更具体地说，它属于 **Turbofan 编译器** 的测试代码。  其主要功能是 **测试 `MachineOperatorReducer` 类的各种归约（reduction）规则**。

**`MachineOperatorReducer` 的功能：**

在 V8 的 Turbofan 编译器中，`MachineOperatorReducer` 负责对图（Graph）中的 **机器操作（Machine Operators）** 进行简化和优化。 这个过程被称为“归约”。  它的目标是将复杂的或冗余的机器操作替换为更简单、更高效的操作，从而提高生成的机器码的性能。

**测试的核心思想：**

该测试文件通过创建各种包含机器操作的图节点，然后应用 `MachineOperatorReducer` 进行归约，并断言归约后的结果是否符合预期。 它针对不同的机器操作（例如，加法、减法、位运算、比较等）和不同的操作数类型（例如，32位整数、64位整数、浮点数）编写了大量的测试用例。

**与 JavaScript 的关系以及 JavaScript 示例：**

`MachineOperatorReducer` 处理的是 JavaScript 代码在 Turbofan 编译器中被编译成的 **低级机器操作**。 因此，它与 JavaScript 的执行性能息息相关。  编译器通过应用这些归约规则，可以优化 JavaScript 代码的执行效率。

以下是一些测试用例及其对应的 JavaScript 例子，展示了 `MachineOperatorReducer` 如何优化 JavaScript 代码：

**1. 常量折叠 (Constant Folding):**

   - **C++ 测试 (例如 `TEST(ReduceWord32And)`):**
     ```c++
     R.CheckFoldBinop<int32_t>(x & y, x, y); // 测试两个常量的位与运算
     ```

   - **JavaScript 例子:**
     ```javascript
     const result = 5 & 3; // JavaScript 位与运算
     // Turbofan 编译器在编译时会直接计算出结果 1，而不会生成实际的位与机器指令。
     ```
     `MachineOperatorReducer` 会识别出 `5` 和 `3` 都是常量，并直接将 `Word32And(Constant(5), Constant(3))` 归约为 `Constant(1)`。

**2. 代数简化 (Algebraic Simplification):**

   - **C++ 测试 (例如 `TEST(ReduceInt32Add)`):**
     ```c++
     R.CheckBinop(x, x, zero);  // x + 0  => x
     ```

   - **JavaScript 例子:**
     ```javascript
     function addZero(a) {
       return a + 0;
     }
     // Turbofan 编译器会将 `a + 0` 归约为 `a`，避免不必要的加法运算。
     ```
     `MachineOperatorReducer` 会识别出加零的操作，并将 `Int32Add(a, Constant(0))` 归约为 `a` 本身。

**3. 移位运算优化 (Shift Operation Optimization):**

   - **C++ 测试 (例如 `TEST(ReduceWord32Shl)`):**
     ```c++
     R.CheckBinop(x, x, zero);  // x << 0  => x
     ```

   - **JavaScript 例子:**
     ```javascript
     function shiftByZero(b) {
       return b << 0;
     }
     // Turbofan 编译器会将 `b << 0` 归约为 `b`。
     ```
     `MachineOperatorReducer` 会识别出移位 0 位的操作，并将 `Word32Shl(b, Constant(0))` 归约为 `b`。

**4. 乘法和除法优化 (Multiplication and Division Optimization):**

   - **C++ 测试 (例如 `TEST(ReduceInt32Mul)`):**
     ```c++
     R.CheckFoldBinop<int32_t>(x, R.machine.Word32Shl(), n, x, multiplier);  // x * 2^n => x << n
     ```

   - **JavaScript 例子:**
     ```javascript
     function multiplyByPowerOfTwo(c) {
       return c * 8; // 8 是 2 的 3 次方
     }
     // Turbofan 编译器会将 `c * 8` 优化为 `c << 3`，因为移位运算通常比乘法运算更快。
     ```
     `MachineOperatorReducer` 会识别出乘以 2 的幂次方的操作，并将其归约为左移操作。

**总结:**

`test-machine-operator-reducer.cc` 文件通过大量的测试用例，验证了 `MachineOperatorReducer` 在 Turbofan 编译器中正确有效地执行各种机器操作的归约和优化。 这些优化直接影响着 JavaScript 代码的执行效率，使得 V8 引擎能够更快速地执行 JavaScript 代码。  理解这些测试用例可以帮助我们更好地理解 V8 编译器的内部工作原理以及 JavaScript 性能优化的机制。

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-machine-operator-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/overflowing-math.h"
#include "src/base/utils/random-number-generator.h"
#include "src/codegen/tick-counter.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/machine-operator-reducer.h"
#include "src/compiler/operator-properties.h"
#include "src/compiler/turbofan-typer.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace compiler {

template <typename T>
const Operator* NewConstantOperator(CommonOperatorBuilder* common,
                                    T value);

template <>
const Operator* NewConstantOperator<int32_t>(CommonOperatorBuilder* common,
                                             int32_t value) {
  return common->Int32Constant(value);
}

template <>
const Operator* NewConstantOperator<int64_t>(CommonOperatorBuilder* common,
                                             int64_t value) {
  return common->Int64Constant(value);
}

template <>
const Operator* NewConstantOperator<double>(CommonOperatorBuilder* common,
                                            double value) {
  return common->Float64Constant(value);
}

template <>
const Operator* NewConstantOperator<float>(CommonOperatorBuilder* common,
                                           float value) {
  return common->Float32Constant(value);
}

template <typename T>
T ValueOfOperator(const Operator* op);

template <>
int32_t ValueOfOperator<int32_t>(const Operator* op) {
  CHECK_EQ(IrOpcode::kInt32Constant, op->opcode());
  return OpParameter<int32_t>(op);
}

template <>
int64_t ValueOfOperator<int64_t>(const Operator* op) {
  CHECK_EQ(IrOpcode::kInt64Constant, op->opcode());
  return OpParameter<int64_t>(op);
}

template <>
float ValueOfOperator<float>(const Operator* op) {
  CHECK_EQ(IrOpcode::kFloat32Constant, op->opcode());
  return OpParameter<float>(op);
}

template <>
double ValueOfOperator<double>(const Operator* op) {
  CHECK_EQ(IrOpcode::kFloat64Constant, op->opcode());
  return OpParameter<double>(op);
}


class ReducerTester : public HandleAndZoneScope {
 public:
  explicit ReducerTester(int num_parameters = 0,
                         MachineOperatorBuilder::Flags flags =
                             MachineOperatorBuilder::kAllOptionalOps)
      : HandleAndZoneScope(kCompressGraphZone),
        isolate(main_isolate()),
        binop(nullptr),
        unop(nullptr),
        machine(main_zone(), MachineType::PointerRepresentation(), flags),
        common(main_zone()),
        graph(main_zone()),
        javascript(main_zone()),
        jsgraph(isolate, &graph, &common, &javascript, nullptr, &machine),
        maxuint32(Constant<int32_t>(kMaxUInt32)),
        graph_reducer(main_zone(), &graph, &tick_counter, nullptr,
                      jsgraph.Dead()) {
    Node* s = graph.NewNode(common.Start(num_parameters));
    graph.SetStart(s);
  }

  Isolate* isolate;
  TickCounter tick_counter;
  const Operator* binop;
  const Operator* unop;
  MachineOperatorBuilder machine;
  CommonOperatorBuilder common;
  Graph graph;
  JSOperatorBuilder javascript;
  JSGraph jsgraph;
  Node* maxuint32;
  GraphReducer graph_reducer;

  template <typename T>
  Node* Constant(T value) {
    return graph.NewNode(NewConstantOperator<T>(&common, value));
  }

  template <typename T>
  const T ValueOf(const Operator* op) {
    return ValueOfOperator<T>(op);
  }

  // Check that the reduction of this binop applied to constants {a} and {b}
  // yields the {expect} value.
  template <typename T>
  void CheckFoldBinop(T expect, T a, T b) {
    CheckFoldBinop<T>(expect, Constant<T>(a), Constant<T>(b));
  }

  // Check that the reduction of this binop applied to {a} and {b} yields
  // the {expect} value.
  template <typename T>
  void CheckFoldBinop(T expect, Node* a, Node* b) {
    CHECK(binop);
    Node* n = CreateBinopNode(a, b);
    MachineOperatorReducer reducer(
        &graph_reducer, &jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    Reduction reduction = reducer.Reduce(n);
    CHECK(reduction.Changed());
    CHECK_NE(n, reduction.replacement());
    // Deal with NaNs.
    if (expect == expect) {
      // We do not expect a NaN, check for equality.
      CHECK_EQ(expect, ValueOf<T>(reduction.replacement()->op()));
    } else {
      // Check for NaN.
      T result = ValueOf<T>(reduction.replacement()->op());
      CHECK_NE(result, result);
    }
  }

  // Check that the reduction of this binop applied to {a} and {b} yields
  // the {expect} node.
  void CheckBinop(Node* expect, Node* a, Node* b) {
    CHECK(binop);
    Node* n = CreateBinopNode(a, b);
    MachineOperatorReducer reducer(
        &graph_reducer, &jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    Reduction reduction = reducer.Reduce(n);
    CHECK(reduction.Changed());
    CHECK_EQ(expect, reduction.replacement());
  }

  // Check that the reduction of this binop applied to {left} and {right} yields
  // this binop applied to {left_expect} and {right_expect}.
  void CheckFoldBinop(Node* left_expect, Node* right_expect, Node* left,
                      Node* right) {
    CHECK(binop);
    Node* n = CreateBinopNode(left, right);
    MachineOperatorReducer reducer(
        &graph_reducer, &jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    Reduction reduction = reducer.Reduce(n);
    CHECK(reduction.Changed());
    CHECK_EQ(binop, reduction.replacement()->op());
    CHECK_EQ(left_expect, reduction.replacement()->InputAt(0));
    CHECK_EQ(right_expect, reduction.replacement()->InputAt(1));
  }

  // Check that the reduction of this binop applied to {left} and {right} yields
  // the {op_expect} applied to {left_expect} and {right_expect}.
  template <typename T>
  void CheckFoldBinop(T left_expect, const Operator* op_expect,
                      Node* right_expect, Node* left, Node* right) {
    CHECK(binop);
    Node* n = CreateBinopNode(left, right);
    MachineOperatorReducer reducer(
        &graph_reducer, &jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    Reduction r = reducer.Reduce(n);
    CHECK(r.Changed());
    CHECK_EQ(op_expect->opcode(), r.replacement()->op()->opcode());
    CHECK_EQ(left_expect, ValueOf<T>(r.replacement()->InputAt(0)->op()));
    CHECK_EQ(right_expect, r.replacement()->InputAt(1));
  }

  // Check that the reduction of this binop applied to {left} and {right} yields
  // the {op_expect} applied to {left_expect} and {right_expect}.
  template <typename T>
  void CheckFoldBinop(Node* left_expect, const Operator* op_expect,
                      T right_expect, Node* left, Node* right) {
    CHECK(binop);
    Node* n = CreateBinopNode(left, right);
    MachineOperatorReducer reducer(
        &graph_reducer, &jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    Reduction r = reducer.Reduce(n);
    CHECK(r.Changed());
    CHECK_EQ(op_expect->opcode(), r.replacement()->op()->opcode());
    CHECK_EQ(OperatorProperties::GetTotalInputCount(op_expect),
             r.replacement()->InputCount());
    CHECK_EQ(left_expect, r.replacement()->InputAt(0));
    CHECK_EQ(right_expect, ValueOf<T>(r.replacement()->InputAt(1)->op()));
  }

  // Check that if the given constant appears on the left, the reducer will
  // swap it to be on the right.
  template <typename T>
  void CheckPutConstantOnRight(T constant) {
    // TODO(titzer): CHECK(binop->HasProperty(Operator::kCommutative));
    Node* p = Parameter();
    Node* k = Constant<T>(constant);
    {
      Node* n = CreateBinopNode(k, p);
      MachineOperatorReducer reducer(
          &graph_reducer, &jsgraph,
          MachineOperatorReducer::kPropagateSignallingNan);
      Reduction reduction = reducer.Reduce(n);
      CHECK(!reduction.Changed() || reduction.replacement() == n);
      CHECK_EQ(p, n->InputAt(0));
      CHECK_EQ(k, n->InputAt(1));
    }
    {
      Node* n = CreateBinopNode(p, k);
      MachineOperatorReducer reducer(
          &graph_reducer, &jsgraph,
          MachineOperatorReducer::kPropagateSignallingNan);
      Reduction reduction = reducer.Reduce(n);
      CHECK(!reduction.Changed());
      CHECK_EQ(p, n->InputAt(0));
      CHECK_EQ(k, n->InputAt(1));
    }
  }

  // Check that if the given constant appears on the left, the reducer will
  // *NOT* swap it to be on the right.
  template <typename T>
  void CheckDontPutConstantOnRight(T constant) {
    CHECK(!binop->HasProperty(Operator::kCommutative));
    Node* p = Parameter();
    Node* k = Constant<T>(constant);
    Node* n = CreateBinopNode(k, p);
    MachineOperatorReducer reducer(
        &graph_reducer, &jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    Reduction reduction = reducer.Reduce(n);
    CHECK(!reduction.Changed());
    CHECK_EQ(k, n->InputAt(0));
    CHECK_EQ(p, n->InputAt(1));
  }

  Node* Parameter(int32_t index = 0) {
    return graph.NewNode(common.Parameter(index), graph.start());
  }

 private:
  Node* CreateBinopNode(Node* left, Node* right) {
    if (binop->ControlInputCount() > 0) {
      return graph.NewNode(binop, left, right, graph.start());
    } else {
      return graph.NewNode(binop, left, right);
    }
  }
};


TEST(ReduceWord32And) {
  ReducerTester R;
  R.binop = R.machine.Word32And();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) { R.CheckFoldBinop<int32_t>(x & y, x, y); }
  }

  R.CheckPutConstantOnRight(33);
  R.CheckPutConstantOnRight(44000);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int32_t>(0);
  Node* minus_1 = R.Constant<int32_t>(-1);

  R.CheckBinop(zero, x, zero);  // x  & 0  => 0
  R.CheckBinop(zero, zero, x);  // 0  & x  => 0
  R.CheckBinop(x, x, minus_1);  // x  & -1 => 0
  R.CheckBinop(x, minus_1, x);  // -1 & x  => 0
  R.CheckBinop(x, x, x);        // x  & x  => x
}


TEST(ReduceWord32Or) {
  ReducerTester R;
  R.binop = R.machine.Word32Or();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) { R.CheckFoldBinop<int32_t>(x | y, x, y); }
  }

  R.CheckPutConstantOnRight(36);
  R.CheckPutConstantOnRight(44001);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int32_t>(0);
  Node* minus_1 = R.Constant<int32_t>(-1);

  R.CheckBinop(x, x, zero);           // x  & 0  => x
  R.CheckBinop(x, zero, x);           // 0  & x  => x
  R.CheckBinop(minus_1, x, minus_1);  // x  & -1 => -1
  R.CheckBinop(minus_1, minus_1, x);  // -1 & x  => -1
  R.CheckBinop(x, x, x);              // x  & x  => x
}


TEST(ReduceWord32Xor) {
  ReducerTester R;
  R.binop = R.machine.Word32Xor();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) { R.CheckFoldBinop<int32_t>(x ^ y, x, y); }
  }

  R.CheckPutConstantOnRight(39);
  R.CheckPutConstantOnRight(4403);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int32_t>(0);

  R.CheckBinop(x, x, zero);            // x ^ 0  => x
  R.CheckBinop(x, zero, x);            // 0 ^ x  => x
  R.CheckFoldBinop<int32_t>(0, x, x);  // x ^ x  => 0
}


TEST(ReduceWord32Shl) {
  ReducerTester R;
  R.binop = R.machine.Word32Shl();

  // TODO(titzer): out of range shifts
  FOR_INT32_INPUTS(x) {
    for (int y = 0; y < 32; y++) {
      R.CheckFoldBinop<int32_t>(base::ShlWithWraparound(x, y), x, y);
    }
  }

  R.CheckDontPutConstantOnRight(44);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int32_t>(0);

  R.CheckBinop(x, x, zero);  // x << 0  => x
}

TEST(ReduceWord64Shl) {
  ReducerTester R;
  R.binop = R.machine.Word64Shl();

  FOR_INT64_INPUTS(x) {
    for (int64_t y = 0; y < 64; y++) {
      R.CheckFoldBinop<int64_t>(base::ShlWithWraparound(x, y), x, y);
    }
  }

  R.CheckDontPutConstantOnRight(44);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int64_t>(0);

  R.CheckBinop(x, x, zero);  // x << 0  => x
}

TEST(ReduceWord32Shr) {
  ReducerTester R;
  R.binop = R.machine.Word32Shr();

  // TODO(titzer): test out of range shifts
  FOR_UINT32_INPUTS(x) {
    for (uint32_t y = 0; y < 32; y++) {
      R.CheckFoldBinop<int32_t>(x >> y, x, y);
    }
  }

  R.CheckDontPutConstantOnRight(44);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int32_t>(0);

  R.CheckBinop(x, x, zero);  // x >>> 0  => x
}

TEST(ReduceWord64Shr) {
  ReducerTester R;
  R.binop = R.machine.Word64Shr();

  FOR_UINT64_INPUTS(x) {
    for (uint64_t y = 0; y < 64; y++) {
      R.CheckFoldBinop<int64_t>(x >> y, x, y);
    }
  }

  R.CheckDontPutConstantOnRight(44);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int64_t>(0);

  R.CheckBinop(x, x, zero);  // x >>> 0  => x
}

TEST(ReduceWord32Sar) {
  ReducerTester R;
  R.binop = R.machine.Word32Sar();

  // TODO(titzer): test out of range shifts
  FOR_INT32_INPUTS(x) {
    for (int32_t y = 0; y < 32; y++) {
      R.CheckFoldBinop<int32_t>(x >> y, x, y);
    }
  }

  R.CheckDontPutConstantOnRight(44);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int32_t>(0);

  R.CheckBinop(x, x, zero);  // x >> 0  => x
}

TEST(ReduceWord64Sar) {
  ReducerTester R;
  R.binop = R.machine.Word64Sar();

  FOR_INT64_INPUTS(x) {
    for (int64_t y = 0; y < 64; y++) {
      R.CheckFoldBinop<int64_t>(x >> y, x, y);
    }
  }

  R.CheckDontPutConstantOnRight(44);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int64_t>(0);

  R.CheckBinop(x, x, zero);  // x >> 0  => x
}

static void CheckJsShift(ReducerTester* R) {
  CHECK(R->machine.Word32ShiftIsSafe());

  Node* x = R->Parameter(0);
  Node* y = R->Parameter(1);
  Node* thirty_one = R->Constant<int32_t>(0x1F);
  Node* y_and_thirty_one =
      R->graph.NewNode(R->machine.Word32And(), y, thirty_one);

  // If the underlying machine shift instructions 'and' their right operand
  // with 0x1F then:  x << (y & 0x1F) => x << y
  R->CheckFoldBinop(x, y, x, y_and_thirty_one);
}


TEST(ReduceJsShifts) {
  ReducerTester R(0, MachineOperatorBuilder::kWord32ShiftIsSafe);

  R.binop = R.machine.Word32Shl();
  CheckJsShift(&R);

  R.binop = R.machine.Word32Shr();
  CheckJsShift(&R);

  R.binop = R.machine.Word32Sar();
  CheckJsShift(&R);
}


TEST(Word32Equal) {
  ReducerTester R;
  R.binop = R.machine.Word32Equal();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) { R.CheckFoldBinop<int32_t>(x == y ? 1 : 0, x, y); }
  }

  R.CheckPutConstantOnRight(48);
  R.CheckPutConstantOnRight(-48);

  Node* x = R.Parameter(0);
  Node* y = R.Parameter(1);
  Node* zero = R.Constant<int32_t>(0);
  Node* sub = R.graph.NewNode(R.machine.Int32Sub(), x, y);

  R.CheckFoldBinop<int32_t>(1, x, x);  // x == x  => 1
  R.CheckFoldBinop(x, y, sub, zero);   // x - y == 0  => x == y
  R.CheckFoldBinop(x, y, zero, sub);   // 0 == x - y  => x == y
}


TEST(ReduceInt32Add) {
  ReducerTester R;
  R.binop = R.machine.Int32Add();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) {
      R.CheckFoldBinop<int32_t>(base::AddWithWraparound(x, y), x, y);
    }
  }

  R.CheckPutConstantOnRight(41);
  R.CheckPutConstantOnRight(4407);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int32_t>(0);

  R.CheckBinop(x, x, zero);  // x + 0  => x
  R.CheckBinop(x, zero, x);  // 0 + x  => x
}

TEST(ReduceInt64Add) {
  ReducerTester R;
  R.binop = R.machine.Int64Add();

  FOR_INT64_INPUTS(x) {
    FOR_INT64_INPUTS(y) {
      R.CheckFoldBinop<int64_t>(base::AddWithWraparound(x, y), x, y);
    }
  }

  R.CheckPutConstantOnRight(41);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int64_t>(0);
  R.CheckBinop(x, x, zero);  // x + 0 => x
  R.CheckBinop(x, zero, x);  // 0 + x => x
}

TEST(ReduceInt32Sub) {
  ReducerTester R;
  R.binop = R.machine.Int32Sub();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) {
      R.CheckFoldBinop<int32_t>(base::SubWithWraparound(x, y), x, y);
    }
  }

  R.CheckDontPutConstantOnRight(412);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int32_t>(0);

  R.CheckBinop(x, x, zero);  // x - 0  => x
}

TEST(ReduceInt64Sub) {
  ReducerTester R;
  R.binop = R.machine.Int64Sub();

  FOR_INT64_INPUTS(x) {
    FOR_INT64_INPUTS(y) {
      R.CheckFoldBinop<int64_t>(base::SubWithWraparound(x, y), x, y);
    }
  }

  R.CheckDontPutConstantOnRight(42);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int64_t>(0);

  R.CheckBinop(x, x, zero);            // x - 0 => x
  R.CheckFoldBinop<int64_t>(0, x, x);  // x - x => 0

  Node* k = R.Constant<int64_t>(6);

  R.CheckFoldBinop<int64_t>(x, R.machine.Int64Add(), -6, x,
                            k);  // x - K => x + -K
}

TEST(ReduceInt32Mul) {
  ReducerTester R;
  R.binop = R.machine.Int32Mul();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) {
      R.CheckFoldBinop<int32_t>(base::MulWithWraparound(x, y), x, y);
    }
  }

  R.CheckPutConstantOnRight(4111);
  R.CheckPutConstantOnRight(-4407);

  Node* x = R.Parameter();
  Node* zero = R.Constant<int32_t>(0);
  Node* one = R.Constant<int32_t>(1);
  Node* minus_one = R.Constant<int32_t>(-1);

  R.CheckBinop(zero, x, zero);  // x * 0  => 0
  R.CheckBinop(zero, zero, x);  // 0 * x  => 0
  R.CheckBinop(x, x, one);      // x * 1  => x
  R.CheckBinop(x, one, x);      // 1 * x  => x
  R.CheckFoldBinop<int32_t>(0, R.machine.Int32Sub(), x, minus_one,
                            x);  // -1 * x  => 0 - x
  R.CheckFoldBinop<int32_t>(0, R.machine.Int32Sub(), x, x,
                            minus_one);  // x * -1  => 0 - x

  for (int32_t n = 1; n < 31; ++n) {
    Node* multiplier = R.Constant<int32_t>(1 << n);
    R.CheckFoldBinop<int32_t>(x, R.machine.Word32Shl(), n, x,
                              multiplier);  // x * 2^n => x << n
    R.CheckFoldBinop<int32_t>(x, R.machine.Word32Shl(), n, multiplier,
                              x);  // 2^n * x => x << n
  }
}


TEST(ReduceInt32Div) {
  ReducerTester R;
  R.binop = R.machine.Int32Div();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) {
      if (y == 0) continue;              // TODO(titzer): test / 0
      int32_t r = y == -1 ? base::NegateWithWraparound(x)
                          : x / y;  // INT_MIN / -1 may explode in C
      R.CheckFoldBinop<int32_t>(r, x, y);
    }
  }

  R.CheckDontPutConstantOnRight(41111);
  R.CheckDontPutConstantOnRight(-44071);

  Node* x = R.Parameter();
  Node* one = R.Constant<int32_t>(1);
  Node* minus_one = R.Constant<int32_t>(-1);

  R.CheckBinop(x, x, one);  // x / 1  => x
  // TODO(titzer):                          // 0 / x  => 0 if x != 0
  // TODO(titzer):                          // x / 2^n => x >> n and round
  R.CheckFoldBinop<int32_t>(0, R.machine.Int32Sub(), x, x,
                            minus_one);  // x / -1  => 0 - x
}


TEST(ReduceUint32Div) {
  ReducerTester R;
  R.binop = R.machine.Uint32Div();

  FOR_UINT32_INPUTS(x) {
    FOR_UINT32_INPUTS(y) {
      if (y == 0) continue;  // TODO(titzer): test / 0
      R.CheckFoldBinop<int32_t>(x / y, x, y);
    }
  }

  R.CheckDontPutConstantOnRight(41311);
  R.CheckDontPutConstantOnRight(-44371);

  Node* x = R.Parameter();
  Node* one = R.Constant<int32_t>(1);

  R.CheckBinop(x, x, one);  // x / 1  => x
  // TODO(titzer):                            // 0 / x  => 0 if x != 0

  for (uint32_t n = 1; n < 32; ++n) {
    Node* divisor = R.Constant<int32_t>(1u << n);
    R.CheckFoldBinop<int32_t>(x, R.machine.Word32Shr(), n, x,
                              divisor);  // x / 2^n => x >> n
  }
}


TEST(ReduceInt32Mod) {
  ReducerTester R;
  R.binop = R.machine.Int32Mod();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) {
      if (y == 0) continue;             // TODO(titzer): test % 0
      int32_t r = y == -1 ? 0 : x % y;  // INT_MIN % -1 may explode in C
      R.CheckFoldBinop<int32_t>(r, x, y);
    }
  }

  R.CheckDontPutConstantOnRight(413);
  R.CheckDontPutConstantOnRight(-4401);

  Node* x = R.Parameter();
  Node* one = R.Constant<int32_t>(1);

  R.CheckFoldBinop<int32_t>(0, x, one);  // x % 1  => 0
  // TODO(titzer):                       // x % 2^n => x & 2^n-1 and round
}


TEST(ReduceUint32Mod) {
  ReducerTester R;
  R.binop = R.machine.Uint32Mod();

  FOR_UINT32_INPUTS(x) {
    FOR_UINT32_INPUTS(y) {
      if (y == 0) continue;  // TODO(titzer): test x % 0
      R.CheckFoldBinop<int32_t>(x % y, x, y);
    }
  }

  R.CheckDontPutConstantOnRight(417);
  R.CheckDontPutConstantOnRight(-4371);

  Node* x = R.Parameter();
  Node* one = R.Constant<int32_t>(1);

  R.CheckFoldBinop<int32_t>(0, x, one);  // x % 1  => 0

  for (uint32_t n = 1; n < 32; ++n) {
    Node* divisor = R.Constant<int32_t>(1u << n);
    R.CheckFoldBinop<int32_t>(x, R.machine.Word32And(), (1u << n) - 1, x,
                              divisor);  // x % 2^n => x & 2^n-1
  }
}


TEST(ReduceInt32LessThan) {
  ReducerTester R;
  R.binop = R.machine.Int32LessThan();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) { R.CheckFoldBinop<int32_t>(x < y ? 1 : 0, x, y); }
  }

  R.CheckDontPutConstantOnRight(41399);
  R.CheckDontPutConstantOnRight(-440197);

  Node* x = R.Parameter(0);

  R.CheckFoldBinop<int32_t>(0, x, x);  // x < x  => 0
}


TEST(ReduceInt32LessThanOrEqual) {
  ReducerTester R;
  R.binop = R.machine.Int32LessThanOrEqual();

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) { R.CheckFoldBinop<int32_t>(x <= y ? 1 : 0, x, y); }
  }

  FOR_INT32_INPUTS(i) { R.CheckDontPutConstantOnRight<int32_t>(i); }

  Node* x = R.Parameter(0);

  R.CheckFoldBinop<int32_t>(1, x, x);  // x <= x => 1
}


TEST(ReduceUint32LessThan) {
  ReducerTester R;
  R.binop = R.machine.Uint32LessThan();

  FOR_UINT32_INPUTS(x) {
    FOR_UINT32_INPUTS(y) { R.CheckFoldBinop<int32_t>(x < y ? 1 : 0, x, y); }
  }

  R.CheckDontPutConstantOnRight(41399);
  R.CheckDontPutConstantOnRight(-440197);

  Node* x = R.Parameter();
  Node* max = R.maxuint32;
  Node* zero = R.Constant<int32_t>(0);

  R.CheckFoldBinop<int32_t>(0, max, x);   // M < x  => 0
  R.CheckFoldBinop<int32_t>(0, x, zero);  // x < 0  => 0
  R.CheckFoldBinop<int32_t>(0, x, x);     // x < x  => 0
}


TEST(ReduceUint32LessThanOrEqual) {
  ReducerTester R;
  R.binop = R.machine.Uint32LessThanOrEqual();

  FOR_UINT32_INPUTS(x) {
    FOR_UINT32_INPUTS(y) { R.CheckFoldBinop<int32_t>(x <= y ? 1 : 0, x, y); }
  }

  R.CheckDontPutConstantOnRight(41399);
  R.CheckDontPutConstantOnRight(-440197);

  Node* x = R.Parameter();
  Node* max = R.maxuint32;
  Node* zero = R.Constant<int32_t>(0);

  R.CheckFoldBinop<int32_t>(1, x, max);   // x <= M  => 1
  R.CheckFoldBinop<int32_t>(1, zero, x);  // 0 <= x  => 1
  R.CheckFoldBinop<int32_t>(1, x, x);     // x <= x  => 1
}


TEST(ReduceLoadStore) {
  ReducerTester R;

  Node* base = R.Constant<int32_t>(11);
  Node* index = R.Constant<int32_t>(4);
  Node* load = R.graph.NewNode(R.machine.Load(MachineType::Int32()), base,
                               index, R.graph.start(), R.graph.start());

  {
    MachineOperatorReducer reducer(
        &R.graph_reducer, &R.jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    Reduction reduction = reducer.Reduce(load);
    CHECK(!reduction.Changed());  // loads should not be reduced.
  }

  {
    Node* store =
        R.graph.NewNode(R.machine.Store(StoreRepresentation(
                            MachineRepresentation::kWord32, kNoWriteBarrier)),
                        base, index, load, load, R.graph.start());
    MachineOperatorReducer reducer(
        &R.graph_reducer, &R.jsgraph,
        MachineOperatorReducer::kPropagateSignallingNan);
    Reduction reduction = reducer.Reduce(store);
    CHECK(!reduction.Changed());  // stores should not be reduced.
  }
}

TEST(ReduceFloat32Sub) {
  ReducerTester R;
  R.binop = R.machine.Float32Sub();

  FOR_FLOAT32_INPUTS(x) {
    FOR_FLOAT32_INPUTS(y) { R.CheckFoldBinop<float>(x - y, x, y); }
  }

  Node* x = R.Parameter();
  Node* nan = R.Constant<float>(std::numeric_limits<float>::quiet_NaN());

  // nan - x  => nan
  R.CheckFoldBinop(std::numeric_limits<float>::quiet_NaN(), nan, x);
  // x - nan => nan
  R.CheckFoldBinop(std::numeric_limits<float>::quiet_NaN(), x, nan);
}

TEST(ReduceFloat64Sub) {
  ReducerTester R;
  R.binop = R.machine.Float64Sub();

  FOR_FLOAT64_INPUTS(x) {
    FOR_FLOAT64_INPUTS(y) { R.CheckFoldBinop<double>(x - y, x, y); }
  }

  Node* x = R.Parameter();
  Node* nan = R.Constant<double>(std::numeric_limits<double>::quiet_NaN());

  // nan - x  => nan
  R.CheckFoldBinop(std::numeric_limits<double>::quiet_NaN(), nan, x);
  // x - nan => nan
  R.CheckFoldBinop(std::numeric_limits<double>::quiet_NaN(), x, nan);
}

// TODO(titzer): test MachineOperatorReducer for Word64And
// TODO(titzer): test MachineOperatorReducer for Word64Or
// TODO(titzer): test MachineOperatorReducer for Word64Xor
// TODO(titzer): test MachineOperatorReducer for Word64Equal
// TODO(titzer): test MachineOperatorReducer for Word64Not
// TODO(titzer): test MachineOperatorReducer for Int64Mul
// TODO(titzer): test MachineOperatorReducer for Int64UMul
// TODO(titzer): test MachineOperatorReducer for Int64Div
// TODO(titzer): test MachineOperatorReducer for Uint64Div
// TODO(titzer): test MachineOperatorReducer for Int64Mod
// TODO(titzer): test MachineOperatorReducer for Uint64Mod
// TODO(titzer): test MachineOperatorReducer for Int64Neg
// TODO(titzer): test MachineOperatorReducer for ChangeInt32ToFloat64
// TODO(titzer): test MachineOperatorReducer for ChangeFloat64ToInt32
// TODO(titzer): test MachineOperatorReducer for Float64Compare
// TODO(titzer): test MachineOperatorReducer for Float64Add
// TODO(titzer): test MachineOperatorReducer for Float64Sub
// TODO(titzer): test MachineOperatorReducer for Float64Mul
// TODO(titzer): test MachineOperatorReducer for Float64Div
// TODO(titzer): test MachineOperatorReducer for Float64Mod

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```