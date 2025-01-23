Response: The user wants a summary of the C++ source code file `v8/test/cctest/torque/test-torque.cc`.
The file appears to contain a series of C++ tests for the Torque language within the V8 JavaScript engine.

**Plan:**
1. Identify the main purpose of the file.
2. Describe the structure of the tests.
3. List some of the specific features of Torque that are being tested.
4. Determine if the file relates to JavaScript functionality.
5. Provide JavaScript examples to illustrate the connection.
这个C++源代码文件 `v8/test/cctest/torque/test-torque.cc` 的主要功能是**测试 V8 JavaScript 引擎中 Torque 语言的各种特性和功能**。

Torque 是一种用于编写 V8 引擎内部 Builtin 函数的领域特定语言 (DSL)。这个测试文件通过定义一系列 C++ 测试用例，来验证 Torque 编译生成的代码是否按照预期工作。

**主要功能归纳:**

1. **定义 `TestTorqueAssembler` 类:**  这是一个继承自 `CodeStubAssembler` 的类，专门用于在测试中构建 Torque 代码。
2. **包含多个 `TEST` 宏定义的测试用例:**  每个 `TEST` 宏定义一个独立的测试，针对 Torque 的特定功能点。
3. **使用 `CodeAssemblerTester`:**  这是一个辅助类，用于在 C++ 测试环境中构建和执行 Torque 代码。
4. **调用 `TestTorqueAssembler` 的方法:**  每个测试用例会调用 `TestTorqueAssembler` 类中以 `Test` 开头的方法（这些方法在其他地方定义，很可能是在与此测试文件同目录下的 `.tq` 文件中，由 Torque 编译器生成）。
5. **断言和检查:**  测试用例通常会使用 `FunctionTester` 来调用生成的代码，并使用 `CHECK_EQ` 或 `CSA_DCHECK` 等宏来验证执行结果是否符合预期。
6. **涵盖 Torque 的多种特性:**  从测试用例的名称可以看出，它涵盖了 Torque 的常量表达式、控制流 (goto, if, for loop)、函数指针、泛型、类型转换、位域操作、结构体、类、异常处理 (catch)、内置函数调用、懒加载、内存管理 (pretenuring) 等等。

**与 JavaScript 的关系及 JavaScript 示例:**

Torque 的主要目的是编写 V8 引擎的内置函数，这些内置函数是 JavaScript 语言的基础组成部分。因此，这个测试文件间接地测试了 JavaScript 的功能，因为它验证了这些底层内置函数的正确性。

**一些测试用例与 JavaScript 功能的关联举例：**

* **`TEST(TestBuiltinSpecialization)` 和 `TEST(TestMacroSpecialization)`:**  Torque 允许对内置函数和宏进行特化，这意味着可以根据参数的类型执行不同的代码路径。这直接影响 JavaScript 中函数的执行效率和行为，例如，V8 会针对不同类型的参数优化内置方法，如 `Array.prototype.map`。

  ```javascript
  // JavaScript 例子，体现了内置函数可能存在的特化
  function add(a, b) {
    return a + b;
  }

  console.log(add(1, 2));      // 数字相加
  console.log(add("hello", " world")); // 字符串拼接
  ```

* **`TEST(TestTernaryOperator)`:**  测试 Torque 中三元运算符的实现，这对应于 JavaScript 中的 `condition ? valueIfTrue : valueIfFalse`。

  ```javascript
  // JavaScript 三元运算符
  let age = 20;
  let status = age >= 18 ? "Adult" : "Minor";
  console.log(status); // 输出 "Adult"
  ```

* **`TEST(TestForLoop)`:**  测试 Torque 中 `for` 循环的实现，这对应于 JavaScript 中的 `for` 循环。

  ```javascript
  // JavaScript for 循环
  for (let i = 0; i < 5; i++) {
    console.log(i);
  }
  ```

* **`TEST(TestTypeswitch)`:** 测试 Torque 中的类型切换功能，这类似于 JavaScript 中根据变量类型执行不同操作的场景。

  ```javascript
  // JavaScript 类型判断
  function processValue(value) {
    if (typeof value === 'number') {
      console.log("It's a number:", value * 2);
    } else if (typeof value === 'string') {
      console.log("It's a string:", value.toUpperCase());
    } else {
      console.log("Unknown type");
    }
  }

  processValue(10);
  processValue("test");
  ```

* **`TEST(TestCatch1)`, `TEST(TestCatch2)`, `TEST(TestCatch3)`:** 测试 Torque 中的异常捕获机制，对应于 JavaScript 中的 `try...catch` 语句。

  ```javascript
  // JavaScript try...catch
  try {
    // 可能会抛出异常的代码
    throw new Error("Something went wrong!");
  } catch (error) {
    console.error("Caught an error:", error.message);
  }
  ```

总而言之，`v8/test/cctest/torque/test-torque.cc` 是 V8 引擎中一个非常重要的测试文件，它确保了 Torque 语言及其生成的代码能够正确地实现 JavaScript 的各种底层功能，从而保证 JavaScript 语言的稳定性和性能。 这些测试覆盖了 Torque 语言的语法和语义，以及它与 V8 引擎内部机制的交互。

### 提示词
```
这是目录为v8/test/cctest/torque/test-torque.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cmath>

#include "src/api/api-inl.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/builtins-promise-gen.h"
#include "src/builtins/builtins-string-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/compiler/node.h"
#include "src/debug/debug.h"
#include "src/execution/isolate.h"
#include "src/objects/elements-kind.h"
#include "src/objects/objects-inl.h"
#include "src/objects/promise-inl.h"
#include "src/objects/torque-defined-classes-inl.h"
#include "src/strings/char-predicates.h"
#include "test/cctest/compiler/function-tester.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/common/code-assembler-tester.h"

namespace v8 {
namespace internal {
namespace compiler {

#include "src/codegen/define-code-stub-assembler-macros.inc"

namespace {

class TestTorqueAssembler : public CodeStubAssembler {
 public:
  explicit TestTorqueAssembler(CodeAssemblerState* state)
      : CodeStubAssembler(state) {}
};

}  // namespace

TEST(TestConstexpr1) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestConstexpr1();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestConstexprIf) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestConstexprIf();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestConstexprReturn) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestConstexprReturn();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestGotoLabel) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  { m.Return(m.TestGotoLabel()); }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.CheckCall(ft.true_value());
}

TEST(TestGotoLabelWithOneParameter) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  { m.Return(m.TestGotoLabelWithOneParameter()); }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.CheckCall(ft.true_value());
}

TEST(TestGotoLabelWithTwoParameters) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  { m.Return(m.TestGotoLabelWithTwoParameters()); }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.CheckCall(ft.true_value());
}

TEST(TestPartiallyUnusedLabel) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  { m.Return(m.TestPartiallyUnusedLabel()); }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.CheckCall(ft.true_value());
}

TEST(TestBuiltinSpecialization) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestBuiltinSpecialization();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestMacroSpecialization) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestMacroSpecialization();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestFunctionPointers) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    auto context = m.GetJSContextParameter();
    m.Return(m.TestFunctionPointers(context));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.CheckCall(ft.true_value());
}

TEST(TestTernaryOperator) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    TNode<Smi> arg = m.Parameter<Smi>(1);
    m.Return(m.TestTernaryOperator(arg));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result1 =
      ft.Call(Handle<Smi>(Smi::FromInt(-5), isolate)).ToHandleChecked();
  CHECK_EQ(-15, Cast<Smi>(*result1).value());
  DirectHandle<Object> result2 =
      ft.Call(Handle<Smi>(Smi::FromInt(3), isolate)).ToHandleChecked();
  CHECK_EQ(103, Cast<Smi>(*result2).value());
}

TEST(TestFunctionPointerToGeneric) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestFunctionPointerToGeneric();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestUnsafeCast) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    TNode<Object> temp = m.SmiConstant(0);
    TNode<Smi> n = m.SmiConstant(10);
    m.Return(m.TestUnsafeCast(m.UncheckedCast<Context>(temp),
                              m.UncheckedCast<Number>(n)));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.CheckCall(ft.true_value());
}

TEST(TestHexLiteral) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestHexLiteral();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestModuleConstBindings) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestModuleConstBindings();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestLocalConstBindings) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestLocalConstBindings();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestForLoop) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestForLoop();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestTypeswitch) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestTypeswitch(m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestGenericOverload) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestGenericOverload(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestEquality) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestEquality(m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestLogicalOperators) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestLogicalOperators();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestOtherwiseAndLabels) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestOtherwiseWithCode1();
    m.TestOtherwiseWithCode2();
    m.TestOtherwiseWithCode3();
    m.TestForwardLabel();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestCatch1) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    TNode<Smi> result =
        m.TestCatch1(m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    USE(result);
    CSA_DCHECK(&m, m.TaggedEqual(result, m.SmiConstant(1)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestCatch2) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    TNode<Smi> result =
        m.TestCatch2(m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    USE(result);
    CSA_DCHECK(&m, m.TaggedEqual(result, m.SmiConstant(2)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestCatch3) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    TNode<Smi> result =
        m.TestCatch3(m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    USE(result);
    CSA_DCHECK(&m, m.TaggedEqual(result, m.SmiConstant(2)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestLookup) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestQualifiedAccess(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestFrame1) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestFrame1(m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestNew) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestNew(m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestStructConstructor) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestStructConstructor(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestInternalClass) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestInternalClass(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestNewFixedArrayFromSpread) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestNewFixedArrayFromSpread(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestReferences) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestReferences();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestSlices) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestSlices();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestSliceEnumeration) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestSliceEnumeration(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestStaticAssert) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestStaticAssert();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestLoadEliminationFixed) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestLoadEliminationFixed(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  asm_tester.GenerateCode();
}

TEST(TestLoadEliminationVariable) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestLoadEliminationVariable(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  asm_tester.GenerateCode();
}

TEST(TestRedundantArrayElementCheck) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.Return(m.TestRedundantArrayElementCheck(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context))));
  }
  asm_tester.GenerateCode();
}

TEST(TestRedundantSmiCheck) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.Return(m.TestRedundantSmiCheck(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context))));
  }
  asm_tester.GenerateCode();
}

TEST(TestGenericStruct1) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestGenericStruct1();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestGenericStruct2) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  CodeAssemblerTester asm_tester(isolate);
  TestTorqueAssembler m(asm_tester.state());
  { m.Return(m.TestGenericStruct2().snd.fst); }
  FunctionTester ft(asm_tester.GenerateCode(), 0);
  ft.Call();
}

TEST(TestBranchOnBoolOptimization) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestBranchOnBoolOptimization(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)),
        m.UncheckedParameter<Smi>(0));
    m.Return(m.UndefinedConstant());
  }
  asm_tester.GenerateCode();
}

TEST(TestBitFieldLoad) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 5;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    // Untag all of the parameters to get plain integer values.
    TNode<Uint8T> val =
        m.UncheckedCast<Uint8T>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(1))));
    TNode<BoolT> expected_a =
        m.UncheckedCast<BoolT>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(2))));
    TNode<Uint16T> expected_b =
        m.UncheckedCast<Uint16T>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(3))));
    TNode<Uint32T> expected_c =
        m.UncheckedCast<Uint32T>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(4))));
    TNode<BoolT> expected_d =
        m.UncheckedCast<BoolT>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(5))));

    // Call the Torque-defined macro, which verifies that reading each bitfield
    // out of val yields the correct result.
    m.TestBitFieldLoad(val, expected_a, expected_b, expected_c, expected_d);
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  // Test every possible bit combination for this 8-bit value.
  for (int a = 0; a <= 1; ++a) {
    for (int b = 0; b <= 7; ++b) {
      for (int c = 0; c <= 7; ++c) {
        for (int d = 0; d <= 1; ++d) {
          int val = a | ((b & 7) << 1) | (c << 4) | (d << 7);
          ft.Call(ft.Val(val), ft.Val(a), ft.Val(b), ft.Val(c), ft.Val(d));
        }
      }
    }
  }
}

TEST(TestBitFieldStore) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    // Untag the parameters to get a plain integer value.
    TNode<Uint8T> val =
        m.UncheckedCast<Uint8T>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(1))));

    m.TestBitFieldStore(val);
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  // Test every possible bit combination for this 8-bit value.
  for (int i = 0; i < 256; ++i) {
    ft.Call(ft.Val(i));
  }
}

TEST(TestBitFieldInit) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 4;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    // Untag all of the parameters to get plain integer values.
    TNode<BoolT> a =
        m.UncheckedCast<BoolT>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(1))));
    TNode<Uint16T> b =
        m.UncheckedCast<Uint16T>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(2))));
    TNode<Uint32T> c =
        m.UncheckedCast<Uint32T>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(3))));
    TNode<BoolT> d =
        m.UncheckedCast<BoolT>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(4))));

    // Call the Torque-defined macro, which verifies that reading each bitfield
    // out of val yields the correct result.
    m.TestBitFieldInit(a, b, c, d);
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  // Test every possible bit combination for this 8-bit value.
  for (int a = 0; a <= 1; ++a) {
    for (int b = 0; b <= 7; ++b) {
      for (int c = 0; c <= 7; ++c) {
        for (int d = 0; d <= 1; ++d) {
          ft.Call(ft.Val(a), ft.Val(b), ft.Val(c), ft.Val(d));
        }
      }
    }
  }
}

TEST(TestBitFieldUintptrOps) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    // Untag the parameters to get a plain integer value.
    TNode<Uint32T> val2 =
        m.UncheckedCast<Uint32T>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(1))));
    TNode<UintPtrT> val3 = m.UncheckedCast<UintPtrT>(
        m.ChangeUint32ToWord(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(2)))));

    m.TestBitFieldUintptrOps(val2, val3);
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  // Construct the expected test values.
  int val2 = 3 | (61 << 5);
  int val3 = 1 | (500 << 1) | (0x1cc << 10);

  ft.Call(ft.Val(val2), ft.Val(val3));
}

TEST(TestBitFieldMultipleFlags) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    TNode<BoolT> a =
        m.UncheckedCast<BoolT>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(0))));
    TNode<Int32T> b = m.SmiToInt32(m.Parameter<Smi>(1));
    TNode<BoolT> c =
        m.UncheckedCast<BoolT>(m.Unsigned(m.SmiToInt32(m.Parameter<Smi>(2))));
    m.TestBitFieldMultipleFlags(a, b, c);
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  // No need to call it; we just checked StaticAsserts during compilation.
}

TEST(TestTestParentFrameArguments) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  Handle<Context> context =
      Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestParentFrameArguments(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  asm_tester.GenerateCode();
}

TEST(TestFullyGeneratedClassFromCpp) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  { m.Return(m.TestFullyGeneratedClassFromCpp()); }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<ExportedSubClass> result =
      Cast<ExportedSubClass>(ft.Call().ToHandleChecked());
  CHECK_EQ(result->c_field(), 7);
  CHECK_EQ(result->d_field(), 8);
  CHECK_EQ(result->e_field(), 9);
}

TEST(TestGeneratedCastOperators) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    Handle<Context> context =
        Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
    m.TestGeneratedCastOperators(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestNewPretenured) {
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    Handle<Context> context =
        Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
    m.TestNewPretenured(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestWord8Phi) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestWord8Phi();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestOffHeapSlice) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  std::string data = "Hello World!";
  {
    m.TestOffHeapSlice(m.PointerConstant(const_cast<char*>(data.data())),
                       m.IntPtrConstant(data.size()));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestCallMultiReturnBuiltin) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    Handle<Context> context =
        Utils::OpenHandle(*v8::Isolate::GetCurrent()->GetCurrentContext());
    m.TestCallMultiReturnBuiltin(
        m.UncheckedCast<Context>(m.HeapConstantNoHole(context)));
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestRunLazyTwice) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  int lazyNumber = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    CodeStubAssembler::LazyNode<Smi> lazy = [&]() {
      return m.SmiConstant(lazyNumber++);
    };
    m.Return(m.TestRunLazyTwice(lazy));
  }
  CHECK_EQ(lazyNumber, 5);
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result = ft.Call().ToHandleChecked();
  CHECK_EQ(7, Cast<Smi>(*result).value());
}

TEST(TestCreateLazyNodeFromTorque) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    m.TestCreateLazyNodeFromTorque();
    m.Return(m.UndefinedConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call();
}

TEST(TestReturnNever_NotCalled) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    auto context = m.GetJSContextParameter();
    TNode<Smi> arg = m.SmiConstant(42);
    TNode<Object> result = m.CallBuiltin(Builtin::kTestCallNever, context, arg);
    m.Return(result);
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result = ft.Call().ToHandleChecked();
  CHECK_EQ(42, Cast<Smi>(*result).value());
}

// Test calling a builtin that calls a runtime fct with return type {never}.
TEST(TestReturnNever_Runtime_Called) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    auto context = m.GetJSContextParameter();
    TNode<Smi> arg = m.SmiConstant(1);
    TNode<Object> result = m.CallBuiltin(Builtin::kTestCallNever, context, arg);
    m.Return(result);
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  MaybeHandle<Object> result = ft.Call();
  CHECK(result.is_null());
  CHECK(isolate->has_exception());
}

// Test calling a builtin that calls another builtin with return type {never}.
TEST(TestReturnNever_Builtin_Called) {
  CcTest::InitializeVM();
  Isolate* isolate(CcTest::i_isolate());
  i::HandleScope scope(isolate);
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    auto context = m.GetJSContextParameter();
    TNode<Smi> arg = m.SmiConstant(-1);
    TNode<Object> result = m.CallBuiltin(Builtin::kTestCallNever, context, arg);
    m.Return(result);
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  MaybeHandle<Object> result = ft.Call();
  CHECK(result.is_null());
  CHECK(isolate->has_exception());
}

int* global_use_counts = nullptr;

void MockUseCounterCallback(v8::Isolate* isolate,
                            v8::Isolate::UseCounterFeature feature) {
  ++global_use_counts[feature];
}

// Test @incrementUseCounter
TEST(TestIncrementUseCounterInBuiltin) {
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;
  int use_counts[v8::Isolate::kUseCounterFeatureCount] = {};
  global_use_counts = use_counts;
  CcTest::isolate()->SetUseCounterCallback(MockUseCounterCallback);

  Isolate* i_isolate(CcTest::i_isolate());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(i_isolate, JSParameterCount(kNumParams));
  TestTorqueAssembler m(asm_tester.state());
  {
    auto context = m.GetJSContextParameter();
    TNode<Object> result =
        m.CallBuiltin(Builtin::kTestIncrementArraySpeciesModified, context);
    m.Return(result);
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(0, use_counts[v8::Isolate::kArraySpeciesModified]);
  ft.Call();
  CHECK_EQ(1, use_counts[v8::Isolate::kArraySpeciesModified]);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```