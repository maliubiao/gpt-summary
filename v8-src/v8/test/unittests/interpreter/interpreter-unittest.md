Response: The user wants a summary of the C++ source code file `v8/test/unittests/interpreter/interpreter-unittest.cc`.
The file seems to be testing the interpreter of the V8 JavaScript engine.
It contains several test cases that verify the functionality of different bytecode instructions.
The instructions cover basic operations like loading constants, arithmetic operations, property access, function calls, and control flow.
The tests also check the type feedback mechanism of the interpreter.
The user also wants an example in Javascript to show the relation between the C++ code and Javascript functionality.

Plan:
1. Summarize the overall purpose of the file.
2. Identify the main categories of tests in the file.
3. Provide a concise description of the functionalities being tested.
4. Create a Javascript example that demonstrates a concept tested in the C++ file.
这是 V8 JavaScript 引擎中解释器部分的单元测试文件。它的主要功能是测试解释器执行各种字节码指令的正确性。

这个文件通过编写一系列的 C++ 测试用例来模拟不同的 JavaScript 代码片段在解释器中执行的过程，并验证执行结果是否符合预期。每个 `TEST_F` 宏定义一个独立的测试用例，用于测试特定的字节码指令或指令组合。

这些测试用例涵盖了 JavaScript 的基本功能，例如：

* **常量加载:**  测试加载 `undefined`, `null`, 布尔值，数字（Smi 和 HeapNumber），字符串等字面量。
* **寄存器操作:** 测试在解释器内部寄存器中存储和加载值的操作。
* **算术和位运算:** 测试各种算术运算符（加、减、乘、除、取模）和位运算符（位或、位异或、位与、左移、右移、无符号右移）在不同数据类型（Smi 和 HeapNumber）上的执行。
* **类型反馈 (Type Feedback):**  测试解释器如何收集和利用类型信息来优化后续的运算，例如针对 Smi、HeapNumber 和 BigInt 的二元运算。
* **字符串操作:** 测试字符串连接操作。
* **参数传递:** 测试函数调用时参数的传递，包括接收器 (receiver) 和普通参数。
* **全局变量操作:** 测试访问和修改全局变量。
* **属性访问:** 测试访问和设置对象的命名属性和索引属性。
* **函数调用:** 测试调用对象属性上的函数。
* **控制流:** 测试跳转指令（无条件跳转、条件跳转、循环跳转）。

**与 Javascript 的关系及示例：**

这个 C++ 文件中的每一个测试用例都对应着一些底层的字节码指令，而这些字节码指令正是 V8 解释器用来执行 JavaScript 代码的。

例如，在 `TEST_F(InterpreterTest, InterpreterReturn)` 中，测试了 `Return` 字节码指令。这个指令对应着 JavaScript 函数中的 `return` 语句。

**JavaScript 示例：**

```javascript
function testFunction() {
  return; // 对应 C++ 测试中的 builder.Return();
}

console.log(testFunction()); // 输出 undefined
```

在 `TEST_F(InterpreterTest, InterpreterLoadUndefined)` 中，测试了 `LoadUndefined` 字节码指令。这个指令对应着 JavaScript 中的 `undefined` 关键字。

**JavaScript 示例：**

```javascript
function testUndefined() {
  return undefined; // 对应 C++ 测试中的 builder.LoadUndefined();
}

console.log(testUndefined()); // 输出 undefined
```

在 `TEST_F(InterpreterTest, InterpreterBinaryOpsSmi)` 中，测试了针对 Smi (Small Integer) 类型的二元算术运算。例如，测试了加法运算符 (`Token::kAdd`)。

**JavaScript 示例：**

```javascript
function addSmis(a, b) {
  return a + b; // 对应 C++ 测试中的 builder.BinaryOperation(Token::kAdd, ...);
}

console.log(addSmis(5, 3)); // 输出 8
```

总而言之，这个 C++ 文件是 V8 引擎为了保证其 JavaScript 解释器正确运行而编写的重要测试组件。它通过模拟各种 JavaScript 代码场景，从底层字节码指令层面验证了解释器的功能和行为。

Prompt: 
```
这是目录为v8/test/unittests/interpreter/interpreter-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/interpreter/interpreter.h"

#include <tuple>

#include "src/api/api-inl.h"
#include "src/base/overflowing-math.h"
#include "src/codegen/compiler.h"
#include "src/execution/execution.h"
#include "src/handles/handles.h"
#include "src/heap/heap-inl.h"
#include "src/init/v8.h"
#include "src/interpreter/bytecode-array-builder.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/interpreter/bytecode-label.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "test/unittests/interpreter/interpreter-tester.h"

namespace v8 {
namespace internal {
namespace interpreter {

class InterpreterTest : public WithContextMixin<TestWithIsolateAndZone> {
 public:
  Handle<Object> RunBytecode(Handle<BytecodeArray> bytecode_array,
                             MaybeHandle<FeedbackMetadata> feedback_metadata =
                                 MaybeHandle<FeedbackMetadata>()) {
    InterpreterTester tester(i_isolate(), bytecode_array, feedback_metadata);
    auto callable = tester.GetCallable<>();
    return callable().ToHandleChecked();
  }
};

static int GetIndex(FeedbackSlot slot) {
  return FeedbackVector::GetIndex(slot);
}

using ToBooleanMode = BytecodeArrayBuilder::ToBooleanMode;

TEST_F(InterpreterTest, InterpreterReturn) {
  Handle<Object> undefined_value = i_isolate()->factory()->undefined_value();

  BytecodeArrayBuilder builder(zone(), 1, 0);
  builder.Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  Handle<Object> return_val = RunBytecode(bytecode_array);
  CHECK(return_val.is_identical_to(undefined_value));
}

TEST_F(InterpreterTest, InterpreterLoadUndefined) {
  Handle<Object> undefined_value = i_isolate()->factory()->undefined_value();

  BytecodeArrayBuilder builder(zone(), 1, 0);
  builder.LoadUndefined().Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  Handle<Object> return_val = RunBytecode(bytecode_array);
  CHECK(return_val.is_identical_to(undefined_value));
}

TEST_F(InterpreterTest, InterpreterLoadNull) {
  Handle<Object> null_value = i_isolate()->factory()->null_value();

  BytecodeArrayBuilder builder(zone(), 1, 0);
  builder.LoadNull().Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  Handle<Object> return_val = RunBytecode(bytecode_array);
  CHECK(return_val.is_identical_to(null_value));
}

TEST_F(InterpreterTest, InterpreterLoadTheHole) {
  Handle<Object> the_hole_value = i_isolate()->factory()->the_hole_value();

  BytecodeArrayBuilder builder(zone(), 1, 0);
  builder.LoadTheHole().Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  Handle<Object> return_val = RunBytecode(bytecode_array);
  CHECK(return_val.is_identical_to(the_hole_value));
}

TEST_F(InterpreterTest, InterpreterLoadTrue) {
  Handle<Object> true_value = i_isolate()->factory()->true_value();

  BytecodeArrayBuilder builder(zone(), 1, 0);
  builder.LoadTrue().Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  Handle<Object> return_val = RunBytecode(bytecode_array);
  CHECK(return_val.is_identical_to(true_value));
}

TEST_F(InterpreterTest, InterpreterLoadFalse) {
  Handle<Object> false_value = i_isolate()->factory()->false_value();

  BytecodeArrayBuilder builder(zone(), 1, 0);
  builder.LoadFalse().Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  Handle<Object> return_val = RunBytecode(bytecode_array);
  CHECK(return_val.is_identical_to(false_value));
}

TEST_F(InterpreterTest, InterpreterLoadLiteral) {
  // Small Smis.
  for (int i = -128; i < 128; i++) {
    BytecodeArrayBuilder builder(zone(), 1, 0);
    builder.LoadLiteral(Smi::FromInt(i)).Return();
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    DirectHandle<Object> return_val = RunBytecode(bytecode_array);
    CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(i));
  }

  // Large Smis.
  {
    BytecodeArrayBuilder builder(zone(), 1, 0);

    builder.LoadLiteral(Smi::FromInt(0x12345678)).Return();
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    DirectHandle<Object> return_val = RunBytecode(bytecode_array);
    CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(0x12345678));
  }

  // Heap numbers.
  {
    AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                HashSeed(i_isolate()));

    BytecodeArrayBuilder builder(zone(), 1, 0);

    builder.LoadLiteral(-2.1e19).Return();

    ast_factory.Internalize(i_isolate());
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    DirectHandle<Object> return_val = RunBytecode(bytecode_array);
    CHECK_EQ(i::Cast<i::HeapNumber>(*return_val)->value(), -2.1e19);
  }

  // Strings.
  {
    AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                HashSeed(i_isolate()));

    BytecodeArrayBuilder builder(zone(), 1, 0);

    const AstRawString* raw_string = ast_factory.GetOneByteString("String");
    builder.LoadLiteral(raw_string).Return();

    ast_factory.Internalize(i_isolate());
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    DirectHandle<Object> return_val = RunBytecode(bytecode_array);
    CHECK(i::Cast<i::String>(*return_val)->Equals(*raw_string->string()));
  }
}

TEST_F(InterpreterTest, InterpreterLoadStoreRegisters) {
  Handle<Object> true_value = i_isolate()->factory()->true_value();
  for (int i = 0; i <= kMaxInt8; i++) {
    BytecodeArrayBuilder builder(zone(), 1, i + 1);

    Register reg(i);
    builder.LoadTrue()
        .StoreAccumulatorInRegister(reg)
        .LoadFalse()
        .LoadAccumulatorWithRegister(reg)
        .Return();
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    Handle<Object> return_val = RunBytecode(bytecode_array);
    CHECK(return_val.is_identical_to(true_value));
  }
}

static const Token::Value kShiftOperators[] = {Token::kShl, Token::kSar,
                                               Token::kShr};

static const Token::Value kArithmeticOperators[] = {
    Token::kBitOr, Token::kBitXor, Token::kBitAnd, Token::kShl,
    Token::kSar,   Token::kShr,    Token::kAdd,    Token::kSub,
    Token::kMul,   Token::kDiv,    Token::kMod};

static double BinaryOpC(Token::Value op, double lhs, double rhs) {
  switch (op) {
    case Token::kAdd:
      return lhs + rhs;
    case Token::kSub:
      return lhs - rhs;
    case Token::kMul:
      return lhs * rhs;
    case Token::kDiv:
      return base::Divide(lhs, rhs);
    case Token::kMod:
      return Modulo(lhs, rhs);
    case Token::kBitOr:
      return (v8::internal::DoubleToInt32(lhs) |
              v8::internal::DoubleToInt32(rhs));
    case Token::kBitXor:
      return (v8::internal::DoubleToInt32(lhs) ^
              v8::internal::DoubleToInt32(rhs));
    case Token::kBitAnd:
      return (v8::internal::DoubleToInt32(lhs) &
              v8::internal::DoubleToInt32(rhs));
    case Token::kShl: {
      return base::ShlWithWraparound(DoubleToInt32(lhs), DoubleToInt32(rhs));
    }
    case Token::kSar: {
      int32_t val = v8::internal::DoubleToInt32(lhs);
      uint32_t count = v8::internal::DoubleToUint32(rhs) & 0x1F;
      int32_t result = val >> count;
      return result;
    }
    case Token::kShr: {
      uint32_t val = v8::internal::DoubleToUint32(lhs);
      uint32_t count = v8::internal::DoubleToUint32(rhs) & 0x1F;
      uint32_t result = val >> count;
      return result;
    }
    default:
      UNREACHABLE();
  }
}

TEST_F(InterpreterTest, InterpreterShiftOpsSmi) {
  int lhs_inputs[] = {0, -17, -182, 1073741823, -1};
  int rhs_inputs[] = {5, 2, 1, -1, -2, 0, 31, 32, -32, 64, 37};
  for (size_t l = 0; l < arraysize(lhs_inputs); l++) {
    for (size_t r = 0; r < arraysize(rhs_inputs); r++) {
      for (size_t o = 0; o < arraysize(kShiftOperators); o++) {
        Factory* factory = i_isolate()->factory();
        FeedbackVectorSpec feedback_spec(zone());
        BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

        FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
        Handle<i::FeedbackMetadata> metadata =
            FeedbackMetadata::New(i_isolate(), &feedback_spec);

        Register reg(0);
        int lhs = lhs_inputs[l];
        int rhs = rhs_inputs[r];
        builder.LoadLiteral(Smi::FromInt(lhs))
            .StoreAccumulatorInRegister(reg)
            .LoadLiteral(Smi::FromInt(rhs))
            .BinaryOperation(kShiftOperators[o], reg, GetIndex(slot))
            .Return();
        Handle<BytecodeArray> bytecode_array =
            builder.ToBytecodeArray(i_isolate());

        InterpreterTester tester(i_isolate(), bytecode_array, metadata);
        auto callable = tester.GetCallable<>();
        DirectHandle<Object> return_value = callable().ToHandleChecked();
        DirectHandle<Object> expected_value =
            factory->NewNumber(BinaryOpC(kShiftOperators[o], lhs, rhs));
        CHECK(Object::SameValue(*return_value, *expected_value));
      }
    }
  }
}

TEST_F(InterpreterTest, InterpreterBinaryOpsSmi) {
  int lhs_inputs[] = {3266, 1024, 0, -17, -18000};
  int rhs_inputs[] = {3266, 5, 4, 3, 2, 1, -1, -2};
  for (size_t l = 0; l < arraysize(lhs_inputs); l++) {
    for (size_t r = 0; r < arraysize(rhs_inputs); r++) {
      for (size_t o = 0; o < arraysize(kArithmeticOperators); o++) {
        Factory* factory = i_isolate()->factory();
        FeedbackVectorSpec feedback_spec(zone());
        BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

        FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
        Handle<i::FeedbackMetadata> metadata =
            FeedbackMetadata::New(i_isolate(), &feedback_spec);

        Register reg(0);
        int lhs = lhs_inputs[l];
        int rhs = rhs_inputs[r];
        builder.LoadLiteral(Smi::FromInt(lhs))
            .StoreAccumulatorInRegister(reg)
            .LoadLiteral(Smi::FromInt(rhs))
            .BinaryOperation(kArithmeticOperators[o], reg, GetIndex(slot))
            .Return();
        Handle<BytecodeArray> bytecode_array =
            builder.ToBytecodeArray(i_isolate());

        InterpreterTester tester(i_isolate(), bytecode_array, metadata);
        auto callable = tester.GetCallable<>();
        DirectHandle<Object> return_value = callable().ToHandleChecked();
        DirectHandle<Object> expected_value =
            factory->NewNumber(BinaryOpC(kArithmeticOperators[o], lhs, rhs));
        CHECK(Object::SameValue(*return_value, *expected_value));
      }
    }
  }
}

TEST_F(InterpreterTest, InterpreterBinaryOpsHeapNumber) {
  double lhs_inputs[] = {3266.101, 1024.12, 0.01, -17.99, -18000.833, 9.1e17};
  double rhs_inputs[] = {3266.101, 5.999, 4.778, 3.331,  2.643,
                         1.1,      -1.8,  -2.9,  8.3e-27};
  for (size_t l = 0; l < arraysize(lhs_inputs); l++) {
    for (size_t r = 0; r < arraysize(rhs_inputs); r++) {
      for (size_t o = 0; o < arraysize(kArithmeticOperators); o++) {
        Factory* factory = i_isolate()->factory();
        FeedbackVectorSpec feedback_spec(zone());
        BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

        FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
        Handle<i::FeedbackMetadata> metadata =
            FeedbackMetadata::New(i_isolate(), &feedback_spec);

        Register reg(0);
        double lhs = lhs_inputs[l];
        double rhs = rhs_inputs[r];
        builder.LoadLiteral(lhs)
            .StoreAccumulatorInRegister(reg)
            .LoadLiteral(rhs)
            .BinaryOperation(kArithmeticOperators[o], reg, GetIndex(slot))
            .Return();
        Handle<BytecodeArray> bytecode_array =
            builder.ToBytecodeArray(i_isolate());

        InterpreterTester tester(i_isolate(), bytecode_array, metadata);
        auto callable = tester.GetCallable<>();
        DirectHandle<Object> return_value = callable().ToHandleChecked();
        DirectHandle<Object> expected_value =
            factory->NewNumber(BinaryOpC(kArithmeticOperators[o], lhs, rhs));
        CHECK(Object::SameValue(*return_value, *expected_value));
      }
    }
  }
}

TEST_F(InterpreterTest, InterpreterBinaryOpsBigInt) {
  // This test only checks that the recorded type feedback is kBigInt.
  AstBigInt inputs[] = {AstBigInt("1"), AstBigInt("-42"), AstBigInt("0xFFFF")};
  for (size_t l = 0; l < arraysize(inputs); l++) {
    for (size_t r = 0; r < arraysize(inputs); r++) {
      for (size_t o = 0; o < arraysize(kArithmeticOperators); o++) {
        // Skip over unsigned right shift.
        if (kArithmeticOperators[o] == Token::kShr) continue;

        FeedbackVectorSpec feedback_spec(zone());
        BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

        FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
        Handle<i::FeedbackMetadata> metadata =
            FeedbackMetadata::New(i_isolate(), &feedback_spec);

        Register reg(0);
        auto lhs = inputs[l];
        auto rhs = inputs[r];
        builder.LoadLiteral(lhs)
            .StoreAccumulatorInRegister(reg)
            .LoadLiteral(rhs)
            .BinaryOperation(kArithmeticOperators[o], reg, GetIndex(slot))
            .Return();
        Handle<BytecodeArray> bytecode_array =
            builder.ToBytecodeArray(i_isolate());

        InterpreterTester tester(i_isolate(), bytecode_array, metadata);
        auto callable = tester.GetCallable<>();
        DirectHandle<Object> return_value = callable().ToHandleChecked();
        CHECK(IsBigInt(*return_value));
        if (tester.HasFeedbackMetadata()) {
          Tagged<MaybeObject> feedback = callable.vector()->Get(slot);
          CHECK(IsSmi(feedback));
          // TODO(panq): Create a standalone unit test for kBigInt64.
          CHECK(BinaryOperationFeedback::kBigInt64 ==
                    feedback.ToSmi().value() ||
                BinaryOperationFeedback::kBigInt == feedback.ToSmi().value());
        }
      }
    }
  }
}

namespace {

struct LiteralForTest {
  enum Type { kString, kHeapNumber, kSmi, kTrue, kFalse, kUndefined, kNull };

  explicit LiteralForTest(const AstRawString* string)
      : type(kString), string(string) {}
  explicit LiteralForTest(double number) : type(kHeapNumber), number(number) {}
  explicit LiteralForTest(int smi) : type(kSmi), smi(smi) {}
  explicit LiteralForTest(Type type) : type(type) {}

  Type type;
  union {
    const AstRawString* string;
    double number;
    int smi;
  };
};

void LoadLiteralForTest(BytecodeArrayBuilder* builder,
                        const LiteralForTest& value) {
  switch (value.type) {
    case LiteralForTest::kString:
      builder->LoadLiteral(value.string);
      return;
    case LiteralForTest::kHeapNumber:
      builder->LoadLiteral(value.number);
      return;
    case LiteralForTest::kSmi:
      builder->LoadLiteral(Smi::FromInt(value.smi));
      return;
    case LiteralForTest::kTrue:
      builder->LoadTrue();
      return;
    case LiteralForTest::kFalse:
      builder->LoadFalse();
      return;
    case LiteralForTest::kUndefined:
      builder->LoadUndefined();
      return;
    case LiteralForTest::kNull:
      builder->LoadNull();
      return;
  }
  UNREACHABLE();
}

}  // anonymous namespace

TEST_F(InterpreterTest, InterpreterStringAdd) {
  Factory* factory = i_isolate()->factory();
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));

  struct TestCase {
    const AstRawString* lhs;
    LiteralForTest rhs;
    Handle<Object> expected_value;
    int32_t expected_feedback;
  } test_cases[] = {
      {ast_factory.GetOneByteString("a"),
       LiteralForTest(ast_factory.GetOneByteString("b")),
       factory->NewStringFromStaticChars("ab"),
       BinaryOperationFeedback::kString},
      {ast_factory.GetOneByteString("aaaaaa"),
       LiteralForTest(ast_factory.GetOneByteString("b")),
       factory->NewStringFromStaticChars("aaaaaab"),
       BinaryOperationFeedback::kString},
      {ast_factory.GetOneByteString("aaa"),
       LiteralForTest(ast_factory.GetOneByteString("bbbbb")),
       factory->NewStringFromStaticChars("aaabbbbb"),
       BinaryOperationFeedback::kString},
      {ast_factory.GetOneByteString(""),
       LiteralForTest(ast_factory.GetOneByteString("b")),
       factory->NewStringFromStaticChars("b"),
       BinaryOperationFeedback::kString},
      {ast_factory.GetOneByteString("a"),
       LiteralForTest(ast_factory.GetOneByteString("")),
       factory->NewStringFromStaticChars("a"),
       BinaryOperationFeedback::kString},
      {ast_factory.GetOneByteString("1.11"), LiteralForTest(2.5),
       factory->NewStringFromStaticChars("1.112.5"),
       BinaryOperationFeedback::kAny},
      {ast_factory.GetOneByteString("-1.11"), LiteralForTest(2.56),
       factory->NewStringFromStaticChars("-1.112.56"),
       BinaryOperationFeedback::kAny},
      {ast_factory.GetOneByteString(""), LiteralForTest(2.5),
       factory->NewStringFromStaticChars("2.5"), BinaryOperationFeedback::kAny},
  };
  ast_factory.Internalize(i_isolate());

  for (size_t i = 0; i < arraysize(test_cases); i++) {
    FeedbackVectorSpec feedback_spec(zone());
    BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);
    FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
    Handle<i::FeedbackMetadata> metadata =
        FeedbackMetadata::New(i_isolate(), &feedback_spec);

    Register reg(0);
    builder.LoadLiteral(test_cases[i].lhs).StoreAccumulatorInRegister(reg);
    LoadLiteralForTest(&builder, test_cases[i].rhs);
    builder.BinaryOperation(Token::kAdd, reg, GetIndex(slot)).Return();
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    InterpreterTester tester(i_isolate(), bytecode_array, metadata);
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *test_cases[i].expected_value));

    if (tester.HasFeedbackMetadata()) {
      Tagged<MaybeObject> feedback = callable.vector()->Get(slot);
      CHECK(IsSmi(feedback));
      CHECK_EQ(test_cases[i].expected_feedback, feedback.ToSmi().value());
    }
  }
}

TEST_F(InterpreterTest, InterpreterReceiverParameter) {
  BytecodeArrayBuilder builder(zone(), 1, 0);

  builder.LoadAccumulatorWithRegister(builder.Receiver()).Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  Handle<JSAny> object = InterpreterTester::NewObject("({ val : 123 })");

  InterpreterTester tester(i_isolate(), bytecode_array);
  auto callable = tester.GetCallableWithReceiver<>();
  Handle<Object> return_val = callable(object).ToHandleChecked();

  CHECK(return_val.is_identical_to(object));
}

TEST_F(InterpreterTest, InterpreterParameter0) {
  BytecodeArrayBuilder builder(zone(), 2, 0);

  builder.LoadAccumulatorWithRegister(builder.Parameter(0)).Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  InterpreterTester tester(i_isolate(), bytecode_array);
  auto callable = tester.GetCallable<Handle<Object>>();

  // Check for heap objects.
  Handle<Object> true_value = i_isolate()->factory()->true_value();
  Handle<Object> return_val = callable(true_value).ToHandleChecked();
  CHECK(return_val.is_identical_to(true_value));

  // Check for Smis.
  return_val =
      callable(Handle<Smi>(Smi::FromInt(3), i_isolate())).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(3));
}

TEST_F(InterpreterTest, InterpreterParameter8) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 8, 0, &feedback_spec);

  FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot1 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot2 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot3 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot4 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot5 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot6 = feedback_spec.AddBinaryOpICSlot();

  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);

  builder.LoadAccumulatorWithRegister(builder.Receiver())
      .BinaryOperation(Token::kAdd, builder.Parameter(0), GetIndex(slot))
      .BinaryOperation(Token::kAdd, builder.Parameter(1), GetIndex(slot1))
      .BinaryOperation(Token::kAdd, builder.Parameter(2), GetIndex(slot2))
      .BinaryOperation(Token::kAdd, builder.Parameter(3), GetIndex(slot3))
      .BinaryOperation(Token::kAdd, builder.Parameter(4), GetIndex(slot4))
      .BinaryOperation(Token::kAdd, builder.Parameter(5), GetIndex(slot5))
      .BinaryOperation(Token::kAdd, builder.Parameter(6), GetIndex(slot6))
      .Return();
  ast_factory.Internalize(i_isolate());
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  InterpreterTester tester(i_isolate(), bytecode_array, metadata);
  using H = Handle<Object>;
  auto callable = tester.GetCallableWithReceiver<H, H, H, H, H, H, H>();

  Handle<Smi> arg1 = Handle<Smi>(Smi::FromInt(1), i_isolate());
  Handle<Smi> arg2 = Handle<Smi>(Smi::FromInt(2), i_isolate());
  Handle<Smi> arg3 = Handle<Smi>(Smi::FromInt(3), i_isolate());
  Handle<Smi> arg4 = Handle<Smi>(Smi::FromInt(4), i_isolate());
  Handle<Smi> arg5 = Handle<Smi>(Smi::FromInt(5), i_isolate());
  Handle<Smi> arg6 = Handle<Smi>(Smi::FromInt(6), i_isolate());
  Handle<Smi> arg7 = Handle<Smi>(Smi::FromInt(7), i_isolate());
  Handle<Smi> arg8 = Handle<Smi>(Smi::FromInt(8), i_isolate());
  // Check for Smis.
  DirectHandle<Object> return_val =
      callable(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
          .ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(36));
}

TEST_F(InterpreterTest, InterpreterBinaryOpTypeFeedback) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));

  struct BinaryOpExpectation {
    Token::Value op;
    LiteralForTest arg1;
    LiteralForTest arg2;
    Handle<Object> result;
    int32_t feedback;
  };

  BinaryOpExpectation const kTestCases[] = {
      // ADD
      {Token::kAdd, LiteralForTest(2), LiteralForTest(3),
       Handle<Smi>(Smi::FromInt(5), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kAdd, LiteralForTest(Smi::kMaxValue), LiteralForTest(1),
       i_isolate()->factory()->NewHeapNumber(Smi::kMaxValue + 1.0),
       BinaryOperationFeedback::kNumber},
      {Token::kAdd, LiteralForTest(3.1415), LiteralForTest(3),
       i_isolate()->factory()->NewHeapNumber(3.1415 + 3),
       BinaryOperationFeedback::kNumber},
      {Token::kAdd, LiteralForTest(3.1415), LiteralForTest(1.4142),
       i_isolate()->factory()->NewHeapNumber(3.1415 + 1.4142),
       BinaryOperationFeedback::kNumber},
      {Token::kAdd, LiteralForTest(ast_factory.GetOneByteString("foo")),
       LiteralForTest(ast_factory.GetOneByteString("bar")),
       i_isolate()->factory()->NewStringFromAsciiChecked("foobar"),
       BinaryOperationFeedback::kString},
      {Token::kAdd, LiteralForTest(2),
       LiteralForTest(ast_factory.GetOneByteString("2")),
       i_isolate()->factory()->NewStringFromAsciiChecked("22"),
       BinaryOperationFeedback::kAny},
      // SUB
      {Token::kSub, LiteralForTest(2), LiteralForTest(3),
       Handle<Smi>(Smi::FromInt(-1), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kSub, LiteralForTest(Smi::kMinValue), LiteralForTest(1),
       i_isolate()->factory()->NewHeapNumber(Smi::kMinValue - 1.0),
       BinaryOperationFeedback::kNumber},
      {Token::kSub, LiteralForTest(3.1415), LiteralForTest(3),
       i_isolate()->factory()->NewHeapNumber(3.1415 - 3),
       BinaryOperationFeedback::kNumber},
      {Token::kSub, LiteralForTest(3.1415), LiteralForTest(1.4142),
       i_isolate()->factory()->NewHeapNumber(3.1415 - 1.4142),
       BinaryOperationFeedback::kNumber},
      {Token::kSub, LiteralForTest(2),
       LiteralForTest(ast_factory.GetOneByteString("1")),
       Handle<Smi>(Smi::FromInt(1), i_isolate()),
       BinaryOperationFeedback::kAny},
      // MUL
      {Token::kMul, LiteralForTest(2), LiteralForTest(3),
       Handle<Smi>(Smi::FromInt(6), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kMul, LiteralForTest(Smi::kMinValue), LiteralForTest(2),
       i_isolate()->factory()->NewHeapNumber(Smi::kMinValue * 2.0),
       BinaryOperationFeedback::kNumber},
      {Token::kMul, LiteralForTest(3.1415), LiteralForTest(3),
       i_isolate()->factory()->NewHeapNumber(3 * 3.1415),
       BinaryOperationFeedback::kNumber},
      {Token::kMul, LiteralForTest(3.1415), LiteralForTest(1.4142),
       i_isolate()->factory()->NewHeapNumber(3.1415 * 1.4142),
       BinaryOperationFeedback::kNumber},
      {Token::kMul, LiteralForTest(2),
       LiteralForTest(ast_factory.GetOneByteString("1")),
       Handle<Smi>(Smi::FromInt(2), i_isolate()),
       BinaryOperationFeedback::kAny},
      // DIV
      {Token::kDiv, LiteralForTest(6), LiteralForTest(3),
       Handle<Smi>(Smi::FromInt(2), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kDiv, LiteralForTest(3), LiteralForTest(2),
       i_isolate()->factory()->NewHeapNumber(3.0 / 2.0),
       BinaryOperationFeedback::kSignedSmallInputs},
      {Token::kDiv, LiteralForTest(3.1415), LiteralForTest(3),
       i_isolate()->factory()->NewHeapNumber(3.1415 / 3),
       BinaryOperationFeedback::kNumber},
      {Token::kDiv, LiteralForTest(3.1415),
       LiteralForTest(-std::numeric_limits<double>::infinity()),
       i_isolate()->factory()->NewHeapNumber(-0.0),
       BinaryOperationFeedback::kNumber},
      {Token::kDiv, LiteralForTest(2),
       LiteralForTest(ast_factory.GetOneByteString("1")),
       Handle<Smi>(Smi::FromInt(2), i_isolate()),
       BinaryOperationFeedback::kAny},
      // MOD
      {Token::kMod, LiteralForTest(5), LiteralForTest(3),
       Handle<Smi>(Smi::FromInt(2), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kMod, LiteralForTest(-4), LiteralForTest(2),
       i_isolate()->factory()->NewHeapNumber(-0.0),
       BinaryOperationFeedback::kNumber},
      {Token::kMod, LiteralForTest(3.1415), LiteralForTest(3),
       i_isolate()->factory()->NewHeapNumber(fmod(3.1415, 3.0)),
       BinaryOperationFeedback::kNumber},
      {Token::kMod, LiteralForTest(-3.1415), LiteralForTest(-1.4142),
       i_isolate()->factory()->NewHeapNumber(fmod(-3.1415, -1.4142)),
       BinaryOperationFeedback::kNumber},
      {Token::kMod, LiteralForTest(3),
       LiteralForTest(ast_factory.GetOneByteString("-2")),
       Handle<Smi>(Smi::FromInt(1), i_isolate()),
       BinaryOperationFeedback::kAny}};
  ast_factory.Internalize(i_isolate());

  for (const BinaryOpExpectation& test_case : kTestCases) {
    i::FeedbackVectorSpec feedback_spec(zone());
    BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

    i::FeedbackSlot slot0 = feedback_spec.AddBinaryOpICSlot();

    Handle<i::FeedbackMetadata> metadata =
        i::FeedbackMetadata::New(i_isolate(), &feedback_spec);

    Register reg(0);
    LoadLiteralForTest(&builder, test_case.arg1);
    builder.StoreAccumulatorInRegister(reg);
    LoadLiteralForTest(&builder, test_case.arg2);
    builder.BinaryOperation(test_case.op, reg, GetIndex(slot0)).Return();

    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    InterpreterTester tester(i_isolate(), bytecode_array, metadata);
    auto callable = tester.GetCallable<>();

    Handle<Object> return_val = callable().ToHandleChecked();
    Tagged<MaybeObject> feedback0 = callable.vector()->Get(slot0);
    CHECK(IsSmi(feedback0));
    CHECK_EQ(test_case.feedback, feedback0.ToSmi().value());
    CHECK(
        Object::Equals(i_isolate(), test_case.result, return_val).ToChecked());
  }
}

TEST_F(InterpreterTest, InterpreterBinaryOpSmiTypeFeedback) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));

  struct BinaryOpExpectation {
    Token::Value op;
    LiteralForTest arg1;
    int32_t arg2;
    Handle<Object> result;
    int32_t feedback;
  };

  BinaryOpExpectation const kTestCases[] = {
      // ADD
      {Token::kAdd, LiteralForTest(2), 42,
       Handle<Smi>(Smi::FromInt(44), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kAdd, LiteralForTest(2), Smi::kMaxValue,
       i_isolate()->factory()->NewHeapNumber(Smi::kMaxValue + 2.0),
       BinaryOperationFeedback::kNumber},
      {Token::kAdd, LiteralForTest(3.1415), 2,
       i_isolate()->factory()->NewHeapNumber(3.1415 + 2.0),
       BinaryOperationFeedback::kNumber},
      {Token::kAdd, LiteralForTest(ast_factory.GetOneByteString("2")), 2,
       i_isolate()->factory()->NewStringFromAsciiChecked("22"),
       BinaryOperationFeedback::kAny},
      // SUB
      {Token::kSub, LiteralForTest(2), 42,
       Handle<Smi>(Smi::FromInt(-40), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kSub, LiteralForTest(Smi::kMinValue), 1,
       i_isolate()->factory()->NewHeapNumber(Smi::kMinValue - 1.0),
       BinaryOperationFeedback::kNumber},
      {Token::kSub, LiteralForTest(3.1415), 2,
       i_isolate()->factory()->NewHeapNumber(3.1415 - 2.0),
       BinaryOperationFeedback::kNumber},
      {Token::kSub, LiteralForTest(ast_factory.GetOneByteString("2")), 2,
       Handle<Smi>(Smi::zero(), i_isolate()), BinaryOperationFeedback::kAny},
      // BIT_OR
      {Token::kBitOr, LiteralForTest(4), 1,
       Handle<Smi>(Smi::FromInt(5), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kBitOr, LiteralForTest(3.1415), 8,
       Handle<Smi>(Smi::FromInt(11), i_isolate()),
       BinaryOperationFeedback::kNumber},
      {Token::kBitOr, LiteralForTest(ast_factory.GetOneByteString("2")), 1,
       Handle<Smi>(Smi::FromInt(3), i_isolate()),
       BinaryOperationFeedback::kAny},
      // BIT_AND
      {Token::kBitAnd, LiteralForTest(3), 1,
       Handle<Smi>(Smi::FromInt(1), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kBitAnd, LiteralForTest(3.1415), 2,
       Handle<Smi>(Smi::FromInt(2), i_isolate()),
       BinaryOperationFeedback::kNumber},
      {Token::kBitAnd, LiteralForTest(ast_factory.GetOneByteString("2")), 1,
       Handle<Smi>(Smi::zero(), i_isolate()), BinaryOperationFeedback::kAny},
      // SHL
      {Token::kShl, LiteralForTest(3), 1,
       Handle<Smi>(Smi::FromInt(6), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kShl, LiteralForTest(3.1415), 2,
       Handle<Smi>(Smi::FromInt(12), i_isolate()),
       BinaryOperationFeedback::kNumber},
      {Token::kShl, LiteralForTest(ast_factory.GetOneByteString("2")), 1,
       Handle<Smi>(Smi::FromInt(4), i_isolate()),
       BinaryOperationFeedback::kAny},
      // SAR
      {Token::kSar, LiteralForTest(3), 1,
       Handle<Smi>(Smi::FromInt(1), i_isolate()),
       BinaryOperationFeedback::kSignedSmall},
      {Token::kSar, LiteralForTest(3.1415), 2,
       Handle<Smi>(Smi::zero(), i_isolate()), BinaryOperationFeedback::kNumber},
      {Token::kSar, LiteralForTest(ast_factory.GetOneByteString("2")), 1,
       Handle<Smi>(Smi::FromInt(1), i_isolate()),
       BinaryOperationFeedback::kAny}};
  ast_factory.Internalize(i_isolate());

  for (const BinaryOpExpectation& test_case : kTestCases) {
    i::FeedbackVectorSpec feedback_spec(zone());
    BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

    i::FeedbackSlot slot0 = feedback_spec.AddBinaryOpICSlot();

    Handle<i::FeedbackMetadata> metadata =
        i::FeedbackMetadata::New(i_isolate(), &feedback_spec);

    Register reg(0);
    LoadLiteralForTest(&builder, test_case.arg1);
    builder.StoreAccumulatorInRegister(reg)
        .LoadLiteral(Smi::FromInt(test_case.arg2))
        .BinaryOperation(test_case.op, reg, GetIndex(slot0))
        .Return();

    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    InterpreterTester tester(i_isolate(), bytecode_array, metadata);
    auto callable = tester.GetCallable<>();

    Handle<Object> return_val = callable().ToHandleChecked();
    Tagged<MaybeObject> feedback0 = callable.vector()->Get(slot0);
    CHECK(IsSmi(feedback0));
    CHECK_EQ(test_case.feedback, feedback0.ToSmi().value());
    CHECK(
        Object::Equals(i_isolate(), test_case.result, return_val).ToChecked());
  }
}

TEST_F(InterpreterTest, InterpreterUnaryOpFeedback) {
  Handle<Smi> smi_one = Handle<Smi>(Smi::FromInt(1), i_isolate());
  Handle<Smi> smi_max = Handle<Smi>(Smi::FromInt(Smi::kMaxValue), i_isolate());
  Handle<Smi> smi_min = Handle<Smi>(Smi::FromInt(Smi::kMinValue), i_isolate());
  Handle<HeapNumber> number = i_isolate()->factory()->NewHeapNumber(2.1);
  Handle<BigInt> bigint =
      BigInt::FromNumber(i_isolate(), smi_max).ToHandleChecked();
  Handle<String> str = i_isolate()->factory()->NewStringFromAsciiChecked("42");

  struct TestCase {
    Token::Value op;
    Handle<Smi> smi_feedback_value;
    Handle<Smi> smi_to_number_feedback_value;
    Handle<HeapNumber> number_feedback_value;
    Handle<BigInt> bigint_feedback_value;
    Handle<Object> any_feedback_value;
  };
  TestCase const kTestCases[] = {
      // Testing ADD and BIT_NOT would require generalizing the test setup.
      {Token::kSub, smi_one, smi_min, number, bigint, str},
      {Token::kInc, smi_one, smi_max, number, bigint, str},
      {Token::kDec, smi_one, smi_min, number, bigint, str}};
  for (TestCase const& test_case : kTestCases) {
    i::FeedbackVectorSpec feedback_spec(zone());
    BytecodeArrayBuilder builder(zone(), 6, 0, &feedback_spec);

    i::FeedbackSlot slot0 = feedback_spec.AddBinaryOpICSlot();
    i::FeedbackSlot slot1 = feedback_spec.AddBinaryOpICSlot();
    i::FeedbackSlot slot2 = feedback_spec.AddBinaryOpICSlot();
    i::FeedbackSlot slot3 = feedback_spec.AddBinaryOpICSlot();
    i::FeedbackSlot slot4 = feedback_spec.AddBinaryOpICSlot();

    Handle<i::FeedbackMetadata> metadata =
        i::FeedbackMetadata::New(i_isolate(), &feedback_spec);

    builder.LoadAccumulatorWithRegister(builder.Parameter(0))
        .UnaryOperation(test_case.op, GetIndex(slot0))
        .LoadAccumulatorWithRegister(builder.Parameter(1))
        .UnaryOperation(test_case.op, GetIndex(slot1))
        .LoadAccumulatorWithRegister(builder.Parameter(2))
        .UnaryOperation(test_case.op, GetIndex(slot2))
        .LoadAccumulatorWithRegister(builder.Parameter(3))
        .UnaryOperation(test_case.op, GetIndex(slot3))
        .LoadAccumulatorWithRegister(builder.Parameter(4))
        .UnaryOperation(test_case.op, GetIndex(slot4))
        .Return();

    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    InterpreterTester tester(i_isolate(), bytecode_array, metadata);
    using H = Handle<Object>;
    auto callable = tester.GetCallable<H, H, H, H, H>();

    Handle<Object> return_val =
        callable(test_case.smi_feedback_value,
                 test_case.smi_to_number_feedback_value,
                 test_case.number_feedback_value,
                 test_case.bigint_feedback_value, test_case.any_feedback_value)
            .ToHandleChecked();
    USE(return_val);
    Tagged<MaybeObject> feedback0 = callable.vector()->Get(slot0);
    CHECK(IsSmi(feedback0));
    CHECK_EQ(BinaryOperationFeedback::kSignedSmall, feedback0.ToSmi().value());

    Tagged<MaybeObject> feedback1 = callable.vector()->Get(slot1);
    CHECK(IsSmi(feedback1));
    CHECK_EQ(BinaryOperationFeedback::kNumber, feedback1.ToSmi().value());

    Tagged<MaybeObject> feedback2 = callable.vector()->Get(slot2);
    CHECK(IsSmi(feedback2));
    CHECK_EQ(BinaryOperationFeedback::kNumber, feedback2.ToSmi().value());

    Tagged<MaybeObject> feedback3 = callable.vector()->Get(slot3);
    CHECK(IsSmi(feedback3));
    CHECK_EQ(BinaryOperationFeedback::kBigInt, feedback3.ToSmi().value());

    Tagged<MaybeObject> feedback4 = callable.vector()->Get(slot4);
    CHECK(IsSmi(feedback4));
    CHECK_EQ(BinaryOperationFeedback::kAny, feedback4.ToSmi().value());
  }
}

TEST_F(InterpreterTest, InterpreterBitwiseTypeFeedback) {
  const Token::Value kBitwiseBinaryOperators[] = {
      Token::kBitOr, Token::kBitXor, Token::kBitAnd,
      Token::kShl,   Token::kShr,    Token::kSar};

  for (Token::Value op : kBitwiseBinaryOperators) {
    i::FeedbackVectorSpec feedback_spec(zone());
    BytecodeArrayBuilder builder(zone(), 5, 0, &feedback_spec);

    i::FeedbackSlot slot0 = feedback_spec.AddBinaryOpICSlot();
    i::FeedbackSlot slot1 = feedback_spec.AddBinaryOpICSlot();
    i::FeedbackSlot slot2 = feedback_spec.AddBinaryOpICSlot();

    Handle<i::FeedbackMetadata> metadata =
        i::FeedbackMetadata::New(i_isolate(), &feedback_spec);

    builder.LoadAccumulatorWithRegister(builder.Parameter(0))
        .BinaryOperation(op, builder.Parameter(1), GetIndex(slot0))
        .BinaryOperation(op, builder.Parameter(2), GetIndex(slot1))
        .BinaryOperation(op, builder.Parameter(3), GetIndex(slot2))
        .Return();

    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    InterpreterTester tester(i_isolate(), bytecode_array, metadata);
    using H = Handle<Object>;
    auto callable = tester.GetCallable<H, H, H, H>();

    Handle<Smi> arg1 = Handle<Smi>(Smi::FromInt(2), i_isolate());
    Handle<Smi> arg2 = Handle<Smi>(Smi::FromInt(2), i_isolate());
    Handle<HeapNumber> arg3 = i_isolate()->factory()->NewHeapNumber(2.2);
    Handle<String> arg4 =
        i_isolate()->factory()->NewStringFromAsciiChecked("2");

    Handle<Object> return_val =
        callable(arg1, arg2, arg3, arg4).ToHandleChecked();
    USE(return_val);
    Tagged<MaybeObject> feedback0 = callable.vector()->Get(slot0);
    CHECK(IsSmi(feedback0));
    CHECK_EQ(BinaryOperationFeedback::kSignedSmall, feedback0.ToSmi().value());

    Tagged<MaybeObject> feedback1 = callable.vector()->Get(slot1);
    CHECK(IsSmi(feedback1));
    CHECK_EQ(BinaryOperationFeedback::kNumber, feedback1.ToSmi().value());

    Tagged<MaybeObject> feedback2 = callable.vector()->Get(slot2);
    CHECK(IsSmi(feedback2));
    CHECK_EQ(BinaryOperationFeedback::kAny, feedback2.ToSmi().value());
  }
}

TEST_F(InterpreterTest, InterpreterParameter1Assign) {
  BytecodeArrayBuilder builder(zone(), 1, 0);

  builder.LoadLiteral(Smi::FromInt(5))
      .StoreAccumulatorInRegister(builder.Receiver())
      .LoadAccumulatorWithRegister(builder.Receiver())
      .Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  InterpreterTester tester(i_isolate(), bytecode_array);
  auto callable = tester.GetCallableWithReceiver<>();

  DirectHandle<Object> return_val =
      callable(Handle<Smi>(Smi::FromInt(3), i_isolate())).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(5));
}

TEST_F(InterpreterTest, InterpreterLoadGlobal) {
  // Test loading a global.
  std::string source(
      "var global = 321;\n"
      "function " +
      InterpreterTester::function_name() +
      "() {\n"
      "  return global;\n"
      "}");
  InterpreterTester tester(i_isolate(), source.c_str());
  auto callable = tester.GetCallable<>();

  DirectHandle<Object> return_val = callable().ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(321));
}

TEST_F(InterpreterTest, InterpreterStoreGlobal) {
  Factory* factory = i_isolate()->factory();

  // Test storing to a global.
  std::string source(
      "var global = 321;\n"
      "function " +
      InterpreterTester::function_name() +
      "() {\n"
      "  global = 999;\n"
      "}");
  InterpreterTester tester(i_isolate(), source.c_str());
  auto callable = tester.GetCallable<>();

  callable().ToHandleChecked();
  Handle<i::String> name = factory->InternalizeUtf8String("global");
  DirectHandle<i::Object> global_obj =
      Object::GetProperty(i_isolate(), i_isolate()->global_object(), name)
          .ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*global_obj), Smi::FromInt(999));
}

TEST_F(InterpreterTest, InterpreterCallGlobal) {
  // Test calling a global function.
  std::string source(
      "function g_add(a, b) { return a + b; }\n"
      "function " +
      InterpreterTester::function_name() +
      "() {\n"
      "  return g_add(5, 10);\n"
      "}");
  InterpreterTester tester(i_isolate(), source.c_str());
  auto callable = tester.GetCallable<>();

  DirectHandle<Object> return_val = callable().ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(15));
}

TEST_F(InterpreterTest, InterpreterLoadUnallocated) {
  // Test loading an unallocated global.
  std::string source(
      "unallocated = 123;\n"
      "function " +
      InterpreterTester::function_name() +
      "() {\n"
      "  return unallocated;\n"
      "}");
  InterpreterTester tester(i_isolate(), source.c_str());
  auto callable = tester.GetCallable<>();

  DirectHandle<Object> return_val = callable().ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(123));
}

TEST_F(InterpreterTest, InterpreterStoreUnallocated) {
  Factory* factory = i_isolate()->factory();

  // Test storing to an unallocated global.
  std::string source(
      "unallocated = 321;\n"
      "function " +
      InterpreterTester::function_name() +
      "() {\n"
      "  unallocated = 999;\n"
      "}");
  InterpreterTester tester(i_isolate(), source.c_str());
  auto callable = tester.GetCallable<>();

  callable().ToHandleChecked();
  Handle<i::String> name = factory->InternalizeUtf8String("unallocated");
  DirectHandle<i::Object> global_obj =
      Object::GetProperty(i_isolate(), i_isolate()->global_object(), name)
          .ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*global_obj), Smi::FromInt(999));
}

TEST_F(InterpreterTest, InterpreterLoadNamedProperty) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));

  FeedbackVectorSpec feedback_spec(zone());
  FeedbackSlot slot = feedback_spec.AddLoadICSlot();

  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);

  const AstRawString* name = ast_factory.GetOneByteString("val");

  BytecodeArrayBuilder builder(zone(), 1, 0, &feedback_spec);

  builder.LoadNamedProperty(builder.Receiver(), name, GetIndex(slot)).Return();
  ast_factory.Internalize(i_isolate());
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  InterpreterTester tester(i_isolate(), bytecode_array, metadata);
  auto callable = tester.GetCallableWithReceiver<>();

  Handle<JSAny> object = InterpreterTester::NewObject("({ val : 123 })");
  // Test IC miss.
  DirectHandle<Object> return_val = callable(object).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(123));

  // Test transition to monomorphic IC.
  return_val = callable(object).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(123));

  // Test transition to polymorphic IC.
  Handle<JSAny> object2 =
      InterpreterTester::NewObject("({ val : 456, other : 123 })");
  return_val = callable(object2).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(456));

  // Test transition to megamorphic IC.
  Handle<JSAny> object3 =
      InterpreterTester::NewObject("({ val : 789, val2 : 123 })");
  callable(object3).ToHandleChecked();
  Handle<JSAny> object4 =
      InterpreterTester::NewObject("({ val : 789, val3 : 123 })");
  callable(object4).ToHandleChecked();
  Handle<JSAny> object5 =
      InterpreterTester::NewObject("({ val : 789, val4 : 123 })");
  return_val = callable(object5).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(789));
}

TEST_F(InterpreterTest, InterpreterLoadKeyedProperty) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));

  FeedbackVectorSpec feedback_spec(zone());
  FeedbackSlot slot = feedback_spec.AddKeyedLoadICSlot();

  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);

  const AstRawString* key = ast_factory.GetOneByteString("key");

  BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

  builder.LoadLiteral(key)
      .LoadKeyedProperty(builder.Receiver(), GetIndex(slot))
      .Return();
  ast_factory.Internalize(i_isolate());
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  InterpreterTester tester(i_isolate(), bytecode_array, metadata);
  auto callable = tester.GetCallableWithReceiver<>();

  Handle<JSAny> object = InterpreterTester::NewObject("({ key : 123 })");
  // Test IC miss.
  DirectHandle<Object> return_val = callable(object).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(123));

  // Test transition to monomorphic IC.
  return_val = callable(object).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(123));

  // Test transition to megamorphic IC.
  Handle<JSAny> object3 =
      InterpreterTester::NewObject("({ key : 789, val2 : 123 })");
  return_val = callable(object3).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(789));
}

TEST_F(InterpreterTest, InterpreterSetNamedProperty) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));

  FeedbackVectorSpec feedback_spec(zone());
  FeedbackSlot slot = feedback_spec.AddStoreICSlot(LanguageMode::kStrict);

  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);

  const AstRawString* name = ast_factory.GetOneByteString("val");

  BytecodeArrayBuilder builder(zone(), 1, 0, &feedback_spec);

  builder.LoadLiteral(Smi::FromInt(999))
      .SetNamedProperty(builder.Receiver(), name, GetIndex(slot),
                        LanguageMode::kStrict)
      .Return();
  ast_factory.Internalize(i_isolate());
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  InterpreterTester tester(i_isolate(), bytecode_array, metadata);
  auto callable = tester.GetCallableWithReceiver<>();
  Handle<JSAny> object = InterpreterTester::NewObject("({ val : 123 })");
  // Test IC miss.
  Handle<Object> result;
  callable(object).ToHandleChecked();
  CHECK(Runtime::GetObjectProperty(i_isolate(), object, name->string())
            .ToHandle(&result));
  CHECK_EQ(Cast<Smi>(*result), Smi::FromInt(999));

  // Test transition to monomorphic IC.
  callable(object).ToHandleChecked();
  CHECK(Runtime::GetObjectProperty(i_isolate(), object, name->string())
            .ToHandle(&result));
  CHECK_EQ(Cast<Smi>(*result), Smi::FromInt(999));

  // Test transition to polymorphic IC.
  Handle<JSAny> object2 =
      InterpreterTester::NewObject("({ val : 456, other : 123 })");
  callable(object2).ToHandleChecked();
  CHECK(Runtime::GetObjectProperty(i_isolate(), object2, name->string())
            .ToHandle(&result));
  CHECK_EQ(Cast<Smi>(*result), Smi::FromInt(999));

  // Test transition to megamorphic IC.
  Handle<JSAny> object3 =
      InterpreterTester::NewObject("({ val : 789, val2 : 123 })");
  callable(object3).ToHandleChecked();
  Handle<JSAny> object4 =
      InterpreterTester::NewObject("({ val : 789, val3 : 123 })");
  callable(object4).ToHandleChecked();
  Handle<JSAny> object5 =
      InterpreterTester::NewObject("({ val : 789, val4 : 123 })");
  callable(object5).ToHandleChecked();
  CHECK(Runtime::GetObjectProperty(i_isolate(), object5, name->string())
            .ToHandle(&result));
  CHECK_EQ(Cast<Smi>(*result), Smi::FromInt(999));
}

TEST_F(InterpreterTest, InterpreterSetKeyedProperty) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));

  FeedbackVectorSpec feedback_spec(zone());
  FeedbackSlot slot = feedback_spec.AddKeyedStoreICSlot(LanguageMode::kSloppy);

  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);

  const AstRawString* name = ast_factory.GetOneByteString("val");

  BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

  builder.LoadLiteral(name)
      .StoreAccumulatorInRegister(Register(0))
      .LoadLiteral(Smi::FromInt(999))
      .SetKeyedProperty(builder.Receiver(), Register(0), GetIndex(slot),
                        i::LanguageMode::kSloppy)
      .Return();
  ast_factory.Internalize(i_isolate());
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  InterpreterTester tester(i_isolate(), bytecode_array, metadata);
  auto callable = tester.GetCallableWithReceiver<>();
  Handle<JSAny> object = InterpreterTester::NewObject("({ val : 123 })");
  // Test IC miss.
  Handle<Object> result;
  callable(object).ToHandleChecked();
  CHECK(Runtime::GetObjectProperty(i_isolate(), object, name->string())
            .ToHandle(&result));
  CHECK_EQ(Cast<Smi>(*result), Smi::FromInt(999));

  // Test transition to monomorphic IC.
  callable(object).ToHandleChecked();
  CHECK(Runtime::GetObjectProperty(i_isolate(), object, name->string())
            .ToHandle(&result));
  CHECK_EQ(Cast<Smi>(*result), Smi::FromInt(999));

  // Test transition to megamorphic IC.
  Handle<JSAny> object2 =
      InterpreterTester::NewObject("({ val : 456, other : 123 })");
  callable(object2).ToHandleChecked();
  CHECK(Runtime::GetObjectProperty(i_isolate(), object2, name->string())
            .ToHandle(&result));
  CHECK_EQ(Cast<Smi>(*result), Smi::FromInt(999));
}

TEST_F(InterpreterTest, InterpreterCall) {
  Factory* factory = i_isolate()->factory();

  FeedbackVectorSpec feedback_spec(zone());
  FeedbackSlot slot = feedback_spec.AddLoadICSlot();
  FeedbackSlot call_slot = feedback_spec.AddCallICSlot();

  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);
  int slot_index = GetIndex(slot);
  int call_slot_index = -1;
  call_slot_index = GetIndex(call_slot);

  // Check with no args.
  {
    AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                HashSeed(i_isolate()));
    const AstRawString* name = ast_factory.GetOneByteString("func");

    BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);
    Register reg = builder.register_allocator()->NewRegister();
    RegisterList args = builder.register_allocator()->NewRegisterList(1);
    builder.LoadNamedProperty(builder.Receiver(), name, slot_index)
        .StoreAccumulatorInRegister(reg)
        .MoveRegister(builder.Receiver(), args[0]);

    builder.CallProperty(reg, args, call_slot_index);

    builder.Return();
    ast_factory.Internalize(i_isolate());
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    InterpreterTester tester(i_isolate(), bytecode_array, metadata);
    auto callable = tester.GetCallableWithReceiver<>();

    Handle<JSAny> object = InterpreterTester::NewObject(
        "new (function Obj() { this.func = function() { return 0x265; }})()");
    DirectHandle<Object> return_val = callable(object).ToHandleChecked();
    CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(0x265));
  }

  // Check that receiver is passed properly.
  {
    AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                HashSeed(i_isolate()));
    const AstRawString* name = ast_factory.GetOneByteString("func");

    BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);
    Register reg = builder.register_allocator()->NewRegister();
    RegisterList args = builder.register_allocator()->NewRegisterList(1);
    builder.LoadNamedProperty(builder.Receiver(), name, slot_index)
        .StoreAccumulatorInRegister(reg)
        .MoveRegister(builder.Receiver(), args[0]);
    builder.CallProperty(reg, args, call_slot_index);
    builder.Return();
    ast_factory.Internalize(i_isolate());
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    InterpreterTester tester(i_isolate(), bytecode_array, metadata);
    auto callable = tester.GetCallableWithReceiver<>();

    Handle<JSAny> object = InterpreterTester::NewObject(
        "new (function Obj() {"
        "  this.val = 1234;"
        "  this.func = function() { return this.val; };"
        "})()");
    DirectHandle<Object> return_val = callable(object).ToHandleChecked();
    CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(1234));
  }

  // Check with two parameters (+ receiver).
  {
    AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                HashSeed(i_isolate()));
    const AstRawString* name = ast_factory.GetOneByteString("func");

    BytecodeArrayBuilder builder(zone(), 1, 4, &feedback_spec);
    Register reg = builder.register_allocator()->NewRegister();
    RegisterList args = builder.register_allocator()->NewRegisterList(3);

    builder.LoadNamedProperty(builder.Receiver(), name, slot_index)
        .StoreAccumulatorInRegister(reg)
        .LoadAccumulatorWithRegister(builder.Receiver())
        .StoreAccumulatorInRegister(args[0])
        .LoadLiteral(Smi::FromInt(51))
        .StoreAccumulatorInRegister(args[1])
        .LoadLiteral(Smi::FromInt(11))
        .StoreAccumulatorInRegister(args[2]);

    builder.CallProperty(reg, args, call_slot_index);

    builder.Return();

    ast_factory.Internalize(i_isolate());
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    InterpreterTester tester(i_isolate(), bytecode_array, metadata);
    auto callable = tester.GetCallableWithReceiver<>();

    Handle<JSAny> object = InterpreterTester::NewObject(
        "new (function Obj() { "
        "  this.func = function(a, b) { return a - b; }"
        "})()");
    DirectHandle<Object> return_val = callable(object).ToHandleChecked();
    CHECK(Object::SameValue(*return_val, Smi::FromInt(40)));
  }

  // Check with 10 parameters (+ receiver).
  {
    AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                HashSeed(i_isolate()));
    const AstRawString* name = ast_factory.GetOneByteString("func");

    BytecodeArrayBuilder builder(zone(), 1, 12, &feedback_spec);
    Register reg = builder.register_allocator()->NewRegister();
    RegisterList args = builder.register_allocator()->NewRegisterList(11);

    builder.LoadNamedProperty(builder.Receiver(), name, slot_index)
        .StoreAccumulatorInRegister(reg)
        .LoadAccumulatorWithRegister(builder.Receiver())
        .StoreAccumulatorInRegister(args[0])
        .LoadLiteral(ast_factory.GetOneByteString("a"))
        .StoreAccumulatorInRegister(args[1])
        .LoadLiteral(ast_factory.GetOneByteString("b"))
        .StoreAccumulatorInRegister(args[2])
        .LoadLiteral(ast_factory.GetOneByteString("c"))
        .StoreAccumulatorInRegister(args[3])
        .LoadLiteral(ast_factory.GetOneByteString("d"))
        .StoreAccumulatorInRegister(args[4])
        .LoadLiteral(ast_factory.GetOneByteString("e"))
        .StoreAccumulatorInRegister(args[5])
        .LoadLiteral(ast_factory.GetOneByteString("f"))
        .StoreAccumulatorInRegister(args[6])
        .LoadLiteral(ast_factory.GetOneByteString("g"))
        .StoreAccumulatorInRegister(args[7])
        .LoadLiteral(ast_factory.GetOneByteString("h"))
        .StoreAccumulatorInRegister(args[8])
        .LoadLiteral(ast_factory.GetOneByteString("i"))
        .StoreAccumulatorInRegister(args[9])
        .LoadLiteral(ast_factory.GetOneByteString("j"))
        .StoreAccumulatorInRegister(args[10]);

    builder.CallProperty(reg, args, call_slot_index);

    builder.Return();

    ast_factory.Internalize(i_isolate());
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

    InterpreterTester tester(i_isolate(), bytecode_array, metadata);
    auto callable = tester.GetCallableWithReceiver<>();

    Handle<JSAny> object = InterpreterTester::NewObject(
        "new (function Obj() { "
        "  this.prefix = \"prefix_\";"
        "  this.func = function(a, b, c, d, e, f, g, h, i, j) {"
        "      return this.prefix + a + b + c + d + e + f + g + h + i + j;"
        "  }"
        "})()");
    DirectHandle<Object> return_val = callable(object).ToHandleChecked();
    DirectHandle<i::String> expected =
        factory->NewStringFromAsciiChecked("prefix_abcdefghij");
    CHECK(i::Cast<i::String>(*return_val)->Equals(*expected));
  }
}

static BytecodeArrayBuilder& SetRegister(BytecodeArrayBuilder* builder,
                                         Register reg, int value,
                                         Register scratch) {
  return builder->StoreAccumulatorInRegister(scratch)
      .LoadLiteral(Smi::FromInt(value))
      .StoreAccumulatorInRegister(reg)
      .LoadAccumulatorWithRegister(scratch);
}

static BytecodeArrayBuilder& IncrementRegister(BytecodeArrayBuilder* builder,
                                               Register reg, int value,
                                               Register scratch,
                                               int slot_index) {
  return builder->StoreAccumulatorInRegister(scratch)
      .LoadLiteral(Smi::FromInt(value))
      .BinaryOperation(Token::kAdd, reg, slot_index)
      .StoreAccumulatorInRegister(reg)
      .LoadAccumulatorWithRegister(scratch);
}

TEST_F(InterpreterTest, InterpreterJumps) {
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 1, 2, &feedback_spec);

  FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot1 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot2 = feedback_spec.AddJumpLoopSlot();

  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);

  Register reg(0), scratch(1);
  BytecodeLoopHeader loop_header;
  BytecodeLabel label[2];

  builder.LoadLiteral(Smi::zero())
      .StoreAccumulatorInRegister(reg)
      .Jump(&label[0]);
  SetRegister(&builder, reg, 1024, scratch).Bind(&label[0]).Bind(&loop_header);
  IncrementRegister(&builder, reg, 1, scratch, GetIndex(slot)).Jump(&label[1]);
  SetRegister(&builder, reg, 2048, scratch)
      .JumpLoop(&loop_header, 0, 0, slot2.ToInt());
  SetRegister(&builder, reg, 4096, scratch).Bind(&label[1]);
  IncrementRegister(&builder, reg, 2, scratch, GetIndex(slot1))
      .LoadAccumulatorWithRegister(reg)
      .Return();

  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
  DirectHandle<Object> return_value = RunBytecode(bytecode_array, metadata);
  CHECK_EQ(Smi::ToInt(*return_value), 3);
}

TEST_F(InterpreterTest, InterpreterConditionalJumps) {
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 1, 2, &feedback_spec);

  FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot1 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot2 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot3 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot4 = feedback_spec.AddBinaryOpICSlot();

  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);

  Register reg(0), scratch(1);
  BytecodeLabel label[2];
  BytecodeLabel done, done1;

  builder.LoadLiteral(Smi::zero())
      .StoreAccumulatorInRegister(reg)
      .LoadFalse()
      .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &label[0]);
  IncrementRegister(&builder, reg, 1024, scratch, GetIndex(slot))
      .Bind(&label[0])
      .LoadTrue()
      .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &done);
  IncrementRegister(&builder, reg, 1, scratch, GetIndex(slot1))
      .LoadTrue()
      .JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &label[1]);
  IncrementRegister(&builder, reg, 2048, scratch, GetIndex(slot2))
      .Bind(&label[1]);
  IncrementRegister(&builder, reg, 2, scratch, GetIndex(slot3))
      .LoadFalse()
      .JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &done1);
  IncrementRegister(&builder, reg, 4, scratch, GetIndex(slot4))
      .LoadAccumulatorWithRegister(reg)
      .Bind(&done)
      .Bind(&done1)
      .Return();

  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
  DirectHandle<Object> return_value = RunBytecode(bytecode_array, metadata);
  CHECK_EQ(Smi::ToInt(*return_value), 7);
}

TEST_F(InterpreterTest, InterpreterConditionalJumps2) {
  // TODO(oth): Add tests for all conditional jumps near and far.

  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 1, 2, &feedback_spec);

  FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot1 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot2 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot3 = feedback_spec.AddBinaryOpICSlot();
  FeedbackSlot slot4 = feedback_spec.AddBinaryOpICSlot();

  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);

  Register reg(0), scratch(1);
  BytecodeLabel label[2];
  BytecodeLabel done, done1;

  builder.LoadLiteral(Smi::zero())
      .StoreAccumulatorInRegister(reg)
      .LoadFalse()
      .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &label[0]);
  IncrementRegister(&builder, reg, 1024, scratch, GetIndex(slot))
      .Bind(&label[0])
      .LoadTrue()
      .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &done);
  IncrementRegister(&builder, reg, 1, scratch, GetIndex(slot1))
      .LoadTrue()
      .JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &label[1]);
  IncrementRegister(&builder, reg, 2048, scratch, GetIndex(slot2))
      .Bind(&label[1]);
  IncrementRegister(&builder, reg, 2, scratch, GetIndex(slot3))
      .LoadFalse()
      .JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &done1);
  IncrementRegister(&builder, reg, 4, scratch, GetIndex(slot4))
      .LoadAccumulatorWithRegister(reg)
      .Bind(&done)
      .Bind(&done1)
      .Return();

  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
  DirectHandle<Object> return_value = RunBytecode(bytecode_array, metadata);
  CHECK_EQ(Smi::ToInt(*return_value), 7);
}

TEST_F(InterpreterTest, InterpreterJumpConstantWith16BitOperand) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 1, 257, &feedback_spec);

  FeedbackSlot slot = feedback_spec.AddBinaryOpICSlot();
  Handle<i::FeedbackMetadata> metadata =
      FeedbackMetadata::New(i_isolate(), &feedback_spec);

  Register reg(0), scratch(256);
  BytecodeLabel done, fake;

  builder.LoadLiteral(Smi::zero());
  builder.StoreAccumulatorInRegister(reg);
  // Conditional jump to the fake label, to force both basic blocks to be live.
  builder.JumpIfTrue(ToBooleanMode::kConvertToBoolean, &fake);
  // Consume all 8-bit operands
  for (int i = 1; i <= 256; i++) {
    builder.LoadLiteral(i + 0.5);
    builder.BinaryOperation(Token::kAdd, reg, GetIndex(slot));
    builder.StoreAccumulatorInRegister(reg);
  }
  builder.Jump(&done);

  // Emit more than 16-bit immediate operands worth of code to jump over.
  builder.Bind(&fake);
  for (int i = 0; i < 6600; i++) {
    builder.LoadLiteral(Smi::zero());  // 1-byte
    builder.BinaryOperation(Token::kAdd, scratch,
                            GetIndex(slot));      // 6-bytes
    builder.StoreAccumulatorInRegister(scratch);  // 4-bytes
    builder.MoveRegister(scratch, reg);           // 6-bytes
  }
  builder.Bind(&done);
  builder.LoadAccumulatorWithRegister(reg);
  builder.Return();

  ast_factory.Internalize(i_isolate());
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
  {
    BytecodeArrayIterator iterator(bytecode_array);

    bool found_16bit_constant_jump = false;
    while (!iterator.done()) {
      if (iterator.current_bytecode() == Bytecode::kJumpConstant &&
          iterator.current_operand_scale() == OperandScale::kDouble) {
        found_16bit_constant_jump = true;
        break;
      }
      iterator.Advance();
    }
    CHECK(found_16bit_constant_jump);
  }

  Handle<Object> return_value = RunBytecode(bytecode_array, metadata);
  CHECK_EQ(Cast<HeapNumber>(return_value)->value(), 256.0 / 2 * (1.5 + 256.5));
}

TEST_F(InterpreterTest, InterpreterJumpWith32BitOperand) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));
  BytecodeArrayBuilder builder(zone(), 1, 1);
  Register reg(0);
  BytecodeLabel done;

  builder.LoadLiteral(Smi::zero());
  builder.StoreAccumulatorInRegister(reg);
  // Consume all 16-bit constant pool entries. Make sure to use doubles so that
  // the jump can't re-use an integer.
  for (int i = 1; i <= 65536; i++) {
    builder.LoadLiteral(i + 0.5);
  }
  builder.Jump(&done);
  
"""


```