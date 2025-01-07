Response:
The user wants to understand the functionality of the provided C++ source code file `v8/test/unittests/interpreter/interpreter-unittest.cc`. They've also provided a few specific instructions related to the content and format of the answer.

Here's a breakdown of the thinking process to address each part of the request:

1. **Overall Functionality:** The first step is to read through the code and identify its main purpose. Keywords like `TEST_F`, `BytecodeArrayBuilder`, `InterpreterTester`, and operations like `Load`, `Store`, and `BinaryOperation` clearly indicate that this file contains unit tests for the V8 interpreter. It specifically tests the execution of different bytecode sequences.

2. **`.tq` Extension:** The user asks about the `.tq` extension. Based on V8 knowledge, `.tq` files are related to Torque, V8's type definition language. Since the provided file is `.cc`, it's a C++ file and *not* a Torque file.

3. **Relationship to JavaScript:** The interpreter is the component of V8 that executes JavaScript bytecode. Therefore, the tests in this file directly relate to how JavaScript code is executed within V8. To illustrate this, simple JavaScript examples that would generate the tested bytecodes need to be provided. For example, `1 + 2` maps to an addition bytecode.

4. **Code Logic and Inference:**  Many of the tests involve simple bytecode sequences that perform operations on specific input values. For these, we can infer the expected output. For instance, loading `true` and returning it should result in the JavaScript `true` value. For binary operations, we can apply the corresponding JavaScript operator to the inputs. The user wants an example of this with assumed inputs and outputs.

5. **Common Programming Errors:** Since the code tests interpreter behavior, common programming errors at the JavaScript level that might lead to these bytecodes being executed are relevant. Examples include type errors in binary operations or accessing undefined variables (although the latter isn't explicitly tested in *this snippet*).

6. **Summarization:** Finally, the user requests a summary of the file's function. This should reiterate that it's a unit test file for the V8 interpreter, focusing on verifying the correct execution of various bytecode instructions.

**Pre-computation and Pre-analysis:**

* **Bytecode Opcodes:** Familiarity with common bytecode opcodes like `Return`, `LoadUndefined`, `LoadLiteral`, `StoreAccumulatorInRegister`, `BinaryOperation` is essential to understand the code.
* **V8 Testing Framework:** Understanding the use of `TEST_F` and `WithContextMixin` for setting up test fixtures in V8's testing environment is helpful.
* **Interpreter Tester:** Knowing that `InterpreterTester` is a utility for running bytecode within a controlled environment is crucial.
* **Feedback Vectors:** Understanding the concept of feedback vectors and their role in optimizing bytecode execution is necessary for tests involving `FeedbackSlot` and `FeedbackMetadata`.

**Drafting the Response (Mental Simulation):**

* Start with the main function: unit testing the interpreter.
* Address the `.tq` question directly and clearly state it's a C++ file.
* Connect the tests to JavaScript execution with examples.
* Choose a simple test case (like adding two numbers) for the input/output inference example.
* Think about common JavaScript mistakes that might trigger the tested bytecodes (e.g., adding a number and a string).
* Conclude with a concise summary.

**Refinement:** Ensure the JavaScript examples are clear and directly relate to the C++ bytecode being tested. Make sure the input/output example is straightforward to follow. The summary should be brief and to the point. Acknowledge that this is the first part of a series.
```cpp
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
       BinaryOperationFeedback::kSignedSmall
Prompt: 
```
这是目录为v8/test/unittests/interpreter/interpreter-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/interpreter/interpreter-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能

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

    InterpreterTester tester(i_isolate(), bytecode_array
"""


```