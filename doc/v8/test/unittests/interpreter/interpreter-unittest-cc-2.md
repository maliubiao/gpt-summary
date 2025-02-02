Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is part of a V8 unit test file specifically for the interpreter.

Here's a breakdown of the code's functionality:

1. **Jump Bytecode Test:** Checks if a jump instruction with a quadruple operand scale is present in generated bytecode.
2. **Smi Comparisons:** Tests the interpreter's behavior for comparing Smis (small integers) using various comparison operators (==, !=, ===, !==, <, <=, >, >=). It also verifies the feedback collected for these operations.
3. **HeapNumber Comparisons:**  Tests comparisons between HeapNumbers (double-precision floating-point numbers) and verifies the feedback.
4. **BigInt Comparisons:** Checks comparisons involving BigInts and confirms the correct feedback is recorded.
5. **String Comparisons:**  Tests string comparisons using different comparison operators and checks the feedback, distinguishing between ordered comparisons and equality comparisons.
6. **Mixed Comparisons (HeapNumber and String):**  Examines comparisons between HeapNumbers and Strings, where implicit type conversion might occur. It tests both internalized and non-internalized strings and checks the feedback.
7. **Strict Not Equal:**  Specifically tests the strict not equal operator (`!==`) with different data types (numbers and strings).
8. **Compare Typeof:** Tests the `typeof` operator by comparing the result against expected literal flags.
9. **InstanceOf:** Tests the `instanceof` operator.
10. **Test In:** Tests the `in` operator to check for property existence on an object.
11. **Unary Not:** Tests the logical NOT operator (`!`) on boolean values.
12. **Unary Not (Non-Boolean):** Tests the logical NOT operator on non-boolean values, verifying the implicit boolean conversion.
13. **Typeof:** Tests the `typeof` operator and compares the results with expected string outputs.
14. **Call Runtime:** Tests calling runtime functions from the interpreter.
15. **Function Literal:** Tests the creation and execution of function literals.
16. **RegExp Literals:** Tests the creation and execution of regular expression literals.
17. **Array Literals:** Tests the creation and access of array literals.
18. **Object Literals:** Tests the creation and access of object literals, including properties, methods, getters, setters, computed property names, and `__proto__`.
19. **Construct:** Tests the `new` operator for object construction.

The code does not end with `.tq`, so it's not Torque code. It heavily relies on JavaScript-like concepts (types, operators, literals, functions, objects) but is implemented in C++ within the V8 interpreter's testing framework.
这段代码是V8 JavaScript 引擎的单元测试的一部分，主要测试了**V8 解释器**在处理各种**比较操作**时的行为和反馈机制。

**功能归纳:**

这段代码主要测试了 V8 解释器如何处理以下类型的比较操作：

1. **基本类型之间的比较:**
   - **Smi (Small Integer) 比较:** 测试了小整数之间的相等性、严格相等性以及大小比较。
   - **HeapNumber (堆分配的浮点数) 比较:** 测试了浮点数之间的相等性、严格相等性以及大小比较。
   - **BigInt 比较:** 测试了大整数之间的比较，并验证了反馈机制是否正确记录了 BigInt 类型。
   - **字符串比较:** 测试了字符串之间的相等性、严格相等性以及大小比较。

2. **混合类型之间的比较:**
   - **数字和字符串的比较:** 测试了数字和字符串之间的比较，包括类型转换和严格比较的情况。

3. **特殊比较运算符:**
   - **严格不等 (!==):** 专门测试了严格不等运算符在不同类型值之间的行为。
   - **typeof 比较:** 测试了 `typeof` 运算符的结果是否符合预期。
   - **instanceof 比较:** 测试了 `instanceof` 运算符的行为。
   - **in 运算符:** 测试了 `in` 运算符，用于检查对象是否具有某个属性。

4. **逻辑非运算符 (!):**
   - 测试了逻辑非运算符对布尔值以及其他类型值的转换和运算。

**关于 .tq 结尾:**

`v8/test/unittests/interpreter/interpreter-unittest.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。如果以 `.tq` 结尾，那才是 V8 Torque 源代码。

**与 JavaScript 的功能关系和示例:**

这段 C++ 代码测试的功能直接对应于 JavaScript 中的各种比较运算符和类型判断操作。以下是一些 JavaScript 示例，对应于代码中测试的内容：

```javascript
// Smi 比较
console.log(1 == 1);       // true
console.log(1 === 1);      // true
console.log(1 < 2);        // true

// HeapNumber 比较
console.log(1.1 == 1.1);   // true
console.log(1.1 === 1.1);  // true
console.log(1.1 > 1);      // true

// BigInt 比较
console.log(10n == 10n);   // true
console.log(10n < 20n);    // true

// 字符串比较
console.log("a" == "a");   // true
console.log("a" === "a");  // true
console.log("a" < "b");    // true

// 数字和字符串的比较
console.log(1 == "1");     // true (类型转换)
console.log(1 === "1");    // false (没有类型转换)

// 严格不等
console.log(1 !== "1");    // true

// typeof 比较
console.log(typeof 1 === "number");   // true
console.log(typeof "hello" === "string"); // true

// instanceof 比较
class MyClass {}
const obj = new MyClass();
console.log(obj instanceof MyClass); // true

// in 运算符
const myObject = { key: "value" };
console.log("key" in myObject);     // true

// 逻辑非运算符
console.log(!true);       // false
console.log(!0);          // true (0 被转换为 false)
```

**代码逻辑推理和假设输入/输出:**

代码中 `InterpreterSmiComparisons` 测试用例展示了代码逻辑推理。它遍历不同的 Smi 输入值和比较运算符，并断言解释器执行的结果与 C++ 代码中的 `CompareC` 函数的计算结果一致。

**假设输入和输出 (以 `InterpreterSmiComparisons` 中的一个迭代为例):**

* **假设输入:**
    * `inputs[i]` 为 `0`
    * `inputs[j]` 为 `1`
    * `comparison` 为 `Token::kLessThan` (`<`)

* **代码逻辑:**
    1. 加载 `0` 和 `1` 到寄存器。
    2. 执行小于比较操作。
    3. 返回比较结果。

* **预期输出:**
    * `CompareC(Token::kLessThan, 0, 1)` 的结果为 `true`。
    * 解释器执行这段字节码后返回的布尔值对象的值应该为 `true`。
    * Feedback metadata 应该记录比较操作的反馈类型为 `CompareOperationFeedback::kSignedSmall`。

**用户常见的编程错误:**

涉及用户常见的编程错误的地方主要体现在混合类型比较和严格相等性/不等性的使用上：

1. **不理解类型转换导致的意外结果:**

   ```javascript
   console.log(1 == "1");  // 输出 true，可能不是期望的结果
   ```
   用户可能期望比较的是数字类型，但 JavaScript 会进行类型转换。

2. **混淆相等 (==) 和严格相等 (===):**

   ```javascript
   console.log(0 == false);  // 输出 true
   console.log(0 === false); // 输出 false
   ```
   用户可能希望区分不同类型的值，但使用了相等运算符，导致了意外的结果。

3. **在需要比较引用类型时使用相等性运算符:**

   ```javascript
   const obj1 = { value: 1 };
   const obj2 = { value: 1 };
   console.log(obj1 == obj2);   // 输出 false
   console.log(obj1 === obj2);  // 输出 false
   ```
   相等性和严格相等性比较的是对象的引用，而不是对象的内容。要比较对象的内容，需要自定义比较逻辑。

**总结这段代码的功能:**

这段 `interpreter-unittest.cc` 代码的目的是全面地测试 V8 JavaScript 引擎的解释器在处理各种比较运算时的正确性和性能反馈机制。它覆盖了基本数据类型、混合类型以及特殊的比较运算符，并验证了解释器生成的字节码和执行结果是否符合预期。同时，它也隐含地测试了 V8 引擎对于 JavaScript 中常见比较操作的规范遵循。

### 提示词
```
这是目录为v8/test/unittests/interpreter/interpreter-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/interpreter/interpreter-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
builder.LoadLiteral(Smi::zero());
  builder.Bind(&done);
  builder.Return();

  ast_factory.Internalize(i_isolate());
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
  {
    BytecodeArrayIterator iterator(bytecode_array);

    bool found_32bit_jump = false;
    while (!iterator.done()) {
      if (iterator.current_bytecode() == Bytecode::kJump &&
          iterator.current_operand_scale() == OperandScale::kQuadruple) {
        found_32bit_jump = true;
        break;
      }
      iterator.Advance();
    }
    CHECK(found_32bit_jump);
  }

  Handle<Object> return_value = RunBytecode(bytecode_array);
  CHECK_EQ(Cast<HeapNumber>(return_value)->value(), 65536.5);
}

static const Token::Value kComparisonTypes[] = {
    Token::kEq,         Token::kEqStrict,    Token::kLessThan,
    Token::kLessThanEq, Token::kGreaterThan, Token::kGreaterThanEq};

template <typename T>
bool CompareC(Token::Value op, T lhs, T rhs, bool types_differed = false) {
  switch (op) {
    case Token::kEq:
      return lhs == rhs;
    case Token::kNotEq:
      return lhs != rhs;
    case Token::kEqStrict:
      return (lhs == rhs) && !types_differed;
    case Token::kNotEqStrict:
      return (lhs != rhs) || types_differed;
    case Token::kLessThan:
      return lhs < rhs;
    case Token::kLessThanEq:
      return lhs <= rhs;
    case Token::kGreaterThan:
      return lhs > rhs;
    case Token::kGreaterThanEq:
      return lhs >= rhs;
    default:
      UNREACHABLE();
  }
}

TEST_F(InterpreterTest, InterpreterSmiComparisons) {
  // NB Constants cover 31-bit space.
  int inputs[] = {v8::internal::kMinInt / 2,
                  v8::internal::kMinInt / 4,
                  -108733832,
                  -999,
                  -42,
                  -2,
                  -1,
                  0,
                  +1,
                  +2,
                  42,
                  12345678,
                  v8::internal::kMaxInt / 4,
                  v8::internal::kMaxInt / 2};

  for (size_t c = 0; c < arraysize(kComparisonTypes); c++) {
    Token::Value comparison = kComparisonTypes[c];
    for (size_t i = 0; i < arraysize(inputs); i++) {
      for (size_t j = 0; j < arraysize(inputs); j++) {
        FeedbackVectorSpec feedback_spec(zone());
        BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

        FeedbackSlot slot = feedback_spec.AddCompareICSlot();
        Handle<i::FeedbackMetadata> metadata =
            FeedbackMetadata::New(i_isolate(), &feedback_spec);

        Register r0(0);
        builder.LoadLiteral(Smi::FromInt(inputs[i]))
            .StoreAccumulatorInRegister(r0)
            .LoadLiteral(Smi::FromInt(inputs[j]))
            .CompareOperation(comparison, r0, GetIndex(slot))
            .Return();

        Handle<BytecodeArray> bytecode_array =
            builder.ToBytecodeArray(i_isolate());
        InterpreterTester tester(i_isolate(), bytecode_array, metadata);
        auto callable = tester.GetCallable<>();
        DirectHandle<Object> return_value = callable().ToHandleChecked();
        CHECK(IsBoolean(*return_value));
        CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()),
                 CompareC(comparison, inputs[i], inputs[j]));
        if (tester.HasFeedbackMetadata()) {
          Tagged<MaybeObject> feedback = callable.vector()->Get(slot);
          CHECK(IsSmi(feedback));
          CHECK_EQ(CompareOperationFeedback::kSignedSmall,
                   feedback.ToSmi().value());
        }
      }
    }
  }
}

TEST_F(InterpreterTest, InterpreterHeapNumberComparisons) {
  double inputs[] = {std::numeric_limits<double>::min(),
                     std::numeric_limits<double>::max(),
                     -0.001,
                     0.01,
                     0.1000001,
                     1e99,
                     -1e-99};
  for (size_t c = 0; c < arraysize(kComparisonTypes); c++) {
    Token::Value comparison = kComparisonTypes[c];
    for (size_t i = 0; i < arraysize(inputs); i++) {
      for (size_t j = 0; j < arraysize(inputs); j++) {
        AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                    HashSeed(i_isolate()));

        FeedbackVectorSpec feedback_spec(zone());
        BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

        FeedbackSlot slot = feedback_spec.AddCompareICSlot();
        Handle<i::FeedbackMetadata> metadata =
            FeedbackMetadata::New(i_isolate(), &feedback_spec);

        Register r0(0);
        builder.LoadLiteral(inputs[i])
            .StoreAccumulatorInRegister(r0)
            .LoadLiteral(inputs[j])
            .CompareOperation(comparison, r0, GetIndex(slot))
            .Return();

        ast_factory.Internalize(i_isolate());
        Handle<BytecodeArray> bytecode_array =
            builder.ToBytecodeArray(i_isolate());
        InterpreterTester tester(i_isolate(), bytecode_array, metadata);
        auto callable = tester.GetCallable<>();
        DirectHandle<Object> return_value = callable().ToHandleChecked();
        CHECK(IsBoolean(*return_value));
        CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()),
                 CompareC(comparison, inputs[i], inputs[j]));
        if (tester.HasFeedbackMetadata()) {
          Tagged<MaybeObject> feedback = callable.vector()->Get(slot);
          CHECK(IsSmi(feedback));
          CHECK_EQ(CompareOperationFeedback::kNumber, feedback.ToSmi().value());
        }
      }
    }
  }
}

TEST_F(InterpreterTest, InterpreterBigIntComparisons) {
  // This test only checks that the recorded type feedback is kBigInt.
  AstBigInt inputs[] = {AstBigInt("0"), AstBigInt("-42"),
                        AstBigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")};
  for (size_t c = 0; c < arraysize(kComparisonTypes); c++) {
    Token::Value comparison = kComparisonTypes[c];
    for (size_t i = 0; i < arraysize(inputs); i++) {
      for (size_t j = 0; j < arraysize(inputs); j++) {
        AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                    HashSeed(i_isolate()));

        FeedbackVectorSpec feedback_spec(zone());
        BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

        FeedbackSlot slot = feedback_spec.AddCompareICSlot();
        Handle<i::FeedbackMetadata> metadata =
            FeedbackMetadata::New(i_isolate(), &feedback_spec);

        Register r0(0);
        builder.LoadLiteral(inputs[i])
            .StoreAccumulatorInRegister(r0)
            .LoadLiteral(inputs[j])
            .CompareOperation(comparison, r0, GetIndex(slot))
            .Return();

        ast_factory.Internalize(i_isolate());
        Handle<BytecodeArray> bytecode_array =
            builder.ToBytecodeArray(i_isolate());
        InterpreterTester tester(i_isolate(), bytecode_array, metadata);
        auto callable = tester.GetCallable<>();
        DirectHandle<Object> return_value = callable().ToHandleChecked();
        CHECK(IsBoolean(*return_value));
        if (tester.HasFeedbackMetadata()) {
          Tagged<MaybeObject> feedback = callable.vector()->Get(slot);
          CHECK(IsSmi(feedback));
          // TODO(panq): Create a standalone unit test for kBigInt64.
          CHECK(CompareOperationFeedback::kBigInt64 ==
                    feedback.ToSmi().value() ||
                CompareOperationFeedback::kBigInt == feedback.ToSmi().value());
        }
      }
    }
  }
}

TEST_F(InterpreterTest, InterpreterStringComparisons) {
  std::string inputs[] = {"A", "abc", "z", "", "Foo!", "Foo"};

  for (size_t c = 0; c < arraysize(kComparisonTypes); c++) {
    Token::Value comparison = kComparisonTypes[c];
    for (size_t i = 0; i < arraysize(inputs); i++) {
      for (size_t j = 0; j < arraysize(inputs); j++) {
        AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                    HashSeed(i_isolate()));

        const char* lhs = inputs[i].c_str();
        const char* rhs = inputs[j].c_str();

        FeedbackVectorSpec feedback_spec(zone());
        FeedbackSlot slot = feedback_spec.AddCompareICSlot();
        Handle<i::FeedbackMetadata> metadata =
            FeedbackMetadata::New(i_isolate(), &feedback_spec);

        BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);
        Register r0(0);
        builder.LoadLiteral(ast_factory.GetOneByteString(lhs))
            .StoreAccumulatorInRegister(r0)
            .LoadLiteral(ast_factory.GetOneByteString(rhs))
            .CompareOperation(comparison, r0, GetIndex(slot))
            .Return();

        ast_factory.Internalize(i_isolate());
        Handle<BytecodeArray> bytecode_array =
            builder.ToBytecodeArray(i_isolate());
        InterpreterTester tester(i_isolate(), bytecode_array, metadata);
        auto callable = tester.GetCallable<>();
        DirectHandle<Object> return_value = callable().ToHandleChecked();
        CHECK(IsBoolean(*return_value));
        CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()),
                 CompareC(comparison, inputs[i], inputs[j]));
        if (tester.HasFeedbackMetadata()) {
          Tagged<MaybeObject> feedback = callable.vector()->Get(slot);
          CHECK(IsSmi(feedback));
          int const expected_feedback =
              Token::IsOrderedRelationalCompareOp(comparison)
                  ? CompareOperationFeedback::kString
                  : CompareOperationFeedback::kInternalizedString;
          CHECK_EQ(expected_feedback, feedback.ToSmi().value());
        }
      }
    }
  }
}

static void LoadStringAndAddSpace(BytecodeArrayBuilder* builder,
                                  AstValueFactory* ast_factory,
                                  const char* cstr,
                                  FeedbackSlot string_add_slot) {
  Register string_reg = builder->register_allocator()->NewRegister();

  (*builder)
      .LoadLiteral(ast_factory->GetOneByteString(cstr))
      .StoreAccumulatorInRegister(string_reg)
      .LoadLiteral(ast_factory->GetOneByteString(" "))
      .BinaryOperation(Token::kAdd, string_reg, GetIndex(string_add_slot));
}

TEST_F(InterpreterTest, InterpreterMixedComparisons) {
  // This test compares a HeapNumber with a String. The latter is
  // convertible to a HeapNumber so comparison will be between numeric
  // values except for the strict comparisons where no conversion is
  // performed.
  const char* inputs[] = {"-1.77", "-40.333", "0.01", "55.77e50", "2.01"};

  enum WhichSideString { kLhsIsString, kRhsIsString };

  enum StringType { kInternalizedStringConstant, kComputedString };

  for (size_t c = 0; c < arraysize(kComparisonTypes); c++) {
    Token::Value comparison = kComparisonTypes[c];
    for (size_t i = 0; i < arraysize(inputs); i++) {
      for (size_t j = 0; j < arraysize(inputs); j++) {
        // We test the case where either the lhs or the rhs is a string...
        for (WhichSideString which_side : {kLhsIsString, kRhsIsString}) {
          // ... and the case when the string is internalized or computed.
          for (StringType string_type :
               {kInternalizedStringConstant, kComputedString}) {
            const char* lhs_cstr = inputs[i];
            const char* rhs_cstr = inputs[j];
            double lhs = StringToDouble(lhs_cstr, NO_CONVERSION_FLAG);
            double rhs = StringToDouble(rhs_cstr, NO_CONVERSION_FLAG);

            AstValueFactory ast_factory(zone(),
                                        i_isolate()->ast_string_constants(),
                                        HashSeed(i_isolate()));
            FeedbackVectorSpec feedback_spec(zone());
            BytecodeArrayBuilder builder(zone(), 1, 0, &feedback_spec);

            FeedbackSlot string_add_slot = feedback_spec.AddBinaryOpICSlot();
            FeedbackSlot slot = feedback_spec.AddCompareICSlot();
            Handle<i::FeedbackMetadata> metadata =
                FeedbackMetadata::New(i_isolate(), &feedback_spec);

            // lhs is in a register, rhs is in the accumulator.
            Register lhs_reg = builder.register_allocator()->NewRegister();

            if (which_side == kRhsIsString) {
              // Comparison with HeapNumber on the lhs and String on the rhs.

              builder.LoadLiteral(lhs).StoreAccumulatorInRegister(lhs_reg);

              if (string_type == kInternalizedStringConstant) {
                // rhs string is internalized.
                builder.LoadLiteral(ast_factory.GetOneByteString(rhs_cstr));
              } else {
                CHECK_EQ(string_type, kComputedString);
                // rhs string is not internalized (append a space to the end).
                LoadStringAndAddSpace(&builder, &ast_factory, rhs_cstr,
                                      string_add_slot);
              }
            } else {
              CHECK_EQ(which_side, kLhsIsString);
              // Comparison with String on the lhs and HeapNumber on the rhs.

              if (string_type == kInternalizedStringConstant) {
                // lhs string is internalized
                builder.LoadLiteral(ast_factory.GetOneByteString(lhs_cstr));
              } else {
                CHECK_EQ(string_type, kComputedString);
                // lhs string is not internalized (append a space to the end).
                LoadStringAndAddSpace(&builder, &ast_factory, lhs_cstr,
                                      string_add_slot);
              }
              builder.StoreAccumulatorInRegister(lhs_reg);

              builder.LoadLiteral(rhs);
            }

            builder.CompareOperation(comparison, lhs_reg, GetIndex(slot))
                .Return();

            ast_factory.Internalize(i_isolate());
            Handle<BytecodeArray> bytecode_array =
                builder.ToBytecodeArray(i_isolate());
            InterpreterTester tester(i_isolate(), bytecode_array, metadata);
            auto callable = tester.GetCallable<>();
            DirectHandle<Object> return_value = callable().ToHandleChecked();
            CHECK(IsBoolean(*return_value));
            CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()),
                     CompareC(comparison, lhs, rhs, true));
            if (tester.HasFeedbackMetadata()) {
              Tagged<MaybeObject> feedback = callable.vector()->Get(slot);
              CHECK(IsSmi(feedback));
              if (kComparisonTypes[c] == Token::kEq) {
                // For sloppy equality, we have more precise feedback.
                CHECK_EQ(
                    CompareOperationFeedback::kNumber |
                        (string_type == kInternalizedStringConstant
                             ? CompareOperationFeedback::kInternalizedString
                             : CompareOperationFeedback::kString),
                    feedback.ToSmi().value());
              } else {
                // Comparison with a number and string collects kAny feedback.
                CHECK_EQ(CompareOperationFeedback::kAny,
                         feedback.ToSmi().value());
              }
            }
          }
        }
      }
    }
  }
}

TEST_F(InterpreterTest, InterpreterStrictNotEqual) {
  Factory* factory = i_isolate()->factory();
  const char* code_snippet =
      "function f(lhs, rhs) {\n"
      "  return lhs !== rhs;\n"
      "}\n"
      "f(0, 0);\n";
  InterpreterTester tester(i_isolate(), code_snippet);
  auto callable = tester.GetCallable<Handle<Object>, Handle<Object>>();

  // Test passing different types.
  const char* inputs[] = {"-1.77", "-40.333", "0.01", "55.77e5", "2.01"};
  for (size_t i = 0; i < arraysize(inputs); i++) {
    for (size_t j = 0; j < arraysize(inputs); j++) {
      double lhs = StringToDouble(inputs[i], NO_CONVERSION_FLAG);
      double rhs = StringToDouble(inputs[j], NO_CONVERSION_FLAG);
      Handle<Object> lhs_obj = factory->NewNumber(lhs);
      Handle<Object> rhs_obj = factory->NewStringFromAsciiChecked(inputs[j]);

      DirectHandle<Object> return_value =
          callable(lhs_obj, rhs_obj).ToHandleChecked();
      CHECK(IsBoolean(*return_value));
      CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()),
               CompareC(Token::kNotEqStrict, lhs, rhs, true));
    }
  }

  // Test passing string types.
  const char* inputs_str[] = {"A", "abc", "z", "", "Foo!", "Foo"};
  for (size_t i = 0; i < arraysize(inputs_str); i++) {
    for (size_t j = 0; j < arraysize(inputs_str); j++) {
      Handle<Object> lhs_obj =
          factory->NewStringFromAsciiChecked(inputs_str[i]);
      Handle<Object> rhs_obj =
          factory->NewStringFromAsciiChecked(inputs_str[j]);

      DirectHandle<Object> return_value =
          callable(lhs_obj, rhs_obj).ToHandleChecked();
      CHECK(IsBoolean(*return_value));
      CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()),
               CompareC(Token::kNotEqStrict, inputs_str[i], inputs_str[j]));
    }
  }

  // Test passing doubles.
  double inputs_number[] = {std::numeric_limits<double>::min(),
                            std::numeric_limits<double>::max(),
                            -0.001,
                            0.01,
                            0.1000001,
                            1e99,
                            -1e-99};
  for (size_t i = 0; i < arraysize(inputs_number); i++) {
    for (size_t j = 0; j < arraysize(inputs_number); j++) {
      Handle<Object> lhs_obj = factory->NewNumber(inputs_number[i]);
      Handle<Object> rhs_obj = factory->NewNumber(inputs_number[j]);

      DirectHandle<Object> return_value =
          callable(lhs_obj, rhs_obj).ToHandleChecked();
      CHECK(IsBoolean(*return_value));
      CHECK_EQ(
          Object::BooleanValue(*return_value, i_isolate()),
          CompareC(Token::kNotEqStrict, inputs_number[i], inputs_number[j]));
    }
  }
}

TEST_F(InterpreterTest, InterpreterCompareTypeOf) {
  using LiteralFlag = TestTypeOfFlags::LiteralFlag;

  Factory* factory = i_isolate()->factory();

  std::pair<Handle<Object>, LiteralFlag> inputs[] = {
      {handle(Smi::FromInt(24), i_isolate()), LiteralFlag::kNumber},
      {factory->NewNumber(2.5), LiteralFlag::kNumber},
      {factory->NewStringFromAsciiChecked("foo"), LiteralFlag::kString},
      {factory
           ->NewConsString(factory->NewStringFromAsciiChecked("foo"),
                           factory->NewStringFromAsciiChecked("bar"))
           .ToHandleChecked(),
       LiteralFlag::kString},
      {factory->prototype_string(), LiteralFlag::kString},
      {factory->NewSymbol(), LiteralFlag::kSymbol},
      {factory->true_value(), LiteralFlag::kBoolean},
      {factory->false_value(), LiteralFlag::kBoolean},
      {factory->undefined_value(), LiteralFlag::kUndefined},
      {InterpreterTester::NewObject(
           "(function() { return function() {}; })();"),
       LiteralFlag::kFunction},
      {InterpreterTester::NewObject("new Object();"), LiteralFlag::kObject},
      {factory->null_value(), LiteralFlag::kObject},
  };
  const LiteralFlag kLiterals[] = {
#define LITERAL_FLAG(name, _) LiteralFlag::k##name,
      TYPEOF_LITERAL_LIST(LITERAL_FLAG)
#undef LITERAL_FLAG
  };

  for (size_t l = 0; l < arraysize(kLiterals); l++) {
    LiteralFlag literal_flag = kLiterals[l];
    if (literal_flag == LiteralFlag::kOther) continue;

    BytecodeArrayBuilder builder(zone(), 2, 0);
    builder.LoadAccumulatorWithRegister(builder.Parameter(0))
        .CompareTypeOf(kLiterals[l])
        .Return();
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
    InterpreterTester tester(i_isolate(), bytecode_array);
    auto callable = tester.GetCallable<Handle<Object>>();

    for (size_t i = 0; i < arraysize(inputs); i++) {
      DirectHandle<Object> return_value =
          callable(inputs[i].first).ToHandleChecked();
      CHECK(IsBoolean(*return_value));
      CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()),
               inputs[i].second == literal_flag);
    }
  }
}

TEST_F(InterpreterTest, InterpreterInstanceOf) {
  Factory* factory = i_isolate()->factory();
  DirectHandle<i::String> name = factory->NewStringFromAsciiChecked("cons");
  Handle<i::JSFunction> func = factory->NewFunctionForTesting(name);
  Handle<i::JSObject> instance = factory->NewJSObject(func);
  Handle<i::Object> other = factory->NewNumber(3.3333);
  Handle<i::Object> cases[] = {Cast<i::Object>(instance), other};
  for (size_t i = 0; i < arraysize(cases); i++) {
    bool expected_value = (i == 0);
    FeedbackVectorSpec feedback_spec(zone());
    BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

    Register r0(0);
    size_t case_entry = builder.AllocateDeferredConstantPoolEntry();
    builder.SetDeferredConstantPoolEntry(case_entry, cases[i]);
    builder.LoadConstantPoolEntry(case_entry).StoreAccumulatorInRegister(r0);

    FeedbackSlot slot = feedback_spec.AddInstanceOfSlot();
    Handle<i::FeedbackMetadata> metadata =
        FeedbackMetadata::New(i_isolate(), &feedback_spec);

    size_t func_entry = builder.AllocateDeferredConstantPoolEntry();
    builder.SetDeferredConstantPoolEntry(func_entry, func);
    builder.LoadConstantPoolEntry(func_entry)
        .CompareOperation(Token::kInstanceOf, r0, GetIndex(slot))
        .Return();

    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
    DirectHandle<Object> return_value = RunBytecode(bytecode_array, metadata);
    CHECK(IsBoolean(*return_value));
    CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()), expected_value);
  }
}

TEST_F(InterpreterTest, InterpreterTestIn) {
  Factory* factory = i_isolate()->factory();
  // Allocate an array
  Handle<i::JSArray> array =
      factory->NewJSArray(0, i::ElementsKind::PACKED_SMI_ELEMENTS);
  // Check for these properties on the array object
  const char* properties[] = {"length", "fuzzle", "x", "0"};
  for (size_t i = 0; i < arraysize(properties); i++) {
    AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                                HashSeed(i_isolate()));

    bool expected_value = (i == 0);
    FeedbackVectorSpec feedback_spec(zone());
    BytecodeArrayBuilder builder(zone(), 1, 1, &feedback_spec);

    Register r0(0);
    builder.LoadLiteral(ast_factory.GetOneByteString(properties[i]))
        .StoreAccumulatorInRegister(r0);

    FeedbackSlot slot = feedback_spec.AddKeyedHasICSlot();
    Handle<i::FeedbackMetadata> metadata =
        FeedbackMetadata::New(i_isolate(), &feedback_spec);

    size_t array_entry = builder.AllocateDeferredConstantPoolEntry();
    builder.SetDeferredConstantPoolEntry(array_entry, array);
    builder.LoadConstantPoolEntry(array_entry)
        .CompareOperation(Token::kIn, r0, GetIndex(slot))
        .Return();

    ast_factory.Internalize(i_isolate());
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
    DirectHandle<Object> return_value = RunBytecode(bytecode_array, metadata);
    CHECK(IsBoolean(*return_value));
    CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()), expected_value);
  }
}

TEST_F(InterpreterTest, InterpreterUnaryNot) {
  for (size_t i = 1; i < 10; i++) {
    bool expected_value = ((i & 1) == 1);
    BytecodeArrayBuilder builder(zone(), 1, 0);

    builder.LoadFalse();
    for (size_t j = 0; j < i; j++) {
      builder.LogicalNot(ToBooleanMode::kAlreadyBoolean);
    }
    builder.Return();
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
    DirectHandle<Object> return_value = RunBytecode(bytecode_array);
    CHECK(IsBoolean(*return_value));
    CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()), expected_value);
  }
}

TEST_F(InterpreterTest, InterpreterUnaryNotNonBoolean) {
  AstValueFactory ast_factory(zone(), i_isolate()->ast_string_constants(),
                              HashSeed(i_isolate()));

  std::pair<LiteralForTest, bool> object_type_tuples[] = {
      std::make_pair(LiteralForTest(LiteralForTest::kUndefined), true),
      std::make_pair(LiteralForTest(LiteralForTest::kNull), true),
      std::make_pair(LiteralForTest(LiteralForTest::kFalse), true),
      std::make_pair(LiteralForTest(LiteralForTest::kTrue), false),
      std::make_pair(LiteralForTest(9.1), false),
      std::make_pair(LiteralForTest(0), true),
      std::make_pair(LiteralForTest(ast_factory.GetOneByteString("hello")),
                     false),
      std::make_pair(LiteralForTest(ast_factory.GetOneByteString("")), true),
  };
  ast_factory.Internalize(i_isolate());

  for (size_t i = 0; i < arraysize(object_type_tuples); i++) {
    BytecodeArrayBuilder builder(zone(), 1, 0);

    LoadLiteralForTest(&builder, object_type_tuples[i].first);
    builder.LogicalNot(ToBooleanMode::kConvertToBoolean).Return();
    Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());
    DirectHandle<Object> return_value = RunBytecode(bytecode_array);
    CHECK(IsBoolean(*return_value));
    CHECK_EQ(Object::BooleanValue(*return_value, i_isolate()),
             object_type_tuples[i].second);
  }
}

TEST_F(InterpreterTest, InterpreterTypeof) {
  std::pair<const char*, const char*> typeof_vals[] = {
      std::make_pair("return typeof undefined;", "undefined"),
      std::make_pair("return typeof null;", "object"),
      std::make_pair("return typeof true;", "boolean"),
      std::make_pair("return typeof false;", "boolean"),
      std::make_pair("return typeof 9.1;", "number"),
      std::make_pair("return typeof 7771;", "number"),
      std::make_pair("return typeof 'hello';", "string"),
      std::make_pair("return typeof global_unallocated;", "undefined"),
  };

  for (size_t i = 0; i < arraysize(typeof_vals); i++) {
    std::string source(InterpreterTester::SourceForBody(typeof_vals[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());

    auto callable = tester.GetCallable<>();
    DirectHandle<v8::internal::String> return_value =
        Cast<v8::internal::String>(callable().ToHandleChecked());
    auto actual = return_value->ToCString();
    CHECK_EQ(strcmp(&actual[0], typeof_vals[i].second), 0);
  }
}

TEST_F(InterpreterTest, InterpreterCallRuntime) {
  BytecodeArrayBuilder builder(zone(), 1, 2);
  RegisterList args = builder.register_allocator()->NewRegisterList(2);

  builder.LoadLiteral(Smi::FromInt(15))
      .StoreAccumulatorInRegister(args[0])
      .LoadLiteral(Smi::FromInt(40))
      .StoreAccumulatorInRegister(args[1])
      .CallRuntime(Runtime::kAdd, args)
      .Return();
  Handle<BytecodeArray> bytecode_array = builder.ToBytecodeArray(i_isolate());

  DirectHandle<Object> return_val = RunBytecode(bytecode_array);
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(55));
}

TEST_F(InterpreterTest, InterpreterFunctionLiteral) {
  // Test calling a function literal.
  std::string source("function " + InterpreterTester::function_name() +
                     "(a) {\n"
                     "  return (function(x){ return x + 2; })(a);\n"
                     "}");
  InterpreterTester tester(i_isolate(), source.c_str());
  auto callable = tester.GetCallable<Handle<Object>>();

  DirectHandle<i::Object> return_val =
      callable(Handle<Smi>(Smi::FromInt(3), i_isolate())).ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::FromInt(5));
}

TEST_F(InterpreterTest, InterpreterRegExpLiterals) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> literals[] = {
      std::make_pair("return /abd/.exec('cccabbdd');\n", factory->null_value()),
      std::make_pair("return /ab+d/.exec('cccabbdd')[0];\n",
                     factory->NewStringFromStaticChars("abbd")),
      std::make_pair("return /AbC/i.exec('ssaBC')[0];\n",
                     factory->NewStringFromStaticChars("aBC")),
      std::make_pair("return 'ssaBC'.match(/AbC/i)[0];\n",
                     factory->NewStringFromStaticChars("aBC")),
      std::make_pair("return 'ssaBCtAbC'.match(/(AbC)/gi)[1];\n",
                     factory->NewStringFromStaticChars("AbC")),
  };

  for (size_t i = 0; i < arraysize(literals); i++) {
    std::string source(InterpreterTester::SourceForBody(literals[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *literals[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterArrayLiterals) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> literals[] = {
      std::make_pair("return [][0];\n", factory->undefined_value()),
      std::make_pair("return [1, 3, 2][1];\n",
                     handle(Smi::FromInt(3), i_isolate())),
      std::make_pair("return ['a', 'b', 'c'][2];\n",
                     factory->NewStringFromStaticChars("c")),
      std::make_pair("var a = 100; return [a, a + 1, a + 2, a + 3][2];\n",
                     handle(Smi::FromInt(102), i_isolate())),
      std::make_pair("return [[1, 2, 3], ['a', 'b', 'c']][1][0];\n",
                     factory->NewStringFromStaticChars("a")),
      std::make_pair("var t = 't'; return [[t, t + 'est'], [1 + t]][0][1];\n",
                     factory->NewStringFromStaticChars("test"))};

  for (size_t i = 0; i < arraysize(literals); i++) {
    std::string source(InterpreterTester::SourceForBody(literals[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *literals[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterObjectLiterals) {
  Factory* factory = i_isolate()->factory();

  std::pair<const char*, Handle<Object>> literals[] = {
      std::make_pair("return { }.name;", factory->undefined_value()),
      std::make_pair("return { name: 'string', val: 9.2 }.name;",
                     factory->NewStringFromStaticChars("string")),
      std::make_pair("var a = 15; return { name: 'string', val: a }.val;",
                     handle(Smi::FromInt(15), i_isolate())),
      std::make_pair("var a = 5; return { val: a, val: a + 1 }.val;",
                     handle(Smi::FromInt(6), i_isolate())),
      std::make_pair("return { func: function() { return 'test' } }.func();",
                     factory->NewStringFromStaticChars("test")),
      std::make_pair("return { func(a) { return a + 'st'; } }.func('te');",
                     factory->NewStringFromStaticChars("test")),
      std::make_pair("return { get a() { return 22; } }.a;",
                     handle(Smi::FromInt(22), i_isolate())),
      std::make_pair("var a = { get b() { return this.x + 't'; },\n"
                     "          set b(val) { this.x = val + 's' } };\n"
                     "a.b = 'te';\n"
                     "return a.b;",
                     factory->NewStringFromStaticChars("test")),
      std::make_pair("var a = 123; return { 1: a }[1];",
                     handle(Smi::FromInt(123), i_isolate())),
      std::make_pair("return Object.getPrototypeOf({ __proto__: null });",
                     factory->null_value()),
      std::make_pair("var a = 'test'; return { [a]: 1 }.test;",
                     handle(Smi::FromInt(1), i_isolate())),
      std::make_pair("var a = 'test'; return { b: a, [a]: a + 'ing' }['test']",
                     factory->NewStringFromStaticChars("testing")),
      std::make_pair("var a = 'proto_str';\n"
                     "var b = { [a]: 1, __proto__: { var : a } };\n"
                     "return Object.getPrototypeOf(b).var",
                     factory->NewStringFromStaticChars("proto_str")),
      std::make_pair("var n = 'name';\n"
                     "return { [n]: 'val', get a() { return 987 } }['a'];",
                     handle(Smi::FromInt(987), i_isolate())),
  };

  for (size_t i = 0; i < arraysize(literals); i++) {
    std::string source(InterpreterTester::SourceForBody(literals[i].first));
    InterpreterTester tester(i_isolate(), source.c_str());
    auto callable = tester.GetCallable<>();

    DirectHandle<i::Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *literals[i].second));
  }
}

TEST_F(InterpreterTest, InterpreterConstruct) {
  std::string source(
      "function counter() { this.count = 0; }\n"
      "function " +
      InterpreterTester::function_name() +
      "() {\n"
      "  var c = new counter();\n"
      "  return c.count;\n"
      "}");
  InterpreterTester tester(i_isolate(), source.c_str());
  auto callable = tester.GetCallable<>();

  DirectHandle<Object> return_val = callable().ToHandleChecked();
  CHECK_EQ(Cast<Smi>(*return_val), Smi::zero());
}

TEST_F(InterpreterTest
```