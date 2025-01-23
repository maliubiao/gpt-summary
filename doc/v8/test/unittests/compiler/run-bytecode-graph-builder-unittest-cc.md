Response:
The user wants to understand the functionality of the C++ source code file `v8/test/unittests/compiler/run-bytecode-graph-builder-unittest.cc`. They've provided the first part of the file's content and are expecting a summary. Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The filename itself gives a strong hint: `run-bytecode-graph-builder-unittest`. This suggests the code is a unit test specifically for the "bytecode graph builder" component within the V8 compiler.

2. **Scan for Key Terms and Structures:** Look for recurring patterns and keywords within the provided code.
    * `TEST_F`:  This macro clearly indicates the presence of Google Test framework tests. The tests are grouped within a class `RunBytecodeGraphBuilderTest`.
    * `BytecodeGraphTester`: This class seems to be a helper for setting up and executing tests. It takes a script string as input and likely handles compilation and execution.
    * `ExpectedSnippet`: This structure holds a JavaScript code snippet and the expected return value. This is a strong indicator of testing specific code behaviors.
    * `CompileRun`:  This function compiles and runs JavaScript code.
    * `GetCallable`: This likely retrieves a callable function from the compiled script.
    *  Various test functions (e.g., `TestBytecodeGraphBuilderNamedStore`, `TestBytecodeGraphBuilderKeyedStore`, etc.): These names directly suggest the aspects of the bytecode graph builder being tested. They seem to cover different JavaScript operations.
    *  Macros like `SHARD_TEST_BY_2`, `SHARD_TEST_BY_4`: These likely indicate that the tests are sharded, possibly for parallel execution or to manage test size.
    * The extensive use of `REPEAT_` macros suggests testing scenarios with a large number of similar operations, possibly to stress test the bytecode graph builder.

3. **Infer Functionality from Test Names and Snippets:** Analyze the names of the test functions and the structure of `ExpectedSnippet`.
    * `BytecodeGraphBuilderReturnStatements`: Tests different types of `return` statements in JavaScript.
    * `BytecodeGraphBuilderPrimitiveExpressions`: Tests basic arithmetic operations.
    * `BytecodeGraphBuilderTwoParameterTests`: Tests operations with two input parameters.
    * `BytecodeGraphBuilderNamedLoad`/`Store`: Tests accessing and modifying object properties using their names.
    * `BytecodeGraphBuilderKeyedLoad`/`Store`: Tests accessing and modifying object properties using bracket notation (keys).
    * `BytecodeGraphBuilderGlobals`: Tests how global variables are handled.
    * `BytecodeGraphBuilderPropertyCall`: Tests calling methods on objects.
    * `BytecodeGraphBuilderCallNew`: Tests the `new` operator for object creation.
    * `BytecodeGraphBuilderCreateClosure`: Tests the creation and behavior of closures.
    * `BytecodeGraphBuilderCallRuntime`: Tests calls to V8's internal runtime functions.
    * `BytecodeGraphBuilderToObject`, `BytecodeGraphBuilderToName`: These hint at testing type conversion operations.
    * `BytecodeGraphBuilderLogicalNot`, `BytecodeGraphBuilderTypeOf`, `BytecodeGraphBuilderCompareTypeOf`: These test logical and type-related operators.

4. **Address Specific Instructions:**  Review the user's specific requests:
    * **Function Listing:**  The decomposed analysis above directly leads to the list of functionalities.
    * **`.tq` Check:**  The code does *not* end with `.tq`. It's C++.
    * **JavaScript Relationship and Examples:** The tests directly involve executing JavaScript code snippets. Provide relevant JavaScript examples based on the tested functionalities.
    * **Code Logic Inference (Assumptions and Outputs):** Choose a simple test case (like `BytecodeGraphBuilderReturnStatements`) and illustrate the input (JavaScript snippet) and expected output (the returned value).
    * **Common Programming Errors:**  Think about typical mistakes related to the tested areas. For example, incorrect property access, type mismatches in comparisons, or misunderstanding the `typeof` operator.
    * **Summary of Functionality (Part 1):** Synthesize the observations into a concise summary of what the provided code does.

5. **Structure the Answer:** Organize the findings logically, addressing each of the user's points in a clear and understandable manner. Use headings and bullet points for better readability.

6. **Refine and Verify:** Review the generated answer to ensure accuracy, completeness (within the context of the provided code snippet), and clarity. Make sure the JavaScript examples are correct and relevant. Double-check that all parts of the user's request have been addressed.
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/pipeline.h"
#include "src/debug/debug-interface.h"
#include "src/execution/execution.h"
#include "src/handles/handles.h"
#include "src/interpreter/bytecode-array-builder.h"
#include "src/interpreter/interpreter.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parse-info.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {

#define SHARD_TEST_BY_2(x)                                   \
  TEST_F(RunBytecodeGraphBuilderTest, x##_0) { Test##x(0); } \
  TEST_F(RunBytecodeGraphBuilderTest, x##_1) { Test##x(1); }
#define SHARD_TEST_BY_4(x)                                   \
  TEST_F(RunBytecodeGraphBuilderTest, x##_0) { Test##x(0); } \
  TEST_F(RunBytecodeGraphBuilderTest, x##_1) { Test##x(1); } \
  TEST_F(RunBytecodeGraphBuilderTest, x##_2) { Test##x(2); } \
  TEST_F(RunBytecodeGraphBuilderTest, x##_3) { Test##x(3); }

static const char kFunctionName[] = "f";

static const Token::Value kCompareOperators[] = {
    Token::kEq,          Token::kNotEq,        Token::kEqStrict,
    Token::kNotEqStrict, Token::kLessThan,     Token::kLessThanEq,
    Token::kGreaterThan, Token::kGreaterThanEq};

static const int SMI_MAX = (1 << 30) - 1;
static const int SMI_MIN = -(1 << 30);

static MaybeHandle<Object> CallFunction(Isolate* isolate,
                                        Handle<JSFunction> function) {
  return Execution::Call(isolate, function,
                         isolate->factory()->undefined_value(), 0, nullptr);
}

template <class... A>
static MaybeHandle<Object> CallFunction(Isolate* isolate,
                                        Handle<JSFunction> function,
                                        A... args) {
  Handle<Object> argv[] = {args...};
  return Execution::Call(isolate, function,
                         isolate->factory()->undefined_value(), sizeof...(args),
                         argv);
}

static v8::Local<v8::Value> CompileRun(v8::Isolate* isolate,
                                       const char* source) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Script> script =
      v8::Script::Compile(
          context, v8::String::NewFromUtf8(isolate, source).ToLocalChecked())
          .ToLocalChecked();

  v8::Local<v8::Value> result;
  if (script->Run(context).ToLocal(&result)) {
    return result;
  } else {
    return v8::Local<v8::Value>();
  }
}

template <class... A>
class BytecodeGraphCallable {
 public:
  BytecodeGraphCallable(Isolate* isolate, Handle<JSFunction> function)
      : isolate_(isolate), function_(function) {}
  virtual ~BytecodeGraphCallable() = default;

  MaybeHandle<Object> operator()(A... args) {
    return CallFunction(isolate_, function_, args...);
  }

 private:
  Isolate* isolate_;
  Handle<JSFunction> function_;
};

class BytecodeGraphTester {
 public:
  BytecodeGraphTester(Isolate* isolate, const char* script,
                      const char* filter = kFunctionName)
      : isolate_(isolate), script_(script) {
    i::v8_flags.always_turbofan = false;
    i::v8_flags.allow_natives_syntax = true;
  }
  virtual ~BytecodeGraphTester() = default;
  BytecodeGraphTester(const BytecodeGraphTester&) = delete;
  BytecodeGraphTester& operator=(const BytecodeGraphTester&) = delete;

  template <class... A>
  BytecodeGraphCallable<A...> GetCallable(
      const char* functionName = kFunctionName) {
    return BytecodeGraphCallable<A...>(isolate_, GetFunction(functionName));
  }

  Local<Message> CheckThrowsReturnMessage() {
    TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate_));
    auto callable = GetCallable<>();
    MaybeHandle<Object> no_result = callable();
    CHECK(isolate_->has_exception());
    CHECK(try_catch.HasCaught());
    CHECK(no_result.is_null());
    CHECK(!try_catch.Message().IsEmpty());
    return try_catch.Message();
  }

 private:
  Isolate* isolate_;
  const char* script_;

  Handle<JSFunction> GetFunction(const char* functionName) {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
    v8::Local<v8::Context> context = v8_isolate->GetCurrentContext();

    CompileRun(v8_isolate, script_);

    Local<Function> api_function = Local<Function>::Cast(
        context->Global()
            ->Get(context, v8::String::NewFromUtf8(v8_isolate, functionName)
                               .ToLocalChecked())
            .ToLocalChecked());
    Handle<JSFunction> function =
        Cast<JSFunction>(v8::Utils::OpenHandle(*api_function));
    IsCompiledScope is_compiled_scope(
        function->shared()->is_compiled_scope(isolate_));
    JSFunction::EnsureFeedbackVector(isolate_, function, &is_compiled_scope);
    CHECK(function->shared()->HasBytecodeArray());

    Zone zone(isolate_->allocator(), ZONE_NAME);
    Handle<SharedFunctionInfo> shared(function->shared(), isolate_);
    OptimizedCompilationInfo compilation_info(&zone, isolate_, shared, function,
                                              CodeKind::TURBOFAN_JS);

    DirectHandle<Code> code =
        Pipeline::GenerateCodeForTesting(&compilation_info, isolate_)
            .ToHandleChecked();
    function->UpdateCode(*code);

    return function;
  }
};

#define SPACE()

#define REPEAT_2(SEP, ...) __VA_ARGS__ SEP() __VA_ARGS__
#define REPEAT_4(SEP, ...) \
  REPEAT_2(SEP, __VA_ARGS__) SEP() REPEAT_2(SEP, __VA_ARGS__)
#define REPEAT_8(SEP, ...) \
  REPEAT_4(SEP, __VA_ARGS__) SEP() REPEAT_4(SEP, __VA_ARGS__)
#define REPEAT_16(SEP, ...) \
  REPEAT_8(SEP, __VA_ARGS__) SEP() REPEAT_8(SEP, __VA_ARGS__)
#define REPEAT_32(SEP, ...) \
  REPEAT_16(SEP, __VA_ARGS__) SEP() REPEAT_16(SEP, __VA_ARGS__)
#define REPEAT_64(SEP, ...) \
  REPEAT_32(SEP, __VA_ARGS__) SEP() REPEAT_32(SEP, __VA_ARGS__)
#define REPEAT_128(SEP, ...) \
  REPEAT_64(SEP, __VA_ARGS__) SEP() REPEAT_64(SEP, __VA_ARGS__)
#define REPEAT_256(SEP, ...) \
  REPEAT_128(SEP, __VA_ARGS__) SEP() REPEAT_128(SEP, __VA_ARGS__)

#define REPEAT_127(SEP, ...)  \
  REPEAT_64(SEP, __VA_ARGS__) \
  SEP()                       \
  REPEAT_32(SEP, __VA_ARGS__) \
  SEP()                       \
  REPEAT_16(SEP, __VA_ARGS__) \
  SEP()                       \
  REPEAT_8(SEP, __VA_ARGS__)  \
  SEP()                       \
  REPEAT_4(SEP, __VA_ARGS__) SEP() REPEAT_2(SEP, __VA_ARGS__) SEP() __VA_ARGS__

template <int N, typename T = Handle<Object>>
struct ExpectedSnippet {
  const char* code_snippet;
  T return_value_and_parameters[N + 1];

  inline T return_value() const { return return_value_and_parameters[0]; }

  inline T parameter(int i) const {
    CHECK_GE(i, 0);
    CHECK_LT(i, N);
    return return_value_and_parameters[1 + i];
  }
};

class RunBytecodeGraphBuilderTest : public TestWithNativeContext {
 public:
  void TestBytecodeGraphBuilderNamedStore(size_t shard) {
    Factory* factory = i_isolate()->factory();

    ExpectedSnippet<1> snippets[] = {
        {"return p1.val = 20;",
         {factory->NewNumberFromInt(20), RunJS("({val : 10})")}},
        {"p1.type = 'int'; return p1.type;",
         {MakeString("int"), RunJS("({val : 10})")}},
        {"p1.name = 'def'; return p1[\"name\"];",
         {MakeString("def"), RunJS("({name : 'abc'})")}},
        {"'use strict'; p1.val = 20; return p1.val;",
         {factory->NewNumberFromInt(20), RunJS("({val : 10 })")}},
        {"'use strict'; return p1.type = 'int';",
         {MakeString("int"), RunJS("({val : 10})")}},
        {"'use strict'; p1.val = 20; return p1[\"val\"];",
         {factory->NewNumberFromInt(20), RunJS("({val : 10, name : 'abc'})")}},
        {"var b = 'abc';\n" REPEAT_127(
             SPACE, " p1.name = b; ") " p1.name = 'def'; return p1.name;\n",
         {MakeString("def"), RunJS("({name : 'abc'})")}},
        {"'use strict'; var b = 'def';\n" REPEAT_127(
             SPACE, " p1.name = 'abc'; ") "p1.name = b; return p1.name;\n",
         {MakeString("def"), RunJS("({ name : 'abc'})")}},
    };

    for (size_t i = 0; i < arraysize(snippets); i++) {
      if ((i % 2) != shard) continue;
      base::ScopedVector<char> script(3072);
      SNPrintF(script, "function %s(p1) { %s };\n%s({});", kFunctionName,
               snippets[i].code_snippet, kFunctionName);

      BytecodeGraphTester tester(i_isolate(), script.begin());
      auto callable = tester.GetCallable<Handle<Object>>();
      DirectHandle<Object> return_value =
          callable(snippets[i].parameter(0)).ToHandleChecked();
      CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
    }
  }

  void TestBytecodeGraphBuilderKeyedStore(size_t shard) {
    Isolate* isolate = i_isolate();
    Factory* factory = isolate->factory();

    ExpectedSnippet<2> snippets[] = {
        {"p1[p2] = 20; return p1[p2];",
         {factory->NewNumberFromInt(20), RunJS("({val : 10})"),
          MakeString("val")}},
        {"return p1[100] = 'def';",
         {MakeString("def"), RunJS("({100 : 'abc'})"),
          factory->NewNumberFromInt(0)}},
        {"var b = 100; p1[b] = 'def'; return p1[b];",
         {MakeString("def"), RunJS("({100 : 'abc'})"),
          factory->NewNumberFromInt(0)}},
        {"'use strict'; p1[p2] = 20; return p1[p2];",
         {factory->NewNumberFromInt(20), RunJS("({val : 10 })"),
          MakeString("val")}},
        {"'use strict'; return p1[100] = 20;",
         {factory->NewNumberFromInt(20), RunJS("({100 : 10})"),
          factory->NewNumberFromInt(0)}},
        {"'use strict'; var b = p2; p1[b] = 'def'; return p1[b];",
         {MakeString("def"), RunJS("({100 : 'abc'})"),
          factory->NewNumberFromInt(100)}},
        {"var b;\n" REPEAT_127(
             SPACE, " b = p1[p2]; ") " p1[p2] = 'def'; return p1[p2];\n",
         {MakeString("def"), RunJS("({100 : 'abc'})"),
          factory->NewNumberFromInt(100)}},
        {"'use strict'; var b;\n" REPEAT_127(
             SPACE, " b = p1[p2]; ") " p1[p2] = 'def'; return p1[p2];\n",
         {MakeString("def"), RunJS("({ 100 : 'abc'})"),
          factory->NewNumberFromInt(100)}},
    };

    for (size_t i = 0; i < arraysize(snippets); i++) {
      if ((i % 2) != shard) continue;
      base::ScopedVector<char> script(2048);
      SNPrintF(script, "function %s(p1, p2) { %s };\n%s({});", kFunctionName,
               snippets[i].code_snippet, kFunctionName);

      BytecodeGraphTester tester(isolate, script.begin());
      auto callable = tester.GetCallable<Handle<Object>>();
      DirectHandle<Object> return_value =
          callable(snippets[i].parameter(0)).ToHandleChecked();
      CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
    }
  }

  void TestBytecodeGraphBuilderGlobals(size_t shard) {
    Isolate* isolate = i_isolate();
    Factory* factory = isolate->factory();

    ExpectedSnippet<0> snippets[] = {
        {"var global = 321;\n function f() { return global; };\n f();",
         {factory->NewNumberFromInt(321)}},
        {"var global = 321;\n"
         "function f() { global = 123; return global };\n f();",
         {factory->NewNumberFromInt(123)}},
        {"var global = function() { return 'abc'};\n"
         "function f() { return global(); };\n f();",
         {MakeString("abc")}},
        {"var global = 456;\n"
         "function f() { 'use strict'; return global; };\n f();",
         {factory->NewNumberFromInt(456)}},
        {"var global = 987;\n"
         "function f() { 'use strict'; global = 789; return global };\n f();",
         {factory->NewNumberFromInt(789)}},
        {"var global = function() { return 'xyz'};\n"
         "function f() { 'use strict'; return global(); };\n f();",
         {MakeString("xyz")}},
        {"var global = 'abc'; var global_obj = {val:123};\n"
         "function f() {\n" REPEAT_127(
             SPACE, " var b = global_obj.name;\n") "return global; };\n f();\n",
         {MakeString("abc")}},
        {"var global = 'abc'; var global_obj = {val:123};\n"
         "function f() { 'use strict';\n" REPEAT_127(
             SPACE, " var b = global_obj.name;\n") "global = 'xyz'; return "
                                                   "global };\n f();\n",
         {MakeString("xyz")}},
        {"function f() { return typeof(undeclared_var); }\n; f();\n",
         {MakeString("undefined")}},
        {"var defined_var = 10; function f() { return typeof(defined_var); "
         "}\n; "
         "f();\n",
         {MakeString("number")}},
    };

    for (size_t i = 0; i < arraysize(snippets); i++) {
      if ((i % 2) != shard) continue;
      BytecodeGraphTester tester(isolate, snippets[i].code_snippet);
      auto callable = tester.GetCallable<>();
      DirectHandle<Object> return_value = callable().ToHandleChecked();
      CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
    }
  }

  void TestJumpWithConstantsAndWideConstants(size_t shard) {
    const int kStep = 46;
    int start = static_cast<int>(7 + 17 * shard);
    for (int constants = start; constants < 300; constants += kStep) {
      std::stringstream filler_os;
      // Generate a string that consumes constant pool entries and
      // spread out branch distances in script below.
      for (int i = 0; i < constants; i++) {
        filler_os << "var x_ = 'x_" << i << "';\n";
      }
      std::string filler(filler_os.str());

      std::stringstream script_os;
      script_os << "function " << kFunctionName << "(a) {\n";
      script_os << "  " << filler;
      script_os << "  for (var i = a; i < 2; i++) {\n";
      script_os << "  " << filler;
      script_os << "    if (i == 0) { " << filler << "i = 10; continue; }\n";
      script_os << "    else if (i == a) { " << filler << "i = 12; break; }\n";
      script_os << "    else { " << filler << " }\n";
      script_os << "  }\n";
      script_os << "  return i;\n";
      script_os << "}\n";
      script_os << kFunctionName << "(0);\n";
      std::string script(script_os.str());

      Isolate* isolate = i_isolate();
      Factory* factory = isolate->factory();
      BytecodeGraphTester tester(isolate, script.c_str());
      auto callable = tester.GetCallable<Handle<Object>>();
      for (int a = 0; a < 3; a++) {
        DirectHandle<Object> return_val =
            callable(factory->NewNumberFromInt(a)).ToHandleChecked();
        static const int results[] = {11, 12, 2};
        CHECK_EQ(Cast<Smi>(*return_val).value(), results[a]);
      }
    }
  }
};

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderReturnStatements) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return;", {factory->undefined_value()}},
      {"return null;", {factory->null_value()}},
      {"return true;", {factory->true_value()}},
      {"return false;", {factory->false_value()}},
      {"return 0;", {factory->NewNumberFromInt(0)}},
      {"return +1;", {factory->NewNumberFromInt(1)}},
      {"return -1;", {factory->NewNumberFromInt(-1)}},
      {"return +127;", {factory->NewNumberFromInt(127)}},
      {"return -128;", {factory->NewNumberFromInt(-128)}},
      {"return 0.001;", {factory->NewNumber(0.001)}},
      {"return 3.7e-60;", {factory->NewNumber(3.7e-60)}},
      {"return -3.7e60;", {factory->NewNumber(-3.7e60)}},
      {"return '';", {MakeString("")}},
      {"return 'catfood';", {MakeString("catfood")}},
      {"return NaN;", {factory->nan_value()}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderPrimitiveExpressions) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return 1 + 1;", {factory->NewNumberFromInt(2)}},
      {"return 20 - 30;", {factory->NewNumberFromInt(-10)}},
      {"return 4 * 100;", {factory->NewNumberFromInt(400)}},
      {"return 100 / 5;", {factory->NewNumberFromInt(20)}},
      {"return 25 % 7;", {factory->NewNumberFromInt(4)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderTwoParameterTests) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<2> snippets[] = {
      // Integers
      {"return p1 + p2;",
       {factory->NewNumberFromInt(-70), factory->NewNumberFromInt(3),
        factory->NewNumberFromInt(-73)}},
      {"return p1 + p2 + 3;",
       {factory->NewNumberFromInt(1139044), factory->NewNumberFromInt(300),
        factory->NewNumberFromInt(1138741)}},
      {"return p1 - p2;",
       {factory->NewNumberFromInt(1100), factory->NewNumberFromInt(1000),
        factory->NewNumberFromInt(-100)}},
      {"return p1 * p2;",
       {factory->NewNumberFromInt(-100000), factory->NewNumberFromInt(1000),
        factory->NewNumberFromInt(-100)}},
      {"return p1 / p2;",
       {factory->NewNumberFromInt(-10), factory->NewNumberFromInt(1000),
        factory->NewNumberFromInt(-100)}},
      {"return p1 % p2;",
       {factory->NewNumberFromInt(5), factory->NewNumberFromInt(373),
        factory->NewNumberFromInt(16)}},
      // Doubles
      {"return p1 + p2;",
       {factory->NewHeapNumber(9.999), factory->NewHeapNumber(3.333),
        factory->NewHeapNumber(6.666)}},
      {"return p1 - p2;",
       {factory->NewHeapNumber(-3.333), factory->NewHeapNumber(3.333),
        factory->NewHeapNumber(6.666)}},
      {"return p1 * p2;",
       {factory->NewHeapNumber(3.333 * 6.666), factory->NewHeapNumber(3.333),
        factory->NewHeapNumber(6.666)}},
      {"return p1 / p2;",
       {factory->NewHeapNumber(2.25), factory->NewHeapNumber(9),
        factory->NewHeapNumber(4)}},
      // Strings
      {"return p1 + p2;",
       {MakeString("abcdef"), MakeString("abc"), MakeString("def")}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1, p2) { %s }\n%s(0, 0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>, Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0), snippets[i].parameter(1))
            .ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderNamedLoad) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return p1.val;",
       {factory->NewNumberFromInt(10), RunJS("({val : 10})")}},
      {"return p1[\"name\"];", {MakeString("abc"), RunJS("({name : 'abc'})")}},
      {"'use strict'; return p1.val;",
       {factory->NewNumberFromInt(10), RunJS("({val : 10 })")}},
      {"'use strict'; return p1[\"val\"];",
       {factory->NewNumberFromInt(10), RunJS("({val : 10, name : 'abc'})")}},
      {"var b;\n" REPEAT_127(SPACE, " b = p1.name; ") " return p1.name;\n",
       {MakeString("abc"), RunJS("({name : 'abc'})")}},
      {"'use strict'; var b;\n" REPEAT_127(
           SPACE, " b = p1.name; ") "return p1.name;\n",
       {MakeString("abc"), RunJS("({ name : 'abc'})")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderKeyedLoad) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<2> snippets[] = {
      {"return p1[p2];",
       {factory->NewNumberFromInt(10), RunJS("({val : 10})"),
        MakeString("val")}},
      {"return p1[100];",
       {MakeString("abc"), RunJS("({100 : 'abc'})"),
        factory->NewNumberFromInt(0)}},
      {"var b = 100; return p1[b];",
       {MakeString("abc"), RunJS("({100 : 'abc'})"),
        factory->NewNumberFromInt(0)}},
      {"'use strict'; return p1[p2];",
       {factory->NewNumberFromInt(10), RunJS("({val : 10 })"),
        MakeString("val")}},
      {"'use strict'; return p1[100];",
       {factory->NewNumberFromInt(10), RunJS("({100 : 10})"),
        factory->NewNumberFromInt(0)}},
      {"'use strict'; var b = p2; return p1[b];",
       {MakeString("abc"), RunJS("({100 : 'abc'})"),
        factory->NewNumberFromInt(100)}},
      {"var b;\n" REPEAT_127(SPACE, " b = p1[p2]; ") " return p1[p2];\n",
       {MakeString("abc"), RunJS("({100 : 'abc'})"),
        factory->
### 提示词
```
这是目录为v8/test/unittests/compiler/run-bytecode-graph-builder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/run-bytecode-graph-builder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/pipeline.h"
#include "src/debug/debug-interface.h"
#include "src/execution/execution.h"
#include "src/handles/handles.h"
#include "src/interpreter/bytecode-array-builder.h"
#include "src/interpreter/interpreter.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parse-info.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {

#define SHARD_TEST_BY_2(x)                                   \
  TEST_F(RunBytecodeGraphBuilderTest, x##_0) { Test##x(0); } \
  TEST_F(RunBytecodeGraphBuilderTest, x##_1) { Test##x(1); }
#define SHARD_TEST_BY_4(x)                                   \
  TEST_F(RunBytecodeGraphBuilderTest, x##_0) { Test##x(0); } \
  TEST_F(RunBytecodeGraphBuilderTest, x##_1) { Test##x(1); } \
  TEST_F(RunBytecodeGraphBuilderTest, x##_2) { Test##x(2); } \
  TEST_F(RunBytecodeGraphBuilderTest, x##_3) { Test##x(3); }

static const char kFunctionName[] = "f";

static const Token::Value kCompareOperators[] = {
    Token::kEq,          Token::kNotEq,        Token::kEqStrict,
    Token::kNotEqStrict, Token::kLessThan,     Token::kLessThanEq,
    Token::kGreaterThan, Token::kGreaterThanEq};

static const int SMI_MAX = (1 << 30) - 1;
static const int SMI_MIN = -(1 << 30);

static MaybeHandle<Object> CallFunction(Isolate* isolate,
                                        Handle<JSFunction> function) {
  return Execution::Call(isolate, function,
                         isolate->factory()->undefined_value(), 0, nullptr);
}

template <class... A>
static MaybeHandle<Object> CallFunction(Isolate* isolate,
                                        Handle<JSFunction> function,
                                        A... args) {
  Handle<Object> argv[] = {args...};
  return Execution::Call(isolate, function,
                         isolate->factory()->undefined_value(), sizeof...(args),
                         argv);
}

static v8::Local<v8::Value> CompileRun(v8::Isolate* isolate,
                                       const char* source) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Script> script =
      v8::Script::Compile(
          context, v8::String::NewFromUtf8(isolate, source).ToLocalChecked())
          .ToLocalChecked();

  v8::Local<v8::Value> result;
  if (script->Run(context).ToLocal(&result)) {
    return result;
  } else {
    return v8::Local<v8::Value>();
  }
}

template <class... A>
class BytecodeGraphCallable {
 public:
  BytecodeGraphCallable(Isolate* isolate, Handle<JSFunction> function)
      : isolate_(isolate), function_(function) {}
  virtual ~BytecodeGraphCallable() = default;

  MaybeHandle<Object> operator()(A... args) {
    return CallFunction(isolate_, function_, args...);
  }

 private:
  Isolate* isolate_;
  Handle<JSFunction> function_;
};

class BytecodeGraphTester {
 public:
  BytecodeGraphTester(Isolate* isolate, const char* script,
                      const char* filter = kFunctionName)
      : isolate_(isolate), script_(script) {
    i::v8_flags.always_turbofan = false;
    i::v8_flags.allow_natives_syntax = true;
  }
  virtual ~BytecodeGraphTester() = default;
  BytecodeGraphTester(const BytecodeGraphTester&) = delete;
  BytecodeGraphTester& operator=(const BytecodeGraphTester&) = delete;

  template <class... A>
  BytecodeGraphCallable<A...> GetCallable(
      const char* functionName = kFunctionName) {
    return BytecodeGraphCallable<A...>(isolate_, GetFunction(functionName));
  }

  Local<Message> CheckThrowsReturnMessage() {
    TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate_));
    auto callable = GetCallable<>();
    MaybeHandle<Object> no_result = callable();
    CHECK(isolate_->has_exception());
    CHECK(try_catch.HasCaught());
    CHECK(no_result.is_null());
    CHECK(!try_catch.Message().IsEmpty());
    return try_catch.Message();
  }

 private:
  Isolate* isolate_;
  const char* script_;

  Handle<JSFunction> GetFunction(const char* functionName) {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
    v8::Local<v8::Context> context = v8_isolate->GetCurrentContext();

    CompileRun(v8_isolate, script_);

    Local<Function> api_function = Local<Function>::Cast(
        context->Global()
            ->Get(context, v8::String::NewFromUtf8(v8_isolate, functionName)
                               .ToLocalChecked())
            .ToLocalChecked());
    Handle<JSFunction> function =
        Cast<JSFunction>(v8::Utils::OpenHandle(*api_function));
    IsCompiledScope is_compiled_scope(
        function->shared()->is_compiled_scope(isolate_));
    JSFunction::EnsureFeedbackVector(isolate_, function, &is_compiled_scope);
    CHECK(function->shared()->HasBytecodeArray());

    Zone zone(isolate_->allocator(), ZONE_NAME);
    Handle<SharedFunctionInfo> shared(function->shared(), isolate_);
    OptimizedCompilationInfo compilation_info(&zone, isolate_, shared, function,
                                              CodeKind::TURBOFAN_JS);

    DirectHandle<Code> code =
        Pipeline::GenerateCodeForTesting(&compilation_info, isolate_)
            .ToHandleChecked();
    function->UpdateCode(*code);

    return function;
  }
};

#define SPACE()

#define REPEAT_2(SEP, ...) __VA_ARGS__ SEP() __VA_ARGS__
#define REPEAT_4(SEP, ...) \
  REPEAT_2(SEP, __VA_ARGS__) SEP() REPEAT_2(SEP, __VA_ARGS__)
#define REPEAT_8(SEP, ...) \
  REPEAT_4(SEP, __VA_ARGS__) SEP() REPEAT_4(SEP, __VA_ARGS__)
#define REPEAT_16(SEP, ...) \
  REPEAT_8(SEP, __VA_ARGS__) SEP() REPEAT_8(SEP, __VA_ARGS__)
#define REPEAT_32(SEP, ...) \
  REPEAT_16(SEP, __VA_ARGS__) SEP() REPEAT_16(SEP, __VA_ARGS__)
#define REPEAT_64(SEP, ...) \
  REPEAT_32(SEP, __VA_ARGS__) SEP() REPEAT_32(SEP, __VA_ARGS__)
#define REPEAT_128(SEP, ...) \
  REPEAT_64(SEP, __VA_ARGS__) SEP() REPEAT_64(SEP, __VA_ARGS__)
#define REPEAT_256(SEP, ...) \
  REPEAT_128(SEP, __VA_ARGS__) SEP() REPEAT_128(SEP, __VA_ARGS__)

#define REPEAT_127(SEP, ...)  \
  REPEAT_64(SEP, __VA_ARGS__) \
  SEP()                       \
  REPEAT_32(SEP, __VA_ARGS__) \
  SEP()                       \
  REPEAT_16(SEP, __VA_ARGS__) \
  SEP()                       \
  REPEAT_8(SEP, __VA_ARGS__)  \
  SEP()                       \
  REPEAT_4(SEP, __VA_ARGS__) SEP() REPEAT_2(SEP, __VA_ARGS__) SEP() __VA_ARGS__

template <int N, typename T = Handle<Object>>
struct ExpectedSnippet {
  const char* code_snippet;
  T return_value_and_parameters[N + 1];

  inline T return_value() const { return return_value_and_parameters[0]; }

  inline T parameter(int i) const {
    CHECK_GE(i, 0);
    CHECK_LT(i, N);
    return return_value_and_parameters[1 + i];
  }
};

class RunBytecodeGraphBuilderTest : public TestWithNativeContext {
 public:
  void TestBytecodeGraphBuilderNamedStore(size_t shard) {
    Factory* factory = i_isolate()->factory();

    ExpectedSnippet<1> snippets[] = {
        {"return p1.val = 20;",
         {factory->NewNumberFromInt(20), RunJS("({val : 10})")}},
        {"p1.type = 'int'; return p1.type;",
         {MakeString("int"), RunJS("({val : 10})")}},
        {"p1.name = 'def'; return p1[\"name\"];",
         {MakeString("def"), RunJS("({name : 'abc'})")}},
        {"'use strict'; p1.val = 20; return p1.val;",
         {factory->NewNumberFromInt(20), RunJS("({val : 10 })")}},
        {"'use strict'; return p1.type = 'int';",
         {MakeString("int"), RunJS("({val : 10})")}},
        {"'use strict'; p1.val = 20; return p1[\"val\"];",
         {factory->NewNumberFromInt(20), RunJS("({val : 10, name : 'abc'})")}},
        {"var b = 'abc';\n" REPEAT_127(
             SPACE, " p1.name = b; ") " p1.name = 'def'; return p1.name;\n",
         {MakeString("def"), RunJS("({name : 'abc'})")}},
        {"'use strict'; var b = 'def';\n" REPEAT_127(
             SPACE, " p1.name = 'abc'; ") "p1.name = b; return p1.name;\n",
         {MakeString("def"), RunJS("({ name : 'abc'})")}},
    };

    for (size_t i = 0; i < arraysize(snippets); i++) {
      if ((i % 2) != shard) continue;
      base::ScopedVector<char> script(3072);
      SNPrintF(script, "function %s(p1) { %s };\n%s({});", kFunctionName,
               snippets[i].code_snippet, kFunctionName);

      BytecodeGraphTester tester(i_isolate(), script.begin());
      auto callable = tester.GetCallable<Handle<Object>>();
      DirectHandle<Object> return_value =
          callable(snippets[i].parameter(0)).ToHandleChecked();
      CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
    }
  }

  void TestBytecodeGraphBuilderKeyedStore(size_t shard) {
    Isolate* isolate = i_isolate();
    Factory* factory = isolate->factory();

    ExpectedSnippet<2> snippets[] = {
        {"p1[p2] = 20; return p1[p2];",
         {factory->NewNumberFromInt(20), RunJS("({val : 10})"),
          MakeString("val")}},
        {"return p1[100] = 'def';",
         {MakeString("def"), RunJS("({100 : 'abc'})"),
          factory->NewNumberFromInt(0)}},
        {"var b = 100; p1[b] = 'def'; return p1[b];",
         {MakeString("def"), RunJS("({100 : 'abc'})"),
          factory->NewNumberFromInt(0)}},
        {"'use strict'; p1[p2] = 20; return p1[p2];",
         {factory->NewNumberFromInt(20), RunJS("({val : 10 })"),
          MakeString("val")}},
        {"'use strict'; return p1[100] = 20;",
         {factory->NewNumberFromInt(20), RunJS("({100 : 10})"),
          factory->NewNumberFromInt(0)}},
        {"'use strict'; var b = p2; p1[b] = 'def'; return p1[b];",
         {MakeString("def"), RunJS("({100 : 'abc'})"),
          factory->NewNumberFromInt(100)}},
        {"var b;\n" REPEAT_127(
             SPACE, " b = p1[p2]; ") " p1[p2] = 'def'; return p1[p2];\n",
         {MakeString("def"), RunJS("({100 : 'abc'})"),
          factory->NewNumberFromInt(100)}},
        {"'use strict'; var b;\n" REPEAT_127(
             SPACE, " b = p1[p2]; ") " p1[p2] = 'def'; return p1[p2];\n",
         {MakeString("def"), RunJS("({ 100 : 'abc'})"),
          factory->NewNumberFromInt(100)}},
    };

    for (size_t i = 0; i < arraysize(snippets); i++) {
      if ((i % 2) != shard) continue;
      base::ScopedVector<char> script(2048);
      SNPrintF(script, "function %s(p1, p2) { %s };\n%s({});", kFunctionName,
               snippets[i].code_snippet, kFunctionName);

      BytecodeGraphTester tester(isolate, script.begin());
      auto callable = tester.GetCallable<Handle<Object>>();
      DirectHandle<Object> return_value =
          callable(snippets[i].parameter(0)).ToHandleChecked();
      CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
    }
  }

  void TestBytecodeGraphBuilderGlobals(size_t shard) {
    Isolate* isolate = i_isolate();
    Factory* factory = isolate->factory();

    ExpectedSnippet<0> snippets[] = {
        {"var global = 321;\n function f() { return global; };\n f();",
         {factory->NewNumberFromInt(321)}},
        {"var global = 321;\n"
         "function f() { global = 123; return global };\n f();",
         {factory->NewNumberFromInt(123)}},
        {"var global = function() { return 'abc'};\n"
         "function f() { return global(); };\n f();",
         {MakeString("abc")}},
        {"var global = 456;\n"
         "function f() { 'use strict'; return global; };\n f();",
         {factory->NewNumberFromInt(456)}},
        {"var global = 987;\n"
         "function f() { 'use strict'; global = 789; return global };\n f();",
         {factory->NewNumberFromInt(789)}},
        {"var global = function() { return 'xyz'};\n"
         "function f() { 'use strict'; return global(); };\n f();",
         {MakeString("xyz")}},
        {"var global = 'abc'; var global_obj = {val:123};\n"
         "function f() {\n" REPEAT_127(
             SPACE, " var b = global_obj.name;\n") "return global; };\n f();\n",
         {MakeString("abc")}},
        {"var global = 'abc'; var global_obj = {val:123};\n"
         "function f() { 'use strict';\n" REPEAT_127(
             SPACE, " var b = global_obj.name;\n") "global = 'xyz'; return "
                                                   "global };\n f();\n",
         {MakeString("xyz")}},
        {"function f() { return typeof(undeclared_var); }\n; f();\n",
         {MakeString("undefined")}},
        {"var defined_var = 10; function f() { return typeof(defined_var); "
         "}\n; "
         "f();\n",
         {MakeString("number")}},
    };

    for (size_t i = 0; i < arraysize(snippets); i++) {
      if ((i % 2) != shard) continue;
      BytecodeGraphTester tester(isolate, snippets[i].code_snippet);
      auto callable = tester.GetCallable<>();
      DirectHandle<Object> return_value = callable().ToHandleChecked();
      CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
    }
  }

  void TestJumpWithConstantsAndWideConstants(size_t shard) {
    const int kStep = 46;
    int start = static_cast<int>(7 + 17 * shard);
    for (int constants = start; constants < 300; constants += kStep) {
      std::stringstream filler_os;
      // Generate a string that consumes constant pool entries and
      // spread out branch distances in script below.
      for (int i = 0; i < constants; i++) {
        filler_os << "var x_ = 'x_" << i << "';\n";
      }
      std::string filler(filler_os.str());

      std::stringstream script_os;
      script_os << "function " << kFunctionName << "(a) {\n";
      script_os << "  " << filler;
      script_os << "  for (var i = a; i < 2; i++) {\n";
      script_os << "  " << filler;
      script_os << "    if (i == 0) { " << filler << "i = 10; continue; }\n";
      script_os << "    else if (i == a) { " << filler << "i = 12; break; }\n";
      script_os << "    else { " << filler << " }\n";
      script_os << "  }\n";
      script_os << "  return i;\n";
      script_os << "}\n";
      script_os << kFunctionName << "(0);\n";
      std::string script(script_os.str());

      Isolate* isolate = i_isolate();
      Factory* factory = isolate->factory();
      BytecodeGraphTester tester(isolate, script.c_str());
      auto callable = tester.GetCallable<Handle<Object>>();
      for (int a = 0; a < 3; a++) {
        DirectHandle<Object> return_val =
            callable(factory->NewNumberFromInt(a)).ToHandleChecked();
        static const int results[] = {11, 12, 2};
        CHECK_EQ(Cast<Smi>(*return_val).value(), results[a]);
      }
    }
  }
};

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderReturnStatements) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return;", {factory->undefined_value()}},
      {"return null;", {factory->null_value()}},
      {"return true;", {factory->true_value()}},
      {"return false;", {factory->false_value()}},
      {"return 0;", {factory->NewNumberFromInt(0)}},
      {"return +1;", {factory->NewNumberFromInt(1)}},
      {"return -1;", {factory->NewNumberFromInt(-1)}},
      {"return +127;", {factory->NewNumberFromInt(127)}},
      {"return -128;", {factory->NewNumberFromInt(-128)}},
      {"return 0.001;", {factory->NewNumber(0.001)}},
      {"return 3.7e-60;", {factory->NewNumber(3.7e-60)}},
      {"return -3.7e60;", {factory->NewNumber(-3.7e60)}},
      {"return '';", {MakeString("")}},
      {"return 'catfood';", {MakeString("catfood")}},
      {"return NaN;", {factory->nan_value()}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderPrimitiveExpressions) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"return 1 + 1;", {factory->NewNumberFromInt(2)}},
      {"return 20 - 30;", {factory->NewNumberFromInt(-10)}},
      {"return 4 * 100;", {factory->NewNumberFromInt(400)}},
      {"return 100 / 5;", {factory->NewNumberFromInt(20)}},
      {"return 25 % 7;", {factory->NewNumberFromInt(4)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s();", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderTwoParameterTests) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<2> snippets[] = {
      // Integers
      {"return p1 + p2;",
       {factory->NewNumberFromInt(-70), factory->NewNumberFromInt(3),
        factory->NewNumberFromInt(-73)}},
      {"return p1 + p2 + 3;",
       {factory->NewNumberFromInt(1139044), factory->NewNumberFromInt(300),
        factory->NewNumberFromInt(1138741)}},
      {"return p1 - p2;",
       {factory->NewNumberFromInt(1100), factory->NewNumberFromInt(1000),
        factory->NewNumberFromInt(-100)}},
      {"return p1 * p2;",
       {factory->NewNumberFromInt(-100000), factory->NewNumberFromInt(1000),
        factory->NewNumberFromInt(-100)}},
      {"return p1 / p2;",
       {factory->NewNumberFromInt(-10), factory->NewNumberFromInt(1000),
        factory->NewNumberFromInt(-100)}},
      {"return p1 % p2;",
       {factory->NewNumberFromInt(5), factory->NewNumberFromInt(373),
        factory->NewNumberFromInt(16)}},
      // Doubles
      {"return p1 + p2;",
       {factory->NewHeapNumber(9.999), factory->NewHeapNumber(3.333),
        factory->NewHeapNumber(6.666)}},
      {"return p1 - p2;",
       {factory->NewHeapNumber(-3.333), factory->NewHeapNumber(3.333),
        factory->NewHeapNumber(6.666)}},
      {"return p1 * p2;",
       {factory->NewHeapNumber(3.333 * 6.666), factory->NewHeapNumber(3.333),
        factory->NewHeapNumber(6.666)}},
      {"return p1 / p2;",
       {factory->NewHeapNumber(2.25), factory->NewHeapNumber(9),
        factory->NewHeapNumber(4)}},
      // Strings
      {"return p1 + p2;",
       {MakeString("abcdef"), MakeString("abc"), MakeString("def")}}};

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1, p2) { %s }\n%s(0, 0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>, Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0), snippets[i].parameter(1))
            .ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderNamedLoad) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return p1.val;",
       {factory->NewNumberFromInt(10), RunJS("({val : 10})")}},
      {"return p1[\"name\"];", {MakeString("abc"), RunJS("({name : 'abc'})")}},
      {"'use strict'; return p1.val;",
       {factory->NewNumberFromInt(10), RunJS("({val : 10 })")}},
      {"'use strict'; return p1[\"val\"];",
       {factory->NewNumberFromInt(10), RunJS("({val : 10, name : 'abc'})")}},
      {"var b;\n" REPEAT_127(SPACE, " b = p1.name; ") " return p1.name;\n",
       {MakeString("abc"), RunJS("({name : 'abc'})")}},
      {"'use strict'; var b;\n" REPEAT_127(
           SPACE, " b = p1.name; ") "return p1.name;\n",
       {MakeString("abc"), RunJS("({ name : 'abc'})")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderKeyedLoad) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<2> snippets[] = {
      {"return p1[p2];",
       {factory->NewNumberFromInt(10), RunJS("({val : 10})"),
        MakeString("val")}},
      {"return p1[100];",
       {MakeString("abc"), RunJS("({100 : 'abc'})"),
        factory->NewNumberFromInt(0)}},
      {"var b = 100; return p1[b];",
       {MakeString("abc"), RunJS("({100 : 'abc'})"),
        factory->NewNumberFromInt(0)}},
      {"'use strict'; return p1[p2];",
       {factory->NewNumberFromInt(10), RunJS("({val : 10 })"),
        MakeString("val")}},
      {"'use strict'; return p1[100];",
       {factory->NewNumberFromInt(10), RunJS("({100 : 10})"),
        factory->NewNumberFromInt(0)}},
      {"'use strict'; var b = p2; return p1[b];",
       {MakeString("abc"), RunJS("({100 : 'abc'})"),
        factory->NewNumberFromInt(100)}},
      {"var b;\n" REPEAT_127(SPACE, " b = p1[p2]; ") " return p1[p2];\n",
       {MakeString("abc"), RunJS("({100 : 'abc'})"),
        factory->NewNumberFromInt(100)}},
      {"'use strict'; var b;\n" REPEAT_127(SPACE,
                                           " b = p1[p2]; ") "return p1[p2];\n",
       {MakeString("abc"), RunJS("({ 100 : 'abc'})"),
        factory->NewNumberFromInt(100)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1, p2) { %s };\n%s(0);", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>, Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0), snippets[i].parameter(1))
            .ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

SHARD_TEST_BY_2(BytecodeGraphBuilderNamedStore)

SHARD_TEST_BY_2(BytecodeGraphBuilderKeyedStore)

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderPropertyCall) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return p1.func();",
       {factory->NewNumberFromInt(25), RunJS("({func() { return 25; }})")}},
      {"return p1.func('abc');",
       {MakeString("abc"), RunJS("({func(a) { return a; }})")}},
      {"return p1.func(1, 2, 3, 4, 5, 6, 7, 8);",
       {factory->NewNumberFromInt(36),
        RunJS("({func(a, b, c, d, e, f, g, h) {\n"
              "  return a + b + c + d + e + f + g + h;}})")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(2048);
    SNPrintF(script, "function %s(p1) { %s };\n%s({func() {}});", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCallNew) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"function counter() { this.count = 20; }\n"
       "function f() {\n"
       "  var c = new counter();\n"
       "  return c.count;\n"
       "}; f()",
       {factory->NewNumberFromInt(20)}},
      {"function counter(arg0) { this.count = 17; this.x = arg0; }\n"
       "function f() {\n"
       "  var c = new counter(6);\n"
       "  return c.count + c.x;\n"
       "}; f()",
       {factory->NewNumberFromInt(23)}},
      {"function counter(arg0, arg1) {\n"
       "  this.count = 17; this.x = arg0; this.y = arg1;\n"
       "}\n"
       "function f() {\n"
       "  var c = new counter(3, 5);\n"
       "  return c.count + c.x + c.y;\n"
       "}; f()",
       {factory->NewNumberFromInt(25)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    BytecodeGraphTester tester(isolate, snippets[i].code_snippet);
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCreateClosure) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"function f() {\n"
       "  function counter() { this.count = 20; }\n"
       "  var c = new counter();\n"
       "  return c.count;\n"
       "}; f()",
       {factory->NewNumberFromInt(20)}},
      {"function f() {\n"
       "  function counter(arg0) { this.count = 17; this.x = arg0; }\n"
       "  var c = new counter(6);\n"
       "  return c.count + c.x;\n"
       "}; f()",
       {factory->NewNumberFromInt(23)}},
      {"function f() {\n"
       "  function counter(arg0, arg1) {\n"
       "    this.count = 17; this.x = arg0; this.y = arg1;\n"
       "  }\n"
       "  var c = new counter(3, 5);\n"
       "  return c.count + c.x + c.y;\n"
       "}; f()",
       {factory->NewNumberFromInt(25)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    BytecodeGraphTester tester(isolate, snippets[i].code_snippet);
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCallRuntime) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"function f(arg0) { return %MaxSmi(); }\nf()",
       {factory->NewNumberFromInt(Smi::kMaxValue), factory->undefined_value()}},
      {"function f(arg0) { return %IsArray(arg0) }\nf(undefined)",
       {factory->true_value(), RunJS("[1, 2, 3]")}},
      {"function f(arg0) { return %Add(arg0, 2) }\nf(1)",
       {factory->NewNumberFromInt(5), factory->NewNumberFromInt(3)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    BytecodeGraphTester tester(isolate, snippets[i].code_snippet);
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

SHARD_TEST_BY_2(BytecodeGraphBuilderGlobals)

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderToObject) {
  // TODO(mythria): tests for ToObject. Needs ForIn.
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderToName) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<0> snippets[] = {
      {"var a = 'val'; var obj = {[a] : 10}; return obj.val;",
       {factory->NewNumberFromInt(10)}},
      {"var a = 20; var obj = {[a] : 10}; return obj['20'];",
       {factory->NewNumberFromInt(10)}},
      {"var a = 20; var obj = {[a] : 10}; return obj[20];",
       {factory->NewNumberFromInt(10)}},
      {"var a = {val:23}; var obj = {[a] : 10}; return obj[a];",
       {factory->NewNumberFromInt(10)}},
      {"var a = {val:23}; var obj = {[a] : 10}; return obj['[object Object]'];",
       {factory->NewNumberFromInt(10)}},
      {"var a = {toString : function() { return 'x'}};\n"
       "var obj = {[a] : 10};\n"
       "return obj.x;",
       {factory->NewNumberFromInt(10)}},
      {"var a = {valueOf : function() { return 'x'}};\n"
       "var obj = {[a] : 10};\n"
       "return obj.x;",
       {factory->undefined_value()}},
      {"var a = {[Symbol.toPrimitive] : function() { return 'x'}};\n"
       "var obj = {[a] : 10};\n"
       "return obj.x;",
       {factory->NewNumberFromInt(10)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s() { %s }\n%s({});", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<>();
    DirectHandle<Object> return_value = callable().ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderLogicalNot) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return !p1;", {factory->false_value(), RunJS("({val : 10})")}},
      {"return !p1;", {factory->true_value(), factory->NewNumberFromInt(0)}},
      {"return !p1;", {factory->true_value(), factory->undefined_value()}},
      {"return !p1;", {factory->false_value(), factory->NewNumberFromInt(10)}},
      {"return !p1;", {factory->false_value(), factory->true_value()}},
      {"return !p1;", {factory->false_value(), MakeString("abc")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1) { %s }\n%s({});", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderTypeOf) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return typeof p1;", {MakeString("object"), RunJS("({val : 10})")}},
      {"return typeof p1;",
       {MakeString("undefined"), factory->undefined_value()}},
      {"return typeof p1;",
       {MakeString("number"), factory->NewNumberFromInt(10)}},
      {"return typeof p1;", {MakeString("boolean"), factory->true_value()}},
      {"return typeof p1;", {MakeString("string"), MakeString("abc")}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVector<char> script(1024);
    SNPrintF(script, "function %s(p1) { %s }\n%s({});", kFunctionName,
             snippets[i].code_snippet, kFunctionName);

    BytecodeGraphTester tester(isolate, script.begin());
    auto callable = tester.GetCallable<Handle<Object>>();
    DirectHandle<Object> return_value =
        callable(snippets[i].parameter(0)).ToHandleChecked();
    CHECK(Object::SameValue(*return_value, *snippets[i].return_value()));
  }
}

TEST_F(RunBytecodeGraphBuilderTest, BytecodeGraphBuilderCompareTypeOf) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  ExpectedSnippet<1> snippets[] = {
      {"return typeof p1 === 'number';",
       {factory->true_value(), factory->NewNumber(1.1)}},
      {"return typeof p1 === 'string';",
       {factory->false_value(), factory->NewNumber(1.1)}},
      {"return typeof p1 === 'string';",
       {factory->true_value(), MakeString("string")}},
      {"return typeof p1 === 'string';",
       {factory->false_value(), factory->undefined_value()}},
      {"return typeof p1 === 'undefined';",
       {factory->true_value(), factory->undefined_value()}},
      {"return typeof p1 === 'object';",
       {factory->true_value(), factory->null_value()}},
      {"return typeof p1 === 'object';",
       {factory->true_value(), RunJS("({val : 10})")}},
      {"return typeof p1 === 'function';",
       {factory->false_value(), RunJS("({val : 10})")}},
      {"return typeof p1 === 'symbol';",
       {factory->true_value(), factory->NewSymbol()}},
      {"return typeof p1 === 'symbol';",
       {factory->false_value(), MakeString("string")}},
      {"return typeof p1 === 'other';",
       {factory->false_value(), factory->NewNumber(1.1)}},
  };

  for (size_t i = 0; i < arraysize(snippets); i++) {
    base::ScopedVecto
```