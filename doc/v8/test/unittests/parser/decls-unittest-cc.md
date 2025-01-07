Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code (`decls-unittest.cc`), treating it as a V8 test file. It also specifies how to handle different file extensions (which is not relevant here as the extension is `.cc`). Finally, it asks for JavaScript examples and explanations of potential programming errors and code logic.

2. **Identify the Core Functionality:**  The code is a unit test file for the V8 JavaScript engine's parser, specifically focusing on how declarations (variables, functions, `let`, `const`) are handled in different scenarios, especially in the presence of interceptors and across different script contexts.

3. **Break Down the Code Structure:** The code is organized using Google Test (`TEST_F`). Each `TEST_F` block focuses on a specific aspect of declaration handling. The `DeclarationContext` class and its subclasses (`AbsentPropertyContext`, `AppearingPropertyContext`, etc.) are helper classes designed to simulate different scenarios involving property interceptors. The `SimpleContext` class is used for testing cross-script declaration behavior.

4. **Analyze Key Classes and Methods:**
    * **`DeclarationContext`:** This is central. It sets up a V8 context with property interceptors. The virtual methods `Get`, `Set`, and `Query` are overridden in subclasses to simulate different interceptor behaviors (e.g., property absent, present in prototype). The `Check` method is crucial for running JavaScript code snippets and verifying the expected number of interceptor calls and the result/exception.
    * **`SimpleContext`:**  This simplifies testing by creating a clean V8 context without interceptors, primarily for cross-script scenarios. The `Check` method is similar to the one in `DeclarationContext`.
    * **`TEST_F` blocks:** Each test case name (e.g., `Unknown`, `Absent`, `Appearing`, `CrossScriptReferences`) hints at the specific declaration-related feature being tested.

5. **Map C++ Tests to JavaScript Concepts:**  The C++ code is testing the *implementation* of JavaScript's declaration semantics. I need to translate these low-level tests into understandable JavaScript examples. For example:
    * Tests involving interceptors are related to how JavaScript engines handle property lookups and assignments, especially when custom logic is involved (though standard JavaScript doesn't directly expose interceptors).
    * Tests involving `var`, `let`, `const` declarations across scripts demonstrate scope and hoisting rules.
    * Tests for `use strict` mode highlight the differences in declaration handling compared to sloppy mode.

6. **Generate JavaScript Examples and Explanations:**  Based on the analysis, I formulate JavaScript examples that illustrate the concepts being tested in the C++ code. I focus on:
    * **Scope:** How variables are accessible in different parts of the code.
    * **Hoisting:**  How declarations are treated before the code is executed.
    * **`var` vs. `let`/`const`:**  Key differences in scope and re-declaration rules.
    * **`use strict`:** How it affects declaration rules and error reporting.
    * **Cross-scripting:** How variables and functions declared in one script interact with another.
    * **`with` statement:**  While generally discouraged, it's tested here for its interaction with scope and declarations.
    * **Global scope:** How declarations affect the global object.

7. **Identify Potential Programming Errors:** By understanding the test cases, I can identify common JavaScript programming errors related to declarations:
    * Redeclaring `let` or `const` in the same scope.
    * Accessing `let` or `const` variables before their declaration (temporal dead zone).
    * Confusing `var` (function-scoped) with `let`/`const` (block-scoped).
    * Unexpected behavior with the `with` statement.
    * Assigning to `const` variables after initialization.

8. **Structure the Answer:** Organize the information into the requested sections:
    * **Functionality:**  A high-level summary of what the code does.
    * **Torque Source:** Address the (irrelevant in this case) file extension question.
    * **Relationship to JavaScript:**  Provide JavaScript examples and explanations.
    * **Code Logic Reasoning:**  Give examples of input and expected output, focusing on the test scenarios.
    * **Common Programming Errors:** List and illustrate potential pitfalls.
    * **Summary (Part 1):**  Concisely reiterate the main purpose of the code.

9. **Review and Refine:**  Check the accuracy and clarity of the explanations and examples. Ensure that the answer directly addresses all parts of the request. For example, make sure to mention that the `DeclarationContext` is simulating interceptor behavior even though JavaScript doesn't directly expose that. Clarify the purpose of each `TEST_F`.

By following these steps, I can create a comprehensive and informative answer that accurately describes the functionality of the given V8 test file and its relevance to JavaScript programming.
好的，让我们来分析一下 `v8/test/unittests/parser/decls-unittest.cc` 这个 V8 源代码文件。

**功能列举:**

`v8/test/unittests/parser/decls-unittest.cc` 文件是 V8 JavaScript 引擎中 **解析器 (parser)** 部分的 **声明 (declarations)** 功能的 **单元测试 (unittests)** 代码。它的主要功能是：

1. **测试 JavaScript 中各种声明语句的解析和处理是否正确。** 这包括 `var`、`function`、`let`、`const` 等关键字声明的变量和函数。
2. **测试声明在不同作用域 (scope) 中的行为。** 例如，全局作用域、函数作用域和块级作用域。
3. **测试声明与属性拦截器 (property interceptors) 的交互。**  属性拦截器允许在对象属性的访问、设置和查询过程中插入自定义逻辑。这个测试文件会验证声明如何在存在拦截器的情况下正确地创建和访问。
4. **测试跨脚本 (cross-script) 引用声明的行为。**  当 JavaScript 代码分布在多个 `<script>` 标签或模块中时，声明在不同脚本之间的可见性和交互方式是需要测试的关键点。
5. **测试声明与严格模式 (`"use strict"`) 的交互。** 严格模式对声明的行为有一些不同的规定，例如不允许隐式全局变量。
6. **测试声明与即时编译 (Just-In-Time Compilation, JIT) 优化的交互。**  例如，测试内联缓存 (Inline Caches, ICs) 在涉及跨脚本声明时的行为。
7. **测试与声明相关的边界情况和错误处理。** 例如，重复声明、在声明前访问 `let` 或 `const` 变量等。

**关于文件后缀:**

`v8/test/unittests/parser/decls-unittest.cc` 的后缀是 `.cc`，这意味着它是一个 **C++ 源代码文件**。 如果文件后缀是 `.tq`，那它才是 V8 Torque 源代码。 Torque 是一种 V8 内部使用的类型化的中间语言，用于生成一些性能关键的代码。

**与 JavaScript 功能的关系 (并举例说明):**

`v8/test/unittests/parser/decls-unittest.cc`  直接测试了 JavaScript 语言中关于声明的核心功能。以下是一些与测试用例相关的 JavaScript 示例：

* **`var` 声明:**
   ```javascript
   var x; // 声明一个全局变量 x
   var y = 10; // 声明并初始化一个全局变量 y

   function myFunction() {
       var z = 20; // 声明一个函数局部变量 z
       console.log(y); // 可以访问外部的全局变量 y
   }
   myFunction();
   console.log(z); // 错误！z 是函数局部变量，外部无法访问
   ```

* **`function` 声明:**
   ```javascript
   function add(a, b) {
       return a + b;
   }
   console.log(add(5, 3)); // 调用函数
   ```

* **`let` 声明 (块级作用域):**
   ```javascript
   let a = 1;
   if (true) {
       let a = 2; // 内部的 a 与外部的 a 是不同的变量
       console.log(a); // 输出 2
   }
   console.log(a); // 输出 1
   ```

* **`const` 声明 (常量，块级作用域):**
   ```javascript
   const PI = 3.14159;
   // PI = 3.14; // 错误！不能重新赋值给常量

   const obj = { value: 1 };
   obj.value = 2; // 可以修改常量对象的属性
   // obj = { value: 3 }; // 错误！不能重新赋值常量对象本身
   ```

* **跨脚本引用:**
   假设有两个 `<script>` 标签：
   ```html
   <script>
       var globalVar = 100;
   </script>
   <script>
       console.log(globalVar); // 可以访问另一个脚本中声明的全局变量
   </script>
   ```

* **严格模式 (`"use strict"`):**
   ```javascript
   "use strict";
   mistypedVar = 10; // 错误！在严格模式下，必须先声明变量才能使用
   ```

**代码逻辑推理 (假设输入与输出):**

测试用例通常会设定一些 JavaScript 代码片段作为输入，然后验证 V8 的解析器是否按照预期的方式处理这些声明。例如，在 `TEST_F(DeclsTest, Unknown)` 中：

* **假设输入 (JavaScript 代码):** `"var x; x"`
* **预期输出 (行为):** 解析器应该能正确解析 `var x;` 这个变量声明，并在访问 `x` 时返回 `undefined`，因为变量虽然声明了，但没有赋值。 相关的断言 (`CHECK_EQ`) 会验证 `DeclarationContext` 中跟踪的属性访问次数。

在更复杂的测试用例中，例如涉及属性拦截器，输入可能会更复杂，预期输出会涉及到拦截器的调用次数和返回值。

**用户常见的编程错误 (并举例说明):**

* **使用 `var` 声明的变量在声明前被访问 (Hoisting 的副作用):**
   ```javascript
   console.log(myVar); // 输出 undefined，而不是报错
   var myVar = 5;
   ```
   **解释:** `var` 声明会被提升到作用域顶部，但赋值操作不会。

* **重复声明 `let` 或 `const` 变量:**
   ```javascript
   let myLet = 10;
   // let myLet = 20; // 错误！Identifier 'myLet' has already been declared
   ```

* **在声明前访问 `let` 或 `const` 变量 (进入 Temporal Dead Zone):**
   ```javascript
   // console.log(myConst); // 错误！Cannot access 'myConst' before initialization
   const myConst = 30;
   ```

* **在块级作用域外访问块级作用域内声明的变量:**
   ```javascript
   if (true) {
       let blockVar = 40;
   }
   // console.log(blockVar); // 错误！blockVar is not defined
   ```

* **尝试修改 `const` 变量的值:**
   ```javascript
   const MY_CONSTANT = 100;
   // MY_CONSTANT = 200; // 错误！Assignment to constant variable.
   ```

* **在非严格模式下意外创建全局变量 (忘记使用 `var`, `let`, 或 `const`):**
   ```javascript
   function myFunction() {
       globalVar = 50; // 如果没有使用 var, let, const 声明，在非严格模式下会创建全局变量
   }
   myFunction();
   console.log(globalVar); // 在全局作用域中可以访问到
   ```

**归纳功能 (第 1 部分):**

总而言之，`v8/test/unittests/parser/decls-unittest.cc` 的主要功能是 **全面测试 V8 JavaScript 引擎解析器对于各种声明语句的正确解析和语义处理**，涵盖了基本声明、作用域规则、与属性拦截器的交互以及跨脚本引用的情况。它通过 C++ 代码编写的单元测试用例，确保 V8 引擎能够准确地理解和执行 JavaScript 中的声明逻辑。

Prompt: 
```
这是目录为v8/test/unittests/parser/decls-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/decls-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2007-2008 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdlib.h>

#include "include/v8-external.h"
#include "include/v8-initialization.h"
#include "include/v8-template.h"
#include "src/init/v8.h"
#include "test/unittests/heap/heap-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

namespace {

enum Expectations { EXPECT_RESULT, EXPECT_EXCEPTION, EXPECT_ERROR };

using DeclsTest = TestWithIsolate;

// A DeclarationContext holds a reference to a v8::Context and keeps
// track of various declaration related counters to make it easier to
// track if global declarations in the presence of interceptors behave
// the right way.
class DeclarationContext {
 public:
  DeclarationContext();

  virtual ~DeclarationContext() {
    if (is_initialized_) {
      HandleScope scope(isolate_);
      Local<Context> context = Local<Context>::New(isolate_, context_);
      context->Exit();
      context_.Reset();
    }
  }

  void Check(const char* source, int get, int set, int has,
             Expectations expectations,
             v8::Local<Value> value = Local<Value>());

  int get_count() const { return get_count_; }
  int set_count() const { return set_count_; }
  int query_count() const { return query_count_; }

 protected:
  virtual v8::Local<Value> Get(Local<Name> key);
  virtual Maybe<bool> Set(Local<Name> key, Local<Value> value);
  virtual v8::Local<Integer> Query(Local<Name> key);

  void InitializeIfNeeded();

  // Perform optional initialization steps on the context after it has
  // been created. Defaults to none but may be overwritten.
  virtual void PostInitializeContext(Local<Context> context) {}

  // Get the holder for the interceptor. Default to the instance template
  // but may be overwritten.
  virtual Local<ObjectTemplate> GetHolder(Local<FunctionTemplate> function) {
    return function->InstanceTemplate();
  }

  // The handlers are called as static functions that forward
  // to the instance specific virtual methods.
  static v8::Intercepted HandleGet(
      Local<Name> key, const v8::PropertyCallbackInfo<v8::Value>& info);
  static v8::Intercepted HandleSet(Local<Name> key, Local<Value> value,
                                   const v8::PropertyCallbackInfo<void>& info);
  static v8::Intercepted HandleQuery(
      Local<Name> key, const v8::PropertyCallbackInfo<v8::Integer>& info);

  v8::Isolate* isolate() const { return isolate_; }

  v8::internal::Isolate* i_isolate() const {
    return reinterpret_cast<i::Isolate*>(isolate_);
  }

 private:
  Isolate* isolate_;
  bool is_initialized_;
  Persistent<Context> context_;

  int get_count_;
  int set_count_;
  int query_count_;

  static DeclarationContext* GetInstance(Local<Value> data);
};

DeclarationContext::DeclarationContext()
    : isolate_(v8::Isolate::GetCurrent()),
      is_initialized_(false),
      get_count_(0),
      set_count_(0),
      query_count_(0) {
  // Do nothing.
}

void DeclarationContext::InitializeIfNeeded() {
  if (is_initialized_) return;
  HandleScope scope(isolate_);
  Local<FunctionTemplate> function = FunctionTemplate::New(isolate_);
  Local<Value> data = External::New(isolate_, this);
  GetHolder(function)->SetHandler(v8::NamedPropertyHandlerConfiguration(
      &HandleGet, &HandleSet, &HandleQuery, nullptr, nullptr, data));
  Local<Context> context = Context::New(
      isolate_, nullptr, function->InstanceTemplate(), Local<Value>());
  context_.Reset(isolate_, context);
  context->Enter();
  is_initialized_ = true;
  // Reset counts. Bootstrapping might have called into the interceptor.
  get_count_ = 0;
  set_count_ = 0;
  query_count_ = 0;
  PostInitializeContext(context);
}

void DeclarationContext::Check(const char* source, int get, int set, int query,
                               Expectations expectations,
                               v8::Local<Value> value) {
  InitializeIfNeeded();
  // A retry after a GC may pollute the counts, so perform gc now
  // to avoid that.
  InvokeMinorGC(i_isolate());
  HandleScope scope(isolate_);
  TryCatch catcher(isolate_);
  catcher.SetVerbose(true);
  Local<Context> context = isolate()->GetCurrentContext();
  MaybeLocal<Script> script = Script::Compile(
      context, String::NewFromUtf8(isolate(), source).ToLocalChecked());
  if (expectations == EXPECT_ERROR) {
    CHECK(script.IsEmpty());
    return;
  }
  CHECK(!script.IsEmpty());
  MaybeLocal<Value> result = script.ToLocalChecked()->Run(context);
  CHECK_EQ(get, get_count());
  CHECK_EQ(set, set_count());
  CHECK_EQ(query, query_count());
  if (expectations == EXPECT_RESULT) {
    CHECK(!catcher.HasCaught());
    if (!value.IsEmpty()) {
      CHECK(value->Equals(context, result.ToLocalChecked()).FromJust());
    }
  } else {
    CHECK(expectations == EXPECT_EXCEPTION);
    CHECK(catcher.HasCaught());
    if (!value.IsEmpty()) {
      CHECK(value->Equals(context, catcher.Exception()).FromJust());
    }
  }
  // Clean slate for the next test.
  InvokeMemoryReducingMajorGCs(i_isolate());
}

v8::Intercepted DeclarationContext::HandleGet(
    Local<Name> key, const v8::PropertyCallbackInfo<v8::Value>& info) {
  DeclarationContext* context = GetInstance(info.Data());
  context->get_count_++;
  auto result = context->Get(key);
  if (!result.IsEmpty()) {
    info.GetReturnValue().SetNonEmpty(result);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted DeclarationContext::HandleSet(
    Local<Name> key, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  DeclarationContext* context = GetInstance(info.Data());
  context->set_count_++;
  Maybe<bool> maybe_result = context->Set(key, value);
  bool result;
  if (maybe_result.To(&result)) {
    if (!result) {
      info.GetReturnValue().SetFalse();
    }
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted DeclarationContext::HandleQuery(
    Local<Name> key, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  DeclarationContext* context = GetInstance(info.Data());
  context->query_count_++;
  auto result = context->Query(key);
  if (!result.IsEmpty()) {
    info.GetReturnValue().SetNonEmpty(result);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

DeclarationContext* DeclarationContext::GetInstance(Local<Value> data) {
  void* value = Local<External>::Cast(data)->Value();
  return static_cast<DeclarationContext*>(value);
}

v8::Local<Value> DeclarationContext::Get(Local<Name> key) {
  return v8::Local<Value>();
}

Maybe<bool> DeclarationContext::Set(Local<Name> key, Local<Value> value) {
  return Nothing<bool>();
}

v8::Local<Integer> DeclarationContext::Query(Local<Name> key) {
  return v8::Local<Integer>();
}

}  // namespace

// Test global declaration of a property the interceptor doesn't know
// about and doesn't handle.
TEST_F(DeclsTest, Unknown) {
  HandleScope scope(isolate());

  {
    DeclarationContext context;
    context.Check("var x; x",
                  1,  // access
                  0, 0, EXPECT_RESULT, Undefined(isolate()));
  }

  {
    DeclarationContext context;
    context.Check("var x = 0; x",
                  1,  // access
                  1,  // initialization
                  0, EXPECT_RESULT, Number::New(isolate(), 0));
  }

  {
    DeclarationContext context;
    context.Check("function x() { }; x",
                  1,  // access
                  1, 1, EXPECT_RESULT);
  }
}

class AbsentPropertyContext : public DeclarationContext {
 protected:
  v8::Local<Integer> Query(Local<Name> key) override {
    return v8::Local<Integer>();
  }
};

TEST_F(DeclsTest, Absent) {
  HandleScope scope(isolate());

  {
    AbsentPropertyContext context;
    context.Check("var x; x",
                  1,  // access
                  0, 0, EXPECT_RESULT, Undefined(isolate()));
  }

  {
    AbsentPropertyContext context;
    context.Check("var x = 0; x",
                  1,  // access
                  1,  // initialization
                  0, EXPECT_RESULT, Number::New(isolate(), 0));
  }

  {
    AbsentPropertyContext context;
    context.Check("function x() { }; x",
                  1,  // access
                  1, 1, EXPECT_RESULT);
  }

  {
    AbsentPropertyContext context;
    context.Check("if (false) { var x = 0 }; x",
                  1,  // access
                  0, 0, EXPECT_RESULT, Undefined(isolate()));
  }
}

class AppearingPropertyContext : public DeclarationContext {
 public:
  enum State { DECLARE, INITIALIZE_IF_ASSIGN, UNKNOWN };

  AppearingPropertyContext() : state_(DECLARE) {}

 protected:
  v8::Local<Integer> Query(Local<Name> key) override {
    switch (state_) {
      case DECLARE:
        // Force declaration by returning that the
        // property is absent.
        state_ = INITIALIZE_IF_ASSIGN;
        return Local<Integer>();
      case INITIALIZE_IF_ASSIGN:
        // Return that the property is present so we only get the
        // setter called when initializing with a value.
        state_ = UNKNOWN;
        return Integer::New(isolate(), v8::None);
      default:
        CHECK(state_ == UNKNOWN);
        break;
    }
    // Do the lookup in the object.
    return v8::Local<Integer>();
  }

 private:
  State state_;
};

TEST_F(DeclsTest, Appearing) {
  HandleScope scope(isolate());

  {
    AppearingPropertyContext context;
    context.Check("var x; x",
                  1,  // access
                  0, 0, EXPECT_RESULT, Undefined(isolate()));
  }

  {
    AppearingPropertyContext context;
    context.Check("var x = 0; x",
                  1,  // access
                  1,  // initialization
                  0, EXPECT_RESULT, Number::New(isolate(), 0));
  }

  {
    AppearingPropertyContext context;
    context.Check("function x() { }; x",
                  1,  // access
                  1, 1, EXPECT_RESULT);
  }
}

class ExistsInPrototypeContext : public DeclarationContext {
 public:
  ExistsInPrototypeContext() { InitializeIfNeeded(); }

 protected:
  v8::Local<Integer> Query(Local<Name> key) override {
    // Let it seem that the property exists in the prototype object.
    return Integer::New(isolate(), v8::None);
  }

  // Use the prototype as the holder for the interceptors.
  Local<ObjectTemplate> GetHolder(Local<FunctionTemplate> function) override {
    return function->PrototypeTemplate();
  }
};

TEST_F(DeclsTest, ExistsInPrototype) {
  HandleScope scope(isolate());

  // Sanity check to make sure that the holder of the interceptor
  // really is the prototype object.
  {
    ExistsInPrototypeContext context;
    context.Check("this.x = 87; this.x", 0, 0, 1, EXPECT_RESULT,
                  Number::New(isolate(), 87));
  }

  {
    ExistsInPrototypeContext context;
    context.Check("var x; x", 0, 0, 0, EXPECT_RESULT, Undefined(isolate()));
  }

  {
    ExistsInPrototypeContext context;
    context.Check("var x = 0; x", 0, 0, 0, EXPECT_RESULT,
                  Number::New(isolate(), 0));
  }
}

class AbsentInPrototypeContext : public DeclarationContext {
 protected:
  v8::Local<Integer> Query(Local<Name> key) override {
    // Let it seem that the property is absent in the prototype object.
    return Local<Integer>();
  }

  // Use the prototype as the holder for the interceptors.
  Local<ObjectTemplate> GetHolder(Local<FunctionTemplate> function) override {
    return function->PrototypeTemplate();
  }
};

TEST_F(DeclsTest, AbsentInPrototype) {
  HandleScope scope(isolate());

  {
    AbsentInPrototypeContext context;
    context.Check("if (false) { var x = 0; }; x", 0, 0, 0, EXPECT_RESULT,
                  Undefined(isolate()));
  }
}

class SimpleContext {
 public:
  SimpleContext()
      : handle_scope_(v8::Isolate::GetCurrent()),
        context_(Context::New(v8::Isolate::GetCurrent())) {
    context_->Enter();
  }

  ~SimpleContext() { context_->Exit(); }

  void Check(const char* source, Expectations expectations,
             v8::Local<Value> value = Local<Value>()) {
    HandleScope scope(context_->GetIsolate());
    TryCatch catcher(context_->GetIsolate());
    catcher.SetVerbose(true);
    MaybeLocal<Script> script = Script::Compile(
        context_,
        String::NewFromUtf8(context_->GetIsolate(), source).ToLocalChecked());
    if (expectations == EXPECT_ERROR) {
      CHECK(script.IsEmpty());
      return;
    }
    CHECK(!script.IsEmpty());
    MaybeLocal<Value> result = script.ToLocalChecked()->Run(context_);
    if (expectations == EXPECT_RESULT) {
      CHECK(!catcher.HasCaught());
      if (!value.IsEmpty()) {
        CHECK(value->Equals(context_, result.ToLocalChecked()).FromJust());
      }
    } else {
      CHECK(expectations == EXPECT_EXCEPTION);
      CHECK(catcher.HasCaught());
      if (!value.IsEmpty()) {
        CHECK(value->Equals(context_, catcher.Exception()).FromJust());
      }
    }
  }

 private:
  HandleScope handle_scope_;
  Local<Context> context_;
};

TEST_F(DeclsTest, CrossScriptReferences) {
  HandleScope scope(isolate());

  {
    SimpleContext context;
    context.Check("var x = 1; x", EXPECT_RESULT, Number::New(isolate(), 1));
    context.Check("var x = 2; x", EXPECT_RESULT, Number::New(isolate(), 2));
    context.Check("x = 5; x", EXPECT_RESULT, Number::New(isolate(), 5));
    context.Check("var x = 6; x", EXPECT_RESULT, Number::New(isolate(), 6));
    context.Check("this.x", EXPECT_RESULT, Number::New(isolate(), 6));
    context.Check("function x() { return 7 }; x()", EXPECT_RESULT,
                  Number::New(isolate(), 7));
  }
}

TEST_F(DeclsTest, CrossScriptReferences_Simple) {
  i::v8_flags.use_strict = true;

  HandleScope scope(isolate());

  {
    SimpleContext context;
    context.Check("let x = 1; x", EXPECT_RESULT, Number::New(isolate(), 1));
    context.Check("let x = 5; x", EXPECT_EXCEPTION);
  }
}

TEST_F(DeclsTest, CrossScriptReferences_Simple2) {
  i::v8_flags.use_strict = true;

  HandleScope scope(isolate());

  for (int k = 0; k < 100; k++) {
    SimpleContext context;
    bool cond = (k % 2) == 0;
    if (cond) {
      context.Check("let x = 1; x", EXPECT_RESULT, Number::New(isolate(), 1));
      context.Check("let z = 4; z", EXPECT_RESULT, Number::New(isolate(), 4));
    } else {
      context.Check("let z = 1; z", EXPECT_RESULT, Number::New(isolate(), 1));
      context.Check("let x = 4; x", EXPECT_RESULT, Number::New(isolate(), 4));
    }
    context.Check("let y = 2; x", EXPECT_RESULT,
                  Number::New(isolate(), cond ? 1 : 4));
  }
}

TEST_F(DeclsTest, CrossScriptReferencesHarmony) {
  HandleScope scope(isolate());

  // Check that simple cross-script global scope access works.
  const char* decs[] = {"'use strict'; var x = 1; x",
                        "x",
                        "'use strict'; function x() { return 1 }; x()",
                        "x()",
                        "'use strict'; let x = 1; x",
                        "x",
                        "'use strict'; const x = 1; x",
                        "x",
                        nullptr};

  for (int i = 0; decs[i] != nullptr; i += 2) {
    SimpleContext context;
    context.Check(decs[i], EXPECT_RESULT, Number::New(isolate(), 1));
    context.Check(decs[i + 1], EXPECT_RESULT, Number::New(isolate(), 1));
  }

  // Check that cross-script global scope access works with late declarations.
  {
    SimpleContext context;
    context.Check("function d0() { return x0 }",  // dynamic lookup
                  EXPECT_RESULT, Undefined(isolate()));
    context.Check(
        "this.x0 = -1;"
        "d0()",
        EXPECT_RESULT, Number::New(isolate(), -1));
    context.Check(
        "'use strict';"
        "function f0() { let y = 10; return x0 + y }"
        "function g0() { let y = 10; return eval('x0 + y') }"
        "function h0() { let y = 10; return (1,eval)('x0') + y }"
        "x0 + f0() + g0() + h0()",
        EXPECT_RESULT, Number::New(isolate(), 26));

    context.Check(
        "'use strict';"
        "let x1 = 1;"
        "function f1() { let y = 10; return x1 + y }"
        "function g1() { let y = 10; return eval('x1 + y') }"
        "function h1() { let y = 10; return (1,eval)('x1') + y }"
        "function i1() { "
        "  let y = 10; return (typeof x2 === 'undefined' ? 0 : 2) + y"
        "}"
        "function j1() { let y = 10; return eval('x2 + y') }"
        "function k1() { let y = 10; return (1,eval)('x2') + y }"
        "function cl() { "
        "  let y = 10; "
        "  return { "
        "    f: function(){ return x1 + y },"
        "    g: function(){ return eval('x1 + y') },"
        "    h: function(){ return (1,eval)('x1') + y },"
        "    i: function(){"
        "      return (typeof x2 == 'undefined' ? 0 : 2) + y"
        "    },"
        "    j: function(){ return eval('x2 + y') },"
        "    k: function(){ return (1,eval)('x2') + y },"
        "  }"
        "}"
        "let o = cl();"
        "x1 + eval('x1') + (1,eval)('x1') + f1() + g1() + h1();",
        EXPECT_RESULT, Number::New(isolate(), 36));
    context.Check("x1 + eval('x1') + (1,eval)('x1') + f1() + g1() + h1();",
                  EXPECT_RESULT, Number::New(isolate(), 36));
    context.Check("o.f() + o.g() + o.h();", EXPECT_RESULT,
                  Number::New(isolate(), 33));
    context.Check("i1() + o.i();", EXPECT_RESULT, Number::New(isolate(), 20));

    context.Check(
        "'use strict';"
        "let x2 = 2;"
        "function f2() { let y = 20; return x2 + y }"
        "function g2() { let y = 20; return eval('x2 + y') }"
        "function h2() { let y = 20; return (1,eval)('x2') + y }"
        "function i2() { let y = 20; return x1 + y }"
        "function j2() { let y = 20; return eval('x1 + y') }"
        "function k2() { let y = 20; return (1,eval)('x1') + y }"
        "x2 + eval('x2') + (1,eval)('x2') + f2() + g2() + h2();",
        EXPECT_RESULT, Number::New(isolate(), 72));
    context.Check("x1 + eval('x1') + (1,eval)('x1') + f1() + g1() + h1();",
                  EXPECT_RESULT, Number::New(isolate(), 36));
    context.Check("i1() + j1() + k1();", EXPECT_RESULT,
                  Number::New(isolate(), 36));
    context.Check("i2() + j2() + k2();", EXPECT_RESULT,
                  Number::New(isolate(), 63));
    context.Check("o.f() + o.g() + o.h();", EXPECT_RESULT,
                  Number::New(isolate(), 33));
    context.Check("o.i() + o.j() + o.k();", EXPECT_RESULT,
                  Number::New(isolate(), 36));
    context.Check("i1() + o.i();", EXPECT_RESULT, Number::New(isolate(), 24));

    context.Check(
        "'use strict';"
        "let x0 = 100;"
        "x0 + eval('x0') + (1,eval)('x0') + "
        "    d0() + f0() + g0() + h0();",
        EXPECT_RESULT, Number::New(isolate(), 730));
    context.Check(
        "x0 + eval('x0') + (1,eval)('x0') + "
        "    d0() + f0() + g0() + h0();",
        EXPECT_RESULT, Number::New(isolate(), 730));
    context.Check(
        "delete this.x0;"
        "x0 + eval('x0') + (1,eval)('x0') + "
        "    d0() + f0() + g0() + h0();",
        EXPECT_RESULT, Number::New(isolate(), 730));
    context.Check(
        "this.x1 = 666;"
        "x1 + eval('x1') + (1,eval)('x1') + f1() + g1() + h1();",
        EXPECT_RESULT, Number::New(isolate(), 36));
    context.Check(
        "delete this.x1;"
        "x1 + eval('x1') + (1,eval)('x1') + f1() + g1() + h1();",
        EXPECT_RESULT, Number::New(isolate(), 36));
  }

  // Check that caching does respect scopes.
  {
    SimpleContext context;
    const char* script1 = "(function(){ return y1 })()";
    const char* script2 = "(function(){ return y2 })()";

    context.Check(script1, EXPECT_EXCEPTION);
    context.Check("this.y1 = 1; this.y2 = 2; 0;", EXPECT_RESULT,
                  Number::New(isolate(), 0));
    context.Check(script1, EXPECT_RESULT, Number::New(isolate(), 1));
    context.Check("'use strict'; let y1 = 3; 0;", EXPECT_RESULT,
                  Number::New(isolate(), 0));
    context.Check(script1, EXPECT_RESULT, Number::New(isolate(), 3));
    context.Check("y1 = 4;", EXPECT_RESULT, Number::New(isolate(), 4));
    context.Check(script1, EXPECT_RESULT, Number::New(isolate(), 4));

    context.Check(script2, EXPECT_RESULT, Number::New(isolate(), 2));
    context.Check("'use strict'; let y2 = 5; 0;", EXPECT_RESULT,
                  Number::New(isolate(), 0));
    context.Check(script1, EXPECT_RESULT, Number::New(isolate(), 4));
    context.Check(script2, EXPECT_RESULT, Number::New(isolate(), 5));
  }
}

TEST_F(DeclsTest, CrossScriptReferencesHarmonyRegress) {
  HandleScope scope(isolate());
  SimpleContext context;
  context.Check(
      "'use strict';"
      "function i1() { "
      "  let y = 10; return (typeof x2 === 'undefined' ? 0 : 2) + y"
      "}"
      "i1();"
      "i1();",
      EXPECT_RESULT, Number::New(isolate(), 10));
  context.Check(
      "'use strict';"
      "let x2 = 2; i1();",
      EXPECT_RESULT, Number::New(isolate(), 12));
}

TEST_F(DeclsTest, GlobalLexicalOSR) {
  i::v8_flags.use_strict = true;

  HandleScope scope(isolate());
  SimpleContext context;

  context.Check(
      "'use strict';"
      "let x = 1; x;",
      EXPECT_RESULT, Number::New(isolate(), 1));
  context.Check(
      "'use strict';"
      "let y = 2*x;"
      "++x;"
      "let z = 0;"
      "const limit = 100000;"
      "for (var i = 0; i < limit; ++i) {"
      "  z += x + y;"
      "}"
      "z;",
      EXPECT_RESULT, Number::New(isolate(), 400000));
}

TEST_F(DeclsTest, CrossScriptConflicts) {
  i::v8_flags.use_strict = true;

  HandleScope scope(isolate());

  const char* firsts[] = {"var x = 1; x", "function x() { return 1 }; x()",
                          "let x = 1; x", "const x = 1; x", nullptr};
  const char* seconds[] = {"var x = 2; x", "function x() { return 2 }; x()",
                           "let x = 2; x", "const x = 2; x", nullptr};

  for (int i = 0; firsts[i] != nullptr; ++i) {
    for (int j = 0; seconds[j] != nullptr; ++j) {
      SimpleContext context;
      context.Check(firsts[i], EXPECT_RESULT, Number::New(isolate(), 1));
      bool success_case = i < 2 && j < 2;
      Local<Value> success_result;
      if (success_case) success_result = Number::New(isolate(), 2);

      context.Check(seconds[j], success_case ? EXPECT_RESULT : EXPECT_EXCEPTION,
                    success_result);
    }
  }
}

TEST_F(DeclsTest, CrossScriptDynamicLookup) {
  HandleScope handle_scope(isolate());

  {
    SimpleContext context;
    Local<String> undefined_string = String::NewFromUtf8Literal(
        isolate(), "undefined", v8::NewStringType::kInternalized);
    Local<String> number_string = String::NewFromUtf8Literal(
        isolate(), "number", v8::NewStringType::kInternalized);

    context.Check(
        "function f(o) { with(o) { return x; } }"
        "function g(o) { with(o) { x = 15; } }"
        "function h(o) { with(o) { return typeof x; } }",
        EXPECT_RESULT, Undefined(isolate()));
    context.Check("h({})", EXPECT_RESULT, undefined_string);
    context.Check(
        "'use strict';"
        "let x = 1;"
        "f({})",
        EXPECT_RESULT, Number::New(isolate(), 1));
    context.Check(
        "'use strict';"
        "g({});0",
        EXPECT_RESULT, Number::New(isolate(), 0));
    context.Check("f({})", EXPECT_RESULT, Number::New(isolate(), 15));
    context.Check("h({})", EXPECT_RESULT, number_string);
  }
}

TEST_F(DeclsTest, CrossScriptGlobal) {
  HandleScope handle_scope(isolate());
  {
    SimpleContext context;

    context.Check(
        "var global = this;"
        "global.x = 255;"
        "x",
        EXPECT_RESULT, Number::New(isolate(), 255));
    context.Check(
        "'use strict';"
        "let x = 1;"
        "global.x",
        EXPECT_RESULT, Number::New(isolate(), 255));
    context.Check("global.x = 15; x", EXPECT_RESULT, Number::New(isolate(), 1));
    context.Check("x = 221; global.x", EXPECT_RESULT,
                  Number::New(isolate(), 15));
    context.Check(
        "z = 15;"
        "function f() { return z; };"
        "for (var k = 0; k < 3; k++) { f(); }"
        "f()",
        EXPECT_RESULT, Number::New(isolate(), 15));
    context.Check(
        "'use strict';"
        "let z = 5; f()",
        EXPECT_RESULT, Number::New(isolate(), 5));
    context.Check(
        "function f() { konst = 10; return konst; };"
        "f()",
        EXPECT_RESULT, Number::New(isolate(), 10));
    context.Check(
        "'use strict';"
        "const konst = 255;"
        "f()",
        EXPECT_EXCEPTION);
  }
}

TEST_F(DeclsTest, CrossScriptStaticLookupUndeclared) {
  HandleScope handle_scope(isolate());

  {
    SimpleContext context;
    Local<String> undefined_string = String::NewFromUtf8Literal(
        isolate(), "undefined", v8::NewStringType::kInternalized);
    Local<String> number_string = String::NewFromUtf8Literal(
        isolate(), "number", v8::NewStringType::kInternalized);

    context.Check(
        "function f(o) { return x; }"
        "function g(v) { x = v; }"
        "function h(o) { return typeof x; }",
        EXPECT_RESULT, Undefined(isolate()));
    context.Check("h({})", EXPECT_RESULT, undefined_string);
    context.Check(
        "'use strict';"
        "let x = 1;"
        "f({})",
        EXPECT_RESULT, Number::New(isolate(), 1));
    context.Check(
        "'use strict';"
        "g(15);x",
        EXPECT_RESULT, Number::New(isolate(), 15));
    context.Check("h({})", EXPECT_RESULT, number_string);
    context.Check("f({})", EXPECT_RESULT, Number::New(isolate(), 15));
    context.Check("h({})", EXPECT_RESULT, number_string);
  }
}

TEST_F(DeclsTest, CrossScriptLoadICs) {
  i::v8_flags.allow_natives_syntax = true;

  HandleScope handle_scope(isolate());

  {
    SimpleContext context;
    context.Check(
        "x = 15;"
        "function f() { return x; };"
        "function g() { return x; };"
        "%PrepareFunctionForOptimization(f);"
        "%PrepareFunctionForOptimization(g);"
        "f()",
        EXPECT_RESULT, Number::New(isolate(), 15));
    context.Check(
        "'use strict';"
        "let x = 5;"
        "f()",
        EXPECT_RESULT, Number::New(isolate(), 5));
    for (int k = 0; k < 3; k++) {
      context.Check("g()", EXPECT_RESULT, Number::New(isolate(), 5));
    }
    for (int k = 0; k < 3; k++) {
      context.Check("f()", EXPECT_RESULT, Number::New(isolate(), 5));
    }
    context.Check("%OptimizeFunctionOnNextCall(g); g()", EXPECT_RESULT,
                  Number::New(isolate(), 5));
    context.Check("%OptimizeFunctionOnNextCall(f); f()", EXPECT_RESULT,
                  Number::New(isolate(), 5));
  }
  {
    SimpleContext context;
    context.Check(
        "x = 15;"
        "function f() { return x; }"
        "%PrepareFunctionForOptimization(f);"
        "f()",
        EXPECT_RESULT, Number::New(isolate(), 15));
    for (int k = 0; k < 3; k++) {
      context.Check("f()", EXPECT_RESULT, Number::New(isolate(), 15));
    }
    context.Check("%OptimizeFunctionOnNextCall(f); f()", EXPECT_RESULT,
                  Number::New(isolate(), 15));
    context.Check(
        "'use strict';"
        "let x = 5;"
        "%PrepareFunctionForOptimization(f);"
        "f()",
        EXPECT_RESULT, Number::New(isolate(), 5));
    for (int k = 0; k < 3; k++) {
      context.Check("f()", EXPECT_RESULT, Number::New(isolate(), 5));
    }
    context.Check("%OptimizeFunctionOnNextCall(f); f()", EXPECT_RESULT,
                  Number::New(isolate(), 5));
  }
}

TEST_F(DeclsTest, CrossScriptStoreICs) {
  i::v8_flags.allow_natives_syntax = true;

  HandleScope handle_scope(isolate());

  {
    SimpleContext context;
    context.Check(
        "var global = this;"
        "x = 15;"
        "function f(v) { x = v; };"
        "function g(v) { x = v; };"
        "%PrepareFunctionForOptimization(f);"
        "%PrepareFunctionForOptimization(g);"
        "f(10); x",
        EXPECT_RESULT, Number::New(isolate(), 10));
    context.Check(
        "'use strict';"
        "let x = 5;"
        "f(7); x",
        EXPECT_RESULT, Number::New(isolate(), 7));
    context.Check("global.x", EXPECT_RESULT, Number::New(isolate(), 10));
    for (int k = 0; k < 3; k++) {
      context.Check("g(31); x", EXPECT_RESULT, Number::New(isolate(), 31));
    }
    context.Check("global.x", EXPECT_RESULT, Number::New(isolate(), 10));
    for (int k = 0; k < 3; k++) {
      context.Check("f(32); x", EXPECT_RESULT, Number::New(isolate(), 32));
    }
    context.Check("global.x", EXPECT_RESULT, Number::New(isolate(), 10));
    context.Check("%OptimizeFunctionOnNextCall(g); g(18); x", EXPECT_RESULT,
                  Number::New(isolate(), 18));
    context.Check("global.x", EXPECT_RESULT, Number::New(isolate(), 10));
    context.Check("%OptimizeFunctionOnNextCall(f); f(33); x", EXPECT_RESULT,
                  Number::New(isolate(), 33));
    context.Check("global.x", EXPECT_RESULT, Number::New(isolate(), 10));
  }
  {
    SimpleContext context;
    context.Check(
        "var global = this;"
        "x = 15;"
        "function f(v) { x = v; };"
        "%PrepareFunctionForOptimization(f);"
        "f(10); x",
        EXPECT_RESULT, Number::New(isolate(), 10));
    for (int k = 0; k < 3; k++) {
      context.Check("f(18); x", EXPECT_RESULT, Number::New(isolate(), 18));
    }
    context.Check("%OptimizeFunctionOnNextCall(f); f(20); x", EXPECT_RESULT,
                  Number::New(isolate(), 20));
    context.Check(
        "'use strict';"
        "let x = 5;"
        "f(8); x",
        EXPECT_RESULT, Number::New(isolate(), 8));
    context.Check("global.x", EXPECT_RESULT, Number::New(isolate(), 20));
    for (int k = 0; k < 3; k++) {
      context.Check("f(13); x", EXPECT_RESULT, Number::New(isolate(), 13));
    }
    context.Check("global.x", EXPECT_RESULT, Number::New(isolate(), 20));
    context.Check(
        "%PrepareFunctionForOptimization(f);"
        "%OptimizeFunctionOnNextCall(f); f(41); x",
        EXPECT_RESULT, Number::New(isolate(), 41));
    context.Check("global.x", EXPECT_RESULT, Number::New(isolate(), 20));
  }
}

TEST_F(DeclsTest, CrossScriptAssignmentToConst) {
  i::v8_flags.allow_natives_syntax = true;

  HandleScope handle_scope(isolate());

  {
    SimpleContext context;

    context.Check("function f() { x = 27; }", EXPECT_RESULT,
                  Undefined(isolate()));
    context.Check("'use strict';const x = 1; x", EXPECT_RESULT,
                  Number::New(isolate(), 1));
    context.Check("%PrepareFunctionForOptimization(f);f();", EXPECT_EXCEPTION);
    context.Check("x", EXPECT_RESULT, Number::New(isolate(), 1));
    context.Check("f();", EXPECT_EXCEPTION);
    context.Check("x", EXPECT_RESULT, Number::New(isolate(), 1));
    context.Check("%OptimizeFunctionOnNextCall(f);f();", EXPECT_EXCEPTION);
    context.Check("x", EXPECT_RESULT, Number::New(isolate(), 1));
  }
}

TEST_F(DeclsTest, Regress425510) {
  i::v8_flags.allow_natives_syntax = true;

  HandleScope handle_scope(isolate());

  {
    SimpleContext context;

    context.Check("'use strict'; o; const o = 10", EXPECT_EXCEPTION);

    for (int i = 0; i < 100; i++) {
      context.Check("o.prototype", EXPECT_EXCEPTION);
    }
  }
}

TEST_F(DeclsTest, Regress3941) {
  i::v8_flags.allow_natives_syntax = true;

  HandleScope handle_scope(isolate());

  {
    S
"""


```