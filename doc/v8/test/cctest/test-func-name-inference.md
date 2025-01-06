Response: The user wants to understand the functionality of the C++ code file `v8/test/cctest/test-func-name-inference.cc`. The request also asks for an explanation of its relationship to JavaScript and a JavaScript example if such a relationship exists.

Here's a breakdown of the thought process to answer this request:

1. **Identify the core purpose of the C++ code:**  The filename `test-func-name-inference.cc` strongly suggests that this code is for testing the "function name inference" feature in V8. The comments at the beginning confirm this, being part of the V8 project's test suite.

2. **Analyze the `CheckFunctionName` function:** This function seems to be the core testing logic. It takes a compiled JavaScript script, a substring of a function within that script, and an expected inferred name. It then:
    * Locates the function within the script source.
    * Retrieves the `SharedFunctionInfo` for that function (this is a V8 internal object holding information about a function).
    * Accesses the `inferred_name` from the `SharedFunctionInfo`.
    * Compares the inferred name with the expected name.

3. **Examine the `TEST` macros:** The rest of the file consists of various `TEST` blocks. Each test:
    * Initializes the V8 environment.
    * Compiles a small JavaScript snippet using `Compile`.
    * Calls `CheckFunctionName` multiple times with different substrings and expected inferred names.

4. **Infer the feature being tested:** The different `TEST` cases cover various JavaScript scenarios:
    * Global function declarations (using `fun1 = function() {}` and `var fun1 = function() {}`).
    * Local function declarations.
    * Functions as object properties.
    * Functions within constructors.
    * Functions in factory patterns.
    * Static methods.
    * Prototype methods.
    * Functions in object literals.
    * Class constructors and methods (both uppercase and lowercase class names).
    * Anonymous functions passed as parameters.
    * Functions defined conditionally.
    * Functions within closures.
    * Functions involved in multiple assignments.
    * Functions passed as constructor parameters.
    * Functions assigned to object properties using bracket notation (including variable keys and conditional keys).
    * Scenarios involving immediately invoked function expressions (IIFEs).
    * Returning anonymous functions.
    * Ignoring `extends` clauses in classes.
    * Arrow functions within parameters.

    All these scenarios point to the core functionality being tested: **how V8 infers the name of a function when it's not explicitly named.**  This is crucial for debugging, profiling, and stack traces in JavaScript.

5. **Connect to JavaScript functionality:** Function name inference is a visible and important feature in JavaScript. When you define a function without a name in certain contexts, the JavaScript engine tries to figure out a sensible name for it. This name is often shown in developer tools.

6. **Create JavaScript examples:** To illustrate the C++ test cases, create corresponding JavaScript snippets that demonstrate the same scenarios and how the inferred names would likely appear in a browser's developer console. Focus on the scenarios where inference is expected to produce a meaningful name.

7. **Summarize the findings:**  Combine the observations into a clear summary that explains:
    * The purpose of the C++ file (testing function name inference).
    * How it works (using `CheckFunctionName` and various test cases).
    * The JavaScript feature it relates to (automatic function naming).
    * Provide the illustrative JavaScript examples.

8. **Review and refine:**  Ensure the explanation is accurate, concise, and easy to understand. Double-check the JavaScript examples for correctness and relevance. For example, note cases where the inference might be an empty string or `<computed>`.
这个C++源代码文件 `v8/test/cctest/test-func-name-inference.cc` 的功能是**测试 V8 JavaScript 引擎的函数名称推断（function name inference）机制**。

更具体地说，它包含了一系列的单元测试，用于验证 V8 在不同 JavaScript 语法结构下，能否正确地推断出匿名函数的名称。这些测试覆盖了各种常见的 JavaScript 代码模式，例如：

* **全局作用域中的函数赋值：** 测试 V8 能否根据变量名推断函数名。
* **局部作用域中的函数赋值：** 测试 V8 在局部变量中能否正确推断函数名。
* **对象属性中的函数：** 测试 V8 能否根据属性名推断函数名。
* **构造函数中的方法：** 测试 V8 能否根据方法名和类名推断函数名。
* **工厂函数中的方法：** 测试 V8 能否根据对象属性名推断函数名。
* **静态方法：** 测试 V8 能否根据类名和静态属性名推断函数名。
* **原型方法：** 测试 V8 能否根据类名和原型属性名推断函数名。
* **对象字面量中的方法：** 测试 V8 能否根据属性名推断函数名。
* **类（Class）中的方法：** 测试 V8 能否根据方法名和类名推断函数名。
* **作为参数传递的匿名函数：** 测试 V8 在这种情况下是否进行推断（通常不推断）。
* **条件表达式中的匿名函数：** 测试 V8 能否根据赋值的变量名推断函数名。
* **对象字面量中的条件表达式匿名函数：** 测试 V8 能否根据属性名推断函数名。
* **匿名闭包中的匿名函数：** 测试 V8 在嵌套匿名函数中的推断行为。
* **命名函数表达式：** 测试 V8 是否优先使用函数表达式的名字。
* **多重赋值：** 测试 V8 能否根据最终赋值的变量名推断函数名。
* **作为构造函数参数的匿名函数：** 测试 V8 在这种情况下是否进行推断（通常不推断）。
* **使用哈希表（对象）动态赋值函数：** 测试 V8 能否根据字符串字面量或变量推断函数名。
* **立即执行函数赋值：** 测试 V8 能否正确处理赋值操作。
* **返回匿名函数：** 测试 V8 在返回匿名函数时的推断行为。
* **忽略 `extends` 子句：** 测试 V8 在类继承中对函数名推断的影响。
* **箭头函数作为参数：** 测试 V8 对箭头函数的推断行为。

**与 JavaScript 的关系：**

这个 C++ 文件直接测试了 V8 JavaScript 引擎的功能，因此与 JavaScript 的功能紧密相关。函数名称推断是 JavaScript 引擎的一个重要特性，它有助于开发者在调试和性能分析时更好地理解代码的执行过程。当匿名函数出现在调用栈、性能分析工具等地方时，引擎推断出的名称可以提供更有意义的信息。

**JavaScript 举例说明：**

假设有以下 JavaScript 代码：

```javascript
// 全局作用域
myFunction = function() {
  console.log("Hello");
};

// 对象属性
const obj = {
  myMethod: function() {
    console.log("World");
  }
};

// 类方法
class MyClass {
  constructor() { }
  classMethod() {
    console.log("!");
  }
}
```

当 V8 引擎执行这段代码时，它会尝试推断匿名函数的名称：

* 对于 `myFunction = function() { ... }`，V8 会推断出函数名为 `myFunction`。
* 对于 `myMethod: function() { ... }`，V8 会推断出函数名为 `obj.myMethod`。
* 对于 `classMethod() { ... }`，V8 会推断出函数名为 `MyClass.classMethod`。

在开发者工具的调用栈或者性能分析中，你可能会看到类似 `myFunction`、`obj.myMethod`、`MyClass.classMethod` 这样的名称，而不是显示为 `anonymous`。

**`test-func-name-inference.cc` 中测试的逻辑就是确保 V8 在各种类似的 JavaScript 场景下都能正确地进行这种名称推断。** 例如，该文件中的 `TEST(GlobalProperty)` 测试用例就对应了上面的全局作用域函数赋值的场景：

```c++
TEST(GlobalProperty) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "fun1 = function() { return 1; }\n"
                                         "fun2 = function() { return 2; }\n");
  CheckFunctionName(script, "return 1", "fun1");
  CheckFunctionName(script, "return 2", "fun2");
}
```

这里的 `CheckFunctionName` 函数会验证 V8 在执行这段 JavaScript 代码后，对于包含 `return 1` 的匿名函数，推断出的名称是否为 "fun1"，对于包含 `return 2` 的匿名函数，推断出的名称是否为 "fun2"。

总之，`v8/test/cctest/test-func-name-inference.cc` 是 V8 引擎的一个测试文件，专门用来验证 JavaScript 函数名称推断功能的正确性，确保在各种 JavaScript 代码模式下，V8 都能为匿名函数推断出有意义的名称，从而提升开发者的调试和性能分析体验。

Prompt: 
```
这是目录为v8/test/cctest/test-func-name-inference.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2011 the V8 project authors. All rights reserved.
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

#include <memory>

#include "src/api/api-inl.h"
#include "src/debug/debug.h"
#include "src/objects/objects-inl.h"
#include "src/strings/string-search.h"
#include "test/cctest/cctest.h"

using ::v8::base::CStrVector;
using ::v8::base::Vector;
using ::v8::internal::DirectHandle;
using ::v8::internal::Factory;
using ::v8::internal::Handle;
using ::v8::internal::Heap;
using ::v8::internal::JSFunction;
using ::v8::internal::Runtime;
using ::v8::internal::SharedFunctionInfo;


static void CheckFunctionName(v8::Local<v8::Script> script,
                              const char* func_pos_src,
                              const char* ref_inferred_name) {
  i::Isolate* isolate = CcTest::i_isolate();

  // Get script source.
  DirectHandle<i::Object> obj = v8::Utils::OpenDirectHandle(*script);
  DirectHandle<SharedFunctionInfo> shared_function(
      IsSharedFunctionInfo(*obj) ? Cast<SharedFunctionInfo>(*obj)
                                 : Cast<JSFunction>(*obj)->shared(),
      isolate);
  Handle<i::Script> i_script(i::Cast<i::Script>(shared_function->script()),
                             isolate);
  CHECK(IsString(i_script->source()));
  DirectHandle<i::String> script_src(i::Cast<i::String>(i_script->source()),
                                     isolate);

  // Find the position of a given func source substring in the source.
  int func_pos;
  {
    i::DisallowGarbageCollection no_gc;
    v8::base::Vector<const uint8_t> func_pos_str =
        v8::base::OneByteVector(func_pos_src);
    i::String::FlatContent script_content = script_src->GetFlatContent(no_gc);
    func_pos = SearchString(isolate, script_content.ToOneByteVector(),
                            func_pos_str, 0);
  }
  CHECK_NE(0, func_pos);

  // Obtain SharedFunctionInfo for the function.
  DirectHandle<SharedFunctionInfo> shared_func_info = Cast<SharedFunctionInfo>(
      isolate->debug()->FindInnermostContainingFunctionInfo(i_script,
                                                            func_pos));

  // Verify inferred function name.
  std::unique_ptr<char[]> inferred_name =
      shared_func_info->inferred_name()->ToCString();
  if (strcmp(ref_inferred_name, inferred_name.get()) != 0) {
    GRACEFUL_FATAL("expected: %s, found: %s\n", ref_inferred_name,
                   inferred_name.get());
  }
}


static v8::Local<v8::Script> Compile(v8::Isolate* isolate, const char* src) {
  return v8::Script::Compile(
             isolate->GetCurrentContext(),
             v8::String::NewFromUtf8(isolate, src).ToLocalChecked())
      .ToLocalChecked();
}


TEST(GlobalProperty) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "fun1 = function() { return 1; }\n"
                                         "fun2 = function() { return 2; }\n");
  CheckFunctionName(script, "return 1", "fun1");
  CheckFunctionName(script, "return 2", "fun2");
}


TEST(GlobalVar) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "var fun1 = function() { return 1; }\n"
              "var fun2 = function() { return 2; }\n");
  CheckFunctionName(script, "return 1", "fun1");
  CheckFunctionName(script, "return 2", "fun2");
}


TEST(LocalVar) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "function outer() {\n"
              "  var fun1 = function() { return 1; }\n"
              "  var fun2 = function() { return 2; }\n"
              "}");
  CheckFunctionName(script, "return 1", "fun1");
  CheckFunctionName(script, "return 2", "fun2");
}

TEST(ObjectProperty) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "var obj = {\n"
              "  fun1: function() { return 1; },\n"
              "  fun2: class { constructor() { return 2; } }\n"
              "}");
  CheckFunctionName(script, "return 1", "obj.fun1");
  CheckFunctionName(script, "return 2", "obj.fun2");
}

TEST(InConstructor) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "function MyClass() {\n"
              "  this.method1 = function() { return 1; }\n"
              "  this.method2 = function() { return 2; }\n"
              "}");
  CheckFunctionName(script, "return 1", "MyClass.method1");
  CheckFunctionName(script, "return 2", "MyClass.method2");
}


TEST(Factory) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "function createMyObj() {\n"
              "  var obj = {};\n"
              "  obj.method1 = function() { return 1; }\n"
              "  obj.method2 = function() { return 2; }\n"
              "  return obj;\n"
              "}");
  CheckFunctionName(script, "return 1", "obj.method1");
  CheckFunctionName(script, "return 2", "obj.method2");
}


TEST(Static) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "function MyClass() {}\n"
              "MyClass.static1 = function() { return 1; }\n"
              "MyClass.static2 = function() { return 2; }\n"
              "MyClass.MyInnerClass = {}\n"
              "MyClass.MyInnerClass.static3 = function() { return 3; }\n"
              "MyClass.MyInnerClass.static4 = function() { return 4; }");
  CheckFunctionName(script, "return 1", "MyClass.static1");
  CheckFunctionName(script, "return 2", "MyClass.static2");
  CheckFunctionName(script, "return 3", "MyClass.MyInnerClass.static3");
  CheckFunctionName(script, "return 4", "MyClass.MyInnerClass.static4");
}


TEST(Prototype) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(
      CcTest::isolate(),
      "function MyClass() {}\n"
      "MyClass.prototype.method1 = function() { return 1; }\n"
      "MyClass.prototype.method2 = function() { return 2; }\n"
      "MyClass.MyInnerClass = function() {}\n"
      "MyClass.MyInnerClass.prototype.method3 = function() { return 3; }\n"
      "MyClass.MyInnerClass.prototype.method4 = function() { return 4; }");
  CheckFunctionName(script, "return 1", "MyClass.method1");
  CheckFunctionName(script, "return 2", "MyClass.method2");
  CheckFunctionName(script, "return 3", "MyClass.MyInnerClass.method3");
  CheckFunctionName(script, "return 4", "MyClass.MyInnerClass.method4");
}


TEST(ObjectLiteral) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "function MyClass() {}\n"
              "MyClass.prototype = {\n"
              "  method1: function() { return 1; },\n"
              "  method2: function() { return 2; } }");
  CheckFunctionName(script, "return 1", "MyClass.method1");
  CheckFunctionName(script, "return 2", "MyClass.method2");
}


TEST(UpperCaseClass) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "'use strict';\n"
                                         "class MyClass {\n"
                                         "  constructor() {\n"
                                         "    this.value = 1;\n"
                                         "  }\n"
                                         "  method() {\n"
                                         "    this.value = 2;\n"
                                         "  }\n"
                                         "}");
  CheckFunctionName(script, "this.value = 1", "MyClass");
  CheckFunctionName(script, "this.value = 2", "MyClass.method");
}


TEST(LowerCaseClass) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "'use strict';\n"
                                         "class myclass {\n"
                                         "  constructor() {\n"
                                         "    this.value = 1;\n"
                                         "  }\n"
                                         "  method() {\n"
                                         "    this.value = 2;\n"
                                         "  }\n"
                                         "}");
  CheckFunctionName(script, "this.value = 1", "myclass");
  CheckFunctionName(script, "this.value = 2", "myclass.method");
}


TEST(AsParameter) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(
      CcTest::isolate(),
      "function f1(a) { return a(); }\n"
      "function f2(a, b) { return a() + b(); }\n"
      "var result1 = f1(function() { return 1; })\n"
      "var result2 = f2(function() { return 2; }, function() { return 3; })");
  // Can't infer names here.
  CheckFunctionName(script, "return 1", "");
  CheckFunctionName(script, "return 2", "");
  CheckFunctionName(script, "return 3", "");
}


TEST(MultipleFuncsConditional) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "var x = 0;\n"
                                         "fun1 = x ?\n"
                                         "    function() { return 1; } :\n"
                                         "    function() { return 2; }");
  CheckFunctionName(script, "return 1", "fun1");
  CheckFunctionName(script, "return 2", "fun1");
}


TEST(MultipleFuncsInLiteral) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "var x = 0;\n"
              "function MyClass() {}\n"
              "MyClass.prototype = {\n"
              "  method1: x ? function() { return 1; } :\n"
              "               function() { return 2; } }");
  CheckFunctionName(script, "return 1", "MyClass.method1");
  CheckFunctionName(script, "return 2", "MyClass.method1");
}


TEST(AnonymousInAnonymousClosure1) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "(function() {\n"
                                         "  (function() {\n"
                                         "      var a = 1;\n"
                                         "      return;\n"
                                         "  })();\n"
                                         "  var b = function() {\n"
                                         "      var c = 1;\n"
                                         "      return;\n"
                                         "  };\n"
                                         "})();");
  CheckFunctionName(script, "return", "");
}


TEST(AnonymousInAnonymousClosure2) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "(function() {\n"
                                         "  (function() {\n"
                                         "      var a = 1;\n"
                                         "      return;\n"
                                         "  })();\n"
                                         "  var c = 1;\n"
                                         "})();");
  CheckFunctionName(script, "return", "");
}


TEST(NamedInAnonymousClosure) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "var foo = function() {\n"
                                         "  (function named() {\n"
                                         "      var a = 1;\n"
                                         "  })();\n"
                                         "  var c = 1;\n"
                                         "  return;\n"
                                         "};");
  CheckFunctionName(script, "return", "foo");
}


// See http://code.google.com/p/v8/issues/detail?id=380
TEST(Issue380) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "function a() {\n"
              "var result = function(p,a,c,k,e,d)"
              "{return p}(\"if blah blah\",62,1976,\'a|b\'.split(\'|\'),0,{})\n"
              "}");
  CheckFunctionName(script, "return p", "");
}


TEST(MultipleAssignments) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "var fun1 = fun2 = function () { return 1; }\n"
              "var bar1 = bar2 = bar3 = function () { return 2; }\n"
              "foo1 = foo2 = function () { return 3; }\n"
              "baz1 = baz2 = baz3 = function () { return 4; }");
  CheckFunctionName(script, "return 1", "fun2");
  CheckFunctionName(script, "return 2", "bar3");
  CheckFunctionName(script, "return 3", "foo2");
  CheckFunctionName(script, "return 4", "baz3");
}


TEST(AsConstructorParameter) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(
      CcTest::isolate(),
      "function Foo() {}\n"
      "var foo = new Foo(function() { return 1; })\n"
      "var bar = new Foo(function() { return 2; }, function() { return 3; })");
  CheckFunctionName(script, "return 1", "");
  CheckFunctionName(script, "return 2", "");
  CheckFunctionName(script, "return 3", "");
}


TEST(FactoryHashmap) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "function createMyObj() {\n"
              "  var obj = {};\n"
              "  obj[\"method1\"] = function() { return 1; }\n"
              "  obj[\"method2\"] = function() { return 2; }\n"
              "  return obj;\n"
              "}");
  CheckFunctionName(script, "return 1", "obj.method1");
  CheckFunctionName(script, "return 2", "obj.method2");
}


TEST(FactoryHashmapVariable) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "function createMyObj() {\n"
              "  var obj = {};\n"
              "  var methodName = \"method1\";\n"
              "  obj[methodName] = function() { return 1; }\n"
              "  methodName = \"method2\";\n"
              "  obj[methodName] = function() { return 2; }\n"
              "  return obj;\n"
              "}");
  // Can't infer function names statically.
  CheckFunctionName(script, "return 1", "obj.<computed>");
  CheckFunctionName(script, "return 2", "obj.<computed>");
}


TEST(FactoryHashmapConditional) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(
      CcTest::isolate(),
      "function createMyObj() {\n"
      "  var obj = {};\n"
      "  obj[0 ? \"method1\" : \"method2\"] = function() { return 1; }\n"
      "  return obj;\n"
      "}");
  // Can't infer the function name statically.
  CheckFunctionName(script, "return 1", "obj.<computed>");
}


TEST(GlobalAssignmentAndCall) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "var Foo = function() {\n"
                                         "  return 1;\n"
                                         "}();\n"
                                         "var Baz = Bar = function() {\n"
                                         "  return 2;\n"
                                         "}");
  // The inferred name is empty, because this is an assignment of a result.
  CheckFunctionName(script, "return 1", "");
  // See MultipleAssignments test.
  CheckFunctionName(script, "return 2", "Bar");
}


TEST(AssignmentAndCall) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "(function Enclosing() {\n"
                                         "  var Foo;\n"
                                         "  Foo = function() {\n"
                                         "    return 1;\n"
                                         "  }();\n"
                                         "  var Baz = Bar = function() {\n"
                                         "    return 2;\n"
                                         "  }\n"
                                         "})();");
  // The inferred name is empty, because this is an assignment of a result.
  CheckFunctionName(script, "return 1", "");
  // See MultipleAssignments test.
  // TODO(2276): Lazy compiling the enclosing outer closure would yield
  // in "Enclosing.Bar" being the inferred name here.
  CheckFunctionName(script, "return 2", "Bar");
}


TEST(MethodAssignmentInAnonymousFunctionCall) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "(function () {\n"
              "    var EventSource = function () { };\n"
              "    EventSource.prototype.addListener = function () {\n"
              "        return 2012;\n"
              "    };\n"
              "    this.PublicEventSource = EventSource;\n"
              "})();");
  CheckFunctionName(script, "return 2012", "EventSource.addListener");
}


TEST(ReturnAnonymousFunction) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "(function() {\n"
                                         "  function wrapCode() {\n"
                                         "    return function () {\n"
                                         "      return 2012;\n"
                                         "    };\n"
                                         "  };\n"
                                         "  var foo = 10;\n"
                                         "  function f() {\n"
                                         "    return wrapCode();\n"
                                         "  }\n"
                                         "  this.ref = f;\n"
                                         "})()");
  script->Run(CcTest::isolate()->GetCurrentContext()).ToLocalChecked();
  CheckFunctionName(script, "return 2012", "");
}

TEST(IgnoreExtendsClause) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script =
      Compile(CcTest::isolate(),
              "(function() {\n"
              "  var foo = {};\n"
              "  foo.C = class {}\n"
              "  class D extends foo.C {}\n"
              "  foo.bar = function() { return 1; };\n"
              "})()");
  script->Run(CcTest::isolate()->GetCurrentContext()).ToLocalChecked();
  CheckFunctionName(script, "return 1", "foo.bar");
}

TEST(ParameterAndArrow) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Script> script = Compile(CcTest::isolate(),
                                         "(function(param) {\n"
                                         "  (() => { return 2017 })();\n"
                                         "})()");
  script->Run(CcTest::isolate()->GetCurrentContext()).ToLocalChecked();
  CheckFunctionName(script, "return 2017", "");
}

"""

```