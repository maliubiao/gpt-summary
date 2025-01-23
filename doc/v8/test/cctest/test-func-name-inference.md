Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The file name `test-func-name-inference.cc` strongly suggests the core functionality being tested. It's about how V8 infers or determines the names of functions in JavaScript code. The `.cc` extension confirms it's C++ source code for a test.

2. **Initial Code Scan - Identify Key Components:**  A quick skim reveals:
    * Includes:  `<memory>`, V8 API headers (`api-inl.h`), debug utilities (`debug.h`), object representations (`objects-inl.h`), string manipulation (`string-search.h`), and the test framework (`cctest.h`). This gives a high-level view of the tools being used.
    * `using` directives:  These simplify the code by allowing the use of short names like `Handle` instead of `v8::internal::Handle`.
    * `CheckFunctionName` function: This looks like the central verification mechanism. It takes a script, a string to locate a function, and an expected inferred name.
    * `Compile` function:  This likely compiles a JavaScript string into a V8 script object.
    * `TEST` macros: These are the individual test cases. Each one focuses on a specific scenario of function name inference.

3. **Deep Dive into `CheckFunctionName`:** This function is crucial. Let's analyze its steps:
    * Takes a `v8::Local<v8::Script>`, `func_pos_src` (a string to find the function), and `ref_inferred_name` (the expected name).
    * Gets the `i::Isolate` (the V8 runtime environment).
    * Extracts the `SharedFunctionInfo` (metadata about a function) from the script.
    * Finds the starting position (`func_pos`) of the `func_pos_src` within the script's source code using `SearchString`. This means the tests rely on finding specific code snippets.
    * Uses `isolate->debug()->FindInnermostContainingFunctionInfo` to get the `SharedFunctionInfo` for the function at the found position. This is the core of the name inference mechanism being tested.
    * Retrieves the *inferred* name using `shared_func_info->inferred_name()->ToCString()`.
    * Compares the inferred name with the `ref_inferred_name`. If they don't match, it throws an error.

4. **Analyze `Compile`:** This function is simpler. It takes a JavaScript string, compiles it using `v8::Script::Compile`, and returns the compiled script.

5. **Examine the `TEST` Cases:** Now, go through each `TEST` case and understand the JavaScript code and the expected inferred name:
    * `GlobalProperty`, `GlobalVar`, `LocalVar`: Test inference for functions assigned to global properties, global variables, and local variables.
    * `ObjectProperty`: Tests functions as object properties.
    * `InConstructor`: Tests methods defined within a constructor.
    * `Factory`: Tests functions within a factory function.
    * `Static`: Tests static methods of classes.
    * `Prototype`: Tests methods added to the prototype.
    * `ObjectLiteral`: Tests methods within an object literal used for the prototype.
    * `UpperCaseClass`, `LowerCaseClass`: Tests class constructor and method naming.
    * `AsParameter`, `AsConstructorParameter`: Tests anonymous functions passed as arguments (expecting empty names).
    * `MultipleFuncsConditional`, `MultipleFuncsInLiteral`: Tests functions defined within conditional expressions or object literals.
    * `AnonymousInAnonymousClosure1`, `AnonymousInAnonymousClosure2`, `NamedInAnonymousClosure`: Tests name inference within nested anonymous or named closures.
    * `Issue380`: Tests a specific bug fix scenario.
    * `MultipleAssignments`: Tests inference when multiple variables are assigned the same function.
    * `FactoryHashmap`, `FactoryHashmapVariable`, `FactoryHashmapConditional`: Tests functions assigned to object properties using bracket notation (including variable and conditional keys).
    * `GlobalAssignmentAndCall`, `AssignmentAndCall`: Tests cases where a function's *result* is assigned (expecting empty names for the assigned result).
    * `MethodAssignmentInAnonymousFunctionCall`: Tests method assignment within an immediately invoked function expression.
    * `ReturnAnonymousFunction`: Tests a function that returns another anonymous function.
    * `IgnoreExtendsClause`: Tests that `extends` clause doesn't interfere with name inference.
    * `ParameterAndArrow`: Tests an arrow function within a parameterized function.

6. **Connect to JavaScript Concepts:**  For each `TEST` case, relate it to corresponding JavaScript features (functions, variables, objects, classes, prototypes, closures, etc.). This helps in understanding *why* V8 might infer a certain name.

7. **Consider Edge Cases and Potential Errors:**  Think about situations where name inference might be tricky or where developers might make mistakes. For example, assigning the *result* of a function call, using computed property names, or deeply nested anonymous functions.

8. **Address Specific Questions:** Finally, go back to the original prompt and answer each question systematically:
    * **Functionality:** Summarize the overall purpose based on the analysis.
    * **`.tq` Extension:** Explain that it's not a Torque file.
    * **JavaScript Relation:** Provide JavaScript examples mirroring the C++ test cases.
    * **Code Logic Inference:** Explain `CheckFunctionName` with input/output examples.
    * **Common Programming Errors:** Give JavaScript examples of mistakes related to function naming and assignment.

**Self-Correction/Refinement During the Process:**

* **Initial assumption:**  Maybe initially I thought the tests directly *executed* the JavaScript. However, seeing the `Compile` and `CheckFunctionName` structure, I realized the C++ code is *analyzing* the *structure* of the JavaScript code to infer names, not necessarily running it for its side effects.
* **Clarifying `CheckFunctionName`:** I needed to carefully understand how `SearchString` and `FindInnermostContainingFunctionInfo` work together to locate the function and then retrieve its inferred name.
* **Categorizing Test Cases:** Grouping similar test cases (e.g., global vs. local variables, different ways of defining object methods) helped in understanding the overall coverage of the tests.
* **Focusing on "Inference":**  Constantly reminding myself that the core purpose is *name inference* helped in interpreting the results of the tests (e.g., why anonymous functions often have empty inferred names).

By following this detailed analysis, we can effectively understand the purpose and logic of the `test-func-name-inference.cc` file.This C++ source code file, `v8/test/cctest/test-func-name-inference.cc`, is a **test suite** for the V8 JavaScript engine. Specifically, it tests the **function name inference** feature.

Here's a breakdown of its functionality:

**Core Functionality:**

The primary goal of this test file is to verify that V8 correctly infers function names in various JavaScript scenarios. This inferred name is used in debugging tools (like stack traces) and developer consoles to provide more meaningful information about the code being executed.

**Key Components:**

1. **`CheckFunctionName` Function:** This is the heart of the testing logic. It takes a compiled JavaScript script, a substring that uniquely identifies a function within that script, and the expected inferred name of that function. It then performs the following steps:
   - Locates the function within the script's source code based on the provided substring.
   - Uses V8's internal debugging tools to find the `SharedFunctionInfo` associated with that function. The `SharedFunctionInfo` object stores metadata about the function, including its inferred name.
   - Retrieves the inferred name from the `SharedFunctionInfo`.
   - **Crucially, it compares the retrieved inferred name with the expected name provided in the test.** If they don't match, the test fails.

2. **`Compile` Function:** This helper function takes a string containing JavaScript code and compiles it into a `v8::Script` object that V8 can understand and analyze.

3. **`TEST` Macros:** Each `TEST` macro defines an individual test case. These test cases cover a wide range of JavaScript syntax and scenarios where function names might be inferred:
   - Global function declarations and assignments.
   - Local function declarations and assignments.
   - Functions as object properties.
   - Methods within constructors.
   - Functions within factory functions.
   - Static methods of classes.
   - Methods added to prototypes.
   - Methods defined within object literals used for prototypes.
   - Functions passed as parameters.
   - Functions defined conditionally.
   - Functions within closures (both named and anonymous).
   - Edge cases and specific bug fixes (like `Issue380`).
   - Functions involved in multiple assignments.
   - Functions assigned to object properties using bracket notation.
   - Scenarios involving immediately invoked function expressions (IIFEs).
   - Functions that return other anonymous functions.
   - Interaction with class syntax.
   - Arrow functions.

**If `v8/test/cctest/test-func-name-inference.cc` ended with `.tq`:**

It would indeed indicate that it's a **V8 Torque source code file**. Torque is a domain-specific language used within V8 for implementing built-in JavaScript functions and runtime code. However, the `.cc` extension confirms this is a standard C++ test file.

**Relationship with JavaScript and Examples:**

The tests in this file directly relate to how function names are perceived and used in JavaScript. Here are examples mirroring some of the test cases:

**1. Global Property:**

```javascript
// JavaScript code corresponding to TEST(GlobalProperty)
fun1 = function() { return 1; };
fun2 = function() { return 2; };

// V8 will infer the name "fun1" for the first function and "fun2" for the second.
```

**2. Local Variable:**

```javascript
// JavaScript code corresponding to TEST(LocalVar)
function outer() {
  var fun1 = function() { return 1; };
  var fun2 = function() { return 2; };
}

// V8 will infer the name "fun1" and "fun2" within the scope of 'outer'.
```

**3. Object Property:**

```javascript
// JavaScript code corresponding to TEST(ObjectProperty)
var obj = {
  fun1: function() { return 1; },
  fun2: class { constructor() { return 2; } }
};

// V8 will infer the name "obj.fun1" and "obj.fun2".
```

**Code Logic Inference (with Hypothetical Example):**

Let's consider the `TEST(GlobalProperty)` case:

**Hypothetical Input (to `CheckFunctionName`):**

- `script`: A compiled `v8::Script` object representing the JavaScript code: `"fun1 = function() { return 1; }\nfun2 = function() { return 2; }\n"`
- `func_pos_src`: `"return 1"` (to locate the first function)
- `ref_inferred_name`: `"fun1"`

**Expected Output (from `CheckFunctionName`):**

- The function will locate the `return 1` statement within the script.
- It will find the `SharedFunctionInfo` for the function containing that statement (which is the anonymous function assigned to `fun1`).
- V8's inference logic will have determined the name of this function to be "fun1" based on the assignment.
- The `CheckFunctionName` will compare the inferred name ("fun1") with the `ref_inferred_name` ("fun1").
- Since they match, this part of the test will pass.

**Hypothetical Input (to `CheckFunctionName` for the second function):**

- `script`: Same as above.
- `func_pos_src`: `"return 2"`
- `ref_inferred_name`: `"fun2"`

**Expected Output:**

- Similar logic, but the inferred name will be "fun2", and the comparison will pass.

**User-Common Programming Errors and Examples:**

This test suite indirectly highlights potential issues related to function naming and debugging:

1. **Anonymous Functions in Stack Traces:** If you rely heavily on anonymous functions, debugging can become harder because stack traces might not provide clear function names.

   ```javascript
   // Example where name inference is helpful
   function processData(callback) {
     // ... some operations ...
     callback(result);
   }

   processData(function(data) { // Anonymous function
     console.log("Data:", data);
   });

   // Without proper inference, the stack trace within the anonymous function might not be very informative.
   ```

2. **Misunderstanding Function Scope and Naming:**  Incorrect assumptions about how V8 infers names in different scopes can lead to confusion when debugging.

   ```javascript
   function outer() {
     var innerFunc = function() { return "inner"; };
     return innerFunc;
   }

   var myFunc = outer(); // myFunc now holds a reference to the inner function

   // V8 will infer the name "innerFunc" (or potentially "outer.innerFunc" in some contexts),
   // helping to understand where the function originated.
   ```

3. **Over-reliance on Computed Property Names:** While flexible, using computed property names for function assignments can sometimes make static analysis and name inference more challenging.

   ```javascript
   var obj = {};
   var methodName = "mySpecialMethod";
   obj[methodName] = function() { /* ... */ };

   // V8 might infer the name as "obj.<computed>" because the name isn't statically known.
   ```

In summary, `v8/test/cctest/test-func-name-inference.cc` is a crucial part of V8's testing infrastructure, ensuring that the function name inference mechanism works correctly across various JavaScript coding patterns. This directly impacts the quality of debugging information available to developers.

### 提示词
```
这是目录为v8/test/cctest/test-func-name-inference.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-func-name-inference.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
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
```