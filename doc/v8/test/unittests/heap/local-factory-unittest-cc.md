Response:
Let's break down the thought process to analyze the C++ code and generate the desired output.

1. **Understand the Core Request:** The primary goal is to understand the functionality of `v8/test/unittests/heap/local-factory-unittest.cc`. The request also asks about potential .tq files, JavaScript relevance, logic inference, and common programming errors.

2. **Initial Code Scan (High-Level):**  Start by skimming the code to get a general idea. Key observations:
    * It's a C++ file.
    * It includes various V8 headers (e.g., `src/ast/...`, `src/heap/...`, `src/objects/...`).
    * It defines a test class `LocalFactoryTest` inheriting from `TestWithIsolateAndZone`. This immediately tells us it's a unit test.
    * It uses the Google Test framework (`TEST_F`).
    * The tests seem to revolve around a `LocalFactory` and creating various V8 objects like strings and functions.

3. **Focus on the Test Class and its Members:** The `LocalFactoryTest` class holds the core logic. Let's examine its members:
    * `reusable_state_`, `parse_info_`:  These likely relate to parsing JavaScript code.
    * `local_isolate_`:  Indicates interaction with an isolated V8 environment.
    * `ParseProgram()`:  This function takes a string, decodes it, and uses the V8 parser. This is crucial for understanding how the tests are set up.
    * `local_factory()`: This accessor points to the `LocalFactory` being tested.

4. **Analyze Individual Tests (Methodical Approach):** Go through each `TEST_F` one by one:
    * **`OneByteInternalizedString_IsAddedToStringTable`**:
        * Creates a one-byte string using `local_factory()->InternalizeString()`.
        * Checks if it's internalized.
        * Creates the same string using the global factory and checks if it's *not* internalized.
        * Internalizes the global string and verifies it's now equal to the first string.
        * **Functionality:** Demonstrates how `LocalFactory::InternalizeString` works and how it differs from the global factory. It also shows deduplication.
    * **`OneByteInternalizedString_DuplicateIsDeduplicated`**:
        * Creates the same string twice using `local_factory()->InternalizeString()`.
        * Verifies they are the same object.
        * **Functionality:**  Confirms the deduplication behavior of `InternalizeString` within the local factory.
    * **`AstRawString_IsInternalized`**:
        * Creates an `AstRawString`.
        * Calls `ast_value_factory.Internalize(local_isolate())`.
        * Checks if the `AstRawString`'s underlying `String` is internalized.
        * **Functionality:** Shows how `LocalFactory` interacts with the AST string representation and ensures internalization.
    * **`AstConsString_CreatesConsString`**:
        * Creates two `AstRawString`s.
        * Concatenates them using `NewConsString`.
        * Internalizes the AST strings.
        * Verifies the resulting `String` is a `ConsString` and has the correct content.
        * **Functionality:** Tests the creation of concatenated strings using the AST and local factory.
    * **`EmptyScript`**:
        * Parses an empty string.
        * Creates a `SharedFunctionInfo` for the top-level program.
        * Checks the `function_literal_id`.
        * **Functionality:** Tests the creation of a `SharedFunctionInfo` for an empty script.
    * **`LazyFunction`**:
        * Parses a script with a lazy function declaration.
        * Extracts the `FunctionLiteral` for the lazy function.
        * Creates a `SharedFunctionInfo`.
        * Checks the `function_literal_id`, name, and compilation status.
        * **Functionality:** Demonstrates the creation of `SharedFunctionInfo` for a lazily compiled function.
    * **`EagerFunction`**:
        * Parses a script with an eagerly compiled function expression.
        * Extracts the `FunctionLiteral`.
        * Creates a `SharedFunctionInfo`.
        * Checks the `function_literal_id`, name, and compilation status (though some checks are commented out).
        * **Functionality:**  Tests the creation of `SharedFunctionInfo` for an eagerly compiled function.
    * **`ImplicitNameFunction`**:
        * Parses a script with an anonymous function assigned to a variable.
        * Extracts the `FunctionLiteral`.
        * Creates a `SharedFunctionInfo`.
        * Checks the `function_literal_id` and that the `SharedFunctionInfo` gets the name of the variable.
        * **Functionality:** Shows how the `LocalFactory` handles implicit function names.
    * **`GCDuringPublish`**:  This test has the *exact same code* as `ImplicitNameFunction`. This is an important observation. It likely indicates a test that was intended to test something related to garbage collection during the publishing of a `SharedFunctionInfo` but currently doesn't do that explicitly.

5. **Synthesize the Functionality:** Based on the individual test analysis, summarize the overall purpose of the code. The key takeaway is that it tests the `LocalFactory`, which is responsible for creating various heap objects within a local isolate.

6. **Address the Specific Questions:**
    * **Functionality Listing:** List the core functionalities tested (string internalization, `SharedFunctionInfo` creation).
    * **.tq Files:** Explain that the file extension is `.cc` and thus not a Torque file.
    * **JavaScript Relevance:** Connect the tested functionalities to JavaScript concepts (strings, functions). Provide concrete JavaScript examples demonstrating similar concepts.
    * **Logic Inference:**  For tests involving parsing, demonstrate the input JavaScript and the expected outcome (e.g., the `function_literal_id`). Choose a clear example like the `LazyFunction` test.
    * **Common Programming Errors:** Think about potential errors related to the tested functionalities. For example, assuming string identity when it's not guaranteed, or misunderstanding the implications of internalization.

7. **Review and Refine:**  Read through the generated output to ensure clarity, accuracy, and completeness. Make sure the JavaScript examples are relevant and easy to understand. Correct any inconsistencies or ambiguities. For example, explicitly point out the redundancy in the `GCDuringPublish` test and speculate on its intended purpose.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the `LocalIsolate`. **Correction:** Realize that the tests are primarily about the `LocalFactory` *within* the `LocalIsolate`.
* **Confusion:**  Initially not fully grasping the role of `AstValueFactory`. **Correction:** Recognize its function in creating AST representations of strings and how the `LocalFactory` then internalizes them.
* **Missing Detail:**  Not initially explaining the significance of `function_literal_id`. **Correction:** Add context that it's an internal identifier for functions within the script.
* **Overlooking Redundancy:**  Potentially missing the identical code in `ImplicitNameFunction` and `GCDuringPublish`. **Correction:**  Carefully comparing the code blocks reveals the duplication, leading to speculation about the intended purpose of the latter.

By following this structured and iterative process, we can effectively analyze the C++ code and generate a comprehensive and accurate explanation.
This C++ source code file, `v8/test/unittests/heap/local-factory-unittest.cc`, contains **unit tests for the `LocalFactory` class in the V8 JavaScript engine**.

Here's a breakdown of its functionalities:

**Core Functionality Under Test: `LocalFactory`**

The `LocalFactory` is a component within a `LocalIsolate` (a lightweight, single-threaded isolate) in V8. Its primary responsibility is to efficiently create and manage heap objects (like strings, functions, etc.) within that local isolate. This is often done to avoid the overhead of the main isolate's heap for short-lived operations, such as during parsing or compilation.

**Specific Functionalities Tested:**

The tests in this file focus on verifying various aspects of the `LocalFactory`, including:

* **String Internalization:**
    * **`OneByteInternalizedString_IsAddedToStringTable`**: Tests that when a one-byte string is internalized using the `LocalFactory`, it's added to the string table. It also checks that a newly created identical string (not via the local factory) is not initially internalized but can be internalized later and will then be the same object.
    * **`OneByteInternalizedString_DuplicateIsDeduplicated`**: Verifies that if the same one-byte string is internalized twice via the `LocalFactory`, both handles will point to the same internalized string object (deduplication).
    * **`AstRawString_IsInternalized`**: Checks that `AstRawString`s (strings used in the Abstract Syntax Tree) are internalized when the `AstValueFactory`'s `Internalize` method is called in the context of the `LocalIsolate`.
    * **`AstConsString_CreatesConsString`**: Tests the creation of `ConsString` objects (concatenated strings) using the `LocalFactory` through the `AstValueFactory`.

* **SharedFunctionInfo Creation:**
    * **`EmptyScript`**: Tests the creation of a `SharedFunctionInfo` (metadata about a function) for an empty script. It verifies that the `function_literal_id` is 0 for the top-level scope.
    * **`LazyFunction`**:  Tests the creation of a `SharedFunctionInfo` for a lazily declared function. It checks that the `function_literal_id` is correct, the name is set, and that it's not yet compiled (has uncompiled data).
    * **`EagerFunction`**: Tests the creation of a `SharedFunctionInfo` for an eagerly evaluated function expression. It verifies the `function_literal_id` and name. (Note: Some compilation-related checks are commented out, suggesting this area might be under development or needs further testing).
    * **`ImplicitNameFunction`**: Tests the creation of a `SharedFunctionInfo` for an anonymous function assigned to a variable. It ensures that the `SharedFunctionInfo` correctly infers the function's name from the variable name.
    * **`GCDuringPublish`**: This test appears to have the same logic as `ImplicitNameFunction`. It likely aims to test scenarios where garbage collection might occur during the process of publishing (making available) a `SharedFunctionInfo`.

**Regarding `.tq` extension:**

The file `v8/test/unittests/heap/local-factory-unittest.cc` has the `.cc` extension, which signifies a **C++ source code file**. Therefore, it is **not** a V8 Torque source code file (which would have a `.tq` extension).

**Relationship with JavaScript and JavaScript Examples:**

The functionalities tested in this file are directly related to how V8 handles JavaScript code internally. Here are JavaScript examples illustrating the concepts:

* **String Internalization:**

   ```javascript
   const str1 = "foo";
   const str2 = "foo";
   console.log(str1 === str2); // true (string literals are often internalized)

   const symbol1 = Symbol("bar");
   const symbol2 = Symbol("bar");
   console.log(symbol1 === symbol2); // false (Symbols are always unique)
   ```

   In JavaScript, string literals are often internalized by the engine for performance. This means that if you have the same string literal in multiple places in your code, the engine might reuse the same string object in memory. The `LocalFactory`'s string internalization tests are mimicking this behavior at a lower level within V8.

* **SharedFunctionInfo:**

   ```javascript
   function myFunction() {
     // ... function body ...
   }

   const anonymousFunction = function() {
     // ... function body ...
   };

   const namedAnonymousFunction = function myNamedFunc() {
     // ... function body ...
   };
   ```

   The `SharedFunctionInfo` in V8 stores metadata about functions, like their name, the script they belong to, and whether they have been compiled. The tests for `SharedFunctionInfo` creation are verifying that this metadata is correctly created and populated by the `LocalFactory` during the parsing and compilation process.

**Code Logic Inference with Assumptions:**

Let's take the `LazyFunction` test as an example:

**Assumed Input (JavaScript source code):**

```javascript
function lazy() {}
```

**Steps Performed by `ParseProgram` and subsequent code:**

1. **Parsing:** The `ParseProgram` function parses the JavaScript code and builds an Abstract Syntax Tree (AST).
2. **Function Literal Extraction:** The test code navigates the AST to find the `FunctionLiteral` node representing the `lazy` function.
3. **`NewSharedFunctionInfoForLiteral`:** The `local_factory()->NewSharedFunctionInfoForLiteral` method is called with the `FunctionLiteral`.

**Expected Output (verified by the test):**

* `lazy_sfi->function_literal_id()` will be `1` (assuming this is the first non-top-level function encountered).
* `lazy_sfi->Name()->IsOneByteEqualTo(base::CStrVector("lazy"))` will be `true`.
* `lazy_sfi->is_compiled()` will be `false`.
* `lazy_sfi->HasUncompiledDataWithoutPreparseData()` will be `true`.

**Common Programming Errors (Related to Concepts Tested):**

* **Assuming String Identity:**  Beginners might assume that if two strings have the same content, they are always the same object in memory. While V8 often internalizes string literals, relying on strict equality (`===`) for object identity of strings created dynamically or through concatenation might lead to unexpected behavior.

   ```javascript
   const str1 = "hello";
   const str2 = "hell" + "o";
   console.log(str1 === str2); // May be false in some cases if not internalized

   const symbol1 = Symbol("test");
   const symbol2 = Symbol("test");
   console.log(symbol1 === symbol2); // Always false
   ```

* **Misunderstanding Function Scope and Names:**  Errors can occur when developers don't fully understand how function names are resolved, especially for anonymous functions. The `ImplicitNameFunction` test highlights how V8 tries to infer names for anonymous functions based on their context. Forgetting that anonymous functions declared within expressions often get an inferred name can be a source of confusion.

   ```javascript
   let myFunc = function() { /* ... */ };
   console.log(myFunc.name); // "myFunc" (inferred name)

   const obj = {
     method: function() {}
   };
   console.log(obj.method.name); // "method"
   ```

In summary, `v8/test/unittests/heap/local-factory-unittest.cc` is a crucial part of V8's testing infrastructure, ensuring the correctness and efficiency of the `LocalFactory` in managing heap objects within local isolates, which is fundamental to V8's performance and functionality.

### 提示词
```
这是目录为v8/test/unittests/heap/local-factory-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/local-factory-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cmath>
#include <iostream>
#include <limits>
#include <memory>

#include "src/ast/ast-value-factory.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/handles/handles-inl.h"
#include "src/handles/handles.h"
#include "src/handles/maybe-handles.h"
#include "src/heap/local-factory-inl.h"
#include "src/objects/fixed-array.h"
#include "src/objects/script.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/string.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parser.h"
#include "src/parsing/rewriter.h"
#include "src/parsing/scanner-character-streams.h"
#include "src/parsing/scanner.h"
#include "src/strings/unicode-inl.h"
#include "src/utils/utils.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {

class LocalIsolate;

namespace {

std::vector<uint16_t> DecodeUtf8(const std::string& string) {
  if (string.empty()) return {};

  auto utf8_data = base::Vector<const uint8_t>::cast(
      base::VectorOf(string.data(), string.length()));
  Utf8Decoder decoder(utf8_data);

  std::vector<uint16_t> utf16(decoder.utf16_length());
  decoder.Decode(&utf16[0], utf8_data);

  return utf16;
}

}  // namespace

class LocalFactoryTest : public TestWithIsolateAndZone {
 public:
  LocalFactoryTest()
      : TestWithIsolateAndZone(),
        reusable_state_(isolate()),
        parse_info_(
            isolate(),
            UnoptimizedCompileFlags::ForToplevelCompile(
                isolate(), true, construct_language_mode(v8_flags.use_strict),
                REPLMode::kNo, ScriptType::kClassic, v8_flags.lazy),
            &state_, &reusable_state_),
        local_isolate_(isolate()->main_thread_local_isolate()) {}

  FunctionLiteral* ParseProgram(const char* source) {
    auto utf16_source = DecodeUtf8(source);

    // Normally this would be an external string or whatever, we don't have to
    // worry about it for now.
    source_string_ = factory()
                         ->NewStringFromUtf8(base::CStrVector(source))
                         .ToHandleChecked();

    script_ = parse_info_.CreateScript(local_isolate(),
                                       local_factory()->empty_string(),
                                       kNullMaybeHandle, ScriptOriginOptions());

    parse_info_.set_character_stream(
        ScannerStream::ForTesting(utf16_source.data(), utf16_source.size()));

    Parser parser(local_isolate(), parse_info());
    parser.InitializeEmptyScopeChain(parse_info());
    parser.ParseOnBackground(local_isolate(), parse_info(), script_, 0, 0,
                             kFunctionLiteralIdTopLevel);

    DeclarationScope::AllocateScopeInfos(parse_info(), script_,
                                         local_isolate());

    // Create the SFI list on the script so that SFI SetScript works.
    DirectHandle<WeakFixedArray> infos = local_factory()->NewWeakFixedArray(
        parse_info()->max_info_id() + 1, AllocationType::kOld);
    script_->set_infos(*infos);

    return parse_info()->literal();
  }

  ParseInfo* parse_info() { return &parse_info_; }

  Handle<Script> script() { return script_; }

  LocalIsolate* local_isolate() { return local_isolate_; }
  LocalFactory* local_factory() { return local_isolate()->factory(); }

 private:
  SaveFlags save_flags_;
  UnoptimizedCompileState state_;
  ReusableUnoptimizedCompileState reusable_state_;
  ParseInfo parse_info_;
  LocalIsolate* local_isolate_;
  Handle<String> source_string_;
  Handle<Script> script_;
};

TEST_F(LocalFactoryTest, OneByteInternalizedString_IsAddedToStringTable) {
  base::Vector<const uint8_t> string_vector = base::StaticOneByteVector("foo");

  DirectHandle<String> string;
  {
    LocalHandleScope handle_scope(local_isolate());

    Handle<String> local_string =
        local_factory()->InternalizeString(string_vector);

    string = local_isolate()->heap()->NewPersistentHandle(local_string);
  }

  EXPECT_TRUE(string->IsOneByteEqualTo(base::CStrVector("foo")));
  EXPECT_TRUE(IsInternalizedString(*string));

  Handle<String> same_string = isolate()
                                   ->factory()
                                   ->NewStringFromOneByte(string_vector)
                                   .ToHandleChecked();
  EXPECT_NE(*string, *same_string);
  EXPECT_FALSE(IsInternalizedString(*same_string));

  DirectHandle<String> internalized_string =
      isolate()->factory()->InternalizeString(same_string);
  EXPECT_EQ(*string, *internalized_string);
}

TEST_F(LocalFactoryTest, OneByteInternalizedString_DuplicateIsDeduplicated) {
  base::Vector<const uint8_t> string_vector = base::StaticOneByteVector("foo");

  DirectHandle<String> string_1;
  DirectHandle<String> string_2;
  {
    LocalHandleScope handle_scope(local_isolate());

    Handle<String> local_string_1 =
        local_factory()->InternalizeString(string_vector);
    Handle<String> local_string_2 =
        local_factory()->InternalizeString(string_vector);

    string_1 = local_isolate()->heap()->NewPersistentHandle(local_string_1);
    string_2 = local_isolate()->heap()->NewPersistentHandle(local_string_2);
  }

  EXPECT_TRUE(string_1->IsOneByteEqualTo(base::CStrVector("foo")));
  EXPECT_TRUE(IsInternalizedString(*string_1));
  EXPECT_EQ(*string_1, *string_2);
}

TEST_F(LocalFactoryTest, AstRawString_IsInternalized) {
  AstValueFactory ast_value_factory(zone(), isolate()->ast_string_constants(),
                                    HashSeed(isolate()));

  const AstRawString* raw_string = ast_value_factory.GetOneByteString("foo");

  DirectHandle<String> string;
  {
    LocalHandleScope handle_scope(local_isolate());

    ast_value_factory.Internalize(local_isolate());

    string = local_isolate()->heap()->NewPersistentHandle(raw_string->string());
  }

  EXPECT_TRUE(string->IsOneByteEqualTo(base::CStrVector("foo")));
  EXPECT_TRUE(IsInternalizedString(*string));
}

TEST_F(LocalFactoryTest, AstConsString_CreatesConsString) {
  AstValueFactory ast_value_factory(zone(), isolate()->ast_string_constants(),
                                    HashSeed(isolate()));

  DirectHandle<String> string;
  {
    LocalHandleScope handle_scope(local_isolate());

    const AstRawString* foo_string = ast_value_factory.GetOneByteString("foo");
    const AstRawString* bar_string =
        ast_value_factory.GetOneByteString("bar-plus-padding-for-length");
    AstConsString* foobar_string =
        ast_value_factory.NewConsString(foo_string, bar_string);

    ast_value_factory.Internalize(local_isolate());

    string = local_isolate()->heap()->NewPersistentHandle(
        foobar_string->GetString(local_isolate()));
  }

  EXPECT_TRUE(IsConsString(*string));
  EXPECT_TRUE(string->Equals(*isolate()->factory()->NewStringFromStaticChars(
      "foobar-plus-padding-for-length")));
}

TEST_F(LocalFactoryTest, EmptyScript) {
  FunctionLiteral* program = ParseProgram("");

  DirectHandle<SharedFunctionInfo> shared;
  {
    LocalHandleScope handle_scope(local_isolate());

    shared = local_isolate()->heap()->NewPersistentHandle(
        local_factory()->NewSharedFunctionInfoForLiteral(program, script(),
                                                         true));
  }
  DirectHandle<SharedFunctionInfo> root_sfi = shared;

  EXPECT_EQ(root_sfi->function_literal_id(), 0);
}

TEST_F(LocalFactoryTest, LazyFunction) {
  FunctionLiteral* program = ParseProgram("function lazy() {}");
  FunctionLiteral* lazy = program->scope()
                              ->declarations()
                              ->AtForTest(0)
                              ->AsFunctionDeclaration()
                              ->fun();

  DirectHandle<SharedFunctionInfo> shared;
  {
    LocalHandleScope handle_scope(local_isolate());

    shared = local_isolate()->heap()->NewPersistentHandle(
        local_factory()->NewSharedFunctionInfoForLiteral(lazy, script(), true));
  }
  DirectHandle<SharedFunctionInfo> lazy_sfi = shared;

  EXPECT_EQ(lazy_sfi->function_literal_id(), 1);
  EXPECT_TRUE(lazy_sfi->Name()->IsOneByteEqualTo(base::CStrVector("lazy")));
  EXPECT_FALSE(lazy_sfi->is_compiled());
  EXPECT_TRUE(lazy_sfi->HasUncompiledDataWithoutPreparseData());
}

TEST_F(LocalFactoryTest, EagerFunction) {
  FunctionLiteral* program = ParseProgram("(function eager() {})");
  // Rewritten to `.result = (function eager() {}); return .result`
  FunctionLiteral* eager = program->body()
                               ->at(0)
                               ->AsExpressionStatement()
                               ->expression()
                               ->AsAssignment()
                               ->value()
                               ->AsFunctionLiteral();

  DirectHandle<SharedFunctionInfo> shared;
  {
    LocalHandleScope handle_scope(local_isolate());

    shared = local_isolate()->heap()->NewPersistentHandle(
        local_factory()->NewSharedFunctionInfoForLiteral(eager, script(),
                                                         true));
  }
  DirectHandle<SharedFunctionInfo> eager_sfi = shared;

  EXPECT_EQ(eager_sfi->function_literal_id(), 1);
  EXPECT_TRUE(eager_sfi->Name()->IsOneByteEqualTo(base::CStrVector("eager")));
  EXPECT_FALSE(eager_sfi->HasUncompiledData());
  // TODO(leszeks): Add compilation support and enable these checks.
  // EXPECT_TRUE(eager_sfi->is_compiled());
  // EXPECT_TRUE(eager_sfi->HasBytecodeArray());
}

TEST_F(LocalFactoryTest, ImplicitNameFunction) {
  FunctionLiteral* program = ParseProgram("let implicit_name = function() {}");
  FunctionLiteral* implicit_name = program->body()
                                       ->at(0)
                                       ->AsBlock()
                                       ->statements()
                                       ->at(0)
                                       ->AsExpressionStatement()
                                       ->expression()
                                       ->AsAssignment()
                                       ->value()
                                       ->AsFunctionLiteral();

  DirectHandle<SharedFunctionInfo> shared;
  {
    LocalHandleScope handle_scope(local_isolate());

    shared = local_isolate()->heap()->NewPersistentHandle(
        local_factory()->NewSharedFunctionInfoForLiteral(implicit_name,
                                                         script(), true));
  }
  DirectHandle<SharedFunctionInfo> implicit_name_sfi = shared;

  EXPECT_EQ(implicit_name_sfi->function_literal_id(), 1);
  EXPECT_TRUE(implicit_name_sfi->Name()->IsOneByteEqualTo(
      base::CStrVector("implicit_name")));
}

TEST_F(LocalFactoryTest, GCDuringPublish) {
  FunctionLiteral* program = ParseProgram("let implicit_name = function() {}");
  FunctionLiteral* implicit_name = program->body()
                                       ->at(0)
                                       ->AsBlock()
                                       ->statements()
                                       ->at(0)
                                       ->AsExpressionStatement()
                                       ->expression()
                                       ->AsAssignment()
                                       ->value()
                                       ->AsFunctionLiteral();

  DirectHandle<SharedFunctionInfo> shared;
  {
    LocalHandleScope handle_scope(local_isolate());

    shared = local_isolate()->heap()->NewPersistentHandle(
        local_factory()->NewSharedFunctionInfoForLiteral(implicit_name,
                                                         script(), true));
  }
  DirectHandle<SharedFunctionInfo> implicit_name_sfi = shared;

  EXPECT_EQ(implicit_name_sfi->function_literal_id(), 1);
  EXPECT_TRUE(implicit_name_sfi->Name()->IsOneByteEqualTo(
      base::CStrVector("implicit_name")));
}

}  // namespace internal
}  // namespace v8
```