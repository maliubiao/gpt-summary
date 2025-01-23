Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Identify the Core Purpose:** The file name `v8-script-unittest.cc` and the `#include "include/v8-script.h"` immediately suggest that this is a unit test file specifically for the `v8::Script` API in V8. The "unittest" part is a strong indicator.

2. **Scan for Test Fixtures:** Look for `TEST_F`. These are the individual test cases. Each `TEST_F` tells you a specific aspect of the `v8::Script` functionality being tested. List them out. This gives a high-level overview of the file's scope.

3. **Examine Included Headers:** The included headers provide clues about the functionalities being tested. For instance:
    * `v8-script.h`: The main subject, dealing with script compilation and execution.
    * `v8-context.h`:  Indicates tests involving script execution within a V8 context.
    * `v8-isolate.h`:  Shows tests might involve different V8 isolates (though less prominent here).
    * `v8-local-handle.h`: Standard V8 handle usage.
    * `v8-primitive.h`, `v8-template.h`: Hints of testing with primitive values and potentially object templates, but not heavily featured in this specific file.
    * `src/objects/objects-inl.h`:  Suggests some internal V8 object manipulation might be indirectly involved, although the tests primarily interact through the public API.
    * `test/common/...`, `testing/gtest/...`:  Standard V8 testing infrastructure.

4. **Analyze Individual Test Cases (Granular View):**  Go through each `TEST_F` and understand its purpose:
    * **`UnboundScriptPosition`**: Focuses on retrieving the script's URL, line, and column number *before* execution. The term "UnboundScript" is key here.
    * **`GetSourceMappingUrlFromComment`**: Tests how V8 extracts source map URLs from special comments within the script.
    * **`OriginSourceMapOverridesSourceMappingUrlComment`**: Examines the priority of source maps provided through the API versus those in comments.
    * **`IgnoreOriginSourceMapEmptyString`**: A specific edge case for the previous test, ensuring an empty API source map doesn't prevent comment-based loading.
    * **`GetSingleStalledTopLevelAwaitMessage`, `GetMultipleStalledTopLevelAwaitMessage`, `GetMixedStalledTopLevelAwaitMessage`, `GetEmptyStalledTopLevelAwaitMessage`**: These clearly test the behavior of top-level `await` in modules, specifically how V8 reports which modules are blocking the initial loading. The helper function `TestGetStalledTopLevelAwaitMessage` is crucial to analyze here.
    * **`ProduceCompileHints`, `ProduceCompileHintsForArrowFunctions`**:  These test the mechanism for *generating* compile hints, which V8 can use to optimize later compilations. The presence of `GetCompileHintsCollector` confirms this.
    * **`ConsumeCompileHints`, `ConsumeCompileHintsForArrowFunctions`**: These test the opposite – how V8 *uses* provided compile hints during compilation. The `CompileHintsCallback` is the key here.
    * **`StreamingCompileHints`**: Tests the scenario where a script is compiled in chunks (streaming) and compile hints are consumed during this process.
    * **`CompileHintsMagicCommentBasic`, `CompileHintsMagicCommentDifferentFunctionTypes`, `CompileHintsMagicCommentBetweenFunctions`, `CompileHintsMagicCommentInvalid`, `CompileHintsMagicCommentInvalid2`, `CompileHintsMagicCommentNotEnabledByCompileOptions`, `StreamingCompileHintsMagic`**: These focus on a specific feature: using special comments (`//# eagerCompilation=all`) to influence compilation behavior. They cover various scenarios, including valid and invalid comments, different function types, and streaming.

5. **Look for Helper Functions and Classes:** The `ScriptTest` and `CompileHintsTest` classes provide setup and utility functions used across multiple tests. The `ValueEqualsString`, `from_v8_string`, and the resolver function for top-level await are important helpers to note.

6. **Identify Key Concepts:** Based on the test cases, identify the main V8 concepts being tested:
    * Script compilation (`v8::ScriptCompiler::Compile`, `v8::ScriptCompiler::CompileModule`).
    * Script execution (`script->Run`).
    * Script metadata (URL, line number, column number, source maps).
    * Top-level `await` in modules.
    * Compile hints (production and consumption).
    * Streaming compilation.
    * Compile hints magic comments.

7. **Consider JavaScript Relevance:**  Many of these tests directly relate to JavaScript features. Think about how these concepts manifest in JavaScript code (e.g., `import`, `await`, sourceMappingURL comments, function declarations).

8. **Look for Logic and Assumptions:** Analyze the code within the test cases. What are the expected inputs and outputs?  For example, the top-level await tests have specific module names ("stall.mjs", "resolve.mjs") to control the promise resolution.

9. **Identify Potential Programming Errors:**  Think about common mistakes developers might make when working with scripts, source maps, or asynchronous operations. The tests for invalid compile hint comments or not enabling the feature are examples of catching such errors.

10. **Structure the Output:** Organize the findings logically, starting with a high-level summary and then going into more detail. Use clear headings and bullet points. Provide code examples where appropriate (especially JavaScript).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This just tests basic script compilation."  **Correction:**  Realized the focus on source maps, top-level await, and compile hints makes it more nuanced.
* **Confusion:**  "What's the difference between `Script` and `UnboundScript`?" **Clarification:**  Recognized that `UnboundScript` holds metadata *before* execution.
* **Oversight:** Initially missed the significance of the `CompileHintsCallback`. **Correction:**  Analyzed its usage to understand the "consume hints" functionality.
* **Focusing too much on internal details:**  Realized the primary goal is to understand the *public API* being tested, not necessarily the intricate implementation details within V8.

By following this structured approach, moving from the general to the specific, and constantly asking "what is this testing?", a comprehensive understanding of the C++ test file can be achieved.
好的，让我们来分析一下 `v8/test/unittests/api/v8-script-unittest.cc` 这个 V8 源代码文件的功能。

**主要功能概览:**

这个 C++ 文件包含了针对 V8 JavaScript 引擎中 `v8::Script` 类的单元测试。 `v8::Script` 类代表了已编译的 JavaScript 代码。  因此，这个文件的主要目的是测试 `v8::Script` 类的各种功能，例如：

* **编译 JavaScript 代码:** 测试如何使用 `v8::ScriptCompiler::Compile` 编译 JavaScript 源代码。
* **获取脚本信息:** 测试获取已编译脚本的各种元数据，例如脚本的 URL、行号、列号、以及 Source Mapping URL。
* **处理 Top-Level Await (顶级 await):** 测试当模块中使用顶级 `await` 时，如何获取卡住的模块信息和错误消息。
* **编译提示 (Compile Hints):** 测试 V8 的编译提示机制，包括生成和消费编译提示，以及通过 Magic Comment 使用编译提示。
* **流式编译 (Streaming Compilation):** 测试以流的方式编译 JavaScript 代码，并结合编译提示。

**具体功能点及代码示例:**

1. **获取 UnboundScript 的位置信息:**

   - 测试 `script->GetUnboundScript()->GetScriptName()`，`GetLineNumber()`，`GetColumnNumber()` 等方法，用于获取脚本的 URL、起始行号和列号。
   - **假设输入:**  创建带有特定 URL 和行列号信息的 `v8::ScriptOrigin` 对象，并用其编译一个脚本。
   - **预期输出:**  `GetScriptName()` 返回预期的 URL，`GetLineNumber()` 和 `GetColumnNumber()` 返回预期的行号和列号。

2. **获取 Source Mapping URL:**

   - 测试从脚本注释中 (`//# sourceMappingURL=...`) 获取 Source Mapping URL 的功能，以及通过 `v8::ScriptOrigin` 显式设置 Source Mapping URL 的功能。
   - **JavaScript 示例:**
     ```javascript
     // foo.js
     var a = 1;
     //# sourceMappingURL=foo.js.map
     ```
   - **测试逻辑:** 编译包含上述注释的脚本，然后使用 `script->GetUnboundScript()->GetSourceMappingURL()` 获取 Source Mapping URL，并验证其是否为 `foo.js.map`。同时测试 API 设置的 Source Mapping URL 优先级高于注释。

3. **处理 Stalled Top-Level Await 消息:**

   - 测试当模块依赖的模块中存在无法解析的顶级 `await` Promise 时，如何获取这些卡住的模块的信息和错误消息。
   - **JavaScript 示例 (module 'stall.mjs'):**
     ```javascript
     const promise = new Promise(() => {}); // Promise never resolves
     await promise;
     ```
   - **测试逻辑:**  编译一个导入 `stall.mjs` 的模块，执行后检查 Promise 的状态是否为 pending，并使用 `root->GetStalledTopLevelAwaitMessages()` 获取卡住的模块和相关的错误消息。
   - **假设输入:** 编译包含 `import 'stall.mjs';` 的模块。
   - **预期输出:**  `GetStalledTopLevelAwaitMessages()` 返回包含 `stall.mjs` 的信息，错误消息为 "Top-level await promise never resolved"，以及相关的代码位置信息。

4. **编译提示 (Compile Hints):**

   - 测试 V8 的编译提示功能，该功能允许引擎记录哪些函数在脚本首次运行时被调用，以便在后续编译中进行优化。
   - **JavaScript 示例:**
     ```javascript
     function lazy1() {}
     function lazy2() {}
     lazy1(); // 首次运行时调用 lazy1
     ```
   - **测试逻辑:**
     - 使用 `v8::ScriptCompiler::CompileOptions::kProduceCompileHints` 编译脚本。
     - 运行脚本，调用 `lazy1`。
     - 使用 `script->GetCompileHintsCollector()->GetCompileHints()` 获取编译提示，验证 `lazy1` 的位置信息被记录。
     - 再次运行包含 `lazy2()` 的脚本，验证 `lazy2` 的位置信息也被记录。
     - 测试 `v8::ScriptCompiler::CompileOptions::kConsumeCompileHints`，允许在编译时利用之前记录的编译提示，提前编译某些函数。

5. **流式编译 (Streaming Compilation):**

   - 测试以流的方式编译 JavaScript 代码，允许在代码完全加载之前开始编译。
   - **测试逻辑:**  使用 `v8::ScriptCompiler::StreamedSource` 创建流式源，然后使用 `v8::ScriptCompiler::StartStreaming` 开始后台编译。最后，使用 `v8::ScriptCompiler::Compile` 完成编译。

6. **编译提示 Magic Comment:**

   - 测试使用特殊的注释 (`//# eagerCompilation=all`) 来指示 V8 积极编译某些函数的功能。
   - **JavaScript 示例:**
     ```javascript
     //# eagerCompilation=all
     function f1() {}
     let f2 = function() {};
     ```
   - **测试逻辑:** 编译包含 Magic Comment 的脚本，并设置编译选项 `v8::ScriptCompiler::CompileOptions::kFollowCompileHintsMagicComment`。运行脚本后，检查 `f1` 和 `f2` 是否已被积极编译。
   - **用户常见编程错误:**  忘记启用 `kFollowCompileHintsMagicComment` 编译选项，导致 Magic Comment 无效。

**如果 `v8/test/unittests/api/v8-script-unittest.cc` 以 `.tq` 结尾:**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 内部使用的领域特定语言，用于定义运行时函数的实现。在这种情况下，该文件将包含使用 Torque 编写的单元测试，用于测试 V8 内部的运行时功能，而不是 `v8::Script` API 的功能。

**总结:**

`v8/test/unittests/api/v8-script-unittest.cc` 是一个重要的 V8 单元测试文件，它全面测试了 `v8::Script` 类的各种功能，涵盖了脚本编译、元数据获取、异步模块处理和编译优化等关键方面。这些测试确保了 V8 引擎在处理 JavaScript 代码时的正确性和可靠性。

### 提示词
```
这是目录为v8/test/unittests/api/v8-script-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/api/v8-script-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-script.h"

#include <algorithm>

#include "include/v8-context.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-primitive.h"
#include "include/v8-template.h"
#include "src/objects/objects-inl.h"
#include "test/common/flag-utils.h"
#include "test/common/streaming-helper.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace {

namespace {
bool ValueEqualsString(v8::Isolate* isolate, Local<Value> lhs,
                       const char* rhs) {
  CHECK(!lhs.IsEmpty());
  CHECK(lhs->IsString());
  String::Utf8Value utf8_lhs(isolate, lhs);
  return strcmp(rhs, *utf8_lhs) == 0;
}

std::string from_v8_string(Isolate* isolate, Local<String> str) {
  String::Utf8Value utf8(isolate, str);
  return *utf8;
}

v8::MaybeLocal<Module> ResolveToTopLevelAwait(Local<Context> context,
                                              Local<String> specifier,
                                              Local<FixedArray> assertions,
                                              Local<Module> referrer) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::ScriptOrigin origin(specifier, 0, 0, false, -1, Local<Value>(), false,
                          false, true);

  String::Utf8Value specifier_string(isolate, specifier);
  std::string source_string =
      "const promise = new Promise((resolve, reject) => {\n"
      "  if (should_resolve) {\n"
      "    resolve();\n"
      "  }\n"
      "});\n"
      "await promise;\n";
  if (strncmp(*specifier_string, "stall", strlen("stall")) == 0) {
    source_string = "const should_resolve = false;\n" + source_string;
  } else if (strncmp(*specifier_string, "resolve", strlen("resolve")) == 0) {
    source_string = "const should_resolve = true;\n" + source_string;
  } else {
    UNREACHABLE();
  }

  v8::ScriptCompiler::Source source(
      v8::String::NewFromUtf8(isolate, source_string.c_str()).ToLocalChecked(),
      origin);
  auto res = v8::ScriptCompiler::CompileModule(isolate, &source);
  return res;
}

class ScriptTest : public TestWithContext {
 protected:
  void TestGetStalledTopLevelAwaitMessage(
      const char* source_str, std::vector<std::string> expected_stalled) {
    v8::Isolate::Scope iscope(isolate());
    v8::HandleScope scope(isolate());
    v8::Local<v8::Context> context = v8::Context::New(isolate());
    v8::Context::Scope cscope(context);

    v8::ScriptOrigin origin(NewString("root.mjs"), 0, 0, false, -1,
                            Local<Value>(), false, false, true);
    v8::ScriptCompiler::Source source(NewString(source_str), origin);
    Local<Module> root =
        v8::ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();

    CHECK(root->InstantiateModule(context, ResolveToTopLevelAwait)
              .FromMaybe(false));

    Local<v8::Promise> promise =
        root->Evaluate(context).ToLocalChecked().As<v8::Promise>();
    isolate()->PerformMicrotaskCheckpoint();
    CHECK_EQ(expected_stalled.size() > 0
                 ? v8::Promise::PromiseState::kPending
                 : v8::Promise::PromiseState::kFulfilled,
             promise->State());

    auto [stalled_modules, stalled_messages] =
        root->GetStalledTopLevelAwaitMessages(isolate());
    CHECK_EQ(expected_stalled.size(), stalled_modules.size());
    CHECK_EQ(expected_stalled.size(), stalled_messages.size());
    for (size_t i = 0; i < expected_stalled.size(); ++i) {
      Local<Message> message = stalled_messages[i];
      CHECK_EQ("Top-level await promise never resolved",
               from_v8_string(isolate(), message->Get()));
      CHECK_EQ(expected_stalled[i],
               from_v8_string(isolate(),
                              message->GetScriptResourceName().As<String>()));
      CHECK_EQ(
          "await promise;",
          from_v8_string(isolate(),
                         message->GetSourceLine(context).ToLocalChecked()));

      CHECK_EQ(7, message->GetLineNumber(context).ToChecked());
      CHECK_EQ(0, message->GetStartColumn(context).ToChecked());
      CHECK_EQ(1, message->GetEndColumn(context).ToChecked());
    }
  }
};

class CompileHintsTest : public ScriptTest {
 protected:
  std::vector<int> ProduceCompileHintsHelper(
      std::initializer_list<const char*> sources) {
    const char* url = "http://www.foo.com/foo.js";
    v8::ScriptOrigin origin(NewString(url), 13, 0);

    Local<Script> top_level_script;
    bool first = true;
    for (auto source : sources) {
      v8::ScriptCompiler::Source script_source(NewString(source), origin);
      Local<Script> script =
          v8::ScriptCompiler::Compile(
              v8_context(), &script_source,
              v8::ScriptCompiler::CompileOptions::kProduceCompileHints)
              .ToLocalChecked();
      if (first) {
        top_level_script = script;
        first = false;
      }

      v8::MaybeLocal<v8::Value> result = script->Run(v8_context());
      EXPECT_FALSE(result.IsEmpty());
    }
    return top_level_script->GetCompileHintsCollector()->GetCompileHints(
        v8_isolate());
  }

  bool FunctionIsCompiled(const char* name) {
    const char* url = "http://www.foo.com/foo.js";
    v8::ScriptOrigin origin(NewString(url), 13, 0);

    v8::ScriptCompiler::Source script_source(NewString(name), origin);

    Local<Script> script =
        v8::ScriptCompiler::Compile(v8_context(), &script_source)
            .ToLocalChecked();
    v8::MaybeLocal<v8::Value> result = script->Run(v8_context());

    auto function =
        i::Cast<i::JSFunction>(Utils::OpenHandle(*result.ToLocalChecked()));
    i::Builtin builtin = function->code(i_isolate())->builtin_id();

    return builtin != i::Builtin::kCompileLazy;
  }
};

}  // namespace

TEST_F(ScriptTest, UnboundScriptPosition) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);
  v8::ScriptCompiler::Source script_source(NewString("var foo;"), origin);

  Local<Script> script =
      v8::ScriptCompiler::Compile(v8_context(), &script_source)
          .ToLocalChecked();
  EXPECT_TRUE(ValueEqualsString(
      isolate(), script->GetUnboundScript()->GetScriptName(), url));
  Local<UnboundScript> unbound_script = script->GetUnboundScript();

  int line_number = unbound_script->GetLineNumber();
  EXPECT_EQ(13, line_number);
  int column_number = unbound_script->GetColumnNumber();
  EXPECT_EQ(0, column_number);
}

TEST_F(ScriptTest, GetSourceMappingUrlFromComment) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url));
  v8::ScriptCompiler::Source script_source(
      NewString("var foo;\n//# sourceMappingURL=foo.js.map"), origin);

  Local<Script> script =
      v8::ScriptCompiler::Compile(v8_context(), &script_source)
          .ToLocalChecked();
  EXPECT_EQ(
      "foo.js.map",
      from_v8_string(
          isolate(),
          script->GetUnboundScript()->GetSourceMappingURL().As<String>()));
}

TEST_F(ScriptTest, OriginSourceMapOverridesSourceMappingUrlComment) {
  const char* url = "http://www.foo.com/foo.js";
  const char* api_source_map = "http://override/foo.js.map";
  v8::ScriptOrigin origin(NewString(url), 13, 0, false, -1,
                          NewString(api_source_map));
  v8::ScriptCompiler::Source script_source(
      NewString("var foo;\n//# sourceMappingURL=foo.js.map"), origin);

  Local<Script> script =
      v8::ScriptCompiler::Compile(v8_context(), &script_source)
          .ToLocalChecked();
  EXPECT_EQ(
      api_source_map,
      from_v8_string(
          isolate(),
          script->GetUnboundScript()->GetSourceMappingURL().As<String>()));
}

TEST_F(ScriptTest, IgnoreOriginSourceMapEmptyString) {
  const char* url = "http://www.foo.com/foo.js";
  const char* api_source_map = "";
  v8::ScriptOrigin origin(NewString(url), 13, 0, false, -1,
                          NewString(api_source_map));
  v8::ScriptCompiler::Source script_source(
      NewString("var foo;\n//# sourceMappingURL=foo.js.map"), origin);

  Local<Script> script =
      v8::ScriptCompiler::Compile(v8_context(), &script_source)
          .ToLocalChecked();
  EXPECT_EQ(
      "foo.js.map",
      from_v8_string(
          isolate(),
          script->GetUnboundScript()->GetSourceMappingURL().As<String>()));
}

TEST_F(ScriptTest, GetSingleStalledTopLevelAwaitMessage) {
  TestGetStalledTopLevelAwaitMessage("import 'stall.mjs';", {"stall.mjs"});
}

TEST_F(ScriptTest, GetMultipleStalledTopLevelAwaitMessage) {
  TestGetStalledTopLevelAwaitMessage(
      "import 'stall.mjs';\n"
      "import 'stall_2.mjs';\n"
      "import 'stall_3.mjs';\n"
      "import 'stall_4.mjs';\n",
      {"stall.mjs", "stall_2.mjs", "stall_3.mjs", "stall_4.mjs"});
}

TEST_F(ScriptTest, GetMixedStalledTopLevelAwaitMessage) {
  TestGetStalledTopLevelAwaitMessage(
      "import 'stall.mjs';\n"
      "import 'resolve.mjs';\n"
      "import 'stall_2.mjs';\n"
      "import 'resolve.mjs';\n",
      {"stall.mjs", "stall_2.mjs"});
}

TEST_F(ScriptTest, GetEmptyStalledTopLevelAwaitMessage) {
  TestGetStalledTopLevelAwaitMessage(
      "import 'resolve.mjs';\n"
      "import 'resolve_2.mjs';\n"
      "import 'resolve_3.mjs';\n",
      {});
}

TEST_F(ScriptTest, ProduceCompileHints) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);

  const char* code = "function lazy1() {} function lazy2() {} lazy1();";
  v8::ScriptCompiler::Source script_source(NewString(code), origin);

  // Test producing compile hints.
  {
    Local<Script> script =
        v8::ScriptCompiler::Compile(
            v8_context(), &script_source,
            v8::ScriptCompiler::CompileOptions::kProduceCompileHints)
            .ToLocalChecked();
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(0u, compile_hints.size());
    }

    v8::Local<v8::Context> context = v8::Context::New(isolate());
    v8::MaybeLocal<v8::Value> result = script->Run(context);
    EXPECT_FALSE(result.IsEmpty());
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(1u, compile_hints.size());
      EXPECT_EQ(14, compile_hints[0]);
    }

    // The previous data is still there if we retrieve compile hints again.
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(1u, compile_hints.size());
      EXPECT_EQ(14, compile_hints[0]);
    }

    // Call the other lazy function and retrieve compile hints again.
    const char* code2 = "lazy2();";
    v8::ScriptCompiler::Source script_source2(NewString(code2), origin);

    Local<Script> script2 =
        v8::ScriptCompiler::Compile(v8_context(), &script_source2)
            .ToLocalChecked();
    v8::MaybeLocal<v8::Value> result2 = script2->Run(context);
    EXPECT_FALSE(result2.IsEmpty());
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(2u, compile_hints.size());
      EXPECT_EQ(14, compile_hints[0]);
      EXPECT_EQ(34, compile_hints[1]);
    }
  }

  // Test that compile hints are not produced unless the relevant compile option
  // is set.
  {
    const char* nohints_code =
        "function nohints_lazy1() {} function nohints_lazy2() {} "
        "nohints_lazy1();";
    v8::ScriptCompiler::Source nohints_script_source(NewString(nohints_code),
                                                     origin);

    Local<Script> script =
        v8::ScriptCompiler::Compile(v8_context(), &nohints_script_source)
            .ToLocalChecked();
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(0u, compile_hints.size());
    }

    v8::Local<v8::Context> context = v8::Context::New(isolate());
    v8::MaybeLocal<v8::Value> result = script->Run(context);
    EXPECT_FALSE(result.IsEmpty());
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(0u, compile_hints.size());
    }
  }
}

TEST_F(ScriptTest, ProduceCompileHintsForArrowFunctions) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);

  const char* code = "lazy1 = () => {}; (() => { lazy2 = () => {} })()";
  v8::ScriptCompiler::Source script_source(NewString(code), origin);

  // Test producing compile hints.
  {
    Local<Script> script =
        v8::ScriptCompiler::Compile(
            v8_context(), &script_source,
            v8::ScriptCompiler::CompileOptions::kProduceCompileHints)
            .ToLocalChecked();
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(0u, compile_hints.size());
    }

    v8::Local<v8::Context> context = v8::Context::New(isolate());
    v8::MaybeLocal<v8::Value> result = script->Run(context);
    EXPECT_FALSE(result.IsEmpty());
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(0u, compile_hints.size());
    }

    // Call one of the lazy functions and retrieve compile hints again.
    const char* code2 = "lazy1();";
    v8::ScriptCompiler::Source script_source2(NewString(code2), origin);

    Local<Script> script2 =
        v8::ScriptCompiler::Compile(v8_context(), &script_source2)
            .ToLocalChecked();
    v8::MaybeLocal<v8::Value> result2 = script2->Run(context);
    EXPECT_FALSE(result2.IsEmpty());
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(1u, compile_hints.size());
      EXPECT_EQ(8, compile_hints[0]);
    }

    // Call the other lazy function and retrieve the compile hints again.
    const char* code3 = "lazy2();";
    v8::ScriptCompiler::Source script_source3(NewString(code3), origin);

    Local<Script> script3 =
        v8::ScriptCompiler::Compile(v8_context(), &script_source3)
            .ToLocalChecked();
    v8::MaybeLocal<v8::Value> result3 = script3->Run(context);
    EXPECT_FALSE(result3.IsEmpty());
    {
      auto compile_hints =
          script->GetCompileHintsCollector()->GetCompileHints(v8_isolate());
      EXPECT_EQ(2u, compile_hints.size());
      EXPECT_EQ(8, compile_hints[0]);
      EXPECT_EQ(35, compile_hints[1]);
    }
  }
}

namespace {
bool CompileHintsCallback(int position, void* data) {
  std::vector<int>* hints = reinterpret_cast<std::vector<int>*>(data);
  return std::find(hints->begin(), hints->end(), position) != hints->end();
}
}  // namespace

TEST_F(CompileHintsTest, ConsumeCompileHints) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);
  v8::Local<v8::Context> context = v8::Context::New(isolate());

  // Produce compile hints which we'll use as data later. The function positions
  // must match the script we're compiling later, but we'll change the script
  // source code to make sure that 1) the compile result is not coming from a
  // cache 2) we're querying the correct functions.
  std::vector<int> compile_hints = ProduceCompileHintsHelper(
      {"function lazy1() {} function lazy2() {}", "lazy1()"});

  {
    const char* code = "function func1() {} function func2() {}";
    v8::ScriptCompiler::Source script_source(
        NewString(code), origin, CompileHintsCallback,
        reinterpret_cast<void*>(&compile_hints));
    Local<Script> script =
        v8::ScriptCompiler::Compile(
            v8_context(), &script_source,
            v8::ScriptCompiler::CompileOptions::kConsumeCompileHints)
            .ToLocalChecked();

    v8::MaybeLocal<v8::Value> result = script->Run(context);
    EXPECT_FALSE(result.IsEmpty());
  }

  EXPECT_TRUE(FunctionIsCompiled("func1"));
  EXPECT_FALSE(FunctionIsCompiled("func2"));
}

TEST_F(CompileHintsTest, ConsumeCompileHintsForArrowFunctions) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);
  v8::Local<v8::Context> context = v8::Context::New(isolate());

  // Produce compile hints which we'll use as data later. The function positions
  // must match the script we're compiling later, but we'll change the script
  // source code to make sure that 1) the compile result is not coming from a
  // cache 2) we're querying the correct functions.
  std::vector<int> compile_hints = ProduceCompileHintsHelper(
      {"lazy1 = (a, b, c) => {}; lazy2 = () => {}", "lazy1()"});

  {
    const char* code = "func1 = (a, b, c) => {}; func2 = () => {}";
    v8::ScriptCompiler::Source script_source(
        NewString(code), origin, CompileHintsCallback,
        reinterpret_cast<void*>(&compile_hints));
    Local<Script> script =
        v8::ScriptCompiler::Compile(
            v8_context(), &script_source,
            v8::ScriptCompiler::CompileOptions::kConsumeCompileHints)
            .ToLocalChecked();

    v8::MaybeLocal<v8::Value> result = script->Run(context);
    EXPECT_FALSE(result.IsEmpty());
  }

  EXPECT_TRUE(FunctionIsCompiled("func1"));
  EXPECT_FALSE(FunctionIsCompiled("func2"));
}

TEST_F(CompileHintsTest, StreamingCompileHints) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);

  // Produce compile hints which we'll use as data later. The function positions
  // must match the script we're compiling later, but we'll change the script
  // source code to make sure that 1) the compile result is not coming from a
  // cache 2) we're querying the correct functions.
  std::vector<int> compile_hints = ProduceCompileHintsHelper(
      {"function lazy1() {} function lazy2() {}", "lazy1()"});

  // Consume compile hints.
  const char* chunks[] = {
      "function func1() {} function fu"
      "nc2() {}",
      nullptr};

  v8::ScriptCompiler::StreamedSource source(
      std::make_unique<i::TestSourceStream>(chunks),
      v8::ScriptCompiler::StreamedSource::ONE_BYTE);
  std::unique_ptr<v8::ScriptCompiler::ScriptStreamingTask> task(
      v8::ScriptCompiler::StartStreaming(isolate(), &source,
                                         v8::ScriptType::kClassic,
                                         ScriptCompiler::kConsumeCompileHints,
                                         CompileHintsCallback, &compile_hints));

  // TestSourceStream::GetMoreData won't block, so it's OK to just join the
  // background task.
  StreamerThread::StartThreadForTaskAndJoin(task.get());
  task.reset();

  std::unique_ptr<char[]> full_source(
      i::TestSourceStream::FullSourceString(chunks));

  v8::Local<Script> script =
      v8::ScriptCompiler::Compile(v8_context(), &source,
                                  NewString(full_source.get()), origin)
          .ToLocalChecked();

  v8::MaybeLocal<v8::Value> result = script->Run(v8_context());
  EXPECT_FALSE(result.IsEmpty());

  EXPECT_TRUE(FunctionIsCompiled("func1"));
  EXPECT_FALSE(FunctionIsCompiled("func2"));
}

TEST_F(CompileHintsTest, CompileHintsMagicCommentBasic) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);
  v8::Local<v8::Context> context = v8::Context::New(isolate());

  // Run the top level code.
  const char* code =
      "//# eagerCompilation=all\n"
      "function f1() {}\n"
      "let f2 = function() { }";
  v8::ScriptCompiler::Source script_source(NewString(code), origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(
          v8_context(), &script_source,
          v8::ScriptCompiler::CompileOptions(
              v8::ScriptCompiler::CompileOptions::kProduceCompileHints |
              v8::ScriptCompiler::CompileOptions::
                  kFollowCompileHintsMagicComment))
          .ToLocalChecked();

  v8::MaybeLocal<v8::Value> result = script->Run(context);
  EXPECT_FALSE(result.IsEmpty());

  EXPECT_TRUE(FunctionIsCompiled("f1"));
  EXPECT_TRUE(FunctionIsCompiled("f2"));
}

TEST_F(CompileHintsTest, CompileHintsMagicCommentDifferentFunctionTypes) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);
  v8::Local<v8::Context> context = v8::Context::New(isolate());

  // Run the top level code.
  const char* code =
      "//# eagerCompilation=all\n"
      "f1 = () => {};\n"
      "class C { f2() { } set f3(x) { } }\n"
      "o = { get f4() { } };\n";
  v8::ScriptCompiler::Source script_source(NewString(code), origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(
          v8_context(), &script_source,
          v8::ScriptCompiler::CompileOptions(
              v8::ScriptCompiler::CompileOptions::kProduceCompileHints |
              v8::ScriptCompiler::CompileOptions::
                  kFollowCompileHintsMagicComment))
          .ToLocalChecked();

  v8::MaybeLocal<v8::Value> result = script->Run(context);
  EXPECT_FALSE(result.IsEmpty());
  EXPECT_TRUE(FunctionIsCompiled("f1"));
  EXPECT_TRUE(FunctionIsCompiled("C.prototype.f2"));
  EXPECT_TRUE(FunctionIsCompiled(
      "Object.getOwnPropertyDescriptor(C.prototype, 'f3').set"));
  EXPECT_TRUE(
      FunctionIsCompiled("Object.getOwnPropertyDescriptor(o, 'f4').get"));
}

TEST_F(CompileHintsTest, CompileHintsMagicCommentBetweenFunctions) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);
  v8::Local<v8::Context> context = v8::Context::New(isolate());

  // Run the top level code.
  const char* code =
      "function f1() {}\n"
      "//# eagerCompilation=all\n"
      "function f2() {}";
  v8::ScriptCompiler::Source script_source(NewString(code), origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(
          v8_context(), &script_source,
          v8::ScriptCompiler::CompileOptions(
              v8::ScriptCompiler::CompileOptions::kProduceCompileHints |
              v8::ScriptCompiler::CompileOptions::
                  kFollowCompileHintsMagicComment))
          .ToLocalChecked();

  v8::MaybeLocal<v8::Value> result = script->Run(context);
  EXPECT_FALSE(result.IsEmpty());

  EXPECT_FALSE(FunctionIsCompiled("f1"));
  EXPECT_TRUE(FunctionIsCompiled("f2"));
}

TEST_F(CompileHintsTest, CompileHintsMagicCommentInvalid) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);
  v8::Local<v8::Context> context = v8::Context::New(isolate());

  // Run the top level code.
  const char* code =
      "//# eagerCompilation=notAll\n"  // Not a valid compile hint.
      "function f1() {}";
  v8::ScriptCompiler::Source script_source(NewString(code), origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(
          v8_context(), &script_source,
          v8::ScriptCompiler::CompileOptions(
              v8::ScriptCompiler::CompileOptions::kProduceCompileHints |
              v8::ScriptCompiler::CompileOptions::
                  kFollowCompileHintsMagicComment))
          .ToLocalChecked();

  v8::MaybeLocal<v8::Value> result = script->Run(context);
  EXPECT_FALSE(result.IsEmpty());

  // Retrieve the function object for f1.
  EXPECT_FALSE(FunctionIsCompiled("f1"));
}

// Regression test for https://issues.chromium.org/issues/351876778 .
TEST_F(ScriptTest, CompileHintsMagicCommentInvalid2) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);
  v8::Local<v8::Context> context = v8::Context::New(isolate());

  const char* code =
      "//# eagerCompilation=\xCF\x80\n"  // Two byte character
      "function f1() {}";
  v8::ScriptCompiler::Source script_source(NewString(code), origin);

  Local<Script> script =
      v8::ScriptCompiler::Compile(
          v8_context(), &script_source,
          v8::ScriptCompiler::CompileOptions(
              v8::ScriptCompiler::CompileOptions::kProduceCompileHints |
              v8::ScriptCompiler::CompileOptions::
                  kFollowCompileHintsMagicComment))
          .ToLocalChecked();

  v8::MaybeLocal<v8::Value> result = script->Run(context);
  EXPECT_FALSE(result.IsEmpty());
}

TEST_F(CompileHintsTest, CompileHintsMagicCommentNotEnabledByCompileOptions) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);
  v8::Local<v8::Context> context = v8::Context::New(isolate());

  // Run the top level code.
  const char* code =
      "//# eagerCompilation=all\n"
      "function f1() {}";
  v8::ScriptCompiler::Source script_source(NewString(code), origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(
          v8_context(), &script_source,
          // Not enabling the magic comment with compile options!
          v8::ScriptCompiler::CompileOptions::kProduceCompileHints)
          .ToLocalChecked();

  v8::MaybeLocal<v8::Value> result = script->Run(context);
  EXPECT_FALSE(result.IsEmpty());

  EXPECT_FALSE(FunctionIsCompiled("f1"));
}

TEST_F(CompileHintsTest, StreamingCompileHintsMagic) {
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(NewString(url), 13, 0);

  // Consume compile hints.
  const char* chunks[] = {
      "//# eagerCompilati"
      "on=all\n"
      "function func1() {} function fu"
      "nc2() {}",
      nullptr};

  v8::ScriptCompiler::StreamedSource source(
      std::make_unique<i::TestSourceStream>(chunks),
      v8::ScriptCompiler::StreamedSource::ONE_BYTE);
  std::unique_ptr<v8::ScriptCompiler::ScriptStreamingTask> task(
      v8::ScriptCompiler::StartStreaming(
          isolate(), &source, v8::ScriptType::kClassic,
          v8::ScriptCompiler::CompileOptions(
              v8::ScriptCompiler::kProduceCompileHints |
              v8::ScriptCompiler::kFollowCompileHintsMagicComment)));

  // TestSourceStream::GetMoreData won't block, so it's OK to just join the
  // background task.
  StreamerThread::StartThreadForTaskAndJoin(task.get());
  task.reset();

  std::unique_ptr<char[]> full_source(
      i::TestSourceStream::FullSourceString(chunks));

  v8::Local<Script> script =
      v8::ScriptCompiler::Compile(v8_context(), &source,
                                  NewString(full_source.get()), origin)
          .ToLocalChecked();

  v8::MaybeLocal<v8::Value> result = script->Run(v8_context());
  EXPECT_FALSE(result.IsEmpty());

  EXPECT_TRUE(FunctionIsCompiled("func1"));
  EXPECT_TRUE(FunctionIsCompiled("func2"));
}

}  // namespace
}  // namespace v8
```