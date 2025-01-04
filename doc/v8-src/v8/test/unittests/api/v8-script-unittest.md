Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The primary request is to understand the functionality of the C++ code in `v8-script-unittest.cc` and relate it to JavaScript, providing examples where possible. This means we need to identify the V8 API being tested and how those APIs are used in a JavaScript context.

2. **Initial Scan for Keywords and Structure:**  A quick skim reveals important keywords: `#include "include/v8-script.h"`, `namespace v8`, `TEST_F`, `Script`, `Module`, `ScriptCompiler`, `Compile`, `Run`, `GetCompileHints`, `GetStalledTopLevelAwaitMessages`, etc. The `TEST_F` structure immediately tells us this is a unit test file. The included header `v8-script.h` is the core of what's being tested.

3. **Identify Major Test Groups:** The `TEST_F` macros with different first arguments (`ScriptTest`, `CompileHintsTest`) indicate distinct areas of functionality being tested. This is a good way to structure the summary.

4. **Analyze `ScriptTest`:**
    * **`UnboundScriptPosition`:**  This test checks that `GetUnboundScript()`, `GetScriptName()`, `GetLineNumber()`, and `GetColumnNumber()` on a compiled script return the expected values based on the `ScriptOrigin`. This relates to how V8 tracks the source location of scripts.
    * **`GetSourceMappingUrlFromComment` and related tests:** These focus on how V8 handles source maps, both through `//# sourceMappingURL=` comments and via the `ScriptOrigin`. The tests cover overriding the comment with the API and ignoring an empty API source map. This directly impacts JavaScript debugging and error reporting.
    * **`GetStalledTopLevelAwaitMessage` and related tests:** This suite of tests specifically deals with asynchronous module loading using `import` and top-level `await`. The tests check if V8 can correctly identify which modules are blocking the loading process due to unresolved promises. This is a crucial feature for modern JavaScript module systems.
    * **`ProduceCompileHints` and `ProduceCompileHintsForArrowFunctions`:** These tests verify the functionality of generating "compile hints."  These hints are used internally by V8 to optimize function compilation based on past execution. The tests check for both regular functions and arrow functions. While not directly exposed to JavaScript, understanding its purpose (optimization) is important.

5. **Analyze `CompileHintsTest`:**
    * **`ConsumeCompileHints` and `ConsumeCompileHintsForArrowFunctions`:** These tests demonstrate *consuming* the compile hints generated earlier. The `CompileHintsCallback` is a key part, allowing external code to influence compilation. Again, this is an internal optimization mechanism.
    * **`StreamingCompileHints`:** This test explores the interaction of compile hints with *streaming compilation*, where the script is processed in chunks.
    * **`CompileHintsMagicCommentBasic` and related tests:** This focuses on the `//# eagerCompilation=all` magic comment. The tests verify that this comment forces the eager compilation of functions defined after the comment. This is a more direct way for developers to influence V8's compilation behavior.

6. **Relate to JavaScript:** For each tested feature, think about how it manifests or is used in JavaScript.
    * **Source Maps:**  Essential for debugging minified or transpiled JavaScript. Browsers and developer tools rely on these.
    * **Top-Level Await:** A relatively recent JavaScript feature that allows `await` outside of async functions in modules. The tests directly relate to the behavior and error reporting of this feature.
    * **Compile Hints:** While not directly scriptable, their effect is visible in performance. The magic comment provides a direct way to influence this.

7. **Construct JavaScript Examples:** For the features directly related to JavaScript behavior (like source maps and top-level await), create simple, illustrative code snippets. For internal optimization features (like general compile hints), explain the *purpose* even if a direct JavaScript equivalent doesn't exist. The magic comment is an exception where there's a clear JavaScript syntax that triggers the tested behavior.

8. **Refine and Organize:** Group the findings logically (based on the test class structure is a good start). Use clear language and avoid overly technical jargon when explaining the JavaScript connections. Ensure the JavaScript examples are concise and demonstrate the relevant behavior. Add a concluding summary to tie everything together.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Compile hints seem complex and internal. Should I skip them in the JavaScript explanation?"
* **Correction:**  "No, even though they aren't directly manipulated in JS, their *purpose* (optimization) is relevant. The magic comment *is* directly controllable by JS."
* **Initial thought:** "Should I explain all the C++ details of the tests?"
* **Correction:** "The focus is on the *functionality* and its relation to JavaScript. Detailed C++ implementation isn't necessary unless it directly clarifies the behavior."
* **Initial thought:** "Just list the test names?"
* **Correction:** "No, summarize the *purpose* of each test or group of tests."

By following these steps, iterating, and refining, we can arrive at a comprehensive and understandable explanation like the example provided in the prompt.
这个C++源代码文件 `v8-script-unittest.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试与 JavaScript **脚本 (Script)** 相关的 API 功能。  它使用 Google Test 框架来编写单元测试。

**核心功能归纳：**

1. **测试脚本的编译和运行：**  测试 `v8::ScriptCompiler::Compile` 和 `v8::Script::Run` 等方法，验证 V8 能否正确地编译和执行 JavaScript 代码。

2. **测试脚本元数据：**  测试与脚本相关的元数据，例如：
    * **脚本来源 (ScriptOrigin)：**  测试如何设置和获取脚本的 URL、行号、列号等信息。
    * **未绑定脚本 (UnboundScript)：** 测试获取 `UnboundScript` 对象及其属性，如脚本名称、行号、列号等。
    * **Source Mapping URL：** 测试从注释中或通过 API 设置的 Source Mapping URL 的获取。这对于调试工具将编译后的代码映射回原始源代码非常重要。

3. **测试异步模块加载 (Top-Level Await)：**  测试使用 `import` 导入模块并且模块中包含顶级 `await` 的情况。主要测试 `GetStalledTopLevelAwaitMessages` 方法，用于获取因顶级 `await` 而处于等待状态的模块及其相关信息。

4. **测试编译提示 (Compile Hints)：**
    * **生成编译提示：** 测试在编译时生成编译提示的功能。编译提示可以用于指导后续的编译优化。
    * **消费编译提示：** 测试在编译时使用之前生成的编译提示。
    * **流式编译提示：** 测试在流式编译场景下使用编译提示。
    * **编译提示魔法注释：** 测试使用 `//# eagerCompilation=all` 等魔法注释来指示 V8 引擎积极编译某些函数。

**与 JavaScript 的关系及示例：**

这个 C++ 文件测试的是 V8 引擎内部实现，但它直接关系到开发者在编写和调试 JavaScript 代码时的体验。

**1. 脚本的编译和运行：**

当你运行一段 JavaScript 代码时，V8 引擎首先会将其编译成可执行的机器码。`v8::ScriptCompiler::Compile` 和 `v8::Script::Run` 就模拟了这个过程。

**JavaScript 示例：**

```javascript
// 这是一个简单的 JavaScript 脚本
console.log("Hello, world!");
```

**2. 脚本元数据和 Source Maps：**

当你设置断点或者查看错误堆栈信息时，浏览器开发者工具能够显示原始的 JavaScript 代码，而不是编译后的代码。这得益于 Source Maps。`v8-script-unittest.cc` 中测试了 V8 如何处理 Source Maps。

**JavaScript 示例：**

```javascript
// source.js
function myFunction() {
  console.log("This is myFunction");
}
myFunction();

//# sourceMappingURL=source.js.map
```

对应的 `source.js.map` 文件会包含将编译后的代码映射回 `source.js` 的信息。

**3. 异步模块加载 (Top-Level Await)：**

ES 模块允许在模块的顶层使用 `await` 关键字。如果一个模块的加载依赖于一个 Promise 的解决，那么这个模块的加载会暂停，直到 Promise 变为 resolved 状态。`GetStalledTopLevelAwaitMessages` 测试了 V8 如何报告这种等待状态。

**JavaScript 示例：**

```javascript
// stall.mjs
const promise = new Promise(resolve => {
  // 此 Promise 永远不会 resolve
});
await promise;
console.log("This will never be printed immediately");

// root.mjs
import './stall.mjs';
console.log("stall.mjs might be stalling");
```

在 `root.mjs` 中导入 `stall.mjs` 后，由于 `stall.mjs` 中的顶级 `await` 永远不会完成，`root.mjs` 的执行也会被阻塞。`GetStalledTopLevelAwaitMessages` 能够检测到 `stall.mjs` 处于等待状态。

**4. 编译提示 (Compile Hints) 和魔法注释：**

编译提示是 V8 内部优化机制，开发者通常不需要直接操作。然而，魔法注释提供了一种间接的方式来影响 V8 的编译行为。`//# eagerCompilation=all` 可以指示 V8 积极地编译后续定义的函数，这可能在某些性能关键场景下有用。

**JavaScript 示例：**

```javascript
//# eagerCompilation=all
function f1() {
  console.log("f1 is eagerly compiled");
}

function f2() {
  console.log("f2 might be lazily compiled");
}

f1();
```

在这个例子中，`f1` 函数很可能会被 V8 引擎更早地编译，而 `f2` 函数可能仍然采用延迟编译的策略。

**总结：**

`v8-script-unittest.cc` 文件虽然是 V8 引擎的内部测试代码，但它测试的功能与 JavaScript 开发者日常使用的语言特性息息相关，包括脚本的加载、执行、调试以及性能优化等方面。 理解这些测试背后的概念有助于更深入地理解 JavaScript 引擎的工作原理。

Prompt: 
```
这是目录为v8/test/unittests/api/v8-script-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```