Response:
The user wants a summary of the provided C++ code snippet from `v8/test/cctest/test-api.cc`.

Here's a breakdown of the thought process to achieve that:

1. **Identify the file type:** The filename `test-api.cc` clearly indicates this is a test file for the V8 API. The `.cc` extension confirms it's C++ code. The prompt explicitly asks what happens if it ends in `.tq`, which is related to Torque, a V8-specific language.

2. **Scan for test names:** The code is structured around `TEST(...)` macros. These mark individual test cases. Listing these provides a high-level overview of what's being tested.

3. **Analyze individual tests:**  For each `TEST(...)` case, read the code within it and infer its purpose. Look for V8 API calls and assertions (`CHECK(...)`).

    * **`ScriptSourceURLAndSourceMappingURL`**: This test manipulates script source code by adding `//# sourceURL=` and `//# sourceMappingURL=` comments. The `SourceURLHelper` function is used, suggesting it verifies how V8 handles these directives for debugging. It also tests edge cases like multiple directives, whitespace, and disallowed characters. It also checks if these directives are ignored in `eval()` calls.

    * **`GetOwnPropertyDescriptor`**: This test uses `Object.defineProperty` in JavaScript to define properties with specific attributes (value, setter, getter, symbol). It then uses the V8 C++ API `GetOwnPropertyDescriptor` to retrieve these descriptors and verify their contents.

    * **`Regress411877`, `GetHiddenPropertyTableAfterAccessCheck`, `Regress411793`**: These tests appear to be regression tests, likely addressing specific bugs (indicated by the issue numbers in the names). They involve `ObjectTemplate`, `AccessCheckCallback`, `SetPrivate`, and `defineProperty`.

    * **Streaming Tests (starting with `RunStreamingTest`)**: This large section focuses on testing V8's *streaming compilation* feature. It involves splitting JavaScript code into chunks and feeding them to the compiler incrementally. It tests various scenarios: simple scripts, scripts with errors, UTF-8 encoding, handling of split UTF-8 characters, debugging during streaming, and interaction with the isolate script cache.

    * **`CodeCache`**: This test checks V8's code caching mechanism. It compiles a script, creates a code cache, disposes of the isolate, creates a new isolate, and then compiles the same script using the cached data.

    * **Synthetic Module Tests (starting with `UnexpectedSyntheticModuleEvaluationStepsCallback`)**: This section tests the functionality of *synthetic modules*. These are modules created directly through the V8 API rather than loading from a file. It tests callbacks for evaluation and error handling.

4. **Address specific instructions in the prompt:**

    * **`.tq` file:** Explain that if the file ended in `.tq`, it would be a Torque file.
    * **JavaScript examples:**  For tests related to JavaScript features (like source URLs and property descriptors), provide corresponding JavaScript code snippets.
    * **Code logic/input/output:** For `ScriptSourceURLAndSourceMappingURL`, give examples of the input JavaScript with source URL/mapping URL comments and the expected output (the extracted URLs).
    * **Common programming errors:**  Point out that incorrect whitespace or disallowed characters in source URL/mapping URL comments are common errors, as demonstrated in the tests.

5. **Synthesize a summary:** Combine the findings from analyzing individual tests into a concise overall description of the file's purpose. Emphasize that it's a collection of tests for various V8 API features.

6. **Handle the "part X of Y" information:**  Acknowledge that this is part 27 of 36 and infer that the file covers a specific subset of V8 API testing.

7. **Review and refine:**  Read through the generated summary and ensure it's accurate, clear, and addresses all aspects of the prompt. For instance, initially, I might not have emphasized the streaming aspect enough. A review would catch this and prompt me to adjust the summary. Similarly, ensuring the JavaScript examples are clear and directly related to the C++ tests is important.
好的，让我们来分析一下 `v8/test/cctest/test-api.cc` 这个代码片段的功能。

**功能归纳：**

这段代码主要测试了 V8 API 中与以下功能相关的部分：

1. **设置和获取脚本的 Source URL 和 Source Mapping URL:**  测试了如何通过特殊的注释 `//# sourceURL=` 和 `//# sourceMappingURL=` 在脚本代码中指定源文件的 URL 和 Source Map 文件的 URL，以及 V8 如何解析和存储这些信息。
2. **获取对象的属性描述符 (Property Descriptor):** 测试了 `v8::Object::GetOwnPropertyDescriptor` API 的功能，它可以获取对象自身属性的描述信息，包括 `value`、`get`、`set` 等。
3. **访问检查回调 (Access Check Callback):**  测试了在对象模板上设置访问检查回调函数后，V8 如何处理属性的访问，这通常用于控制对特定对象的访问权限。
4. **隐藏属性表 (Hidden Property Table):** 测试了在设置访问检查回调后，如何使用 `SetPrivate` 设置和访问对象的私有属性。
5. **流式编译 (Streaming Compilation):**  这是代码片段的核心部分，测试了 V8 的流式编译功能，即可以一边接收脚本代码的数据流，一边进行编译，而无需等待整个脚本加载完成。 这部分测试了：
    * 基本的流式编译流程。
    * 流式编译对常量数组的处理。
    * 流式编译对 `eval` 和作用域的影响。
    * 较大的脚本的流式编译。
    * 流式编译处理语法错误的情况。
    * 流式编译处理 UTF-8 编码的脚本，包括字符被分割在不同数据块的情况。
    * 在启用调试器的情况下进行流式编译。
    * 流式编译处理无效 UTF-8 编码的情况。
    * 流式编译与 Harmony (ES6+) 作用域的交互。
    * 流式编译与 Isolate 级别的脚本缓存的交互。
6. **代码缓存 (Code Cache):** 测试了 V8 的代码缓存功能，可以将编译后的代码缓存起来，以便下次执行相同的脚本时可以更快地加载和执行。
7. **合成模块 (Synthetic Module):**  测试了如何通过 V8 API 创建和评估合成模块，这些模块不是从文件中加载的，而是通过代码动态创建的。

**关于代码片段的特定测试用例分析：**

* **`TEST(ScriptSourceURLAndSourceMappingURL)`:**
    * 功能：测试通过 `//# sourceURL=` 和 `//# sourceMappingURL=` 注释设置脚本的源 URL 和 Source Map URL。
    * JavaScript 示例：
      ```javascript
      function foo() {}
      //# sourceURL=my-script.js
      //# sourceMappingURL=my-script.js.map
      ```
    * 代码逻辑推理（假设输入与输出）：
        * 输入：包含 `//# sourceURL=test.js` 的字符串。
        * 输出：`CheckMagicComments` 函数会验证获取到的 Source URL 是否为 "test.js"。
    * 常见编程错误：
        * 错误地添加空格，例如 `//#  sourceURL=...` 或 `//# sourceURL = ...`，会导致 V8 无法识别。
        * 在 URL 中使用不允许的字符。

* **`TEST(GetOwnPropertyDescriptor)`:**
    * 功能：测试 `GetOwnPropertyDescriptor` API 获取对象属性描述符的功能。
    * JavaScript 示例：
      ```javascript
      var x = { value: 13 };
      Object.defineProperty(x, 'p0', { value: 12 });
      Object.defineProperty(x, 'p1', {
        set: function(value) { this.value = value; },
        get: function() { return this.value; }
      });
      ```
    * 代码逻辑推理：
        * 输入：一个包含属性 `p0` (值为 12) 和 `p1` (带有 getter 和 setter) 的 JavaScript 对象。
        * 输出：`GetOwnPropertyDescriptor` 应该返回描述这些属性的对象，可以通过访问该对象的 `value` 属性或 `get` 和 `set` 属性来验证。

* **`TEST(Regress411877)`, `TEST(GetHiddenPropertyTableAfterAccessCheck)`, `TEST(Regress411793)`:** 这些通常是回归测试，用于确保修复的 bug 不会再次出现。它们涉及到对象模板、访问检查回调和隐藏属性等 API 的使用。

* **流式编译相关的 `TEST(...)` 用例 (例如 `TEST(StreamingSimpleScript)`, `TEST(StreamingBiggerScript)`, `TEST(StreamingUtf8Script)` 等):**
    * 功能：测试 V8 的流式编译功能在各种场景下的正确性。
    * 代码逻辑推理： 这些测试会将 JavaScript 代码分割成多个 `chunks`，然后模拟数据流的方式提供给 V8 进行编译。`RunStreamingTest` 函数负责启动流式编译任务并验证结果。
    * 常见编程错误：虽然测试本身不直接涉及用户编程错误，但流式编译的意义在于可以更早地开始编译和执行，减少加载时间，这对于大型脚本或网络加载的脚本至关重要。

* **`TEST(CodeCache)`:**
    * 功能：测试代码缓存的创建和使用。
    * 代码逻辑推理：该测试在一个 Isolate 中编译脚本并创建代码缓存，然后在另一个 Isolate 中使用该缓存来编译相同的脚本，验证是否能成功加载缓存并执行。

* **合成模块相关的 `TEST(...)` 用例：**
    * 功能：测试创建和评估合成模块的功能，包括设置评估步骤的回调。

**关于 `.tq` 结尾：**

如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种用于在 V8 中实现内置函数和运行时调用的领域特定语言。 Torque 代码会被编译成 C++ 代码，然后与 V8 的其余部分一起编译。这个文件中就不会包含像现在这样的 C++ 测试用例，而是会包含用 Torque 编写的逻辑。

**总结第 27 部分的功能：**

作为 36 个部分中的第 27 部分，这个代码片段专注于测试 V8 API 中与 **脚本元信息（Source URL 和 Source Map URL）、对象属性描述符、访问控制机制、流式编译以及代码缓存和合成模块** 相关的特定功能。  它通过一系列细致的测试用例，覆盖了这些 API 的基本用法、边界情况以及错误处理，确保 V8 在这些方面的行为符合预期。 尤其是流式编译部分占据了很大的篇幅，表明这是 V8 中一个重要的优化特性，需要进行全面的测试。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第27部分，共36部分，请归纳一下它的功能

"""
   Local<v8::Module> module =
        v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
    CheckMagicComments(isolate, module->GetUnboundModuleScript(),
                       expected_source_url, expected_source_mapping_url);
  }
}

TEST(ScriptSourceURLAndSourceMappingURL) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceURL=bar1.js\n",
                  "bar1.js", nullptr);
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceMappingURL=bar2.js\n",
                  nullptr, "bar2.js");

  // Both sourceURL and sourceMappingURL.
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceURL=bar3.js\n"
                  "//# sourceMappingURL=bar4.js\n",
                  "bar3.js", "bar4.js");

  // Two source URLs; the first one is ignored.
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceURL=ignoreme.js\n"
                  "//# sourceURL=bar5.js\n",
                  "bar5.js", nullptr);
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceMappingURL=ignoreme.js\n"
                  "//# sourceMappingURL=bar6.js\n",
                  nullptr, "bar6.js");

  // SourceURL or sourceMappingURL in the middle of the script.
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceURL=bar7.js\n"
                  "function baz() {}\n",
                  "bar7.js", nullptr);
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceMappingURL=bar8.js\n"
                  "function baz() {}\n",
                  nullptr, "bar8.js");

  // Too much whitespace.
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//#  sourceURL=bar9.js\n"
                  "//#  sourceMappingURL=bar10.js\n",
                  nullptr, nullptr);
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceURL =bar11.js\n"
                  "//# sourceMappingURL =bar12.js\n",
                  nullptr, nullptr);

  // Disallowed characters in value.
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceURL=bar13 .js   \n"
                  "//# sourceMappingURL=bar14 .js \n",
                  nullptr, nullptr);
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceURL=bar15\t.js   \n"
                  "//# sourceMappingURL=bar16\t.js \n",
                  nullptr, nullptr);

  // Not too much whitespace.
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "//# sourceURL=  bar21.js   \n"
                  "//# sourceMappingURL=  bar22.js \n",
                  "bar21.js", "bar22.js");

  // Comments in eval'd script should be ignored.
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "eval(\"\\\n//# sourceURL=bar23.js\");\n"
                  "eval(\"\\\n//# sourceMappingURL=bar24.js\");\n",
                  nullptr, nullptr);
  SourceURLHelper(isolate,
                  "function foo() {}\n"
                  "eval('\\\n//# sourceURL=bar23.js');\n"
                  "eval('\\\n//# sourceMappingURL=bar24.js');\n",
                  nullptr, nullptr);

  // Inline data: URLs are allowed.
  SourceURLHelper(
      isolate,
      "function foo() {}\n"
      "//# sourceMappingURL=  data:application/json,{\"version\":3}  \n",
      nullptr, "data:application/json,{\"version\":3}");
}


TEST(GetOwnPropertyDescriptor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  CompileRun(
      "var x = { value : 13};"
      "Object.defineProperty(x, 'p0', {value : 12});"
      "Object.defineProperty(x, Symbol.toStringTag, {value: 'foo'});"
      "Object.defineProperty(x, 'p1', {"
      "  set : function(value) { this.value = value; },"
      "  get : function() { return this.value; },"
      "});");
  Local<Object> x = Local<Object>::Cast(
      env->Global()->Get(env.local(), v8_str("x")).ToLocalChecked());
  Local<Value> desc =
      x->GetOwnPropertyDescriptor(env.local(), v8_str("no_prop"))
          .ToLocalChecked();
  CHECK(desc->IsUndefined());
  desc =
      x->GetOwnPropertyDescriptor(env.local(), v8_str("p0")).ToLocalChecked();
  CHECK(v8_num(12)
            ->Equals(env.local(), Local<Object>::Cast(desc)
                                      ->Get(env.local(), v8_str("value"))
                                      .ToLocalChecked())
            .FromJust());
  desc =
      x->GetOwnPropertyDescriptor(env.local(), v8_str("p1")).ToLocalChecked();
  Local<Function> set =
      Local<Function>::Cast(Local<Object>::Cast(desc)
                                ->Get(env.local(), v8_str("set"))
                                .ToLocalChecked());
  Local<Function> get =
      Local<Function>::Cast(Local<Object>::Cast(desc)
                                ->Get(env.local(), v8_str("get"))
                                .ToLocalChecked());
  CHECK(v8_num(13)
            ->Equals(env.local(),
                     get->Call(env.local(), x, 0, nullptr).ToLocalChecked())
            .FromJust());
  Local<Value> args[] = {v8_num(14)};
  set->Call(env.local(), x, 1, args).ToLocalChecked();
  CHECK(v8_num(14)
            ->Equals(env.local(),
                     get->Call(env.local(), x, 0, nullptr).ToLocalChecked())
            .FromJust());
  desc =
      x->GetOwnPropertyDescriptor(env.local(), Symbol::GetToStringTag(isolate))
          .ToLocalChecked();
  CHECK(v8_str("foo")
            ->Equals(env.local(), Local<Object>::Cast(desc)
                                      ->Get(env.local(), v8_str("value"))
                                      .ToLocalChecked())
            .FromJust());
}


TEST(Regress411877) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetAccessCheckCallback(AccessCounter);

  v8::Local<Context> context = Context::New(isolate);
  v8::Context::Scope context_scope(context);

  CHECK(context->Global()
            ->Set(context, v8_str("o"),
                  object_template->NewInstance(context).ToLocalChecked())
            .FromJust());
  CompileRun("Object.getOwnPropertyNames(o)");
}


TEST(GetHiddenPropertyTableAfterAccessCheck) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetAccessCheckCallback(AccessCounter);

  v8::Local<Context> context = Context::New(isolate);
  v8::Context::Scope context_scope(context);

  v8::Local<v8::Object> obj =
      object_template->NewInstance(context).ToLocalChecked();
  obj->Set(context, v8_str("key"), v8_str("value")).FromJust();
  obj->Delete(context, v8_str("key")).FromJust();

  obj->SetPrivate(context, v8::Private::New(isolate, v8_str("hidden key 2")),
                  v8_str("hidden value 2"))
      .FromJust();
}


TEST(Regress411793) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetAccessCheckCallback(AccessCounter);

  v8::Local<Context> context = Context::New(isolate);
  v8::Context::Scope context_scope(context);

  CHECK(context->Global()
            ->Set(context, v8_str("o"),
                  object_template->NewInstance(context).ToLocalChecked())
            .FromJust());
  CompileRun(
      "Object.defineProperty(o, 'key', "
      "    { get: function() {}, set: function() {} });");
}

v8::MaybeLocal<Module> UnexpectedModuleResolveCallback(
    Local<Context> context, Local<String> specifier,
    Local<FixedArray> import_attributes, Local<Module> referrer) {
  CHECK_WITH_MSG(false, "Unexpected call to resolve callback");
}

// Helper function for running streaming tests.
void RunStreamingTest(const char** chunks, v8::ScriptType type,
                      v8::ScriptCompiler::StreamedSource::Encoding encoding =
                          v8::ScriptCompiler::StreamedSource::ONE_BYTE,
                      bool expected_success = true,
                      const char* expected_source_url = nullptr,
                      const char* expected_source_mapping_url = nullptr) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);

  v8::ScriptCompiler::StreamedSource source(
      std::make_unique<i::TestSourceStream>(chunks), encoding);
  v8::ScriptCompiler::ScriptStreamingTask* task =
      v8::ScriptCompiler::StartStreaming(isolate, &source, type);

  // TestSourceStream::GetMoreData won't block, so it's OK to just join the
  // background task.
  StreamerThread::StartThreadForTaskAndJoin(task);
  delete task;

  // Possible errors are only produced while compiling.
  CHECK(!try_catch.HasCaught());

  v8::ScriptOrigin origin(v8_str("http://foo.com"), 0, 0, false, -1,
                          v8::Local<v8::Value>(), false, false,
                          type == v8::ScriptType::kModule);

  char* full_source = i::TestSourceStream::FullSourceString(chunks);
  if (type == v8::ScriptType::kClassic) {
    v8::MaybeLocal<Script> script = v8::ScriptCompiler::Compile(
        env.local(), &source, v8_str(full_source), origin);
    if (expected_success) {
      CHECK(!script.IsEmpty());
      v8::Local<Value> result(
          script.ToLocalChecked()->Run(env.local()).ToLocalChecked());
      // All scripts are supposed to return the fixed value 13 when ran.
      CHECK_EQ(13, result->Int32Value(env.local()).FromJust());
      CheckMagicComments(isolate, script.ToLocalChecked()->GetUnboundScript(),
                         expected_source_url, expected_source_mapping_url);
    } else {
      CHECK(script.IsEmpty());
    }
  } else {
    v8::MaybeLocal<Module> maybe_module = v8::ScriptCompiler::CompileModule(
        env.local(), &source, v8_str(full_source), origin);
    if (expected_success) {
      v8::Local<v8::Module> module = maybe_module.ToLocalChecked();
      CHECK(
          module
              ->InstantiateModule(env.local(), UnexpectedModuleResolveCallback)
              .FromJust());
      CHECK_EQ(Module::kInstantiated, module->GetStatus());
      v8::Local<Value> result = module->Evaluate(env.local()).ToLocalChecked();
      CHECK_EQ(Module::kEvaluated, module->GetStatus());
      v8::Local<v8::Promise> promise = result.As<v8::Promise>();
      CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
      CHECK(promise->Result()->IsUndefined());
      // Fulfilled top-level await promises always resolve to undefined. Check
      // the test result via a global variable.
      CHECK_EQ(13, env->Global()
                       ->Get(env.local(), v8_str("Result"))
                       .ToLocalChecked()
                       ->Int32Value(env.local())
                       .FromJust());
    } else {
      CHECK(maybe_module.IsEmpty());
    }
  }
  if (!expected_success) CHECK(try_catch.HasCaught());
  delete[] full_source;
}

void RunStreamingTest(const char** chunks,
                      v8::ScriptCompiler::StreamedSource::Encoding encoding =
                          v8::ScriptCompiler::StreamedSource::ONE_BYTE,
                      bool expected_success = true,
                      const char* expected_source_url = nullptr,
                      const char* expected_source_mapping_url = nullptr) {
  RunStreamingTest(chunks, v8::ScriptType::kClassic, encoding, expected_success,
                   expected_source_url, expected_source_mapping_url);
  RunStreamingTest(chunks, v8::ScriptType::kModule, encoding, expected_success,
                   expected_source_url, expected_source_mapping_url);
}

TEST(StreamingSimpleScript) {
  // This script is unrealistically small, since no one chunk is enough to fill
  // the backing buffer of Scanner, let alone overflow it.
  const char* chunks[] = {"function foo() { ret",
                          "urn 13; } globalThis.Result = f", "oo(); ", nullptr};
  RunStreamingTest(chunks);
}

TEST(StreamingScriptConstantArray) {
  // When run with Ignition, tests that the streaming parser canonicalizes
  // handles so that they are only added to the constant pool array once.
  const char* chunks[] = {"var a = {};",
                          "var b = {};",
                          "var c = 'testing';",
                          "var d = 'testing';",
                          "globalThis.Result = 13;",
                          nullptr};
  RunStreamingTest(chunks);
}

TEST(StreamingScriptEvalShadowing) {
  // When run with Ignition, tests that the streaming parser canonicalizes
  // handles so the Variable::is_possibly_eval() is correct.
  const char* chunk1 =
      "(function() {\n"
      "  var y = 2;\n"
      "  return (function() {\n"
      "    eval('var y = 13;');\n"
      "    function g() {\n"
      "      return y\n"
      "    }\n"
      "    return (globalThis.Result = g());\n"
      "  })()\n"
      "})()\n";
  const char* chunks[] = {chunk1, nullptr};
  // Only run the script version of this test.
  RunStreamingTest(chunks, v8::ScriptType::kClassic);
}

TEST(StreamingBiggerScript) {
  const char* chunk1 =
      "function foo() {\n"
      "  // Make this chunk sufficiently long so that it will overflow the\n"
      "  // backing buffer of the Scanner.\n"
      "  var i = 0;\n"
      "  var result = 0;\n"
      "  for (i = 0; i < 13; ++i) { result = result + 1; }\n"
      "  result = 0;\n"
      "  for (i = 0; i < 13; ++i) { result = result + 1; }\n"
      "  result = 0;\n"
      "  for (i = 0; i < 13; ++i) { result = result + 1; }\n"
      "  result = 0;\n"
      "  for (i = 0; i < 13; ++i) { result = result + 1; }\n"
      "  return result;\n"
      "}\n";
  const char* chunks[] = {chunk1, "globalThis.Result = foo(); ", nullptr};
  RunStreamingTest(chunks);
}


TEST(StreamingScriptWithParseError) {
  // Test that parse errors from streamed scripts are propagated correctly.
  {
    char chunk1[] =
        "  // This will result in a parse error.\n"
        "  var if else then foo";
    char chunk2[] = "  13\n";
    const char* chunks[] = {chunk1, chunk2, "globalThis.Result = foo();",
                            nullptr};

    RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::ONE_BYTE,
                     false);
  }
  // Test that the next script succeeds normally.
  {
    char chunk1[] =
        "  // This will be parsed successfully.\n"
        "  function foo() { return ";
    char chunk2[] = "  13; }\n";
    const char* chunks[] = {chunk1, chunk2, "globalThis.Result = foo();",
                            nullptr};

    RunStreamingTest(chunks);
  }
}


TEST(StreamingUtf8Script) {
  // We'd want to write \uc481 instead of \xec\x92\x81, but Windows compilers
  // don't like it.
  const char* chunk1 =
      "function foo() {\n"
      "  // This function will contain an UTF-8 character which is not in\n"
      "  // ASCII.\n"
      "  var foob\xec\x92\x81r = 13;\n"
      "  return foob\xec\x92\x81r;\n"
      "}\n";
  const char* chunks[] = {chunk1, "globalThis.Result = foo(); ", nullptr};
  RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8);
}


TEST(StreamingUtf8ScriptWithSplitCharactersSanityCheck) {
  // A sanity check to prove that the approach of splitting UTF-8
  // characters is correct. Here is an UTF-8 character which will take three
  // bytes.
  const char* reference = "\xec\x92\x81";
  CHECK_EQ(3, strlen(reference));

  char chunk1[] =
      "function foo() {\n"
      "  // This function will contain an UTF-8 character which is not in\n"
      "  // ASCII.\n"
      "  var foob";
  char chunk2[] =
      "XXXr = 13;\n"
      "  return foob\xec\x92\x81r;\n"
      "}\n";
  for (int i = 0; i < 3; ++i) {
    chunk2[i] = reference[i];
  }
  const char* chunks[] = {chunk1, chunk2, "globalThis.Result = foo();",
                          nullptr};
  RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8);
}


TEST(StreamingUtf8ScriptWithSplitCharacters) {
  // Stream data where a multi-byte UTF-8 character is split between two data
  // chunks.
  const char* reference = "\xec\x92\x81";
  char chunk1[] =
      "function foo() {\n"
      "  // This function will contain an UTF-8 character which is not in\n"
      "  // ASCII.\n"
      "  var foobX";
  char chunk2[] =
      "XXr = 13;\n"
      "  return foob\xec\x92\x81r;\n"
      "}\n";
  chunk1[strlen(chunk1) - 1] = reference[0];
  chunk2[0] = reference[1];
  chunk2[1] = reference[2];
  const char* chunks[] = {chunk1, chunk2, "globalThis.Result = foo();",
                          nullptr};
  RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8);
}


TEST(StreamingUtf8ScriptWithSplitCharactersValidEdgeCases) {
  // Tests edge cases which should still be decoded correctly.

  // Case 1: a chunk contains only bytes for a split character (and no other
  // data). This kind of a chunk would be exceptionally small, but we should
  // still decode it correctly.
  const char* reference = "\xec\x92\x81";
  // The small chunk is at the beginning of the split character
  {
    char chunk1[] =
        "function foo() {\n"
        "  // This function will contain an UTF-8 character which is not in\n"
        "  // ASCII.\n"
        "  var foob";
    char chunk2[] = "XX";
    char chunk3[] =
        "Xr = 13;\n"
        "  return foob\xec\x92\x81r;\n"
        "}\n";
    chunk2[0] = reference[0];
    chunk2[1] = reference[1];
    chunk3[0] = reference[2];
    const char* chunks[] = {chunk1, chunk2, chunk3,
                            "globalThis.Result = foo();", nullptr};
    RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8);
  }
  // The small chunk is at the end of a character
  {
    char chunk1[] =
        "function foo() {\n"
        "  // This function will contain an UTF-8 character which is not in\n"
        "  // ASCII.\n"
        "  var foobX";
    char chunk2[] = "XX";
    char chunk3[] =
        "r = 13;\n"
        "  return foob\xec\x92\x81r;\n"
        "}\n";
    chunk1[strlen(chunk1) - 1] = reference[0];
    chunk2[0] = reference[1];
    chunk2[1] = reference[2];
    const char* chunks[] = {chunk1, chunk2, chunk3,
                            "globalThis.Result = foo();", nullptr};
    RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8);
  }
  // Case 2: the script ends with a multi-byte character. Make sure that it's
  // decoded correctly and not just ignored.
  {
    char chunk1[] =
        "var foob\xec\x92\x81 = 13;\n"
        "globalThis.Result = foob\xec\x92\x81";
    const char* chunks[] = {chunk1, nullptr};
    RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8);
  }
}


TEST(StreamingUtf8ScriptWithSplitCharactersInvalidEdgeCases) {
  // Test cases where a UTF-8 character is split over several chunks. Those
  // cases are not supported (the embedder should give the data in big enough
  // chunks), but we shouldn't crash and parse this just fine.
  const char* reference = "\xec\x92\x81";
  char chunk1[] =
      "function foo() {\n"
      "  // This function will contain an UTF-8 character which is not in\n"
      "  // ASCII.\n"
      "  var foobX";
  char chunk2[] = "X";
  char chunk3[] =
      "Xr = 13;\n"
      "  return foob\xec\x92\x81r;\n"
      "}\n";
  chunk1[strlen(chunk1) - 1] = reference[0];
  chunk2[0] = reference[1];
  chunk3[0] = reference[2];
  const char* chunks[] = {chunk1, chunk2, chunk3, "globalThis.Result = foo();",
                          nullptr};

  RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8);
}



TEST(StreamingWithDebuggingEnabledLate) {
  // The streaming parser can only parse lazily, i.e. inner functions are not
  // fully parsed. However, we may compile inner functions eagerly when
  // debugging. Make sure that we can deal with this when turning on debugging
  // after streaming parser has already finished parsing.
  const char* chunks[] = {"with({x:1}) {",
                          "  var foo = function foo(y) {",
                          "    return x + y;",
                          "  };",
                          "  foo(2);",
                          "}",
                          nullptr};

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);

  v8::ScriptCompiler::StreamedSource source(
      std::make_unique<i::TestSourceStream>(chunks),
      v8::ScriptCompiler::StreamedSource::ONE_BYTE);
  v8::ScriptCompiler::ScriptStreamingTask* task =
      v8::ScriptCompiler::StartStreaming(isolate, &source);

  // TestSourceStream::GetMoreData won't block, so it's OK to just join the
  // background task.
  StreamerThread::StartThreadForTaskAndJoin(task);
  delete task;

  CHECK(!try_catch.HasCaught());

  v8::ScriptOrigin origin(v8_str("http://foo.com"));
  char* full_source = i::TestSourceStream::FullSourceString(chunks);

  EnableDebugger(isolate);

  v8::Local<Script> script =
      v8::ScriptCompiler::Compile(env.local(), &source, v8_str(full_source),
                                  origin)
          .ToLocalChecked();

  Maybe<uint32_t> result =
      script->Run(env.local()).ToLocalChecked()->Uint32Value(env.local());
  CHECK_EQ(3U, result.FromMaybe(0));

  delete[] full_source;

  DisableDebugger(isolate);
}


TEST(StreamingScriptWithInvalidUtf8) {
  // Regression test for a crash: test that invalid UTF-8 bytes in the end of a
  // chunk don't produce a crash.
  const char* reference = "\xec\x92\x81\x80\x80";
  char chunk1[] =
      "function foo() {\n"
      "  // This function will contain an UTF-8 character which is not in\n"
      "  // ASCII.\n"
      "  var foobXXXXX";  // Too many bytes which look like incomplete chars!
  char chunk2[] =
      "r = 13;\n"
      "  return foob\xec\x92\x81\x80\x80r;\n"
      "}\n";
  for (int i = 0; i < 5; ++i) chunk1[strlen(chunk1) - 5 + i] = reference[i];

  const char* chunks[] = {chunk1, chunk2, "globalThis.Result = foo();",
                          nullptr};
  RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8, false);
}


TEST(StreamingUtf8ScriptWithMultipleMultibyteCharactersSomeSplit) {
  // Regression test: Stream data where there are several multi-byte UTF-8
  // characters in a sequence and one of them is split between two data chunks.
  const char* reference = "\xec\x92\x81";
  char chunk1[] =
      "function foo() {\n"
      "  // This function will contain an UTF-8 character which is not in\n"
      "  // ASCII.\n"
      "  var foob\xec\x92\x81X";
  char chunk2[] =
      "XXr = 13;\n"
      "  return foob\xec\x92\x81\xec\x92\x81r;\n"
      "}\n";
  chunk1[strlen(chunk1) - 1] = reference[0];
  chunk2[0] = reference[1];
  chunk2[1] = reference[2];
  const char* chunks[] = {chunk1, chunk2, "globalThis.Result = foo();",
                          nullptr};
  RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8);
}


TEST(StreamingUtf8ScriptWithMultipleMultibyteCharactersSomeSplit2) {
  // Another regression test, similar to the previous one. The difference is
  // that the split character is not the last one in the sequence.
  const char* reference = "\xec\x92\x81";
  char chunk1[] =
      "function foo() {\n"
      "  // This function will contain an UTF-8 character which is not in\n"
      "  // ASCII.\n"
      "  var foobX";
  char chunk2[] =
      "XX\xec\x92\x81r = 13;\n"
      "  return foob\xec\x92\x81\xec\x92\x81r;\n"
      "}\n";
  chunk1[strlen(chunk1) - 1] = reference[0];
  chunk2[0] = reference[1];
  chunk2[1] = reference[2];
  const char* chunks[] = {chunk1, chunk2, "globalThis.Result = foo();",
                          nullptr};
  RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8);
}


TEST(StreamingWithHarmonyScopes) {
  // Don't use RunStreamingTest here so that both scripts get to use the same
  // LocalContext and HandleScope.
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // First, run a script with a let variable.
  CompileRun("\"use strict\"; let x = 1;");

  // Then stream a script which (erroneously) tries to introduce the same
  // variable again.
  const char* chunks[] = {"\"use strict\"; let x = 2;", nullptr};

  v8::TryCatch try_catch(isolate);
  v8::ScriptCompiler::StreamedSource source(
      std::make_unique<i::TestSourceStream>(chunks),
      v8::ScriptCompiler::StreamedSource::ONE_BYTE);
  v8::ScriptCompiler::ScriptStreamingTask* task =
      v8::ScriptCompiler::StartStreaming(isolate, &source);

  // TestSourceStream::GetMoreData won't block, so it's OK to just join the
  // background task.
  StreamerThread::StartThreadForTaskAndJoin(task);
  delete task;

  // Parsing should succeed (the script will be parsed and compiled in a context
  // independent way, so the error is not detected).
  CHECK(!try_catch.HasCaught());

  v8::ScriptOrigin origin(v8_str("http://foo.com"));
  char* full_source = i::TestSourceStream::FullSourceString(chunks);
  v8::Local<Script> script =
      v8::ScriptCompiler::Compile(env.local(), &source, v8_str(full_source),
                                  origin)
          .ToLocalChecked();
  CHECK(!script.IsEmpty());
  CHECK(!try_catch.HasCaught());

  // Running the script exposes the error.
  CHECK(script->Run(env.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
  delete[] full_source;
}

namespace {
void StreamingWithIsolateScriptCache(bool run_gc) {
  i::v8_flags.expose_gc = true;
  const char* chunks[] = {"'use strict'; (function test() { return 13; })",
                          nullptr};
  const char* full_source = chunks[0];
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin(v8_str("http://foo.com"), 0, 0, false, -1,
                          v8::Local<v8::Value>(), false, false, false);
  v8::Local<Value> first_function_untyped;
  i::DirectHandle<i::JSFunction> first_function;
  i::DirectHandle<i::JSFunction> second_function;

  // Run the script using streaming.
  {
    LocalContext env;
    v8::EscapableHandleScope inner_scope(isolate);

    v8::ScriptCompiler::StreamedSource source(
        std::make_unique<i::TestSourceStream>(chunks),
        v8::ScriptCompiler::StreamedSource::ONE_BYTE);
    v8::ScriptCompiler::ScriptStreamingTask* task =
        v8::ScriptCompiler::StartStreaming(isolate, &source,
                                           v8::ScriptType::kClassic);
    StreamerThread::StartThreadForTaskAndJoin(task);
    delete task;
    v8::Local<Script> script =
        v8::ScriptCompiler::Compile(env.local(), &source, v8_str(full_source),
                                    origin)
            .ToLocalChecked();
    CHECK_EQ(source.compilation_details().in_memory_cache_result,
             v8::ScriptCompiler::InMemoryCacheResult::kMiss);
    v8::Local<Value> result(script->Run(env.local()).ToLocalChecked());
    first_function_untyped = inner_scope.Escape(result);

    if (run_gc) {
      // Age the top-level bytecode for the script to encourage the Isolate
      // script cache to evict it. However, there are still active Handles
      // referring to functions in that script, so the script itself should stay
      // alive and reachable via the Isolate script cache.
      i::DirectHandle<i::JSFunction> script_function =
          i::Cast<i::JSFunction>(v8::Utils::OpenDirectHandle(*script));
      i::SharedFunctionInfo::EnsureOldForTesting(script_function->shared());
    }
  }

  first_function = i::Cast<i::JSFunction>(
      v8::Utils::OpenDirectHandle(*first_function_untyped));

  // Run the same script in another Context without streaming.
  {
    LocalContext env;

    if (run_gc) {
      // Perform garbage collection, which should remove the top-level
      // SharedFunctionInfo from the Isolate script cache. However, the
      // corresponding Script is still reachable and therefore still present in
      // the Isolate script cache.
      CompileRun("gc();");
    }

    v8::ScriptCompiler::Source script_source(v8_str(full_source), origin);
    Local<Script> script =
        v8::ScriptCompiler::Compile(env.local(), &script_source)
            .ToLocalChecked();
    CHECK_EQ(script_source.GetCompilationDetails().in_memory_cache_result,
             run_gc ? v8::ScriptCompiler::InMemoryCacheResult::kPartial
                    : v8::ScriptCompiler::InMemoryCacheResult::kHit);
    v8::Local<Value> result(script->Run(env.local()).ToLocalChecked());
    second_function =
        i::Cast<i::JSFunction>(v8::Utils::OpenDirectHandle(*result));
  }

  // The functions created by both copies of the script should refer to the same
  // SharedFunctionInfo instance due to the isolate script cache.
  CHECK_EQ(first_function->shared(), second_function->shared());
}
}  // namespace

// Regression test for crbug.com/v8/12668. Verifies that after a streamed script
// is inserted into the isolate script cache, a non-streamed script with
// identical origin can reuse that data.
TEST(StreamingWithIsolateScriptCache) {
  StreamingWithIsolateScriptCache(false);
}

// Variant of the above test which evicts the root SharedFunctionInfo from the
// Isolate script cache but still reuses the same Script.
TEST(StreamingWithIsolateScriptCacheClearingRootSFI) {
  StreamingWithIsolateScriptCache(true);
}

TEST(CodeCache) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();

  const char* source = "Math.sqrt(4)";
  const char* origin = "code cache test";
  v8::ScriptCompiler::CachedData* cache;

  v8::Isolate* isolate1 = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope iscope(isolate1);
    v8::HandleScope scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope cscope(context);
    v8::Local<v8::String> source_string = v8_str(source);
    v8::ScriptOrigin script_origin(v8_str(origin));
    v8::ScriptCompiler::Source script_source(source_string, script_origin);
    v8::ScriptCompiler::CompileOptions option =
        v8::ScriptCompiler::kNoCompileOptions;
    v8::Local<v8::Script> script =
        v8::ScriptCompiler::Compile(context, &script_source, option)
            .ToLocalChecked();
    cache = v8::ScriptCompiler::CreateCodeCache(script->GetUnboundScript());
  }
  isolate1->Dispose();

  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope iscope(isolate2);
    v8::HandleScope scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope cscope(context);
    v8::Local<v8::String> source_string = v8_str(source);
    v8::ScriptOrigin script_origin(v8_str(origin));
    v8::ScriptCompiler::Source script_source(source_string, script_origin,
                                             cache);
    v8::ScriptCompiler::CompileOptions option =
        v8::ScriptCompiler::kConsumeCodeCache;
    v8::Local<v8::Script> script;
    {
      i::DisallowCompilation no_compile(
          reinterpret_cast<i::Isolate*>(isolate2));
      script = v8::ScriptCompiler::Compile(context, &script_source, option)
                   .ToLocalChecked();
    }
    CHECK_EQ(2, script->Run(context)
                    .ToLocalChecked()
                    ->ToInt32(context)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  isolate2->Dispose();
}

v8::MaybeLocal<Value> UnexpectedSyntheticModuleEvaluationStepsCallback(
    Local<Context> context, Local<Module> module) {
  CHECK_WITH_MSG(false, "Unexpected call to synthetic module re callback");
}

static int synthetic_module_callback_count;

v8::MaybeLocal<Value> SyntheticModuleEvaluationStepsCallback(
    Local<Context> context, Local<Module> module) {
  synthetic_module_callback_count++;
  return v8::Undefined(reinterpret_cast<v8::Isolate*>(context->GetIsolate()));
}

v8::MaybeLocal<Value> SyntheticModuleEvaluationStepsCallbackFail(
    Local<Context> context, Local<Module> module) {
  synthetic_module_callback_count++;
  context->GetIsolate()->ThrowException(
      v8_str("SyntheticModuleEvaluationStepsCallbackFail exception"));
  return v8::MaybeLocal<Value>();
}

v8::MaybeLocal<Value> SyntheticModuleEvaluationStepsCallbackSet
"""


```