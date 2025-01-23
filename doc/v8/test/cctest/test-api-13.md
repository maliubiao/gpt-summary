Response: The user wants a summary of the C++ code provided, which is a test file for the V8 JavaScript engine's API.

The file `v8/test/cctest/test-api.cc` contains various tests for the C++ API of V8, specifically focusing on how JavaScript features interact with the C++ embedding API.

This is part 14 of 18, suggesting this section likely focuses on a specific set of related features.

Looking at the code, the tests in this section seem to revolve around:

1. **Source URLs and Source Mapping URLs:** The `ScriptSourceURLAndSourceMappingURL` test checks how V8 handles `//# sourceURL=` and `//# sourceMappingURL=` comments within JavaScript code, both for regular scripts and modules. This is crucial for debugging, allowing developers to map code executed within the V8 engine back to its original source files.

2. **`GetOwnPropertyDescriptor`:** This tests the `GetOwnPropertyDescriptor` method of V8 objects, which retrieves the property descriptor of an object's own property. It covers cases with data properties, accessor properties (getters/setters), and symbol properties.

3. **Access Checks and Hidden Properties:** Tests like `Regress411877`, `GetHiddenPropertyTableAfterAccessCheck`, and `Regress411793` seem related to V8's access control mechanisms and how hidden properties interact with these checks.

4. **Streaming Compilation:** A significant portion of this section is dedicated to testing V8's streaming compilation feature. This allows V8 to start parsing and compiling JavaScript code even before the entire script has been downloaded, improving startup performance. The tests cover various aspects of streaming, including basic functionality, handling of UTF-8 characters (including splitting across chunks), error handling, interaction with debugging, and the Isolate script cache.

5. **Code Caching:** Tests like `CodeCache`, `ModuleCodeCache`, `CodeCacheModuleScriptMismatch`, `CodeCacheScriptModuleMismatch`, and `InvalidCodeCacheData` are concerned with V8's code caching mechanism. This allows V8 to store compiled code and reuse it across different runs or isolates, further improving performance. The tests cover caching for both scripts and modules, and how V8 handles invalid cache data.

6. **Synthetic Modules:** The tests starting with `CreateSyntheticModule` focus on a specific V8 API for creating "synthetic" modules in C++. These modules don't load from external files but are defined and controlled directly from C++ code. The tests cover creation, setting exports, evaluation, and interaction with regular JavaScript modules through imports.

7. **Module Evaluation and Termination:** The tests `ModuleEvaluateTerminateExecution` and `ModuleEvaluateImportTerminateExecution` explore the behavior of module evaluation when execution is terminated prematurely.

8. **Other Edge Cases:**  There are also tests for things like string concatenation overflow and interactions with TurboFan (V8's optimizing compiler) and detaching ArrayBuffers.

In summary, this section primarily focuses on testing:
- **Source mapping and URLs**
- **Property descriptors**
- **Access checks and hidden properties**
- **Streaming compilation of JavaScript code**
- **Code caching for scripts and modules**
- **The creation and manipulation of synthetic modules**
- **Module evaluation and termination scenarios**

Let's illustrate the `sourceURL` functionality with a JavaScript example.
```cpp
/*
 * Copyright 2013 the V8 project authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "src/base/platform/mutex.h"
#include "src/codegen/source-position-table.h"
#include "src/common/globals.h"
#include "src/compiler/turboshaft/turboshaft.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/isolate.h"
#include "src/execution/vm-state-inl.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-inl.h"
#include "src/init/v8.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/cell.h"
#include "src/objects/code-inl.h"
#include "src/objects/debug-objects-inl.h"
#include "src/objects/fixed-array-inl.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/promise-inl.h"
#include "src/objects/scope-info.h"
#include "src/objects/script-inl.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/objects/source-text-module-inl.h"
#include "src/objects/stack-frame-info-inl.h"
#include "src/objects/string.h"
#include "src/objects/synthetic-module.h"
#include "src/objects/value-proxy.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parsing.h"
#include "src/regexp/regexp-parser.h"
#include "src/strings/string-builder-inl.h"
#include "src/strings/unicode-inl.h"
#include "src/tasks/task-utils.h"
#include "src/test/cctest/cctest.h"
#include "src/test/cctest/heap/heap-utils.h"
#include "src/test/cctest/profiler-extension.h"
#include "src/test/cctest/trace-extension.h"
#include "src/tracing/tracing-category-registry.h"
#include "src/wasm/wasm-code-manager.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include " TorqueBuiltins.inc"

#include <atomic>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace v8 {
namespace internal {
class Isolate;
}  // namespace internal

namespace {

void CheckMagicComments(v8::Isolate* isolate, Local<UnboundScript> script,
                        const char* expected_source_url,
                        const char* expected_source_mapping_url) {
  v8::ScriptCompiler::SourceCode source_code(script->GetSource());
  CHECK_EQ(expected_source_url != nullptr,
           source_code.HasSourceURL(isolate));
  if (expected_source_url != nullptr) {
    v8::String::Utf8Value actual_source_url(isolate,
                                            source_code.GetSourceURL(isolate));
    CHECK_EQ(expected_source_url, *actual_source_url);
  }
  CHECK_EQ(expected_source_mapping_url != nullptr,
           source_code.HasSourceMappingURL(isolate));
  if (expected_source_mapping_url != nullptr) {
    v8::String::Utf8Value actual_source_mapping_url(
        isolate, source_code.GetSourceMappingURL(isolate));
    CHECK_EQ(expected_source_mapping_url, *actual_source_mapping_url);
  }
}

void SourceURLHelper(v8::Isolate* isolate, const char* source_string,
                     const char* expected_source_url,
                     const char* expected_source_mapping_url) {
  Local<Context> context = Context::New(isolate);
  Context::Scope context_scope(context);
  Local<String> source =
      String::NewFromUtf8(isolate, source_string).ToLocalChecked();
  {
    v8::ScriptCompiler::Source script_source(source);
    Local<Script> script =
        v8::ScriptCompiler::Compile(context, &script_source).ToLocalChecked();
    CheckMagicComments(isolate, script->GetUnboundScript(),
                       expected_source_url, expected_source_mapping_url);
  }
  {
    v8::ScriptCompiler::Source script_source(source);
    script_source.GetCompilerOptions()->SetIsModule(true);
    Local<v8::Module> module =
        v8::ScriptCompiler::CompileModule(isolate, &script_source).ToLocalChecked();
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

  v8::ScriptCompiler
### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第14部分，共18部分，请归纳一下它的功能
```

### 源代码
```
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

v8::MaybeLocal<Value> SyntheticModuleEvaluationStepsCallbackSetExport(
    Local<Context> context, Local<Module> module) {
  Maybe<bool> set_export_result = module->SetSyntheticModuleExport(
      context->GetIsolate(), v8_str("test_export"), v8_num(42));
  CHECK(set_export_result.FromJust());
  return v8::Undefined(reinterpret_cast<v8::Isolate*>(context->GetIsolate()));
}

namespace {

Local<Module> CompileAndInstantiateModule(v8::Isolate* isolate,
                                          Local<Context> context,
                                          const char* resource_name,
                                          const char* source) {
  Local<String> source_string = v8_str(source);
  v8::ScriptOrigin script_origin(v8_str(resource_name), 0, 0, false, -1,
                                 Local<v8::Value>(), false, false, true);
  v8::ScriptCompiler::Source script_compiler_source(source_string,
                                                    script_origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &script_compiler_source)
          .ToLocalChecked();
  module->InstantiateModule(context, UnexpectedModuleResolveCallback)
      .ToChecked();

  return module;
}

Local<Module> CreateAndInstantiateSyntheticModule(
    v8::Isolate* isolate, Local<String> module_name, Local<Context> context,
    const v8::MemorySpan<const v8::Local<v8::String>>& export_names,
    v8::Module::SyntheticModuleEvaluationSteps evaluation_steps) {
  Local<Module> module = v8::Module::CreateSyntheticModule(
      isolate, module_name, export_names, evaluation_steps);
  module->InstantiateModule(context, UnexpectedModuleResolveCallback)
      .ToChecked();

  return module;
}

Local<Module> CompileAndInstantiateModuleFromCache(
    v8::Isolate* isolate, Local<Context> context, const char* resource_name,
    const char* source, v8::ScriptCompiler::CachedData* cache) {
  Local<String> source_string = v8_str(source);
  v8::ScriptOrigin script_origin(v8_str(resource_name), 0, 0, false, -1,
                                 Local<v8::Value>(), false, false, true);
  v8::ScriptCompiler::Source script_compiler_source(source_string,
                                                    script_origin, cache);

  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &script_compiler_source,
                                        v8::ScriptCompiler::kConsumeCodeCache)
          .ToLocalChecked();
  module->InstantiateModule(context, UnexpectedModuleResolveCallback)
      .ToChecked();

  return module;
}

}  // namespace

v8::MaybeLocal<Module> SyntheticModuleResolveCallback(
    Local<Context> context, Local<String> specifier,
    Local<FixedArray> import_attributes, Local<Module> referrer) {
  auto export_names = v8::to_array<Local<v8::String>>({v8_str("test_export")});
  Local<Module> module = CreateAndInstantiateSyntheticModule(
      context->GetIsolate(),
      v8_str("SyntheticModuleResolveCallback-TestSyntheticModule"), context,
      export_names, SyntheticModuleEvaluationStepsCallbackSetExport);
  return v8::MaybeLocal<Module>(module);
}

v8::MaybeLocal<Module> SyntheticModuleThatThrowsDuringEvaluateResolveCallback(
    Local<Context> context, Local<String> specifier,
    Local<FixedArray> import_attributes, Local<Module> referrer) {
  auto export_names = v8::to_array<Local<v8::String>>({v8_str("test_export")});
  Local<Module> module = CreateAndInstantiateSyntheticModule(
      context->GetIsolate(),
      v8_str("SyntheticModuleThatThrowsDuringEvaluateResolveCallback-"
             "TestSyntheticModule"),
      context, export_names, SyntheticModuleEvaluationStepsCallbackFail);
  return v8::MaybeLocal<Module>(module);
}

TEST(ModuleCodeCache) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();

  const char* origin = "code cache test";
  const char* source =
      "export default 5; export const a = 10; function f() { return 42; } "
      "(function() { globalThis.Result = f(); })();";

  v8::ScriptCompiler::CachedData* cache;
  {
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope cscope(context);

      Local<Module> module =
          CompileAndInstantiateModule(isolate, context, origin, source);

      // Fetch the shared function info before evaluation.
      Local<v8::UnboundModuleScript> unbound_module_script =
          module->GetUnboundModuleScript();

      // Evaluate for possible lazy compilation.
      Local<Value> completion_value =
          module->Evaluate(context).ToLocalChecked();
      Local<v8::Promise> promise(Local<v8::Promise>::Cast(completion_value));
      CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
      CHECK(promise->Result()->IsUndefined());
      CHECK_EQ(42, context->Global()
                       ->Get(context, v8_str("Result"))
                       .ToLocalChecked()
                       ->Int32Value(context)
                       .FromJust());

      // Now create the cache. Note that it is freed, obscurely, when
      // ScriptCompiler::Source goes out of scope below.
      cache = v8::ScriptCompiler::CreateCodeCache(unbound_module_script);
    }
    isolate->Dispose();
  }

  // Test that the cache is consumed and execution still works.
  {
    // Disable --always_turbofan, otherwise we try to optimize during module
    // instantiation, violating the DisallowCompilation scope.
    i::v8_flags.always_turbofan = false;
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope cscope(context);

      Local<Module> module;
      {
        i::DisallowCompilation no_compile(
            reinterpret_cast<i::Isolate*>(isolate));
        module = CompileAndInstantiateModuleFromCache(isolate, context, origin,
                                                      source, cache);
      }

      Local<Value> completion_value =
          module->Evaluate(context).ToLocalChecked();
      Local<v8::Promise> promise(Local<v8::Promise>::Cast(completion_value));
      CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
      CHECK(promise->Result()->IsUndefined());
      CHECK_EQ(42, context->Global()
                       ->Get(context, v8_str("Result"))
                       .ToLocalChecked()
                       ->Int32Value(context)
                       .FromJust());
    }
    isolate->Dispose();
  }
}

TEST(CreateSyntheticModule) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  auto export_names = v8::to_array<Local<v8::String>>({v8_str("default")});

  Local<Module> module = CreateAndInstantiateSyntheticModule(
      isolate, v8_str("CreateSyntheticModule-TestSyntheticModule"), context,
      export_names, UnexpectedSyntheticModuleEvaluationStepsCallback);
  i::DirectHandle<i::SyntheticModule> i_module =
      i::Cast<i::SyntheticModule>(v8::Utils::OpenDirectHandle(*module));
  i::DirectHandle<i::ObjectHashTable> exports(i_module->exports(), i_isolate);
  i::Handle<i::String> default_name =
      i_isolate->factory()->NewStringFromAsciiChecked("default");

  CHECK(
      IsCell(*i::Handle<i::Object>(exports->Lookup(default_name), i_isolate)));
  CHECK(IsUndefined(
      i::Cast<i::Cell>(
          i::Handle<i::Object>(exports->Lookup(default_name), i_isolate))
          ->value()));
  CHECK_EQ(i_module->export_names()->length(), 1);
  CHECK(i::Cast<i::String>(i_module->export_names()->get(0))
            ->Equals(*default_name));
  CHECK_EQ(i_module->status(), i::Module::kLinked);
  CHECK(module->IsSyntheticModule());
  CHECK(!module->IsSourceTextModule());
  CHECK_EQ(module->GetModuleRequests()->Length(), 0);
}

TEST(CreateSyntheticModuleGC) {
#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
  // Try to make sure that CreateSyntheticModule() deals well with a GC
  // happening during its execution.
  i::HeapAllocator::SetAllocationGcInterval(10);
#endif
  i::v8_flags.inline_new = false;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  auto export_names = v8::to_array<Local<v8::String>>({v8_str("default")});
  v8::Local<v8::String> module_name =
      v8_str("CreateSyntheticModule-TestSyntheticModuleGC");

  for (int i = 0; i < 200; i++) {
    Local<Module> module = v8::Module::CreateSyntheticModule(
        isolate, module_name, export_names,
        UnexpectedSyntheticModuleEvaluationStepsCallback);
    USE(module);
  }
}

TEST(CreateSyntheticModuleGCName) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  Local<Module> module;

  {
    v8::EscapableHandleScope inner_scope(isolate);
    auto export_names = v8::to_array<Local<v8::String>>({v8_str("default")});
    v8::Local<v8::String> module_name =
        v8_str("CreateSyntheticModuleGCName-TestSyntheticModule");
    module = inner_scope.Escape(v8::Module::CreateSyntheticModule(
        isolate, module_name, export_names,
        UnexpectedSyntheticModuleEvaluationStepsCallback));
  }

  i::heap::InvokeMajorGC(CcTest::heap());
#ifdef VERIFY_HEAP
  i::DirectHandle<i::HeapObject> i_module =
      i::Cast<i::HeapObject>(v8::Utils::OpenDirectHandle(*module));
  i_module->HeapObjectVerify(reinterpret_cast<i::Isolate*>(isolate));
#endif
}

TEST(SyntheticModuleSetExports) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  Local<String> foo_string = v8_str("foo");
  Local<String> bar_string = v8_str("bar");
  auto export_names = v8::to_array<Local<v8::String>>({foo_string});

  Local<Module> module = CreateAndInstantiateSyntheticModule(
      isolate, v8_str("SyntheticModuleSetExports-TestSyntheticModule"), context,
      export_names, UnexpectedSyntheticModuleEvaluationStepsCallback);

  i::DirectHandle<i::SyntheticModule> i_module =
      i::Cast<i::SyntheticModule>(v8::Utils::OpenDirectHandle(*module));
  i::DirectHandle<i::ObjectHashTable> exports(i_module->exports(), i_isolate);

  i::DirectHandle<i::Cell> foo_cell =
      i::Cast<i::Cell>(i::DirectHandle<i::Object>(
          exports->Lookup(v8::Utils::OpenHandle(*foo_string)), i_isolate));

  // During Instantiation there should be a Cell for the export initialized to
  // undefined.
  CHECK(IsUndefined(foo_cell->value()));

  Maybe<bool> set_export_result =
      module->SetSyntheticModuleExport(isolate, foo_string, bar_string);
  CHECK(set_export_result.FromJust());

  // After setting the export the Cell should still have the same idenitity.
  CHECK_EQ(exports->Lookup(v8::Utils::OpenHandle(*foo_string)), *foo_cell);

  // Test that the export value was actually set.
  CHECK(i::Cast<i::String>(i::Handle<i::Object>(foo_cell->value(), i_isolate))
            ->Equals(*v8::Utils::OpenDirectHandle(*bar_string)));
}

TEST(SyntheticModuleSetMissingExport) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  Local<String> foo_string = v8_str("foo");
  Local<String> bar_string = v8_str("bar");

  Local<Module> module = CreateAndInstantiateSyntheticModule(
      isolate, v8_str("SyntheticModuleSetExports-TestSyntheticModule"), context,
      {}, UnexpectedSyntheticModuleEvaluationStepsCallback);

  i::DirectHandle<i::SyntheticModule> i_module =
      i::Cast<i::SyntheticModule>(v8::Utils::OpenDirectHandle(*module));
  i::DirectHandle<i::ObjectHashTable> exports(i_module->exports(), i_isolate);

  TryCatch try_catch(isolate);
  Maybe<bool> set_export_result =
      module->SetSyntheticModuleExport(isolate, foo_string, bar_string);
  CHECK(set_export_result.IsNothing());
  CHECK(try_catch.HasCaught());
}

TEST(SyntheticModuleEvaluationStepsNoThrow) {
  synthetic_module_callback_count = 0;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  auto export_names = v8::to_array<Local<v8::String>>({v8_str("default")});

  Local<Module> module = CreateAndInstantiateSyntheticModule(
      isolate,
      v8_str("SyntheticModuleEvaluationStepsNoThrow-TestSyntheticModule"),
      context, export_names, SyntheticModuleEvaluationStepsCallback);
  CHECK_EQ(synthetic_module_callback_count, 0);
  Local<Value> completion_value = module->Evaluate(context).ToLocalChecked();
  CHECK(completion_value->IsUndefined());
  CHECK_EQ(synthetic_module_callback_count, 1);
  CHECK_EQ(module->GetStatus(), Module::kEvaluated);
}

TEST(SyntheticModuleEvaluationStepsThrow) {
  synthetic_module_callback_count = 0;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  v8::Context::Scope cscope(context);

  auto export_names = v8::to_array<Local<v8::String>>({v8_str("default")});

  Local<Module> module = CreateAndInstantiateSyntheticModule(
      isolate,
      v8_str("SyntheticModuleEvaluationStepsThrow-TestSyntheticModule"),
      context, export_names, SyntheticModuleEvaluationStepsCallbackFail);
  TryCatch try_catch(isolate);
  CHECK_EQ(synthetic_module_callback_count, 0);
  v8::MaybeLocal<Value> completion_value = module->Evaluate(context);
  CHECK(completion_value.IsEmpty());
  CHECK_EQ(synthetic_module_callback_count, 1);
  CHECK_EQ(module->GetStatus(), Module::kErrored);
  CHECK(try_catch.HasCaught());
}

TEST(SyntheticModuleEvaluationStepsSetExport) {
  synthetic_module_callback_count = 0;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  Local<String> test_export_string = v8_str("test_export");
  auto export_names = v8::to_array<Local<v8::String>>({test_export_string});

  Local<Module> module = CreateAndInstantiateSyntheticModule(
      isolate,
      v8_str("SyntheticModuleEvaluationStepsSetExport-TestSyntheticModule"),
      context, export_names, SyntheticModuleEvaluationStepsCallbackSetExport);

  i::DirectHandle<i::SyntheticModule> i_module =
      i::Cast<i::SyntheticModule>(v8::Utils::OpenDirectHandle(*module));
  i::DirectHandle<i::ObjectHashTable> exports(i_module->exports(), i_isolate);

  i::DirectHandle<i::Cell> test_export_cell =
      i::Cast<i::Cell>(i::DirectHandle<i::Object>(
          exports->Lookup(v8::Utils::OpenHandle(*test_export_string)),
          i_isolate));
  CHECK(IsUndefined(test_export_cell->value()));

  Local<Value> completion_value = module->Evaluate(context).ToLocalChecked();
  CHECK(completion_value->IsUndefined());
  CHECK_EQ(42, i::Object::NumberValue(test_export_cell->value()));
  CHECK_EQ(module->GetStatus(), Module::kEvaluated);
}

TEST(ImportFromSyntheticModule) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  Local<String> url = v8_str("www.test.com");
  Local<String> source_text = v8_str(
      "import {test_export} from './synthetic.module'; "
      "(function() { globalThis.Result = test_export; })();");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module->InstantiateModule(context, SyntheticModuleResolveCallback)
      .ToChecked();

  Local<Value> completion_value = module->Evaluate(context).ToLocalChecked();
  Local<v8::Promise> promise(Local<v8::Promise>::Cast(completion_value));
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
  CHECK(promise->Result()->IsUndefined());
  CHECK_EQ(42, context->Global()
                   ->Get(context, v8_str("Result"))
                   .ToLocalChecked()
                   ->Int32Value(context)
                   .FromJust());
}

TEST(ImportFromSyntheticModuleThrow) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  Local<String> url = v8_str("www.test.com");
  Local<String> source_text = v8_str(
      "import {test_export} from './synthetic.module';"
      "(function() { return test_export; })();");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module
      ->InstantiateModule(
          context, SyntheticModuleThatThrowsDuringEvaluateResolveCallback)
      .ToChecked();

  CHECK_EQ(module->GetStatus(), Module::kInstantiated);
  TryCatch try_catch(isolate);
  v8::MaybeLocal<Value> completion_value = module->Evaluate(context);
  Local<v8::Promise> promise(
      Local<v8::Promise>::Cast(completion_value.ToLocalChecked()));
  CHECK_EQ(promise->State(), v8::Promise::kRejected);

  CHECK_EQ(module->GetStatus(), Module::kErrored);
  CHECK(!try_catch.HasCaught());
}

namespace {

v8::MaybeLocal<Module> ModuleEvaluateTerminateExecutionResolveCallback(
    Local<Context> context, Local<String> specifier,
    Local<FixedArray> import_attributes, Local<Module> referrer) {
  v8::Isolate* isolate = context->GetIsolate();

  Local<String> url = v8_str("www.test.com");
  Local<String> source_text = v8_str("await Promise.resolve();");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module
      ->InstantiateModule(context,
                          ModuleEvaluateTerminateExecutionResolveCallback)
      .ToChecked();

  CHECK_EQ(module->GetStatus(), Module::kInstantiated);
  return module;
}

void ModuleEvaluateTerminateExecution(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate::GetCurrent()->TerminateExecution();
}
}  // namespace

TEST(ModuleEvaluateTerminateExecution) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  v8::Local<v8::Function> terminate_execution =
      v8::Function::New(context, ModuleEvaluateTerminateExecution,
                        v8_str("terminate_execution"))
          .ToLocalChecked();
  context->Global()
      ->Set(context, v8_str("terminate_execution"), terminate_execution)
      .FromJust();

  Local<String> url = v8_str("www.test.com");
  Local<String> source_text = v8_str(
      "terminate_execution();"
      "await Promise.resolve();");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module
      ->InstantiateModule(context,
                          ModuleEvaluateTerminateExecutionResolveCallback)
      .ToChecked();

  CHECK_EQ(module->GetStatus(), Module::kInstantiated);
  TryCatch try_catch(isolate);
  v8::MaybeLocal<Value> completion_value = module->Evaluate(context);
  CHECK(completion_value.IsEmpty());

  CHECK_EQ(module->GetStatus(), Module::kErrored);
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.HasTerminated());
}

TEST(ModuleEvaluateImportTerminateExecution) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Isolate::Scope iscope(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope cscope(context);

  v8::Local<v8::Function> terminate_execution =
      v8::Function::New(context, ModuleEvaluateTerminateExecution,
                        v8_str("terminate_execution"))
          .ToLocalChecked();
  context->Global()
      ->Set(context, v8_str("terminate_execution"), terminate_execution)
      .FromJust();

  Local<String> url = v8_str("www.test.com");
  Local<String> source_text = v8_str(
      "import './synthetic.module';"
      "terminate_execution();"
      "await Promise.resolve();");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module
      ->InstantiateModule(context,
                          ModuleEvaluateTerminateExecutionResolveCallback)
      .ToChecked();

  CHECK_EQ(module->GetStatus(), Module::kInstantiated);
  TryCatch try_catch(isolate);
  v8::MaybeLocal<Value> completion_value = module->Evaluate(context);
  Local<v8::Promise> promise(
      Local<v8::Promise>::Cast(completion_value.ToLocalChecked()));
  CHECK_EQ(promise->State(), v8::Promise::kPending);
  isolate->PerformMicrotaskCheckpoint();

  // The exception thrown by terminate execution is not catchable by JavaScript
  // so the promise can not be settled.
  CHECK_EQ(promise->State(), v8::Promise::kPending);
  CHECK_EQ(module->GetStatus(), Module::kEvaluated);
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.HasTerminated());
}

// Tests that the code cache does not confuse the same source code compiled as a
// script and as a module.
TEST(CodeCacheModuleScriptMismatch) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();

  const char* origin = "code cache test";
  const char* source = "42";

  v8::ScriptCompiler::CachedData* cache;
  {
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope cscope(context);

      Local<Module> module =
          CompileAndInstantiateModule(isolate, context, origin, source);

      // Fetch the shared function info before evaluation.
      Local<v8::UnboundModuleScript> unbound_module_script =
          module->GetUnboundModuleScript();

      // Evaluate for possible lazy compilation.
      Local<Value> completion_value =
          module->Evaluate(context).ToLocalChecked();
      Local<v8::Promise> promise(Local<v8::Promise>::Cast(completion_value));
      CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
      CHECK(promise->Result()->IsUndefined());

      // Now create the cache. Note that it is freed, obscurely, when
      // ScriptCompiler::Source goes out of scope below.
      cache = v8::ScriptCompiler::CreateCodeCache(unbound_module_script);
    }
    isolate->Dispose();
  }

  // Test that the cache is not consumed when source is compiled as a script.
  {
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope cscope(context);

      v8::ScriptOrigin script_origin(v8_str(origin));
      v8::ScriptCompiler::Source script_compiler_source(v8_str(source),
                                                        script_origin, cache);

      v8::Local<v8::Script> script =
          v8::ScriptCompiler::Compile(context, &script_compiler_source,
                                      v8::ScriptCompiler::kConsumeCodeCache)
              .ToLocalChecked();

      CHECK(cache->rejected);

      CHECK_EQ(42, script->Run(context)
                       .ToLocalChecked()
                       ->ToInt32(context)
                       .ToLocalChecked()
                       ->Int32Value(context)
                       .FromJust());
    }
    isolate->Dispose();
  }
}

// Same as above but other way around.
TEST(CodeCacheScriptModuleMismatch) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();

  const char* origin = "code cache test";
  const char* source = "42";

  v8::ScriptCompiler::CachedData* cache;
  {
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
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
    isolate->Dispose();
  }

  // Test that the cache is not consumed when source is compiled as a module.
  {
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope cscope(context);

      v8::ScriptOrigin script_origin(v8_str(origin), 0, 0, false, -1,
                                     Local<v8::Value>(), false, false, true);
      v8::ScriptCompiler::Source script_compiler_source(v8_str(source),
                                                        script_origin, cache);

      Local<Module> module = v8::ScriptCompiler::CompileModule(
                                 isolate, &script_compiler_source,
                                 v8::ScriptCompiler::kConsumeCodeCache)
                                 .ToLocalChecked();
      module->InstantiateModule(context, UnexpectedModuleResolveCallback)
          .ToChecked();

      CHECK(cache->rejected);

      Local<Value> completion_value =
          module->Evaluate(context).ToLocalChecked();
      Local<v8::Promise> promise(Local<v8::Promise>::Cast(completion_value));
      CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
      CHECK(promise->Result()->IsUndefined());
    }
    isolate->Dispose();
  }
}

// Tests that compilation can handle a garbled cache.
TEST(InvalidCodeCacheDataInCompileModule) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext local_context;

  const char* garbage = "garbage garbage garbage garbage garbage garbage";
  const uint8_t* data = reinterpret_cast<const uint8_t*>(garbage);
  Local<String> origin = v8_str("origin");
  int length = 16;
  v8::ScriptCompiler::CachedData* cached_data =
      new v8::ScriptCompiler::CachedData(data, length);
  CHECK(!cached_data->rejected);

  v8::ScriptOrigin script_origin(origin, 0, 0, false, -1, Local<v8::Value>(),
                                 false, false, true);
  v8::ScriptCompiler::Source source(v8_str("42"), script_origin, cached_data);
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();

  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source,
                                        v8::ScriptCompiler::kConsumeCodeCache)
          .ToLocalChecked();
  module->InstantiateModule(context, UnexpectedModuleResolveCallback)
      .ToChecked();

  CHECK(cached_data->rejected);
  Local<Value> completion_value = module->Evaluate(context).ToLocalChecked();
  Local<v8::Promise> promise(Local<v8::Promise>::Cast(completion_value));
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
  CHECK(promise->Result()->IsUndefined());
}

void TestInvalidCacheData(v8::ScriptCompiler::CompileOptions option) {
  const char* garbage = "garbage garbage garbage garbage garbage garbage";
  const uint8_t* data = reinterpret_cast<const uint8_t*>(garbage);
  int length = 16;
  v8::Isolate* isolate = CcTest::isolate();
  v8::ScriptCompiler::CachedData* cached_data =
      new v8::ScriptCompiler::CachedData(data, length);
  CHECK(!cached_data->rejected);
  v8::ScriptOrigin origin(v8_str("origin"));
  v8::ScriptCompiler::Source source(v8_str("42"), origin, cached_data);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Script> script =
      v8::ScriptCompiler::Compile(context, &source, option).ToLocalChecked();
  CHECK(cached_data->rejected);
  CHECK_EQ(
      42,
      script->Run(context).ToLocalChecked()->Int32Value(context).FromJust());
}

TEST(InvalidCodeCacheData) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext context;
  TestInvalidCacheData(v8::ScriptCompiler::kConsumeCodeCache);
}

TEST(StringConcatOverflow) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  RandomLengthOneByteResource* r =
      new RandomLengthOneByteResource(i::String::kMaxLength);
  v8::Local<v8::String> str =
      v8::String::NewExternalOneByte(isolate, r).ToLocalChecked();
  CHECK(!str.IsEmpty());
  v8::TryCatch try_catch(isolate);
  v8::Local<v8::String> result = v8::String::Concat(isolate, str, str);
  v8::String::Concat(CcTest::isolate(), str, str);
  CHECK(result.IsEmpty());
  CHECK(!try_catch.HasCaught());
}

TEST(TurboAsmDisablesDetach) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(CcTest::isolate());
  LocalContext context;
  const char* load =
      "function Module(stdlib, foreign, heap) {"
      "  'use asm';"
      "  var MEM32 = new stdlib.Int32Array(heap);"
      "  function load() { return MEM32[0] | 0; }"
      "  return { load: load };"
      "}"
      "var buffer = new ArrayBuffer(4096);"
      "var module = Module(this, {}, buffer);"
      "module.load();"
      "buffer";

  v8::Local<v8::ArrayBuffer> result = CompileRun(load).As<v8::ArrayBuffer>();
  CHECK(!result->IsDetachable());

  const char* store =
      "function Module(stdlib, foreign, heap) {"
      "  'use asm';"
      "  var MEM32 = new stdlib.Int32Array(heap);"
      "  function store() { MEM32[0] = 0; }"
      "  return { store: store };"
      "}"
      "var buffer = new ArrayBuffer(4096);"
      "var module = Module(this, {}, buffer);"
      "module.store();"
      "buffer";

  result = CompileRun(store).As<v8::ArrayBuffer>();
  CHECK(!result->IsDetachable());
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
}

TEST(ClassPrototypeCreationContext) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext env;

  Local<Object> result = Local<Object>::Cast(
      CompileRun("'use strict'; class Example { }; Example.prototype"));
  CHECK(env.local() == result->GetCreationContext(isolate).ToLocalChecked());
}


TEST(SimpleStreamingScriptWithSourceURL) {
  const char* chunks[] = {"function foo() { ret",
                          "urn 13; } globalThis.Result = f", "oo();\n",
                          "//# sourceURL=bar2.js\n", nullptr};
  RunStr
```