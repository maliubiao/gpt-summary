Response: The user is asking for a summary of the functionality of the provided C++ code snippet, which is part 2 of a 4-part file. The code is from `v8/test/cctest/test-serialize.cc` and likely tests the serialization and deserialization of JavaScript code within the V8 engine.

Based on the test names and the operations within the tests, here's a breakdown of the functionality:

1. **Code Caching and Deserialization:** The primary focus is on testing the code caching mechanism and how serialized code can be deserialized and executed. This involves compiling JavaScript code, serializing it into a cache, and then deserializing and running it again.

2. **Profiler Integration:**  One test specifically checks how the code serializer interacts with the profiler, ensuring source positions are collected after deserialization when the profiler is enabled.

3. **Compilation Cache Behavior:** Several tests explore the behavior of the compilation cache, verifying that cached code is reused when appropriate and that lookups succeed or fail based on various factors (e.g., source code, host-defined options, script details, language mode).

4. **Handling Different Code States:** Tests cover scenarios with and without interpreted frames, with debuggers attached, and with block coverage enabled to see how serialization handles these different contexts.

5. **Function Compilation Caching:** A test specifically examines the caching of compiled functions, including how arguments and host-defined options affect cache lookups.

6. **Internalized and External Strings:** The code includes tests for serializing and deserializing scripts that contain internalized strings (strings stored once in memory) and external strings (strings whose content is managed outside V8). This includes testing large strings and large external strings.

7. **Script Names:** There are tests to confirm that external script names are correctly serialized and deserialized.

8. **Cross-Isolate Code Sharing:** Several tests demonstrate how serialized code can be shared and executed across different V8 isolates. This verifies the portability of the cached code.

9. **Code Caching Strategies (Eager, Lazy, After Execute):** The code tests different code caching strategies, such as eager compilation (compiling everything upfront) and caching after execution.

10. **Context Dependencies:** A test checks the handling of context dependencies, particularly when using `eval` within a function.

11. **Flag Changes and Cache Invalidation:**  A test ensures that the code cache is invalidated and not reused when V8 flags that affect compilation are changed.

12. **Cached Data Integrity:** Tests verify the integrity of the cached data, including compatibility checks and checks for bit flips or corruption.

13. **Harmony Scoping (let/const):**  A test specifically looks at how the serializer handles scripts using ES6 scoping features (`let`).

14. **Incremental Marking (Garbage Collection):** Several tests explore the interaction of code serialization with the incremental marking garbage collection process, including scenarios with large objects and weak cells.

15. **Error Handling during Snapshot Creation:** There are tests related to `SnapshotCreator` which checks if it handles exceptions gracefully even if a snapshot blob isn't created.

**JavaScript Examples:**

Here are some JavaScript examples that relate to the concepts being tested in the C++ code:

* **Basic Caching:**

```javascript
// First run (compilation and caching)
function add(a, b) {
  return a + b;
}
add(1, 2);

// Subsequent runs (cache reuse)
function add(a, b) {
  return a + b;
}
add(3, 4);
```

* **Profiler Influence:** When the V8 profiler is enabled, it needs accurate source location information. The tests ensure that even after deserialization, this information is available. In JavaScript, you might enable profiling via command-line flags or DevTools.

* **Host-Defined Options:** While not directly exposed in standard JavaScript, V8 allows embedding applications to provide custom options that can affect script compilation. The tests verify that these options are considered for cache lookups.

* **Internalized Strings:**

```javascript
let str1 = "hello";
let str2 = "hello";
// V8 might internalize str1 and str2, making them refer to the same memory location.
```

* **External Strings:** This is less common in typical JavaScript but relevant for embedding scenarios where string data might be managed externally.

* **Cross-Isolate Usage:**

```javascript
// Imagine two separate V8 instances (isolates)
// You could compile a function in one isolate and then,
// using the serialized cache, run it in the other.
```

* **`eval` and Context Dependencies:**

```javascript
function outer() {
  let localVar = "secret";
  function inner(code) {
    eval(code); // The evaluated code might access 'localVar'
    return localVar;
  }
  return inner;
}

let myInner = outer();
myInner(''); // Accesses the 'localVar' from the outer function's scope.
```

* **`let` Scoping:**

```javascript
'use strict';
let message = "hello";

function greet() {
  let message = "hi"; // Different 'message' in the function scope
  console.log(message);
}

greet(); // Output: "hi"
console.log(message); // Output: "hello"
```

In essence, this C++ code thoroughly tests the serialization and deserialization mechanisms in V8, ensuring that cached JavaScript code can be reliably stored, retrieved, and executed in various scenarios and across different V8 instances. It verifies the correctness and robustness of the code caching infrastructure.
This C++ code file (`v8/test/cctest/test-serialize.cc`, part 2 of 4) continues to test the **serialization and deserialization of JavaScript code** within the V8 engine. It focuses on verifying the correctness and robustness of V8's code caching mechanism under various conditions.

Here's a breakdown of the functionality demonstrated in this part:

* **Code Caching with Profiler Enabled:** The `TEST(CodeSerializerWithProfiler)` specifically checks if source position information is correctly preserved and available after deserialization when the V8 profiler is active. This is important for debugging and performance analysis.

* **Basic Code Serialization and Deserialization:** The `TEST(CodeSerializerOnePlusOne)` and related tests (`TestCodeSerializerOnePlusOneImpl`, `CodeSerializerOnePlusOneWithInterpretedFramesNativeStack`, `CodeSerializerOnePlusOneWithDebugger`, `CodeSerializerOnePlusOneWithBlockCoverage`) test a very simple JavaScript expression ("1 + 1") to ensure the fundamental serialization and deserialization process works correctly. They also test how different configurations (interpreted frames, debugger presence, block coverage) affect the process.

* **Compilation Cache Promotion and Lookups:** The `TEST(CodeSerializerPromotedToCompilationCache)` delves into how compiled code is stored and retrieved from the compilation cache. It tests various scenarios for looking up cached code based on factors like:
    * **Identical source code:**  Cached code should be found.
    * **Equal but not identical source code strings:** Cached code should still be found.
    * **Different source code:** Cached code should not be found.
    * **Different script details (name, position, language mode, options):** Cached code should not be found.
    * **Host-defined options:**  It verifies that custom host options are considered during cache lookups.

* **Caching Compiled Functions:** The `TEST(CompileFunctionCompilationCache)` focuses on how individual JavaScript functions (not just top-level scripts) are cached. It tests cache lookups based on:
    * **Function arguments:** Changes in arguments should invalidate the cache.
    * **Host-defined options:** Custom options are considered for function caching.
    * **Source code and script details:**  Similar to script caching, changes in these invalidate the function cache.

* **Serialization of Internalized Strings:**  `TEST(CodeSerializerInternalizedString)` checks if strings that are "internalized" (stored only once in memory if identical) are handled correctly during serialization and deserialization. It ensures that the deserialized code uses the same internalized string object.

* **Handling Large Code Objects:** `TEST(CodeSerializerLargeCodeObject)` and `TEST(CodeSerializerLargeCodeObjectWithIncrementalMarking)` verify that the serialization process can handle scripts that generate large amounts of compiled code. The incremental marking test specifically checks for issues that might arise during garbage collection while deserializing large code objects.

* **Serialization of Large Strings:** `TEST(CodeSerializerLargeStrings)` and `TEST(CodeSerializerThreeBigStrings)` test the serialization of scripts containing very large string literals. It verifies that these large strings are handled efficiently and don't lead to excessive cache sizes.

* **Serialization of External Strings:** `TEST(CodeSerializerExternalString)` and `TEST(CodeSerializerLargeExternalString)` test how strings whose content is stored outside of V8's heap (external strings) are serialized. This is important for embedding scenarios where strings might be managed by the host application.

* **Serialization of External Script Names:** `TEST(CodeSerializerExternalScriptName)` ensures that when a script has an external name (a string managed outside V8), this name is correctly serialized and restored.

* **Cross-Isolate Code Caching:** The `TEST(CodeSerializerIsolates)`, `TEST(CodeSerializerIsolatesEager)`, and `TEST(CodeSerializerAfterExecute)` tests demonstrate how serialized code can be shared between different V8 isolates (independent instances of the V8 engine). This is a key feature for improving startup time and sharing code across contexts. They test different caching strategies (lazy, eager, after execute).

* **Handling Context Dependencies:** `TEST(CodeSerializerEmptyContextDependency)` tests a scenario involving `eval` and how serialization handles dependencies on the surrounding context.

* **Code Cache Invalidation on Flag Changes:** `TEST(CodeSerializerFlagChange)` verifies that the code cache is correctly invalidated when V8 flags that affect compilation are changed. This prevents using cached code compiled under different settings.

* **Cached Data Compatibility Checks:** `TEST(CachedDataCompatibilityCheck)` tests the mechanism that verifies if a cached data blob is compatible with the current V8 version and configuration. It simulates incompatible scenarios to ensure the checks work.

* **Integrity of Cached Data:** `TEST(CodeSerializerBitFlip)` checks the robustness of the serialization process by intentionally corrupting the cached data (flipping a bit) and verifying that V8 detects this corruption and rejects the cache.

* **Serialization with Harmony (ES6) Scoping:** `TEST(CodeSerializerWithHarmonyScoping)` specifically tests the serialization of code that uses ES6 features like `let`, ensuring that the scoping rules are preserved after deserialization, even if scripts are run in a different order initially.

* **Interaction with Incremental Marking GC:** `TEST(Regress503552)` and related tests ensure that the code serialization process interacts correctly with V8's incremental marking garbage collector, particularly when dealing with weak references.

* **Merging Deserialized Scripts:** `TEST(CodeSerializerMergeDeserializedScript)` and `TEST(CodeSerializerMergeDeserializedScriptRetainingToplevelSfi)` test how V8 handles deserializing a script when a script with the same source already exists in the isolate. It checks if the existing script object can be reused and how the top-level SharedFunctionInfo is handled.

* **Snapshot Creation Error Handling:** `UNINITIALIZED_TEST(SnapshotCreatorBlobNotCreated)` and `UNINITIALIZED_TEST(SnapshotCreatorMultipleContexts)` (the latter is incomplete in the provided snippet) focus on the `SnapshotCreator` API, which is used to create a serialized representation of the initial V8 heap. These tests seem to check how the `SnapshotCreator` handles errors or specific scenarios like creating multiple contexts.

**Relationship to JavaScript Functionality (with Examples):**

The core functionality being tested is directly related to how V8 compiles and executes JavaScript code efficiently. Code caching is a crucial optimization that avoids recompiling the same code repeatedly.

* **Basic Execution and Caching:** When you run a JavaScript function multiple times, V8 might compile and cache it after the first execution. Subsequent calls can then use the cached compiled code, making execution faster.

```javascript
function greet(name) {
  console.log("Hello, " + name + "!");
}

greet("Alice"); // Compilation might happen here
greet("Bob");   // Likely uses cached code
```

* **Profiler Accuracy:** When you use browser developer tools or Node.js profilers to analyze your JavaScript code's performance, the profiler relies on accurate source position information. The tests ensure this information is preserved even when code is loaded from a cache.

* **Module Systems and Caching:**  When you use module systems (like ES modules or CommonJS in Node.js), the JavaScript engine often caches the compiled code of modules to speed up imports. The C++ tests are validating the underlying mechanisms that make this possible.

* **`eval()` and Contexts:** The `eval()` function executes a string of JavaScript code within the current scope. The tests related to context dependencies ensure that when code containing `eval()` is cached and restored, it still behaves correctly with respect to the surrounding variables and functions.

```javascript
function outer() {
  let message = "secret";
  function inner(code) {
    eval(code); // Might access 'message'
    return message;
  }
  return inner;
}

let revealSecret = outer();
console.log(revealSecret("")); // Accesses 'message' from outer scope
```

* **Large Strings:**  JavaScript can handle very large strings. The tests ensure that V8 can efficiently serialize and deserialize scripts that contain these large strings, which is important for applications that process text data.

```javascript
let longText = "a".repeat(1000000);
function processText(text) {
  // ... some operation on longText ...
}
processText(longText);
```

In summary, this part of the `test-serialize.cc` file rigorously tests the core mechanisms that V8 uses to optimize JavaScript execution through code caching. It ensures that this caching is reliable, handles various JavaScript features correctly, and works consistently across different V8 configurations and isolates.

Prompt: 
```
这是目录为v8/test/cctest/test-serialize.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
TEST(CodeSerializerWithProfiler) {
  v8_flags.enable_lazy_source_positions = true;
  v8_flags.stress_lazy_source_positions = false;

  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  const char* source = "1 + 1";

  Handle<String> orig_source = isolate->factory()
                                   ->NewStringFromUtf8(base::CStrVector(source))
                                   .ToHandleChecked();
  Handle<String> copy_source = isolate->factory()
                                   ->NewStringFromUtf8(base::CStrVector(source))
                                   .ToHandleChecked();
  CHECK(!orig_source.is_identical_to(copy_source));
  CHECK(orig_source->Equals(*copy_source));

  AlignedCachedData* cache = nullptr;

  ScriptDetails default_script_details;
  DirectHandle<SharedFunctionInfo> orig = CompileScriptAndProduceCache(
      isolate, orig_source, default_script_details, &cache,
      v8::ScriptCompiler::kNoCompileOptions);

  CHECK(!orig->GetBytecodeArray(isolate)->HasSourcePositionTable());

  isolate->SetIsProfiling(true);

  // This does not assert that no compilation can happen as source position
  // collection could trigger it.
  DirectHandle<SharedFunctionInfo> copy =
      CompileScript(isolate, copy_source, default_script_details, cache,
                    v8::ScriptCompiler::kConsumeCodeCache);

  // Since the profiler is now enabled, source positions should be collected
  // after deserialization.
  CHECK(copy->GetBytecodeArray(isolate)->HasSourcePositionTable());

  delete cache;
}

void TestCodeSerializerOnePlusOneImpl(bool verify_builtins_count = true) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  const char* source = "1 + 1";

  Handle<String> orig_source = isolate->factory()
                                   ->NewStringFromUtf8(base::CStrVector(source))
                                   .ToHandleChecked();
  Handle<String> copy_source = isolate->factory()
                                   ->NewStringFromUtf8(base::CStrVector(source))
                                   .ToHandleChecked();
  CHECK(!orig_source.is_identical_to(copy_source));
  CHECK(orig_source->Equals(*copy_source));

  AlignedCachedData* cache = nullptr;

  ScriptDetails default_script_details;
  DirectHandle<SharedFunctionInfo> orig = CompileScriptAndProduceCache(
      isolate, orig_source, default_script_details, &cache,
      v8::ScriptCompiler::kNoCompileOptions);

  int builtins_count = CountBuiltins();

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, copy_source, default_script_details, cache,
                         v8::ScriptCompiler::kConsumeCodeCache);
  }

  CHECK_NE(*orig, *copy);
  CHECK(Cast<String>(Cast<Script>(copy->script())->source())
            ->Equals(*copy_source));

  Handle<JSFunction> copy_fun =
      Factory::JSFunctionBuilder{isolate, copy, isolate->native_context()}
          .Build();
  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  DirectHandle<Object> copy_result =
      Execution::CallScript(isolate, copy_fun, global,
                            isolate->factory()->empty_fixed_array())
          .ToHandleChecked();
  CHECK_EQ(2, Cast<Smi>(*copy_result).value());

  if (verify_builtins_count) CHECK_EQ(builtins_count, CountBuiltins());

  delete cache;
}

TEST(CodeSerializerOnePlusOne) { TestCodeSerializerOnePlusOneImpl(); }

// See bug v8:9122
TEST(CodeSerializerOnePlusOneWithInterpretedFramesNativeStack) {
  v8_flags.interpreted_frames_native_stack = true;
  // We pass false because this test will create IET copies (which are
  // builtins).
  TestCodeSerializerOnePlusOneImpl(false);
}

TEST(CodeSerializerOnePlusOneWithDebugger) {
  v8::HandleScope scope(CcTest::isolate());
  static v8::debug::DebugDelegate dummy_delegate;
  v8::debug::SetDebugDelegate(CcTest::isolate(), &dummy_delegate);
  TestCodeSerializerOnePlusOneImpl();
}

TEST(CodeSerializerOnePlusOneWithBlockCoverage) {
  v8::HandleScope scope(CcTest::isolate());
  static v8::debug::DebugDelegate dummy_delegate;
  v8::debug::SetDebugDelegate(CcTest::isolate(), &dummy_delegate);
  Coverage::SelectMode(CcTest::i_isolate(), debug::CoverageMode::kBlockCount);
  TestCodeSerializerOnePlusOneImpl();
}

TEST(CodeSerializerPromotedToCompilationCache) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();

  v8::HandleScope scope(CcTest::isolate());

  const char* source = "1 + 1";

  Handle<String> src = isolate->factory()->NewStringFromAsciiChecked(source);
  AlignedCachedData* cache = nullptr;

  Handle<FixedArray> default_host_defined_options =
      isolate->factory()->NewFixedArray(2);
  default_host_defined_options->set(0, Smi::FromInt(0));
  const char* default_host_defined_option_1_string = "custom string";
  DirectHandle<String> default_host_defined_option_1 =
      isolate->factory()->NewStringFromAsciiChecked(
          default_host_defined_option_1_string);
  default_host_defined_options->set(1, *default_host_defined_option_1);

  ScriptDetails default_script_details(src);
  default_script_details.host_defined_options = default_host_defined_options;
  CompileScriptAndProduceCache(isolate, src, default_script_details, &cache,
                               v8::ScriptCompiler::kNoCompileOptions,
                               ScriptCompiler::InMemoryCacheResult::kMiss);

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, src, default_script_details, cache,
                         v8::ScriptCompiler::kConsumeCodeCache,
                         ScriptCompiler::InMemoryCacheResult::kHit);
  }

  {
    ScriptDetails script_details(src);
    script_details.host_defined_options =
        default_script_details.host_defined_options;
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK_EQ(*lookup_result.toplevel_sfi().ToHandleChecked(), *copy);
  }

  {
    // Lookup with strictly equal host_defined_options should succeed:
    ScriptDetails script_details(src);
    Handle<FixedArray> host_defined_options =
        isolate->factory()->NewFixedArray(2);
    host_defined_options->set(0, default_host_defined_options->get(0));
    DirectHandle<String> host_defined_option_1 =
        isolate->factory()->NewStringFromAsciiChecked(
            default_host_defined_option_1_string);
    host_defined_options->set(1, *host_defined_option_1);
    script_details.host_defined_options = host_defined_options;
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK_EQ(*lookup_result.toplevel_sfi().ToHandleChecked(), *copy);
  }

  {
    // Lookup with different string with same contents should succeed:
    ScriptDetails script_details(
        isolate->factory()->NewStringFromAsciiChecked(source));
    script_details.host_defined_options =
        default_script_details.host_defined_options;
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK_EQ(*lookup_result.toplevel_sfi().ToHandleChecked(), *copy);
  }

  {
    // Lookup with different name string should fail:
    ScriptDetails script_details(
        isolate->factory()->NewStringFromAsciiChecked("other"));
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different position should fail:
    ScriptDetails script_details(src);
    script_details.line_offset = 0xFF;
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different position should fail:
    ScriptDetails script_details(src);
    script_details.column_offset = 0xFF;
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different language mode should fail:
    ScriptDetails script_details(src);
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kStrict);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different script_options should fail
    ScriptOriginOptions origin_options(false, true);
    CHECK_NE(ScriptOriginOptions().Flags(), origin_options.Flags());
    ScriptDetails script_details(src, origin_options);
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different host_defined_options should fail:
    ScriptDetails script_details(src);
    script_details.host_defined_options = isolate->factory()->NewFixedArray(5);
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  // Compile the script again with different options.
  ScriptDetails alternative_script_details(src);
  ScriptCompiler::CompilationDetails compilation_details;
  DirectHandle<SharedFunctionInfo> alternative_toplevel_sfi =
      Compiler::GetSharedFunctionInfoForScript(
          isolate, src, alternative_script_details,
          ScriptCompiler::kNoCompileOptions, ScriptCompiler::kNoCacheNoReason,
          NOT_NATIVES_CODE, &compilation_details)
          .ToHandleChecked();
  CHECK_NE(*copy, *alternative_toplevel_sfi);
  CHECK_EQ(compilation_details.in_memory_cache_result,
           ScriptCompiler::InMemoryCacheResult::kMiss);

  {
    // The original script can still be found.
    ScriptDetails script_details(src);
    script_details.host_defined_options =
        default_script_details.host_defined_options;
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK_EQ(*lookup_result.toplevel_sfi().ToHandleChecked(), *copy);
  }

  {
    // The new script can also be found.
    ScriptDetails script_details(src);
    auto lookup_result = isolate->compilation_cache()->LookupScript(
        src, script_details, LanguageMode::kSloppy);
    CHECK_EQ(*lookup_result.toplevel_sfi().ToHandleChecked(),
             *alternative_toplevel_sfi);
  }

  delete cache;
}

TEST(CompileFunctionCompilationCache) {
  LocalContext env;
  Isolate* i_isolate = CcTest::i_isolate();

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  const char* source = "a + b";
  v8::Local<v8::String> src = v8_str(source);
  v8::Local<v8::String> resource_name = v8_str("test");
  Handle<String> i_src = Utils::OpenHandle(*src);
  Handle<String> i_resource_name = Utils::OpenHandle(*resource_name);

  v8::Local<v8::PrimitiveArray> host_defined_options =
      v8::PrimitiveArray::New(isolate, 1);
  v8::Local<v8::Symbol> sym = v8::Symbol::New(isolate, v8_str("hdo"));
  host_defined_options->Set(isolate, 0, sym);

  Handle<FixedArray> i_host_defined_options =
      i_isolate->factory()->NewFixedArray(1);
  DirectHandle<Symbol> i_sym = Utils::OpenDirectHandle(*sym);
  i_host_defined_options->set(0, *i_sym);

  v8::ScriptOrigin origin(resource_name, 0, 0, false, -1,
                          v8::Local<v8::Value>(), false, false, false,
                          host_defined_options);

  std::vector<const char*> raw_args = {"a", "b"};

  std::vector<v8::Local<v8::String>> args;
  for (size_t i = 0; i < raw_args.size(); ++i) {
    args.push_back(v8_str(raw_args[i]));
  }
  Handle<FixedArray> i_args =
      i_isolate->factory()->NewFixedArray(static_cast<int>(args.size()));
  for (size_t i = 0; i < raw_args.size(); ++i) {
    DirectHandle<String> arg =
        i_isolate->factory()->NewStringFromAsciiChecked(raw_args[i]);
    i_args->set(static_cast<int>(i), *arg);
  }

  DirectHandle<SharedFunctionInfo> sfi;
  v8::ScriptCompiler::CachedData* cache;
  {
    v8::ScriptCompiler::Source script_source(src, origin);
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(
            env.local(), &script_source, args.size(), args.data(), 0, nullptr,
            v8::ScriptCompiler::kEagerCompile)
            .ToLocalChecked();
    cache = v8::ScriptCompiler::CreateCodeCacheForFunction(fun);
    auto js_function = Cast<JSFunction>(Utils::OpenDirectHandle(*fun));
    sfi = direct_handle(js_function->shared(), i_isolate);
  }

  {
    DisallowCompilation no_compile_expected(i_isolate);
    v8::ScriptCompiler::Source script_source(src, origin, cache);
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(
            env.local(), &script_source, args.size(), args.data(), 0, nullptr,
            v8::ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();
    auto js_function = Cast<JSFunction>(Utils::OpenDirectHandle(*fun));
    CHECK_EQ(js_function->shared(), *sfi);
  }

  auto CopyScriptDetails = [&](ScriptOriginOptions origin_options =
                                   v8::ScriptOriginOptions()) {
    ScriptDetails script_details(i_resource_name, origin_options);
    script_details.wrapped_arguments = i_args;
    script_details.host_defined_options = i_host_defined_options;
    return script_details;
  };

  {
    // Lookup with the same wrapped arguments should succeed.
    ScriptDetails script_details = CopyScriptDetails();
    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK_EQ(*lookup_result.toplevel_sfi().ToHandleChecked(), *sfi);
  }

  {
    // Lookup with empty wrapped arguments and host-defined options should fail:
    ScriptDetails script_details = CopyScriptDetails();
    script_details.wrapped_arguments = kNullMaybeHandle;

    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different wrapped arguments should fail:
    Handle<FixedArray> new_args = i_isolate->factory()->NewFixedArray(3);
    DirectHandle<String> arg_1 =
        i_isolate->factory()->NewStringFromAsciiChecked("a");
    DirectHandle<String> arg_2 =
        i_isolate->factory()->NewStringFromAsciiChecked("b");
    DirectHandle<String> arg_3 =
        i_isolate->factory()->NewStringFromAsciiChecked("c");
    new_args->set(0, *arg_1);
    new_args->set(1, *arg_2);
    new_args->set(2, *arg_3);
    ScriptDetails script_details = CopyScriptDetails();
    script_details.wrapped_arguments = new_args;

    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different host_defined_options should fail:
    Handle<FixedArray> new_options = i_isolate->factory()->NewFixedArray(1);
    DirectHandle<Symbol> new_sym = i_isolate->factory()->NewSymbol();
    new_options->set(0, *new_sym);
    ScriptDetails script_details = CopyScriptDetails();
    script_details.host_defined_options = new_options;

    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different string with same contents should succeed:
    ScriptDetails script_details = CopyScriptDetails();

    Handle<String> new_src =
        i_isolate->factory()->NewStringFromAsciiChecked(source);
    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        new_src, script_details, LanguageMode::kSloppy);
    CHECK_EQ(*lookup_result.toplevel_sfi().ToHandleChecked(), *sfi);
  }

  {
    // Lookup with different content should fail;
    ScriptDetails script_details = CopyScriptDetails();

    Handle<String> new_src =
        i_isolate->factory()->NewStringFromAsciiChecked("a + b + 1");
    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        new_src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different name string should fail:
    ScriptDetails script_details = CopyScriptDetails();
    script_details.name_obj =
        i_isolate->factory()->NewStringFromAsciiChecked("other");

    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different position should fail:
    ScriptDetails script_details = CopyScriptDetails();
    script_details.line_offset = 0xFF;

    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different position should fail:
    ScriptDetails script_details = CopyScriptDetails();
    script_details.column_offset = 0xFF;

    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different language mode should fail:
    ScriptDetails script_details = CopyScriptDetails();

    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kStrict);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  {
    // Lookup with different script_options should fail
    ScriptOriginOptions origin_options(false, true);
    CHECK_NE(ScriptOriginOptions().Flags(), origin_options.Flags());
    ScriptDetails script_details = CopyScriptDetails(origin_options);

    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK(lookup_result.script().is_null() &&
          lookup_result.toplevel_sfi().is_null());
  }

  // Compile the function again with different options.
  DirectHandle<SharedFunctionInfo> other_sfi;
  v8::Local<v8::Symbol> other_sym;
  {
    v8::Local<v8::PrimitiveArray> other_options =
        v8::PrimitiveArray::New(isolate, 1);
    other_sym = v8::Symbol::New(isolate, v8_str("hdo2"));
    other_options->Set(isolate, 0, other_sym);
    v8::ScriptOrigin other_origin(resource_name, 0, 0, false, -1,
                                  v8::Local<v8::Value>(), false, false, false,
                                  other_options);

    v8::ScriptCompiler::Source script_source(src, other_origin);
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(
            env.local(), &script_source, args.size(), args.data(), 0, nullptr,
            v8::ScriptCompiler::kNoCompileOptions,
            ScriptCompiler::kNoCacheNoReason)
            .ToLocalChecked();
    auto js_function = Cast<JSFunction>(Utils::OpenDirectHandle(*fun));
    other_sfi = direct_handle(js_function->shared(), i_isolate);
    CHECK_NE(*other_sfi, *sfi);
  }

  {
    // The original script can still be found.
    ScriptDetails script_details = CopyScriptDetails();
    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK_EQ(*lookup_result.toplevel_sfi().ToHandleChecked(), *sfi);
  }

  {
    // The new script can also be found.
    Handle<FixedArray> other_options = i_isolate->factory()->NewFixedArray(1);
    DirectHandle<Symbol> i_other_sym = Utils::OpenDirectHandle(*other_sym);
    other_options->set(0, *i_other_sym);
    ScriptDetails script_details = CopyScriptDetails();
    script_details.host_defined_options = other_options;

    auto lookup_result = i_isolate->compilation_cache()->LookupScript(
        i_src, script_details, LanguageMode::kSloppy);
    CHECK_EQ(*lookup_result.toplevel_sfi().ToHandleChecked(), *other_sfi);
  }
}

TEST(CodeSerializerInternalizedString) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  const char* source = "'string1'";

  Handle<String> orig_source = isolate->factory()
                                   ->NewStringFromUtf8(base::CStrVector(source))
                                   .ToHandleChecked();
  Handle<String> copy_source = isolate->factory()
                                   ->NewStringFromUtf8(base::CStrVector(source))
                                   .ToHandleChecked();
  CHECK(!orig_source.is_identical_to(copy_source));
  CHECK(orig_source->Equals(*copy_source));

  Handle<JSObject> global(isolate->context()->global_object(), isolate);

  i::AlignedCachedData* cached_data = nullptr;
  DirectHandle<SharedFunctionInfo> orig = CompileScriptAndProduceCache(
      isolate, orig_source, ScriptDetails(), &cached_data,
      v8::ScriptCompiler::kNoCompileOptions);
  Handle<JSFunction> orig_fun =
      Factory::JSFunctionBuilder{isolate, orig, isolate->native_context()}
          .Build();
  Handle<Object> orig_result =
      Execution::CallScript(isolate, orig_fun, global,
                            isolate->factory()->empty_fixed_array())
          .ToHandleChecked();
  CHECK(IsInternalizedString(*orig_result));

  int builtins_count = CountBuiltins();

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, copy_source, ScriptDetails(), cached_data,
                         v8::ScriptCompiler::kConsumeCodeCache);
  }
  CHECK_NE(*orig, *copy);
  CHECK(Cast<String>(Cast<Script>(copy->script())->source())
            ->Equals(*copy_source));

  Handle<JSFunction> copy_fun =
      Factory::JSFunctionBuilder{isolate, copy, isolate->native_context()}
          .Build();
  CHECK_NE(*orig_fun, *copy_fun);
  Handle<Object> copy_result =
      Execution::CallScript(isolate, copy_fun, global,
                            isolate->factory()->empty_fixed_array())
          .ToHandleChecked();
  CHECK(orig_result.is_identical_to(copy_result));
  DirectHandle<String> expected =
      isolate->factory()->NewStringFromAsciiChecked("string1");

  CHECK(Cast<String>(copy_result)->Equals(*expected));
  CHECK_EQ(builtins_count, CountBuiltins());

  delete cached_data;
}

TEST(CodeSerializerLargeCodeObject) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  // The serializer only tests the shared code, which is always the unoptimized
  // code. Don't even bother generating optimized code to avoid timeouts.
  v8_flags.always_turbofan = false;

  base::Vector<const char> source = ConstructSource(
      base::StaticCharVector("var j=1; if (j == 0) {"),
      base::StaticCharVector(
          "for (let i of Object.prototype) for (let k = 0; k < 0; ++k);"),
      base::StaticCharVector("} j=7; j"), 2000);
  Handle<String> source_str =
      isolate->factory()->NewStringFromUtf8(source).ToHandleChecked();

  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  AlignedCachedData* cache = nullptr;

  DirectHandle<SharedFunctionInfo> orig =
      CompileScriptAndProduceCache(isolate, source_str, ScriptDetails(), &cache,
                                   v8::ScriptCompiler::kNoCompileOptions);

  // The object may end up in LO_SPACE or TRUSTED_LO_SPACE depending on whether
  // the sandbox is enabled.
  CHECK(
      isolate->heap()->InSpace(orig->abstract_code(isolate), LO_SPACE) ||
      isolate->heap()->InSpace(orig->abstract_code(isolate), TRUSTED_LO_SPACE));

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, source_str, ScriptDetails(), cache,
                         v8::ScriptCompiler::kConsumeCodeCache);
  }
  CHECK_NE(*orig, *copy);

  Handle<JSFunction> copy_fun =
      Factory::JSFunctionBuilder{isolate, copy, isolate->native_context()}
          .Build();

  DirectHandle<Object> copy_result =
      Execution::CallScript(isolate, copy_fun, global,
                            isolate->factory()->empty_fixed_array())
          .ToHandleChecked();

  int result_int;
  CHECK(Object::ToInt32(*copy_result, &result_int));
  CHECK_EQ(7, result_int);

  delete cache;
  source.Dispose();
}

TEST(CodeSerializerLargeCodeObjectWithIncrementalMarking) {
  if (!v8_flags.incremental_marking) return;
  if (!v8_flags.compact) return;
  ManualGCScope manual_gc_scope;
  v8_flags.always_turbofan = false;
  const char* filter_flag = "--turbo-filter=NOTHING";
  FlagList::SetFlagsFromString(filter_flag, strlen(filter_flag));
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  base::Vector<const char> source = ConstructSource(
      base::StaticCharVector("var j=1; if (j == 0) {"),
      base::StaticCharVector("for (var i = 0; i < Object.prototype; i++);"),
      base::StaticCharVector("} j=7; var s = 'happy_hippo'; j"), 20000);
  Handle<String> source_str =
      isolate->factory()->NewStringFromUtf8(source).ToHandleChecked();

  // Create a string on an evacuation candidate in old space.
  DirectHandle<String> moving_object;
  PageMetadata* ec_page;
  {
    AlwaysAllocateScopeForTesting always_allocate(heap);
    heap::SimulateFullSpace(heap->old_space());
    moving_object = isolate->factory()->InternalizeString(
        isolate->factory()->NewStringFromAsciiChecked("happy_hippo"));
    ec_page = PageMetadata::FromHeapObject(*moving_object);
  }

  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  AlignedCachedData* cache = nullptr;

  DirectHandle<SharedFunctionInfo> orig =
      CompileScriptAndProduceCache(isolate, source_str, ScriptDetails(), &cache,
                                   v8::ScriptCompiler::kNoCompileOptions);

  // The object may end up in LO_SPACE or TRUSTED_LO_SPACE depending on whether
  // the sandbox is enabled.
  CHECK(heap->InSpace(orig->abstract_code(isolate), LO_SPACE) ||
        heap->InSpace(orig->abstract_code(isolate), TRUSTED_LO_SPACE));

  // Pretend that incremental marking is on when deserialization begins.
  heap::ForceEvacuationCandidate(ec_page);
  heap::SimulateIncrementalMarking(heap, false);
  IncrementalMarking* marking = heap->incremental_marking();
  CHECK(marking->black_allocation());
  CHECK(marking->IsCompacting());
  CHECK(MarkCompactCollector::IsOnEvacuationCandidate(*moving_object));

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, source_str, ScriptDetails(), cache,
                         v8::ScriptCompiler::kConsumeCodeCache);
  }
  CHECK_NE(*orig, *copy);

  // We should have missed a write barrier. Complete incremental marking
  // to flush out the bug.
  heap::SimulateIncrementalMarking(heap, true);
  heap::InvokeMajorGC(heap);

  Handle<JSFunction> copy_fun =
      Factory::JSFunctionBuilder{isolate, copy, isolate->native_context()}
          .Build();

  DirectHandle<Object> copy_result =
      Execution::CallScript(isolate, copy_fun, global,
                            isolate->factory()->empty_fixed_array())
          .ToHandleChecked();

  int result_int;
  CHECK(Object::ToInt32(*copy_result, &result_int));
  CHECK_EQ(7, result_int);

  delete cache;
  source.Dispose();
}

TEST(CodeSerializerLargeStrings) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  Factory* f = isolate->factory();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  base::Vector<const char> source_s = ConstructSource(
      base::StaticCharVector("var s = \""), base::StaticCharVector("abcdef"),
      base::StaticCharVector("\";"), 1000000);
  base::Vector<const char> source_t = ConstructSource(
      base::StaticCharVector("var t = \""), base::StaticCharVector("uvwxyz"),
      base::StaticCharVector("\"; s + t"), 999999);
  Handle<String> source_str =
      f->NewConsString(f->NewStringFromUtf8(source_s).ToHandleChecked(),
                       f->NewStringFromUtf8(source_t).ToHandleChecked())
          .ToHandleChecked();

  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  AlignedCachedData* cache = nullptr;

  DirectHandle<SharedFunctionInfo> orig =
      CompileScriptAndProduceCache(isolate, source_str, ScriptDetails(), &cache,
                                   v8::ScriptCompiler::kNoCompileOptions);

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, source_str, ScriptDetails(), cache,
                         v8::ScriptCompiler::kConsumeCodeCache);
  }
  CHECK_NE(*orig, *copy);

  Handle<JSFunction> copy_fun =
      Factory::JSFunctionBuilder{isolate, copy, isolate->native_context()}
          .Build();

  Handle<Object> copy_result =
      Execution::CallScript(isolate, copy_fun, global,
                            isolate->factory()->empty_fixed_array())
          .ToHandleChecked();

  CHECK_EQ(6 * 1999999, Cast<String>(copy_result)->length());
  DirectHandle<Object> property = JSReceiver::GetDataProperty(
      isolate, isolate->global_object(), f->NewStringFromAsciiChecked("s"));
  CHECK(isolate->heap()->InSpace(Cast<HeapObject>(*property), LO_SPACE));
  property = JSReceiver::GetDataProperty(isolate, isolate->global_object(),
                                         f->NewStringFromAsciiChecked("t"));
  CHECK(isolate->heap()->InSpace(Cast<HeapObject>(*property), LO_SPACE));
// Make sure we do not serialize too much.
#ifdef DEBUG
  CHECK_LT(cache->length(), 24100000);
#else
  // Make sure we don't include the source string.
  CHECK_LT(cache->length(), 13000000);
#endif

  delete cache;
  source_s.Dispose();
  source_t.Dispose();
}

TEST(CodeSerializerThreeBigStrings) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  Factory* f = isolate->factory();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  const int32_t length_of_a = kMaxRegularHeapObjectSize * 2;
  const int32_t length_of_b = kMaxRegularHeapObjectSize / 2;
  const int32_t length_of_c = kMaxRegularHeapObjectSize / 2;

  base::Vector<const char> source_a = ConstructSource(
      base::StaticCharVector("var a = \""), base::StaticCharVector("a"),
      base::StaticCharVector("\";"), length_of_a);
  Handle<String> source_a_str =
      f->NewStringFromUtf8(source_a).ToHandleChecked();

  base::Vector<const char> source_b = ConstructSource(
      base::StaticCharVector("var b = \""), base::StaticCharVector("b"),
      base::StaticCharVector("\";"), length_of_b);
  Handle<String> source_b_str =
      f->NewStringFromUtf8(source_b).ToHandleChecked();

  base::Vector<const char> source_c = ConstructSource(
      base::StaticCharVector("var c = \""), base::StaticCharVector("c"),
      base::StaticCharVector("\";"), length_of_c);
  Handle<String> source_c_str =
      f->NewStringFromUtf8(source_c).ToHandleChecked();

  Handle<String> source_str =
      f->NewConsString(
           f->NewConsString(source_a_str, source_b_str).ToHandleChecked(),
           source_c_str)
          .ToHandleChecked();

  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  AlignedCachedData* cache = nullptr;

  DirectHandle<SharedFunctionInfo> orig =
      CompileScriptAndProduceCache(isolate, source_str, ScriptDetails(), &cache,
                                   v8::ScriptCompiler::kNoCompileOptions);

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, source_str, ScriptDetails(), cache,
                         v8::ScriptCompiler::kConsumeCodeCache);
  }
  CHECK_NE(*orig, *copy);

  Handle<JSFunction> copy_fun =
      Factory::JSFunctionBuilder{isolate, copy, isolate->native_context()}
          .Build();

  USE(Execution::CallScript(isolate, copy_fun, global,
                            isolate->factory()->empty_fixed_array()));

  v8::Maybe<int32_t> result =
      CompileRun("(a + b).length")
          ->Int32Value(CcTest::isolate()->GetCurrentContext());
  CHECK_EQ(length_of_a + length_of_b, result.FromJust());
  result = CompileRun("(b + c).length")
               ->Int32Value(CcTest::isolate()->GetCurrentContext());
  CHECK_EQ(length_of_b + length_of_c, result.FromJust());
  Heap* heap = isolate->heap();
  v8::Local<v8::String> result_str =
      CompileRun("a")
          ->ToString(CcTest::isolate()->GetCurrentContext())
          .ToLocalChecked();
  CHECK(heap->InSpace(*v8::Utils::OpenDirectHandle(*result_str), LO_SPACE));
  result_str = CompileRun("b")
                   ->ToString(CcTest::isolate()->GetCurrentContext())
                   .ToLocalChecked();
  CHECK(heap->InSpace(*v8::Utils::OpenDirectHandle(*result_str), OLD_SPACE));

  result_str = CompileRun("c")
                   ->ToString(CcTest::isolate()->GetCurrentContext())
                   .ToLocalChecked();
  CHECK(heap->InSpace(*v8::Utils::OpenDirectHandle(*result_str), OLD_SPACE));

  delete cache;
  source_a.Dispose();
  source_b.Dispose();
  source_c.Dispose();
}

class SerializerOneByteResource
    : public v8::String::ExternalOneByteStringResource {
 public:
  SerializerOneByteResource(const char* data, size_t length)
      : data_(data), length_(length), dispose_count_(0) {}
  const char* data() const override { return data_; }
  size_t length() const override { return length_; }
  void Dispose() override { dispose_count_++; }
  int dispose_count() { return dispose_count_; }

 private:
  const char* data_;
  size_t length_;
  int dispose_count_;
};

class SerializerTwoByteResource : public v8::String::ExternalStringResource {
 public:
  SerializerTwoByteResource(const uint16_t* data, size_t length)
      : data_(data), length_(length), dispose_count_(0) {}
  ~SerializerTwoByteResource() override { DeleteArray<const uint16_t>(data_); }

  const uint16_t* data() const override { return data_; }
  size_t length() const override { return length_; }
  void Dispose() override { dispose_count_++; }
  int dispose_count() { return dispose_count_; }

 private:
  const uint16_t* data_;
  size_t length_;
  int dispose_count_;
};

TEST(CodeSerializerExternalString) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  // Obtain external internalized one-byte string.
  SerializerOneByteResource one_byte_resource("one_byte", 8);
  Handle<String> one_byte_string =
      isolate->factory()->NewStringFromAsciiChecked("one_byte");
  one_byte_string = isolate->factory()->InternalizeString(one_byte_string);
  one_byte_string->MakeExternal(isolate, &one_byte_resource);
  CHECK(IsExternalOneByteString(*one_byte_string));
  CHECK(IsInternalizedString(*one_byte_string));

  // Obtain external internalized two-byte string.
  size_t two_byte_length;
  uint16_t* two_byte = AsciiToTwoByteString(u"two_byte 🤓", &two_byte_length);
  SerializerTwoByteResource two_byte_resource(two_byte, two_byte_length);
  Handle<String> two_byte_string =
      isolate->factory()
          ->NewStringFromTwoByte(base::VectorOf(two_byte, two_byte_length))
          .ToHandleChecked();
  two_byte_string = isolate->factory()->InternalizeString(two_byte_string);
  two_byte_string->MakeExternal(isolate, &two_byte_resource);
  CHECK(IsExternalTwoByteString(*two_byte_string));
  CHECK(IsInternalizedString(*two_byte_string));

  const char* source =
      "var o = {}               \n"
      "o.one_byte = 7;          \n"
      "o.two_byte = 8;          \n"
      "o.one_byte + o.two_byte; \n";
  Handle<String> source_string =
      isolate->factory()
          ->NewStringFromUtf8(base::CStrVector(source))
          .ToHandleChecked();

  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  AlignedCachedData* cache = nullptr;

  DirectHandle<SharedFunctionInfo> orig = CompileScriptAndProduceCache(
      isolate, source_string, ScriptDetails(), &cache,
      v8::ScriptCompiler::kNoCompileOptions);

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, source_string, ScriptDetails(), cache,
                         v8::ScriptCompiler::kConsumeCodeCache);
  }
  CHECK_NE(*orig, *copy);

  Handle<JSFunction> copy_fun =
      Factory::JSFunctionBuilder{isolate, copy, isolate->native_context()}
          .Build();

  DirectHandle<Object> copy_result =
      Execution::CallScript(isolate, copy_fun, global,
                            isolate->factory()->empty_fixed_array())
          .ToHandleChecked();

  CHECK_EQ(15.0, Object::NumberValue(*copy_result));

  // This avoids the GC from trying to free stack allocated resources.
  i::Cast<i::ExternalOneByteString>(one_byte_string)
      ->SetResource(isolate, nullptr);
  i::Cast<i::ExternalTwoByteString>(two_byte_string)
      ->SetResource(isolate, nullptr);
  delete cache;
}

TEST(CodeSerializerLargeExternalString) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  Factory* f = isolate->factory();

  v8::HandleScope scope(CcTest::isolate());

  // Create a huge external internalized string to use as variable name.
  base::Vector<const char> string = ConstructSource(
      base::StaticCharVector(""), base::StaticCharVector("abcdef"),
      base::StaticCharVector(""), 999999);
  Handle<String> name = f->NewStringFromUtf8(string).ToHandleChecked();
  SerializerOneByteResource one_byte_resource(
      reinterpret_cast<const char*>(string.begin()), string.length());
  name = f->InternalizeString(name);
  name->MakeExternal(isolate, &one_byte_resource);
  CHECK(IsExternalOneByteString(*name));
  CHECK(IsInternalizedString(*name));
  CHECK(isolate->heap()->InSpace(*name, LO_SPACE));

  // Create the source, which is "var <literal> = 42; <literal>".
  Handle<String> source_str =
      f->NewConsString(
           f->NewConsString(f->NewStringFromAsciiChecked("var "), name)
               .ToHandleChecked(),
           f->NewConsString(f->NewStringFromAsciiChecked(" = 42; "), name)
               .ToHandleChecked())
          .ToHandleChecked();

  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  AlignedCachedData* cache = nullptr;

  DirectHandle<SharedFunctionInfo> orig =
      CompileScriptAndProduceCache(isolate, source_str, ScriptDetails(), &cache,
                                   v8::ScriptCompiler::kNoCompileOptions);

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, source_str, ScriptDetails(), cache,
                         v8::ScriptCompiler::kConsumeCodeCache);
  }
  CHECK_NE(*orig, *copy);

  Handle<JSFunction> copy_fun =
      Factory::JSFunctionBuilder{isolate, copy, isolate->native_context()}
          .Build();

  DirectHandle<Object> copy_result =
      Execution::CallScript(isolate, copy_fun, global,
                            isolate->factory()->empty_fixed_array())
          .ToHandleChecked();

  CHECK_EQ(42.0, Object::NumberValue(*copy_result));

  // This avoids the GC from trying to free stack allocated resources.
  i::Cast<i::ExternalOneByteString>(name)->SetResource(isolate, nullptr);
  delete cache;
  string.Dispose();
}

TEST(CodeSerializerExternalScriptName) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  Factory* f = isolate->factory();

  v8::HandleScope scope(CcTest::isolate());

  const char* source =
      "var a = [1, 2, 3, 4];"
      "a.reduce(function(x, y) { return x + y }, 0)";

  Handle<String> source_string =
      f->NewStringFromUtf8(base::CStrVector(source)).ToHandleChecked();

  const SerializerOneByteResource one_byte_resource("one_byte", 8);
  Handle<String> name =
      f->NewExternalStringFromOneByte(&one_byte_resource).ToHandleChecked();
  CHECK(IsExternalOneByteString(*name));
  CHECK(!IsInternalizedString(*name));

  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  AlignedCachedData* cache = nullptr;

  DirectHandle<SharedFunctionInfo> orig = CompileScriptAndProduceCache(
      isolate, source_string, ScriptDetails(name), &cache,
      v8::ScriptCompiler::kNoCompileOptions);

  DirectHandle<SharedFunctionInfo> copy;
  {
    DisallowCompilation no_compile_expected(isolate);
    copy = CompileScript(isolate, source_string, ScriptDetails(name), cache,
                         v8::ScriptCompiler::kConsumeCodeCache);
  }
  CHECK_NE(*orig, *copy);

  Handle<JSFunction> copy_fun =
      Factory::JSFunctionBuilder{isolate, copy, isolate->native_context()}
          .Build();

  DirectHandle<Object> copy_result =
      Execution::CallScript(isolate, copy_fun, global,
                            isolate->factory()->empty_fixed_array())
          .ToHandleChecked();

  CHECK_EQ(10.0, Object::NumberValue(*copy_result));

  // This avoids the GC from trying to free stack allocated resources.
  i::Cast<i::ExternalOneByteString>(name)->SetResource(isolate, nullptr);
  delete cache;
}

static bool toplevel_test_code_event_found = false;

static void SerializerLogEventListener(const v8::JitCodeEvent* event) {
  if (event->type == v8::JitCodeEvent::CODE_ADDED &&
      (memcmp(event->name.str, "Script:~ test", 13) == 0 ||
       memcmp(event->name.str, "Script: test", 12) == 0)) {
    toplevel_test_code_event_found = true;
  }
}

v8::ScriptCompiler::CachedData* CompileRunAndProduceCache(
    const char* js_source, CodeCacheType cacheType = CodeCacheType::kLazy) {
  v8::ScriptCompiler::CachedData* cache;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate1 = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope iscope(isolate1);
    v8::HandleScope scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source_str = v8_str(js_source);
    v8::ScriptOrigin origin(v8_str("test"));
    v8::ScriptCompiler::Source source(source_str, origin);
    v8::ScriptCompiler::CompileOptions options;
    switch (cacheType) {
      case CodeCacheType::kEager:
        options = v8::ScriptCompiler::kEagerCompile;
        break;
      case CodeCacheType::kLazy:
      case CodeCacheType::kAfterExecute:
        options = v8::ScriptCompiler::kNoCompileOptions;
        break;
      default:
        UNREACHABLE();
    }
    v8::Local<v8::UnboundScript> script =
        v8::ScriptCompiler::CompileUnboundScript(isolate1, &source, options)
            .ToLocalChecked();

    if (cacheType != CodeCacheType::kAfterExecute) {
      cache = ScriptCompiler::CreateCodeCache(script);
    }

    v8::Local<v8::Value> result = script->BindToCurrentContext()
                                      ->Run(isolate1->GetCurrentContext())
                                      .ToLocalChecked();
    v8::Local<v8::String> result_string =
        result->ToString(isolate1->GetCurrentContext()).ToLocalChecked();
    CHECK(result_string->Equals(isolate1->GetCurrentContext(), v8_str("abcdef"))
              .FromJust());

    if (cacheType == CodeCacheType::kAfterExecute) {
      cache = ScriptCompiler::CreateCodeCache(script);
    }
    CHECK(cache);
  }
  isolate1->Dispose();
  return cache;
}

TEST(CodeSerializerIsolates) {
  const char* js_source = "function f() { return 'abc'; }; f() + 'def'";
  v8::ScriptCompiler::CachedData* cache = CompileRunAndProduceCache(js_source);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  isolate2->SetJitCodeEventHandler(v8::kJitCodeEventDefault,
                                   SerializerLogEventListener);
  toplevel_test_code_event_found = false;
  {
    v8::Isolate::Scope iscope(isolate2);
    v8::HandleScope scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source_str = v8_str(js_source);
    v8::ScriptOrigin origin(v8_str("test"));
    v8::ScriptCompiler::Source source(source_str, origin, cache);
    v8::Local<v8::UnboundScript> script;
    {
      DisallowCompilation no_compile(reinterpret_cast<Isolate*>(isolate2));
      script = v8::ScriptCompiler::CompileUnboundScript(
                   isolate2, &source, v8::ScriptCompiler::kConsumeCodeCache)
                   .ToLocalChecked();
    }
    CHECK(!cache->rejected);
    v8::Local<v8::Value> result = script->BindToCurrentContext()
                                      ->Run(isolate2->GetCurrentContext())
                                      .ToLocalChecked();
    CHECK(result->ToString(isolate2->GetCurrentContext())
              .ToLocalChecked()
              ->Equals(isolate2->GetCurrentContext(), v8_str("abcdef"))
              .FromJust());
  }
  CHECK(toplevel_test_code_event_found);
  isolate2->Dispose();
}

TEST(CodeSerializerIsolatesEager) {
  const char* js_source =
      "function f() {"
      "  return function g() {"
      "    return 'abc';"
      "  }"
      "}"
      "f()() + 'def'";
  v8::ScriptCompiler::CachedData* cache =
      CompileRunAndProduceCache(js_source, CodeCacheType::kEager);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  isolate2->SetJitCodeEventHandler(v8::kJitCodeEventDefault,
                                   SerializerLogEventListener);
  toplevel_test_code_event_found = false;
  {
    v8::Isolate::Scope iscope(isolate2);
    v8::HandleScope scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source_str = v8_str(js_source);
    v8::ScriptOrigin origin(v8_str("test"));
    v8::ScriptCompiler::Source source(source_str, origin, cache);
    v8::Local<v8::UnboundScript> script;
    {
      DisallowCompilation no_compile(reinterpret_cast<Isolate*>(isolate2));
      script = v8::ScriptCompiler::CompileUnboundScript(
                   isolate2, &source, v8::ScriptCompiler::kConsumeCodeCache)
                   .ToLocalChecked();
    }
    CHECK(!cache->rejected);
    v8::Local<v8::Value> result = script->BindToCurrentContext()
                                      ->Run(isolate2->GetCurrentContext())
                                      .ToLocalChecked();
    CHECK(result->ToString(isolate2->GetCurrentContext())
              .ToLocalChecked()
              ->Equals(isolate2->GetCurrentContext(), v8_str("abcdef"))
              .FromJust());
  }
  CHECK(toplevel_test_code_event_found);
  isolate2->Dispose();
}

TEST(CodeSerializerAfterExecute) {
  // We test that no compilations happen when running this code. Forcing
  // to always optimize breaks this test.
  bool prev_always_turbofan_value = v8_flags.always_turbofan;
  v8_flags.always_turbofan = false;
  const char* js_source = "function f() { return 'abc'; }; f() + 'def'";
  v8::ScriptCompiler::CachedData* cache =
      CompileRunAndProduceCache(js_source, CodeCacheType::kAfterExecute);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  Isolate* i_isolate2 = reinterpret_cast<Isolate*>(isolate2);

  {
    v8::Isolate::Scope iscope(isolate2);
    v8::HandleScope scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source_str = v8_str(js_source);
    v8::ScriptOrigin origin(v8_str("test"));
    v8::ScriptCompiler::Source source(source_str, origin, cache);
    v8::Local<v8::UnboundScript> script;
    {
      DisallowCompilation no_compile_expected(i_isolate2);
      script = v8::ScriptCompiler::CompileUnboundScript(
                   isolate2, &source, v8::ScriptCompiler::kConsumeCodeCache)
                   .ToLocalChecked();
    }
    CHECK(!cache->rejected);

    DirectHandle<SharedFunctionInfo> sfi = v8::Utils::OpenDirectHandle(*script);
    CHECK(sfi->HasBytecodeArray());

    {
      DisallowCompilation no_compile_expected(i_isolate2);
      v8::Local<v8::Value> result = script->BindToCurrentContext()
                                        ->Run(isolate2->GetCurrentContext())
                                        .ToLocalChecked();
      v8::Local<v8::String> result_string =
          result->ToString(isolate2->GetCurrentContext()).ToLocalChecked();
      CHECK(
          result_string->Equals(isolate2->GetCurrentContext(), v8_str("abcdef"))
              .FromJust());
    }
  }
  isolate2->Dispose();

  // Restore the flags.
  v8_flags.always_turbofan = prev_always_turbofan_value;
}

TEST(CodeSerializerEmptyContextDependency) {
  bool prev_allow_natives_syntax = v8_flags.allow_natives_syntax;
  v8_flags.allow_natives_syntax = true;
  bool prev_empty_context_extension_dep = v8_flags.empty_context_extension_dep;
  v8_flags.empty_context_extension_dep = true;

  const char* js_source = R"(
    function f() {
      var foo = 'abc';
      function g(src) {
        eval(src);
        return foo;
      }
      return g;
    };
    var g = f();
    %PrepareFunctionForOptimization(g);
    g('') + 'def';
    %OptimizeFunctionOnNextCall(g);
    g('') + 'def';
  )";
  v8::ScriptCompiler::CachedData* cache =
      CompileRunAndProduceCache(js_source, CodeCacheType::kAfterExecute);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate2 = v8::Isolate::New(create_params);

  {
    v8::Isolate::Scope iscope(isolate2);
    v8::HandleScope scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source_str = v8_str(js_source);
    v8::ScriptOrigin origin(v8_str("test"));
    v8::ScriptCompiler::Source source(source_str, origin, cache);
    v8::Local<v8::UnboundScript> script;
    {
      script = v8::ScriptCompiler::CompileUnboundScript(
                   isolate2, &source, v8::ScriptCompiler::kConsumeCodeCache)
                   .ToLocalChecked();
    }
    CHECK(!cache->rejected);

    DirectHandle<SharedFunctionInfo> sfi = v8::Utils::OpenDirectHandle(*script);
    CHECK(sfi->HasBytecodeArray());

    {
      v8::Local<v8::Value> result = script->BindToCurrentContext()
                                        ->Run(isolate2->GetCurrentContext())
                                        .ToLocalChecked();
      v8::Local<v8::String> result_string =
          result->ToString(isolate2->GetCurrentContext()).ToLocalChecked();
      CHECK(
          result_string->Equals(isolate2->GetCurrentContext(), v8_str("abcdef"))
              .FromJust());
    }
  }
  isolate2->Dispose();

  // Restore the flags.
  v8_flags.allow_natives_syntax = prev_allow_natives_syntax;
  v8_flags.empty_context_extension_dep = prev_empty_context_extension_dep;
}

TEST(CodeSerializerFlagChange) {
  const char* js_source = "function f() { return 'abc'; }; f() + 'def'";
  v8::ScriptCompiler::CachedData* cache = CompileRunAndProduceCache(js_source);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate2 = v8::Isolate::New(create_params);

  v8_flags.allow_natives_syntax =
      true;  // Flag change should trigger cache reject.
  FlagList::EnforceFlagImplications();
  {
    v8::Isolate::Scope iscope(isolate2);
    v8::HandleScope scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source_str = v8_str(js_source);
    v8::ScriptOrigin origin(v8_str("test"));
    v8::ScriptCompiler::Source source(source_str, origin, cache);
    v8::ScriptCompiler::CompileUnboundScript(
        isolate2, &source, v8::ScriptCompiler::kConsumeCodeCache)
        .ToLocalChecked();
    CHECK(cache->rejected);
  }
  isolate2->Dispose();
}

TEST(CachedDataCompatibilityCheck) {
  {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    // Hand-craft a zero-filled cached data which cannot be valid.
    int length = 64;
    uint8_t* payload = new uint8_t[length];
    memset(payload, 0, length);
    v8::ScriptCompiler::CachedData cache(
        payload, length, v8::ScriptCompiler::CachedData::BufferOwned);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::ScriptCompiler::CachedData::CompatibilityCheckResult result =
          cache.CompatibilityCheck(isolate);
      CHECK_NE(result, v8::ScriptCompiler::CachedData::kSuccess);
    }
    isolate->Dispose();
  }

  const char* js_source = "function f() { return 'abc'; }; f() + 'def'";
  std::unique_ptr<v8::ScriptCompiler::CachedData> cache;
  {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::ScriptCompiler::Source source(v8_str(js_source), {v8_str("test")});
      v8::Local<v8::UnboundScript> script =
          v8::ScriptCompiler::CompileUnboundScript(
              isolate, &source, v8::ScriptCompiler::kEagerCompile)
              .ToLocalChecked();
      cache.reset(ScriptCompiler::CreateCodeCache(script));
    }
    isolate->Dispose();
  }

  {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::ScriptCompiler::CachedData::CompatibilityCheckResult result =
          cache->CompatibilityCheck(isolate);
      CHECK_EQ(result, v8::ScriptCompiler::CachedData::kSuccess);
    }
    isolate->Dispose();
  }

  {
    v8_flags.allow_natives_syntax =
        true;  // Flag change should trigger cache reject.
    FlagList::EnforceFlagImplications();
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope iscope(isolate);
      v8::ScriptCompiler::CachedData::CompatibilityCheckResult result =
          cache->CompatibilityCheck(isolate);
      CHECK_EQ(result, v8::ScriptCompiler::CachedData::kFlagsMismatch);
    }
    isolate->Dispose();
  }
}

TEST(CodeSerializerBitFlip) {
  i::v8_flags.verify_snapshot_checksum = true;
  const char* js_source = "function f() { return 'abc'; }; f() + 'def'";
  v8::ScriptCompiler::CachedData* cache = CompileRunAndProduceCache(js_source);

  // Arbitrary bit flip.
  int arbitrary_spot = 237;
  CHECK_LT(arbitrary_spot, cache->length);
  const_cast<uint8_t*>(cache->data)[arbitrary_spot] ^= 0x40;

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope iscope(isolate2);
    v8::HandleScope scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source_str = v8_str(js_source);
    v8::ScriptOrigin origin(v8_str("test"));
    v8::ScriptCompiler::Source source(source_str, origin, cache);
    v8::ScriptCompiler::CompileUnboundScript(
        isolate2, &source, v8::ScriptCompiler::kConsumeCodeCache)
        .ToLocalChecked();
    CHECK(cache->rejected);
  }
  isolate2->Dispose();
}

TEST(CodeSerializerWithHarmonyScoping) {
  const char* source1 = "'use strict'; let x = 'X'";
  const char* source2 = "'use strict'; let y = 'Y'";
  const char* source3 = "'use strict'; x + y";

  v8::ScriptCompiler::CachedData* cache;

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate1 = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope iscope(isolate1);
    v8::HandleScope scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope context_scope(context);

    CompileRun(source1);
    CompileRun(source2);

    v8::Local<v8::String> source_str = v8_str(source3);
    v8::ScriptOrigin origin(v8_str("test"));
    v8::ScriptCompiler::Source source(source_str, origin);
    v8::Local<v8::UnboundScript> script =
        v8::ScriptCompiler::CompileUnboundScript(
            isolate1, &source, v8::ScriptCompiler::kNoCompileOptions)
            .ToLocalChecked();
    cache = v8::ScriptCompiler::CreateCodeCache(script);
    CHECK(cache);

    v8::Local<v8::Value> result = script->BindToCurrentContext()
                                      ->Run(isolate1->GetCurrentContext())
                                      .ToLocalChecked();
    v8::Local<v8::String> result_str =
        result->ToString(isolate1->GetCurrentContext()).ToLocalChecked();
    CHECK(result_str->Equals(isolate1->GetCurrentContext(), v8_str("XY"))
              .FromJust());
  }
  isolate1->Dispose();

  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope iscope(isolate2);
    v8::HandleScope scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope context_scope(context);

    // Reverse order of prior running scripts.
    CompileRun(source2);
    CompileRun(source1);

    v8::Local<v8::String> source_str = v8_str(source3);
    v8::ScriptOrigin origin(v8_str("test"));
    v8::ScriptCompiler::Source source(source_str, origin, cache);
    v8::Local<v8::UnboundScript> script;
    {
      DisallowCompilation no_compile(reinterpret_cast<Isolate*>(isolate2));
      script = v8::ScriptCompiler::CompileUnboundScript(
                   isolate2, &source, v8::ScriptCompiler::kConsumeCodeCache)
                   .ToLocalChecked();
    }
    v8::Local<v8::Value> result = script->BindToCurrentContext()
                                      ->Run(isolate2->GetCurrentContext())
                                      .ToLocalChecked();
    v8::Local<v8::String> result_str =
        result->ToString(isolate2->GetCurrentContext()).ToLocalChecked();
    CHECK(result_str->Equals(isolate2->GetCurrentContext(), v8_str("XY"))
              .FromJust());
  }
  isolate2->Dispose();
}

TEST(Regress503552) {
  if (!v8_flags.incremental_marking) return;
  // Test that the code serializer can deal with weak cells that form a linked
  // list during incremental marking.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();

  HandleScope scope(isolate);
  Handle<String> source = isolate->factory()->NewStringFromAsciiChecked(
      "function f() {} function g() {}");
  AlignedCachedData* cached_data = nullptr;
  DirectHandle<SharedFunctionInfo> shared = CompileScriptAndProduceCache(
      isolate, source, ScriptDetails(), &cached_data,
      v8::ScriptCompiler::kNoCompileOptions);
  delete cached_data;

  heap::SimulateIncrementalMarking(isolate->heap());

  v8::ScriptCompiler::CachedData* cache_data =
      CodeSerializer::Serialize(isolate, indirect_handle(shared, isolate));
  delete cache_data;
}

static void CodeSerializerMergeDeserializedScript(bool retain_toplevel_sfi) {
  v8_flags.stress_background_compile = false;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();

  HandleScope outer_scope(isolate);
  Handle<String> source = isolate->factory()->NewStringFromAsciiChecked(
      "(function () {return 123;})");
  AlignedCachedData* cached_data = nullptr;
  DirectHandle<Script> script;
  {
    HandleScope first_compilation_scope(isolate);
    DirectHandle<SharedFunctionInfo> shared = CompileScriptAndProduceCache(
        isolate, source, ScriptDetails(), &cached_data,
        v8::ScriptCompiler::kNoCompileOptions,
        ScriptCompiler::InMemoryCacheResult::kMiss);
    SharedFunctionInfo::EnsureOldForTesting(*shared);
    Handle<Script> local_script(Cast<Script>(shared->script()), isolate);
    script = first_compilation_scope.CloseAndEscape(local_script);
  }

  DirectHandle<HeapObject> retained_toplevel_sfi;
  if (retain_toplevel_sfi) {
    retained_toplevel_sfi = direct_handle(script->infos()
                                              ->get(kFunctionLiteralIdTopLevel)
                                              .GetHeapObjectAssumeWeak(),
                                          isolate);
  }

  // GC twice in case incremental marking had already marked the bytecode array.
  // After this, the Isolate compilation cache contains a weak reference to the
  // Script but not the top-level SharedFunctionInfo.
  heap::InvokeMajorGC(isolate->heap());
  heap::InvokeMajorGC(isolate->heap());

  // If the top-level SFI was compiled by Sparkplug, and flushing of Sparkplug
  // code is not enabled, then the cache entry can never be cleared.
  ScriptCompiler::InMemoryCacheResult expected_lookup_result =
      v8_flags.always_sparkplug && !v8_flags.flush_baseline_code
          ? ScriptCompiler::InMemoryCacheResult::kHit
          : ScriptCompiler::InMemoryCacheResult::kPartial;

  DirectHandle<SharedFunctionInfo> copy = CompileScript(
      isolate, source, ScriptDetails(), cached_data,
      v8::ScriptCompiler::kConsumeCodeCache, expected_lookup_result);
  delete cached_data;

  // The existing Script was reused.
  CHECK_EQ(*script, copy->script());

  // The existing top-level SharedFunctionInfo was also reused.
  if (retain_toplevel_sfi) {
    CHECK_EQ(*retained_toplevel_sfi, *copy);
  }
}

TEST(CodeSerializerMergeDeserializedScript) {
  CodeSerializerMergeDeserializedScript(/*retain_toplevel_sfi=*/false);
}

TEST(CodeSerializerMergeDeserializedScriptRetainingToplevelSfi) {
  CodeSerializerMergeDeserializedScript(/*retain_toplevel_sfi=*/true);
}

UNINITIALIZED_TEST(SnapshotCreatorBlobNotCreated) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::TryCatch try_catch(isolate);
      v8::Local<v8::String> code = v8_str("throw new Error('test');");
      CHECK(v8::Script::Compile(context, code)
                .ToLocalChecked()
                ->Run(context)
                .IsEmpty());
      CHECK(try_catch.HasCaught());
    }
    // SnapshotCreator should be destroyed just fine even when no
    // blob is created.
  }

  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(SnapshotCreatorMultipleContexts) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_
"""


```