Response:
My thought process to analyze the given C++ code snippet and fulfill the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze a V8 test file (`test-serialize.cc`) and describe its functionality, relating it to JavaScript where possible, providing examples, and summarizing its overall purpose. The prompt specifically mentions this is part 3 of 8, suggesting a larger context of serialization testing.

2. **Initial Scan for Keywords:** I quickly scan the code for keywords like `TEST`, `LocalContext`, `Isolate`, `CompileScript`, `ProduceCache`, `ConsumeCodeCache`, `CHECK`, `ScriptDetails`, `CompilationCache`, etc. These keywords provide strong hints about the code's purpose. The presence of `TEST` immediately tells me these are unit tests within the V8 project.

3. **Identify Core Functionality:** The terms `Serialize`, `Cache`, `CompileScript`, `ProduceCache`, and `ConsumeCodeCache` strongly suggest that the code is about V8's code caching and serialization mechanisms. It appears to be testing the process of compiling JavaScript code, caching the compiled output, and then reusing that cache.

4. **Analyze Individual Tests:**  I then examine each `TEST` function individually.

    * **`TEST(CodeSerializerWithProfiler)`:**  This test checks if enabling the profiler affects the deserialization process and if source positions are correctly collected after deserialization when the profiler is on.

    * **`TEST(CodeSerializerOnePlusOne...)`:** These tests (without the profiler, with interpreted frames, with a debugger, with block coverage) all seem to be variations of a basic test case: compiling and caching a simple "1 + 1" script. The core logic is repeated, with different flags or settings enabled. This tells me that the fundamental serialization/deserialization process is being tested under various conditions. The `DisallowCompilation` block is crucial – it verifies that the code is *actually* loaded from the cache and not recompiled.

    * **`TEST(CodeSerializerPromotedToCompilationCache)`:** This test focuses on the compilation cache itself and how it stores and retrieves compiled code based on `ScriptDetails`, including host-defined options, source code, and other attributes. The multiple `lookup_result` checks are designed to verify the correctness of the cache lookup logic with different parameters.

    * **`TEST(CompileFunctionCompilationCache)`:** Similar to the previous test, but this one focuses on caching the compilation results of *functions* rather than entire scripts. It also tests the impact of function arguments and host-defined options on cache lookups.

    * **`TEST(CodeSerializerInternalizedString)`:** This test specifically examines how internalized strings (strings stored in a special, deduplicated region of memory) are handled during serialization and deserialization. The check `IsInternalizedString(*orig_result)` and `orig_result.is_identical_to(copy_result)` are key here.

    * **`TEST(CodeSerializerLargeCodeObject)`:** This test deals with serializing and deserializing code that results in large objects in memory (likely in the large object heap). The `v8_flags.always_turbofan = false;` is a hint that it's focused on the unoptimized code path.

    * **`TEST(CodeSerializerLargeCodeObjectWithIncrementalMarking)`:** This test adds the complexity of incremental garbage collection (incremental marking) to the large code object scenario. It seems to be checking for potential issues related to write barriers during deserialization when the garbage collector is running incrementally.

    * **`TEST(CodeSerializerLargeStrings)`:**  This test focuses on how large string literals within scripts are handled during serialization. The checks on `cache->length()` are intended to ensure that the serialized cache doesn't include the entire source string, saving space.

    * **`TEST(CodeSerializerThreeBigStrings)`:**  This test builds upon the previous one by using multiple very large strings, potentially exceeding the regular heap object size, to further test the serialization of large string constants.

5. **Relate to JavaScript:** The core functionality of these tests directly relates to how JavaScript code is executed in V8. When V8 compiles JavaScript, it can cache the resulting bytecode or machine code. This caching mechanism speeds up subsequent executions of the same code. The tests are essentially verifying that this caching and retrieval process works correctly, even under various conditions.

    * **Example:**  I'd use the "1 + 1" example to illustrate basic caching. Running the same script twice should ideally be faster the second time due to caching.

6. **Identify Potential Errors:** The tests implicitly highlight potential errors:

    * **Incorrect cache invalidation:**  If the cache isn't properly invalidated when the source code or relevant options change, V8 might use an outdated cached version, leading to incorrect behavior. The `CodeSerializerPromotedToCompilationCache` tests are specifically designed to check this.
    * **Deserialization errors:** If the deserialization process is buggy, the restored code might be corrupted or incomplete.
    * **Memory management issues:** The large object tests and the incremental marking test highlight potential problems with managing large memory allocations and ensuring data integrity during garbage collection.

7. **Code Logic Reasoning (Hypothetical):**  While the provided code is *testing* logic, I can create hypothetical scenarios:

    * **Input:** A JavaScript string "const a = 5; a + 2;".
    * **Process:** `CompileScriptAndProduceCache` would compile this and create a cache. `CompileScript` with `kConsumeCodeCache` would load from the cache.
    * **Output:** The result of executing the script (7) would be the same whether compiled directly or loaded from the cache. The important aspect here is *not* recompiling when the cache is used.

8. **Structure the Output:** I'd organize the findings into the requested categories: functionality, relation to JavaScript (with examples), potential errors, code logic reasoning, and finally, a summary of the overall purpose based on the analysis. The prompt specifically asks for JavaScript examples, so I'd make sure to include those.

9. **Address Specific Constraints:** The prompt mentions checking for `.tq` files (Torque) – I confirm this isn't a Torque file. It also emphasizes this being part 3 of 8, so the summary should reflect this broader context of serialization testing.

By following these steps, I can systematically analyze the provided C++ code snippet and generate a comprehensive and accurate response that addresses all aspects of the user's request.
这是提供的 v8 源代码文件 `v8/test/cctest/test-serialize.cc` 的第三部分，主要功能是 **测试 V8 引擎中代码的序列化和反序列化机制，特别是与编译缓存相关的部分**。

**功能归纳：**

这部分代码主要关注以下几个方面：

1. **验证代码缓存的正确性：**  测试将编译后的代码（`SharedFunctionInfo`）序列化到缓存，然后在后续执行中反序列化并使用，确保反序列化后的代码与原始编译的代码行为一致。

2. **测试不同场景下的代码缓存：**  测试在启用 Profiler、Interpreted Frames Native Stack、Debugger 以及 Block Coverage 等不同特性时，代码缓存的序列化和反序列化是否正常工作。

3. **验证编译缓存的查找机制：** 测试 `CompilationCache` 的 `LookupScript` 方法，确保在不同的 `ScriptDetails` (例如，源代码、Host Defined Options、语言模式、脚本选项等) 下，能够正确地命中或未命中缓存。

4. **测试函数编译的缓存：** 专门测试了对函数进行编译并缓存的场景，验证了函数级别的代码缓存机制。

5. **验证内部化字符串的序列化：** 测试包含内部化字符串（在 V8 内部共享的字符串）的代码在序列化和反序列化后，这些字符串是否仍然是内部化的，并且引用相同。

6. **测试大型代码对象的序列化：** 验证对于生成大型代码对象（例如，包含大量循环或复杂逻辑的代码）的脚本，其序列化和反序列化过程是否正确。

7. **测试大型字符串的序列化：**  测试包含大型字符串字面量的脚本的序列化，并验证缓存大小是否合理，避免将整个大型字符串都包含在缓存中。

**如果 v8/test/cctest/test-serialize.cc 以 .tq 结尾：**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是 V8 用来定义内置函数和运行时函数的领域特定语言。当前提供的代码是 C++ 代码，所以不是 Torque 文件。

**与 JavaScript 的功能关系和 JavaScript 示例：**

`v8/test/cctest/test-serialize.cc` 中测试的功能直接关系到 JavaScript 代码的执行效率。代码缓存允许 V8 在重复执行相同代码时，避免重新编译，从而显著提升性能。

**JavaScript 示例：**

```javascript
// 第一次执行，V8 会编译这段代码并可能将其缓存
function add(a, b) {
  return a + b;
}
console.log(add(1, 2)); // 输出 3

// 第二次执行，如果代码缓存生效，V8 可能会直接使用缓存的编译结果，
// 而不是重新编译，提高执行速度。
console.log(add(3, 4)); // 输出 7
```

在这个例子中，`test-serialize.cc` 中测试的逻辑就是确保当 `add` 函数第二次被调用时，V8 的代码缓存机制能够正常工作，从而加速第二次执行。

**代码逻辑推理（假设输入与输出）：**

**假设输入：**

* 一个简单的 JavaScript 源代码字符串 `"1 + 1"`。
* 首次编译时，`v8::ScriptCompiler::kNoCompileOptions` 被使用，表示不使用任何编译选项。
* 第二次编译时，使用之前生成的缓存数据，并设置 `v8::ScriptCompiler::kConsumeCodeCache`，表示尝试使用代码缓存。

**预期输出：**

* 首次编译会生成 `SharedFunctionInfo` 对象，并且会生成缓存数据。
* 第二次编译时，由于使用了相同的源代码和缓存数据，并且设置了 `kConsumeCodeCache`，应该能够成功从缓存中恢复 `SharedFunctionInfo` 对象，而不会触发重新编译。
* 执行从缓存恢复的代码后，结果应该与首次编译执行的结果一致，即 `2`。

**代码逻辑推理示例（基于 `TEST(CodeSerializerOnePlusOne)`）：**

1. **首次编译:**  `CompileScriptAndProduceCache` 会编译 `"1 + 1"`，生成 `orig` (一个 `SharedFunctionInfo`) 和 `cache` (缓存数据)。
2. **禁用编译:**  `DisallowCompilation no_compile_expected(isolate);`  确保在接下来的代码块中不会发生新的编译。
3. **使用缓存编译:** `CompileScript` 使用相同的源代码和之前生成的 `cache`，并指定 `v8::ScriptCompiler::kConsumeCodeCache`。
4. **断言:** `CHECK_NE(*orig, *copy);` 断言 `copy` (从缓存恢复的 `SharedFunctionInfo`) 与 `orig` 不是同一个对象（因为是从缓存恢复的新对象）。
5. **验证结果:** 执行 `copy` 对应的函数，结果应该仍然是 `2`，证明缓存的代码行为正确。

**涉及用户常见的编程错误：**

虽然这个测试文件主要是测试 V8 内部机制，但它所覆盖的功能与用户在编写 JavaScript 代码时可能遇到的一些问题有关：

1. **性能问题：** 如果 V8 的代码缓存机制失效，会导致 JavaScript 代码重复编译，降低执行效率，尤其是在循环或者频繁调用的函数中。
2. **代码一致性问题：** 如果缓存机制存在 Bug，可能会导致在某些情况下使用了错误的缓存代码，从而导致程序行为异常。

**总结 `test-serialize.cc` 的这部分功能：**

这部分 `test-serialize.cc` 的核心功能是 **系统地测试 V8 引擎的代码序列化和反序列化机制，特别是针对编译缓存的各个方面进行细致的验证**。它通过模拟不同的场景和配置，确保代码缓存能够正确地生成、存储、加载和使用，从而保证 JavaScript 代码执行的效率和一致性。这部分测试是 V8 引擎稳定性和性能的关键组成部分。

Prompt: 
```
这是目录为v8/test/cctest/test-serialize.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-serialize.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能

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
      f->NewStr
"""


```