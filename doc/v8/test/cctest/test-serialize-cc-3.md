Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-serialize.cc`. I need to analyze the code to understand its purpose and then explain it in a concise way, addressing the specific points mentioned in the prompt.

Here's a plan:
1. **Identify the main goal:** Look for keywords like `TEST`, `Serialize`, `CodeCache`, `CompileScript`, and related V8 APIs to understand what the code is testing.
2. **Analyze individual tests:** Break down each `TEST` function to understand its specific scenario and how it relates to serialization.
3. **Check for JavaScript interaction:** Look for code that compiles and runs JavaScript code using V8's API. Provide examples if found.
4. **Identify code logic and potential assumptions:** Analyze the flow of execution within tests, paying attention to variable assignments and checks. Formulate assumptions about inputs and outputs.
5. **Look for common programming errors:**  Consider potential issues developers might face when dealing with code caching and serialization, and see if the tests cover any of those.
6. **Address the `.tq` extension:**  Confirm that the file does not end in `.tq`.
7. **Synthesize the findings:** Combine the analysis of individual tests into a cohesive summary of the file's functionality.
这是 `v8/test/cctest/test-serialize.cc` 的第 4 部分，该文件主要功能是测试 V8 引擎的代码序列化和反序列化机制。更具体地说，这部分代码侧重于以下几个方面：

1. **ConsString 的代码缓存:** 测试由多个 ConsString（由多个小的字符串连接而成的字符串）组成的源代码的编译和代码缓存机制。它验证了在重新使用缓存时，不会重新编译，并且可以正确执行。

2. **外部字符串的代码缓存:** 测试包含外部字符串（由 C++ 代码提供的字符串数据）的源代码的代码缓存。它涵盖了 OneByte 和 TwoByte 的外部字符串，以及大型外部字符串作为变量名的情况。它还测试了外部字符串作为脚本名称的情况。

3. **跨 Isolate 的代码缓存:**  测试在不同的 V8 Isolate 实例之间共享代码缓存的功能。这包括 eager 模式（在编译时就生成代码缓存）和 after-execute 模式（在执行后生成代码缓存）的情况。

4. **依赖空上下文的代码缓存:** 测试当代码依赖于空上下文扩展时，代码缓存的正确性。

5. **代码缓存对 Flag 变化的敏感性:** 测试当 V8 的 Flag 发生变化时，之前生成的代码缓存是否会被正确地拒绝使用。

6. **代码缓存的兼容性检查:** 测试 V8 提供的 API `CompatibilityCheck`，用于检查代码缓存是否与当前 Isolate 兼容。这包括手动创建无效缓存以及测试 Flag 不匹配的情况。

7. **代码缓存的校验和验证:** 测试当代码缓存中的数据被篡改（例如，发生 bit flip）时，V8 是否能够检测到并拒绝使用。

8. **带有 Harmony Scoping 的代码缓存:** 测试在使用 `let` 和 `const` 等 ES6 特性时，代码缓存的正确性，以及不同脚本执行顺序的影响。

9. **处理增量标记期间的弱 Cell:** 测试代码序列化器是否能够处理在增量标记期间形成的弱 Cell 链表。

10. **合并反序列化的 Script:** 测试在反序列化 Script 时，如何重用已经存在的 Script 和顶层 SharedFunctionInfo。

11. **SnapshotCreator 的相关测试:**  测试在 `SnapshotCreator` 没有创建 blob 的情况下和创建多个上下文的情况下的行为。

**关于代码形式和 JavaScript 关系：**

* `v8/test/cctest/test-serialize.cc` 以 `.cc` 结尾，因此它是 **V8 C++ 源代码**，而不是 Torque 源代码。
* 该文件与 JavaScript 的功能有密切关系，因为它测试的是 **JavaScript 代码的编译和代码缓存**机制。

**JavaScript 示例说明:**

```javascript
// 这是测试用例中经常使用的 JavaScript 代码模式
function add(a, b) {
  return a + b;
}

add(5, 3); // 首次执行，可能需要编译
```

测试用例会先编译这段代码并生成代码缓存，然后在另一个 Isolate 中尝试使用这个缓存，以验证跨 Isolate 的代码缓存是否有效。

**代码逻辑推理示例：**

在 `TEST(CodeSerializerConsString)` 中，有如下逻辑：

**假设输入：**

* `source_a = "hello"` (length_of_a = 5)
* `source_b = "world"` (length_of_b = 5)
* `source_c = "!"` (length_of_c = 1)

**执行的代码:**

```c++
  v8::Maybe<int32_t> result =
      CompileRun("(a + b).length")
          ->Int32Value(CcTest::isolate()->GetCurrentContext());
  CHECK_EQ(length_of_a + length_of_b, result.FromJust());
  result = CompileRun("(b + c).length")
               ->Int32Value(CcTest::isolate()->GetCurrentContext());
  CHECK_EQ(length_of_b + length_of_c, result.FromJust());
```

**预期输出：**

* `(a + b).length` 的结果是 5 + 5 = 10
* `(b + c).length` 的结果是 5 + 1 = 6

**常见的编程错误示例:**

在处理代码缓存时，一个常见的错误是 **假设代码缓存在不同的 V8 版本或配置下总是有效的**。`TEST(CodeSerializerFlagChange)` 就演示了这种情况：如果 V8 的 Flag 发生了变化（例如，是否允许使用 Native Syntax），那么之前生成的代码缓存就可能不再适用，需要重新编译。开发者需要意识到代码缓存的兼容性问题，并采取相应的措施（例如，在 Flag 变化时失效缓存）。

**归纳一下它的功能 (第 4 部分):**

这部分 `test-serialize.cc` 主要深入测试了 V8 代码序列化器在处理各种复杂场景下的能力，包括由 `ConsString` 组成的源代码、外部字符串、跨 Isolate 的代码共享、对上下文依赖的处理、对 V8 配置变化的敏感性、缓存数据的完整性校验以及与 ES6 新特性和增量垃圾回收的交互。 此外，它还包含了对 `SnapshotCreator` 的相关测试，验证了在特定场景下 `SnapshotCreator` 的正确行为。 总体而言，这部分测试旨在确保 V8 的代码缓存机制在各种情况下都能可靠地工作，提高代码加载速度和执行效率。

### 提示词
```
这是目录为v8/test/cctest/test-serialize.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-serialize.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ingFromUtf8(source_c).ToHandleChecked();

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
```