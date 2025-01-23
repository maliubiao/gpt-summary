Response: The user wants a summary of the C++ code in `v8/test/cctest/test-api.cc`, specifically focusing on its functionality and how it relates to JavaScript. Since this is part 15 of 18, it's likely testing various aspects of the V8 JavaScript engine's API.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Purpose:** The filename and the presence of `TEST` macros strongly suggest this file contains C++ tests for the V8 API.

2. **Analyze Individual Tests:** Go through each `TEST` block and try to understand what it's verifying. Look for:
    * **V8 API calls:** Functions like `v8::ScriptCompiler::Compile`, `v8::Context::New`, `v8::Object::New`, `v8::Map::New`, etc. are key indicators.
    * **Assertions:** `CHECK`, `CHECK_EQ`, `ExpectTrue`, `ExpectString` reveal the expected behavior.
    * **Setup and Teardown:**  Look for `LocalContext env;` which sets up a V8 environment for the test.
    * **JavaScript Code Execution:**  `CompileRun("...")` indicates that the C++ test is interacting with the JavaScript engine.

3. **Group Similar Tests:**  Notice patterns in the tests. For example, several tests deal with:
    * Script compilation and streaming.
    * `Map` and `Set` functionality.
    * Handle scopes.
    * Access checks.
    * Template intrinsics.
    * Proxies.
    * Memory pressure.
    * Module loading (dynamic import, import meta).
    * Shadow Realms.

4. **Relate to JavaScript Features:** Connect the C++ API usage to corresponding JavaScript language features. For example:
    * `v8::ScriptCompiler::Compile` relates to running JavaScript code.
    * `v8::Map` and `v8::Set` directly correspond to the JavaScript `Map` and `Set` objects.
    * Streaming compilation is about how JavaScript code can be processed in chunks.
    * `v8::Proxy` is the C++ representation of the JavaScript `Proxy` object.
    * Dynamic import and import meta are JavaScript module features.
    * Shadow Realms are a newer JavaScript feature for creating isolated execution environments.

5. **Provide Concrete JavaScript Examples:** For the most relevant tests, demonstrate the JavaScript behavior being tested. This clarifies the connection between the C++ API and the JavaScript functionality. Focus on the core aspect being tested.

6. **Summarize the Overall Functionality:**  Based on the analysis of individual tests and their JavaScript counterparts, write a concise summary of the file's purpose. Highlight the key areas being tested.

7. **Address the "Part X of Y" Instruction:** Acknowledge that this is part of a larger test suite and that it likely covers a subset of V8's API.

8. **Refine and Organize:**  Structure the summary logically, using clear language and bullet points for readability. Ensure the JavaScript examples are correct and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Simply list each test and its C++ API calls.
* **Correction:** This is too low-level. The user needs to understand the *purpose* and the JavaScript connection. Need to abstract and categorize.
* **Initial thought:**  Just show the `CompileRun` strings as JavaScript examples.
* **Correction:** These strings are often test-specific setup. Need to provide cleaner, more illustrative JavaScript examples that directly demonstrate the feature being tested.
* **Initial thought:** Focus heavily on all the C++ details.
* **Correction:** The prompt emphasizes the *JavaScript* relationship. Prioritize explaining how the C++ code tests JavaScript features.

By following this iterative process of analysis, connection, and refinement, the final summary effectively addresses the user's request.
这个C++代码文件 `v8/test/cctest/test-api.cc` 的第 15 部分，主要功能是**测试 V8 JavaScript 引擎提供的 C++ API 的各种功能和行为**。  因为它属于 `test-api.cc` 文件，所以专注于测试直接与 V8 引擎交互的 C++ 接口。

从这段代码片段来看，主要测试了以下几个方面：

1. **流式脚本编译 (Streaming Script Compilation):**
   - 测试使用 `v8::ScriptCompiler::StreamedSource` 来编译 JavaScript 代码，模拟代码分块加载的情况。
   - 验证在流式编译过程中，`sourceURL` 和 `sourceMappingURL` 的处理是否正确，即使它们出现在代码的不同片段中。

2. **获取宿主定义的选项 (Get Current Host Defined Options):**
   - 测试 `v8::Isolate::GetCurrentHostDefinedOptions()` API，用于获取宿主程序在创建 Isolate 时设置的自定义选项。
   - 通过 `v8::ScriptOrigin` 中的 `host_defined_options` 传递数据，并在 JavaScript 中通过 C++ 回调函数 `GetCurrentHostDefinedOptionsTest` 获取并验证这些选项。

3. **创建过长字符串 (New String Range Error):**
   - 测试创建超出 V8 字符串长度限制的字符串时，API 的行为，预期不会抛出异常。

4. **密封 HandleScope (Seal HandleScope):**
   - 测试 `v8::SealHandleScope` 的功能，用于限制在作用域内创建新的 V8 对象句柄，防止内存泄漏。

5. **Map 和 Set 数据结构 (Map and Set):**
   - 测试 V8 提供的 `v8::Map` 和 `v8::Set` C++ API，对应 JavaScript 中的 `Map` 和 `Set` 对象。
   - 测试它们的创建、大小、添加、删除、查找、清空等基本操作。
   - 特别测试了在删除元素后再转换为数组 (`AsArray`) 的行为，以确保不会出现未定义的元素。

6. **兼容的接收者检查 (Compatible Receiver Check On Cached IC Handler):**
   - 测试在具有继承关系的类中，当子类的实例调用父类原型链上的访问器属性时，V8 能否正确处理接收者类型，避免缓存的内联缓存 (IC) 处理器被错误地使用。

7. **访问器的接收者转换 (Receiver Conversion For Accessors):**
   - 测试在 C++ 中定义的访问器属性，当在不同类型的 JavaScript 对象上调用时，V8 能否正确地转换 `this` 指向的接收者。

8. **中断执行 (Futex Interruption and StackCheckTermination):**
   - 测试如何通过 `v8::Isolate::TerminateExecution()` 来中断 JavaScript 代码的执行，模拟超时或其他中断场景。
   - `FutexInterruption` 使用 `Atomics.wait` 来模拟一个可以被中断的等待操作。
   - `StackCheckTermination` 通过递归调用来触发栈溢出检查，并测试中断执行的效果。

9. **未捕获异常的处理 (Abort On Uncaught Exception No Abort):**
   - 测试 `v8::Isolate::SetAbortOnUncaughtExceptionCallback()` API，允许自定义未捕获异常的处理方式，而不是直接中止程序。

10. **访问检查和 @@isConcatSpreadable (AccessCheckedIsConcatSpreadable):**
    - 测试当对具有访问检查的对象使用 `concat` 方法时，`Symbol.isConcatSpreadable` 的行为。如果访问被阻止，则忽略该属性。

11. **访问检查和 @@toStringTag (AccessCheckedToStringTag):**
    - 测试当对具有访问检查的对象调用 `Object.prototype.toString` 时，`Symbol.toStringTag` 的行为。如果访问被阻止，则忽略该属性。

12. **模板迭代器原型内建属性 (TemplateIteratorPrototypeIntrinsics):**
    - 测试在对象模板和函数模板上设置 `v8::kIteratorPrototype` 内建属性的效果，确保创建的对象和函数的原型链上能正确访问到迭代器原型。

13. **模板异步迭代器原型内建属性 (TemplateAsyncIteratorPrototypeIntrinsics):**
    - 类似于迭代器原型，测试 `v8::kAsyncIteratorPrototype` 内建属性。

14. **模板错误原型内建属性 (TemplateErrorPrototypeIntrinsics):**
    - 测试在对象模板和函数模板上设置 `v8::kErrorPrototype` 内建属性的效果。

15. **对象模板数组原型内建属性 (ObjectTemplateArrayProtoIntrinsics):**
    - 测试在对象模板上设置 `v8::kArrayProto_entries`、`v8::kArrayProto_forEach`、`v8::kArrayProto_keys`、`v8::kArrayProto_values` 等内建属性的效果，验证它们指向的是 `Array.prototype` 上的相应方法。

16. **对象模板按上下文内建属性 (ObjectTemplatePerContextIntrinsics):**
    - 测试在不同 Context 中创建的对象模板实例，其内建属性指向的是各自 Context 的原型对象。

17. **Proxy 对象 (Proxy):**
    - 测试 `v8::Proxy::New` API，用于创建 JavaScript `Proxy` 对象，并测试其 `IsRevoked`、`GetTarget`、`GetHandler` 等方法。

18. **内存压力通知 (MemoryPressure):**
    - 测试 `v8::Isolate::MemoryPressureNotification()` API，用于向 V8 引擎发送内存压力通知，并观察其触发垃圾回收的行为。

19. **设置完整性级别 (SetIntegrityLevel):**
    - 测试 `v8::Object::SetIntegrityLevel()` API，用于冻结或密封 JavaScript 对象。

20. **私有符号用于 API (PrivateForApiIsNumber):**
    - 测试 `v8::Private::ForApi()` 在处理字符串参数时的行为，不应该崩溃。

21. **不可变的 __proto__ (Immutable Proto):**
    - 测试使用 `v8::FunctionTemplate::InstanceTemplate()->SetImmutableProto()` 设置对象实例的 `__proto__` 为不可变后，尝试修改 `__proto__` 的行为。

22. **跨上下文求值 (CrossActivationEval):**
    - 测试在不同的 Context 中执行 `eval` 的情况，涉及到 Context 的切换和绑定。

23. **访问检查上下文中的求值 (Eval In Access Checked Context):**
    - 测试在具有访问检查的 Context 中使用 `eval` 的行为，验证访问检查回调的影响。

24. **具有父类的不可变 __proto__ (Immutable Proto With Parent):**
    - 类似于之前的不可变 `__proto__` 测试，但这次涉及到类的继承。

25. **全局代理上的内部字段 (Internal Fields On Global Proxy):**
    - 测试在具有内部字段的对象模板创建的 Context 中，全局对象的内部字段计数。

26. **全局对象的不可变/可变 __proto__ (ImmutableProtoGlobal 和 MutableProtoGlobal):**
    - 测试设置全局对象的 `__proto__` 为不可变或可变时的行为。

27. **设置原型提供器模板 (SetPrototypeTemplate):**
    - 测试 `v8::FunctionTemplate::SetPrototypeProviderTemplate()` API，用于指定函数模板的原型应该从哪个模板获取。

28. **全局访问器信息 (GlobalAccessorInfo):**
    - 测试全局对象的访问器属性，确保访问器回调中的接收者是全局代理。

29. **确定性的随机数生成 (DeterministicRandomNumberGeneration):**
    - 测试通过设置 `i::v8_flags.random_seed` 来控制 `Math.random()` 的随机数生成，使其在不同执行中产生相同的结果。

30. **允许 Atomics.wait (AllowAtomicsWait):**
    - 测试在创建 Isolate 时禁用 `atomics_wait` 后，能否通过 `isolate->SetAllowAtomicsWait(true)` 重新启用。

31. **正确的已进入上下文 (CorrectEnteredContext):**
    - 测试 `v8::Isolate::GetEnteredOrMicrotaskContext()` API 能否正确返回当前已进入的 Context，即使在嵌套的 Context 中。

32. **动态导入 (DynamicImport 和 DynamicImportWithAttributes):**
    - 测试 `import()` 表达式的 C++ API 支持，包括自定义的 `HostImportModuleDynamicallyCallback` 用于处理模块的加载和解析。
    - `DynamicImportWithAttributes` 测试了带有 Import Attributes 的动态导入。

33. **Import Meta (ImportMeta, ImportMetaThrowUnhandled, ImportMetaThrowHandled):**
    - 测试 `import.meta` 的 C++ API 支持，包括自定义的 `HostInitializeImportMetaObjectCallback` 用于初始化 `import.meta` 对象。
    - 测试了在初始化回调中抛出异常的不同处理情况。

34. **创建 ShadowRealm 上下文 (CreateShadowRealmContextHostNotSupported, CreateShadowRealmContext, CreateShadowRealmContextThrow):**
    - 测试 ShadowRealm 的 C++ API 支持，包括自定义的 `HostCreateShadowRealmContextCallback` 用于创建新的 ShadowRealm Context。
    - 测试了当宿主不支持 ShadowRealm 或创建过程中抛出异常的情况。

35. **获取模块命名空间 (GetModuleNamespace):**
    - 测试 `v8::Module::GetModuleNamespace()` API，用于获取模块的命名空间对象。

36. **模块获取未绑定模块脚本 (ModuleGetUnboundModuleScript):**
    - 测试 `v8::Module::GetUnboundModuleScript()` API，用于获取模块的脚本对象，即使该模块尚未被实例化。

**与 JavaScript 的关系：**

所有这些测试都直接关联到 JavaScript 的功能。例如：

- **流式脚本编译** 关系到 JavaScript 代码如何逐步加载和执行。
  ```javascript
  // bar2.js (分块加载)
  function foo() { return 13; }
  globalThis.Result = foo();
  //# sourceURL=bar2.js
  ```

- **获取宿主定义的选项** 允许宿主程序向 JavaScript 环境传递配置信息。
  ```javascript
  // 在 C++ 中设置 host_defined_options
  v8::Local<v8::PrimitiveArray> host_defined_options =
      v8::PrimitiveArray::New(isolate, 1);
  host_defined_options->Set(isolate, 0, v8_num(4.2));
  // 在 JavaScript 中通过回调函数访问
  function test() {
    // 这里的实现会检查宿主传递的选项
  }
  [1].forEach(test);
  ```

- **Map 和 Set** 测试的是 JavaScript 中 `Map` 和 `Set` 数据结构的行为。
  ```javascript
  const map = new Map([[1, 2], [3, 4]]);
  console.log(map.get(1)); // 输出 2

  const set = new Set([1, 2]);
  console.log(set.has(1)); // 输出 true
  ```

- **Proxy** 测试的是 JavaScript `Proxy` 对象的功能。
  ```javascript
  const target = {};
  const handler = {
    get: function(obj, prop) {
      console.log(`有人访问了 ${prop}!`);
      return obj[prop];
    }
  };
  const proxy = new Proxy(target, handler);
  proxy.name; // 会触发 handler.get
  ```

- **动态导入** 测试的是 JavaScript 的 `import()` 表达式。
  ```javascript
  import('./my-module.js').then(module => {
    console.log(module.default);
  });
  ```

- **Import Meta** 测试的是 JavaScript 的 `import.meta` 对象。
  ```javascript
  // my-module.js
  console.log(import.meta.url);
  ```

- **ShadowRealm** 测试的是 JavaScript 的 `ShadowRealm` API。
  ```javascript
  const realm = new ShadowRealm();
  realm.evaluate('1 + 2');
  ```

总而言之，这个代码片段是 V8 引擎的底层测试，用于确保 V8 提供的 C++ API 能够正确地支持和实现各种 JavaScript 语言特性和功能。这些测试覆盖了脚本编译、对象管理、数据结构、模块加载、安全机制、以及一些高级特性。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第15部分，共18部分，请归纳一下它的功能
```

### 源代码
```
eamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8, true,
                   "bar2.js");
}


TEST(StreamingScriptWithSplitSourceURL) {
  const char* chunks[] = {"function foo() { ret",
                          "urn 13; } globalThis.Result = f",
                          "oo();\n//# sourceURL=b", "ar2.js\n", nullptr};
  RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8, true,
                   "bar2.js");
}


TEST(StreamingScriptWithSourceMappingURLInTheMiddle) {
  const char* chunks[] = {"function foo() { ret", "urn 13; }\n//#",
                          " sourceMappingURL=bar2.js\n",
                          "globalThis.Result = foo();", nullptr};
  RunStreamingTest(chunks, v8::ScriptCompiler::StreamedSource::UTF8, true,
                   nullptr, "bar2.js");
}

void GetCurrentHostDefinedOptionsTest(
    const v8::FunctionCallbackInfo<Value>& info) {
  v8::Local<v8::Data> host_defined_options =
      info.GetIsolate()->GetCurrentHostDefinedOptions().ToLocalChecked();
  CHECK(host_defined_options.As<v8::PrimitiveArray>()
            ->Get(info.GetIsolate(), 0)
            ->StrictEquals(v8_num(4.2)));
}

THREADED_TEST(TestGetCurrentHostDefinedOptions) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  context->Global()
      ->Set(context, v8_str("test"),
            v8::Function::New(context, GetCurrentHostDefinedOptionsTest)
                .ToLocalChecked())
      .ToChecked();

  {
    v8::Local<v8::PrimitiveArray> host_defined_options =
        v8::PrimitiveArray::New(isolate, 1);
    host_defined_options->Set(isolate, 0, v8_num(4.2));
    v8::ScriptOrigin origin(v8_str(""), 0, 0, false, -1, Local<v8::Value>(),
                            false, false, false, host_defined_options);
    v8::ScriptCompiler::Source source(
        v8::String::NewFromUtf8Literal(isolate, "eval('[1].forEach(test)')"),
        origin);
    v8::Local<v8::Script> script =
        v8::ScriptCompiler::Compile(context, &source).ToLocalChecked();
    script->Run(context).ToLocalChecked();
  }

  {
    v8::Local<v8::PrimitiveArray> host_defined_options =
        v8::PrimitiveArray::New(isolate, 1);
    host_defined_options->Set(isolate, 0, v8_num(4.2));
    v8::ScriptOrigin origin(v8_str(""), 0, 0, false, -1, Local<v8::Value>(),
                            false, false, true, host_defined_options);
    v8::ScriptCompiler::Source source(
        v8::String::NewFromUtf8Literal(isolate, "eval('[1].forEach(test)')"),
        origin);
    v8::Local<v8::Module> module =
        v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
    module->InstantiateModule(context, UnexpectedModuleResolveCallback)
        .ToChecked();
    module->Evaluate(context).ToLocalChecked();
  }
}

TEST(NewStringRangeError) {
  // This test uses a lot of memory and fails with flaky OOM when run
  // with --stress-incremental-marking on TSAN.
  i::v8_flags.stress_incremental_marking = false;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  const int length = i::String::kMaxLength + 1;
  const int buffer_size = length * sizeof(uint16_t);
  void* buffer = malloc(buffer_size);
  if (buffer == nullptr) return;
  memset(buffer, 'A', buffer_size);
  {
    v8::TryCatch try_catch(isolate);
    char* data = reinterpret_cast<char*>(buffer);
    CHECK(v8::String::NewFromUtf8(isolate, data, v8::NewStringType::kNormal,
                                  length)
              .IsEmpty());
    CHECK(!try_catch.HasCaught());
  }
  {
    v8::TryCatch try_catch(isolate);
    uint8_t* data = reinterpret_cast<uint8_t*>(buffer);
    CHECK(v8::String::NewFromOneByte(isolate, data, v8::NewStringType::kNormal,
                                     length)
              .IsEmpty());
    CHECK(!try_catch.HasCaught());
  }
  {
    v8::TryCatch try_catch(isolate);
    uint16_t* data = reinterpret_cast<uint16_t*>(buffer);
    CHECK(v8::String::NewFromTwoByte(isolate, data, v8::NewStringType::kNormal,
                                     length)
              .IsEmpty());
    CHECK(!try_catch.HasCaught());
  }
  free(buffer);
}


TEST(SealHandleScope) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext env;

  v8::SealHandleScope seal(isolate);

  // Should fail
  v8::Local<v8::Object> obj = v8::Object::New(isolate);

  USE(obj);
}


TEST(SealHandleScopeNested) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext env;

  v8::SealHandleScope seal(isolate);

  {
    v8::HandleScope inner_handle_scope(isolate);

    // Should work
    v8::Local<v8::Object> obj = v8::Object::New(isolate);

    USE(obj);
  }
}

TEST(Map) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext env;

  v8::Local<v8::Map> map = v8::Map::New(isolate);
  CHECK(map->IsObject());
  CHECK(map->IsMap());
  CHECK(map->GetPrototypeV2()->StrictEquals(CompileRun("Map.prototype")));
  CHECK_EQ(0U, map->Size());

  v8::Local<v8::Value> val = CompileRun("new Map([[1, 2], [3, 4]])");
  CHECK(val->IsMap());
  map = v8::Local<v8::Map>::Cast(val);
  CHECK_EQ(2U, map->Size());

  v8::Local<v8::Array> contents = map->AsArray();
  CHECK_EQ(4U, contents->Length());
  CHECK_EQ(
      1,
      contents->Get(env.local(), 0).ToLocalChecked().As<v8::Int32>()->Value());
  CHECK_EQ(
      2,
      contents->Get(env.local(), 1).ToLocalChecked().As<v8::Int32>()->Value());
  CHECK_EQ(
      3,
      contents->Get(env.local(), 2).ToLocalChecked().As<v8::Int32>()->Value());
  CHECK_EQ(
      4,
      contents->Get(env.local(), 3).ToLocalChecked().As<v8::Int32>()->Value());

  CHECK_EQ(2U, map->Size());

  CHECK(map->Has(env.local(), v8::Integer::New(isolate, 1)).FromJust());
  CHECK(map->Has(env.local(), v8::Integer::New(isolate, 3)).FromJust());

  CHECK(!map->Has(env.local(), v8::Integer::New(isolate, 2)).FromJust());
  CHECK(!map->Has(env.local(), map).FromJust());

  CHECK_EQ(2, map->Get(env.local(), v8::Integer::New(isolate, 1))
                  .ToLocalChecked()
                  ->Int32Value(env.local())
                  .FromJust());
  CHECK_EQ(4, map->Get(env.local(), v8::Integer::New(isolate, 3))
                  .ToLocalChecked()
                  ->Int32Value(env.local())
                  .FromJust());

  CHECK(map->Get(env.local(), v8::Integer::New(isolate, 42))
            .ToLocalChecked()
            ->IsUndefined());

  CHECK(!map->Set(env.local(), map, map).IsEmpty());
  CHECK_EQ(3U, map->Size());
  CHECK(map->Has(env.local(), map).FromJust());

  CHECK(map->Delete(env.local(), map).FromJust());
  CHECK_EQ(2U, map->Size());
  CHECK(!map->Has(env.local(), map).FromJust());
  CHECK(!map->Delete(env.local(), map).FromJust());

  map->Clear();
  CHECK_EQ(0U, map->Size());
}


TEST(Set) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext env;

  v8::Local<v8::Set> set = v8::Set::New(isolate);
  CHECK(set->IsObject());
  CHECK(set->IsSet());
  CHECK(set->GetPrototypeV2()->StrictEquals(CompileRun("Set.prototype")));
  CHECK_EQ(0U, set->Size());

  v8::Local<v8::Value> val = CompileRun("new Set([1, 2])");
  CHECK(val->IsSet());
  set = v8::Local<v8::Set>::Cast(val);
  CHECK_EQ(2U, set->Size());

  v8::Local<v8::Array> keys = set->AsArray();
  CHECK_EQ(2U, keys->Length());
  CHECK_EQ(1,
           keys->Get(env.local(), 0).ToLocalChecked().As<v8::Int32>()->Value());
  CHECK_EQ(2,
           keys->Get(env.local(), 1).ToLocalChecked().As<v8::Int32>()->Value());

  CHECK_EQ(2U, set->Size());

  CHECK(set->Has(env.local(), v8::Integer::New(isolate, 1)).FromJust());
  CHECK(set->Has(env.local(), v8::Integer::New(isolate, 2)).FromJust());

  CHECK(!set->Has(env.local(), v8::Integer::New(isolate, 3)).FromJust());
  CHECK(!set->Has(env.local(), set).FromJust());

  CHECK(!set->Add(env.local(), set).IsEmpty());
  CHECK_EQ(3U, set->Size());
  CHECK(set->Has(env.local(), set).FromJust());

  CHECK(set->Delete(env.local(), set).FromJust());
  CHECK_EQ(2U, set->Size());
  CHECK(!set->Has(env.local(), set).FromJust());
  CHECK(!set->Delete(env.local(), set).FromJust());

  set->Clear();
  CHECK_EQ(0U, set->Size());
}

TEST(SetDeleteThenAsArray) {
  // https://bugs.chromium.org/p/v8/issues/detail?id=4946
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext env;

  // make a Set
  v8::Local<v8::Value> val = CompileRun("new Set([1, 2, 3])");
  v8::Local<v8::Set> set = v8::Local<v8::Set>::Cast(val);
  CHECK_EQ(3U, set->Size());

  // delete the "middle" element (using AsArray to
  // determine which element is the "middle" element)
  v8::Local<v8::Array> array1 = set->AsArray();
  CHECK_EQ(3U, array1->Length());
  CHECK(set->Delete(env.local(), array1->Get(env.local(), 1).ToLocalChecked())
            .FromJust());

  // make sure there are no undefined values when we convert to an array again.
  v8::Local<v8::Array> array2 = set->AsArray();
  uint32_t length = array2->Length();
  CHECK_EQ(2U, length);
  for (uint32_t i = 0; i < length; i++) {
    CHECK(!array2->Get(env.local(), i).ToLocalChecked()->IsUndefined());
  }
}

TEST(MapDeleteThenAsArray) {
  // https://bugs.chromium.org/p/v8/issues/detail?id=4946
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext env;

  // make a Map
  v8::Local<v8::Value> val = CompileRun("new Map([[1, 2], [3, 4], [5, 6]])");
  v8::Local<v8::Map> map = v8::Local<v8::Map>::Cast(val);
  CHECK_EQ(3U, map->Size());

  // delete the "middle" element (using AsArray to
  // determine which element is the "middle" element)
  v8::Local<v8::Array> array1 = map->AsArray();
  CHECK_EQ(6U, array1->Length());
  // Map::AsArray returns a flat array, so the second key is at index 2.
  v8::Local<v8::Value> key = array1->Get(env.local(), 2).ToLocalChecked();
  CHECK(map->Delete(env.local(), key).FromJust());

  // make sure there are no undefined values when we convert to an array again.
  v8::Local<v8::Array> array2 = map->AsArray();
  uint32_t length = array2->Length();
  CHECK_EQ(4U, length);
  for (uint32_t i = 0; i < length; i++) {
    CHECK(!array2->Get(env.local(), i).ToLocalChecked()->IsUndefined());
  }
}

TEST(CompatibleReceiverCheckOnCachedICHandler) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> parent = FunctionTemplate::New(isolate);
  v8::Local<v8::Signature> signature = v8::Signature::New(isolate, parent);
  auto returns_42 =
      v8::FunctionTemplate::New(isolate, Returns42, Local<Value>(), signature);
  parent->PrototypeTemplate()->SetAccessorProperty(v8_str("age"), returns_42);
  v8::Local<v8::FunctionTemplate> child = v8::FunctionTemplate::New(isolate);
  child->Inherit(parent);
  LocalContext env;
  CHECK(env->Global()
            ->Set(env.local(), v8_str("Child"),
                  child->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  // Make sure there's a compiled stub for "Child.prototype.age" in the cache.
  CompileRun(
      "var real = new Child();\n"
      "for (var i = 0; i < 3; ++i) {\n"
      "  real.age;\n"
      "}\n");

  // Check that the cached stub is never used.
  ExpectInt32(
      "var fake = Object.create(Child.prototype);\n"
      "var result = 0;\n"
      "function test(d) {\n"
      "  if (d == 3) return;\n"
      "  try {\n"
      "    fake.age;\n"
      "    result = 1;\n"
      "  } catch (e) {\n"
      "  }\n"
      "  test(d+1);\n"
      "}\n"
      "test(0);\n"
      "result;\n",
      0);
}

THREADED_TEST(ReceiverConversionForAccessors) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> acc =
      v8::FunctionTemplate::New(isolate, Returns42);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("acc"),
                  acc->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetAccessorProperty(v8_str("acc"), acc, acc);
  Local<v8::Object> instance = templ->NewInstance(env.local()).ToLocalChecked();

  CHECK(env->Global()->Set(env.local(), v8_str("p"), instance).FromJust());
  CHECK(CompileRun("(p.acc == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(p.acc = 7) == 7")->BooleanValue(isolate));

  CHECK(!CompileRun("Number.prototype.__proto__ = p;"
                    "var a = 1;")
             .IsEmpty());
  CHECK(CompileRun("(a.acc == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(a.acc = 7) == 7")->BooleanValue(isolate));

  CHECK(!CompileRun("Boolean.prototype.__proto__ = p;"
                    "var a = true;")
             .IsEmpty());
  CHECK(CompileRun("(a.acc == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(a.acc = 7) == 7")->BooleanValue(isolate));

  CHECK(!CompileRun("String.prototype.__proto__ = p;"
                    "var a = 'foo';")
             .IsEmpty());
  CHECK(CompileRun("(a.acc == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(a.acc = 7) == 7")->BooleanValue(isolate));

  CHECK(CompileRun("acc.call(1) == 42")->BooleanValue(isolate));
  CHECK(CompileRun("acc.call(true)==42")->BooleanValue(isolate));
  CHECK(CompileRun("acc.call('aa')==42")->BooleanValue(isolate));
  CHECK(CompileRun("acc.call(null) == 42")->BooleanValue(isolate));
  CHECK(CompileRun("acc.call(undefined) == 42")->BooleanValue(isolate));
}

class TerminateExecutionThread : public v8::base::Thread {
 public:
  explicit TerminateExecutionThread(v8::Isolate* isolate)
      : Thread(Options("TerminateExecutionThread")), isolate_(isolate) {}

  void Run() override {
    // Wait a bit before terminating.
    v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));
    isolate_->TerminateExecution();
  }

 private:
  v8::Isolate* isolate_;
};

TEST(FutexInterruption) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  TerminateExecutionThread timeout_thread(isolate);

  v8::TryCatch try_catch(CcTest::isolate());
  CHECK(timeout_thread.Start());

  CompileRun(
      "var ab = new SharedArrayBuffer(4);"
      "var i32a = new Int32Array(ab);"
      "Atomics.wait(i32a, 0, 0);");
  CHECK(try_catch.HasTerminated());
  timeout_thread.Join();
}

TEST(StackCheckTermination) {
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = CcTest::i_isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  TerminateExecutionThread timeout_thread(isolate);

  v8::TryCatch try_catch(isolate);
  CHECK(timeout_thread.Start());
  auto should_continue = [i_isolate]() {
    using StackLimitCheck = i::StackLimitCheck;
    STACK_CHECK(i_isolate, false);
    return true;
  };
  while (should_continue()) {
  }
  if (i_isolate->has_exception()) i_isolate->ReportPendingMessages();
  CHECK(try_catch.HasTerminated());
  timeout_thread.Join();
}

static int nb_uncaught_exception_callback_calls = 0;


bool NoAbortOnUncaughtException(v8::Isolate* isolate) {
  ++nb_uncaught_exception_callback_calls;
  return false;
}


TEST(AbortOnUncaughtExceptionNoAbort) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  LocalContext env(nullptr, global_template);

  i::v8_flags.abort_on_uncaught_exception = true;
  isolate->SetAbortOnUncaughtExceptionCallback(NoAbortOnUncaughtException);

  CompileRun("function boom() { throw new Error(\"boom\") }");

  v8::Local<v8::Object> global_object = env->Global();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      global_object->Get(env.local(), v8_str("boom")).ToLocalChecked());

  CHECK(foo->Call(env.local(), global_object, 0, nullptr).IsEmpty());

  CHECK_EQ(1, nb_uncaught_exception_callback_calls);
}


TEST(AccessCheckedIsConcatSpreadable) {
  v8::Isolate* isolate = CcTest::isolate();
  HandleScope scope(isolate);
  LocalContext env;

  // Object with access check
  Local<ObjectTemplate> spreadable_template = v8::ObjectTemplate::New(isolate);
  spreadable_template->SetAccessCheckCallback(AccessBlocker);
  spreadable_template->Set(v8::Symbol::GetIsConcatSpreadable(isolate),
                           v8::Boolean::New(isolate, true));
  Local<Object> object =
      spreadable_template->NewInstance(env.local()).ToLocalChecked();

  allowed_access = true;
  CHECK(env->Global()->Set(env.local(), v8_str("object"), object).FromJust());
  object->Set(env.local(), v8_str("length"), v8_num(2)).FromJust();
  object->Set(env.local(), 0U, v8_str("a")).FromJust();
  object->Set(env.local(), 1U, v8_str("b")).FromJust();

  // Access check is allowed, and the object is spread
  CompileRun("var result = [].concat(object)");
  ExpectTrue("Array.isArray(result)");
  ExpectString("result[0]", "a");
  ExpectString("result[1]", "b");
  ExpectTrue("result.length === 2");
  ExpectTrue("object[Symbol.isConcatSpreadable]");

  // If access check fails, the value of @@isConcatSpreadable is ignored
  allowed_access = false;
  CompileRun("var result = [].concat(object)");
  ExpectTrue("Array.isArray(result)");
  ExpectTrue("result[0] === object");
  ExpectTrue("result.length === 1");
  ExpectTrue("object[Symbol.isConcatSpreadable] === undefined");
}


TEST(AccessCheckedToStringTag) {
  v8::Isolate* isolate = CcTest::isolate();
  HandleScope scope(isolate);
  LocalContext env;

  // Object with access check
  Local<ObjectTemplate> object_template = v8::ObjectTemplate::New(isolate);
  object_template->SetAccessCheckCallback(AccessBlocker);
  Local<Object> object =
      object_template->NewInstance(env.local()).ToLocalChecked();

  allowed_access = true;
  env->Global()->Set(env.local(), v8_str("object"), object).FromJust();
  object->Set(env.local(), v8::Symbol::GetToStringTag(isolate), v8_str("hello"))
      .FromJust();

  // Access check is allowed, and the toStringTag is read
  CompileRun("var result = Object.prototype.toString.call(object)");
  ExpectString("result", "[object hello]");
  ExpectString("object[Symbol.toStringTag]", "hello");

  // ToString through the API should succeed too.
  String::Utf8Value result_allowed(
      isolate, object->ObjectProtoToString(env.local()).ToLocalChecked());
  CHECK_EQ(0, strcmp(*result_allowed, "[object hello]"));

  // If access check fails, the value of @@toStringTag is ignored
  allowed_access = false;
  CompileRun("var result = Object.prototype.toString.call(object)");
  ExpectString("result", "[object Object]");
  ExpectTrue("object[Symbol.toStringTag] === undefined");

  // ToString through the API should also fail.
  String::Utf8Value result_denied(
      isolate, object->ObjectProtoToString(env.local()).ToLocalChecked());
  CHECK_EQ(0, strcmp(*result_denied, "[object Object]"));
}

TEST(TemplateIteratorPrototypeIntrinsics) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  // Object templates.
  {
    Local<ObjectTemplate> object_template = v8::ObjectTemplate::New(isolate);
    object_template->SetIntrinsicDataProperty(v8_str("iter_proto"),
                                              v8::kIteratorPrototype);
    Local<Object> object =
        object_template->NewInstance(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), object).FromJust());
    ExpectTrue("obj.iter_proto === [][Symbol.iterator]().__proto__.__proto__");
  }
  // Setting %IteratorProto% on the function object's prototype template.
  {
    Local<FunctionTemplate> func_template = v8::FunctionTemplate::New(isolate);
    func_template->PrototypeTemplate()->SetIntrinsicDataProperty(
        v8_str("iter_proto"), v8::kIteratorPrototype);
    Local<Function> func1 =
        func_template->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("func1"), func1).FromJust());
    Local<Function> func2 =
        func_template->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("func2"), func2).FromJust());
    ExpectTrue(
        "func1.prototype.iter_proto === "
        "[][Symbol.iterator]().__proto__.__proto__");
    ExpectTrue(
        "func2.prototype.iter_proto === "
        "[][Symbol.iterator]().__proto__.__proto__");
    ExpectTrue("func1.prototype.iter_proto === func2.prototype.iter_proto");

    Local<Object> instance1 = func1->NewInstance(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("instance1"), instance1)
              .FromJust());
    ExpectFalse("instance1.hasOwnProperty('iter_proto')");
    ExpectTrue("'iter_proto' in instance1.__proto__");
    ExpectTrue(
        "instance1.iter_proto === [][Symbol.iterator]().__proto__.__proto__");
  }
  // Put %IteratorProto% in a function object's inheritance chain.
  {
    Local<FunctionTemplate> parent_template =
        v8::FunctionTemplate::New(isolate);
    parent_template->RemovePrototype();  // Remove so there is no name clash.
    parent_template->SetIntrinsicDataProperty(v8_str("prototype"),
                                              v8::kIteratorPrototype);
    Local<FunctionTemplate> func_template = v8::FunctionTemplate::New(isolate);
    func_template->Inherit(parent_template);

    Local<Function> func =
        func_template->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("func"), func).FromJust());
    ExpectTrue(
        "func.prototype.__proto__ === "
        "[][Symbol.iterator]().__proto__.__proto__");

    Local<Object> func_instance =
        func->NewInstance(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("instance"), func_instance)
              .FromJust());
    ExpectTrue(
        "instance.__proto__.__proto__ === "
        "[][Symbol.iterator]().__proto__.__proto__");
    ExpectTrue("instance.__proto__.__proto__.__proto__ === Object.prototype");
  }
}

TEST(TemplateAsyncIteratorPrototypeIntrinsics) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  // Object templates.
  {
    Local<ObjectTemplate> object_template = v8::ObjectTemplate::New(isolate);
    object_template->SetIntrinsicDataProperty(v8_str("iter_proto"),
                                              v8::kAsyncIteratorPrototype);
    Local<Object> object =
        object_template->NewInstance(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), object).FromJust());
    ExpectTrue(
        "obj.iter_proto === "
        "(async function* (){}).prototype.__proto__.__proto__");
  }
  // Setting %AsyncIteratorProto% on the function object's prototype template.
  {
    Local<FunctionTemplate> func_template = v8::FunctionTemplate::New(isolate);
    func_template->PrototypeTemplate()->SetIntrinsicDataProperty(
        v8_str("iter_proto"), v8::kAsyncIteratorPrototype);
    Local<Function> func1 =
        func_template->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("func1"), func1).FromJust());
    Local<Function> func2 =
        func_template->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("func2"), func2).FromJust());
    ExpectTrue(
        "func1.prototype.iter_proto === "
        "(async function* (){}).prototype.__proto__.__proto__");
    ExpectTrue(
        "func2.prototype.iter_proto === "
        "(async function* (){}).prototype.__proto__.__proto__");
    ExpectTrue("func1.prototype.iter_proto === func2.prototype.iter_proto");

    Local<Object> instance1 = func1->NewInstance(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("instance1"), instance1)
              .FromJust());
    ExpectFalse("instance1.hasOwnProperty('iter_proto')");
    ExpectTrue("'iter_proto' in instance1.__proto__");
    ExpectTrue(
        "instance1.iter_proto === "
        "(async function* (){}).prototype.__proto__.__proto__");
  }
  // Put %AsyncIteratorProto% in a function object's inheritance chain.
  {
    Local<FunctionTemplate> parent_template =
        v8::FunctionTemplate::New(isolate);
    parent_template->RemovePrototype();  // Remove so there is no name clash.
    parent_template->SetIntrinsicDataProperty(v8_str("prototype"),
                                              v8::kAsyncIteratorPrototype);
    Local<FunctionTemplate> func_template = v8::FunctionTemplate::New(isolate);
    func_template->Inherit(parent_template);

    Local<Function> func =
        func_template->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("func"), func).FromJust());
    ExpectTrue(
        "func.prototype.__proto__ === "
        "(async function* (){}).prototype.__proto__.__proto__");

    Local<Object> func_instance =
        func->NewInstance(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("instance"), func_instance)
              .FromJust());
    ExpectTrue(
        "instance.__proto__.__proto__ === "
        "(async function* (){}).prototype.__proto__.__proto__");
    ExpectTrue("instance.__proto__.__proto__.__proto__ === Object.prototype");
  }
}

TEST(TemplateErrorPrototypeIntrinsics) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  // Object templates.
  {
    Local<ObjectTemplate> object_template = v8::ObjectTemplate::New(isolate);
    object_template->SetIntrinsicDataProperty(v8_str("error_proto"),
                                              v8::kErrorPrototype);
    Local<Object> object =
        object_template->NewInstance(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), object).FromJust());
    ExpectTrue("obj.error_proto === Error.prototype");
    Local<Value> error = v8::Exception::Error(v8_str("error message"));
    CHECK(env->Global()->Set(env.local(), v8_str("err"), error).FromJust());
    ExpectTrue("obj.error_proto === Object.getPrototypeOf(err)");
  }
  // Setting %ErrorPrototype% on the function object's prototype template.
  {
    Local<FunctionTemplate> func_template = v8::FunctionTemplate::New(isolate);
    func_template->PrototypeTemplate()->SetIntrinsicDataProperty(
        v8_str("error_proto"), v8::kErrorPrototype);
    Local<Function> func1 =
        func_template->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("func1"), func1).FromJust());
    Local<Function> func2 =
        func_template->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("func2"), func2).FromJust());
    ExpectTrue("func1.prototype.error_proto === Error.prototype");
    ExpectTrue("func2.prototype.error_proto === Error.prototype");
    ExpectTrue("func1.prototype.error_proto === func2.prototype.error_proto");

    Local<Object> instance1 = func1->NewInstance(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("instance1"), instance1)
              .FromJust());
    ExpectFalse("instance1.hasOwnProperty('error_proto')");
    ExpectTrue("'error_proto' in instance1.__proto__");
    ExpectTrue("instance1.error_proto === Error.prototype");
  }
  // Put %ErrorPrototype% in a function object's inheritance chain.
  {
    Local<FunctionTemplate> parent_template =
        v8::FunctionTemplate::New(isolate);
    parent_template->RemovePrototype();  // Remove so there is no name clash.
    parent_template->SetIntrinsicDataProperty(v8_str("prototype"),
                                              v8::kErrorPrototype);
    Local<FunctionTemplate> func_template = v8::FunctionTemplate::New(isolate);
    func_template->Inherit(parent_template);

    Local<Function> func =
        func_template->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("func"), func).FromJust());
    ExpectTrue("func.prototype.__proto__ === Error.prototype");

    Local<Object> func_instance =
        func->NewInstance(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("instance"), func_instance)
              .FromJust());
    ExpectTrue("instance.__proto__.__proto__.__proto__ === Object.prototype");
    // Now let's check if %ErrorPrototype% properties are in the instance.
    ExpectTrue("'constructor' in instance");
    ExpectTrue("'message' in instance");
    ExpectTrue("'name' in instance");
    ExpectTrue("'toString' in instance");
  }
}

TEST(ObjectTemplateArrayProtoIntrinsics) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  Local<ObjectTemplate> object_template = v8::ObjectTemplate::New(isolate);
  object_template->SetIntrinsicDataProperty(v8_str("prop_entries"),
                                            v8::kArrayProto_entries);
  object_template->SetIntrinsicDataProperty(v8_str("prop_forEach"),
                                            v8::kArrayProto_forEach);
  object_template->SetIntrinsicDataProperty(v8_str("prop_keys"),
                                            v8::kArrayProto_keys);
  object_template->SetIntrinsicDataProperty(v8_str("prop_values"),
                                            v8::kArrayProto_values);
  Local<Object> object =
      object_template->NewInstance(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("obj1"), object).FromJust());

  const struct {
    const char* const object_property_name;
    const char* const array_property_name;
  } intrinsics_comparisons[] = {
      {"prop_entries", "Array.prototype.entries"},
      {"prop_forEach", "Array.prototype.forEach"},
      {"prop_keys", "Array.prototype.keys"},
      {"prop_values", "Array.prototype[Symbol.iterator]"},
  };

  for (unsigned i = 0; i < arraysize(intrinsics_comparisons); i++) {
    v8::base::ScopedVector<char> test_string(64);

    v8::base::SNPrintF(test_string, "typeof obj1.%s",
                       intrinsics_comparisons[i].object_property_name);
    ExpectString(test_string.begin(), "function");

    v8::base::SNPrintF(test_string, "obj1.%s === %s",
                       intrinsics_comparisons[i].object_property_name,
                       intrinsics_comparisons[i].array_property_name);
    ExpectTrue(test_string.begin());

    v8::base::SNPrintF(test_string, "obj1.%s = 42",
                       intrinsics_comparisons[i].object_property_name);
    CompileRun(test_string.begin());

    v8::base::SNPrintF(test_string, "obj1.%s === %s",
                       intrinsics_comparisons[i].object_property_name,
                       intrinsics_comparisons[i].array_property_name);
    ExpectFalse(test_string.begin());

    v8::base::SNPrintF(test_string, "typeof obj1.%s",
                       intrinsics_comparisons[i].object_property_name);
    ExpectString(test_string.begin(), "number");
  }
}

TEST(ObjectTemplatePerContextIntrinsics) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  Local<ObjectTemplate> object_template = v8::ObjectTemplate::New(isolate);
  object_template->SetIntrinsicDataProperty(v8_str("values"),
                                            v8::kArrayProto_values);
  Local<Object> object =
      object_template->NewInstance(env.local()).ToLocalChecked();

  CHECK(env->Global()->Set(env.local(), v8_str("obj1"), object).FromJust());
  ExpectString("typeof obj1.values", "function");

  auto values = Local<Function>::Cast(
      object->Get(env.local(), v8_str("values")).ToLocalChecked());
  auto fn = i::Cast<i::JSFunction>(v8::Utils::OpenHandle(*values));
  auto ctx = v8::Utils::OpenHandle(*env.local());
  CHECK_EQ(fn->GetCreationContext().value(), *ctx);

  {
    LocalContext env2;
    Local<Object> object2 =
        object_template->NewInstance(env2.local()).ToLocalChecked();
    CHECK(
        env2->Global()->Set(env2.local(), v8_str("obj2"), object2).FromJust());
    ExpectString("typeof obj2.values", "function");
    CHECK_NE(*object->Get(env2.local(), v8_str("values")).ToLocalChecked(),
             *object2->Get(env2.local(), v8_str("values")).ToLocalChecked());

    auto values2 = Local<Function>::Cast(
        object2->Get(env2.local(), v8_str("values")).ToLocalChecked());
    auto fn2 = i::Cast<i::JSFunction>(v8::Utils::OpenHandle(*values2));
    auto ctx2 = v8::Utils::OpenHandle(*env2.local());
    CHECK_EQ(fn2->GetCreationContext().value(), *ctx2);
  }
}


TEST(Proxy) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> target = CompileRun("({})").As<v8::Object>();
  v8::Local<v8::Object> handler = CompileRun("({})").As<v8::Object>();

  v8::Local<v8::Proxy> proxy =
      v8::Proxy::New(context.local(), target, handler).ToLocalChecked();
  CHECK(proxy->IsProxy());
  CHECK(!target->IsProxy());
  CHECK(!proxy->IsRevoked());
  CHECK(proxy->GetTarget()->SameValue(target));
  CHECK(proxy->GetHandler()->SameValue(handler));

  proxy->Revoke();
  CHECK(proxy->IsProxy());
  CHECK(!target->IsProxy());
  CHECK(proxy->IsRevoked());
  CHECK(proxy->GetTarget()->IsNull());
  CHECK(proxy->GetHandler()->IsNull());
}

WeakCallCounterAndPersistent<Value>* CreateGarbageWithWeakCallCounter(
    v8::Isolate* isolate, WeakCallCounter* counter) {
  v8::Locker locker(isolate);
  LocalContext env;
  HandleScope scope(isolate);
  WeakCallCounterAndPersistent<Value>* val =
      new WeakCallCounterAndPersistent<Value>(counter);
  val->handle.Reset(isolate, Object::New(isolate));
  val->handle.SetWeak(val, &WeakPointerCallback,
                      v8::WeakCallbackType::kParameter);
  return val;
}

class MemoryPressureThread : public v8::base::Thread {
 public:
  explicit MemoryPressureThread(v8::Isolate* isolate,
                                v8::MemoryPressureLevel level)
      : Thread(Options("MemoryPressureThread")),
        isolate_(isolate),
        level_(level) {}

  void Run() override { isolate_->MemoryPressureNotification(level_); }

 private:
  v8::Isolate* isolate_;
  v8::MemoryPressureLevel level_;
};

TEST(MemoryPressure) {
  if (i::v8_flags.optimize_for_size) return;
  v8::Isolate* isolate = CcTest::isolate();
  WeakCallCounter counter(1234);

  // Conservative stack scanning might break results.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  // Check that critical memory pressure notification sets GC interrupt.
  auto garbage = CreateGarbageWithWeakCallCounter(isolate, &counter);
  CHECK(!v8::Locker::IsLocked(isolate));
  {
    v8::Locker locker(isolate);
    v8::HandleScope scope(isolate);
    LocalContext env;
    MemoryPressureThread memory_pressure_thread(
        isolate, v8::MemoryPressureLevel::kCritical);
    CHECK(memory_pressure_thread.Start());
    memory_pressure_thread.Join();
    // This should trigger GC.
    CHECK_EQ(0, counter.NumberOfWeakCalls());
    CompileRun("(function noop() { return 0; })()");
    CHECK_EQ(1, counter.NumberOfWeakCalls());
  }
  delete garbage;
  // Check that critical memory pressure notification triggers GC.
  garbage = CreateGarbageWithWeakCallCounter(isolate, &counter);
  {
    v8::Locker locker(isolate);
    // If isolate is locked, memory pressure notification should trigger GC.
    CHECK_EQ(1, counter.NumberOfWeakCalls());
    isolate->MemoryPressureNotification(v8::MemoryPressureLevel::kCritical);
    CHECK_EQ(2, counter.NumberOfWeakCalls());
  }
  delete garbage;
  // Check that moderate memory pressure notification sets GC into memory
  // optimizing mode.
  isolate->MemoryPressureNotification(v8::MemoryPressureLevel::kModerate);
  CHECK(CcTest::i_isolate()->heap()->ShouldOptimizeForMemoryUsage());
  // Check that disabling memory pressure returns GC into normal mode.
  isolate->MemoryPressureNotification(v8::MemoryPressureLevel::kNone);
  CHECK(!CcTest::i_isolate()->heap()->ShouldOptimizeForMemoryUsage());
}

TEST(SetIntegrityLevel) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  CHECK(context->Global()->Set(context.local(), v8_str("o"), obj).FromJust());

  v8::Local<v8::Value> is_frozen = CompileRun("Object.isFrozen(o)");
  CHECK(!is_frozen->BooleanValue(isolate));

  CHECK(obj->SetIntegrityLevel(context.local(), v8::IntegrityLevel::kFrozen)
            .FromJust());

  is_frozen = CompileRun("Object.isFrozen(o)");
  CHECK(is_frozen->BooleanValue(isolate));
}

TEST(PrivateForApiIsNumber) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Shouldn't crash.
  v8::Private::ForApi(isolate, v8_str("42"));
}

THREADED_TEST(ImmutableProto) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetImmutableProto();

  Local<v8::Object> object = templ->GetFunction(context.local())
                                 .ToLocalChecked()
                                 ->NewInstance(context.local())
                                 .ToLocalChecked();

  // Look up the prototype
  Local<v8::Value> original_proto =
      object->Get(context.local(), v8_str("__proto__")).ToLocalChecked();

  // Setting the prototype (e.g., to null) throws
  CHECK(object->SetPrototypeV2(context.local(), v8::Null(isolate)).IsNothing());

  // The original prototype is still there
  Local<Value> new_proto =
      object->Get(context.local(), v8_str("__proto__")).ToLocalChecked();
  CHECK(new_proto->IsObject());
  CHECK(new_proto.As<v8::Object>()
            ->Equals(context.local(), original_proto)
            .FromJust());
}

namespace {

v8::Global<v8::Context> call_eval_context_global;
v8::Global<v8::Function> call_eval_bound_function_global;

void CallEval(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  Local<v8::Context> call_eval_context = call_eval_context_global.Get(isolate);
  Local<v8::Function> call_eval_bound_function =
      call_eval_bound_function_global.Get(isolate);
  v8::Context::Scope scope(call_eval_context);
  info.GetReturnValue().Set(
      call_eval_bound_function
          ->Call(call_eval_context, call_eval_context->Global(), 0, nullptr)
          .ToLocalChecked());
}

}  // namespace

TEST(CrossActivationEval) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  {
    Local<v8::Context> call_eval_context = v8::Context::New(isolate);
    call_eval_context_global.Reset(isolate, call_eval_context);
    v8::Context::Scope context_scope(call_eval_context);
    v8::Local<v8::Function> call_eval_bound_function =
        Local<Function>::Cast(CompileRun("eval.bind(this, '1')"));
    call_eval_bound_function_global.Reset(isolate, call_eval_bound_function);
  }
  env->Global()
      ->Set(env.local(), v8_str("CallEval"),
            v8::FunctionTemplate::New(isolate, CallEval)
                ->GetFunction(env.local())
                .ToLocalChecked())
      .FromJust();
  Local<Value> result = CompileRun("CallEval();");
  CHECK(result->IsInt32());
  CHECK_EQ(1, result->Int32Value(env.local()).FromJust());
  call_eval_context_global.Reset();
  call_eval_bound_function_global.Reset();
}

TEST(EvalInAccessCheckedContext) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> obj_template = v8::ObjectTemplate::New(isolate);

  obj_template->SetAccessCheckCallback(AccessAlwaysAllowed);

  v8::Local<Context> context0 = Context::New(isolate, nullptr, obj_template);
  v8::Local<Context> context1 = Context::New(isolate, nullptr, obj_template);

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to different domains.
  context0->SetSecurityToken(foo);
  context1->SetSecurityToken(bar);

  // Set up function in context0 that uses eval from context0.
  context0->Enter();
  v8::Local<v8::Value> fun = CompileRun(
      "var x = 42;"
      "(function() {"
      "  var e = eval;"
      "  return function(s) { return e(s); }"
      "})()");
  context0->Exit();

  // Put the function into context1 and call it. Since the access check
  // callback always returns true, the call succeeds even though the tokens
  // are different.
  context1->Enter();
  context1->Global()->Set(context1, v8_str("fun"), fun).FromJust();
  v8::Local<v8::Value> x_value = CompileRun("fun('x')");
  CHECK_EQ(42, x_value->Int32Value(context1).FromJust());
  context1->Exit();
}

THREADED_TEST(ImmutableProtoWithParent) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> parent = v8::FunctionTemplate::New(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->Inherit(parent);
  templ->PrototypeTemplate()->SetImmutableProto();

  Local<v8::Function> function =
      templ->GetFunction(context.local()).ToLocalChecked();
  Local<v8::Object> instance =
      function->NewInstance(context.local()).ToLocalChecked();
  Local<v8::Object> prototype =
      instance->Get(context.local(), v8_str("__proto__"))
          .ToLocalChecked()
          ->ToObject(context.local())
          .ToLocalChecked();

  // Look up the prototype
  Local<v8::Value> original_proto =
      prototype->Get(context.local(), v8_str("__proto__")).ToLocalChecked();

  // Setting the prototype (e.g., to null) throws
  CHECK(prototype->SetPrototypeV2(context.local(), v8::Null(isolate))
            .IsNothing());

  // The original prototype is still there
  Local<Value> new_proto =
      prototype->Get(context.local(), v8_str("__proto__")).ToLocalChecked();
  CHECK(new_proto->IsObject());
  CHECK(new_proto.As<v8::Object>()
            ->Equals(context.local(), original_proto)
            .FromJust());
}

TEST(InternalFieldsOnGlobalProxy) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> obj_template = v8::ObjectTemplate::New(isolate);
  obj_template->SetInternalFieldCount(1);

  v8::Local<v8::Context> context = Context::New(isolate, nullptr, obj_template);
  v8::Local<v8::Object> global = context->Global();
  CHECK_EQ(1, global->InternalFieldCount());
}

THREADED_TEST(ImmutableProtoGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
  global_template->SetImmutableProto();
  v8::Local<Context> context = Context::New(isolate, nullptr, global_template);
  Context::Scope context_scope(context);
  v8::Local<Value> result = CompileRun(
      "global = this;"
      "(function() {"
      "  try {"
      "    global.__proto__ = {};"
      "    return 0;"
      "  } catch (e) {"
      "    return 1;"
      "  }"
      "})()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 1))
            .FromJust());
}

THREADED_TEST(MutableProtoGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
  v8::Local<Context> context = Context::New(isolate, nullptr, global_template);
  Context::Scope context_scope(context);
  v8::Local<Value> result = CompileRun(
      "global = this;"
      "(function() {"
      "  try {"
      "    global.__proto__ = {};"
      "    return 0;"
      "  } catch (e) {"
      "    return 1;"
      "  }"
      "})()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 0))
            .FromJust());
}

TEST(SetPrototypeTemplate) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<FunctionTemplate> HTMLElementTemplate = FunctionTemplate::New(isolate);
  Local<FunctionTemplate> HTMLImageElementTemplate =
      FunctionTemplate::New(isolate);
  HTMLImageElementTemplate->Inherit(HTMLElementTemplate);

  Local<FunctionTemplate> ImageTemplate = FunctionTemplate::New(isolate);
  ImageTemplate->SetPrototypeProviderTemplate(HTMLImageElementTemplate);

  Local<Function> HTMLImageElement =
      HTMLImageElementTemplate->GetFunction(env.local()).ToLocalChecked();
  Local<Function> Image =
      ImageTemplate->GetFunction(env.local()).ToLocalChecked();

  CHECK(env->Global()
            ->Set(env.local(), v8_str("HTMLImageElement"), HTMLImageElement)
            .FromJust());
  CHECK(env->Global()->Set(env.local(), v8_str("Image"), Image).FromJust());

  ExpectTrue("Image.prototype === HTMLImageElement.prototype");
}

void ensure_receiver_is_global_proxy(
    v8::Local<v8::Name>, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(*info.This())));
}

THREADED_TEST(GlobalAccessorInfo) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::ObjectTemplate> global_template = v8::ObjectTemplate::New(isolate);
  global_template->SetNativeDataProperty(
      v8::String::NewFromUtf8Literal(isolate, "prop",
                                     v8::NewStringType::kInternalized),
      &ensure_receiver_is_global_proxy);
  LocalContext env(nullptr, global_template);
  CompileRun("for (var i = 0; i < 10; i++) this.prop");
  CompileRun("for (var i = 0; i < 10; i++) prop");
}

TEST(DeterministicRandomNumberGeneration) {
  v8::HandleScope scope(CcTest::isolate());

  int previous_seed = i::v8_flags.random_seed;
  i::v8_flags.random_seed = 1234;

  double first_value;
  double second_value;
  {
    v8::Local<Context> context = Context::New(CcTest::isolate());
    Context::Scope context_scope(context);
    v8::Local<Value> result = CompileRun("Math.random();");
    first_value = result->ToNumber(context).ToLocalChecked()->Value();
  }
  {
    v8::Local<Context> context = Context::New(CcTest::isolate());
    Context::Scope context_scope(context);
    v8::Local<Value> result = CompileRun("Math.random();");
    second_value = result->ToNumber(context).ToLocalChecked()->Value();
  }
  CHECK_EQ(first_value, second_value);

  i::v8_flags.random_seed = previous_seed;
}

UNINITIALIZED_TEST(AllowAtomicsWait) {
  v8::Isolate::CreateParams create_params;
  create_params.allow_atomics_wait = false;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  {
    CHECK_EQ(false, i_isolate->allow_atomics_wait());
    isolate->SetAllowAtomicsWait(true);
    CHECK_EQ(true, i_isolate->allow_atomics_wait());
  }
  isolate->Dispose();
}

enum ContextId { EnteredContext, CurrentContext };

void CheckContexts(v8::Isolate* isolate) {
  CHECK_EQ(CurrentContext, isolate->GetCurrentContext()
                               ->GetEmbedderData(1)
                               .As<v8::Integer>()
                               ->Value());
  CHECK_EQ(EnteredContext, isolate->GetEnteredOrMicrotaskContext()
                               ->GetEmbedderData(1)
                               .As<v8::Integer>()
                               ->Value());
}

void ContextCheckGetter(Local<Name> name,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CheckContexts(info.GetIsolate());
  info.GetReturnValue().Set(true);
}

void ContextCheckSetter(Local<Name> name, Local<Value>,
                        const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CheckContexts(info.GetIsolate());
}

void ContextCheckToString(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CheckContexts(info.GetIsolate());
  info.GetReturnValue().Set(v8_str("foo"));
}

TEST(CorrectEnteredContext) {
  v8::HandleScope scope(CcTest::isolate());

  LocalContext currentContext;
  currentContext->SetEmbedderData(
      1, v8::Integer::New(currentContext->GetIsolate(), CurrentContext));
  LocalContext enteredContext;
  enteredContext->SetEmbedderData(
      1, v8::Integer::New(enteredContext->GetIsolate(), EnteredContext));

  v8::Context::Scope contextScope(enteredContext.local());

  v8::Local<v8::ObjectTemplate> object_template =
      ObjectTemplate::New(currentContext->GetIsolate());
  object_template->SetNativeDataProperty(v8_str("p"), &ContextCheckGetter,
                                         &ContextCheckSetter);

  v8::Local<v8::Object> object =
      object_template->NewInstance(currentContext.local()).ToLocalChecked();

  object->Get(currentContext.local(), v8_str("p")).ToLocalChecked();
  object->Set(currentContext.local(), v8_str("p"), v8_int(0)).FromJust();

  v8::Local<v8::Function> to_string =
      v8::Function::New(currentContext.local(), ContextCheckToString)
          .ToLocalChecked();

  to_string->Call(currentContext.local(), object, 0, nullptr).ToLocalChecked();

  object
      ->CreateDataProperty(currentContext.local(), v8_str("toString"),
                           to_string)
      .FromJust();

  object->ToString(currentContext.local()).ToLocalChecked();
}

// For testing only, the host-defined options are provided entirely by the host
// and have an abritrary length. Use this constant here for testing that we get
// the correct value during the tests.
const int kCustomHostDefinedOptionsLengthForTesting = 7;

v8::MaybeLocal<v8::Promise> HostImportModuleDynamicallyCallbackResolve(
    Local<v8::Context> context, Local<v8::Data> host_defined_options,
    Local<v8::Value> resource_name, Local<v8::String> specifier,
    Local<v8::FixedArray> import_attributes) {
  String::Utf8Value referrer_utf8(context->GetIsolate(),
                                  resource_name.As<String>());
  CHECK_EQ(0, strcmp("www.google.com", *referrer_utf8));
  CHECK_EQ(host_defined_options.As<v8::FixedArray>()->Length(),
           kCustomHostDefinedOptionsLengthForTesting);
  CHECK(!specifier.IsEmpty());
  String::Utf8Value specifier_utf8(context->GetIsolate(), specifier);
  CHECK_EQ(0, strcmp("index.js", *specifier_utf8));

  CHECK_EQ(0, import_attributes->Length());

  Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context).ToLocalChecked();
  auto result = v8_str("hello world");
  resolver->Resolve(context, result).ToChecked();
  return resolver->GetPromise();
}

TEST(DynamicImport) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->SetHostImportModuleDynamicallyCallback(
      HostImportModuleDynamicallyCallbackResolve);

  i::DirectHandle<i::String> url =
      v8::Utils::OpenDirectHandle(*v8_str("www.google.com"));
  i::Handle<i::Object> specifier(v8::Utils::OpenHandle(*v8_str("index.js")));
  i::DirectHandle<i::String> result =
      v8::Utils::OpenDirectHandle(*v8_str("hello world"));
  i::DirectHandle<i::String> source =
      v8::Utils::OpenDirectHandle(*v8_str("foo"));
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Handle<i::Script> referrer = i_isolate->factory()->NewScript(source);
  referrer->set_name(*url);
  i::DirectHandle<i::FixedArray> options = i_isolate->factory()->NewFixedArray(
      kCustomHostDefinedOptionsLengthForTesting);
  referrer->set_host_defined_options(*options);
  i::MaybeHandle<i::JSPromise> maybe_promise =
      i_isolate->RunHostImportModuleDynamicallyCallback(
          referrer, specifier, v8::ModuleImportPhase::kEvaluation,
          i::MaybeHandle<i::Object>());
  i::DirectHandle<i::JSPromise> promise = maybe_promise.ToHandleChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK(result->Equals(i::Cast<i::String>(promise->result())));
}

v8::MaybeLocal<v8::Promise>
HostImportModuleDynamicallyWithAttributesCallbackResolve(
    Local<v8::Context> context, Local<v8::Data> host_defined_options,
    Local<v8::Value> resource_name, Local<v8::String> specifier,
    Local<v8::FixedArray> import_attributes) {
  String::Utf8Value referrer_utf8(context->GetIsolate(),
                                  resource_name.As<String>());
  CHECK_EQ(0, strcmp("www.google.com", *referrer_utf8));
  CHECK_EQ(host_defined_options.As<v8::FixedArray>()->Length(),
           kCustomHostDefinedOptionsLengthForTesting);

  CHECK(!specifier.IsEmpty());
  String::Utf8Value specifier_utf8(context->GetIsolate(), specifier);
  CHECK_EQ(0, strcmp("index.js", *specifier_utf8));

  CHECK_EQ(8, import_attributes->Length());
  constexpr int kAttributeEntrySizeForDynamicImport = 2;
  for (int i = 0;
       i < import_attributes->Length() / kAttributeEntrySizeForDynamicImport;
       ++i) {
    Local<String> attribute_key =
        import_attributes
            ->Get(context, (i * kAttributeEntrySizeForDynamicImport))
            .As<Value>()
            .As<String>();
    Local<String> attribute_value =
        import_attributes
            ->Get(context, (i * kAttributeEntrySizeForDynamicImport) + 1)
            .As<Value>()
            .As<String>();
    if (v8_str("a")->StrictEquals(attribute_key)) {
      CHECK(v8_str("z")->StrictEquals(attribute_value));
    } else if (v8_str("aa")->StrictEquals(attribute_key)) {
      CHECK(v8_str("x")->StrictEquals(attribute_value));
    } else if (v8_str("b")->StrictEquals(attribute_key)) {
      CHECK(v8_str("w")->StrictEquals(attribute_value));
    } else if (v8_str("c")->StrictEquals(attribute_key)) {
      CHECK(v8_str("y")->StrictEquals(attribute_value));
    } else {
      UNREACHABLE();
    }
  }

  Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context).ToLocalChecked();
  auto result = v8_str("hello world");
  resolver->Resolve(context, result).ToChecked();
  return resolver->GetPromise();
}

TEST(DynamicImportWithAttributes) {
  FLAG_SCOPE(harmony_import_attributes);

  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->SetHostImportModuleDynamicallyCallback(
      HostImportModuleDynamicallyWithAttributesCallbackResolve);

  i::DirectHandle<i::String> url =
      v8::Utils::OpenDirectHandle(*v8_str("www.google.com"));
  i::Handle<i::Object> specifier(v8::Utils::OpenHandle(*v8_str("index.js")));
  i::DirectHandle<i::String> result =
      v8::Utils::OpenDirectHandle(*v8_str("hello world"));
  i::DirectHandle<i::String> source(v8::Utils::OpenHandle(*v8_str("foo")));
  v8::Local<v8::Object> import_options =
      CompileRun(
          "var arg = { with: { 'b': 'w', aa: 'x',  c: 'y', a: 'z'} };"
          "arg;")
          ->ToObject(context.local())
          .ToLocalChecked();

  i::Handle<i::Object> i_import_options =
      v8::Utils::OpenHandle(*import_options);

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Handle<i::Script> referrer = i_isolate->factory()->NewScript(source);
  referrer->set_name(*url);
  i::DirectHandle<i::FixedArray> options = i_isolate->factory()->NewFixedArray(
      kCustomHostDefinedOptionsLengthForTesting);
  referrer->set_host_defined_options(*options);
  i::MaybeHandle<i::JSPromise> maybe_promise =
      i_isolate->RunHostImportModuleDynamicallyCallback(
          referrer, specifier, v8::ModuleImportPhase::kEvaluation,
          i_import_options);
  i::DirectHandle<i::JSPromise> promise = maybe_promise.ToHandleChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK(result->Equals(i::Cast<i::String>(promise->result())));
}

void HostInitializeImportMetaObjectCallbackStatic(Local<Context> context,
                                                  Local<Module> module,
                                                  Local<Object> meta) {
  CHECK(!module.IsEmpty());
  meta->CreateDataProperty(context, v8_str("foo"), v8_str("bar")).ToChecked();
}

TEST(ImportMeta) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostInitializeImportMetaObjectCallback(
      HostInitializeImportMetaObjectCallbackStatic);

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("globalThis.Result = import.meta;");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  i::Handle<i::JSObject> meta =
      i::SourceTextModule::GetImportMeta(
          i_isolate,
          i::Cast<i::SourceTextModule>(v8::Utils::OpenHandle(*module)))
          .ToHandleChecked();
  Local<Object> meta_obj = Local<Object>::Cast(v8::Utils::ToLocal(meta));
  CHECK(meta_obj->Get(context.local(), v8_str("foo"))
            .ToLocalChecked()
            ->IsString());
  CHECK(meta_obj->Get(context.local(), v8_str("zapp"))
            .ToLocalChecked()
            ->IsUndefined());

  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();
  Local<Value> result = module->Evaluate(context.local()).ToLocalChecked();
  Local<v8::Promise> promise(Local<v8::Promise>::Cast(result));
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
  CHECK(promise->Result()->IsUndefined());
  CHECK(context.local()
            ->Global()
            ->Get(context.local(), v8_str("Result"))
            .ToLocalChecked()
            ->StrictEquals(Local<v8::Value>::Cast(v8::Utils::ToLocal(meta))));
}

void HostInitializeImportMetaObjectCallbackThrow(Local<Context> context,
                                                 Local<Module> module,
                                                 Local<Object> meta) {
  CcTest::isolate()->ThrowException(v8_num(42));
}

TEST(ImportMetaThrowUnhandled) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostInitializeImportMetaObjectCallback(
      HostInitializeImportMetaObjectCallbackThrow);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text =
      v8_str("export default function() { return import.meta }");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();

  Local<Value> result = module->Evaluate(context.local()).ToLocalChecked();
  auto promise = Local<v8::Promise>::Cast(result);
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);

  Local<Object> ns = module->GetModuleNamespace().As<Object>();
  Local<Value> closure =
      ns->Get(context.local(), v8_str("default")).ToLocalChecked();

  v8::TryCatch try_catch(isolate);
  CHECK(Function::Cast(*closure)
            ->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.Exception()->StrictEquals(v8_num(42)));
}

TEST(ImportMetaThrowHandled) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostInitializeImportMetaObjectCallback(
      HostInitializeImportMetaObjectCallbackThrow);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str(R"javascript(
      export default function() {
        try {
          import.meta;
        } catch {
          return true;
        }
        return false;
      }
      )javascript");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();

  Local<Value> result = module->Evaluate(context.local()).ToLocalChecked();
  auto promise = Local<v8::Promise>::Cast(result);
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);

  Local<Object> ns = module->GetModuleNamespace().As<Object>();
  Local<Value> closure =
      ns->Get(context.local(), v8_str("default")).ToLocalChecked();

  v8::TryCatch try_catch(isolate);
  CHECK(Function::Cast(*closure)
            ->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
            .ToLocalChecked()
            ->IsTrue());
  CHECK(!try_catch.HasCaught());
}

v8::MaybeLocal<v8::Context> HostCreateShadowRealmContextCallbackStatic(
    v8::Local<v8::Context> initiator_context) {
  CHECK(!initiator_context.IsEmpty());
  return v8::Context::New(initiator_context->GetIsolate());
}

TEST(CreateShadowRealmContextHostNotSupported) {
  i::v8_flags.harmony_shadow_realm = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("new ShadowRealm()");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, false);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(context.local(), &source).ToLocalChecked();

  v8::TryCatch try_catch(isolate);
  v8::MaybeLocal<v8::Value> result = script->Run(context.local());
  CHECK(try_catch.HasCaught());
  CHECK(result.IsEmpty());
  CHECK(v8_str("Error: Not supported")
            ->Equals(isolate->GetCurrentContext(),
                     try_catch.Exception()
                         ->ToString(isolate->GetCurrentContext())
                         .ToLocalChecked())
            .FromJust());
}

TEST(CreateShadowRealmContext) {
  i::v8_flags.harmony_shadow_realm = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostCreateShadowRealmContextCallback(
      HostCreateShadowRealmContextCallbackStatic);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("new ShadowRealm()");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, false);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(context.local(), &source).ToLocalChecked();

  Local<Value> result = script->Run(context.local()).ToLocalChecked();
  CHECK(result->IsObject());
  i::DirectHandle<i::Object> object = v8::Utils::OpenDirectHandle(*result);
  CHECK(IsJSShadowRealm(*object));
}

v8::MaybeLocal<v8::Context> HostCreateShadowRealmContextCallbackThrow(
    v8::Local<v8::Context> initiator_context) {
  CcTest::isolate()->ThrowException(v8_num(42));
  return v8::MaybeLocal<v8::Context>();
}

TEST(CreateShadowRealmContextThrow) {
  i::v8_flags.harmony_shadow_realm = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetHostCreateShadowRealmContextCallback(
      HostCreateShadowRealmContextCallbackThrow);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("new ShadowRealm()");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, false);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(context.local(), &source).ToLocalChecked();

  v8::TryCatch try_catch(isolate);
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.Exception()->StrictEquals(v8_num(42)));
}

TEST(GetModuleNamespace) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("export default 5; export const a = 10;");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();
  module->Evaluate(context.local()).ToLocalChecked();

  Local<Value> ns_val = module->GetModuleNamespace();
  CHECK(ns_val->IsModuleNamespaceObject());
  Local<Object> ns = ns_val.As<Object>();
  CHECK(ns->Get(context.local(), v8_str("default"))
            .ToLocalChecked()
            ->StrictEquals(v8::Number::New(isolate, 5)));
  CHECK(ns->Get(context.local(), v8_str("a"))
            .ToLocalChecked()
            ->StrictEquals(v8::Number::New(isolate, 10)));
}

TEST(ModuleGetUnboundModuleScript) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<String> url = v8_str("www.google.c
```