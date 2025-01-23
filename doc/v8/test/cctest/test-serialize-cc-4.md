Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-serialize.cc`. I need to analyze the code and identify its main purpose and features.

Here's a breakdown of the code's key aspects:

1. **Snapshot Creation and Deserialization:** The core of the code revolves around creating and deserializing V8 snapshots. This is evident from the use of `v8::SnapshotCreator` and the loading of snapshot blobs (`v8::StartupData`).

2. **Context Management:** The code manipulates multiple V8 contexts. It creates contexts, sets default contexts for snapshots, and retrieves contexts from snapshots.

3. **External References:**  The code deals with external references, which are pointers to C++ functions or data that are referenced from within the V8 snapshot. It tests scenarios with different sets of external references, including cases where the deserialization uses a different set than the creation.

4. **Callbacks and Accessors:** The code defines and uses V8 callbacks (`SerializedCallback`, `SerializedCallbackReplacement`) and property accessors (`NamedPropertyGetterForSerialization`, `AccessorForSerialization`). These are serialized and deserialized as part of the snapshot.

5. **Internal Fields:** The code demonstrates the serialization and deserialization of internal fields of V8 objects and context embedder data. It uses callbacks (`SerializeInternalFields`, `DeserializeInternalFields`, `SerializeContextData`, `DeserializeContextData`) for this purpose.

6. **Function Code Handling:** The code uses `v8::SnapshotCreator::FunctionCodeHandling::kClear` and `kKeep` to control how function code is handled during snapshot creation.

7. **Testing Scenarios:** The code consists of several `UNINITIALIZED_TEST` and `TEST` blocks, indicating that it's part of a test suite for the serialization functionality. Each test focuses on a specific aspect of snapshot creation and deserialization.

Based on these observations, I can formulate the summary of the code's functionality. I also need to address the user's specific requests regarding Torque, JavaScript examples, logic inference, common programming errors, and the part number.
这是 `v8/test/cctest/test-serialize.cc` 的一个代码片段，主要功能是 **测试 V8 的快照（Snapshot）创建和反序列化机制**，特别是针对以下方面的测试：

1. **多上下文快照：** 测试在一个快照中包含多个 V8 上下文的能力，以及在反序列化时恢复这些上下文。
2. **外部引用：** 测试快照中对外部 C++ 函数和数据的引用，以及在反序列化时如何处理这些引用（包括使用相同的引用、替换引用和缺少引用的情况）。
3. **序列化回调函数：** 测试序列化包含 C++ 回调函数的 JavaScript 函数，并在反序列化后调用这些回调函数。
4. **序列化属性访问器：** 测试序列化带有 C++ 属性访问器的对象，并在反序列化后访问这些属性。
5. **外部字符串：** 测试序列化和反序列化指向外部内存的字符串（`v8::String::NewExternalOneByte` 和 `v8::String::NewExternalTwoByte`）。
6. **快照创建选项：** 测试 `SnapshotCreator::FunctionCodeHandling` 选项，例如 `kClear` (清除函数代码) 和 `kKeep` (保留函数代码)。
7. **模板和内部字段：** 测试序列化和反序列化对象模板和对象的内部字段，包括使用回调函数自定义序列化和反序列化过程。
8. **上下文数据：** 测试序列化和反序列化与 V8 上下文关联的嵌入器数据。

**关于代码片段的分析：**

*   **`UNINITIALIZED_TEST(SnapshotCreatorMultipleContexts)`**:
    *   **功能:** 测试创建包含多个上下文的快照，并在反序列化时恢复这些上下文。
    *   **代码逻辑推理:**
        *   **假设输入:** 创建一个 `SnapshotCreator`，依次创建和添加三个上下文，每个上下文都定义了一个全局变量 `f`，但 `f` 的行为不同。
        *   **预期输出:** 反序列化后，创建新的 Isolate 并从快照中恢复上下文。在不同的上下文中调用 `f()` 应该返回不同的值 (1, 2, undefined)。
*   **`UNINITIALIZED_TEST(SnapshotCreatorExternalReferences)`**:
    *   **功能:** 测试快照创建和反序列化过程中对外部 C++ 函数（`SerializedCallback`，`SerializedCallbackReplacement`）和静态数据（`serialized_static_field`）的引用。
    *   **代码逻辑推理:**
        *   **假设输入:** 创建一个包含对 `SerializedCallback` 和 `serialized_static_field` 引用的快照。
        *   **预期输出:**
            *   使用原始外部引用反序列化：调用 `f()` 会执行 `SerializedCallback`，返回 42，并且 `serialized_static_field` 的值会被递增。
            *   使用替换外部引用反序列化：调用 `f()` 会执行 `SerializedCallbackReplacement`，返回 1337。
    *   **用户常见的编程错误:**
        *   **外部引用不匹配:**  如果反序列化时提供的外部引用表与创建快照时使用的不一致，可能会导致程序崩溃或行为异常。例如，如果 `SerializedCallback` 的地址在反序列化时发生了变化，但外部引用表没有更新，那么调用 `f()` 可能会导致错误。
        *   **忘记更新外部引用:** 当修改了引用的 C++ 函数或数据时，需要重新生成包含正确外部引用的快照。
*   **`UNINITIALIZED_TEST(SnapshotCreatorShortExternalReferences)`**:
    *   **功能:** 测试反序列化时提供的外部引用列表比创建快照时使用的列表短的情况。
    *   **代码逻辑推理:**
        *   **假设输入:** 创建一个包含对 `SerializedCallback` 引用的快照，然后尝试使用只包含 `SerializedCallbackReplacement` 的外部引用列表进行反序列化。
        *   **预期输出:** 调用 `f()` 将会执行 `short_external_references` 中提供的回调 `SerializedCallbackReplacement`，返回 1337。这说明 V8 会根据提供的外部引用列表来查找匹配的引用。
*   **`UNINITIALIZED_TEST(SnapshotCreatorNoExternalReferencesDefault)`**:
    *   **功能:** 测试在没有提供外部引用的情况下反序列化包含外部引用的快照（默认上下文）。
    *   **代码逻辑推理:**
        *   **假设输入:** 创建一个包含对 `SerializedCallback` 引用的快照，然后尝试在不提供任何外部引用的情况下反序列化默认上下文。
        *   **预期输出:** 调用 `f()` 将执行快照中保存的默认行为，即返回 41。这说明默认上下文的外部引用信息是被包含在快照中的。
*   **`v8::StartupData CreateCustomSnapshotWithPreparseDataAndNoOuterScope()` 和 `UNINITIALIZED_TEST(SnapshotCreatorPreparseDataAndNoOuterScope)`**:
    *   **功能:** 测试序列化和反序列化具有预解析数据但没有外部作用域的函数。这通常涉及到性能优化。
*   **`v8::StartupData CreateCustomSnapshotArrayJoinWithKeep()` 和 `UNINITIALIZED_TEST(SnapshotCreatorArrayJoinWithKeep)`**:
    *   **功能:** 测试在使用 `FunctionCodeHandling::kKeep` 时，序列化包含数组 `join` 操作的快照。
*   **`v8::StartupData CreateCustomSnapshotWithDuplicateFunctions()` 和 `UNINITIALIZED_TEST(SnapshotCreatorDuplicateFunctions)`**:
    *   **功能:** 测试序列化包含重复函数的快照。
*   **`TEST(SnapshotCreatorNoExternalReferencesCustomFail1)` 和 `TEST(SnapshotCreatorNoExternalReferencesCustomFail2)`**:
    *   **功能:**  测试在没有提供外部引用的情况下反序列化包含外部引用的快照（非默认上下文）。这些测试预期会失败，因为自定义上下文依赖于外部引用。
*   **`UNINITIALIZED_TEST(SnapshotCreatorUnknownExternalReferences)`**:
    *   **功能:** 测试创建包含未知外部引用的快照。
*   **`UNINITIALIZED_TEST(SnapshotCreatorTemplates)`**:
    *   **功能:**  测试序列化和反序列化对象模板和对象的内部字段，包括设置和获取内部字段的值，以及使用自定义的序列化和反序列化回调。
*   **`namespace context_data_test` 和 `UNINITIALIZED_TEST(SerializeContextData)`**:
    *   **功能:** 测试序列化和反序列化与 V8 上下文关联的嵌入器数据，并使用回调函数自定义序列化和反序列化过程。

**与 JavaScript 的关系及示例：**

快照功能允许将 V8 引擎的当前状态（包括 JavaScript 代码、对象等）保存到磁盘，并在后续启动时快速恢复。这对于启动速度敏感的应用非常有用。

**JavaScript 示例:**

```javascript
// 创建快照前的 JavaScript 代码
var globalVar = 10;
function add(a, b) {
  return a + b;
}

// ... 创建快照 ...

// 快照加载后，之前的 JavaScript 代码和状态被恢复
console.log(globalVar); // 输出 10
console.log(add(5, 3));  // 输出 8
```

**如果 `v8/test/cctest/test-serialize.cc` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的类型化中间语言，用于编写 V8 的内置函数。当前的 `.cc` 结尾表示它是 C++ 源代码。

**归纳一下它的功能 (第 5 部分，共 8 部分):**

到目前为止，这个代码片段主要集中在测试 **`v8::SnapshotCreator` 的高级功能**，包括：

*   处理多个上下文。
*   管理和验证外部引用（包括替换和缺少的情况）。
*   序列化和反序列化回调函数和属性访问器。
*   处理不同类型的外部字符串。
*   测试 `FunctionCodeHandling` 选项。
*   开始涉及模板和内部字段的序列化。

总的来说，这部分测试旨在确保 V8 的快照机制在更复杂的场景下也能正确工作，为 V8 的快速启动和状态恢复提供保障。

### 提示词
```
这是目录为v8/test/cctest/test-serialize.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-serialize.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun("var f = function() { return 1; }");
      creator.SetDefaultContext(context);
    }
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun("var f = function() { return 2; }");
      CHECK_EQ(0u, creator.AddContext(context));
    }
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      CHECK_EQ(1u, creator.AddContext(context));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &blob;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();
  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      ExpectInt32("f()", 1);
    }
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context =
          v8::Context::FromSnapshot(isolate, 0).ToLocalChecked();
      v8::Context::Scope context_scope(context);
      ExpectInt32("f()", 2);
    }
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context =
          v8::Context::FromSnapshot(isolate, 1).ToLocalChecked();
      v8::Context::Scope context_scope(context);
      ExpectUndefined("this.f");
    }
  }

  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

namespace {
int serialized_static_field = 314;

void SerializedCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (info.Data()->IsExternal()) {
    CHECK_EQ(info.Data().As<v8::External>()->Value(),
             static_cast<void*>(&serialized_static_field));
    int* value =
        reinterpret_cast<int*>(info.Data().As<v8::External>()->Value());
    (*value)++;
  }
  info.GetReturnValue().Set(v8_num(42));
}

void SerializedCallbackReplacement(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_num(1337));
}

v8::Intercepted NamedPropertyGetterForSerialization(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  if (name->Equals(context, v8_str("x")).FromJust()) {
    info.GetReturnValue().Set(v8_num(2016));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

void AccessorForSerialization(v8::Local<v8::Name> property,
                              const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_num(2017));
}

SerializerOneByteResource serializable_one_byte_resource("one_byte", 8);
SerializerTwoByteResource serializable_two_byte_resource(
    AsciiToTwoByteString(u"two_byte 🤓"), 11);

intptr_t original_external_references[] = {
    reinterpret_cast<intptr_t>(SerializedCallback),
    reinterpret_cast<intptr_t>(&serialized_static_field),
    reinterpret_cast<intptr_t>(&NamedPropertyGetterForSerialization),
    reinterpret_cast<intptr_t>(&AccessorForSerialization),
    reinterpret_cast<intptr_t>(&serialized_static_field),  // duplicate entry
    reinterpret_cast<intptr_t>(&serializable_one_byte_resource),
    reinterpret_cast<intptr_t>(&serializable_two_byte_resource),
    0};

intptr_t replaced_external_references[] = {
    reinterpret_cast<intptr_t>(SerializedCallbackReplacement),
    reinterpret_cast<intptr_t>(&serialized_static_field),
    reinterpret_cast<intptr_t>(&NamedPropertyGetterForSerialization),
    reinterpret_cast<intptr_t>(&AccessorForSerialization),
    reinterpret_cast<intptr_t>(&serialized_static_field),
    reinterpret_cast<intptr_t>(&serializable_one_byte_resource),
    reinterpret_cast<intptr_t>(&serializable_two_byte_resource),
    0};

intptr_t short_external_references[] = {
    reinterpret_cast<intptr_t>(SerializedCallbackReplacement), 0};

}  // namespace

UNINITIALIZED_TEST(SnapshotCreatorExternalReferences) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params(original_external_references);
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::Local<v8::FunctionTemplate> callback =
          v8::FunctionTemplate::New(isolate, SerializedCallback);
      v8::Local<v8::Value> function =
          callback->GetFunction(context).ToLocalChecked();
      CHECK(context->Global()->Set(context, v8_str("f"), function).FromJust());

      CHECK(context->Global()
                ->Set(context, v8_str("one_byte"),
                      v8::String::NewExternalOneByte(
                          isolate, &serializable_one_byte_resource)
                          .ToLocalChecked())
                .FromJust());
      CHECK(context->Global()
                ->Set(context, v8_str("two_byte"),
                      v8::String::NewExternalTwoByte(
                          isolate, &serializable_two_byte_resource)
                          .ToLocalChecked())
                .FromJust());

      ExpectInt32("f()", 42);
      ExpectString("one_byte", "one_byte");
      ExpectString("two_byte", "two_byte 🤓");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  CHECK_EQ(1, serializable_one_byte_resource.dispose_count());
  CHECK_EQ(1, serializable_two_byte_resource.dispose_count());

  // Deserialize with the original external reference.
  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    params.external_references = original_external_references;
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      ExpectInt32("f()", 42);
      ExpectString("one_byte", "one_byte");
      ExpectString("two_byte", "two_byte 🤓");
      v8::Local<v8::String> one_byte = CompileRun("one_byte").As<v8::String>();
      v8::Local<v8::String> two_byte = CompileRun("two_byte").As<v8::String>();
      CHECK(one_byte->IsExternalOneByte());
      CHECK(!one_byte->IsExternalTwoByte());
      CHECK(!two_byte->IsExternalOneByte());
      CHECK(two_byte->IsExternalTwoByte());
    }
    isolate->Dispose();
  }

  CHECK_EQ(2, serializable_one_byte_resource.dispose_count());
  CHECK_EQ(2, serializable_two_byte_resource.dispose_count());

  // Deserialize with some other external reference.
  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    params.external_references = replaced_external_references;
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      ExpectInt32("f()", 1337);
    }
    isolate->Dispose();
  }

  CHECK_EQ(3, serializable_one_byte_resource.dispose_count());
  CHECK_EQ(3, serializable_two_byte_resource.dispose_count());

  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(SnapshotCreatorShortExternalReferences) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params(original_external_references);
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::Local<v8::FunctionTemplate> callback =
          v8::FunctionTemplate::New(isolate, SerializedCallback);
      v8::Local<v8::Value> function =
          callback->GetFunction(context).ToLocalChecked();
      CHECK(context->Global()->Set(context, v8_str("f"), function).FromJust());
      ExpectInt32("f()", 42);
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  // Deserialize with an incomplete list of external references.
  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    params.external_references = short_external_references;
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      ExpectInt32("f()", 1337);
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

namespace {
v8::StartupData CreateSnapshotWithDefaultAndCustom() {
  SnapshotCreatorParams testing_params(original_external_references);
  v8::SnapshotCreator creator(testing_params.create_params);
  v8::Isolate* isolate = creator.GetIsolate();
  {
    v8::HandleScope handle_scope(isolate);
    {
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun("function f() { return 41; }");
      creator.SetDefaultContext(context);
      ExpectInt32("f()", 41);
    }
    {
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::Local<v8::FunctionTemplate> function_template =
          v8::FunctionTemplate::New(isolate, SerializedCallback);
      v8::Local<v8::Value> function =
          function_template->GetFunction(context).ToLocalChecked();
      CHECK(context->Global()->Set(context, v8_str("f"), function).FromJust());
      v8::Local<v8::ObjectTemplate> object_template =
          v8::ObjectTemplate::New(isolate);
      object_template->SetNativeDataProperty(v8_str("x"),
                                             AccessorForSerialization);
      v8::Local<v8::Object> object =
          object_template->NewInstance(context).ToLocalChecked();
      CHECK(context->Global()->Set(context, v8_str("o"), object).FromJust());
      ExpectInt32("f()", 42);
      ExpectInt32("o.x", 2017);
      creator.AddContext(context);
    }
  }
  return creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
}
}  // namespace

UNINITIALIZED_TEST(SnapshotCreatorNoExternalReferencesDefault) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob = CreateSnapshotWithDefaultAndCustom();

  // Deserialize with an incomplete list of external references.
  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    params.external_references = nullptr;
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      ExpectInt32("f()", 41);
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

v8::StartupData CreateCustomSnapshotWithPreparseDataAndNoOuterScope() {
  SnapshotCreatorParams testing_params;
  v8::SnapshotCreator creator(testing_params.create_params);
  v8::Isolate* isolate = creator.GetIsolate();
  {
    v8::HandleScope handle_scope(isolate);
    {
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "var foo = {\n"
          "  // This function is not top-level, but also has no outer scope.\n"
          "  bar: function(){\n"
          "    // Add an inner function so that the outer one has preparse\n"
          "    // scope data.\n"
          "    return function(){}\n"
          "  }\n"
          "};\n");
      creator.SetDefaultContext(context);
    }
  }
  return creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
}

UNINITIALIZED_TEST(SnapshotCreatorPreparseDataAndNoOuterScope) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob = CreateCustomSnapshotWithPreparseDataAndNoOuterScope();

  // Deserialize with an incomplete list of external references.
  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

v8::StartupData CreateCustomSnapshotArrayJoinWithKeep() {
  SnapshotCreatorParams testing_params;
  v8::SnapshotCreator creator(testing_params.create_params);
  v8::Isolate* isolate = creator.GetIsolate();
  {
    v8::HandleScope handle_scope(isolate);
    {
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "[].join('');\n"
          "function g() { return String([1,2,3]); }\n");
      ExpectString("g()", "1,2,3");
      creator.SetDefaultContext(context);
    }
  }
  return creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kKeep);
}

UNINITIALIZED_TEST(SnapshotCreatorArrayJoinWithKeep) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob = CreateCustomSnapshotArrayJoinWithKeep();

  // Deserialize with an incomplete list of external references.
  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      ExpectString("g()", "1,2,3");
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

v8::StartupData CreateCustomSnapshotWithDuplicateFunctions() {
  SnapshotCreatorParams testing_params;
  v8::SnapshotCreator creator(testing_params.create_params);
  v8::Isolate* isolate = creator.GetIsolate();
  {
    v8::HandleScope handle_scope(isolate);
    {
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "function f() { return (() => 'a'); }\n"
          "let g1 = f();\n"
          "let g2 = f();\n");
      ExpectString("g1()", "a");
      ExpectString("g2()", "a");
      creator.SetDefaultContext(context);
    }
  }
  return creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kKeep);
}

UNINITIALIZED_TEST(SnapshotCreatorDuplicateFunctions) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob = CreateCustomSnapshotWithDuplicateFunctions();

  // Deserialize with an incomplete list of external references.
  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      ExpectString("g1()", "a");
      ExpectString("g2()", "a");
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

#ifndef V8_SHARED_RO_HEAP
// We do not support building multiple snapshots when read-only heap is shared.

TEST(SnapshotCreatorNoExternalReferencesCustomFail1) {
  DisableAlwaysOpt();
  v8::StartupData blob = CreateSnapshotWithDefaultAndCustom();

  // Deserialize with an incomplete list of external references.
  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    params.external_references = nullptr;
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context =
          v8::Context::FromSnapshot(isolate, 0).ToLocalChecked();
      v8::Context::Scope context_scope(context);
      ExpectInt32("f()", 42);
    }
    isolate->Dispose();
  }
  delete[] blob.data;
}

TEST(SnapshotCreatorNoExternalReferencesCustomFail2) {
  DisableAlwaysOpt();
  v8::StartupData blob = CreateSnapshotWithDefaultAndCustom();

  // Deserialize with an incomplete list of external references.
  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    params.external_references = nullptr;
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context =
          v8::Context::FromSnapshot(isolate, 0).ToLocalChecked();
      v8::Context::Scope context_scope(context);
      ExpectInt32("o.x", 2017);
    }
    isolate->Dispose();
  }
  delete[] blob.data;
}

#endif  // V8_SHARED_RO_HEAP

UNINITIALIZED_TEST(SnapshotCreatorUnknownExternalReferences) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  SnapshotCreatorParams testing_params;
  v8::SnapshotCreator creator(testing_params.create_params);
  v8::Isolate* isolate = creator.GetIsolate();
  {
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::FunctionTemplate> callback =
        v8::FunctionTemplate::New(isolate, SerializedCallback);
    v8::Local<v8::Value> function =
        callback->GetFunction(context).ToLocalChecked();
    CHECK(context->Global()->Set(context, v8_str("f"), function).FromJust());
    ExpectInt32("f()", 42);

    creator.SetDefaultContext(context);
  }
  v8::StartupData blob =
      creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);

  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(SnapshotCreatorTemplates) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;

  {
    InternalFieldData* a1 = new InternalFieldData{11};
    InternalFieldData* b1 = new InternalFieldData{20};
    InternalFieldData* c1 = new InternalFieldData{30};

    SnapshotCreatorParams testing_params(original_external_references);
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::ExtensionConfiguration* no_extension = nullptr;
      v8::Local<v8::ObjectTemplate> global_template =
          v8::ObjectTemplate::New(isolate);
      v8::Local<v8::External> external =
          v8::External::New(isolate, &serialized_static_field);
      v8::Local<v8::FunctionTemplate> callback =
          v8::FunctionTemplate::New(isolate, SerializedCallback, external);
      global_template->Set(isolate, "f", callback);
      v8::Local<v8::Context> context =
          v8::Context::New(isolate, no_extension, global_template);
      creator.SetDefaultContext(context);
      context = v8::Context::New(isolate, no_extension, global_template);
      v8::Local<v8::ObjectTemplate> object_template =
          v8::ObjectTemplate::New(isolate);
      object_template->SetInternalFieldCount(3);

      v8::Context::Scope context_scope(context);
      ExpectInt32("f()", 42);
      CHECK_EQ(315, serialized_static_field);

      v8::Local<v8::Object> a =
          object_template->NewInstance(context).ToLocalChecked();
      v8::Local<v8::Object> b =
          object_template->NewInstance(context).ToLocalChecked();
      v8::Local<v8::Object> c =
          object_template->NewInstance(context).ToLocalChecked();
      v8::Local<v8::External> resource_external =
          v8::External::New(isolate, &serializable_one_byte_resource);
      v8::Local<v8::External> field_external =
          v8::External::New(isolate, &serialized_static_field);

      a->SetInternalField(0, b);
      b->SetInternalField(0, c);

      a->SetAlignedPointerInInternalField(1, a1);
      b->SetAlignedPointerInInternalField(1, b1);
      c->SetAlignedPointerInInternalField(1, c1);

      a->SetInternalField(2, resource_external);
      b->SetInternalField(2, field_external);
      c->SetInternalField(2, v8_num(35));
      CHECK(context->Global()->Set(context, v8_str("a"), a).FromJust());

      CHECK_EQ(0u,
               creator.AddContext(context, v8::SerializeInternalFieldsCallback(
                                               SerializeInternalFields,
                                               reinterpret_cast<void*>(2000))));
      CHECK_EQ(0u, creator.AddData(callback));
      CHECK_EQ(1u, creator.AddData(global_template));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);

    delete a1;
    delete b1;
    delete c1;
  }

  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    params.external_references = original_external_references;
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      {
        // Create a new context without a new object template.
        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Context> context =
            v8::Context::FromSnapshot(
                isolate, 0,
                v8::DeserializeInternalFieldsCallback(
                    DeserializeInternalFields, reinterpret_cast<void*>(2017)))
                .ToLocalChecked();
        v8::Context::Scope context_scope(context);
        ExpectInt32("f()", 42);
        CHECK_EQ(316, serialized_static_field);

        // Retrieve the snapshotted object template.
        v8::Local<v8::ObjectTemplate> obj_template =
            isolate->GetDataFromSnapshotOnce<v8::ObjectTemplate>(1)
                .ToLocalChecked();
        CHECK(!obj_template.IsEmpty());
        v8::Local<v8::Object> object =
            obj_template->NewInstance(context).ToLocalChecked();
        CHECK(context->Global()->Set(context, v8_str("o"), object).FromJust());
        ExpectInt32("o.f()", 42);
        CHECK_EQ(317, serialized_static_field);
        // Check that it instantiates to the same prototype.
        ExpectTrue("o.f.prototype === f.prototype");

        // Retrieve the snapshotted function template.
        v8::Local<v8::FunctionTemplate> fun_template =
            isolate->GetDataFromSnapshotOnce<v8::FunctionTemplate>(0)
                .ToLocalChecked();
        CHECK(!fun_template.IsEmpty());
        v8::Local<v8::Function> fun =
            fun_template->GetFunction(context).ToLocalChecked();
        CHECK(context->Global()->Set(context, v8_str("g"), fun).FromJust());
        ExpectInt32("g()", 42);
        // Check that it instantiates to the same prototype.
        ExpectTrue("g.prototype === f.prototype");

        // Retrieve embedder fields.
        v8::Local<v8::Object> a = context->Global()
                                      ->Get(context, v8_str("a"))
                                      .ToLocalChecked()
                                      ->ToObject(context)
                                      .ToLocalChecked();
        v8::Local<v8::Object> b = a->GetInternalField(0)
                                      .As<v8::Value>()
                                      ->ToObject(context)
                                      .ToLocalChecked();
        v8::Local<v8::Object> c = b->GetInternalField(0)
                                      .As<v8::Value>()
                                      ->ToObject(context)
                                      .ToLocalChecked();

        InternalFieldData* a1 = reinterpret_cast<InternalFieldData*>(
            a->GetAlignedPointerFromInternalField(1));
        v8::Local<v8::Value> a2 = a->GetInternalField(2).As<v8::Value>();

        InternalFieldData* b1 = reinterpret_cast<InternalFieldData*>(
            b->GetAlignedPointerFromInternalField(1));
        v8::Local<v8::Value> b2 = b->GetInternalField(2).As<v8::Value>();

        v8::Local<v8::Value> c0 = c->GetInternalField(0).As<v8::Value>();
        InternalFieldData* c1 = reinterpret_cast<InternalFieldData*>(
            c->GetAlignedPointerFromInternalField(1));
        v8::Local<v8::Value> c2 = c->GetInternalField(2).As<v8::Value>();

        CHECK(c0->IsUndefined());

        CHECK_EQ(11u, a1->data);
        CHECK_EQ(20u, b1->data);
        CHECK_EQ(30u, c1->data);

        CHECK(a2->IsExternal());
        CHECK_EQ(static_cast<void*>(&serializable_one_byte_resource),
                 v8::Local<v8::External>::Cast(a2)->Value());
        CHECK(b2->IsExternal());
        CHECK_EQ(static_cast<void*>(&serialized_static_field),
                 v8::Local<v8::External>::Cast(b2)->Value());
        CHECK(c2->IsInt32() && c2->Int32Value(context).FromJust() == 35);

        // Calling GetDataFromSnapshotOnce again returns an empty MaybeLocal.
        CHECK(
            isolate->GetDataFromSnapshotOnce<v8::ObjectTemplate>(1).IsEmpty());
        CHECK(isolate->GetDataFromSnapshotOnce<v8::FunctionTemplate>(0)
                  .IsEmpty());
        CHECK(v8::Context::FromSnapshot(isolate, 1).IsEmpty());

        for (auto data : deserialized_data) delete data;
        deserialized_data.clear();
      }
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

namespace context_data_test {

// Data passed to callbacks.
static int serialize_internal_fields_data = 2016;
static int serialize_context_data_data = 2017;
static int deserialize_internal_fields_data = 2018;
static int deserialize_context_data_data = 2019;

InternalFieldData context_data = InternalFieldData{11};
InternalFieldData object_data = InternalFieldData{22};

v8::StartupData SerializeInternalFields(v8::Local<v8::Object> holder, int index,
                                        void* data) {
  CHECK_EQ(data, &serialize_internal_fields_data);
  InternalFieldData* field = static_cast<InternalFieldData*>(
      holder->GetAlignedPointerFromInternalField(index));
  if (index == 0) {
    CHECK_NULL(field);
    return {nullptr, 0};
  }
  CHECK_EQ(1, index);
  CHECK_EQ(object_data.data, field->data);
  int size = sizeof(*field);
  char* payload = new char[size];
  // We simply use memcpy to serialize the content.
  memcpy(payload, field, size);
  return {payload, size};
}

v8::StartupData SerializeContextData(v8::Local<v8::Context> context, int index,
                                     void* data) {
  CHECK_EQ(data, &serialize_context_data_data);
  InternalFieldData* field = static_cast<InternalFieldData*>(
      context->GetAlignedPointerFromEmbedderData(index));
  if (index == 0) {
    CHECK_NULL(field);
    return {nullptr, 0};
  }
  CHECK_EQ(1, index);
  CHECK_EQ(context_data.data, field->data);
  int size = sizeof(*field);
  char* payload = new char[size];
  // We simply use memcpy to serialize the content.
  memcpy(payload, field, size);
  return {payload, size};
}

void DeserializeInternalFields(v8::Local<v8::Object> holder, int index,
                               v8::StartupData payload, void* data) {
  CHECK_EQ(data, &deserialize_internal_fields_data);
  CHECK_EQ(1, index);
  InternalFieldData* field = new InternalFieldData{0};
  memcpy(field, payload.data, payload.raw_size);
  CHECK_EQ(object_data.data, field->data);
  holder->SetAlignedPointerInInternalField(index, field);
}

void DeserializeContextData(v8::Local<v8::Context> context, int index,
                            v8::StartupData payload, void* data) {
  CHECK_EQ(data, &deserialize_context_data_data);
  CHECK_EQ(1, index);
  InternalFieldData* field = new InternalFieldData{0};
  memcpy(field, payload.data, payload.raw_size);
  CHECK_EQ(context_data.data, field->data);
  context->SetAlignedPointerInEmbedderData(index, field);
}

}  // namespace context_data_test

UNINITIALIZED_TEST(SerializeContextData) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();

  v8::SerializeInternalFieldsCallback serialize_internal_fields(
      context_data_test::SerializeInternalFields,
      &context_data_test::serialize_internal_fields_data);
  v8::SerializeContextDataCallback serialize_context_data(
      context_data_test::SerializeContextData,
      &context_data_test::serialize_context_data_data);
  v8::DeserializeInternalFieldsCallback deserialize_internal_fields(
      context_data_test::DeserializeInternalFields,
      &context_data_test::deserialize_internal_fields_data);
  v8::DeserializeContextDataCallback deserialize_context_data(
      context_data_test::DeserializeContextData,
      &context_data_test::deserialize_context_data_data);

  {
    v8::StartupData blob;
    {
      SnapshotCreatorParams params;
      v8::SnapshotCreator creator(params.create_params);
      v8::Isolate* isolate = creator.GetIsolate();
      {
        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);
        context->SetAlignedPointerInEmbedderData(0, nullptr);
        context->SetAlignedPointerInEmbedderData(
            1, &context_data_test::context_data);

        v8::Local<v8::ObjectTemplate> object_template =
            v8::ObjectTemplate::New(isolate);
        object_template->SetInternalFieldCount(2);
        v8::Local<v8::Object> obj =
            object_template->NewInstance(context).ToLocalChecked();
        obj->SetAlignedPointerInInternalField(0, nullptr);
        obj->SetAlignedPointerInInternalField(1,
                                              &context_data_test::object_data);

        CHECK(context->Global()->Set(context, v8_str("obj"), obj).FromJust());
        creator.SetDefaultContext(context, serialize_internal_fields,
                                  serialize_context_data);
      }

      blob =
          creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
    }

    {
      v8::Isolate::CreateParams params;
      params.snapshot_blob = &blob;
      params.array_buffer_allocator = CcTest::array_buffer_allocator();
      // Test-appropriate equivalent of v8::Isolate::New.
      v8::Isolate* isolate = TestSerializer::NewIsolate(params);
      {
        v8::Isolate::Scope isolate_scope(isolate);

        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Context> context = v8::Context::New(
            isolate, nullptr, {}, {}, deserialize_internal_fields, nullptr,
            deserialize_context_data);
        InternalFieldData* data
```