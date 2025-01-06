Response: The user wants a summary of the C++ code provided, which is a test file for V8's serialization functionality.

The code focuses on testing the `v8::SnapshotCreator` and related APIs for creating and using snapshots of the V8 heap. It checks various aspects of serialization, including:

*   **Multiple contexts:**  Creating snapshots with multiple contexts and restoring them.
*   **External references:**  Handling external references (C++ functions and data) during serialization and deserialization, including replacement and handling missing references.
*   **Function code handling:**  Different options for how function code is handled in snapshots.
*   **Templates:**  Serializing and deserializing function and object templates.
*   **Internal fields:**  Serializing and deserializing objects with internal fields, including custom serialization and deserialization callbacks.
*   **Context data:**  Serializing and deserializing data associated with contexts, including custom callbacks.
*   **API wrapper data:** Serializing and deserializing C++ objects wrapped in V8 objects.
*   **Data serialization:**  Adding and retrieving arbitrary data to/from snapshots.
*   **Global proxy:**  Including or excluding the global proxy in snapshots.
*   **JS Collections:** Testing rehashing of JS collections after snapshot deserialization.

To illustrate the connection with JavaScript, I need to show how the C++ code manipulates JavaScript concepts and how these are affected by the serialization process.
这是v8 JavaScript引擎的测试文件，专门测试其序列化（serialization）功能。该文件的主要目的是验证 `v8::SnapshotCreator` API 的正确性，确保 V8 引擎能够将 JavaScript 堆的状态保存到快照（snapshot）中，并在后续启动时从该快照恢复状态。

具体来说，这部分代码主要测试了以下功能：

1. **创建包含多个上下文的快照 (Snapshot with Multiple Contexts):** 代码演示了如何使用 `v8::SnapshotCreator` 创建一个包含多个独立 JavaScript 上下文的快照。每个上下文都定义了一个名为 `f` 的函数，但具有不同的行为。然后，它测试了从该快照恢复后，可以正确地访问和执行不同上下文中的 `f` 函数。

2. **处理外部引用 (External References):** 代码测试了在序列化和反序列化过程中如何处理外部 C++ 函数和数据。它定义了几个 C++ 函数 (`SerializedCallback`, `SerializedCallbackReplacement`, `NamedPropertyGetterForSerialization`, `AccessorForSerialization`) 和一个静态变量 (`serialized_static_field`)，并将它们作为外部引用与 JavaScript 代码关联。测试验证了：
    *   使用相同的外部引用列表反序列化后，可以正确调用原始的 C++ 函数。
    *   使用不同的外部引用列表反序列化后，关联的 C++ 函数可以被替换。
    *   如果外部引用列表不完整，反序列化后可能会使用替换的函数。

**与 JavaScript 的关系及示例：**

序列化功能使得 V8 引擎可以将 JavaScript 运行时的状态保存下来，以便快速启动或在不同的进程/机器之间迁移状态。这在很多场景下非常有用，例如：

*   **加速启动:**  Node.js 等环境可以使用快照来避免每次启动时都重新编译和执行启动脚本。
*   **代码缓存:**  浏览器可以使用快照来缓存已编译的 JavaScript 代码。
*   **隔离:**  可以在不同的 V8 Isolate 中恢复不同的快照，从而实现代码和数据的隔离。

**JavaScript 示例:**

```javascript
// 假设我们有一个简单的 JavaScript 函数
function greet(name) {
  return "Hello, " + name + "!";
}

// 在 V8 内部，可以使用 SnapshotCreator 将包含这个函数的运行时状态保存下来。

// ... (C++ 代码使用 SnapshotCreator 创建快照) ...

// 之后，在新的 V8 Isolate 中，可以从这个快照恢复状态：
// ... (C++ 代码使用快照初始化新的 Isolate) ...

// 在新的 Isolate 中，我们无需重新定义 greet 函数，它可以直接使用：
console.log(greet("World")); // 输出 "Hello, World!"
```

**代码中与 JavaScript 相关的操作:**

*   `CompileRun("var f = function() { return 1; }")`: 这行 C++ 代码实际上是在 V8 引擎中执行 JavaScript 代码，定义了一个函数 `f`。
*   `ExpectInt32("f()", 1)`: 这行代码也是在 V8 引擎中执行 JavaScript 代码 `f()`，并断言其返回值是整数 `1`。
*   `v8::FunctionTemplate::New(isolate, SerializedCallback)`: 这行代码创建了一个 JavaScript 函数模板，并将 C++ 函数 `SerializedCallback` 与之关联。当从 JavaScript 调用该模板创建的函数时，会执行 `SerializedCallback`。
*   `context->Global()->Set(context, v8_str("f"), function)`: 这行代码将 JavaScript 函数 `function` 绑定到全局对象的一个名为 `f` 的属性上。
*   `v8::String::NewExternalOneByte(...)` 和 `v8::String::NewExternalTwoByte(...)`: 这两行代码创建了外部字符串，其数据存储在 C++ 中。序列化机制需要处理这些外部资源。

总而言之，这段 C++ 代码深入测试了 V8 引擎的序列化机制，确保它能够正确地保存和恢复 JavaScript 运行时的各种状态，包括上下文、函数、外部引用等关键元素。这对于 V8 引擎的稳定性和在各种环境下的应用至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-serialize.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
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
        InternalFieldData* data = static_cast<InternalFieldData*>(
            context->GetAlignedPointerFromEmbedderData(1));
        CHECK_EQ(context_data_test::context_data.data, data->data);
        context->SetAlignedPointerInEmbedderData(1, nullptr);
        delete data;

        v8::Local<v8::Value> obj_val =
            context->Global()->Get(context, v8_str("obj")).ToLocalChecked();
        CHECK(obj_val->IsObject());
        v8::Local<v8::Object> obj = obj_val.As<v8::Object>();
        InternalFieldData* field = static_cast<InternalFieldData*>(
            obj->GetAlignedPointerFromInternalField(1));
        CHECK_EQ(context_data_test::object_data.data, field->data);
        obj->SetAlignedPointerInInternalField(1, nullptr);
        delete field;
      }
      isolate->Dispose();
    }
    delete[] blob.data;
  }
  {
    v8::StartupData blob;
    {
      SnapshotCreatorParams params;
      v8::SnapshotCreator creator(params.create_params);
      v8::Isolate* isolate = creator.GetIsolate();
      {
        v8::HandleScope handle_scope(isolate);

        v8::Local<v8::Context> default_context = v8::Context::New(isolate);
        creator.SetDefaultContext(default_context);

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
        CHECK_EQ(0, creator.AddContext(context, serialize_internal_fields,
                                       serialize_context_data));
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
        v8::Local<v8::Context> context =
            v8::Context::FromSnapshot(isolate, 0, deserialize_internal_fields,
                                      nullptr, v8::MaybeLocal<v8::Value>(),
                                      nullptr, deserialize_context_data)
                .ToLocalChecked();
        InternalFieldData* data = static_cast<InternalFieldData*>(
            context->GetAlignedPointerFromEmbedderData(1));
        CHECK_EQ(context_data_test::context_data.data, data->data);
        context->SetAlignedPointerInEmbedderData(1, nullptr);
        delete data;

        v8::Local<v8::Value> obj_val =
            context->Global()->Get(context, v8_str("obj")).ToLocalChecked();
        CHECK(obj_val->IsObject());
        v8::Local<v8::Object> obj = obj_val.As<v8::Object>();
        InternalFieldData* field = static_cast<InternalFieldData*>(
            obj->GetAlignedPointerFromInternalField(1));
        CHECK_EQ(context_data_test::object_data.data, field->data);
        obj->SetAlignedPointerInInternalField(1, nullptr);
        delete field;
      }
      isolate->Dispose();
    }
    delete[] blob.data;
  }
  {
    // Check that embedder pointers set on a context serialize into a snapshot
    // as nullptr if a context_data_serializer is not provided.

    char raw_data[] = "hey hey hey";
    v8::StartupData blob;
    {
      SnapshotCreatorParams params;
      v8::SnapshotCreator creator(params.create_params);
      v8::Isolate* isolate = creator.GetIsolate();
      {
        v8::HandleScope handle_scope(isolate);

        v8::Local<v8::Context> default_context = v8::Context::New(isolate);
        creator.SetDefaultContext(default_context);

        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);
        context->SetAlignedPointerInEmbedderData(0, nullptr);
        context->SetAlignedPointerInEmbedderData(1, raw_data);

        v8::Local<v8::ObjectTemplate> object_template =
            v8::ObjectTemplate::New(isolate);
        v8::Local<v8::Object> obj =
            object_template->NewInstance(context).ToLocalChecked();
        USE(obj);
        CHECK(context->Global()->Set(context, v8_str("obj"), obj).FromJust());
        CHECK_EQ(0, creator.AddContext(context));
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
        v8::Local<v8::Context> context =
            v8::Context::FromSnapshot(isolate, 0).ToLocalChecked();
        CHECK_NULL(context->GetAlignedPointerFromEmbedderData(0));
        // It would be more consistent if the API would always null out pointers
        // stored in embedder slots (if no custom serializer/deserializer is
        // provided), but in the wide pointer case we don't actually know
        // whether it's a pointer or a Smi, so we just let these values pass
        // through.
        if (V8_ENABLE_SANDBOX_BOOL)
          CHECK_NULL(context->GetAlignedPointerFromEmbedderData(1));
        else
          CHECK_EQ(raw_data, context->GetAlignedPointerFromEmbedderData(1));
      }
      isolate->Dispose();
    }
    delete[] blob.data;
  }

  FreeCurrentEmbeddedBlob();
}

class DummyWrappable : public cppgc::GarbageCollected<DummyWrappable> {
 public:
  void Trace(cppgc::Visitor*) const {}

  bool is_special = false;
};

static constexpr char kSpecialTag = 1;

static v8::StartupData SerializeAPIWrapperCallback(Local<v8::Object> holder,
                                                   void* cpp_heap_pointer,
                                                   void* data) {
  auto* wrappable = reinterpret_cast<DummyWrappable*>(cpp_heap_pointer);
  if (wrappable && wrappable->is_special) {
    *reinterpret_cast<int64_t*>(data) += 1;
    return v8::StartupData{&kSpecialTag, 1};
  }
  return v8::StartupData{nullptr, 0};
}

static void DeserializeAPIWrapperCallback(Local<v8::Object> holder,
                                          v8::StartupData payload, void* data) {
  if (payload.raw_size == 1 &&
      *reinterpret_cast<const char*>(payload.data) == kSpecialTag) {
    *reinterpret_cast<int64_t*>(data) -= 1;
  }
}

START_ALLOW_USE_DEPRECATED()

UNINITIALIZED_TEST(SerializeApiWrapperData) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();

  int64_t special_objects_encountered = 0;

  v8::SerializeAPIWrapperCallback serialize_api_fields(
      &SerializeAPIWrapperCallback, &special_objects_encountered);
  v8::DeserializeAPIWrapperCallback deserialize_api_fields(
      &DeserializeAPIWrapperCallback, &special_objects_encountered);

  v8::StartupData blob;
  auto* platform = V8::GetCurrentPlatform();
  {
    // Create a blob with API wrapper objects. One of the objects is marked as
    // special which results in providing a tag via embedder callbacks.

    SnapshotCreatorParams params;
    params.create_params.cpp_heap =
        v8::CppHeap::Create(platform, v8::CppHeapCreateParams({})).release();
    v8::SnapshotCreator creator(params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    v8::CppHeap* cpp_heap = isolate->GetCppHeap();
    DummyWrappable *wrappable1, *wrappable2;
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      v8::Local<v8::FunctionTemplate> function_template =
          v8::FunctionTemplate::New(isolate);
      auto object_template = function_template->InstanceTemplate();

      v8::Local<v8::Object> obj1 =
          object_template->NewInstance(context).ToLocalChecked();
      wrappable1 = cppgc::MakeGarbageCollected<DummyWrappable>(
          cpp_heap->GetAllocationHandle());
      v8::Object::Wrap<v8::CppHeapPointerTag::kDefaultTag>(isolate, obj1,
                                                           wrappable1);
      CHECK_EQ(wrappable1, v8::Object::Unwrap<CppHeapPointerTag::kDefaultTag>(
                               isolate, obj1));
      CHECK(context->Global()->Set(context, v8_str("obj1"), obj1).FromJust());

      v8::Local<v8::Object> obj2 =
          object_template->NewInstance(context).ToLocalChecked();
      wrappable2 = cppgc::MakeGarbageCollected<DummyWrappable>(
          cpp_heap->GetAllocationHandle());
      wrappable2->is_special = true;
      v8::Object::Wrap<v8::CppHeapPointerTag::kDefaultTag>(isolate, obj2,
                                                           wrappable2);
      CHECK_EQ(wrappable2, v8::Object::Unwrap<CppHeapPointerTag::kDefaultTag>(
                               isolate, obj2));
      CHECK(context->Global()->Set(context, v8_str("obj2"), obj2).FromJust());

      creator.SetDefaultContext(context, SerializeInternalFieldsCallback(),
                                SerializeContextDataCallback(),
                                serialize_api_fields);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
    CHECK_EQ(special_objects_encountered, 1);
  }
  {
    // Initialize an Isolate from the blob.

    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(
          isolate, nullptr, {}, {}, DeserializeInternalFieldsCallback(),
          nullptr, DeserializeContextDataCallback(), deserialize_api_fields);
      v8::Local<v8::Value> obj1 =
          context->Global()->Get(context, v8_str("obj1")).ToLocalChecked();
      CHECK(obj1->IsObject());
      v8::Local<v8::Value> obj2 =
          context->Global()->Get(context, v8_str("obj2")).ToLocalChecked();
      CHECK(obj2->IsObject());
      CHECK_EQ(nullptr, v8::Object::Unwrap<CppHeapPointerTag::kDefaultTag>(
                            isolate, obj1.As<v8::Object>()));
      CHECK_EQ(nullptr, v8::Object::Unwrap<CppHeapPointerTag::kDefaultTag>(
                            isolate, obj2.As<v8::Object>()));
      CHECK_EQ(special_objects_encountered, 0);
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

END_ALLOW_USE_DEPRECATED()

MaybeLocal<v8::Module> ResolveCallback(Local<v8::Context> context,
                                       Local<v8::String> specifier,
                                       Local<v8::FixedArray> import_attributes,
                                       Local<v8::Module> referrer) {
  return {};
}

UNINITIALIZED_TEST(SnapshotCreatorAddData) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;

  // i::PerformCastCheck(Data*) should compile and be no-op
  {
    v8::Local<v8::Data> data;
    i::PerformCastCheck(*data);
  }

  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    v8::Eternal<v8::Value> eternal_number;
    v8::Persistent<v8::Value> persistent_number_1;
    v8::Persistent<v8::Value> persistent_number_2;
    v8::Persistent<v8::Context> persistent_context;
    {
      v8::HandleScope handle_scope(isolate);

      eternal_number.Set(isolate, v8_num(2017));
      persistent_number_1.Reset(isolate, v8_num(2018));
      persistent_number_2.Reset(isolate, v8_num(2019));

      v8::Local<v8::Context> context = v8::Context::New(isolate);
      CHECK_EQ(0u, creator.AddData(context, persistent_number_2.Get(isolate)));
      creator.SetDefaultContext(context);
      context = v8::Context::New(isolate);
      persistent_context.Reset(isolate, context);

      v8::Context::Scope context_scope(context);

      v8::Local<v8::Object> object = CompileRun("({ p: 12 })").As<v8::Object>();

      v8::Local<v8::ObjectTemplate> object_template =
          v8::ObjectTemplate::New(isolate);
      object_template->SetInternalFieldCount(3);

      v8::Local<v8::Private> private_symbol =
          v8::Private::ForApi(isolate, v8_str("private_symbol"));

      v8::Local<v8::Signature> signature =
          v8::Signature::New(isolate, v8::FunctionTemplate::New(isolate));

      v8::ScriptOrigin origin(v8_str(""), {}, {}, {}, {}, {}, {}, {}, true);
      v8::ScriptCompiler::Source source(
          v8::String::NewFromUtf8Literal(
              isolate, "export let a = 42; globalThis.a = {};"),
          origin);
      v8::Local<v8::Module> module =
          v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
      module->InstantiateModule(context, ResolveCallback).ToChecked();
      module->Evaluate(context).ToLocalChecked();

      CHECK_EQ(0u, creator.AddData(context, object));
      CHECK_EQ(1u, creator.AddData(context, v8_str("context-dependent")));
      CHECK_EQ(2u, creator.AddData(context, persistent_number_1.Get(isolate)));
      CHECK_EQ(3u, creator.AddData(context, object_template));
      CHECK_EQ(4u, creator.AddData(context, persistent_context.Get(isolate)));
      CHECK_EQ(5u, creator.AddData(context, module));
      creator.AddContext(context);

      CHECK_EQ(0u, creator.AddData(v8_str("context-independent")));
      CHECK_EQ(1u, creator.AddData(eternal_number.Get(isolate)));
      CHECK_EQ(2u, creator.AddData(object_template));
      CHECK_EQ(3u, creator.AddData(v8::FunctionTemplate::New(isolate)));
      CHECK_EQ(4u, creator.AddData(private_symbol));
      CHECK_EQ(5u, creator.AddData(signature));
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
      v8::Local<v8::Context> context =
          v8::Context::FromSnapshot(isolate, 0).ToLocalChecked();

      // Check serialized data on the context.
      v8::Local<v8::Object> object =
          context->GetDataFromSnapshotOnce<v8::Object>(0).ToLocalChecked();
      CHECK(context->GetDataFromSnapshotOnce<v8::Object>(0).IsEmpty());
      CHECK_EQ(12, object->Get(context, v8_str("p"))
                       .ToLocalChecked()
                       ->Int32Value(context)
                       .FromJust());

      v8::Local<v8::String> string =
          context->GetDataFromSnapshotOnce<v8::String>(1).ToLocalChecked();
      CHECK(context->GetDataFromSnapshotOnce<v8::String>(1).IsEmpty());
      CHECK(string->Equals(context, v8_str("context-dependent")).FromJust());

      v8::Local<v8::Number> number =
          context->GetDataFromSnapshotOnce<v8::Number>(2).ToLocalChecked();
      CHECK(context->GetDataFromSnapshotOnce<v8::Number>(2).IsEmpty());
      CHECK_EQ(2018, number->Int32Value(context).FromJust());

      v8::Local<v8::ObjectTemplate> templ =
          context->GetDataFromSnapshotOnce<v8::ObjectTemplate>(3)
              .ToLocalChecked();
      CHECK(context->GetDataFromSnapshotOnce<v8::ObjectTemplate>(3).IsEmpty());
      CHECK_EQ(3, templ->InternalFieldCount());

      v8::Local<v8::Context> serialized_context =
          context->GetDataFromSnapshotOnce<v8::Context>(4).ToLocalChecked();
      CHECK(context->GetDataFromSnapshotOnce<v8::Context>(4).IsEmpty());
      CHECK_EQ(*v8::Utils::OpenDirectHandle(*serialized_context),
               *v8::Utils::OpenDirectHandle(*context));

      v8::Local<v8::Module> serialized_module =
          context->GetDataFromSnapshotOnce<v8::Module>(5).ToLocalChecked();
      CHECK(context->GetDataFromSnapshotOnce<v8::Context>(5).IsEmpty());
      {
        v8::Context::Scope context_scope(context);
        v8::Local<v8::Object> mod_ns =
            serialized_module->GetModuleNamespace().As<v8::Object>();
        CHECK(mod_ns->Get(context, v8_str("a"))
                  .ToLocalChecked()
                  ->StrictEquals(v8_num(42.0)));
      }

      CHECK(context->GetDataFromSnapshotOnce<v8::Value>(6).IsEmpty());

      // Check serialized data on the isolate.
      string = isolate->GetDataFromSnapshotOnce<v8::String>(0).ToLocalChecked();
      CHECK(context->GetDataFromSnapshotOnce<v8::String>(0).IsEmpty());
      CHECK(string->Equals(context, v8_str("context-independent")).FromJust());

      number = isolate->GetDataFromSnapshotOnce<v8::Number>(1).ToLocalChecked();
      CHECK(isolate->GetDataFromSnapshotOnce<v8::Number>(1).IsEmpty());
      CHECK_EQ(2017, number->Int32Value(context).FromJust());

      templ = isolate->GetDataFromSnapshotOnce<v8::ObjectTemplate>(2)
                  .ToLocalChecked();
      CHECK(isolate->GetDataFromSnapshotOnce<v8::ObjectTemplate>(2).IsEmpty());
      CHECK_EQ(3, templ->InternalFieldCount());

      isolate->GetDataFromSnapshotOnce<v8::FunctionTemplate>(3)
          .ToLocalChecked();
      CHECK(
          isolate->GetDataFromSnapshotOnce<v8::FunctionTemplate>(3).IsEmpty());

      isolate->GetDataFromSnapshotOnce<v8::Private>(4).ToLocalChecked();
      CHECK(isolate->GetDataFromSnapshotOnce<v8::Private>(4).IsEmpty());

      isolate->GetDataFromSnapshotOnce<v8::Signature>(5).ToLocalChecked();
      CHECK(isolate->GetDataFromSnapshotOnce<v8::Signature>(5).IsEmpty());

      CHECK(isolate->GetDataFromSnapshotOnce<v8::Value>(7).IsEmpty());
    }
    isolate->Dispose();
  }
  {
    SnapshotCreatorParams testing_params(nullptr, &blob);
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      // Adding data to a snapshot replaces the list of existing data.
      v8::HandleScope hscope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      creator.SetDefaultContext(context);
      context = v8::Context::FromSnapshot(isolate, 0).ToLocalChecked();
      v8::Local<v8::String> string =
          context->GetDataFromSnapshotOnce<v8::String>(1).ToLocalChecked();
      CHECK(context->GetDataFromSnapshotOnce<v8::String>(1).IsEmpty());
      CHECK(string->Equals(context, v8_str("context-dependent")).FromJust());
      v8::Local<v8::Number> number =
          isolate->GetDataFromSnapshotOnce<v8::Number>(1).ToLocalChecked();
      CHECK(isolate->GetDataFromSnapshotOnce<v8::Number>(1).IsEmpty());
      CHECK_EQ(2017, number->Int32Value(context).FromJust());

      CHECK_EQ(0u, creator.AddData(context, v8_num(2016)));
      CHECK_EQ(0u, creator.AddContext(context));
      CHECK_EQ(0u, creator.AddData(v8_str("stuff")));
    }
    delete[] blob.data;
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

      // Context where we did not re-add data no longer has data.
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      CHECK(context->GetDataFromSnapshotOnce<v8::Object>(0).IsEmpty());

      // Context where we re-added data has completely new ones.
      context = v8::Context::FromSnapshot(isolate, 0).ToLocalChecked();
      v8::Local<v8::Value> value =
          context->GetDataFromSnapshotOnce<v8::Value>(0).ToLocalChecked();
      CHECK_EQ(2016, value->Int32Value(context).FromJust());
      CHECK(context->GetDataFromSnapshotOnce<v8::Value>(1).IsEmpty());

      // Ditto for the isolate.
      v8::Local<v8::String> string =
          isolate->GetDataFromSnapshotOnce<v8::String>(0).ToLocalChecked();
      CHECK(string->Equals(context, v8_str("stuff")).FromJust());
      CHECK(context->GetDataFromSnapshotOnce<v8::String>(1).IsEmpty());
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

TEST(SnapshotCreatorUnknownHandles) {
  DisableAlwaysOpt();
  v8::StartupData blob;

  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    v8::Eternal<v8::Value> eternal_number;
    v8::Persistent<v8::Value> persistent_number;
    {
      v8::HandleScope handle_scope(isolate);

      eternal_number.Set(isolate, v8_num(2017));
      persistent_number.Reset(isolate, v8_num(2018));

      v8::Local<v8::Context> context = v8::Context::New(isolate);
      creator.SetDefaultContext(context);
    }

    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }
  delete[] blob.data;
}

UNINITIALIZED_TEST(SnapshotAccessorDescriptors) {
  const char* source1 =
      "var bValue = 38;\n"
      "Object.defineProperty(this, 'property1', {\n"
      "    get() { return bValue; },\n"
      "    set(newValue) { bValue = newValue; },\n"
      "});";
  v8::StartupData data1 = CreateSnapshotDataBlob(source1);

  v8::Isolate::CreateParams params1;
  params1.snapshot_blob = &data1;
  params1.array_buffer_allocator = CcTest::array_buffer_allocator();

  v8::Isolate* isolate1 = v8::Isolate::New(params1);
  {
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope c_scope(context);
    ExpectInt32("this.property1", 38);
  }
  isolate1->Dispose();
  delete[] data1.data;
}

UNINITIALIZED_TEST(SnapshotObjectDefinePropertyWhenNewGlobalTemplate) {
  const char* source1 =
      "Object.defineProperty(this, 'property1', {\n"
      "  value: 42,\n"
      "  writable: false\n"
      "});\n"
      "var bValue = 38;\n"
      "Object.defineProperty(this, 'property2', {\n"
      "  get() { return bValue; },\n"
      "  set(newValue) { bValue = newValue; }\n"
      "});";
  v8::StartupData data1 = CreateSnapshotDataBlob(source1);

  v8::Isolate::CreateParams params1;
  params1.snapshot_blob = &data1;
  params1.array_buffer_allocator = CcTest::array_buffer_allocator();

  v8::Isolate* isolate1 = v8::Isolate::New(params1);
  {
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::ObjectTemplate> global_template =
        v8::ObjectTemplate::New(isolate1);
    v8::Local<v8::Context> context =
        v8::Context::New(isolate1, nullptr, global_template);
    v8::Context::Scope c_scope(context);
    ExpectInt32("this.property1", 42);
    ExpectInt32("this.property2", 38);
  }
  isolate1->Dispose();
  delete[] data1.data;
}

UNINITIALIZED_TEST(SnapshotCreatorIncludeGlobalProxy) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;

  {
    SnapshotCreatorParams testing_params(original_external_references);
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      // Set default context. This context implicitly does *not* serialize
      // the global proxy, and upon deserialization one has to be created
      // in the bootstrapper from the global object template.
      // Side effects from extensions are persisted though.
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::ObjectTemplate> global_template =
          v8::ObjectTemplate::New(isolate);
      v8::Local<v8::FunctionTemplate> callback =
          v8::FunctionTemplate::New(isolate, SerializedCallback);
      global_template->Set(isolate, "f", callback);
      global_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
          NamedPropertyGetterForSerialization));
      v8::Local<v8::Context> context =
          v8::Context::New(isolate, nullptr, global_template);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "function h() { return 13; };"
          "function i() { return 14; };"
          "var o = { p: 7 };");
      ExpectInt32("f()", 42);
      ExpectInt32("h()", 13);
      ExpectInt32("o.p", 7);
      ExpectInt32("x", 2016);
      creator.SetDefaultContext(context);
    }
    {
      // Add additional context. This context implicitly *does* serialize
      // the global proxy, and upon deserialization one has to be created
      // in the bootstrapper from the global object template.
      // Side effects from extensions are persisted.
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::ObjectTemplate> global_template =
          v8::ObjectTemplate::New(isolate);
      v8::Local<v8::FunctionTemplate> callback =
          v8::FunctionTemplate::New(isolate, SerializedCallback);
      global_template->SetInternalFieldCount(3);
      global_template->Set(isolate, "f", callback);
      global_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
          NamedPropertyGetterForSerialization));
      global_template->SetNativeDataProperty(v8_str("y"),
                                             AccessorForSerialization);
      v8::Local<v8::Private> priv =
          v8::Private::ForApi(isolate, v8_str("cached"));
      global_template->SetAccessorProperty(
          v8_str("cached"),
          v8::FunctionTemplate::NewWithCache(isolate, SerializedCallback, priv,
                                             v8::Local<v8::Value>()));
      v8::Local<v8::Context> context =
          v8::Context::New(isolate, nullptr, global_template);
      v8::Context::Scope context_scope(context);

      CHECK(context->Global()
                ->SetPrivate(context, priv, v8_str("cached string"))
                .FromJust());
      v8::Local<v8::Private> hidden =
          v8::Private::ForApi(isolate, v8_str("hidden"));
      CHECK(context->Global()
                ->SetPrivate(context, hidden, v8_str("hidden string"))
                .FromJust());

      ExpectInt32("f()", 42);
      ExpectInt32("x", 2016);
      ExpectInt32("y", 2017);
      CHECK(v8_str("hidden string")
                ->Equals(context, context->Global()
                                      ->GetPrivate(context, hidden)
                                      .ToLocalChecked())
                .FromJust());

      CHECK_EQ(0u,
               creator.AddContext(context, v8::SerializeInternalFieldsCallback(
                                               SerializeInternalFields,
                                               reinterpret_cast<void*>(2016))));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
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
      // We can introduce new extensions, which could override functions already
      // in the snapshot.
      auto extension =
          std::make_unique<v8::Extension>("new extension",
                                          "function i() { return 24; }"
                                          "function j() { return 25; }"
                                          "let a = 26;"
                                          "try {"
                                          "  if (o.p == 7) o.p++;"
                                          "} catch {}");
      extension->set_auto_enable(true);
      v8::RegisterExtension(std::move(extension));
      {
        // Create a new context from default context snapshot. This will also
        // deserialize its global object with interceptor.
        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);
        ExpectInt32("f()", 42);
        ExpectInt32("h()", 13);
        ExpectInt32("i()", 24);
        ExpectInt32("j()", 25);
        ExpectInt32("o.p", 8);
        ExpectInt32("a", 26);
        ExpectInt32("x", 2016);
      }
      {
        // Create a new context from first additional context snapshot. This
        // will use the global object from the snapshot, including interceptor.
        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Context> context =
            v8::Context::FromSnapshot(
                isolate, 0,
                v8::DeserializeInternalFieldsCallback(
                    DeserializeInternalFields, reinterpret_cast<void*>(2017)))
                .ToLocalChecked();

        {
          v8::Context::Scope context_scope(context);
          ExpectInt32("f()", 42);
          ExpectInt32("i()", 24);
          ExpectInt32("j()", 25);
          ExpectInt32("x", 2016);
          v8::Local<v8::Private> hidden =
              v8::Private::ForApi(isolate, v8_str("hidden"));
          CHECK(v8_str("hidden string")
                    ->Equals(context, context->Global()
                                          ->GetPrivate(context, hidden)
                                          .ToLocalChecked())
                    .FromJust());
          ExpectString("cached", "cached string");
        }

        v8::Local<v8::Object> global = context->Global();
        CHECK_EQ(3, global->InternalFieldCount());
        context->DetachGlobal();

        // New context, but reuse global proxy.
        v8::ExtensionConfiguration* no_extensions = nullptr;
        v8::Local<v8::Context> context2 =
            v8::Context::FromSnapshot(
                isolate, 0,
                v8::DeserializeInternalFieldsCallback(
                    DeserializeInternalFields, reinterpret_cast<void*>(2017)),
                no_extensions, global)
                .ToLocalChecked();
        {
          v8::Context::Scope context_scope(context2);
          ExpectInt32("f()", 42);
          ExpectInt32("i()", 24);
          ExpectInt32("j()", 25);
          ExpectInt32("x", 2016);
          v8::Local<v8::Private> hidden =
              v8::Private::ForApi(isolate, v8_str("hidden"));
          CHECK(v8_str("hidden string")
                    ->Equals(context2, context2->Global()
                                           ->GetPrivate(context2, hidden)
                                           .ToLocalChecked())
                    .FromJust());

          // Set cached accessor property again.
          v8::Local<v8::Private> priv =
              v8::Private::ForApi(isolate, v8_str("cached"));
          CHECK(context2->Global()
                    ->SetPrivate(context2, priv, v8_str("cached string 1"))
                    .FromJust());
          ExpectString("cached", "cached string 1");
        }

        CHECK(context2->Global()->Equals(context2, global).FromJust());
      }
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ReinitializeHashSeedJSCollectionRehashable) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      // Create an object with an ordered hash table.
      CompileRun(
          "var m = new Map();"
          "m.set('a', 1);"
          "m.set('b', 2);"
          "var s = new Set();"
          "
"""


```