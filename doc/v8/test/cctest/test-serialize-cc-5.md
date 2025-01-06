Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/test-serialize.cc`. The request also has several constraints: identify functionality, check if it's a Torque file (it's not, as it doesn't end in `.tq`), relate to JavaScript if possible with examples, provide logic inference with input/output, point out common programming errors, and summarize its function as part 6 of 8.

Here's a breakdown of the thought process to address these points:

1. **Overall Goal:** Understand what the C++ code is testing related to V8's serialization.

2. **Code Examination - Initial Scan:**  The code uses `v8::StartupData`, `v8::SnapshotCreator`, `v8::Isolate`, `v8::Context`, `v8::Object`, and related V8 APIs. Keywords like `Serialize`, `Deserialize`, `Snapshot` are prominent. This strongly suggests the code is testing V8's snapshot creation and deserialization mechanisms.

3. **Functionality Breakdown - By Code Block:**
    * **First Block (Context Embedder Data & Internal Fields):**  This block creates a snapshot with a context and an object. It sets embedder data on the context and an internal field on the object. It then deserializes the snapshot and verifies that the embedder data and internal field values are correctly restored. Crucially, it uses custom serialize and deserialize callbacks (`serialize_internal_fields`, `deserialize_internal_fields`, `serialize_context_data`, `deserialize_context_data`). The `CHECK_EQ` calls confirm the data round-trips successfully. This demonstrates testing the serialization and deserialization of custom data attached to contexts and objects.

    * **Second Block (Context Embedder Data - No Custom Serializer):**  This block is similar but *doesn't* provide custom serialization for the context embedder data. It checks that during deserialization, the embedder data is either `nullptr` (in sandboxed mode) or retains its original value (outside sandboxed mode). This highlights how V8 handles embedder data without explicit serialization instructions.

    * **Third Block (API Wrapper Data):** This section deals with API wrappers (C++ objects wrapped in JavaScript objects). It uses `SerializeAPIWrapperCallback` and `DeserializeAPIWrapperCallback`. A "special" object is marked, and the callbacks are used to tag it during serialization and potentially perform actions during deserialization. The checks involve ensuring the tag is correctly applied and that unwrapping the objects after deserialization results in `nullptr` (meaning the original C++ objects weren't directly serialized, but the wrapping information might have been).

    * **Fourth Block (SnapshotCreator::AddData):** This part focuses on the `AddData` method of `SnapshotCreator`. It demonstrates adding various V8 objects (numbers, strings, object templates, contexts, modules, function templates, private symbols, signatures) to the snapshot, both context-dependent and context-independent. The deserialization part verifies that these added data objects can be retrieved using `GetDataFromSnapshotOnce`. It also tests adding data to an existing snapshot and how it replaces the previous data.

    * **Fifth Block (SnapshotCreator Unknown Handles):**  This seems like a basic test ensuring that creating a snapshot with eternal and persistent handles doesn't cause issues, even if these handles might not be fully "known" during snapshot creation. It's a simpler test case.

    * **Sixth Block (SnapshotAccessorDescriptors):** This tests the serialization and deserialization of accessor properties defined using `Object.defineProperty`. It checks if the getter and setter logic is preserved across snapshots.

    * **Seventh Block (SnapshotObjectDefinePropertyWhenNewGlobalTemplate):**  This tests how properties defined with `Object.defineProperty` interact with the creation of a new global object template during deserialization. It ensures the properties are correctly present on the global object.

    * **Eighth Block (SnapshotCreatorIncludeGlobalProxy):** This is a more complex test case dealing with the serialization of the global proxy object. It explores scenarios where the global proxy is implicitly serialized or not, and how extensions and interceptors on the global object are handled during snapshot creation and deserialization. It also covers reusing global proxies across contexts.

    * **Ninth Block (ReinitializeHashSeedJSCollectionRehashable):**  This block is about testing the rehashability of JavaScript collections (like `Map` and `Set`) when using snapshots with different hash seeds. The `i::v8_flags.rehash_snapshot` flag is significant here.

4. **JavaScript Relevance:**  Many of the concepts tested directly relate to JavaScript features: objects, properties (including accessors), global objects, modules, Maps, and Sets. The JavaScript examples in the response illustrate how these features are used and how the C++ code verifies their correct serialization and deserialization.

5. **Logic Inference:**  The input is the state of the V8 isolate and context when the snapshot is created. The output is the state of the *new* isolate and context after deserializing the snapshot. The `CHECK_EQ` and `ExpectInt32/ExpectString` calls are the core of this verification. The example provided in the prompt focuses on verifying the preservation of embedder data and internal field data.

6. **Common Programming Errors:** The example focuses on the crucial distinction between providing custom serialization callbacks and not. Forgetting to provide these callbacks when relying on specific data can lead to unexpected `nullptr` values or incorrect data restoration after deserialization. This is a common mistake when working with V8's embedding APIs.

7. **Torque Check:**  The code doesn't end in `.tq`, so it's not a Torque file.

8. **Part 6 Summary:** Based on the detailed breakdown, the core function of this part of the test suite is to rigorously verify V8's snapshot serialization and deserialization capabilities, focusing on how different types of data (embedder data, internal fields, API wrappers, and various V8 objects) are handled during this process.

By following these steps, one can systematically analyze the C++ code and address all aspects of the user's request, including providing relevant JavaScript examples, logic inference, and identifying potential programming errors.
```cpp
= static_cast<InternalFieldData*>(
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
        CHECK_EQ(context_data_test::object_data, field); // Correction: comparing pointers
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
        
Prompt: 
```
这是目录为v8/test/cctest/test-serialize.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-serialize.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能

"""
= static_cast<InternalFieldData*>(
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