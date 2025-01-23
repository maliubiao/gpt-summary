Response:
The user wants a summary of the provided C++ code snippet from V8's `test-api.cc` file.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Functionality:**  The code primarily revolves around testing the module system in V8, particularly focusing on *synthetic modules* and *code caching* for modules.

2. **Synthetic Modules:** Look for keywords like `SyntheticModule`, `CreateSyntheticModule`, `SetSyntheticModuleExport`, `SyntheticModuleEvaluationStepsCallback`. Notice the callbacks and how they are used to define the behavior of synthetic modules.

3. **Code Caching:** Search for terms like `CodeCache`, `CompileModule`, `CompileAndInstantiateModuleFromCache`, `ScriptCompiler::CachedData`. Observe how code caching is used for module compilation and the checks for its validity and interaction with different script types.

4. **Module Instantiation and Evaluation:**  Functions like `CompileAndInstantiateModule`, `InstantiateModule`, and `Evaluate` are crucial for understanding how modules are loaded and executed.

5. **Error Handling and Termination:**  Examine tests involving `TryCatch`, `TerminateExecution`, and how these interact with module evaluation.

6. **Relationship to JavaScript:** Think about how these C++ APIs relate to JavaScript's module system. The code is testing the underlying implementation of JavaScript's `import` and `export` statements, particularly for scenarios involving dynamically created modules.

7. **Structure the Summary:** Organize the findings into logical categories. Start with the high-level purpose and then drill down into specific functionalities.

8. **Address Specific Instructions:**  Review the user's request to ensure all points are covered:
    * **Functionality listing:**  Explicitly list the capabilities demonstrated in the code.
    * **`.tq` check:**  Confirm it's not a Torque file.
    * **JavaScript examples:** Provide concrete JavaScript examples illustrating the tested concepts.
    * **Logic reasoning (input/output):**  For code caching, give an example of how providing a valid cache affects execution.
    * **Common programming errors:** Illustrate a potential issue related to module exports.
    * **Part of a larger series:** Acknowledge that this is a segment and summarize the overall focus.

9. **Refine and Clarify:** Ensure the summary is clear, concise, and uses appropriate terminology. For example, explain what "synthetic modules" are.

**(Self-Correction during the process):**

* Initially, I might have focused too much on the individual test cases. It's important to abstract the common themes and functionalities being tested across those cases.
* I needed to ensure the JavaScript examples directly related to the C++ code's purpose (module features, not just general JavaScript).
* The "logic reasoning" aspect required framing a test scenario in terms of inputs (code, cache) and outputs (execution behavior).

By following these steps, the comprehensive summary addressing all aspects of the user's request can be constructed.
```cpp
Export(
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
    v8::
### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第28部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
Export(
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