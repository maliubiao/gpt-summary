Response: The user wants a summary of the C++ source code file `v8/test/cctest/test-api.cc`, specifically section 16 out of 18. They are also interested in the relationship with JavaScript and want examples.

**Plan:**

1. **Identify the main functionality being tested in this section.**  Look for `TEST` macros and the operations being performed within them.
2. **Summarize the purpose of each test case.**
3. **If a test case relates to a JavaScript feature, explain the connection and provide a JavaScript example.**
This section of the `v8/test/cctest/test-api.cc` file focuses on testing various V8 C++ API functionalities, particularly those related to:

* **Modules:**  Verifying the behavior of compiled and instantiated JavaScript modules.
* **Global Templates:** Testing how properties are set on global object templates.
* **Primitive Arrays:**  Examining the functionality of `v8::PrimitiveArray` for storing primitive values.
* **Persistent Value Maps:**  Testing the `v8::PersistentValueMap` for storing persistent key-value pairs.
* **Atomics Wait Callback:**  Extensively testing the `v8::Isolate::SetAtomicsWaitCallback` API, which allows interception and control of `Atomics.wait()` behavior in JavaScript.
* **WebAssembly (if enabled):** Testing specific WebAssembly features related to code flushing on memory pressure and the `Atomics.wait()` callback.
* **BigInt API:**  Verifying the functionality of the `v8::BigInt` API for handling large integers.
* **JSEntryStubs:**  Checking the retrieval of JavaScript entry stubs.
* **Microtask Context:** Ensuring that the microtask context is a native context.
* **Iterator Preview:** Testing the `PreviewEntries` functionality of JavaScript iterators, especially in scenarios involving deleted elements in Sets and Maps.
* **Nested Isolates:**  Verifying the behavior of V8 when using multiple isolates.
* **Fast API Calls (if enabled):**  Testing the performance-oriented fast API call mechanism for C++ callbacks.

**Relationship with JavaScript and Examples:**

Many of these tests directly relate to JavaScript features. Here's a breakdown with examples:

1. **Modules:** The tests `ModuleUnboundModuleScript`, `ModuleScriptId`, and `ModuleIsSourceTextModule` directly test the V8 API for handling JavaScript modules (`export`, `import`).

    ```javascript
    // Example of a JavaScript module
    // my_module.js
    export default 5;
    export const a = 10;
    ```

    The C++ code compiles this JavaScript code into a `v8::Module` and then checks properties like its `UnboundModuleScript` (which represents the compiled but not yet linked module) and its `ScriptId`.

2. **Global Templates:** The `GlobalTemplateWithDoubleProperty` test verifies that you can set properties (like "double" with a value of 3.14) on the global object using `v8::ObjectTemplate`. This is how you can expose C++ objects and values to the JavaScript environment.

    ```javascript
    // After setting the global template in C++
    console.log(double); // Output: 3.14
    ```

3. **Primitive Arrays:** The `PrimitiveArray` test checks the functionality of `v8::PrimitiveArray`, which is a V8-specific data structure for efficiently storing JavaScript primitive types (symbols, strings, numbers, booleans, null). While not directly exposed in JavaScript, it's an internal optimization within V8.

4. **Atomics Wait Callback:** The `AtomicsWaitCallback` test is crucial for verifying the `v8::Isolate::SetAtomicsWaitCallback` API. This API allows embedders to intercept and customize the behavior of the JavaScript `Atomics.wait()` function, which is used for implementing synchronization primitives.

    ```javascript
    // JavaScript using Atomics.wait()
    const sab = new SharedArrayBuffer(4);
    const int32Array = new Int32Array(sab);
    int32Array[0] = 0;

    // This will potentially trigger the AtomicsWaitCallback in C++
    Atomics.wait(int32Array, 0, 0);
    ```

    The C++ test simulates various scenarios (interruptions, timeouts, API stops) and checks if the callback is invoked correctly with the expected parameters.

5. **WebAssembly:** The tests under the `v8::internal::wasm` namespace (if `V8_ENABLE_WEBASSEMBLY` is defined) test WebAssembly-specific integrations. `WasmCodeFlushingOnMemoryPressure` checks if Liftoff-compiled WebAssembly code is flushed when memory pressure is high. `WasmI32AtomicWaitCallback` and `WasmI64AtomicWaitCallback` test the interaction between WebAssembly's atomic wait instructions and the V8 `AtomicsWaitCallback`.

    ```javascript
    // Example of WebAssembly using Atomics.wait (indirectly)
    // (This is a simplified representation, actual WebAssembly is binary)
    // function signature: (i32, i32, f64) -> i32
    // body:
    //   atomic.wait.i32(local.get 0, local.get 1, i64.sconvert_f64(local.get 2))

    // When this WebAssembly function is called, it might trigger the AtomicsWaitCallback
    // if the memory is shared and the conditions for waiting are met.
    ```

6. **BigInt API:** The `BigIntAPI` test verifies how the V8 C++ API handles JavaScript `BigInt` values. It checks methods like `Uint64Value`, `Int64Value`, and `NewFromWords`.

    ```javascript
    // JavaScript using BigInt
    const bigIntValue = 123456789012345678901234567890n;
    console.log(bigIntValue);
    ```

7. **JSEntryStubs:** The `GetJSEntryStubs` test examines how to retrieve the entry points for different kinds of JavaScript execution (normal calls, constructor calls, microtask execution) from the V8 API. These are internal details but can be useful for embedders who need fine-grained control over execution.

8. **Microtask Context:** The `MicrotaskContextShouldBeNativeContext` test ensures that when a microtask (like a promise resolution) is being executed, the current context is a "native context". Native contexts are associated with the global object and built-in JavaScript functionality.

    ```javascript
    // Example triggering a microtask
    Promise.resolve().then(() => {
      // Code inside this then() block runs as a microtask
    });
    ```

9. **Iterator Preview:** The `PreviewSetKeysIteratorEntriesWithDeleted`, `PreviewSetValuesIteratorEntriesWithDeleted`, `PreviewMapEntriesIteratorEntries`, `PreviewMapValuesIteratorEntriesWithDeleted`, and `PreviewMapKeysIteratorEntriesWithDeleted` tests verify the `PreviewEntries` method on JavaScript iterators. This method allows you to get a snapshot of the remaining elements in an iterator without fully consuming it, even if elements have been deleted from the underlying collection (Set or Map).

    ```javascript
    // Example using Set iterator's preview
    const mySet = new Set([1, 2, 3]);
    mySet.delete(1);
    const iterator = mySet.keys();
    const preview = iterator.PreviewEntries();
    console.log(preview); // Likely output: [2, 3]
    ```

10. **Nested Isolates:** The `NestedIsolates` test is about running V8 in multiple isolated environments within the same process. This is a more advanced embedding scenario where you might want to run different JavaScript contexts with complete separation.

11. **Fast API Calls:** The tests related to `BasicApiChecker` (if `V8_ENABLE_TURBOFAN` is defined and V8 is not in lite mode) demonstrate V8's ability to optimize calls from JavaScript to C++ functions. By providing a "fast" C++ callback, V8 can potentially bypass some of the overhead of the standard function call mechanism.

In summary, this section of the test file thoroughly examines various aspects of the V8 C++ API, with a strong focus on features that directly interact with and control JavaScript execution and data structures. The tests ensure the correctness and reliability of these APIs for embedders of the V8 engine.

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第16部分，共18部分，请归纳一下它的功能

"""
om");
  Local<String> source_text = v8_str("export default 5; export const a = 10;");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  Local<v8::UnboundModuleScript> sfi_before_instantiation =
      module->GetUnboundModuleScript();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();
  Local<v8::UnboundModuleScript> sfi_after_instantiation =
      module->GetUnboundModuleScript();

  // Check object identity.
  {
    i::DirectHandle<i::Object> s1 =
        v8::Utils::OpenDirectHandle(*sfi_before_instantiation);
    i::DirectHandle<i::Object> s2 =
        v8::Utils::OpenDirectHandle(*sfi_after_instantiation);
    CHECK_EQ(*s1, *s2);
  }
}

TEST(ModuleScriptId) {
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
  int id_before_instantiation = module->ScriptId();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();
  int id_after_instantiation = module->ScriptId();

  CHECK_EQ(id_before_instantiation, id_after_instantiation);
  CHECK_NE(id_before_instantiation, v8::UnboundScript::kNoScriptId);
}

TEST(ModuleIsSourceTextModule) {
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
  CHECK(module->IsSourceTextModule());
  CHECK(!module->IsSyntheticModule());
}

TEST(GlobalTemplateWithDoubleProperty) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
  global->Set(isolate, "double", v8_num(3.14));

  v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);

  v8::Context::Scope context_scope(context);

  Local<Value> result = CompileRun("double");
  CHECK(result->IsNumber());
  CheckDoubleEquals(3.14, result->NumberValue(context).ToChecked());
}

TEST(PrimitiveArray) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  int length = 5;
  Local<v8::PrimitiveArray> array(v8::PrimitiveArray::New(isolate, 5));
  CHECK_EQ(length, array->Length());

  for (int i = 0; i < length; i++) {
    Local<v8::Primitive> item = array->Get(isolate, i);
    CHECK(item->IsUndefined());
  }

  Local<v8::Symbol> symbol(v8::Symbol::New(isolate));
  array->Set(isolate, 0, symbol);
  CHECK(array->Get(isolate, 0)->IsSymbol());

  Local<v8::String> string = v8::String::NewFromUtf8Literal(
      isolate, "test", v8::NewStringType::kInternalized);
  array->Set(isolate, 1, string);
  CHECK(array->Get(isolate, 0)->IsSymbol());
  CHECK(array->Get(isolate, 1)->IsString());

  Local<v8::Number> num = v8::Number::New(env->GetIsolate(), 3.1415926);
  array->Set(isolate, 2, num);
  CHECK(array->Get(isolate, 0)->IsSymbol());
  CHECK(array->Get(isolate, 1)->IsString());
  CHECK(array->Get(isolate, 2)->IsNumber());

  v8::Local<v8::Boolean> f = v8::False(isolate);
  array->Set(isolate, 3, f);
  CHECK(array->Get(isolate, 0)->IsSymbol());
  CHECK(array->Get(isolate, 1)->IsString());
  CHECK(array->Get(isolate, 2)->IsNumber());
  CHECK(array->Get(isolate, 3)->IsBoolean());

  v8::Local<v8::Primitive> n = v8::Null(isolate);
  array->Set(isolate, 4, n);
  CHECK(array->Get(isolate, 0)->IsSymbol());
  CHECK(array->Get(isolate, 1)->IsString());
  CHECK(array->Get(isolate, 2)->IsNumber());
  CHECK(array->Get(isolate, 3)->IsBoolean());
  CHECK(array->Get(isolate, 4)->IsNull());
}

TEST(PersistentValueMap) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  v8::PersistentValueMap<
      std::string, v8::Value,
      v8::DefaultPersistentValueMapTraits<std::string, v8::Value>>
      map(isolate);
  v8::Local<v8::Value> value = v8::String::NewFromUtf8Literal(
      isolate, "value", v8::NewStringType::kInternalized);
  map.Set("key", value);
}

enum class AtomicsWaitCallbackAction {
  Interrupt,
  StopAndThrowInFirstCall,
  StopAndThrowInSecondCall,
  StopFromThreadAndThrow,
  KeepWaiting
};

class StopAtomicsWaitThread;

struct AtomicsWaitCallbackInfo {
  v8::Isolate* isolate;
  v8::Isolate::AtomicsWaitWakeHandle* wake_handle;
  std::unique_ptr<StopAtomicsWaitThread> stop_thread;
  AtomicsWaitCallbackAction action;

  Local<v8::SharedArrayBuffer> expected_sab;
  v8::Isolate::AtomicsWaitEvent expected_event;
  double expected_timeout;
  int64_t expected_value;
  size_t expected_offset;

  size_t ncalls = 0;
};

class StopAtomicsWaitThread : public v8::base::Thread {
 public:
  explicit StopAtomicsWaitThread(AtomicsWaitCallbackInfo* info)
      : Thread(Options("StopAtomicsWaitThread")), info_(info) {}

  void Run() override {
    CHECK_NOT_NULL(info_->wake_handle);
    info_->wake_handle->Wake();
  }

 private:
  AtomicsWaitCallbackInfo* info_;
};

void AtomicsWaitCallbackForTesting(
    v8::Isolate::AtomicsWaitEvent event, Local<v8::SharedArrayBuffer> sab,
    size_t offset_in_bytes, int64_t value, double timeout_in_ms,
    v8::Isolate::AtomicsWaitWakeHandle* wake_handle, void* data) {
  AtomicsWaitCallbackInfo* info = static_cast<AtomicsWaitCallbackInfo*>(data);
  info->ncalls++;
  info->wake_handle = wake_handle;
  CHECK(sab->StrictEquals(info->expected_sab));
  CHECK_EQ(timeout_in_ms, info->expected_timeout);
  CHECK_EQ(value, info->expected_value);
  CHECK_EQ(offset_in_bytes, info->expected_offset);
  CHECK_EQ(v8::StateTag::ATOMICS_WAIT,
           reinterpret_cast<i::Isolate*>(info->isolate)->current_vm_state());

  auto ThrowSomething = [&]() {
    info->isolate->ThrowException(v8::Integer::New(info->isolate, 42));
  };

  if (event == v8::Isolate::AtomicsWaitEvent::kStartWait) {
    CHECK_NOT_NULL(wake_handle);
    switch (info->action) {
      case AtomicsWaitCallbackAction::Interrupt:
        info->isolate->TerminateExecution();
        break;
      case AtomicsWaitCallbackAction::StopAndThrowInFirstCall:
        ThrowSomething();
        [[fallthrough]];
      case AtomicsWaitCallbackAction::StopAndThrowInSecondCall:
        wake_handle->Wake();
        break;
      case AtomicsWaitCallbackAction::StopFromThreadAndThrow:
        info->stop_thread = std::make_unique<StopAtomicsWaitThread>(info);
        CHECK(info->stop_thread->Start());
        break;
      case AtomicsWaitCallbackAction::KeepWaiting:
        break;
    }
  } else {
    CHECK_EQ(event, info->expected_event);
    CHECK_NULL(wake_handle);

    if (info->stop_thread) {
      info->stop_thread->Join();
      info->stop_thread.reset();
    }

    if (info->action == AtomicsWaitCallbackAction::StopAndThrowInSecondCall ||
        info->action == AtomicsWaitCallbackAction::StopFromThreadAndThrow) {
      ThrowSomething();
    }
  }
}

// Must be called from within HandleScope
void AtomicsWaitCallbackCommon(v8::Isolate* isolate, Local<Value> sab,
                               size_t initial_offset,
                               size_t offset_multiplier) {
  CHECK(sab->IsSharedArrayBuffer());

  AtomicsWaitCallbackInfo info;
  info.isolate = isolate;
  info.expected_sab = sab.As<v8::SharedArrayBuffer>();
  isolate->SetAtomicsWaitCallback(AtomicsWaitCallbackForTesting, &info);

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kTerminatedExecution;
    info.action = AtomicsWaitCallbackAction::Interrupt;
    info.ncalls = 0;
    CompileRun("wait(0, 0);");
    CHECK_EQ(info.ncalls, 2);
    CHECK(try_catch.HasTerminated());
  }

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 1;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kNotEqual;
    info.action = AtomicsWaitCallbackAction::KeepWaiting;
    info.ncalls = 0;
    CompileRun("wait(1, 1);");  // real value is 0 != 1
    CHECK_EQ(info.ncalls, 2);
    CHECK(!try_catch.HasCaught());
  }

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = 0.125;
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kTimedOut;
    info.action = AtomicsWaitCallbackAction::KeepWaiting;
    info.ncalls = 0;
    CompileRun("wait(1, 0, 0.125);");  // timeout
    CHECK_EQ(info.ncalls, 2);
    CHECK(!try_catch.HasCaught());
  }

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kAPIStopped;
    info.action = AtomicsWaitCallbackAction::StopAndThrowInFirstCall;
    info.ncalls = 0;
    CompileRun("wait(1, 0);");
    CHECK_EQ(info.ncalls, 1);  // Only one extra call
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()->IsInt32());
    CHECK_EQ(try_catch.Exception().As<v8::Int32>()->Value(), 42);
  }

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kAPIStopped;
    info.action = AtomicsWaitCallbackAction::StopAndThrowInSecondCall;
    info.ncalls = 0;
    CompileRun("wait(1, 0);");
    CHECK_EQ(info.ncalls, 2);
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()->IsInt32());
    CHECK_EQ(try_catch.Exception().As<v8::Int32>()->Value(), 42);
  }

  {
    // Same test as before, but with a different `expected_value`.
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 200;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kAPIStopped;
    info.action = AtomicsWaitCallbackAction::StopAndThrowInSecondCall;
    info.ncalls = 0;
    CompileRun(
        "setArrayElemAs(1, 200);"
        "wait(1, 200);");
    CHECK_EQ(info.ncalls, 2);
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()->IsInt32());
    CHECK_EQ(try_catch.Exception().As<v8::Int32>()->Value(), 42);
  }

  {
    // Wake the `Atomics.wait()` call from a thread.
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kAPIStopped;
    info.action = AtomicsWaitCallbackAction::StopFromThreadAndThrow;
    info.ncalls = 0;
    CompileRun(
        "setArrayElemAs(1, 0);"
        "wait(0, 0);");
    CHECK_EQ(info.ncalls, 2);
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()->IsInt32());
    CHECK_EQ(try_catch.Exception().As<v8::Int32>()->Value(), 42);
  }
}

TEST(AtomicsWaitCallback) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  const char* init = R"(
      let sab = new SharedArrayBuffer(16);
      let int32arr = new Int32Array(sab, 4);
      let setArrayElemAs = function(id, val) {
        int32arr[id] = val;
      };
      let wait = function(id, val, timeout) {
        if(arguments.length == 2) return Atomics.wait(int32arr, id, val);
        return Atomics.wait(int32arr, id, val, timeout);
      };
      sab;)";
  AtomicsWaitCallbackCommon(isolate, CompileRun(init), 4, 4);
}

#if V8_ENABLE_WEBASSEMBLY
namespace v8::internal::wasm {

TEST(WasmCodeFlushingOnMemoryPressure) {
  i::v8_flags.flush_liftoff_code = true;
  WasmRunner<int32_t> r(TestExecutionTier::kLiftoff);
  r.Build({WASM_I32_ADD(WASM_I32V_1(11), WASM_I32V_1(44))});
  CHECK_EQ(55, r.Call());

  // We should have some Liftoff code compiled.
  CHECK_NE(GetWasmEngine()->GetLiftoffCodeSizeForTesting(), 0);

  v8::Isolate* isolate = CcTest::isolate();
  isolate->MemoryPressureNotification(v8::MemoryPressureLevel::kCritical);
  // When there is memory pressure, flush all Liftoff code.
  CHECK_EQ(GetWasmEngine()->GetLiftoffCodeSizeForTesting(), 0);
}

TEST(WasmI32AtomicWaitCallback) {
  WasmRunner<int32_t, int32_t, int32_t, double> r(TestExecutionTier::kTurbofan);
  r.builder().AddMemory(kWasmPageSize, SharedFlag::kShared);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_WAIT(kExprI32AtomicWait, WASM_LOCAL_GET(0),
                             WASM_LOCAL_GET(1),
                             WASM_I64_SCONVERT_F64(WASM_LOCAL_GET(2)), 2, 4)});
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  Handle<JSFunction> func = r.builder().WrapCode(0);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("func"), v8::Utils::ToLocal(func))
            .FromJust());
  Handle<JSArrayBuffer> memory(
      r.builder().trusted_instance_data()->memory_object(0)->array_buffer(),
      i_isolate);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("sab"), v8::Utils::ToLocal(memory))
            .FromJust());

  const char* init = R"(
      let int32arr = new Int32Array(sab, 4);
      let setArrayElemAs = function(id, val) {
        int32arr[id] = val;
      };
      let wait = function(id, val, timeout) {
        if(arguments.length === 2)
          return func(id << 2, val, -1);
        return func(id << 2, val, timeout*1000000);
      };
      sab;)";
  AtomicsWaitCallbackCommon(isolate, CompileRun(init), 4, 4);
}

TEST(WasmI64AtomicWaitCallback) {
  WasmRunner<int32_t, int32_t, double, double> r(TestExecutionTier::kTurbofan);
  r.builder().AddMemory(kWasmPageSize, SharedFlag::kShared);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_WAIT(kExprI64AtomicWait, WASM_LOCAL_GET(0),
                             WASM_I64_SCONVERT_F64(WASM_LOCAL_GET(1)),
                             WASM_I64_SCONVERT_F64(WASM_LOCAL_GET(2)), 3, 8)});
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  Handle<JSFunction> func = r.builder().WrapCode(0);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("func"), v8::Utils::ToLocal(func))
            .FromJust());
  Handle<JSArrayBuffer> memory(
      r.builder().trusted_instance_data()->memory_object(0)->array_buffer(),
      i_isolate);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("sab"), v8::Utils::ToLocal(memory))
            .FromJust());

  const char* init = R"(
      let int64arr = new BigInt64Array(sab, 8);
      let setArrayElemAs = function(id, val) {
        int64arr[id] = BigInt(val);
      };
      let wait = function(id, val, timeout) {
        if(arguments.length === 2)
          return func(id << 3, val, -1);
        return func(id << 3, val, timeout*1000000);
      };
      sab;)";
  AtomicsWaitCallbackCommon(isolate, CompileRun(init), 8, 8);
}

}  // namespace v8::internal::wasm
#endif  // V8_ENABLE_WEBASSEMBLY

TEST(BigIntAPI) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  bool lossless;
  uint64_t words1[10];
  uint64_t words2[10];

  {
    Local<Value> bi = CompileRun("12n");
    CHECK(bi->IsBigInt());

    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(), 12);
    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(&lossless), 12);
    CHECK_EQ(lossless, true);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(), 12);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(&lossless), 12);
    CHECK_EQ(lossless, true);
  }

  {
    Local<Value> bi = CompileRun("-12n");
    CHECK(bi->IsBigInt());

    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(), static_cast<uint64_t>(-12));
    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(&lossless),
             static_cast<uint64_t>(-12));
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(), -12);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(&lossless), -12);
    CHECK_EQ(lossless, true);
  }

  {
    Local<Value> bi = CompileRun("123456789012345678901234567890n");
    CHECK(bi->IsBigInt());

    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(), 14083847773837265618ULL);
    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(&lossless),
             14083847773837265618ULL);
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(), -4362896299872285998LL);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(&lossless),
             -4362896299872285998LL);
    CHECK_EQ(lossless, false);
  }

  {
    Local<Value> bi = CompileRun("-123456789012345678901234567890n");
    CHECK(bi->IsBigInt());

    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(), 4362896299872285998LL);
    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(&lossless),
             4362896299872285998LL);
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(), 4362896299872285998LL);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(&lossless), 4362896299872285998LL);
    CHECK_EQ(lossless, false);
  }

  {
    Local<v8::BigInt> bi =
        v8::BigInt::NewFromWords(env.local(), 0, 0, words1).ToLocalChecked();
    CHECK_EQ(bi->Uint64Value(), 0);
    CHECK_EQ(bi->WordCount(), 0);
  }

  {
    TryCatch try_catch(isolate);
    v8::MaybeLocal<v8::BigInt> bi = v8::BigInt::NewFromWords(
        env.local(), 0, std::numeric_limits<int>::max(), words1);
    CHECK(bi.IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  {
    TryCatch try_catch(isolate);
    v8::MaybeLocal<v8::BigInt> bi =
        v8::BigInt::NewFromWords(env.local(), 0, -1, words1);
    CHECK(bi.IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  {
    TryCatch try_catch(isolate);
    v8::MaybeLocal<v8::BigInt> bi =
        v8::BigInt::NewFromWords(env.local(), 0, 1 << 30, words1);
    CHECK(bi.IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  for (int sign_bit = 0; sign_bit <= 1; sign_bit++) {
    words1[0] = 0xffffffff00000000ULL;
    words1[1] = 0x00000000ffffffffULL;
    v8::Local<v8::BigInt> bi =
        v8::BigInt::NewFromWords(env.local(), sign_bit, 2, words1)
            .ToLocalChecked();
    CHECK_EQ(bi->Uint64Value(&lossless),
             sign_bit ? static_cast<uint64_t>(-static_cast<int64_t>(words1[0]))
                      : words1[0]);
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi->Int64Value(&lossless), sign_bit
                                            ? -static_cast<int64_t>(words1[0])
                                            : static_cast<int64_t>(words1[0]));
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi->WordCount(), 2);
    int real_sign_bit;
    int word_count = arraysize(words2);
    bi->ToWordsArray(&real_sign_bit, &word_count, words2);
    CHECK_EQ(real_sign_bit, sign_bit);
    CHECK_EQ(word_count, 2);
  }
}

TEST(GetJSEntryStubs) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);

  v8::JSEntryStubs entry_stubs = isolate->GetJSEntryStubs();

  v8::JSEntryStub entry_stub = entry_stubs.js_entry_stub;
  CHECK_EQ(
      i_isolate->builtins()->code(i::Builtin::kJSEntry)->instruction_start(),
      reinterpret_cast<i::Address>(entry_stub.code.start));

  v8::JSEntryStub construct_stub = entry_stubs.js_construct_entry_stub;
  CHECK_EQ(i_isolate->builtins()
               ->code(i::Builtin::kJSConstructEntry)
               ->instruction_start(),
           reinterpret_cast<i::Address>(construct_stub.code.start));

  v8::JSEntryStub microtask_stub = entry_stubs.js_run_microtasks_entry_stub;
  CHECK_EQ(i_isolate->builtins()
               ->code(i::Builtin::kJSRunMicrotasksEntry)
               ->instruction_start(),
           reinterpret_cast<i::Address>(microtask_stub.code.start));
}

TEST(MicrotaskContextShouldBeNativeContext) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  auto callback = [](const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Isolate* isolate = info.GetIsolate();
    v8::HandleScope scope(isolate);
    i::DirectHandle<i::Context> context =
        v8::Utils::OpenDirectHandle(*isolate->GetEnteredOrMicrotaskContext());

    CHECK(IsNativeContext(*context));
    info.GetReturnValue().SetUndefined();
  };

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->SetCallAsFunctionHandler(callback);
  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();

  CHECK(env->Global()->Set(env.local(), v8_str("callback"), obj).FromJust());
  CompileRun(
      "with({}){(async ()=>{"
      "  await 42;"
      "})().then(callback);}");

  isolate->PerformMicrotaskCheckpoint();
}

TEST(PreviewSetKeysIteratorEntriesWithDeleted) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  {
    // Create set, delete entry, create iterator, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.delete(1); set.keys()")
            ->ToObject(context)
            .ToLocalChecked();
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.keys()")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, iterate, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.keys(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(1, entries->Length());
    CHECK_EQ(3, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, iterate until empty, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.keys(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next(); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(0, entries->Length());
  }
  {
    // Create set, create iterator, delete entry, iterate, trigger rehash,
    // preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.keys(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next();");
    CompileRun("for (var i = 4; i < 20; i++) set.add(i);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(17, entries->Length());
    for (uint32_t i = 0; i < 17; i++) {
      CHECK_EQ(i + 3, entries->Get(context, i)
                          .ToLocalChecked()
                          ->Int32Value(context)
                          .FromJust());
    }
  }
}

TEST(PreviewSetValuesIteratorEntriesWithDeleted) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  {
    // Create set, delete entry, create iterator, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.delete(1); set.values()")
            ->ToObject(context)
            .ToLocalChecked();
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.values()")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, iterate, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.values(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(1, entries->Length());
    CHECK_EQ(3, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, iterate until empty, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.values(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next(); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(0, entries->Length());
  }
  {
    // Create set, create iterator, delete entry, iterate, trigger rehash,
    // preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.values(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next();");
    CompileRun("for (var i = 4; i < 20; i++) set.add(i);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(17, entries->Length());
    for (uint32_t i = 0; i < 17; i++) {
      CHECK_EQ(i + 3, entries->Get(context, i)
                          .ToLocalChecked()
                          ->Int32Value(context)
                          .FromJust());
    }
  }
}

TEST(PreviewMapEntriesIteratorEntries) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();
  {
    // Create set, delete entry, create entries iterator, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.delete(2); set.entries()")
            ->ToObject(context)
            .ToLocalChecked();
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(is_key);
    CHECK_EQ(4, entries->Length());
    uint32_t first = entries->Get(context, 0)
                         .ToLocalChecked()
                         ->Int32Value(context)
                         .FromJust();
    uint32_t second = entries->Get(context, 2)
                          .ToLocalChecked()
                          ->Int32Value(context)
                          .FromJust();
    CHECK_EQ(1, first);
    CHECK_EQ(3, second);
    CHECK_EQ(first, entries->Get(context, 1)
                        .ToLocalChecked()
                        ->Int32Value(context)
                        .FromJust());
    CHECK_EQ(second, entries->Get(context, 3)
                         .ToLocalChecked()
                         ->Int32Value(context)
                         .FromJust());
  }
}

TEST(PreviewMapValuesIteratorEntriesWithDeleted) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  {
    // Create map, delete entry, create iterator, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = {}; map.set(key, 1);"
                                         "map.set({}, 2); map.set({}, 3);"
                                         "map.delete(key);"
                                         "map.values()")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create map, create iterator, delete entry, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = {}; map.set(key, 1);"
                                         "map.set({}, 2); map.set({}, 3);"
                                         "map.values()")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    CompileRun("map.delete(key);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create map, create iterator, delete entry, iterate, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = {}; map.set(key, 1);"
                                         "map.set({}, 2); map.set({}, 3);"
                                         "var it = map.values(); it")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    CompileRun("map.delete(key); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(1, entries->Length());
    CHECK_EQ(3, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create map, create iterator, delete entry, iterate until empty, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = {}; map.set(key, 1);"
                                         "map.set({}, 2); map.set({}, 3);"
                                         "var it = map.values(); it")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    CompileRun("map.delete(key); it.next(); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(0, entries->Length());
  }
  {
    // Create map, create iterator, delete entry, iterate, trigger rehash,
    // preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = {}; map.set(key, 1);"
                                         "map.set({}, 2); map.set({}, 3);"
                                         "var it = map.values(); it")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    CompileRun("map.delete(key); it.next();");
    CompileRun("for (var i = 4; i < 20; i++) map.set({}, i);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(17, entries->Length());
    for (uint32_t i = 0; i < 17; i++) {
      CHECK_EQ(i + 3, entries->Get(context, i)
                          .ToLocalChecked()
                          ->Int32Value(context)
                          .FromJust());
    }
  }
}

TEST(PreviewMapKeysIteratorEntriesWithDeleted) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  {
    // Create map, delete entry, create iterator, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = 1; map.set(key, {});"
                                         "map.set(2, {}); map.set(3, {});"
                                         "map.delete(key);"
                                         "map.keys()")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create map, create iterator, delete entry, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = 1; map.set(key, {});"
                                         "map.set(2, {}); map.set(3, {});"
                                         "map.keys()")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    CompileRun("map.delete(key);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create map, create iterator, delete entry, iterate, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = 1; map.set(key, {});"
                                         "map.set(2, {}); map.set(3, {});"
                                         "var it = map.keys(); it")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    CompileRun("map.delete(key); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(1, entries->Length());
    CHECK_EQ(3, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create map, create iterator, delete entry, iterate until empty, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = 1; map.set(key, {});"
                                         "map.set(2, {}); map.set(3, {});"
                                         "var it = map.keys(); it")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    CompileRun("map.delete(key); it.next(); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(0, entries->Length());
  }
}

namespace {
static v8::Isolate* isolate_1;
static v8::Isolate* isolate_2;
v8::Persistent<v8::Context> context_1;
v8::Persistent<v8::Context> context_2;

void CallIsolate1(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Isolate::Scope isolate_scope(isolate_1);
  v8::HandleScope handle_scope(isolate_1);
  v8::Local<v8::Context> context =
      v8::Local<v8::Context>::New(isolate_1, context_1);
  v8::Context::Scope context_scope(context);
  CompileRun("f1() //# sourceURL=isolate1b");
}

void CallIsolate2(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Isolate::Scope isolate_scope(isolate_2);
  v8::HandleScope handle_scope(isolate_2);
  v8::Local<v8::Context> context =
      v8::Local<v8::Context>::New(isolate_2, context_2);
  v8::Context::Scope context_scope(context);
  i::Heap* heap_2 = reinterpret_cast<i::Isolate*>(isolate_2)->heap();
  i::heap::InvokeMajorGC(heap_2, i::GCFlag::kForced);
  CompileRun("f2() //# sourceURL=isolate2b");
}

}  // anonymous namespace

UNINITIALIZED_TEST(NestedIsolates) {
#ifdef VERIFY_HEAP
  i::v8_flags.verify_heap = true;
#endif  // VERIFY_HEAP
  // Create two isolates and set up C++ functions via function templates that
  // call into the other isolate. Recurse a few times, trigger GC along the way,
  // and finally capture a stack trace. Check that the stack trace only includes
  // frames from its own isolate.
  i::v8_flags.stack_trace_limit = 20;
  i::v8_flags.experimental_stack_trace_frames = true;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  isolate_1 = v8::Isolate::New(create_params);
  isolate_2 = v8::Isolate::New(create_params);

  {
    v8::Isolate::Scope isolate_scope(isolate_1);
    v8::HandleScope handle_scope(isolate_1);

    v8::Local<v8::Context> context = v8::Context::New(isolate_1);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate_1, CallIsolate2);
    fun_templ->SetClassName(v8_str(isolate_1, "call_isolate_2"));
    Local<Function> fun = fun_templ->GetFunction(context).ToLocalChecked();
    CHECK(context->Global()
              ->Set(context, v8_str(isolate_1, "call_isolate_2"), fun)
              .FromJust());
    CompileRun(
        "let c = 0;"
        "function f1() {"
        "  c++;"
        "  return call_isolate_2();"
        "} //# sourceURL=isolate1a");
    context_1.Reset(isolate_1, context);
  }

  {
    v8::Isolate::Scope isolate_scope(isolate_2);
    v8::HandleScope handle_scope(isolate_2);

    v8::Local<v8::Context> context = v8::Context::New(isolate_2);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate_2, CallIsolate1);
    fun_templ->SetClassName(v8_str(isolate_2, "call_isolate_1"));
    Local<Function> fun = fun_templ->GetFunction(context).ToLocalChecked();

    CHECK(context->Global()
              ->Set(context, v8_str(isolate_2, "call_isolate_1"), fun)
              .FromJust());
    CompileRun(
        "let c = 4;"
        "let result = undefined;"
        "function f2() {"
        "  if (c-- > 0) return call_isolate_1();"
        "  else result = new Error().stack;"
        "} //# sourceURL=isolate2a");
    context_2.Reset(isolate_2, context);

    v8::Local<v8::String> result =
        CompileRun("f2(); result //# sourceURL=isolate2c")
            ->ToString(context)
            .ToLocalChecked();
    v8::Local<v8::String> expectation =
        v8_str(isolate_2,
               "Error\n"
               "    at f2 (isolate2a:1:104)\n"
               "    at isolate2b:1:1\n"
               "    at call_isolate_1 (<anonymous>)\n"
               "    at f2 (isolate2a:1:71)\n"
               "    at isolate2b:1:1\n"
               "    at call_isolate_1 (<anonymous>)\n"
               "    at f2 (isolate2a:1:71)\n"
               "    at isolate2b:1:1\n"
               "    at call_isolate_1 (<anonymous>)\n"
               "    at f2 (isolate2a:1:71)\n"
               "    at isolate2b:1:1\n"
               "    at call_isolate_1 (<anonymous>)\n"
               "    at f2 (isolate2a:1:71)\n"
               "    at isolate2c:1:1");
    CHECK(result->StrictEquals(expectation));
  }

  {
    v8::Isolate::Scope isolate_scope(isolate_1);
    v8::HandleScope handle_scope(isolate_1);
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(isolate_1, context_1);
    v8::Context::Scope context_scope(context);
    ExpectInt32("c", 4);
  }

  isolate_1->Dispose();
  isolate_2->Dispose();
}

#undef THREADED_PROFILED_TEST

#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
namespace {

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
template <typename Value>
Value PrimitiveFromMixedType(v8::AnyCType argument);

template <>
bool PrimitiveFromMixedType(v8::AnyCType argument) {
  return argument.bool_value;
}
template <>
int32_t PrimitiveFromMixedType(v8::AnyCType argument) {
  return argument.int32_value;
}
template <>
uint32_t PrimitiveFromMixedType(v8::AnyCType argument) {
  return argument.uint32_value;
}
template <>
int64_t PrimitiveFromMixedType(v8::AnyCType argument) {
  return argument.int64_value;
}
template <>
uint64_t PrimitiveFromMixedType(v8::AnyCType argument) {
  return argument.uint64_value;
}
template <>
float PrimitiveFromMixedType(v8::AnyCType argument) {
  return argument.float_value;
}
template <>
double PrimitiveFromMixedType(v8::AnyCType argument) {
  return argument.double_value;
}
template <>
v8::Local<v8::Value> PrimitiveFromMixedType(v8::AnyCType argument) {
  return argument.object_value;
}

template <typename T>
v8::AnyCType PrimitiveToMixedType(T value) {
  return v8::AnyCType();
}

template <>
v8::AnyCType PrimitiveToMixedType(bool value) {
  v8::AnyCType ret;
  ret.bool_value = value;
  return ret;
}
template <>
v8::AnyCType PrimitiveToMixedType(int32_t value) {
  v8::AnyCType ret;
  ret.int32_value = value;
  return ret;
}
template <>
v8::AnyCType PrimitiveToMixedType(uint32_t value) {
  v8::AnyCType ret;
  ret.uint32_value = value;
  return ret;
}
template <>
v8::AnyCType PrimitiveToMixedType(float value) {
  v8::AnyCType ret;
  ret.float_value = value;
  return ret;
}
template <>
v8::AnyCType PrimitiveToMixedType(double value) {
  v8::AnyCType ret;
  ret.double_value = value;
  return ret;
}

#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

template <typename Value, typename Impl, typename Ret>
struct BasicApiChecker {
  static Ret FastCallback(v8::Local<v8::Object> receiver, Value argument,
                          v8::FastApiCallbackOptions& options) {
    // TODO(mslekova): Refactor the data checking.
    CHECK(options.data->IsNumber());
    CHECK_EQ(Local<v8::Number>::Cast(options.data)->Value(), 42.5);
    return Impl::FastCallback(receiver, argument, options);
  }
  static Ret FastCallbackNoOptions(v8::Local<v8::Object> receiver,
                                   Value argument) {
    v8::FastApiCallbackOptions options =
        v8::FastApiCallbackOptions::CreateForTesting(v8::Isolate::GetCurrent());
    return Impl::FastCallback(receiver, argument, options);
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    Impl::SlowCallback(info);
  }

  bool DidCallFast() const { return (result_ & ApiCheckerResult::kFastCalled); }
  bool DidCallSlow() const { return (result_ & ApiCheckerResult::kSlowCalled); }

  void SetCallFast() { result_ |= ApiCheckerResult::kFastCalled; }
  void SetCallSlow() { result_ |= ApiCheckerResult::kSlowCalled; }

  void Reset() { result_ = ApiCheckerResult::kNotCalled; }

 private:
  ApiCheckerResultFlags result_ = ApiCheckerResult::kNotCalled;
};

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
template <typename Value, typename Impl, typename Ret,
          typename = std::enable_if_t<!std::is_void<Ret>::value>>
static v8::AnyCType FastCallbackPatch(v8::AnyCType receiver,
                                      v8::AnyCType argument,
                                      v8::AnyCType options) {
  v8::AnyCType ret = PrimitiveToMixedType<Ret>(Impl::FastCallback(
      receiver.object_value, PrimitiveFromMixedType<Value>(argument),
      *(options.options_value)));
  return ret;
}
template <typename Value, typename Impl, typename Ret,
          typename = std::enable_if_t<!std::is_void<Ret>::value>>
static v8::AnyCType FastCallbackNoOptionsWrapper(v8::AnyCType receiver,
                                                 v8::AnyCType argument) {
  v8::FastApiCallbackOptions options =
      v8::FastApiCallbackOptions::CreateForTesting(v8::Isolate::GetCurrent());
  v8::AnyCType ret = PrimitiveToMixedType<Ret>(Impl::FastCallback(
      receiver.object_value, PrimitiveFromMixedType<Value>(argument), options));
  return ret;
}
template <typename Value, typename Impl, typename Ret,
          typename = std::enable_if_t<std::is_void<Ret>::value>>
static void FastCallbackPatch(v8::AnyCType receiver, v8::AnyCType argument,
                              v8::AnyCType options) {
  return Impl::FastCallback(receiver.object_value,
                            PrimitiveFromMixedType<Value>(argument),
                            *(options.options_value));
}
template <typename Value, typename Impl, typename Ret,
          typename = std::enable_if_t<std::is_void<Ret>::value>>
static void FastCallbackNoOptionsWrapper(v8::AnyCType receiver,
                                         v8::AnyCType argument) {
  v8::FastApiCallbackOptions options =
      v8::FastApiCallbackOptions::CreateForTesting(v8::Isolate::GetCurrent());
  return Impl::FastCallback(receiver.object_value,
                            PrimitiveFromMixedType<Value>(argument), options);
}
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

enum class Behavior {
  kNoException,
  kException,  // An exception should be thrown by the callback function.
};

template <typename T>
struct ApiNumberChecker : BasicApiChecker<T, ApiNumberChecker<T>, void> {
  explicit ApiNumberChecker(
      T value, Behavior raise_exception = Behavior::kNoException,
      int args_count = 1)
      : raise_exception_(raise_exception),
        args_count_(args_count) {}

  static void FastCallback(v8::Local<v8::Object> receiver, T argument,
                           v8::FastApiCallbackOptions& options) {
    v8::Object* receiver_obj = *receiver;
    CHECK(IsValidUnwrapObject(receiver_obj));
    ApiNumberChecker<T>* receiver_ptr =
        GetInternalField<ApiNumberChecker<T>>(receiver_obj);
    receiver_ptr->SetCallFast();
    receiver_ptr->fast_value_ = argument;
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    v8::Object* receiver = v8::Object::Cast(*info.HolderSoonToBeDeprecated());
    if (!IsValidUnwrapObject(receiver)) {
      info.GetIsolate()->ThrowException(v8_str("Called with a non-object."));
      return;
    }
    ApiNumberChecker<T>* checker =
        GetInternalField<ApiNumberChecker<T>>(receiver);
    CHECK_EQ(info.Length(), checker->args_count_);

    checker->SetCallSlow();

    LocalContext env;
    checker->slow_value_ = ConvertJSValue<T>::Get(info[0], env.local());

    if (checker->raise_exception_ == Behavior::kException) {
      info.GetIsolate()->ThrowException(v8_str("Callback error"));
    }
  }

  T fast_value_ = T();
  Maybe<T> slow_value_ = v8::Nothing<T>();
  Behavior raise_exception_ = Behavior::kNoException;
  int args_count_ = 1;
};

struct UnexpectedObjectChecker
    : BasicApiChecker<v8::Local<v8::Value>, UnexpectedObjectChecker, void> {
  static void FastCallback(v8::Local<v8::Object> receiver,
                           v8::Local<v8::Value> argument,
                           v8::FastApiCallbackOptions& options) {
    UnexpectedObjectChecker* receiver_ptr =
        GetInternalField<UnexpectedObjectChecker>(*receiver);
    receiver_ptr->SetCallFast();
    if (argument->IsObject()) {
      v8::Object* argument_obj = v8::Object::Cast(*argument);
      CHECK(!IsValidUnwrapObject(argument_obj));
    }
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    v8::Object* receiver_obj =
        v8::Object::Cast(*info.HolderSoonToBeDeprecated());
    UnexpectedObjectChecker* receiver_ptr =
        GetInternalField<UnexpectedObjectChecker>(receiver_obj);
    receiver_ptr->SetCallSlow();
    if (info[0]->IsObject()) {
      v8::Object* argument_obj = v8::Object::Cast(*info[0]);
      CHECK(!IsValidUnwrapObject(argument_obj));
    }
  }
};

struct EmbedderType {
  int data;
};

struct ApiObjectChecker
    : BasicApiChecker<v8::Local<v8::Value>, ApiObjectChecker, void> {
  ApiObjectChecker(v8::FunctionTemplate* ctor, int data)
      : ctor_(ctor), initial_data_(data) {}

  static void FastCallback(v8::Local<v8::Object> receiver,
                           v8::Local<v8::Value> argument,
                           v8::FastApiCallbackOptions& options) {
    ApiObjectChecker* receiver_ptr =
        GetInternalField<ApiObjectChecker>(*receiver);
    receiver_ptr->SetCallFast();

    v8::Object* argument_obj = v8::Object::Cast(*argument);
    EmbedderType* argument_ptr = GetInternalField<EmbedderType>(argument_obj);
    CHECK(receiver_ptr->ctor_->IsLeafTemplateForApiObject(argument));

    argument_ptr->data = receiver_ptr->initial_data_;
  }
  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    v8::Object* receiver_obj =
        v8::Object::Cast(*info.HolderSoonToBeDeprecated());
    ApiObjectChecker* receiver_ptr =
        GetInternalField<ApiObjectChecker>(receiver_obj);
    receiver_ptr->SetCallSlow();

    CHECK(info[0]->IsObject());
    v8::Local<v8::Object> argument_obj = info[0].As<v8::Object>();
    CHECK(receiver_ptr->ctor_->IsLeafTemplateForApiObject(argument_obj));
  }

  v8::FunctionTemplate* ctor_;
  int fast_value_ = 0;
  int initial_data_;
};

template <typename Value, typename Impl, typename Ret>
bool SetupTest(v8::Local<v8::Value> initial_value, LocalContext* env,
               BasicApiChecker<Value, Impl, Ret>* checker,
               const char* source_code, bool has_options = true,
               bool accept_any_receiver = true, bool setup_try_catch = true) {
  v8::Isolate* isolate = CcTest::isolate();
  std::optional<v8::TryCatch> try_catch;
  if (setup_try_catch) {
    try_catch.emplace(isolate);
  }

  v8::CFunction c_func;
  if (has_options) {
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    c_func =
        v8::CFunction::Make(BasicApiChecker<Value, Impl, Ret>::FastCallback,
                            FastCallbackPatch<Value, Impl, Ret>);
#else   // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    c_func =
        v8::CFunction::Make(BasicApiChecker<Value, Impl, Ret>::FastCallback);
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  } else {
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    c_func = v8::CFunction::Make(
        BasicApiChecker<Value, Impl, Ret>::FastCallbackNoOptions,
        FastCallbackNoOptionsWrapper<Value, Impl, Ret>);
#else   // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    c_func = v8::CFunction::Make(
        BasicApiChecker<Value, Impl, Ret>::FastCallbackNoOptions);
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  }
  CHECK_EQ(c_func.ArgumentInfo(0).GetType(), v8::CTypeInfo::Type::kV8Value);

  Local<v8::FunctionTemplate> checker_templ = v8::FunctionTemplate::New(
      isolate, BasicApiChecker<Value, Impl, Ret>::SlowCallback,
      v8::Number::New(isolate, 42.5), v8::Local<v8::Signature>(), 1,
      v8::ConstructorBehavior::kThrow, v8::SideEffectType::kHasSideEffect,
      &c_func);
  if (!accept_any_receiver) {
    checker_templ->SetAcceptAnyReceiver(false);
  }

  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetInternalFieldCount(kV8WrapperObjectIndex + 1);
  object_template->Set(isolate, "api_func", checker_templ);

  v8::Local<v8::Object> object =
      object_template->NewInstance(env->local()).ToLocalChecked();
  object->SetAlignedPointerInInternalField(kV8WrapperObjectIndex,
                                           reinterpret_cast<void*>(checker));

  CHECK((*env)
            ->Global()
            ->Set(env->local(), v8_str("receiver"), object)
            .FromJust());
  CHECK((*env)
            ->Global()
            ->Set(env->local(), v8_str("value"), initial_value)
            .FromJust());
  USE(CompileRun(source_code));
  return setup_try_catch ? try_catch->HasCaught() : false;
}

template <typename I, std::enable_if_t<std::is_integral<I>::value, bool> = true>
void CheckEqual(I actual, I expected, std::ostringstream& error_msg) {
  if (actual != expected) {
    error_msg << "Value mismatch (expected: " << expected
              << ", actual: " << actual << ")";
  }
}

template <typename F,
          std::enable_if_t<std::is_floating_point<F>::value, bool> = true>
void CheckEqual(F actual, F expected, std::ostringstream& error_msg) {
  if (std::isnan(expected)) {
    if (!std::isnan(actual)) {
      error_msg << "Value mismatch (expected: " << expected
                << ", actual: " << actual << ")";
    }
  } else {
    // This differentiates between -0 and +0.
    if (std::signbit(actual) != std::signbit(expected) || actual != expected) {
      error_msg << "Value mismatch (expected: " << expected
                << ", actual: " << actual << ")";
    }
  }
}

#if V8_ENABLE_WEBASSEMBLY
void CallAndCheckFromWasm() {
  LocalContext env;
  int32_t expected_value = -32;
  ApiNumberChecker<int32_t> checker(expected_value, Behavior::kNoException);
  v8::Local<v8::Value> initial_value = v8_num(expected_value);
  bool has_caught = SetupTest<int32_t, ApiNumberChecker<int32_t>, void>(
      initial_value, &env, &checker,
      "function func(arg) {"
      "  const buffer = new Uint8Array(["
      "  0x00, 0x61, 0x73, 0x6d,"  // wasm magic
      "  0x01, 0x00, 0x00, 0x00,"  // wasm version

      "  0x01,                  "  // section kind: Type
      "  0x06,                  "  // section length 6
      "  0x01,                  "  // types count 1
      "  0x60,                  "  //  kind: func
      "  0x02,                  "  // param count 2
      "  0x6f, 0x7f,            "  // externref i32
      "  0x00,                  "  // return count 0

      "  0x02,                  "  // section kind: Import
      "  0x0b,                  "  // section length 11
      "  0x01,                  "  // imports count 1: import #0
      "  0x03,                  "  // module name length:  3
      "  0x6d, 0x6f, 0x64,      "  // module name: mod
      "  0x03,                  "  // field name length:  3
      "  0x66, 0x6f, 0x6f,      "  // field name: foo
      "  0x00, 0x00,            "  // kind: function (param externref i32)

      "  0x03,                  "  // section kind: Function
      "  0x02,                  "  // section length 2
      "  0x01, 0x00,            "  // num functions 1, sig (param externref i32)

      "  0x07,                  "  // section kind: Export
      "  0x08,                  "  // section length 8
      "  0x01,                  "  // exports count 1: export # 0
      "  0x04,                  "  // field name length:  4
      "  0x6d, 0x61, 0x69, 0x6e,"  // field name: main
      "  0x00, 0x01,            "  // kind: function index:  1

      "  0x0a,                  "  // section kind: Code
      "  0x0a,                  "  // section length 10
      "  0x01,                  "  // functions count 1
      "                         "  // function #1 $main
      "  0x08,                  "  // body size 8
      "  0x00,                  "  // 0 entries in locals list
      "  0x20, 0x00,            "  // local.get $var0
      "  0x20, 0x01,            "  // local.get $var1
      "  0x10, 0x00,            "  // call $mod.foo
      "  0x0b,                  "  // end
      "]);"
      "  const wasmModule = new WebAssembly.Module(buffer);"
      "  const boundImport = Function.prototype.call.bind(receiver.api_func);"
      "  const wasmImport = {mod: {foo: boundImport}};"
      "  const instance = new WebAssembly.Instance(wasmModule, wasmImport);"
      "  return instance.exports.main(receiver, arg);"
      "}"
      "func(value);",
      true, false, false);
  CHECK(!has_caught);
  checker.Reset();

  v8::Isolate* isolate = CcTest::isolate();
  v8::TryCatch try_catch(isolate);
  v8::Local<v8::Value> result = CompileRun("func(value);");
  CHECK(!try_catch.HasCaught());
  CHECK_EQ(result->Int32Value(env.local()).ToChecked(), 0);
  CHECK(checker.DidCallFast());
  CHECK(!checker.DidCallSlow());
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename T>
void CallAndCheck(T expected_value, Behavior expected_behavior,
                  ApiCheckerResultFlags expected_path,
                  v8::Local<v8::Value> initial_value,
                  Behavior raise_exception = Behavior::kNoException) {
  LocalContext env;
  ApiNumberChecker<T> checker(expected_value, raise_exception);

  bool has_caught = SetupTest<T, ApiNumberChecker<T>, void>(
      initial_value, &env, &checker,
      "function func(arg) { return receiver.api_func(arg); }"
      "%PrepareFunctionForOptimization(func);"
      "func(value);");
  checker.Reset();

  v8::Isolate* isolate = CcTest::isolate();
  v8::TryCatch try_catch(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "%OptimizeFunctionOnNextCall(func);"
      "func(value);");
  if (!try_catch.HasCaught()) {
    CHECK(result->IsUndefined());
  }

  CHECK_EQ(expected_behavior == Behavior::kException, has_caught);

  std::ostringstream error_msg;
  if (expected_path == ApiCheckerResult::kSlowCalled) {
    if (checker.DidCallFast()) {
      error_msg << "Fast path was called when only the default was expected. ";
    }
  }
  if (expected_path == ApiCheckerResult::kFastCalled) {
    if (checker.DidCallSlow()) {
      error_msg << "Default path was called when fast path was expected. ";
    }
  }
  if (error_msg.str().length() > 0) {
    error_msg << "Expected value was: " << expected_value;
    CHECK_WITH_MSG(false, error_msg.str().c_str());
  }

  if (expected_path & ApiCheckerResult::kSlowCalled) {
    if (!checker.DidCallSlow()) {
      error_msg << "Default path was expected, but wasn't called. ";
    }
    if (expected_behavior != Behavior::kException) {
      CheckEqual(checker.slow_value_.ToChecked(), expected_value, error_msg);
    }
    if (error_msg.str().length() > 0) {
      error_msg << " from default path. ";
    }
  }
  if (expected_path & ApiCheckerResult::kFastCalled) {
    if (!checker.DidCallFast()) {
      error_msg << "Fast path was expected, but wasn't called. ";
    }
    CheckEqual(checker.fast_value_, expected_value, error_msg);
    if (error_msg.str().length() > 0) {
      error_msg << " from fast path";
    }
  }
  if (error_msg.str().length() > 0) {
    CHECK_WITH_MSG(false, error_msg.str().c_str());
  }
}

void CheckApiObjectArg() {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  Local<v8::FunctionTemplate> api_obj_ctor = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::ObjectTemplate> api_obj_template =
      api_obj_ctor->InstanceTemplate();
  api_obj_template->SetInternalFieldCount(kV8WrapperObjectIndex + 1);

  EmbedderType embedder_obj;
  v8::Local<v8::Object> api_obj =
      api_obj_template->NewInstance(env.local()).ToLocalChecked();
  api_obj->SetAlignedPointerInInternalField(
      kV8WrapperObjectIndex, reinterpret_cast<void*>(&embedder_obj));
  CHECK(env->Global()
            ->Set(env.local(), v8_str("api_object"), api_obj)
            .FromJust());

  const int data = 42;
  ApiObjectChecker checker(*api_obj_ctor, data);
  bool has_caught =
      SetupTest(v8_num(data), &env, &checker,
                "function func() { return receiver.api_func(api_object); }"
                "%PrepareFunctionForOptimization(func);"
                "func();");
  checker.Reset();
  CHECK(!has_caught);

  CompileRun(
      "%OptimizeFunctionOnNextCall(func);"
      "func();");

  CHECK(checker.DidCallFast());
  CHECK_EQ(embedder_obj.data, data);
  CHECK(!checker.DidCallSlow());
}

static const char* fast_calls_error_message = nullptr;
static const char* fast_calls_error_location = nullptr;
void FastCallsErrorCallback(const char* location, const char* message) {
  fast_calls_error_message = message;
  fast_calls_error_location = location;
}

void CheckFastCallsWithConstructor() {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  CcTest::isolate()->SetFatalErrorHandler(FastCallsErrorCallback);

  CHECK_NULL(fast_calls_error_message);

  v8::CFunction c_func_ctor =
      v8::CFunction::Make(ApiObjectChecker::FastCallback);
  v8::FunctionTemplate::New(isolate, ApiObjectChecker::SlowCallback,
                            Local<v8::Value>(), v8::Local<v8::Signature>(), 1,
                            v8::ConstructorBehavior::kAllow,
                            v8::SideEffectType::kHasSideEffect, &c_func_ctor);
  CHECK_NOT_NULL(fast_calls_error_message);
  CHECK_EQ(
      0, strcmp(fast_calls_error_message,
                "Fast API calls are not supported for constructor functions"));
  CHECK_NOT_NULL(fast_calls_error_location);
  CHECK_EQ(0, strcmp(fast_calls_error_location, "FunctionTemplate::New"));

  fast_calls_error_message = nullptr;
  const v8::CFunction c_func_ctor_overloads[] = {c_func_ctor};
  v8::FunctionTemplate::NewWithCFunctionOverloads(
      isolate, ApiObjectChecker::SlowCallback, Local<v8::Value>(),
      v8::Local<v8::Signature>(), 1, v8::ConstructorBehavior::kAllow,
      v8::SideEffectType::kHasSideEffect, {c_func_ctor_overloads, 1});
  CHECK_NOT_NULL(fast_calls_error_message);
  CHECK_EQ(
      0, strcmp(fast_calls_error_message,
                "Fast API calls are not supported for constructor functions"));
  CHECK_NOT_NULL(fast_calls_error_location);
  CHECK_EQ(0, strcmp(fast_calls_error_location,
                     "FunctionTemplate::NewWithCFunctionOverloads"));
}

template <typename T>
struct ReturnValueChecker : BasicApiChecker<T, ReturnValueChecker<T>, T> {
  static T FastCallback(v8::Local<v8::Object
"""


```