Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. The snippet contains several independent test cases using the V8 C++ API. I need to analyze each test case and identify its purpose. I also need to address the specific questions about `.tq` files, JavaScript relevance, logic reasoning, common programming errors, and the section number.

Here's a breakdown of the code and my thought process:

1. **Streaming Tests:** The first few tests (`StreamingScript`, `StreamingScriptWithSplitSourceURL`, `StreamingScriptWithSourceMappingURLInTheMiddle`) are clearly testing V8's ability to compile JavaScript code in a streaming fashion. This involves feeding the source code in chunks.

2. **`TestGetCurrentHostDefinedOptions`:** This test checks how to pass and retrieve host-defined options during script compilation and module instantiation. It uses `GetCurrentHostDefinedOptions`.

3. **`NewStringRangeError`:** This test specifically aims to check the behavior of `v8::String::NewFromUtf8`, `v8::String::NewFromOneByte`, and `v8::String::NewFromTwoByte` when provided with a length exceeding the maximum allowed string length. It expects these calls to return empty handles without throwing exceptions.

4. **Handle Scope Tests (`SealHandleScope`, `SealHandleScopeNested`):** These tests are about the `v8::SealHandleScope`. They verify that once a `SealHandleScope` is active, new handles cannot be created in that scope (except in nested `HandleScope`s). This is a memory management feature.

5. **`Map` and `Set` Tests:** These tests cover the basic functionality of the `v8::Map` and `v8::Set` C++ API, mimicking the behavior of JavaScript's `Map` and `Set` objects (creation, size, adding/deleting elements, clearing).

6. **`SetDeleteThenAsArray` and `MapDeleteThenAsArray`:** These tests focus on a specific scenario: deleting elements from a `Set` or `Map` and then converting it to an array using `AsArray`. They likely target a bug fix related to how deleted elements are handled in this conversion.

7. **`CompatibleReceiverCheckOnCachedICHandler`:** This test seems to be about how V8 handles cached inline caches (ICs) when the receiver object is not of the expected type. It sets up an inheritance scenario and checks that a cached handler for a parent class is not incorrectly used for an object that only structurally resembles the parent.

8. **`ReceiverConversionForAccessors`:** This test explores how V8 handles receiver conversion when calling accessors. It sets up an accessor on an object and then tries to access it through the prototype chain of primitive types (Number, Boolean, String) and directly via `call`.

9. **`FutexInterruption` and `StackCheckTermination`:** These tests deal with interrupting JavaScript execution. `FutexInterruption` uses `Atomics.wait` and `TerminateExecution`. `StackCheckTermination` relies on the stack overflow check mechanism and `TerminateExecution`.

10. **`AbortOnUncaughtExceptionNoAbort`:** This test checks the behavior of the `SetAbortOnUncaughtExceptionCallback`. It verifies that when a custom callback is set, the default behavior of aborting on an uncaught exception can be overridden.

11. **Access Check Tests (`AccessCheckedIsConcatSpreadable`, `AccessCheckedToStringTag`):** These tests examine how access checks (using `SetAccessCheckCallback`) interact with specific JavaScript mechanisms like `Symbol.isConcatSpreadable` and `Symbol.toStringTag`. They verify that access checks can prevent the retrieval of these symbols' values.

12. **Template Intrinsic Tests (`TemplateIteratorPrototypeIntrinsics`, `TemplateAsyncIteratorPrototypeIntrinsics`, `TemplateErrorPrototypeIntrinsics`, `ObjectTemplateArrayProtoIntrinsics`, `ObjectTemplatePerContextIntrinsics`):** These tests explore the `SetIntrinsicDataProperty` method of `ObjectTemplate` and `FunctionTemplate`. They verify that it's possible to set up properties that resolve to built-in prototype objects (like `%IteratorPrototype%`, `%AsyncIteratorPrototype%`, `%ErrorPrototype%`, and methods from `Array.prototype`). `ObjectTemplatePerContextIntrinsics` specifically checks that intrinsics are per-context.

13. **`Proxy` Test:** The snippet ends abruptly within a `Proxy` test. The functionality is likely related to testing the C++ API for creating and interacting with JavaScript proxies.

Now, let's address the specific questions:

* **`.tq` files:**  The code is in `test-api.cc`, so it's C++ and not Torque.
* **JavaScript relevance:**  Many tests directly relate to JavaScript features (`Map`, `Set`, iterators, async iterators, `Symbol.isConcatSpreadable`, `Symbol.toStringTag`, proxies, error handling, etc.).
* **Logic reasoning:**  The tests involve setting up specific conditions and then asserting expected outcomes.
* **Common programming errors:** The `SealHandleScope` tests relate to a common error in V8 API usage: trying to create handles after a scope has been sealed. The `NewStringRangeError` test touches upon the limits of string sizes, a potential source of errors.
* **Section number:** The prompt states this is part 29 of 36.

Finally, I need to synthesize this information into a concise summary.
```cpp
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
        func->NewInstance(env.local()).
### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第29部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  v8::Isola
```