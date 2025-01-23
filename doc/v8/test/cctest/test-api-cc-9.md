Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`.

Here's a plan to address the request:

1. **Identify the main purpose:** The file name suggests it tests the V8 API. Scanning the code confirms this, focusing on features like weak handles, internal fields, and string manipulation.
2. **Break down into functional units:** Analyze the different `TEST` macros to understand the specific API features being tested.
3. **Describe each functional unit:** Explain what each test does, focusing on the V8 API aspects.
4. **Address specific instructions:**
    - Check for `.tq` extension (not present).
    - Look for JavaScript relationships and provide examples.
    - Analyze code logic and provide input/output examples.
    - Identify potential user errors and illustrate them.
    - Summarize the overall functionality as requested in part 10/36.

**Detailed Breakdown and Considerations:**

- **`TEST(IndependentWeakHandle)`:** Tests the behavior of independent weak handles and garbage collection. It involves setting weak callbacks and verifying their execution after GC.
- **`TEST(InternalFieldCallback)`:** Tests the usage of internal fields in V8 objects and weak callbacks associated with them.
- **`TEST(ResetWeakHandle)`:**  Tests resetting weak handles during weak callback execution.
- **`TEST(GCFromWeakCallbacks)`:** Examines the ability to trigger garbage collection from within weak callbacks.
- **`THREADED_TEST(Arguments)`:** Tests how arguments are passed to C++ functions called from JavaScript.
- **`THREADED_TEST(GetterHolders)` and `THREADED_TEST(PreInterceptorHolders)`:** These tests relate to property getters and interceptors, demonstrating how V8 resolves property access and the role of `this` and `Holder`.
- **`THREADED_TEST(ObjectInstantiation)`:** Checks the creation of new object instances from templates and their prototype relationships.
- **`THREADED_TEST(StringWrite)`:** Focuses on various ways to write string data (UTF-8, one-byte, two-byte) from V8 strings to C++ buffers, including handling of surrogates and null termination.
- **`THREADED_TEST(OverlongSequencesAndSurrogates)`:** Tests V8's handling of invalid UTF-8 sequences (overlong, surrogate-related) when converting to UTF-16.
- **`THREADED_TEST(Utf16)`:**  Likely tests UTF-16 string manipulation, although the provided snippet is incomplete.

**JavaScript Relationships:** Many of these tests directly relate to JavaScript concepts:
    - Weak references are analogous to `WeakRef` in JavaScript.
    - Internal fields can be thought of as private data associated with JavaScript objects.
    - Property getters are directly used in JavaScript via `get` syntax or `defineProperty`.
    - Object instantiation using templates is similar to class construction in JavaScript.
    - String manipulation is a fundamental aspect of JavaScript.

**Code Logic and Input/Output:** For tests involving weak handles and GC, the input is the creation of objects and setting up weak callbacks. The output is the execution of the callbacks and the state of flags. String tests have inputs as V8 strings and outputs as the content written to C++ buffers.

**User Errors:**  Common errors might involve:
    - Incorrectly managing weak handles, leading to dangling pointers.
    - Mishandling internal fields, causing type errors or memory issues.
    - Errors in UTF-8 encoding/decoding when interacting with V8 strings.

**Final Summary:** The file tests various aspects of the V8 C++ API related to object lifecycle management (weak handles, garbage collection), internal object data, interaction between C++ and JavaScript functions (arguments), property access control (getters, interceptors), object creation from templates, and string manipulation (encoding, writing to buffers).
```cpp
;
  context->GetIsolate()->RemoveMessageListeners(
      MissingScriptInfoMessageListener);
}

struct FlagAndPersistent {
  bool flag;
  v8::Global<v8::Object> handle;
};

static void SetFlag(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->flag = true;
  data.GetParameter()->handle.Reset();
}

static void IndependentWeakHandle(bool global_gc, bool interlinked) {
  i::ManualGCScope manual_gc_scope;
  // Parallel scavenge introduces too much fragmentation.
  i::v8_flags.parallel_scavenge = false;

  v8::Isolate* iso = CcTest::isolate();
  v8::HandleScope scope(iso);

  FlagAndPersistent object_a, object_b;

  size_t big_heap_size = 0;
  size_t big_array_size = 0;

  {
    v8::Local<Context> context = Context::New(iso);
    Context::Scope context_scope(context);
    v8::HandleScope handle_scope(iso);
    Local<Object> a(v8::Object::New(iso));
    Local<Object> b(v8::Object::New(iso));
    object_a.handle.Reset(iso, a);
    object_b.handle.Reset(iso, b);
    if (interlinked) {
      a->Set(context, v8_str("x"), b).FromJust();
      b->Set(context, v8_str("x"), a).FromJust();
    }
    if (i::v8_flags.single_generation || global_gc) {
      i::heap::InvokeMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
    v8::Local<Value> big_array = v8::Array::New(CcTest::isolate(), 5000);
    // Verify that we created an array where the space was reserved up front.
    big_array_size =
        i::Cast<i::JSArray>(*v8::Utils::OpenDirectHandle(*big_array))
            ->elements()
            ->Size();
    CHECK_LE(20000, big_array_size);
    a->Set(context, v8_str("y"), big_array).FromJust();
    big_heap_size = CcTest::heap()->SizeOfObjects();
  }

  object_a.flag = false;
  object_b.flag = false;
  object_a.handle.SetWeak(&object_a, &SetFlag,
                          v8::WeakCallbackType::kParameter);
  object_b.handle.SetWeak(&object_b, &SetFlag,
                          v8::WeakCallbackType::kParameter);
  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());

    if (i::v8_flags.single_generation || global_gc) {
      i::heap::InvokeMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }
  // A single GC should be enough to reclaim the memory, since we are using
  // phantom handles.
  CHECK_GT(big_heap_size - big_array_size, CcTest::heap()->SizeOfObjects());
  CHECK(object_a.flag);
  CHECK(object_b.flag);
}

TEST(IndependentWeakHandle) {
  IndependentWeakHandle(false, false);
  IndependentWeakHandle(false, true);
  IndependentWeakHandle(true, false);
  IndependentWeakHandle(true, true);
}

class Trivial {
 public:
  explicit Trivial(int x) : x_(x) {}

  int x() { return x_; }
  void set_x(int x) { x_ = x; }

 private:
  int x_;
};

class Trivial2 {
 public:
  Trivial2(int x, int y) : y_(y), x_(x) {}

  int x() { return x_; }
  void set_x(int x) { x_ = x; }

  int y() { return y_; }
  void set_y(int y) { y_ = y; }

 private:
  int y_;
  int x_;
};

void CheckInternalFields(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  v8::Persistent<v8::Object>* handle = data.GetParameter();
  handle->Reset();
  Trivial* t1 = reinterpret_cast<Trivial*>(data.GetInternalField(0));
  Trivial2* t2 = reinterpret_cast<Trivial2*>(data.GetInternalField(1));
  CHECK_EQ(42, t1->x());
  CHECK_EQ(103, t2->x());
  t1->set_x(1729);
  t2->set_x(33550336);
}

void InternalFieldCallback(bool global_gc) {
  // Manual GC scope as --stress-incremental-marking starts marking early and
  // setting internal pointer fields mark the object for a heap layout change,
  // which prevents it from being reclaimed and the callbacks from being
  // executed.
  i::ManualGCScope manual_gc_scope;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Trivial* t1;
  Trivial2* t2;
  v8::Persistent<v8::Object> handle;
  {
    Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
    Local<v8::ObjectTemplate> instance_templ = templ->InstanceTemplate();
    instance_templ->SetInternalFieldCount(2);

    v8::HandleScope inner_scope(isolate);
    Local<v8::Object> obj = templ->GetFunction(env.local())
                                .ToLocalChecked()
                                ->NewInstance(env.local())
                                .ToLocalChecked();
    handle.Reset(isolate, obj);
    CHECK_EQ(2, obj->InternalFieldCount());
    CHECK(obj->GetInternalField(0).As<v8::Value>()->IsUndefined());
    t1 = new Trivial(42);
    t2 = new Trivial2(103, 9);

    obj->SetAlignedPointerInInternalField(0, t1);
    t1 = reinterpret_cast<Trivial*>(obj->GetAlignedPointerFromInternalField(0));
    CHECK_EQ(42, t1->x());

    obj->SetAlignedPointerInInternalField(1, t2);
    t2 =
        reinterpret_cast<Trivial2*>(obj->GetAlignedPointerFromInternalField(1));
    CHECK_EQ(103, t2->x());

    handle.SetWeak<v8::Persistent<v8::Object>>(
        &handle, CheckInternalFields, v8::WeakCallbackType::kInternalFields);
  }

  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());

    if (i::v8_flags.single_generation || global_gc) {
      i::heap::InvokeMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }

  CHECK_EQ(1729, t1->x());
  CHECK_EQ(33550336, t2->x());

  delete t1;
  delete t2;
}

TEST(InternalFieldCallback) {
  InternalFieldCallback(false);
  InternalFieldCallback(true);
}

static void ResetUseValueAndSetFlag(
    const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  // Blink will reset the handle, and then use the other handle, so they
  // can't use the same backing slot.
  data.GetParameter()->handle.Reset();
  data.GetParameter()->flag = true;
}

void i::heap::HeapTester::ResetWeakHandle(bool global_gc) {
  if (v8_flags.stress_incremental_marking) return;
  using v8::Context;
  using v8::Local;
  using v8::Object;

  v8::Isolate* iso = CcTest::isolate();
  v8::HandleScope scope(iso);

  FlagAndPersistent object_a, object_b;

  {
    v8::Local<Context> context = Context::New(iso);
    Context::Scope context_scope(context);
    v8::HandleScope handle_scope(iso);
    Local<Object> a(v8::Object::New(iso));
    Local<Object> b(v8::Object::New(iso));
    object_a.handle.Reset(iso, a);
    object_b.handle.Reset(iso, b);
    if (global_gc || v8_flags.single_generation) {
      i::heap::InvokeAtomicMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }

  object_a.flag = false;
  object_b.flag = false;
  object_a.handle.SetWeak(&object_a, &ResetUseValueAndSetFlag,
                          v8::WeakCallbackType::kParameter);
  object_b.handle.SetWeak(&object_b, &ResetUseValueAndSetFlag,
                          v8::WeakCallbackType::kParameter);

  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());

    if (global_gc || v8_flags.single_generation || v8_flags.sticky_mark_bits) {
      i::heap::InvokeAtomicMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }
  CHECK(object_a.flag);
  CHECK(object_b.flag);
}

TEST(ResetWeakHandle) {
  i::heap::HeapTester::ResetWeakHandle(false);
  i::heap::HeapTester::ResetWeakHandle(true);
}

static void ForceMinorGC2(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->flag = true;
  i::heap::InvokeMinorGC(CcTest::heap());
}

static void ForceMinorGC1(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->handle.Reset();
  data.SetSecondPassCallback(ForceMinorGC2);
}

static void ForceFullGC2(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->flag = true;
  i::heap::InvokeMajorGC(CcTest::heap());
}

static void ForceFullGC1(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->handle.Reset();
  data.SetSecondPassCallback(ForceFullGC2);
}

TEST(GCFromWeakCallbacks) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Locker locker(CcTest::isolate());
  LocalContext env;

  // In this test, we need to invoke GC without stack, otherwise the weak
  // references may not be cleared because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  if (i::v8_flags.single_generation) {
    FlagAndPersistent object;
    {
      v8::HandleScope handle_scope(isolate);
      object.handle.Reset(isolate, v8::Object::New(isolate));
    }
    object.flag = false;
    object.handle.SetWeak(&object, &ForceFullGC1,
                          v8::WeakCallbackType::kParameter);
    i::heap::InvokeMajorGC(CcTest::heap());
    EmptyMessageQueues(isolate);
    CHECK(object.flag);
    return;
  }

  static const int kNumberOfGCTypes = 2;
  using Callback = v8::WeakCallbackInfo<FlagAndPersistent>::Callback;
  Callback gc_forcing_callback[kNumberOfGCTypes] = {&ForceMinorGC1,
                                                    &ForceFullGC1};

  using GCInvoker = void (*)();

  GCInvoker invoke_gc[kNumberOfGCTypes] = {
      []() { i::heap::InvokeMinorGC(CcTest::heap()); },
      []() { i::heap::InvokeMajorGC(CcTest::heap()); }};

  for (int outer_gc = 0; outer_gc < kNumberOfGCTypes; outer_gc++) {
    for (int inner_gc = 0; inner_gc < kNumberOfGCTypes; inner_gc++) {
      FlagAndPersistent object;
      {
        v8::HandleScope handle_scope(isolate);
        object.handle.Reset(isolate, v8::Object::New(isolate));
      }
      object.flag = false;
      object.handle.SetWeak(&object, gc_forcing_callback[inner_gc],
                            v8::WeakCallbackType::kParameter);
      invoke_gc[outer_gc]();
      EmptyMessageQueues(isolate);
      CHECK(object.flag);
    }
  }
}

static void ArgumentsTestCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  CHECK_EQ(3, args.Length());
  CHECK(v8::Integer::New(isolate, 1)->Equals(context, args[0]).FromJust());
  CHECK(v8::Integer::New(isolate, 2)->Equals(context, args[1]).FromJust());
  CHECK(v8::Integer::New(isolate, 3)->Equals(context, args[2]).FromJust());
  CHECK(v8::Undefined(isolate)->Equals(context, args[3]).FromJust());
  v8::HandleScope scope(args.GetIsolate());
  i::heap::InvokeMajorGC(CcTest::heap());
}

THREADED_TEST(Arguments) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> global = ObjectTemplate::New(isolate);
  global->Set(isolate, "f",
              v8::FunctionTemplate::New(isolate, ArgumentsTestCallback));
  LocalContext context(nullptr, global);
  v8_compile("f(1, 2, 3)")->Run(context.local()).ToLocalChecked();
}

namespace {
int p_getter_count;
int p_getter_count2;

void PGetter(Local<Name> name,
             const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  p_getter_count++;
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Local<v8::Object> global = context->Global();
  CHECK(
      info.HolderV2()
          ->Equals(context, global->Get(context, v8_str("o1")).ToLocalChecked())
          .FromJust());
  if (name->Equals(context, v8_str("p1")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o1")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p2")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o2")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p3")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o3")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p4")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o4")).ToLocalChecked())
              .FromJust());
  }
}

void RunHolderTest(v8::Local<v8::ObjectTemplate> obj) {
  ApiTestFuzzer::Fuzz();
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o1"),
                  obj->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun(
    "o1.__proto__ = { };"
    "var o2 = { __proto__: o1 };"
    "var o3 = { __proto__: o2 };"
    "var o4 = { __proto__: o3 };"
    "for (var i = 0; i < 10; i++) o4.p4;"
    "for (var i = 0; i < 10; i++) o3.p3;"
    "for (var i = 0; i < 10; i++) o2.p2;"
    "for (var i = 0; i < 10; i++) o1.p1;");
}

v8::Intercepted PGetter2(Local<Name> name,
                         const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  p_getter_count2++;
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> global = context->Global();
  CHECK(
      info.HolderV2()
          ->Equals(context, global->Get(context, v8_str("o1")).ToLocalChecked())
          .FromJust());
  if (name->Equals(context, v8_str("p1")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o1")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p2")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o2")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p3")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o3")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p4")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o4")).ToLocalChecked())
              .FromJust());
  }
  // Return something to indicate that the operation was intercepted.
  info.GetReturnValue().Set(True(isolate));
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(GetterHolders) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("p1"), PGetter);
  obj->SetNativeDataProperty(v8_str("p2"), PGetter);
  obj->SetNativeDataProperty(v8_str("p3"), PGetter);
  obj->SetNativeDataProperty(v8_str("p4"), PGetter);
  p_getter_count = 0;
  RunHolderTest(obj);
  CHECK_EQ(40, p_getter_count);
}

THREADED_TEST(PreInterceptorHolders) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(PGetter2));
  p_getter_count2 = 0;
  RunHolderTest(obj);
  CHECK_EQ(40, p_getter_count2);
}

THREADED_TEST(ObjectInstantiation) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("t"), PGetter);
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  for (int i = 0; i < 100; i++) {
    v8::HandleScope inner_scope(CcTest::isolate());
    v8::Local<v8::Object> obj =
        templ->NewInstance(context.local()).ToLocalChecked();
    CHECK(!obj->Equals(context.local(), context->Global()
                                            ->Get(context.local(), v8_str("o"))
                                            .ToLocalChecked())
               .FromJust());
    CHECK(
        context->Global()->Set(context.local(), v8_str("o2"), obj).FromJust());
    v8::Local<Value> value = CompileRun("o.__proto__ === o2.__proto__");
    CHECK(v8::True(isolate)->Equals(context.local(), value).FromJust());
    CHECK(context->Global()->Set(context.local(), v8_str("o"), obj).FromJust());
  }
}

static int StrCmp16(uint16_t* a, uint16_t* b) {
  while (true) {
    if (*a == 0 && *b == 0) return 0;
    if (*a != *b) return 0 + *a - *b;
    a++;
    b++;
  }
}

static int StrNCmp16(uint16_t* a, uint16_t* b, int n) {
  while (true) {
    if (n-- == 0) return 0;
    if (*a == 0 && *b == 0) return 0;
    if (*a != *b) return 0 + *a - *b;
    a++;
    b++;
  }
}

THREADED_TEST(StringWrite) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<String> str = v8_str("abcde");
  // abc<Icelandic eth><Unicode snowman>.
  v8::Local<String> str2 = v8_str("abc\xC3\xB0\xE2\x98\x83");
  v8::Local<String> str3 =
      v8::String::NewFromUtf8Literal(context->GetIsolate(), "abc\0def");
  // "ab" + lead surrogate + "wx" + trail surrogate + "yz"
  uint16_t orphans[8] = {0x61, 0x62, 0xD800, 0x77, 0x78, 0xDC00, 0x79, 0x7A};
  v8::Local<String> orphans_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), orphans,
                                 v8::NewStringType::kNormal, 8)
          .ToLocalChecked();
  // single lead surrogate
  uint16_t lead[1] = {0xD800};
  v8::Local<String> lead_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), lead,
                                 v8::NewStringType::kNormal, 1)
          .ToLocalChecked();
  // single trail surrogate
  uint16_t trail[1] = {0xDC00};
  v8::Local<String> trail_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), trail,
                                 v8::NewStringType::kNormal, 1)
          .ToLocalChecked();
  // surrogate pair
  uint16_t pair[2] = {0xD800, 0xDC00};
  v8::Local<String> pair_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), pair,
                                 v8::NewStringType::kNormal, 2)
          .ToLocalChecked();
  const int kStride = 4;  // Must match stride in for loops in JS below.
  CompileRun(
      "var left = '';"
      "for (var i = 0; i < 0xD800; i += 4) {"
      "  left = left + String.fromCharCode(i);"
      "}");
  CompileRun(
      "var right = '';"
      "for (var i = 0; i < 0xD800; i += 4) {"
      "  right = String.fromCharCode(i) + right;"
      "}");
  v8::Local<v8::Object> global = context->Global();
  Local<String> left_tree = global->Get(context.local(), v8_str("left"))
                                .ToLocalChecked()
                                .As<String>();
  Local<String> right_tree = global->Get(context.local(), v8_str("right"))
                                 .ToLocalChecked()
                                 .As<String>();

  CHECK_EQ(5, str2->Length());
  CHECK_EQ(0xD800 / kStride, left_tree->Length());
  CHECK_EQ(0xD800 / kStride, right_tree->Length());

  char buf[100];
  char utf8buf[0xD800 * 3];
  uint16_t wbuf[100];
  size_t len;

  memset(utf8buf, 0x1, 1000);
  len = v8::String::Empty(isolate)->WriteUtf8V2(
      isolate, utf8buf, sizeof(utf8buf), String::WriteFlags::kNullTerminate);
  CHECK_EQ(1, len);
  CHECK_EQ(0, strcmp(utf8buf, ""));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(9, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83"));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 8);
  CHECK_EQ(8, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83\x01", 9));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 7);
  CHECK_EQ(5, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\x01", 5));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 6);
  CHECK_EQ(5, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\x01", 5));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 5);
  CHECK_EQ(5, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\x01", 5));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 4);
  CHECK_EQ(3, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\x01", 4));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 3);
  CHECK_EQ(3, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\x01", 4));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 2);
  CHECK_EQ(2, len);
  CHECK_EQ(0, strncmp(utf8buf, "ab\x01", 3));

  // always write a null terminator if requested, even if there isn't enough
  // space for all characters of the string
  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 4,
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(4, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc"));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8
### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
;
  context->GetIsolate()->RemoveMessageListeners(
      MissingScriptInfoMessageListener);
}


struct FlagAndPersistent {
  bool flag;
  v8::Global<v8::Object> handle;
};

static void SetFlag(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->flag = true;
  data.GetParameter()->handle.Reset();
}

static void IndependentWeakHandle(bool global_gc, bool interlinked) {
  i::ManualGCScope manual_gc_scope;
  // Parallel scavenge introduces too much fragmentation.
  i::v8_flags.parallel_scavenge = false;

  v8::Isolate* iso = CcTest::isolate();
  v8::HandleScope scope(iso);

  FlagAndPersistent object_a, object_b;

  size_t big_heap_size = 0;
  size_t big_array_size = 0;

  {
    v8::Local<Context> context = Context::New(iso);
    Context::Scope context_scope(context);
    v8::HandleScope handle_scope(iso);
    Local<Object> a(v8::Object::New(iso));
    Local<Object> b(v8::Object::New(iso));
    object_a.handle.Reset(iso, a);
    object_b.handle.Reset(iso, b);
    if (interlinked) {
      a->Set(context, v8_str("x"), b).FromJust();
      b->Set(context, v8_str("x"), a).FromJust();
    }
    if (i::v8_flags.single_generation || global_gc) {
      i::heap::InvokeMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
    v8::Local<Value> big_array = v8::Array::New(CcTest::isolate(), 5000);
    // Verify that we created an array where the space was reserved up front.
    big_array_size =
        i::Cast<i::JSArray>(*v8::Utils::OpenDirectHandle(*big_array))
            ->elements()
            ->Size();
    CHECK_LE(20000, big_array_size);
    a->Set(context, v8_str("y"), big_array).FromJust();
    big_heap_size = CcTest::heap()->SizeOfObjects();
  }

  object_a.flag = false;
  object_b.flag = false;
  object_a.handle.SetWeak(&object_a, &SetFlag,
                          v8::WeakCallbackType::kParameter);
  object_b.handle.SetWeak(&object_b, &SetFlag,
                          v8::WeakCallbackType::kParameter);
  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());

    if (i::v8_flags.single_generation || global_gc) {
      i::heap::InvokeMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }
  // A single GC should be enough to reclaim the memory, since we are using
  // phantom handles.
  CHECK_GT(big_heap_size - big_array_size, CcTest::heap()->SizeOfObjects());
  CHECK(object_a.flag);
  CHECK(object_b.flag);
}

TEST(IndependentWeakHandle) {
  IndependentWeakHandle(false, false);
  IndependentWeakHandle(false, true);
  IndependentWeakHandle(true, false);
  IndependentWeakHandle(true, true);
}

class Trivial {
 public:
  explicit Trivial(int x) : x_(x) {}

  int x() { return x_; }
  void set_x(int x) { x_ = x; }

 private:
  int x_;
};


class Trivial2 {
 public:
  Trivial2(int x, int y) : y_(y), x_(x) {}

  int x() { return x_; }
  void set_x(int x) { x_ = x; }

  int y() { return y_; }
  void set_y(int y) { y_ = y; }

 private:
  int y_;
  int x_;
};

void CheckInternalFields(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  v8::Persistent<v8::Object>* handle = data.GetParameter();
  handle->Reset();
  Trivial* t1 = reinterpret_cast<Trivial*>(data.GetInternalField(0));
  Trivial2* t2 = reinterpret_cast<Trivial2*>(data.GetInternalField(1));
  CHECK_EQ(42, t1->x());
  CHECK_EQ(103, t2->x());
  t1->set_x(1729);
  t2->set_x(33550336);
}

void InternalFieldCallback(bool global_gc) {
  // Manual GC scope as --stress-incremental-marking starts marking early and
  // setting internal pointer fields mark the object for a heap layout change,
  // which prevents it from being reclaimed and the callbacks from being
  // executed.
  i::ManualGCScope manual_gc_scope;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Trivial* t1;
  Trivial2* t2;
  v8::Persistent<v8::Object> handle;
  {
    Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
    Local<v8::ObjectTemplate> instance_templ = templ->InstanceTemplate();
    instance_templ->SetInternalFieldCount(2);

    v8::HandleScope inner_scope(isolate);
    Local<v8::Object> obj = templ->GetFunction(env.local())
                                .ToLocalChecked()
                                ->NewInstance(env.local())
                                .ToLocalChecked();
    handle.Reset(isolate, obj);
    CHECK_EQ(2, obj->InternalFieldCount());
    CHECK(obj->GetInternalField(0).As<v8::Value>()->IsUndefined());
    t1 = new Trivial(42);
    t2 = new Trivial2(103, 9);

    obj->SetAlignedPointerInInternalField(0, t1);
    t1 = reinterpret_cast<Trivial*>(obj->GetAlignedPointerFromInternalField(0));
    CHECK_EQ(42, t1->x());

    obj->SetAlignedPointerInInternalField(1, t2);
    t2 =
        reinterpret_cast<Trivial2*>(obj->GetAlignedPointerFromInternalField(1));
    CHECK_EQ(103, t2->x());

    handle.SetWeak<v8::Persistent<v8::Object>>(
        &handle, CheckInternalFields, v8::WeakCallbackType::kInternalFields);
  }

  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());

    if (i::v8_flags.single_generation || global_gc) {
      i::heap::InvokeMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }

  CHECK_EQ(1729, t1->x());
  CHECK_EQ(33550336, t2->x());

  delete t1;
  delete t2;
}

TEST(InternalFieldCallback) {
  InternalFieldCallback(false);
  InternalFieldCallback(true);
}

static void ResetUseValueAndSetFlag(
    const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  // Blink will reset the handle, and then use the other handle, so they
  // can't use the same backing slot.
  data.GetParameter()->handle.Reset();
  data.GetParameter()->flag = true;
}

void i::heap::HeapTester::ResetWeakHandle(bool global_gc) {
  if (v8_flags.stress_incremental_marking) return;
  using v8::Context;
  using v8::Local;
  using v8::Object;

  v8::Isolate* iso = CcTest::isolate();
  v8::HandleScope scope(iso);

  FlagAndPersistent object_a, object_b;

  {
    v8::Local<Context> context = Context::New(iso);
    Context::Scope context_scope(context);
    v8::HandleScope handle_scope(iso);
    Local<Object> a(v8::Object::New(iso));
    Local<Object> b(v8::Object::New(iso));
    object_a.handle.Reset(iso, a);
    object_b.handle.Reset(iso, b);
    if (global_gc || v8_flags.single_generation) {
      i::heap::InvokeAtomicMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }

  object_a.flag = false;
  object_b.flag = false;
  object_a.handle.SetWeak(&object_a, &ResetUseValueAndSetFlag,
                          v8::WeakCallbackType::kParameter);
  object_b.handle.SetWeak(&object_b, &ResetUseValueAndSetFlag,
                          v8::WeakCallbackType::kParameter);

  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());

    if (global_gc || v8_flags.single_generation || v8_flags.sticky_mark_bits) {
      i::heap::InvokeAtomicMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }
  CHECK(object_a.flag);
  CHECK(object_b.flag);
}

TEST(ResetWeakHandle) {
  i::heap::HeapTester::ResetWeakHandle(false);
  i::heap::HeapTester::ResetWeakHandle(true);
}

static void ForceMinorGC2(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->flag = true;
  i::heap::InvokeMinorGC(CcTest::heap());
}

static void ForceMinorGC1(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->handle.Reset();
  data.SetSecondPassCallback(ForceMinorGC2);
}

static void ForceFullGC2(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->flag = true;
  i::heap::InvokeMajorGC(CcTest::heap());
}

static void ForceFullGC1(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->handle.Reset();
  data.SetSecondPassCallback(ForceFullGC2);
}

TEST(GCFromWeakCallbacks) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Locker locker(CcTest::isolate());
  LocalContext env;

  // In this test, we need to invoke GC without stack, otherwise the weak
  // references may not be cleared because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  if (i::v8_flags.single_generation) {
    FlagAndPersistent object;
    {
      v8::HandleScope handle_scope(isolate);
      object.handle.Reset(isolate, v8::Object::New(isolate));
    }
    object.flag = false;
    object.handle.SetWeak(&object, &ForceFullGC1,
                          v8::WeakCallbackType::kParameter);
    i::heap::InvokeMajorGC(CcTest::heap());
    EmptyMessageQueues(isolate);
    CHECK(object.flag);
    return;
  }

  static const int kNumberOfGCTypes = 2;
  using Callback = v8::WeakCallbackInfo<FlagAndPersistent>::Callback;
  Callback gc_forcing_callback[kNumberOfGCTypes] = {&ForceMinorGC1,
                                                    &ForceFullGC1};

  using GCInvoker = void (*)();

  GCInvoker invoke_gc[kNumberOfGCTypes] = {
      []() { i::heap::InvokeMinorGC(CcTest::heap()); },
      []() { i::heap::InvokeMajorGC(CcTest::heap()); }};

  for (int outer_gc = 0; outer_gc < kNumberOfGCTypes; outer_gc++) {
    for (int inner_gc = 0; inner_gc < kNumberOfGCTypes; inner_gc++) {
      FlagAndPersistent object;
      {
        v8::HandleScope handle_scope(isolate);
        object.handle.Reset(isolate, v8::Object::New(isolate));
      }
      object.flag = false;
      object.handle.SetWeak(&object, gc_forcing_callback[inner_gc],
                            v8::WeakCallbackType::kParameter);
      invoke_gc[outer_gc]();
      EmptyMessageQueues(isolate);
      CHECK(object.flag);
    }
  }
}

static void ArgumentsTestCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  CHECK_EQ(3, args.Length());
  CHECK(v8::Integer::New(isolate, 1)->Equals(context, args[0]).FromJust());
  CHECK(v8::Integer::New(isolate, 2)->Equals(context, args[1]).FromJust());
  CHECK(v8::Integer::New(isolate, 3)->Equals(context, args[2]).FromJust());
  CHECK(v8::Undefined(isolate)->Equals(context, args[3]).FromJust());
  v8::HandleScope scope(args.GetIsolate());
  i::heap::InvokeMajorGC(CcTest::heap());
}


THREADED_TEST(Arguments) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> global = ObjectTemplate::New(isolate);
  global->Set(isolate, "f",
              v8::FunctionTemplate::New(isolate, ArgumentsTestCallback));
  LocalContext context(nullptr, global);
  v8_compile("f(1, 2, 3)")->Run(context.local()).ToLocalChecked();
}

namespace {
int p_getter_count;
int p_getter_count2;

void PGetter(Local<Name> name,
             const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  p_getter_count++;
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Local<v8::Object> global = context->Global();
  CHECK(
      info.HolderV2()
          ->Equals(context, global->Get(context, v8_str("o1")).ToLocalChecked())
          .FromJust());
  if (name->Equals(context, v8_str("p1")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o1")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p2")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o2")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p3")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o3")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p4")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o4")).ToLocalChecked())
              .FromJust());
  }
}

void RunHolderTest(v8::Local<v8::ObjectTemplate> obj) {
  ApiTestFuzzer::Fuzz();
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o1"),
                  obj->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun(
    "o1.__proto__ = { };"
    "var o2 = { __proto__: o1 };"
    "var o3 = { __proto__: o2 };"
    "var o4 = { __proto__: o3 };"
    "for (var i = 0; i < 10; i++) o4.p4;"
    "for (var i = 0; i < 10; i++) o3.p3;"
    "for (var i = 0; i < 10; i++) o2.p2;"
    "for (var i = 0; i < 10; i++) o1.p1;");
}

v8::Intercepted PGetter2(Local<Name> name,
                         const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  p_getter_count2++;
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> global = context->Global();
  CHECK(
      info.HolderV2()
          ->Equals(context, global->Get(context, v8_str("o1")).ToLocalChecked())
          .FromJust());
  if (name->Equals(context, v8_str("p1")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o1")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p2")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o2")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p3")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o3")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p4")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o4")).ToLocalChecked())
              .FromJust());
  }
  // Return something to indicate that the operation was intercepted.
  info.GetReturnValue().Set(True(isolate));
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(GetterHolders) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("p1"), PGetter);
  obj->SetNativeDataProperty(v8_str("p2"), PGetter);
  obj->SetNativeDataProperty(v8_str("p3"), PGetter);
  obj->SetNativeDataProperty(v8_str("p4"), PGetter);
  p_getter_count = 0;
  RunHolderTest(obj);
  CHECK_EQ(40, p_getter_count);
}


THREADED_TEST(PreInterceptorHolders) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(PGetter2));
  p_getter_count2 = 0;
  RunHolderTest(obj);
  CHECK_EQ(40, p_getter_count2);
}


THREADED_TEST(ObjectInstantiation) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("t"), PGetter);
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  for (int i = 0; i < 100; i++) {
    v8::HandleScope inner_scope(CcTest::isolate());
    v8::Local<v8::Object> obj =
        templ->NewInstance(context.local()).ToLocalChecked();
    CHECK(!obj->Equals(context.local(), context->Global()
                                            ->Get(context.local(), v8_str("o"))
                                            .ToLocalChecked())
               .FromJust());
    CHECK(
        context->Global()->Set(context.local(), v8_str("o2"), obj).FromJust());
    v8::Local<Value> value = CompileRun("o.__proto__ === o2.__proto__");
    CHECK(v8::True(isolate)->Equals(context.local(), value).FromJust());
    CHECK(context->Global()->Set(context.local(), v8_str("o"), obj).FromJust());
  }
}


static int StrCmp16(uint16_t* a, uint16_t* b) {
  while (true) {
    if (*a == 0 && *b == 0) return 0;
    if (*a != *b) return 0 + *a - *b;
    a++;
    b++;
  }
}


static int StrNCmp16(uint16_t* a, uint16_t* b, int n) {
  while (true) {
    if (n-- == 0) return 0;
    if (*a == 0 && *b == 0) return 0;
    if (*a != *b) return 0 + *a - *b;
    a++;
    b++;
  }
}

THREADED_TEST(StringWrite) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<String> str = v8_str("abcde");
  // abc<Icelandic eth><Unicode snowman>.
  v8::Local<String> str2 = v8_str("abc\xC3\xB0\xE2\x98\x83");
  v8::Local<String> str3 =
      v8::String::NewFromUtf8Literal(context->GetIsolate(), "abc\0def");
  // "ab" + lead surrogate + "wx" + trail surrogate + "yz"
  uint16_t orphans[8] = {0x61, 0x62, 0xD800, 0x77, 0x78, 0xDC00, 0x79, 0x7A};
  v8::Local<String> orphans_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), orphans,
                                 v8::NewStringType::kNormal, 8)
          .ToLocalChecked();
  // single lead surrogate
  uint16_t lead[1] = {0xD800};
  v8::Local<String> lead_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), lead,
                                 v8::NewStringType::kNormal, 1)
          .ToLocalChecked();
  // single trail surrogate
  uint16_t trail[1] = {0xDC00};
  v8::Local<String> trail_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), trail,
                                 v8::NewStringType::kNormal, 1)
          .ToLocalChecked();
  // surrogate pair
  uint16_t pair[2] = {0xD800, 0xDC00};
  v8::Local<String> pair_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), pair,
                                 v8::NewStringType::kNormal, 2)
          .ToLocalChecked();
  const int kStride = 4;  // Must match stride in for loops in JS below.
  CompileRun(
      "var left = '';"
      "for (var i = 0; i < 0xD800; i += 4) {"
      "  left = left + String.fromCharCode(i);"
      "}");
  CompileRun(
      "var right = '';"
      "for (var i = 0; i < 0xD800; i += 4) {"
      "  right = String.fromCharCode(i) + right;"
      "}");
  v8::Local<v8::Object> global = context->Global();
  Local<String> left_tree = global->Get(context.local(), v8_str("left"))
                                .ToLocalChecked()
                                .As<String>();
  Local<String> right_tree = global->Get(context.local(), v8_str("right"))
                                 .ToLocalChecked()
                                 .As<String>();

  CHECK_EQ(5, str2->Length());
  CHECK_EQ(0xD800 / kStride, left_tree->Length());
  CHECK_EQ(0xD800 / kStride, right_tree->Length());

  char buf[100];
  char utf8buf[0xD800 * 3];
  uint16_t wbuf[100];
  size_t len;

  memset(utf8buf, 0x1, 1000);
  len = v8::String::Empty(isolate)->WriteUtf8V2(
      isolate, utf8buf, sizeof(utf8buf), String::WriteFlags::kNullTerminate);
  CHECK_EQ(1, len);
  CHECK_EQ(0, strcmp(utf8buf, ""));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(9, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83"));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 8);
  CHECK_EQ(8, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83\x01", 9));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 7);
  CHECK_EQ(5, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\x01", 5));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 6);
  CHECK_EQ(5, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\x01", 5));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 5);
  CHECK_EQ(5, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\x01", 5));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 4);
  CHECK_EQ(3, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\x01", 4));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 3);
  CHECK_EQ(3, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\x01", 4));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 2);
  CHECK_EQ(2, len);
  CHECK_EQ(0, strncmp(utf8buf, "ab\x01", 3));

  // always write a null terminator if requested, even if there isn't enough
  // space for all characters of the string
  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 4,
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(4, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc"));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 5,
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(4, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc"));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 6,
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(6, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc\xC3\xB0"));

  // allow orphan surrogates by default
  memset(utf8buf, 0x1, 1000);
  len = orphans_str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                                 String::WriteFlags::kNullTerminate);
  CHECK_EQ(13, len);
  CHECK_EQ(0, strcmp(utf8buf, "ab\xED\xA0\x80wx\xED\xB0\x80yz"));

  // replace orphan surrogates with Unicode replacement character
  memset(utf8buf, 0x1, 1000);
  len = orphans_str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                                 String::WriteFlags::kNullTerminate |
                                     String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(13, len);
  CHECK_EQ(0, strcmp(utf8buf, "ab\xEF\xBF\xBDwx\xEF\xBF\xBDyz"));

  // replace single lead surrogate with Unicode replacement character
  memset(utf8buf, 0x1, 1000);
  len = lead_str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                              String::WriteFlags::kNullTerminate |
                                  String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(4, len);
  CHECK_EQ(0, strcmp(utf8buf, "\xEF\xBF\xBD"));

  // replace single trail surrogate with Unicode replacement character
  memset(utf8buf, 0x1, 1000);
  len = trail_str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                               String::WriteFlags::kNullTerminate |
                                   String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(4, len);
  CHECK_EQ(0, strcmp(utf8buf, "\xEF\xBF\xBD"));

  // do not replace / write anything if surrogate pair does not fit the buffer
  // space
  memset(utf8buf, 0x1, 1000);
  len = pair_str->WriteUtf8V2(isolate, utf8buf, 3,
                              String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(0, len);

  memset(utf8buf, 0x1, sizeof(utf8buf));
  len = left_tree->Utf8LengthV2(isolate);
  int utf8_expected =
      (0x80 + (0x800 - 0x80) * 2 + (0xD800 - 0x800) * 3) / kStride;
  CHECK_EQ(utf8_expected, len);
  len = left_tree->WriteUtf8V2(isolate, utf8buf, utf8_expected);
  CHECK_EQ(utf8_expected, len);
  CHECK_EQ(0xED, static_cast<unsigned char>(utf8buf[utf8_expected - 3]));
  CHECK_EQ(0x9F, static_cast<unsigned char>(utf8buf[utf8_expected - 2]));
  CHECK_EQ(0xC0 - kStride,
           static_cast<unsigned char>(utf8buf[utf8_expected - 1]));
  CHECK_EQ(1, utf8buf[utf8_expected]);

  memset(utf8buf, 0x1, sizeof(utf8buf));
  len = right_tree->Utf8LengthV2(isolate);
  CHECK_EQ(utf8_expected, len);
  len = right_tree->WriteUtf8V2(isolate, utf8buf, utf8_expected);
  CHECK_EQ(utf8_expected, len);
  CHECK_EQ(0xED, static_cast<unsigned char>(utf8buf[0]));
  CHECK_EQ(0x9F, static_cast<unsigned char>(utf8buf[1]));
  CHECK_EQ(0xC0 - kStride, static_cast<unsigned char>(utf8buf[2]));
  CHECK_EQ(1, utf8buf[utf8_expected]);

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 0, str->Length(),
                      reinterpret_cast<uint8_t*>(buf),
                      String::WriteFlags::kNullTerminate);
  str->WriteV2(isolate, 0, str->Length(), wbuf,
               String::WriteFlags::kNullTerminate);
  CHECK_EQ(0, strcmp("abcde", buf));
  uint16_t answer1[] = {'a', 'b', 'c', 'd', 'e', '\0'};
  CHECK_EQ(0, StrCmp16(answer1, wbuf));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 0, 4, reinterpret_cast<uint8_t*>(buf));
  str->WriteV2(isolate, 0, 4, wbuf);
  CHECK_EQ(0, strncmp("abcd\x01", buf, 5));
  uint16_t answer2[] = {'a', 'b', 'c', 'd', 0x101};
  CHECK_EQ(0, StrNCmp16(answer2, wbuf, 5));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 0, 5, reinterpret_cast<uint8_t*>(buf));
  str->WriteV2(isolate, 0, 5, wbuf);
  CHECK_EQ(0, strncmp("abcde\x01", buf, 6));
  uint16_t answer3[] = {'a', 'b', 'c', 'd', 'e', 0x101};
  CHECK_EQ(0, StrNCmp16(answer3, wbuf, 6));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 0, 5, reinterpret_cast<uint8_t*>(buf),
                      String::WriteFlags::kNullTerminate);
  str->WriteV2(isolate, 0, 5, wbuf, String::WriteFlags::kNullTerminate);
  CHECK_EQ(0, strcmp("abcde", buf));
  uint16_t answer4[] = {'a', 'b', 'c', 'd', 'e', '\0'};
  CHECK_EQ(0, StrCmp16(answer4, wbuf));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 4, 1, reinterpret_cast<uint8_t*>(buf),
                      String::WriteFlags::kNullTerminate);
  str->WriteV2(isolate, 4, 1, wbuf, String::WriteFlags::kNullTerminate);
  CHECK_EQ(0, strcmp("e", buf));
  uint16_t answer5[] = {'e', '\0'};
  CHECK_EQ(0, StrCmp16(answer5, wbuf));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 4, 1, reinterpret_cast<uint8_t*>(buf));
  str->WriteV2(isolate, 4, 1, wbuf);
  CHECK_EQ(0, strncmp("e\x01", buf, 2));
  uint16_t answer6[] = {'e', 0x101};
  CHECK_EQ(0, StrNCmp16(answer6, wbuf, 2));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 3, 1, reinterpret_cast<uint8_t*>(buf));
  str->WriteV2(isolate, 3, 1, wbuf);
  CHECK_EQ(0, strncmp("d\x01", buf, 2));
  uint16_t answer7[] = {'d', 0x101};
  CHECK_EQ(0, StrNCmp16(answer7, wbuf, 2));

  memset(wbuf, 0x1, sizeof(wbuf));
  wbuf[5] = 'X';
  str->WriteV2(isolate, 0, 5, wbuf);
  CHECK_EQ('X', wbuf[5]);
  uint16_t answer8a[] = {'a', 'b', 'c', 'd', 'e'};
  uint16_t answer8b[] = {'a', 'b', 'c', 'd', 'e', '\0'};
  CHECK_EQ(0, StrNCmp16(answer8a, wbuf, 5));
  CHECK_NE(0, StrCmp16(answer8b, wbuf));
  wbuf[5] = '\0';
  CHECK_EQ(0, StrCmp16(answer8b, wbuf));

  memset(buf, 0x1, sizeof(buf));
  buf[5] = 'X';
  str->WriteOneByteV2(isolate, 0, 5, reinterpret_cast<uint8_t*>(buf));
  CHECK_EQ('X', buf[5]);
  CHECK_EQ(0, strncmp("abcde", buf, 5));
  CHECK_NE(0, strcmp("abcde", buf));
  buf[5] = '\0';
  CHECK_EQ(0, strcmp("abcde", buf));

  memset(utf8buf, 0x1, sizeof(utf8buf));
  utf8buf[8] = 'X';
  str2->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf));
  CHECK_EQ('X', utf8buf[8]);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83", 8));
  CHECK_NE(0, strcmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83"));
  utf8buf[8] = '\0';
  CHECK_EQ(0, strcmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83"));

  memset(utf8buf, 0x1, sizeof(utf8buf));
  utf8buf[5] = 'X';
  len = str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf));
  CHECK_EQ(5, len);
  CHECK_EQ('X', utf8buf[5]);  // Test that the sixth character is untouched.
  utf8buf[5] = '\0';
  CHECK_EQ(0, strcmp(utf8buf, "abcde"));

  memset(buf, 0x1, sizeof(buf));
  str3->WriteOneByteV2(isolate, 0, str3->Length(),
                       reinterpret_cast<uint8_t*>(buf),
                       String::WriteFlags::kNullTerminate);
  CHECK_EQ(0, strcmp("abc", buf));
  CHECK_EQ(0, buf[3]);
  CHECK_EQ(0, strcmp("def", buf + 4));

  str->WriteOneByteV2(isolate, 0, 0, nullptr);
  str->WriteV2(isolate, 0, 0, nullptr);
  len = str->WriteUtf8V2(isolate, nullptr, 0);
  CHECK_EQ(0, len);
}

static void Utf16Helper(LocalContext& context, const char* name,
                        const char* lengths_name, int len) {
  Local<v8::Array> a = Local<v8::Array>::Cast(
      context->Global()->Get(context.local(), v8_str(name)).ToLocalChecked());
  Local<v8::Array> alens =
      Local<v8::Array>::Cast(context->Global()
                                 ->Get(context.local(), v8_str(lengths_name))
                                 .ToLocalChecked());
  for (int i = 0; i < len; i++) {
    Local<v8::String> string =
        Local<v8::String>::Cast(a->Get(context.local(), i).ToLocalChecked());
    Local<v8::Number> expected_len = Local<v8::Number>::Cast(
        alens->Get(context.local(), i).ToLocalChecked());
    size_t length = string->Utf8LengthV2(context->GetIsolate());
    CHECK_EQ(expected_len->Value(), length);
  }
}

void TestUtf8DecodingAgainstReference(
    v8::Isolate* isolate, const char* cases[],
    const std::vector<std::vector<uint16_t>>& unicode_expected) {
  for (size_t test_ix = 0; test_ix < unicode_expected.size(); ++test_ix) {
    v8::Local<String> str = v8_str(cases[test_ix]);
    CHECK_EQ(unicode_expected[test_ix].size(), str->Length());

    uint32_t length = str->Length();
    std::unique_ptr<uint16_t[]> buffer(new uint16_t[length]);
    str->WriteV2(isolate, 0, length, buffer.get());

    for (size_t i = 0; i < unicode_expected[test_ix].size(); ++i) {
      CHECK_EQ(unicode_expected[test_ix][i], buffer[i]);
    }
  }
}

THREADED_TEST(OverlongSequencesAndSurrogates) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  const char* cases[] = {
      // Overlong 2-byte sequence.
      "X\xc0\xbfY\0",
      // Another overlong 2-byte sequence.
      "X\xc1\xbfY\0",
      // Overlong 3-byte sequence.
      "X\xe0\x9f\xbfY\0",
      // Overlong 4-byte sequence.
      "X\xf0\x89\xbf\xbfY\0",
      // Invalid 3-byte sequence (reserved for surrogates).
      "X\xed\xa0\x80Y\0",
      // Invalid 4-bytes sequence (value out of range).
      "X\xf4\x90\x80\x80Y\0",

      // Start of an overlong 3-byte sequence but not enough continuation bytes.
      "X\xe0\x9fY\0",
      // Start of an overlong 4-byte sequence but not enough continuation bytes.
      "X\xf0\x89\xbfY\0",
      // Start of an invalid 3-byte sequence (reserved for surrogates) but not
      // enough continuation bytes.
      "X\xed\xa0Y\0",
      // Start of an invalid 4-bytes sequence (value out of range) but not
      // enough continuation bytes.
      "X\xf4\x90\x80Y\0",
  };
  const std::vector<std::vector<uint16_t>> unicode_expected = {
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
  };
  CHECK_EQ(unicode_expected.size(), arraysize(cases));
  TestUtf8DecodingAgainstReference(context->GetIsolate(), cases,
                                   unicode_expected);
}

THREADED_TEST(Utf16) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  CompileRun(
      "var pad = '01234567890123456789';"
      "var p = [];"
      "var plens = [20, 3, 3];"
      "p.push('01234567890123456789');"
      "var lead = 0xD800;"
      "var trail = 0xDC00;"
      "p.push(String.fromCharCode(0xD800));"
      "p.push(String.fromCharCode(0xDC00));"
      "var a = [];"
      "var b = [];"
      "var c = [];"
      "var alens = [];"
      "for (var i = 0; i < 3; i++) {"
      "  p[1] = String.fromCharCode(lead++);"
      "  for (var j = 0; j < 3; j++) {"
      "    p[2] = String.fromCharCode(trail++);"
      "    a.push(p[i] + p[j]);"
      "    b.push(p[i] + p[j]);"
      "    c.push(p[i] + p[j]);"
      "    alens.push(plens[i] + plens[j]);"
      "  }"
      "}"
      "alens
```