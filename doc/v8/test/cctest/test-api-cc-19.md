Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `test-api.cc` file. They also have several specific questions:

1. **List the functionalities:** I need to analyze the code and identify the core features being tested.
2. **.tq extension:**  Check if the file name ends with `.tq`. If so, it's Torque code.
3. **Relationship to JavaScript:** Identify if the tests relate to JavaScript features and provide JavaScript examples if they do.
4. **Code logic reasoning:**  Find sections with clear input/output relationships and provide examples.
5. **Common programming errors:**  Look for tests that highlight potential mistakes developers might make when using the V8 API.
6. **归纳功能 (Summarize functionality):** Provide a concise summary of the code's purpose.
7. **Part number:** Acknowledge that this is part 20 of 36.

**Plan:**

1. **Analyze each `TEST` macro:** Treat each `TEST` block as a unit of functionality being tested.
2. **Identify the V8 API elements being used:** Look for calls to `v8::...`.
3. **Infer the purpose of each test:**  Based on the API calls and the assertions (`CHECK_EQ`, `CHECK`, etc.).
4. **Connect tests to JavaScript concepts:** If a test manipulates Promises, handles exceptions, uses `eval`, or deals with function properties, it likely has a JavaScript counterpart.
5. **Construct JavaScript examples:**  Demonstrate the JavaScript behavior that the C++ test verifies.
6. **Identify input/output:** For tests that set up conditions and then check results (e.g., promise states, error messages), define the setup as input and the assertions as output.
7. **Spot error-related tests:** Tests involving `TryCatch` or those that manipulate function properties (like `name`) might relate to common errors.
8. **Synthesize the overall purpose:** Combine the individual test functionalities into a concise summary.
```cpp
 Promise {\n"
      "  static get [Symbol.species]() {\n"
      "    return Y;\n"
      "  }\n"
      "}\n"
      "class Y {\n"
      "  constructor(executor) {\n"
      "    return new Proxy(new Promise(executor), {});\n"
      "  }\n"
      "}\n"
      "var x = X.resolve().then(() => {});\n";

  CompileRun(source);

  promise_hook_data->Reset();
  source =
      "var resolve, value = '';\n"
      "var p = new Promise(r => resolve = r);\n";

  CompileRun(source);
  CHECK_EQ(v8::Promise::kPending, GetPromise("p")->State());
  CompileRun("resolve(Promise.resolve(value));\n");
  CHECK_EQ(v8::Promise::kFulfilled, GetPromise("p")->State());
  CHECK_EQ(11, promise_hook_data->promise_hook_count);

  promise_hook_data->Reset();
  source =
      "var p = Promise.resolve({\n"
      "  then(r) {\n"
      "    r();\n"
      "  }\n"
      "});";
  CompileRun(source);
  CHECK_EQ(GetPromise("p")->State(), v8::Promise::kFulfilled);
  CHECK_EQ(promise_hook_data->promise_hook_count, 5);

  delete promise_hook_data;
  isolate->SetPromiseHook(nullptr);
}

TEST(EvalWithSourceURLInMessageScriptResourceNameOrSourceURL) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  const char *source =
    "function outer() {\n"
    "  var scriptContents = \"function foo() { FAIL.FAIL; }\\\n"
    "  //# sourceURL=source_url\";\n"
    "  eval(scriptContents);\n"
    "  foo(); }\n"
    "outer();\n"
    "//# sourceURL=outer_url";

  v8::TryCatch try_catch(context->GetIsolate());
  CompileRun(source);
  CHECK(try_catch.HasCaught());

  Local<v8::Message> message = try_catch.Message();
  Local<Value> sourceURL = message->GetScriptOrigin().ResourceName();
  CHECK_EQ(0, strcmp(*v8::String::Utf8Value(context->GetIsolate(), sourceURL),
                     "source_url"));
}

TEST(RecursionWithSourceURLInMessageScriptResourceNameOrSourceURL) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  const char *source =
    "function outer() {\n"
    "  var scriptContents = \"function boo(){ boo(); }\\\n"
    "  //# sourceURL=source_url\";\n"
    "  eval(scriptContents);\n"
    "  boo(); }\n"
    "outer();\n"
    "//# sourceURL=outer_url";

  v8::TryCatch try_catch(context->GetIsolate());
  CompileRun(source);
  CHECK(try_catch.HasCaught());

  Local<v8::Message> message = try_catch.Message();
  Local<Value> sourceURL = message->GetScriptOrigin().ResourceName();
  CHECK_EQ(0, strcmp(*v8::String::Utf8Value(context->GetIsolate(), sourceURL),
                     "source_url"));
}

TEST(Regress2333) {
  LocalContext env;
  for (int i = 0; i < 3; i++) {
    i::heap::InvokeMinorGC(CcTest::heap());
  }
}

static uint32_t* stack_limit;

static void GetStackLimitCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  stack_limit = reinterpret_cast<uint32_t*>(
      CcTest::i_isolate()->stack_guard()->real_climit());
}

// Uses the address of a local variable to determine the stack top now.
// Given a size, returns an address that is that far from the current
// top of stack.
static uint32_t* ComputeStackLimit(uint32_t size) {
  // Disable the gcc error which (very correctly) notes that this is an
  // out-of-bounds access.
#if V8_CC_GNU
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif  // V8_CC_GNU
  uint32_t* answer = &size - (size / sizeof(size));
#if V8_CC_GNU
#pragma GCC diagnostic pop
#endif  // V8_CC_GNU
  // If the size is very large and the stack is very near the bottom of
  // memory then the calculation above may wrap around and give an address
  // that is above the (downwards-growing) stack. In that case we return
  // a very low address.
  if (answer > &size) return reinterpret_cast<uint32_t*>(sizeof(size));
  return answer;
}

// We need at least 165kB for an x64 debug build with clang and ASAN.
static const int stack_breathing_room = 256 * i::KB;

TEST(SetStackLimit) {
  uint32_t* set_limit = ComputeStackLimit(stack_breathing_room);

  // Set stack limit.
  CcTest::isolate()->SetStackLimit(reinterpret_cast<uintptr_t>(set_limit));

  // Execute a script.
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(env->GetIsolate(), GetStackLimitCallback);
  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()
            ->Set(env.local(), v8_str("get_stack_limit"), fun)
            .FromJust());
  CompileRun("get_stack_limit();");

  CHECK(stack_limit == set_limit);
}

TEST(SetStackLimitInThread) {
  uint32_t* set_limit;
  {
    v8::Locker locker(CcTest::isolate());
    set_limit = ComputeStackLimit(stack_breathing_room);

    // Set stack limit.
    CcTest::isolate()->SetStackLimit(reinterpret_cast<uintptr_t>(set_limit));

    // Execute a script.
    v8::HandleScope scope(CcTest::isolate());
    LocalContext env;
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(CcTest::isolate(), GetStackLimitCallback);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("get_stack_limit"), fun)
              .FromJust());
    CompileRun("get_stack_limit();");

    CHECK(stack_limit == set_limit);
  }
  {
    v8::Locker locker(CcTest::isolate());
    CHECK(stack_limit == set_limit);
  }
}

THREADED_TEST(GetHeapStatistics) {
  LocalContext c1;
  v8::HandleScope scope(c1->GetIsolate());
  v8::HeapStatistics heap_statistics;
  CHECK_EQ(0u, heap_statistics.total_heap_size());
  CHECK_EQ(0u, heap_statistics.used_heap_size());
  c1->GetIsolate()->GetHeapStatistics(&heap_statistics);
  CHECK_NE(static_cast<int>(heap_statistics.total_heap_size()), 0);
}

TEST(GetHeapSpaceStatistics) {
  // This test is incompatible with concurrent allocation, which may occur
  // while collecting the statistics and break the final `CHECK_EQ`s.
  if (i::v8_flags.stress_concurrent_allocation) return;

  LocalContext c1;
  v8::Isolate* isolate = c1->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::HeapStatistics heap_statistics;

  // Force allocation in LO_SPACE and TRUSTED_LO_SPACE so that every space has
  // non-zero size.
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  auto unused = i_isolate->factory()->TryNewFixedArray(512 * 1024,
                                                       i::AllocationType::kOld);
  USE(unused);

  isolate->GetHeapStatistics(&heap_statistics);

  // Ensure that the sum of all the spaces matches the totals from
  // GetHeapSpaceStatistics.
  size_t total_size = 0u;
  size_t total_used_size = 0u;
  size_t total_available_size = 0u;
  size_t total_physical_size = 0u;
  for (size_t i = 0; i < isolate->NumberOfHeapSpaces(); ++i) {
    v8::HeapSpaceStatistics space_statistics;
    isolate->GetHeapSpaceStatistics(&space_statistics, i);
    CHECK_NOT_NULL(space_statistics.space_name());
    total_size += space_statistics.space_size();
    total_used_size += space_statistics.space_used_size();
    total_available_size += space_statistics.space_available_size();
    total_physical_size += space_statistics.physical_space_size();
  }
  total_available_size += CcTest::heap()->memory_allocator()->Available();

  CHECK_EQ(total_size, heap_statistics.total_heap_size());
  CHECK_EQ(total_used_size, heap_statistics.used_heap_size());
  CHECK_EQ(total_available_size, heap_statistics.total_available_size());
  CHECK_EQ(total_physical_size, heap_statistics.total_physical_size());
}

TEST(NumberOfNativeContexts) {
  static const size_t kNumTestContexts = 10;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);
  v8::Global<v8::Context> context[kNumTestContexts];
  v8::HeapStatistics heap_statistics;

  // In this test, we need to invoke GC without stack, otherwise some objects
  // may not be reclaimed because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  CHECK_EQ(0u, heap_statistics.number_of_native_contexts());
  CcTest::isolate()->GetHeapStatistics(&heap_statistics);
  CHECK_EQ(0u, heap_statistics.number_of_native_contexts());
  for (size_t i = 0; i < kNumTestContexts; i++) {
    i::HandleScope inner(isolate);
    context[i].Reset(CcTest::isolate(), v8::Context::New(CcTest::isolate()));
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(i + 1, heap_statistics.number_of_native_contexts());
  }
  for (size_t i = 0; i < kNumTestContexts; i++) {
    context[i].Reset();
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(kNumTestContexts - i - 1u,
             heap_statistics.number_of_native_contexts());
  }
}

TEST(NumberOfDetachedContexts) {
  static const size_t kNumTestContexts = 10;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);
  v8::Global<v8::Context> context[kNumTestContexts];
  v8::HeapStatistics heap_statistics;

  // In this test, we need to invoke GC without stack, otherwise some objects
  // may not be reclaimed because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  CHECK_EQ(0u, heap_statistics.number_of_detached_contexts());
  CcTest::isolate()->GetHeapStatistics(&heap_statistics);
  CHECK_EQ(0u, heap_statistics.number_of_detached_contexts());
  for (size_t i = 0; i < kNumTestContexts; i++) {
    i::HandleScope inner(isolate);
    v8::Local<v8::Context> local = v8::Context::New(CcTest::isolate());
    context[i].Reset(CcTest::isolate(), local);
    local->DetachGlobal();
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(i + 1, heap_statistics.number_of_detached_contexts());
  }
  for (size_t i = 0; i < kNumTestContexts; i++) {
    context[i].Reset();
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(kNumTestContexts - i - 1u,
             heap_statistics.number_of_detached_contexts());
  }
}

TEST(ExternalizeOldSpaceTwoByteCons) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> cons =
      CompileRun("%ConstructConsString('Romeo Montague ', 'Juliet Capulet ❤️')")
          ->ToString(env.local())
          .ToLocalChecked();
  CHECK(IsConsString(*v8::Utils::OpenDirectHandle(*cons)));
  i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  CHECK(CcTest::heap()->old_space()->Contains(
      *v8::Utils::OpenDirectHandle(*cons)));

  TestResource* resource = new TestResource(
      AsciiToTwoByteString(u"Romeo Montague Juliet Capulet ❤️"));
  cons->MakeExternal(isolate, resource);

  CHECK(cons->IsExternalTwoByte());
  CHECK(cons->IsExternal());
  CHECK_EQ(resource, cons->GetExternalStringResource());
  String::Encoding encoding;
  CHECK_EQ(resource, cons->GetExternalStringResourceBase(&encoding));
  CHECK_EQ(String::TWO_BYTE_ENCODING, encoding);
}

TEST(ExternalizeOldSpaceOneByteCons) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> cons =
      CompileRun("%ConstructConsString('Romeo Montague ', 'Juliet Capulet')")
          ->ToString(env.local())
          .ToLocalChecked();
  CHECK(IsConsString(*v8::Utils::OpenDirectHandle(*cons)));
  i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  CHECK(CcTest::heap()->old_space()->Contains(
      *v8::Utils::OpenDirectHandle(*cons)));

  TestOneByteResource* resource =
      new TestOneByteResource(i::StrDup("Romeo Montague Juliet Capulet"));
  cons->MakeExternal(isolate, resource);

  CHECK(cons->IsExternalOneByte());
  CHECK_EQ(resource, cons->GetExternalOneByteStringResource());
  String::Encoding encoding;
  CHECK_EQ(resource, cons->GetExternalStringResourceBase(&encoding));
  CHECK_EQ(String::ONE_BYTE_ENCODING, encoding);
}

TEST(ExternalStringCollectedAtTearDown) {
  int destroyed = 0;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  { v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    const char* s = "One string to test them all, one string to find them.";
    TestOneByteResource* inscription =
        new TestOneByteResource(i::StrDup(s), &destroyed);
    v8::Local<v8::String> ring =
        v8::String::NewExternalOneByte(isolate, inscription).ToLocalChecked();
    // Ring is still alive. Orcs are roaming freely across our lands.
    CHECK_EQ(0, destroyed);
    USE(ring);
  }

  isolate->Dispose();
  // Ring has been destroyed. Free Peoples of Middle-earth Rejoice.
  CHECK_EQ(1, destroyed);
}

TEST(ExternalInternalizedStringCollectedAtTearDown) {
  int destroyed = 0;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  { v8::Isolate::Scope isolate_scope(isolate);
    LocalContext env(isolate);
    v8::HandleScope handle_scope(isolate);
    CompileRun("var ring = 'One string to test them all';");
    const char* s = "One string to test them all";
    TestOneByteResource* inscription =
        new TestOneByteResource(i::StrDup(s), &destroyed);
    v8::Local<v8::String> ring =
        CompileRun("ring")->ToString(env.local()).ToLocalChecked();
    CHECK(IsInternalizedString(*v8::Utils::OpenDirectHandle(*ring)));
    ring->MakeExternal(isolate, inscription);
    // Ring is still alive. Orcs are roaming freely across our lands.
    CHECK_EQ(0, destroyed);
    USE(ring);
  }

  isolate->Dispose();
  // Ring has been destroyed. Free Peoples of Middle-earth Rejoice.
  CHECK_EQ(1, destroyed);
}

TEST(ExternalInternalizedStringCollectedAtGC) {
  int destroyed = 0;
  { LocalContext env;
    v8::HandleScope handle_scope(env->GetIsolate());
    CompileRun("var ring = 'One string to test them all';");
    const char* s = "One string to test them all";
    TestOneByteResource* inscription =
        new TestOneByteResource(i::StrDup(s), &destroyed);
    v8::Local<v8::String> ring = CompileRun("ring").As<v8::String>();
    CHECK(IsInternalizedString(*v8::Utils::OpenDirectHandle(*ring)));
    ring->MakeExternal(env->GetIsolate(), inscription);
    // Ring is still alive. Orcs are roaming freely across our lands.
    CHECK_EQ(0, destroyed);
    USE(ring);
  }

  // Garbage collector deals swift blows to evil.
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }

  // Ring has been destroyed. Free Peoples of Middle-earth Rejoice.
  CHECK_EQ(1, destroyed);
}

static double DoubleFromBits(uint64_t value) {
  double target;
  i::MemCopy(&target, &value, sizeof(target));
  return target;
}

static uint64_t DoubleToBits(double value) {
  uint64_t target;
  i::MemCopy(&target, &value, sizeof(target));
  return target;
}

static double DoubleToDateTime(double input) {
  double date_limit = 864e13;
  if (std::isnan(input) || input < -date_limit || input > date_limit) {
    return std::numeric_limits<double>::quiet_NaN();
  }
  return (input < 0) ? -(std::floor(-input)) : std::floor(input);
}

// We don't have a consistent way to write 64-bit constants syntactically, so we
// split them into two 32-bit constants and combine them programmatically.
static double DoubleFromBits(uint32_t high_bits, uint32_t low_bits) {
  return DoubleFromBits((static_cast<uint64_t>(high_bits) << 32) | low_bits);
}

THREADED_TEST(QuietSignalingNaNs) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);

  // Special double values.
  double snan = DoubleFromBits(0x7FF00000, 0x00000001);
  double qnan = DoubleFromBits(0x7FF80000, 0x00000000);
  double infinity = DoubleFromBits(0x7FF00000, 0x00000000);
  double max_normal = DoubleFromBits(0x7FEFFFFF, 0xFFFFFFFFu);
  double min_normal = DoubleFromBits(0x00100000, 0x00000000);
  double max_denormal = DoubleFromBits(0x000FFFFF, 0xFFFFFFFFu);
  double min_denormal = DoubleFromBits(0x00000000, 0x00000001);

  // Date values are capped at +/-100000000 days (times 864e5 ms per day)
  // on either side of the epoch.
  double date_limit = 864e13;

  double test_values[] = {
      snan,
      qnan,
      infinity,
      max_normal,
      date_limit + 1,
      date_limit,
      min_normal,
      max_denormal,
      min_denormal,
      0,
      -0,
      -min_denormal,
      -max_denormal,
      -min_normal,
      -date_limit,
      -date_limit - 1,
      -max_normal,
      -infinity,
      -qnan,
      -snan
  };
  int num_test_values = 20;

  for (int i = 0; i < num_test_values; i++) {
    double test_value = test_values[i];

    // Check that Number::New preserves non-NaNs and quiets SNaNs.
    v8::Local<v8::Value> number = v8::Number::New(isolate, test_value);
    double stored_number = number->NumberValue(context.local()).FromJust();
    if (!std::isnan(test_value)) {
      CHECK_EQ(test_value, stored_number);
    } else {
      uint64_t stored_bits = DoubleToBits(stored_number);
      // Check if quiet nan (bits 51..62 all set).
#if (defined(V8_TARGET_ARCH_MIPS64)) && !defined(_MIPS_ARCH_MIPS64R6) && \
    !defined(USE_SIMULATOR)
      // Most significant fraction bit for quiet nan is set to 0
      // on MIPS architecture. Allowed by IEEE-754.
      CHECK_EQ(0xFFE, static_cast<int>((stored_bits >> 51) & 0xFFF));
#else
      CHECK_EQ(0xFFF, static_cast<int>((stored_bits >> 51) & 0xFFF));
#endif
    }

    // Check that Date::New preserves non-NaNs in the date range and
    // quiets SNaNs.
    v8::Local<v8::Value> date =
        v8::Date::New(context.local(), test_value).ToLocalChecked();
    double expected_stored_date = DoubleToDateTime(test_value);
    double stored_date = date->NumberValue(context.local()).FromJust();
    if (!std::isnan(expected_stored_date)) {
      CHECK_EQ(expected_stored_date, stored_date);
    } else {
      uint64_t stored_bits = DoubleToBits(stored_date);
      // Check if quiet nan (bits 51..62 all set).
#if (defined(V8_TARGET_ARCH_MIPS64)) && !defined(_MIPS_ARCH_MIPS64R6) && \
    !defined(USE_SIMULATOR)
      // Most significant fraction bit for quiet nan is set to 0
      // on MIPS architecture. Allowed by IEEE-754.
      CHECK_EQ(0xFFE, static_cast<int>((stored_bits >> 51) & 0xFFF));
#else
      CHECK_EQ(0xFFF, static_cast<int>((stored_bits >> 51) & 0xFFF));
#endif
    }
  }
}

static void SpaghettiIncident(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::HandleScope scope(args.GetIsolate());
  v8::TryCatch tc(args.GetIsolate());
  v8::MaybeLocal<v8::String> str(
      args[0]->ToString(args.GetIsolate()->GetCurrentContext()));
  USE(str);
  if (tc.HasCaught()) {
    CHECK(args.GetIsolate()->HasPendingException());
    tc.ReThrow();
    CHECK(args.GetIsolate()->HasPendingException());
  }
}

// Test that an exception can be propagated down through a spaghetti
// stack using ReThrow.
THREADED_TEST(SpaghettiStackReThrow) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("s"),
            v8::FunctionTemplate::New(isolate, SpaghettiIncident)
                ->GetFunction(context.local())
                .ToLocalChecked())
      .FromJust();
  v8::TryCatch try_catch(isolate);
  CompileRun(
      "var i = 0;"
      "var o = {"
      "  toString: function () {"
      "    if (i == 10) {"
      "      throw 'Hey!';"
      "    } else {"
      "      i++;"
      "      return s(o);"
      "    }"
      "  }"
      "};"
      "s(o);");
  CHECK(try_catch.HasCaught());
  v8::String::Utf8Value value(isolate, try_catch.Exception());
  CHECK_EQ(0, strcmp(*value, "Hey!"));
}

TEST(Regress528) {
  i::ManualGCScope manual_gc_scope;
  v8::Isolate* isolate = CcTest::isolate();
  i::v8_flags.retain_maps_for_n_gc = 0;
  v8::HandleScope scope(isolate);
  int gc_count;

  // In this test, we need to invoke GC without stack, otherwise some objects
  // may not be reclaimed because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  // Create a context used to keep the code from aging in the compilation
  // cache.
  LocalContext other_context(isolate);

  // Context-dependent context data creates reference from the compilation
  // cache to the global object.
  const char* source_simple = "1";
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<Context> context = Context::New(isolate);

    context->Enter();
    Local<v8::String> obj = v8_str("");
    context->SetEmbedderData(0, obj);
    CompileRun(source_simple);
    context->Exit();
  }
  isolate->ContextDisposedNotification();
  for (gc_count = 1; gc_count < 10; gc_count++) {
    other_context->Enter();
    CompileRun(source_simple);
    other_context->Exit();
    i::heap::InvokeMajorGC(CcTest::heap());
    if (GetGlobalObjectsCount() == 1) break;
  }
  CHECK_GE(2, gc_count);
  CHECK_EQ(1, GetGlobalObjectsCount());

  // Eval in a function creates reference from the compilation cache to the
  // global object.
  const char* source_eval = "function f(){eval('1')}; f()";
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<Context> context = Context::New(isolate);

    context->Enter();
    CompileRun(source_eval);
    context->Exit();
  }
  isolate->ContextDisposedNotification();
  for (gc_count = 1; gc_count < 10; gc_count++) {
    other_context->Enter();
    CompileRun(source_eval);
    other_context->Exit();
    i::heap::InvokeMajorGC(CcTest::heap());
    if (GetGlobalObjectsCount() == 1) break;
  }
  CHECK_GE(2, gc_count);
  CHECK_EQ(1, GetGlobalObjectsCount());

  // Looking up the line number for an exception creates reference from the
  // compilation cache to the global object.
  const char* source_exception = "function f(){throw 1;} f()";
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<Context> context = Context::New(isolate);

    context->Enter();
    v8::TryCatch try_catch(isolate);
    CompileRun(source_exception);
    CHECK(try_catch.HasCaught());
    v8::Local<v8::Message> message = try_catch.Message();
    CHECK(!message.IsEmpty());
    CHECK_EQ(1, message->GetLineNumber(context).FromJust());
    context->Exit();
  }
  isolate->ContextDisposedNotification();
  for (gc_count = 1; gc_count < 10; gc_count++) {
    other_context->Enter();
    CompileRun(source_exception);
    other_context->Exit();
    i::heap::InvokeMajorGC(CcTest::heap());
    if (GetGlobalObjectsCount() == 1) break;
  }
  CHECK_GE(2, gc_count);
  CHECK_EQ(1, GetGlobalObjectsCount());

  isolate->ContextDisposedNotification();
}

THREADED_TEST(ScriptOrigin) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::PrimitiveArray> array(v8::PrimitiveArray::New(isolate, 1));
  Local<v8::Symbol> symbol(v8::Symbol::New(isolate));
  array->Set(isolate, 0, symbol);

  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 1, 1, true, -1,
                                             v8_str("http://sourceMapUrl"),
                                             true, false, false, array);
  v8::Local<v8::String> script = v8_str("function f() {}\n\nfunction g() {}");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str
Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第20部分，共36部分，请归纳一下它的功能

"""
 Promise {\n"
      "  static get [Symbol.species]() {\n"
      "    return Y;\n"
      "  }\n"
      "}\n"
      "class Y {\n"
      "  constructor(executor) {\n"
      "    return new Proxy(new Promise(executor), {});\n"
      "  }\n"
      "}\n"
      "var x = X.resolve().then(() => {});\n";

  CompileRun(source);

  promise_hook_data->Reset();
  source =
      "var resolve, value = '';\n"
      "var p = new Promise(r => resolve = r);\n";

  CompileRun(source);
  CHECK_EQ(v8::Promise::kPending, GetPromise("p")->State());
  CompileRun("resolve(Promise.resolve(value));\n");
  CHECK_EQ(v8::Promise::kFulfilled, GetPromise("p")->State());
  CHECK_EQ(11, promise_hook_data->promise_hook_count);

  promise_hook_data->Reset();
  source =
      "var p = Promise.resolve({\n"
      "  then(r) {\n"
      "    r();\n"
      "  }\n"
      "});";
  CompileRun(source);
  CHECK_EQ(GetPromise("p")->State(), v8::Promise::kFulfilled);
  CHECK_EQ(promise_hook_data->promise_hook_count, 5);

  delete promise_hook_data;
  isolate->SetPromiseHook(nullptr);
}


TEST(EvalWithSourceURLInMessageScriptResourceNameOrSourceURL) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  const char *source =
    "function outer() {\n"
    "  var scriptContents = \"function foo() { FAIL.FAIL; }\\\n"
    "  //# sourceURL=source_url\";\n"
    "  eval(scriptContents);\n"
    "  foo(); }\n"
    "outer();\n"
    "//# sourceURL=outer_url";

  v8::TryCatch try_catch(context->GetIsolate());
  CompileRun(source);
  CHECK(try_catch.HasCaught());

  Local<v8::Message> message = try_catch.Message();
  Local<Value> sourceURL = message->GetScriptOrigin().ResourceName();
  CHECK_EQ(0, strcmp(*v8::String::Utf8Value(context->GetIsolate(), sourceURL),
                     "source_url"));
}


TEST(RecursionWithSourceURLInMessageScriptResourceNameOrSourceURL) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  const char *source =
    "function outer() {\n"
    "  var scriptContents = \"function boo(){ boo(); }\\\n"
    "  //# sourceURL=source_url\";\n"
    "  eval(scriptContents);\n"
    "  boo(); }\n"
    "outer();\n"
    "//# sourceURL=outer_url";

  v8::TryCatch try_catch(context->GetIsolate());
  CompileRun(source);
  CHECK(try_catch.HasCaught());

  Local<v8::Message> message = try_catch.Message();
  Local<Value> sourceURL = message->GetScriptOrigin().ResourceName();
  CHECK_EQ(0, strcmp(*v8::String::Utf8Value(context->GetIsolate(), sourceURL),
                     "source_url"));
}


TEST(Regress2333) {
  LocalContext env;
  for (int i = 0; i < 3; i++) {
    i::heap::InvokeMinorGC(CcTest::heap());
  }
}

static uint32_t* stack_limit;

static void GetStackLimitCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  stack_limit = reinterpret_cast<uint32_t*>(
      CcTest::i_isolate()->stack_guard()->real_climit());
}


// Uses the address of a local variable to determine the stack top now.
// Given a size, returns an address that is that far from the current
// top of stack.
static uint32_t* ComputeStackLimit(uint32_t size) {
  // Disable the gcc error which (very correctly) notes that this is an
  // out-of-bounds access.
#if V8_CC_GNU
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif  // V8_CC_GNU
  uint32_t* answer = &size - (size / sizeof(size));
#if V8_CC_GNU
#pragma GCC diagnostic pop
#endif  // V8_CC_GNU
  // If the size is very large and the stack is very near the bottom of
  // memory then the calculation above may wrap around and give an address
  // that is above the (downwards-growing) stack.  In that case we return
  // a very low address.
  if (answer > &size) return reinterpret_cast<uint32_t*>(sizeof(size));
  return answer;
}


// We need at least 165kB for an x64 debug build with clang and ASAN.
static const int stack_breathing_room = 256 * i::KB;


TEST(SetStackLimit) {
  uint32_t* set_limit = ComputeStackLimit(stack_breathing_room);

  // Set stack limit.
  CcTest::isolate()->SetStackLimit(reinterpret_cast<uintptr_t>(set_limit));

  // Execute a script.
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(env->GetIsolate(), GetStackLimitCallback);
  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()
            ->Set(env.local(), v8_str("get_stack_limit"), fun)
            .FromJust());
  CompileRun("get_stack_limit();");

  CHECK(stack_limit == set_limit);
}


TEST(SetStackLimitInThread) {
  uint32_t* set_limit;
  {
    v8::Locker locker(CcTest::isolate());
    set_limit = ComputeStackLimit(stack_breathing_room);

    // Set stack limit.
    CcTest::isolate()->SetStackLimit(reinterpret_cast<uintptr_t>(set_limit));

    // Execute a script.
    v8::HandleScope scope(CcTest::isolate());
    LocalContext env;
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(CcTest::isolate(), GetStackLimitCallback);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("get_stack_limit"), fun)
              .FromJust());
    CompileRun("get_stack_limit();");

    CHECK(stack_limit == set_limit);
  }
  {
    v8::Locker locker(CcTest::isolate());
    CHECK(stack_limit == set_limit);
  }
}

THREADED_TEST(GetHeapStatistics) {
  LocalContext c1;
  v8::HandleScope scope(c1->GetIsolate());
  v8::HeapStatistics heap_statistics;
  CHECK_EQ(0u, heap_statistics.total_heap_size());
  CHECK_EQ(0u, heap_statistics.used_heap_size());
  c1->GetIsolate()->GetHeapStatistics(&heap_statistics);
  CHECK_NE(static_cast<int>(heap_statistics.total_heap_size()), 0);
}

TEST(GetHeapSpaceStatistics) {
  // This test is incompatible with concurrent allocation, which may occur
  // while collecting the statistics and break the final `CHECK_EQ`s.
  if (i::v8_flags.stress_concurrent_allocation) return;

  LocalContext c1;
  v8::Isolate* isolate = c1->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::HeapStatistics heap_statistics;

  // Force allocation in LO_SPACE and TRUSTED_LO_SPACE so that every space has
  // non-zero size.
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  auto unused = i_isolate->factory()->TryNewFixedArray(512 * 1024,
                                                       i::AllocationType::kOld);
  USE(unused);

  isolate->GetHeapStatistics(&heap_statistics);

  // Ensure that the sum of all the spaces matches the totals from
  // GetHeapSpaceStatistics.
  size_t total_size = 0u;
  size_t total_used_size = 0u;
  size_t total_available_size = 0u;
  size_t total_physical_size = 0u;
  for (size_t i = 0; i < isolate->NumberOfHeapSpaces(); ++i) {
    v8::HeapSpaceStatistics space_statistics;
    isolate->GetHeapSpaceStatistics(&space_statistics, i);
    CHECK_NOT_NULL(space_statistics.space_name());
    total_size += space_statistics.space_size();
    total_used_size += space_statistics.space_used_size();
    total_available_size += space_statistics.space_available_size();
    total_physical_size += space_statistics.physical_space_size();
  }
  total_available_size += CcTest::heap()->memory_allocator()->Available();

  CHECK_EQ(total_size, heap_statistics.total_heap_size());
  CHECK_EQ(total_used_size, heap_statistics.used_heap_size());
  CHECK_EQ(total_available_size, heap_statistics.total_available_size());
  CHECK_EQ(total_physical_size, heap_statistics.total_physical_size());
}

TEST(NumberOfNativeContexts) {
  static const size_t kNumTestContexts = 10;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);
  v8::Global<v8::Context> context[kNumTestContexts];
  v8::HeapStatistics heap_statistics;

  // In this test, we need to invoke GC without stack, otherwise some objects
  // may not be reclaimed because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  CHECK_EQ(0u, heap_statistics.number_of_native_contexts());
  CcTest::isolate()->GetHeapStatistics(&heap_statistics);
  CHECK_EQ(0u, heap_statistics.number_of_native_contexts());
  for (size_t i = 0; i < kNumTestContexts; i++) {
    i::HandleScope inner(isolate);
    context[i].Reset(CcTest::isolate(), v8::Context::New(CcTest::isolate()));
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(i + 1, heap_statistics.number_of_native_contexts());
  }
  for (size_t i = 0; i < kNumTestContexts; i++) {
    context[i].Reset();
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(kNumTestContexts - i - 1u,
             heap_statistics.number_of_native_contexts());
  }
}

TEST(NumberOfDetachedContexts) {
  static const size_t kNumTestContexts = 10;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);
  v8::Global<v8::Context> context[kNumTestContexts];
  v8::HeapStatistics heap_statistics;

  // In this test, we need to invoke GC without stack, otherwise some objects
  // may not be reclaimed because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  CHECK_EQ(0u, heap_statistics.number_of_detached_contexts());
  CcTest::isolate()->GetHeapStatistics(&heap_statistics);
  CHECK_EQ(0u, heap_statistics.number_of_detached_contexts());
  for (size_t i = 0; i < kNumTestContexts; i++) {
    i::HandleScope inner(isolate);
    v8::Local<v8::Context> local = v8::Context::New(CcTest::isolate());
    context[i].Reset(CcTest::isolate(), local);
    local->DetachGlobal();
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(i + 1, heap_statistics.number_of_detached_contexts());
  }
  for (size_t i = 0; i < kNumTestContexts; i++) {
    context[i].Reset();
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(kNumTestContexts - i - 1u,
             heap_statistics.number_of_detached_contexts());
  }
}

TEST(ExternalizeOldSpaceTwoByteCons) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> cons =
      CompileRun("%ConstructConsString('Romeo Montague ', 'Juliet Capulet ❤️')")
          ->ToString(env.local())
          .ToLocalChecked();
  CHECK(IsConsString(*v8::Utils::OpenDirectHandle(*cons)));
  i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  CHECK(CcTest::heap()->old_space()->Contains(
      *v8::Utils::OpenDirectHandle(*cons)));

  TestResource* resource = new TestResource(
      AsciiToTwoByteString(u"Romeo Montague Juliet Capulet ❤️"));
  cons->MakeExternal(isolate, resource);

  CHECK(cons->IsExternalTwoByte());
  CHECK(cons->IsExternal());
  CHECK_EQ(resource, cons->GetExternalStringResource());
  String::Encoding encoding;
  CHECK_EQ(resource, cons->GetExternalStringResourceBase(&encoding));
  CHECK_EQ(String::TWO_BYTE_ENCODING, encoding);
}


TEST(ExternalizeOldSpaceOneByteCons) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> cons =
      CompileRun("%ConstructConsString('Romeo Montague ', 'Juliet Capulet')")
          ->ToString(env.local())
          .ToLocalChecked();
  CHECK(IsConsString(*v8::Utils::OpenDirectHandle(*cons)));
  i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  CHECK(CcTest::heap()->old_space()->Contains(
      *v8::Utils::OpenDirectHandle(*cons)));

  TestOneByteResource* resource =
      new TestOneByteResource(i::StrDup("Romeo Montague Juliet Capulet"));
  cons->MakeExternal(isolate, resource);

  CHECK(cons->IsExternalOneByte());
  CHECK_EQ(resource, cons->GetExternalOneByteStringResource());
  String::Encoding encoding;
  CHECK_EQ(resource, cons->GetExternalStringResourceBase(&encoding));
  CHECK_EQ(String::ONE_BYTE_ENCODING, encoding);
}

TEST(ExternalStringCollectedAtTearDown) {
  int destroyed = 0;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  { v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    const char* s = "One string to test them all, one string to find them.";
    TestOneByteResource* inscription =
        new TestOneByteResource(i::StrDup(s), &destroyed);
    v8::Local<v8::String> ring =
        v8::String::NewExternalOneByte(isolate, inscription).ToLocalChecked();
    // Ring is still alive.  Orcs are roaming freely across our lands.
    CHECK_EQ(0, destroyed);
    USE(ring);
  }

  isolate->Dispose();
  // Ring has been destroyed.  Free Peoples of Middle-earth Rejoice.
  CHECK_EQ(1, destroyed);
}


TEST(ExternalInternalizedStringCollectedAtTearDown) {
  int destroyed = 0;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  { v8::Isolate::Scope isolate_scope(isolate);
    LocalContext env(isolate);
    v8::HandleScope handle_scope(isolate);
    CompileRun("var ring = 'One string to test them all';");
    const char* s = "One string to test them all";
    TestOneByteResource* inscription =
        new TestOneByteResource(i::StrDup(s), &destroyed);
    v8::Local<v8::String> ring =
        CompileRun("ring")->ToString(env.local()).ToLocalChecked();
    CHECK(IsInternalizedString(*v8::Utils::OpenDirectHandle(*ring)));
    ring->MakeExternal(isolate, inscription);
    // Ring is still alive.  Orcs are roaming freely across our lands.
    CHECK_EQ(0, destroyed);
    USE(ring);
  }

  isolate->Dispose();
  // Ring has been destroyed.  Free Peoples of Middle-earth Rejoice.
  CHECK_EQ(1, destroyed);
}


TEST(ExternalInternalizedStringCollectedAtGC) {
  int destroyed = 0;
  { LocalContext env;
    v8::HandleScope handle_scope(env->GetIsolate());
    CompileRun("var ring = 'One string to test them all';");
    const char* s = "One string to test them all";
    TestOneByteResource* inscription =
        new TestOneByteResource(i::StrDup(s), &destroyed);
    v8::Local<v8::String> ring = CompileRun("ring").As<v8::String>();
    CHECK(IsInternalizedString(*v8::Utils::OpenDirectHandle(*ring)));
    ring->MakeExternal(env->GetIsolate(), inscription);
    // Ring is still alive.  Orcs are roaming freely across our lands.
    CHECK_EQ(0, destroyed);
    USE(ring);
  }

  // Garbage collector deals swift blows to evil.
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }

  // Ring has been destroyed.  Free Peoples of Middle-earth Rejoice.
  CHECK_EQ(1, destroyed);
}

static double DoubleFromBits(uint64_t value) {
  double target;
  i::MemCopy(&target, &value, sizeof(target));
  return target;
}


static uint64_t DoubleToBits(double value) {
  uint64_t target;
  i::MemCopy(&target, &value, sizeof(target));
  return target;
}


static double DoubleToDateTime(double input) {
  double date_limit = 864e13;
  if (std::isnan(input) || input < -date_limit || input > date_limit) {
    return std::numeric_limits<double>::quiet_NaN();
  }
  return (input < 0) ? -(std::floor(-input)) : std::floor(input);
}


// We don't have a consistent way to write 64-bit constants syntactically, so we
// split them into two 32-bit constants and combine them programmatically.
static double DoubleFromBits(uint32_t high_bits, uint32_t low_bits) {
  return DoubleFromBits((static_cast<uint64_t>(high_bits) << 32) | low_bits);
}


THREADED_TEST(QuietSignalingNaNs) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);

  // Special double values.
  double snan = DoubleFromBits(0x7FF00000, 0x00000001);
  double qnan = DoubleFromBits(0x7FF80000, 0x00000000);
  double infinity = DoubleFromBits(0x7FF00000, 0x00000000);
  double max_normal = DoubleFromBits(0x7FEFFFFF, 0xFFFFFFFFu);
  double min_normal = DoubleFromBits(0x00100000, 0x00000000);
  double max_denormal = DoubleFromBits(0x000FFFFF, 0xFFFFFFFFu);
  double min_denormal = DoubleFromBits(0x00000000, 0x00000001);

  // Date values are capped at +/-100000000 days (times 864e5 ms per day)
  // on either side of the epoch.
  double date_limit = 864e13;

  double test_values[] = {
      snan,
      qnan,
      infinity,
      max_normal,
      date_limit + 1,
      date_limit,
      min_normal,
      max_denormal,
      min_denormal,
      0,
      -0,
      -min_denormal,
      -max_denormal,
      -min_normal,
      -date_limit,
      -date_limit - 1,
      -max_normal,
      -infinity,
      -qnan,
      -snan
  };
  int num_test_values = 20;

  for (int i = 0; i < num_test_values; i++) {
    double test_value = test_values[i];

    // Check that Number::New preserves non-NaNs and quiets SNaNs.
    v8::Local<v8::Value> number = v8::Number::New(isolate, test_value);
    double stored_number = number->NumberValue(context.local()).FromJust();
    if (!std::isnan(test_value)) {
      CHECK_EQ(test_value, stored_number);
    } else {
      uint64_t stored_bits = DoubleToBits(stored_number);
      // Check if quiet nan (bits 51..62 all set).
#if (defined(V8_TARGET_ARCH_MIPS64)) && !defined(_MIPS_ARCH_MIPS64R6) && \
    !defined(USE_SIMULATOR)
      // Most significant fraction bit for quiet nan is set to 0
      // on MIPS architecture. Allowed by IEEE-754.
      CHECK_EQ(0xFFE, static_cast<int>((stored_bits >> 51) & 0xFFF));
#else
      CHECK_EQ(0xFFF, static_cast<int>((stored_bits >> 51) & 0xFFF));
#endif
    }

    // Check that Date::New preserves non-NaNs in the date range and
    // quiets SNaNs.
    v8::Local<v8::Value> date =
        v8::Date::New(context.local(), test_value).ToLocalChecked();
    double expected_stored_date = DoubleToDateTime(test_value);
    double stored_date = date->NumberValue(context.local()).FromJust();
    if (!std::isnan(expected_stored_date)) {
      CHECK_EQ(expected_stored_date, stored_date);
    } else {
      uint64_t stored_bits = DoubleToBits(stored_date);
      // Check if quiet nan (bits 51..62 all set).
#if (defined(V8_TARGET_ARCH_MIPS64)) && !defined(_MIPS_ARCH_MIPS64R6) && \
    !defined(USE_SIMULATOR)
      // Most significant fraction bit for quiet nan is set to 0
      // on MIPS architecture. Allowed by IEEE-754.
      CHECK_EQ(0xFFE, static_cast<int>((stored_bits >> 51) & 0xFFF));
#else
      CHECK_EQ(0xFFF, static_cast<int>((stored_bits >> 51) & 0xFFF));
#endif
    }
  }
}


static void SpaghettiIncident(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::HandleScope scope(args.GetIsolate());
  v8::TryCatch tc(args.GetIsolate());
  v8::MaybeLocal<v8::String> str(
      args[0]->ToString(args.GetIsolate()->GetCurrentContext()));
  USE(str);
  if (tc.HasCaught()) {
    CHECK(args.GetIsolate()->HasPendingException());
    tc.ReThrow();
    CHECK(args.GetIsolate()->HasPendingException());
  }
}


// Test that an exception can be propagated down through a spaghetti
// stack using ReThrow.
THREADED_TEST(SpaghettiStackReThrow) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("s"),
            v8::FunctionTemplate::New(isolate, SpaghettiIncident)
                ->GetFunction(context.local())
                .ToLocalChecked())
      .FromJust();
  v8::TryCatch try_catch(isolate);
  CompileRun(
      "var i = 0;"
      "var o = {"
      "  toString: function () {"
      "    if (i == 10) {"
      "      throw 'Hey!';"
      "    } else {"
      "      i++;"
      "      return s(o);"
      "    }"
      "  }"
      "};"
      "s(o);");
  CHECK(try_catch.HasCaught());
  v8::String::Utf8Value value(isolate, try_catch.Exception());
  CHECK_EQ(0, strcmp(*value, "Hey!"));
}


TEST(Regress528) {
  i::ManualGCScope manual_gc_scope;
  v8::Isolate* isolate = CcTest::isolate();
  i::v8_flags.retain_maps_for_n_gc = 0;
  v8::HandleScope scope(isolate);
  int gc_count;

  // In this test, we need to invoke GC without stack, otherwise some objects
  // may not be reclaimed because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  // Create a context used to keep the code from aging in the compilation
  // cache.
  LocalContext other_context(isolate);

  // Context-dependent context data creates reference from the compilation
  // cache to the global object.
  const char* source_simple = "1";
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<Context> context = Context::New(isolate);

    context->Enter();
    Local<v8::String> obj = v8_str("");
    context->SetEmbedderData(0, obj);
    CompileRun(source_simple);
    context->Exit();
  }
  isolate->ContextDisposedNotification();
  for (gc_count = 1; gc_count < 10; gc_count++) {
    other_context->Enter();
    CompileRun(source_simple);
    other_context->Exit();
    i::heap::InvokeMajorGC(CcTest::heap());
    if (GetGlobalObjectsCount() == 1) break;
  }
  CHECK_GE(2, gc_count);
  CHECK_EQ(1, GetGlobalObjectsCount());

  // Eval in a function creates reference from the compilation cache to the
  // global object.
  const char* source_eval = "function f(){eval('1')}; f()";
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<Context> context = Context::New(isolate);

    context->Enter();
    CompileRun(source_eval);
    context->Exit();
  }
  isolate->ContextDisposedNotification();
  for (gc_count = 1; gc_count < 10; gc_count++) {
    other_context->Enter();
    CompileRun(source_eval);
    other_context->Exit();
    i::heap::InvokeMajorGC(CcTest::heap());
    if (GetGlobalObjectsCount() == 1) break;
  }
  CHECK_GE(2, gc_count);
  CHECK_EQ(1, GetGlobalObjectsCount());

  // Looking up the line number for an exception creates reference from the
  // compilation cache to the global object.
  const char* source_exception = "function f(){throw 1;} f()";
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<Context> context = Context::New(isolate);

    context->Enter();
    v8::TryCatch try_catch(isolate);
    CompileRun(source_exception);
    CHECK(try_catch.HasCaught());
    v8::Local<v8::Message> message = try_catch.Message();
    CHECK(!message.IsEmpty());
    CHECK_EQ(1, message->GetLineNumber(context).FromJust());
    context->Exit();
  }
  isolate->ContextDisposedNotification();
  for (gc_count = 1; gc_count < 10; gc_count++) {
    other_context->Enter();
    CompileRun(source_exception);
    other_context->Exit();
    i::heap::InvokeMajorGC(CcTest::heap());
    if (GetGlobalObjectsCount() == 1) break;
  }
  CHECK_GE(2, gc_count);
  CHECK_EQ(1, GetGlobalObjectsCount());

  isolate->ContextDisposedNotification();
}


THREADED_TEST(ScriptOrigin) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::PrimitiveArray> array(v8::PrimitiveArray::New(isolate, 1));
  Local<v8::Symbol> symbol(v8::Symbol::New(isolate));
  array->Set(isolate, 0, symbol);

  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 1, 1, true, -1,
                                             v8_str("http://sourceMapUrl"),
                                             true, false, false, array);
  v8::Local<v8::String> script = v8_str("function f() {}\n\nfunction g() {}");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("f")).ToLocalChecked());
  v8::Local<v8::Function> g = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("g")).ToLocalChecked());

  v8::ScriptOrigin script_origin_f = f->GetScriptOrigin();
  CHECK_EQ(0, strcmp("test",
                     *v8::String::Utf8Value(env->GetIsolate(),
                                            script_origin_f.ResourceName())));
  CHECK_EQ(1, script_origin_f.LineOffset());
  CHECK(script_origin_f.Options().IsSharedCrossOrigin());
  CHECK(script_origin_f.Options().IsOpaque());
  printf("is name = %d\n", script_origin_f.SourceMapUrl()->IsUndefined());
  CHECK(script_origin_f.GetHostDefinedOptions()
            .As<v8::PrimitiveArray>()
            ->Get(isolate, 0)
            ->IsSymbol());

  CHECK_EQ(0, strcmp("http://sourceMapUrl",
                     *v8::String::Utf8Value(env->GetIsolate(),
                                            script_origin_f.SourceMapUrl())));

  v8::ScriptOrigin script_origin_g = g->GetScriptOrigin();
  CHECK_EQ(0, strcmp("test",
                     *v8::String::Utf8Value(env->GetIsolate(),
                                            script_origin_g.ResourceName())));
  CHECK_EQ(1, script_origin_g.LineOffset());
  CHECK(script_origin_g.Options().IsSharedCrossOrigin());
  CHECK(script_origin_g.Options().IsOpaque());
  CHECK_EQ(0, strcmp("http://sourceMapUrl",
                     *v8::String::Utf8Value(env->GetIsolate(),
                                            script_origin_g.SourceMapUrl())));
  CHECK(script_origin_g.GetHostDefinedOptions()
            .As<v8::PrimitiveArray>()
            ->Get(isolate, 0)
            ->IsSymbol());
}


THREADED_TEST(FunctionGetInferredName) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script =
      v8_str("var foo = { bar : { baz : function() {}}}; var f = foo.bar.baz;");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("f")).ToLocalChecked());
  CHECK_EQ(0,
           strcmp("foo.bar.baz", *v8::String::Utf8Value(env->GetIsolate(),
                                                        f->GetInferredName())));
}


THREADED_TEST(FunctionGetDebugName) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  const char* code =
      "var error = false;"
      "function a() { this.x = 1; };"
      "Object.defineProperty(a, 'name', {value: 'display_a'});"
      "var b = (function() {"
      "  var f = function() { this.x = 2; };"
      "  Object.defineProperty(f, 'name', {value: 'display_b'});"
      "  return f;"
      "})();"
      "var c = function() {};"
      "c.__defineGetter__('name', function() {"
      "  error = true;"
      "  throw new Error();"
      "});"
      "function d() {};"
      "d.__defineGetter__('name', function() {"
      "  error = true;"
      "  return 'wrong_display_name';"
      "});"
      "function e() {};"
      "Object.defineProperty(e, 'name', {value: 'wrong_display_name'});"
      "e.__defineSetter__('name', function() {"
      "  error = true;"
      "  throw new Error();"
      "});"
      "function f() {};"
      "Object.defineProperty(f, 'name', {value: {foo: 6, toString: function() {"
      "  error = true;"
      "  return 'wrong_display_name';"
      "}}});"
      "var g = function() {"
      "  Object.defineProperty(arguments.callee, 'name', {"
      "    value: 'set_in_runtime'"
      "  });"
      "}; g();"
      "var h = function() {};"
      "h.displayName = 'displayName';"
      "Object.defineProperty(h, 'name', { value: 'function.name' });"
      "var i = function() {};"
      "i.displayName = 239;"
      "Object.defineProperty(i, 'name', { value: 'function.name' });"
      "var j = function() {};"
      "Object.defineProperty(j, 'name', { value: 'function.name' });"
      "var foo = { bar : { baz : (0, function() {})}}; var k = foo.bar.baz;"
      "var foo = { bar : { baz : function() {} }}; var l = foo.bar.baz;";
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Script::Compile(env.local(), v8_str(code), &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Value> error =
      env->Global()->Get(env.local(), v8_str("error")).ToLocalChecked();
  CHECK(!error->BooleanValue(isolate));
  const char* functions[] = {"a", "display_a",
                             "b", "display_b",
                             "c", "c",
                             "d", "d",
                             "e", "e",
                             "f", "f",
                             "g", "set_in_runtime",
                             "h", "function.name",
                             "i", "function.name",
                             "j", "function.name",
                             "k", "foo.bar.baz",
                             "l", "baz"};
  for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]) / 2; ++i) {
    v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
        env->Global()
            ->Get(env.local(),
                  v8::String::NewFromUtf8(isolate, functions[i * 2])
                      .ToLocalChecked())
            .ToLocalChecked());
    std::string expected(functions[i * 2 + 1]);
    std::string actual = *v8::String::Utf8Value(isolate, f->GetDebugName());
    CHECK_EQ(expected, actual);
  }
}


THREADED_TEST(ScriptLineNumber) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script = v8_str("function f() {}\n\nfunction g() {}");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("f")).ToLocalChecked());
  v8::Local<v8::Function> g = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("g")).ToLocalChecked());
  CHECK_EQ(0, f->GetScriptLineNumber());
  CHECK_EQ(2, g->GetScriptLineNumber());
}


THREADED_TEST(ScriptColumnNumber) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 3, 2);
  v8::Local<v8::String> script =
      v8_str("function foo() {}\n\n     function bar() {}");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("foo")).ToLocalChecked());
  v8::Local<v8::Function> bar = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("bar")).ToLocalChecked());
  CHECK_EQ(14, foo->GetScriptColumnNumber());
  CHECK_EQ(17, bar->GetScriptColumnNumber());
}

THREADED_TEST(ScriptStartPosition) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 3, 2);
  v8::Local<v8::String> script =
      v8_str("function foo() {}\n\n     function bar() {}");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("foo")).ToLocalChecked());
  v8::Local<v8::Function> bar = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("bar")).ToLocalChecked());
  CHECK_EQ(12, foo->GetScriptStartPosition());
  CHECK_EQ(36, bar->GetScriptStartPosition());
}

THREADED_TEST(FunctionGetScriptId) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 3, 2);
  v8::Local<v8::String> scriptSource =
      v8_str("function foo() {}\n\n     function bar() {}");
  v8::Local<v8::Script> script(
      v8::Script::Compile(env.local(), scriptSource, &origin).ToLocalChecked());
  script->Run(env.local()).ToLocalChecked();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("foo")).ToLocalChecked());
  v8::Local<v8::Function> bar = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("bar")).ToLocalChecked());
  CHECK_EQ(script->GetUnboundScri
"""


```