Response:
My thinking process to arrive at the summary of the provided V8 code snippet goes like this:

1. **Identify the Core Functionality:** The dominant part of the code involves testing the `CallAndCheck` family of functions and `CheckFastReturnValue`. These functions appear to be related to testing how V8 calls C++ functions from JavaScript. The names suggest verifying both the behavior of the call (exception or no exception) and whether the call went through a fast or slow path.

2. **Recognize the Test Focus:**  The various `CallAndCheck` calls are testing different scenarios:
    * **Data Type Conversions:** Testing how various JavaScript values (numbers, strings, booleans, objects, etc.) are converted and passed as arguments to C++ functions (represented by the template parameter of `CallAndCheck`). This includes integer types (int32_t, uint32_t, int64_t, uint64_t), floating-point types (float, double), and booleans.
    * **Edge Cases and Corner Cases:** Testing the limits of numerical types (min, max, NaN, Infinity), empty strings, null, undefined, etc.
    * **Fast vs. Slow Paths:** The `ApiCheckerResult` enum and the `kFastCalled`/`kSlowCalled` values clearly indicate testing whether V8 is taking optimized ("fast") or less optimized ("slow") paths when calling C++ functions.
    * **Error Handling:** Testing for expected exceptions (`Behavior::kException`).
    * **Receiver Types:** Testing how different JavaScript receiver objects behave when a C++ function is called as a method.
    * **Argument Counts:** Testing calls with too few or too many arguments.

3. **Infer the Purpose of Helper Functions/Macros:** The `v8_num`, `v8_str`, and `CompileRun` functions are likely helper functions to easily create V8 `Local<Value>` objects representing numbers, strings, and the result of executing JavaScript code, respectively.

4. **Connect to JavaScript:**  Since the code is testing interactions between JavaScript and C++, I looked for examples of how these interactions might occur in JavaScript. The `receiver.api_func(arg)` pattern in the `SeqOneByteStringChecker` test is a key indicator. This points to defining C++ functions that can be called from JavaScript on specific objects.

5. **Consider the `.tq` Check:** The prompt mentions `.tq` files and Torque. This signals that V8 might be using Torque (its own type system and compiler) to generate some of the C++ code for these fast API calls.

6. **Identify Potential Programming Errors:** The tests involving incorrect argument types, receiver types, and argument counts directly relate to common programming errors when interacting with APIs.

7. **Address the "归纳一下它的功能" (Summarize its function) requirement:**  This requires synthesizing the observations into a concise summary. I focused on the core purpose: testing the fast API calling mechanism in V8, particularly data type conversions, error handling, and the selection of fast vs. slow paths.

8. **Structure the Answer:**  I organized the answer into logical sections based on the identified functionalities:
    * Core function (testing API calls).
    * Key testing aspects (data types, fast/slow paths, errors).
    * Connection to JavaScript with an example.
    * Potential for Torque.
    * Common programming errors.
    * The final summary.

9. **Refine and Elaborate:** I added details to explain the meaning of "fast path" vs. "slow path," and clarified the examples to make them more understandable. I also made sure to address all the specific points raised in the prompt. For example, I explicitly stated that the provided code snippet itself is C++, not Torque, as the filename ends with `.cc`.

By following these steps, I could systematically analyze the code snippet and produce a comprehensive and informative summary that addresses all aspects of the prompt. The key was to identify the primary goal of the code (testing API calls) and then break down the various test cases to understand the specific aspects being verified.
```cpp
::kNoException,
                         expected_path_for_64bit_test, v8_num(-0.0));

  // TODO(mslekova): We deopt for unsafe integers, but ultimately we want to
  // stay on the fast path.
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(1ull << 63));
  CallAndCheck<int64_t>(
      std::numeric_limits<int64_t>::min(), Behavior::kNoException,
      ApiCheckerResult::kSlowCalled,
      v8_num(static_cast<double>(std::numeric_limits<int64_t>::max()) + 3.14));
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(static_cast<double>(1ull << 63)));
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(-static_cast<double>(1ll << 63)));
  CallAndCheck<uint64_t>(1ull << 63, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8_num(static_cast<double>(1ull << 63)));

  // Corner cases - float and double
#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  // Source:
  // https://en.wikipedia.org/wiki/Single-precision_floating-point_format#Precision_limitations_on_integer_values
  constexpr float kMaxSafeFloat = 16777215;  // 2^24-1
  CallAndCheck<float>(std::numeric_limits<float>::min(), Behavior::kNoException,
                      ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::min()));
  CallAndCheck<float>(-kMaxSafeFloat, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(-kMaxSafeFloat));
  CallAndCheck<float>(-0.0f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(-0.0));
  CallAndCheck<float>(0.0f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(0.0));
  CallAndCheck<float>(kMaxSafeFloat, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(kMaxSafeFloat));
  CallAndCheck<float>(std::numeric_limits<float>::max(), Behavior::kNoException,
                      ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::max()));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::quiet_NaN()));
  CallAndCheck<float>(std::numeric_limits<float>::infinity(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::infinity()));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      v8_str("some_string"));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      CompileRun("new Proxy({}, {});"));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      v8::Object::New(isolate));
  CallAndCheck<float>(0, Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      v8::Array::New(isolate));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kException, ApiCheckerResult::kSlowCalled,
                      v8::BigInt::New(isolate, 42));
  CallAndCheck<float>(-std::numeric_limits<float>::infinity(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(-std::numeric_limits<double>::max()));
  CallAndCheck<float>(std::numeric_limits<float>::infinity(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<double>::max()));
  CallAndCheck<float>(kMaxSafeFloat + 1.0f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled,
                      v8_num(static_cast<double>(kMaxSafeFloat) + 2.0));

  CallAndCheck<double>(std::numeric_limits<double>::min(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::min()));
  CallAndCheck<double>(-i::kMaxSafeInteger, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled,
                       v8_num(-i::kMaxSafeInteger));
  CallAndCheck<double>(std::numeric_limits<float>::min(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<float>::min()));
  CallAndCheck<double>(-0.0, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled, v8_num(-0.0));
  CallAndCheck<double>(0.0, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled, v8_num(0.0));
  CallAndCheck<double>(std::numeric_limits<float>::max(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<float>::max()));
  CallAndCheck<double>(i::kMaxSafeInteger, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled,
                       v8_num(i::kMaxSafeInteger));
  CallAndCheck<double>(i::kMaxSafeInteger + 1, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled,
                       v8_num(i::kMaxSafeInteger + 1));
  CallAndCheck<double>(std::numeric_limits<double>::max(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::max()));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::quiet_NaN()));
  CallAndCheck<double>(std::numeric_limits<double>::infinity(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::infinity()));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       v8_str("some_string"));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       CompileRun("new Proxy({}, {});"));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       v8::Object::New(isolate));
  CallAndCheck<double>(0, Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       v8::Array::New(isolate));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kException, ApiCheckerResult::kSlowCalled,
                       v8::BigInt::New(isolate, 42));
#endif

  // Corner cases - bool
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Undefined(isolate));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Null(isolate));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_num(0));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_num(42));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_str(""));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_str("some_string"));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Symbol::New(isolate));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled,
                     v8::BigInt::New(isolate, 0));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled,
                     v8::BigInt::New(isolate, 42));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Object::New(isolate));

  // Test return values
  CheckFastReturnValue<bool>(v8::Boolean::New(isolate, true),
                             ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<bool>(v8::Boolean::New(isolate, false),
                             ApiCheckerResult::kFastCalled);

  CheckFastReturnValue<int32_t>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<int32_t>(v8_num(std::numeric_limits<int32_t>::min()),
                                ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<int32_t>(v8_num(std::numeric_limits<int32_t>::max()),
                                ApiCheckerResult::kFastCalled);

  CheckFastReturnValue<uint32_t>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<uint32_t>(v8_num(std::numeric_limits<uint32_t>::min()),
                                 ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<uint32_t>(v8_num(std::numeric_limits<uint32_t>::max()),
                                 ApiCheckerResult::kFastCalled);

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  CheckFastReturnValue<float>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(-0.0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::quiet_NaN()),
                              ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::infinity()),
                              ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::min()),
                              ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::max()),
                              ApiCheckerResult::kFastCalled);

  CheckFastReturnValue<double>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(-0.0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::quiet_NaN()),
                               ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::infinity()),
                               ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::min()),
                               ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::max()),
                               ApiCheckerResult::kFastCalled);
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE

  // Check for the deopt loop protection
  CallAndDeopt();

  // Test callbacks without options
  CallNoOptions(42);

  // Test callback requesting access checks
  CallNoConvertReceiver(42);

  CheckDynamicTypeInfo();

  // Throw an exception.
  CallAndCheck<int32_t>(42, Behavior::kException, ApiCheckerResult::kFastCalled,
                        v8_num(42), Behavior::kException);

  CallAndCheck<int32_t>(44, Behavior::kNoException,
                        ApiCheckerResult::kFastCalled, v8_num(44),
                        Behavior::kNoException);

  // Wrong number of arguments
  CallWithLessArguments();
  CallWithMoreArguments();

  // Wrong types of receiver
  CallWithUnexpectedReceiverType(v8_num(123));
  CallWithUnexpectedReceiverType(v8_str("str"));
  CallWithUnexpectedReceiverType(CompileRun("new Proxy({}, {});"));

  // Wrong types for argument of type object
  CallWithUnexpectedObjectType(v8_num(123));
  CallWithUnexpectedObjectType(v8_str("str"));
  CallWithUnexpectedObjectType(CompileRun("new Proxy({}, {});"));

  CheckApiObjectArg();
  CheckFastCallsWithConstructor();

  // TODO(mslekova): Restructure the tests so that the fast optimized calls
  // are compared against the slow optimized calls.
  // TODO(mslekova): Add tests for FTI that requires access check.
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
}

template <typename Ret, v8::CFunctionInfo::Int64Representation Int64Repr =
                            v8::CFunctionInfo::Int64Representation::kNumber>
struct SeqOneByteStringChecker {
  static void Test(std::function<Ret()> f) {
    LocalContext env;
    v8::Isolate* isolate = CcTest::isolate();

    static v8::CFunction c_function =
        v8::CFunction::Make(FastCallback, Int64Repr);
    v8::Local<v8::FunctionTemplate> checker_templ = v8::FunctionTemplate::New(
        isolate, SlowCallback, {}, {}, 1, v8::ConstructorBehavior::kThrow,
        v8::SideEffectType::kHasSideEffect, &c_function);

    v8::Local<v8::ObjectTemplate> object_template =
        v8::ObjectTemplate::New(isolate);
    object_template->SetInternalFieldCount(kV8WrapperObjectIndex + 1);
    object_template->Set(isolate, "api_func", checker_templ);

    SeqOneByteStringChecker checker{f};

    v8::Local<v8::Object> object =
        object_template->NewInstance(env.local()).ToLocalChecked();
    object->SetAlignedPointerInInternalField(kV8WrapperObjectIndex,
                                             reinterpret_cast<void*>(&checker));
    CHECK((*env)
              ->Global()
              ->Set(env.local(), v8_str("receiver"), object)
              .FromJust());

    v8::TryCatch try_catch(isolate);
    CompileRun(
        "function func(arg) { return receiver.api_func(arg); }"
        "%PrepareFunctionForOptimization(func);"
        "func('');");
    CHECK(!try_catch.HasCaught());
    CHECK(checker.DidCallSlow());
    checker.Reset();

    CompileRun(
        "%OptimizeFunctionOnNextCall(func);"
        "const fastr = func('');");
    CHECK(!try_catch.HasCaught());
    CHECK(checker.DidCallFast());
    checker.Reset();

    // Call func with two-byte string to take slow path
    CompileRun("const slowr = func('\\u{1F4A9}');");
    CHECK(!try_catch.HasCaught());
    CHECK(checker.DidCallSlow());

    if constexpr (std::is_same_v<Ret, void*>) {
      CompileRun(
          "if (typeof slowr !== 'object') { throw new Error(`${slowr} is not "
          "object`) }");
    } else {
      CompileRun(
          "if (!Object.is(fastr, slowr)) { throw new Error(`${slowr} is not "
          "${fastr}`); }");
    }
    CHECK(!try_catch.HasCaught());
  }

  static Ret FastCallback(v8::Local<v8::Object> receiver,
                          const v8::FastOneByteString& string) {
    SeqOneByteStringChecker* receiver_ptr =
        GetInternalField<SeqOneByteStringChecker>(*receiver);
    receiver_ptr->result_ |= ApiCheckerResult::kFastCalled;

    return receiver_ptr->func_();
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Object* receiver_obj = v8::Object::Cast(*info.This());
    SeqOneByteStringChecker* receiver_ptr =
        GetInternalField<SeqOneByteStringChecker>(receiver_obj);
    receiver_ptr->result_ |= ApiCheckerResult::kSlowCalled;

    CHECK(info[0]->IsString());
    if constexpr (std::is_void<Ret>::value) {
      // do nothing
    } else if constexpr (std::is_same_v<Ret, void*>) {
      info.GetReturnValue().Set(
          v8::External::New(info.GetIsolate(), receiver_ptr->func_()));
    } else if constexpr (sizeof(Ret) == 8 &&
                         Int64Repr ==
                             v8::CFunctionInfo::Int64Representation::kBigInt) {
      if constexpr (std::is_same_v<Ret, int64_t>) {
        info.GetReturnValue().Set(
            v8::BigInt::New(info.GetIsolate(), receiver_ptr->func_()));
      } else {
        info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(
            info.GetIsolate(), receiver_ptr->func_()));
      }
    } else if constexpr (std::is_same_v<Ret, uint64_t>) {
      info.GetReturnValue().Set(v8::Number::New(
          info.GetIsolate(), static_cast<double>(receiver_ptr->func_())));
    } else {
      info.GetReturnValue().Set(receiver_ptr->func_());
    }
  }

  explicit SeqOneByteStringChecker(std::function<Ret()> f) : func_(f) {}

  bool DidCallFast() const { return (result_ & ApiCheckerResult::kFastCalled); }
  bool DidCallSlow() const { return (result_ & ApiCheckerResult::kSlowCalled); }

  void Reset() { result_ = ApiCheckerResult::kNotCalled; }

 private:
  std::function<Ret()> func_;
  ApiCheckerResultFlags result_ = ApiCheckerResult::kNotCalled;
};

TEST(FastApiCallsString) {
#if !defined(V8_LITE_MODE) &&                          \
    !defined(V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS) && \
    defined(V8_ENABLE_TURBOFAN)
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  i::v8_flags.fast_api_allow_float_in_sim = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);
  LocalContext env;

  SeqOneByteStringChecker<void>::Test([]() {});

  SeqOneByteStringChecker<void*>::Test(
      []() { return reinterpret_cast<void*>(0xFF); });

  SeqOneByteStringChecker<bool>::Test([]() { return true; });
  SeqOneByteStringChecker<bool>::Test([]() { return false; });

  SeqOneByteStringChecker<int32_t>::Test([]() { return 0; });
  SeqOneByteStringChecker<int32_t>::Test(
      []() { return std::numeric_limits<int32_t>::min(); });
  SeqOneByteStringChecker<int32_t>::Test(
      []() { return std::numeric_limits<int32_t>::max(); });

  SeqOneByteStringChecker<uint32_t>::Test([]() { return 0; });
  SeqOneByteStringChecker<uint32_t>::Test(
      []() { return std::numeric_limits<uint32_t>::min(); });
  SeqOneByteStringChecker<uint32_t>::Test(
      []() { return std::numeric_limits<uint32_t>::max(); });

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  SeqOneByteStringChecker<float>::Test([]() { return 0; });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::quiet_NaN(); });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::infinity(); });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::min(); });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::max(); });

  SeqOneByteStringChecker<double>::Test([]() { return 0; });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::quiet_NaN(); });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::infinity(); });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::min(); });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::max(); });
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE

#ifdef V8_TARGET_ARCH_64_BIT
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return std::numeric_limits<int64_t>::min();
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    // The highest int64_t representable as double.
    return 0x7ffffffffffff000L;
  });

  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<int64_t>::min();
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<int64_t>::max();
  });

  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return std::numeric_limits<uint64_t>::min();
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    // The highest uint64 representable as double.
    return 0xfffffffffffff000UL;
  });

  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<uint64_t>::min();
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<uint64_t>::max();
  });
#endif  // V8_TARGET_ARCH_64_BIT

#endif  // !defined(V8_LITE_MODE) &&
        // !defined(V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS) &&
        // defined(V8_ENABLE_TURBOFAN)
}

#if V8_ENABLE_WEBASSEMBLY
TEST(FastApiCallsFromWasm) {
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.liftoff = false;
  i::v8_flags.turboshaft_wasm = true;
  i::v8_flags.wasm_fast_api = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.wasm_lazy_compilation = true;
  i::v8_flags.fast_api_allow_float_in_sim = true;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);
  LocalContext env;

  CallAndCheckFromWasm();
}
#endif
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
namespace {
static Trivial* UnwrapTrivialObject(Local<Object> object) {
  i::Address addr = i::ValueHelper::ValueAsAddress(*object);
  auto instance_type = i::Internals::GetInstanceType(addr);
  bool is_valid =
      (v8::base::IsInRange(instance_type, i::Internals::kFirstJSApiObjectType,
                           i::Internals::kLastJSApiObjectType) ||
       instance_type == i::Internals::kJSSpecialApiObjectType);
  if (!is_valid) {
    return nullptr;
  }
  Trivial* wrapped = static_cast<Trivial*>(
      object->GetAlignedPointerFromInternalField(kV8WrapperObjectIndex));
  CHECK_NOT_NULL(wrapped);
  return wrapped;
}

void FastCallback2JSArray(v8::Local<v8::Object> receiver, int arg0,
                          v8::Local<v8::Array> arg1) {
  Trivial* self = UnwrapTrivialObject(receiver);
  CHECK_NOT_NULL(self);
  CHECK_EQ(arg0, arg1->Length());
  self->set_x(arg0);
}

void FastCallback3SwappedParams(v8::Local<v8::Object> receiver,
                                v8::Local<v8::Array> arg0, int arg1) {}

void FastCallback4Scalar(v8::Local<v8::Object> receiver, int arg0, float arg1) {
}

void FastCallback5DifferentArity(v8::Local<v8::Object> receiver, int arg0,
                                 v8::Local<v8::Array> arg1, float arg2) {}

}  // namespace
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)

START_ALLOW_USE_DEPRECATED()
TEST(FastApiOverloadResolution) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::FlagList::EnforceFlagImplications();

  v8::CFunction js_array_callback =
      v8::CFunctionBuilder().Fn(FastCallback2JSArray).Build();

  v8::
### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第34部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
::kNoException,
                         expected_path_for_64bit_test, v8_num(-0.0));

  // TODO(mslekova): We deopt for unsafe integers, but ultimately we want to
  // stay on the fast path.
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(1ull << 63));
  CallAndCheck<int64_t>(
      std::numeric_limits<int64_t>::min(), Behavior::kNoException,
      ApiCheckerResult::kSlowCalled,
      v8_num(static_cast<double>(std::numeric_limits<int64_t>::max()) + 3.14));
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(static_cast<double>(1ull << 63)));
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(-static_cast<double>(1ll << 63)));
  CallAndCheck<uint64_t>(1ull << 63, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8_num(static_cast<double>(1ull << 63)));

  // Corner cases - float and double
#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  // Source:
  // https://en.wikipedia.org/wiki/Single-precision_floating-point_format#Precision_limitations_on_integer_values
  constexpr float kMaxSafeFloat = 16777215;  // 2^24-1
  CallAndCheck<float>(std::numeric_limits<float>::min(), Behavior::kNoException,
                      ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::min()));
  CallAndCheck<float>(-kMaxSafeFloat, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(-kMaxSafeFloat));
  CallAndCheck<float>(-0.0f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(-0.0));
  CallAndCheck<float>(0.0f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(0.0));
  CallAndCheck<float>(kMaxSafeFloat, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(kMaxSafeFloat));
  CallAndCheck<float>(std::numeric_limits<float>::max(), Behavior::kNoException,
                      ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::max()));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::quiet_NaN()));
  CallAndCheck<float>(std::numeric_limits<float>::infinity(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::infinity()));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      v8_str("some_string"));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      CompileRun("new Proxy({}, {});"));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      v8::Object::New(isolate));
  CallAndCheck<float>(0, Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      v8::Array::New(isolate));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kException, ApiCheckerResult::kSlowCalled,
                      v8::BigInt::New(isolate, 42));
  CallAndCheck<float>(-std::numeric_limits<float>::infinity(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(-std::numeric_limits<double>::max()));
  CallAndCheck<float>(std::numeric_limits<float>::infinity(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<double>::max()));
  CallAndCheck<float>(kMaxSafeFloat + 1.0f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled,
                      v8_num(static_cast<double>(kMaxSafeFloat) + 2.0));

  CallAndCheck<double>(std::numeric_limits<double>::min(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::min()));
  CallAndCheck<double>(-i::kMaxSafeInteger, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled,
                       v8_num(-i::kMaxSafeInteger));
  CallAndCheck<double>(std::numeric_limits<float>::min(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<float>::min()));
  CallAndCheck<double>(-0.0, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled, v8_num(-0.0));
  CallAndCheck<double>(0.0, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled, v8_num(0.0));
  CallAndCheck<double>(std::numeric_limits<float>::max(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<float>::max()));
  CallAndCheck<double>(i::kMaxSafeInteger, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled,
                       v8_num(i::kMaxSafeInteger));
  CallAndCheck<double>(i::kMaxSafeInteger + 1, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled,
                       v8_num(i::kMaxSafeInteger + 1));
  CallAndCheck<double>(std::numeric_limits<double>::max(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::max()));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::quiet_NaN()));
  CallAndCheck<double>(std::numeric_limits<double>::infinity(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::infinity()));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       v8_str("some_string"));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       CompileRun("new Proxy({}, {});"));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       v8::Object::New(isolate));
  CallAndCheck<double>(0, Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       v8::Array::New(isolate));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kException, ApiCheckerResult::kSlowCalled,
                       v8::BigInt::New(isolate, 42));
#endif

  // Corner cases - bool
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Undefined(isolate));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Null(isolate));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_num(0));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_num(42));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_str(""));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_str("some_string"));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Symbol::New(isolate));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled,
                     v8::BigInt::New(isolate, 0));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled,
                     v8::BigInt::New(isolate, 42));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Object::New(isolate));

  // Test return values
  CheckFastReturnValue<bool>(v8::Boolean::New(isolate, true),
                             ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<bool>(v8::Boolean::New(isolate, false),
                             ApiCheckerResult::kFastCalled);

  CheckFastReturnValue<int32_t>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<int32_t>(v8_num(std::numeric_limits<int32_t>::min()),
                                ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<int32_t>(v8_num(std::numeric_limits<int32_t>::max()),
                                ApiCheckerResult::kFastCalled);

  CheckFastReturnValue<uint32_t>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<uint32_t>(v8_num(std::numeric_limits<uint32_t>::min()),
                                 ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<uint32_t>(v8_num(std::numeric_limits<uint32_t>::max()),
                                 ApiCheckerResult::kFastCalled);

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  CheckFastReturnValue<float>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(-0.0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::quiet_NaN()),
                              ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::infinity()),
                              ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::min()),
                              ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::max()),
                              ApiCheckerResult::kFastCalled);

  CheckFastReturnValue<double>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(-0.0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::quiet_NaN()),
                               ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::infinity()),
                               ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::min()),
                               ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::max()),
                               ApiCheckerResult::kFastCalled);
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE

  // Check for the deopt loop protection
  CallAndDeopt();

  // Test callbacks without options
  CallNoOptions(42);

  // Test callback requesting access checks
  CallNoConvertReceiver(42);

  CheckDynamicTypeInfo();

  // Throw an exception.
  CallAndCheck<int32_t>(42, Behavior::kException, ApiCheckerResult::kFastCalled,
                        v8_num(42), Behavior::kException);

  CallAndCheck<int32_t>(44, Behavior::kNoException,
                        ApiCheckerResult::kFastCalled, v8_num(44),
                        Behavior::kNoException);

  // Wrong number of arguments
  CallWithLessArguments();
  CallWithMoreArguments();

  // Wrong types of receiver
  CallWithUnexpectedReceiverType(v8_num(123));
  CallWithUnexpectedReceiverType(v8_str("str"));
  CallWithUnexpectedReceiverType(CompileRun("new Proxy({}, {});"));

  // Wrong types for argument of type object
  CallWithUnexpectedObjectType(v8_num(123));
  CallWithUnexpectedObjectType(v8_str("str"));
  CallWithUnexpectedObjectType(CompileRun("new Proxy({}, {});"));

  CheckApiObjectArg();
  CheckFastCallsWithConstructor();

  // TODO(mslekova): Restructure the tests so that the fast optimized calls
  // are compared against the slow optimized calls.
  // TODO(mslekova): Add tests for FTI that requires access check.
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
}

template <typename Ret, v8::CFunctionInfo::Int64Representation Int64Repr =
                            v8::CFunctionInfo::Int64Representation::kNumber>
struct SeqOneByteStringChecker {
  static void Test(std::function<Ret()> f) {
    LocalContext env;
    v8::Isolate* isolate = CcTest::isolate();

    static v8::CFunction c_function =
        v8::CFunction::Make(FastCallback, Int64Repr);
    v8::Local<v8::FunctionTemplate> checker_templ = v8::FunctionTemplate::New(
        isolate, SlowCallback, {}, {}, 1, v8::ConstructorBehavior::kThrow,
        v8::SideEffectType::kHasSideEffect, &c_function);

    v8::Local<v8::ObjectTemplate> object_template =
        v8::ObjectTemplate::New(isolate);
    object_template->SetInternalFieldCount(kV8WrapperObjectIndex + 1);
    object_template->Set(isolate, "api_func", checker_templ);

    SeqOneByteStringChecker checker{f};

    v8::Local<v8::Object> object =
        object_template->NewInstance(env.local()).ToLocalChecked();
    object->SetAlignedPointerInInternalField(kV8WrapperObjectIndex,
                                             reinterpret_cast<void*>(&checker));
    CHECK((*env)
              ->Global()
              ->Set(env.local(), v8_str("receiver"), object)
              .FromJust());

    v8::TryCatch try_catch(isolate);
    CompileRun(
        "function func(arg) { return receiver.api_func(arg); }"
        "%PrepareFunctionForOptimization(func);"
        "func('');");
    CHECK(!try_catch.HasCaught());
    CHECK(checker.DidCallSlow());
    checker.Reset();

    CompileRun(
        "%OptimizeFunctionOnNextCall(func);"
        "const fastr = func('');");
    CHECK(!try_catch.HasCaught());
    CHECK(checker.DidCallFast());
    checker.Reset();

    // Call func with two-byte string to take slow path
    CompileRun("const slowr = func('\\u{1F4A9}');");
    CHECK(!try_catch.HasCaught());
    CHECK(checker.DidCallSlow());

    if constexpr (std::is_same_v<Ret, void*>) {
      CompileRun(
          "if (typeof slowr !== 'object') { throw new Error(`${slowr} is not "
          "object`) }");
    } else {
      CompileRun(
          "if (!Object.is(fastr, slowr)) { throw new Error(`${slowr} is not "
          "${fastr}`); }");
    }
    CHECK(!try_catch.HasCaught());
  }

  static Ret FastCallback(v8::Local<v8::Object> receiver,
                          const v8::FastOneByteString& string) {
    SeqOneByteStringChecker* receiver_ptr =
        GetInternalField<SeqOneByteStringChecker>(*receiver);
    receiver_ptr->result_ |= ApiCheckerResult::kFastCalled;

    return receiver_ptr->func_();
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Object* receiver_obj = v8::Object::Cast(*info.This());
    SeqOneByteStringChecker* receiver_ptr =
        GetInternalField<SeqOneByteStringChecker>(receiver_obj);
    receiver_ptr->result_ |= ApiCheckerResult::kSlowCalled;

    CHECK(info[0]->IsString());
    if constexpr (std::is_void<Ret>::value) {
      // do nothing
    } else if constexpr (std::is_same_v<Ret, void*>) {
      info.GetReturnValue().Set(
          v8::External::New(info.GetIsolate(), receiver_ptr->func_()));
    } else if constexpr (sizeof(Ret) == 8 &&
                         Int64Repr ==
                             v8::CFunctionInfo::Int64Representation::kBigInt) {
      if constexpr (std::is_same_v<Ret, int64_t>) {
        info.GetReturnValue().Set(
            v8::BigInt::New(info.GetIsolate(), receiver_ptr->func_()));
      } else {
        info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(
            info.GetIsolate(), receiver_ptr->func_()));
      }
    } else if constexpr (std::is_same_v<Ret, uint64_t>) {
      info.GetReturnValue().Set(v8::Number::New(
          info.GetIsolate(), static_cast<double>(receiver_ptr->func_())));
    } else {
      info.GetReturnValue().Set(receiver_ptr->func_());
    }
  }

  explicit SeqOneByteStringChecker(std::function<Ret()> f) : func_(f) {}

  bool DidCallFast() const { return (result_ & ApiCheckerResult::kFastCalled); }
  bool DidCallSlow() const { return (result_ & ApiCheckerResult::kSlowCalled); }

  void Reset() { result_ = ApiCheckerResult::kNotCalled; }

 private:
  std::function<Ret()> func_;
  ApiCheckerResultFlags result_ = ApiCheckerResult::kNotCalled;
};

TEST(FastApiCallsString) {
#if !defined(V8_LITE_MODE) &&                          \
    !defined(V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS) && \
    defined(V8_ENABLE_TURBOFAN)
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  i::v8_flags.fast_api_allow_float_in_sim = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);
  LocalContext env;

  SeqOneByteStringChecker<void>::Test([]() {});

  SeqOneByteStringChecker<void*>::Test(
      []() { return reinterpret_cast<void*>(0xFF); });

  SeqOneByteStringChecker<bool>::Test([]() { return true; });
  SeqOneByteStringChecker<bool>::Test([]() { return false; });

  SeqOneByteStringChecker<int32_t>::Test([]() { return 0; });
  SeqOneByteStringChecker<int32_t>::Test(
      []() { return std::numeric_limits<int32_t>::min(); });
  SeqOneByteStringChecker<int32_t>::Test(
      []() { return std::numeric_limits<int32_t>::max(); });

  SeqOneByteStringChecker<uint32_t>::Test([]() { return 0; });
  SeqOneByteStringChecker<uint32_t>::Test(
      []() { return std::numeric_limits<uint32_t>::min(); });
  SeqOneByteStringChecker<uint32_t>::Test(
      []() { return std::numeric_limits<uint32_t>::max(); });

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  SeqOneByteStringChecker<float>::Test([]() { return 0; });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::quiet_NaN(); });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::infinity(); });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::min(); });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::max(); });

  SeqOneByteStringChecker<double>::Test([]() { return 0; });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::quiet_NaN(); });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::infinity(); });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::min(); });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::max(); });
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE

#ifdef V8_TARGET_ARCH_64_BIT
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return std::numeric_limits<int64_t>::min();
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    // The highest int64_t representable as double.
    return 0x7ffffffffffff000L;
  });

  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<int64_t>::min();
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<int64_t>::max();
  });

  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return std::numeric_limits<uint64_t>::min();
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    // The highest uint64 representable as double.
    return 0xfffffffffffff000UL;
  });

  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<uint64_t>::min();
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<uint64_t>::max();
  });
#endif  // V8_TARGET_ARCH_64_BIT

#endif  // !defined(V8_LITE_MODE) &&
        // !defined(V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS) &&
        // defined(V8_ENABLE_TURBOFAN)
}

#if V8_ENABLE_WEBASSEMBLY
TEST(FastApiCallsFromWasm) {
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.liftoff = false;
  i::v8_flags.turboshaft_wasm = true;
  i::v8_flags.wasm_fast_api = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.wasm_lazy_compilation = true;
  i::v8_flags.fast_api_allow_float_in_sim = true;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);
  LocalContext env;

  CallAndCheckFromWasm();
}
#endif
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
namespace {
static Trivial* UnwrapTrivialObject(Local<Object> object) {
  i::Address addr = i::ValueHelper::ValueAsAddress(*object);
  auto instance_type = i::Internals::GetInstanceType(addr);
  bool is_valid =
      (v8::base::IsInRange(instance_type, i::Internals::kFirstJSApiObjectType,
                           i::Internals::kLastJSApiObjectType) ||
       instance_type == i::Internals::kJSSpecialApiObjectType);
  if (!is_valid) {
    return nullptr;
  }
  Trivial* wrapped = static_cast<Trivial*>(
      object->GetAlignedPointerFromInternalField(kV8WrapperObjectIndex));
  CHECK_NOT_NULL(wrapped);
  return wrapped;
}

void FastCallback2JSArray(v8::Local<v8::Object> receiver, int arg0,
                          v8::Local<v8::Array> arg1) {
  Trivial* self = UnwrapTrivialObject(receiver);
  CHECK_NOT_NULL(self);
  CHECK_EQ(arg0, arg1->Length());
  self->set_x(arg0);
}

void FastCallback3SwappedParams(v8::Local<v8::Object> receiver,
                                v8::Local<v8::Array> arg0, int arg1) {}

void FastCallback4Scalar(v8::Local<v8::Object> receiver, int arg0, float arg1) {
}

void FastCallback5DifferentArity(v8::Local<v8::Object> receiver, int arg0,
                                 v8::Local<v8::Array> arg1, float arg2) {}

}  // namespace
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)

START_ALLOW_USE_DEPRECATED()
TEST(FastApiOverloadResolution) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::FlagList::EnforceFlagImplications();

  v8::CFunction js_array_callback =
      v8::CFunctionBuilder().Fn(FastCallback2JSArray).Build();

  v8::CFunction swapped_params_callback =
      v8::CFunctionBuilder().Fn(FastCallback3SwappedParams).Build();

  // Check that difference in > 1 position is not possible.
  CHECK_EQ(v8::CFunction::OverloadResolution::kImpossible,
           js_array_callback.GetOverloadResolution(&swapped_params_callback));

  v8::CFunction scalar_callback =
      v8::CFunctionBuilder().Fn(FastCallback4Scalar).Build();

  // Check that resolving when there is a scalar at the difference position
  // is not possible.
  CHECK_EQ(v8::CFunction::OverloadResolution::kImpossible,
           js_array_callback.GetOverloadResolution(&scalar_callback));

  v8::CFunction diff_arity_callback =
      v8::CFunctionBuilder().Fn(FastCallback5DifferentArity).Build();

  // Check that overload resolution between different number of arguments
  // is possible.
  CHECK_EQ(v8::CFunction::OverloadResolution::kAtCompileTime,
           js_array_callback.GetOverloadResolution(&diff_arity_callback));

#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
}
END_ALLOW_USE_DEPRECATED()

TEST(Recorder_GetContext) {
  using v8::Context;
  using v8::Local;
  using v8::MaybeLocal;

  // Set up isolate and context.
  v8::Isolate* iso = CcTest::isolate();

  v8::metrics::Recorder::ContextId original_id;
  std::vector<v8::metrics::Recorder::ContextId> ids;
  {
    v8::HandleScope scope(iso);
    Local<Context> context = Context::New(iso);

    // Ensure that we get a valid context id.
    original_id = v8::metrics::Recorder::GetContextId(context);
    CHECK(!original_id.IsEmpty());

    // Request many context ids to ensure correct growth behavior.
    for (size_t count = 0; count < 50; ++count) {
      Local<Context> temp_context = Context::New(iso);
      ids.push_back(v8::metrics::Recorder::GetContextId(temp_context));
    }
    for (const v8::metrics::Recorder::ContextId& id : ids) {
      CHECK(!v8::metrics::Recorder::GetContext(iso, id).IsEmpty());
    }

    // Ensure that we can get the context from the context id.
    MaybeLocal<Context> retrieved_context =
        v8::metrics::Recorder::GetContext(iso, original_id);
    CHECK_EQ(context, retrieved_context.ToLocalChecked());

    // Ensure that an empty context id returns an empty handle.
    retrieved_context = v8::metrics::Recorder::GetContext(
        iso, v8::metrics::Recorder::ContextId::Empty());
    CHECK(retrieved_context.IsEmpty());

    // Ensure that repeated context id accesses return the same context id.
    v8::metrics::Recorder::ContextId new_id =
        v8::metrics::Recorder::GetContextId(context);
    CHECK_EQ(original_id, new_id);
  }

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    // Invalidate the context and therefore the context id.
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  }

  // Ensure that a stale context id returns an empty handle.
  {
    v8::HandleScope scope(iso);
    MaybeLocal<Context> retrieved_context =
        v8::metrics::Recorder::GetContext(iso, original_id);
    CHECK(retrieved_context.IsEmpty());

    for (const v8::metrics::Recorder::ContextId& id : ids) {
      CHECK(v8::metrics::Recorder::GetContext(iso, id).IsEmpty());
    }
  }
}

namespace {

class MetricsRecorder : public v8::metrics::Recorder {
 public:
  v8::Isolate* isolate_;
  size_t count_ = 0;
  size_t module_count_ = 0;
  int64_t time_in_us_ = -1;

  explicit MetricsRecorder(v8::Isolate* isolate) : isolate_(isolate) {}

  void AddMainThreadEvent(const v8::metrics::WasmModuleDecoded& event,
                          v8::metrics::Recorder::ContextId id) override {
    if (v8::metrics::Recorder::GetContext(isolate_, id).IsEmpty()) return;
    ++count_;
    time_in_us_ = event.wall_clock_duration_in_us;
  }

  void AddThreadSafeEvent(
      const v8::metrics::WasmModulesPerIsolate& event) override {
    ++count_;
    module_count_ = event.count;
  }
};

}  // namespace

TEST(TriggerMainThreadMetricsEvent) {
  using v8::Context;
  using v8::Local;
  using v8::MaybeLocal;

  // Set up isolate and context.
  v8::Isolate* iso = CcTest::isolate();
  i::Isolate* i_iso = reinterpret_cast<i::Isolate*>(iso);
  CHECK(i_iso->metrics_recorder());
  v8::metrics::WasmModuleDecoded event;
  v8::metrics::Recorder::ContextId context_id;
  std::shared_ptr<MetricsRecorder> recorder =
      std::make_shared<MetricsRecorder>(iso);
  iso->SetMetricsRecorder(recorder);
  {
    v8::HandleScope scope(iso);
    Local<Context> context = Context::New(iso);
    context_id = v8::metrics::Recorder::GetContextId(context);

    // Check that event submission works.
    {
      i::metrics::TimedScope<v8::metrics::WasmModuleDecoded> timed_scope(
          &event);
      v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));
    }
    i_iso->metrics_recorder()->AddMainThreadEvent(event, context_id);
    CHECK_EQ(recorder->count_, 1);  // Increased.
    CHECK_GT(recorder->time_in_us_, 100);
  }

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  }

  // Check that event submission doesn't break even if the context id is
  // invalid.
  i_iso->metrics_recorder()->AddMainThreadEvent(event, context_id);
  CHECK_EQ(recorder->count_, 1);  // Unchanged.
}

TEST(TriggerDelayedMainThreadMetricsEvent) {
  using v8::Context;
  using v8::Local;
  using v8::MaybeLocal;
  i::v8_flags.stress_concurrent_allocation = false;

  // Set up isolate and context.
  v8::Isolate* iso = CcTest::isolate();
  i::Isolate* i_iso = reinterpret_cast<i::Isolate*>(iso);
  CHECK(i_iso->metrics_recorder());
  v8::metrics::WasmModuleDecoded event;
  v8::metrics::Recorder::ContextId context_id;
  std::shared_ptr<MetricsRecorder> recorder =
      std::make_shared<MetricsRecorder>(iso);
  iso->SetMetricsRecorder(recorder);
  {
    v8::HandleScope scope(iso);
    Local<Context> context = Context::New(iso);
    context_id = v8::metrics::Recorder::GetContextId(context);

    // Check that event submission works.
    {
      i::metrics::TimedScope<v8::metrics::WasmModuleDecoded> timed_scope(
          &event);
      v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));
    }
    i_iso->metrics_recorder()->DelayMainThreadEvent(event, context_id);
    CHECK_EQ(recorder->count_, 0);        // Unchanged.
    CHECK_EQ(recorder->time_in_us_, -1);  // Unchanged.
    v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(1100));
    while (v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(), iso)) {
    }
    CHECK_EQ(recorder->count_, 1);  // Increased.
    CHECK_GT(recorder->time_in_us_, 100);
  }

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  }

  // Check that event submission doesn't break even if the context id is
  // invalid.
  i_iso->metrics_recorder()->DelayMainThreadEvent(event, context_id);
  v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(1100));
  while (v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(), iso)) {
  }
  CHECK_EQ(recorder->count_, 1);  // Unchanged.
}

TEST(TriggerThreadSafeMetricsEvent) {
  // Set up isolate and context.
  v8::Isolate* iso = CcTest::isolate();
  i::Isolate* i_iso = reinterpret_cast<i::Isolate*>(iso);
  CHECK(i_iso->metrics_recorder());
  v8::metrics::WasmModulesPerIsolate event;
  std::shared_ptr<MetricsRecorder> recorder =
      std::make_shared<MetricsRecorder>(iso);
  iso->SetMetricsRecorder(recorder);

  // Check that event submission works.
  event.count = 42;
  i_iso->metrics_recorder()->AddThreadSafeEvent(event);
  CHECK_EQ(recorder->count_, 1);  // Increased.
  CHECK_EQ(recorder->module_count_, 42);
}

void SetupCodeLike(LocalContext* env, const char* name,
                   v8::Local<v8::FunctionTemplate> to_string,
                   bool is_code_like) {
  // Setup a JS construct
```