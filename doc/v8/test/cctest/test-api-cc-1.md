Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite.

Here's a breakdown of the code and its purpose:

1. **String Creation and Internalization:** Tests the creation of internalized strings, which are unique string objects in V8's heap. It involves creating a string, triggering garbage collection to move it to old generation, and then internalizing it.

2. **External String Resources:** Defines custom resource classes (`RandomLengthResource`, `RandomLengthOneByteResource`) that simulate external string data with a specific length.

3. **External String Creation Limits:** Tests the behavior of creating very long external strings (near the 2GB limit). It checks that the creation fails gracefully without crashing or throwing exceptions.

4. **Scavenging External Strings:** Focuses on garbage collection behavior with external strings. It tests how minor and major garbage collections affect external strings and verifies that the `Dispose` method of the external resource is called when the string is no longer needed. This includes scenarios for both two-byte and one-byte strings. It also explores the impact of conservative stack scanning on garbage collection.

5. **External String Resource Disposal Control:** Introduces a more sophisticated external string resource (`TestOneByteResourceWithDisposeControl`) where the disposal can be controlled. It tests how V8 handles the disposal of these resources during garbage collection, especially when the resource is stack-allocated versus heap-allocated. It ensures that the `Dispose` method is called appropriately, and that double deletion is avoided.

6. **String Concatenation with External Strings:** Tests the concatenation of various types of strings (internal one-byte, internal two-byte, external one-byte, external two-byte). It verifies that string concatenation works correctly even when external strings are involved.

7. **Global Properties:** Tests the ability to set and retrieve properties on the global object in a V8 context.

8. **Function Callbacks:** Introduces various function callbacks (`handle_callback`, `handle_callback_2`, `construct_callback`, `Return239Callback`) used for testing interactions between JavaScript and C++. These callbacks demonstrate setting return values and manipulating the `this` object. It also includes basic fuzzing and validation checks within the callbacks.

9. **Function Templates:**  Extensively tests `v8::FunctionTemplate`, which is used to create JavaScript functions from C++. This includes:
    - Setting call handlers.
    - Setting up constructor behavior.
    - Adding properties to the prototype.
    - Setting native data properties with accessors.
    - Testing function templates with proxies.

10. **Simple Callbacks:** Tests basic function callbacks using `v8::ObjectTemplate::Set`.

11. **Fast Return Values:** Explores optimized return value handling from C++ callbacks to JavaScript. It tests returning various primitive types (int32_t, uint32_t, double, bool, null, undefined, empty string) and objects.

12. **Function Template Length:** Tests the `SetLength` method of `v8::FunctionTemplate`, which allows specifying the expected number of arguments for a JavaScript function.

13. **External Pointer Wrapping:** Tests the ability to associate external C++ data with JavaScript objects using `v8::External`. It verifies that the correct pointer can be retrieved within a callback function. It also tests wrapping various types of pointers, including aligned, unaligned, stack-allocated, heap-allocated, and potentially invalid addresses.

14. **Prototype Chain Traversal (`FindInstanceInPrototypeChain`):**  Tests the `FindInstanceInPrototypeChain` method, which allows checking if an object is an instance of a specific function template by traversing its prototype chain. It also checks the interaction with proxies.

15. **Integer Creation (`TinyInteger`, `BigSmiInteger`, `BigInteger`, `TinyUnsignedInteger`, `BigUnsignedSmiInteger`, `BigUnsignedInteger`, `OutOfSignedRangeUnsignedInteger`):** Tests the creation of different kinds of integer objects in V8, including small integers (Smis), larger integers that fit in signed and unsigned 32-bit integers, and numbers that exceed the range of signed integers but fit within unsigned integers.

Based on this analysis, here's a summary of the functionality of the provided code snippet:
This code snippet from `v8/test/cctest/test-api.cc` focuses on testing various aspects of V8's C++ API related to **string handling, garbage collection, and function/object creation with callbacks and templates**.

Here's a breakdown of its key functionalities:

* **String Creation and Management:**
    * **Internalized Strings:** Tests the creation and management of internalized strings, which are unique string objects within V8's heap. This ensures efficient string comparison and memory usage.
    * **External Strings:**  Extensively tests the creation and handling of external strings. These are strings whose data is stored outside of V8's managed heap. This is crucial for integrating with external libraries and data sources. The tests cover:
        * Creating external strings with different encodings (one-byte and two-byte).
        * Handling very large external strings (testing memory allocation limits).
        * **Garbage Collection of External Strings:** Verifies that external string resources are correctly disposed of when the string is no longer needed, both during minor (scavenge) and major garbage collection cycles. It tests the interaction with conservative stack scanning.
        * **Controlling Disposal:**  Tests scenarios where the disposal of the external resource is explicitly managed.
    * **String Concatenation:** Checks if string concatenation works correctly when combining internal and external strings with different encodings.

* **Global Object Interaction:** Tests setting and getting properties on the global object.

* **Function Callbacks:**
    * **Basic Callbacks:** Tests simple function callbacks from JavaScript to C++.
    * **Callbacks with Return Values:**  Verifies that return values from C++ callbacks are correctly passed back to JavaScript.
    * **Constructor Callbacks:** Tests callbacks used for object construction.
    * **Property Callbacks (Accessors):** Demonstrates how to define property accessors using callbacks.
    * **Callbacks with Fuzzing and Validation:** Includes basic checks to validate the `FunctionCallbackInfo` and a call to a fuzzer.

* **Function Templates:**
    * **Creating Functions from Templates:** Tests the creation of JavaScript functions using `v8::FunctionTemplate`.
    * **Setting Call Handlers:** Verifies that callbacks associated with function templates are invoked correctly.
    * **Constructor Behavior:**  Tests the use of function templates as constructors.
    * **Prototype Manipulation:** Shows how to set properties on the prototype of functions created from templates.
    * **Native Data Properties:** Demonstrates how to associate native data (using accessors) with objects created from function templates.
    * **Function Templates with Proxies:**  Tests the interaction between function templates and JavaScript proxies.
    * **Setting Function Length:** Checks the ability to define the `length` property of functions created from templates.

* **Fast Return Value Optimization:** Tests optimized mechanisms for returning values from C++ callbacks to JavaScript, covering various data types (integers, doubles, booleans, null, undefined, empty string, and objects).

* **External Data Wrapping:** Tests the ability to associate external C++ data pointers with JavaScript objects using `v8::External`. It verifies that the correct pointer can be retrieved in callbacks.

* **Prototype Chain Inspection:** Tests the `FindInstanceInPrototypeChain` method, which allows checking if an object is an instance of a specific function template by traversing its prototype chain, including scenarios with proxies.

* **Integer Object Creation:** Tests the creation of different types of integer objects in V8, including:
    * Small integers (Smis).
    * Larger signed and unsigned 32-bit integers.
    * Integers outside the range of signed 32-bit integers but within the unsigned range.

**If `v8/test/cctest/test-api.cc` ended with `.tq`, it would be a V8 Torque source code file.** Torque is V8's internal language for implementing built-in JavaScript functions and runtime operations. The current file is C++, part of the testing infrastructure.

**Relationship with JavaScript and Examples:**

Many of the functionalities tested in this C++ code directly relate to how JavaScript code interacts with V8's underlying C++ implementation. Here are some examples:

* **Internalized Strings:** When you have the same string literal used multiple times in JavaScript, V8 often internalizes it to save memory.
    ```javascript
    const str1 = "hello";
    const str2 = "hello";
    // In V8, str1 and str2 might point to the same internalized string object.
    ```

* **External Strings:** When you load a large text file or interact with external data, V8 might use external strings to avoid copying the entire data into its heap.
    ```javascript
    // Imagine reading a large file:
    // const largeText = readLargeFile();
    // V8 might represent largeText as an external string.
    ```

* **Function Callbacks:** This is the core mechanism for extending JavaScript with native code.
    ```javascript
    // Let's say you have a C++ function registered as 'nativeAdd' in V8.
    const result = nativeAdd(5, 3); // This calls the C++ callback.
    ```

* **Function Templates:** Used extensively to define the structure and behavior of JavaScript classes and functions implemented in C++.
    ```javascript
    class MyClass {
      constructor(value) {
        this.internalValue = value;
      }
      getValue() {
        return this.internalValue;
      }
    }
    // The behavior of 'MyClass' and its methods might be defined using function templates in C++.
    const obj = new MyClass(10);
    console.log(obj.getValue());
    ```

* **Fast Return Values:** Optimizes the performance of calling native functions. If a C++ function can return a simple value quickly, V8 can avoid the overhead of creating a full JavaScript object.

* **External Data Wrapping:**  Allows you to pass raw C++ pointers to JavaScript and back. This is often used for interacting with native APIs.
    ```javascript
    // Imagine you have a C++ object and you want to access it from JavaScript.
    // const nativeObjectPtr = getNativeObject();
    // You could wrap nativeObjectPtr using v8::External and pass it to JavaScript.
    ```

**Code Logic Reasoning (Hypothetical Example):**

Let's take the `ScavengeExternalString` test as an example:

**Hypothetical Input:**
1. Create an external two-byte string in the young generation of the heap.
2. Perform a minor GC.

**Expected Output:**
1. The external string object might be promoted to the old generation during the minor GC if it survives.
2. The `dispose_count` for the associated external resource should remain 0 after the minor GC, as the string is still reachable.
3. After a subsequent major GC (without the string being referenced anymore), the `Dispose` method of the external resource should be called, and `dispose_count` should become 1.

**User Common Programming Errors:**

* **Incorrectly Managing External Resources:** A common error is failing to properly manage the lifecycle of resources associated with external strings. If the `Dispose` method is not implemented correctly or if the resource is prematurely freed, it can lead to crashes or memory corruption.
    ```c++
    // Potential error: Not freeing the memory in the Dispose method.
    class BadResource : public v8::String::ExternalOneByteStringResource {
     public:
      BadResource(char* data, size_t length) : data_(data), length_(length) {}
      const char* data() const override { return data_; }
      size_t length() const override { return length_; }
      void Dispose() override {
        // Oops, forgot to delete data_!
      }
     private:
      char* data_;
      size_t length_;
    };
    ```

* **Memory Leaks with External Strings:** If an external string is created but the associated resource is never released (even after the string is no longer used in JavaScript), it can lead to memory leaks outside of V8's managed heap.

* **Accessing Disposed Resources:**  Trying to access the data of an external string after its resource has been disposed of will lead to undefined behavior.

**Summary of Functionality (Part 2):**

This second part of the `test-api.cc` file primarily focuses on **testing the creation, management, and garbage collection of various types of strings (especially external strings), the interaction between JavaScript and C++ through function callbacks and templates (including optimizations like fast returns), and the ability to associate external data with JavaScript objects.** It ensures that V8's C++ API functions as expected in these areas and helps to catch potential issues related to memory management, resource handling, and the correct execution of native code within the V8 environment.

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
one_byte_string)))
            .ToLocalChecked();
    i::Handle<i::String> istring = v8::Utils::OpenHandle(*string);
    // Trigger GCs so that the newly allocated string moves to old gen.
    i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
    i::DirectHandle<i::String> isymbol = factory->InternalizeString(istring);
    CHECK(IsInternalizedString(*isymbol));
  }
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
}


class RandomLengthResource : public v8::String::ExternalStringResource {
 public:
  explicit RandomLengthResource(int length) : length_(length) {}
  const uint16_t* data() const override { return string_; }
  size_t length() const override { return length_; }

 private:
  uint16_t string_[10];
  int length_;
};


class RandomLengthOneByteResource
    : public v8::String::ExternalOneByteStringResource {
 public:
  explicit RandomLengthOneByteResource(int length) : length_(length) {}
  const char* data() const override { return string_; }
  size_t length() const override { return length_; }

 private:
  char string_[10];
  int length_;
};


THREADED_TEST(NewExternalForVeryLongString) {
  auto isolate = CcTest::isolate();
  {
    v8::HandleScope scope(isolate);
    v8::TryCatch try_catch(isolate);
    RandomLengthOneByteResource r(1 << 30);
    v8::MaybeLocal<v8::String> maybe_str =
        v8::String::NewExternalOneByte(isolate, &r);
    CHECK(maybe_str.IsEmpty());
    CHECK(!try_catch.HasCaught());
  }

  {
    v8::HandleScope scope(isolate);
    v8::TryCatch try_catch(isolate);
    RandomLengthResource r(1 << 30);
    v8::MaybeLocal<v8::String> maybe_str =
        v8::String::NewExternalTwoByte(isolate, &r);
    CHECK(maybe_str.IsEmpty());
    CHECK(!try_catch.HasCaught());
  }
}

TEST(ScavengeExternalString) {
  i::ManualGCScope manual_gc_scope;
  i::v8_flags.stress_compaction = false;
  i::v8_flags.gc_global = false;

  int dispose_count = 0;
  bool in_young_generation = false;
  {
    v8::HandleScope scope(CcTest::isolate());
    uint16_t* two_byte_string = AsciiToTwoByteString("test string");
    Local<String> string =
        String::NewExternalTwoByte(
            CcTest::isolate(),
            new TestResource(two_byte_string, &dispose_count))
            .ToLocalChecked();
    i::DirectHandle<i::String> istring = v8::Utils::OpenDirectHandle(*string);
    i::heap::InvokeMinorGC(CcTest::heap());
    in_young_generation = i::HeapLayout::InYoungGeneration(*istring);
    CHECK_IMPLIES(!in_young_generation,
                  CcTest::heap()->old_space()->Contains(*istring));
    CHECK_EQ(0, dispose_count);
  }
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    in_young_generation ? i::heap::InvokeMinorGC(CcTest::heap())
                        : i::heap::InvokeMajorGC(CcTest::heap());
  }
  CHECK_EQ(1, dispose_count);
}

TEST(ScavengeExternalOneByteString) {
  i::ManualGCScope manual_gc_scope;
  i::v8_flags.stress_compaction = false;
  i::v8_flags.gc_global = false;

  int dispose_count = 0;
  bool in_young_generation = false;
  {
    v8::HandleScope scope(CcTest::isolate());
    const char* one_byte_string = "test string";
    Local<String> string =
        String::NewExternalOneByte(
            CcTest::isolate(),
            new TestOneByteResource(i::StrDup(one_byte_string), &dispose_count))
            .ToLocalChecked();
    i::DirectHandle<i::String> istring = v8::Utils::OpenDirectHandle(*string);
    i::heap::InvokeMinorGC(CcTest::heap());
    in_young_generation = i::HeapLayout::InYoungGeneration(*istring);
    CHECK_IMPLIES(!in_young_generation,
                  CcTest::heap()->old_space()->Contains(*istring));
    CHECK_EQ(0, dispose_count);
  }
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    in_young_generation ? i::heap::InvokeMinorGC(CcTest::heap())
                        : i::heap::InvokeMajorGC(CcTest::heap());
  }
  CHECK_EQ(1, dispose_count);
}


class TestOneByteResourceWithDisposeControl : public TestOneByteResource {
 public:
  // Only used by non-threaded tests, so it can use static fields.
  static int dispose_calls;
  static int dispose_count;

  TestOneByteResourceWithDisposeControl(const char* data, bool dispose)
      : TestOneByteResource(data, &dispose_count), dispose_(dispose) {}

  void Dispose() override {
    ++dispose_calls;
    if (dispose_) delete this;
  }
 private:
  bool dispose_;
};


int TestOneByteResourceWithDisposeControl::dispose_count = 0;
int TestOneByteResourceWithDisposeControl::dispose_calls = 0;


TEST(ExternalStringWithDisposeHandling) {
  const char* c_source = "1 + 2 * 3";

  // Use a stack allocated external string resource allocated object.
  TestOneByteResourceWithDisposeControl::dispose_count = 0;
  TestOneByteResourceWithDisposeControl::dispose_calls = 0;
  TestOneByteResourceWithDisposeControl res_stack(i::StrDup(c_source), false);
  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    Local<String> source =
        String::NewExternalOneByte(env->GetIsolate(), &res_stack)
            .ToLocalChecked();
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(7, value->Int32Value(env.local()).FromJust());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
    CHECK_EQ(0, TestOneByteResourceWithDisposeControl::dispose_count);
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }
  CHECK_EQ(1, TestOneByteResourceWithDisposeControl::dispose_calls);
  CHECK_EQ(0, TestOneByteResourceWithDisposeControl::dispose_count);

  // Use a heap allocated external string resource allocated object.
  TestOneByteResourceWithDisposeControl::dispose_count = 0;
  TestOneByteResourceWithDisposeControl::dispose_calls = 0;
  TestOneByteResource* res_heap =
      new TestOneByteResourceWithDisposeControl(i::StrDup(c_source), true);
  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    Local<String> source =
        String::NewExternalOneByte(env->GetIsolate(), res_heap)
            .ToLocalChecked();
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(7, value->Int32Value(env.local()).FromJust());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
    CHECK_EQ(0, TestOneByteResourceWithDisposeControl::dispose_count);
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }
  CHECK_EQ(1, TestOneByteResourceWithDisposeControl::dispose_calls);
  CHECK_EQ(1, TestOneByteResourceWithDisposeControl::dispose_count);
}


THREADED_TEST(StringConcat) {
  {
    LocalContext env;
    v8::Isolate* isolate = env->GetIsolate();
    v8::HandleScope scope(isolate);
    const char* one_byte_string_1 = "function a_times_t";
    const char* two_byte_string_1 = "wo_plus_b(a, b) {return ";
    const char* one_byte_extern_1 = "a * 2 + b;} a_times_two_plus_b(4, 8) + ";
    const char* two_byte_extern_1 = "a_times_two_plus_b(4, 8) + ";
    const char* one_byte_string_2 = "a_times_two_plus_b(4, 8) + ";
    const char* two_byte_string_2 = "a_times_two_plus_b(4, 8) + ";
    const char* two_byte_extern_2 = "a_times_two_plus_b(1, 2);";
    Local<String> left = v8_str(one_byte_string_1);

    uint16_t* two_byte_source = AsciiToTwoByteString(two_byte_string_1);
    Local<String> right =
        String::NewFromTwoByte(env->GetIsolate(), two_byte_source)
            .ToLocalChecked();
    i::DeleteArray(two_byte_source);

    Local<String> source = String::Concat(isolate, left, right);
    right = String::NewExternalOneByte(
                env->GetIsolate(),
                new TestOneByteResource(i::StrDup(one_byte_extern_1)))
                .ToLocalChecked();
    source = String::Concat(isolate, source, right);
    right = String::NewExternalTwoByte(
                env->GetIsolate(),
                new TestResource(AsciiToTwoByteString(two_byte_extern_1)))
                .ToLocalChecked();
    source = String::Concat(isolate, source, right);
    right = v8_str(one_byte_string_2);
    source = String::Concat(isolate, source, right);

    two_byte_source = AsciiToTwoByteString(two_byte_string_2);
    right = String::NewFromTwoByte(env->GetIsolate(), two_byte_source)
                .ToLocalChecked();
    i::DeleteArray(two_byte_source);

    source = String::Concat(isolate, source, right);
    right = String::NewExternalTwoByte(
                env->GetIsolate(),
                new TestResource(AsciiToTwoByteString(two_byte_extern_2)))
                .ToLocalChecked();
    source = String::Concat(isolate, source, right);
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(68, value->Int32Value(env.local()).FromJust());
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
}


THREADED_TEST(GlobalProperties) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Object> global = env->Global();
  CHECK(global->Set(env.local(), v8_str("pi"), v8_num(3.1415926)).FromJust());
  Local<Value> pi = global->Get(env.local(), v8_str("pi")).ToLocalChecked();
  CHECK_EQ(3.1415926, pi->NumberValue(env.local()).FromJust());
}


static void handle_callback_impl(const v8::FunctionCallbackInfo<Value>& info,
                                 i::Address callback) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CHECK(i::ValidateCallbackInfo(info));
  CheckReturnValue(info, callback);
  info.GetReturnValue().Set(v8_str("bad value"));
  info.GetReturnValue().Set(v8_num(102));
}


static void handle_callback(const v8::FunctionCallbackInfo<Value>& info) {
  return handle_callback_impl(info, FUNCTION_ADDR(handle_callback));
}


static void handle_callback_2(const v8::FunctionCallbackInfo<Value>& info) {
  return handle_callback_impl(info, FUNCTION_ADDR(handle_callback_2));
}

static void construct_callback(
    const v8::FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(construct_callback));
  CHECK(
      info.This()
          ->Set(info.GetIsolate()->GetCurrentContext(), v8_str("x"), v8_num(1))
          .FromJust());
  CHECK(
      info.This()
          ->Set(info.GetIsolate()->GetCurrentContext(), v8_str("y"), v8_num(2))
          .FromJust());
  info.GetReturnValue().Set(v8_str("bad value"));
  info.GetReturnValue().Set(info.This());
}

static void Return239Callback(Local<Name> name,
                              const v8::PropertyCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(Return239Callback));
  info.GetReturnValue().Set(v8_str("bad value"));
  info.GetReturnValue().Set(v8_num(239));
}

template<typename Handler>
static void TestFunctionTemplateInitializer(Handler handler,
                                            Handler handler_2) {
  // Test constructor calls.
  {
    LocalContext env;
    v8::Isolate* isolate = env->GetIsolate();
    v8::HandleScope scope(isolate);

    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, handler);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj()");
    for (int i = 0; i < 30; i++) {
      CHECK_EQ(102, v8_run_int32value(script));
    }
  }
  // Use SetCallHandler to initialize a function template, should work like
  // the previous one.
  {
    LocalContext env;
    v8::Isolate* isolate = env->GetIsolate();
    v8::HandleScope scope(isolate);

    Local<v8::FunctionTemplate> fun_templ = v8::FunctionTemplate::New(isolate);
    fun_templ->SetCallHandler(handler_2);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj()");
    for (int i = 0; i < 30; i++) {
      CHECK_EQ(102, v8_run_int32value(script));
    }
  }
}

template<typename Constructor, typename Accessor>
static void TestFunctionTemplateAccessor(Constructor constructor,
                                         Accessor accessor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(isolate, constructor);
  fun_templ->PrototypeTemplate()->Set(
      v8::Symbol::GetToStringTag(isolate), v8_str("funky"),
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum));
  fun_templ->InstanceTemplate()->SetNativeDataProperty(v8_str("m"), accessor);

  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
  Local<Value> result = CompileRun("(new obj()).toString()");
  CHECK(v8_str("[object funky]")->Equals(env.local(), result).FromJust());
  CompileRun("var obj_instance = new obj();");

  Local<Script> script = v8_compile("obj_instance.x");
  for (int i = 0; i < 30; i++) {
    CHECK_EQ(1, v8_run_int32value(script));
  }
  script = v8_compile("obj_instance.m");
  for (int i = 0; i < 30; i++) {
    CHECK_EQ(239, v8_run_int32value(script));
  }
}


THREADED_PROFILED_TEST(FunctionTemplate) {
  TestFunctionTemplateInitializer(handle_callback, handle_callback_2);
  TestFunctionTemplateAccessor(construct_callback, Return239Callback);
}

static void FunctionCallbackForProxyTest(
    const v8::FunctionCallbackInfo<Value>& info) {
  info.GetReturnValue().Set(info.This());
}

THREADED_TEST(FunctionTemplateWithProxy) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(isolate, FunctionCallbackForProxyTest);
  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();
  CHECK((*env)->Global()->Set(env.local(), v8_str("f"), function).FromJust());
  v8::Local<v8::Value> proxy =
      CompileRun("var proxy = new Proxy({}, {}); proxy");
  CHECK(proxy->IsProxy());

  v8::Local<v8::Value> result = CompileRun("f(proxy)");
  CHECK(result->Equals(env.local(), (*env)->Global()).FromJust());

  result = CompileRun("f.call(proxy)");
  CHECK(result->Equals(env.local(), proxy).FromJust());

  result = CompileRun("Reflect.apply(f, proxy, [1])");
  CHECK(result->Equals(env.local(), proxy).FromJust());
}

static void SimpleCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(SimpleCallback));
  info.GetReturnValue().Set(v8_num(51423 + info.Length()));
}


template<typename Callback>
static void TestSimpleCallback(Callback callback) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->Set(isolate, "callback",
                       v8::FunctionTemplate::New(isolate, callback));
  v8::Local<v8::Object> object =
      object_template->NewInstance(env.local()).ToLocalChecked();
  CHECK((*env)
            ->Global()
            ->Set(env.local(), v8_str("callback_object"), object)
            .FromJust());
  v8::Local<v8::Script> script;
  script = v8_compile("callback_object.callback(17)");
  for (int i = 0; i < 30; i++) {
    CHECK_EQ(51424, v8_run_int32value(script));
  }
  script = v8_compile("callback_object.callback(17, 24)");
  for (int i = 0; i < 30; i++) {
    CHECK_EQ(51425, v8_run_int32value(script));
  }
}


THREADED_PROFILED_TEST(SimpleCallback) {
  TestSimpleCallback(SimpleCallback);
}


template<typename T>
void FastReturnValueCallback(const v8::FunctionCallbackInfo<v8::Value>& info);

// constant return values
static int32_t fast_return_value_int32 = 471;
static uint32_t fast_return_value_uint32 = 571;
static const double kFastReturnValueDouble = 2.7;
// variable return values
static bool fast_return_value_bool = false;
enum ReturnValueOddball {
  kNullReturnValue,
  kUndefinedReturnValue,
  kEmptyStringReturnValue
};
static ReturnValueOddball fast_return_value_void;
static bool fast_return_value_object_is_empty = false;

// Helper function to avoid compiler error: insufficient contextual information
// to determine type when applying FUNCTION_ADDR to a template function.
static i::Address address_of(v8::FunctionCallback callback) {
  return FUNCTION_ADDR(callback);
}

template<>
void FastReturnValueCallback<int32_t>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<int32_t>));
  info.GetReturnValue().Set(fast_return_value_int32);
}

template<>
void FastReturnValueCallback<uint32_t>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<uint32_t>));
  info.GetReturnValue().Set(fast_return_value_uint32);
}

template<>
void FastReturnValueCallback<double>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<double>));
  info.GetReturnValue().Set(kFastReturnValueDouble);
}

template<>
void FastReturnValueCallback<bool>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<bool>));
  info.GetReturnValue().Set(fast_return_value_bool);
}

template<>
void FastReturnValueCallback<void>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<void>));
  switch (fast_return_value_void) {
    case kNullReturnValue:
      // Ensure that setting return value to empty handle does not break
      // static roots optimization.
      info.GetReturnValue().Set(v8::Local<v8::Value>{});
      info.GetReturnValue().SetNull();
      break;
    case kUndefinedReturnValue: {
      // Ensure that setting return value to Smi handle does not break
      // static roots optimization.
      info.GetReturnValue().Set(v8::Integer::New(info.GetIsolate(), 153));
      info.GetReturnValue().SetUndefined();
      break;
    }
    case kEmptyStringReturnValue:
      // Ensure that setting return value to Smi does not break
      // static roots optimization.
      info.GetReturnValue().Set(142);
      info.GetReturnValue().SetEmptyString();
      break;
  }
}

template<>
void FastReturnValueCallback<Object>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Object> object;
  if (!fast_return_value_object_is_empty) {
    object = Object::New(info.GetIsolate());
  }
  info.GetReturnValue().Set(object);
}

template <typename T>
Local<Value> TestFastReturnValues() {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::EscapableHandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  v8::FunctionCallback callback = &FastReturnValueCallback<T>;
  object_template->Set(isolate, "callback",
                       v8::FunctionTemplate::New(isolate, callback));
  v8::Local<v8::Object> object =
      object_template->NewInstance(env.local()).ToLocalChecked();
  CHECK((*env)
            ->Global()
            ->Set(env.local(), v8_str("callback_object"), object)
            .FromJust());
  return scope.Escape(CompileRun("callback_object.callback()"));
}


THREADED_PROFILED_TEST(FastReturnValues) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> value;
  // check int32_t and uint32_t
  int32_t int_values[] = {
      0, 234, -723,
      i::Smi::kMinValue, i::Smi::kMaxValue
  };
  for (size_t i = 0; i < arraysize(int_values); i++) {
    for (int modifier = -1; modifier <= 1; modifier++) {
      int int_value = v8::base::AddWithWraparound(int_values[i], modifier);
      // check int32_t
      fast_return_value_int32 = int_value;
      value = TestFastReturnValues<int32_t>();
      CHECK(value->IsInt32());
      CHECK_EQ(fast_return_value_int32,
               value->Int32Value(env.local()).FromJust());
      // check uint32_t
      fast_return_value_uint32 = static_cast<uint32_t>(int_value);
      value = TestFastReturnValues<uint32_t>();
      CHECK(value->IsUint32());
      CHECK_EQ(fast_return_value_uint32,
               value->Uint32Value(env.local()).FromJust());
    }
  }
  // check double
  value = TestFastReturnValues<double>();
  CHECK(value->IsNumber());
  CHECK_EQ(kFastReturnValueDouble,
           value->ToNumber(env.local()).ToLocalChecked()->Value());
  // check bool values
  for (int i = 0; i < 2; i++) {
    fast_return_value_bool = i == 0;
    value = TestFastReturnValues<bool>();
    CHECK(value->IsBoolean());
    CHECK_EQ(fast_return_value_bool, value->BooleanValue(isolate));
  }
  // check oddballs
  ReturnValueOddball oddballs[] = {
      kNullReturnValue,
      kUndefinedReturnValue,
      kEmptyStringReturnValue
  };
  for (size_t i = 0; i < arraysize(oddballs); i++) {
    fast_return_value_void = oddballs[i];
    value = TestFastReturnValues<void>();
    switch (fast_return_value_void) {
      case kNullReturnValue:
        CHECK(value->IsNull());
        break;
      case kUndefinedReturnValue:
        CHECK(value->IsUndefined());
        break;
      case kEmptyStringReturnValue:
        CHECK(value->IsString());
        CHECK_EQ(0, v8::String::Cast(*value)->Length());
        break;
    }
  }
  // check handles
  fast_return_value_object_is_empty = false;
  value = TestFastReturnValues<Object>();
  CHECK(value->IsObject());
  fast_return_value_object_is_empty = true;
  value = TestFastReturnValues<Object>();
  CHECK(value->IsUndefined());
}


THREADED_TEST(FunctionTemplateSetLength) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  {
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, handle_callback, Local<v8::Value>(),
                                  Local<v8::Signature>(), 23);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj.length");
    CHECK_EQ(23, v8_run_int32value(script));
  }
  {
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, handle_callback);
    fun_templ->SetLength(22);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj.length");
    CHECK_EQ(22, v8_run_int32value(script));
  }
  {
    // Without setting length it defaults to 0.
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, handle_callback);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj.length");
    CHECK_EQ(0, v8_run_int32value(script));
  }
}


static void* expected_ptr;
static void callback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  void* ptr = v8::External::Cast(*args.Data())->Value();
  CHECK_EQ(expected_ptr, ptr);
  args.GetReturnValue().Set(true);
}


static void TestExternalPointerWrapping() {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  int* ptr = new int;
  expected_ptr = ptr;

  v8::Local<v8::Value> data = v8::External::New(isolate, expected_ptr);

  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  CHECK(obj->Set(env.local(), v8_str("func"),
                 v8::FunctionTemplate::New(isolate, callback, data)
                     ->GetFunction(env.local())
                     .ToLocalChecked())
            .FromJust());
  CHECK(env->Global()->Set(env.local(), v8_str("obj"), obj).FromJust());

  CHECK(CompileRun("function foo() {\n"
                   "  for (var i = 0; i < 13; i++) obj.func();\n"
                   "}\n"
                   "foo(), true")
            ->BooleanValue(isolate));

  delete ptr;
}


THREADED_TEST(ExternalWrap) {
  // Check heap allocated object.
  int* ptr = new int;
  expected_ptr = ptr;
  TestExternalPointerWrapping();
  delete ptr;

  // Check stack allocated object.
  int foo;
  expected_ptr = &foo;
  TestExternalPointerWrapping();

  // Check not aligned addresses.
  const int n = 100;
  char* s = new char[n];
  for (int i = 0; i < n; i++) {
    expected_ptr = s + i;
    TestExternalPointerWrapping();
  }

  delete[] s;

  // Check several invalid addresses.
  expected_ptr = reinterpret_cast<void*>(1);
  TestExternalPointerWrapping();

  expected_ptr = reinterpret_cast<void*>(0xDEADBEEF);
  TestExternalPointerWrapping();

  expected_ptr = reinterpret_cast<void*>(0xDEADBEEF + 1);
  TestExternalPointerWrapping();

#if defined(V8_HOST_ARCH_X64)
  // Check a value with a leading 1 bit in x64 Smi encoding.
  expected_ptr = reinterpret_cast<void*>(0x400000000);
  TestExternalPointerWrapping();

  expected_ptr = reinterpret_cast<void*>(0xDEADBEEFDEADBEEF);
  TestExternalPointerWrapping();

  expected_ptr = reinterpret_cast<void*>(0xDEADBEEFDEADBEEF + 1);
  TestExternalPointerWrapping();
#endif
}


THREADED_TEST(FindInstanceInPrototypeChain) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> base = v8::FunctionTemplate::New(isolate);
  Local<v8::FunctionTemplate> derived = v8::FunctionTemplate::New(isolate);
  Local<v8::FunctionTemplate> other = v8::FunctionTemplate::New(isolate);
  derived->Inherit(base);

  Local<v8::Function> base_function =
      base->GetFunction(env.local()).ToLocalChecked();
  Local<v8::Function> derived_function =
      derived->GetFunction(env.local()).ToLocalChecked();
  Local<v8::Function> other_function =
      other->GetFunction(env.local()).ToLocalChecked();

  Local<v8::Object> base_instance =
      base_function->NewInstance(env.local()).ToLocalChecked();
  Local<v8::Object> derived_instance =
      derived_function->NewInstance(env.local()).ToLocalChecked();
  Local<v8::Object> derived_instance2 =
      derived_function->NewInstance(env.local()).ToLocalChecked();
  Local<v8::Object> other_instance =
      other_function->NewInstance(env.local()).ToLocalChecked();
  CHECK(
      derived_instance2->Set(env.local(), v8_str("__proto__"), derived_instance)
          .FromJust());
  CHECK(other_instance->Set(env.local(), v8_str("__proto__"), derived_instance2)
            .FromJust());

  // base_instance is only an instance of base.
  CHECK(base_instance->Equals(env.local(),
                              base_instance->FindInstanceInPrototypeChain(base))
            .FromJust());
  CHECK(base_instance->FindInstanceInPrototypeChain(derived).IsEmpty());
  CHECK(base_instance->FindInstanceInPrototypeChain(other).IsEmpty());

  // derived_instance is an instance of base and derived.
  CHECK(derived_instance->Equals(env.local(),
                                 derived_instance->FindInstanceInPrototypeChain(
                                     base))
            .FromJust());
  CHECK(derived_instance->Equals(env.local(),
                                 derived_instance->FindInstanceInPrototypeChain(
                                     derived))
            .FromJust());
  CHECK(derived_instance->FindInstanceInPrototypeChain(other).IsEmpty());

  // other_instance is an instance of other and its immediate
  // prototype derived_instance2 is an instance of base and derived.
  // Note, derived_instance is an instance of base and derived too,
  // but it comes after derived_instance2 in the prototype chain of
  // other_instance.
  CHECK(derived_instance2->Equals(
                             env.local(),
                             other_instance->FindInstanceInPrototypeChain(base))
            .FromJust());
  CHECK(derived_instance2->Equals(env.local(),
                                  other_instance->FindInstanceInPrototypeChain(
                                      derived))
            .FromJust());
  CHECK(other_instance->Equals(
                          env.local(),
                          other_instance->FindInstanceInPrototypeChain(other))
            .FromJust());
}

THREADED_TEST(FindInstanceInPrototypeChainWithProxy) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::Object> proxy =
      CompileRun("var proxy = new Proxy({}, {}); proxy").As<Object>();
  CHECK(proxy->FindInstanceInPrototypeChain(function_template).IsEmpty());
}

THREADED_TEST(TinyInteger) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  int32_t value = 239;
  Local<v8::Integer> value_obj = v8::Integer::New(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(BigSmiInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  int32_t value = i::Smi::kMaxValue;
  // We cannot add one to a Smi::kMaxValue without wrapping.
  if (i::SmiValuesAre31Bits()) {
    CHECK(i::Smi::IsValid(value));
    CHECK(!i::Smi::IsValid(value + 1));

    Local<v8::Integer> value_obj = v8::Integer::New(isolate, value);
    CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
  }
}


THREADED_TEST(BigInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  // We cannot add one to a Smi::kMaxValue without wrapping.
  if (i::SmiValuesAre31Bits()) {
    // The casts allow this to compile, even if Smi::kMaxValue is 2^31-1.
    // The code will not be run in that case, due to the "if" guard.
    int32_t value =
        static_cast<int32_t>(static_cast<uint32_t>(i::Smi::kMaxValue) + 1);
    CHECK_GT(value, i::Smi::kMaxValue);
    CHECK(!i::Smi::IsValid(value));

    Local<v8::Integer> value_obj = v8::Integer::New(isolate, value);
    CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
  }
}


THREADED_TEST(TinyUnsignedInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  uint32_t value = 239;

  Local<v8::Integer> value_obj = v8::Integer::NewFromUnsigned(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(BigUnsignedSmiInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  uint32_t value = static_cast<uint32_t>(i::Smi::kMaxValue);
  CHECK(i::Smi::IsValid(value));
  CHECK(!i::Smi::IsValid(value + 1));

  Local<v8::Integer> value_obj = v8::Integer::NewFromUnsigned(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(BigUnsignedInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  uint32_t value = static_cast<uint32_t>(i::Smi::kMaxValue) + 1;
  CHECK(value > static_cast<uint32_t>(i::Smi::kMaxValue));
  CHECK(!i::Smi::IsValid(value));

  Local<v8::Integer> value_obj = v8::Integer::NewFromUnsigned(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(OutOfSignedRangeUnsignedInteger) {
  LocalContext env;
  v8::HandleSco
```