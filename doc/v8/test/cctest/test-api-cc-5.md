Response:
The user wants a summary of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. The summary should include:

1. **Functionality:** What does the code do?
2. **Torque Source Check:** Is it a Torque file (ends with `.tq`)?
3. **JavaScript Relation:** If related to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** If there's logical deduction, give example input and output.
5. **Common Programming Errors:** If it touches upon common mistakes, provide examples.
6. **Overall Function:**  A concise summary of the code's purpose within the larger context of `test-api.cc`.

Let's break down the code section by section:

* **`TwoPassPhantomCallbacks` related tests:** These tests seem to be about ensuring that weak callbacks, specifically two-pass phantom callbacks, work correctly during garbage collection. They involve creating objects with weak references and verifying that the callbacks are executed as expected during GC cycles. The "two-pass" aspect suggests a first callback when the object is about to be collected and a second after it's been fully collected. The string allocation test (`TwoPassPhantomCallbacksTriggeredByStringAlloc`) checks if these callbacks still function correctly when GC is triggered by memory pressure from string allocation.

* **`GlobalValueMap` related tests:** These tests are about the `v8::GlobalValueMap` API. It seems to be a custom map-like structure that holds global handles to V8 objects, potentially with weak references and custom behavior defined by `StdMapTraits`. The tests cover basic map operations like `Set`, `Get`, `Remove`, `Clear`, and different configurations including weak references and internal fields.

* **`VectorOfGlobals` test:** This checks how `std::vector` handles `v8::Global` objects, verifying that the global handles are managed correctly during insertion, copying, and clearing of the vector.

* **`GlobalHandleUpcast` test:** This test checks if you can safely cast a `v8::Persistent<String>` to a more general `v8::Persistent<Value>`.

* **`HandleEquality` and `HandleEqualityPrimitives` tests:** These tests verify the behavior of equality operators (`==` and `!=`) for `v8::Persistent` and `v8::Local` handles, especially the difference in behavior for primitive values.

* **`LocalHandle` test:** A simple test to create and use a `v8::Local` handle.

* **`WeakCallCounter` and `WeakPointerCallback` test:** This section tests weak persistent handles and their callbacks. It creates a persistent handle to an object and sets up a weak callback. The callback should be executed when the object is garbage collected.

* **`ScriptException` test:**  This tests the `v8::TryCatch` mechanism to catch exceptions thrown from JavaScript code.

* **`MessageHandler` tests (0-5):** These tests are focused on the message listener API in V8. They demonstrate how to add and remove message listeners, and how the listeners receive information about JavaScript errors (messages), including the error value itself, script origin (name, line, column, etc.), and cross-origin status.

* **`Message` attribute tests (`MessageGetLineNumber`, `MessageGetStartColumn`, etc.):** These tests verify the API for accessing different attributes of a `v8::Message` object, which is typically created from an exception. They check things like line number, column number, source code snippet, and the source line where the error occurred.

* **`GetStackTraceLimit` tests:** These tests check the `v8::Isolate::GetStackTraceLimit()` API, which controls the maximum number of frames captured in a stack trace. It also verifies that JavaScript code can modify this limit through `Error.stackTraceLimit`.

* **`CurrentStackTraceHasUniqueIDs` test:**  This tests that different calls to `v8::StackTrace::CurrentStackTrace()` return stack traces with unique IDs.

* **`MessagePrintCurrentStackTrace` test:** This verifies the functionality of `v8::Message::PrintCurrentStackTrace()`, which outputs the current JavaScript call stack to a stream.

* **`GetSetProperty` test:** This test demonstrates how to set and get properties on a V8 object (the global object in this case) using different key types (strings, integers, numbers).

* **`PropertyAttributes` test:** This test explores the different property attributes (None, ReadOnly, DontDelete, DontEnum) and how they affect property behavior.

**Overall Function:** The code primarily tests various aspects of the V8 API related to object lifecycle (weak handles, garbage collection callbacks), global handle management, exception handling, error reporting (message listeners and message object attributes), and object property manipulation.

Now, let's address the specific points in the prompt.
Let's break down the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`.

**1. Functionality Breakdown:**

This code snippet primarily focuses on testing various aspects of the V8 C++ API, particularly related to:

* **Weak Persistent Handles and Phantom Callbacks:**  It tests how weak persistent handles behave during garbage collection (GC), specifically focusing on "two-pass" phantom callbacks. These callbacks are executed in two stages when an object is about to be garbage collected. The tests verify the correct execution order and the ability to execute JavaScript code within the second-pass callback.
* **Global Value Maps:** It tests the functionality of `v8::GlobalValueMap`, a utility for managing global handles to V8 objects, including scenarios with weak references and internal fields.
* **Global Handle Management:**  It tests how `v8::Global` handles are managed within standard C++ containers like `std::vector`.
* **Handle Equality:** It tests the behavior of equality operators (`==` and `!=`) for `v8::Local` and `v8::Persistent` handles.
* **Exception Handling:** It tests the `v8::TryCatch` mechanism for catching JavaScript exceptions.
* **Message Listeners:** It tests the API for adding and removing message listeners, which receive notifications about JavaScript errors and warnings. The tests cover different scenarios, including cross-origin errors and attaching data to messages.
* **Message Object Attributes:** It tests the API for accessing information about error messages, such as line number, column number, source code, and source line.
* **Stack Trace Limits:** It tests the `v8::Isolate::GetStackTraceLimit()` API and how it can be modified from JavaScript.
* **Current Stack Trace:** It tests the `v8::StackTrace::CurrentStackTrace()` and `v8::Message::PrintCurrentStackTrace()` APIs.
* **Property Getters and Setters:** It tests setting and getting properties on V8 objects using different key types (strings, integers, numbers).
* **Property Attributes:** It tests the different property attributes (e.g., read-only, don't delete, don't enumerate) and their effects.

**2. Torque Source Check:**

The filename ends with `.cc`, not `.tq`. Therefore, this is **not** a V8 Torque source file.

**3. JavaScript Relation and Examples:**

Many of these tests directly relate to how V8 interacts with JavaScript code. Here are some examples:

* **Two-Pass Phantom Callbacks:**  While the callbacks themselves are in C++, they are triggered by the garbage collection of JavaScript objects. Imagine a scenario where you want to perform some cleanup *before* an object is fully collected and a final cleanup *after*.

   ```javascript
   // Hypothetical scenario (not directly testable like this in JS)
   let obj = {};
   let weakRef = new WeakRef(obj, {
       firstPass: () => { console.log("Object is about to be collected"); },
       secondPass: () => { console.log("Object has been collected"); }
   });
   obj = null; // Make the object eligible for GC
   // ... trigger garbage collection ...
   ```

* **Message Listeners:** These directly correspond to the `window.onerror` event and other error reporting mechanisms in JavaScript.

   ```javascript
   window.onerror = function(message, source, lineno, colno, error) {
       console.error("An error occurred:", message, source, lineno, colno, error);
   };

   throw new Error("Something went wrong!");
   ```

* **Stack Trace Limit:** The tests check `Error.stackTraceLimit`.

   ```javascript
   Error.stackTraceLimit = 5;

   function a() { b(); }
   function b() { c(); }
   function c() { throw new Error("Test"); }

   try {
       a();
   } catch (e) {
       console.log(e.stack); // The stack trace will have a maximum of 5 frames.
   }
   ```

* **Property Attributes:**  These relate to property descriptors in JavaScript.

   ```javascript
   let obj = {};
   Object.defineProperty(obj, 'readOnlyProp', {
       value: 7,
       writable: false // Corresponds to v8::ReadOnly
   });

   console.log(obj.readOnlyProp); // Output: 7
   obj.readOnlyProp = 9;
   console.log(obj.readOnlyProp); // Output: 7 (assignment has no effect)

   Object.defineProperty(obj, 'nonDeletableProp', {
       value: 13,
       configurable: false // Corresponds to v8::DontDelete
   });

   delete obj.nonDeletableProp;
   console.log(obj.nonDeletableProp); // Output: 13

   Object.defineProperty(obj, 'nonEnumerableProp', {
       value: 28,
       enumerable: false // Corresponds to v8::DontEnum
   });

   for (let prop in obj) {
       console.log(prop); // nonEnumerableProp will not be iterated.
   }
   ```

**4. Code Logic Inference (with Assumptions):**

* **`TwoPassPhantomCallbacks` Tests:**
    * **Assumption:** Garbage collection will occur after the `InvokeMajorGC` call.
    * **Input:** Creates `kLength` (20) `TwoPassCallbackData` objects with weak references.
    * **Output:**  The `metadata.instance_counter` should initially be `kLength`. After GC and processing message queues, if the weak callbacks are working correctly, the counter should remain at `kLength` because the phantom callbacks likely increment it. The second pass callback might be doing something else depending on its implementation.
* **`TwoPassPhantomCallbacksNestedGc` Tests:**
    * **Assumption:** Marking objects for GC will influence the GC process.
    * **Input:** Creates `kLength` `TwoPassCallbackData` objects and marks some for immediate GC.
    * **Output:** Similar to the previous test, but the marking might cause specific callbacks to execute sooner.
* **`TwoPassPhantomCallbacksTriggeredByStringAlloc`:**
    * **Assumption:** Allocating a large number of strings will trigger garbage collection.
    * **Input:** Creates one `TwoPassCallbackData` object and then repeatedly allocates large strings.
    * **Output:** The `while` loop continues until garbage collection occurs and the second-pass callback is invoked, presumably changing `metadata.instance_counter`.
* **`GlobalValueMap` Tests:**
    * **Assumption:** The `StdGlobalValueMap` and the custom `WeakMap` will behave as expected for map operations.
    * **Input:** Various `Set`, `Get`, `Remove`, and `Clear` operations with different keys and values.
    * **Output:** The `Size()` of the map and the retrieved values should match the expected state after each operation. For the `WeakMap`, after GC, the size should decrease if the weak references are collected.
* **`HandleEqualityPrimitives` Test:**
    * **Assumption:**  `Local::operator==` behaves like strict equality for objects but has special handling for primitives.
    * **Input:** Comparison of two newly created string locals and two newly created number locals.
    * **Output:** The string locals will be unequal (different instances), while the number locals with the same value (1) will be equal.

**5. Common Programming Errors Illustrated:**

* **Forgetting to handle empty `MaybeLocal`:** The code frequently uses `ToLocalChecked()`. If a `MaybeLocal` is empty (operation failed), `ToLocalChecked()` will crash. A safer approach is to check `IsEmpty()` before calling `ToLocalChecked()` or use `ToLocal(&local_variable)`.

   ```c++
   v8::MaybeLocal<v8::String> maybe_string = ...;
   if (!maybe_string.IsEmpty()) {
       v8::Local<v8::String> local_string = maybe_string.ToLocalChecked();
       // Use local_string
   } else {
       // Handle the error case
   }
   ```

* **Incorrectly assuming equality of newly created string locals:** As shown in `HandleEqualityPrimitives`, two `v8::Local<String>` objects created with the same string literal will not be equal using `operator==`. You need to compare their values.

   ```c++
   v8::Local<v8::String> str1 = v8_str("hello");
   v8::Local<v8::String> str2 = v8_str("hello");
   // str1 == str2 will be false (comparing pointers)
   str1->Equals(context.local(), str2); // Correct way to compare string values
   ```

* **Not understanding the implications of weak handles:**  If you hold only a weak handle to an object, it can be garbage collected at any time. You need to be prepared for the handle to become invalid.

* **Memory leaks with global handles:**  `v8::Global` handles prevent objects from being garbage collected. If you create global handles and don't explicitly `Reset()` them, you can cause memory leaks. The `VectorOfGlobals` test demonstrates proper clearing of the vector to release the global handles.

**6. Summary of Functionality:**

This code snippet is a collection of unit tests for various low-level features of the V8 JavaScript engine's C++ API. It specifically targets memory management (weak handles, garbage collection), object manipulation (properties, global handles), error reporting, and fundamental handle operations. These tests are crucial for ensuring the stability and correctness of the V8 engine.

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共36部分，请归纳一下它的功能

"""
econdPassCallback(const v8::WeakCallbackInfo<TwoPassCallbackData>& data) {
  data.GetParameter()->SecondPass(data.GetIsolate());
}


void FirstPassCallback(const v8::WeakCallbackInfo<TwoPassCallbackData>& data) {
  data.GetParameter()->FirstPass();
  data.SetSecondPassCallback(SecondPassCallback);
}

}  // namespace


TEST(TwoPassPhantomCallbacks) {
  auto isolate = CcTest::isolate();
  GCCallbackMetadata metadata;
  const size_t kLength = 20;
  for (size_t i = 0; i < kLength; ++i) {
    auto data = new TwoPassCallbackData(isolate, &metadata);
    data->SetWeak();
  }
  CHECK_EQ(static_cast<int>(kLength), metadata.instance_counter);
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  EmptyMessageQueues(isolate);
}


TEST(TwoPassPhantomCallbacksNestedGc) {
  auto isolate = CcTest::isolate();
  GCCallbackMetadata metadata;
  const size_t kLength = 20;
  TwoPassCallbackData* array[kLength];
  for (size_t i = 0; i < kLength; ++i) {
    array[i] = new TwoPassCallbackData(isolate, &metadata);
    array[i]->SetWeak();
  }
  array[5]->MarkTriggerGc();
  array[10]->MarkTriggerGc();
  array[15]->MarkTriggerGc();
  CHECK_EQ(static_cast<int>(kLength), metadata.instance_counter);
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  EmptyMessageQueues(isolate);
}

// The string creation API methods forbid executing JS code while they are
// on the stack. Make sure that when such a string creation triggers GC,
// the second pass callback can still execute JS as per its API contract.
TEST(TwoPassPhantomCallbacksTriggeredByStringAlloc) {
  auto isolate = CcTest::isolate();
  GCCallbackMetadata metadata;
  auto data = new TwoPassCallbackData(isolate, &metadata);
  data->SetWeak();
  CHECK_EQ(metadata.instance_counter, 1);

  v8::base::ScopedVector<uint8_t> source(200000);

  // In the rest of this test, we need to invoke GC without stack, otherwise the
  // weak references may not be cleared because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  // Creating a few large strings suffices to trigger GC.
  while (metadata.instance_counter == 1) {
    v8::HandleScope handle_scope(isolate);
    USE(v8::String::NewFromOneByte(isolate, source.begin(),
                                   v8::NewStringType::kNormal,
                                   static_cast<int>(source.size())));
  }
  EmptyMessageQueues(isolate);
}

namespace {

void* IntKeyToVoidPointer(int key) { return reinterpret_cast<void*>(key << 1); }


Local<v8::Object> NewObjectForIntKey(
    v8::Isolate* isolate, const v8::Global<v8::ObjectTemplate>& templ,
    int key) {
  auto local = Local<v8::ObjectTemplate>::New(isolate, templ);
  auto obj = local->NewInstance(isolate->GetCurrentContext()).ToLocalChecked();
  obj->SetAlignedPointerInInternalField(0, IntKeyToVoidPointer(key));
  return obj;
}


template <typename K, typename V>
class PhantomStdMapTraits : public v8::StdMapTraits<K, V> {
 public:
  using MapType = typename v8::GlobalValueMap<K, V, PhantomStdMapTraits<K, V>>;
  static const v8::PersistentContainerCallbackType kCallbackType =
      v8::kWeakWithInternalFields;
  struct WeakCallbackDataType {
    MapType* map;
    K key;
  };
  static WeakCallbackDataType* WeakCallbackParameter(MapType* map, const K& key,
                                                     Local<V> value) {
    WeakCallbackDataType* data = new WeakCallbackDataType;
    data->map = map;
    data->key = key;
    return data;
  }
  static MapType* MapFromWeakCallbackInfo(
      const v8::WeakCallbackInfo<WeakCallbackDataType>& data) {
    return data.GetParameter()->map;
  }
  static K KeyFromWeakCallbackInfo(
      const v8::WeakCallbackInfo<WeakCallbackDataType>& data) {
    return data.GetParameter()->key;
  }
  static void DisposeCallbackData(WeakCallbackDataType* data) { delete data; }
  static void Dispose(v8::Isolate* isolate, v8::Global<V> value, K key) {
    CHECK_EQ(IntKeyToVoidPointer(key),
             v8::Object::GetAlignedPointerFromInternalField(value, 0));
  }
  static void OnWeakCallback(
      const v8::WeakCallbackInfo<WeakCallbackDataType>&) {}
  static void DisposeWeak(
      const v8::WeakCallbackInfo<WeakCallbackDataType>& info) {
    K key = KeyFromWeakCallbackInfo(info);
    CHECK_EQ(IntKeyToVoidPointer(key), info.GetInternalField(0));
    DisposeCallbackData(info.GetParameter());
  }
};


template <typename Map>
void TestGlobalValueMap() {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Global<ObjectTemplate> templ;
  {
    HandleScope scope(isolate);
    auto t = ObjectTemplate::New(isolate);
    t->SetInternalFieldCount(1);
    templ.Reset(isolate, t);
  }
  Map map(isolate);
  i::GlobalHandles* global_handles =
      reinterpret_cast<i::Isolate*>(isolate)->global_handles();
  size_t initial_handle_count = global_handles->handles_count();
  CHECK_EQ(0, static_cast<int>(map.Size()));
  {
    HandleScope scope(isolate);
    Local<v8::Object> obj = map.Get(7);
    CHECK(obj.IsEmpty());
    Local<v8::Object> expected = v8::Object::New(isolate);
    map.Set(7, expected);
    CHECK_EQ(1, static_cast<int>(map.Size()));
    obj = map.Get(7);
    CHECK(expected->Equals(env.local(), obj).FromJust());
    {
      typename Map::PersistentValueReference ref = map.GetReference(7);
      CHECK(expected->Equals(env.local(), ref.NewLocal(isolate)).FromJust());
    }
    v8::Global<v8::Object> removed = map.Remove(7);
    CHECK_EQ(0, static_cast<int>(map.Size()));
    CHECK(expected == removed);
    removed = map.Remove(7);
    CHECK(removed.IsEmpty());
    map.Set(8, expected);
    CHECK_EQ(1, static_cast<int>(map.Size()));
    map.Set(8, expected);
    CHECK_EQ(1, static_cast<int>(map.Size()));
    {
      typename Map::PersistentValueReference ref;
      Local<v8::Object> expected2 = NewObjectForIntKey(isolate, templ, 8);
      removed = map.Set(8, v8::Global<v8::Object>(isolate, expected2), &ref);
      CHECK_EQ(1, static_cast<int>(map.Size()));
      CHECK(expected == removed);
      CHECK(expected2->Equals(env.local(), ref.NewLocal(isolate)).FromJust());
    }
  }
  CHECK_EQ(initial_handle_count + 1, global_handles->handles_count());
  if (map.IsWeak()) {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  } else {
    map.Clear();
  }
  CHECK_EQ(0, static_cast<int>(map.Size()));
  CHECK_EQ(initial_handle_count, global_handles->handles_count());
  {
    HandleScope scope(isolate);
    Local<v8::Object> value = NewObjectForIntKey(isolate, templ, 9);
    map.Set(9, value);
    map.Clear();
  }
  CHECK_EQ(0, static_cast<int>(map.Size()));
  CHECK_EQ(initial_handle_count, global_handles->handles_count());
}

}  // namespace


TEST(GlobalValueMap) {
  // Default case, w/o weak callbacks:
  TestGlobalValueMap<v8::StdGlobalValueMap<int, v8::Object>>();

  // Custom traits with weak callbacks:
  using WeakMap =
      v8::GlobalValueMap<int, v8::Object, PhantomStdMapTraits<int, v8::Object>>;
  TestGlobalValueMap<WeakMap>();
}

TEST(VectorOfGlobals) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::GlobalHandles* global_handles =
      reinterpret_cast<i::Isolate*>(isolate)->global_handles();
  size_t handle_count = global_handles->handles_count();
  HandleScope scope(isolate);

  std::vector<v8::Global<v8::Object>> vector;

  Local<v8::Object> obj1 = v8::Object::New(isolate);
  Local<v8::Object> obj2 = v8::Object::New(isolate);
  v8::Global<v8::Object> obj3(isolate, v8::Object::New(isolate));

  CHECK(vector.empty());
  CHECK_EQ(0, static_cast<int>(vector.size()));

  vector.reserve(3);
  CHECK(vector.empty());

  vector.emplace_back(isolate, obj1);
  vector.emplace_back(isolate, obj2);
  vector.emplace_back(isolate, obj1);
  vector.emplace_back(obj3.Pass());
  vector.emplace_back(isolate, obj1);

  CHECK(!vector.empty());
  CHECK_EQ(5, static_cast<int>(vector.size()));
  CHECK(obj3.IsEmpty());
  CHECK(obj1->Equals(env.local(), vector[0].Get(isolate)).FromJust());
  CHECK(obj1->Equals(env.local(), vector[2].Get(isolate)).FromJust());
  CHECK(obj1->Equals(env.local(), vector[4].Get(isolate)).FromJust());
  CHECK(obj2->Equals(env.local(), vector[1].Get(isolate)).FromJust());

  CHECK_EQ(5 + handle_count, global_handles->handles_count());

  vector.clear();
  CHECK(vector.empty());
  CHECK_EQ(0, static_cast<int>(vector.size()));
  CHECK_EQ(handle_count, global_handles->handles_count());
}

THREADED_TEST(GlobalHandleUpcast) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<String> local = v8::Local<String>::New(isolate, v8_str("str"));
  v8::Persistent<String> global_string(isolate, local);
  v8::Persistent<Value>& global_value =
      v8::Persistent<Value>::Cast(global_string);
  CHECK(v8::Local<v8::Value>::New(isolate, global_value)->IsString());
  CHECK(global_string == v8::Persistent<String>::Cast(global_value));
  global_string.Reset();
}


THREADED_TEST(HandleEquality) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Persistent<String> global1;
  v8::Persistent<String> global2;
  {
    v8::HandleScope scope(isolate);
    global1.Reset(isolate, v8_str("str"));
    global2.Reset(isolate, v8_str("str2"));
  }
  CHECK(global1 == global1);
  CHECK(!(global1 != global1));
  {
    v8::HandleScope scope(isolate);
    Local<String> local1 = Local<String>::New(isolate, global1);
    Local<String> local2 = Local<String>::New(isolate, global2);

    CHECK(global1 == local1);
    CHECK(!(global1 != local1));
    CHECK(local1 == global1);
    CHECK(!(local1 != global1));

    CHECK(!(global1 == local2));
    CHECK(global1 != local2);
    CHECK(!(local2 == global1));
    CHECK(local2 != global1);

    CHECK(!(local1 == local2));
    CHECK(local1 != local2);

    Local<String> anotherLocal1 = Local<String>::New(isolate, global1);
    CHECK(local1 == anotherLocal1);
    CHECK(!(local1 != anotherLocal1));
  }
  global1.Reset();
  global2.Reset();
}

THREADED_TEST(HandleEqualityPrimitives) {
  v8::HandleScope scope(CcTest::isolate());
  // Local::operator== works like strict equality except for primitives.
  CHECK_NE(v8_str("str"), v8_str("str"));
  CHECK_NE(v8::Number::New(CcTest::isolate(), 0.5),
           v8::Number::New(CcTest::isolate(), 0.5));
  CHECK_EQ(v8::Number::New(CcTest::isolate(), 1),
           v8::Number::New(CcTest::isolate(), 1));
}

THREADED_TEST(LocalHandle) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<String> local =
      v8::Local<String>::New(CcTest::isolate(), v8_str("str"));
  CHECK_EQ(3, local->Length());
}


class WeakCallCounter {
 public:
  explicit WeakCallCounter(int id) : id_(id), number_of_weak_calls_(0) {}
  int id() { return id_; }
  void increment() { number_of_weak_calls_++; }
  int NumberOfWeakCalls() { return number_of_weak_calls_; }

 private:
  int id_;
  int number_of_weak_calls_;
};


template <typename T>
struct WeakCallCounterAndPersistent {
  explicit WeakCallCounterAndPersistent(WeakCallCounter* counter)
      : counter(counter) {}
  WeakCallCounter* counter;
  v8::Persistent<T> handle;
};


template <typename T>
static void WeakPointerCallback(
    const v8::WeakCallbackInfo<WeakCallCounterAndPersistent<T>>& data) {
  CHECK_EQ(1234, data.GetParameter()->counter->id());
  data.GetParameter()->counter->increment();
  data.GetParameter()->handle.Reset();
}

THREADED_TEST(ScriptException) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<Script> script = v8_compile("throw 'panama!';");
  v8::TryCatch try_catch(env->GetIsolate());
  v8::MaybeLocal<Value> result = script->Run(env.local());
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  String::Utf8Value exception_value(env->GetIsolate(), try_catch.Exception());
  CHECK_EQ(0, strcmp(*exception_value, "panama!"));
}

bool message_received;


static void check_message_0(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  CHECK_EQ(5.76, data->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  CHECK(!message->IsSharedCrossOrigin());
  message_received = true;
}


THREADED_TEST(MessageHandler0) {
  message_received = false;
  v8::HandleScope scope(CcTest::isolate());
  CHECK(!message_received);
  LocalContext context;
  CcTest::isolate()->AddMessageListener(check_message_0, v8_num(5.76));
  v8::Local<v8::Script> script =
      CompileWithOrigin("throw 'error'", "6.75", false);
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  CcTest::isolate()->RemoveMessageListeners(check_message_0);
}


static void check_message_1(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  CHECK(data->IsNumber());
  CHECK_EQ(1337,
           data->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK(!message->IsSharedCrossOrigin());
  message_received = true;
}


TEST(MessageHandler1) {
  message_received = false;
  v8::HandleScope scope(CcTest::isolate());
  CHECK(!message_received);
  CcTest::isolate()->AddMessageListener(check_message_1);
  LocalContext context;
  CompileRun("throw 1337;");
  CHECK(message_received);
  // clear out the message listener
  CcTest::isolate()->RemoveMessageListeners(check_message_1);
}


static void check_message_2(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  LocalContext context;
  CHECK(data->IsObject());
  v8::Local<v8::Value> hidden_property =
      v8::Object::Cast(*data)
          ->GetPrivate(
              context.local(),
              v8::Private::ForApi(CcTest::isolate(), v8_str("hidden key")))
          .ToLocalChecked();
  CHECK(v8_str("hidden value")
            ->Equals(context.local(), hidden_property)
            .FromJust());
  CHECK(!message->IsSharedCrossOrigin());
  message_received = true;
}


TEST(MessageHandler2) {
  message_received = false;
  v8::HandleScope scope(CcTest::isolate());
  CHECK(!message_received);
  CcTest::isolate()->AddMessageListener(check_message_2);
  LocalContext context;
  v8::Local<v8::Value> error = v8::Exception::Error(v8_str("custom error"));
  v8::Object::Cast(*error)
      ->SetPrivate(context.local(),
                   v8::Private::ForApi(CcTest::isolate(), v8_str("hidden key")),
                   v8_str("hidden value"))
      .FromJust();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("error"), error)
            .FromJust());
  CompileRun("throw error;");
  CHECK(message_received);
  // clear out the message listener
  CcTest::isolate()->RemoveMessageListeners(check_message_2);
}


static void check_message_3(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  CHECK(message->IsSharedCrossOrigin());
  CHECK(message->GetScriptOrigin().Options().IsSharedCrossOrigin());
  CHECK(message->GetScriptOrigin().Options().IsOpaque());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  CHECK_EQ(7.40, message->GetScriptOrigin()
                     .SourceMapUrl()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  message_received = true;
}


TEST(MessageHandler3) {
  message_received = false;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  CHECK(!message_received);
  isolate->AddMessageListener(check_message_3);
  LocalContext context;
  v8::ScriptOrigin origin =
      v8::ScriptOrigin(v8_str("6.75"), 1, 2, true, -1, v8_str("7.40"), true);
  v8::Local<v8::Script> script =
      Script::Compile(context.local(), v8_str("throw 'error'"), &origin)
          .ToLocalChecked();
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  isolate->RemoveMessageListeners(check_message_3);
}


static void check_message_4(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  CHECK(!message->IsSharedCrossOrigin());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  message_received = true;
}


TEST(MessageHandler4) {
  message_received = false;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  CHECK(!message_received);
  isolate->AddMessageListener(check_message_4);
  LocalContext context;
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("6.75"), 1, 2, false);
  v8::Local<v8::Script> script =
      Script::Compile(context.local(), v8_str("throw 'error'"), &origin)
          .ToLocalChecked();
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  isolate->RemoveMessageListeners(check_message_4);
}


static void check_message_5a(v8::Local<v8::Message> message,
                             v8::Local<Value> data) {
  CHECK(message->IsSharedCrossOrigin());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  message_received = true;
}


static void check_message_5b(v8::Local<v8::Message> message,
                             v8::Local<Value> data) {
  CHECK(!message->IsSharedCrossOrigin());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  message_received = true;
}


TEST(MessageHandler5) {
  message_received = false;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  CHECK(!message_received);
  isolate->AddMessageListener(check_message_5a);
  LocalContext context;
  v8::ScriptOrigin origin1 = v8::ScriptOrigin(v8_str("6.75"), 1, 2, true);
  v8::Local<v8::Script> script =
      Script::Compile(context.local(), v8_str("throw 'error'"), &origin1)
          .ToLocalChecked();
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  isolate->RemoveMessageListeners(check_message_5a);

  message_received = false;
  isolate->AddMessageListener(check_message_5b);
  v8::ScriptOrigin origin2 = v8::ScriptOrigin(v8_str("6.75"), 1, 2, false);
  script = Script::Compile(context.local(), v8_str("throw 'error'"), &origin2)
               .ToLocalChecked();
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  isolate->RemoveMessageListeners(check_message_5b);
}

namespace {

// Verifies that after throwing an exception the message object is set up in
// some particular way by calling the supplied |tester| function. The tests that
// use this purposely test only a single getter as the getter updates the cached
// state of the object which could affect the results of other functions.
const char message_attributes_script[] =
    R"javascript(
    (function() {
      throw new Error();
    })();
    )javascript";

void CheckMessageAttributes(std::function<void(v8::Local<v8::Context> context,
                                               v8::Local<v8::Message> message)>
                                tester) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  TryCatch try_catch(context->GetIsolate());
  CompileRun(message_attributes_script);
  CHECK(try_catch.HasCaught());

  v8::Local<v8::Value> error = try_catch.Exception();
  v8::Local<v8::Message> message =
      v8::Exception::CreateMessage(context->GetIsolate(), error);
  CHECK(!message.IsEmpty());

  tester(context.local(), message);
}

}  // namespace

TEST(MessageGetLineNumber) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(3, message->GetLineNumber(context).FromJust());
      });
}

TEST(MessageGetStartColumn) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(12, message->GetStartColumn(context).FromJust());
      });
}

TEST(MessageGetEndColumn) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(13, message->GetEndColumn(context).FromJust());
      });
}

TEST(MessageGetStartPosition) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(31, message->GetStartPosition());
      });
}

TEST(MessageGetEndPosition) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(32, message->GetEndPosition());
      });
}

TEST(MessageGetSource) {
  CheckMessageAttributes([](v8::Local<v8::Context> context,
                            v8::Local<v8::Message> message) {
    std::string result(*v8::String::Utf8Value(
        context->GetIsolate(), message->GetSource(context).ToLocalChecked()));
    CHECK_EQ(message_attributes_script, result);
  });
}

TEST(MessageGetSourceLine) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        std::string result(*v8::String::Utf8Value(
            context->GetIsolate(),
            message->GetSourceLine(context).ToLocalChecked()));
        CHECK_EQ("      throw new Error();", result);
      });
}

TEST(GetStackTraceLimit) {
  i::v8_flags.stack_trace_limit = 10;

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  const int stack_trace_limit = isolate->GetStackTraceLimit();
  CHECK_EQ(10, stack_trace_limit);
}

TEST(GetStackTraceLimitSetFromJS) {
  i::v8_flags.stack_trace_limit = 10;

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script = v8_str("Error.stackTraceLimit = 5;\n");
  v8::Script::Compile(context.local(), script, &origin)
      .ToLocalChecked()
      ->Run(context.local())
      .ToLocalChecked();

  const int stack_trace_limit = isolate->GetStackTraceLimit();
  CHECK_EQ(5, stack_trace_limit);
}

TEST(GetStackTraceLimitSetNegativeFromJS) {
  i::v8_flags.stack_trace_limit = 10;

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script = v8_str("Error.stackTraceLimit = -5;\n");
  v8::Script::Compile(context.local(), script, &origin)
      .ToLocalChecked()
      ->Run(context.local())
      .ToLocalChecked();

  const int stack_trace_limit = isolate->GetStackTraceLimit();
  CHECK_EQ(0, stack_trace_limit);
}

void GetCurrentStackTraceID(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  v8::Local<v8::StackTrace> stack_trace =
      v8::StackTrace::CurrentStackTrace(isolate, 1);
  args.GetReturnValue().Set(v8::Integer::New(isolate, stack_trace->GetID()));
}

THREADED_TEST(CurrentStackTraceHasUniqueIDs) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "getCurrentStackTraceID",
             v8::FunctionTemplate::New(isolate, GetCurrentStackTraceID));
  LocalContext context(nullptr, templ);
  CompileRun(
      "function foo() {"
      "  return getCurrentStackTraceID();"
      "}");
  Local<Function> foo = Local<Function>::Cast(
      context->Global()->Get(context.local(), v8_str("foo")).ToLocalChecked());

  Local<v8::Integer> id1 =
      foo->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
          .ToLocalChecked()
          .As<v8::Integer>();
  Local<v8::Integer> id2 =
      foo->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
          .ToLocalChecked()
          .As<v8::Integer>();

  CHECK_NE(id1->Value(), id2->Value());
}

void GetCurrentStackTrace(const v8::FunctionCallbackInfo<v8::Value>& args) {
  std::stringstream ss;
  v8::Message::PrintCurrentStackTrace(args.GetIsolate(), ss);
  std::string str = ss.str();
  args.GetReturnValue().Set(v8_str(str.c_str()));
}

THREADED_TEST(MessagePrintCurrentStackTrace) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "getCurrentStackTrace",
             v8::FunctionTemplate::New(isolate, GetCurrentStackTrace));
  LocalContext context(nullptr, templ);

  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script = v8_str(
      "function c() {\n"
      "  return getCurrentStackTrace();\n"
      "}\n"
      "function b() {\n"
      "  return c();\n"
      "}\n"
      "function a() {\n"
      "  return b();\n"
      "}\n"
      "a();");
  v8::Local<v8::Value> stack_trace =
      v8::Script::Compile(context.local(), script, &origin)
          .ToLocalChecked()
          ->Run(context.local())
          .ToLocalChecked();

  CHECK(stack_trace->IsString());
  v8::String::Utf8Value stack_trace_value(isolate,
                                          stack_trace.As<v8::String>());
  std::string stack_trace_string(*stack_trace_value);
  std::string expected(
      "c (test:2:10)\n"
      "b (test:5:10)\n"
      "a (test:8:10)\n"
      "test:10:1");
  CHECK_EQ(stack_trace_string, expected);
}

THREADED_TEST(GetSetProperty) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("foo"), v8_num(14))
            .FromJust());
  CHECK(context->Global()
            ->Set(context.local(), v8_str("12"), v8_num(92))
            .FromJust());
  CHECK(context->Global()
            ->Set(context.local(), v8::Integer::New(isolate, 16), v8_num(32))
            .FromJust());
  CHECK(context->Global()
            ->Set(context.local(), v8_num(13), v8_num(56))
            .FromJust());
  Local<Value> foo = CompileRun("this.foo");
  CHECK_EQ(14, foo->Int32Value(context.local()).FromJust());
  Local<Value> twelve = CompileRun("this[12]");
  CHECK_EQ(92, twelve->Int32Value(context.local()).FromJust());
  Local<Value> sixteen = CompileRun("this[16]");
  CHECK_EQ(32, sixteen->Int32Value(context.local()).FromJust());
  Local<Value> thirteen = CompileRun("this[13]");
  CHECK_EQ(56, thirteen->Int32Value(context.local()).FromJust());
  CHECK_EQ(92, context->Global()
                   ->Get(context.local(), v8::Integer::New(isolate, 12))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(92, context->Global()
                   ->Get(context.local(), v8_str("12"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(92, context->Global()
                   ->Get(context.local(), v8_num(12))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(32, context->Global()
                   ->Get(context.local(), v8::Integer::New(isolate, 16))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(32, context->Global()
                   ->Get(context.local(), v8_str("16"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(32, context->Global()
                   ->Get(context.local(), v8_num(16))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(56, context->Global()
                   ->Get(context.local(), v8::Integer::New(isolate, 13))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(56, context->Global()
                   ->Get(context.local(), v8_str("13"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(56, context->Global()
                   ->Get(context.local(), v8_num(13))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
}


THREADED_TEST(PropertyAttributes) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  // none
  Local<String> prop = v8_str("none");
  CHECK(context->Global()->Set(context.local(), prop, v8_num(7)).FromJust());
  CHECK_EQ(v8::None, context->Global()
                         ->GetPropertyAttributes(context.local(), prop)
                         .FromJust());
  // read-only
  prop = v8_str("read_only");
  context->Global()
      ->DefineOwnProperty(context.local(), prop, v8_num(7), v8::ReadOnly)
      .FromJust();
  CHECK_EQ(7, context->Global()
                  ->Get(context.local(), prop)
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(v8::ReadOnly, context->Global()
                             ->GetPropertyAttributes(context.local(), prop)
                             .FromJust());
  CompileRun("read_only = 9");
  CHECK_EQ(7, context->Global()
                  ->Get(context.local(), prop)
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK(context->Global()->Set(context.local(), prop, v8_num(10)).FromJust());
  CHECK_EQ(7, context->Global()
                  ->Get(context.local(), prop)
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  // dont-delete
  prop = v8_str("dont_delete");
  context->Global()
      ->DefineOwnProperty(context.local(), prop, v8_num(13), v8::DontDelete)
      .FromJust();
  CHECK_EQ(13, context->Global()
                   ->Get(context.local(), prop)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CompileRun("delete dont_delete");
  CHECK_EQ(13, context->Global()
                   ->Get(context.local(), prop)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(v8::DontDelete, context->Global()
                               ->GetPropertyAttributes(context.local(), prop)
                               .FromJust());
  // dont-enum
  prop = v8_str("dont_enum");
  context->Global()
      ->DefineOwnProperty(context.local(), prop, v8_num(28), v8::DontEnum)
      .FromJust();
  CHECK_EQ(v8::DontEnum, context->Global()
                             ->GetPropertyAttributes(context.local(), prop)
                             .FromJust());
  // absent
  prop = v8_str("absent");
  CHECK_EQ(v8::None, context->Global()
                         ->GetPropertyAttributes(context.local(), prop)
                         .FromJust());
  Local<Value> fake_prop = v8_num(1);
  CHECK_EQ(v8::None, context->Global()
                         ->GetPropertyAttributes(context.local(), fake_prop)
                         .FromJust());
  // exception
  TryCatch try_catch(context->GetIsolate());
  Local<Value> exception =
      CompileRun("({ toString: function() { throw 'exception';} })");
  CHECK(context->Global()
            ->GetPropertyAttributes(context.local(), exception)
            .IsNothing());
  CHECK(try_catch.HasCaught());
  String::Utf8Value exception_value(context->GetIsolate(),
                                    try_catch.Exception());
  CHECK_
"""


```