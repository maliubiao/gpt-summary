Response:
The user wants a summary of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite. Here's a breakdown of the thought process:

1. **Identify the File and Purpose:** The file is `v8/test/cctest/test-api.cc`. The `test-api.cc` naming convention strongly suggests this file contains tests for the V8 API. The `#include` directives (not shown but implied) would likely confirm this.

2. **Scan for `TEST` Macros:** The code is heavily populated with `TEST(...)` macros. This is a clear indication of unit tests within the V8 testing framework.

3. **Analyze Individual Tests:**  Go through each `TEST` block and try to understand its function:
    * `PreviewMapValuesIteratorEntriesWithDeleted`: This test focuses on the `PreviewEntries` method of a Map iterator. The operations involve creating a map, adding elements, creating an iterator, deleting elements, iterating, and then using `PreviewEntries`. The checks (`CHECK`) verify the state of the iterator's preview after these operations.
    * `PreviewMapKeysIteratorEntriesWithDeleted`: Similar to the previous test, but this one specifically uses the `keys()` iterator of a Map. The operations and checks are analogous.
    * `NestedIsolates`: This test involves creating and interacting with two separate V8 isolates. It sets up functions in each isolate that call into the other, triggering garbage collection and capturing stack traces. The purpose seems to be testing how nested isolates and stack traces work.
    * (The rest of the code deals with Fast API calls, which require deeper analysis of the template metaprogramming and C++ function registrations.)

4. **Recognize Patterns and Concepts:**
    * **Map Iterators and `PreviewEntries`:** The repeated testing of `PreviewEntries` on Map iterators suggests this is a key feature being tested. The scenarios involve modifications to the underlying map during iteration.
    * **Isolates:** The `NestedIsolates` test directly addresses V8's isolation capabilities.
    * **Fast API Calls:** The latter part of the code uses templates and C++ function pointers, likely related to V8's "Fast API calls" feature, which allows more efficient interaction between JavaScript and C++. This involves concepts like `v8::CFunction`, `v8::FunctionTemplate`, and different callback types (fast and slow).

5. **Address Specific Instructions:**
    * **Functionality Listing:** Summarize the purpose of each test as described above.
    * **`.tq` Extension:** Explicitly state that the file is C++ and not Torque.
    * **JavaScript Examples:**  For the Map iterator tests, provide corresponding JavaScript code that demonstrates the core functionality being tested (creating maps, iterators, `delete`, `next`, and the concept of previewing).
    * **Code Logic Reasoning (Input/Output):** For the Map iterator tests, provide specific examples of map states and expected `PreviewEntries` outputs after a sequence of operations.
    * **Common Programming Errors:**  Relate the Map iterator tests to common errors like using iterators after the underlying collection has been modified.
    * **Part 32 of 36:**  Note that this is a part of a larger test suite, and it likely focuses on API features related to collections (like Maps) and isolate management.

6. **Structure the Output:** Organize the information logically, starting with a high-level summary and then going into more detail for each aspect. Use clear headings and bullet points for readability.

7. **Refine and Elaborate:** Add explanations of key V8 concepts like isolates and fast API calls. Ensure the JavaScript examples are accurate and illustrative.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus on the C++ API calls directly.
* **Correction:** Realize the tests are *about* the JavaScript API and how it interacts with the C++ layer. The JavaScript examples are crucial for understanding the *user-facing* functionality being tested.
* **Initial thought:**  Just describe the C++ code.
* **Correction:**  The prompt explicitly asks for JavaScript examples where applicable, so bridge the gap between the C++ tests and the JavaScript functionality they are testing.
* **Initial thought:**  Treat each `TEST` as completely independent.
* **Correction:** Recognize the thematic groupings, like the Map iterator tests, and summarize their overall purpose. Also, note the shift in focus to Fast API calls later in the snippet.
好的，让我们来分析一下 `v8/test/cctest/test-api.cc` 的第 32 部分代码的功能。

**核心功能归纳**

这部分代码主要测试了 V8 JavaScript 引擎中 `Map` 对象迭代器的 `PreviewEntries` 方法在涉及元素删除操作时的行为。此外，还测试了嵌套 `Isolate` 的相关功能，以及 V8 的 Fast API Call 机制。

**具体功能拆解**

1. **`PreviewMapValuesIteratorEntriesWithDeleted` 测试:**
   - 测试了当使用 `map.values()` 创建的迭代器，并且在迭代过程中或迭代前删除了 `Map` 中的元素时，调用 `iterator->PreviewEntries(&is_key)` 的行为。
   - 重点验证了 `PreviewEntries` 方法返回的预览条目是否正确反映了删除操作后的 `Map` 状态。
   - 测试了不同的场景，包括：
     - 先删除元素，再创建迭代器并预览。
     - 创建迭代器后删除元素并预览。
     - 创建迭代器后删除元素，迭代部分元素后预览。
     - 创建迭代器后删除元素，迭代到空后预览。
     - 创建迭代器后删除元素，迭代部分元素，触发 `Map` 的 rehash 后预览。

2. **`PreviewMapKeysIteratorEntriesWithDeleted` 测试:**
   - 与上面的测试类似，但这次使用的是 `map.keys()` 创建的迭代器。
   - 测试了在删除 `Map` 中的键后，`keys()` 迭代器的 `PreviewEntries` 方法的行为。
   - 同样覆盖了多种删除和迭代的组合场景。

3. **`NestedIsolates` 测试:**
   - 测试了在嵌套的 V8 `Isolate` 环境中进行函数调用的功能。
   - 创建了两个独立的 `Isolate` (`isolate_1` 和 `isolate_2`)。
   - 在每个 `Isolate` 中创建了上下文和全局函数 (`f1` 和 `f2`)。
   - `f1` 调用了 `isolate_2` 中的 C++ 函数 `CallIsolate2`，`CallIsolate2` 又会调用 `isolate_2` 中的 JavaScript 函数 `f2`。
   - `f2` 反过来也通过 `CallIsolate1` 调用 `isolate_1` 中的 `f1`。
   - 测试中还触发了垃圾回收 (`i::heap::InvokeMajorGC`)。
   - 最终，在 `isolate_2` 中捕获了一个错误堆栈信息，并验证了堆栈信息中只包含来自 `isolate_2` 的帧，以此来确保 `Isolate` 之间的隔离性。

4. **Fast API Call 相关测试 (以 `V8_ENABLE_TURBOFAN` 为前提):**
   - 这部分代码定义了一些模板结构 (`BasicApiChecker`, `ApiNumberChecker`, `ApiObjectChecker` 等) 和辅助函数 (`SetupTest`, `CallAndCheck` 等)，用于测试 V8 的 Fast API Call 机制。
   - Fast API Call 允许 C++ 函数以更高效的方式被 JavaScript 调用，绕过一些常规的调用开销。
   - 测试涵盖了：
     - 基本的 Fast Callback 和 Slow Callback 的调用路径。
     - 不同类型的参数 (数值、对象) 如何传递给 Fast Callback。
     - 如何检测 Fast Callback 是否被调用。
     - 当 Fast Callback 不可用时，是否会回退到 Slow Callback。
     - 涉及 WebAssembly 的场景 (`CallAndCheckFromWasm`)。
     - 尝试为构造函数设置 Fast Callback 时会报错 (`CheckFastCallsWithConstructor`)。
     - 测试具有返回值的 Fast Callback (`ReturnValueChecker`)。

**如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾**

如果文件以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。当前的 `test-api.cc` 是 C++ 文件，用于进行 API 级别的测试。

**与 JavaScript 功能的关系及示例**

1. **`Map` 迭代器和 `PreviewEntries`:**

   ```javascript
   const map = new Map();
   map.set('a', 1);
   map.set('b', 2);
   map.set('c', 3);

   const iterator = map.values();

   // 模拟 C++ 中的 it.next()
   iterator.next();

   // 模拟 C++ 中的 iterator->PreviewEntries()
   // JavaScript 中没有直接对应的 API，但我们可以通过手动迭代来模拟预览
   const previewedEntries = [];
   let tempIterator = map.values();
   tempIterator.next(); // 跳过第一个元素，因为前面的 it.next()
   let result = tempIterator.next();
   while (!result.done) {
     previewedEntries.push(result.value);
     result = tempIterator.next();
   }
   console.log(previewedEntries); // 输出可能是 [2, 3] 或 [3, 2]，取决于 Map 的内部顺序

   // 模拟 C++ 中的 map.delete('a')
   map.delete('a');

   // 再次模拟预览
   const previewedEntriesAfterDelete = [];
   tempIterator = map.values();
   result = tempIterator.next();
   while (!result.done) {
     previewedEntriesAfterDelete.push(result.value);
     result = tempIterator.next();
   }
   console.log(previewedEntriesAfterDelete); // 输出可能是 [2, 3] 或 [3, 2] (如果 'a' 是第一个被删除的)
   ```

2. **嵌套 `Isolate` (JavaScript 中无法直接模拟 V8 `Isolate`):**

   V8 `Isolate` 是一个独立的 JavaScript 引擎实例。在 JavaScript 中，我们无法直接创建或操作 V8 的 `Isolate`。这个测试主要关注 V8 内部的隔离机制。

3. **Fast API Call:**

   Fast API Call 是 V8 引擎为了优化 JavaScript 与 C++ 代码交互而设计的。在 JavaScript 中，你不会直接感知到 Fast API Call 或 Slow API Call 的区别，你只需要调用 JavaScript 函数即可。V8 内部会根据情况选择使用哪种调用方式。

   例如，你可能有一个 C++ 函数通过 V8 API 暴露给 JavaScript：

   ```cpp
   // C++ 代码
   void MyFastFunction(const v8::FunctionCallbackInfo<v8::Value>& info) {
     // ... 执行一些快速操作 ...
     info.GetReturnValue().Set(v8::Number::New(info.GetIsolate(), 42));
   }

   void Init(v8::Local<v8::Object> exports) {
     v8::Isolate* isolate = exports->GetIsolate();
     exports->Set(isolate->GetCurrentContext(),
                  v8_str(isolate, "myFastFunc"),
                  v8::FunctionTemplate::New(isolate, MyFastFunction).
                      GetFunction(isolate->GetCurrentContext()).ToLocalChecked());
   }

   NODE_MODULE_INIT(Init)
   ```

   ```javascript
   // JavaScript 代码
   const addon = require('./my_addon'); // 假设 C++ 代码被编译成一个 Node.js addon
   const result = addon.myFastFunc(); // V8 可能会使用 Fast API Call 来调用 MyFastFunction
   console.log(result); // 输出 42
   ```

**代码逻辑推理 (假设输入与输出)**

**`PreviewMapValuesIteratorEntriesWithDeleted` 示例:**

**假设输入:**

```javascript
const map = new Map();
const key1 = {};
map.set(key1, 1);
map.set({}, 2);
map.set({}, 3);
const it = map.values();
```

**场景 1: 先删除，后预览**

```c++
// 对应 C++ 代码：
// CompileRun("map.delete(key);");
// v8::Local<v8::Array> entries = iterator->PreviewEntries(&is_key).ToLocalChecked();
```

**预期输出 (C++ `entries` 的内容):**  取决于 `Map` 的内部顺序，可能是 `[1, 2, 3]` (如果删除的是 `key1` 对应的元素，且预览时迭代器还没有前进)。更准确地说，如果 `iterator` 在 `delete` 之前创建，且没有调用 `next()`, 预览会包含所有剩余的 value，排序取决于内部实现。

**场景 2: 删除后迭代，再预览**

```c++
// 对应 C++ 代码：
// CompileRun("map.delete(key); it.next();");
// v8::Local<v8::Array> entries = iterator->PreviewEntries(&is_key).ToLocalChecked();
```

**预期输出 (C++ `entries` 的内容):**  假设 `it.next()` 返回了 `1`，那么预览会跳过第一个元素，并包含剩余的 value，例如 `[2, 3]`。

**涉及用户常见的编程错误**

1. **在迭代过程中修改 `Map` 或其他集合:**  这是使用迭代器时一个常见的陷阱。如果在迭代过程中直接添加或删除元素，可能会导致迭代器失效或产生意想不到的结果。V8 的 `PreviewEntries` 方法可以帮助开发者更好地理解迭代器在修改后的状态。

   ```javascript
   const map = new Map([['a', 1], ['b', 2], ['c', 3]]);
   const iterator = map.keys();
   for (const key of iterator) {
     console.log(key);
     if (key === 'b') {
       map.delete('c'); // 错误：在迭代过程中修改了 Map
     }
   }
   ```

2. **不理解迭代器的生命周期:**  迭代器通常与创建它的集合相关联。如果集合被销毁或清空，迭代器可能不再有效。

**归纳一下它的功能 (第 32 部分，共 36 部分)**

作为 `v8/test/cctest/test-api.cc` 的一部分，这第 32 部分主要关注以下 API 功能的测试：

- **`Map` 迭代器的 `PreviewEntries` 方法:**  特别是在 `Map` 在迭代过程中被修改（删除元素）的情况下的行为和正确性。这有助于确保 V8 引擎在处理迭代器和集合修改时的内部逻辑是正确的。
- **嵌套 `Isolate` 的功能:**  验证了 V8 引擎在处理多个独立 `Isolate` 时的隔离性和交互能力，包括跨 `Isolate` 的函数调用和堆栈信息的管理。
- **V8 的 Fast API Call 机制:**  测试了如何将 C++ 函数高效地暴露给 JavaScript，以及 V8 如何选择和执行 Fast Callback 和 Slow Callback。

考虑到这是 36 个部分中的第 32 部分，可以推测 `test-api.cc` 的整体目标是对 V8 JavaScript 引擎的各种 C++ API 进行全面的单元测试，涵盖了从基本的数据结构操作到更复杂的引擎特性（如 `Isolate` 管理和性能优化机制）。这部分可能集中在集合类型 (`Map`) 的迭代器行为和 V8 的扩展机制 (Fast API Calls)。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第32部分，共36部分，请归纳一下它的功能

"""
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