Response: Let's break down the thought process for analyzing the C++ code and connecting it to JavaScript's tracing capabilities.

1. **Understanding the Goal:** The request asks for the functionality of the C++ code and its relationship to JavaScript. This means I need to identify what the C++ code *does* and then see if there's a corresponding feature or interaction in JavaScript.

2. **Initial Scan for Key Terms:** I'll quickly scan the code for keywords that hint at its purpose. Terms like "trace," "event," "category," "platform," "controller," "args," "timestamp," and "javascript" (or related terms like "v8") are good starting points. The filename itself, `test-trace-event.cc`, is a strong indicator.

3. **Identifying the Core Functionality (C++ side):**

   * **Mocking:** The presence of `MockTracingController` and `MockTracingPlatform` immediately suggests this is a *testing* file. These mock classes simulate the real tracing infrastructure without actually performing the full tracing process. This is crucial to understand. It's not about *actually* tracing, but about *testing* the tracing *mechanism*.
   * **Data Structures:** The `MockTraceObject` struct defines how trace event data is stored in this test environment. It holds information like phase, name, ID, arguments, and timestamp. This tells me what kind of information the tracing system handles.
   * **`AddTraceEvent` and `AddTraceEventWithTimestamp`:** These methods within `MockTracingController` are the core of the simulated tracing. They receive trace event information and store it in the `trace_objects_` vector. This confirms the code's purpose is about capturing trace events.
   * **Category Filtering:** The `GetCategoryGroupEnabled` method demonstrates a mechanism for enabling or disabling tracing for specific categories (e.g., "v8-cat"). This is a standard feature in tracing systems.
   * **Testing Macros (`TEST_WITH_PLATFORM`):**  These indicate the code contains unit tests that exercise the tracing functionality using the mock platform. The individual test cases demonstrate how to emit different types of trace events (with/without arguments, scoped, with IDs, etc.).

4. **Connecting to JavaScript:**

   * **V8 Context:** The code includes `<v8.h>` and uses `v8::Isolate`, `v8::Context`, and related V8 API elements. This strongly links the code to the V8 JavaScript engine.
   * **Built-in Functions:** The tests `BuiltinsIsTraceCategoryEnabled` and `BuiltinsTrace` directly interact with JavaScript. They retrieve functions named "isTraceCategoryEnabled" and "trace" from a "binding" object. The "binding" object is a common way for V8 to expose internal functionalities to JavaScript. This is a *key* connection.
   * **`isTraceCategoryEnabled`:** This JavaScript function, tested in the C++ code, directly corresponds to the C++ `GetCategoryGroupEnabled` functionality. It allows JavaScript code to query if tracing is enabled for a given category.
   * **`trace`:**  This JavaScript function takes parameters that map directly to the arguments of the C++ `AddTraceEvent` functions (phase, category, name, ID, data). This is how JavaScript code can trigger the creation of trace events within the V8 engine.

5. **Constructing the Explanation:**

   * **Start with the high-level purpose:** Clearly state that the code is for testing the tracing infrastructure within the V8 engine.
   * **Explain the mocking mechanism:** Emphasize that `MockTracingController` and `MockTracingPlatform` are for testing, not actual tracing.
   * **Summarize the C++ functionality:**  Describe how the mock objects store trace event data and how category filtering is implemented.
   * **Detail the JavaScript connection:**  Focus on the "isTraceCategoryEnabled" and "trace" functions, explaining their roles and how they relate to the C++ code.
   * **Provide JavaScript examples:**  Illustrate how these JavaScript functions are used to check category status and emit trace events. The examples should mirror the test cases in the C++ code. Show both enabling and disabling scenarios.
   * **Explain the "why":**  Conclude by explaining the importance of tracing for performance analysis and debugging in JavaScript.

6. **Refinement and Clarity:**

   * **Use clear and concise language.** Avoid overly technical jargon where possible.
   * **Organize the explanation logically.** Start with the C++ functionality and then connect it to JavaScript.
   * **Use code examples effectively.** Make sure the JavaScript examples are easy to understand and directly relate to the C++ concepts.
   * **Double-check for accuracy.** Ensure that the JavaScript examples and explanations accurately reflect the C++ code's behavior.

By following this thought process, I can systematically analyze the C++ code, identify its core functionalities, and establish the crucial link to JavaScript's tracing capabilities, ultimately producing a comprehensive and accurate explanation.
这个C++源代码文件 `v8/test/cctest/test-trace-event.cc` 的功能是**测试 V8 JavaScript 引擎的 tracing (跟踪) 功能**。 更具体地说，它通过创建一个模拟的 tracing 环境来验证 V8 引擎中 trace event 机制的正确性。

以下是其主要功能点的归纳：

1. **模拟 Tracing 环境:**
   - 定义了一个 `MockTraceObject` 结构体，用于存储模拟的 trace event 数据，例如事件的阶段 (phase)、名称 (name)、ID、绑定 ID、参数数量、标志和时间戳。
   - 创建了一个 `MockTracingController` 类，它继承自 `v8::TracingController` 并重写了关键的 tracing 方法，例如 `AddTraceEvent` 和 `AddTraceEventWithTimestamp`。 这个模拟的 controller 不会真正地将 trace event 发送到外部系统，而是将它们存储在内部的 `trace_objects_` 列表中。
   - 创建了一个 `MockTracingPlatform` 类，它继承自 `TestPlatform` 并返回 `MockTracingController` 的实例。这模拟了 V8 平台层提供的 tracing controller。

2. **测试 Trace Event 的添加和存储:**
   - 使用 V8 提供的 `TRACE_EVENT_*` 宏 (例如 `TRACE_EVENT_BEGIN0`, `TRACE_EVENT_END0`, `TRACE_EVENT1`, `TRACE_EVENT_WITH_FLOW0`, `TRACE_EVENT_ASYNC_BEGIN0` 等) 来模拟在 V8 代码中添加 trace event 的行为。
   - 在每个测试用例中，断言 (使用 `CHECK_EQ`)  `MockTracingPlatform` 中存储的 `MockTraceObject` 的数量和内容是否与预期一致。这包括验证事件的阶段、名称、参数数量、ID、绑定 ID 和标志等。

3. **测试 Trace Category 的启用和禁用:**
   - `MockTracingController::GetCategoryGroupEnabled` 方法模拟了根据 category 名称判断是否启用 tracing 的逻辑。在这个测试环境中，只有以 "v8-cat" 开头的 category 是启用的。
   - 测试用例会验证，当 tracing category 被禁用时，相应的 `TRACE_EVENT_*` 宏不会产生任何 trace event。

4. **测试带参数的 Trace Event:**
   - 测试用例验证了可以添加带有不同数量参数 (0个、1个、2个) 的 trace event，并检查参数数量是否被正确记录。

5. **测试 Scoped Trace Event:**
   - 测试用例使用了 `TRACE_EVENT0`, `TRACE_EVENT1`, `TRACE_EVENT2` 等宏来创建作用域内的 trace event，这些事件在作用域结束时会自动结束。

6. **测试带有 Flow ID 和异步 ID 的 Trace Event:**
   - 测试用例验证了 `TRACE_EVENT_WITH_FLOW0` 宏可以添加带有 flow ID 的 trace event，用于关联不同时间点的事件。
   - 测试了 `TRACE_EVENT_ASYNC_BEGIN0` 和 `TRACE_EVENT_ASYNC_END0` 宏，用于测试异步事件的开始和结束。

7. **测试带有时间戳的 Trace Event:**
   - 测试用例验证了可以指定时间戳来创建 trace event。

8. **测试 JavaScript 中调用 Tracing 功能:**
   - `BuiltinsIsTraceCategoryEnabled` 测试用例验证了 JavaScript 中 `isTraceCategoryEnabled` 函数的功能，该函数用于检查特定 tracing category 是否已启用。
   - `BuiltinsTrace` 测试用例验证了 JavaScript 中 `trace` 函数的功能，该函数允许 JavaScript 代码手动添加 trace event。

**与 JavaScript 的关系：**

这个测试文件直接测试了 V8 引擎暴露给 JavaScript 的 tracing 相关功能。  `BuiltinsIsTraceCategoryEnabled` 和 `BuiltinsTrace` 这两个测试用例展示了 JavaScript 如何与 V8 的 tracing 机制进行交互。

**JavaScript 示例：**

在 JavaScript 中，我们可以使用 `__proto__.isTraceCategoryEnabled` 和 `__proto__.trace` (通常通过一些内部绑定暴露出来) 来进行 tracing 相关的操作。

例如，在 V8 的上下文中，你可能会看到类似这样的 JavaScript 代码：

```javascript
// 假设 'binding' 是一个包含 V8 内部绑定的对象
const binding = process.binding('trace_events'); // 这只是一个假设，实际绑定名称可能不同

// 检查 'v8-cat' category 是否启用
if (binding.isTraceCategoryEnabled('v8-cat')) {
  console.log('v8-cat is enabled');
} else {
  console.log('v8-cat is disabled');
}

// 添加一个 trace event
binding.trace('B', 'v8-cat', 'myEvent', 123, { detail: 'some info' });
binding.trace('E', 'v8-cat', 'myEvent', 123, { detail: 'some info' });
```

**解释：**

- `binding.isTraceCategoryEnabled('v8-cat')` 对应了 C++ 测试中的 `BuiltinsIsTraceCategoryEnabled`，它会调用 V8 内部的逻辑来判断 'v8-cat' 这个 tracing category 是否被激活。
- `binding.trace('B', 'v8-cat', 'myEvent', 123, { detail: 'some info' })` 对应了 C++ 测试中的 `BuiltinsTrace`。
    - `'B'` 表示事件的阶段是 "Begin"。
    - `'v8-cat'` 是 tracing category 的名称。
    - `'myEvent'` 是事件的名称。
    - `123` 是事件的 ID。
    - `{ detail: 'some info' }` 是与事件关联的数据，在 C++ 代码中会被作为参数处理。

**总结：**

`test-trace-event.cc` 文件是 V8 引擎中 tracing 功能的关键测试文件，它通过模拟 tracing 环境和 JavaScript 调用来确保 tracing 机制的正确性和稳定性。它直接验证了 V8 暴露给 JavaScript 的 tracing API 的行为。 理解这个文件有助于理解 V8 引擎是如何实现 tracing 功能以及 JavaScript 代码如何与这些底层机制进行交互的。

### 提示词
```
这是目录为v8/test/cctest/test-trace-event.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>
#include <string.h>

#include "include/v8-function.h"
#include "include/v8-platform.h"
#include "src/init/v8.h"
#include "src/tracing/trace-event.h"
#include "test/cctest/cctest.h"

namespace {

struct MockTraceObject {
  char phase;
  std::string name;
  uint64_t id;
  uint64_t bind_id;
  int num_args;
  unsigned int flags;
  int64_t timestamp;
  MockTraceObject(char phase, std::string name, uint64_t id, uint64_t bind_id,
                  int num_args, int flags, int64_t timestamp)
      : phase(phase),
        name(name),
        id(id),
        bind_id(bind_id),
        num_args(num_args),
        flags(flags),
        timestamp(timestamp) {}
};

class MockTracingController : public v8::TracingController {
 public:
  MockTracingController() = default;
  MockTracingController(const MockTracingController&) = delete;
  MockTracingController& operator=(const MockTracingController&) = delete;

  uint64_t AddTraceEvent(
      char phase, const uint8_t* category_enabled_flag, const char* name,
      const char* scope, uint64_t id, uint64_t bind_id, int num_args,
      const char** arg_names, const uint8_t* arg_types,
      const uint64_t* arg_values,
      std::unique_ptr<v8::ConvertableToTraceFormat>* arg_convertables,
      unsigned int flags) override {
    return AddTraceEventWithTimestamp(
        phase, category_enabled_flag, name, scope, id, bind_id, num_args,
        arg_names, arg_types, arg_values, arg_convertables, flags, 0);
  }

  uint64_t AddTraceEventWithTimestamp(
      char phase, const uint8_t* category_enabled_flag, const char* name,
      const char* scope, uint64_t id, uint64_t bind_id, int num_args,
      const char** arg_names, const uint8_t* arg_types,
      const uint64_t* arg_values,
      std::unique_ptr<v8::ConvertableToTraceFormat>* arg_convertables,
      unsigned int flags, int64_t timestamp) override {
    std::unique_ptr<MockTraceObject> to = std::make_unique<MockTraceObject>(
        phase, std::string(name), id, bind_id, num_args, flags, timestamp);
    trace_objects_.push_back(std::move(to));
    return 0;
  }

  void UpdateTraceEventDuration(const uint8_t* category_enabled_flag,
                                const char* name, uint64_t handle) override {}

  const uint8_t* GetCategoryGroupEnabled(const char* name) override {
    if (strncmp(name, "v8-cat", 6)) {
      static uint8_t no = 0;
      return &no;
    } else {
      static uint8_t yes = 0x7;
      return &yes;
    }
  }

  const std::vector<std::unique_ptr<MockTraceObject>>& GetMockTraceObjects()
      const {
    return trace_objects_;
  }

 private:
  std::vector<std::unique_ptr<MockTraceObject>> trace_objects_;
};

class MockTracingPlatform : public TestPlatform {
 public:
  v8::TracingController* GetTracingController() override {
    return &tracing_controller_;
  }

  size_t NumberOfTraceObjects() {
    return tracing_controller_.GetMockTraceObjects().size();
  }

  MockTraceObject* GetTraceObject(size_t index) {
    return tracing_controller_.GetMockTraceObjects().at(index).get();
  }

 private:
  MockTracingController tracing_controller_;
};

}  // namespace

TEST_WITH_PLATFORM(TraceEventDisabledCategory, MockTracingPlatform) {
  // Disabled category, will not add events.
  TRACE_EVENT_BEGIN0("cat", "e1");
  TRACE_EVENT_END0("cat", "e1");
  CHECK_EQ(0, platform.NumberOfTraceObjects());
}

TEST_WITH_PLATFORM(TraceEventNoArgs, MockTracingPlatform) {
  // Enabled category will add 2 events.
  TRACE_EVENT_BEGIN0("v8-cat", "e1");
  TRACE_EVENT_END0("v8-cat", "e1");

  CHECK_EQ(2, platform.NumberOfTraceObjects());
  CHECK_EQ('B', platform.GetTraceObject(0)->phase);
  CHECK_EQ("e1", platform.GetTraceObject(0)->name);
  CHECK_EQ(0, platform.GetTraceObject(0)->num_args);

  CHECK_EQ('E', platform.GetTraceObject(1)->phase);
  CHECK_EQ("e1", platform.GetTraceObject(1)->name);
  CHECK_EQ(0, platform.GetTraceObject(1)->num_args);
}

TEST_WITH_PLATFORM(TraceEventWithOneArg, MockTracingPlatform) {
  TRACE_EVENT_BEGIN1("v8-cat", "e1", "arg1", 42);
  TRACE_EVENT_END1("v8-cat", "e1", "arg1", 42);
  TRACE_EVENT_BEGIN1("v8-cat", "e2", "arg1", "abc");
  TRACE_EVENT_END1("v8-cat", "e2", "arg1", "abc");

  CHECK_EQ(4, platform.NumberOfTraceObjects());

  CHECK_EQ(1, platform.GetTraceObject(0)->num_args);
  CHECK_EQ(1, platform.GetTraceObject(1)->num_args);
  CHECK_EQ(1, platform.GetTraceObject(2)->num_args);
  CHECK_EQ(1, platform.GetTraceObject(3)->num_args);
}

TEST_WITH_PLATFORM(TraceEventWithTwoArgs, MockTracingPlatform) {
  TRACE_EVENT_BEGIN2("v8-cat", "e1", "arg1", 42, "arg2", "abc");
  TRACE_EVENT_END2("v8-cat", "e1", "arg1", 42, "arg2", "abc");
  TRACE_EVENT_BEGIN2("v8-cat", "e2", "arg1", "abc", "arg2", 43);
  TRACE_EVENT_END2("v8-cat", "e2", "arg1", "abc", "arg2", 43);

  CHECK_EQ(4, platform.NumberOfTraceObjects());

  CHECK_EQ(2, platform.GetTraceObject(0)->num_args);
  CHECK_EQ(2, platform.GetTraceObject(1)->num_args);
  CHECK_EQ(2, platform.GetTraceObject(2)->num_args);
  CHECK_EQ(2, platform.GetTraceObject(3)->num_args);
}

TEST_WITH_PLATFORM(ScopedTraceEvent, MockTracingPlatform) {
  { TRACE_EVENT0("v8-cat", "e"); }

  CHECK_EQ(1, platform.NumberOfTraceObjects());
  CHECK_EQ(0, platform.GetTraceObject(0)->num_args);

  { TRACE_EVENT1("v8-cat", "e1", "arg1", "abc"); }

  CHECK_EQ(2, platform.NumberOfTraceObjects());
  CHECK_EQ(1, platform.GetTraceObject(1)->num_args);

  { TRACE_EVENT2("v8-cat", "e1", "arg1", "abc", "arg2", 42); }

  CHECK_EQ(3, platform.NumberOfTraceObjects());
  CHECK_EQ(2, platform.GetTraceObject(2)->num_args);
}

TEST_WITH_PLATFORM(TestEventWithFlow, MockTracingPlatform) {
  static uint64_t bind_id = 21;
  {
    TRACE_EVENT_WITH_FLOW0("v8-cat", "f1", bind_id, TRACE_EVENT_FLAG_FLOW_OUT);
  }
  {
    TRACE_EVENT_WITH_FLOW0(
        "v8-cat", "f2", bind_id,
        TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  }
  { TRACE_EVENT_WITH_FLOW0("v8-cat", "f3", bind_id, TRACE_EVENT_FLAG_FLOW_IN); }

  CHECK_EQ(3, platform.NumberOfTraceObjects());
  CHECK_EQ(bind_id, platform.GetTraceObject(0)->bind_id);
  CHECK_EQ(TRACE_EVENT_FLAG_FLOW_OUT, platform.GetTraceObject(0)->flags);
  CHECK_EQ(bind_id, platform.GetTraceObject(1)->bind_id);
  CHECK_EQ(TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
           platform.GetTraceObject(1)->flags);
  CHECK_EQ(bind_id, platform.GetTraceObject(2)->bind_id);
  CHECK_EQ(TRACE_EVENT_FLAG_FLOW_IN, platform.GetTraceObject(2)->flags);
}

TEST_WITH_PLATFORM(TestEventWithId, MockTracingPlatform) {
  static uint64_t event_id = 21;
  TRACE_EVENT_ASYNC_BEGIN0("v8-cat", "a1", event_id);
  TRACE_EVENT_ASYNC_END0("v8-cat", "a1", event_id);

  CHECK_EQ(2, platform.NumberOfTraceObjects());
  CHECK_EQ(TRACE_EVENT_PHASE_ASYNC_BEGIN, platform.GetTraceObject(0)->phase);
  CHECK_EQ(event_id, platform.GetTraceObject(0)->id);
  CHECK_EQ(TRACE_EVENT_PHASE_ASYNC_END, platform.GetTraceObject(1)->phase);
  CHECK_EQ(event_id, platform.GetTraceObject(1)->id);
}

TEST_WITH_PLATFORM(TestEventWithTimestamp, MockTracingPlatform) {
  TRACE_EVENT_INSTANT_WITH_TIMESTAMP0("v8-cat", "0arg",
                                      TRACE_EVENT_SCOPE_GLOBAL, 1729);
  TRACE_EVENT_INSTANT_WITH_TIMESTAMP1("v8-cat", "1arg",
                                      TRACE_EVENT_SCOPE_GLOBAL, 4104, "val", 1);
  TRACE_EVENT_MARK_WITH_TIMESTAMP2("v8-cat", "mark", 13832, "a", 1, "b", 2);

  TRACE_EVENT_COPY_NESTABLE_ASYNC_BEGIN_WITH_TIMESTAMP0("v8-cat", "begin", 5,
                                                        20683);
  TRACE_EVENT_COPY_NESTABLE_ASYNC_END_WITH_TIMESTAMP0("v8-cat", "end", 5,
                                                      32832);

  CHECK_EQ(5, platform.NumberOfTraceObjects());

  CHECK_EQ(1729, platform.GetTraceObject(0)->timestamp);
  CHECK_EQ(0, platform.GetTraceObject(0)->num_args);

  CHECK_EQ(4104, platform.GetTraceObject(1)->timestamp);
  CHECK_EQ(1, platform.GetTraceObject(1)->num_args);

  CHECK_EQ(13832, platform.GetTraceObject(2)->timestamp);
  CHECK_EQ(2, platform.GetTraceObject(2)->num_args);

  CHECK_EQ(20683, platform.GetTraceObject(3)->timestamp);
  CHECK_EQ(32832, platform.GetTraceObject(4)->timestamp);
}

TEST_WITH_PLATFORM(BuiltinsIsTraceCategoryEnabled, MockTracingPlatform) {
  CcTest::InitializeVM();

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext env;

  v8::Local<v8::Object> binding = env->GetExtrasBindingObject();
  CHECK(!binding.IsEmpty());

  auto undefined = v8::Undefined(isolate);
  auto isTraceCategoryEnabled =
      binding->Get(env.local(), v8_str("isTraceCategoryEnabled"))
          .ToLocalChecked()
          .As<v8::Function>();

  {
    // Test with an enabled category
    v8::Local<v8::Value> argv[] = {v8_str("v8-cat")};
    auto result = isTraceCategoryEnabled->Call(env.local(), undefined, 1, argv)
                      .ToLocalChecked()
                      .As<v8::Boolean>();

    CHECK(result->BooleanValue(isolate));
  }

  {
    // Test with a disabled category
    v8::Local<v8::Value> argv[] = {v8_str("cat")};
    auto result = isTraceCategoryEnabled->Call(env.local(), undefined, 1, argv)
                      .ToLocalChecked()
                      .As<v8::Boolean>();

    CHECK(!result->BooleanValue(isolate));
  }

  {
    // Test with an enabled utf8 category
    v8::Local<v8::Value> argv[] = {v8_str("v8-cat\u20ac")};
    auto result = isTraceCategoryEnabled->Call(env.local(), undefined, 1, argv)
                      .ToLocalChecked()
                      .As<v8::Boolean>();

    CHECK(result->BooleanValue(isolate));
  }
}

TEST_WITH_PLATFORM(BuiltinsTrace, MockTracingPlatform) {
  CcTest::InitializeVM();

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  LocalContext env;

  v8::Local<v8::Object> binding = env->GetExtrasBindingObject();
  CHECK(!binding.IsEmpty());

  auto undefined = v8::Undefined(isolate);
  auto trace = binding->Get(env.local(), v8_str("trace"))
                   .ToLocalChecked()
                   .As<v8::Function>();

  // Test with disabled category
  {
    v8::Local<v8::String> category = v8_str("cat");
    v8::Local<v8::String> name = v8_str("name");
    v8::Local<v8::Value> argv[] = {
        v8::Integer::New(isolate, 'b'),                // phase
        category, name, v8::Integer::New(isolate, 0),  // id
        undefined                                      // data
    };
    auto result = trace->Call(env.local(), undefined, 5, argv)
                      .ToLocalChecked()
                      .As<v8::Boolean>();

    CHECK(!result->BooleanValue(isolate));
    CHECK_EQ(0, platform.NumberOfTraceObjects());
  }

  // Test with enabled category
  {
    v8::Local<v8::String> category = v8_str("v8-cat");
    v8::Local<v8::String> name = v8_str("name");
    v8::Local<v8::Object> data = v8::Object::New(isolate);
    data->Set(context, v8_str("foo"), v8_str("bar")).FromJust();
    v8::Local<v8::Value> argv[] = {
        v8::Integer::New(isolate, 'b'),                  // phase
        category, name, v8::Integer::New(isolate, 123),  // id
        data                                             // data arg
    };
    auto result = trace->Call(env.local(), undefined, 5, argv)
                      .ToLocalChecked()
                      .As<v8::Boolean>();

    CHECK(result->BooleanValue(isolate));
    CHECK_EQ(1, platform.NumberOfTraceObjects());

    CHECK_EQ(123, platform.GetTraceObject(0)->id);
    CHECK_EQ('b', platform.GetTraceObject(0)->phase);
    CHECK_EQ("name", platform.GetTraceObject(0)->name);
    CHECK_EQ(1, platform.GetTraceObject(0)->num_args);
  }

  // Test with enabled utf8 category
  {
    v8::Local<v8::String> category = v8_str("v8-cat\u20ac");
    v8::Local<v8::String> name = v8_str("name\u20ac");
    v8::Local<v8::Object> data = v8::Object::New(isolate);
    data->Set(context, v8_str("foo"), v8_str("bar")).FromJust();
    v8::Local<v8::Value> argv[] = {
        v8::Integer::New(isolate, 'b'),                  // phase
        category, name, v8::Integer::New(isolate, 123),  // id
        data                                             // data arg
    };
    auto result = trace->Call(env.local(), undefined, 5, argv)
                      .ToLocalChecked()
                      .As<v8::Boolean>();

    CHECK(result->BooleanValue(isolate));
    CHECK_EQ(2, platform.NumberOfTraceObjects());

    CHECK_EQ(123, platform.GetTraceObject(1)->id);
    CHECK_EQ('b', platform.GetTraceObject(1)->phase);
    CHECK_EQ("name\u20ac", platform.GetTraceObject(1)->name);
    CHECK_EQ(1, platform.GetTraceObject(1)->num_args);
  }
}
```