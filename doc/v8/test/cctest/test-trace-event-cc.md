Response:
Let's break down the thought process for analyzing the provided C++ code and generating the requested information.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `v8/test/cctest/test-trace-event.cc`. The prompt also specifies additional considerations like Torque files, JavaScript relationships, logical reasoning with input/output, and common programming errors.

**2. Initial Code Scan and High-Level Overview:**

The first step is a quick scan of the code to identify key elements:

* **Includes:**  `v8-function.h`, `v8-platform.h`, `v8.h`, `trace-event.h`, `cctest.h`. This immediately signals that the code is related to V8's internal testing framework (`cctest`) and specifically interacts with its tracing mechanism (`trace-event.h`).
* **Namespaces:**  The code uses an anonymous namespace and the global namespace implicitly.
* **`MockTraceObject` struct:**  This looks like a data structure to hold information about a trace event. The members (`phase`, `name`, `id`, etc.) are indicative of trace event properties.
* **`MockTracingController` class:** This class inherits from `v8::TracingController`. The methods like `AddTraceEventWithTimestamp` and `GetCategoryGroupEnabled` strongly suggest it's a custom implementation for testing purposes. It *intercepts* trace events instead of actually sending them somewhere. The `trace_objects_` member confirms this by storing the captured events.
* **`MockTracingPlatform` class:** This inherits from `TestPlatform` and returns the `MockTracingController`. This is part of the `cctest` framework, allowing tests to use custom platform implementations.
* **`TEST_WITH_PLATFORM` macros:** These are clearly part of the `cctest` framework and define individual test cases. Each test focuses on a specific aspect of the tracing functionality.
* **`TRACE_EVENT_*` macros:**  These are the core of the tracing mechanism being tested. The suffixes (e.g., `_BEGIN0`, `_END1`, `_INSTANT_WITH_TIMESTAMP0`) indicate different types of trace events and the number of arguments they take.
* **`CHECK_EQ` macro:** This is a standard assertion macro in `cctest`, used to verify expected outcomes.
* **`BuiltinsIsTraceCategoryEnabled` and `BuiltinsTrace` tests:** These tests interact with V8's built-in functions related to tracing, likely exposed through the `binding` object in JavaScript.

**3. Detailed Analysis of Key Components:**

* **`MockTraceObject`:**  This is straightforward. It's a simple structure to hold the attributes of a trace event. It helps in inspecting what the tracing macros are doing.
* **`MockTracingController`:** The crucial part here is that it *doesn't* perform actual tracing. Instead, it captures the information passed to the tracing macros and stores it in the `trace_objects_` vector. The `GetCategoryGroupEnabled` method provides a way to simulate category enabling/disabling for testing. The "v8-cat" category is explicitly enabled.
* **`MockTracingPlatform`:** This ties the custom controller into the testing framework. When the tests are run, they use this platform, and thus the custom tracing controller.

**4. Analyzing Individual Tests:**

Each `TEST_WITH_PLATFORM` block tests a specific scenario:

* **`TraceEventDisabledCategory`:** Verifies that events in disabled categories are not recorded.
* **`TraceEventNoArgs`:** Tests basic event creation without arguments.
* **`TraceEventWithOneArg`, `TraceEventWithTwoArgs`:** Tests events with arguments.
* **`ScopedTraceEvent`:** Demonstrates the convenience of using the macros within a scope to automatically generate begin/end events.
* **`TestEventWithFlow`:** Examines flow events and their flags.
* **`TestEventWithId`:** Tests asynchronous events and their IDs.
* **`TestEventWithTimestamp`:** Verifies the recording of timestamps.
* **`BuiltinsIsTraceCategoryEnabled`:** Tests the JavaScript function that checks if a trace category is enabled.
* **`BuiltinsTrace`:** Tests the JavaScript function that allows triggering trace events from JavaScript.

**5. Addressing Specific Prompt Requirements:**

* **Functionality:**  Summarize the purpose of each test and the overall goal of the file (testing V8's tracing mechanism).
* **Torque:** Explicitly state that the file is C++ and not a Torque file (since it doesn't end in `.tq`).
* **JavaScript Relationship:** Focus on the `BuiltinsIsTraceCategoryEnabled` and `BuiltinsTrace` tests. Explain how they interact with JavaScript and provide JavaScript examples that would trigger these built-in functions. This requires understanding how V8 exposes internal functionality to JavaScript (often through a `binding` object).
* **Logical Reasoning (Input/Output):**  Choose a simple test case (like `TraceEventNoArgs`) and illustrate the expected input (macro calls) and output (captured `MockTraceObject` data).
* **Common Programming Errors:** Think about how developers might misuse tracing. Examples include forgetting to `END` an event, using the wrong number of arguments in the macros, or relying on tracing in production code without proper configuration.

**6. Structuring the Output:**

Organize the information logically, following the order of the prompt's questions. Use clear headings and bullet points for readability. Provide code snippets where appropriate.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `MockTracingController` actually sends events somewhere.
* **Correction:**  Closer examination reveals the `trace_objects_` vector, indicating it's for capturing, not sending.
* **Initial thought:** Focus heavily on the C++ aspects.
* **Refinement:**  The prompt specifically asks about JavaScript interaction, so emphasize the `BuiltinsIsTraceCategoryEnabled` and `BuiltinsTrace` tests and provide relevant JavaScript examples.
* **Initial thought:**  Input/output should be a complex scenario.
* **Refinement:**  A simple case like `TraceEventNoArgs` is more illustrative for demonstrating the basic concept.

By following this structured approach, combining code analysis with an understanding of the prompt's requirements, and performing self-correction, we can arrive at a comprehensive and accurate explanation of the provided V8 source code.
好的，让我们来分析一下 `v8/test/cctest/test-trace-event.cc` 这个 V8 源代码文件的功能。

**文件功能概述:**

`v8/test/cctest/test-trace-event.cc` 是 V8 JavaScript 引擎的一个单元测试文件。它的主要目的是测试 V8 的**跟踪事件 (Trace Event)** 功能。  更具体地说，它测试了 V8 内部使用的用于记录性能和调试信息的 `TRACE_EVENT` 宏及其相关机制。

这个测试文件并没有实际地将跟踪事件输出到外部（例如文件），而是通过创建一个**模拟 (Mock)** 的跟踪控制器和平台来捕获和验证生成的跟踪事件数据。

**具体功能拆解:**

1. **模拟跟踪基础设施:**
   - 文件中定义了 `MockTraceObject` 结构体，用于存储捕获到的跟踪事件的各种属性，例如事件的阶段 (开始/结束/瞬时等)、名称、ID、绑定 ID、参数数量、标志和时间戳。
   - 定义了 `MockTracingController` 类，它继承自 `v8::TracingController`。这个类重写了 `AddTraceEventWithTimestamp` 等方法，**并没有真正地进行跟踪操作，而是将跟踪事件的信息存储到 `trace_objects_` 向量中**。它还模拟了类别启用状态的判断 (`GetCategoryGroupEnabled`)。
   - 定义了 `MockTracingPlatform` 类，它继承自 `TestPlatform`。这个类提供了 `MockTracingController` 的实例，使得测试可以使用模拟的跟踪基础设施。

2. **测试 `TRACE_EVENT` 宏的不同用法:**
   - 文件中包含了多个以 `TEST_WITH_PLATFORM` 开头的测试用例，每个用例都测试了 `TRACE_EVENT` 宏的不同变体和使用场景：
     - `TraceEventDisabledCategory`: 测试在禁用类别下，事件不会被记录。
     - `TraceEventNoArgs`: 测试不带参数的 `TRACE_EVENT_BEGIN0` 和 `TRACE_EVENT_END0`。
     - `TraceEventWithOneArg`, `TraceEventWithTwoArgs`: 测试带有不同数量参数的 `TRACE_EVENT_BEGIN` 和 `TRACE_EVENT_END` 宏。
     - `ScopedTraceEvent`: 测试使用 `TRACE_EVENT0`, `TRACE_EVENT1`, `TRACE_EVENT2` 宏创建的作用域跟踪事件。
     - `TestEventWithFlow`: 测试带有流 ID 和标志的 `TRACE_EVENT_WITH_FLOW0` 宏。
     - `TestEventWithId`: 测试异步跟踪事件的 `TRACE_EVENT_ASYNC_BEGIN0` 和 `TRACE_EVENT_ASYNC_END0` 宏。
     - `TestEventWithTimestamp`: 测试带有时间戳的瞬时、标记和异步跟踪事件宏。

3. **测试 JavaScript 中与跟踪相关的内置函数:**
   - `BuiltinsIsTraceCategoryEnabled`: 测试 V8 的 JavaScript 内置函数 `isTraceCategoryEnabled`，该函数用于检查指定的跟踪类别是否已启用。测试用例验证了启用和禁用的类别，以及包含 UTF-8 字符的类别名称。
   - `BuiltinsTrace`: 测试 V8 的 JavaScript 内置函数 `trace`，该函数允许从 JavaScript 代码中手动触发跟踪事件。测试用例验证了在启用和禁用类别下调用 `trace` 函数的行为，以及传递不同的参数（包括数据对象）。

**关于文件后缀和 Torque:**

如果 `v8/test/cctest/test-trace-event.cc` 的文件名以 `.tq` 结尾，那么它就是一个 V8 Torque 源代码文件。Torque 是 V8 用于定义运行时内置函数的一种领域特定语言。然而，这个文件的后缀是 `.cc`，表明它是一个 C++ 源代码文件。因此，它不是 Torque 代码。

**与 JavaScript 功能的关系及示例:**

`v8/test/cctest/test-trace-event.cc` 中的 `BuiltinsIsTraceCategoryEnabled` 和 `BuiltinsTrace` 测试用例直接关联到 V8 暴露给 JavaScript 的跟踪功能。

**JavaScript 示例:**

```javascript
// 假设在 V8 环境中运行

// 检查 'v8-cat' 类别是否已启用
let isEnabled = isTraceCategoryEnabled('v8-cat');
console.log(isEnabled); // 输出 true (根据测试代码中的模拟)

// 检查 'cat' 类别是否已启用
isEnabled = isTraceCategoryEnabled('cat');
console.log(isEnabled); // 输出 false

// 触发一个跟踪事件
trace('b', 'v8-cat', 'myEvent', 123, { foo: 'bar' });
```

在这个 JavaScript 示例中：

- `isTraceCategoryEnabled('v8-cat')` 会调用 V8 内部的 `isTraceCategoryEnabled` 函数，该函数在测试环境中会被 `MockTracingController::GetCategoryGroupEnabled` 模拟，返回 true。
- `trace('b', 'v8-cat', 'myEvent', 123, { foo: 'bar' })` 会调用 V8 内部的 `trace` 函数，该函数在测试环境中会被 `MockTracingController::AddTraceEventWithTimestamp` 捕获，并存储相应的事件信息。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (来自 `TraceEventNoArgs` 测试用例):**

```c++
TRACE_EVENT_BEGIN0("v8-cat", "e1");
TRACE_EVENT_END0("v8-cat", "e1");
```

**模拟跟踪控制器 `MockTracingController` 的行为：**

1. 当执行 `TRACE_EVENT_BEGIN0("v8-cat", "e1");` 时：
   - `GetCategoryGroupEnabled("v8-cat")` 被调用，由于 "v8-cat" 是模拟启用的类别，返回一个表示启用的值。
   - `AddTraceEventWithTimestamp` 方法被调用，参数如下（部分）：
     - `phase`: 'B' (Begin)
     - `name`: "e1"
     - `num_args`: 0
   - 创建一个新的 `MockTraceObject` 实例，并添加到 `trace_objects_` 向量中。

2. 当执行 `TRACE_EVENT_END0("v8-cat", "e1");` 时：
   - `GetCategoryGroupEnabled("v8-cat")` 被调用，返回启用状态。
   - `AddTraceEventWithTimestamp` 方法被调用，参数如下（部分）：
     - `phase`: 'E' (End)
     - `name`: "e1"
     - `num_args`: 0
   - 创建一个新的 `MockTraceObject` 实例，并添加到 `trace_objects_` 向量中。

**预期输出 (验证部分):**

```c++
CHECK_EQ(2, platform.NumberOfTraceObjects()); // 捕获到 2 个跟踪对象
CHECK_EQ('B', platform.GetTraceObject(0)->phase); // 第一个对象的 phase 是 'B'
CHECK_EQ("e1", platform.GetTraceObject(0)->name); // 第一个对象的 name 是 "e1"
CHECK_EQ(0, platform.GetTraceObject(0)->num_args); // 第一个对象的参数数量是 0

CHECK_EQ('E', platform.GetTraceObject(1)->phase); // 第二个对象的 phase 是 'E'
CHECK_EQ("e1", platform.GetTraceObject(1)->name); // 第二个对象的 name 是 "e1"
CHECK_EQ(0, platform.GetTraceObject(1)->num_args); // 第二个对象的参数数量是 0
```

**涉及用户常见的编程错误 (举例说明):**

1. **忘记配对 `TRACE_EVENT_BEGIN` 和 `TRACE_EVENT_END`:**
   - 如果用户调用了 `TRACE_EVENT_BEGIN` 但忘记了调用相应的 `TRACE_EVENT_END`，可能会导致跟踪数据不完整，无法正确计算持续时间。
   ```c++
   // 错误示例
   TRACE_EVENT_BEGIN0("my-category", "my-event");
   // ... 一些代码 ...
   // 忘记调用 TRACE_EVENT_END0("my-category", "my-event");
   ```

2. **`TRACE_EVENT` 宏的参数数量不匹配:**
   - 使用 `TRACE_EVENT_BEGIN1` 却不提供一个参数，或者提供错误类型的参数，会导致编译错误或未定义的行为。
   ```c++
   // 错误示例：参数数量不匹配
   TRACE_EVENT_BEGIN1("my-category", "my-event"); // 缺少一个参数

   // 错误示例：参数类型不匹配 (假设期望的是整数)
   TRACE_EVENT_BEGIN1("my-category", "my-event", "not an integer");
   ```

3. **在不应该使用跟踪宏的地方使用:**
   - 在性能关键的代码路径中过度使用跟踪宏，即使类别被禁用，也会带来一定的性能开销（虽然很小）。应该根据需要合理地添加跟踪点。

4. **在 JavaScript 中使用 `trace` 时传递错误的参数类型或数量:**
   -  `trace` 函数期望特定类型的参数（phase 为字符或数字，category 和 name 为字符串，id 为数字，data 为对象或 undefined）。传递错误的类型可能导致错误或跟踪数据丢失。
   ```javascript
   // JavaScript 错误示例
   trace(123, 'my-category', 'my-event', 'not a number', { data: 'ok' }); // phase 应该是字符
   trace('b', 123, 'my-event', 1, {}); // category 应该是字符串
   ```

总而言之，`v8/test/cctest/test-trace-event.cc` 是一个重要的测试文件，它通过模拟的方式全面地测试了 V8 内部跟踪事件机制的正确性和功能，并间接地测试了暴露给 JavaScript 的相关 API。这有助于确保 V8 的跟踪功能能够可靠地用于性能分析和调试。

Prompt: 
```
这是目录为v8/test/cctest/test-trace-event.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-trace-event.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```