Response: The user wants a summary of the C++ source code file `v8/test/unittests/libplatform/tracing-unittest.cc`. This file seems to contain unit tests for the tracing functionality within the V8 JavaScript engine's platform abstraction layer.

Here's a breakdown of the thought process to arrive at the summary and JavaScript example:

1. **Identify the core purpose:** The file name strongly suggests it's about testing the "tracing" functionality. The directory `unittests` confirms this. The `libplatform` part indicates it's testing the platform-independent tracing API.

2. **Scan the includes:**  The includes provide valuable clues about the components being tested:
    * `"include/libplatform/v8-tracing.h"`:  This is likely the main header defining the tracing API.
    * `"src/base/platform/platform.h"` and `"src/libplatform/default-platform.h"`:  These suggest testing the interaction with the underlying platform and the default platform implementation.
    * `"src/tracing/trace-event.h"`:  This is the core tracing mechanism within V8.
    * `"testing/gtest/include/gtest/gtest.h"`: Confirms it's using Google Test for unit testing.
    * The `perfetto` includes (when `V8_USE_PERFETTO` is defined) indicate that the tracing system can integrate with the Perfetto tracing framework.

3. **Examine the test structure:** The file uses Google Test's `TEST_F` macro, indicating that the tests are grouped within a fixture class (`PlatformTracingTest`). This class likely provides common setup.

4. **Analyze individual tests (without Perfetto):**
    * `TestTraceConfig`: Tests the `TraceConfig` class, which is responsible for configuring tracing, such as enabling/disabling categories.
    * `TestTraceObject`: Tests the `TraceObject` class, which represents a single trace event. It checks the initialization and properties of a trace event.
    * `TestTraceBufferRingBuffer`: Tests a specific `TraceBuffer` implementation (ring buffer), verifying its ability to store and retrieve trace events and handle buffer overflow.
    * `TestJSONTraceWriter`: Tests the `JSONTraceWriter`, ensuring it correctly formats trace events into JSON. It also checks the functionality of adding a custom tag.
    * `TestTracingController`: Tests the `TracingController`, which manages the tracing process. It verifies that it correctly starts and stops tracing and filters events based on categories.
    * `TestTracingControllerMultipleArgsAndCopy`:  Tests the ability to log trace events with various argument types and verifies that string arguments are copied correctly. It also includes tests for `TRACE_EVENT_INSTANT` with custom formatting objects.
    * `TracingObservers`: Tests the mechanism for observing trace state changes (enabled/disabled).
    * `AddTraceEventMultiThreaded`: Checks that adding trace events from multiple threads is handled correctly.

5. **Analyze individual tests (with Perfetto):** The tests under `V8_USE_PERFETTO` are effectively replacements or adaptations of the non-Perfetto tests. They use Perfetto's API directly. Key things to note:
    * They don't use `TraceObject` or the ring buffer directly.
    * They utilize a `TestListener` to parse the Perfetto trace stream.
    * The tests verify the correct formatting of trace events in the Perfetto format.

6. **Identify the relationship with JavaScript:** The tracing functionality in V8 is used to monitor the execution of JavaScript code. Trace events can be emitted at various points during JavaScript execution, providing insights into performance and behavior.

7. **Construct the JavaScript example:**  To illustrate the connection, demonstrate how JavaScript code can trigger the underlying C++ tracing mechanism. The `console.time()` and `console.timeEnd()` methods are the most direct and user-facing way to interact with V8's tracing from JavaScript. Explain how these JavaScript calls map to the creation of trace events within the C++ layer.

8. **Summarize the findings:** Combine the analysis of individual tests and the overall purpose of the file into a concise summary, highlighting the tested components and functionalities. Mention the conditional compilation for Perfetto.

9. **Review and refine:** Ensure the summary is clear, accurate, and addresses the user's request. Check the JavaScript example for correctness and clarity. Make sure to mention the connection between JavaScript's `console.time` and the underlying tracing mechanism.
这个C++源代码文件 `v8/test/unittests/libplatform/tracing-unittest.cc` 是 V8 JavaScript 引擎的一部分，它的主要功能是**对 V8 平台的 tracing（追踪）功能进行单元测试**。

具体来说，这个文件测试了以下几个方面的 tracing 功能：

1. **`TraceConfig`**:  测试了 `TraceConfig` 类的功能，这个类用于配置 tracing，例如指定需要包含的 tracing 分类（categories）。通过 `AddIncludedCategory` 方法添加需要追踪的分类，并通过 `IsCategoryGroupEnabled` 方法检查某个分类是否被启用。

2. **`TraceObject` (在未使用 Perfetto 的情况下)**: 测试了 `TraceObject` 类的功能，这个类代表一个单独的追踪事件。测试了 `TraceObject` 的初始化和属性设置。

3. **`TraceBuffer` (在未使用 Perfetto 的情况下)**: 测试了 `TraceBuffer` 的环形缓冲区实现 (`CreateTraceBufferRingBuffer`)。测试了向缓冲区添加追踪事件 (`AddTraceEvent`)，根据句柄获取事件 (`GetEventByHandle`) 以及刷新缓冲区 (`Flush`) 的功能。这部分测试了缓冲区在容量有限的情况下，旧的事件被覆盖，只能获取到最近的事件。

4. **`TraceWriter` (在未使用 Perfetto 的情况下)**: 测试了将追踪事件写入不同格式的功能，特别是 `JSONTraceWriter`。测试了将 `TraceObject` 转换为 JSON 格式，并可以添加自定义的标签。

5. **`TracingController`**: 测试了 `TracingController` 类的功能，这个类负责管理 tracing 的生命周期，包括开始 (`StartTracing`) 和停止 (`StopTracing`) tracing，以及根据配置的分类来过滤追踪事件。

6. **多线程 tracing (在未使用 Perfetto 的情况下)**: 测试了在多线程环境下添加追踪事件的安全性。

7. **与 Perfetto 集成 (在定义了 `V8_USE_PERFETTO` 的情况下)**:  如果定义了 `V8_USE_PERFETTO` 宏，则会测试 V8 的 tracing 功能与 Perfetto 追踪框架的集成。这部分测试使用了 Perfetto 提供的 API 来发送和接收追踪事件，并验证事件的正确性。

**它与 JavaScript 的功能的关系：**

V8 引擎的 tracing 功能可以用来追踪 JavaScript 代码的执行过程，例如函数调用、垃圾回收、编译优化等。这些 tracing 信息可以用于性能分析和调试。

当 JavaScript 代码执行时，V8 引擎会在关键点生成 tracing 事件，这些事件会被 `TracingController` 管理，并根据配置写入到不同的输出（例如 JSON 文件）。

**JavaScript 示例：**

虽然这段 C++ 代码本身是测试代码，但它测试的 tracing 功能可以直接被 JavaScript 代码触发。例如，在 Chrome 开发者工具中启用 tracing 功能后，执行以下 JavaScript 代码将会产生 tracing 事件：

```javascript
console.time("myFunction");

// 一些需要追踪的代码
for (let i = 0; i < 1000; i++) {
  // ...
}

console.timeEnd("myFunction");
```

在这个例子中，`console.time("myFunction")` 和 `console.timeEnd("myFunction")` 会在 V8 内部生成相应的 tracing 事件，这些事件会被 `TracingController` 捕获并记录下来。  这些事件可能包含了 "myFunction" 开始和结束的时间戳，以及执行 duration 等信息。

在 C++ 的测试代码中，类似 `TRACE_EVENT0("v8", "v8.Test");` 的宏调用就模拟了 JavaScript 代码执行时可能触发的 tracing 事件的生成。`"v8"` 就是一个 tracing 的分类，可以对应到 V8 引擎内部的某个模块或功能。

**总结:**

`v8/test/unittests/libplatform/tracing-unittest.cc` 文件通过单元测试验证了 V8 平台层 tracing 功能的正确性，包括配置、事件对象、缓冲区管理、输出格式以及控制器的行为。这些底层的 tracing 功能是支持 JavaScript 性能分析和调试的重要基础。当你在 Chrome 开发者工具中进行性能分析时，背后就有这些 tracing 机制在工作。

Prompt: 
```
这是目录为v8/test/unittests/libplatform/tracing-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <limits>

#include "include/libplatform/v8-tracing.h"
#include "src/base/platform/platform.h"
#include "src/libplatform/default-platform.h"
#include "src/tracing/trace-event.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

#ifdef V8_USE_PERFETTO
#include "perfetto/tracing/track_event.h"         // nogncheck
#include "perfetto/tracing/track_event_legacy.h"  // nogncheck
#include "protos/perfetto/trace/trace.pb.h"  // nogncheck
#include "src/libplatform/tracing/trace-event-listener.h"
#include "src/tracing/traced-value.h"
#endif  // V8_USE_PERFETTO

namespace v8 {
namespace platform {
namespace tracing {

class PlatformTracingTest : public TestWithPlatform {};

TEST_F(PlatformTracingTest, TestTraceConfig) {
  TraceConfig* trace_config = new TraceConfig();
  trace_config->AddIncludedCategory("v8");
  trace_config->AddIncludedCategory(TRACE_DISABLED_BY_DEFAULT("v8.runtime"));

  CHECK_EQ(trace_config->IsSystraceEnabled(), false);
  CHECK_EQ(trace_config->IsArgumentFilterEnabled(), false);
  CHECK_EQ(trace_config->IsCategoryGroupEnabled("v8"), true);
  CHECK_EQ(trace_config->IsCategoryGroupEnabled("v8.cpu_profile"), false);
  CHECK_EQ(trace_config->IsCategoryGroupEnabled(
               TRACE_DISABLED_BY_DEFAULT("v8.runtime")),
           true);
  CHECK_EQ(trace_config->IsCategoryGroupEnabled("v8,v8.cpu_profile"), true);
  CHECK_EQ(
      trace_config->IsCategoryGroupEnabled("v8,disabled-by-default-v8.runtime"),
      true);
  CHECK_EQ(trace_config->IsCategoryGroupEnabled("v8_cpu_profile"), false);

  delete trace_config;
}

// Perfetto doesn't use TraceObject.
#if !defined(V8_USE_PERFETTO)
TEST_F(PlatformTracingTest, TestTraceObject) {
  TraceObject trace_object;
  uint8_t category_enabled_flag = 41;
  trace_object.Initialize('X', &category_enabled_flag, "Test.Trace",
                          "Test.Scope", 42, 123, 0, nullptr, nullptr, nullptr,
                          nullptr, 0, 1729, 4104);
  CHECK_EQ('X', trace_object.phase());
  CHECK_EQ(category_enabled_flag, *trace_object.category_enabled_flag());
  CHECK_EQ(std::string("Test.Trace"), std::string(trace_object.name()));
  CHECK_EQ(std::string("Test.Scope"), std::string(trace_object.scope()));
  CHECK_EQ(0u, trace_object.duration());
  CHECK_EQ(0u, trace_object.cpu_duration());
}

class ConvertableToTraceFormatMock : public v8::ConvertableToTraceFormat {
 public:
  ConvertableToTraceFormatMock(const ConvertableToTraceFormatMock&) = delete;
  ConvertableToTraceFormatMock& operator=(const ConvertableToTraceFormatMock&) =
      delete;
  explicit ConvertableToTraceFormatMock(int value) : value_(value) {}
  void AppendAsTraceFormat(std::string* out) const override {
    *out += "[" + std::to_string(value_) + "," + std::to_string(value_) + "]";
  }

 private:
  int value_;
};

class MockTraceWriter : public TraceWriter {
 public:
  void AppendTraceEvent(TraceObject* trace_event) override {
    // TraceObject might not have been initialized.
    const char* name = trace_event->name() ? trace_event->name() : "";
    events_.push_back(name);
  }

  void Flush() override {}

  std::vector<std::string> events() { return events_; }

 private:
  std::vector<std::string> events_;
};
#endif  // !defined(V8_USE_PERFETTO)

// Perfetto doesn't use the ring buffer.
#if !defined(V8_USE_PERFETTO)
TEST_F(PlatformTracingTest, TestTraceBufferRingBuffer) {
  // We should be able to add kChunkSize * 2 + 1 trace events.
  const int HANDLES_COUNT = TraceBufferChunk::kChunkSize * 2 + 1;
  MockTraceWriter* writer = new MockTraceWriter();
  TraceBuffer* ring_buffer =
      TraceBuffer::CreateTraceBufferRingBuffer(2, writer);
  std::string names[HANDLES_COUNT];
  for (int i = 0; i < HANDLES_COUNT; ++i) {
    names[i] = "Test.EventNo" + std::to_string(i);
  }

  std::vector<uint64_t> handles(HANDLES_COUNT);
  uint8_t category_enabled_flag = 41;
  for (size_t i = 0; i < handles.size(); ++i) {
    TraceObject* trace_object = ring_buffer->AddTraceEvent(&handles[i]);
    CHECK_NOT_NULL(trace_object);
    trace_object->Initialize('X', &category_enabled_flag, names[i].c_str(),
                             "Test.Scope", 42, 123, 0, nullptr, nullptr,
                             nullptr, nullptr, 0, 1729, 4104);
    trace_object = ring_buffer->GetEventByHandle(handles[i]);
    CHECK_NOT_NULL(trace_object);
    CHECK_EQ('X', trace_object->phase());
    CHECK_EQ(names[i], std::string(trace_object->name()));
    CHECK_EQ(category_enabled_flag, *trace_object->category_enabled_flag());
  }

  // We should only be able to retrieve the last kChunkSize + 1.
  for (size_t i = 0; i < TraceBufferChunk::kChunkSize; ++i) {
    CHECK_NULL(ring_buffer->GetEventByHandle(handles[i]));
  }

  for (size_t i = TraceBufferChunk::kChunkSize; i < handles.size(); ++i) {
    TraceObject* trace_object = ring_buffer->GetEventByHandle(handles[i]);
    CHECK_NOT_NULL(trace_object);
    // The object properties should be correct.
    CHECK_EQ('X', trace_object->phase());
    CHECK_EQ(names[i], std::string(trace_object->name()));
    CHECK_EQ(category_enabled_flag, *trace_object->category_enabled_flag());
  }

  // Check Flush(), that the writer wrote the last kChunkSize  1 event names.
  ring_buffer->Flush();
  auto events = writer->events();
  CHECK_EQ(TraceBufferChunk::kChunkSize + 1, events.size());
  for (size_t i = TraceBufferChunk::kChunkSize; i < handles.size(); ++i) {
    CHECK_EQ(names[i], events[i - TraceBufferChunk::kChunkSize]);
  }
  delete ring_buffer;
}
#endif  // !defined(V8_USE_PERFETTO)

// Perfetto has an internal JSON exporter.
#if !defined(V8_USE_PERFETTO)
void PopulateJSONWriter(TraceWriter* writer) {
  v8::Platform* old_platform = i::V8::GetCurrentPlatform();
  std::unique_ptr<v8::Platform> default_platform(
      v8::platform::NewDefaultPlatform());
  i::V8::SetPlatformForTesting(default_platform.get());
  auto tracing = std::make_unique<v8::platform::tracing::TracingController>();
  v8::platform::tracing::TracingController* tracing_controller = tracing.get();
  static_cast<v8::platform::DefaultPlatform*>(default_platform.get())
      ->SetTracingController(std::move(tracing));

  TraceBuffer* ring_buffer =
      TraceBuffer::CreateTraceBufferRingBuffer(1, writer);
  tracing_controller->Initialize(ring_buffer);
  TraceConfig* trace_config = new TraceConfig();
  trace_config->AddIncludedCategory("v8-cat");
  tracing_controller->StartTracing(trace_config);

  TraceObject trace_object;
  trace_object.InitializeForTesting(
      'X', tracing_controller->GetCategoryGroupEnabled("v8-cat"), "Test0",
      v8::internal::tracing::kGlobalScope, 42, 0x1234, 0, nullptr, nullptr,
      nullptr, nullptr, TRACE_EVENT_FLAG_HAS_ID, 11, 22, 100, 50, 33, 44);
  writer->AppendTraceEvent(&trace_object);
  trace_object.InitializeForTesting(
      'Y', tracing_controller->GetCategoryGroupEnabled("v8-cat"), "Test1",
      v8::internal::tracing::kGlobalScope, 43, 0x5678, 0, nullptr, nullptr,
      nullptr, nullptr, TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
      55, 66, 110, 55, 77, 88);
  writer->AppendTraceEvent(&trace_object);
  tracing_controller->StopTracing();
  i::V8::SetPlatformForTesting(old_platform);
}

TEST_F(PlatformTracingTest, TestJSONTraceWriter) {
  std::ostringstream stream;
  TraceWriter* writer = TraceWriter::CreateJSONTraceWriter(stream);
  PopulateJSONWriter(writer);
  std::string trace_str = stream.str();
  std::string expected_trace_str =
      "{\"traceEvents\":[{\"pid\":11,\"tid\":22,\"ts\":100,\"tts\":50,"
      "\"ph\":\"X\",\"cat\":\"v8-cat\",\"name\":\"Test0\",\"dur\":33,"
      "\"tdur\":44,\"id\":\"0x2a\",\"args\":{}},{\"pid\":55,\"tid\":66,"
      "\"ts\":110,\"tts\":55,\"ph\":\"Y\",\"cat\":\"v8-cat\",\"name\":"
      "\"Test1\",\"dur\":77,\"tdur\":88,\"bind_id\":\"0x5678\","
      "\"flow_in\":true,\"flow_out\":true,\"args\":{}}]}";

  CHECK_EQ(expected_trace_str, trace_str);
}

TEST_F(PlatformTracingTest, TestJSONTraceWriterWithCustomtag) {
  std::ostringstream stream;
  TraceWriter* writer = TraceWriter::CreateJSONTraceWriter(stream, "customTag");
  PopulateJSONWriter(writer);
  std::string trace_str = stream.str();
  std::string expected_trace_str =
      "{\"customTag\":[{\"pid\":11,\"tid\":22,\"ts\":100,\"tts\":50,"
      "\"ph\":\"X\",\"cat\":\"v8-cat\",\"name\":\"Test0\",\"dur\":33,"
      "\"tdur\":44,\"id\":\"0x2a\",\"args\":{}},{\"pid\":55,\"tid\":66,"
      "\"ts\":110,\"tts\":55,\"ph\":\"Y\",\"cat\":\"v8-cat\",\"name\":"
      "\"Test1\",\"dur\":77,\"tdur\":88,\"bind_id\":\"0x5678\","
      "\"flow_in\":true,\"flow_out\":true,\"args\":{}}]}";

  CHECK_EQ(expected_trace_str, trace_str);
}
#endif  // !defined(V8_USE_PERFETTO)

void GetJSONStrings(std::vector<std::string>* ret, const std::string& str,
                    const std::string& param, const std::string& start_delim,
                    const std::string& end_delim) {
  size_t pos = str.find(param);
  while (pos != std::string::npos) {
    size_t start_pos = str.find(start_delim, pos + param.length());
    size_t end_pos = str.find(end_delim, start_pos + 1);
    CHECK_NE(start_pos, std::string::npos);
    CHECK_NE(end_pos, std::string::npos);
    ret->push_back(str.substr(start_pos + 1, end_pos - start_pos - 1));
    pos = str.find(param, pos + 1);
  }
}

// With Perfetto the tracing controller doesn't observe events.
#if !defined(V8_USE_PERFETTO)
TEST_F(PlatformTracingTest, TestTracingController) {
  v8::Platform* old_platform = i::V8::GetCurrentPlatform();
  std::unique_ptr<v8::Platform> default_platform(
      v8::platform::NewDefaultPlatform());
  i::V8::SetPlatformForTesting(default_platform.get());

  auto tracing = std::make_unique<v8::platform::tracing::TracingController>();
  v8::platform::tracing::TracingController* tracing_controller = tracing.get();
  static_cast<v8::platform::DefaultPlatform*>(default_platform.get())
      ->SetTracingController(std::move(tracing));

  MockTraceWriter* writer = new MockTraceWriter();
  TraceBuffer* ring_buffer =
      TraceBuffer::CreateTraceBufferRingBuffer(1, writer);
  tracing_controller->Initialize(ring_buffer);
  TraceConfig* trace_config = new TraceConfig();
  trace_config->AddIncludedCategory("v8");
  tracing_controller->StartTracing(trace_config);

  TRACE_EVENT0("v8", "v8.Test");
  // cat category is not included in default config
  TRACE_EVENT0("cat", "v8.Test2");
  TRACE_EVENT0("v8", "v8.Test3");
  tracing_controller->StopTracing();

  CHECK_EQ(2u, writer->events().size());
  CHECK_EQ(std::string("v8.Test"), writer->events()[0]);
  CHECK_EQ(std::string("v8.Test3"), writer->events()[1]);

  i::V8::SetPlatformForTesting(old_platform);
}

TEST_F(PlatformTracingTest, TestTracingControllerMultipleArgsAndCopy) {
  std::ostringstream stream, perfetto_stream;
  uint64_t aa = 11;
  unsigned int bb = 22;
  uint16_t cc = 33;
  unsigned char dd = 44;
  int64_t ee = -55;
  int ff = -66;
  int16_t gg = -77;
  signed char hh = -88;
  bool ii1 = true;
  bool ii2 = false;
  double jj1 = 99.0;
  double jj2 = 1e100;
  double jj3 = std::numeric_limits<double>::quiet_NaN();
  double jj4 = std::numeric_limits<double>::infinity();
  double jj5 = -std::numeric_limits<double>::infinity();
  void* kk = &aa;
  const char* ll = "100";
  std::string mm = "INIT";
  std::string mmm = "\"INIT\"";

  // Create a scope for the tracing controller to terminate the trace writer.
  {
    v8::Platform* old_platform = i::V8::GetCurrentPlatform();
    std::unique_ptr<v8::Platform> default_platform(
        v8::platform::NewDefaultPlatform());
    i::V8::SetPlatformForTesting(default_platform.get());

    auto tracing = std::make_unique<v8::platform::tracing::TracingController>();
    v8::platform::tracing::TracingController* tracing_controller =
        tracing.get();
    static_cast<v8::platform::DefaultPlatform*>(default_platform.get())
        ->SetTracingController(std::move(tracing));
    TraceWriter* writer = TraceWriter::CreateJSONTraceWriter(stream);

    TraceBuffer* ring_buffer =
        TraceBuffer::CreateTraceBufferRingBuffer(1, writer);
    tracing_controller->Initialize(ring_buffer);
    TraceConfig* trace_config = new TraceConfig();
    trace_config->AddIncludedCategory("v8");
    tracing_controller->StartTracing(trace_config);

    {
      TRACE_EVENT1("v8", "v8.Test.aa", "aa", aa);
      TRACE_EVENT1("v8", "v8.Test.bb", "bb", bb);
      TRACE_EVENT1("v8", "v8.Test.cc", "cc", cc);
      TRACE_EVENT1("v8", "v8.Test.dd", "dd", dd);
      TRACE_EVENT1("v8", "v8.Test.ee", "ee", ee);
      TRACE_EVENT1("v8", "v8.Test.ff", "ff", ff);
      TRACE_EVENT1("v8", "v8.Test.gg", "gg", gg);
      TRACE_EVENT1("v8", "v8.Test.hh", "hh", hh);
      TRACE_EVENT1("v8", "v8.Test.ii", "ii1", ii1);
      TRACE_EVENT1("v8", "v8.Test.ii", "ii2", ii2);
      TRACE_EVENT1("v8", "v8.Test.jj1", "jj1", jj1);
      TRACE_EVENT1("v8", "v8.Test.jj2", "jj2", jj2);
      TRACE_EVENT1("v8", "v8.Test.jj3", "jj3", jj3);
      TRACE_EVENT1("v8", "v8.Test.jj4", "jj4", jj4);
      TRACE_EVENT1("v8", "v8.Test.jj5", "jj5", jj5);
      TRACE_EVENT1("v8", "v8.Test.kk", "kk", kk);
      TRACE_EVENT1("v8", "v8.Test.ll", "ll", ll);
      TRACE_EVENT1("v8", "v8.Test.mm", "mm", TRACE_STR_COPY(mmm.c_str()));

      TRACE_EVENT2("v8", "v8.Test2.1", "aa", aa, "ll", ll);
      TRACE_EVENT2("v8", "v8.Test2.2", "mm1", TRACE_STR_COPY(mm.c_str()), "mm2",
                   TRACE_STR_COPY(mmm.c_str()));

      // Check copies are correct.
      TRACE_EVENT_COPY_INSTANT0("v8", mm.c_str(), TRACE_EVENT_SCOPE_THREAD);
      TRACE_EVENT_COPY_INSTANT2("v8", mm.c_str(), TRACE_EVENT_SCOPE_THREAD,
                                "mm1", mm.c_str(), "mm2", mmm.c_str());
      mm = "CHANGED";
      mmm = "CHANGED";

      TRACE_EVENT_INSTANT1("v8", "v8.Test", TRACE_EVENT_SCOPE_THREAD, "a1",
                           new ConvertableToTraceFormatMock(42));
      std::unique_ptr<ConvertableToTraceFormatMock> trace_event_arg(
          new ConvertableToTraceFormatMock(42));
      TRACE_EVENT_INSTANT2("v8", "v8.Test", TRACE_EVENT_SCOPE_THREAD, "a1",
                           std::move(trace_event_arg), "a2",
                           new ConvertableToTraceFormatMock(123));
    }

    tracing_controller->StopTracing();

    i::V8::SetPlatformForTesting(old_platform);
  }

  std::string trace_str = stream.str();

  std::vector<std::string> all_args, all_names, all_cats;
  GetJSONStrings(&all_args, trace_str, "\"args\"", "{", "}");
  GetJSONStrings(&all_names, trace_str, "\"name\"", "\"", "\"");
  GetJSONStrings(&all_cats, trace_str, "\"cat\"", "\"", "\"");

  CHECK_EQ(all_args.size(), 24u);
  CHECK_EQ(all_args[0], "\"aa\":11");
  CHECK_EQ(all_args[1], "\"bb\":22");
  CHECK_EQ(all_args[2], "\"cc\":33");
  CHECK_EQ(all_args[3], "\"dd\":44");
  CHECK_EQ(all_args[4], "\"ee\":-55");
  CHECK_EQ(all_args[5], "\"ff\":-66");
  CHECK_EQ(all_args[6], "\"gg\":-77");
  CHECK_EQ(all_args[7], "\"hh\":-88");
  CHECK_EQ(all_args[8], "\"ii1\":true");
  CHECK_EQ(all_args[9], "\"ii2\":false");
  CHECK_EQ(all_args[10], "\"jj1\":99.0");
  CHECK_EQ(all_args[11], "\"jj2\":1e+100");
  CHECK_EQ(all_args[12], "\"jj3\":\"NaN\"");
  CHECK_EQ(all_args[13], "\"jj4\":\"Infinity\"");
  CHECK_EQ(all_args[14], "\"jj5\":\"-Infinity\"");
  std::ostringstream pointer_stream;
  pointer_stream << "\"kk\":\"" << &aa << "\"";
  CHECK_EQ(all_args[15], pointer_stream.str());
  CHECK_EQ(all_args[16], "\"ll\":\"100\"");
  CHECK_EQ(all_args[17], "\"mm\":\"\\\"INIT\\\"\"");

  CHECK_EQ(all_names[18], "v8.Test2.1");
  CHECK_EQ(all_args[18], "\"aa\":11,\"ll\":\"100\"");
  CHECK_EQ(all_args[19], "\"mm1\":\"INIT\",\"mm2\":\"\\\"INIT\\\"\"");

  CHECK_EQ(all_names[20], "INIT");
  CHECK_EQ(all_names[21], "INIT");
  CHECK_EQ(all_args[21], "\"mm1\":\"INIT\",\"mm2\":\"\\\"INIT\\\"\"");
  CHECK_EQ(all_args[22], "\"a1\":[42,42]");
  CHECK_EQ(all_args[23], "\"a1\":[42,42],\"a2\":[123,123]");
}
#endif  // !defined(V8_USE_PERFETTO)

// In Perfetto build there are no TracingObservers. Instead the code relies on
// TrackEventSessionObserver to track tracing sessions, which is tested
// upstream.
#if !defined(V8_USE_PERFETTO)
namespace {

class TraceStateObserverImpl : public TracingController::TraceStateObserver {
 public:
  void OnTraceEnabled() override { ++enabled_count; }
  void OnTraceDisabled() override { ++disabled_count; }

  int enabled_count = 0;
  int disabled_count = 0;
};

}  // namespace

TEST_F(PlatformTracingTest, TracingObservers) {
  v8::Platform* old_platform = i::V8::GetCurrentPlatform();
  std::unique_ptr<v8::Platform> default_platform(
      v8::platform::NewDefaultPlatform());
  i::V8::SetPlatformForTesting(default_platform.get());

  auto tracing = std::make_unique<v8::platform::tracing::TracingController>();
  v8::platform::tracing::TracingController* tracing_controller = tracing.get();
  static_cast<v8::platform::DefaultPlatform*>(default_platform.get())
      ->SetTracingController(std::move(tracing));
  MockTraceWriter* writer = new MockTraceWriter();
  v8::platform::tracing::TraceBuffer* ring_buffer =
      v8::platform::tracing::TraceBuffer::CreateTraceBufferRingBuffer(1,
                                                                      writer);
  tracing_controller->Initialize(ring_buffer);
  v8::platform::tracing::TraceConfig* trace_config =
      new v8::platform::tracing::TraceConfig();
  trace_config->AddIncludedCategory("v8");

  TraceStateObserverImpl observer;
  tracing_controller->AddTraceStateObserver(&observer);

  CHECK_EQ(0, observer.enabled_count);
  CHECK_EQ(0, observer.disabled_count);

  tracing_controller->StartTracing(trace_config);

  CHECK_EQ(1, observer.enabled_count);
  CHECK_EQ(0, observer.disabled_count);

  TraceStateObserverImpl observer2;
  tracing_controller->AddTraceStateObserver(&observer2);

  CHECK_EQ(1, observer2.enabled_count);
  CHECK_EQ(0, observer2.disabled_count);

  tracing_controller->RemoveTraceStateObserver(&observer2);

  CHECK_EQ(1, observer2.enabled_count);
  CHECK_EQ(0, observer2.disabled_count);

  tracing_controller->StopTracing();

  CHECK_EQ(1, observer.enabled_count);
  CHECK_EQ(1, observer.disabled_count);
  CHECK_EQ(1, observer2.enabled_count);
  CHECK_EQ(0, observer2.disabled_count);

  tracing_controller->RemoveTraceStateObserver(&observer);

  CHECK_EQ(1, observer.enabled_count);
  CHECK_EQ(1, observer.disabled_count);

  trace_config = new v8::platform::tracing::TraceConfig();
  tracing_controller->StartTracing(trace_config);
  tracing_controller->StopTracing();

  CHECK_EQ(1, observer.enabled_count);
  CHECK_EQ(1, observer.disabled_count);

  i::V8::SetPlatformForTesting(old_platform);
}
#endif  // !defined(V8_USE_PERFETTO)

// With Perfetto the tracing controller doesn't observe events.
#if !defined(V8_USE_PERFETTO)
class TraceWritingThread : public base::Thread {
 public:
  TraceWritingThread(
      v8::platform::tracing::TracingController* tracing_controller)
      : base::Thread(base::Thread::Options("TraceWritingThread")),
        tracing_controller_(tracing_controller) {}

  void Run() override {
    while (!stopped_.load()) {
      TRACE_EVENT0("v8", "v8.Test");
      tracing_controller_->AddTraceEvent('A', nullptr, "v8", "", 1, 1, 0,
                                         nullptr, nullptr, nullptr, nullptr, 0);
      tracing_controller_->AddTraceEventWithTimestamp('A', nullptr, "v8", "", 1,
                                                      1, 0, nullptr, nullptr,
                                                      nullptr, nullptr, 0, 0);
    }
  }

  void Stop() { stopped_.store(true); }

 private:
  std::atomic_bool stopped_{false};
  v8::platform::tracing::TracingController* tracing_controller_;
};

TEST_F(PlatformTracingTest, AddTraceEventMultiThreaded) {
  v8::Platform* old_platform = i::V8::GetCurrentPlatform();
  std::unique_ptr<v8::Platform> default_platform(
      v8::platform::NewDefaultPlatform());
  i::V8::SetPlatformForTesting(default_platform.get());

  auto tracing = std::make_unique<v8::platform::tracing::TracingController>();
  v8::platform::tracing::TracingController* tracing_controller = tracing.get();
  static_cast<v8::platform::DefaultPlatform*>(default_platform.get())
      ->SetTracingController(std::move(tracing));

  MockTraceWriter* writer = new MockTraceWriter();
  TraceBuffer* ring_buffer =
      TraceBuffer::CreateTraceBufferRingBuffer(1, writer);
  tracing_controller->Initialize(ring_buffer);
  TraceConfig* trace_config = new TraceConfig();
  trace_config->AddIncludedCategory("v8");
  tracing_controller->StartTracing(trace_config);

  TraceWritingThread thread(tracing_controller);
  thread.StartSynchronously();
  TRACE_EVENT0("v8", "v8.Test2");
  TRACE_EVENT0("v8", "v8.Test2");

  base::OS::Sleep(base::TimeDelta::FromMilliseconds(10));
  tracing_controller->StopTracing();

  thread.Stop();
  thread.Join();

  i::V8::SetPlatformForTesting(old_platform);
}
#endif  // !defined(V8_USE_PERFETTO)

#ifdef V8_USE_PERFETTO

using TrackEvent = ::perfetto::protos::TrackEvent;

class TestListener : public TraceEventListener {
 public:
  void ParseFromArray(const std::vector<char>& array) {
    perfetto::protos::Trace trace;
    CHECK(trace.ParseFromArray(array.data(), static_cast<int>(array.size())));

    for (int i = 0; i < trace.packet_size(); i++) {
      // TODO(petermarshall): ChromeTracePacket instead.
      const perfetto::protos::TracePacket& packet = trace.packet(i);
      ProcessPacket(packet);
    }
  }

  const std::string& get_event(size_t index) { return events_.at(index); }

  size_t events_size() const { return events_.size(); }

 private:
  void ProcessPacket(const ::perfetto::protos::TracePacket& packet) {
    if (packet.incremental_state_cleared()) {
      categories_.clear();
      event_names_.clear();
      debug_annotation_names_.clear();
    }

    if (!packet.has_track_event()) return;

    // Update incremental state.
    if (packet.has_interned_data()) {
      const auto& interned_data = packet.interned_data();
      for (const auto& it : interned_data.event_categories()) {
        CHECK_EQ(categories_.find(it.iid()), categories_.end());
        categories_[it.iid()] = it.name();
      }
      for (const auto& it : interned_data.event_names()) {
        CHECK_EQ(event_names_.find(it.iid()), event_names_.end());
        event_names_[it.iid()] = it.name();
      }
      for (const auto& it : interned_data.debug_annotation_names()) {
        CHECK_EQ(debug_annotation_names_.find(it.iid()),
                 debug_annotation_names_.end());
        debug_annotation_names_[it.iid()] = it.name();
      }
    }
    const auto& track_event = packet.track_event();
    std::string slice;
    switch (track_event.type()) {
      case perfetto::protos::TrackEvent::TYPE_SLICE_BEGIN:
        slice += "B";
        break;
      case perfetto::protos::TrackEvent::TYPE_SLICE_END:
        slice += "E";
        break;
      case perfetto::protos::TrackEvent::TYPE_INSTANT:
        slice += "I";
        break;
      default:
      case perfetto::protos::TrackEvent::TYPE_UNSPECIFIED:
        CHECK(false);
    }
    slice += ":" +
             (track_event.category_iids_size()
                  ? categories_[track_event.category_iids().Get(0)]
                  : "") +
             ".";
    if (track_event.name_iid()) {
      slice += event_names_[track_event.name_iid()];
    } else {
      slice += track_event.name();
    }

    if (track_event.debug_annotations_size()) {
      slice += "(";
      bool first_annotation = true;
      for (const auto& it : track_event.debug_annotations()) {
        if (!first_annotation) {
          slice += ",";
        }
        if (!it.name().empty()) {
          slice += it.name();
        } else {
          slice += debug_annotation_names_[it.name_iid()];
        }
        slice += "=";
        std::stringstream value;
        if (it.has_bool_value()) {
          value << "(bool)" << it.bool_value();
        } else if (it.has_uint_value()) {
          value << "(uint)" << it.uint_value();
        } else if (it.has_int_value()) {
          value << "(int)" << it.int_value();
        } else if (it.has_double_value()) {
          value << "(double)" << it.double_value();
        } else if (it.has_string_value()) {
          value << "(string)" << it.string_value();
        } else if (it.has_pointer_value()) {
          value << "(pointer)0x" << std::hex << it.pointer_value();
        } else if (it.has_legacy_json_value()) {
          value << "(json)" << it.legacy_json_value();
        } else if (it.has_nested_value()) {
          value << "(nested)" << it.nested_value().string_value();
        }
        slice += value.str();
        first_annotation = false;
      }
      slice += ")";
    }
    events_.push_back(slice);
  }

  std::vector<std::string> events_;
  std::map<uint64_t, std::string> categories_;
  std::map<uint64_t, std::string> event_names_;
  std::map<uint64_t, std::string> debug_annotation_names_;
};

class TracingTestHarness {
 public:
  TracingTestHarness() {
    old_platform_ = i::V8::GetCurrentPlatform();
    default_platform_ = v8::platform::NewDefaultPlatform();
    i::V8::SetPlatformForTesting(default_platform_.get());

    auto tracing = std::make_unique<v8::platform::tracing::TracingController>();
    tracing_controller_ = tracing.get();
    static_cast<v8::platform::DefaultPlatform*>(default_platform_.get())
        ->SetTracingController(std::move(tracing));

    tracing_controller_->InitializeForPerfetto(&perfetto_json_stream_);
    tracing_controller_->SetTraceEventListenerForTesting(&listener_);
  }

  ~TracingTestHarness() { i::V8::SetPlatformForTesting(old_platform_); }

  void StartTracing() {
    TraceConfig* trace_config = new TraceConfig();
    trace_config->AddIncludedCategory("v8");
    tracing_controller_->StartTracing(trace_config);
  }

  void StopTracing() {
    v8::TrackEvent::Flush();
    tracing_controller_->StopTracing();
  }

  const std::string& get_event(size_t index) {
    return listener_.get_event(index);
  }
  size_t events_size() const { return listener_.events_size(); }

  std::string perfetto_json_stream() { return perfetto_json_stream_.str(); }

 private:
  std::unique_ptr<v8::Platform> default_platform_;
  v8::Platform* old_platform_;
  v8::platform::tracing::TracingController* tracing_controller_;
  TestListener listener_;
  std::ostringstream perfetto_json_stream_;
};

TEST_F(PlatformTracingTest, Perfetto) {
  TracingTestHarness harness;
  harness.StartTracing();

  uint64_t uint64_arg = 1024;
  const char* str_arg = "str_arg";

  {
    TRACE_EVENT0("v8", "test1");
    TRACE_EVENT1("v8", "test2", "arg1", uint64_arg);
    TRACE_EVENT2("v8", "test3", "arg1", uint64_arg, "arg2", str_arg);
  }

  harness.StopTracing();

  CHECK_EQ("B:v8.test1", harness.get_event(0));
  CHECK_EQ("B:v8.test2(arg1=(uint)1024)", harness.get_event(1));
  CHECK_EQ("B:v8.test3(arg1=(uint)1024,arg2=(string)str_arg)",
           harness.get_event(2));
  CHECK_EQ("E:.", harness.get_event(3));
  CHECK_EQ("E:.", harness.get_event(4));
  CHECK_EQ("E:.", harness.get_event(5));

  CHECK_EQ(6, harness.events_size());
}

// Replacement for 'TestTracingController'
TEST_F(PlatformTracingTest, Categories) {
  TracingTestHarness harness;
  harness.StartTracing();

  {
    TRACE_EVENT0("v8", "v8.Test");
    // cat category is not included in default config
    TRACE_EVENT0("cat", "v8.Test2");
    TRACE_EVENT0("v8", "v8.Test3");
  }

  harness.StopTracing();

  CHECK_EQ(4, harness.events_size());
  CHECK_EQ("B:v8.v8.Test", harness.get_event(0));
  CHECK_EQ("B:v8.v8.Test3", harness.get_event(1));
  CHECK_EQ("E:.", harness.get_event(2));
  CHECK_EQ("E:.", harness.get_event(3));
}

// Replacement for 'TestTracingControllerMultipleArgsAndCopy'
TEST_F(PlatformTracingTest, MultipleArgsAndCopy) {
  uint64_t aa = 11;
  unsigned int bb = 22;
  uint16_t cc = 33;
  unsigned char dd = 44;
  int64_t ee = -55;
  int ff = -66;
  int16_t gg = -77;
  signed char hh = -88;
  bool ii1 = true;
  bool ii2 = false;
  double jj1 = 99.0;
  double jj2 = 1e100;
  double jj3 = std::numeric_limits<double>::quiet_NaN();
  double jj4 = std::numeric_limits<double>::infinity();
  double jj5 = -std::numeric_limits<double>::infinity();
  void* kk = &aa;
  const char* ll = "100";
  std::string mm = "INIT";
  std::string mmm = "\"INIT\"";

  TracingTestHarness harness;
  harness.StartTracing();

  // Create a scope for the tracing controller to terminate the trace writer.
  {
    TRACE_EVENT1("v8", "v8.Test.aa", "aa", aa);
    TRACE_EVENT1("v8", "v8.Test.bb", "bb", bb);
    TRACE_EVENT1("v8", "v8.Test.cc", "cc", cc);
    TRACE_EVENT1("v8", "v8.Test.dd", "dd", dd);
    TRACE_EVENT1("v8", "v8.Test.ee", "ee", ee);
    TRACE_EVENT1("v8", "v8.Test.ff", "ff", ff);
    TRACE_EVENT1("v8", "v8.Test.gg", "gg", gg);
    TRACE_EVENT1("v8", "v8.Test.hh", "hh", hh);
    TRACE_EVENT1("v8", "v8.Test.ii", "ii1", ii1);
    TRACE_EVENT1("v8", "v8.Test.ii", "ii2", ii2);
    TRACE_EVENT1("v8", "v8.Test.jj1", "jj1", jj1);
    TRACE_EVENT1("v8", "v8.Test.jj2", "jj2", jj2);
    TRACE_EVENT1("v8", "v8.Test.jj3", "jj3", jj3);
    TRACE_EVENT1("v8", "v8.Test.jj4", "jj4", jj4);
    TRACE_EVENT1("v8", "v8.Test.jj5", "jj5", jj5);
    TRACE_EVENT1("v8", "v8.Test.kk", "kk", kk);
    TRACE_EVENT1("v8", "v8.Test.ll", "ll", ll);
    TRACE_EVENT1("v8", "v8.Test.mm", "mm", TRACE_STR_COPY(mmm.c_str()));

    TRACE_EVENT2("v8", "v8.Test2.1", "aa", aa, "ll", ll);
    TRACE_EVENT2("v8", "v8.Test2.2", "mm1", TRACE_STR_COPY(mm.c_str()), "mm2",
                 TRACE_STR_COPY(mmm.c_str()));

    // Check copies are correct.
    TRACE_EVENT_COPY_INSTANT0("v8", mm.c_str(), TRACE_EVENT_SCOPE_THREAD);
    TRACE_EVENT_COPY_INSTANT2("v8", mm.c_str(), TRACE_EVENT_SCOPE_THREAD, "mm1",
                              mm.c_str(), "mm2", mmm.c_str());
    mm = "CHANGED";
    mmm = "CHANGED";

    auto arg = v8::tracing::TracedValue::Create();
    arg->SetInteger("value", 42);
    TRACE_EVENT_INSTANT1("v8", "v8.Test", TRACE_EVENT_SCOPE_THREAD, "a1",
                         std::move(arg));

    arg = v8::tracing::TracedValue::Create();
    arg->SetString("value", "string");
    auto arg2 = v8::tracing::TracedValue::Create();
    arg2->SetDouble("value", 1.23);
    TRACE_EVENT_INSTANT2("v8", "v8.Test", TRACE_EVENT_SCOPE_THREAD, "a1",
                         std::move(arg), "a2", std::move(arg2));
  }

  harness.StopTracing();

  CHECK_EQ("B:v8.v8.Test.aa(aa=(uint)11)", harness.get_event(0));
  CHECK_EQ("B:v8.v8.Test.bb(bb=(uint)22)", harness.get_event(1));
  CHECK_EQ("B:v8.v8.Test.cc(cc=(uint)33)", harness.get_event(2));
  CHECK_EQ("B:v8.v8.Test.dd(dd=(uint)44)", harness.get_event(3));
  CHECK_EQ("B:v8.v8.Test.ee(ee=(int)-55)", harness.get_event(4));
  CHECK_EQ("B:v8.v8.Test.ff(ff=(int)-66)", harness.get_event(5));
  CHECK_EQ("B:v8.v8.Test.gg(gg=(int)-77)", harness.get_event(6));
  CHECK_EQ("B:v8.v8.Test.hh(hh=(int)-88)", harness.get_event(7));
  CHECK_EQ("B:v8.v8.Test.ii(ii1=(bool)1)", harness.get_event(8));
  CHECK_EQ("B:v8.v8.Test.ii(ii2=(bool)0)", harness.get_event(9));
  CHECK_EQ("B:v8.v8.Test.jj1(jj1=(double)99)", harness.get_event(10));
  CHECK_EQ("B:v8.v8.Test.jj2(jj2=(double)1e+100)", harness.get_event(11));
  CHECK_EQ("B:v8.v8.Test.jj3(jj3=(double)nan)", harness.get_event(12));
  CHECK_EQ("B:v8.v8.Test.jj4(jj4=(double)inf)", harness.get_event(13));
  CHECK_EQ("B:v8.v8.Test.jj5(jj5=(double)-inf)", harness.get_event(14));

  std::ostringstream pointer_stream;
  pointer_stream << "B:v8.v8.Test.kk(kk=(pointer)" << &aa << ")";
  CHECK_EQ(pointer_stream.str().c_str(), harness.get_event(15));

  CHECK_EQ("B:v8.v8.Test.ll(ll=(string)100)", harness.get_event(16));
  CHECK_EQ("B:v8.v8.Test.mm(mm=(string)\"INIT\")", harness.get_event(17));
  CHECK_EQ("B:v8.v8.Test2.1(aa=(uint)11,ll=(string)100)",
           harness.get_event(18));
  CHECK_EQ("B:v8.v8.Test2.2(mm1=(string)INIT,mm2=(string)\"INIT\")",
           harness.get_event(19));
  CHECK_EQ("I:v8.INIT", harness.get_event(20));
  CHECK_EQ("I:v8.INIT(mm1=(string)INIT,mm2=(string)\"INIT\")",
           harness.get_event(21));
  CHECK_EQ("I:v8.v8.Test(a1=(json){\"value\":42})", harness.get_event(22));
  CHECK_EQ(
      "I:v8.v8.Test(a1=(json){\"value\":\"string\"},a2=(json){\"value\":1.23})",
      harness.get_event(23));

  // Check the terminating end events.
  for (size_t i = 0; i < 20; i++) CHECK_EQ("E:.", harness.get_event(24 + i));
}

TEST_F(PlatformTracingTest, JsonIntegrationTest) {
  // Check that tricky values are rendered correctly in the JSON output.
  double big_num = 1e100;
  double nan_num = std::numeric_limits<double>::quiet_NaN();
  double inf_num = std::numeric_limits<double>::infinity();
  double neg_inf_num = -std::numeric_limits<double>::infinity();

  TracingTestHarness harness;
  harness.StartTracing();

  {
    TRACE_EVENT1("v8", "v8.Test.1", "1", big_num);
    TRACE_EVENT1("v8", "v8.Test.2", "2", nan_num);
    TRACE_EVENT1("v8", "v8.Test.3", "3", inf_num);
    TRACE_EVENT1("v8", "v8.Test.4", "4", neg_inf_num);
  }

  harness.StopTracing();
  std::string json = harness.perfetto_json_stream();
  std::cout << json << "\n";

  std::vector<std::string> all_args, all_cats;
  GetJSONStrings(&all_args, json, "\"args\"", "{", "}");
  GetJSONStrings(&all_cats, json, "\"cat\"", "\"", "\"");

  // Ignore the metadata events.
  int i = 0;
  while (all_cats[i] == "__metadata") ++i;

  CHECK_EQ("\"1\":1e+100", all_args[i++]);
  CHECK_EQ("\"2\":\"NaN\"", all_args[i++]);
  CHECK_EQ("\"3\":\"Infinity\"", all_args[i++]);
  CHECK_EQ("\"4\":\"-Infinity\"", all_args[i++]);
}

#endif  // V8_USE_PERFETTO

}  // namespace tracing
}  // namespace platform
}  // namespace v8

"""

```