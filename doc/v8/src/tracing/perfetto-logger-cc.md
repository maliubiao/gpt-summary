Response:
Let's break down the thought process for analyzing the `perfetto-logger.cc` file.

1. **Understand the Purpose:** The filename itself, "perfetto-logger.cc," strongly suggests this code is responsible for logging V8's internal events to Perfetto. Perfetto is a system tracing tool, so the goal is to provide insights into V8's runtime behavior.

2. **Initial Scan for Key Includes:**  Looking at the `#include` directives gives a good overview of the dependencies and functionalities involved:
    * `<memory>`:  Likely involves smart pointers (like `std::unique_ptr`).
    * `absl/container/flat_hash_map.h`: Indicates the use of a hash map, probably for storing associations (e.g., Isolate to Logger).
    * `protos/perfetto/...`:  Confirms the interaction with Perfetto through protobuf messages. These messages define the structure of the data being logged.
    * `src/base/...`:  Indicates use of V8's platform abstraction layer for things like mutexes and time.
    * `src/builtins/builtins.h`, `src/execution/isolate.h`, `src/handles/...`, `src/heap/...`, `src/objects/...`:  These are core V8 components, revealing that the logger interacts with V8's internal representation of code, objects, and execution environments.
    * `src/tracing/...`:  Shows this is part of V8's tracing infrastructure, and likely interacts with other tracing components like `CodeDataSource`.

3. **Identify Key Classes and Structures:** Scan the code for class definitions and important data structures:
    * `PerfettoLogger`: This is the central class. Its methods likely correspond to different events being logged.
    * `IsolateRegistry`: A singleton that manages the association between V8 `Isolate`s and their `PerfettoLogger` instances. This is crucial for multi-threading and multiple V8 instances.
    * `CodeTraceContext`:  Seems to encapsulate the context for logging code-related events, including the current trace packet and incremental state.
    * Protobuf message types like `V8InternalCode`, `V8JsCode`, `TracePacket`:  These define the data format for different kinds of logged events.

4. **Analyze Key Functions and Methods:**  Focus on the main functions and methods within the classes:
    * `PerfettoLogger::RegisterIsolate`, `UnregisterIsolate`:  Manage the lifecycle of the logger for each `Isolate`.
    * `PerfettoLogger::OnCodeDataSourceStart`, `OnCodeDataSourceStop`:  Control when logging is active. The `IsolateRegistry` plays a central role here, ensuring all isolates start/stop logging consistently.
    * `PerfettoLogger::LogExistingCode`:  Logs code that already exists when tracing starts.
    * `PerfettoLogger::CodeCreateEvent` (multiple overloads):  The core method for logging the creation of different types of code (internal, JS, WASM, RegExp).
    * `PerfettoLogger::CodeMoveEvent`, `BytecodeMoveEvent`:  Log when code or bytecode is moved in memory (important for understanding garbage collection and optimization).
    * Other event logging methods like `CallbackEvent`, `RegExpCodeCreateEvent`, `CodeDisableOptEvent`, `CodeDeoptEvent`, etc.:  These cover various V8 runtime events.
    * Helper functions like `NewTracePacket`, `NewCodeTraceContext`, `WriteJsCode`.

5. **Understand the Control Flow and Logic:**
    * **Isolate Management:** The `IsolateRegistry` pattern ensures that each V8 isolate has its own `PerfettoLogger`. The `num_active_data_sources_` counter manages the global logging state.
    * **Event Handling:** The `PerfettoLogger` acts as a listener for V8's code events. When an event occurs (like code creation), the corresponding `CodeCreateEvent` method is called.
    * **Perfetto Integration:** The code uses Perfetto's protobuf definitions to create structured log messages. The `CodeDataSource::Trace` function likely handles the actual sending of these messages to Perfetto.
    * **Incremental State:** The `TracePacket::SEQ_NEEDS_INCREMENTAL_STATE` and `TracePacket::SEQ_INCREMENTAL_STATE_CLEARED` flags indicate support for incremental tracing, where only changes are logged to reduce overhead.

6. **Address Specific Questions from the Prompt:**  Now, systematically go through each requirement in the prompt:
    * **Functionality:** Summarize the core tasks based on the analysis above.
    * **`.tq` Extension:**  Check the filename. It's `.cc`, not `.tq`.
    * **JavaScript Relationship:** Look for interactions with JS concepts (like `SharedFunctionInfo`, script names, bytecode, different compilation tiers). Then, construct JavaScript examples that trigger these events (function creation, execution, etc.).
    * **Code Logic Inference:**  Identify parts with clear input/output. The `WriteJsCode` function is a good example. Make assumptions about the `abstract_code` and predict the `code_proto` values.
    * **Common Programming Errors:** Consider potential pitfalls related to logging:
        * **Performance overhead:** Excessive logging can slow down the application.
        * **Data volume:**  Large amounts of trace data can be hard to analyze.
        * **Incorrect configuration:** Not enabling the data source.

7. **Refine and Organize:**  Structure the findings logically, using headings and bullet points for clarity. Ensure the JavaScript examples are concrete and easy to understand. Double-check the assumptions and reasoning.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe it just logs code creation."  **Correction:**  Realize it logs a wider range of events, including code movement, deoptimization, etc.
* **Initial thought:** "The `IsolateRegistry` is just a simple map." **Correction:** Notice the mutex usage, indicating thread-safety and the need to coordinate logging across isolates.
* **Initial thought:** "Just describe the methods." **Correction:**  Connect the methods to the broader purpose of providing insights into V8's behavior for performance analysis and debugging.
* **Realization:** Need to explain *why* certain information (like instruction pointers, sizes, tiers) is being logged – it's for detailed code-level analysis in Perfetto.

By following these steps, a comprehensive understanding of the `perfetto-logger.cc` file can be achieved, addressing all the points raised in the prompt.
好的，让我们来分析一下 `v8/src/tracing/perfetto-logger.cc` 这个文件。

**1. 文件功能概要**

`v8/src/tracing/perfetto-logger.cc` 的主要功能是将 V8 引擎内部发生的各种代码相关的事件记录到 Perfetto 追踪系统中。Perfetto 是一个开源的系统级追踪和分析工具。通过将 V8 的事件记录到 Perfetto，开发者可以更深入地了解 V8 的代码执行、优化、垃圾回收等行为，从而进行性能分析和问题排查。

具体来说，这个文件实现了以下功能：

* **注册和管理 Isolate 的 Logger:**  V8 引擎可以有多个独立的执行环境（Isolate）。这个文件中的 `IsolateRegistry` 类负责管理每个 Isolate 对应的 `PerfettoLogger` 实例，确保每个 Isolate 的事件都能被正确记录。
* **监听代码事件:** `PerfettoLogger` 类实现了 V8 提供的代码事件监听接口。当 V8 内部发生代码创建、移动、禁用优化、反优化等事件时，`PerfettoLogger` 相应的方法会被调用。
* **将代码事件转换为 Perfetto 追踪事件:**  当代码事件发生时，`PerfettoLogger` 会将事件信息（例如代码类型、名称、起始地址、大小等）封装成 Perfetto 的 protobuf 消息（定义在 `protos/perfetto/trace/chrome/v8.pbzero.h` 中），并通过 `CodeDataSource` 将这些消息发送到 Perfetto 系统。
* **处理不同类型的代码:**  这个文件能够处理多种类型的 V8 代码，包括：
    * JavaScript 代码（解释执行、基线编译、优化编译等不同层级）
    * 内置函数 (Builtins)
    * 正则表达式代码
    * WebAssembly 代码
    * Bytecode 处理程序
    * 等等。
* **记录代码的指令:**  可以选择记录代码的机器码或字节码，以便进行更底层的分析。
* **记录代码移动:**  当代码在内存中移动（例如，由于垃圾回收）时，会记录移动的源地址和目标地址。
* **记录其他相关事件:**  例如，回调函数的创建、共享函数信息和原生上下文的移动等。

**2. 关于 `.tq` 扩展名**

如果 `v8/src/tracing/perfetto-logger.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 用于生成高效的内置函数和运行时函数的领域特定语言。但是，根据你提供的文件内容，该文件以 `.cc` 结尾，所以它是一个 C++ 源代码文件。

**3. 与 JavaScript 功能的关系及 JavaScript 示例**

`perfetto-logger.cc` 记录的事件直接反映了 JavaScript 代码在 V8 引擎中的执行过程。以下是一些 JavaScript 示例及其可能触发的 Perfetto 事件：

* **函数定义和调用：**

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

   * **Perfetto 事件：**  当 `add` 函数被定义时，会触发 `CodeCreateEvent`，记录该函数的字节码或编译后的机器码。当 `add` 函数被调用时，可能会触发更多的内部执行事件。如果 V8 对该函数进行了优化编译，还会触发新的 `CodeCreateEvent` 来记录优化后的代码。

* **内置函数的使用：**

```javascript
console.log("Hello");
```

   * **Perfetto 事件：** 调用 `console.log` 会触发对 V8 内置函数的调用，这会触发 `CodeCreateEvent` 来记录相关内置函数的代码。

* **正则表达式的使用：**

```javascript
const regex = /abc/g;
const str = "abcadef";
str.match(regex);
```

   * **Perfetto 事件：** 创建正则表达式 `regex` 会触发 `RegExpCodeCreateEvent`，记录正则表达式的编译代码。

* **动态代码生成 (例如 `eval`)：**

```javascript
eval("const x = 10;");
```

   * **Perfetto 事件：** `eval` 执行的代码会被编译，这会触发 `CodeCreateEvent`。

**4. 代码逻辑推理和假设输入输出**

让我们看一个简单的代码逻辑部分：`WriteJsCode` 函数。

**假设输入：**

* `ctx`: 一个 `CodeTraceContext` 对象，假设其 `log_instructions()` 返回 `true`。
* `abstract_code`: 一个指向 JavaScript 函数的抽象代码的指针。 假设 `abstract_code` 指向一个已经过 TurboFan 优化的函数。

**代码逻辑：**

```c++
void WriteJsCode(const CodeTraceContext& ctx,
                 Tagged<AbstractCode> abstract_code, V8JsCode& code_proto) {
  // ... (省略部分代码) ...
  DCHECK(IsCode(abstract_code));
  Tagged<Code> code = abstract_code->GetCode();

  V8JsCode::Tier tier = V8JsCode::TIER_UNKNOWN;
  switch (code->kind()) {
    // ... (省略其他 case) ...
    case CodeKind::TURBOFAN_JS:
      tier = V8JsCode::TIER_TURBOFAN;
      break;
    // ...
  }

  code_proto.set_tier(tier);
  code_proto.set_instruction_start(code->instruction_start());
  code_proto.set_instruction_size_bytes(code->instruction_size());
  if (ctx.log_instructions()) {
    code_proto.set_machine_code(
        reinterpret_cast<const uint8_t*>(code->instruction_start()),
        code->instruction_size());
  }
}
```

**推理：**

1. 由于假设 `abstract_code` 指向一个经过 TurboFan 优化的函数，所以 `IsCode(abstract_code)` 会返回 `true`。
2. `code->kind()` 将会是 `CodeKind::TURBOFAN_JS`。
3. `tier` 将被设置为 `V8JsCode::TIER_TURBOFAN`。
4. `code_proto` 的 `tier` 字段将被设置为 `V8JsCode::TIER_TURBOFAN`。
5. `code_proto` 的 `instruction_start` 字段将被设置为该优化后代码的起始地址。
6. `code_proto` 的 `instruction_size_bytes` 字段将被设置为该优化后代码的大小。
7. 由于 `ctx.log_instructions()` 返回 `true`，`code_proto` 的 `machine_code` 字段将被设置为指向该优化后代码的原始字节的指针，长度为 `code->instruction_size()`。

**假设输出 (部分 `code_proto` 内容):**

```protobuf
tier: TIER_TURBOFAN
instruction_start: 0x12345678 // 假设的起始地址
instruction_size_bytes: 1024 // 假设的大小
machine_code: "\x55\x48\x89\xe5..." // 假设的机器码
```

**5. 涉及用户常见的编程错误**

虽然 `perfetto-logger.cc` 本身是 V8 内部的代码，但它可以帮助开发者发现他们 JavaScript 代码中的性能问题。一些常见的编程错误可能会导致 V8 产生大量的代码优化或反优化事件，从而在 Perfetto 追踪中显现出来：

* **频繁的类型更改：**  JavaScript 是一门动态类型语言，但频繁地更改变量的类型会导致 V8 的优化器失效，触发反优化事件。

   ```javascript
   function example(input) {
     let x = input;
     if (typeof x === 'number') {
       x = "a string"; // 类型从 number 变为 string
     }
     return x;
   }

   for (let i = 0; i < 1000; i++) {
     example(i);
   }
   example(true); // 再次更改类型
   ```

   * **Perfetto 可能看到的事件：**  大量的 `CodeDeoptEvent` 表明 V8 正在频繁地放弃对 `example` 函数的优化。

* **在热点代码中使用 `eval` 或 `with`：**  这些特性会使 V8 难以进行静态分析和优化。

   ```javascript
   function calculate(expression) {
     return eval(expression);
   }

   calculate("1 + 2 * 3");
   ```

   * **Perfetto 可能看到的事件：**  可能缺少对 `calculate` 函数的有效优化，或者看到与动态代码生成相关的事件。

* **创建大量的小型、生命周期短的函数：**  这可能会导致 V8 花费大量时间进行编译和垃圾回收。

   ```javascript
   for (let i = 0; i < 10000; i++) {
     const tempFunc = () => i * 2;
     tempFunc();
   }
   ```

   * **Perfetto 可能看到的事件：**  大量的 `CodeCreateEvent` 和潜在的垃圾回收相关的事件。

* **在循环中创建闭包：** 如果闭包捕获了循环变量，可能会导致性能问题。

   ```javascript
   function createHandlers() {
     const handlers = [];
     for (var i = 0; i < 5; i++) {
       handlers.push(() => console.log(i));
     }
     return handlers;
   }

   const myHandlers = createHandlers();
   myHandlers.forEach(handler => handler()); // 所有的 handler 都会打印 5
   ```

   * **Perfetto 可能看到的事件：**  关于函数创建和闭包的事件，可能揭示 V8 如何处理这些闭包。

总而言之，`v8/src/tracing/perfetto-logger.cc` 是 V8 引擎中一个至关重要的组件，它将 V8 的内部运作透明化，为开发者提供了强大的性能分析工具。通过分析 Perfetto 记录的事件，开发者可以更好地理解他们的 JavaScript 代码在 V8 中的执行情况，并识别潜在的性能瓶颈和错误。

### 提示词
```
这是目录为v8/src/tracing/perfetto-logger.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/tracing/perfetto-logger.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/tracing/perfetto-logger.h"

#include <memory>

#include "absl/container/flat_hash_map.h"
#include "protos/perfetto/common/builtin_clock.pbzero.h"
#include "protos/perfetto/trace/chrome/v8.pbzero.h"
#include "protos/perfetto/trace/trace_packet.pbzero.h"
#include "protos/perfetto/trace/trace_packet_defaults.pbzero.h"
#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/time.h"
#include "src/builtins/builtins.h"
#include "src/execution/isolate.h"
#include "src/handles/handles.h"
#include "src/heap/spaces.h"
#include "src/logging/log.h"
#include "src/objects/abstract-code.h"
#include "src/objects/code-kind.h"
#include "src/objects/heap-object.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/script.h"
#include "src/objects/string.h"
#include "src/objects/tagged.h"
#include "src/tracing/code-data-source.h"
#include "src/tracing/code-trace-context.h"
#include "src/tracing/perfetto-utils.h"

namespace v8 {
namespace internal {
namespace {

using ::perfetto::protos::pbzero::BuiltinClock;
using ::perfetto::protos::pbzero::TracePacket;
using ::perfetto::protos::pbzero::V8InternalCode;
using ::perfetto::protos::pbzero::V8JsCode;

CodeDataSource::TraceContext::TracePacketHandle NewTracePacket(
    CodeDataSource::TraceContext& context) {
  CodeDataSourceIncrementalState* inc_state = context.GetIncrementalState();
  auto packet = context.NewTracePacket();
  packet->set_timestamp(base::TimeTicks::Now().since_origin().InNanoseconds());

  if (inc_state->is_initialized()) {
    packet->set_sequence_flags(TracePacket::SEQ_NEEDS_INCREMENTAL_STATE);
    return packet;
  }

  inc_state->Init(context);

  packet->set_sequence_flags(TracePacket::SEQ_INCREMENTAL_STATE_CLEARED);

  auto* defaults = packet->set_trace_packet_defaults();
  defaults->set_timestamp_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC);

  auto* v8_defaults = defaults->set_v8_code_defaults();
  v8_defaults->set_tid(base::OS::GetCurrentThreadId());

  return packet;
}

CodeTraceContext NewCodeTraceContext(CodeDataSource::TraceContext& ctx) {
  return CodeTraceContext(NewTracePacket(ctx), ctx.GetIncrementalState());
}

class IsolateRegistry {
 public:
  static IsolateRegistry& GetInstance() {
    static IsolateRegistry* g_instance = new IsolateRegistry();
    return *g_instance;
  }

  void Register(Isolate* isolate) {
    auto logger = std::make_unique<PerfettoLogger>(isolate);
    base::MutexGuard lock(&mutex_);
    if (num_active_data_sources_ != 0) {
      isolate->logger()->AddListener(logger.get());
    }
    CHECK(isolates_.emplace(isolate, std::move(logger)).second);
  }

  void Unregister(Isolate* isolate) {
    base::MutexGuard lock(&mutex_);
    auto it = isolates_.find(isolate);
    CHECK(it != isolates_.end());
    if (num_active_data_sources_ != 0) {
      isolate->logger()->RemoveListener(it->second.get());
    }
    isolates_.erase(it);
  }

  void OnCodeDataSourceStart() {
    base::MutexGuard lock(&mutex_);
    ++num_active_data_sources_;
    if (num_active_data_sources_ == 1) {
      StartLogging(lock);
    }
    LogExistingCodeForAllIsolates(lock);
  }

  void OnCodeDataSourceStop() {
    base::MutexGuard lock(&mutex_);
    DCHECK_LT(0, num_active_data_sources_);
    --num_active_data_sources_;
    if (num_active_data_sources_ == 0) {
      StopLogging(lock);
    }
  }

 private:
  void StartLogging(const base::MutexGuard&) {
    for (const auto& [isolate, logger] : isolates_) {
      isolate->logger()->AddListener(logger.get());
    }
  }

  void StopLogging(const base::MutexGuard&) {
    for (const auto& [isolate, logger] : isolates_) {
      isolate->logger()->RemoveListener(logger.get());
    }
  }

  void LogExistingCodeForAllIsolates(const base::MutexGuard&) {
    for (const auto& [isolate, listener] : isolates_) {
      isolate->RequestInterrupt(
          [](v8::Isolate*, void* data) {
            PerfettoLogger* listener = reinterpret_cast<PerfettoLogger*>(data);
            listener->LogExistingCode();
          },
          listener.get());
    }
  }

  base::Mutex mutex_;
  int num_active_data_sources_ = 0;
  absl::flat_hash_map<Isolate*, std::unique_ptr<PerfettoLogger>> isolates_;
};

void WriteJsCode(const CodeTraceContext& ctx,
                 Tagged<AbstractCode> abstract_code, V8JsCode& code_proto) {
  if (IsBytecodeArray(abstract_code)) {
    Tagged<BytecodeArray> bytecode = abstract_code->GetBytecodeArray();
    code_proto.set_tier(V8JsCode::TIER_IGNITION);
    code_proto.set_instruction_start(bytecode->GetFirstBytecodeAddress());
    code_proto.set_instruction_size_bytes(bytecode->length());
    if (ctx.log_instructions()) {
      code_proto.set_bytecode(
          reinterpret_cast<const uint8_t*>(bytecode->GetFirstBytecodeAddress()),
          bytecode->length());
    }
    return;
  }

  DCHECK(IsCode(abstract_code));
  Tagged<Code> code = abstract_code->GetCode();

  V8JsCode::Tier tier = V8JsCode::TIER_UNKNOWN;
  switch (code->kind()) {
    case CodeKind::BUILTIN:
      if (code->builtin_id() == Builtin::kInterpreterEntryTrampoline) {
        DCHECK(v8_flags.interpreted_frames_native_stack);
        DCHECK(code->has_instruction_stream());
        tier = V8JsCode::TIER_IGNITION;
        break;
      }

      // kEmptyFunction is used as a placeholder sometimes.
      DCHECK_EQ(code->builtin_id(), Builtin::kEmptyFunction);
      DCHECK(!code->has_instruction_stream());
      return;

    case CodeKind::INTERPRETED_FUNCTION:
      // Handled above.
      UNREACHABLE();

    case CodeKind::BASELINE:
      tier = V8JsCode::TIER_SPARKPLUG;
      break;
    case CodeKind::MAGLEV:
      tier = V8JsCode::TIER_MAGLEV;
      break;
    case CodeKind::TURBOFAN_JS:
      tier = V8JsCode::TIER_TURBOFAN;
      break;

    case CodeKind::BYTECODE_HANDLER:
    case CodeKind::FOR_TESTING:
    case CodeKind::REGEXP:
    case CodeKind::WASM_FUNCTION:
    case CodeKind::WASM_TO_CAPI_FUNCTION:
    case CodeKind::WASM_TO_JS_FUNCTION:
    case CodeKind::JS_TO_WASM_FUNCTION:
    case CodeKind::C_WASM_ENTRY:
      UNREACHABLE();
  }

  code_proto.set_tier(tier);
  code_proto.set_instruction_start(code->instruction_start());
  code_proto.set_instruction_size_bytes(code->instruction_size());
  if (ctx.log_instructions()) {
    code_proto.set_machine_code(
        reinterpret_cast<const uint8_t*>(code->instruction_start()),
        code->instruction_size());
  }
}

}  // namespace

// static
void PerfettoLogger::RegisterIsolate(Isolate* isolate) {
  IsolateRegistry::GetInstance().Register(isolate);
  // TODO(carlscab): Actually if both perfetto and file logging are active the
  // builtins will be logged twice to the file (EmitCodeCreateEvents is called
  // somewhere in the isolate setup code). Probably not very likely to happen
  // but we should find a better way.
  CodeDataSource::CallIfEnabled(
      [isolate](uint32_t) { Builtins::EmitCodeCreateEvents(isolate); });
}

// static
void PerfettoLogger::UnregisterIsolate(Isolate* isolate) {
  IsolateRegistry::GetInstance().Unregister(isolate);
}

// static
void PerfettoLogger::OnCodeDataSourceStart() {
  IsolateRegistry::GetInstance().OnCodeDataSourceStart();
}

// static
void PerfettoLogger::OnCodeDataSourceStop() {
  IsolateRegistry::GetInstance().OnCodeDataSourceStop();
}

void PerfettoLogger::LogExistingCode() {
  HandleScope scope(&isolate_);
  ExistingCodeLogger logger(&isolate_, this);
  logger.LogBuiltins();
  logger.LogCodeObjects();
  logger.LogCompiledFunctions();
}

PerfettoLogger::PerfettoLogger(Isolate* isolate) : isolate_(*isolate) {}
PerfettoLogger::~PerfettoLogger() {}

void PerfettoLogger::CodeCreateEvent(CodeTag tag,
                                     Handle<AbstractCode> abstract_code,
                                     const char* name) {
  DisallowGarbageCollection no_gc;
  if (!IsCode(*abstract_code)) return;
  Tagged<Code> code = abstract_code->GetCode();

  V8InternalCode::Type type = V8InternalCode::TYPE_UNKNOWN;
  switch (code->kind()) {
    case CodeKind::REGEXP:
      RegExpCodeCreateEvent(abstract_code, Handle<String>(), {});
      break;
    case CodeKind::BYTECODE_HANDLER:
      type = V8InternalCode::TYPE_BYTECODE_HANDLER;
      break;
    case CodeKind::FOR_TESTING:
      type = V8InternalCode::TYPE_FOR_TESTING;
      break;
    case CodeKind::BUILTIN:
      type = V8InternalCode::TYPE_BUILTIN;
      break;
    case CodeKind::WASM_FUNCTION:
      type = V8InternalCode::TYPE_WASM_FUNCTION;
      break;
    case CodeKind::WASM_TO_CAPI_FUNCTION:
      type = V8InternalCode::TYPE_WASM_TO_CAPI_FUNCTION;
      break;
    case CodeKind::WASM_TO_JS_FUNCTION:
      type = V8InternalCode::TYPE_WASM_TO_JS_FUNCTION;
      break;
    case CodeKind::JS_TO_WASM_FUNCTION:
      type = V8InternalCode::TYPE_JS_TO_WASM_FUNCTION;
      break;
    case CodeKind::C_WASM_ENTRY:
      type = V8InternalCode::TYPE_C_WASM_ENTRY;
      break;

    case CodeKind::INTERPRETED_FUNCTION:
    case CodeKind::BASELINE:
    case CodeKind::MAGLEV:
    case CodeKind::TURBOFAN_JS:
      UNREACHABLE();
  }

  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);

        auto* code_proto = ctx.set_v8_internal_code();
        code_proto->set_v8_isolate_iid(ctx.InternIsolate(isolate_));
        code_proto->set_name(name);
        code_proto->set_type(type);
        if (code->is_builtin()) {
          code_proto->set_builtin_id(static_cast<int32_t>(code->builtin_id()));
        }
        code_proto->set_instruction_start(code->instruction_start());
        code_proto->set_instruction_size_bytes(code->instruction_size());
        if (ctx.log_instructions()) {
          code_proto->set_machine_code(
              reinterpret_cast<const uint8_t*>(code->instruction_start()),
              code->instruction_size());
        }
      });
}

void PerfettoLogger::CodeCreateEvent(CodeTag tag,
                                     Handle<AbstractCode> abstract_code,
                                     Handle<Name> name) {
  DisallowGarbageCollection no_gc;
  if (!IsString(*name)) return;
  CodeCreateEvent(tag, abstract_code, Cast<String>(*name)->ToCString().get());
}

void PerfettoLogger::CodeCreateEvent(CodeTag tag,
                                     Handle<AbstractCode> abstract_code,
                                     Handle<SharedFunctionInfo> info,
                                     Handle<Name> script_name) {
  CodeCreateEvent(tag, abstract_code, info, script_name, 0, 0);
}

void PerfettoLogger::CodeCreateEvent(CodeTag tag,
                                     Handle<AbstractCode> abstract_code,
                                     Handle<SharedFunctionInfo> info,
                                     Handle<Name> script_name, int line,
                                     int column) {
  DisallowGarbageCollection no_gc;
  DCHECK(IsScript(info->script()));

  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);

        auto* code_proto = ctx.set_v8_js_code();
        code_proto->set_v8_isolate_iid(ctx.InternIsolate(isolate_));
        code_proto->set_v8_js_function_iid(ctx.InternJsFunction(
            isolate_, info,
            ctx.InternJsScript(isolate_, Cast<Script>(info->script())), line,
            column));
        WriteJsCode(ctx, *abstract_code, *code_proto);
      });
}
#if V8_ENABLE_WEBASSEMBLY
void PerfettoLogger::CodeCreateEvent(CodeTag tag, const wasm::WasmCode* code,
                                     wasm::WasmName name,
                                     const char* source_url, int code_offset,
                                     int script_id) {
  DisallowGarbageCollection no_gc;

  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);

        auto* code_proto = ctx.set_v8_wasm_code();
        code_proto->set_v8_isolate_iid(ctx.InternIsolate(isolate_));
        code_proto->set_v8_wasm_script_iid(
            ctx.InternWasmScript(isolate_, script_id, source_url));
        code_proto->set_function_name(name.begin(), name.size());
        // TODO(carlscab): Set tier
        code_proto->set_instruction_start(code->instruction_start());
        code_proto->set_instruction_size_bytes(code->instructions_size());
        if (ctx.log_instructions()) {
          code_proto->set_machine_code(
              reinterpret_cast<const uint8_t*>(code->instruction_start()),
              code->instructions_size());
        }
      });
}
#endif  // V8_ENABLE_WEBASSEMBLY

void PerfettoLogger::CallbackEvent(Handle<Name> name, Address entry_point) {}
void PerfettoLogger::GetterCallbackEvent(Handle<Name> name,
                                         Address entry_point) {}
void PerfettoLogger::SetterCallbackEvent(Handle<Name> name,
                                         Address entry_point) {}
void PerfettoLogger::RegExpCodeCreateEvent(Handle<AbstractCode> abstract_code,
                                           Handle<String> pattern,
                                           RegExpFlags flags) {
  DisallowGarbageCollection no_gc;
  DCHECK(IsCode(*abstract_code));
  Tagged<Code> code = abstract_code->GetCode();
  DCHECK(code->kind() == CodeKind::REGEXP);

  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);

        auto* code_proto = ctx.set_v8_reg_exp_code();
        code_proto->set_v8_isolate_iid(ctx.InternIsolate(isolate_));

        if (!pattern.is_null()) {
          PerfettoV8String(*pattern).WriteToProto(*code_proto->set_pattern());
        }
        code_proto->set_instruction_start(code->instruction_start());
        code_proto->set_instruction_size_bytes(code->instruction_size());
        if (ctx.log_instructions()) {
          code_proto->set_machine_code(
              reinterpret_cast<const uint8_t*>(code->instruction_start()),
              code->instruction_size());
        }
      });
}

void PerfettoLogger::CodeMoveEvent(Tagged<InstructionStream> from,
                                   Tagged<InstructionStream> to) {
  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);
        auto* code_move = ctx.set_code_move();
        code_move->set_isolate_iid(ctx.InternIsolate(isolate_));
        code_move->set_from_instruction_start_address(
            from->instruction_start());
        code_move->set_to_instruction_start_address(to->instruction_start());
        Tagged<Code> code = to->code(AcquireLoadTag());
        code_move->set_instruction_size_bytes(code->instruction_size());
        if (ctx.log_instructions()) {
          code_move->set_to_machine_code(
              reinterpret_cast<const uint8_t*>(code->instruction_start()),
              code->instruction_size());
        }
      });
}
void PerfettoLogger::BytecodeMoveEvent(Tagged<BytecodeArray> from,
                                       Tagged<BytecodeArray> to) {
  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);
        auto* code_move = ctx.set_code_move();
        code_move->set_isolate_iid(ctx.InternIsolate(isolate_));
        code_move->set_from_instruction_start_address(
            from->GetFirstBytecodeAddress());
        code_move->set_to_instruction_start_address(
            to->GetFirstBytecodeAddress());
        code_move->set_instruction_size_bytes(to->length());
        if (ctx.log_instructions()) {
          code_move->set_to_bytecode(
              reinterpret_cast<const uint8_t*>(to->GetFirstBytecodeAddress()),
              to->length());
        }
      });
}

void PerfettoLogger::SharedFunctionInfoMoveEvent(Address from, Address to) {}
void PerfettoLogger::NativeContextMoveEvent(Address from, Address to) {}
void PerfettoLogger::CodeMovingGCEvent() {}
void PerfettoLogger::CodeDisableOptEvent(Handle<AbstractCode> code,
                                         Handle<SharedFunctionInfo> shared) {}
void PerfettoLogger::CodeDeoptEvent(Handle<Code> code, DeoptimizeKind kind,
                                    Address pc, int fp_to_sp_delta) {}
void PerfettoLogger::CodeDependencyChangeEvent(
    Handle<Code> code, Handle<SharedFunctionInfo> shared, const char* reason) {}
void PerfettoLogger::WeakCodeClearEvent() {}

bool PerfettoLogger::is_listening_to_code_events() { return true; }

}  // namespace internal
}  // namespace v8
```