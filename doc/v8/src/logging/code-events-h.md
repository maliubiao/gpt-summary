Response:
Let's break down the thought process for analyzing the provided C++ header file.

**1. Initial Scan and Goal Identification:**

The first thing I do is a quick scan of the code, looking for keywords and structure. I see: `#ifndef`, `#define`, `#include`, `namespace v8::internal`, `class`, `enum`, `virtual`, `Handle`, `Tagged`, `LOG_EVENT_LIST`, `CODE_TYPE_LIST`. This immediately tells me it's a C++ header file related to logging and event handling within the V8 JavaScript engine. The name `code-events.h` strongly suggests it deals with events related to code execution.

My primary goal is to understand the file's functionality and relate it to JavaScript where possible. The prompt also asks about `.tq` files and common programming errors, so I need to keep those in mind.

**2. Understanding the Core Components:**

I start by dissecting the key components:

* **`LOG_EVENT_LIST` and `CODE_TYPE_LIST` macros:** These are clearly defining lists of events and code types. I mentally (or actually) expand them to see the concrete values (e.g., `kCodeCreation`, `kCodeDisableOpt`, `kBuiltin`, `kFunction`). This tells me the different kinds of code-related events and categories of code being tracked.

* **`LogEventListener` class:**  This is the core interface for receiving code-related events. The presence of virtual functions like `CodeCreateEvent`, `CodeMoveEvent`, etc., indicates an observer pattern. Different parts of the V8 engine can notify listeners about these code events. The `virtual` keyword means this class is designed for inheritance, allowing for different implementations of how these events are handled (e.g., writing to a log file, updating internal statistics).

* **`Logger` class:** This class acts as a central dispatcher for the events. It manages a list of `LogEventListener` objects and iterates through them to notify each listener when an event occurs. The mutex (`base::RecursiveMutex`) suggests thread safety is a concern.

* **Handles (`Handle<T>`) and Tagged pointers (`Tagged<T>`):** These are V8-specific smart pointer types for managing garbage-collected objects. They indicate that the events often involve V8's internal object representation.

* **Namespaces (`v8::internal`):**  This signifies that the code is part of V8's internal implementation and not directly exposed to JavaScript developers.

**3. Inferring Functionality:**

Based on the components, I can infer the following functionality:

* **Code Event Tracking:** The primary function is to track significant events related to code within V8, such as creation, optimization/deoptimization, movement in memory, and deletion.
* **Categorization:**  Code is categorized by type (Builtin, JS Function, RegExp, etc.), providing more granular information about the events.
* **Observer Pattern:**  The `Logger` and `LogEventListener` classes implement the observer pattern, allowing different parts of the engine to observe and react to code events without tight coupling.
* **Performance Monitoring/Debugging:** This infrastructure is likely used for performance analysis, debugging, profiling, and potentially for tools that provide insights into V8's internal workings.

**4. Relating to JavaScript:**

This is where I bridge the gap between the C++ internals and the JavaScript world. I think about what JavaScript actions would trigger these code events:

* **Function Definition/Execution:** Defining or calling a JavaScript function will trigger `kCodeCreation` events for the generated machine code or bytecode.
* **Optimization:** V8's optimizing compiler (TurboFan) will generate optimized code, leading to `kCodeCreation` and potentially `kCodeMove` events.
* **Deoptimization:** If optimized code becomes invalid, a `kCodeDeopt` event will occur, and V8 might fall back to less optimized code.
* **Garbage Collection:**  Moving garbage collection can trigger `kCodeMovingGC` and `kCodeMove` events as code objects are relocated in memory.
* **Callbacks:** Events like `CallbackEvent`, `GetterCallbackEvent`, `SetterCallbackEvent` are related to how native C++ code interacts with JavaScript (e.g., through built-in functions or object properties with custom accessors).
* **Regular Expressions:** Compiling and executing regular expressions involves the creation of specialized code (`kRegExp`).

I then try to construct simple JavaScript examples that would likely trigger these events.

**5. Torque and `.tq` Files:**

The prompt specifically asks about `.tq` files. My knowledge base tells me that `.tq` files are related to Torque, V8's internal language for defining built-in functions. So, if `code-events.h` were `code-events.tq`, it would be a Torque definition potentially describing how these logging events are triggered within Torque-defined built-ins.

**6. Code Logic Reasoning and Assumptions:**

I look for patterns in the function signatures and names. For instance, multiple `CodeCreateEvent` overloads suggest flexibility in the information available when creating code. The `Logger` class's methods simply forward the events to its listeners. I can make assumptions about the data flow: an event originates somewhere in the V8 engine, the relevant data is packaged, and the `Logger` dispatches it to the registered listeners.

**7. Common Programming Errors:**

I consider how the logging mechanism itself could be misused or reveal common JavaScript/V8 issues. For instance:

* **Too many deoptimizations:**  Frequent `kCodeDeopt` events could indicate performance problems in the JavaScript code.
* **Unexpected code creation:**  A large number of `kCodeCreation` events might signal inefficient code generation or excessive dynamic code creation (e.g., through `eval`).

**8. Structuring the Output:**

Finally, I organize my findings into the requested sections: functionality, `.tq` explanation, JavaScript examples, code logic reasoning, and common programming errors. I use clear and concise language, referencing specific elements from the header file. I aim to provide both a high-level overview and some specific details.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe this is directly used by JavaScript developers for debugging."  **Correction:**  The `v8::internal` namespace and use of `Handle` and `Tagged` indicate it's for internal V8 use, although the *effects* are observable in JavaScript performance.
* **Considering the `.tq` aspect:** I initially might just say "It would be a Torque file." **Refinement:** I realize I need to explain *what* that implies – that it would likely define how these events are triggered within built-in functions implemented using Torque.
* **JavaScript examples:** I start with very basic examples. **Refinement:** I try to make them slightly more illustrative of the *type* of event being triggered (e.g., showing a simple function for `kCodeCreation` and then a scenario that might lead to deoptimization).

By following this structured thinking process, I can systematically analyze the C++ header file and generate a comprehensive and accurate explanation.
这是一个V8源代码文件，定义了用于记录代码事件的接口和实现。

**功能列表:**

1. **定义代码事件类型:**  通过 `LOG_EVENT_LIST` 宏定义了一系列表示不同代码事件的枚举值，例如 `kCodeCreation` (代码创建), `kCodeDisableOpt` (禁用代码优化), `kCodeMove` (代码移动), `kCodeDeopt` (代码去优化), `kCodeDelete` (代码删除) 等。这些事件代表了V8引擎中代码生命周期的关键阶段。

2. **定义代码类型标签:** 通过 `CODE_TYPE_LIST` 宏定义了一系列表示不同代码类型的枚举值，例如 `kBuiltin` (内置函数), `kCallback` (回调函数), `kEval` (eval执行的代码), `kFunction` (JS函数), `kHandler` (异常处理器), `kBytecodeHandler` (字节码处理器), `kRegExp` (正则表达式代码), `kScript` (脚本代码), `kStub` (桩代码), `kNativeFunction` (原生函数), `kNativeScript` (原生脚本)。 这有助于区分不同来源和用途的代码。

3. **定义 `LogEventListener` 接口:**  这是一个抽象基类，定义了用于接收和处理各种代码事件的回调函数。任何希望监听代码事件的类都需要继承这个接口并实现相应的方法。例如，`CodeCreateEvent` 方法在代码被创建时被调用，并携带代码的类型、地址和相关信息。

4. **定义 `Logger` 类:**  这是一个用于管理和分发代码事件的类。它维护一个 `LogEventListener` 列表，并在代码事件发生时通知所有注册的监听器。`Logger` 类提供了添加和移除监听器的方法，以及触发各种代码事件的方法，例如 `CodeCreateEvent`, `CodeMoveEvent`, `CodeDeoptEvent` 等。

5. **线程安全:**  `Logger` 类使用 `base::RecursiveMutex` 来保护其内部状态（例如监听器列表），确保在多线程环境下的安全性。

**关于 `.tq` 文件:**

如果 `v8/src/logging/code-events.h` 以 `.tq` 结尾，那么它的确是一个 **V8 Torque 源代码** 文件。Torque 是 V8 内部使用的一种领域特定语言 (DSL)，用于定义 V8 的内置函数和运行时库。在这种情况下，该文件会包含使用 Torque 语法定义的代码事件相关的逻辑和数据结构。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

`v8/src/logging/code-events.h` 中定义的事件与 JavaScript 代码的执行和 V8 引擎的内部运作密切相关。以下是一些 JavaScript 示例，它们的操作可能会触发这里定义的某些代码事件：

1. **函数定义和调用 (触发 `kCodeCreation`, `kFunction`)**:

   ```javascript
   function myFunction(x) {
     return x * 2;
   }

   myFunction(5); // 调用函数
   ```
   当 `myFunction` 被定义时，V8 会为其生成机器码或字节码，这会触发 `kCodeCreation` 事件，并且 `CodeTag` 会是 `kFunction`。

2. **使用 `eval()` (触发 `kCodeCreation`, `kEval`)**:

   ```javascript
   let code = 'console.log("dynamically generated code");';
   eval(code);
   ```
   `eval()` 函数会动态地编译和执行字符串中的代码，这会触发 `kCodeCreation` 事件，并且 `CodeTag` 会是 `kEval`。

3. **正则表达式 (触发 `kCodeCreation`, `kRegExp`)**:

   ```javascript
   const regex = /ab+c/;
   const str = 'abbcdef';
   regex.test(str);
   ```
   当正则表达式被创建时，V8 会为其编译生成用于匹配的机器码，这会触发 `kCodeCreation` 事件，并且 `CodeTag` 会是 `kRegExp`。

4. **代码优化和去优化 (触发 `kCodeDisableOpt`, `kCodeDeopt`)**:

   V8 引擎会尝试优化频繁执行的 JavaScript 代码。如果优化后的代码由于某些原因不再有效（例如，类型假设失败），V8 会进行去优化。

   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(1, 2); // 假设 a 和 b 都是数字
   add("hello", "world"); // 假设失败，可能导致去优化
   ```
   当 V8 禁用某个函数的优化版本时，会触发 `kCodeDisableOpt` 事件。当代码被去优化时，会触发 `kCodeDeopt` 事件。

5. **垃圾回收 (可能触发 `kCodeMove`, `kCodeMovingGC`, `kCodeDelete`)**:

   V8 的垃圾回收器在运行时会移动内存中的对象，包括代码对象。这可能会触发 `kCodeMove` (当单个代码对象被移动) 或 `kCodeMovingGC` (表示正在进行移动垃圾回收) 事件。不再使用的代码对象会被删除，触发 `kCodeDelete` 事件。

**代码逻辑推理示例 (假设输入与输出):**

假设有一个 `Logger` 实例和两个 `LogEventListener` 实例 `listener1` 和 `listener2`。

**假设输入:**

1. 调用 `logger.AddListener(listener1)` 和 `logger.AddListener(listener2)` 将这两个监听器添加到 `Logger` 中。
2. 执行一段 JavaScript 代码，导致 V8 创建了一个新的 JS 函数的机器码。
3. V8 内部调用 `logger.CodeCreateEvent(Logger::CodeTag::kFunction, code_handle, shared_function_info_handle, name_handle)`，其中 `code_handle` 是新创建的代码的句柄，其他参数也相应设置。

**预期输出:**

1. `listener1` 的 `CodeCreateEvent` 方法会被调用，参数为 `Logger::CodeTag::kFunction`, `code_handle`, `shared_function_info_handle`, `name_handle`。
2. `listener2` 的 `CodeCreateEvent` 方法也会被调用，参数相同。

**涉及用户常见的编程错误:**

虽然这个头文件定义的是 V8 内部的日志机制，但通过分析这些日志事件，我们可以间接地了解一些用户常见的编程错误及其影响：

1. **频繁的代码去优化 (大量的 `kCodeDeopt` 事件):** 这通常意味着代码的类型不稳定，V8 的优化器做出了错误的假设。常见的导致去优化的错误包括：
   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(1, 2);
   add("hello", "world"); // 类型不一致，可能导致去优化
   ```

2. **过多的动态代码生成 (大量的 `kCodeCreation` 事件，`CodeTag` 为 `kEval` 等):**  过度使用 `eval()` 或 `Function()` 构造函数会生成大量的动态代码，这会影响性能，因为每次都需要进行编译。
   ```javascript
   for (let i = 0; i < 1000; i++) {
     eval(`console.log(${i})`); // 效率低下
   }
   ```

3. **不必要的函数或闭包创建 (大量的 `kCodeCreation` 事件，`CodeTag` 为 `kFunction`):**  在循环中或高频调用的地方创建不必要的函数或闭包会增加代码创建的开销。
   ```javascript
   function processArray(arr) {
     return arr.map(item => { // 每次 map 都创建一个新的匿名函数
       return item * 2;
     });
   }
   ```

**总结:**

`v8/src/logging/code-events.h` 定义了一个用于记录 V8 引擎内部代码事件的强大机制。它允许 V8 的各个部分报告代码的创建、移动、优化、去优化和删除等事件，并通过 `Logger` 类将这些事件分发给感兴趣的监听器。虽然这是一个内部 API，但通过理解这些事件，我们可以更好地理解 V8 的工作原理，并间接地诊断 JavaScript 代码中的性能问题。如果该文件以 `.tq` 结尾，则表示它是使用 Torque 语言定义的，用于 V8 的内置功能实现。

### 提示词
```
这是目录为v8/src/logging/code-events.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/logging/code-events.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_LOGGING_CODE_EVENTS_H_
#define V8_LOGGING_CODE_EVENTS_H_

#include <vector>

#include "src/base/platform/mutex.h"
#include "src/base/vector.h"
#include "src/common/globals.h"
#include "src/objects/bytecode-array.h"
#include "src/objects/code.h"
#include "src/objects/instruction-stream.h"
#include "src/objects/name.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/string.h"

namespace v8 {
namespace internal {

class AbstractCode;
class Name;
class SharedFunctionInfo;
class String;

namespace wasm {
class WasmCode;
using WasmName = base::Vector<const char>;
}  // namespace wasm

#define LOG_EVENT_LIST(V)                         \
  V(kCodeCreation, "code-creation")               \
  V(kCodeDisableOpt, "code-disable-optimization") \
  V(kCodeMove, "code-move")                       \
  V(kCodeDeopt, "code-deopt")                     \
  V(kCodeDelete, "code-delete")                   \
  V(kCodeMovingGC, "code-moving-gc")              \
  V(kSharedFuncMove, "sfi-move")                  \
  V(kSnapshotCodeName, "snapshot-code-name")      \
  V(kTick, "tick")

#define CODE_TYPE_LIST(V)              \
  V(kBuiltin, Builtin)                 \
  V(kCallback, Callback)               \
  V(kEval, Eval)                       \
  V(kFunction, JS)                     \
  V(kHandler, Handler)                 \
  V(kBytecodeHandler, BytecodeHandler) \
  V(kRegExp, RegExp)                   \
  V(kScript, Script)                   \
  V(kStub, Stub)                       \
  V(kNativeFunction, JS)               \
  V(kNativeScript, Script)
// Note that 'Native' cases for functions and scripts are mapped onto
// original tags when writing to the log.

#define PROFILE(the_isolate, Call) (the_isolate)->logger()->Call;

class LogEventListener {
 public:
#define DECLARE_ENUM(enum_item, _) enum_item,
  enum class Event : uint8_t { LOG_EVENT_LIST(DECLARE_ENUM) kLength };
  enum class CodeTag : uint8_t { CODE_TYPE_LIST(DECLARE_ENUM) kLength };
#undef DECLARE_ENUM

  virtual ~LogEventListener() = default;

  virtual void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                               const char* name) = 0;
  virtual void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                               Handle<Name> name) = 0;
  virtual void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                               Handle<SharedFunctionInfo> shared,
                               Handle<Name> script_name) = 0;
  virtual void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                               Handle<SharedFunctionInfo> shared,
                               Handle<Name> script_name, int line,
                               int column) = 0;
#if V8_ENABLE_WEBASSEMBLY
  virtual void CodeCreateEvent(CodeTag tag, const wasm::WasmCode* code,
                               wasm::WasmName name, const char* source_url,
                               int code_offset, int script_id) = 0;
#endif  // V8_ENABLE_WEBASSEMBLY

  virtual void CallbackEvent(Handle<Name> name, Address entry_point) = 0;
  virtual void GetterCallbackEvent(Handle<Name> name, Address entry_point) = 0;
  virtual void SetterCallbackEvent(Handle<Name> name, Address entry_point) = 0;
  virtual void RegExpCodeCreateEvent(Handle<AbstractCode> code,
                                     Handle<String> source,
                                     RegExpFlags flags) = 0;
  // Not handlified as this happens during GC. No allocation allowed.
  virtual void CodeMoveEvent(Tagged<InstructionStream> from,
                             Tagged<InstructionStream> to) = 0;
  virtual void BytecodeMoveEvent(Tagged<BytecodeArray> from,
                                 Tagged<BytecodeArray> to) = 0;
  virtual void SharedFunctionInfoMoveEvent(Address from, Address to) = 0;
  virtual void NativeContextMoveEvent(Address from, Address to) = 0;
  virtual void CodeMovingGCEvent() = 0;
  virtual void CodeDisableOptEvent(Handle<AbstractCode> code,
                                   Handle<SharedFunctionInfo> shared) = 0;
  virtual void CodeDeoptEvent(Handle<Code> code, DeoptimizeKind kind,
                              Address pc, int fp_to_sp_delta) = 0;
  // These events can happen when 1. an assumption made by optimized code fails
  // or 2. a weakly embedded object dies.
  virtual void CodeDependencyChangeEvent(Handle<Code> code,
                                         Handle<SharedFunctionInfo> shared,
                                         const char* reason) = 0;
  // Called during GC shortly after any weak references to code objects are
  // cleared.
  virtual void WeakCodeClearEvent() = 0;

  virtual bool is_listening_to_code_events() { return false; }
  virtual bool allows_code_compaction() { return true; }
};

// Dispatches events to a set of registered listeners.
class Logger {
 public:
  using Event = LogEventListener::Event;
  using CodeTag = LogEventListener::CodeTag;

  Logger() = default;
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  bool AddListener(LogEventListener* listener) {
    base::RecursiveMutexGuard guard(&mutex_);
    auto position = std::find(listeners_.begin(), listeners_.end(), listener);
    if (position != listeners_.end()) return false;
    // Add the listener to the end and update the element
    listeners_.push_back(listener);
    return true;
  }

  bool RemoveListener(LogEventListener* listener) {
    base::RecursiveMutexGuard guard(&mutex_);
    auto position = std::find(listeners_.begin(), listeners_.end(), listener);
    if (position == listeners_.end()) return false;
    listeners_.erase(position);
    return true;
  }

  bool is_listening_to_code_events() {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      if (listener->is_listening_to_code_events()) return true;
    }
    return false;
  }

  bool allows_code_compaction() {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      if (!listener->allows_code_compaction()) return false;
    }
    return true;
  }

  void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                       const char* comment) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeCreateEvent(tag, code, comment);
    }
  }

  void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                       Handle<Name> name) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeCreateEvent(tag, code, name);
    }
  }

  void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                       Handle<SharedFunctionInfo> shared, Handle<Name> name) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeCreateEvent(tag, code, shared, name);
    }
  }

  void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                       Handle<SharedFunctionInfo> shared, Handle<Name> source,
                       int line, int column) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeCreateEvent(tag, code, shared, source, line, column);
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  void CodeCreateEvent(CodeTag tag, const wasm::WasmCode* code,
                       wasm::WasmName name, const char* source_url,
                       int code_offset, int script_id) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeCreateEvent(tag, code, name, source_url, code_offset,
                                script_id);
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  void CallbackEvent(Handle<Name> name, Address entry_point) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CallbackEvent(name, entry_point);
    }
  }

  void GetterCallbackEvent(Handle<Name> name, Address entry_point) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->GetterCallbackEvent(name, entry_point);
    }
  }

  void SetterCallbackEvent(Handle<Name> name, Address entry_point) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->SetterCallbackEvent(name, entry_point);
    }
  }

  void RegExpCodeCreateEvent(Handle<AbstractCode> code, Handle<String> source,
                             RegExpFlags flags) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->RegExpCodeCreateEvent(code, source, flags);
    }
  }

  void CodeMoveEvent(Tagged<InstructionStream> from,
                     Tagged<InstructionStream> to) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeMoveEvent(from, to);
    }
  }

  void BytecodeMoveEvent(Tagged<BytecodeArray> from, Tagged<BytecodeArray> to) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->BytecodeMoveEvent(from, to);
    }
  }

  void SharedFunctionInfoMoveEvent(Address from, Address to) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->SharedFunctionInfoMoveEvent(from, to);
    }
  }

  void NativeContextMoveEvent(Address from, Address to) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->NativeContextMoveEvent(from, to);
    }
  }

  void CodeMovingGCEvent() {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeMovingGCEvent();
    }
  }

  void CodeDisableOptEvent(Handle<AbstractCode> code,
                           Handle<SharedFunctionInfo> shared) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeDisableOptEvent(code, shared);
    }
  }

  void CodeDeoptEvent(Handle<Code> code, DeoptimizeKind kind, Address pc,
                      int fp_to_sp_delta) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeDeoptEvent(code, kind, pc, fp_to_sp_delta);
    }
  }

  void CodeDependencyChangeEvent(Handle<Code> code,
                                 Handle<SharedFunctionInfo> sfi,
                                 const char* reason) {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->CodeDependencyChangeEvent(code, sfi, reason);
    }
  }

  void WeakCodeClearEvent() {
    base::RecursiveMutexGuard guard(&mutex_);
    for (auto listener : listeners_) {
      listener->WeakCodeClearEvent();
    }
  }

 private:
  std::vector<LogEventListener*> listeners_;
  base::RecursiveMutex mutex_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_LOGGING_CODE_EVENTS_H_
```