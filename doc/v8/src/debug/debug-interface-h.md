Response:
Let's break down the thought process for analyzing this header file.

1. **Initial Scan for Purpose:** The filename `debug-interface.h` immediately suggests this file is about providing an interface for debugging V8. The `#ifndef V8_DEBUG_DEBUG_INTERFACE_H_` pattern confirms it's a header guard, common in C++.

2. **Include Directives - Clues to Functionality:**  Look at the included header files. These give hints about the types and functionalities exposed.
    * `include/v8-callbacks.h`, `include/v8-date.h`, `include/v8-debug.h`, `include/v8-embedder-heap.h`, `include/v8-isolate.h`, `include/v8-local-handle.h`, `include/v8-memory-span.h`, `include/v8-promise.h`, `include/v8-script.h`, `include/v8-util.h`:  These suggest interactions with core V8 concepts like callbacks, dates, debugging features, memory management, isolates (independent V8 instances), handles to JavaScript objects, memory regions, promises, scripts, and utilities.
    * `src/base/enum-set.h`, `src/base/vector.h`, `src/common/globals.h`: These indicate use of internal V8 data structures and global definitions.
    * `src/debug/interface-types.h`:  This is a strong signal that this file defines the *interface* and relies on other files for the implementation details.

3. **Namespace Analysis:** The code is within the `v8::debug` namespace. This reinforces the debugging focus. The presence of `v8_inspector` namespace suggests integration with the Chrome DevTools protocol or a similar debugging infrastructure.

4. **Function Grouping and Naming Conventions:**  Start grouping the functions based on their names and parameters. Look for patterns.

    * **Context and Isolate Management:** Functions like `SetContextId`, `GetContextId`, `SetInspector`, `GetInspector` clearly relate to managing debugging contexts and the inspector.

    * **String Representation:** Functions like `GetBigIntStringValue`, `GetBigIntDescription`, `GetDateDescription`, `GetFunctionDescription` are about obtaining string representations of JavaScript values for debugging purposes.

    * **Breakpoints:**  `SetBreakOnNextFunctionCall`, `ClearBreakOnNextFunctionCall`, `ChangeBreakOnException`, `RemoveBreakpoint`, `SetBreakPointsActive`, `PrepareStep`, `BreakRightNow`, `SetTerminateOnResume`, `CanBreakProgram`, `SetBreakpoint`, `SetFunctionBreakpoint`, `RemoveWasmBreakpoint`, `BreakProgramRequested`, `BreakOnInstrumentation`, `BreakpointConditionEvaluated`. This is a significant cluster related to pausing execution.

    * **Script and Source Code Inspection:** `GetInternalProperties`, `GetPrivateMembers`, `GetCreationContext`, `ScriptSource`, `Script`, `GetLoadedScripts`, `CompileInspectorScript`, `SetScriptSource`, `GetPossibleBreakpoints`, `GetSourceOffset`, `GetSourceLocation`, `IsWasm`, `WasmScript`, `GetDebugSymbols`, `Disassemble`. These functions deal with accessing script information, source code, and potentially WebAssembly specifics.

    * **Live Edit:**  `LiveEditResult`, `SetScriptSource` (with `allow_top_frame_live_editing`). This hints at the ability to modify code while the program is running.

    * **Stepping:** `StepAction`, `PrepareStep`, `ClearStepping`.

    * **Stack Frames and Scopes:**  `StackTraceIterator`, `ScopeIterator`, `GlobalLexicalScopeNames`, `Evaluate`, `EvaluateGlobal`, `CallFunctionOn`. These are for inspecting the execution stack and variable scopes.

    * **Code Coverage:** `Coverage`, `Coverage::ScriptData`, `Coverage::FunctionData`, `Coverage::BlockData`, `CollectPrecise`, `CollectBestEffort`, `SelectMode`. This clearly deals with code coverage analysis.

    * **Asynchronous Operations:** `AsyncEventDelegate`, `SetAsyncEventDelegate`, `RecordAsyncStackTaggingCreateTaskCall`. This suggests debugging of asynchronous operations.

    * **Internal V8 Objects:** `GeneratorObject`, `EphemeronTable`, `AccessorPair`, `PropertyIterator`, `WasmValueObject`. These offer ways to interact with internal V8 object representations for debugging.

    * **Utilities:** `EstimatedValueSize`, `GetBuiltin`, `CreateMessageFromException`, `GetNextRandomInt64`, `GetCurrentPlatform`, `ForceGarbageCollection`.

    * **Delegates/Listeners:** `DebugDelegate`, `SetDebugDelegate`, `ConsoleDelegate`, `SetConsoleDelegate`. This pattern indicates a way for external code to receive notifications and customize debugging behavior.

    * **Interrupt Control:** `PostponeInterruptsScope`, `DisableBreakScope`. These seem to be mechanisms for temporarily controlling interrupt behavior, likely for internal V8 use during debugging operations.

5. **Torque Check:** The prompt asks about the `.tq` extension. Since this file is `.h`, it's a C++ header, *not* a Torque file. Torque files are used for defining built-in JavaScript functions in a more structured way.

6. **JavaScript Relevance and Examples:** For functions related to JavaScript concepts (like getting descriptions, properties, etc.), provide simple JavaScript examples. This helps illustrate how the C++ interface relates to the user-facing language.

7. **Code Logic and Assumptions (Hypothetical Inputs and Outputs):**  For functions with clear inputs and outputs (e.g., `GetContextId`), suggest simple scenarios to illustrate the flow. For more complex functions, acknowledge the complexity and potentially give a high-level example.

8. **Common Programming Errors:**  Think about how the debugging features exposed by this interface could help users identify common mistakes (e.g., exceptions, incorrect variable values).

9. **Structure and Clarity:** Organize the findings into logical categories. Use clear and concise language. Explain technical terms where necessary. Use formatting (like bullet points) to improve readability.

10. **Review and Refine:** After the initial analysis, review the findings for accuracy and completeness. Ensure the explanations are clear and the examples are relevant. Double-check for any missed functions or important details. For example, initially, I might have missed the connection between `v8_inspector` and Chrome DevTools, but a second pass looking for external integrations would highlight this.
这是一个V8 C++头文件，定义了 V8 引擎调试接口的公共 API。它主要用于 V8 引擎的调试器和集成调试功能的工具（如 Chrome DevTools）。

**以下是 `v8/src/debug/debug-interface.h` 的主要功能：**

1. **上下文和Isolate管理:**
   - `SetContextId(Local<Context> context, int id)`: 为 V8 上下文设置一个调试器 ID。
   - `GetContextId(Local<Context> context)`: 获取 V8 上下文的调试器 ID。
   - `SetInspector(Isolate* isolate, v8_inspector::V8Inspector*)`: 将 V8 Inspector 对象关联到特定的 Isolate。
   - `GetInspector(Isolate* isolate)`: 获取与特定 Isolate 关联的 V8 Inspector 对象。

2. **获取值的调试描述:**
   - `GetBigIntStringValue(Isolate* isolate, Local<BigInt> bigint)`: 获取 BigInt 值的字符串表示形式，不包含尾部的 "n"。
   - `GetBigIntDescription(Isolate* isolate, Local<BigInt> bigint)`: 获取 BigInt 值的调试字符串表示形式。
   - `GetDateDescription(Local<Date> date)`: 获取 Date 对象的调试字符串表示形式。
   - `GetFunctionDescription(Local<Function> function)`: 获取 Function 对象的调试字符串表示形式。

   **JavaScript 示例:**  这些函数在调试器中显示变量值时非常有用。例如，当你在 Chrome DevTools 的控制台中查看一个 `Date` 对象时，看到的字符串表示就是通过类似 `GetDateDescription` 的机制生成的。

   ```javascript
   const now = new Date();
   function myFunction() {}
   const bigIntValue = 9007199254740991n;

   // 当你在调试器中查看这些变量时，V8 会使用类似上述 C++ 函数来生成它们的字符串表示。
   ```

3. **断点控制:**
   - `SetBreakOnNextFunctionCall(Isolate* isolate)`: 设置一个断点，在给定 Isolate 中调用的下一个函数时触发。
   - `ClearBreakOnNextFunctionCall(Isolate* isolate)`: 清除已设置的在下一个函数调用时触发的断点。
   - `GetInternalProperties(Isolate* isolate, Local<Value> value)`: 获取特定值类型的内部属性。
   - `GetPrivateMembers(...)`: 获取对象的私有成员（字段、方法、访问器）。
   - `GetCreationContext(Local<Object> value)`: 获取对象创建时的上下文。
   - `ChangeBreakOnException(Isolate* isolate, ExceptionBreakState state)`: 设置 V8 在抛出异常时是否暂停执行。
   - `RemoveBreakpoint(Isolate* isolate, BreakpointId id)`: 移除指定 ID 的断点。
   - `SetBreakPointsActive(Isolate* isolate, bool is_active)`: 激活或禁用给定 Isolate 中的所有断点。
   - `PrepareStep(Isolate* isolate, StepAction action)`: 准备执行单步调试操作（步入、步过、步出）。
   - `ClearStepping(Isolate* isolate)`: 清除当前的单步调试设置。
   - `BreakRightNow(Isolate* isolate, base::EnumSet<BreakReason> break_reason = {})`: 立即触发调试器中断。
   - `SetTerminateOnResume(Isolate* isolate)`: 设置在恢复执行前终止的标记。
   - `CanBreakProgram(Isolate* isolate)`: 检查当前是否可以中断程序执行。
   - `SetBreakpoint(v8::Local<v8::String> condition, debug::Location* location, BreakpointId* id) const`: 在脚本的特定位置设置断点。
   - `SetFunctionBreakpoint(v8::Local<v8::Function> function, v8::Local<v8::String> condition, BreakpointId* id)`: 在函数入口处设置断点。

   **JavaScript 示例:** 这些功能对应于调试器中设置断点、单步执行、异常时暂停等操作。

   ```javascript
   function add(a, b) {
       debugger; // 相当于 BreakRightNow
       return a + b;
   }

   add(5, 10); // 执行到 debugger 语句时会暂停

   // 在 Chrome DevTools 中，你可以：
   // - 在特定行号设置断点
   // - 设置条件断点 (对应 SetBreakpoint 的 condition 参数)
   // - 单步执行 (对应 PrepareStep)
   // - 设置在捕获或未捕获的异常时暂停 (对应 ChangeBreakOnException)
   ```

4. **脚本和代码信息:**
   - `ScriptSource`: 表示脚本的源代码，可以是 JavaScript 字符串或 WebAssembly 字节码。
   - `Script`: 提供访问 V8 内部 `Script` 对象的包装器，包含脚本的元数据（ID、名称、URL、起始/结束行列号等）、源代码以及设置断点和执行代码修改的功能。
   - `GetLoadedScripts(Isolate* isolate, std::vector<v8::Global<Script>>& scripts)`: 获取已加载的所有脚本。
   - `CompileInspectorScript(Isolate* isolate, Local<String> source)`: 编译用于 Inspector 的脚本。
   - `SetScriptSource(v8::Local<v8::String> newSource, bool preview, bool allow_top_frame_live_editing, LiveEditResult* result) const`: 修改脚本的源代码（用于热重载等）。
   - `GetPossibleBreakpoints(...)`: 获取脚本中可能的断点位置。
   - `GetSourceOffset(...)`: 获取源代码位置的偏移量。
   - `GetSourceLocation(int offset) const`: 获取给定偏移量的源代码位置。
   - `WasmScript`: `Script` 的子类，专门用于 WebAssembly 脚本，提供 wasm 特定的调试信息。
   - `Disassemble(...)`: 反汇编 WebAssembly 代码。

   **JavaScript 示例:** 当你在 Chrome DevTools 的 "Sources" 面板中查看代码时，或者使用像 `console.trace()` 打印堆栈信息时，V8 会使用这些接口来获取脚本的源信息和位置。

5. **代码热重载 (Live Edit):**
   - `LiveEditResult`: 描述代码修改操作的结果。
   - `SetScriptSource` 方法允许在运行时修改脚本的源代码。

   **JavaScript 示例:**  在支持热重载的开发环境中，当你修改 JavaScript 代码并保存时，调试器可能会使用 `SetScriptSource` 来更新 V8 引擎中的脚本，而无需完全重新加载页面。

6. **调用栈和作用域检查:**
   - `StackTraceIterator`: 遍历 JavaScript 调用栈。
   - `ScopeIterator`: 遍历指定作用域中的变量。
   - `GlobalLexicalScopeNames(v8::Local<v8::Context> context, std::vector<v8::Global<v8::String>>* names)`: 获取全局词法作用域中的变量名。
   - `Evaluate(v8::Local<v8::String> source, bool throw_on_side_effect)`: 在当前栈帧中执行 JavaScript 代码。
   - `EvaluateGlobal(...)`: 在全局作用域中执行 JavaScript 代码。
   - `GeneratorObject`: 提供访问生成器对象内部状态的接口。

   **JavaScript 示例:**  这些接口用于调试器中查看调用栈信息、检查变量值、在特定作用域中执行代码片段等。

   ```javascript
   function outer() {
       let x = 10;
       function inner() {
           let y = 20;
           debugger;
       }
       inner();
   }
   outer();

   // 当程序暂停在 debugger 处时，调试器可以使用 StackTraceIterator 来查看 outer 和 inner 函数的调用关系，
   // 并使用 ScopeIterator 来查看当前作用域 (inner) 中的变量 y 和闭包作用域 (outer) 中的变量 x 的值。
   ```

7. **代码覆盖率:**
   - `Coverage`: 用于收集和访问代码覆盖率信息。
   - `Coverage::ScriptData`, `Coverage::FunctionData`, `Coverage::BlockData`: 用于组织覆盖率数据的结构。
   - `CollectPrecise(...)`, `CollectBestEffort(...)`: 启动代码覆盖率收集。
   - `SelectMode(...)`: 设置代码覆盖率的收集模式。

   **JavaScript 示例:**  像 Istanbul.js 这样的代码覆盖率工具，在底层会使用 V8 提供的接口来收集哪些代码被执行的信息。

8. **调试事件委托:**
   - `DebugDelegate`: 定义了一个接口，用于接收 V8 调试事件的通知，例如脚本编译完成、程序中断、异常抛出等。
   - `SetDebugDelegate(Isolate* isolate, DebugDelegate* listener)`: 设置调试事件的监听器。
   - `AsyncEventDelegate`: 用于异步操作的调试事件。
   - `SetAsyncEventDelegate(...)`: 设置异步事件的监听器。

9. **控制台集成:**
   - `SetConsoleDelegate(Isolate* isolate, ConsoleDelegate* delegate)`: 设置控制台输出的委托。
   - `CreateMessageFromException(...)`: 从异常创建一个消息对象。

10. **其他实用工具:**
    - `EstimatedValueSize(...)`: 估计一个值的大小。
    - `GetBuiltin(...)`: 获取内置函数的句柄。
    - `GetNextRandomInt64(...)`: 获取下一个随机 64 位整数。
    - `ForceGarbageCollection(...)`: 强制进行垃圾回收。
    - `PostponeInterruptsScope`, `DisableBreakScope`: 用于控制中断的 RAII 作用域。
    - `EphemeronTable`: 表示弱哈希表的类。
    - `AccessorPair`: 表示访问器对（getter 和 setter）。
    - `PropertyIterator`: 用于迭代对象的属性。
    - `WasmValueObject`: 表示 WebAssembly 值的对象。
    - `GetMessageFromPromise(...)`: 从 Promise 获取消息。
    - `RecordAsyncStackTaggingCreateTaskCall(...)`: 记录异步堆栈标记的任务调用。
    - `NotifyDebuggerPausedEventSent(...)`: 通知调试器暂停事件已发送。
    - `GetDebuggingId(v8::Local<v8::Function> function)`: 获取函数的调试 ID。
    - `GetCurrentPlatform()`: 获取当前的平台对象。

**关于 `.tq` 结尾：**

如果 `v8/src/debug/debug-interface.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是一种用于定义 V8 运行时内置函数和类型的领域特定语言。`.tq` 文件会被编译成 C++ 代码。

**这个文件不是 `.tq` 文件，因此它是一个标准的 C++ 头文件。**

**与 JavaScript 功能的关系：**

这个头文件中定义的接口是 V8 引擎实现其调试功能的基础。 当你在 Chrome DevTools 中使用调试器时，或者使用 `console.log` 等方法时，V8 引擎内部会调用这些 C++ 接口来完成相应的操作。

**代码逻辑推理示例：**

假设我们有一个 JavaScript 函数：

```javascript
function myFunction(x) {
  return x * 2;
}
```

并且我们在 `return x * 2;` 这一行设置了一个断点。

**假设输入：**

- `Isolate* isolate`: 当前 V8 Isolate 的指针。
- `StepAction action = StepOver`: 用户在调试器中点击了 "单步跳过" 按钮。

**输出：**

`PrepareStep(isolate, StepOver)` 函数会被调用，V8 引擎会执行当前行代码，然后暂停在 `myFunction` 函数的下一行（如果存在），或者返回到调用 `myFunction` 的地方。

**用户常见的编程错误示例：**

1. **未捕获的异常：** 当 JavaScript 代码抛出一个未捕获的异常时，调试器可以通过 `ChangeBreakOnException(isolate, BreakOnUncaughtException)` 设置为暂停。这可以帮助开发者快速定位导致错误的异常。

   ```javascript
   function divide(a, b) {
       if (b === 0) {
           throw new Error("Cannot divide by zero");
       }
       return a / b;
   }

   divide(10, 0); // 抛出异常，如果设置了断点，调试器会暂停
   ```

2. **变量值错误：**  在调试过程中，开发者可以使用断点和作用域检查功能来查看变量的值，从而发现逻辑错误。

   ```javascript
   function calculateTotal(price, quantity) {
       let taxRate = 0.1;
       let total = price + quantity * taxRate; // 错误：应该先计算价格乘以数量
       return total;
   }

   // 在调试器中，开发者可以检查 total 的值，发现计算错误。
   ```

总而言之，`v8/src/debug/debug-interface.h` 是 V8 调试功能的基石，它定义了 V8 引擎与外部调试工具交互的桥梁。理解这个头文件的内容有助于深入了解 V8 引擎的调试机制。

### 提示词
```
这是目录为v8/src/debug/debug-interface.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/debug-interface.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_DEBUG_DEBUG_INTERFACE_H_
#define V8_DEBUG_DEBUG_INTERFACE_H_

#include <memory>

#include "include/v8-callbacks.h"
#include "include/v8-date.h"
#include "include/v8-debug.h"
#include "include/v8-embedder-heap.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-memory-span.h"
#include "include/v8-promise.h"
#include "include/v8-script.h"
#include "include/v8-util.h"
#include "src/base/enum-set.h"
#include "src/base/vector.h"
#include "src/common/globals.h"
#include "src/debug/interface-types.h"

namespace v8_inspector {
class V8Inspector;
}  // namespace v8_inspector

namespace v8 {

class Platform;

namespace internal {
struct CoverageBlock;
struct CoverageFunction;
struct CoverageScript;
class Coverage;
class DisableBreak;
class PostponeInterruptsScope;
class Script;
}  // namespace internal

namespace debug {

void SetContextId(Local<Context> context, int id);
int GetContextId(Local<Context> context);

void SetInspector(Isolate* isolate, v8_inspector::V8Inspector*);
v8_inspector::V8Inspector* GetInspector(Isolate* isolate);

// Returns a debug string representation of the bigint without tailing `n`.
Local<String> GetBigIntStringValue(Isolate* isolate, Local<BigInt> bigint);

// Returns a debug string representation of the bigint.
Local<String> GetBigIntDescription(Isolate* isolate, Local<BigInt> bigint);

// Returns a debug string representation of the date.
Local<String> GetDateDescription(Local<Date> date);

// Returns a debug string representation of the function.
Local<String> GetFunctionDescription(Local<Function> function);

// Schedule a debugger break to happen when function is called inside given
// isolate.
V8_EXPORT_PRIVATE void SetBreakOnNextFunctionCall(Isolate* isolate);

// Remove scheduled debugger break in given isolate if it has not
// happened yet.
V8_EXPORT_PRIVATE void ClearBreakOnNextFunctionCall(Isolate* isolate);

/**
 * Returns array of internal properties specific to the value type. Result has
 * the following format: [<name>, <value>,...,<name>, <value>]. Result array
 * will be allocated in the current context.
 */
MaybeLocal<Array> GetInternalProperties(Isolate* isolate, Local<Value> value);

enum class PrivateMemberFilter {
  kPrivateMethods = 1,
  kPrivateFields = 1 << 1,
  kPrivateAccessors = 1 << 2,
};

/**
 * Retrieve both instance and static private members on an object.
 * filter should be a combination of PrivateMemberFilter.
 * Returns through the out parameters names_out a vector of names
 * in v8::String and through values_out the corresponding values.
 * Private fields and methods are returned directly while accessors are
 * returned as v8::debug::AccessorPair. Missing components in the accessor
 * pairs are null.
 * If an exception occurs, false is returned. Otherwise true is returned.
 * Results will be allocated in the current context and handle scope.
 */
V8_EXPORT_PRIVATE bool GetPrivateMembers(Local<Context> context,
                                         Local<Object> value, int filter,
                                         LocalVector<Value>* names_out,
                                         LocalVector<Value>* values_out);

/**
 * Forwards to v8::Object::CreationContext, but with special handling for
 * JSGlobalProxy objects.
 */
MaybeLocal<Context> GetCreationContext(Local<Object> value);

enum ExceptionBreakState {
  NoBreakOnException = 0,
  BreakOnCaughtException = 1,
  BreakOnUncaughtException = 2,
  BreakOnAnyException = 3,
};

/**
 * Defines if VM will pause on exceptions or not.
 * If BreakOnAnyExceptions is set then VM will pause on caught and uncaught
 * exception, if BreakOnUncaughtException is set then VM will pause only on
 * uncaught exception, otherwise VM won't stop on any exception.
 */
void ChangeBreakOnException(Isolate* isolate, ExceptionBreakState state);

void RemoveBreakpoint(Isolate* isolate, BreakpointId id);
void SetBreakPointsActive(Isolate* isolate, bool is_active);

enum StepAction {
  StepOut = 0,   // Step out of the current function.
  StepOver = 1,  // Step to the next statement in the current function.
  StepInto = 2   // Step into new functions invoked or the next statement
                 // in the current function.
};

// Record the reason for why the debugger breaks.
enum class BreakReason : uint8_t {
  kAlreadyPaused,
  kStep,
  kAsyncStep,
  kException,
  kAssert,
  kDebuggerStatement,
  kOOM,
  kScheduled,
  kAgent
};
typedef base::EnumSet<BreakReason> BreakReasons;

void PrepareStep(Isolate* isolate, StepAction action);
bool PrepareRestartFrame(Isolate* isolate, int callFrameOrdinal);
void ClearStepping(Isolate* isolate);
V8_EXPORT_PRIVATE void BreakRightNow(
    Isolate* isolate, base::EnumSet<BreakReason> break_reason = {});

// Use `SetTerminateOnResume` to indicate that an TerminateExecution interrupt
// should be set shortly before resuming, i.e. shortly before returning into
// the JavaScript stack frames on the stack. In contrast to setting the
// interrupt with `RequestTerminateExecution` directly, this flag allows
// the isolate to be entered for further JavaScript execution.
V8_EXPORT_PRIVATE void SetTerminateOnResume(Isolate* isolate);

bool CanBreakProgram(Isolate* isolate);

class Script;

struct LiveEditResult {
  enum Status {
    OK,
    COMPILE_ERROR,
    BLOCKED_BY_RUNNING_GENERATOR,
    BLOCKED_BY_ACTIVE_FUNCTION,
    BLOCKED_BY_TOP_LEVEL_ES_MODULE_CHANGE,
  };
  Status status = OK;
  bool stack_changed = false;
  // Available only for OK.
  v8::Local<v8::debug::Script> script;
  bool restart_top_frame_required = false;
  // Fields below are available only for COMPILE_ERROR.
  v8::Local<v8::String> message;
  int line_number = -1;
  int column_number = -1;
};

/**
 * An internal representation of the source for a given
 * `v8::debug::Script`, which can be a `v8::String`, in
 * which case it represents JavaScript source, or it can
 * be a managed pointer to a native Wasm module, or it
 * can be undefined to indicate that source is unavailable.
 */
class V8_EXPORT_PRIVATE ScriptSource {
 public:
  // The number of characters in case of JavaScript or
  // the size of the memory in case of WebAssembly.
  size_t Length() const;

  // The actual size of the source in bytes.
  size_t Size() const;

  MaybeLocal<String> JavaScriptCode() const;
#if V8_ENABLE_WEBASSEMBLY
  Maybe<MemorySpan<const uint8_t>> WasmBytecode() const;
#endif  // V8_ENABLE_WEBASSEMBLY
};

/**
 * Native wrapper around v8::internal::Script object.
 */
class V8_EXPORT_PRIVATE Script {
 public:
  v8::Isolate* GetIsolate() const;

  ScriptOriginOptions OriginOptions() const;
  bool WasCompiled() const;
  bool IsEmbedded() const;
  int Id() const;
  int StartLine() const;
  int StartColumn() const;
  int EndLine() const;
  int EndColumn() const;
  MaybeLocal<String> Name() const;
  MaybeLocal<String> SourceURL() const;
  MaybeLocal<String> SourceMappingURL() const;
  MaybeLocal<String> GetSha256Hash() const;
  Maybe<int> ContextId() const;
  Local<ScriptSource> Source() const;
  bool IsModule() const;
  bool GetPossibleBreakpoints(
      const debug::Location& start, const debug::Location& end,
      bool restrict_to_function,
      std::vector<debug::BreakLocation>* locations) const;
  enum class GetSourceOffsetMode { kStrict, kClamp };
  Maybe<int> GetSourceOffset(
      const debug::Location& location,
      GetSourceOffsetMode mode = GetSourceOffsetMode::kStrict) const;
  v8::debug::Location GetSourceLocation(int offset) const;
  bool SetScriptSource(v8::Local<v8::String> newSource, bool preview,
                       bool allow_top_frame_live_editing,
                       LiveEditResult* result) const;
  bool SetBreakpoint(v8::Local<v8::String> condition, debug::Location* location,
                     BreakpointId* id) const;
#if V8_ENABLE_WEBASSEMBLY
  bool IsWasm() const;
  void RemoveWasmBreakpoint(BreakpointId id);
#endif  // V8_ENABLE_WEBASSEMBLY
  bool SetInstrumentationBreakpoint(BreakpointId* id) const;
};

class DisassemblyCollector {
 public:
  virtual void ReserveLineCount(size_t count) = 0;
  virtual void AddLine(const char* src, size_t length,
                       uint32_t bytecode_offset) = 0;
};

#if V8_ENABLE_WEBASSEMBLY
// Specialization for wasm Scripts.
class WasmScript : public Script {
 public:
  static WasmScript* Cast(Script* script);

  struct DebugSymbols {
    enum class Type { SourceMap, EmbeddedDWARF, ExternalDWARF };
    Type type;
    v8::MemorySpan<const char> external_url;
  };
  std::vector<DebugSymbols> GetDebugSymbols() const;

  int NumFunctions() const;
  int NumImportedFunctions() const;

  std::pair<int, int> GetFunctionRange(int function_index) const;
  int GetContainingFunction(int byte_offset) const;

  void Disassemble(DisassemblyCollector* collector,
                   std::vector<int>* function_body_offsets);

  uint32_t GetFunctionHash(int function_index);

  int CodeOffset() const;
  int CodeLength() const;
};

// "Static" version of WasmScript::Disassemble, for use with cached scripts
// where we only have raw wire bytes available.
void Disassemble(base::Vector<const uint8_t> wire_bytes,
                 DisassemblyCollector* collector,
                 std::vector<int>* function_body_offsets);

#endif  // V8_ENABLE_WEBASSEMBLY

V8_EXPORT_PRIVATE void GetLoadedScripts(
    Isolate* isolate, std::vector<v8::Global<Script>>& scripts);

MaybeLocal<UnboundScript> CompileInspectorScript(Isolate* isolate,
                                                 Local<String> source);

enum ExceptionType { kException, kPromiseRejection };

class DebugDelegate {
 public:
  virtual ~DebugDelegate() = default;
  virtual void ScriptCompiled(v8::Local<Script> script, bool is_live_edited,
                              bool has_compile_error) {}
  // |inspector_break_points_hit| contains id of breakpoints installed with
  // debug::Script::SetBreakpoint API.
  virtual void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<debug::BreakpointId>& inspector_break_points_hit,
      base::EnumSet<BreakReason> break_reasons = {}) {}
  enum class ActionAfterInstrumentation {
    kPause,
    kPauseIfBreakpointsHit,
    kContinue
  };
  virtual ActionAfterInstrumentation BreakOnInstrumentation(
      v8::Local<v8::Context> paused_context,
      const debug::BreakpointId instrumentationId) {
    return ActionAfterInstrumentation::kPauseIfBreakpointsHit;
  }
  virtual void ExceptionThrown(v8::Local<v8::Context> paused_context,
                               v8::Local<v8::Value> exception,
                               v8::Local<v8::Value> promise, bool is_uncaught,
                               ExceptionType exception_type) {}
  virtual bool IsFunctionBlackboxed(v8::Local<debug::Script> script,
                                    const debug::Location& start,
                                    const debug::Location& end) {
    return false;
  }
  virtual bool ShouldBeSkipped(v8::Local<v8::debug::Script> script, int line,
                               int column) {
    return false;
  }

  // Called every time a breakpoint condition is evaluated. This method is
  // called before `BreakProgramRequested` if the condition is truthy.
  virtual void BreakpointConditionEvaluated(v8::Local<v8::Context> context,
                                            debug::BreakpointId breakpoint_id,
                                            bool exception_thrown,
                                            v8::Local<v8::Value> exception) {}
};

V8_EXPORT_PRIVATE void SetDebugDelegate(Isolate* isolate,
                                        DebugDelegate* listener);

#if V8_ENABLE_WEBASSEMBLY
V8_EXPORT_PRIVATE void EnterDebuggingForIsolate(Isolate* isolate);
V8_EXPORT_PRIVATE void LeaveDebuggingForIsolate(Isolate* isolate);
#endif  // V8_ENABLE_WEBASSEMBLY

class AsyncEventDelegate {
 public:
  virtual ~AsyncEventDelegate() = default;
  virtual void AsyncEventOccurred(debug::DebugAsyncActionType type, int id,
                                  bool is_blackboxed) = 0;
};

V8_EXPORT_PRIVATE void SetAsyncEventDelegate(Isolate* isolate,
                                             AsyncEventDelegate* delegate);

void ResetBlackboxedStateCache(Isolate* isolate,
                               v8::Local<debug::Script> script);

int EstimatedValueSize(Isolate* isolate, v8::Local<v8::Value> value);

enum Builtin { kStringToLowerCase };

Local<Function> GetBuiltin(Isolate* isolate, Builtin builtin);

V8_EXPORT_PRIVATE void SetConsoleDelegate(Isolate* isolate,
                                          ConsoleDelegate* delegate);

V8_EXPORT_PRIVATE v8::Local<v8::Message> CreateMessageFromException(
    Isolate* isolate, v8::Local<v8::Value> error);

/**
 * Native wrapper around v8::internal::JSGeneratorObject object.
 */
class GeneratorObject {
 public:
  v8::MaybeLocal<debug::Script> Script();
  v8::Local<v8::Function> Function();
  debug::Location SuspendedLocation();
  bool IsSuspended();

  static v8::Local<debug::GeneratorObject> Cast(v8::Local<v8::Value> value);
};

/*
 * Provide API layer between inspector and code coverage.
 */
class V8_EXPORT_PRIVATE Coverage {
 public:
  MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(Coverage);

  // Forward declarations.
  class ScriptData;
  class FunctionData;

  class V8_EXPORT_PRIVATE BlockData {
   public:
    MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(BlockData);

    int StartOffset() const;
    int EndOffset() const;
    uint32_t Count() const;

   private:
    explicit BlockData(i::CoverageBlock* block,
                       std::shared_ptr<i::Coverage> coverage)
        : block_(block), coverage_(std::move(coverage)) {}

    i::CoverageBlock* block_;
    std::shared_ptr<i::Coverage> coverage_;

    friend class v8::debug::Coverage::FunctionData;
  };

  class V8_EXPORT_PRIVATE FunctionData {
   public:
    MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(FunctionData);

    int StartOffset() const;
    int EndOffset() const;
    uint32_t Count() const;
    MaybeLocal<String> Name() const;
    size_t BlockCount() const;
    bool HasBlockCoverage() const;
    BlockData GetBlockData(size_t i) const;

   private:
    explicit FunctionData(i::CoverageFunction* function,
                          std::shared_ptr<i::Coverage> coverage)
        : function_(function), coverage_(std::move(coverage)) {}

    i::CoverageFunction* function_;
    std::shared_ptr<i::Coverage> coverage_;

    friend class v8::debug::Coverage::ScriptData;
  };

  class V8_EXPORT_PRIVATE ScriptData {
   public:
    MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(ScriptData);

    Local<debug::Script> GetScript() const;
    size_t FunctionCount() const;
    FunctionData GetFunctionData(size_t i) const;

   private:
    explicit ScriptData(size_t index, std::shared_ptr<i::Coverage> c);

    i::CoverageScript* script_;
    std::shared_ptr<i::Coverage> coverage_;

    friend class v8::debug::Coverage;
  };

  static Coverage CollectPrecise(Isolate* isolate);
  static Coverage CollectBestEffort(Isolate* isolate);

  static void SelectMode(Isolate* isolate, CoverageMode mode);

  size_t ScriptCount() const;
  ScriptData GetScriptData(size_t i) const;
  bool IsEmpty() const { return coverage_ == nullptr; }

 private:
  explicit Coverage(std::shared_ptr<i::Coverage> coverage)
      : coverage_(std::move(coverage)) {}
  std::shared_ptr<i::Coverage> coverage_;
};

class V8_EXPORT_PRIVATE ScopeIterator {
 public:
  static std::unique_ptr<ScopeIterator> CreateForFunction(
      v8::Isolate* isolate, v8::Local<v8::Function> func);
  static std::unique_ptr<ScopeIterator> CreateForGeneratorObject(
      v8::Isolate* isolate, v8::Local<v8::Object> generator);

  ScopeIterator() = default;
  virtual ~ScopeIterator() = default;
  ScopeIterator(const ScopeIterator&) = delete;
  ScopeIterator& operator=(const ScopeIterator&) = delete;

  enum ScopeType {
    ScopeTypeGlobal = 0,
    ScopeTypeLocal,
    ScopeTypeWith,
    ScopeTypeClosure,
    ScopeTypeCatch,
    ScopeTypeBlock,
    ScopeTypeScript,
    ScopeTypeEval,
    ScopeTypeModule,
    ScopeTypeWasmExpressionStack
  };

  virtual bool Done() = 0;
  virtual void Advance() = 0;
  virtual ScopeType GetType() = 0;
  virtual v8::Local<v8::Object> GetObject() = 0;
  virtual v8::Local<v8::Value> GetFunctionDebugName() = 0;
  virtual int GetScriptId() = 0;
  virtual bool HasLocationInfo() = 0;
  virtual debug::Location GetStartLocation() = 0;
  virtual debug::Location GetEndLocation() = 0;

  virtual bool SetVariableValue(v8::Local<v8::String> name,
                                v8::Local<v8::Value> value) = 0;
};

class V8_EXPORT_PRIVATE StackTraceIterator {
 public:
  static std::unique_ptr<StackTraceIterator> Create(Isolate* isolate,
                                                    int index = 0);
  StackTraceIterator() = default;
  virtual ~StackTraceIterator() = default;
  StackTraceIterator(const StackTraceIterator&) = delete;
  StackTraceIterator& operator=(const StackTraceIterator&) = delete;

  virtual bool Done() const = 0;
  virtual void Advance() = 0;

  virtual int GetContextId() const = 0;
  virtual v8::MaybeLocal<v8::Value> GetReceiver() const = 0;
  virtual v8::Local<v8::Value> GetReturnValue() const = 0;
  virtual v8::Local<v8::String> GetFunctionDebugName() const = 0;
  virtual v8::Local<v8::debug::Script> GetScript() const = 0;
  virtual debug::Location GetSourceLocation() const = 0;
  virtual debug::Location GetFunctionLocation() const = 0;
  virtual v8::Local<v8::Function> GetFunction() const = 0;
  virtual std::unique_ptr<ScopeIterator> GetScopeIterator() const = 0;
  virtual bool CanBeRestarted() const = 0;

  virtual v8::MaybeLocal<v8::Value> Evaluate(v8::Local<v8::String> source,
                                             bool throw_on_side_effect) = 0;
};

void GlobalLexicalScopeNames(v8::Local<v8::Context> context,
                             std::vector<v8::Global<v8::String>>* names);

void SetReturnValue(v8::Isolate* isolate, v8::Local<v8::Value> value);

enum class NativeAccessorType {
  None = 0,
  HasGetter = 1 << 0,
  HasSetter = 1 << 1,
  IsValueUnavailable = 1 << 2
};

int64_t GetNextRandomInt64(v8::Isolate* isolate);

MaybeLocal<Value> CallFunctionOn(Local<Context> context,
                                 Local<Function> function, Local<Value> recv,
                                 int argc, Global<Value> argv[],
                                 bool throw_on_side_effect);

enum class EvaluateGlobalMode {
  kDefault,
  kDisableBreaks,
  kDisableBreaksAndThrowOnSideEffect
};

V8_EXPORT_PRIVATE v8::MaybeLocal<v8::Value> EvaluateGlobal(
    v8::Isolate* isolate, v8::Local<v8::String> source, EvaluateGlobalMode mode,
    bool repl_mode = false);

int GetDebuggingId(v8::Local<v8::Function> function);

V8_EXPORT_PRIVATE bool SetFunctionBreakpoint(v8::Local<v8::Function> function,
                                             v8::Local<v8::String> condition,
                                             BreakpointId* id);

v8::Platform* GetCurrentPlatform();

void ForceGarbageCollection(v8::Isolate* isolate,
                            v8::StackState embedder_stack_state);

class V8_NODISCARD PostponeInterruptsScope {
 public:
  explicit PostponeInterruptsScope(v8::Isolate* isolate);
  ~PostponeInterruptsScope();

 private:
  std::unique_ptr<i::PostponeInterruptsScope> scope_;
};

class V8_NODISCARD DisableBreakScope {
 public:
  explicit DisableBreakScope(v8::Isolate* isolate);
  ~DisableBreakScope();

 private:
  std::unique_ptr<i::DisableBreak> scope_;
};

class EphemeronTable : public v8::Object {
 public:
  EphemeronTable() = delete;
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT v8::MaybeLocal<v8::Value> Get(
      v8::Isolate* isolate, v8::Local<v8::Value> key);
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT v8::Local<EphemeronTable> Set(
      v8::Isolate* isolate, v8::Local<v8::Value> key,
      v8::Local<v8::Value> value);

  V8_EXPORT_PRIVATE static Local<EphemeronTable> New(v8::Isolate* isolate);
  V8_INLINE static EphemeronTable* Cast(Value* obj);
};

/**
 * Pairs of accessors.
 *
 * In the case of private accessors, getters and setters are either null or
 * Functions.
 */
class V8_EXPORT_PRIVATE AccessorPair : public v8::Value {
 public:
  AccessorPair() = delete;
  v8::Local<v8::Value> getter();
  v8::Local<v8::Value> setter();

  static bool IsAccessorPair(v8::Local<v8::Value> obj);
  V8_INLINE static AccessorPair* Cast(v8::Value* obj);

 private:
  static void CheckCast(v8::Value* obj);
};

struct PropertyDescriptor {
  bool enumerable : 1;
  bool has_enumerable : 1;
  bool configurable : 1;
  bool has_configurable : 1;
  bool writable : 1;
  bool has_writable : 1;
  v8::Local<v8::Value> value;
  v8::Local<v8::Value> get;
  v8::Local<v8::Value> set;
};

class V8_EXPORT_PRIVATE PropertyIterator {
 public:
  // Creating a PropertyIterator can potentially throw an exception.
  // The returned std::unique_ptr is empty iff that happens.
  V8_WARN_UNUSED_RESULT static std::unique_ptr<PropertyIterator> Create(
      v8::Local<v8::Context> context, v8::Local<v8::Object> object,
      bool skip_indices = false);

  virtual ~PropertyIterator() = default;

  virtual bool Done() const = 0;
  // Returns |Nothing| should |Advance| throw an exception,
  // |true| otherwise.
  V8_WARN_UNUSED_RESULT virtual Maybe<bool> Advance() = 0;

  virtual v8::Local<v8::Name> name() const = 0;

  virtual bool is_native_accessor() = 0;
  virtual bool has_native_getter() = 0;
  virtual bool has_native_setter() = 0;
  virtual Maybe<PropertyAttribute> attributes() = 0;
  virtual Maybe<PropertyDescriptor> descriptor() = 0;

  virtual bool is_own() = 0;
  virtual bool is_array_index() = 0;
};

#if V8_ENABLE_WEBASSEMBLY
class V8_EXPORT_PRIVATE WasmValueObject : public v8::Object {
 public:
  WasmValueObject() = delete;
  static bool IsWasmValueObject(v8::Local<v8::Value> obj);
  static WasmValueObject* Cast(v8::Value* value) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(value);
#endif
    return static_cast<WasmValueObject*>(value);
  }

  v8::Local<v8::String> type() const;

 private:
  static void CheckCast(v8::Value* obj);
};
#endif  // V8_ENABLE_WEBASSEMBLY

AccessorPair* AccessorPair::Cast(v8::Value* value) {
#ifdef V8_ENABLE_CHECKS
  CheckCast(value);
#endif
  return static_cast<AccessorPair*>(value);
}

MaybeLocal<Message> GetMessageFromPromise(Local<Promise> promise);

void RecordAsyncStackTaggingCreateTaskCall(v8::Isolate* isolate);

void NotifyDebuggerPausedEventSent(v8::Isolate* isolate);

}  // namespace debug
}  // namespace v8

#endif  // V8_DEBUG_DEBUG_INTERFACE_H_
```