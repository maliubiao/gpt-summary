Response:
The user wants a summary of the functionality of the `v8/src/execution/isolate.h` header file in the V8 JavaScript engine. The summary should include:

1. **General Functionality:** A description of what this header file is responsible for.
2. **Torque Source:** Confirmation that it's not a Torque file based on the file extension.
3. **JavaScript Relationship:**  Explanation of how the contents relate to JavaScript execution, with JavaScript examples.
4. **Code Logic Inference:** Examples of input and output if the header contained code logic. (Since it's a header, this will likely be about the types and structures defined).
5. **Common Programming Errors:** Examples of common errors related to the concepts defined in the header.
6. **Overall Functionality Summary:** A concise summary of the header's role.

Let's break down the header content to address each point.

**1. General Functionality:**

The header file defines the `Isolate` class. Looking at the members and includes, the `Isolate` appears to be the central, independent execution environment for JavaScript code within V8. It manages:

*   Heap management (`heap/heap.h`)
*   Garbage collection
*   Compilation and execution (`execution/execution.h`)
*   Handles and object management (`handles/handles.h`)
*   Contexts (`objects/contexts.h`)
*   Built-in functions (`builtins/builtins.h`)
*   Debugging (`debug/interface-types.h`)
*   Error handling
*   Interactions with the embedder (the application hosting V8)

**2. Torque Source:**

The filename ends in `.h`, not `.tq`, so it's not a Torque source file.

**3. JavaScript Relationship:**

The `Isolate` is fundamental to how JavaScript runs. When you execute JavaScript code in V8, it happens within an `Isolate`. Key relationships:

*   **Contexts:**  JavaScript code runs within a context, which is managed by the `Isolate`.
*   **Heap:**  JavaScript objects are allocated on the `Isolate's` heap.
*   **Built-ins:**  The `Isolate` provides access to built-in JavaScript functions.
*   **Error Handling:**  JavaScript exceptions are managed by the `Isolate`.

**JavaScript Example:**

```javascript
// In a Node.js environment (which uses V8)
// or in a browser's JavaScript engine:

// Creating a new execution environment (implicitly, an Isolate is involved)
// This is handled by the engine, you don't directly create Isolates in JS.

let x = 10;
console.log(x); // Accessing variables within the current execution environment.

function add(a, b) {
  return a + b; // Executing JavaScript code.
}

add(5, 3);
```

**4. Code Logic Inference (Types and Structures):**

The header defines the structure of the `Isolate` class and related classes like `PerIsolateThreadData`.

*   **Input (Hypothetical):**  Creating a new `Isolate` object.
*   **Output (Inferred):**  An instance of the `Isolate` class is created, initializing its member variables (heap, string table, etc.).

*   **Input (Hypothetical):** Entering an `Isolate` on a thread.
*   **Output (Inferred):** A `PerIsolateThreadData` object is associated with the thread and the `Isolate`, storing thread-specific information like the stack limit and current context.

**5. Common Programming Errors:**

While you don't directly interact with the `Isolate` class in typical JavaScript development, understanding its role helps in understanding errors:

*   **"Out of memory" errors:**  Relate to the `Isolate's` heap management. If JavaScript code consumes too much memory, the `Isolate` will trigger an out-of-memory error.
*   **Stack overflow errors:** Related to the stack limit managed within the `PerIsolateThreadData`. Excessive recursion can exceed this limit.
*   **Incorrect assumptions about global state:**  Each `Isolate` has its own independent global state. Passing objects or data between different `Isolates` requires careful handling.

**6. Overall Functionality Summary:**

The `v8/src/execution/isolate.h` header file defines the `Isolate` class, which represents an isolated execution environment for JavaScript code in V8. It encapsulates all the necessary components for running JavaScript, including memory management, compilation, execution, and access to built-in functionality. It's a fundamental building block of the V8 engine.
好的，让我们来分析一下 `v8/src/execution/isolate.h` 这个 V8 源代码文件。

**1. 功能列举:**

`v8/src/execution/isolate.h` 文件定义了 V8 JavaScript 引擎中的 `Isolate` 类。`Isolate` 是 V8 中最核心的概念之一，它代表了一个独立的 JavaScript 执行环境。以下是其主要功能：

*   **独立的执行环境:**  `Isolate` 封装了执行 JavaScript 代码所需的所有资源，例如堆内存、垃圾回收器、编译器、内置函数等。不同的 `Isolate` 之间是完全隔离的，它们不会互相干扰。这允许多个独立的 JavaScript 虚拟机实例在同一个进程中共存。
*   **堆管理:** `Isolate` 负责管理其自身的堆内存，用于分配和回收 JavaScript 对象。它包含了 `Heap` 类的实例。
*   **上下文管理:** `Isolate` 管理着 JavaScript 代码执行的上下文 (`Context`)。一个 `Isolate` 可以包含多个 `Context`，每个 `Context` 拥有独立的全局对象。
*   **内置函数和对象:** `Isolate` 提供了访问内置 JavaScript 函数和对象的入口。
*   **错误处理:** `Isolate` 负责处理 JavaScript 代码执行期间发生的异常。
*   **编译和执行:** `Isolate` 协调 JavaScript 代码的编译（例如，通过 TurboFan 或 Ignition）和执行。
*   **句柄管理:** `Isolate` 管理着指向 JavaScript 堆对象的句柄 (`Handle`)，以确保对象在垃圾回收期间不会被意外回收。
*   **线程管理:** `Isolate` 提供了管理与该执行环境关联的线程的机制，例如 `PerIsolateThreadData` 用于存储线程本地数据。
*   **调试支持:** `Isolate` 包含了支持 JavaScript 代码调试的功能接口。
*   **性能分析:** `Isolate` 提供了性能分析和监控的接口，例如 CPU 分析器。
*   **快照支持:** `Isolate` 支持创建和加载快照，用于加速 V8 的启动过程。
*   **嵌入器集成:** `Isolate` 提供了与嵌入器（例如 Node.js 或 Chrome 浏览器）交互的接口。
*   **WebAssembly 支持:** `Isolate` 也集成了对 WebAssembly 的支持。
*   **国际化支持:**  通过条件编译 (`V8_INTL_SUPPORT`)，`Isolate` 可以支持国际化功能。

**2. 是否为 Torque 源代码:**

`v8/src/execution/isolate.h` 的文件名以 `.h` 结尾，而不是 `.tq`。因此，**它不是一个 V8 Torque 源代码文件**。它是一个 C++ 头文件。

**3. 与 JavaScript 的功能关系及 JavaScript 示例:**

`Isolate` 是 V8 引擎运行 JavaScript 代码的基础。当你执行 JavaScript 代码时，V8 引擎会在一个 `Isolate` 内部完成编译、执行和内存管理等操作。

**JavaScript 示例:**

虽然你不能直接在 JavaScript 代码中创建或操作 `Isolate` 对象，但你的 JavaScript 代码的运行都依赖于 `Isolate` 提供的环境。例如：

```javascript
// 全局变量和函数都存在于一个上下文中，而上下文属于一个 Isolate。
let myVariable = 10;

function myFunction() {
  console.log("Hello from Isolate!");
}

myFunction();

// 创建对象会在 Isolate 的堆上分配内存。
const myObject = { key: "value" };

// 异常处理机制由 Isolate 管理。
try {
  throw new Error("Something went wrong!");
} catch (e) {
  console.error(e.message);
}
```

在上述 JavaScript 代码的背后，V8 引擎使用 `Isolate` 来管理全局变量的存储、函数的执行、对象的创建和内存分配，以及异常的捕获和处理。

**4. 代码逻辑推理 (假设):**

由于 `v8/src/execution/isolate.h` 是一个头文件，它主要定义了类的结构和成员，不包含实际的代码逻辑实现。代码逻辑通常在对应的 `.cc` 文件中。

然而，我们可以根据头文件中的类型和成员来推断一些行为。

**假设输入：** 创建一个新的 `Isolate` 对象。

**推断输出：**

*   `Isolate` 对象的构造函数会被调用。
*   会初始化 `Isolate` 的各种成员变量，例如 `Heap` 实例、字符串表、各种锁等。
*   可能会分配一些初始的内存空间。

**假设输入：** 调用 `Isolate::Enter()` 方法。

**推断输出：**

*   当前线程会被标记为进入了该 `Isolate`。
*   可能会分配或关联一个 `PerIsolateThreadData` 对象，用于存储该线程在该 `Isolate` 中的本地数据。
*   可能会更新一些全局状态，指示当前正在执行的 `Isolate`。

**5. 涉及用户常见的编程错误:**

虽然开发者通常不直接操作 `Isolate`，但理解 `Isolate` 的概念有助于理解一些与 V8 相关的错误：

*   **内存泄漏:**  如果 JavaScript 代码中创建了大量不再使用的对象，但没有被垃圾回收器回收，就会导致内存泄漏。这与 `Isolate` 的堆管理有关。
*   **栈溢出:**  过深的函数调用栈会导致栈溢出错误。这与 `Isolate` 管理的执行栈有关。
*   **尝试在不同的 Isolate 之间共享对象而不进行适当处理:**  由于 `Isolate` 之间的隔离性，直接在不同的 `Isolate` 之间传递对象会导致错误。你需要使用特定的机制（例如，序列化和反序列化）来跨 `Isolate` 传递数据。
*   **误解全局状态:**  在多 `Isolate` 应用中，每个 `Isolate` 拥有独立的全局状态。开发者可能会错误地认为全局变量在所有 `Isolate` 之间共享。

**示例 (尝试在不同的 Isolate 之间共享对象):**

假设你有两个独立的 `Isolate`：`isolate1` 和 `isolate2`。

```c++
// 这是一个 C++ 示例，展示了 Isolate 的使用方式

#include "v8.h"

v8::Isolate* isolate1 = v8::Isolate::New();
v8::Isolate* isolate2 = v8::Isolate::New();

// ... 在 isolate1 中创建一个对象 ...
{
  v8::Isolate::Scope isolate_scope(isolate1);
  v8::HandleScope handle_scope(isolate1);
  v8::Local<v8::Context> context = v8::Context::New(isolate1);
  v8::Context::Scope context_scope(context);

  v8::Local<v8::Object> obj = v8::Object::New(isolate1);
  // ... 将数据添加到 obj ...

  // 尝试在 isolate2 中使用 obj (这是错误的)
  {
    v8::Isolate::Scope isolate_scope2(isolate2);
    v8::HandleScope handle_scope2(isolate2);
    v8::Local<v8::Context> context2 = v8::Context::New(isolate2);
    v8::Context::Scope context_scope2(context2);

    // 尝试在 isolate2 的上下文中访问属于 isolate1 的对象会导致错误。
    // v8::Local<v8::Value> value = obj->Get(context2, v8::String::NewFromUtf8Literal(isolate2, "key")).ToLocalChecked();
  }
}

v8::Isolate::Dispose(isolate1);
v8::Isolate::Dispose(isolate2);
```

直接尝试在 `isolate2` 中访问属于 `isolate1` 的对象会导致错误或未定义的行为。

**6. 功能归纳:**

总而言之，`v8/src/execution/isolate.h` 定义了 `Isolate` 类，它是 V8 JavaScript 引擎中一个**独立的、自包含的 JavaScript 执行环境**。`Isolate` 负责管理执行 JavaScript 代码所需的所有核心资源，包括堆内存、上下文、内置功能、错误处理、编译和执行流程。它是 V8 架构中实现隔离性和并发性的关键组件。理解 `Isolate` 的概念对于深入理解 V8 的工作原理至关重要。

Prompt: 
```
这是目录为v8/src/execution/isolate.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_EXECUTION_ISOLATE_H_
#define V8_EXECUTION_ISOLATE_H_

#include <atomic>
#include <cstddef>
#include <functional>
#include <list>
#include <memory>
#include <optional>
#include <queue>
#include <unordered_map>
#include <vector>

#include "include/v8-context.h"
#include "include/v8-internal.h"
#include "include/v8-isolate.h"
#include "include/v8-metrics.h"
#include "include/v8-snapshot.h"
#include "src/base/macros.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/platform-posix.h"
#include "src/builtins/builtins.h"
#include "src/common/globals.h"
#include "src/common/thread-local-storage.h"
#include "src/debug/interface-types.h"
#include "src/execution/execution.h"
#include "src/execution/futex-emulation.h"
#include "src/execution/isolate-data.h"
#include "src/execution/messages.h"
#include "src/execution/shared-mutex-guard-if-off-thread.h"
#include "src/execution/stack-guard.h"
#include "src/handles/handles.h"
#include "src/handles/traced-handles.h"
#include "src/heap/factory.h"
#include "src/heap/heap.h"
#include "src/heap/read-only-heap.h"
#include "src/init/isolate-group.h"
#include "src/objects/code.h"
#include "src/objects/contexts.h"
#include "src/objects/debug-objects.h"
#include "src/objects/js-objects.h"
#include "src/objects/tagged.h"
#include "src/runtime/runtime.h"
#include "src/sandbox/code-pointer-table.h"
#include "src/sandbox/external-pointer-table.h"
#include "src/sandbox/trusted-pointer-table.h"
#include "src/utils/allocation.h"

#ifdef DEBUG
#include "src/runtime/runtime-utils.h"
#endif

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/stacks.h"
#endif

#ifdef V8_INTL_SUPPORT
#include "unicode/uversion.h"  // Define U_ICU_NAMESPACE.
namespace U_ICU_NAMESPACE {
class UMemory;
}  // namespace U_ICU_NAMESPACE
#endif  // V8_INTL_SUPPORT

#if USE_SIMULATOR
#include "src/execution/encoded-c-signature.h"
namespace v8 {
namespace internal {
class SimulatorData;
}
}  // namespace v8
#endif

namespace v8_inspector {
class V8Inspector;
}  // namespace v8_inspector

namespace v8 {

class EmbedderState;

namespace base {
class RandomNumberGenerator;
}  // namespace base

namespace bigint {
class Processor;
}

namespace debug {
class ConsoleDelegate;
class AsyncEventDelegate;
}  // namespace debug

namespace internal {

void DefaultWasmAsyncResolvePromiseCallback(
    v8::Isolate* isolate, v8::Local<v8::Context> context,
    v8::Local<v8::Promise::Resolver> resolver,
    v8::Local<v8::Value> compilation_result, WasmAsyncSuccess success);

namespace heap {
class HeapTester;
}  // namespace heap

namespace maglev {
class MaglevConcurrentDispatcher;
}  // namespace maglev

class AddressToIndexHashMap;
class AstStringConstants;
class Bootstrapper;
class BuiltinsConstantsTableBuilder;
class CancelableTaskManager;
class Logger;
class CodeTracer;
class CommonFrame;
class CompilationCache;
class CompilationStatistics;
class Counters;
class Debug;
class Deoptimizer;
class DescriptorLookupCache;
class EmbeddedFileWriterInterface;
class EternalHandles;
class GlobalHandles;
class GlobalSafepoint;
class HandleScopeImplementer;
class HeapObjectToIndexHashMap;
class HeapProfiler;
class InnerPointerToCodeCache;
class LazyCompileDispatcher;
class LocalIsolate;
class V8FileLogger;
class MaterializedObjectStore;
class Microtask;
class MicrotaskQueue;
class OptimizingCompileDispatcher;
class PersistentHandles;
class PersistentHandlesList;
class ReadOnlyArtifacts;
class RegExpStack;
class RootVisitor;
class SetupIsolateDelegate;
class SharedStructTypeRegistry;
class Simulator;
class SnapshotData;
class StackFrame;
class StringForwardingTable;
class StringTable;
class StubCache;
class ThreadManager;
class ThreadState;
class ThreadVisitor;  // Defined in v8threads.h
class TieringManager;
class TracingCpuProfilerImpl;
class UnicodeCache;
struct ManagedPtrDestructor;

template <StateTag Tag>
class VMState;

namespace baseline {
class BaselineBatchCompiler;
}  // namespace baseline

namespace interpreter {
class Interpreter;
}  // namespace interpreter

namespace compiler {
class NodeObserver;
class PerIsolateCompilerCache;
namespace turboshaft {
class WasmRevecVerifier;
}  // namespace turboshaft
}  // namespace compiler

namespace win64_unwindinfo {
class BuiltinUnwindInfo;
}  // namespace win64_unwindinfo

namespace metrics {
class Recorder;
}  // namespace metrics

namespace wasm {

#if V8_ENABLE_DRUMBRAKE
class WasmExecutionTimer;
#endif  // V8_ENABLE_DRUMBRAKE
class WasmCodeLookupCache;
class WasmOrphanedGlobalHandle;
}

namespace detail {
class WaiterQueueNode;
}  // namespace detail

#define RETURN_FAILURE_IF_EXCEPTION(isolate)         \
  do {                                               \
    Isolate* __isolate__ = (isolate);                \
    if (__isolate__->has_exception()) {              \
      return ReadOnlyRoots(__isolate__).exception(); \
    }                                                \
  } while (false)

#define RETURN_FAILURE_IF_EXCEPTION_DETECTOR(isolate, detector) \
  do {                                                          \
    Isolate* __isolate__ = (isolate);                           \
    if (__isolate__->has_exception()) {                         \
      detector.AcceptSideEffects();                             \
      return ReadOnlyRoots(__isolate__).exception();            \
    }                                                           \
  } while (false)

// Macros for MaybeHandle.

#define RETURN_VALUE_IF_EXCEPTION(isolate, value) \
  do {                                            \
    Isolate* __isolate__ = (isolate);             \
    if (__isolate__->has_exception()) {           \
      return value;                               \
    }                                             \
  } while (false)

#define RETURN_VALUE_IF_EXCEPTION_DETECTOR(isolate, detector, value) \
  RETURN_VALUE_IF_EXCEPTION(isolate, (detector.AcceptSideEffects(), value))

#define RETURN_EXCEPTION_IF_EXCEPTION(isolate) \
  RETURN_VALUE_IF_EXCEPTION(isolate, kNullMaybeHandle)

#define MAYBE_RETURN_ON_EXCEPTION_VALUE(isolate, call, value) \
  do {                                                        \
    if ((call).IsNothing()) {                                 \
      DCHECK((isolate)->has_exception());                     \
      return value;                                           \
    }                                                         \
  } while (false)

/**
 * RETURN_RESULT_OR_FAILURE is used in functions with return type Object (such
 * as "RUNTIME_FUNCTION(...) {...}" or "BUILTIN(...) {...}" ) to return either
 * the contents of a MaybeHandle<X>, or the "exception" sentinel value.
 * Example usage:
 *
 * RUNTIME_FUNCTION(Runtime_Func) {
 *   ...
 *   RETURN_RESULT_OR_FAILURE(
 *       isolate,
 *       FunctionWithReturnTypeMaybeHandleX(...));
 * }
 *
 * If inside a function with return type MaybeHandle<X> use RETURN_ON_EXCEPTION
 * instead.
 * If inside a function with return type Handle<X>, or Maybe<X> use
 * RETURN_ON_EXCEPTION_VALUE instead.
 */
#define RETURN_RESULT_OR_FAILURE(isolate, call)      \
  do {                                               \
    DirectHandle<Object> __result__;                 \
    Isolate* __isolate__ = (isolate);                \
    if (!(call).ToHandle(&__result__)) {             \
      DCHECK(__isolate__->has_exception());          \
      return ReadOnlyRoots(__isolate__).exception(); \
    }                                                \
    DCHECK(!__isolate__->has_exception());           \
    return *__result__;                              \
  } while (false)

#define ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, dst, call, value) \
  do {                                                              \
    if (!(call).ToHandle(&dst)) {                                   \
      DCHECK((isolate)->has_exception());                           \
      return value;                                                 \
    }                                                               \
  } while (false)

#define ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, dst, call)                \
  do {                                                                        \
    auto* __isolate__ = (isolate);                                            \
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(__isolate__, dst, call,                  \
                                     ReadOnlyRoots(__isolate__).exception()); \
  } while (false)

#define ASSIGN_RETURN_ON_EXCEPTION(isolate, dst, call) \
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, dst, call, kNullMaybeHandle)

#define THROW_NEW_ERROR_RETURN_FAILURE(isolate, call)         \
  do {                                                        \
    auto* __isolate__ = (isolate);                            \
    return __isolate__->Throw(*__isolate__->factory()->call); \
  } while (false)

#define THROW_NEW_ERROR_RETURN_VALUE(isolate, call, value) \
  do {                                                     \
    auto* __isolate__ = (isolate);                         \
    __isolate__->Throw(*__isolate__->factory()->call);     \
    return value;                                          \
  } while (false)

#define THROW_NEW_ERROR(isolate, call) \
  THROW_NEW_ERROR_RETURN_VALUE(isolate, call, kNullMaybeHandle)

/**
 * RETURN_ON_EXCEPTION_VALUE conditionally returns the given value when the
 * given MaybeHandle is empty. It is typically used in functions with return
 * type Maybe<X> or Handle<X>. Example usage:
 *
 * Handle<X> Func() {
 *   ...
 *   RETURN_ON_EXCEPTION_VALUE(
 *       isolate,
 *       FunctionWithReturnTypeMaybeHandleX(...),
 *       Handle<X>());
 *   // code to handle non exception
 *   ...
 * }
 *
 * Maybe<bool> Func() {
 *   ..
 *   RETURN_ON_EXCEPTION_VALUE(
 *       isolate,
 *       FunctionWithReturnTypeMaybeHandleX(...),
 *       Nothing<bool>);
 *   // code to handle non exception
 *   return Just(true);
 * }
 *
 * If inside a function with return type MaybeHandle<X>, use RETURN_ON_EXCEPTION
 * instead.
 * If inside a function with return type Object, use
 * RETURN_FAILURE_ON_EXCEPTION instead.
 */
#define RETURN_ON_EXCEPTION_VALUE(isolate, call, value) \
  do {                                                  \
    if ((call).is_null()) {                             \
      DCHECK((isolate)->has_exception());               \
      return value;                                     \
    }                                                   \
  } while (false)

/**
 * RETURN_FAILURE_ON_EXCEPTION conditionally returns the "exception" sentinel if
 * the given MaybeHandle is empty; so it can only be used in functions with
 * return type Object, such as RUNTIME_FUNCTION(...) {...} or BUILTIN(...)
 * {...}. Example usage:
 *
 * RUNTIME_FUNCTION(Runtime_Func) {
 *   ...
 *   RETURN_FAILURE_ON_EXCEPTION(
 *       isolate,
 *       FunctionWithReturnTypeMaybeHandleX(...));
 *   // code to handle non exception
 *   ...
 * }
 *
 * If inside a function with return type MaybeHandle<X>, use RETURN_ON_EXCEPTION
 * instead.
 * If inside a function with return type Maybe<X> or Handle<X>, use
 * RETURN_ON_EXCEPTION_VALUE instead.
 */
#define RETURN_FAILURE_ON_EXCEPTION(isolate, call)                     \
  do {                                                                 \
    Isolate* __isolate__ = (isolate);                                  \
    RETURN_ON_EXCEPTION_VALUE(__isolate__, call,                       \
                              ReadOnlyRoots(__isolate__).exception()); \
  } while (false);

/**
 * RETURN_ON_EXCEPTION conditionally returns an empty MaybeHandle<T> if the
 * given MaybeHandle is empty. Use it to return immediately from a function with
 * return type MaybeHandle when an exception was thrown. Example usage:
 *
 * MaybeHandle<X> Func() {
 *   ...
 *   RETURN_ON_EXCEPTION(
 *       isolate,
 *       FunctionWithReturnTypeMaybeHandleY(...),
 *       X);
 *   // code to handle non exception
 *   ...
 * }
 *
 * If inside a function with return type Object, use
 * RETURN_FAILURE_ON_EXCEPTION instead.
 * If inside a function with return type
 * Maybe<X> or Handle<X>, use RETURN_ON_EXCEPTION_VALUE instead.
 */
#define RETURN_ON_EXCEPTION(isolate, call) \
  RETURN_ON_EXCEPTION_VALUE(isolate, call, kNullMaybeHandle)

#define RETURN_FAILURE(isolate, should_throw, call) \
  do {                                              \
    if ((should_throw) == kDontThrow) {             \
      return Just(false);                           \
    } else {                                        \
      isolate->Throw(*isolate->factory()->call);    \
      return Nothing<bool>();                       \
    }                                               \
  } while (false)

#define MAYBE_RETURN(call, value)         \
  do {                                    \
    if ((call).IsNothing()) return value; \
  } while (false)

#define MAYBE_RETURN_NULL(call) MAYBE_RETURN(call, kNullMaybeHandle)

#define API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, dst, call, value) \
  do {                                                                  \
    if (!(call).ToLocal(&dst)) {                                        \
      DCHECK((isolate)->has_exception());                               \
      return value;                                                     \
    }                                                                   \
  } while (false)

#define MAYBE_RETURN_ON_EXCEPTION_VALUE(isolate, call, value) \
  do {                                                        \
    if ((call).IsNothing()) {                                 \
      DCHECK((isolate)->has_exception());                     \
      return value;                                           \
    }                                                         \
  } while (false)

#define MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, dst, call, value) \
  do {                                                                    \
    if (!(call).To(&dst)) {                                               \
      DCHECK((isolate)->has_exception());                                 \
      return value;                                                       \
    }                                                                     \
  } while (false)

#define MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, dst, call) \
  do {                                                               \
    Isolate* __isolate__ = (isolate);                                \
    if (!(call).To(&dst)) {                                          \
      DCHECK(__isolate__->has_exception());                          \
      return ReadOnlyRoots(__isolate__).exception();                 \
    }                                                                \
  } while (false)

#define FOR_WITH_HANDLE_SCOPE(isolate, loop_var_type, init, loop_var,      \
                              limit_check, increment, body)                \
  do {                                                                     \
    loop_var_type init;                                                    \
    loop_var_type for_with_handle_limit = loop_var;                        \
    Isolate* for_with_handle_isolate = isolate;                            \
    while (limit_check) {                                                  \
      for_with_handle_limit += 1024;                                       \
      HandleScope loop_scope(for_with_handle_isolate);                     \
      for (; limit_check && loop_var < for_with_handle_limit; increment) { \
        body                                                               \
      }                                                                    \
    }                                                                      \
  } while (false)

#define WHILE_WITH_HANDLE_SCOPE(isolate, limit_check, body)                  \
  do {                                                                       \
    Isolate* for_with_handle_isolate = isolate;                              \
    while (limit_check) {                                                    \
      HandleScope loop_scope(for_with_handle_isolate);                       \
      for (int for_with_handle_it = 0;                                       \
           limit_check && for_with_handle_it < 1024; ++for_with_handle_it) { \
        body                                                                 \
      }                                                                      \
    }                                                                        \
  } while (false)

#define FIELD_ACCESSOR(type, name)                \
  inline void set_##name(type v) { name##_ = v; } \
  inline type name() const { return name##_; }

// Controls for manual embedded blob lifecycle management, used by tests and
// mksnapshot.
V8_EXPORT_PRIVATE void DisableEmbeddedBlobRefcounting();
V8_EXPORT_PRIVATE void FreeCurrentEmbeddedBlob();

#ifdef DEBUG

#define ISOLATE_INIT_DEBUG_ARRAY_LIST(V)               \
  V(int, code_kind_statistics, kCodeKindCount)
#else

#define ISOLATE_INIT_DEBUG_ARRAY_LIST(V)

#endif

#define ISOLATE_INIT_ARRAY_LIST(V)                                             \
  /* SerializerDeserializer state. */                                          \
  V(int32_t, jsregexp_static_offsets_vector, kJSRegexpStaticOffsetsVectorSize) \
  V(int, bad_char_shift_table, kUC16AlphabetSize)                              \
  V(int, good_suffix_shift_table, (kBMMaxShift + 1))                           \
  V(int, suffix_table, (kBMMaxShift + 1))                                      \
  ISOLATE_INIT_DEBUG_ARRAY_LIST(V)

using DebugObjectCache = std::vector<Handle<HeapObject>>;

#define ISOLATE_INIT_LIST(V)                                                  \
  /* Assembler state. */                                                      \
  V(FatalErrorCallback, exception_behavior, nullptr)                          \
  V(OOMErrorCallback, oom_behavior, nullptr)                                  \
  V(LogEventCallback, event_logger, nullptr)                                  \
  V(ModifyCodeGenerationFromStringsCallback2, modify_code_gen_callback,       \
    nullptr)                                                                  \
  V(AllowWasmCodeGenerationCallback, allow_wasm_code_gen_callback, nullptr)   \
  V(ExtensionCallback, wasm_module_callback, &NoExtension)                    \
  V(ExtensionCallback, wasm_instance_callback, &NoExtension)                  \
  V(SharedArrayBufferConstructorEnabledCallback,                              \
    sharedarraybuffer_constructor_enabled_callback, nullptr)                  \
  V(WasmStreamingCallback, wasm_streaming_callback, nullptr)                  \
  V(WasmAsyncResolvePromiseCallback, wasm_async_resolve_promise_callback,     \
    DefaultWasmAsyncResolvePromiseCallback)                                   \
  V(WasmLoadSourceMapCallback, wasm_load_source_map_callback, nullptr)        \
  V(WasmImportedStringsEnabledCallback,                                       \
    wasm_imported_strings_enabled_callback, nullptr)                          \
  V(JavaScriptCompileHintsMagicEnabledCallback,                               \
    compile_hints_magic_enabled_callback, nullptr)                            \
  V(WasmJSPIEnabledCallback, wasm_jspi_enabled_callback, nullptr)             \
  /* State for Relocatable. */                                                \
  V(Relocatable*, relocatable_top, nullptr)                                   \
  V(DebugObjectCache*, string_stream_debug_object_cache, nullptr)             \
  V(Tagged<Object>, string_stream_current_security_token, Tagged<Object>())   \
  V(const intptr_t*, api_external_references, nullptr)                        \
  V(AddressToIndexHashMap*, external_reference_map, nullptr)                  \
  V(HeapObjectToIndexHashMap*, root_index_map, nullptr)                       \
  V(MicrotaskQueue*, default_microtask_queue, nullptr)                        \
  V(CodeTracer*, code_tracer, nullptr)                                        \
  V(PromiseRejectCallback, promise_reject_callback, nullptr)                  \
  V(ExceptionPropagationCallback, exception_propagation_callback, nullptr)    \
  V(const v8::StartupData*, snapshot_blob, nullptr)                           \
  V(int, code_and_metadata_size, 0)                                           \
  V(int, bytecode_and_metadata_size, 0)                                       \
  V(int, external_script_source_size, 0)                                      \
  /* Number of CPU profilers running on the isolate. */                       \
  V(size_t, num_cpu_profilers, 0)                                             \
  /* true if a trace is being formatted through Error.prepareStackTrace. */   \
  V(bool, formatting_stack_trace, false)                                      \
  V(bool, disable_bytecode_flushing, false)                                   \
  V(int, last_console_context_id, 0)                                          \
  V(v8_inspector::V8Inspector*, inspector, nullptr)                           \
  V(int, embedder_wrapper_type_index, -1)                                     \
  V(int, embedder_wrapper_object_index, -1)                                   \
  V(compiler::NodeObserver*, node_observer, nullptr)                          \
  V(bool, javascript_execution_assert, true)                                  \
  V(bool, javascript_execution_throws, true)                                  \
  V(bool, javascript_execution_dump, true)                                    \
  V(uint32_t, javascript_execution_counter, 0)                                \
  V(bool, deoptimization_assert, true)                                        \
  V(bool, compilation_assert, true)                                           \
  V(bool, no_exception_assert, true)                                          \
  V(uint32_t, wasm_switch_to_the_central_stack_counter, 0)

#define THREAD_LOCAL_TOP_ACCESSOR(type, name)                         \
  inline void set_##name(type v) { thread_local_top()->name##_ = v; } \
  inline type name() const { return thread_local_top()->name##_; }

#define THREAD_LOCAL_TOP_ADDRESS(type, name) \
  inline type* name##_address() { return &thread_local_top()->name##_; }

// Do not use this variable directly, use Isolate::Current() instead.
// Defined outside of Isolate because Isolate uses V8_EXPORT_PRIVATE.
__attribute__((tls_model(V8_TLS_MODEL))) extern thread_local Isolate*
    g_current_isolate_ V8_CONSTINIT;

// HiddenFactory exists so Isolate can privately inherit from it without making
// Factory's members available to Isolate directly.
class V8_EXPORT_PRIVATE HiddenFactory : private Factory {};

class V8_EXPORT_PRIVATE Isolate final : private HiddenFactory {
  // These forward declarations are required to make the friend declarations in
  // PerIsolateThreadData work on some older versions of gcc.
  class ThreadDataTable;
  class EntryStackItem;

 public:
  Isolate(const Isolate&) = delete;
  Isolate& operator=(const Isolate&) = delete;

  using HandleScopeType = HandleScope;
  void* operator new(size_t) = delete;
  void operator delete(void*) = delete;

  // A thread has a PerIsolateThreadData instance for each isolate that it has
  // entered. That instance is allocated when the isolate is initially entered
  // and reused on subsequent entries.
  class PerIsolateThreadData {
   public:
    PerIsolateThreadData(Isolate* isolate, ThreadId thread_id)
        : isolate_(isolate),
          thread_id_(thread_id),
          stack_limit_(0),
          thread_state_(nullptr)
#if USE_SIMULATOR
          ,
          simulator_(nullptr)
#endif
    {
    }
    ~PerIsolateThreadData();
    PerIsolateThreadData(const PerIsolateThreadData&) = delete;
    PerIsolateThreadData& operator=(const PerIsolateThreadData&) = delete;
    Isolate* isolate() const { return isolate_; }
    ThreadId thread_id() const { return thread_id_; }

    FIELD_ACCESSOR(uintptr_t, stack_limit)
    FIELD_ACCESSOR(ThreadState*, thread_state)
#if USE_SIMULATOR
    FIELD_ACCESSOR(Simulator*, simulator)
#endif

    bool Matches(Isolate* isolate, ThreadId thread_id) const {
      return isolate_ == isolate && thread_id_ == thread_id;
    }

   private:
    Isolate* isolate_;
    ThreadId thread_id_;
    uintptr_t stack_limit_;
    ThreadState* thread_state_;

#if USE_SIMULATOR
    Simulator* simulator_;
#endif

    friend class Isolate;
    friend class ThreadDataTable;
    friend class EntryStackItem;
  };

  // Used for walking the promise tree for catch prediction.
  struct PromiseHandler {
    Tagged<SharedFunctionInfo> function_info;
    bool async;
  };

  static void InitializeOncePerProcess();

  // Creates Isolate object. Must be used instead of constructing Isolate with
  // new operator.
  static Isolate* New();
  static Isolate* New(IsolateGroup* isolate_group);

  // Deletes Isolate object. Must be used instead of delete operator.
  // Destroys the non-default isolates.
  // Sets default isolate into "has_been_disposed" state rather then destroying,
  // for legacy API reasons.
  static void Delete(Isolate* isolate);

  void SetUpFromReadOnlyArtifacts(ReadOnlyArtifacts* artifacts,
                                  ReadOnlyHeap* ro_heap);
  void set_read_only_heap(ReadOnlyHeap* ro_heap) { read_only_heap_ = ro_heap; }

  // Page allocator that must be used for allocating V8 heap pages.
  v8::PageAllocator* page_allocator() const;

  // Returns the PerIsolateThreadData for the current thread (or nullptr if one
  // is not currently set).
  V8_INLINE static PerIsolateThreadData* CurrentPerIsolateThreadData();

  // Returns the isolate inside which the current thread is running or nullptr.
  V8_TLS_DECLARE_GETTER(TryGetCurrent, Isolate*, g_current_isolate_)

  // Returns the isolate inside which the current thread is running.
  V8_INLINE static Isolate* Current();
  static void SetCurrent(Isolate* isolate);

  inline bool IsCurrent() const;

  // Usually called by Init(), but can be called early e.g. to allow
  // testing components that require logging but not the whole
  // isolate.
  //
  // Safe to call more than once.
  void InitializeLoggingAndCounters();
  bool InitializeCounters();  // Returns false if already initialized.

  bool InitWithoutSnapshot();
  bool InitWithSnapshot(SnapshotData* startup_snapshot_data,
                        SnapshotData* read_only_snapshot_data,
                        SnapshotData* shared_heap_snapshot_data,
                        bool can_rehash);

  // True if at least one thread Enter'ed this isolate.
  bool IsInUse() { return entry_stack_ != nullptr; }

  void ReleaseSharedPtrs();

  void ClearSerializerData();

  void UpdateLogObjectRelocation();

  // Initializes the current thread to run this Isolate.
  // Not thread-safe. Multiple threads should not Enter/Exit the same isolate
  // at the same time, this should be prevented using external locking.
  void Enter();

  // Exits the current thread. The previously entered Isolate is restored
  // for the thread.
  // Not thread-safe. Multiple threads should not Enter/Exit the same isolate
  // at the same time, this should be prevented using external locking.
  void Exit();

  // Find the PerThread for this particular (isolate, thread) combination.
  // If one does not yet exist, allocate a new one.
  PerIsolateThreadData* FindOrAllocatePerThreadDataForThisThread();

  // Find the PerThread for this particular (isolate, thread) combination
  // If one does not yet exist, return null.
  PerIsolateThreadData* FindPerThreadDataForThisThread();

  // Find the PerThread for given (isolate, thread) combination
  // If one does not yet exist, return null.
  PerIsolateThreadData* FindPerThreadDataForThread(ThreadId thread_id);

  // Discard the PerThread for this particular (isolate, thread) combination
  // If one does not yet exist, no-op.
  void DiscardPerThreadDataForThisThread();

  // Mutex for serializing access to break control structures.
  base::RecursiveMutex* break_access() { return &break_access_; }

  // Shared mutex for allowing thread-safe concurrent reads of FeedbackVectors.
  base::SharedMutex* feedback_vector_access() {
    return &feedback_vector_access_;
  }

  // Shared mutex for allowing thread-safe concurrent reads of
  // InternalizedStrings.
  base::SharedMutex* internalized_string_access() {
    return &internalized_string_access_;
  }

  // Shared mutex for allowing thread-safe concurrent reads of TransitionArrays
  // of kind kFullTransitionArray.
  base::SharedMutex* full_transition_array_access() {
    return &full_transition_array_access_;
  }

  // Shared mutex for allowing thread-safe concurrent reads of
  // SharedFunctionInfos.
  base::SharedMutex* shared_function_info_access() {
    return &shared_function_info_access_;
  }

  // Protects (most) map update operations, see also MapUpdater.
  base::SharedMutex* map_updater_access() { return &map_updater_access_; }

  // Protects JSObject boilerplate migrations (i.e. calls to MigrateInstance on
  // boilerplate objects; elements kind transitions are *not* protected).
  // Note this lock interacts with `map_updater_access` as follows
  //
  // - boilerplate migrations may trigger map updates.
  // - if so, `boilerplate_migration_access` is locked before
  //   `map_updater_access`.
  // - backgrounds threads must use the same lock order to avoid deadlocks.
  base::SharedMutex* boilerplate_migration_access() {
    return &boilerplate_migration_access_;
  }

  ReadOnlyArtifacts* read_only_artifacts() const {
    ReadOnlyArtifacts* artifacts = isolate_group()->read_only_artifacts();
    DCHECK_IMPLIES(ReadOnlyHeap::IsReadOnlySpaceShared(), artifacts != nullptr);
    return artifacts;
  }

  // The isolate's string table.
  StringTable* string_table() const {
    return OwnsStringTables() ? string_table_.get()
                              : shared_space_isolate()->string_table_.get();
  }
  StringForwardingTable* string_forwarding_table() const {
    return OwnsStringTables()
               ? string_forwarding_table_.get()
               : shared_space_isolate()->string_forwarding_table_.get();
  }

  SharedStructTypeRegistry* shared_struct_type_registry() const {
    return is_shared_space_isolate()
               ? shared_struct_type_registry_.get()
               : shared_space_isolate()->shared_struct_type_registry_.get();
  }

  Address get_address_from_id(IsolateAddressId id);

  // Access to top context (where the current function object was created).
  Tagged<Context> context() const { return thread_local_top()->context_; }
  inline void set_context(Tagged<Context> context);
  Tagged<Context>* context_address() { return &thread_local_top()->context_; }

  // The "topmost script-having execution context" from the Web IDL spec
  // (i.e. the context of the topmost user JavaScript code, see
  // https://html.spec.whatwg.org/multipage/webappapis.html#topmost-script-having-execution-context)
  // if known or Context::kNoContext otherwise.
  Tagged<Context> topmost_script_having_context() const {
    return thread_local_top()->topmost_script_having_context_;
  }
  inline void set_topmost_script_having_context(Tagged<Context> context);
  inline void clear_topmost_script_having_context();
  Tagged<Context>* topmost_script_having_context_address() {
    return &thread_local_top()->topmost_script_having_context_;
  }

  // Access to current thread id.
  inline void set_thread_id(ThreadId id) {
    thread_local_top()->thread_id_.store(id, std::memory_order_relaxed);
  }
  inline ThreadId thread_id() const {
    return thread_local_top()->thread_id_.load(std::memory_order_relaxed);
  }

  void InstallConditionalFeatures(Handle<NativeContext> context);

#if V8_ENABLE_WEBASSEMBLY
  void WasmInitJSPIFeature();
#endif

  bool IsSharedArrayBufferConstructorEnabled(Handle<NativeContext> context);

  bool IsWasmStringRefEnabled(Handle<NativeContext> context);
  bool IsWasmImportedStringsEnabled(Handle<NativeContext> context);
  // Has the JSPI flag been requested?
  // Used only during initialization of contexts.
  bool IsWasmJSPIRequested(Handle<NativeContext> context);
  // Has JSPI been enabled successfully?
  bool IsWasmJSPIEnabled(Handle<NativeContext> context);
  bool IsCompileHintsMagicEnabled(Handle<NativeContext> context);

  THREAD_LOCAL_TOP_ADDRESS(Tagged<Context>, pending_handler_context)
  THREAD_LOCAL_TOP_ADDRESS(Address, pending_handler_en
"""


```