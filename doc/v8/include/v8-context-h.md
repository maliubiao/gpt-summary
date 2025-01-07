Response:
Let's break down the thought process for analyzing this V8 header file.

1. **Identify the Core Purpose:** The filename `v8-context.h` and the class name `Context` immediately suggest this file is about managing execution contexts within the V8 JavaScript engine.

2. **Scan for Key Classes/Structs:** Look for defined classes and structs. This reveals `ExtensionConfiguration`, `Context`, `DeepFreezeDelegate`, and `Scope`/`BackupIncumbentScope`. These are the main building blocks the file defines.

3. **Analyze Each Class/Struct (Method by Method):**

   * **`ExtensionConfiguration`:**  Simple struct. The constructor and `begin`/`end` methods clearly indicate it's used for passing a list of extension names.

   * **`Context` (The Big One):** This is where the bulk of the functionality resides. Go through each public method and try to understand its purpose based on its name and parameters. Look for patterns and groupings of related methods.

     * **Global Object Related:** `Global()`, `DetachGlobal()`. These strongly suggest managing the global object of a context.

     * **Context Creation:** `New()`, `FromSnapshot()`, `NewRemoteContext()`. These are the different ways to create a `Context`. Note the variations in parameters (extensions, templates, snapshots).

     * **Security:** `SetSecurityToken()`, `UseDefaultSecurityToken()`, `GetSecurityToken()`. This clearly relates to security boundaries between contexts.

     * **Execution Control:** `Enter()`, `Exit()`. Fundamental for switching between execution contexts.

     * **Deep Freezing:** `DeepFreeze()`, `DeepFreezeDelegate`. This is a more advanced feature for ensuring immutability.

     * **Embedder Data:** `GetNumberOfEmbedderDataFields()`, `GetEmbedderData()`, `SetEmbedderData()`, `GetAlignedPointerFromEmbedderData()`, `SetAlignedPointerInEmbedderData()`. These are for embedding host-specific data within the V8 context.

     * **Code Generation Control:** `AllowCodeGenerationFromStrings()`, `IsCodeGenerationFromStringsAllowed()`, `SetErrorMessageForCodeGenerationFromStrings()`, `SetErrorMessageForWasmCodeGeneration()`. Relates to security and feature control.

     * **Snapshot Data:** `GetDataFromSnapshotOnce()`. Allows retrieval of data saved during snapshot creation.

     * **Script Abort:** `SetAbortScriptExecution()`. A way to interrupt script execution.

     * **Promise Hooks:** `SetPromiseHooks()`. For observing promise lifecycle events.

     * **Template Literal Tracking:** `HasTemplateLiteralObject()`. A specialized internal check.

     * **Scoping Helpers:** `Scope`, `BackupIncumbentScope`. RAII-style helpers for managing context entry/exit and backup incumbent settings.

     * **Casting:** `Cast()`. A utility for safely casting `Data*` to `Context*`.

   * **`DeepFreezeDelegate`:** An interface for customizing the deep freeze process for embedder-specific objects.

   * **`Scope`:**  A simple RAII class for ensuring `Enter()` and `Exit()` are called correctly.

   * **`BackupIncumbentScope`:**  More complex scope for managing the backup incumbent settings object stack.

4. **Identify Relationships and Dependencies:** Notice how `Context` uses `ExtensionConfiguration`, `ObjectTemplate`, `Value`, etc. These indicate how the `Context` interacts with other V8 components.

5. **Consider Edge Cases and Advanced Features:**  Things like snapshots, security tokens, and deep freezing are not basic JavaScript concepts. Recognizing these points to more advanced uses of the V8 API.

6. **Connect to JavaScript Concepts (Where Applicable):**  Think about how these C++ concepts relate to JavaScript. For example, a V8 `Context` is analogous to a JavaScript global environment. `eval()` and `Function()` relate to code generation from strings. Promises have a well-defined lifecycle.

7. **Look for Potential Pitfalls:**  Methods like `Enter()`/`Exit()` require careful management. Misusing embedder data or security tokens can lead to errors. Trying to deep freeze objects that can't be frozen will throw exceptions.

8. **Address the Specific Prompts:**  Go back to the original request and ensure each part is addressed:

   * **Functionality Listing:** Summarize the purpose of each class and its methods.
   * **Torque:** Check the file extension. Since it's `.h`, it's a C++ header, not Torque.
   * **JavaScript Relationship and Examples:** Provide concrete JavaScript examples that demonstrate the concepts behind the C++ API (e.g., creating different global scopes, using `eval`).
   * **Code Logic and Assumptions:** For methods with more complex logic (like `New` and `FromSnapshot`), explain the assumptions and how different input parameters affect the output.
   * **Common Programming Errors:**  Point out typical mistakes developers might make when using the API (e.g., forgetting to exit a context, mishandling security tokens).

9. **Refine and Organize:**  Structure the analysis logically with clear headings and bullet points. Ensure the language is clear and concise. Provide code examples in the correct format.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is `Data` a base class?" (Yes, indicated by `public Data`). This helps understand the inheritance hierarchy.
* **Realization:** The various overloads of `New` and `FromSnapshot` cater to different scenarios of context creation.
* **Clarification:** The explanation of the global proxy object needs to highlight the security implications.
* **Emphasis:**  The importance of matching deserialization callbacks during snapshot creation should be stressed.
* **Accuracy:** Double-check the names of JavaScript functions and their behavior.

By following this structured approach, combining a top-down overview with a detailed analysis of individual components, it's possible to gain a comprehensive understanding of a complex header file like `v8-context.h`.
这是一个 V8 引擎的头文件 `v8/include/v8-context.h`，它定义了 `v8::Context` 类以及相关的辅助类和枚举。`v8::Context` 类代表了 V8 引擎中的一个独立的执行上下文，它拥有自己的一套内置对象和函数。

**v8/include/v8-context.h 的功能列表：**

1. **定义执行上下文 (Execution Context):**
   - `v8::Context` 类是 V8 中表示一个沙箱化的 JavaScript 执行环境的核心类。
   - 每个 Context 都有自己的全局对象、内置对象（如 `Object`, `Array` 等）和函数。
   - 不同的 Context 之间是隔离的，在一个 Context 中运行的代码无法直接访问另一个 Context 的内容，除非它们共享相同的安全令牌。

2. **创建和管理 Context:**
   - `Context::New()`: 静态方法，用于创建一个新的 Context 实例。可以指定扩展、全局对象模板、预先存在的全局对象、反序列化回调以及微任务队列。
   - `Context::FromSnapshot()`: 静态方法，用于从快照中创建一个新的 Context。
   - `Context::NewRemoteContext()`: 静态方法，创建一个不与实际上下文关联的全局对象，通常用于需要访问检查的场景。

3. **全局对象访问和管理:**
   - `Global()`: 返回 Context 的全局代理对象。这是一个指向实际全局对象的薄包装器，出于安全考虑而存在。
   - `DetachGlobal()`: 将全局对象从其 Context 中分离，以便可以复用该全局对象来创建新的 Context。

4. **安全控制:**
   - `SetSecurityToken()`: 设置 Context 的安全令牌。只有具有相同安全令牌的 Context 才能互相访问对象。
   - `UseDefaultSecurityToken()`: 将安全令牌恢复为默认值。
   - `GetSecurityToken()`: 获取 Context 的安全令牌。

5. **上下文切换:**
   - `Enter()`: 进入当前 Context。进入后，所有编译和运行的代码都会在这个 Context 中执行。
   - `Exit()`: 退出当前 Context，恢复进入当前 Context 之前的 Context。

6. **深度冻结对象:**
   - `DeepFreeze()`: 尝试递归地冻结从当前 Context 可达的所有对象。某些类型的对象（如生成器、迭代器）无法冻结。
   - `DeepFreezeDelegate`: 辅助类，用于处理嵌入器特定的对象冻结。

7. **获取关联信息:**
   - `GetIsolate()`: 返回与当前 Context 关联的 Isolate 实例。
   - `GetMicrotaskQueue()`: 返回与当前 Context 关联的微任务队列。
   - `SetMicrotaskQueue()`: 设置与当前 Context 关联的微任务队列。

8. **嵌入器数据 (Embedder Data):**
   - `GetNumberOfEmbedderDataFields()`: 返回为嵌入器数据分配的字段数量。
   - `GetEmbedderData()`: 获取指定索引的嵌入器数据。
   - `SetEmbedderData()`: 设置指定索引的嵌入器数据。
   - `GetAlignedPointerFromEmbedderData()`: 获取指定索引的 2 字节对齐的本地指针嵌入器数据。
   - `SetAlignedPointerInEmbedderData()`: 设置指定索引的 2 字节对齐的本地指针嵌入器数据。

9. **控制代码生成:**
   - `AllowCodeGenerationFromStrings()`: 控制是否允许从字符串生成代码（例如 `eval()` 和 `Function` 构造函数）。
   - `IsCodeGenerationFromStringsAllowed()`: 返回当前 Context 是否允许从字符串生成代码。
   - `SetErrorMessageForCodeGenerationFromStrings()`: 设置当不允许从字符串生成代码时抛出的异常错误信息。
   - `SetErrorMessageForWasmCodeGeneration()`: 设置当不允许 WebAssembly 代码生成时抛出的异常错误信息。

10. **从快照获取数据:**
    - `GetDataFromSnapshotOnce()`: 返回之前通过 `SnapshotCreator` 附加到上下文快照的数据，并移除对其的引用。

11. **中止脚本执行:**
    - `SetAbortScriptExecution()`: 设置一个回调函数，用于在尝试执行 JavaScript 时中止执行并抛出异常。

12. **Promise Hooks:**
    - `SetPromiseHooks()`: 设置用于监听 Promise 生命周期操作的回调函数。

13. **模板字面量对象跟踪:**
    - `HasTemplateLiteralObject()`: 检查给定的 Value 是否是模板字面量对象。

14. **作用域管理:**
    - `Scope`: 一个栈分配的类，用于设置在局部作用域内执行的所有操作的执行上下文，确保 `Enter()` 和 `Exit()` 成对调用。
    - `BackupIncumbentScope`: 用于支持备份当前设置对象栈的栈分配类。

15. **辅助类:**
    - `ExtensionConfiguration`: 用于存储扩展名称的容器。

**关于 .tq 结尾：**

如果 `v8/include/v8-context.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 使用的一种领域特定语言，用于生成高效的运行时代码。但是，根据您提供的文件名，它是 `.h` 结尾，所以它是一个 C++ 头文件。

**与 JavaScript 的关系和示例：**

`v8::Context` 直接对应于 JavaScript 中的全局执行环境。每个 iframe、每个 Service Worker、甚至浏览器的主窗口都有一个关联的 JavaScript Context。

```javascript
// JavaScript 示例，展示了 Context 的概念

// 在浏览器环境中，每个浏览器的 tab 或 iframe 都有自己的全局对象和执行上下文。
// 这意味着在一个 tab 中定义的变量和函数，在另一个 tab 中是不可见的。

// 例如，在第一个 tab 中：
var myVariable = "hello from tab 1";
function myFunction() {
  console.log("Function from tab 1");
}

// 在第二个 tab 中，尝试访问第一个 tab 的变量或函数会报错或得到 undefined。
// console.log(myVariable); // 报错或 undefined
// myFunction(); // 报错或 undefined

// 在 Node.js 环境中，使用 `vm` 模块可以创建不同的 Context：
const vm = require('vm');

// 创建一个新的 Context
const context = vm.createContext({ myVar: 'initial value' });

// 在新的 Context 中执行代码
vm.runInContext('console.log(myVar); myVar = "modified value";', context); // 输出: initial value
console.log(context.myVar); // 输出: modified value

// 创建另一个独立的 Context
const anotherContext = vm.createContext({ myVar: 'another initial value' });
vm.runInContext('console.log(myVar);', anotherContext); // 输出: another initial value
console.log(anotherContext.myVar); // 输出: another initial value

// 可以看到，不同的 Context 拥有独立的变量和状态。
```

在 V8 的 C++ API 中，`v8::Context` 允许嵌入器（如 Chrome、Node.js）创建和管理这些隔离的 JavaScript 执行环境。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下代码片段使用 `v8::Context::New()`：

```c++
#include "include/v8.h"
#include <iostream>

int main() {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);

    // 创建一个新的 Context
    v8::Local<v8::Context> context = v8::Context::New(isolate);

    if (!context.IsEmpty()) {
      std::cout << "Context created successfully." << std::endl;
      // 获取全局对象
      v8::Local<v8::Object> global = context->Global();
      // ... 可以继续在 context 中执行 JavaScript 代码
    } else {
      std::cerr << "Failed to create context." << std::endl;
    }
  }
  isolate->Dispose();
  delete create_params.array_buffer_allocator;
  return 0;
}
```

**假设输入:** `v8::Isolate` 的一个有效实例。

**输出:**
- 如果 Context 创建成功，`v8::Context::New()` 将返回一个 `v8::Local<v8::Context>` 的非空实例，并且控制台输出 "Context created successfully."。
- 如果 Context 创建失败（例如，由于内存不足），`v8::Context::New()` 将返回一个空的 `v8::Local<v8::Context>`，并且控制台输出 "Failed to create context."。

**涉及用户常见的编程错误：**

1. **忘记进入或退出 Context：**

   ```c++
   v8::Local<v8::Context> context = v8::Context::New(isolate);
   // 错误：直接操作 context，而没有进入其作用域
   v8::Local<v8::String> name = v8::String::NewFromUtf8Literal(isolate, "world");
   // ... 其他操作
   // 忘记调用 context->Exit();
   ```

   **正确做法：** 使用 `v8::Context::Scope` 管理 Context 的生命周期。

   ```c++
   v8::Local<v8::Context> context = v8::Context::New(isolate);
   {
     v8::Context::Scope context_scope(context);
     v8::Local<v8::String> name = v8::String::NewFromUtf8Literal(isolate, "world");
     // ... 其他操作
   } // context_scope 的析构函数会自动调用 context->Exit();
   ```

2. **在错误的 Isolate 上创建或使用 Context：** 每个 Context 都与一个特定的 Isolate 关联。尝试在一个 Isolate 中创建的 Context 在另一个 Isolate 中使用会导致错误。

3. **不正确地使用安全令牌：** 如果需要在不同的 Context 之间共享对象，需要正确设置和管理安全令牌。忘记设置或设置不匹配的令牌会导致访问被拒绝。

4. **在不允许的情况下尝试从字符串生成代码：** 如果调用了 `context->AllowCodeGenerationFromStrings(false)`，则尝试使用 `eval()` 或 `Function()` 构造函数会抛出异常。

   ```javascript
   // JavaScript 代码在不允许代码生成的 Context 中
   eval("console.log('This will throw an error');");
   new Function("console.log('This will also throw an error');");
   ```

5. **不匹配的快照反序列化回调：** 如果使用快照创建 Context，必须确保提供的反序列化回调与创建快照时使用的回调匹配，否则可能导致程序崩溃或数据损坏。

理解 `v8::Context` 的作用和正确的使用方式是进行 V8 引擎嵌入开发的基石。这个头文件定义了与 JavaScript 执行环境交互的关键接口。

Prompt: 
```
这是目录为v8/include/v8-context.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-context.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_CONTEXT_H_
#define INCLUDE_V8_CONTEXT_H_

#include <stdint.h>

#include <vector>

#include "v8-data.h"          // NOLINT(build/include_directory)
#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8-maybe.h"         // NOLINT(build/include_directory)
#include "v8-snapshot.h"      // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

namespace v8 {

class Function;
class MicrotaskQueue;
class Object;
class ObjectTemplate;
class Value;
class String;

/**
 * A container for extension names.
 */
class V8_EXPORT ExtensionConfiguration {
 public:
  ExtensionConfiguration() : name_count_(0), names_(nullptr) {}
  ExtensionConfiguration(int name_count, const char* names[])
      : name_count_(name_count), names_(names) {}

  const char** begin() const { return &names_[0]; }
  const char** end() const { return &names_[name_count_]; }

 private:
  const int name_count_;
  const char** names_;
};

/**
 * A sandboxed execution context with its own set of built-in objects
 * and functions.
 */
class V8_EXPORT Context : public Data {
 public:
  /**
   * Returns the global proxy object.
   *
   * Global proxy object is a thin wrapper whose prototype points to actual
   * context's global object with the properties like Object, etc. This is done
   * that way for security reasons (for more details see
   * https://wiki.mozilla.org/Gecko:SplitWindow).
   *
   * Please note that changes to global proxy object prototype most probably
   * would break VM---v8 expects only global object as a prototype of global
   * proxy object.
   */
  Local<Object> Global();

  /**
   * Detaches the global object from its context before
   * the global object can be reused to create a new context.
   */
  void DetachGlobal();

  /**
   * Creates a new context and returns a handle to the newly allocated
   * context.
   *
   * \param isolate The isolate in which to create the context.
   *
   * \param extensions An optional extension configuration containing
   * the extensions to be installed in the newly created context.
   *
   * \param global_template An optional object template from which the
   * global object for the newly created context will be created.
   *
   * \param global_object An optional global object to be reused for
   * the newly created context. This global object must have been
   * created by a previous call to Context::New with the same global
   * template. The state of the global object will be completely reset
   * and only object identify will remain.
   *
   * \param internal_fields_deserializer An optional callback used
   * to deserialize fields set by
   * v8::Object::SetAlignedPointerInInternalField() in wrapper objects
   * from the default context snapshot. It should match the
   * SerializeInternalFieldsCallback() used by
   * v8::SnapshotCreator::SetDefaultContext() when the default context
   * snapshot is created. It does not need to be configured if the default
   * context snapshot contains no wrapper objects with pointer internal
   * fields, or if no custom startup snapshot is configured
   * in the v8::CreateParams used to create the isolate.
   *
   * \param microtask_queue An optional microtask queue used to manage
   * the microtasks created in this context. If not set the per-isolate
   * default microtask queue would be used.
   *
   * \param context_data_deserializer An optional callback used
   * to deserialize embedder data set by
   * v8::Context::SetAlignedPointerInEmbedderData() in the default
   * context from the default context snapshot. It does not need to be
   * configured if the default context snapshot contains no pointer embedder
   * data, or if no custom startup snapshot is configured in the
   * v8::CreateParams used to create the isolate.
   *
   * \param api_wrapper_deserializer An optional callback used to deserialize
   * API wrapper objects that was initially set with v8::Object::Wrap() and then
   * serialized using SerializeAPIWrapperCallback.
   */
  static Local<Context> New(
      Isolate* isolate, ExtensionConfiguration* extensions = nullptr,
      MaybeLocal<ObjectTemplate> global_template = MaybeLocal<ObjectTemplate>(),
      MaybeLocal<Value> global_object = MaybeLocal<Value>(),
      DeserializeInternalFieldsCallback internal_fields_deserializer =
          DeserializeInternalFieldsCallback(),
      MicrotaskQueue* microtask_queue = nullptr,
      DeserializeContextDataCallback context_data_deserializer =
          DeserializeContextDataCallback(),
      DeserializeAPIWrapperCallback api_wrapper_deserializer =
          DeserializeAPIWrapperCallback());

  /**
   * Create a new context from a (non-default) context snapshot. There
   * is no way to provide a global object template since we do not create
   * a new global object from template, but we can reuse a global object.
   *
   * \param isolate See v8::Context::New().
   *
   * \param context_snapshot_index The index of the context snapshot to
   * deserialize from. Use v8::Context::New() for the default snapshot.
   *
   * \param internal_fields_deserializer An optional callback used
   * to deserialize fields set by
   * v8::Object::SetAlignedPointerInInternalField() in wrapper objects
   * from the default context snapshot. It does not need to be
   * configured if there are no wrapper objects with no internal
   * pointer fields in the default context snapshot or if no startup
   * snapshot is configured when the isolate is created.
   *
   * \param extensions See v8::Context::New().
   *
   * \param global_object See v8::Context::New().
   *
   * \param internal_fields_deserializer Similar to
   * internal_fields_deserializer in v8::Context::New() but applies to
   * the context specified by the context_snapshot_index.
   *
   * \param microtask_queue  See v8::Context::New().
   *
   * \param context_data_deserializer  Similar to
   * context_data_deserializer in v8::Context::New() but applies to
   * the context specified by the context_snapshot_index.
   *
   *\param api_wrapper_deserializer Similar to api_wrapper_deserializer in
   * v8::Context::New() but applies to the context specified by the
   * context_snapshot_index.
   */
  static MaybeLocal<Context> FromSnapshot(
      Isolate* isolate, size_t context_snapshot_index,
      DeserializeInternalFieldsCallback internal_fields_deserializer =
          DeserializeInternalFieldsCallback(),
      ExtensionConfiguration* extensions = nullptr,
      MaybeLocal<Value> global_object = MaybeLocal<Value>(),
      MicrotaskQueue* microtask_queue = nullptr,
      DeserializeContextDataCallback context_data_deserializer =
          DeserializeContextDataCallback(),
      DeserializeAPIWrapperCallback api_wrapper_deserializer =
          DeserializeAPIWrapperCallback());

  /**
   * Returns an global object that isn't backed by an actual context.
   *
   * The global template needs to have access checks with handlers installed.
   * If an existing global object is passed in, the global object is detached
   * from its context.
   *
   * Note that this is different from a detached context where all accesses to
   * the global proxy will fail. Instead, the access check handlers are invoked.
   *
   * It is also not possible to detach an object returned by this method.
   * Instead, the access check handlers need to return nothing to achieve the
   * same effect.
   *
   * It is possible, however, to create a new context from the global object
   * returned by this method.
   */
  static MaybeLocal<Object> NewRemoteContext(
      Isolate* isolate, Local<ObjectTemplate> global_template,
      MaybeLocal<Value> global_object = MaybeLocal<Value>());

  /**
   * Sets the security token for the context.  To access an object in
   * another context, the security tokens must match.
   */
  void SetSecurityToken(Local<Value> token);

  /** Restores the security token to the default value. */
  void UseDefaultSecurityToken();

  /** Returns the security token of this context.*/
  Local<Value> GetSecurityToken();

  /**
   * Enter this context.  After entering a context, all code compiled
   * and run is compiled and run in this context.  If another context
   * is already entered, this old context is saved so it can be
   * restored when the new context is exited.
   */
  void Enter();

  /**
   * Exit this context.  Exiting the current context restores the
   * context that was in place when entering the current context.
   */
  void Exit();

  /**
   * Delegate to help with Deep freezing embedder-specific objects (such as
   * JSApiObjects) that can not be frozen natively.
   */
  class DeepFreezeDelegate {
   public:
    /**
     * Performs embedder-specific operations to freeze the provided embedder
     * object. The provided object *will* be frozen by DeepFreeze after this
     * function returns, so only embedder-specific objects need to be frozen.
     * This function *may not* create new JS objects or perform JS allocations.
     * Any v8 objects reachable from the provided embedder object that should
     * also be considered for freezing should be added to the children_out
     * parameter. Returns true if the operation completed successfully.
     */
    virtual bool FreezeEmbedderObjectAndGetChildren(
        Local<Object> obj, LocalVector<Object>& children_out) = 0;
  };

  /**
   * Attempts to recursively freeze all objects reachable from this context.
   * Some objects (generators, iterators, non-const closures) can not be frozen
   * and will cause this method to throw an error. An optional delegate can be
   * provided to help freeze embedder-specific objects.
   *
   * Freezing occurs in two steps:
   * 1. "Marking" where we iterate through all objects reachable by this
   *    context, accumulating a list of objects that need to be frozen and
   *    looking for objects that can't be frozen. This step is separated because
   *    it is more efficient when we can assume there is no garbage collection.
   * 2. "Freezing" where we go through the list of objects and freezing them.
   *    This effectively requires copying them so it may trigger garbage
   *    collection.
   */
  Maybe<void> DeepFreeze(DeepFreezeDelegate* delegate = nullptr);

  /** Returns the isolate associated with a current context. */
  Isolate* GetIsolate();

  /** Returns the microtask queue associated with a current context. */
  MicrotaskQueue* GetMicrotaskQueue();

  /** Sets the microtask queue associated with the current context. */
  void SetMicrotaskQueue(MicrotaskQueue* queue);

  /**
   * The field at kDebugIdIndex used to be reserved for the inspector.
   * It now serves no purpose.
   */
  enum EmbedderDataFields { kDebugIdIndex = 0 };

  /**
   * Return the number of fields allocated for embedder data.
   */
  uint32_t GetNumberOfEmbedderDataFields();

  /**
   * Gets the embedder data with the given index, which must have been set by a
   * previous call to SetEmbedderData with the same index.
   */
  V8_INLINE Local<Value> GetEmbedderData(int index);

  /**
   * Gets the binding object used by V8 extras. Extra natives get a reference
   * to this object and can use it to "export" functionality by adding
   * properties. Extra natives can also "import" functionality by accessing
   * properties added by the embedder using the V8 API.
   */
  Local<Object> GetExtrasBindingObject();

  /**
   * Sets the embedder data with the given index, growing the data as
   * needed. Note that index 0 currently has a special meaning for Chrome's
   * debugger.
   */
  void SetEmbedderData(int index, Local<Value> value);

  /**
   * Gets a 2-byte-aligned native pointer from the embedder data with the given
   * index, which must have been set by a previous call to
   * SetAlignedPointerInEmbedderData with the same index. Note that index 0
   * currently has a special meaning for Chrome's debugger.
   */
  V8_INLINE void* GetAlignedPointerFromEmbedderData(Isolate* isolate,
                                                    int index);
  V8_INLINE void* GetAlignedPointerFromEmbedderData(int index);

  /**
   * Sets a 2-byte-aligned native pointer in the embedder data with the given
   * index, growing the data as needed. Note that index 0 currently has a
   * special meaning for Chrome's debugger.
   */
  void SetAlignedPointerInEmbedderData(int index, void* value);

  /**
   * Control whether code generation from strings is allowed. Calling
   * this method with false will disable 'eval' and the 'Function'
   * constructor for code running in this context. If 'eval' or the
   * 'Function' constructor are used an exception will be thrown.
   *
   * If code generation from strings is not allowed the
   * V8::ModifyCodeGenerationFromStringsCallback callback will be invoked if
   * set before blocking the call to 'eval' or the 'Function'
   * constructor. If that callback returns true, the call will be
   * allowed, otherwise an exception will be thrown. If no callback is
   * set an exception will be thrown.
   */
  void AllowCodeGenerationFromStrings(bool allow);

  /**
   * Returns true if code generation from strings is allowed for the context.
   * For more details see AllowCodeGenerationFromStrings(bool) documentation.
   */
  bool IsCodeGenerationFromStringsAllowed() const;

  /**
   * Sets the error description for the exception that is thrown when
   * code generation from strings is not allowed and 'eval' or the 'Function'
   * constructor are called.
   */
  void SetErrorMessageForCodeGenerationFromStrings(Local<String> message);

  /**
   * Sets the error description for the exception that is thrown when
   * wasm code generation is not allowed.
   */
  void SetErrorMessageForWasmCodeGeneration(Local<String> message);

  /**
   * Return data that was previously attached to the context snapshot via
   * SnapshotCreator, and removes the reference to it.
   * Repeated call with the same index returns an empty MaybeLocal.
   */
  template <class T>
  V8_INLINE MaybeLocal<T> GetDataFromSnapshotOnce(size_t index);

  /**
   * If callback is set, abort any attempt to execute JavaScript in this
   * context, call the specified callback, and throw an exception.
   * To unset abort, pass nullptr as callback.
   */
  using AbortScriptExecutionCallback = void (*)(Isolate* isolate,
                                                Local<Context> context);
  void SetAbortScriptExecution(AbortScriptExecutionCallback callback);

  /**
   * Set or clear hooks to be invoked for promise lifecycle operations.
   * To clear a hook, set it to an empty v8::Function. Each function will
   * receive the observed promise as the first argument. If a chaining
   * operation is used on a promise, the init will additionally receive
   * the parent promise as the second argument.
   */
  void SetPromiseHooks(Local<Function> init_hook, Local<Function> before_hook,
                       Local<Function> after_hook,
                       Local<Function> resolve_hook);

  bool HasTemplateLiteralObject(Local<Value> object);
  /**
   * Stack-allocated class which sets the execution context for all
   * operations executed within a local scope.
   */
  class V8_NODISCARD Scope {
   public:
    explicit V8_INLINE Scope(Local<Context> context) : context_(context) {
      context_->Enter();
    }
    V8_INLINE ~Scope() { context_->Exit(); }

   private:
    Local<Context> context_;
  };

  /**
   * Stack-allocated class to support the backup incumbent settings object
   * stack.
   * https://html.spec.whatwg.org/multipage/webappapis.html#backup-incumbent-settings-object-stack
   */
  class V8_EXPORT V8_NODISCARD BackupIncumbentScope final {
   public:
    /**
     * |backup_incumbent_context| is pushed onto the backup incumbent settings
     * object stack.
     */
    explicit BackupIncumbentScope(Local<Context> backup_incumbent_context);
    ~BackupIncumbentScope();

   private:
    friend class internal::Isolate;

    uintptr_t JSStackComparableAddressPrivate() const {
      return js_stack_comparable_address_;
    }

    Local<Context> backup_incumbent_context_;
    uintptr_t js_stack_comparable_address_ = 0;
    const BackupIncumbentScope* prev_ = nullptr;
  };

  V8_INLINE static Context* Cast(Data* data);

 private:
  friend class Value;
  friend class Script;
  friend class Object;
  friend class Function;

  static void CheckCast(Data* obj);

  internal::ValueHelper::InternalRepresentationType GetDataFromSnapshotOnce(
      size_t index);
  Local<Value> SlowGetEmbedderData(int index);
  void* SlowGetAlignedPointerFromEmbedderData(int index);
};

// --- Implementation ---

Local<Value> Context::GetEmbedderData(int index) {
#ifndef V8_ENABLE_CHECKS
  using A = internal::Address;
  using I = internal::Internals;
  A ctx = internal::ValueHelper::ValueAsAddress(this);
  A embedder_data =
      I::ReadTaggedPointerField(ctx, I::kNativeContextEmbedderDataOffset);
  int value_offset =
      I::kEmbedderDataArrayHeaderSize + (I::kEmbedderDataSlotSize * index);
  A value = I::ReadRawField<A>(embedder_data, value_offset);
#ifdef V8_COMPRESS_POINTERS
  // We read the full pointer value and then decompress it in order to avoid
  // dealing with potential endiannes issues.
  value = I::DecompressTaggedField(embedder_data, static_cast<uint32_t>(value));
#endif

  auto isolate = reinterpret_cast<v8::Isolate*>(
      internal::IsolateFromNeverReadOnlySpaceObject(ctx));
  return Local<Value>::New(isolate, value);
#else
  return SlowGetEmbedderData(index);
#endif
}

void* Context::GetAlignedPointerFromEmbedderData(Isolate* isolate, int index) {
#if !defined(V8_ENABLE_CHECKS)
  using A = internal::Address;
  using I = internal::Internals;
  A ctx = internal::ValueHelper::ValueAsAddress(this);
  A embedder_data =
      I::ReadTaggedPointerField(ctx, I::kNativeContextEmbedderDataOffset);
  int value_offset = I::kEmbedderDataArrayHeaderSize +
                     (I::kEmbedderDataSlotSize * index) +
                     I::kEmbedderDataSlotExternalPointerOffset;
  return reinterpret_cast<void*>(
      I::ReadExternalPointerField<internal::kEmbedderDataSlotPayloadTag>(
          isolate, embedder_data, value_offset));
#else
  return SlowGetAlignedPointerFromEmbedderData(index);
#endif
}

void* Context::GetAlignedPointerFromEmbedderData(int index) {
#if !defined(V8_ENABLE_CHECKS)
  using A = internal::Address;
  using I = internal::Internals;
  A ctx = internal::ValueHelper::ValueAsAddress(this);
  A embedder_data =
      I::ReadTaggedPointerField(ctx, I::kNativeContextEmbedderDataOffset);
  int value_offset = I::kEmbedderDataArrayHeaderSize +
                     (I::kEmbedderDataSlotSize * index) +
                     I::kEmbedderDataSlotExternalPointerOffset;
  Isolate* isolate = I::GetIsolateForSandbox(ctx);
  return reinterpret_cast<void*>(
      I::ReadExternalPointerField<internal::kEmbedderDataSlotPayloadTag>(
          isolate, embedder_data, value_offset));
#else
  return SlowGetAlignedPointerFromEmbedderData(index);
#endif
}

template <class T>
MaybeLocal<T> Context::GetDataFromSnapshotOnce(size_t index) {
  if (auto repr = GetDataFromSnapshotOnce(index);
      repr != internal::ValueHelper::kEmpty) {
    internal::PerformCastCheck(internal::ValueHelper::ReprAsValue<T>(repr));
    return Local<T>::FromRepr(repr);
  }
  return {};
}

Context* Context::Cast(v8::Data* data) {
#ifdef V8_ENABLE_CHECKS
  CheckCast(data);
#endif
  return static_cast<Context*>(data);
}

}  // namespace v8

#endif  // INCLUDE_V8_CONTEXT_H_

"""

```