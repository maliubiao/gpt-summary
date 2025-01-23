Response:
Let's break down the thought process for analyzing the `source-text-module.h` file.

1. **Understand the Goal:** The primary goal is to understand the *purpose* and *functionality* of this header file within the V8 JavaScript engine. We need to extract key information, identify relationships with JavaScript, and address potential developer pitfalls.

2. **Initial Scan and Keywords:**  First, I'd quickly scan the code for obvious keywords and patterns:
    * `#ifndef`, `#define`, `#include`:  Standard C++ header guards and includes. Not directly related to functionality *yet*, but important for context.
    * `namespace v8`, `namespace internal`: Indicates this is part of the V8 engine's internal implementation.
    * `class SourceTextModule`: This is the core of the file. The name strongly suggests it's about representing JavaScript modules.
    * Inheritance (`: public TorqueGeneratedSourceTextModule<...>`) hints at code generation and a base class. `Module` as the ultimate base class is important.
    * `Tagged<>`:  A V8-specific smart pointer for garbage-collected objects. This is a crucial V8 concept.
    * `Handle<>`: Another V8 smart pointer, representing a managed reference.
    * `enum`, `static constexpr`: Standard C++ for defining enumerations and constants.
    * `DECL_...`, `DEFINE_...`, `TQ_OBJECT_CONSTRUCTORS`: Macros – likely V8-specific for boilerplate code generation (accessors, verifiers, etc.).
    * Comments like "// The runtime representation of an ECMAScript Source Text Module Record." are invaluable.
    * Mentions of "async", "await", "import", "export", "namespace", "import.meta": These directly connect to JavaScript module features.

3. **Focus on `SourceTextModule` Class:** This is the central point. I'd analyze its members:
    * **Public Members:**  These define the interface for interacting with `SourceTextModule` objects.
        * `GetSharedFunctionInfo()`, `GetScript()`:  Relate the module to its code.
        * `has_toplevel_await()`:  A boolean flag – important for understanding asynchronous modules.
        * `info()`: Returns a `SourceTextModuleInfo` object – likely metadata about the module.
        * `GetCell()`, `LoadVariable()`, `StoreVariable()`:  Suggest how module variables are stored and accessed. The `cell_index` hints at an internal storage mechanism.
        * `ImportIndex()`, `ExportIndex()`: Relate to module imports and exports.
        * `AsyncModuleExecutionFulfilled()`, `AsyncModuleExecutionRejected()`:  Clearly for handling the completion/failure of asynchronous module execution.
        * `GetModuleNamespace()`:  Returns the namespace object, a key concept in ES modules.
        * `GetImportMeta()`:  Deals with the `import.meta` object.
    * **Private Members:** These are internal implementation details. While understanding them deeply isn't the initial goal, noticing things like `AsyncEvaluationOrdinalCompare`, `AvailableAncestorsSet`, and methods for managing asynchronous dependencies is important for grasping the complexity of module loading.
    * **Static Methods:**  Many static methods indicate utility functions or factory-like operations related to `SourceTextModule` instances. Methods like `CreateExport`, `ResolveExport`, `PrepareInstantiate`, and `Evaluate` point to the module lifecycle.

4. **Identify Key Concepts and Relationships:**
    * **ECMAScript Modules:** The comments and member names directly link this class to the ECMAScript specification for modules.
    * **Asynchronous Modules:**  The presence of `async`, `await`, and related methods highlights the support for asynchronous module loading.
    * **Module Linking and Evaluation:**  Methods like `Instantiate`, `Evaluate`, `ResolveExport`, and `ResolveImport` are crucial for the module linking and evaluation process.
    * **Module Namespace:**  The `GetModuleNamespace` method emphasizes the concept of a module's namespace.
    * **`import.meta`:** The `GetImportMeta` method shows how `import.meta` is handled.
    * **`SourceTextModuleInfo`:** This class seems to hold static information about the module, like imports and exports.
    * **`ModuleRequest`:** Represents a request to import another module.

5. **Connect to JavaScript:**  Now, I'd start thinking about how these internal C++ structures relate to JavaScript code:
    * **`import` and `export` statements:** The C++ code clearly reflects the functionality of `import` and `export`. The `ResolveImport` and `ResolveExport` methods are directly involved in resolving these.
    * **`async` and `await` in modules:**  The `has_toplevel_await`, `AsyncModuleExecutionFulfilled`, etc., directly map to the behavior of asynchronous modules.
    * **Module namespace objects:**  The `GetModuleNamespace` method creates the JavaScript object that represents the module's exports.
    * **`import.meta`:** The `GetImportMeta` method handles the creation and initialization of the `import.meta` object.

6. **Address Specific Prompts:**
    * **Functionality Listing:**  Based on the analysis, I'd create a list of the key functionalities, focusing on the most important aspects.
    * **`.tq` Extension:**  The comment about `.tq` files indicates Torque, V8's internal language.
    * **JavaScript Examples:**  I would construct simple JavaScript examples that demonstrate the C++ code's functionality (e.g., `import`, `export`, `async import`).
    * **Code Logic Inference:** I'd try to infer the logic of key operations like `LoadVariable` and `StoreVariable`, providing hypothetical inputs and outputs.
    * **Common Programming Errors:** I'd think about common mistakes developers make with JavaScript modules that might relate to the C++ code (e.g., circular dependencies, incorrect import paths, using `import.meta` outside modules).

7. **Structure and Refine:** Finally, I'd organize the information logically, using clear language and providing examples where necessary. I'd review the answer to ensure it's comprehensive and addresses all aspects of the prompt.

**Self-Correction/Refinement During the Process:**

* **Initial Overwhelm:**  The initial scan might feel overwhelming due to the V8-specific terminology. I'd focus on the class names, comments, and keywords first to get a general idea.
* **Macro Mystery:**  While the macros aren't essential for understanding the high-level functionality, I'd note their existence and understand they likely generate boilerplate code.
* **Deep Dive vs. High-Level:**  I'd consciously decide to focus on the *what* and *why* of the class rather than getting bogged down in the low-level implementation details (unless specifically requested).
* **Connecting the Dots:**  The key is to consistently connect the C++ code back to the corresponding JavaScript concepts.

By following this structured approach, I can effectively analyze the C++ header file and extract the necessary information to answer the prompt comprehensively.
`v8/src/objects/source-text-module.h` 是 V8 引擎中表示 ECMAScript 模块（也称为 ES 模块）的核心数据结构定义文件。它定义了 `SourceTextModule` 类，该类用于存储和管理模块的各种状态和信息。

以下是该文件列举的功能：

**核心功能：表示和管理 ECMAScript 模块**

* **模块元数据存储:** `SourceTextModule` 类存储了关于一个源文本模块的关键信息，例如：
    * **共享函数信息 (`SharedFunctionInfo`):**  指向模块代码编译后的共享函数信息。
    * **脚本 (`Script`):**  指向包含模块源代码的脚本对象。
    * **是否包含顶层 `await` (`has_toplevel_await`):** 标记模块是否使用了顶层 `await` 语法。
    * **模块信息 (`SourceTextModuleInfo`):**  一个包含模块静态信息的对象，例如导入和导出声明。
    * **模块状态 (`status` inherited from `Module`):**  模块的加载、实例化和求值状态 (e.g., Uninstantiated, Instantiated, Evaluating, Evaluated, Errored)。
    * **异步模块相关信息:** 用于管理异步模块加载和执行的状态，如 `async_evaluation_ordinal` 和 `async_parent_modules`。

* **模块变量管理:**
    * **`GetCell(int cell_index)`:**  获取存储模块变量的 `Cell` 对象。`Cell` 是 V8 中用于存储变量的容器。
    * **`LoadVariable(Isolate*, DirectHandle<SourceTextModule>, int)`:**  加载模块变量的值。
    * **`StoreVariable(DirectHandle<SourceTextModule>, int, DirectHandle<Object>)`:**  存储模块变量的值。
    * `ImportIndex`, `ExportIndex`: 将 `cell_index` 映射到导入或导出的索引。

* **异步模块执行控制:**
    * **`AsyncModuleExecutionFulfilled` 和 `AsyncModuleExecutionRejected`:**  用于在异步模块执行完成或失败时触发的操作，通常与 Promise 关联。

* **模块命名空间管理:**
    * **`GetModuleNamespace(Isolate*, DirectHandle<SourceTextModule>, int)`:** 获取给定模块请求的模块命名空间对象。

* **`import.meta` 支持:**
    * **`GetImportMeta(Isolate*, Handle<SourceTextModule>)`:**  获取模块的 `import.meta` 对象。

* **模块实例化和求值流程控制:**
    * **`PrepareInstantiate`, `FinishInstantiate`:**  模块实例化过程的步骤。
    * **`RunInitializationCode`:**  执行模块的初始化代码。
    * **`Evaluate`, `InnerModuleEvaluation`:**  模块求值过程的实现。
    * **`InnerExecuteAsyncModule`, `ExecuteModule`, `ExecuteAsyncModule`:**  同步和异步模块执行的实现。

* **处理顶层 `await`:**
    * `GetStalledTopLevelAwaitMessages`: 获取因顶层 `await` 而暂停的模块的消息。

**其他功能：**

* **数据结构定义:**  定义了与模块相关的其他数据结构，如 `SourceTextModuleInfo`（存储模块的静态元数据）、`ModuleRequest`（表示模块的导入请求）和 `SourceTextModuleInfoEntry`（表示模块信息中的条目，如导出或导入）。
* **调试支持:** 包含了打印模块信息的宏 `DECL_PRINTER(SourceTextModule)`。
* **内存管理:** 使用 `Tagged<>` 和 `Handle<>` 等 V8 的内存管理机制来安全地引用垃圾回收堆上的对象.

**关于 `.tq` 扩展名:**

文件中包含了 `#include "torque-generated/src/objects/source-text-module-tq.inc"`。根据命名约定，`.tq` 文件是 **V8 Torque 源代码**。 Torque 是 V8 内部使用的一种类型化的中间语言，用于生成高效的 C++ 代码，特别是在对象布局和内置函数方面。 因此，`SourceTextModule` 类很可能是用 Torque 定义了其布局和一些基本操作。

**与 JavaScript 的关系及示例:**

`v8/src/objects/source-text-module.h` 中定义的 `SourceTextModule` 类是 V8 引擎实现 JavaScript 模块功能的基础。 当 JavaScript 代码中使用 `import` 和 `export` 语句时，V8 内部会创建并操作 `SourceTextModule` 对象来管理这些模块。

**JavaScript 示例:**

```javascript
// moduleA.js
export const message = "Hello from moduleA";

// moduleB.js
import { message } from './moduleA.js';

console.log(message); // 输出 "Hello from moduleA"

async function fetchData() {
  await new Promise(resolve => setTimeout(resolve, 1000));
  return "Data fetched";
}

export async function getAsyncData() {
  return await fetchData();
}

// moduleC.js
import { getAsyncData } from './moduleB.js';

async function main() {
  const data = await getAsyncData();
  console.log(data); // 1秒后输出 "Data fetched"
}

main();

// moduleD.js
import.meta.url; // 可以获取当前模块的 URL
```

当 V8 执行这些 JavaScript 代码时，会发生以下与 `SourceTextModule` 相关的操作：

1. **模块加载和解析:** V8 会解析 `moduleA.js`, `moduleB.js`, `moduleC.js`, `moduleD.js` 的源代码。
2. **`SourceTextModule` 创建:**  对于每个解析成功的模块，V8 会创建一个 `SourceTextModule` 对象来表示它。
3. **模块依赖关系分析:** V8 会分析 `import` 语句，确定模块之间的依赖关系。  `ModuleRequest` 对象会被创建来表示这些依赖。
4. **模块实例化:**
    * V8 会根据 `import` 和 `export` 声明填充 `SourceTextModuleInfo` 对象。
    *  `ResolveExport` 和 `ResolveImport` 等方法会被调用来解析导入和导出，并将它们链接到相应的 `Cell` 对象。
5. **模块求值:**
    * 对于同步模块，`ExecuteModule` 会被调用来执行模块的代码。
    * 对于包含顶层 `await` 的模块（如 `moduleC.js` 如果其顶层直接使用了 `await`），或者异步模块函数，会使用 `InnerExecuteAsyncModule` 和 `ExecuteAsyncModule` 来管理异步执行。
6. **变量访问:** 当代码访问模块导出的变量时，V8 会使用 `LoadVariable` 从相应的 `Cell` 中读取值。
7. **`import.meta`:** 当访问 `import.meta` 时，`GetImportMeta` 会被调用来获取或创建该对象。

**代码逻辑推理示例:**

假设有以下简化版的 `LoadVariable` 函数的逻辑：

```c++
// 简化示例，实际实现更复杂
Tagged<Object> SourceTextModule::LoadVariable(Isolate* isolate,
                                            DirectHandle<SourceTextModule> module,
                                            int cell_index) {
  // 获取模块的变量数组
  Tagged<FixedArray> variables = module->variables(); // 假设 SourceTextModule 有一个 variables() 方法

  // 检查 cell_index 是否有效
  if (cell_index >= 0 && cell_index < variables->length()) {
    // 返回指定索引的变量
    return variables->get(cell_index);
  } else {
    // 抛出错误或返回 undefined，这里简化为返回空对象
    return ReadOnlyRoots(isolate).undefined_value();
  }
}
```

**假设输入:**

* `module`: 一个 `SourceTextModule` 对象的句柄，代表 `moduleA.js`。
* `cell_index`:  假设 `message` 变量在 `moduleA.js` 的变量数组中的索引是 0。

**预期输出:**

* `Tagged<Object>`:  包含字符串 "Hello from moduleA" 的 `String` 对象。

**用户常见的编程错误示例:**

1. **循环依赖:**  如果模块之间存在循环导入关系，例如：

   ```javascript
   // a.js
   import { b } from './b.js';
   export const a = 1;

   // b.js
   import { a } from './a.js';
   export const b = 2;
   ```

   V8 的模块加载器需要处理这种情况，可能会导致某些变量在初始化时为 `undefined`。  `PrepareInstantiate` 和 `FinishInstantiate` 等方法会参与检测和处理循环依赖。

2. **模块说明符错误:** `import` 语句中的路径不正确，导致模块加载失败。例如：

   ```javascript
   import { something } from './nonexistent-module.js'; // 文件不存在
   ```

   这会导致模块实例化或求值阶段出错，V8 会抛出错误，这可能涉及到 `PrepareInstantiate` 中的模块解析逻辑。

3. **访问未导出的变量:**  在一个模块中尝试导入另一个模块中未导出的变量。例如：

   ```javascript
   // module_x.js
   const internalValue = 42; // 未导出

   // module_y.js
   import { internalValue } from './module_x.js'; // 错误！
   ```

   V8 在模块实例化阶段会检查导入和导出的匹配性，`ResolveImport` 和 `ResolveExport` 方法会参与这个过程，并在发现不匹配时报错。

4. **在非模块环境中使用模块语法:**  在不支持模块的环境（例如，未声明 `type="module"` 的 `<script>` 标签）中使用 `import` 或 `export` 语法会导致语法错误。

了解 `v8/src/objects/source-text-module.h` 中的定义有助于理解 V8 引擎如何管理和执行 JavaScript 模块，以及在出现模块相关错误时，引擎内部可能发生的操作。

### 提示词
```
这是目录为v8/src/objects/source-text-module.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/source-text-module.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_SOURCE_TEXT_MODULE_H_
#define V8_OBJECTS_SOURCE_TEXT_MODULE_H_

#include "src/objects/contexts.h"
#include "src/objects/module.h"
#include "src/objects/promise.h"
#include "src/objects/string.h"
#include "src/zone/zone-containers.h"
#include "torque-generated/bit-fields.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

class UnorderedModuleSet;
class StructBodyDescriptor;

#include "torque-generated/src/objects/source-text-module-tq.inc"

// The runtime representation of an ECMAScript Source Text Module Record.
// https://tc39.github.io/ecma262/#sec-source-text-module-records
class SourceTextModule
    : public TorqueGeneratedSourceTextModule<SourceTextModule, Module> {
 public:
  NEVER_READ_ONLY_SPACE
  DECL_VERIFIER(SourceTextModule)
  DECL_PRINTER(SourceTextModule)

  // The shared function info in case {status} is not kEvaluating, kEvaluated or
  // kErrored.
  Tagged<SharedFunctionInfo> GetSharedFunctionInfo() const;

  Tagged<Script> GetScript() const;

  // Whether or not this module contains a toplevel await. Set during module
  // creation and does not change afterwards.
  DECL_BOOLEAN_ACCESSORS(has_toplevel_await)

  // Get the SourceTextModuleInfo associated with the code.
  inline Tagged<SourceTextModuleInfo> info() const;

  Tagged<Cell> GetCell(int cell_index);
  static Handle<Object> LoadVariable(Isolate* isolate,
                                     DirectHandle<SourceTextModule> module,
                                     int cell_index);
  static void StoreVariable(DirectHandle<SourceTextModule> module,
                            int cell_index, DirectHandle<Object> value);

  static int ImportIndex(int cell_index);
  static int ExportIndex(int cell_index);

  // Used by builtins to fulfill or reject the promise associated
  // with async SourceTextModules. Return Nothing if the execution is
  // terminated.
  static Maybe<bool> AsyncModuleExecutionFulfilled(
      Isolate* isolate, Handle<SourceTextModule> module);
  static void AsyncModuleExecutionRejected(
      Isolate* isolate, DirectHandle<SourceTextModule> module,
      Handle<Object> exception);

  // Get the namespace object for [module_request] of [module].  If it doesn't
  // exist yet, it is created.
  static Handle<JSModuleNamespace> GetModuleNamespace(
      Isolate* isolate, DirectHandle<SourceTextModule> module,
      int module_request);

  // Get the import.meta object of [module].  If it doesn't exist yet, it is
  // created and passed to the embedder callback for initialization.
  V8_EXPORT_PRIVATE static MaybeHandle<JSObject> GetImportMeta(
      Isolate* isolate, Handle<SourceTextModule> module);

  using BodyDescriptor =
      SubclassBodyDescriptor<Module::BodyDescriptor,
                             FixedBodyDescriptor<kCodeOffset, kSize, kSize>>;

  static constexpr unsigned kFirstAsyncEvaluationOrdinal = 2;

  enum ExecuteAsyncModuleContextSlots {
    kModule = Context::MIN_CONTEXT_SLOTS,
    kContextLength,
  };

  V8_EXPORT_PRIVATE
  std::vector<std::tuple<Handle<SourceTextModule>, Handle<JSMessageObject>>>
  GetStalledTopLevelAwaitMessages(Isolate* isolate);

 private:
  friend class Factory;
  friend class Module;

  struct AsyncEvaluationOrdinalCompare;
  using AvailableAncestorsSet =
      ZoneSet<Handle<SourceTextModule>, AsyncEvaluationOrdinalCompare>;

  // Appends a tuple of module and generator to the async parent modules
  // ArrayList.
  inline static void AddAsyncParentModule(
      Isolate* isolate, DirectHandle<SourceTextModule> module,
      DirectHandle<SourceTextModule> parent);

  // Get the non-hole cycle root. Only valid when status >= kEvaluated.
  inline Handle<SourceTextModule> GetCycleRoot(Isolate* isolate) const;

  // Returns a SourceTextModule, the
  // ith parent in depth first traversal order of a given async child.
  inline Handle<SourceTextModule> GetAsyncParentModule(Isolate* isolate,
                                                       int index);

  // Returns the number of async parent modules for a given async child.
  inline int AsyncParentModuleCount();

  inline bool HasAsyncEvaluationOrdinal() const;

  inline bool HasPendingAsyncDependencies();
  inline void IncrementPendingAsyncDependencies();
  inline void DecrementPendingAsyncDependencies();

  // Bits for flags.
  DEFINE_TORQUE_GENERATED_SOURCE_TEXT_MODULE_FLAGS()

  // async_evaluation_ordinal, top_level_capability, pending_async_dependencies,
  // and async_parent_modules are used exclusively during evaluation of async
  // modules and the modules which depend on them.
  //
  // If >1, this module is async and evaluating or currently evaluating an async
  // child. The integer is an ordinal for when this module first started async
  // evaluation and is used for sorting async parent modules when determining
  // which parent module can start executing after an async evaluation
  // completes.
  //
  // If 1, this module has finished async evaluating.
  //
  // If 0, this module is not async or has not been async evaluated.
  static constexpr unsigned kNotAsyncEvaluated = 0;
  static constexpr unsigned kAsyncEvaluateDidFinish = 1;
  static_assert(kNotAsyncEvaluated < kAsyncEvaluateDidFinish);
  static_assert(kAsyncEvaluateDidFinish < kFirstAsyncEvaluationOrdinal);
  DECL_PRIMITIVE_ACCESSORS(async_evaluation_ordinal, unsigned)

  // The parent modules of a given async dependency, use async_parent_modules()
  // to retrieve the ArrayList representation.
  DECL_ACCESSORS(async_parent_modules, Tagged<ArrayList>)

  // Helpers for Instantiate and Evaluate.
  static void CreateExport(Isolate* isolate,
                           DirectHandle<SourceTextModule> module,
                           int cell_index, DirectHandle<FixedArray> names);
  static void CreateIndirectExport(Isolate* isolate,
                                   DirectHandle<SourceTextModule> module,
                                   Handle<String> name,
                                   Handle<SourceTextModuleInfoEntry> entry);

  static V8_WARN_UNUSED_RESULT MaybeHandle<Cell> ResolveExport(
      Isolate* isolate, Handle<SourceTextModule> module,
      Handle<String> module_specifier, Handle<String> export_name,
      MessageLocation loc, bool must_resolve, ResolveSet* resolve_set);
  static V8_WARN_UNUSED_RESULT MaybeHandle<Cell> ResolveImport(
      Isolate* isolate, DirectHandle<SourceTextModule> module,
      Handle<String> name, int module_request_index, MessageLocation loc,
      bool must_resolve, ResolveSet* resolve_set);

  static V8_WARN_UNUSED_RESULT MaybeHandle<Cell> ResolveExportUsingStarExports(
      Isolate* isolate, DirectHandle<SourceTextModule> module,
      Handle<String> module_specifier, Handle<String> export_name,
      MessageLocation loc, bool must_resolve, ResolveSet* resolve_set);

  static V8_WARN_UNUSED_RESULT bool PrepareInstantiate(
      Isolate* isolate, Handle<SourceTextModule> module,
      v8::Local<v8::Context> context,
      v8::Module::ResolveModuleCallback module_callback,
      v8::Module::ResolveSourceCallback source_callback);
  static V8_WARN_UNUSED_RESULT bool FinishInstantiate(
      Isolate* isolate, Handle<SourceTextModule> module,
      ZoneForwardList<Handle<SourceTextModule>>* stack, unsigned* dfs_index,
      Zone* zone);
  static V8_WARN_UNUSED_RESULT bool RunInitializationCode(
      Isolate* isolate, DirectHandle<SourceTextModule> module);

  static void FetchStarExports(Isolate* isolate,
                               Handle<SourceTextModule> module, Zone* zone,
                               UnorderedModuleSet* visited);

  static void GatherAvailableAncestors(Isolate* isolate, Zone* zone,
                                       Handle<SourceTextModule> start,
                                       AvailableAncestorsSet* exec_list);

  // Implementation of spec concrete method Evaluate.
  static V8_WARN_UNUSED_RESULT MaybeHandle<Object> Evaluate(
      Isolate* isolate, Handle<SourceTextModule> module);

  // Implementation of spec abstract operation InnerModuleEvaluation.
  static V8_WARN_UNUSED_RESULT MaybeHandle<Object> InnerModuleEvaluation(
      Isolate* isolate, Handle<SourceTextModule> module,
      ZoneForwardList<Handle<SourceTextModule>>* stack, unsigned* dfs_index);

  // Returns true if the evaluation exception was catchable by js, and false
  // for termination exceptions.
  bool MaybeHandleEvaluationException(
      Isolate* isolate, ZoneForwardList<Handle<SourceTextModule>>* stack);

  static V8_WARN_UNUSED_RESULT bool MaybeTransitionComponent(
      Isolate* isolate, DirectHandle<SourceTextModule> module,
      ZoneForwardList<Handle<SourceTextModule>>* stack, Status new_status);

  // Implementation of spec ExecuteModule is broken up into
  // InnerExecuteAsyncModule for asynchronous modules and ExecuteModule
  // for synchronous modules.
  static V8_WARN_UNUSED_RESULT MaybeHandle<Object> InnerExecuteAsyncModule(
      Isolate* isolate, DirectHandle<SourceTextModule> module,
      DirectHandle<JSPromise> capability);

  static V8_WARN_UNUSED_RESULT MaybeHandle<Object> ExecuteModule(
      Isolate* isolate, DirectHandle<SourceTextModule> module,
      MaybeHandle<Object>* exception_out);

  // Implementation of spec ExecuteAsyncModule. Return Nothing if the execution
  // is been terminated.
  static V8_WARN_UNUSED_RESULT Maybe<bool> ExecuteAsyncModule(
      Isolate* isolate, DirectHandle<SourceTextModule> module);

  static void Reset(Isolate* isolate, DirectHandle<SourceTextModule> module);

  V8_EXPORT_PRIVATE void InnerGetStalledTopLevelAwaitModule(
      Isolate* isolate, UnorderedModuleSet* visited,
      std::vector<Handle<SourceTextModule>>* result);

  TQ_OBJECT_CONSTRUCTORS(SourceTextModule)
};

// SourceTextModuleInfo is to SourceTextModuleDescriptor what ScopeInfo is to
// Scope.
class SourceTextModuleInfo : public FixedArray {
 public:
  template <typename IsolateT>
  static Handle<SourceTextModuleInfo> New(IsolateT* isolate, Zone* zone,
                                          SourceTextModuleDescriptor* descr);

  inline Tagged<FixedArray> module_requests() const;
  inline Tagged<FixedArray> special_exports() const;
  inline Tagged<FixedArray> regular_exports() const;
  inline Tagged<FixedArray> regular_imports() const;
  inline Tagged<FixedArray> namespace_imports() const;

  // Accessors for [regular_exports].
  int RegularExportCount() const;
  Tagged<String> RegularExportLocalName(int i) const;
  int RegularExportCellIndex(int i) const;
  Tagged<FixedArray> RegularExportExportNames(int i) const;

#ifdef DEBUG
  inline bool Equals(Tagged<SourceTextModuleInfo> other) const;
#endif

 private:
  template <typename Impl>
  friend class FactoryBase;
  friend class SourceTextModuleDescriptor;
  enum {
    kModuleRequestsIndex,
    kSpecialExportsIndex,
    kRegularExportsIndex,
    kNamespaceImportsIndex,
    kRegularImportsIndex,
    kLength
  };
  enum {
    kRegularExportLocalNameOffset,
    kRegularExportCellIndexOffset,
    kRegularExportExportNamesOffset,
    kRegularExportLength
  };
};

class ModuleRequest
    : public TorqueGeneratedModuleRequest<ModuleRequest, Struct> {
 public:
  NEVER_READ_ONLY_SPACE
  DECL_VERIFIER(ModuleRequest)

  template <typename IsolateT>
  static Handle<ModuleRequest> New(IsolateT* isolate,
                                   DirectHandle<String> specifier,
                                   ModuleImportPhase phase,
                                   DirectHandle<FixedArray> import_attributes,
                                   int position);

  // The number of entries in the import_attributes FixedArray that are used for
  // a single attribute.
  static const size_t kAttributeEntrySize = 3;

  // Bits for flags.
  DEFINE_TORQUE_GENERATED_MODULE_REQUEST_FLAGS()
  static_assert(PositionBits::kMax >= String::kMaxLength,
                "String::kMaxLength should fit in PositionBits::kMax");
  DECL_PRIMITIVE_ACCESSORS(position, unsigned)
  inline void set_phase(ModuleImportPhase phase);
  inline ModuleImportPhase phase() const;

  using BodyDescriptor = StructBodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(ModuleRequest)
};

class SourceTextModuleInfoEntry
    : public TorqueGeneratedSourceTextModuleInfoEntry<SourceTextModuleInfoEntry,
                                                      Struct> {
 public:
  DECL_VERIFIER(SourceTextModuleInfoEntry)

  template <typename IsolateT>
  static Handle<SourceTextModuleInfoEntry> New(
      IsolateT* isolate, DirectHandle<UnionOf<String, Undefined>> export_name,
      DirectHandle<UnionOf<String, Undefined>> local_name,
      DirectHandle<UnionOf<String, Undefined>> import_name, int module_request,
      int cell_index, int beg_pos, int end_pos);

  using BodyDescriptor = StructBodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(SourceTextModuleInfoEntry)
};

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_SOURCE_TEXT_MODULE_H_
```