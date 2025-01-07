Response:
Let's break down the thought process for analyzing the `contexts.cc` file.

1. **Understand the Request:** The core request is to analyze the provided C++ code snippet from V8 and explain its functionalities, relation to JavaScript, potential errors, and illustrate with examples. The `.tq` check is a specific instruction.

2. **Initial Scan and High-Level Understanding:**  The first step is a quick skim of the code. Keywords like `Context`, `ScriptContext`, `NativeContext`, `ScopeInfo`, `Lookup`, `Add`, `Initialize`, `HashTable` immediately jump out. The copyright notice confirms it's part of the V8 project. The includes suggest interaction with other parts of V8, like AST, debugging, execution, and object management. This suggests the file is central to how V8 manages execution environments.

3. **Check for `.tq`:** The request explicitly asks about the `.tq` extension. A quick look at the provided content reveals standard C++ includes and syntax (`#include`, `namespace`, class definitions). There's no sign of Torque-specific syntax. Therefore, the answer to that part is straightforward: it's not a Torque file.

4. **Identify Core Functionalities (Iterative Refinement):** Now, the more detailed analysis begins. We go through the code block by block, trying to understand the purpose of each function and class.

    * **`ScriptContextTable`:** The names and methods (`New`, `Add`, `Lookup`) suggest it's a table for managing script contexts. The `NameToIndexHashTable` association indicates it maps names to indices within the table. The `AddLocalNamesFromContext` helper function reinforces this idea of associating names with contexts.

    * **`Context` Class:** This seems like the base class for different types of execution contexts. Methods like `Initialize`, `Lookup`, `declaration_context`, `closure_context`, `extension_object`, `script_context`, `global_object`, and `module` point to the core responsibilities of tracking the lexical environment, scope, and global objects.

    * **`Context::Lookup`:** This function is crucial. The detailed logic within it, including checking global objects, with contexts, function/block/script/module contexts, debug evaluation contexts, and handling block lists, reveals its role in variable resolution.

    * **Context Side Properties (`GetOrCreateContextSidePropertyCell`, `GetScriptContextSideProperty`, `LoadScriptContextElement`, `StoreScriptContextAndUpdateSlotProperty`):** These functions, especially with the `v8_flags.script_context_mutable_heap_number` and `v8_flags.const_tracking_let` conditions, indicate features related to optimizing or tracking the mutability of variables within script contexts.

    * **`NativeContext`:** This appears to be a specialized context, likely representing the global environment for a particular realm or iframe. Methods like `ResetErrorsThrown` and `IncrementErrorsThrown` suggest tracking runtime errors.

    * **Promise Hooks (`RunPromiseHook`):** The conditional compilation based on `V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS` and the function's logic indicate it's responsible for executing user-defined hooks at various stages of promise lifecycle.

5. **Relate to JavaScript (and Provide Examples):**  As functionalities are identified, the next step is to connect them to corresponding JavaScript concepts.

    * **Scope and Variable Lookup:** The `Context::Lookup` function directly implements the JavaScript scope chain and variable resolution rules. The examples with nested functions, `with` statements, and module imports illustrate these concepts.

    * **Global Objects:** The `global_object()` method clearly links to the JavaScript global object (e.g., `window` in browsers, `global` in Node.js).

    * **Modules:** The `module()` method relates to JavaScript modules and how V8 manages their scope and exports/imports.

    * **`with` statement:** The code explicitly handles `WithContext`, directly corresponding to the JavaScript `with` statement.

    * **`let` and `const`:** The context side property logic, particularly with constant tracking, directly relates to the behavior of `let` and `const` declarations in JavaScript.

    * **Promise Hooks:**  The `RunPromiseHook` function clearly maps to the JavaScript Promise Hooks API.

6. **Identify Potential Programming Errors:** Based on the understanding of the code, think about common mistakes JavaScript developers might make that this code is designed to handle or that relate to the concepts it manages.

    * **Scope Issues:**  Misunderstanding scope, especially with closures and `with`, is a common error.

    * **`with` statement (Anti-pattern):** The code's handling of `with` provides an opportunity to mention why it's generally discouraged.

    * **`let` and `const` Re-declaration/Re-assignment:** The constant tracking logic links to errors related to trying to reassign `const` variables or redeclaring `let` variables in the same scope.

7. **Construct Input/Output Examples (for Logical Reasoning):** For functions with clear logic, create simple input scenarios and predict the output. The `ScriptContextTable::Add` and `Context::Lookup` functions are good candidates for this. The goal is to illustrate how the data structures are modified and how lookups work.

8. **Structure the Answer:** Organize the findings into logical sections as requested: functionalities, relation to JavaScript, examples, code logic reasoning, and common errors. Use clear and concise language.

9. **Review and Refine:** After drafting the answer, reread it to ensure accuracy, clarity, and completeness. Check that all parts of the original request have been addressed. For instance, double-check the `.tq` answer. Ensure the JavaScript examples are correct and illustrative.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `ScriptContextTable` is just a simple array of contexts.
* **Correction:**  The presence of `NameToIndexHashTable` and the `Lookup` method suggests it's optimized for name-based lookups, not just index-based access.

* **Initial thought:** The context side properties are just about storing extra data.
* **Refinement:** The logic related to `kConst`, `kMutableHeapNumber`, and deoptimization hints at performance optimizations and potentially how V8 tracks immutability for optimization purposes.

By following this iterative and analytical process, we can systematically dissect the C++ code and generate a comprehensive and informative explanation.
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/contexts.h"

#include <optional>

#include "src/ast/modules.h"
#include "src/debug/debug.h"
#include "src/execution/isolate-inl.h"
#include "src/init/bootstrapper.h"
#include "src/objects/dependent-code.h"
#include "src/objects/heap-number.h"
#include "src/objects/module-inl.h"
#include "src/objects/property-cell.h"
#include "src/objects/string-set-inl.h"

namespace v8::internal {

// static
Handle<ScriptContextTable> ScriptContextTable::New(Isolate* isolate,
                                                   int capacity,
                                                   AllocationType allocation) {
  // ... implementation ...
}

namespace {

// Adds local names from `script_context` to the hash table.
Handle<NameToIndexHashTable> AddLocalNamesFromContext(
    Isolate* isolate, Handle<NameToIndexHashTable> names_table,
    DirectHandle<Context> script_context, bool ignore_duplicates,
    int script_context_index) {
  // ... implementation ...
}

}  // namespace

Handle<ScriptContextTable> ScriptContextTable::Add(
    Isolate* isolate, Handle<ScriptContextTable> table,
    DirectHandle<Context> script_context, bool ignore_duplicates) {
  // ... implementation ...
}

void Context::Initialize(Isolate* isolate) {
  // ... implementation ...
}

bool ScriptContextTable::Lookup(Handle<String> name,
                                VariableLookupResult* result) {
  // ... implementation ...
}

bool Context::is_declaration_context() const {
  // ... implementation ...
}

Tagged<Context> Context::declaration_context() const {
  // ... implementation ...
}

Tagged<Context> Context::closure_context() const {
  // ... implementation ...
}

Tagged<JSObject> Context::extension_object() const {
  // ... implementation ...
}

Tagged<JSReceiver> Context::extension_receiver() const {
  // ... implementation ...
}

Tagged<SourceTextModule> Context::module() const {
  // ... implementation ...
}

Tagged<JSGlobalObject> Context::global_object() const {
  // ... implementation ...
}

Tagged<Context> Context::script_context() const {
  // ... implementation ...
}

Tagged<JSGlobalProxy> Context::global_proxy() const {
  // ... implementation ...
}

/**
 * Lookups a property in an object environment, taking the unscopables into
 * account. This is used For HasBinding spec algorithms for ObjectEnvironment.
 */
static Maybe<bool> UnscopableLookup(LookupIterator* it, bool is_with_context) {
  // ... implementation ...
}

static PropertyAttributes GetAttributesForMode(VariableMode mode) {
  // ... implementation ...
}

// static
Handle<Object> Context::Lookup(Handle<Context> context, Handle<String> name,
                               ContextLookupFlags flags, int* index,
                               PropertyAttributes* attributes,
                               InitializationFlag* init_flag,
                               VariableMode* variable_mode,
                               bool* is_sloppy_function_name) {
  // ... implementation ...
}

Tagged<ContextSidePropertyCell> Context::GetOrCreateContextSidePropertyCell(
    DirectHandle<Context> script_context, size_t index,
    ContextSidePropertyCell::Property property, Isolate* isolate) {
  // ... implementation ...
}

std::optional<ContextSidePropertyCell::Property>
Context::GetScriptContextSideProperty(size_t index) const {
  // ... implementation ...
}

namespace {
bool IsMutableHeapNumber(DirectHandle<Context> script_context, int index,
                         DirectHandle<Object> value) {
  // ... implementation ...
}
}  // namespace

DirectHandle<Object> Context::LoadScriptContextElement(
    DirectHandle<Context> script_context, int index, DirectHandle<Object> value,
    Isolate* isolate) {
  // ... implementation ...
}

void Context::StoreScriptContextAndUpdateSlotProperty(
    DirectHandle<Context> script_context, int index,
    DirectHandle<Object> new_value, Isolate* isolate) {
  // ... implementation ...
}

bool NativeContext::HasTemplateLiteralObject(Tagged<JSArray> array) {
  // ... implementation ...
}

Handle<Object> Context::ErrorMessageForCodeGenerationFromStrings() {
  // ... implementation ...
}

Handle<Object> Context::ErrorMessageForWasmCodeGeneration() {
  // ... implementation ...
}

#ifdef VERIFY_HEAP
namespace {
// TODO(v8:12298): Fix js-context-specialization cctests to set up full
// native contexts instead of using dummy internalized strings as
// extensions.
bool IsContexExtensionTestObject(Tagged<HeapObject> extension) {
  return IsInternalizedString(extension) &&
         Cast<String>(extension)->length() == 1;
}
}  // namespace

void Context::VerifyExtensionSlot(Tagged<HeapObject> extension) {
  // ... implementation ...
}
#endif  // VERIFY_HEAP

void Context::set_extension(Tagged<HeapObject> object, WriteBarrierMode mode) {
  // ... implementation ...
}

#ifdef DEBUG

bool Context::IsBootstrappingOrValidParentContext(Tagged<Object> object,
                                                  Tagged<Context> child) {
  // ... implementation ...
}

#endif

void NativeContext::ResetErrorsThrown() { set_errors_thrown(Smi::FromInt(0)); }

void NativeContext::IncrementErrorsThrown() {
  // ... implementation ...
}

int NativeContext::GetErrorsThrown() { return errors_thrown().value(); }

static_assert(Context::MIN_CONTEXT_SLOTS == 2);
static_assert(Context::MIN_CONTEXT_EXTENDED_SLOTS == 3);
static_assert(NativeContext::kScopeInfoOffset ==
              Context::OffsetOfElementAt(NativeContext::SCOPE_INFO_INDEX));
static_assert(NativeContext::kPreviousOffset ==
              Context::OffsetOfElementAt(NativeContext::PREVIOUS_INDEX));
static_assert(NativeContext::kExtensionOffset ==
              Context::OffsetOfElementAt(NativeContext::EXTENSION_INDEX));

static_assert(NativeContext::kStartOfStrongFieldsOffset ==
              Context::OffsetOfElementAt(-1));
static_assert(NativeContext::kStartOfWeakFieldsOffset ==
              Context::OffsetOfElementAt(NativeContext::FIRST_WEAK_SLOT));
static_assert(NativeContext::kMicrotaskQueueOffset ==
              Context::SizeFor(NativeContext::NATIVE_CONTEXT_SLOTS));
static_assert(NativeContext::kSize ==
              (Context::SizeFor(NativeContext::NATIVE_CONTEXT_SLOTS) +
               kSystemPointerSize));

#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
void NativeContext::RunPromiseHook(PromiseHookType type,
                                   Handle<JSPromise> promise,
                                   Handle<Object> parent) {
  // ... implementation ...
}
#endif

}  // namespace v8::internal
```

### 功能列举

`v8/src/objects/contexts.cc` 文件的主要功能是定义和管理 V8 引擎中的执行上下文（Contexts）。执行上下文是 JavaScript 代码执行的环境，它包含了变量、函数、作用域链等信息。

具体来说，该文件实现了以下功能：

1. **定义了 `Context` 类及其子类 `NativeContext` 和相关的数据结构 `ScriptContextTable`:**
   - `Context` 类是所有上下文对象的基类，它维护了上下文的基本信息，如作用域信息 (`ScopeInfo`)、父上下文 (`previous`)、扩展对象 (`extension`) 等。
   - `NativeContext` 类代表全局上下文，例如浏览器中的 `window` 对象或 Node.js 中的 `global` 对象。它还包含了一些全局级别的状态，如错误计数。
   - `ScriptContextTable` 类用于管理脚本级别的上下文，它是一个哈希表，用于存储脚本中声明的全局变量和函数。

2. **实现了上下文的创建和初始化:**
   - `ScriptContextTable::New` 用于创建新的脚本上下文表。
   - `Context::Initialize` 用于初始化上下文中的局部变量。

3. **实现了变量的查找 (Lexical Scope Resolution):**
   - `Context::Lookup` 函数是核心，它负责在当前上下文及其父上下文中查找变量。这个过程模拟了 JavaScript 的作用域链查找规则。
   - `ScriptContextTable::Lookup` 用于在脚本上下文表中查找全局变量。

4. **管理上下文的扩展对象:**
   - 上下文可以关联一个扩展对象，例如 `with` 语句创建的临时对象或者模块的命名空间对象。
   - 相关的函数如 `extension_object()`, `extension_receiver()` 用于获取这些扩展对象。

5. **处理模块上下文:**
   - 包含了与 JavaScript 模块相关的逻辑，如获取模块对象 (`module()`).

6. **管理与 `let` 和 `const` 声明相关的上下文侧属性:**
   - `ContextSidePropertyCell` 及其相关函数用于优化和跟踪 `let` 和 `const` 变量的状态，例如是否已被初始化或是否是常量。

7. **提供错误处理相关的功能:**
   - `NativeContext` 中包含了记录错误次数的功能 (`ResetErrorsThrown`, `IncrementErrorsThrown`, `GetErrorsThrown`).
   - `ErrorMessageForCodeGenerationFromStrings`, `ErrorMessageForWasmCodeGeneration` 用于获取特定场景下的错误消息。

8. **支持 Promise Hooks (如果启用):**
   - `NativeContext::RunPromiseHook` 用于在 Promise 的生命周期中执行用户定义的回调函数。

### 关于 .tq 扩展名

如果 `v8/src/objects/contexts.cc` 以 `.tq` 结尾，那么它将是一个 **v8 Torque 源代码**文件。Torque 是 V8 开发的一种用于定义内置函数和对象的领域特定语言。由于该文件以 `.cc` 结尾，所以它是一个标准的 C++ 源代码文件。

### 与 JavaScript 功能的关系及举例说明

`v8/src/objects/contexts.cc` 文件中的代码直接支持着 JavaScript 的作用域和变量查找机制。以下是一些 JavaScript 功能与该文件中代码的对应关系：

1. **作用域链和变量查找:** `Context::Lookup` 函数模拟了 JavaScript 的作用域链。当 JavaScript 引擎需要查找一个变量时，它会从当前上下文开始，逐级向上查找父上下文，直到找到该变量或到达全局上下文。

   ```javascript
   function outer() {
     const outerVar = 'outer';
     function inner() {
       console.log(outerVar); // 引擎需要向上查找 outerVar
     }
     inner();
   }
   outer();
   ```
   在这个例子中，当 `inner` 函数尝试访问 `outerVar` 时，V8 会使用类似 `Context::Lookup` 的机制在 `inner` 函数的上下文和 `outer` 函数的上下文中查找 `outerVar`。

2. **全局变量和脚本上下文:** `ScriptContextTable` 存储了脚本级别的全局变量。

   ```javascript
   var globalVar = 'global'; // 这个变量会被存储在脚本上下文中

   function accessGlobal() {
     console.log(globalVar);
   }
   accessGlobal();
   ```
   V8 会将 `globalVar` 存储在脚本上下文中，并通过 `ScriptContextTable` 进行管理和查找。

3. **`with` 语句:** `Context` 类中与 `extension_object` 和 `extension_receiver` 相关的代码支持 `with` 语句。

   ```javascript
   const obj = { a: 1, b: 2 };
   with (obj) {
     console.log(a + b); // V8 需要在 obj 的上下文中查找 a 和 b
   }
   ```
   当执行 `with (obj)` 时，V8 会创建一个新的上下文，并将 `obj` 作为其扩展对象。在 `with` 语句块中查找变量时，会先在这个扩展对象中查找。

4. **模块 (Modules):** `Context` 类中的 `module()` 方法以及相关的逻辑支持 JavaScript 模块的导入和导出。

   ```javascript
   // module.js
   export const message = 'Hello';

   // main.js
   import { message } from './module.js';
   console.log(message);
   ```
   V8 会为每个模块创建一个模块上下文，并通过 `Context::module()` 等方法来管理模块的命名空间。

5. **`let` 和 `const` 的作用域:** `ContextSidePropertyCell` 及其相关逻辑支持 `let` 和 `const` 的块级作用域和常量特性。

   ```javascript
   function example() {
     let x = 10;
     const y = 20;
     if (true) {
       let x = 30; // 内部作用域的 x
       // y = 40; // 错误：尝试修改常量
       console.log(x, y);
     }
     console.log(x, y);
   }
   example();
   ```
   V8 使用上下文侧属性来跟踪 `let` 和 `const` 变量的状态，确保它们遵循块级作用域规则，并且 `const` 变量不会被重新赋值。

### 代码逻辑推理 (假设输入与输出)

考虑 `ScriptContextTable::Add` 函数，其功能是向脚本上下文表中添加一个新的脚本上下文。

**假设输入:**

- `isolate`: 当前 V8 引擎的隔离区。
- `table`: 一个已存在的 `ScriptContextTable` 对象（可能为空）。
- `script_context`: 一个新的 `Context` 对象，代表要添加的脚本上下文。假设这个上下文中声明了一个变量 `myVar`。
- `ignore_duplicates`: `false`。

**代码逻辑推理:**

1. **检查容量:** `Add` 函数首先检查 `table` 的容量是否已满。如果已满，则会创建一个新的、容量更大的 `ScriptContextTable`，并将旧表中的内容复制到新表。
2. **添加本地名称:** 调用 `AddLocalNamesFromContext` 函数，将 `script_context` 中声明的局部变量（例如 `myVar`) 添加到 `table` 的 `names_to_context_index_` 哈希表中，并关联到新添加的上下文的索引。
3. **添加上下文:** 将 `script_context` 添加到 `table` 的数组中。
4. **更新长度:** 更新 `table` 的长度。

**预期输出:**

- `table` 对象现在包含了新添加的 `script_context`。
- `table` 的 `names_to_context_index_` 哈希表中包含了 `myVar` 及其对应于新添加的 `script_context` 的索引。
- `table` 的长度增加了 1。

考虑 `Context::Lookup` 函数，其功能是在上下文中查找变量。

**假设输入:**

- `context`: 当前执行的上下文，假设是一个函数上下文，其父上下文是一个脚本上下文。
- `name`: 要查找的变量名，例如 `"myVar"`.
- `flags`: `FOLLOW_CONTEXT_CHAIN`，表示需要向上查找父上下文。
- `index`, `attributes`, `init_flag`, `variable_mode`, `is_sloppy_function_name`: 输出参数。

**代码逻辑推理:**

1. **在当前上下文查找:** `Lookup` 函数首先在当前函数上下文中查找 `myVar`。如果找不到，则会继续向上查找父上下文。
2. **在父上下文查找:** 假设 `myVar` 是在脚本上下文中声明的全局变量，那么 `Lookup` 会在脚本上下文中找到它（可能通过 `ScriptContextTable::Lookup`）。
3. **设置输出参数:** 如果找到 `myVar`，则会将相应的索引、属性、初始化标志和变量模式设置到输出参数中。

**预期输出:**

- 返回值: 指向包含 `myVar` 的上下文对象（脚本上下文）。
- `index`: `myVar` 在脚本上下文中的槽位索引。
- `attributes`: `myVar` 的属性（例如，是否可写）。
- `variable_mode`: `myVar` 的变量模式（例如，`VAR`, `LET`, `CONST`）。

### 用户常见的编程错误

该文件中的代码与许多常见的 JavaScript 编程错误相关，特别是与作用域和变量声明相关的错误：

1. **未声明的变量:** 如果在代码中使用了未声明的变量，`Context::Lookup` 将无法找到该变量，导致 `ReferenceError`。

   ```javascript
   function example() {
     console.log(undeclaredVar); // ReferenceError: undeclaredVar is not defined
   }
   example();
   ```

2. **作用域混淆:**  对作用域理解不足可能导致访问到错误的变量或无法访问到预期的变量。

   ```javascript
   function outer() {
     var localVar = 'outer';
     function inner() {
       // console.log(localVar); // 可以访问 outer 的 localVar
     }
     console.log(localVar); // 可以访问 outer 的 localVar
     inner();
   }
   outer();

   function anotherOuter() {
     if (true) {
       var blockVar = 'inside';
       let blockLet = 'inside_let';
     }
     console.log(blockVar); // 可以访问，var 没有块级作用域
     // console.log(blockLet); // 错误：blockLet 是块级作用域
   }
   anotherOuter();
   ```
   V8 的上下文管理确保了 `var` 的函数作用域和 `let`/`const` 的块级作用域的正确行为。

3. **在 `const` 变量声明前访问:**  `const` 变量必须在声明时初始化，并且在其声明之前不能访问，这与 `ContextSidePropertyCell` 的初始化状态跟踪有关。

   ```javascript
   function example() {
     // console.log(myConst); // 错误：Cannot access 'myConst' before initialization
     const myConst = 10;
     console.log(myConst);
   }
   example();
   ```

4. **尝试修改 `const` 变量:**  尝试重新赋值 `const` 变量会导致 `TypeError`，这与 `ContextSidePropertyCell` 对常量状态的跟踪和保护有关。

   ```javascript
   function example() {
     const myConst = 10;
     // myConst = 20; // TypeError: Assignment to constant variable.
   }
   example();
   ```

5. **滥用 `with` 语句:** 虽然 `with` 语句由 `Context` 类支持，但过度使用或不当使用 `with` 会使代码难以理解和调试，因为它会动态改变作用域。

   ```javascript
   const config = { database: 'mydb', user: 'admin' };
   with (config) {
     console.log(database, user); // 看上去简洁，但作用域不清晰
   }
   ```
   V8 的上下文机制正确地实现了 `with` 语句的作用域，但也暴露了其可能带来的作用域混乱问题。

理解 `v8/src/objects/contexts.cc` 的功能有助于深入理解 JavaScript 引擎的工作原理，特别是关于作用域、变量查找和上下文管理的部分。

Prompt: 
```
这是目录为v8/src/objects/contexts.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/contexts.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/contexts.h"

#include <optional>

#include "src/ast/modules.h"
#include "src/debug/debug.h"
#include "src/execution/isolate-inl.h"
#include "src/init/bootstrapper.h"
#include "src/objects/dependent-code.h"
#include "src/objects/heap-number.h"
#include "src/objects/module-inl.h"
#include "src/objects/property-cell.h"
#include "src/objects/string-set-inl.h"

namespace v8::internal {

// static
Handle<ScriptContextTable> ScriptContextTable::New(Isolate* isolate,
                                                   int capacity,
                                                   AllocationType allocation) {
  DCHECK_GE(capacity, 0);
  DCHECK_LE(capacity, kMaxCapacity);

  auto names = NameToIndexHashTable::New(isolate, 16);

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<ScriptContextTable> result =
      Allocate(isolate, capacity, &no_gc, allocation);
  result->set_length(0, kReleaseStore);
  result->set_names_to_context_index(*names);
  ReadOnlyRoots roots{isolate};
  MemsetTagged(result->RawFieldOfFirstElement(), roots.undefined_value(),
               capacity);
  return result;
}

namespace {

// Adds local names from `script_context` to the hash table.
Handle<NameToIndexHashTable> AddLocalNamesFromContext(
    Isolate* isolate, Handle<NameToIndexHashTable> names_table,
    DirectHandle<Context> script_context, bool ignore_duplicates,
    int script_context_index) {
  ReadOnlyRoots roots(isolate);
  Handle<ScopeInfo> scope_info(script_context->scope_info(), isolate);
  int local_count = scope_info->ContextLocalCount();
  names_table = names_table->EnsureCapacity(isolate, names_table, local_count);

  for (auto it : ScopeInfo::IterateLocalNames(scope_info)) {
    Handle<Name> name(it->name(), isolate);
    if (ignore_duplicates) {
      int32_t hash = NameToIndexShape::Hash(roots, name);
      if (names_table->FindEntry(isolate, roots, name, hash).is_found()) {
        continue;
      }
    }
    names_table = NameToIndexHashTable::Add(isolate, names_table, name,
                                            script_context_index);
  }

  return names_table;
}

}  // namespace

Handle<ScriptContextTable> ScriptContextTable::Add(
    Isolate* isolate, Handle<ScriptContextTable> table,
    DirectHandle<Context> script_context, bool ignore_duplicates) {
  DCHECK(script_context->IsScriptContext());

  int old_length = table->length(kAcquireLoad);
  int new_length = old_length + 1;
  DCHECK_LE(0, old_length);

  Handle<ScriptContextTable> result = table;
  int old_capacity = table->capacity();
  DCHECK_LE(old_length, old_capacity);
  if (old_length == old_capacity) {
    int new_capacity = NewCapacityForIndex(old_length, old_capacity);
    auto new_table = New(isolate, new_capacity);
    new_table->set_length(old_length, kReleaseStore);
    new_table->set_names_to_context_index(table->names_to_context_index());
    CopyElements(isolate, *new_table, 0, *table, 0, old_length);
    result = new_table;
  }

  Handle<NameToIndexHashTable> names_table(result->names_to_context_index(),
                                           isolate);
  names_table = AddLocalNamesFromContext(isolate, names_table, script_context,
                                         ignore_duplicates, old_length);
  result->set_names_to_context_index(*names_table);

  result->set(old_length, *script_context, kReleaseStore);
  result->set_length(new_length, kReleaseStore);
  return result;
}

void Context::Initialize(Isolate* isolate) {
  Tagged<ScopeInfo> scope_info = this->scope_info();
  int header = scope_info->ContextHeaderLength();
  for (int var = 0; var < scope_info->ContextLocalCount(); var++) {
    if (scope_info->ContextLocalInitFlag(var) == kNeedsInitialization) {
      set(header + var, ReadOnlyRoots(isolate).the_hole_value());
    }
  }
}

bool ScriptContextTable::Lookup(Handle<String> name,
                                VariableLookupResult* result) {
  DisallowGarbageCollection no_gc;
  int index = names_to_context_index()->Lookup(name);
  if (index == -1) return false;
  DCHECK_LE(0, index);
  DCHECK_LT(index, length(kAcquireLoad));
  Tagged<Context> context = get(index);
  DCHECK(context->IsScriptContext());
  int slot_index = context->scope_info()->ContextSlotIndex(name, result);
  if (slot_index < 0) return false;
  result->context_index = index;
  result->slot_index = slot_index;
  return true;
}

bool Context::is_declaration_context() const {
  if (IsFunctionContext() || IsNativeContext(*this) || IsScriptContext() ||
      IsModuleContext()) {
    return true;
  }
  if (IsEvalContext()) {
    return scope_info()->language_mode() == LanguageMode::kStrict;
  }
  if (!IsBlockContext()) return false;
  return scope_info()->is_declaration_scope();
}

Tagged<Context> Context::declaration_context() const {
  Tagged<Context> current = *this;
  while (!current->is_declaration_context()) {
    current = current->previous();
  }
  return current;
}

Tagged<Context> Context::closure_context() const {
  Tagged<Context> current = *this;
  while (!current->IsFunctionContext() && !current->IsScriptContext() &&
         !current->IsModuleContext() && !IsNativeContext(current) &&
         !current->IsEvalContext()) {
    current = current->previous();
  }
  return current;
}

Tagged<JSObject> Context::extension_object() const {
  DCHECK(IsNativeContext(*this) || IsFunctionContext() || IsBlockContext() ||
         IsEvalContext() || IsCatchContext());
  Tagged<HeapObject> object = extension();
  if (IsUndefined(object)) return JSObject();
  DCHECK(IsJSContextExtensionObject(object) ||
         (IsNativeContext(*this) && IsJSGlobalObject(object)));
  return Cast<JSObject>(object);
}

Tagged<JSReceiver> Context::extension_receiver() const {
  DCHECK(IsNativeContext(*this) || IsWithContext() || IsEvalContext() ||
         IsFunctionContext() || IsBlockContext());
  return IsWithContext() ? Cast<JSReceiver>(extension()) : extension_object();
}

Tagged<SourceTextModule> Context::module() const {
  Tagged<Context> current = *this;
  while (!current->IsModuleContext()) {
    current = current->previous();
  }
  return Cast<SourceTextModule>(current->extension());
}

Tagged<JSGlobalObject> Context::global_object() const {
  return Cast<JSGlobalObject>(native_context()->extension());
}

Tagged<Context> Context::script_context() const {
  Tagged<Context> current = *this;
  while (!current->IsScriptContext()) {
    current = current->previous();
  }
  return current;
}

Tagged<JSGlobalProxy> Context::global_proxy() const {
  return native_context()->global_proxy_object();
}

/**
 * Lookups a property in an object environment, taking the unscopables into
 * account. This is used For HasBinding spec algorithms for ObjectEnvironment.
 */
static Maybe<bool> UnscopableLookup(LookupIterator* it, bool is_with_context) {
  Isolate* isolate = it->isolate();

  Maybe<bool> found = JSReceiver::HasProperty(it);
  if (!is_with_context || found.IsNothing() || !found.FromJust()) return found;

  Handle<Object> unscopables;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unscopables,
      JSReceiver::GetProperty(isolate, Cast<JSReceiver>(it->GetReceiver()),
                              isolate->factory()->unscopables_symbol()),
      Nothing<bool>());
  if (!IsJSReceiver(*unscopables)) return Just(true);
  Handle<Object> blocklist;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, blocklist,
      JSReceiver::GetProperty(isolate, Cast<JSReceiver>(unscopables),
                              it->name()),
      Nothing<bool>());
  return Just(!Object::BooleanValue(*blocklist, isolate));
}

static PropertyAttributes GetAttributesForMode(VariableMode mode) {
  DCHECK(IsSerializableVariableMode(mode));
  return IsImmutableLexicalOrPrivateVariableMode(mode) ? READ_ONLY : NONE;
}

// static
Handle<Object> Context::Lookup(Handle<Context> context, Handle<String> name,
                               ContextLookupFlags flags, int* index,
                               PropertyAttributes* attributes,
                               InitializationFlag* init_flag,
                               VariableMode* variable_mode,
                               bool* is_sloppy_function_name) {
  Isolate* isolate = context->GetIsolate();

  bool follow_context_chain = (flags & FOLLOW_CONTEXT_CHAIN) != 0;
  bool has_seen_debug_evaluate_context = false;
  *index = kNotFound;
  *attributes = ABSENT;
  *init_flag = kCreatedInitialized;
  *variable_mode = VariableMode::kVar;
  if (is_sloppy_function_name != nullptr) {
    *is_sloppy_function_name = false;
  }

  if (v8_flags.trace_contexts) {
    PrintF("Context::Lookup(");
    ShortPrint(*name);
    PrintF(")\n");
  }

  do {
    if (v8_flags.trace_contexts) {
      PrintF(" - looking in context %p",
             reinterpret_cast<void*>(context->ptr()));
      if (context->IsScriptContext()) PrintF(" (script context)");
      if (IsNativeContext(*context)) PrintF(" (native context)");
      if (context->IsDebugEvaluateContext()) PrintF(" (debug context)");
      PrintF("\n");
    }

    // 1. Check global objects, subjects of with, and extension objects.
    DCHECK_IMPLIES(context->IsEvalContext() && context->has_extension(),
                   IsTheHole(context->extension(), isolate));
    if ((IsNativeContext(*context) || context->IsWithContext() ||
         context->IsFunctionContext() || context->IsBlockContext()) &&
        context->has_extension() && !context->extension_receiver().is_null()) {
      Handle<JSReceiver> object(context->extension_receiver(), isolate);

      if (IsNativeContext(*context)) {
        DisallowGarbageCollection no_gc;
        if (v8_flags.trace_contexts) {
          PrintF(" - trying other script contexts\n");
        }
        // Try other script contexts.
        Tagged<ScriptContextTable> script_contexts =
            context->native_context()->script_context_table();
        VariableLookupResult r;
        if (script_contexts->Lookup(name, &r)) {
          Tagged<Context> script_context =
              script_contexts->get(r.context_index);
          if (v8_flags.trace_contexts) {
            PrintF("=> found property in script context %d: %p\n",
                   r.context_index,
                   reinterpret_cast<void*>(script_context.ptr()));
          }
          *index = r.slot_index;
          *variable_mode = r.mode;
          *init_flag = r.init_flag;
          *attributes = GetAttributesForMode(r.mode);
          return handle(script_context, isolate);
        }
      }

      // Context extension objects needs to behave as if they have no
      // prototype.  So even if we want to follow prototype chains, we need
      // to only do a local lookup for context extension objects.
      Maybe<PropertyAttributes> maybe = Nothing<PropertyAttributes>();
      if ((flags & FOLLOW_PROTOTYPE_CHAIN) == 0 ||
          IsJSContextExtensionObject(*object)) {
        maybe = JSReceiver::GetOwnPropertyAttributes(object, name);
      } else {
        // A with context will never bind "this", but debug-eval may look into
        // a with context when resolving "this". Other synthetic variables such
        // as new.target may be resolved as VariableMode::kDynamicLocal due to
        // bug v8:5405 , skipping them here serves as a workaround until a more
        // thorough fix can be applied.
        // TODO(v8:5405): Replace this check with a DCHECK when resolution of
        // of synthetic variables does not go through this code path.
        if (ScopeInfo::VariableIsSynthetic(*name)) {
          maybe = Just(ABSENT);
        } else {
          LookupIterator it(isolate, object, name, object);
          Maybe<bool> found = UnscopableLookup(&it, context->IsWithContext());
          if (found.IsNothing()) {
            maybe = Nothing<PropertyAttributes>();
          } else {
            // Luckily, consumers of |maybe| only care whether the property
            // was absent or not, so we can return a dummy |NONE| value
            // for its attributes when it was present.
            maybe = Just(found.FromJust() ? NONE : ABSENT);
          }
        }
      }

      if (maybe.IsNothing()) return Handle<Object>();
      DCHECK(!isolate->has_exception());
      *attributes = maybe.FromJust();

      if (maybe.FromJust() != ABSENT) {
        if (v8_flags.trace_contexts) {
          PrintF("=> found property in context object %p\n",
                 reinterpret_cast<void*>(object->ptr()));
        }
        return object;
      }
    }

    // 2. Check the context proper if it has slots.
    if (context->IsFunctionContext() || context->IsBlockContext() ||
        context->IsScriptContext() || context->IsEvalContext() ||
        context->IsModuleContext() || context->IsCatchContext()) {
      DisallowGarbageCollection no_gc;
      // Use serialized scope information of functions and blocks to search
      // for the context index.
      Tagged<ScopeInfo> scope_info = context->scope_info();
      VariableLookupResult lookup_result;
      int slot_index = scope_info->ContextSlotIndex(name, &lookup_result);
      DCHECK(slot_index < 0 || slot_index >= MIN_CONTEXT_SLOTS);
      if (slot_index >= 0) {
        // Re-direct lookup to the ScriptContextTable in case we find a hole in
        // a REPL script context. REPL scripts allow re-declaration of
        // script-level let bindings. The value itself is stored in the script
        // context of the first script that declared a variable, all other
        // script contexts will contain 'the hole' for that particular name.
        if (scope_info->IsReplModeScope() &&
            IsTheHole(context->get(slot_index), isolate)) {
          context = Handle<Context>(context->previous(), isolate);
          continue;
        }

        if (v8_flags.trace_contexts) {
          PrintF("=> found local in context slot %d (mode = %hhu)\n",
                 slot_index, static_cast<uint8_t>(lookup_result.mode));
        }
        *index = slot_index;
        *variable_mode = lookup_result.mode;
        *init_flag = lookup_result.init_flag;
        *attributes = GetAttributesForMode(lookup_result.mode);
        return context;
      }

      // Check the slot corresponding to the intermediate context holding
      // only the function name variable. It's conceptually (and spec-wise)
      // in an outer scope of the function's declaration scope.
      if (follow_context_chain && context->IsFunctionContext()) {
        int function_index = scope_info->FunctionContextSlotIndex(*name);
        if (function_index >= 0) {
          if (v8_flags.trace_contexts) {
            PrintF("=> found intermediate function in context slot %d\n",
                   function_index);
          }
          *index = function_index;
          *attributes = READ_ONLY;
          *init_flag = kCreatedInitialized;
          *variable_mode = VariableMode::kConst;
          if (is_sloppy_function_name != nullptr &&
              is_sloppy(scope_info->language_mode())) {
            *is_sloppy_function_name = true;
          }
          return context;
        }
      }

      // Lookup variable in module imports and exports.
      if (context->IsModuleContext()) {
        VariableMode mode;
        InitializationFlag flag;
        MaybeAssignedFlag maybe_assigned_flag;
        int cell_index =
            scope_info->ModuleIndex(*name, &mode, &flag, &maybe_assigned_flag);
        if (cell_index != 0) {
          if (v8_flags.trace_contexts) {
            PrintF("=> found in module imports or exports\n");
          }
          *index = cell_index;
          *variable_mode = mode;
          *init_flag = flag;
          *attributes = SourceTextModuleDescriptor::GetCellIndexKind(
                            cell_index) == SourceTextModuleDescriptor::kExport
                            ? GetAttributesForMode(mode)
                            : READ_ONLY;
          return handle(context->module(), isolate);
        }
      }
    } else if (context->IsDebugEvaluateContext()) {
      has_seen_debug_evaluate_context = true;

      // Check materialized locals.
      Tagged<Object> ext = context->get(EXTENSION_INDEX);
      if (IsJSReceiver(ext)) {
        Handle<JSReceiver> extension(Cast<JSReceiver>(ext), isolate);
        LookupIterator it(isolate, extension, name, extension);
        Maybe<bool> found = JSReceiver::HasProperty(&it);
        if (found.FromMaybe(false)) {
          *attributes = NONE;
          return extension;
        }
      }

      // Check the original context, but do not follow its context chain.
      Tagged<Object> obj = context->get(WRAPPED_CONTEXT_INDEX);
      if (IsContext(obj)) {
        Handle<Context> wrapped_context(Cast<Context>(obj), isolate);
        Handle<Object> result =
            Context::Lookup(wrapped_context, name, DONT_FOLLOW_CHAINS, index,
                            attributes, init_flag, variable_mode);
        if (!result.is_null()) return result;
      }
    }

    // 3. Prepare to continue with the previous (next outermost) context.
    if (IsNativeContext(*context)) break;

    // In case we saw any DebugEvaluateContext, we'll need to check the block
    // list before we can advance to properly "shadow" stack-allocated
    // variables.
    // Note that this implicitly skips the block list check for the
    // "wrapped" context lookup for DebugEvaluateContexts. In that case
    // `has_seen_debug_evaluate_context` will always be false.
    if (has_seen_debug_evaluate_context &&
        IsEphemeronHashTable(isolate->heap()->locals_block_list_cache())) {
      Handle<ScopeInfo> scope_info = handle(context->scope_info(), isolate);
      Tagged<Object> maybe_outer_block_list =
          isolate->LocalsBlockListCacheGet(scope_info);
      if (IsStringSet(maybe_outer_block_list) &&
          Cast<StringSet>(maybe_outer_block_list)->Has(isolate, name)) {
        if (v8_flags.trace_contexts) {
          PrintF(" - name is blocklisted. Aborting.\n");
        }
        break;
      }
    }

    context = Handle<Context>(context->previous(), isolate);
  } while (follow_context_chain);

  if (v8_flags.trace_contexts) {
    PrintF("=> no property/slot found\n");
  }
  return Handle<Object>::null();
}

Tagged<ContextSidePropertyCell> Context::GetOrCreateContextSidePropertyCell(
    DirectHandle<Context> script_context, size_t index,
    ContextSidePropertyCell::Property property, Isolate* isolate) {
  DCHECK(v8_flags.script_context_mutable_heap_number ||
         v8_flags.const_tracking_let);
  DCHECK(script_context->IsScriptContext());
  DCHECK_NE(property, ContextSidePropertyCell::kOther);
  int side_data_index =
      static_cast<int>(index - Context::MIN_CONTEXT_EXTENDED_SLOTS);
  DirectHandle<FixedArray> side_data(
      Cast<FixedArray>(script_context->get(CONTEXT_SIDE_TABLE_PROPERTY_INDEX)),
      isolate);
  Tagged<Object> object = side_data->get(side_data_index);
  if (!IsContextSidePropertyCell(object)) {
    // If these CHECKs fail, there's a code path which initializes or assigns a
    // top-level `let` variable but doesn't update the side data.
    object = *isolate->factory()->NewContextSidePropertyCell(property);
    side_data->set(side_data_index, object);
  }
  return Cast<ContextSidePropertyCell>(object);
}

std::optional<ContextSidePropertyCell::Property>
Context::GetScriptContextSideProperty(size_t index) const {
  DCHECK(v8_flags.script_context_mutable_heap_number ||
         v8_flags.const_tracking_let);
  DCHECK(IsScriptContext());
  int side_data_index =
      static_cast<int>(index - Context::MIN_CONTEXT_EXTENDED_SLOTS);
  Tagged<FixedArray> side_data =
      Cast<FixedArray>(get(CONTEXT_SIDE_TABLE_PROPERTY_INDEX));
  Tagged<Object> object = side_data->get(side_data_index);
  if (IsUndefined(object)) return {};
  if (IsContextSidePropertyCell(object)) {
    return Cast<ContextSidePropertyCell>(object)->context_side_property();
  }
  CHECK(IsSmi(object));
  return ContextSidePropertyCell::FromSmi(object.ToSmi());
}

namespace {
bool IsMutableHeapNumber(DirectHandle<Context> script_context, int index,
                         DirectHandle<Object> value) {
  DCHECK(v8_flags.script_context_mutable_heap_number);
  DCHECK(script_context->IsScriptContext());
  if (!IsHeapNumber(*value)) return false;
  const int side_data_index = index - Context::MIN_CONTEXT_EXTENDED_SLOTS;
  Tagged<FixedArray> side_data_table = Cast<FixedArray>(
      script_context->get(Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX));
  Tagged<Object> data = side_data_table->get(side_data_index);
  if (IsUndefined(data)) return false;
  if (IsSmi(data)) {
    return data.ToSmi().value() == ContextSidePropertyCell::kMutableHeapNumber;
  }
  CHECK(Is<ContextSidePropertyCell>(data));
  return Cast<ContextSidePropertyCell>(data)->context_side_property() ==
         ContextSidePropertyCell::kMutableHeapNumber;
}
}  // namespace

DirectHandle<Object> Context::LoadScriptContextElement(
    DirectHandle<Context> script_context, int index, DirectHandle<Object> value,
    Isolate* isolate) {
  DCHECK(v8_flags.script_context_mutable_heap_number);
  DCHECK(script_context->IsScriptContext());
  if (IsMutableHeapNumber(script_context, index, value)) {
    return isolate->factory()->NewHeapNumber(Cast<HeapNumber>(*value)->value());
  }
  return value;
}

void Context::StoreScriptContextAndUpdateSlotProperty(
    DirectHandle<Context> script_context, int index,
    DirectHandle<Object> new_value, Isolate* isolate) {
  DCHECK(v8_flags.const_tracking_let);
  DCHECK(script_context->IsScriptContext());

  DirectHandle<Object> old_value(script_context->get(index), isolate);
  const int side_data_index = index - Context::MIN_CONTEXT_EXTENDED_SLOTS;
  DirectHandle<FixedArray> side_data(
      Cast<FixedArray>(
          script_context->get(Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX)),
      isolate);

  if (IsTheHole(*old_value)) {
    // Setting the initial value. Here we cannot assert the corresponding side
    // data is `undefined` - that won't hold w/ variable redefinitions in REPL.
    side_data->set(side_data_index, ContextSidePropertyCell::Const());
    script_context->set(index, *new_value);
    return;
  }

  // If we are assigning the same value, the property won't change.
  if (*old_value == *new_value) {
    return;
  }
  // If both values are HeapNumbers with the same double value, the property
  // won't change either.
  if (Is<HeapNumber>(*old_value) && Is<HeapNumber>(*new_value) &&
      Cast<HeapNumber>(*old_value)->value() ==
          Cast<HeapNumber>(*new_value)->value()) {
    return;
  }

  // From now on, we know the value is no longer a constant.

  Tagged<Object> data = side_data->get(side_data_index);
  std::optional<Tagged<ContextSidePropertyCell>> maybe_cell;
  ContextSidePropertyCell::Property property;

  if (IsContextSidePropertyCell(data)) {
    maybe_cell = Cast<ContextSidePropertyCell>(data);
    property = maybe_cell.value()->context_side_property();
  } else {
    CHECK(IsSmi(data));
    property = ContextSidePropertyCell::FromSmi(data.ToSmi());
  }

  switch (property) {
    case ContextSidePropertyCell::kConst:
      if (maybe_cell) {
        DependentCode::DeoptimizeDependencyGroups(
            isolate, maybe_cell.value(),
            DependentCode::kScriptContextSlotPropertyChangedGroup);
      }
      if (v8_flags.script_context_mutable_heap_number) {
        // It can transition to Smi, MutableHeapNumber or Other.
        if (IsHeapNumber(*new_value)) {
          side_data->set(side_data_index,
                         ContextSidePropertyCell::MutableHeapNumber());
          Handle<HeapNumber> new_number = isolate->factory()->NewHeapNumber(
              Cast<HeapNumber>(*new_value)->value());
          script_context->set(index, *new_number);
        } else {
          side_data->set(side_data_index,
                         IsSmi(*new_value)
                             ? ContextSidePropertyCell::SmiMarker()
                             : ContextSidePropertyCell::Other());
          script_context->set(index, *new_value);
        }
      } else {
        // MutableHeapNumber is not supported, just transition the property to
        // kOther.
        side_data->set(side_data_index, ContextSidePropertyCell::Other());
        script_context->set(index, *new_value);
      }

      break;
    case ContextSidePropertyCell::kSmi:
      if (IsSmi(*new_value)) {
        script_context->set(index, *new_value);
      } else {
        if (maybe_cell) {
          DependentCode::DeoptimizeDependencyGroups(
              isolate, maybe_cell.value(),
              DependentCode::kScriptContextSlotPropertyChangedGroup);
        }
        // It can transition to a MutableHeapNumber or Other.
        if (IsHeapNumber(*new_value)) {
          side_data->set(side_data_index,
                         ContextSidePropertyCell::MutableHeapNumber());
          Handle<HeapNumber> new_number = isolate->factory()->NewHeapNumber(
              Cast<HeapNumber>(*new_value)->value());
          script_context->set(index, *new_number);
        } else {
          side_data->set(side_data_index, ContextSidePropertyCell::Other());
          script_context->set(index, *new_value);
        }
      }
      break;
    case ContextSidePropertyCell::kMutableHeapNumber:
      CHECK(IsHeapNumber(*old_value));
      if (IsSmi(*new_value)) {
        Cast<HeapNumber>(old_value)->set_value(
            static_cast<double>(Cast<Smi>(*new_value).value()));
      } else if (IsHeapNumber(*new_value)) {
        Cast<HeapNumber>(old_value)->set_value(
            Cast<HeapNumber>(*new_value)->value());
      } else {
        if (maybe_cell) {
          DependentCode::DeoptimizeDependencyGroups(
              isolate, maybe_cell.value(),
              DependentCode::kScriptContextSlotPropertyChangedGroup);
        }
        // It can only transition to Other.
        side_data->set(side_data_index, ContextSidePropertyCell::Other());
        script_context->set(index, *new_value);
      }
      break;
    case ContextSidePropertyCell::kOther:
      // We should not have a code depending on Other.
      DCHECK(!maybe_cell.has_value());
      // No need to update side data, this is a sink state...
      script_context->set(index, *new_value);
      break;
  }
}

bool NativeContext::HasTemplateLiteralObject(Tagged<JSArray> array) {
  return array->map() == js_array_template_literal_object_map();
}

Handle<Object> Context::ErrorMessageForCodeGenerationFromStrings() {
  Isolate* isolate = GetIsolate();
  Handle<Object> result(error_message_for_code_gen_from_strings(), isolate);
  if (!IsUndefined(*result, isolate)) return result;
  return isolate->factory()->NewStringFromStaticChars(
      "Code generation from strings disallowed for this context");
}

Handle<Object> Context::ErrorMessageForWasmCodeGeneration() {
  Isolate* isolate = GetIsolate();
  Handle<Object> result(error_message_for_wasm_code_gen(), isolate);
  if (!IsUndefined(*result, isolate)) return result;
  return isolate->factory()->NewStringFromStaticChars(
      "Wasm code generation disallowed by embedder");
}

#ifdef VERIFY_HEAP
namespace {
// TODO(v8:12298): Fix js-context-specialization cctests to set up full
// native contexts instead of using dummy internalized strings as
// extensions.
bool IsContexExtensionTestObject(Tagged<HeapObject> extension) {
  return IsInternalizedString(extension) &&
         Cast<String>(extension)->length() == 1;
}
}  // namespace

void Context::VerifyExtensionSlot(Tagged<HeapObject> extension) {
  CHECK(scope_info()->HasContextExtensionSlot());
  // Early exit for potentially uninitialized contexfts.
  if (IsUndefined(extension)) return;
  if (IsJSContextExtensionObject(extension)) {
    CHECK((IsBlockContext() && scope_info()->is_declaration_scope()) ||
          IsFunctionContext());
  } else if (IsModuleContext()) {
    CHECK(IsSourceTextModule(extension));
  } else if (IsDebugEvaluateContext() || IsWithContext()) {
    CHECK(IsJSReceiver(extension) ||
          (IsWithContext() && IsContexExtensionTestObject(extension)));
  } else if (IsNativeContext(*this)) {
    CHECK(IsJSGlobalObject(extension) ||
          IsContexExtensionTestObject(extension));
  } else if (IsScriptContext()) {
    // Host-defined options can be stored on the context for classic scripts.
    CHECK(IsFixedArray(extension));
  }
}
#endif  // VERIFY_HEAP

void Context::set_extension(Tagged<HeapObject> object, WriteBarrierMode mode) {
  DCHECK(scope_info()->HasContextExtensionSlot());
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) VerifyExtensionSlot(object);
#endif
  set(EXTENSION_INDEX, object, mode);
}

#ifdef DEBUG

bool Context::IsBootstrappingOrValidParentContext(Tagged<Object> object,
                                                  Tagged<Context> child) {
  // During bootstrapping we allow all objects to pass as
  // contexts. This is necessary to fix circular dependencies.
  if (child->GetIsolate()->bootstrapper()->IsActive()) return true;
  if (!IsContext(object)) return false;
  Tagged<Context> context = Cast<Context>(object);
  return IsNativeContext(context) || context->IsScriptContext() ||
         context->IsModuleContext() || !child->IsModuleContext();
}

#endif

void NativeContext::ResetErrorsThrown() { set_errors_thrown(Smi::FromInt(0)); }

void NativeContext::IncrementErrorsThrown() {
  int previous_value = errors_thrown().value();
  set_errors_thrown(Smi::FromInt(previous_value + 1));
}

int NativeContext::GetErrorsThrown() { return errors_thrown().value(); }

static_assert(Context::MIN_CONTEXT_SLOTS == 2);
static_assert(Context::MIN_CONTEXT_EXTENDED_SLOTS == 3);
static_assert(NativeContext::kScopeInfoOffset ==
              Context::OffsetOfElementAt(NativeContext::SCOPE_INFO_INDEX));
static_assert(NativeContext::kPreviousOffset ==
              Context::OffsetOfElementAt(NativeContext::PREVIOUS_INDEX));
static_assert(NativeContext::kExtensionOffset ==
              Context::OffsetOfElementAt(NativeContext::EXTENSION_INDEX));

static_assert(NativeContext::kStartOfStrongFieldsOffset ==
              Context::OffsetOfElementAt(-1));
static_assert(NativeContext::kStartOfWeakFieldsOffset ==
              Context::OffsetOfElementAt(NativeContext::FIRST_WEAK_SLOT));
static_assert(NativeContext::kMicrotaskQueueOffset ==
              Context::SizeFor(NativeContext::NATIVE_CONTEXT_SLOTS));
static_assert(NativeContext::kSize ==
              (Context::SizeFor(NativeContext::NATIVE_CONTEXT_SLOTS) +
               kSystemPointerSize));

#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
void NativeContext::RunPromiseHook(PromiseHookType type,
                                   Handle<JSPromise> promise,
                                   Handle<Object> parent) {
  Isolate* isolate = promise->GetIsolate();
  DCHECK(isolate->HasContextPromiseHooks());
  int contextSlot;

  switch (type) {
    case PromiseHookType::kInit:
      contextSlot = PROMISE_HOOK_INIT_FUNCTION_INDEX;
      break;
    case PromiseHookType::kResolve:
      contextSlot = PROMISE_HOOK_RESOLVE_FUNCTION_INDEX;
      break;
    case PromiseHookType::kBefore:
      contextSlot = PROMISE_HOOK_BEFORE_FUNCTION_INDEX;
      break;
    case PromiseHookType::kAfter:
      contextSlot = PROMISE_HOOK_AFTER_FUNCTION_INDEX;
      break;
    default:
      UNREACHABLE();
  }

  Handle<Object> hook(isolate->native_context()->get(contextSlot), isolate);
  if (IsUndefined(*hook)) return;

  int argc = type == PromiseHookType::kInit ? 2 : 1;
  Handle<Object> argv[2] = {Cast<Object>(promise), parent};

  Handle<Object> receiver = isolate->global_proxy();

  StackLimitCheck check(isolate);
  bool failed = false;
  if (check.HasOverflowed()) {
    isolate->StackOverflow();
    failed = true;
  } else {
    failed = Execution::Call(isolate, hook, receiver, argc, argv).is_null();
  }
  if (failed) {
    DCHECK(isolate->has_exception());
    Handle<Object> exception(isolate->exception(), isolate);

    MessageLocation* no_location = nullptr;
    Handle<JSMessageObject> message =
        isolate->CreateMessageOrAbort(exception, no_location);
    MessageHandler::ReportMessage(isolate, no_location, message);

    isolate->clear_exception();
  }
}
#endif

}  // namespace v8::internal

"""

```