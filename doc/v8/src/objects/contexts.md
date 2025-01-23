Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The primary goal is to summarize the functionality of `v8/src/objects/contexts.cc` and explain its relationship to JavaScript, using JavaScript examples where applicable.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the file for prominent keywords and structural elements. Things like:
    * `#include`:  Indicates dependencies on other V8 components.
    * `namespace v8::internal`: This tells us we're in V8's internal implementation details.
    * Class names like `ScriptContextTable`, `Context`, `NativeContext`. These are likely the core data structures.
    * Method names like `New`, `Add`, `Lookup`, `Initialize`, `set`, `get`. These suggest actions performed on these data structures.
    * Comments, especially the copyright notice and any explanatory comments.
    * Use of `Handle<>`, `Tagged<>`, `Isolate*`: These are V8-specific smart pointers and core engine concepts.
    * Conditional compilation (`#ifdef`, `#endif`).

3. **Focus on Key Classes and their Responsibilities:**  The names `ScriptContextTable` and `Context` stand out. Let's try to infer their purposes:
    * **`ScriptContextTable`**: The methods `New`, `Add`, `Lookup` strongly suggest a table-like structure for managing `ScriptContext` objects. The name implies it deals with contexts related to scripts.
    * **`Context`**: This seems like a fundamental concept. Methods like `Initialize`, `Lookup`, `declaration_context`, `closure_context`, `extension_object` suggest it holds information about the execution environment, scopes, and variable lookups.

4. **Analyze Key Methods and their Interactions:**
    * **`ScriptContextTable::New` and `ScriptContextTable::Add`**: These manage the creation and population of the `ScriptContextTable`. The `Add` method suggests it dynamically grows. The use of `NameToIndexHashTable` hints at efficient lookups by name.
    * **`ScriptContextTable::Lookup`**:  Confirms the role of the table in finding `ScriptContext` objects based on variable names.
    * **`Context::Initialize`**:  Suggests setting up the initial state of a context.
    * **`Context::Lookup`**:  This looks like the core mechanism for variable resolution. It traverses the context chain, checking different types of contexts (function, block, script, etc.) and extension objects. The logic around `FOLLOW_CONTEXT_CHAIN` is important.
    * **Methods like `declaration_context`, `closure_context`, `script_context`, `module`**: These provide ways to navigate the context hierarchy.
    * **Methods related to `extension_object` and `extension_receiver`**:  Indicate how objects associated with contexts (like `with` statements or function scopes) are accessed.

5. **Connect to JavaScript Concepts:**  As the analysis proceeds, consciously map the C++ concepts to corresponding JavaScript features:
    * **Scopes:**  The `Context` objects and the context chain directly relate to JavaScript's lexical scoping rules. Function scopes, block scopes, global scope – these are represented by different `Context` types.
    * **Variable Lookup:** The `Context::Lookup` method implements the JavaScript variable resolution algorithm (scope chain traversal).
    * **`with` statement:** The code explicitly mentions `IsWithContext` and `UnscopableLookup`, directly linking to the behavior of the `with` statement.
    * **Modules:** `IsModuleContext` and the handling of imports/exports tie into JavaScript modules.
    * **Global Object:**  `global_object()` clearly relates to JavaScript's global object.
    * **Closures:** `closure_context()` is directly related to the concept of closures in JavaScript.
    * **`let` and `const`:** The code mentions `v8_flags.const_tracking_let` and methods like `StoreScriptContextAndUpdateSlotProperty`, suggesting it's involved in how `let` and `const` are handled, especially their immutability and initialization.
    * **REPL (Read-Eval-Print Loop):** The comments about "REPL script context" indicate how V8 handles variable redeclarations in interactive environments.

6. **Formulate the Summary:** Based on the analysis, construct a concise summary of the file's purpose, highlighting the key classes and their roles. Emphasize the connection to JavaScript's scoping and variable resolution mechanisms.

7. **Create JavaScript Examples:**  For the most significant connections, create simple JavaScript code snippets that demonstrate the concepts managed by the C++ code:
    * **Scope Chain:**  Demonstrate nested functions and how variables are resolved in outer scopes.
    * **`with` statement:** Show how `with` modifies the scope chain.
    * **Closures:** Illustrate how inner functions retain access to variables from their enclosing scopes.
    * **Modules:**  Provide a basic example of importing and exporting variables between modules.
    * **`let` and `const` (if directly evident in the code):** Show how their scoping and immutability differ from `var`.

8. **Refine and Organize:** Review the summary and examples for clarity, accuracy, and completeness. Ensure the language is understandable to someone with a basic understanding of JavaScript and some awareness of engine internals. Organize the information logically, perhaps starting with the core function and then moving to specific examples.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This seems like just a bunch of C++ data structures."
* **Correction:** "No, the names and methods strongly suggest these structures are central to how JavaScript's execution model is implemented, especially scoping and variable access."
* **Initial thought about examples:** "Should I show low-level V8 API usage?"
* **Correction:** "No, the request is to relate it to *JavaScript* functionality, so JavaScript code examples are more appropriate and easier to understand."
* **Ensuring accuracy:** Double-check the code comments and method names to confirm the inferred functionality. For example, the `UnscopableLookup` method clearly links to the `with` statement's special behavior.

By following this systematic approach, combining code analysis with knowledge of JavaScript concepts, and iteratively refining the understanding, we can arrive at a comprehensive and helpful explanation of the given C++ file.
这个C++源代码文件 `v8/src/objects/contexts.cc`  定义并实现了 V8 JavaScript 引擎中 **上下文 (Contexts)** 相关的对象和功能。  Context 是 V8 中一个非常核心的概念，它代表了 JavaScript 代码执行时的环境，包含了变量、作用域链等信息。

**主要功能归纳:**

1. **定义 Context 对象及其子类:**  定义了 `Context` 类以及它的各种子类，例如 `NativeContext` (代表全局上下文)、`FunctionContext` (代表函数调用上下文)、`ScriptContext` (代表脚本执行上下文)、`BlockContext` (代表块级作用域上下文) 和 `ModuleContext` (代表模块上下文) 等。这些类用于存储不同类型作用域的相关信息。

2. **管理作用域链 (Scope Chain):**  Context 对象通过 `previous()` 指针链接形成作用域链。  `Context::Lookup` 方法实现了在作用域链上查找变量的功能。  它会沿着链向上查找，直到找到变量或者到达全局上下文。

3. **管理脚本上下文表 (ScriptContextTable):**  `ScriptContextTable` 用于存储和管理所有的 `ScriptContext` 对象。这对于在不同的脚本之间共享全局变量或者在 REPL 环境中重新声明变量非常重要。`ScriptContextTable::Add` 用于添加新的脚本上下文， `ScriptContextTable::Lookup` 用于在表中查找变量。

4. **处理 `with` 语句:**  代码中包含对 `with` 语句的支持，例如 `UnscopableLookup` 函数用于处理 `with` 语句带来的作用域变化以及 `unscopables` 符号。

5. **处理模块 (Modules):**  定义了 `ModuleContext` 并包含了在模块上下文中查找变量的逻辑，涉及模块的导入和导出。

6. **处理 `let` 和 `const` 声明:**  代码中包含对 `let` 和 `const` 声明的特殊处理，例如 `Context::StoreScriptContextAndUpdateSlotProperty` 函数用于在脚本上下文中存储 `let` 和 `const` 变量的值，并跟踪其是否被修改。

7. **处理调试 (Debug):**  `DebugEvaluateContext` 相关的逻辑用于在调试环境中执行代码。

8. **处理错误信息:**  提供了获取与代码生成相关的错误信息的函数，例如 `ErrorMessageForCodeGenerationFromStrings` 和 `ErrorMessageForWasmCodeGeneration`。

9. **提供 Promise Hook:** 在 `NativeContext` 中包含了与 Promise Hook 相关的函数，允许在 Promise 的生命周期中执行自定义的 JavaScript 代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`v8/src/objects/contexts.cc` 中定义的功能直接对应了 JavaScript 中 **作用域 (Scope)** 和 **上下文 (Context)** 的概念。  JavaScript 的执行依赖于这些 Context 对象来管理变量的访问和生命周期。

以下是一些 JavaScript 示例，展示了 `contexts.cc` 中功能在 JavaScript 中的体现：

**1. 作用域链 (Scope Chain):**

```javascript
function outer() {
  var outerVar = 10;
  function inner() {
    var innerVar = 20;
    console.log(outerVar); // 可以访问 outerVar，因为 inner 函数的作用域链包含了 outer 函数的作用域
  }
  inner();
}
outer();
```

在这个例子中，`inner` 函数的执行上下文会形成一个作用域链，包含了自己的局部变量 (`innerVar`) 和外部函数 `outer` 的局部变量 (`outerVar`)。 V8 的 `Context` 对象和 `Context::Lookup` 方法负责实现这种作用域链的查找。

**2. `with` 语句:**

```javascript
const obj = { a: 1, b: 2 };
with (obj) {
  console.log(a + b); // 直接访问 obj 的属性，不需要 obj.a 或 obj.b
}
```

`with` 语句会临时将 `obj` 添加到作用域链的前端。`UnscopableLookup` 等函数在 `contexts.cc` 中处理了这种特殊的作用域行为。

**3. 闭包 (Closures):**

```javascript
function createCounter() {
  let count = 0;
  return function() {
    count++;
    console.log(count);
  };
}

const counter = createCounter();
counter(); // 输出 1
counter(); // 输出 2
```

`createCounter` 函数返回的匿名函数形成了一个闭包，它可以访问 `createCounter` 函数作用域中的 `count` 变量，即使 `createCounter` 函数已经执行完毕。 V8 的 `closure_context()` 方法以及 `Context` 对象的结构支持了闭包的实现。

**4. 模块 (Modules):**

```javascript
// moduleA.js
export const message = "Hello from module A";

// moduleB.js
import { message } from './moduleA.js';
console.log(message);
```

JavaScript 模块通过 `import` 和 `export` 关键字实现代码的组织和复用。 `ModuleContext` 对象以及相关的查找逻辑在 `contexts.cc` 中负责管理模块的作用域和变量的访问。

**5. `let` 和 `const`:**

```javascript
function example() {
  let localVar = 30;
  const constVar = 40;

  // ...
  localVar = 31; // 可以重新赋值
  // constVar = 41; // 错误：常量不能重新赋值
}
```

`let` 和 `const` 声明的变量具有块级作用域，并且 `const` 声明的变量是只读的。  `Context::StoreScriptContextAndUpdateSlotProperty` 等函数参与了 `let` 和 `const` 变量的存储和属性更新，确保了其作用域和不可变性。

**总结:**

`v8/src/objects/contexts.cc` 是 V8 引擎中负责管理 JavaScript 执行上下文的核心文件。它定义了各种上下文对象，实现了作用域链的查找机制，并处理了 `with` 语句、模块、闭包以及 `let` 和 `const` 等关键的 JavaScript 语言特性。  理解这个文件的功能对于深入理解 JavaScript 的执行原理至关重要。

### 提示词
```
这是目录为v8/src/objects/contexts.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```