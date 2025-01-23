Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the requested summary.

**1. Initial Scan and Identification of Key Areas:**

The first step is to quickly read through the code to identify the major components and their purpose. Keywords like `ScopeInfo`, `Create`, `Flags`, `Variable`, `Context`, `Module`, and `#ifdef DEBUG` stand out. The file path `v8/src/objects/scope-info.cc` immediately tells us this is about how V8 represents scope information internally.

**2. Understanding the Core Purpose of `ScopeInfo`:**

The name "ScopeInfo" strongly suggests it's about storing information related to JavaScript scopes. The `Create` methods confirm this, as they take a `Scope` object (from the AST) as input. The code iterates through `scope->locals()`, suggesting it's recording details about variables declared within a scope.

**3. Deconstructing the `Create` Method:**

The `Create` method is central to understanding the functionality. I would analyze its key parts:

* **Variable Counting:** The loops counting `context_local_count` and `module_vars_count` indicate that `ScopeInfo` tracks different kinds of variables.
* **`receiver_info` and `function_name_info`:** These variables indicate the tracking of `this` and the function's name, respectively.
* **Flags Encoding:** The block of code setting `flags` using bitwise OR and `encode` methods suggests that `ScopeInfo` uses flags to store various boolean properties about the scope. The names of the flag bits (e.g., `ScopeTypeBits`, `SloppyEvalCanExtendVarsBit`) are informative.
* **Length Calculation:** The calculation of `length` reveals what data is stored in the `ScopeInfo` object. It includes space for flags, parameter counts, local variable names, and potentially outer scope information, module information, etc.
* **Allocation and Initialization:** The code allocates a `ScopeInfo` object and then populates its fields. The use of `set` methods with different types (Smi, Object) indicates the different kinds of data stored.
* **Handling Different Variable Locations:** The `switch` statement based on `var->location()` shows how different types of variables (CONTEXT, MODULE) are handled and stored.
* **Parameter Number Encoding:** The logic for encoding parameter numbers indicates that `ScopeInfo` helps in resolving parameter names to their positions.

**4. Analyzing the `Equals` Method (Debug Section):**

The `#ifdef DEBUG` block with the `Equals` method is important for understanding how V8 compares `ScopeInfo` objects, particularly in the context of live editing. It highlights which fields are considered for equality and which are ignored during live edits (position information, dependent code).

**5. Examining Other Methods:**

The other methods like `CreateForWithScope`, `CreateGlobalThisBinding`, `CreateForEmptyFunction`, etc., show specialized ways of creating `ScopeInfo` for different built-in or special scope types. These reinforce the idea that `ScopeInfo` is a versatile structure for representing various kinds of scopes.

**6. Connecting to JavaScript Concepts:**

After understanding the internal representation, the next step is to connect it to JavaScript concepts. The terms "scope," "variables," "context," "module," "this," and "function name" directly correspond to JavaScript features. Thinking about how these concepts behave in JavaScript helps in generating relevant examples.

**7. Considering Torque (.tq) Files:**

The prompt specifically asks about `.tq` files. Knowing that Torque is V8's domain-specific language for implementing built-ins helps in answering that part.

**8. Identifying Potential Programming Errors:**

Thinking about common JavaScript errors related to scope (e.g., accessing variables before declaration, closure issues) helps in generating examples of user programming errors that might relate to `ScopeInfo`.

**9. Structuring the Output:**

Finally, I would structure the output according to the prompt's requirements:

* **List of functions:**  Start with a clear list of the key functionalities.
* **Torque files:** Address the `.tq` question.
* **JavaScript examples:** Provide illustrative JavaScript code snippets.
* **Code Logic Inference:** Explain the logic with assumptions and expected output.
* **Common Programming Errors:** Give concrete examples of errors.
* **Summary:** Provide a concise overview of the file's purpose.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe `ScopeInfo` just stores the names of variables."
* **Correction:**  The code also stores information about variable location (CONTEXT, MODULE, STACK), initialization flags, and other metadata. The `Flags` field is crucial and stores more than just variable names.
* **Initial thought:** "The JavaScript examples should be very complex."
* **Refinement:** Simple, focused examples that directly illustrate the connection to `ScopeInfo` concepts are more effective.
* **Initial thought:** "The code logic inference should cover every branch."
* **Refinement:** Focusing on a specific, illustrative scenario with clear inputs and outputs is better than trying to cover all possibilities.

By following these steps, combining code analysis with knowledge of JavaScript concepts and V8 internals, and iteratively refining the understanding, it's possible to generate a comprehensive and accurate summary of the `scope-info.cc` file.
```
这是目录为v8/src/objects/scope-info.cc的一个v8源代码， 请列举一下它的功能,
```
这个C++源代码文件 `v8/src/objects/scope-info.cc` 在 V8 JavaScript 引擎中扮演着至关重要的角色，其主要功能是**定义和实现 `ScopeInfo` 对象**。`ScopeInfo` 对象是 V8 内部用来**表示和存储 JavaScript 代码作用域信息的关键数据结构**。

具体来说，`v8/src/objects/scope-info.cc` 实现了以下功能：

1. **定义 `ScopeInfo` 类的结构和方法:**
   - 定义了 `ScopeInfo` 对象的内部布局，包括存储作用域类型、标志位（flags）、变量信息、参数信息、嵌套作用域信息等。
   - 提供了访问和修改 `ScopeInfo` 对象内部数据的方法（getter 和 setter）。
   - 定义了用于比较两个 `ScopeInfo` 对象是否相等的方法 (`Equals`)，这在例如热重载（live edit）等场景中用于判断作用域信息是否发生变化。

2. **实现创建 `ScopeInfo` 对象的方法 (`Create`):**
   - 提供了多种静态 `Create` 方法，用于根据不同的作用域类型（例如函数作用域、块级作用域、模块作用域、with 作用域等）创建相应的 `ScopeInfo` 对象。
   - `Create` 方法接收 `Scope` (抽象语法树中的作用域节点) 对象作为输入，并从中提取作用域的各种属性，例如：
     - 作用域类型 (`scope_type()`)
     - 局部变量 (`locals()`) 及其属性 (位置、模式、初始化状态等)
     - 参数信息 (`num_parameters()`)
     - 是否捕获了 `this` 或 `new.target`
     - 是否是严格模式 (`language_mode()`)
     - 是否允许 `eval` 引入的变量扩展外部作用域 (`sloppy_eval_can_extend_vars()`)
     - 嵌套的外部作用域信息 (`outer_scope`)
     - 模块信息 (`module()`) (对于模块作用域)
     - 函数名信息 (`function_var()`)
     - 推断的函数名 (`inferred_function_name`)
     - 等等。
   - `Create` 方法会将这些信息编码并存储到新创建的 `ScopeInfo` 对象中。

3. **提供访问作用域信息的方法:**
   - 提供了各种访问 `ScopeInfo` 对象中存储信息的便捷方法，例如 `scope_type()`, `ContextLength()`, `HasReceiver()`, `ParameterCount()`, `LocalCount()`, `FunctionName()`, `OuterScopeInfo()`, 等等。这些方法允许 V8 的其他组件快速访问和查询作用域的属性。

4. **处理不同类型的局部变量:**
   - 代码区分了不同存储位置的局部变量（例如，存储在上下文 Context 中的变量，存储在栈上的变量，模块级别的变量），并将其信息存储在 `ScopeInfo` 中。

5. **处理模块作用域:**
   - 专门处理模块作用域，存储模块变量的信息。

6. **支持 With 语句:**
   - 提供了 `CreateForWithScope` 方法来创建表示 `with` 语句引入的作用域的 `ScopeInfo` 对象。

7. **支持启动时的特殊作用域:**
   - 提供了 `CreateGlobalThisBinding`, `CreateForEmptyFunction`, `CreateForNativeContext` 等方法来创建用于启动 V8 引擎的特殊作用域的 `ScopeInfo` 对象。

```
如果v8/src/objects/scope-info.cc以.tq结尾，那它是个v8 torque源代码，
```
是的，如果文件名为 `v8/src/objects/scope-info.tq`，那么它将是一个 **V8 Torque 源代码文件**。

Torque 是 V8 使用的一种领域特定语言（DSL），用于生成高效的 C++ 代码，特别是用于实现 V8 的内置函数、运行时函数以及对象布局。

如果 `scope-info.cc` 是用 Torque 编写的，那么它将包含 Torque 语法，描述 `ScopeInfo` 对象的布局、创建和访问逻辑，然后 Torque 编译器会将其转换成 C++ 代码。

**当前 `v8/src/objects/scope-info.cc` 是一个标准的 C++ 文件，而不是 Torque 文件。**

```
如果它与javascript的功能有关系，请用javascript举例说明,
```

`v8/src/objects/scope-info.cc` 直接关系到 JavaScript 的**作用域（Scope）**概念。JavaScript 中的作用域决定了变量和函数的可见性以及生命周期。

**JavaScript 例子:**

```javascript
function outerFunction(param1) {
  const outerVar = 'I am in outer scope';

  function innerFunction(param2) {
    const innerVar = 'I am in inner scope';
    console.log(param1); // 可以访问 outerFunction 的参数
    console.log(outerVar); // 可以访问 outerFunction 的变量
    console.log(innerVar);
  }

  innerFunction('inner param');
}

outerFunction('outer param');
```

**`ScopeInfo` 在这个例子中的作用:**

- 当 V8 编译 `outerFunction` 时，会创建一个 `ScopeInfo` 对象来描述 `outerFunction` 的作用域。这个 `ScopeInfo` 对象会记录：
    - `outerFunction` 的作用域类型（函数作用域）。
    - 参数 `param1` 的信息。
    - 局部变量 `outerVar` 的信息（例如，它的名称、存储位置）。
- 当 V8 编译 `innerFunction` 时，也会创建一个 `ScopeInfo` 对象来描述 `innerFunction` 的作用域。这个 `ScopeInfo` 对象会记录：
    - `innerFunction` 的作用域类型（函数作用域）。
    - 参数 `param2` 的信息。
    - 局部变量 `innerVar` 的信息。
    - **重要的是，`innerFunction` 的 `ScopeInfo` 对象会包含对 `outerFunction` 的 `ScopeInfo` 对象的引用（通过 "outer scope info"），从而实现了词法作用域的链式查找。** 当在 `innerFunction` 中访问 `param1` 或 `outerVar` 时，V8 会沿着作用域链向上查找。

**其他 JavaScript 概念与 `ScopeInfo` 的关联:**

- **块级作用域 (let, const):**  对于使用 `let` 或 `const` 声明的变量，V8 会为块级作用域创建独立的 `ScopeInfo` 对象。
- **闭包 (Closures):** `ScopeInfo` 对象对于实现闭包至关重要。当一个内部函数被传递到外部作用域并被调用时，即使外部函数已经执行完毕，内部函数仍然可以访问其创建时的作用域，这正是通过 `ScopeInfo` 对象及其链接来实现的。
- **模块 (Modules):**  对于 JavaScript 模块，V8 会创建模块作用域的 `ScopeInfo` 对象，用于管理模块级别的变量和导入导出。
- **`eval()`:**  `eval()` 函数可以引入新的作用域，V8 会相应地创建新的 `ScopeInfo` 对象来描述 `eval()` 执行时的作用域。
- **`with` 语句:** `with` 语句创建的作用域也会有对应的 `ScopeInfo` 对象。

```
如果有代码逻辑推理，请给出假设输入与输出，
```

**代码逻辑推理示例：`ScopeInfo::Create` 方法**

**假设输入:**

- `isolate`: 当前 V8 隔离区（Isolate）的指针。
- `zone`: 用于内存分配的 Zone 对象。
- `scope`: 一个表示以下 JavaScript 函数的 `Scope` 对象：

  ```javascript
  function example(a, b) {
    let sum = a + b;
    return sum;
  }
  ```

- `outer_scope`:  `MaybeHandle<ScopeInfo>::null()`, 因为这是一个顶层函数。

**代码逻辑推理过程 (简化):**

1. **统计局部变量:** `Create` 方法会遍历 `scope->locals()`，找到 `sum` 变量，它是一个块级作用域的变量，但会被提升到函数作用域进行管理（取决于具体的 V8 版本和优化）。 假设它被当作上下文局部变量处理。 `context_local_count` 将为 1。
2. **处理参数:**  `scope->num_parameters()` 将返回 2 (`a` 和 `b`).
3. **确定标志位:**
   - `scope_type()` 将是 `FUNCTION_SCOPE`.
   - `language_mode()` 将取决于该函数定义所在的上下文（可能是严格模式或非严格模式）。
   - 其他标志位将根据 `scope` 的属性进行设置。
4. **计算长度:** `length` 的计算会考虑参数数量、局部变量数量等。
5. **创建 `ScopeInfo` 对象:** 分配一个足够大小的 `ScopeInfo` 对象。
6. **设置基本信息:** 设置 `flags`, `parameter_count`, `context_local_count` 等基本字段。
7. **存储局部变量信息:**
   - 将 `sum` 的名称 ("sum") 存储在 `ScopeInfo` 的相应位置。
   - 将 `sum` 的属性（例如，`let` 声明，未初始化或已初始化）编码并存储。
8. **存储参数信息:**  将参数 `a` 和 `b` 与其在上下文中的位置或栈上的位置关联起来。
9. **设置外部作用域信息:** 由于 `outer_scope` 为空，所以不会设置外部作用域信息。

**假设输出 (`ScopeInfo` 对象的部分内容):**

```
ScopeInfo {
  flags:  ... (包含作用域类型、模式等信息的位掩码)
  parameter_count: 2
  context_local_count: 1
  position_info_start: ...
  position_info_end: ...
  // 假设局部变量名内联存储
  context_local_names: ["sum"]
  context_local_infos: [ ... (sum 变量的属性信息) ]
  outer_scope_info: <empty>
  ...
}
```

**注意:** 这只是一个简化的示例，实际的 `ScopeInfo` 对象包含更多信息，并且其内部布局和编码方式比较复杂。

```
如果涉及用户常见的编程错误，请举例说明
```

与 `ScopeInfo` 相关的用户常见编程错误通常与 JavaScript 的**作用域理解**有关：

1. **在声明之前访问变量（`let` 和 `const` 的暂时性死区）：**

   ```javascript
   function example() {
     console.log(myVar); // ReferenceError: Cannot access 'myVar' before initialization
     let myVar = 10;
   }
   example();
   ```

   V8 在编译时会为 `example` 函数创建一个 `ScopeInfo` 对象。当执行到 `console.log(myVar)` 时，V8 会查找 `myVar`。由于 `myVar` 是用 `let` 声明的，它存在于块级作用域的 `ScopeInfo` 中，但在声明之前访问会导致错误。

2. **不理解闭包导致意外的变量共享:**

   ```javascript
   function createFunctions() {
     const functions = [];
     for (var i = 0; i < 5; i++) {
       functions.push(function() {
         console.log(i);
       });
     }
     return functions;
   }

   const funcs = createFunctions();
   funcs[0](); // 输出 5，而不是期望的 0
   ```

   在这个例子中，由于 `var` 声明的 `i` 是函数作用域的，所有内部函数都共享同一个 `i` 变量的 `ScopeInfo` 条目。当循环结束时，`i` 的值是 5。解决办法是使用 `let` 创建块级作用域的 `i`。

3. **在全局作用域意外创建变量 (忘记 `var`, `let`, `const`):**

   ```javascript
   function example() {
     globalVar = 20; // 意外创建全局变量
   }
   example();
   console.log(globalVar); // 可以访问到
   ```

   虽然这不会直接导致 `ScopeInfo` 报错，但它违反了良好的编程实践，可能导致命名冲突和意外行为。V8 在处理这类代码时，会在全局作用域的 `ScopeInfo` 中记录该变量。

4. **`with` 语句的滥用导致作用域混乱:**

   ```javascript
   const obj = { x: 1, y: 2 };
   function example() {
     with (obj) {
       console.log(x + y);
     }
   }
   example();
   ```

   `with` 语句会创建一个新的词法作用域，其 `ScopeInfo` 对象指向 `obj`。虽然这在某些情况下很方便，但它会使作用域链变得复杂，难以理解和优化，并且可能导致性能问题。

5. **在 `eval()` 中引入变量导致作用域混乱:**

   ```javascript
   function example() {
     const localVar = 30;
     eval('var evalVar = 40;');
     console.log(evalVar); // 可以访问到，因为它被添加到 `example` 的作用域中（非严格模式）
   }
   example();
   ```

   在非严格模式下，`eval()` 中声明的变量会添加到 `eval()` 执行时所在的作用域的 `ScopeInfo` 中，这可能导致意外的变量访问和污染。

这些错误都与 JavaScript 的作用域规则密切相关，而 `ScopeInfo` 正是 V8 内部用来表示和管理这些作用域规则的关键数据结构。理解 `ScopeInfo` 的作用有助于更深入地理解 JavaScript 的作用域机制以及避免相关的编程错误。

```
这是第1部分，共2部分，请归纳一下它的功能
```

**归纳一下 `v8/src/objects/scope-info.cc` 的功能 (第 1 部分):**

`v8/src/objects/scope-info.cc` 文件是 V8 JavaScript 引擎中用于**定义和管理 `ScopeInfo` 对象的关键组件**。`ScopeInfo` 对象是 V8 内部用来**表示和存储 JavaScript 代码作用域信息的核心数据结构**。

其主要功能包括：

1. **定义 `ScopeInfo` 对象的结构和方法:** 描述了 `ScopeInfo` 的内部布局，提供了访问和修改其数据的方法，以及比较两个 `ScopeInfo` 对象的方法。
2. **实现创建 `ScopeInfo` 对象的方法 (`Create`)**: 提供了多种 `Create` 方法，用于根据不同的作用域类型，从抽象语法树的 `Scope` 节点中提取信息，并创建相应的 `ScopeInfo` 对象。这些信息包括作用域类型、局部变量、参数、外部作用域、模块信息等。
3. **提供访问作用域信息的方法:** 提供了便捷的接口，允许 V8 的其他组件查询 `ScopeInfo` 对象中存储的各种作用域属性。
4. **处理不同类型的局部变量:** 能够区分和存储不同存储位置的局部变量信息。
5. **支持特定作用域类型:**  包括对模块作用域和 `with` 语句的支持，以及为引擎启动时的特殊作用域创建 `ScopeInfo` 对象。

总而言之，`v8/src/objects/scope-info.cc` 的核心职责是**提供 `ScopeInfo` 对象的定义、创建和管理机制**，这是 V8 引擎理解和执行 JavaScript 代码中作用域规则的基础。它将抽象的 JavaScript 作用域概念转化为 V8 内部可操作的数据结构。

### 提示词
```
这是目录为v8/src/objects/scope-info.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/scope-info.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/scope-info.h"

#include <stdlib.h>

#include "src/ast/scopes.h"
#include "src/ast/variables.h"
#include "src/init/bootstrapper.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/scope-info-inl.h"
#include "src/objects/string-set-inl.h"
#include "src/roots/roots.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

#ifdef DEBUG
bool ScopeInfo::Equals(Tagged<ScopeInfo> other,
                       bool is_live_edit_compare) const {
  if (length() != other->length()) return false;
  if (Flags() != other->Flags()) return false;
  for (int index = 0; index < length(); ++index) {
    if (index == kFlags) continue;
    if (is_live_edit_compare && index >= kPositionInfoStart &&
        index <= kPositionInfoEnd) {
      continue;
    }
    Tagged<Object> entry = get(index);
    Tagged<Object> other_entry = other->get(index);
    if (IsSmi(entry)) {
      if (entry != other_entry) return false;
    } else {
      if (Cast<HeapObject>(entry)->map()->instance_type() !=
          Cast<HeapObject>(other_entry)->map()->instance_type()) {
        return false;
      }
      if (IsString(entry)) {
        if (!Cast<String>(entry)->Equals(Cast<String>(other_entry))) {
          return false;
        }
      } else if (IsScopeInfo(entry)) {
        if (!is_live_edit_compare && !Cast<ScopeInfo>(entry)->Equals(
                                         Cast<ScopeInfo>(other_entry), false)) {
          return false;
        }
      } else if (IsSourceTextModuleInfo(entry)) {
        if (!is_live_edit_compare &&
            !Cast<SourceTextModuleInfo>(entry)->Equals(
                Cast<SourceTextModuleInfo>(other_entry))) {
          return false;
        }
      } else if (IsOddball(entry)) {
        if (Cast<Oddball>(entry)->kind() !=
            Cast<Oddball>(other_entry)->kind()) {
          return false;
        }
      } else if (IsDependentCode(entry)) {
        DCHECK(IsDependentCode(other_entry));
        // Ignore the dependent code field since all the code have to be
        // deoptimized anyway in case of a live-edit.
      } else {
        UNREACHABLE();
      }
    }
  }
  return true;
}
#endif

// static
template <typename IsolateT>
Handle<ScopeInfo> ScopeInfo::Create(IsolateT* isolate, Zone* zone, Scope* scope,
                                    MaybeHandle<ScopeInfo> outer_scope) {
  // Collect variables.
  int context_local_count = 0;
  int module_vars_count = 0;
  // Stack allocated block scope variables are allocated in the parent
  // declaration scope, but are recorded in the block scope's scope info. First
  // slot index indicates at which offset a particular scope starts in the
  // parent declaration scope.
  for (Variable* var : *scope->locals()) {
    switch (var->location()) {
      case VariableLocation::CONTEXT:
      case VariableLocation::REPL_GLOBAL:
        context_local_count++;
        break;
      case VariableLocation::MODULE:
        module_vars_count++;
        break;
      default:
        break;
    }
  }
  // Determine use and location of the "this" binding if it is present.
  VariableAllocationInfo receiver_info;
  if (scope->is_declaration_scope() &&
      scope->AsDeclarationScope()->has_this_declaration()) {
    Variable* var = scope->AsDeclarationScope()->receiver();
    if (!var->is_used()) {
      receiver_info = VariableAllocationInfo::UNUSED;
    } else if (var->IsContextSlot()) {
      receiver_info = VariableAllocationInfo::CONTEXT;
    } else {
      DCHECK(var->IsParameter());
      receiver_info = VariableAllocationInfo::STACK;
    }
  } else {
    receiver_info = VariableAllocationInfo::NONE;
  }

  DCHECK(module_vars_count == 0 || scope->is_module_scope());

  // Make sure we allocate the correct amount.
  DCHECK_EQ(scope->ContextLocalCount(), context_local_count);

  // If the number of locals is small, we inline directly
  // in the scope info object.
  bool has_inlined_local_names =
      context_local_count < kScopeInfoMaxInlinedLocalNamesSize;

  const bool has_new_target =
      scope->is_declaration_scope() &&
      scope->AsDeclarationScope()->new_target_var() != nullptr;
  // TODO(cbruni): Don't always waste a field for the inferred name.
  const bool has_inferred_function_name = scope->is_function_scope();

  // Determine use and location of the function variable if it is present.
  VariableAllocationInfo function_name_info;
  if (scope->is_function_scope()) {
    if (scope->AsDeclarationScope()->function_var() != nullptr) {
      Variable* var = scope->AsDeclarationScope()->function_var();
      if (!var->is_used()) {
        function_name_info = VariableAllocationInfo::UNUSED;
      } else if (var->IsContextSlot()) {
        function_name_info = VariableAllocationInfo::CONTEXT;
      } else {
        DCHECK(var->IsStackLocal());
        function_name_info = VariableAllocationInfo::STACK;
      }
    } else {
      // Always reserve space for the debug name in the scope info.
      function_name_info = VariableAllocationInfo::UNUSED;
    }
  } else if (scope->is_module_scope() || scope->is_script_scope() ||
             scope->is_eval_scope()) {
    // Always reserve space for the debug name in the scope info.
    function_name_info = VariableAllocationInfo::UNUSED;
  } else {
    function_name_info = VariableAllocationInfo::NONE;
  }

  const bool has_brand =
      scope->is_class_scope()
          ? scope->AsClassScope()->brand() != nullptr
          : scope->IsConstructorScope() &&
                scope->AsDeclarationScope()->class_scope_has_private_brand();
  const bool should_save_class_variable_index =
      scope->is_class_scope()
          ? scope->AsClassScope()->should_save_class_variable_index()
          : false;
  const bool has_function_name =
      function_name_info != VariableAllocationInfo::NONE;
  const int parameter_count =
      scope->is_declaration_scope()
          ? scope->AsDeclarationScope()->num_parameters()
          : 0;
  const bool has_outer_scope_info = !outer_scope.is_null();

  Handle<SourceTextModuleInfo> module_info;
  if (scope->is_module_scope()) {
    module_info = SourceTextModuleInfo::New(isolate, zone,
                                            scope->AsModuleScope()->module());
  }

  // Make sure the Fields enum agrees with Torque-generated offsets.
  static_assert(OffsetOfElementAt(kFlags) == kFlagsOffset);
  static_assert(OffsetOfElementAt(kParameterCount) == kParameterCountOffset);
  static_assert(OffsetOfElementAt(kContextLocalCount) ==
                kContextLocalCountOffset);

  FunctionKind function_kind = FunctionKind::kNormalFunction;
  bool sloppy_eval_can_extend_vars = false;
  if (scope->is_declaration_scope()) {
    function_kind = scope->AsDeclarationScope()->function_kind();
    sloppy_eval_can_extend_vars =
        scope->AsDeclarationScope()->sloppy_eval_can_extend_vars();
  }
  DCHECK_IMPLIES(sloppy_eval_can_extend_vars, scope->HasContextExtensionSlot());

  const int local_names_container_size =
      has_inlined_local_names ? context_local_count : 1;

  const int has_dependent_code = sloppy_eval_can_extend_vars;
  const int length =
      kVariablePartIndex + local_names_container_size + context_local_count +
      (should_save_class_variable_index ? 1 : 0) +
      (has_function_name ? kFunctionNameEntries : 0) +
      (has_inferred_function_name ? 1 : 0) + (has_outer_scope_info ? 1 : 0) +
      (scope->is_module_scope()
           ? 2 + kModuleVariableEntryLength * module_vars_count
           : 0) +
      (has_dependent_code ? 1 : 0);

  // Create hash table if local names are not inlined.
  Handle<NameToIndexHashTable> local_names_hashtable;
  if (!has_inlined_local_names) {
    local_names_hashtable = NameToIndexHashTable::New(
        isolate, context_local_count, AllocationType::kOld);
  }

  Handle<ScopeInfo> scope_info_handle =
      isolate->factory()->NewScopeInfo(length);
  int index = kVariablePartIndex;
  {
    DisallowGarbageCollection no_gc;
    Tagged<ScopeInfo> scope_info = *scope_info_handle;
    WriteBarrierMode mode = scope_info->GetWriteBarrierMode(no_gc);

    bool has_simple_parameters = false;
    bool is_asm_module = false;
    if (scope->is_function_scope()) {
      DeclarationScope* function_scope = scope->AsDeclarationScope();
      has_simple_parameters = function_scope->has_simple_parameters();
#if V8_ENABLE_WEBASSEMBLY
      is_asm_module = function_scope->is_asm_module();
#endif  // V8_ENABLE_WEBASSEMBLY
    }

    // Encode the flags.
    uint32_t flags =
        ScopeTypeBits::encode(scope->scope_type()) |
        SloppyEvalCanExtendVarsBit::encode(sloppy_eval_can_extend_vars) |
        LanguageModeBit::encode(scope->language_mode()) |
        DeclarationScopeBit::encode(scope->is_declaration_scope()) |
        ReceiverVariableBits::encode(receiver_info) |
        ClassScopeHasPrivateBrandBit::encode(has_brand) |
        HasSavedClassVariableBit::encode(should_save_class_variable_index) |
        HasNewTargetBit::encode(has_new_target) |
        FunctionVariableBits::encode(function_name_info) |
        HasInferredFunctionNameBit::encode(has_inferred_function_name) |
        IsAsmModuleBit::encode(is_asm_module) |
        HasSimpleParametersBit::encode(has_simple_parameters) |
        FunctionKindBits::encode(function_kind) |
        HasOuterScopeInfoBit::encode(has_outer_scope_info) |
        IsDebugEvaluateScopeBit::encode(scope->is_debug_evaluate_scope()) |
        ForceContextAllocationBit::encode(
            scope->ForceContextForLanguageMode()) |
        PrivateNameLookupSkipsOuterClassBit::encode(
            scope->private_name_lookup_skips_outer_class()) |
        HasContextExtensionSlotBit::encode(scope->HasContextExtensionSlot()) |
        IsHiddenBit::encode(scope->is_hidden()) |
        IsWrappedFunctionBit::encode(scope->is_wrapped_function());
    scope_info->set_flags(flags, kRelaxedStore);

    scope_info->set_parameter_count(parameter_count);
    scope_info->set_context_local_count(context_local_count);

    scope_info->set_position_info_start(scope->start_position());
    scope_info->set_position_info_end(scope->end_position());

    if (scope->is_module_scope()) {
      scope_info->set_module_variable_count(module_vars_count);
      ++index;
    }
    if (!has_inlined_local_names) {
      scope_info->set_context_local_names_hashtable(*local_names_hashtable);
    }

    // Add context locals' names and info, module variables' names and info.
    // Context locals are added using their index.
    int context_local_base = index;
    int context_local_info_base =
        context_local_base + local_names_container_size;
    int module_var_entry = scope_info->ModuleVariablesIndex();

    for (Variable* var : *scope->locals()) {
      switch (var->location()) {
        case VariableLocation::CONTEXT:
        case VariableLocation::REPL_GLOBAL: {
          // Due to duplicate parameters, context locals aren't guaranteed to
          // come in order.
          int local_index = var->index() - scope->ContextHeaderLength();
          DCHECK_LE(0, local_index);
          DCHECK_LT(local_index, context_local_count);
          uint32_t info =
              VariableModeBits::encode(var->mode()) |
              InitFlagBit::encode(var->initialization_flag()) |
              MaybeAssignedFlagBit::encode(var->maybe_assigned()) |
              ParameterNumberBits::encode(ParameterNumberBits::kMax) |
              IsStaticFlagBit::encode(var->is_static_flag());
          if (has_inlined_local_names) {
            scope_info->set(context_local_base + local_index, *var->name(),
                            mode);
          } else {
            Handle<NameToIndexHashTable> new_table = NameToIndexHashTable::Add(
                isolate, local_names_hashtable, var->name(), local_index);
            DCHECK_EQ(*new_table, *local_names_hashtable);
            USE(new_table);
          }
          scope_info->set(context_local_info_base + local_index,
                          Smi::FromInt(info));
          break;
        }
        case VariableLocation::MODULE: {
          scope_info->set(
              module_var_entry +
                  TorqueGeneratedModuleVariableOffsets::kNameOffset /
                      kTaggedSize,
              *var->name(), mode);
          scope_info->set(
              module_var_entry +
                  TorqueGeneratedModuleVariableOffsets::kIndexOffset /
                      kTaggedSize,
              Smi::FromInt(var->index()));
          uint32_t properties =
              VariableModeBits::encode(var->mode()) |
              InitFlagBit::encode(var->initialization_flag()) |
              MaybeAssignedFlagBit::encode(var->maybe_assigned()) |
              ParameterNumberBits::encode(ParameterNumberBits::kMax) |
              IsStaticFlagBit::encode(var->is_static_flag());
          scope_info->set(
              module_var_entry +
                  TorqueGeneratedModuleVariableOffsets::kPropertiesOffset /
                      kTaggedSize,
              Smi::FromInt(properties));
          module_var_entry += kModuleVariableEntryLength;
          break;
        }
        default:
          break;
      }
    }

    if (scope->is_declaration_scope()) {
      // Mark contexts slots with the parameter number they represent. We walk
      // the list of parameters. That can include duplicate entries if a
      // parameter name is repeated. By walking upwards, we'll automatically
      // mark the context slot with the highest parameter number that uses this
      // variable. That will be the parameter number that is represented by the
      // context slot. All lower parameters will only be available on the stack
      // through the arguments object.
      for (int i = 0; i < parameter_count; i++) {
        Variable* parameter = scope->AsDeclarationScope()->parameter(i);
        if (parameter->location() != VariableLocation::CONTEXT) continue;
        int param_index = parameter->index() - scope->ContextHeaderLength();
        int info_index = context_local_info_base + param_index;
        int info = Smi::ToInt(scope_info->get(info_index));
        info = ParameterNumberBits::update(info, i);
        scope_info->set(info_index, Smi::FromInt(info));
      }
    }

    // Advance past local names and local names info.
    index += local_names_container_size + context_local_count;

    DCHECK_EQ(index, scope_info->SavedClassVariableInfoIndex());
    // If the scope is a class scope and has used static private methods, save
    // the context slot index of the class variable.
    // Store the class variable index.
    if (should_save_class_variable_index) {
      Variable* class_variable = scope->AsClassScope()->class_variable();
      DCHECK_EQ(class_variable->location(), VariableLocation::CONTEXT);
      int local_index;
      if (has_inlined_local_names) {
        local_index = class_variable->index();
      } else {
        Handle<Name> name = class_variable->name();
        InternalIndex entry = local_names_hashtable->FindEntry(isolate, name);
        local_index = entry.as_int();
      }
      scope_info->set(index++, Smi::FromInt(local_index));
    }

    // If present, add the function variable name and its index.
    DCHECK_EQ(index, scope_info->FunctionVariableInfoIndex());
    if (has_function_name) {
      Variable* var = scope->AsDeclarationScope()->function_var();
      int var_index = -1;
      Tagged<Object> name = Smi::zero();
      if (var != nullptr) {
        var_index = var->index();
        name = *var->name();
      }
      scope_info->set(index++, name, mode);
      scope_info->set(index++, Smi::FromInt(var_index));
      DCHECK(function_name_info != VariableAllocationInfo::CONTEXT ||
             var_index == scope_info->ContextLength() - 1);
    }

    DCHECK_EQ(index, scope_info->InferredFunctionNameIndex());
    if (has_inferred_function_name) {
      // The inferred function name is taken from the SFI.
      index++;
    }

    // If present, add the outer scope info.
    DCHECK_EQ(index, scope_info->OuterScopeInfoIndex());
    if (has_outer_scope_info) {
      scope_info->set(index++, *outer_scope.ToHandleChecked(), mode);
    }

    // Module-specific information (only for module scopes).
    if (scope->is_module_scope()) {
      DCHECK_EQ(index, scope_info->ModuleInfoIndex());
      scope_info->set(index++, *module_info);
      DCHECK_EQ(index, scope_info->ModuleVariablesIndex());
      // The variable entries themselves have already been written above.
      index += kModuleVariableEntryLength * module_vars_count;
    }

    DCHECK_EQ(index, scope_info->DependentCodeIndex());
    if (has_dependent_code) {
      ReadOnlyRoots roots(isolate);
      scope_info->set(index++, DependentCode::empty_dependent_code(roots));
    }
  }

  DCHECK_EQ(index, scope_info_handle->length());
  DCHECK_EQ(length, scope_info_handle->length());
  DCHECK_EQ(parameter_count, scope_info_handle->ParameterCount());
  DCHECK_EQ(scope->num_heap_slots(), scope_info_handle->ContextLength());

  return scope_info_handle;
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<ScopeInfo> ScopeInfo::Create(Isolate* isolate, Zone* zone,
                                        Scope* scope,
                                        MaybeHandle<ScopeInfo> outer_scope);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<ScopeInfo> ScopeInfo::Create(LocalIsolate* isolate, Zone* zone,
                                        Scope* scope,
                                        MaybeHandle<ScopeInfo> outer_scope);

// static
Handle<ScopeInfo> ScopeInfo::CreateForWithScope(
    Isolate* isolate, MaybeHandle<ScopeInfo> outer_scope) {
  const bool has_outer_scope_info = !outer_scope.is_null();
  const int length = kVariablePartIndex + (has_outer_scope_info ? 1 : 0);

  Factory* factory = isolate->factory();
  Handle<ScopeInfo> scope_info = factory->NewScopeInfo(length);

  // Encode the flags.
  uint32_t flags =
      ScopeTypeBits::encode(WITH_SCOPE) |
      SloppyEvalCanExtendVarsBit::encode(false) |
      LanguageModeBit::encode(LanguageMode::kSloppy) |
      DeclarationScopeBit::encode(false) |
      ReceiverVariableBits::encode(VariableAllocationInfo::NONE) |
      ClassScopeHasPrivateBrandBit::encode(false) |
      HasSavedClassVariableBit::encode(false) | HasNewTargetBit::encode(false) |
      FunctionVariableBits::encode(VariableAllocationInfo::NONE) |
      IsAsmModuleBit::encode(false) | HasSimpleParametersBit::encode(true) |
      FunctionKindBits::encode(FunctionKind::kNormalFunction) |
      HasOuterScopeInfoBit::encode(has_outer_scope_info) |
      IsDebugEvaluateScopeBit::encode(false) |
      ForceContextAllocationBit::encode(false) |
      PrivateNameLookupSkipsOuterClassBit::encode(false) |
      HasContextExtensionSlotBit::encode(true) | IsHiddenBit::encode(false) |
      IsWrappedFunctionBit::encode(false);
  scope_info->set_flags(flags, kRelaxedStore);

  scope_info->set_parameter_count(0);
  scope_info->set_context_local_count(0);

  scope_info->set_position_info_start(0);
  scope_info->set_position_info_end(0);

  int index = kVariablePartIndex;
  DCHECK_EQ(index, scope_info->FunctionVariableInfoIndex());
  DCHECK_EQ(index, scope_info->InferredFunctionNameIndex());
  DCHECK_EQ(index, scope_info->OuterScopeInfoIndex());
  if (has_outer_scope_info) {
    Tagged<ScopeInfo> outer = *outer_scope.ToHandleChecked();
    scope_info->set(index++, outer);
  }
  DCHECK_EQ(index, scope_info->DependentCodeIndex());
  DCHECK_EQ(index, scope_info->length());
  DCHECK_EQ(length, scope_info->length());
  DCHECK_EQ(0, scope_info->ParameterCount());
  DCHECK_EQ(scope_info->ContextHeaderLength(), scope_info->ContextLength());
  return scope_info;
}

// static
Handle<ScopeInfo> ScopeInfo::CreateGlobalThisBinding(Isolate* isolate) {
  return CreateForBootstrapping(isolate, BootstrappingType::kScript);
}

// static
Handle<ScopeInfo> ScopeInfo::CreateForEmptyFunction(Isolate* isolate) {
  return CreateForBootstrapping(isolate, BootstrappingType::kFunction);
}

// static
Handle<ScopeInfo> ScopeInfo::CreateForNativeContext(Isolate* isolate) {
  return CreateForBootstrapping(isolate, BootstrappingType::kNative);
}

// static
Handle<ScopeInfo> ScopeInfo::CreateForShadowRealmNativeContext(
    Isolate* isolate) {
  return CreateForBootstrapping(isolate, BootstrappingType::kShadowRealm);
}

// static
Handle<ScopeInfo> ScopeInfo::CreateForBootstrapping(Isolate* isolate,
                                                    BootstrappingType type) {
  const int parameter_count = 0;
  const bool is_empty_function = type == BootstrappingType::kFunction;
  const bool is_native_context = (type == BootstrappingType::kNative) ||
                                 (type == BootstrappingType::kShadowRealm);
  const bool is_script = type == BootstrappingType::kScript;
  const bool is_shadow_realm = type == BootstrappingType::kShadowRealm;
  const bool has_const_tracking_let_side_data = is_script;
  const int context_local_count =
      is_empty_function || is_native_context ? 0 : 1;
  const bool has_inferred_function_name = is_empty_function;
  // NOTE: Local names are always inlined here, since context_local_count < 2.
  DCHECK_LT(context_local_count, kScopeInfoMaxInlinedLocalNamesSize);
  const int length = kVariablePartIndex + 2 * context_local_count +
                     (is_empty_function ? kFunctionNameEntries : 0) +
                     (has_inferred_function_name ? 1 : 0);

  Factory* factory = isolate->factory();
  Handle<ScopeInfo> scope_info =
      factory->NewScopeInfo(length, AllocationType::kReadOnly);
  DisallowGarbageCollection _nogc;
  // Encode the flags.
  DCHECK_IMPLIES(is_shadow_realm || is_script, !is_empty_function);
  uint32_t flags =
      ScopeTypeBits::encode(
          is_empty_function
              ? FUNCTION_SCOPE
              : (is_shadow_realm ? SHADOW_REALM_SCOPE : SCRIPT_SCOPE)) |
      SloppyEvalCanExtendVarsBit::encode(false) |
      LanguageModeBit::encode(LanguageMode::kSloppy) |
      DeclarationScopeBit::encode(true) |
      ReceiverVariableBits::encode(is_script ? VariableAllocationInfo::CONTEXT
                                             : VariableAllocationInfo::UNUSED) |
      ClassScopeHasPrivateBrandBit::encode(false) |
      HasSavedClassVariableBit::encode(false) | HasNewTargetBit::encode(false) |
      FunctionVariableBits::encode(is_empty_function
                                       ? VariableAllocationInfo::UNUSED
                                       : VariableAllocationInfo::NONE) |
      HasInferredFunctionNameBit::encode(has_inferred_function_name) |
      IsAsmModuleBit::encode(false) | HasSimpleParametersBit::encode(true) |
      FunctionKindBits::encode(FunctionKind::kNormalFunction) |
      HasOuterScopeInfoBit::encode(false) |
      IsDebugEvaluateScopeBit::encode(false) |
      ForceContextAllocationBit::encode(false) |
      PrivateNameLookupSkipsOuterClassBit::encode(false) |
      HasContextExtensionSlotBit::encode(is_native_context ||
                                         has_const_tracking_let_side_data) |
      IsHiddenBit::encode(false) | IsWrappedFunctionBit::encode(false);
  Tagged<ScopeInfo> raw_scope_info = *scope_info;
  raw_scope_info->set_flags(flags, kRelaxedStore);
  raw_scope_info->set_parameter_count(parameter_count);
  raw_scope_info->set_context_local_count(context_local_count);
  raw_scope_info->set_position_info_start(0);
  raw_scope_info->set_position_info_end(0);

  int index = kVariablePartIndex;

  // Here we add info for context-allocated "this".
  DCHECK_EQ(index, raw_scope_info->ContextLocalNamesIndex());
  ReadOnlyRoots roots(isolate);
  if (context_local_count) {
    raw_scope_info->set(index++, roots.this_string());
  }
  DCHECK_EQ(index, raw_scope_info->ContextLocalInfosIndex());
  if (context_local_count > 0) {
    const uint32_t value =
        VariableModeBits::encode(VariableMode::kConst) |
        InitFlagBit::encode(kCreatedInitialized) |
        MaybeAssignedFlagBit::encode(kNotAssigned) |
        ParameterNumberBits::encode(ParameterNumberBits::kMax) |
        IsStaticFlagBit::encode(IsStaticFlag::kNotStatic);
    raw_scope_info->set(index++, Smi::FromInt(value));
  }

  DCHECK_EQ(index, raw_scope_info->FunctionVariableInfoIndex());
  if (is_empty_function) {
    raw_scope_info->set(index++, roots.empty_string());
    raw_scope_info->set(index++, Smi::zero());
  }
  DCHECK_EQ(index, raw_scope_info->InferredFunctionNameIndex());
  if (has_inferred_function_name) {
    raw_scope_info->set(index++, roots.empty_string());
  }
  DCHECK_EQ(index, raw_scope_info->OuterScopeInfoIndex());
  DCHECK_EQ(index, raw_scope_info->DependentCodeIndex());
  DCHECK_EQ(index, raw_scope_info->length());
  DCHECK_EQ(length, raw_scope_info->length());
  DCHECK_EQ(raw_scope_info->ParameterCount(), parameter_count);
  if (is_empty_function || is_native_context) {
    DCHECK_EQ(raw_scope_info->ContextLength(), 0);
  } else {
    DCHECK_EQ(raw_scope_info->ContextLength(),
              raw_scope_info->ContextHeaderLength() + 1);
  }

  return scope_info;
}

Tagged<Object> ScopeInfo::get(int index) const {
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return get(cage_base, index);
}

Tagged<Object> ScopeInfo::get(PtrComprCageBase cage_base, int index) const {
  DCHECK_LT(static_cast<unsigned>(index), static_cast<unsigned>(length()));
  return TaggedField<Object>::Relaxed_Load(cage_base, *this,
                                           OffsetOfElementAt(index));
}

void ScopeInfo::set(int index, Tagged<Smi> value) {
  DCHECK_LT(static_cast<unsigned>(index), static_cast<unsigned>(length()));
  DCHECK(IsSmi(Tagged<Object>(value)));
  int offset = OffsetOfElementAt(index);
  RELAXED_WRITE_FIELD(*this, offset, value);
}

void ScopeInfo::set(int index, Tagged<Object> value, WriteBarrierMode mode) {
  DCHECK_LT(static_cast<unsigned>(index), static_cast<unsigned>(length()));
  int offset = OffsetOfElementAt(index);
  RELAXED_WRITE_FIELD(*this, offset, value);
  CONDITIONAL_WRITE_BARRIER(*this, offset, value, mode);
}

void ScopeInfo::CopyElements(Isolate* isolate, int dst_index,
                             Tagged<ScopeInfo> src, int src_index, int len,
                             WriteBarrierMode mode) {
  if (len == 0) return;
  DCHECK_LE(src_index + len, src->length());
  DisallowGarbageCollection no_gc;

  ObjectSlot dst_slot(RawFieldOfElementAt(dst_index));
  ObjectSlot src_slot(src->RawFieldOfElementAt(src_index));
  isolate->heap()->CopyRange(*this, dst_slot, src_slot, len, mode);
}

ObjectSlot ScopeInfo::RawFieldOfElementAt(int index) {
  return RawField(OffsetOfElementAt(index));
}

int ScopeInfo::length() const {
  // AllocatedSize() is generated by Torque and represents the size in bytes of
  // the object, as computed from flags, context_local_count, and possibly
  // module_variable_count. Convert that size into a number of slots.
  return (AllocatedSize() - HeapObject::kHeaderSize) / kTaggedSize;
}

Tagged<ScopeInfo> ScopeInfo::Empty(Isolate* isolate) {
  return ReadOnlyRoots(isolate).empty_scope_info();
}

bool ScopeInfo::IsEmpty() const { return IsEmptyBit::decode(Flags()); }

ScopeType ScopeInfo::scope_type() const {
  DCHECK(!this->IsEmpty());
  return ScopeTypeBits::decode(Flags());
}

bool ScopeInfo::is_script_scope() const {
  return !this->IsEmpty() &&
         (scope_type() == SCRIPT_SCOPE || scope_type() == REPL_MODE_SCOPE);
}

bool ScopeInfo::SloppyEvalCanExtendVars() const {
  bool sloppy_eval_can_extend_vars =
      SloppyEvalCanExtendVarsBit::decode(Flags());
  DCHECK_IMPLIES(sloppy_eval_can_extend_vars, is_sloppy(language_mode()));
  DCHECK_IMPLIES(sloppy_eval_can_extend_vars, is_declaration_scope());
  return sloppy_eval_can_extend_vars;
}

LanguageMode ScopeInfo::language_mode() const {
  return LanguageModeBit::decode(Flags());
}

bool ScopeInfo::is_declaration_scope() const {
  return DeclarationScopeBit::decode(Flags());
}

int ScopeInfo::ContextLength() const {
  if (this->IsEmpty()) return 0;
  int context_locals = ContextLocalCount();
  bool function_name_context_slot = HasContextAllocatedFunctionName();
  bool force_context = ForceContextAllocationBit::decode(Flags());
  bool has_context =
      context_locals > 0 || force_context || function_name_context_slot ||
      scope_type() == WITH_SCOPE || scope_type() == CLASS_SCOPE ||
      (scope_type() == BLOCK_SCOPE && SloppyEvalCanExtendVars() &&
       is_declaration_scope()) ||
      (scope_type() == FUNCTION_SCOPE && SloppyEvalCanExtendVars()) ||
      (scope_type() == FUNCTION_SCOPE && IsAsmModule()) ||
      scope_type() == MODULE_SCOPE;

  if (!has_context) return 0;
  return ContextHeaderLength() + context_locals +
         (function_name_context_slot ? 1 : 0);
}

// Needs to be kept in sync with Scope::UniqueIdInScript and
// SharedFunctionInfo::UniqueIdInScript.
int ScopeInfo::UniqueIdInScript() const {
  // Script scopes start "before" the script to avoid clashing with a scope that
  // starts on character 0.
  if (is_script_scope() || scope_type() == EVAL_SCOPE ||
      scope_type() == MODULE_SCOPE) {
    return -2;
  }
  // Wrapped functions start before the function body, but after the script
  // start, to avoid clashing with a scope starting on character 0.
  if (IsWrappedFunctionScope()) {
    return -1;
  }
  // Default constructors have the same start position as their parent class
  // scope. Use the next char position to distinguish this scope.
  return StartPosition() + IsDefaultConstructor(function_kind());
}

bool ScopeInfo::HasContextExtensionSlot() const {
  return HasContextExtensionSlotBit::decode(Flags());
}

bool ScopeInfo::SomeContextHasExtension() const {
  return SomeContextHasExtensionBit::decode(Flags());
}

void ScopeInfo::mark_some_context_has_extension() {
  set_flags(SomeContextHasExtensionBit::update(Flags(), true), kRelaxedStore);
}

int ScopeInfo::ContextHeaderLength() const {
  return HasContextExtensionSlot() ? Context::MIN_CONTEXT_EXTENDED_SLOTS
                                   : Context::MIN_CONTEXT_SLOTS;
}

bool ScopeInfo::HasReceiver() const {
  return VariableAllocationInfo::NONE != ReceiverVariableBits::decode(Flags());
}

bool ScopeInfo::HasAllocatedReceiver() const {
  // The receiver is allocated and needs to be deserialized during reparsing
  // when:
  // 1. During the initial parsing, it's been observed that the inner
  //    scopes are accessing this, so the receiver should be allocated
  //    again. This can be inferred when the receiver variable is
  //    recorded as being allocated on the stack or context.
  // 2. The scope is created as a debug evaluate scope, so this is not
  //    an actual reparse, we are not sure if the inner scope will access
  //    this, but the receiver should be allocated just in case.
  VariableAllocationInfo allocation = ReceiverVariableBits::decode(Flags());
  return allocation == VariableAllocationInfo::STACK ||
         allocation == VariableAllocationInfo::CONTEXT ||
         IsDebugEvaluateScope();
}

bool ScopeInfo::ClassScopeHasPrivateBrand() const {
  return ClassScopeHasPrivateBrandBit::decode(Flags());
}

bool ScopeInfo::HasSavedClassVariable() const {
  return HasSavedClassVariableBit::decode(Flags());
}

bool ScopeInfo::HasNewTarget() const {
  return HasNewTargetBit::decode(Flags());
}

bool ScopeInfo::HasFunctionName() const {
  return VariableAllocationInfo::NONE != FunctionVariableBits::decode(Flags());
}

bool ScopeInfo::HasContextAllocatedFunctionName() const {
  return VariableAllocationInfo::CONTEXT ==
         FunctionVariableBits::decode(Flags());
}

bool ScopeInfo::HasInferredFunctionName() const {
  return HasInferredFunctionNameBit::decode(Flags());
}

bool ScopeInfo::HasPositionInfo() const { return !this->IsEmpty(); }

bool ScopeInfo::HasSharedFunctionName() const {
  return FunctionName() != SharedFunctionInfo::kNoSharedNameSentinel;
}

void ScopeInfo::SetFunctionName(Tagged<UnionOf<Smi, String>> name) {
  DCHECK(HasFunctionName());
  DCHECK(IsString(name) || name == SharedFunctionInfo::kNoSharedNameSentinel);
  DCHECK_IMPLIES(HasContextAllocatedFunctionName(), IsInternalizedString(name));
  set_function_variable_info_name(name);
}

void ScopeInfo::SetInferredFunctionName(Tagged<String> name) {
  DCHECK(HasInferredFunctionName());
  set_inferred_function_name(name);
}

bool ScopeInfo::HasOuterScopeInfo() const {
  return HasOuterScopeInfoBit::decode(Flags
```