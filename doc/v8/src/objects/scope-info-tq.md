Response:
Let's break down the thought process for analyzing the `scope-info.tq` file.

1. **Understanding the File Extension:** The first giveaway is the `.tq` extension. The prompt itself highlights this, correctly identifying it as a Torque source file in V8. This immediately tells us this isn't standard C++ or JavaScript. Torque is a V8-specific language for defining object layouts and low-level operations.

2. **Initial Scan for Keywords:** I'd quickly scan the file for keywords like `extern`, `enum`, `bitfield`, `struct`, `class`, `const`, `macro`, and `@`. These are strong indicators of definitions and declarations within the Torque language.

3. **Deconstructing the Enums:** The `enum` definitions are relatively straightforward. They define sets of named constants representing different states or types related to scopes and variables. I'd list these out and briefly explain their purpose based on the names. For instance, `ScopeType` clearly enumerates different kinds of scopes (SCRIPT, CLASS, FUNCTION, etc.).

4. **Analyzing the Bitfields and Structs:** The `bitfield struct ScopeFlags` is more complex but crucial. The `bitfield` keyword suggests efficient storage using individual bits. I'd go through each field, noting its name, type, and bit width. The comments provide valuable context here (e.g., "In class scope, this indicates whether the class has a private brand"). The other structs (`PositionInfo`, `FunctionVariableInfo`, `ModuleVariable`) are simpler, defining grouped data with named fields.

5. **Focusing on the `ScopeInfo` Class:** The `extern class ScopeInfo extends HeapObject` is the core of the file. This defines the structure of the `ScopeInfo` object in V8's heap. I'd systematically examine each member:
    * **Flags:**  The `flags: ScopeFlags` is immediately important, connecting back to the bitfield structure.
    * **Padding:**  The conditional padding (`@if(TAGGED_SIZE_8_BYTES)`) indicates platform-specific memory layout considerations.
    * **Counters:** `parameter_count` and `context_local_count` are clearly related to the number of variables.
    * **Position Information:** `position_info` points to source code locations.
    * **Conditional Members:**  The `?[]` syntax is crucial. It means a field is *optional* and only exists under certain conditions, specified within the brackets. For example, `module_variable_count` only exists for `MODULE_SCOPE`. This requires careful attention to the conditions. I'd explicitly list the conditions for each optional member.
    * **Arrays:**  Arrays like `context_local_names` and `module_variables` store collections of related data. The conditional sizing of `context_local_names` is interesting and suggests optimization strategies.
    * **Object References:**  Fields like `context_local_names_hashtable`, `outer_scope_info`, and `module_info` point to other V8 objects, indicating relationships and data structures.
    * **Dependent Code:** `dependent_code` hints at optimizations related to code invalidation.

6. **Examining the Macros:** The `extern macro` and `@export macro` definitions describe reusable code snippets within Torque. `EmptyScopeInfoConstant` is a simple constant. `NameToIndexHashTableLookup` suggests looking up names in a hash table. The `IndexOfInlinedLocalName` and `IndexOfLocalName` macros are crucial for understanding how variable names are resolved within a scope. The conditional logic in `IndexOfLocalName` based on `kMaxInlinedLocalNamesSize` is a performance optimization worth noting.

7. **Connecting to JavaScript (Conceptual):**  While this is a low-level file, I'd think about how these concepts map to JavaScript. Scopes in JavaScript (global, function, block) directly relate to the `ScopeType` enum. Variable declarations (`let`, `const`, `var`) connect to `VariableMode`. Concepts like closures and nested scopes relate to `outer_scope_info`. Private class members are linked to the `class_scope_has_private_brand` flag.

8. **Generating JavaScript Examples:** To illustrate the connection to JavaScript, I'd create simple code snippets that demonstrate different scope types and variable declarations. The goal isn't to show *exactly* how the Torque code works, but to illustrate the high-level JavaScript concepts that these low-level structures represent.

9. **Inferring Code Logic and Examples:** The `IndexOfLocalName` macro presents a good opportunity for demonstrating code logic. I'd create a simple scenario with a `ScopeInfo` and a name and trace how the macro would behave based on whether the names are inlined or in a hash table.

10. **Identifying Potential Programming Errors:**  By understanding how scopes and variables are managed, I could infer potential JavaScript errors. For example, using `let` or `const` before declaration, accessing variables in the wrong scope, or redeclaring variables.

11. **Structuring the Output:** Finally, I'd organize the findings into logical sections (file type, core functionality, enum explanations, struct/bitfield details, `ScopeInfo` class breakdown, macro explanations, JavaScript connections, code logic example, and common errors). This makes the information easier to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "Maybe I should try to understand every single bit in `ScopeFlags` immediately."
* **Correction:** "No, focus on the high-level purpose first. The names and comments provide enough initial information. I can delve deeper into specific bits if needed later."
* **Initial thought:** "Should I try to write Torque code examples?"
* **Correction:** "The prompt asks for JavaScript examples, as the connection is between the Torque structure and JavaScript behavior. Torque is too low-level for typical user programming."
* **Initial thought:** "Just list the members of `ScopeInfo`."
* **Correction:** "Explain the *purpose* of each member and especially the conditions for optional members. This provides more valuable insight."
* **Initial thought:**  "The code logic example should be complex."
* **Correction:** "Keep it simple and focused on illustrating the inlining vs. hash table lookup in `IndexOfLocalName`."

By following this structured approach and iteratively refining my understanding, I can effectively analyze the `scope-info.tq` file and generate a comprehensive explanation.
好的，让我们来分析一下 `v8/src/objects/scope-info.tq` 这个 V8 Torque 源代码文件的功能。

**1. 文件类型和核心功能：**

*   正如你所说，`.tq` 扩展名表明这是一个 **V8 Torque 源代码文件**。
*   它的核心功能是 **定义 `ScopeInfo` 对象的结构和相关枚举、位域等**。`ScopeInfo` 是 V8 引擎中用于描述 JavaScript 代码作用域信息的关键数据结构。  它存储了关于特定作用域的各种属性，例如作用域类型、变量信息、嵌套关系等等。

**2. 详细功能分解：**

*   **定义 `ScopeType` 枚举：**  列举了 JavaScript 中各种作用域的类型，例如 `SCRIPT_SCOPE`（脚本作用域）、`FUNCTION_SCOPE`（函数作用域）、`BLOCK_SCOPE`（块级作用域）等。这有助于 V8 区分不同类型的代码作用域。
*   **定义 `VariableAllocationInfo` 枚举：**  描述了变量是如何分配的，例如 `STACK`（栈上分配）、`CONTEXT`（上下文中分配）。
*   **定义 `VariableMode` 枚举：**  表示变量的声明方式，例如 `kLet`、`kConst`、`kVar` 等。
*   **定义 `InitializationFlag` 枚举：**  指示变量是否需要初始化。
*   **定义 `IsStaticFlag` 枚举：**  用于标记是否是静态成员（主要用于类）。
*   **定义 `MaybeAssignedFlag` 枚举：**  指示变量是否可能被赋值。
*   **定义 `ScopeFlags` 位域结构体：**  这是一个关键的结构，使用位域有效地存储了作用域的各种布尔属性和枚举值，例如：
    *   `scope_type`: 作用域类型（使用 `ScopeType` 枚举）。
    *   `sloppy_eval_can_extend_vars`:  指示 `eval` 是否可以扩展变量。
    *   `language_mode`:  代码的语言模式（严格模式或非严格模式）。
    *   `declaration_scope`: 是否为声明作用域。
    *   `receiver_variable`:  `this` 变量的分配信息。
    *   `class_scope_has_private_brand`: 类作用域是否拥有私有 brand。
    *   ... 以及其他与作用域特性相关的标志。
*   **定义 `PositionInfo` 结构体：**  存储作用域在源代码中的起始和结束位置。
*   **定义 `FunctionVariableInfo` 结构体：**  存储函数变量的名称以及在上下文或栈中的位置。
*   **定义 `VariableProperties` 位域结构体：** 存储变量的属性，例如模式、初始化标志等。
*   **定义 `ModuleVariable` 结构体：**  存储模块中导出的变量信息。
*   **定义 `ScopeInfo` 类：**  这是最核心的部分，它定义了 `ScopeInfo` 对象的布局：
    *   `flags`:  `ScopeFlags` 位域，存储作用域的各种标志。
    *   `parameter_count`:  参数的数量。
    *   `context_local_count`:  在上下文中分配的局部变量的数量。
    *   `position_info`:  `PositionInfo` 结构体，存储作用域的位置信息。
    *   `context_local_names`:  存储上下文中局部变量的名称（如果数量较少，会直接内联存储）。
    *   `context_local_names_hashtable`:  当局部变量数量较多时，使用哈希表来存储名称。
    *   `context_local_infos`:  存储上下文中局部变量的属性（使用 `VariableProperties`）。
    *   `saved_class_variable_info`:  用于存储类变量的信息（用于私有方法等）。
    *   `function_variable_info`:  `FunctionVariableInfo` 结构体，存储函数变量的信息。
    *   `inferred_function_name`:  推断出的函数名。
    *   `outer_scope_info`:  指向外部作用域的 `ScopeInfo` 对象的指针，用于实现作用域链。
    *   `module_info`:  模块作用域的元数据。
    *   `module_variables`:  存储模块中导出的变量。
    *   `dependent_code`:  依赖于此 `ScopeInfo` 的代码对象。
*   **定义宏 (`macro`)：** 定义了一些用于操作 `ScopeInfo` 的辅助函数，例如：
    *   `EmptyScopeInfoConstant`: 获取一个空的 `ScopeInfo` 常量。
    *   `NameToIndexHashTableLookup`: 在哈希表中查找变量名对应的索引。
    *   `IndexOfInlinedLocalName`: 在内联存储的局部变量名数组中查找索引。
    *   `IndexOfLocalName`:  查找局部变量名的索引，根据是否内联选择不同的查找方式。

**3. 与 JavaScript 功能的关系及示例：**

`ScopeInfo` 对象在 JavaScript 的执行过程中扮演着至关重要的角色，它存储了 V8 引擎理解和管理 JavaScript 代码作用域所需的所有信息。

**JavaScript 示例：**

```javascript
function outerFunction(x) {
  let outerVar = 10;

  function innerFunction(y) {
    const innerConst = 20;
    console.log(x + outerVar + y + innerConst);
  }

  innerFunction(5);
}

outerFunction(3);
```

在这个例子中，会创建多个 `ScopeInfo` 对象：

*   **全局作用域：** 对应一个 `SCRIPT_SCOPE` 的 `ScopeInfo`。
*   **`outerFunction` 的函数作用域：** 对应一个 `FUNCTION_SCOPE` 的 `ScopeInfo`。这个 `ScopeInfo` 会记录参数 `x` 和局部变量 `outerVar` 的信息，例如它们的 `VariableMode`（`kVar` 对于 `x`，`kLet` 对于 `outerVar`），以及它们在上下文中的位置。
*   **`innerFunction` 的函数作用域：** 对应另一个 `FUNCTION_SCOPE` 的 `ScopeInfo`。这个 `ScopeInfo` 会记录参数 `y` 和局部常量 `innerConst` 的信息（`VariableMode` 为 `kConst`），以及通过 `outer_scope_info` 指向 `outerFunction` 的作用域，从而实现闭包。

**具体到 `ScopeInfo` 的字段：**

*   对于 `outerFunction` 的 `ScopeInfo`，`parameter_count` 为 1，`context_local_count` 至少为 1（`outerVar`），`flags.scope_type` 为 `FUNCTION_SCOPE`。
*   对于 `innerFunction` 的 `ScopeInfo`，`parameter_count` 为 1，`context_local_count` 至少为 1（`innerConst`），`flags.scope_type` 为 `FUNCTION_SCOPE`，`outer_scope_info` 会指向 `outerFunction` 的 `ScopeInfo`。
*   变量 `x`、`outerVar`、`y`、`innerConst` 的信息（例如 `VariableMode`、是否需要初始化等）会存储在 `context_local_infos` 数组中。它们的名称可能会存储在 `context_local_names` 中，或者如果数量很多，则存储在 `context_local_names_hashtable` 中。

**4. 代码逻辑推理及假设输入输出：**

让我们来看一下 `IndexOfLocalName` 这个宏的逻辑：

**假设输入：**

*   `scopeInfo`:  一个指向 `outerFunction` 的 `ScopeInfo` 对象的指针。
*   `name`:  一个表示字符串 `"outerVar"` 的 `Name` 对象。

**代码逻辑：**

1. 获取 `scopeInfo` 的 `context_local_count`，假设其值为 1。
2. 判断 `count` (1) 是否小于 `kMaxInlinedLocalNamesSize`。 假设 `kMaxInlinedLocalNamesSize` 为一个大于 1 的值（例如 4）。
3. 由于条件成立，调用 `IndexOfInlinedLocalName(scopeInfo, name)`。
4. 在 `IndexOfInlinedLocalName` 中，遍历 `scopeInfo.context_local_names` 数组（只有一个元素）。
5. 将输入的 `name` (指向 `"outerVar"`) 与 `scopeInfo.context_local_names[0]` 进行比较。 假设 `scopeInfo.context_local_names[0]` 存储的是指向 `"outerVar"` 的 `String` 对象。
6. 由于 `TaggedEqual` 返回真，宏返回索引 `i`，即 0。

**输出：**

*   宏 `IndexOfLocalName` 返回值：`0`，表示 `"outerVar"` 是该作用域中索引为 0 的局部变量。

**假设输入（另一种情况）：**

*   `scopeInfo`:  一个拥有大量局部变量的函数的 `ScopeInfo` 对象，假设 `context_local_count` 为 100。
*   `name`:  一个表示字符串 `"myVeryLongLocalVariableName"` 的 `Name` 对象。

**代码逻辑：**

1. 获取 `scopeInfo` 的 `context_local_count`，值为 100。
2. 判断 `count` (100) 是否小于 `kMaxInlinedLocalNamesSize` (假设为 4)。
3. 由于条件不成立，调用 `NameToIndexHashTableLookup(scopeInfo.context_local_names_hashtable, name)`。
4. `NameToIndexHashTableLookup` 会在 `scopeInfo` 的哈希表中查找与 `name` 相等的键，并返回其对应的索引。

**输出：**

*   宏 `IndexOfLocalName` 返回值：如果在哈希表中找到了 `"myVeryLongLocalVariableName"`，则返回其对应的索引；否则，会跳转到 `NotFound` 标签（虽然这里没有明确的返回值，但在实际的 Torque 代码中会处理 `NotFound` 的情况）。

**5. 涉及用户常见的编程错误：**

`ScopeInfo` 的设计和使用与一些常见的 JavaScript 编程错误密切相关：

*   **未声明的变量：** 当尝试访问一个在当前作用域或其父作用域中未声明的变量时，V8 需要查找作用域链。如果找不到，就会抛出 `ReferenceError`。 `ScopeInfo` 及其 `outer_scope_info` 字段用于遍历这个作用域链。
*   **块级作用域错误（`let` 和 `const`）：** 使用 `let` 和 `const` 声明的变量具有块级作用域。如果在声明之前访问这些变量，会导致 "暂时性死区" 错误。 `ScopeInfo` 中的 `scope_type` 和变量的 `VariableMode` 帮助 V8 实施这些规则。
    ```javascript
    function example() {
      console.log(myLet); // ReferenceError: Cannot access 'myLet' before initialization
      let myLet = 5;
    }
    ```
*   **变量提升（`var`）：** 使用 `var` 声明的变量会被提升到其所在函数或全局作用域的顶部。虽然不会报错，但可能导致意外的行为。 `ScopeInfo` 中 `VariableMode` 为 `kVar` 的变量会受到提升的影响。
    ```javascript
    function example() {
      console.log(myVar); // 输出 undefined，不会报错
      var myVar = 10;
    }
    ```
*   **闭包中的变量访问：** 闭包允许内部函数访问其外部函数的作用域中的变量。 `ScopeInfo` 的 `outer_scope_info` 字段是实现闭包的关键，它维护了作用域链。 错误地理解闭包可能导致意外的值或行为。
    ```javascript
    function createCounter() {
      let count = 0;
      return function() {
        count++;
        return count;
      };
    }

    const counter1 = createCounter();
    console.log(counter1()); // 1
    console.log(counter1()); // 2
    ```
*   **`eval` 的作用域问题：** `eval` 可以在运行时执行字符串形式的 JavaScript 代码，并且可以访问和修改当前作用域的变量（在非严格模式下，甚至可以扩展作用域）。 `ScopeInfo` 的 `sloppy_eval_can_extend_vars` 标志和相关的机制用于处理 `eval` 的作用域影响。

总结来说，`v8/src/objects/scope-info.tq` 定义了 V8 引擎中用于表示 JavaScript 代码作用域的关键数据结构，它包含了作用域的类型、变量信息、嵌套关系等，是 V8 理解和执行 JavaScript 代码的基础。理解 `ScopeInfo` 的结构有助于我们更深入地了解 JavaScript 的作用域机制以及可能出现的编程错误。

Prompt: 
```
这是目录为v8/src/objects/scope-info.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/scope-info.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern macro EmptyScopeInfoConstant(): ScopeInfo;
const kEmptyScopeInfo: ScopeInfo = EmptyScopeInfoConstant();

extern enum ScopeType extends uint32 {
  // The empty scope info for builtins and NativeContexts is allocated
  // in a way that it gets the first scope type in line, see
  // Heap::CreateInitialMaps(). It's always guarded with the IsEmpty
  // bit, so it doesn't matter what scope type it gets.
  SCRIPT_SCOPE,
  REPL_MODE_SCOPE,
  CLASS_SCOPE,
  EVAL_SCOPE,
  FUNCTION_SCOPE,
  MODULE_SCOPE,
  CATCH_SCOPE,
  BLOCK_SCOPE,
  WITH_SCOPE,
  SHADOW_REALM_SCOPE
}

extern enum VariableAllocationInfo extends uint32 {
  NONE,
  STACK,
  CONTEXT,
  UNUSED
}

extern enum VariableMode extends uint32 {
  kLet,
  kConst,
  kUsing,
  kAwaitUsing,
  kVar,
  kTemporary,
  kDynamic,
  kDynamicGlobal,
  kDynamicLocal,
  kPrivateMethod,
  kPrivateSetterOnly,
  kPrivateGetterOnly,
  kPrivateGetterAndSetter
}

extern enum InitializationFlag extends uint32 {
  kNeedsInitialization,
  kCreatedInitialized
}

extern enum IsStaticFlag extends uint32 { kNotStatic, kStatic }

extern enum MaybeAssignedFlag extends uint32 { kNotAssigned, kMaybeAssigned }

// Properties of scopes.
bitfield struct ScopeFlags extends uint32 {
  scope_type: ScopeType: 4 bit;
  sloppy_eval_can_extend_vars: bool: 1 bit;
  language_mode: LanguageMode: 1 bit;
  declaration_scope: bool: 1 bit;
  receiver_variable: VariableAllocationInfo: 2 bit;
  // In class scope, this indicates whether the class has a private brand.
  // In constructor scope, this indicates whether the constructor needs
  // private brand initialization.
  class_scope_has_private_brand: bool: 1 bit;
  has_saved_class_variable: bool: 1 bit;
  has_new_target: bool: 1 bit;
  // TODO(cbruni): Combine with function variable field when only storing the
  // function name.
  function_variable: VariableAllocationInfo: 2 bit;
  has_inferred_function_name: bool: 1 bit;
  is_asm_module: bool: 1 bit;
  has_simple_parameters: bool: 1 bit;
  function_kind: FunctionKind: 5 bit;
  has_outer_scope_info: bool: 1 bit;
  is_debug_evaluate_scope: bool: 1 bit;
  force_context_allocation: bool: 1 bit;
  private_name_lookup_skips_outer_class: bool: 1 bit;
  // Indicates that the context has a context extension slot.
  has_context_extension_slot: bool: 1 bit;
  // Indicates that there are contexts with a context extension (meaningful
  // only for contexts with "sloppy_eval_can_extend_vars" flag set).
  some_context_has_extension: bool: 1 bit;
  is_hidden: bool: 1 bit;
  is_empty: bool: 1 bit;
  is_wrapped_function: bool: 1 bit;
}

struct PositionInfo {
  start: Smi;
  end: Smi;
}

struct FunctionVariableInfo {
  name: String|Zero;
  context_or_stack_slot_index: Smi;
}

bitfield struct VariableProperties extends uint31 {
  variable_mode: VariableMode: 4 bit;
  init_flag: InitializationFlag: 1 bit;
  maybe_assigned_flag: MaybeAssignedFlag: 1 bit;
  parameter_number: uint32: 16 bit;
  is_static_flag: IsStaticFlag: 1 bit;
}

struct ModuleVariable {
  name: String;
  index: Smi;
  properties: SmiTagged<VariableProperties>;
}

const kMaxInlinedLocalNamesSize:
    constexpr int32 generates 'kScopeInfoMaxInlinedLocalNamesSize';

@generateBodyDescriptor
extern class ScopeInfo extends HeapObject {
  @cppRelaxedLoad @cppRelaxedStore const flags: ScopeFlags;

  @if(TAGGED_SIZE_8_BYTES) optional_padding: uint32;
  @ifnot(TAGGED_SIZE_8_BYTES) optional_padding: void;

  // The number of parameters. For non-function scopes this is 0.
  parameter_count: Smi;

  // The number of non-parameter and parameter variables allocated in the
  // context.
  const context_local_count: Smi;

  // Contains two slots with a) the startPosition and b) the endPosition.
  position_info: PositionInfo;

  // This value must be before any object values, so that the GC can correctly
  // determine the size of a partially initialized object during
  // deserialization.
  const module_variable_count?
      [flags.scope_type == ScopeType::MODULE_SCOPE]: Smi;

  // Contains the names of inlined local variables and parameters that are
  // allocated in the context. They are stored in increasing order of the
  // context slot index starting with Context::MIN_CONTEXT_SLOTS.
  context_local_names[Convert<intptr>(context_local_count) < kMaxInlinedLocalNamesSize ? context_local_count : 0]:
      String;

  // Contains a hash_map from local names to context slot index.
  // This is only used when local names are not inlined in the scope info.
  context_local_names_hashtable?
      [kMaxInlinedLocalNamesSize <= Convert<intptr>(context_local_count)]:
          NameToIndexHashTable;

  // Contains the variable modes and initialization flags corresponding to
  // the context locals in ContextLocalNames.
  context_local_infos[context_local_count]: SmiTagged<VariableProperties>;

  // If the scope is a class scope and it has static private methods that
  // may be accessed directly or through eval, one slot is reserved to hold
  // the offset in the field storage of the hash table (or the slot index if
  // local names are inlined) for the class variable.
  saved_class_variable_info?[flags.has_saved_class_variable]: Smi;

  // If the scope belongs to a named function expression this part contains
  // information about the function variable. It always occupies two array
  // slots:  a. The name of the function variable.
  //         b. The context or stack slot index for the variable.
  function_variable_info?
      [flags.function_variable !=
       FromConstexpr<VariableAllocationInfo>(VariableAllocationInfo::NONE)]:
          FunctionVariableInfo;

  inferred_function_name?[flags.has_inferred_function_name]: String|Undefined;

  outer_scope_info?[flags.has_outer_scope_info]: ScopeInfo|TheHole;

  // For a module scope, this part contains the SourceTextModuleInfo and the
  // metadata of module-allocated variables. For non-module scopes it is empty.
  module_info?
      [flags.scope_type == ScopeType::MODULE_SCOPE]: SourceTextModuleInfo;
  module_variables[flags.scope_type == ScopeType::MODULE_SCOPE ? module_variable_count : 0]:
      ModuleVariable;

  // EmptyContextExtension-dependent code objects.
  dependent_code?[flags.sloppy_eval_can_extend_vars]: DependentCode;
}

extern macro NameToIndexHashTableLookup(
    NameToIndexHashTable, Name): intptr labels NotFound;

macro IndexOfInlinedLocalName(
    scopeInfo: ScopeInfo, name: Name): intptr labels NotFound {
  const count: intptr = Convert<intptr>(scopeInfo.context_local_count);
  for (let i: intptr = 0; i < count; ++i) {
    if (TaggedEqual(name, scopeInfo.context_local_names[i])) {
      return i;
    }
  }
  goto NotFound;
}

// Returns the index of the named local in a ScopeInfo.
// Assumes that the given name is internalized; uses pointer comparisons.
@export
macro IndexOfLocalName(
    scopeInfo: ScopeInfo, name: Name): intptr labels NotFound {
  const count: intptr = Convert<intptr>(scopeInfo.context_local_count);
  if (count < kMaxInlinedLocalNamesSize) {
    return IndexOfInlinedLocalName(scopeInfo, name) otherwise goto NotFound;
  } else {
    return NameToIndexHashTableLookup(
        scopeInfo.context_local_names_hashtable, name) otherwise goto NotFound;
  }
}

"""

```