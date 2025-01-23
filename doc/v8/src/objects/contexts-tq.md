Response:
Let's break down the thought process to analyze the provided Torque file (`contexts.tq`).

**1. Understanding the Core Request:**

The request asks for the functionality of the file `v8/src/objects/contexts.tq`. It also specifies that since the file ends with `.tq`, it's a Torque source file and requires analysis in that context. The request further asks to relate the functionality to JavaScript, provide examples, infer logic, and highlight common programming errors.

**2. Initial Analysis of the File Content:**

The first step is to scan through the file and identify key elements:

* **Copyright and License:** Standard boilerplate, indicates the file's origin.
* **`@abstract class Context`:**  This immediately suggests a base class for different types of contexts. The `@generateBodyDescriptor` indicates it might influence memory layout. The `GetScopeInfo()` macro and `length` and `elements` members hint at how context data is stored and accessed.
* **`@cppObjectLayoutDefinition class ScriptContextTable`:** Another key data structure, likely used to manage script contexts. The members `capacity`, `length`, `names_to_context_index`, and `objects` provide clues about its purpose (hashing, storing contexts).
* **Several `extern class ... extends Context`:**  This confirms the inheritance structure and indicates different specific context types (Await, Block, Catch, etc.). The `generates 'TNode<Context>'` is a Torque-specific detail about how these classes are represented in the generated code.
* **`extern class FunctionContext extends Context`:**  A specific type of context, likely important for function execution.
* **Constants like `kInitialContextSlotValue`:** These are likely default values.
* **`@export macro AllocateSyntheticFunctionContext(...)`:**  A function-like construct in Torque for creating function contexts.
* **`extern class NativeContext extends Context`:**  Another crucial context type, fundamental to the JavaScript environment.
* **`type Slot<...>`:** Defines a type alias, indicating how context slots are represented (as `intptr`).
* **`macro InitContextSlot<...>` and `macro ContextSlot<...>`:**  These are critical macros for interacting with context slots (setting and getting values). The type parameters suggest strong typing.
* **`extern enum ContextSlot extends intptr constexpr 'Context::Field' { ... }`:**  This is a highly informative section. It defines the different slots within a context, each with a specific purpose and often a type. Many of these slot names are directly related to JavaScript concepts (e.g., `ARRAY_FUNCTION_INDEX`, `PROMISE_FUNCTION_INDEX`).
* **`@export macro LoadContextElement(...)` and `@export macro StoreContextElement(...)`:**  Macros for reading and writing context elements, similar to array access. The different overloads for `intptr`, `Smi`, and `constexpr int32` are typical in low-level code for optimization.
* **`builtin AllocateIfMutableHeapNumberScriptContextSlot(...)` and other `builtin` functions:** These are likely interfaces to C++ runtime functions for more complex operations.
* **`namespace runtime { extern runtime InvalidateDependentCodeForScriptContextSlot(...); }`:** Indicates interaction with the V8 runtime for invalidating optimized code.
* **`macro StoreScriptContextAndUpdateSlotProperty(...)`:** A sophisticated macro for storing context elements, specifically handling side data for optimizations and `let` declarations. The logic inside is quite involved.
* **`macro LoadScriptContextElementImpl(...)` and `macro IsMutableHeapNumber(...)`:** Helper macros for loading and checking mutable heap numbers.
* **`type NoContext extends Smi; extern macro NoContextConstant(): NoContext; const kNoContext: NoContext;`:** Defines a special "no context" value.

**3. Identifying Key Functionalities:**

Based on the identified elements, we can start listing the functionalities:

* **Defining the Context Hierarchy:** The `Context` base class and its derived classes (FunctionContext, ScriptContext, etc.) establish a clear hierarchy for managing different execution environments.
* **Managing Context Slots:** The `ContextSlot` enum and the `ContextSlot`, `InitContextSlot` macros are central to how data is stored and accessed within a context.
* **Native Context Management:** The `NativeContext` and its slots are crucial for storing built-in objects and functions.
* **Script Context Management:** The `ScriptContextTable` likely manages the contexts associated with different scripts.
* **Allocation of Contexts:** The `AllocateSyntheticFunctionContext` macro demonstrates how specific context types are created.
* **Accessing Context Elements:** The `LoadContextElement` and `StoreContextElement` macros provide basic access.
* **Handling Mutable Heap Numbers:** The `AllocateIfMutableHeapNumberScriptContextSlot`, `IsMutableHeapNumber`, and related logic deal with an optimization for numbers in certain contexts.
* **Side Data for `let` Declarations:** The `StoreScriptContextAndUpdateSlotProperty` macro and the related logic handle the complexities of top-level `let` declarations, including invalidating optimized code when their values change.

**4. Connecting to JavaScript:**

Now, map the identified functionalities to JavaScript concepts:

* **Context Hierarchy:**  Relates to the concept of execution contexts in JavaScript (global context, function context, etc.).
* **Context Slots:**  Correspond to the variables and bindings accessible within a specific scope.
* **Native Context:** Holds the global object, built-in functions (like `Array`, `Math`), and other core JavaScript components.
* **Script Context:** Represents the context of a specific script or module.
* **Allocation of Contexts:** Happens when functions are called or new scripts are evaluated.
* **Accessing Context Elements:** Corresponds to variable access within a scope.
* **Mutable Heap Numbers:**  An optimization, not directly visible in JavaScript, but affects performance.
* **Side Data for `let` Declarations:**  Directly related to the behavior of `let` in the global scope, particularly regarding constness and potential reassignments.

**5. Providing JavaScript Examples:**

Create simple JavaScript examples to illustrate the connection:

* **Context Hierarchy:** Show nested functions and how they create different scopes.
* **Native Context:** Demonstrate using built-in objects like `Array` and `Math`.
* **Script Context:** Implicitly shown when running any JavaScript code.
* **Side Data for `let`:** Illustrate the difference between `const` and `let` at the top level and how reassigning `let` can have side effects.

**6. Inferring Logic and Providing Examples:**

Focus on the more complex parts like `StoreScriptContextAndUpdateSlotProperty`:

* **Hypothesize Input:** A ScriptContext, an index corresponding to a top-level `let` variable, and a new value.
* **Predict Output:** The context slot at that index will be updated, and potentially, dependent optimized code will be invalidated.
* **Code Logic Reasoning:** Explain how the macro checks for existing side data, whether the variable was initially constant, and how it updates the side data based on the new value's type.

**7. Identifying Common Programming Errors:**

Think about how the concepts in the file relate to common JavaScript mistakes:

* **Confusing `var` and `let`/`const`:**  The side data logic directly relates to the differences.
* **Unexpected behavior with top-level `let`:**  Reassigning top-level `let` can have performance implications due to potential deoptimizations.
* **Trying to modify `const` variables:** This will lead to errors, and the side data mechanism helps enforce this.

**8. Structuring the Answer:**

Organize the findings into clear sections:

* **File Functionality:**  Summarize the main purposes.
* **Torque Source File:** Explain what that means.
* **Relationship to JavaScript:**  Connect the concepts to JavaScript.
* **JavaScript Examples:** Provide concrete code snippets.
* **Code Logic Inference:** Focus on a complex macro like `StoreScriptContextAndUpdateSlotProperty`.
* **Common Programming Errors:** Highlight related mistakes.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe focus too much on low-level memory details.
* **Correction:** Shift focus to the *purpose* of these structures and how they enable JavaScript features.
* **Initial thought:**  Provide overly technical explanations of Torque syntax.
* **Correction:** Keep the Torque explanations concise and focus on the *what* rather than the *how* of Torque. Prioritize the connection to JavaScript.
* **Initial thought:**  Not enough concrete JavaScript examples.
* **Correction:** Add specific and illustrative examples.

By following this structured analysis, combining code inspection with knowledge of JavaScript internals, and iteratively refining the understanding, we can arrive at a comprehensive and accurate answer like the example provided in the prompt.
好的，让我们来分析一下 `v8/src/objects/contexts.tq` 这个文件。

**文件功能概述**

`v8/src/objects/contexts.tq` 文件是 V8 JavaScript 引擎中关于执行上下文（Contexts）的 Torque 源代码定义文件。它的主要功能是：

1. **定义了 Context 对象的结构和层次关系:**  定义了 `Context` 类作为所有上下文对象的基类，并派生出各种具体的上下文类型，如 `FunctionContext`、`ScriptContext`、`BlockContext` 等。这些不同的上下文类型代表了 JavaScript 代码执行过程中不同的作用域和环境。
2. **定义了 Context 中存储数据的布局 (Slots):**  通过 `ContextSlot` 枚举定义了 `Context` 对象内部用于存储各种信息的槽位（slots）。这些槽位存储了诸如作用域信息、父级上下文、内置对象（如 `Array`、`Promise` 的构造函数）、以及用于优化的元数据等。
3. **提供了操作 Context 槽位的宏 (Macros):**  定义了 `GetScopeInfo`、`InitContextSlot`、`ContextSlot`、`LoadContextElement`、`StoreContextElement` 等宏，用于安全且类型化的访问和修改 `Context` 对象内部的槽位数据。
4. **定义了 ScriptContextTable 用于管理脚本级别的上下文:** `ScriptContextTable` 类用于存储和管理与特定脚本关联的上下文信息。
5. **处理 `let` 变量的常量性追踪和更新:** 文件中包含 `StoreScriptContextAndUpdateSlotProperty` 等宏，用于处理在脚本上下文中 `let` 变量的常量性追踪。当一个最初被认为是常量的 `let` 变量被重新赋值时，V8 需要更新相关的元数据并可能使某些优化失效。

**`.tq` 文件和 V8 Torque 源代码**

是的，正如你所说，以 `.tq` 结尾的文件是 V8 的 Torque 源代码文件。 Torque 是一种 V8 内部使用的类型化的中间语言，用于生成高效的 C++ 代码。它允许 V8 团队以更安全、更易于维护的方式编写底层的对象操作和运行时逻辑。

**与 JavaScript 功能的关系及 JavaScript 示例**

`v8/src/objects/contexts.tq` 中定义的内容直接关系到 JavaScript 中作用域（Scope）和闭包（Closure）的概念。

* **Context 层次结构对应 JavaScript 的作用域链:**  每当 JavaScript 执行进入一个新的函数、块级作用域或者模块时，V8 都会创建一个新的 Context 对象。这些 Context 对象通过 `PREVIOUS_INDEX` 槽位链接起来，形成了作用域链。当查找一个变量时，JavaScript 引擎会沿着作用域链向上查找，直到找到该变量的声明。

* **`FunctionContext` 对应函数作用域:**  当一个函数被调用时，会创建一个 `FunctionContext`，其中存储了该函数的局部变量、`arguments` 对象等。

* **`BlockContext` 对应块级作用域:**  `let` 和 `const` 声明会创建块级作用域，对应着 `BlockContext`。

* **`ScriptContext` 对应全局作用域或模块作用域:**  当执行一个脚本或模块时，会创建一个 `ScriptContext`。

* **`NativeContext` 存储内置对象:**  `NativeContext` 是一个特殊的上下文，它包含了 JavaScript 的全局对象（如 `globalThis` 或 `window`），以及内置的构造函数和对象（如 `Array`、`Object`、`Promise` 等）。`ContextSlot` 枚举中定义了许多以 `_INDEX` 结尾的常量，它们指向 `NativeContext` 中存储的各种内置对象。

**JavaScript 示例**

```javascript
// 示例 1: 函数作用域和 FunctionContext
function outerFunction() {
  const outerVariable = 10;

  function innerFunction() {
    const innerVariable = 20;
    console.log(outerVariable + innerVariable); // 可以访问外部函数的变量
  }

  innerFunction();
}

outerFunction();

// 在 V8 内部，当 innerFunction 被调用时，会创建一个 FunctionContext。
// 这个 FunctionContext 会通过其 PREVIOUS_INDEX 指向 outerFunction 的 FunctionContext，
// 从而可以访问 outerVariable。

// 示例 2: 块级作用域和 BlockContext
function blockScopeExample() {
  if (true) {
    let blockVariable = 30;
    console.log(blockVariable);
  }
  // console.log(blockVariable); // Error: blockVariable is not defined here
}

blockScopeExample();

// 在 V8 内部，if 语句会创建一个 BlockContext。
// blockVariable 存储在这个 BlockContext 中。

// 示例 3: NativeContext 和内置对象
console.log(Array); // 访问全局对象 Array
const arr = new Array(1, 2, 3);

// 在 V8 内部，Array 构造函数存储在 NativeContext 的某个槽位中，
// 例如 ARRAY_FUNCTION_INDEX。
```

**代码逻辑推理 (假设输入与输出)**

让我们关注 `StoreScriptContextAndUpdateSlotProperty` 这个宏，它涉及到 `let` 变量的常量性追踪。

**假设输入:**

* `c`: 一个 `ScriptContext` 对象，代表脚本的执行上下文。
* `index`: 一个整数，表示 `ScriptContext` 中一个槽位的索引，这个槽位存储了一个使用 `let` 声明的顶层变量的值。
* `newValue`: 一个新的 JavaScript 值，将被赋给该 `let` 变量。

**假设初始状态 (在赋值之前):**

* `c.elements[index]` 的值可能是 `TheHole` (如果变量尚未初始化) 或者一个初始值。
* `c` 的 `CONTEXT_SIDE_TABLE_PROPERTY_INDEX` 槽位指向一个 `FixedArray`，用于存储额外的元数据。
* `sideDataFixedArray.objects[sideDataIndex]` 的值可能为 `Undefined` (如果变量是新声明的)，或者 `SmiTag(kContextSidePropertyConst)` (如果变量被认为是常量)，或者一个 `ContextSidePropertyCell` 对象（如果已经发生了更改）。

**预期输出 (在赋值之后):**

* `c.elements[index]` 的值会被更新为 `newValue`。
* 如果初始状态认为该 `let` 变量是常量 (`sideDataFixedArray.objects[sideDataIndex] == SmiTag(kContextSidePropertyConst))`:
    * `sideDataFixedArray.objects[sideDataIndex]` 的值会被更新，例如更新为 `SmiTag(kContextSidePropertySmi)`、`SmiTag(kContextSidePropertyHeapNumber)` 或 `SmiTag(kContextSidePropertyOther)`，具体取决于 `newValue` 的类型。
    * 如果存在依赖于该变量为常量的优化代码，可能会调用 `runtime::InvalidateDependentCodeForScriptContextSlot` 来使其失效。
* 如果 `newValue` 是一个 `HeapNumber`，并且开启了 `IsScriptContextMutableHeapNumberFlag()`，则可能会分配一个新的 `HeapNumber` 对象来存储值。

**示例推理:**

假设我们有一个脚本级别的 `let` 声明 `let x = 5;`。

1. **初始化:** 当执行到这行代码时，`x` 的值可能会在 `ScriptContext` 的某个槽位中初始化为 `5`，并且对应的 side data 可能会被设置为 `SmiTag(kContextSidePropertyConst)`，表示 `x` 当前被认为是常量。
2. **赋值:** 如果后续执行 `x = 10;`，则 `StoreScriptContextAndUpdateSlotProperty` 宏会被调用，输入可能是：
   * `c`: 当前的 `ScriptContext`。
   * `index`:  `x` 对应的槽位索引。
   * `newValue`: `10`。
3. **宏的执行:**
   * 宏会检查 side data，发现 `x` 最初被认为是常量。
   * 由于 `newValue` (10) 仍然是一个 Smi，side data 可能会更新为 `SmiTag(kContextSidePropertySmi)`。
   * `c.elements[index]` 的值会被更新为 `10`。

如果后续执行 `x = 3.14;`：

1. **宏的执行:**
   * 宏会检查 side data，发现 `x` 的 side data 是 `SmiTag(kContextSidePropertySmi)`。
   * 由于 `newValue` (3.14) 是一个 HeapNumber，side data 可能会更新为 `SmiTag(kContextSidePropertyHeapNumber)`。
   * 如果开启了可变 HeapNumber 的优化，可能会分配一个新的 HeapNumber 对象来存储 3.14，并将其存储到 `c.elements[index]`。

**用户常见的编程错误**

与 `v8/src/objects/contexts.tq` 中定义的概念相关的常见编程错误包括：

1. **在不期望的地方访问变量:**  理解作用域链对于避免访问到未定义的变量至关重要。例如，在内部函数中错误地假设可以访问外部函数中没有定义的变量。

   ```javascript
   function outer() {
     let outerVar = 5;
     function inner() {
       console.log(someUndeclaredVariable); // 错误：someUndeclaredVariable 未定义
     }
     inner();
   }
   outer();
   ```

2. **误解 `var` 和 `let`/`const` 的作用域差异:** `var` 声明的变量具有函数作用域，而 `let` 和 `const` 具有块级作用域。这可能导致意外的行为。

   ```javascript
   function exampleVarLet() {
     if (true) {
       var x = 10;
       let y = 20;
     }
     console.log(x); // 输出 10，因为 var 是函数作用域
     // console.log(y); // 错误：y 在此处未定义，因为 let 是块级作用域
   }
   exampleVarLet();
   ```

3. **尝试修改 `const` 声明的变量:** `const` 声明的变量必须在声明时赋值，并且之后不能重新赋值（对于基本类型的值）。

   ```javascript
   const PI = 3.14159;
   // PI = 3.14; // TypeError: Assignment to constant variable.

   const obj = { value: 1 };
   obj.value = 2; // 合法，因为 const 对象本身不能被重新赋值，但其属性可以修改
   // obj = { value: 3 }; // TypeError: Assignment to constant variable.
   ```

4. **在闭包中对循环变量的误解 (尤其是在 ES5 中使用 `var`):** 在 ES5 中，使用 `var` 声明的循环变量在循环结束后仍然存在于函数作用域中，可能导致闭包捕获到的是循环的最终值，而不是每次迭代的值。`let` 可以通过创建块级作用域来避免这个问题。

   ```javascript
   // 使用 var 的常见错误
   for (var i = 0; i < 5; i++) {
     setTimeout(function() {
       console.log(i); // 每次输出 5，因为闭包捕获的是循环结束后的 i 的值
     }, 100);
   }

   // 使用 let 可以解决这个问题
   for (let j = 0; j < 5; j++) {
     setTimeout(function() {
       console.log(j); // 每次输出 0, 1, 2, 3, 4，因为 let 创建了块级作用域
     }, 100);
   }
   ```

理解 `v8/src/objects/contexts.tq` 中定义的概念有助于更深入地理解 JavaScript 的作用域和闭包机制，从而避免这些常见的编程错误，并编写出更健壮和可预测的代码。

### 提示词
```
这是目录为v8/src/objects/contexts.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/contexts.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

@abstract
// We normally don't generate a BodyDescriptor for an abstact class, but here we
// do since all context classes share the same BodyDescriptor.
@generateBodyDescriptor
extern class Context extends HeapObject {
  macro GetScopeInfo(): ScopeInfo {
    return *ContextSlot(this, ContextSlot::SCOPE_INFO_INDEX);
  }
  const length: Smi;
  elements[length]: Object;
}

@cppObjectLayoutDefinition
extern class ScriptContextTable extends HeapObject {
  const capacity: Smi;
  length: Smi;
  names_to_context_index: NameToIndexHashTable;
  objects[capacity]: Context;
}

extern class AwaitContext extends Context generates 'TNode<Context>';
extern class BlockContext extends Context generates 'TNode<Context>';
extern class CatchContext extends Context generates 'TNode<Context>';
extern class DebugEvaluateContext extends Context
    generates 'TNode<Context>';
extern class EvalContext extends Context generates 'TNode<Context>';
extern class ModuleContext extends Context generates 'TNode<Context>';
extern class ScriptContext extends Context generates 'TNode<Context>';
extern class WithContext extends Context generates 'TNode<Context>';

extern class FunctionContext extends Context generates 'TNode<Context>';

const kInitialContextSlotValue: Smi = 0;

@export
macro AllocateSyntheticFunctionContext(
    nativeContext: NativeContext, slots: constexpr int31): FunctionContext {
  return AllocateSyntheticFunctionContext(
      nativeContext, Convert<intptr>(slots));
}

macro AllocateSyntheticFunctionContext(
    nativeContext: NativeContext, slots: intptr): FunctionContext {
  static_assert(slots >= ContextSlot::MIN_CONTEXT_SLOTS);
  const map =
      *ContextSlot(nativeContext, ContextSlot::FUNCTION_CONTEXT_MAP_INDEX);
  const result = new FunctionContext{
    map,
    length: Convert<Smi>(slots),
    elements: ...ConstantIterator<Smi>(kInitialContextSlotValue)
  };
  InitContextSlot(result, ContextSlot::SCOPE_INFO_INDEX, kEmptyScopeInfo);
  InitContextSlot(result, ContextSlot::PREVIOUS_INDEX, Undefined);
  return result;
}

extern class NativeContext extends Context;

type Slot<Container : type extends Context, T : type extends Object> extends
    intptr;

// We cannot use ContextSlot() for initialization since that one asserts the
// slot has the right type already.
macro InitContextSlot<
    ArgumentContext: type, AnnotatedContext: type, T: type, U: type>(
    context: ArgumentContext, index: Slot<AnnotatedContext, T>,
    value: U): void {
  // Make sure the arguments have the right type.
  const context: AnnotatedContext = context;
  const value: T = value;
  dcheck(TaggedEqual(context.elements[index], kInitialContextSlotValue));
  context.elements[index] = value;
}

macro ContextSlot<ArgumentContext: type, AnnotatedContext: type, T: type>(
    context: ArgumentContext, index: Slot<AnnotatedContext, T>):&T {
  const context: AnnotatedContext = context;
  return torque_internal::unsafe::ReferenceCast<T>(&context.elements[index]);
}

macro NativeContextSlot<T: type>(
    context: NativeContext, index: Slot<NativeContext, T>):&T {
  return ContextSlot(context, index);
}
macro NativeContextSlot<T: type>(
    context: Context, index: Slot<NativeContext, T>):&T {
  return ContextSlot(LoadNativeContext(context), index);
}
macro NativeContextSlot<C: type, T: type>(
    implicit context: C)(index: Slot<NativeContext, T>):&T {
  return NativeContextSlot(context, index);
}

extern enum ContextSlot extends intptr constexpr 'Context::Field' {
  SCOPE_INFO_INDEX: Slot<Context, ScopeInfo>,
  // Zero is used for the NativeContext, Undefined is used for synthetic
  // function contexts.
  PREVIOUS_INDEX: Slot<Context, Context|Zero|Undefined>,

  AGGREGATE_ERROR_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  ARRAY_BUFFER_FUN_INDEX: Slot<NativeContext, Constructor>,
  ARRAY_BUFFER_NOINIT_FUN_INDEX: Slot<NativeContext, JSFunction>,
  ARRAY_BUFFER_MAP_INDEX: Slot<NativeContext, Map>,
  ARRAY_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  ARRAY_JOIN_STACK_INDEX: Slot<NativeContext, Undefined|FixedArray>,
  OBJECT_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  ITERATOR_RESULT_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_MAP_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_FILTER_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_TAKE_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_DROP_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_FLAT_MAP_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  VALID_ITERATOR_WRAPPER_MAP_INDEX: Slot<NativeContext, Map>,
  JS_ARRAY_PACKED_ELEMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  JS_MAP_MAP_INDEX: Slot<NativeContext, Map>,
  JS_SET_MAP_INDEX: Slot<NativeContext, Map>,
  MATH_RANDOM_CACHE_INDEX: Slot<NativeContext, FixedDoubleArray>,
  MATH_RANDOM_INDEX_INDEX: Slot<NativeContext, Smi>,
  NUMBER_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  PROXY_REVOCABLE_RESULT_MAP_INDEX: Slot<NativeContext, Map>,
  REFLECT_APPLY_INDEX: Slot<NativeContext, Callable>,
  REGEXP_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  REGEXP_LAST_MATCH_INFO_INDEX: Slot<NativeContext, RegExpMatchInfo>,
  INITIAL_STRING_ITERATOR_MAP_INDEX: Slot<NativeContext, Map>,
  INITIAL_ARRAY_ITERATOR_MAP_INDEX: Slot<NativeContext, Map>,
  INITIAL_ITERATOR_PROTOTYPE_INDEX: Slot<NativeContext, JSObject>,
  SLOW_OBJECT_WITH_NULL_PROTOTYPE_MAP: Slot<NativeContext, Map>,
  STRICT_ARGUMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  SLOPPY_ARGUMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  FAST_ALIASED_ARGUMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  FUNCTION_CONTEXT_MAP_INDEX: Slot<NativeContext, Map>,
  FUNCTION_PROTOTYPE_APPLY_INDEX: Slot<NativeContext, JSFunction>,
  STRING_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,

  UINT8_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  INT8_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  UINT16_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  INT16_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  UINT32_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  INT32_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  FLOAT16_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  FLOAT32_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  FLOAT64_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  UINT8_CLAMPED_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  BIGUINT64_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  BIGINT64_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,

  RAB_GSAB_UINT8_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_INT8_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_UINT16_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_INT16_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_UINT32_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_INT32_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_FLOAT16_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_FLOAT32_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_FLOAT64_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_UINT8_CLAMPED_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_BIGUINT64_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_BIGINT64_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,

  ACCESSOR_PROPERTY_DESCRIPTOR_MAP_INDEX: Slot<NativeContext, Map>,
  DATA_PROPERTY_DESCRIPTOR_MAP_INDEX: Slot<NativeContext, Map>,

  PROMISE_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  PROMISE_THEN_INDEX: Slot<NativeContext, JSFunction>,
  PROMISE_PROTOTYPE_INDEX: Slot<NativeContext, JSObject>,
  STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX: Slot<NativeContext, Map>,

  PROMISE_HOOK_INIT_FUNCTION_INDEX: Slot<NativeContext, Undefined|Callable>,
  PROMISE_HOOK_BEFORE_FUNCTION_INDEX: Slot<NativeContext, Undefined|Callable>,
  PROMISE_HOOK_AFTER_FUNCTION_INDEX: Slot<NativeContext, Undefined|Callable>,
  PROMISE_HOOK_RESOLVE_FUNCTION_INDEX: Slot<NativeContext, Undefined|Callable>,

  // @if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA)
  CONTINUATION_PRESERVED_EMBEDDER_DATA_INDEX: Slot<NativeContext, HeapObject>,

  BOUND_FUNCTION_WITH_CONSTRUCTOR_MAP_INDEX: Slot<NativeContext, Map>,
  BOUND_FUNCTION_WITHOUT_CONSTRUCTOR_MAP_INDEX: Slot<NativeContext, Map>,

  WRAPPED_FUNCTION_MAP_INDEX: Slot<NativeContext, Map>,

  @sameEnumValueAs(MIN_CONTEXT_SLOTS)
  CONTEXT_SIDE_TABLE_PROPERTY_INDEX: Slot<Context, HeapObject>,

  MIN_CONTEXT_SLOTS,
  MIN_CONTEXT_EXTENDED_SLOTS,
  ...
}

@export
macro LoadContextElement(c: Context, i: intptr): Object {
  return c.elements[i];
}

@export
macro LoadContextElement(c: Context, i: Smi): Object {
  return c.elements[i];
}

@export
macro LoadContextElement(c: Context, i: constexpr int32): Object {
  return c.elements[i];
}

@export
macro LoadScriptContextElement(c: Context, i: intptr): Object {
  return LoadScriptContextElementImpl(c, i);
}

@export
macro LoadScriptContextElement(c: Context, i: Smi): Object {
  return LoadScriptContextElementImpl(c, SmiUntag(i));
}

@export
macro LoadScriptContextElement(c: Context, i: constexpr int32): Object {
  return LoadScriptContextElementImpl(c, i);
}

@export
macro StoreContextElement(c: Context, i: intptr, o: Object): void {
  c.elements[i] = o;
}

@export
macro StoreContextElement(c: Context, i: Smi, o: Object): void {
  c.elements[i] = o;
}

@export
macro StoreContextElement(c: Context, i: constexpr int32, o: Object): void {
  c.elements[i] = o;
}

@export
macro StoreContextElementAndUpdateSideData(
    c: Context, i: intptr, o: Object): void {
  StoreScriptContextAndUpdateSlotProperty(c, i, o);
}

@export
macro StoreContextElementAndUpdateSideData(
    c: Context, i: constexpr int32, o: Object): void {
  StoreScriptContextAndUpdateSlotProperty(c, i, o);
}

builtin AllocateIfMutableHeapNumberScriptContextSlot(
    n: Object, c: Object, i: Smi): JSAny {
  const number = UnsafeCast<HeapNumber>(n);
  const context = UnsafeCast<Context>(c);
  const index = SmiUntag(i);
  if (IsMutableHeapNumber(context, index, number)) {
    return AllocateHeapNumberWithValue(number.value);
  }
  return number;
}

builtin StoreCurrentScriptContextSlotBaseline(o: Object, i: Smi): JSAny {
  const context = internal::LoadContextFromBaseline();
  const index = SmiUntag(i);
  StoreScriptContextAndUpdateSlotProperty(context, index, o);
  return Undefined;
}

builtin StoreScriptContextSlotBaseline(
    c: Object, o: Object, i: Smi, d: TaggedIndex): JSAny {
  let context = UnsafeCast<Context>(c);
  let depth = TaggedIndexToIntPtr(d);
  while (depth > 0) {
    --depth;
    context =
        UnsafeCast<Context>(context.elements[ContextSlot::PREVIOUS_INDEX]);
  }

  const index = SmiUntag(i);
  StoreScriptContextAndUpdateSlotProperty(context, index, o);
  return Undefined;
}

namespace runtime {
extern runtime InvalidateDependentCodeForScriptContextSlot(Context, Object):
    JSAny;
}  // namespace runtime

macro StoreScriptContextAndUpdateSlotProperty(
    c: Context, index: intptr, newValue: Object): void {
  const scriptContext = Cast<ScriptContext>(c) otherwise unreachable;

  const sideDataIndex = index - ContextSlot::MIN_CONTEXT_EXTENDED_SLOTS;
  const sideData: Object = *ContextSlot(
      scriptContext, ContextSlot::CONTEXT_SIDE_TABLE_PROPERTY_INDEX);

  const sideDataFixedArray: FixedArray =
      Cast<FixedArray>(sideData) otherwise return;
  if (sideDataFixedArray.length == 0) {
    // No side data (maybe the const tracking let flag is not on).
    return;
  }

  const oldValue = c.elements[index];
  if (oldValue == TheHole) {
    // Setting the initial value.
    dcheck(sideDataFixedArray.objects[sideDataIndex] == Undefined);
    sideDataFixedArray.objects[sideDataIndex] =
        SmiTag(kContextSidePropertyConst);
    c.elements[index] = newValue;
    return;
  }

  // If we are assigning the same value, the property won't change.
  if (TaggedEqual(oldValue, newValue)) {
    return;
  }
  // If both values are HeapNumbers with the same double value, the property
  // won't change either.
  if (Is<HeapNumber>(oldValue) && Is<HeapNumber>(newValue)) {
    const oldNumber = Cast<HeapNumber>(oldValue) otherwise unreachable;
    const newNumber = Cast<HeapNumber>(newValue) otherwise unreachable;
    if (oldNumber.value == newNumber.value && oldNumber.value != 0) {
      return;
    }
  }

  // From now on, we know the value is no longer a constant.

  const data = sideDataFixedArray.objects[sideDataIndex];
  let maybeCell: Undefined|ContextSidePropertyCell;
  let property: intptr;

  // From now on, we know the value is no longer a constant. If there's a
  // DependentCode, invalidate it.

  typeswitch (data) {
    case (property_raw: Smi): {
      maybeCell = Undefined;
      property = SmiUntag(property_raw);
    }
    case (cell: ContextSidePropertyCell): {
      maybeCell = cell;
      property = SmiUntag(cell.property_details_raw);
    }
    case (Object): {
      // If this is reached, there's a code path which initializes or assigns a
      // top-level `let` variable but doesn't update the side data.
      unreachable;
    }
  }

  if (property == kContextSidePropertyConst) {
    if (Is<ContextSidePropertyCell>(maybeCell)) {
      runtime::InvalidateDependentCodeForScriptContextSlot(c, maybeCell);
    }
    if (IsScriptContextMutableHeapNumberFlag()) {
      // It can transition to Smi, MutableHeapNumber or Other.
      if (Is<HeapNumber>(newValue)) {
        sideDataFixedArray.objects[sideDataIndex] =
            SmiTag(kContextSidePropertyHeapNumber);
        const newNumber = Cast<HeapNumber>(newValue) otherwise unreachable;
        c.elements[index] = AllocateHeapNumberWithValue(newNumber.value);
      } else {
        if (Is<Smi>(newValue)) {
          sideDataFixedArray.objects[sideDataIndex] =
              SmiTag(kContextSidePropertySmi);
        } else {
          sideDataFixedArray.objects[sideDataIndex] =
              SmiTag(kContextSidePropertyOther);
        }
        c.elements[index] = newValue;
      }
    } else {
      // MutableHeapNumber is not supported, just transition the property to
      // kOther.
      sideDataFixedArray.objects[sideDataIndex] =
          SmiTag(kContextSidePropertyOther);
      c.elements[index] = newValue;
    }
  } else if (property == kContextSidePropertySmi) {
    if (Is<Smi>(newValue)) {
      c.elements[index] = newValue;
    } else {
      if (Is<ContextSidePropertyCell>(maybeCell)) {
        runtime::InvalidateDependentCodeForScriptContextSlot(c, maybeCell);
      }
      // It can transition to a MutableHeapNumber or Other.
      if (Is<HeapNumber>(newValue)) {
        sideDataFixedArray.objects[sideDataIndex] =
            SmiTag(kContextSidePropertyHeapNumber);
        const newNumber = Cast<HeapNumber>(newValue) otherwise unreachable;
        c.elements[index] = AllocateHeapNumberWithValue(newNumber.value);
      } else {
        sideDataFixedArray.objects[sideDataIndex] =
            SmiTag(kContextSidePropertyOther);
        c.elements[index] = newValue;
      }
    }
  } else if (property == kContextSidePropertyHeapNumber) {
    const oldNumber = Cast<HeapNumber>(oldValue) otherwise unreachable;
    if (Is<Smi>(newValue)) {
      const newNumber = Cast<Smi>(newValue) otherwise unreachable;
      oldNumber.value = SmiToFloat64(newNumber);
    } else if (Is<HeapNumber>(newValue)) {
      const newNumber = Cast<HeapNumber>(newValue) otherwise unreachable;
      oldNumber.value = newNumber.value;
    } else {
      if (Is<ContextSidePropertyCell>(maybeCell)) {
        runtime::InvalidateDependentCodeForScriptContextSlot(c, maybeCell);
      }
      // It can only transition to Other.
      sideDataFixedArray.objects[sideDataIndex] =
          SmiTag(kContextSidePropertyOther);
      c.elements[index] = newValue;
    }
  } else {
    dcheck(property == kContextSidePropertyOther);
    // We should not have a code depending on Other.
    dcheck(IsUndefined(maybeCell));
    // No need to update side data, this is a sink state...
    c.elements[index] = newValue;
  }
}

macro LoadScriptContextElementImpl(c: Context, i: intptr): Object {
  dcheck(Is<ScriptContext>(c));
  const val = c.elements[i];
  if (IsMutableHeapNumber(c, i, val)) {
    const number = Cast<HeapNumber>(val) otherwise unreachable;
    return AllocateHeapNumberWithValue(number.value);
  }
  return val;
}

macro IsMutableHeapNumber(c: Context, index: intptr, val: Object): bool {
  if (!Is<HeapNumber>(val)) return false;
  const scriptContext = Cast<ScriptContext>(c) otherwise unreachable;

  const sideDataIndex = index - ContextSlot::MIN_CONTEXT_EXTENDED_SLOTS;
  const sideData: Object = *ContextSlot(
      scriptContext, ContextSlot::CONTEXT_SIDE_TABLE_PROPERTY_INDEX);

  const sideDataFixedArray: FixedArray =
      Cast<FixedArray>(sideData) otherwise return false;
  if (sideDataFixedArray.length == 0) {
    // No side data (maybe the const tracking let flag is not on).
    return false;
  }

  typeswitch (sideDataFixedArray.objects[sideDataIndex]) {
    case (Undefined): {
      return false;
    }
    case (cell: ContextSidePropertyCell): {
      return SmiUntag(cell.property_details_raw) ==
          kContextSidePropertyHeapNumber;
    }
    case (property: Smi): {
      return SmiUntag(property) == kContextSidePropertyHeapNumber;
    }
    case (Object): {
      unreachable;
    }
  }
}

// A dummy used instead of a context constant for runtime calls that don't need
// a context.
type NoContext extends Smi;
extern macro NoContextConstant(): NoContext;
const kNoContext: NoContext = NoContextConstant();
```