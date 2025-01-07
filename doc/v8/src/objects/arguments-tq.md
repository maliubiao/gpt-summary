Response:
Let's break down the thought process for analyzing the provided Torque code.

**1. Initial Understanding - The "What":**

The first thing to recognize is the file extension `.tq`. The prompt itself gives a huge clue: "if v8/src/objects/arguments.tq ends with .tq, then it's a v8 torque source code."  This immediately tells us we're dealing with V8's internal implementation, not standard JavaScript.

**2. High-Level Purpose - The "Why":**

Looking at the filename `arguments.tq`,  and the class names like `JSArgumentsObject`, `SloppyArgumentsElements`, and `StrictArgumentsElements`, it's clear this code deals with how JavaScript's `arguments` object is implemented within the V8 engine. The comments at the beginning also confirm this.

**3. Identifying Key Structures and Concepts:**

I started looking for keywords and recognizable patterns:

* **`extern class` and `extern shape`:** These suggest declarations of classes and their basic layout/properties. `JSArgumentsObject`, `JSSloppyArgumentsObject`, and `JSStrictArgumentsObject` are the core object types. The `shape` keyword implies these are initial layouts that can be modified later.
* **`class SloppyArgumentsElements extends FixedArrayBase`:** This defines the internal structure used to store the arguments. The members `context`, `arguments`, and `mapped_entries` hint at the complexity of handling `arguments` in sloppy mode (where parameters can be aliased).
* **`macro`:**  These are Torque's way of defining reusable code snippets, similar to functions. Many macros here start with `New...`, indicating they are responsible for creating instances of the defined classes. Others like `IsJSArgumentsObjectWithLength` are for type checking.
* **`builtin`:** These signify functions that are implemented in C++ and exposed to the Torque layer. They are lower-level operations.
* **`namespace arguments { ... }`:**  This organizes related macros.
* **`struct`:**  `ParameterMapIterator` and `ParameterValueIterator` are helper structures to iterate over parameters and their values.
* **`@export`:** This likely makes the macro accessible from other parts of the V8 codebase.
* **`typeswitch`:** This is Torque's equivalent of a switch statement, allowing branching based on the type of a variable.
* **Keywords related to memory and data structures:** `FixedArray`, `NumberDictionary`, `Smi` (Small Integer), `TheHole` (V8's representation of an uninitialized or deleted value).

**4. Discerning the Different Types of `arguments`:**

The code clearly distinguishes between "sloppy" and "strict" mode `arguments` objects. This is a crucial distinction in JavaScript, and the Torque code reflects it with separate classes (`JSSloppyArgumentsObject`, `JSStrictArgumentsObject`) and logic. The presence of `callee` in `JSSloppyArgumentsObject` but not in the strict version is another indicator.

**5. Tracing the Creation Process:**

I followed the `New...` macros to understand how different types of `arguments` objects are created:

* `NewStrictArguments`: Creates a strict mode `arguments` object.
* `NewSloppyArguments`: Creates a sloppy mode `arguments` object, with more complexity involving parameter mapping.
* `NewRestArguments`: Creates an array for rest parameters.
* `NewAllArguments`: Creates an array containing all arguments.

**6. Analyzing the `AccessSloppyArgumentsCommon` Macro:**

This macro is critical for understanding how elements within a sloppy mode `arguments` object are accessed. The logic involving `mapped_entries`, `context`, and the fallback to `arguments` (FixedArray or NumberDictionary) reveals the aliasing mechanism in sloppy mode.

**7. Connecting to JavaScript:**

At this point, I started thinking about how these internal V8 structures and mechanisms relate to the JavaScript `arguments` object that developers use. I recalled the key differences between strict and sloppy mode `arguments`.

**8. Crafting Examples and Explanations:**

Based on the understanding of the code, I constructed JavaScript examples to illustrate the concepts:

* **Strict vs. Sloppy Mode:** Showed how `arguments` behaves differently in the two modes (no `callee`, no aliasing in strict mode).
* **Rest Parameters:**  Connected the `NewRestArguments` logic to the `...args` syntax.
* **Common Errors:** Highlighted the dangers of relying on `arguments.callee` in strict mode and the potential confusion with aliasing in sloppy mode.

**9. Code Logic Inference (Hypothetical):**

I focused on the `AccessSloppyArgumentsCommon` macro and constructed a scenario to demonstrate the aliasing:  If you modify a named parameter, the corresponding element in the `arguments` object also changes (in sloppy mode).

**10. Iterative Refinement:**

Throughout this process, I reread parts of the code, refined my understanding, and ensured the explanations and examples accurately reflected the underlying mechanisms. I paid attention to the comments in the Torque code, which often provided valuable insights. For example, the comment about "FastAliasedArguments should really be a type for itself" hints at potential future refactoring.

Essentially, the process involved a combination of:

* **Keyword and syntax recognition (Torque-specific constructs).**
* **Inferring purpose from naming conventions.**
* **Tracing the flow of data and control (especially through `New...` macros).**
* **Connecting internal mechanisms to observable JavaScript behavior.**
* **Using JavaScript knowledge to create relevant examples.**
* **Structuring the information in a clear and organized manner.**
好的，让我们来分析一下 `v8/src/objects/arguments.tq` 这个文件。

**1. 文件类型和功能总览**

*   **文件类型**:  正如你所说，`arguments.tq` 以 `.tq` 结尾，这表明它是一个 **V8 Torque 源代码文件**。 Torque 是一种由 V8 团队开发的类型化的中间语言，用于编写 V8 内部的运行时代码，特别是对象创建、方法调用等底层操作。

*   **核心功能**:  该文件的核心功能是定义和实现 JavaScript 中 `arguments` 对象的各种形态以及相关的操作。`arguments` 对象是一个在非箭头函数中可用的局部变量，它包含了传递给该函数的参数列表。由于 `arguments` 对象的行为在 JavaScript 的不同模式（严格模式和非严格模式）下有所不同，并且为了性能考虑，V8 内部对其进行了精细的区分和优化，因此需要专门的代码来处理。

**2. 代码结构和关键概念**

*   **`extern class JSArgumentsObject extends JSObject {}`**:  声明了一个外部类 `JSArgumentsObject`，它继承自 `JSObject`。这表明 `arguments` 对象在 V8 内部也是一种特殊的 JavaScript 对象。

*   **`type JSArgumentsObjectWithLength = JSSloppyArgumentsObject|JSStrictArgumentsObject;`**: 定义了一个类型别名，表示带有 `length` 属性的 `arguments` 对象可以是 `JSSloppyArgumentsObject` 或 `JSStrictArgumentsObject`。这直接揭示了 `arguments` 对象的两种主要类型。

*   **`extern shape JSSloppyArgumentsObject extends JSArgumentsObject { ... }` 和 `extern shape JSStrictArgumentsObject extends JSArgumentsObject { ... }`**:  定义了非严格模式（sloppy mode）和严格模式（strict mode）下 `arguments` 对象的初始形状（shape）。注意，非严格模式的 `arguments` 对象额外拥有 `callee` 属性。

*   **`class SloppyArgumentsElements extends FixedArrayBase { ... }`**: 定义了非严格模式 `arguments` 对象的元素存储结构。它包含了上下文信息 (`context`)、实际参数数组 (`arguments`) 和映射条目 (`mapped_entries`)。`mapped_entries` 是实现非严格模式下参数名和 `arguments` 对象属性之间映射的关键。

*   **`macro NewJSStrictArgumentsObject(...)` 和 `macro NewJSSloppyArgumentsObject(...)`**:  定义了创建严格模式和非严格模式 `arguments` 对象的宏。这些宏会设置对象的 map（用于描述对象的结构和类型）、属性存储和元素存储。

*   **`macro NewFastAliasedArgumentsObject(...)`**: 定义了创建一种特殊的非严格模式 `arguments` 对象，它用于优化的场景。

*   **`struct ParameterMapIterator` 和 `struct ParameterValueIterator`**: 定义了用于迭代参数映射关系的迭代器，这在创建非严格模式 `arguments` 对象时会用到。

*   **`macro NewAllArguments(...)`, `macro NewRestArguments(...)`, `macro NewStrictArguments(...)`, `macro NewSloppyArguments(...)`**:  定义了创建各种 `arguments` 对象或类似数组的结构的宏，这些宏会根据不同的场景（例如，所有参数、剩余参数、严格模式参数、非严格模式参数）调用相应的对象创建逻辑。

*   **`builtin NewSloppyArgumentsElements(...)`, `builtin NewStrictArgumentsElements(...)`, `builtin NewRestArgumentsElements(...)`, `builtin FastNewSloppyArguments(...)`, `builtin FastNewStrictArguments(...)`, `builtin FastNewRestArguments(...)`**:  声明了内置函数（通常在 C++ 中实现），用于执行更底层的操作，例如创建元素存储。

*   **`macro AccessSloppyArgumentsCommon(...)`, `macro SloppyArgumentsLoad(...)`, `macro SloppyArgumentsHas(...)`, `macro SloppyArgumentsStore(...)`**: 定义了访问和操作非严格模式 `arguments` 对象属性的宏，其中 `AccessSloppyArgumentsCommon` 包含了复杂的逻辑来处理参数名和 `arguments` 索引之间的映射关系。

**3. 与 JavaScript 功能的关系 (附带 JavaScript 示例)**

`v8/src/objects/arguments.tq` 中定义的逻辑直接对应于 JavaScript 中 `arguments` 对象的行为。

*   **非严格模式 `arguments` 对象的 `callee` 属性**:

    ```javascript
    function foo(a, b) {
      console.log(arguments.callee); // 输出函数 foo 本身
    }
    foo(1, 2);
    ```
    在 `JSSloppyArgumentsObject` 的定义中，你可以看到 `callee: JSAny;`，这正是 JavaScript 中非严格模式 `arguments` 对象拥有 `callee` 属性的体现。

*   **严格模式 `arguments` 对象没有 `callee` 属性**:

    ```javascript
    "use strict";
    function bar(a, b) {
      console.log(arguments.callee); // 报错：TypeError: 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode functions or the arguments objects for calls to them
    }
    bar(3, 4);
    ```
    `JSStrictArgumentsObject` 的定义中没有 `callee` 属性，这与 JavaScript 的行为一致。

*   **非严格模式 `arguments` 对象的参数名映射 (Aliasing)**:

    ```javascript
    function baz(a) {
      console.log("Before:", a, arguments[0]); // 输出 "Before:", 1, 1
      a = 5;
      console.log("After:", a, arguments[0]);  // 输出 "After:", 5, 5
      arguments[0] = 10;
      console.log("Finally:", a, arguments[0]); // 输出 "Finally:", 10, 10
    }
    baz(1);
    ```
    `SloppyArgumentsElements` 中的 `mapped_entries` 和 `AccessSloppyArgumentsCommon` 宏实现了这种参数名和 `arguments` 对象属性之间的双向映射。当你修改形参 `a` 的值时，`arguments[0]` 的值也会随之改变，反之亦然。

*   **严格模式 `arguments` 对象的独立性**:

    ```javascript
    "use strict";
    function qux(a) {
      console.log("Before:", a, arguments[0]); // 输出 "Before:", 1, 1
      a = 5;
      console.log("After:", a, arguments[0]);  // 输出 "After:", 1, 1
      arguments[0] = 10;
      console.log("Finally:", a, arguments[0]); // 输出 "Finally:", 10, 5
    }
    qux(1);
    ```
    在严格模式下，修改形参 `a` 不会影响 `arguments[0]`，反之亦然。这反映了严格模式 `arguments` 对象更像是一个参数值的快照。

*   **剩余参数 (Rest Parameters)**:

    ```javascript
    function sum(...numbers) {
      console.log(numbers); // 输出传递的参数数组
      return numbers.reduce((acc, val) => acc + val, 0);
    }
    console.log(sum(1, 2, 3, 4)); // 输出 [1, 2, 3, 4] 和 10
    ```
    `NewRestArguments` 宏对应了 JavaScript 中的剩余参数语法 `...numbers`，它会将剩余的参数收集到一个真正的数组中。

**4. 代码逻辑推理 (假设输入与输出)**

让我们关注 `AccessSloppyArgumentsCommon` 宏，因为它涉及到非严格模式下参数映射的复杂逻辑。

**假设输入:**

*   `receiver`: 一个 `JSSloppyArgumentsObject` 实例。
*   `keyObject`: 一个 `Smi` 类型的对象，表示要访问的索引，例如 `Smi(0)`。

**代码逻辑推演:**

1. `Cast<Smi>(keyObject) otherwise Bailout;`: 将 `keyObject` 转换为 `Smi` 类型。如果转换失败，则跳转到 `Bailout` 标签（表示访问失败）。
2. `Cast<SloppyArgumentsElements>(receiver.elements) otherwise Bailout;`: 获取 `receiver` 的元素存储，并将其转换为 `SloppyArgumentsElements` 类型。如果转换失败，则跳转到 `Bailout`。
3. `if (OutOfBounds(key, elements.length)) goto Unmapped;`: 检查索引 `key` 是否越界。如果越界，则跳转到 `Unmapped` 标签，表示该索引没有对应的映射参数。
4. `const mappedIndex = elements.mapped_entries[key];`: 获取 `mapped_entries` 数组中对应索引的条目。这个条目可能是一个 `Smi`（表示映射到某个上下文槽）或 `TheHole`（表示未映射）。
5. `typeswitch (mappedIndex)`:
    *   `case (contextIndex: Smi)`: 如果 `mappedIndex` 是一个 `Smi`，则表示该索引映射到一个上下文槽。`return &(elements.context.elements[contextIndex]);` 返回指向该上下文槽的引用，这意味着修改这个引用会影响到对应的参数变量。
    *   `case (TheHole)`: 如果 `mappedIndex` 是 `TheHole`，则跳转到 `Unmapped` 标签。
6. `label Unmapped`: 如果索引未映射，则尝试直接从 `arguments` 数组中获取值。
    *   `typeswitch (elements.arguments)`:
        *   `case (NumberDictionary)`: 如果 `arguments` 是一个 `NumberDictionary`（一种稀疏数组），则跳转到 `Bailout`（简化起见，这里假设无法直接访问）。
        *   `case (arguments: FixedArray)`: 如果 `arguments` 是一个 `FixedArray`，则检查索引是否越界，以及该位置是否为 `TheHole`。如果都没问题，则返回指向 `arguments` 数组对应位置的引用。

**假设输入与输出示例:**

*   **输入:** `receiver` 是一个非严格模式 `arguments` 对象，对应于函数 `function foo(a) { ... }` 的调用，且 `a` 的值为 `1`。`keyObject` 是 `Smi(0)`。
*   **输出:**  如果参数 `a` 被映射（通常是这种情况），`AccessSloppyArgumentsCommon` 将返回一个指向存储 `a` 值的内存位置的引用。修改这个引用会同时修改 `a` 的值和 `arguments[0]` 的值。

**5. 涉及用户常见的编程错误**

*   **在严格模式下使用 `arguments.callee` 或 `arguments.caller`**:  这是严格模式禁止的操作，会导致 `TypeError`。
    ```javascript
    "use strict";
    function strictModeFunction() {
      console.log(arguments.callee); // TypeError
    }
    strictModeFunction();
    ```

*   **误以为非严格模式 `arguments` 对象是参数的副本**:  新手可能会认为 `arguments` 只是参数值的副本，但实际上在非严格模式下，它与具名参数存在映射关系，修改其中一个会影响另一个。

    ```javascript
    function sloppyModeFunction(param) {
      console.log("Initial param:", param); // 输出 1
      arguments[0] = 5;
      console.log("Param after arguments change:", param); // 输出 5
      param = 10;
      console.log("Param after direct change:", param); // 输出 10
      console.log("Arguments[0] after direct change:", arguments[0]); // 输出 10
    }
    sloppyModeFunction(1);
    ```

*   **在需要真正的数组方法时使用 `arguments` 对象**:  `arguments` 对象虽然看起来像数组（有 `length` 属性和索引），但它不是 `Array` 的实例，缺少一些数组方法（例如 `forEach`, `map`, `filter`）。如果需要使用这些方法，需要先将其转换为真正的数组：

    ```javascript
    function processArgs() {
      // 错误的做法：arguments.forEach(...)  // TypeError: arguments.forEach is not a function
      const argsArray = Array.prototype.slice.call(arguments);
      argsArray.forEach(arg => console.log(arg));
    }
    processArgs(1, 2, 3);
    ```

*   **过度依赖 `arguments` 对象，而不是使用剩余参数**:  现代 JavaScript 推荐使用剩余参数 (`...args`) 来获取函数的所有参数，因为它更清晰，返回的是一个真正的数组，并且在严格模式下行为更一致。

总而言之，`v8/src/objects/arguments.tq` 是 V8 引擎中一个关键的文件，它细致地实现了 JavaScript 中 `arguments` 对象的各种行为和优化策略，区分了严格模式和非严格模式，并处理了参数映射等复杂逻辑。理解这个文件可以帮助我们更深入地了解 JavaScript 的底层运行机制。

Prompt: 
```
这是目录为v8/src/objects/arguments.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/arguments.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern class JSArgumentsObject extends JSObject {}

type JSArgumentsObjectWithLength =
    JSSloppyArgumentsObject|JSStrictArgumentsObject;

@export
macro IsJSArgumentsObjectWithLength(
    implicit context: Context)(o: Object): bool {
  return Is<JSArgumentsObjectWithLength>(o);
}

// Just a starting shape for JSObject; properties can move after initialization.
extern shape JSSloppyArgumentsObject extends JSArgumentsObject {
  length: JSAny;
  callee: JSAny;
}

// Just a starting shape for JSObject; properties can move after initialization.
extern shape JSStrictArgumentsObject extends JSArgumentsObject {
  length: JSAny;
}

@cppObjectLayoutDefinition
class SloppyArgumentsElements extends FixedArrayBase {
  context: Context;
  arguments: FixedArray|NumberDictionary;
  mapped_entries[length]: Smi|TheHole;
}

macro NewSloppyArgumentsElements<Iterator: type>(
    length: Smi, context: Context, arguments: FixedArray,
    it: Iterator): SloppyArgumentsElements {
  return new
  SloppyArgumentsElements{length, context, arguments, mapped_entries: ...it};
}

extern class AliasedArgumentsEntry extends Struct {
  aliased_context_slot: Smi;
}

// TODO(danno): This should be a namespace {} once supported
namespace arguments {

macro NewJSStrictArgumentsObject(
    implicit context: Context)(elements: FixedArray): JSStrictArgumentsObject {
  const map = GetStrictArgumentsMap();
  return new JSStrictArgumentsObject{
    map,
    properties_or_hash: kEmptyFixedArray,
    elements,
    length: elements.length
  };
}

macro NewJSSloppyArgumentsObject(
    implicit context: Context)(elements: FixedArrayBase,
    callee: JSFunction): JSSloppyArgumentsObject {
  const map = GetSloppyArgumentsMap();
  return new JSSloppyArgumentsObject{
    map,
    properties_or_hash: kEmptyFixedArray,
    elements,
    length: elements.length,
    callee
  };
}

macro NewJSFastAliasedArgumentsObject(
    implicit context: Context)(elements: FixedArrayBase, length: Smi,
    callee: JSFunction): JSSloppyArgumentsObject {
  // TODO(danno): FastAliasedArguments should really be a type for itself
  const map = GetFastAliasedArgumentsMap();
  return new JSSloppyArgumentsObject{
    map,
    properties_or_hash: kEmptyFixedArray,
    elements,
    length,
    callee
  };
}

struct ParameterMapIterator {
  macro Next(): Smi labels NoMore {
    if (this.currentIndex == this.endInterationIndex) goto NoMore;
    this.currentIndex--;
    return Convert<Smi>(this.currentIndex);
  }
  currentIndex: intptr;
  const endInterationIndex: intptr;
}

macro NewParameterMapIterator(
    context: Context, formalParameterCount: intptr,
    mappedCount: intptr): ParameterMapIterator {
  const flags = context.GetScopeInfo().flags;
  let contextHeaderSize: intptr = ContextSlot::MIN_CONTEXT_SLOTS;
  if (flags.has_context_extension_slot) ++contextHeaderSize;
  if (flags.receiver_variable ==
      FromConstexpr<VariableAllocationInfo>(VariableAllocationInfo::CONTEXT)) {
    ++contextHeaderSize;
  }
  // Copy the parameter slots and the holes in the arguments.
  // We need to fill in mapped_count slots. They index the context,
  // where parameters are stored in reverse order, at
  //   context_header_size .. context_header_size+argument_count-1
  // The mapped parameter thus need to get indices
  //   context_header_size+parameter_count-1 ..
  //       context_header_size+argument_count-mapped_count
  // We loop from right to left.
  const afterLastContextIndex = contextHeaderSize + formalParameterCount;
  const firstContextIndex = afterLastContextIndex - mappedCount;
  return ParameterMapIterator{
    currentIndex: afterLastContextIndex,
    endInterationIndex: firstContextIndex
  };
}

struct ParameterValueIterator {
  macro Next(): Object labels NoMore() {
    if (this.mapped_count != 0) {
      this.mapped_count--;
      return TheHole;
    }
    if (this.current == this.arguments.length) goto NoMore;
    return this.arguments[this.current++];
  }
  mapped_count: intptr;
  const arguments: Arguments;
  current: intptr;
}

macro NewParameterValueIterator(mappedCount: intptr, arguments: Arguments):
    ParameterValueIterator {
  return ParameterValueIterator{
    mapped_count: mappedCount,
    arguments,
    current: mappedCount
  };
}

macro NewAllArguments(
    implicit context: Context)(frame: FrameWithArguments,
    argumentCount: intptr): JSArray {
  const map = GetFastPackedElementsJSArrayMap();
  const arguments = GetFrameArguments(frame, argumentCount);
  const it = ArgumentsIterator{arguments, current: 0};
  const elements = NewFixedArray(argumentCount, it);
  return NewJSArray(map, elements);
}

macro NewRestArgumentsElements(
    frame: FrameWithArguments, formalParameterCount: intptr,
    argumentCount: intptr): FixedArray {
  const length = (formalParameterCount >= argumentCount) ?
      0 :
      argumentCount - formalParameterCount;
  const arguments = GetFrameArguments(frame, argumentCount);
  const it = ArgumentsIterator{arguments, current: formalParameterCount};
  return NewFixedArray(length, it);
}

macro NewRestArguments(
    implicit context: Context)(info: FrameWithArgumentsInfo): JSArray {
  const argumentCount = Convert<intptr>(info.argument_count);
  const formalParameterCount = Convert<intptr>(info.formal_parameter_count);
  const map = GetFastPackedElementsJSArrayMap();
  const elements =
      NewRestArgumentsElements(info.frame, formalParameterCount, argumentCount);
  return NewJSArray(map, elements);
}

macro NewStrictArgumentsElements(
    frame: FrameWithArguments, argumentCount: intptr): FixedArray {
  const arguments = GetFrameArguments(frame, argumentCount);
  const it = ArgumentsIterator{arguments, current: 0};
  return NewFixedArray(argumentCount, it);
}

macro NewStrictArguments(
    implicit context: Context)(
    info: FrameWithArgumentsInfo): JSStrictArgumentsObject {
  const argumentCount = Convert<intptr>(info.argument_count);
  const elements = NewStrictArgumentsElements(info.frame, argumentCount);
  return NewJSStrictArgumentsObject(elements);
}

macro NewSloppyArgumentsElements(
    frame: FrameWithArguments, formalParameterCount: intptr,
    argumentCount: intptr): FixedArray {
  const arguments = GetFrameArguments(frame, argumentCount);
  if (formalParameterCount == 0) {
    const it = ArgumentsIterator{arguments, current: 0};
    return NewFixedArray(argumentCount, it);
  }
  const mappedCount = IntPtrMin(formalParameterCount, argumentCount);
  const it = NewParameterValueIterator(mappedCount, arguments);
  return NewFixedArray(argumentCount, it);
}

macro NewSloppyArguments(
    implicit context: Context)(info: FrameWithArgumentsInfo,
    callee: JSFunction): JSSloppyArgumentsObject {
  const argumentCount = Convert<intptr>(info.argument_count);
  const formalParameterCount = Convert<intptr>(info.formal_parameter_count);
  const parameterValues = arguments::NewSloppyArgumentsElements(
      info.frame, formalParameterCount, argumentCount);
  if (formalParameterCount == 0) {
    return NewJSSloppyArgumentsObject(parameterValues, callee);
  }
  const mappedCount = IntPtrMin(formalParameterCount, argumentCount);
  let paramIter =
      NewParameterMapIterator(context, formalParameterCount, mappedCount);
  const elementsLength = Convert<Smi>(mappedCount);
  const elements = NewSloppyArgumentsElements(
      elementsLength, context, parameterValues, paramIter);
  const length = Convert<Smi>(argumentCount);
  return NewJSFastAliasedArgumentsObject(elements, length, callee);
}

}  // namespace arguments

@export
macro EmitFastNewAllArguments(
    implicit context: Context)(frame: FrameWithArguments,
    argc: intptr): JSArray {
  return arguments::NewAllArguments(frame, argc);
}

@export
macro EmitFastNewRestArguments(
    implicit context: Context)(_f: JSFunction): JSArray {
  const info = GetFrameWithArgumentsInfo();
  return arguments::NewRestArguments(info);
}

@export
macro EmitFastNewStrictArguments(
    implicit context: Context)(_f: JSFunction): JSStrictArgumentsObject {
  const info = GetFrameWithArgumentsInfo();
  return arguments::NewStrictArguments(info);
}

@export
macro EmitFastNewSloppyArguments(
    implicit context: Context)(f: JSFunction): JSSloppyArgumentsObject {
  const info = GetFrameWithArgumentsInfo();
  return arguments::NewSloppyArguments(info, f);
}

builtin NewSloppyArgumentsElements(
    frame: FrameWithArguments, formalParameterCount: intptr,
    argumentCount: Smi): FixedArray {
  return arguments::NewSloppyArgumentsElements(
      frame, formalParameterCount, Convert<intptr>(argumentCount));
}

builtin NewStrictArgumentsElements(
    frame: FrameWithArguments, _formalParameterCount: intptr,
    argumentCount: Smi): FixedArray {
  return arguments::NewStrictArgumentsElements(
      frame, Convert<intptr>(argumentCount));
}

builtin NewRestArgumentsElements(
    frame: FrameWithArguments, formalParameterCount: intptr,
    argumentCount: Smi): FixedArray {
  return arguments::NewRestArgumentsElements(
      frame, formalParameterCount, Convert<intptr>(argumentCount));
}

macro NewRestArgumentsFromArguments(
    implicit context: Context)(arguments: Arguments, start: intptr): JSArray {
  dcheck(start <= arguments.length);
  const map = GetFastPackedElementsJSArrayMap();
  const it = ArgumentsIterator{arguments, current: start};
  const elements = NewFixedArray(arguments.length - start, it);
  return NewJSArray(map, elements);
}

builtin FastNewSloppyArguments(
    implicit context: Context)(f: JSFunction): JSSloppyArgumentsObject {
  return EmitFastNewSloppyArguments(f);
}

builtin FastNewStrictArguments(
    implicit context: Context)(f: JSFunction): JSStrictArgumentsObject {
  return EmitFastNewStrictArguments(f);
}

builtin FastNewRestArguments(
    implicit context: Context)(f: JSFunction): JSArray {
  return EmitFastNewRestArguments(f);
}

macro AccessSloppyArgumentsCommon(
    receiver: JSObject, keyObject: Object): &Object labels Bailout {
  const key = Cast<Smi>(keyObject) otherwise Bailout;
  const elements =
      Cast<SloppyArgumentsElements>(receiver.elements) otherwise Bailout;

  try {
    if (OutOfBounds(key, elements.length)) goto Unmapped;
    const mappedIndex = elements.mapped_entries[key];
    typeswitch (mappedIndex) {
      case (contextIndex: Smi): {
        return &(elements.context.elements[contextIndex]);
      }
      case (TheHole): {
        goto Unmapped;
      }
    }
  } label Unmapped {
    typeswitch (elements.arguments) {
      case (NumberDictionary): {
        goto Bailout;
      }
      case (arguments: FixedArray): {
        if (OutOfBounds(key, arguments.length)) goto Bailout;
        if (arguments.objects[key] == TheHole) goto Bailout;
        return &(arguments.objects[key]);
      }
    }
  }
}

@export
macro SloppyArgumentsLoad(
    receiver: JSObject, keyObject: Object): JSAny labels Bailout {
  return UnsafeCast<JSAny>(
      *AccessSloppyArgumentsCommon(receiver, keyObject) otherwise Bailout);
}

@export
macro SloppyArgumentsHas(
    receiver: JSObject, keyObject: Object): JSAny labels Bailout {
  AccessSloppyArgumentsCommon(receiver, keyObject) otherwise Bailout;
  return True;
}

@export
macro SloppyArgumentsStore(
    receiver: JSObject, keyObject: Object, value: JSAny): JSAny labels Bailout {
  let destination =
      AccessSloppyArgumentsCommon(receiver, keyObject) otherwise Bailout;
  *destination = value;
  return value;
}

"""

```