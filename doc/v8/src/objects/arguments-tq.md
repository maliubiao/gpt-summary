Response: Let's break down the thought process for analyzing this Torque code.

1. **Understand the Goal:** The primary request is to understand the functionality of the `arguments.tq` file in V8, relate it to JavaScript, provide examples, and identify potential programming errors.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the code for prominent keywords like `class`, `type`, `macro`, `extern`, `builtin`, `struct`, `namespace`, and `@export`. Notice the file deals with different "kinds" of arguments objects (Sloppy, Strict, FastAliased). The `@export` macros suggest these are entry points or functionalities exposed elsewhere in the V8 codebase.

3. **Identify Key Data Structures:**  Focus on `class` and `struct` definitions:
    * `JSArgumentsObject`, `JSSloppyArgumentsObject`, `JSStrictArgumentsObject`: These are clearly the core data structures representing JavaScript `arguments` objects. Note the inheritance (`extends`).
    * `SloppyArgumentsElements`: This seems to hold the actual argument values and mapping information for sloppy arguments. The fields `context`, `arguments`, and `mapped_entries` are important.
    * `AliasedArgumentsEntry`:  This likely deals with how arguments are linked to variables in the surrounding scope.
    * `ParameterMapIterator`, `ParameterValueIterator`: These look like helper structures for iterating through arguments during creation.

4. **Analyze Macros and Their Purpose:** Macros (introduced by `macro`) are like functions in Torque. Examine the names and parameters:
    * `IsJSArgumentsObjectWithLength`: A type check.
    * `NewSloppyArgumentsElements`, `NewStrictArgumentsElements`, `NewRestArgumentsElements`:  These clearly handle the *creation* of the underlying storage for arguments. The different names suggest different scenarios.
    * `NewJSStrictArgumentsObject`, `NewJSSloppyArgumentsObject`, `NewJSFastAliasedArgumentsObject`: These create the JavaScript-visible `arguments` objects themselves.
    * `NewAllArguments`, `NewRestArguments`, `NewStrictArguments`, `NewSloppyArguments`: Higher-level macros orchestrating the creation of different `arguments` objects, often using the element creation macros. Notice they often take `FrameWithArgumentsInfo` as input, suggesting they operate within the context of a function call.
    * `EmitFastNew...Arguments`: These seem to be optimized paths for creating arguments objects.
    * `AccessSloppyArgumentsCommon`, `SloppyArgumentsLoad`, `SloppyArgumentsHas`, `SloppyArgumentsStore`: These are for accessing and modifying elements of *sloppy* arguments objects. The "Common" suffix suggests shared logic. The `labels Bailout` indicate potential error handling.

5. **Connect to JavaScript Concepts:** Start linking the Torque structures and macros to JavaScript behavior:
    * `JSStrictArgumentsObject`:  This strongly relates to strict mode functions where `arguments` behaves like a normal array-like object.
    * `JSSloppyArgumentsObject`:  This maps to the traditional `arguments` object in non-strict mode, with its "magical" aliasing behavior. The `callee` property also hints at sloppy mode.
    * `NewRestArguments`:  Directly corresponds to the rest parameter syntax (`...args`).
    * The various `New...ArgumentsElements` relate to how arguments are captured and stored when a function is called.

6. **Infer Logic and Data Flow:**  Trace the execution flow within macros like `NewSloppyArguments`:
    * It gets argument counts.
    * It creates the underlying elements (`NewSloppyArgumentsElements`).
    * If there are formal parameters, it creates a mapping (`NewParameterMapIterator`, `NewSloppyArgumentsElements` with mapping). This is the key to the aliasing behavior.
    * It constructs the `JSSloppyArgumentsObject`.

7. **Formulate Assumptions and Examples:** Based on the analysis, create concrete examples:
    * **Strict Mode:** Show how `arguments` is not aliased.
    * **Sloppy Mode:** Demonstrate the aliasing behavior between `arguments` and named parameters.
    * **Rest Parameters:**  Show the creation of an array-like object with `...`.

8. **Identify Potential Errors:**  Think about what could go wrong or what common mistakes JavaScript developers make related to `arguments`:
    * Modifying `arguments` in strict mode (not directly an error *here*, but the code handles strict mode differently).
    * Assuming `arguments` is always a true array (it's array-like).
    * Being surprised by the aliasing in sloppy mode.
    * Issues with `arguments.callee` in strict mode (though this file mostly deals with object creation).

9. **Structure the Answer:** Organize the findings into logical sections: Functionality, Relationship to JavaScript, Logic Reasoning (with input/output), and Common Errors.

10. **Refine and Elaborate:** Review the generated answer. Are the explanations clear? Are the examples accurate and helpful?  Add more detail where needed. For instance, explain *why* sloppy arguments have aliasing (historical reasons, optimization trade-offs). Explain the purpose of the `SloppyArgumentsElements` structure in managing the mapping.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe all `arguments` objects are handled the same way. **Correction:** The code clearly distinguishes between strict and sloppy modes.
* **Initial thought:**  The iterators are just for simple looping. **Correction:**  They are used specifically during the *creation* of the arguments objects to handle mapping and initial values.
* **Initial thought:**  The `context` field in `SloppyArgumentsElements` is just a general context. **Correction:** It's specifically the *function's* context where the named parameters reside.

By following this structured approach, combining code analysis with knowledge of JavaScript semantics, one can effectively understand and explain the functionality of complex code like this V8 Torque file.
这个V8 Torque源代码文件 `v8/src/objects/arguments.tq` 的主要功能是 **定义和管理 JavaScript 函数的 `arguments` 对象**。它包含了创建、访问和操作 `arguments` 对象的底层实现细节。

**功能归纳:**

1. **定义 `arguments` 对象的结构:** 文件中定义了不同类型的 `arguments` 对象，例如 `JSSloppyArgumentsObject` (用于非严格模式函数) 和 `JSStrictArgumentsObject` (用于严格模式函数)。它还定义了用于存储 `arguments` 元素的数据结构 `SloppyArgumentsElements`。

2. **提供创建 `arguments` 对象的宏:**  文件中包含多个宏 (类似 C++ 中的宏或函数) 用于创建不同类型的 `arguments` 对象。例如：
   - `NewJSStrictArgumentsObject`: 创建严格模式的 `arguments` 对象。
   - `NewJSSloppyArgumentsObject`: 创建非严格模式的 `arguments` 对象。
   - `NewFastAliasedArgumentsObject`: 创建一种优化的、带有别名的非严格模式 `arguments` 对象。
   - `NewAllArguments`: 创建一个包含所有参数的新的 `JSArray`。
   - `NewRestArguments`: 创建一个用于 rest 参数 (`...args`) 的 `JSArray`。

3. **处理参数映射 (Parameter Mapping):**  对于非严格模式的 `arguments` 对象，代码实现了参数名和 `arguments` 对象索引之间的映射。这使得在函数内部修改命名参数会反映到 `arguments` 对象上，反之亦然。`SloppyArgumentsElements` 中的 `mapped_entries` 字段和相关的迭代器 (`ParameterMapIterator`, `ParameterValueIterator`) 用于实现这一功能。

4. **提供访问和修改 `arguments` 元素的宏:**  例如 `SloppyArgumentsLoad`, `SloppyArgumentsHas`, `SloppyArgumentsStore` 这些宏定义了如何读取、检查和写入非严格模式 `arguments` 对象的元素。

5. **支持不同类型的参数处理:** 文件中区分了严格模式和非严格模式下 `arguments` 对象的创建和行为，以及 rest 参数的特殊处理。

**与 JavaScript 功能的关系及示例:**

这个文件直接关联到 JavaScript 中函数内部可访问的 `arguments` 对象以及 ES6 中引入的 rest 参数。

**非严格模式 `arguments` 对象 (Sloppy Arguments):**

```javascript
function foo(a, b) {
  console.log(arguments[0]); // 输出传入的第一个参数的值
  a = 10; // 修改命名参数 a
  console.log(arguments[0]); // 输出 10，因为 arguments[0] 和 a 之间存在映射

  arguments[1] = 20; // 修改 arguments 对象
  console.log(b); // 输出 20，因为 b 和 arguments[1] 之间存在映射
}

foo(1, 2);
```

在 `arguments.tq` 中，`JSSloppyArgumentsObject` 和相关的宏 (例如 `NewSloppyArguments`, `AccessSloppyArgumentsCommon`) 负责实现这种映射行为。`SloppyArgumentsElements` 的 `mapped_entries` 数组记录了哪些 `arguments` 索引映射到函数的哪个命名参数。

**严格模式 `arguments` 对象 (Strict Arguments):**

```javascript
"use strict";
function bar(a, b) {
  console.log(arguments[0]); // 输出传入的第一个参数的值
  a = 10; // 修改命名参数 a
  console.log(arguments[0]); // 输出 1，因为在严格模式下，arguments 对象不再与命名参数绑定

  arguments[1] = 20; // 修改 arguments 对象
  console.log(b); // 输出 2，因为在严格模式下，命名参数不受 arguments 对象修改的影响
}

bar(1, 2);
```

在 `arguments.tq` 中，`JSStrictArgumentsObject` 和 `NewStrictArguments` 宏用于创建这种没有参数映射的 `arguments` 对象。

**Rest 参数:**

```javascript
function baz(...args) {
  console.log(args); // 输出一个包含所有传入参数的数组
}

baz(1, 2, 3); // 输出: [1, 2, 3]
```

`NewRestArguments` 宏负责创建用于 rest 参数的数组。它从函数调用帧中提取参数，并将它们放入一个新的 `JSArray` 中。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  一个非严格模式函数 `function example(x, y) { ... }` 被调用，传入参数 `example(5, 10)`.

**宏调用:**  当 V8 执行这个函数调用时，`NewSloppyArguments` 宏会被调用。

**内部处理 (简化):**

1. `info.argument_count` 将是 `2`。
2. `info.formal_parameter_count` 将是 `2`。
3. `NewSloppyArgumentsElements` 会创建一个 `FixedArray`，包含参数值 `[5, 10]`。
4. `NewParameterMapIterator` 会创建一个迭代器，用于生成参数映射的索引。
5. `NewSloppyArgumentsElements` (第二个) 会创建一个 `SloppyArgumentsElements` 对象，其 `mapped_entries` 数组会记录 `arguments[0]` 映射到 `x`，`arguments[1]` 映射到 `y` 的上下文槽位。
6. `NewJSFastAliasedArgumentsObject` 会创建一个 `JSSloppyArgumentsObject` 实例，其 `elements` 指向 `SloppyArgumentsElements` 对象。

**输出:**  在函数 `example` 内部，`arguments` 对象将是一个类数组对象，其行为与传入的参数和命名参数绑定。 `arguments[0]` 的值是 `5`， `arguments[1]` 的值是 `10`。修改 `x` 会影响 `arguments[0]`，反之亦然。

**涉及用户常见的编程错误:**

1. **在严格模式下尝试访问 `arguments.callee` 或 `arguments.caller`:**

   ```javascript
   "use strict";
   function strictFunction() {
     console.log(arguments.callee); // TypeError: 'caller', 'callee', and 'arguments' properties cannot be accessed on strict mode functions or the arguments objects for calls to them
   }
   strictFunction();
   ```

   在严格模式下，`arguments.callee` 指向当前正在执行的函数，但在严格模式下被禁用。这个文件定义了 `JSStrictArgumentsObject` 不包含 `callee` 属性，从而在底层避免了这种错误。

2. **误认为 `arguments` 是一个真正的数组:**

   ```javascript
   function argFunc() {
     const argsArray = arguments.slice(); // TypeError: arguments.slice is not a function
     // 正确的做法是使用 Array.prototype.slice.call(arguments) 或扩展运算符
     const argsArrayCorrect = [...arguments];
     console.log(argsArrayCorrect);
   }
   argFunc(1, 2, 3);
   ```

   `arguments` 是一个类数组对象，它有 `length` 属性和可以通过索引访问元素，但它不继承自 `Array.prototype`，因此不能直接调用数组的方法。虽然这个文件主要关注 `arguments` 对象的创建和底层访问，但理解 `arguments` 的本质有助于避免这类错误。

3. **在非严格模式下依赖 `arguments` 的别名行为而导致意外的副作用:**

   ```javascript
   function sloppyFunc(a) {
     arguments[0] = 100;
     console.log(a); // 输出 100，可能会出乎意料
   }
   sloppyFunc(1);
   ```

   在非严格模式下，修改 `arguments` 对象的元素会影响到对应的命名参数，反之亦然。这种别名行为有时会导致难以调试的错误，特别是当代码不清晰地表明 `arguments` 被修改时。

总而言之，`v8/src/objects/arguments.tq` 是 V8 引擎中关于 JavaScript 函数 `arguments` 对象的核心实现文件，它定义了 `arguments` 对象的结构、创建过程以及访问和操作方式，并区分了严格模式和非严格模式下的不同行为，以及对 rest 参数的支持。理解这个文件有助于深入了解 JavaScript 函数调用的底层机制。

Prompt: 
```
这是目录为v8/src/objects/arguments.tq的一个v8 torque源代码， 请归纳一下它的功能, 
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