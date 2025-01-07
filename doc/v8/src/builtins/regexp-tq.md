Response: Let's break down the thought process for analyzing this Torque file.

1. **Initial Understanding of Torque:**  The first step is recognizing that this is V8's Torque language. Torque is used for defining built-in functions in V8. It generates C++ code that implements the core logic of JavaScript's built-in objects and functions. Therefore, this file likely deals with the internal implementation of `RegExp` and its associated methods.

2. **Scanning for Key Terms and Patterns:**  A quick scan reveals recurring keywords and structures that provide clues about the file's purpose. Look for:
    * `@export`: Indicates a macro or transition that is exposed and potentially used elsewhere.
    * `transitioning macro`:  Suggests functions or operations that can potentially involve garbage collection or other state changes.
    * `implicit context: Context`:  A common pattern in V8 internals, referring to the execution context.
    * `JSRegExp`, `String`, `Number`, `JSAny`:  V8's internal type system. `JSRegExp` is clearly the core focus.
    * `RegExp.prototype.exec`, `RegExp.prototype.global`, etc.:  These are standard JavaScript `RegExp` methods and properties. This strongly suggests the file implements their behavior.
    * `IsFastRegExpForMatch`, `BranchIfFastRegExpForMatch`: Indicates optimization paths for regular expressions. V8 often has "fast path" and "slow path" implementations.
    * `RegExpExecInternal_Single`, `ConstructNewResultFromMatchInfo`:  Internal routines for the core matching logic and result construction.
    * `LoadLastIndex`, `StoreLastIndex`:  Relates to the `lastIndex` property of `RegExp` objects.
    * `FlagGetter`: A function used to retrieve the boolean values of various `RegExp` flags.
    * `IsRegExp`:  The implementation of the `IsRegExp()` abstract operation.

3. **Grouping Functionality by JavaScript API:**  Organize the identified terms and structures according to the JavaScript `RegExp` API they relate to. This helps create a clear structure for the analysis:
    * **`RegExp.prototype.exec()`:**  The `RegExpExec` macro, `RegExpPrototypeExecBodyWithoutResult`, and `RegExpPrototypeExecBody` are clearly involved in implementing this method. The fast and slow path variations are also important.
    * **`RegExp.prototype.test()` (Implicit):** While not explicitly named, the `IsFastRegExpForMatch` and related macros suggest optimizations related to the `test()` method as well, since `test()` often uses the same underlying matching engine.
    * **`RegExp.prototype.flags` and individual flag getters (`global`, `ignoreCase`, etc.):** The `FlagGetter`, `RegExpPrototypeGlobalGetter`, `RegExpPrototypeIgnoreCaseGetter`, etc., are direct implementations of these property accessors.
    * **`RegExp.prototype.lastIndex`:** The `LoadLastIndex` and `StoreLastIndex` macros handle getting and setting this property.
    * **`RegExp` constructor:** The `RegExpCreate` macro is the internal mechanism for creating `RegExp` objects.
    * **`Symbol.match` and `IsRegExp()`:** The `IsRegExp` macro implements the logic for determining if an object is a regular expression, considering the `Symbol.match` property.

4. **Analyzing Key Macros and Transitions:**  For each identified area, dive deeper into the specific macros and transitions:
    * **`RegExpExec`:** Notice it first tries to get the `exec` property of the receiver, potentially calling a custom `exec` method. If not callable, and the receiver is a `RegExp`, it calls `RegExpPrototypeExecSlow`. This reveals the logic for handling subclasses of `RegExp` or objects with a custom `exec`.
    * **`RegExpPrototypeExecBodyWithoutResult`:** This is the core matching logic *without* creating the result object. Pay attention to the handling of `lastIndex` and the conditional update based on the `global` or `sticky` flags. The calls to `RegExpExecInternal_Single` are crucial. The "fast path" optimization is evident.
    * **`RegExpPrototypeExecBody`:** This macro builds on the previous one by calling `ConstructNewResultFromMatchInfo` to create the actual result object.
    * **`FlagGetter`:** Understand how it checks the receiver type and handles cases where the receiver is not a `RegExp` instance but might be the `RegExp.prototype` itself. The use of `IncrementUseCounter` is for internal V8 statistics.
    * **`LoadLastIndex`/`StoreLastIndex`:** Differentiate between the fast and slow paths, which likely depend on the internal representation of the `RegExp` object.
    * **`IsRegExp`:** The logic around checking for the `Symbol.match` property is important for understanding how JavaScript's type coercion interacts with regular expressions.
    * **`RegExpCreate`:** Note the separation of allocation and initialization/compilation.

5. **Connecting to JavaScript Behavior:**  For each functional area, formulate concrete JavaScript examples that demonstrate the behavior implemented by the Torque code. This bridges the gap between the internal implementation and the observable JavaScript behavior.

6. **Identifying Potential Programming Errors:**  Based on the internal logic, think about common mistakes developers make when working with regular expressions that this code might be handling or related to. For example:
    * Incorrectly assuming `lastIndex` is always reset.
    * Not understanding the implications of the `global` and `sticky` flags.
    * Passing non-`RegExp` objects to `RegExp.prototype.exec`.

7. **Inferring Logic and Assumptions:**  When direct code logic isn't immediately obvious, make educated guesses based on the naming conventions and the overall purpose of the code. For example, the "fast path" likely assumes certain properties of the `RegExp` object haven't been modified.

8. **Structuring the Output:** Organize the findings in a clear and logical manner, starting with a high-level summary and then delving into specific functionalities with code examples, logic inferences, and common errors.

9. **Refinement and Review:**  After the initial analysis, review the findings for accuracy and completeness. Ensure the JavaScript examples accurately reflect the behavior described by the Torque code.

By following these steps, one can effectively analyze and understand complex Torque code like the example provided. The key is to combine knowledge of JavaScript's `RegExp` API with an understanding of V8's internal structures and conventions.
这个v8 torque文件 `v8/src/builtins/regexp.tq` 实现了 ECMAScript 规范中关于 `RegExp` 对象及其原型方法的核心功能。它使用 V8 的 Torque 语言编写，旨在生成高效的 C++ 代码。

以下是对其功能的归纳：

**主要功能:**

1. **`RegExp.prototype.exec()` 的实现:**
   - 提供了快速和慢速两种路径的实现，以优化常见用例。
   - 负责执行正则表达式匹配，并返回匹配结果数组或 `null`。
   - 处理 `global` 和 `sticky` 标志对 `lastIndex` 属性的影响。
   - 涉及到内部的匹配信息结构 (`RegExpMatchInfo`) 的创建和使用。
   - 能够调用用户自定义的 `exec` 方法（如果存在）。

2. **`RegExp.prototype` 的属性 getter 的实现:**
   - 实现了 `global`, `ignoreCase`, `multiline`, `sticky`, `unicode`, `dotAll`, `hasIndices`, `linear`, `unicodeSets` 等属性的 getter 方法。
   - 提供了快速和慢速路径的标志位获取方式。
   - 检查接收者是否为 `RegExp` 实例或其原型。

3. **`RegExp.prototype.flags` 的实现:**
   - 返回一个包含当前正则表达式标志的字符串。
   - 同样提供快速和慢速路径。

4. **`RegExp.prototype.lastIndex` 的读取和设置:**
   - 提供了 `LoadLastIndex` 和 `StoreLastIndex` 宏用于高效地读取和设置 `lastIndex` 属性。
   - 区分快速和慢速路径。

5. **`IsRegExp(argument)` 抽象操作的实现:**
   - 判断一个对象是否为正则表达式。
   - 考虑了 `Symbol.match` 属性的存在和值。

6. **`RegExp` 构造函数的辅助功能:**
   - `RegExpCreate` 宏用于创建和初始化 `RegExp` 对象。
   - 涉及到正则表达式的编译 (`RegExpInitializeAndCompile`)。

7. **内部优化和辅助宏:**
   - 提供了用于判断是否为快速正则表达式的宏 (`IsFastRegExpForMatch`, `IsFastRegExpForSearch`, `IsFastRegExpStrict`, `IsFastRegExpPermissive`)，以便选择优化的执行路径。
   - 提供了 `AdvanceStringIndex` 宏用于在字符串中前进索引，处理 Unicode 字符。

**与 JavaScript 功能的关系及示例:**

```javascript
// RegExp.prototype.exec()
const regex = /abc/g;
const str = 'abcadef';
let match;

while ((match = regex.exec(str)) !== null) {
  console.log(`Found ${match[0]} at index ${match.index}. Next starts at ${regex.lastIndex}.`);
}
// 输出:
// Found abc at index 0. Next starts at 3.

// RegExp.prototype.global, RegExp.prototype.ignoreCase 等
const regex2 = /abc/gi;
console.log(regex2.global);     // true
console.log(regex2.ignoreCase); // true

// RegExp.prototype.flags
console.log(regex2.flags);      // "gi"

// RegExp.prototype.lastIndex
const regex3 = /abc/g;
const str3 = 'abcadef';
regex3.exec(str3);
console.log(regex3.lastIndex); // 3

// IsRegExp()
console.log(typeof /abc/);       // "object"
console.log(/abc/ instanceof RegExp); // true
console.log(RegExp(/abc/));        // /abc/
console.log(RegExp('abc'));        // /abc/

// 涉及 Symbol.match 的情况
const nonRegExp = {
  [Symbol.match](str) {
    return '自定义匹配';
  }
};
console.log(IsRegExp(nonRegExp)); // 根据内部逻辑，这里会返回 true，因为 Symbol.match 存在且为 truthy
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- `regexp`: 一个 `JSRegExp` 对象，模式为 `/a(b)c/g`，`lastIndex` 为 `0`。
- `string`: 字符串 `"xabcyabc"`。

**执行 `RegExpPrototypeExecBodyWithoutResultFast(regexp, string)`:**

1. **检查标志:** `global` 标志存在，`shouldUpdateLastIndex` 为 `true`。
2. **初始 `lastIndex`:**  `lastIndex` 为 `0`，小于字符串长度。
3. **调用 `RegExpExecInternal_Single(regexp, string, lastIndex)`:** 内部执行匹配，找到 "abc" 在索引 `1` 处匹配。
4. **`matchIndices`:** 假设 `RegExpExecInternal_Single` 返回一个 `RegExpMatchInfo` 对象，其中包含：
   - 索引 `0` 的起始位置: `1`
   - 索引 `0` 的结束位置: `4`
   - 捕获组 1 的起始位置: `2`
   - 捕获组 1 的结束位置: `3`
5. **更新 `lastIndex`:** `newLastIndex` 为 `4` (匹配结束位置)。
6. **存储 `lastIndex`:**  `regexp.lastIndex` 被更新为 `4`。
7. **输出:** 返回 `RegExpMatchInfo` 对象。

**如果输入字符串没有匹配项:**

- `RegExpExecInternal_Single` 将返回 `Null`。
- `RegExpPrototypeExecBodyWithoutResultFast` 会跳转到 `IfDidNotMatch` 标签。

**用户常见的编程错误:**

1. **忘记处理 `global` 标志对 `lastIndex` 的影响:**

   ```javascript
   const regex = /abc/g;
   const str = 'abcadef abc';
   console.log(regex.exec(str)); // ["abc", index: 0, input: "abcadef abc", groups: undefined]
   console.log(regex.exec(str)); // ["abc", index: 8, input: "abcadef abc", groups: undefined]
   console.log(regex.exec(str)); // null
   ```
   不理解 `global` 标志会导致每次 `exec` 调用后 `lastIndex` 更新，可能导致意外的结果或无限循环。

2. **在非 `global` 或 `sticky` 的正则表达式上错误地依赖 `lastIndex`:**

   ```javascript
   const regex = /abc/; // 没有 g 或 y 标志
   const str = 'abcadef abc';
   console.log(regex.exec(str)); // ["abc", index: 0, input: "abcadef abc", groups: undefined]
   console.log(regex.exec(str)); // ["abc", index: 0, input: "abcadef abc", groups: undefined]
   ```
   在这种情况下，`lastIndex` 不会被更新，每次 `exec` 都会从头开始匹配。

3. **将非 `RegExp` 对象传递给 `RegExp.prototype.exec`:**

   ```javascript
   const notRegex = { exec: () => 'custom exec' };
   const str = 'some string';
   // 根据代码，这里会先尝试调用对象的 exec 方法
   console.log(RegExp.prototype.exec.call(notRegex, str)); // "custom exec"

   const notRegex2 = {};
   // 如果对象没有 exec 方法，且不是 RegExp 实例，则会抛出 TypeError
   // RegExp.prototype.exec.call(notRegex2, str); // TypeError: RegExp.prototype.exec called on incompatible receiver [object Object]
   ```

4. **误解 `IsRegExp` 的行为:**  `IsRegExp` 不仅仅检查 `instanceof RegExp`，还会考虑 `Symbol.match` 属性，这在某些情况下可能会导致混淆。

总而言之，`v8/src/builtins/regexp.tq` 文件是 V8 引擎中实现正则表达式功能的核心部分，它直接关联到 JavaScript 中 `RegExp` 对象的行为和规范。理解这个文件有助于深入了解 JavaScript 正则表达式的内部工作原理和性能优化。

Prompt: 
```
这是目录为v8/src/builtins/regexp.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-regexp-gen.h'

namespace regexp {

extern macro RegExpBuiltinsAssembler::BranchIfFastRegExpForMatch(
    implicit context: Context)(HeapObject): never labels IsFast,
    IsSlow;
macro IsFastRegExpForMatch(implicit context: Context)(o: HeapObject): bool {
  BranchIfFastRegExpForMatch(o) otherwise return true, return false;
}

extern macro RegExpBuiltinsAssembler::BranchIfFastRegExpForSearch(
    implicit context: Context)(HeapObject): never labels IsFast,
    IsSlow;
macro IsFastRegExpForSearch(implicit context: Context)(o: HeapObject):
    bool {
  BranchIfFastRegExpForSearch(o) otherwise return true, return false;
}

extern macro RegExpBuiltinsAssembler::BranchIfFastRegExp_Strict(
    implicit context: Context)(HeapObject): never labels IsFast,
    IsSlow;
macro IsFastRegExpStrict(implicit context: Context)(o: HeapObject): bool {
  BranchIfFastRegExp_Strict(o) otherwise return true, return false;
}

extern macro RegExpBuiltinsAssembler::BranchIfFastRegExp_Permissive(
    implicit context: Context)(HeapObject): never labels IsFast,
    IsSlow;

@export
macro IsFastRegExpPermissive(implicit context: Context)(o: HeapObject):
    bool {
  BranchIfFastRegExp_Permissive(o) otherwise return true, return false;
}

// ES#sec-regexpexec Runtime Semantics: RegExpExec ( R, S )
@export
transitioning macro RegExpExec(
    implicit context: Context)(receiver: JSReceiver, string: String): JSAny {
  // Take the slow path of fetching the exec property, calling it, and
  // verifying its return value.

  const exec = GetProperty(receiver, 'exec');

  // Is {exec} callable?
  typeswitch (exec) {
    case (execCallable: Callable): {
      const result = Call(context, execCallable, receiver, string);
      if (result != Null) {
        ThrowIfNotJSReceiver(
            result, MessageTemplate::kInvalidRegExpExecResult, '');
      }
      return result;
    }
    case (Object): {
      const regexp = Cast<JSRegExp>(receiver) otherwise ThrowTypeError(
          MessageTemplate::kIncompatibleMethodReceiver, 'RegExp.prototype.exec',
          receiver);
      return RegExpPrototypeExecSlow(regexp, string);
    }
  }
}

extern macro RegExpBuiltinsAssembler::ConstructNewResultFromMatchInfo(
    implicit context: Context)(JSRegExp, RegExpMatchInfo, String,
    Number): JSRegExpResult|JSRegExpResultWithIndices;

const kGlobalOrSticky: constexpr int31
    generates 'JSRegExp::kGlobal | JSRegExp::kSticky';

extern macro RegExpBuiltinsAssembler::RegExpExecInternal_Single(
    implicit context: Context)(JSRegExp, String, Number): HeapObject;

// ES#sec-regexp.prototype.exec
// RegExp.prototype.exec ( string )
// Implements the core of RegExp.prototype.exec but without actually
// constructing the JSRegExpResult. Returns a fixed array containing match
// indices as returned by RegExpExecStub on successful match, and jumps to
// IfDidNotMatch otherwise.
transitioning macro RegExpPrototypeExecBodyWithoutResult(
    implicit context: Context)(regexp: JSRegExp, string: String,
    regexpLastIndex: Number,
    isFastPath: constexpr bool): RegExpMatchInfo labels IfDidNotMatch {
  if (isFastPath) {
    dcheck(HasInitialRegExpMap(regexp));
  } else {
    IncrementUseCounter(context, SmiConstant(kRegExpExecCalledOnSlowRegExp));
  }

  let lastIndex = regexpLastIndex;

  // Check whether the regexp is global or sticky, which determines whether we
  // update last index later on.
  const flags = UnsafeCast<Smi>(regexp.flags);
  const isGlobalOrSticky: intptr =
      SmiUntag(flags) & IntPtrConstant(kGlobalOrSticky);
  const shouldUpdateLastIndex: bool = isGlobalOrSticky != 0;

  // Grab and possibly update last index.
  if (shouldUpdateLastIndex) {
    if (!TaggedIsSmi(lastIndex) || (lastIndex > string.length_smi)) {
      StoreLastIndex(regexp, SmiConstant(0), isFastPath);
      goto IfDidNotMatch;
    }
  } else {
    lastIndex = SmiConstant(0);
  }

  const matchIndices = RegExpExecInternal_Single(regexp, string, lastIndex);

  // {match_indices} is either null or the RegExpMatchInfo array.
  // Return early if exec failed, possibly updating last index.
  if (matchIndices != Null) {
    const matchIndicesRegExpMatchInfo =
        UnsafeCast<RegExpMatchInfo>(matchIndices);
    if (shouldUpdateLastIndex) {
      // Update the new last index from {match_indices}.
      const newLastIndex: Smi = matchIndicesRegExpMatchInfo.GetEndOfCapture(0);
      StoreLastIndex(regexp, newLastIndex, isFastPath);
    }
    return matchIndicesRegExpMatchInfo;
  }
  if (shouldUpdateLastIndex) {
    StoreLastIndex(regexp, SmiConstant(0), isFastPath);
  }
  goto IfDidNotMatch;
}

@export
transitioning macro RegExpPrototypeExecBodyWithoutResultFast(
    implicit context: Context)(regexp: JSRegExp,
    string: String): RegExpMatchInfo labels IfDidNotMatch {
  const lastIndex = LoadLastIndexAsLength(regexp, true);
  return RegExpPrototypeExecBodyWithoutResult(regexp, string, lastIndex, true)
      otherwise IfDidNotMatch;
}

transitioning macro RegExpPrototypeExecBodyWithoutResultFast(
    implicit context: Context)(regexp: JSRegExp, string: String,
    lastIndex: Number): RegExpMatchInfo labels IfDidNotMatch {
  return RegExpPrototypeExecBodyWithoutResult(regexp, string, lastIndex, true)
      otherwise IfDidNotMatch;
}

// ES#sec-regexp.prototype.exec
// RegExp.prototype.exec ( string )
transitioning macro RegExpPrototypeExecBody(
    implicit context: Context)(receiver: JSReceiver, string: String,
    isFastPath: constexpr bool): JSAny {
  let regexp: JSRegExp;
  if constexpr (isFastPath) {
    regexp = UnsafeCast<JSRegExp>(receiver);
  } else {
    regexp = Cast<JSRegExp>(receiver) otherwise ThrowTypeError(
        MessageTemplate::kIncompatibleMethodReceiver, 'RegExp.prototype.exec',
        receiver);
  }
  const lastIndex = LoadLastIndexAsLength(regexp, isFastPath);
  const matchIndices: RegExpMatchInfo = RegExpPrototypeExecBodyWithoutResult(
      regexp, string, lastIndex, isFastPath) otherwise return Null;
  return ConstructNewResultFromMatchInfo(
      regexp, matchIndices, string, lastIndex);
}

macro LoadRegExpFunction(nativeContext: NativeContext): JSFunction {
  return *NativeContextSlot(nativeContext, ContextSlot::REGEXP_FUNCTION_INDEX);
}

// Note this doesn't guarantee const-ness of object properties, just
// unchanged object layout.
macro HasInitialRegExpMap(implicit context: Context)(o: HeapObject): bool {
  const nativeContext = LoadNativeContext(context);
  const function = LoadRegExpFunction(nativeContext);
  const initialMap = UnsafeCast<Map>(function.prototype_or_initial_map);
  return initialMap == o.map;
}

macro IsReceiverInitialRegExpPrototype(
    implicit context: Context)(receiver: Object): bool {
  const nativeContext = LoadNativeContext(context);
  const regexpFun = LoadRegExpFunction(nativeContext);
  const initialMap = UnsafeCast<Map>(regexpFun.prototype_or_initial_map);
  const initialPrototype: HeapObject = initialMap.prototype;
  return TaggedEqual(receiver, initialPrototype);
}

extern enum Flag constexpr 'JSRegExp::Flag' {
  kNone,
  kGlobal,
  kIgnoreCase,
  kMultiline,
  kSticky,
  kUnicode,
  kDotAll,
  kHasIndices,
  kLinear,
  kUnicodeSets
}

const kNoCounterFlagGetter: constexpr int31 = -1;
const kRegExpPrototypeStickyGetter: constexpr int31
    generates 'v8::Isolate::kRegExpPrototypeStickyGetter';
const kRegExpPrototypeUnicodeGetter: constexpr int31
    generates 'v8::Isolate::kRegExpPrototypeUnicodeGetter';

extern macro RegExpBuiltinsAssembler::FastFlagGetter(JSRegExp, constexpr Flag):
    bool;

macro FlagGetter(
    implicit context: Context)(receiver: Object, flag: constexpr Flag,
    counter: constexpr int31, methodName: constexpr string): JSAny {
  typeswitch (receiver) {
    case (receiver: JSRegExp): {
      return SelectBooleanConstant(FastFlagGetter(receiver, flag));
    }
    case (Object): {
    }
  }
  if (!IsReceiverInitialRegExpPrototype(receiver)) {
    ThrowTypeError(MessageTemplate::kRegExpNonRegExp, methodName);
  }
  if constexpr (counter != -1) {
    IncrementUseCounter(context, SmiConstant(counter));
  }
  return Undefined;
}

// ES6 21.2.5.4.
// ES #sec-get-regexp.prototype.global
transitioning javascript builtin RegExpPrototypeGlobalGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return FlagGetter(
      receiver, Flag::kGlobal, kNoCounterFlagGetter, 'RegExp.prototype.global');
}

// ES6 21.2.5.5.
// ES #sec-get-regexp.prototype.ignorecase
transitioning javascript builtin RegExpPrototypeIgnoreCaseGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return FlagGetter(
      receiver, Flag::kIgnoreCase, kNoCounterFlagGetter,
      'RegExp.prototype.ignoreCase');
}

// ES6 21.2.5.7.
// ES #sec-get-regexp.prototype.multiline
transitioning javascript builtin RegExpPrototypeMultilineGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return FlagGetter(
      receiver, Flag::kMultiline, kNoCounterFlagGetter,
      'RegExp.prototype.multiline');
}

transitioning javascript builtin RegExpPrototypeHasIndicesGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return FlagGetter(
      receiver, Flag::kHasIndices, kNoCounterFlagGetter,
      'RegExp.prototype.hasIndices');
}

transitioning javascript builtin RegExpPrototypeLinearGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return FlagGetter(
      receiver, Flag::kLinear, kNoCounterFlagGetter, 'RegExp.prototype.linear');
}

// ES #sec-get-regexp.prototype.dotAll
transitioning javascript builtin RegExpPrototypeDotAllGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return FlagGetter(
      receiver, Flag::kDotAll, kNoCounterFlagGetter, 'RegExp.prototype.dotAll');
}

// ES6 21.2.5.12.
// ES #sec-get-regexp.prototype.sticky
transitioning javascript builtin RegExpPrototypeStickyGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return FlagGetter(
      receiver, Flag::kSticky, kRegExpPrototypeStickyGetter,
      'RegExp.prototype.sticky');
}

// ES6 21.2.5.15.
// ES #sec-get-regexp.prototype.unicode
transitioning javascript builtin RegExpPrototypeUnicodeGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return FlagGetter(
      receiver, Flag::kUnicode, kRegExpPrototypeUnicodeGetter,
      'RegExp.prototype.unicode');
}

// ES2023 22.2.5.14
// ES #sec-get-regexp.prototype.unicodeSets
transitioning javascript builtin RegExpPrototypeUnicodeSetsGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return FlagGetter(
      receiver, Flag::kUnicodeSets, kNoCounterFlagGetter,
      'RegExp.prototype.unicodeSets');
}

extern transitioning macro RegExpBuiltinsAssembler::FlagsGetter(
    implicit context: Context)(Object, constexpr bool): String;

transitioning macro FastFlagsGetter(
    implicit context: Context)(receiver: FastJSRegExp): String {
  return FlagsGetter(receiver, true);
}

transitioning macro SlowFlagsGetter(
    implicit context: Context)(receiver: JSAny): String {
  return FlagsGetter(receiver, false);
}

// ES #sec-get-regexp.prototype.flags
// TFJ(RegExpPrototypeFlagsGetter, 0, kReceiver) \
transitioning javascript builtin RegExpPrototypeFlagsGetter(
    js-implicit context: NativeContext, receiver: JSAny)(): String {
  ThrowIfNotJSReceiver(
      receiver, MessageTemplate::kRegExpNonObject, 'RegExp.prototype.flags');

  // The check is strict because the following code relies on individual flag
  // getters on the regexp prototype (e.g.: global, sticky, ...). We don't
  // bother to check these individually.
  const fastRegexp = Cast<FastJSRegExp>(receiver)
      otherwise return SlowFlagsGetter(receiver);
  return FastFlagsGetter(fastRegexp);
}

extern transitioning macro RegExpBuiltinsAssembler::SlowLoadLastIndex(
    implicit context: Context)(JSAny): JSAny;
extern transitioning macro RegExpBuiltinsAssembler::SlowStoreLastIndex(
    implicit context: Context)(JSAny, JSAny): void;

extern macro RegExpBuiltinsAssembler::FastLoadLastIndex(JSRegExp): Smi;
extern macro RegExpBuiltinsAssembler::FastStoreLastIndex(JSRegExp, Smi): void;

@export
transitioning macro LoadLastIndex(
    implicit context: Context)(regexp: JSAny,
    isFastPath: constexpr bool): JSAny {
  return isFastPath ? FastLoadLastIndex(UnsafeCast<JSRegExp>(regexp)) :
                      SlowLoadLastIndex(regexp);
}

@export
transitioning macro LoadLastIndexAsLength(
    implicit context: Context)(regexp: JSRegExp,
    isFastPath: constexpr bool): Number {
  const lastIndex = LoadLastIndex(regexp, isFastPath);
  if (isFastPath) {
    // ToLength on a positive smi is a nop and can be skipped.
    return UnsafeCast<PositiveSmi>(lastIndex);
  } else {
    // Omit ToLength if last_index is a non-negative smi.
    typeswitch (lastIndex) {
      case (i: PositiveSmi): {
        return i;
      }
      case (o: JSAny): {
        return ToLength_Inline(o);
      }
    }
  }
}

@export
transitioning macro StoreLastIndex(
    implicit context: Context)(regexp: JSAny, value: Number,
    isFastPath: constexpr bool): void {
  if (isFastPath) {
    FastStoreLastIndex(UnsafeCast<JSRegExp>(regexp), UnsafeCast<Smi>(value));
  } else {
    SlowStoreLastIndex(regexp, value);
  }
}

extern macro RegExpBuiltinsAssembler::AdvanceStringIndex(
    String, Number, bool, constexpr bool): Number;
extern macro RegExpBuiltinsAssembler::AdvanceStringIndexFast(
    String, Smi, bool): Smi;
extern macro RegExpBuiltinsAssembler::AdvanceStringIndexSlow(
    String, Number, bool): Smi;

const kRegExpMatchIsTrueishOnNonJSRegExp: constexpr UseCounterFeature
    generates 'v8::Isolate::kRegExpMatchIsTrueishOnNonJSRegExp';
const kRegExpMatchIsFalseishOnJSRegExp: constexpr UseCounterFeature
    generates 'v8::Isolate::kRegExpMatchIsFalseishOnJSRegExp';
const kRegExpExecCalledOnSlowRegExp: constexpr UseCounterFeature
    generates 'v8::Isolate::kRegExpExecCalledOnSlowRegExp';

// ES#sec-isregexp IsRegExp ( argument )
@export
transitioning macro IsRegExp(implicit context: Context)(obj: JSAny): bool {
  const receiver = Cast<JSReceiver>(obj) otherwise return false;

  // Check @match.
  const value = GetProperty(receiver, MatchSymbolConstant());
  if (value == Undefined) {
    return Is<JSRegExp>(receiver);
  }

  dcheck(value != Undefined);
  // The common path. Symbol.match exists, equals the RegExpPrototypeMatch
  // function (and is thus trueish), and the receiver is a JSRegExp.
  if (ToBoolean(value)) {
    if (!Is<JSRegExp>(receiver)) {
      IncrementUseCounter(
          context, SmiConstant(kRegExpMatchIsTrueishOnNonJSRegExp));
    }
    return true;
  }

  dcheck(!ToBoolean(value));
  if (Is<JSRegExp>(receiver)) {
    IncrementUseCounter(context, SmiConstant(kRegExpMatchIsFalseishOnJSRegExp));
  }
  return false;
}

extern runtime RegExpInitializeAndCompile(Context, JSRegExp, String, String):
    JSAny;

@export
transitioning macro RegExpCreate(
    implicit context: Context)(nativeContext: NativeContext,
    maybeString: JSAny, flags: String): JSAny {
  const regexpFun = LoadRegExpFunction(nativeContext);
  const initialMap = UnsafeCast<Map>(regexpFun.prototype_or_initial_map);
  return RegExpCreate(initialMap, maybeString, flags);
}

extern macro ClearTrustedPointerField(HeapObject, constexpr int31): void;
const kJSRegExpRegExpDataOffset:
    constexpr int31 generates 'JSRegExp::kDataOffset';

@export
transitioning macro RegExpCreate(
    implicit context: Context)(initialMap: Map, maybeString: JSAny,
    flags: String): JSAny {
  const pattern: String =
      maybeString == Undefined ? kEmptyString : ToString_Inline(maybeString);
  const regexp =
      UnsafeCast<JSRegExp>(AllocateFastOrSlowJSObjectFromMap(initialMap));
  // Clear the data field, as a GC can be triggered before the field is set
  // during compilation.
  ClearTrustedPointerField(regexp, kJSRegExpRegExpDataOffset);
  return RegExpInitializeAndCompile(context, regexp, pattern, flags);
}
}

"""

```