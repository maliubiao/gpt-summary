Response:
Let's break down the thought process for analyzing this V8 header file.

**1. Initial Scan and Keyword Spotting:**

The first step is to quickly read through the code, looking for recognizable keywords and patterns. Things that immediately jump out are:

* `// Copyright`:  Standard copyright notice.
* `#ifndef`, `#define`, `#include`: C++ preprocessor directives, indicating a header file.
* `namespace v8`, `namespace internal`:  V8's internal organization.
* `class RegExpBuiltinsAssembler`: The central class, likely responsible for implementing RegExp built-in functions.
* `: public CodeStubAssembler`:  Inheritance, suggesting `RegExpBuiltinsAssembler` uses the capabilities of `CodeStubAssembler`. This hints at low-level code generation.
* `TNode<>`:  A common V8 type for representing nodes in an abstract syntax tree or intermediate representation during code generation.
* `Smi`, `IntPtrT`, `String`, `JSRegExp`, `Context`, `BoolT`, `FixedArray`, `RegExpData`, `RegExpMatchInfo`, `JSArray`, `HeapObject`, `Map`, `NativeContext`:  V8-specific types related to its object model and internal representations.
* Function names like `AllocateRegExpResult`, `FastLoadLastIndex`, `SlowStoreLastIndex`, `RegExpExecInternal`, `BranchIfFastRegExp`, `FlagsGetter`, `RegExpInitialize`, `AdvanceStringIndex`, `RegExpPrototypeSplitBody`, `RegExpMatchGlobal`, `RegExpReplaceGlobalSimpleString`. These strongly suggest functionality related to regular expression operations.
* Comments like `// Allocate either a JSRegExpResult...`, `// Low level logic around the actual call...`, `// Are you afraid? If not, you should be.` These offer direct clues about the purpose of the code.

**2. Understanding the Core Class: `RegExpBuiltinsAssembler`**

The name itself is very informative. "RegExpBuiltins" signifies that this class deals with the implementation of built-in regular expression methods in JavaScript. "Assembler" and the base class `CodeStubAssembler` point towards code generation, likely using V8's internal assembly-like language (Torque).

**3. Deciphering Key Functions (and their naming conventions):**

The function names often follow a pattern:

* **`Allocate...`**:  Functions for creating and allocating memory for specific V8 objects related to regular expressions.
* **`Load...`, `Store...`**: Functions for reading and writing properties of regular expression objects (like `lastIndex`). The `Fast` and `Slow` prefixes suggest optimizations for common cases versus more general handling.
* **`Get...`**: Functions for retrieving data (like `GetStringPointers`).
* **`Initialize...`**: Functions for setting up the initial state of objects.
* **`Exec...`**: Functions related to the core operation of executing a regular expression against a string. The `Internal` suffix often indicates a lower-level or internal implementation. `Single` and `Batched` suggest different execution strategies.
* **`BranchIf...`**: Functions for conditional branching during code generation, based on properties of regular expression objects (like whether it's a "fast" RegExp).
* **`IsFastRegExp...`**: Functions for checking if a regular expression object meets certain "fast path" criteria.
* **`FlagsGetter`**:  A getter for retrieving the flags of a regular expression.
* **`AdvanceStringIndex`**:  A function to move the index pointer in a string, handling Unicode correctly.
* **`...Prototype...`**: Functions likely implementing methods found on the `RegExp.prototype` object in JavaScript.
* **`AppendStringSlice`**: A utility for manipulating strings.
* **`RegExpReplaceGlobalSimpleString`**:  A specialized function for a common `replace` use case.

**4. Identifying Relationships and Logic:**

As you examine the functions, connections and logical flows begin to emerge:

* The functions related to `lastIndex` (`FastLoadLastIndex`, `SlowLoadLastIndex`, `FastStoreLastIndex`, `SlowStoreLastIndex`) are essential for the stateful nature of global regular expressions.
* The `RegExpExecInternal` family of functions forms the core of the matching process. The distinction between `Single` and `Batched` highlights different performance optimization strategies.
* The `BranchIfFastRegExp` family reveals a focus on optimizing common regular expression usage patterns by avoiding slower, more general code paths.
* The functions dealing with `RegExpMatchInfo` and result allocation (`AllocateRegExpResult`, `InitializeMatchInfoFromRegisters`) are about structuring the output of a regular expression match.
* The presence of `Unicode` and `UnicodeSets` flags in function names indicates support for advanced Unicode features in regular expressions.

**5. Connecting to JavaScript:**

With a good understanding of the C++ code, the next step is to link it to the JavaScript RegExp API. This involves thinking about how common JavaScript RegExp methods are implemented under the hood:

* `exec()`:  Likely involves calls to `RegExpExecInternal`.
* `test()`: Could be a simplified version of `exec()`.
* `match()`:  The global version likely uses `RegExpExecInternal_Batched` or `RegExpMatchGlobal`.
* `matchAll()`: The `RegExpMatchAllAssembler` class suggests a dedicated implementation for this.
* `replace()`: The presence of `RegExpReplaceGlobalSimpleString` hints at optimized implementations.
* `search()`:  The `BranchIfFastRegExpForSearch` function indicates specific fast-path logic for this method.
* `split()`:  The `RegExpPrototypeSplitBody` function clearly implements this.
* `flags` property:  The `FlagsGetter` and `FastFlagGetter`/`SlowFlagGetter` functions are involved.
* `lastIndex` property: The `FastLoadLastIndex`/`SlowLoadLastIndex` and `FastStoreLastIndex`/`SlowStoreLastIndex` functions are directly related.
* `new RegExp()`: The `RegExpInitialize` function likely handles the initialization of new RegExp objects.

**6. Inferring Torque Usage (Based on File Extension):**

The instruction specifically mentions checking the file extension. If the file ended in `.tq`, then it would indeed be a Torque source file. Even without that, the presence of `CodeStubAssembler` and `TNode<>` strongly suggests that Torque (or a similar code generation mechanism) is being used.

**7. Considering Common Errors and Assumptions:**

Think about how developers might misuse regular expressions or make assumptions that V8 optimizes for:

* **Modifying `RegExp.prototype`:** The extensive fast-path checking logic directly addresses this. Developers might add custom methods or override existing ones.
* **Incorrectly using `lastIndex`:**  Forgetting to reset `lastIndex` for non-global regexps can lead to unexpected results.
* **Performance issues with complex regexps:**  The fast-path optimizations aim to mitigate this for simpler cases.
* **Misunderstanding Unicode handling:** The presence of Unicode-aware functions highlights the complexity of this area.

**8. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each part of the prompt:

* **Functionality:**  Provide a high-level overview and then detail the purpose of key function groups.
* **Torque:** Explain how to identify Torque usage and its role.
* **JavaScript Examples:**  Provide concrete examples showing how the C++ functions relate to JavaScript RegExp methods.
* **Logic and Assumptions:**  Illustrate the fast-path logic with a simple scenario.
* **Common Errors:** Give examples of typical mistakes developers make.

By following these steps – scanning, identifying key elements, understanding relationships, connecting to JavaScript, and considering potential issues – you can effectively analyze and explain the purpose of a complex header file like this.
这个头文件 `v8/src/builtins/builtins-regexp-gen.h` 是 V8 JavaScript 引擎中关于正则表达式内置函数的代码生成器头文件。它定义了一个名为 `RegExpBuiltinsAssembler` 的 C++ 类，该类继承自 `CodeStubAssembler`。 `CodeStubAssembler` 是 V8 中用于生成高效机器码的工具，通常用于实现内置函数。

**`RegExpBuiltinsAssembler` 类的主要功能：**

1. **提供用于生成正则表达式相关内置函数的构建块:**  这个类包含了许多辅助函数，用于在编译时生成实现各种 JavaScript 正则表达式操作所需的机器码。这些操作包括但不限于：
    * 正则表达式的执行 (`exec`, `test`, `match`, `matchAll`)
    * 字符串的分割 (`split`)
    * 字符串的替换 (`replace`)
    * 获取正则表达式的属性（如 `flags`, `lastIndex`)
    * 创建新的正则表达式对象

2. **处理正则表达式的快速路径优化:**  V8 尝试优化常见的正则表达式使用场景，避免进入更通用的、性能较慢的代码路径。这个类中包含了一些用于检查是否可以走快速路径的函数（例如 `BranchIfFastRegExp` 系列的函数）。

3. **与 V8 内部的正则表达式引擎交互:**  它包含了调用 V8 内部正则表达式匹配引擎的函数，例如 `RegExpExecInternal` 和 `RegExpExecAtom`。

4. **管理正则表达式执行结果:**  它提供了分配和初始化正则表达式结果对象的函数 (`AllocateRegExpResult`)，以及处理匹配信息的函数 (`InitializeMatchInfoFromRegisters`).

5. **处理 `lastIndex` 属性:**  提供了快速和慢速加载/存储 `lastIndex` 属性的函数，因为这个属性在全局正则表达式中具有状态。

**关于 `.tq` 文件:**

你提到如果 `v8/src/builtins/builtins-regexp-gen.h` 以 `.tq` 结尾，那它会是一个 V8 Torque 源代码。这是正确的。Torque 是 V8 用来定义内置函数的领域特定语言。虽然这个文件本身是 `.h` 头文件，但它定义了在 Torque 代码中可能被调用的 C++ 类和辅助函数。实际使用这些构建块的 Torque 代码通常位于以 `.tq` 结尾的文件中，例如可能存在一个 `v8/src/builtins/regexp-builtins.tq` 文件。

**与 JavaScript 功能的关系及示例:**

`RegExpBuiltinsAssembler` 中定义的功能直接对应于 JavaScript 中 `RegExp` 对象及其原型上的方法。

**示例：`exec()` 方法**

`RegExpBuiltinsAssembler` 中的 `RegExpExecInternal` 或其变体函数负责实现 `RegExp.prototype.exec()` 方法的核心逻辑。

```javascript
const regex = /ab*/g;
const str = 'abbcdefabh';
let array;

while ((array = regex.exec(str)) !== null) {
  console.log(`Found ${array[0]}. Next starts at ${regex.lastIndex}.`);
  // Expected output: "Found abb. Next starts at 3."
  // Expected output: "Found ab. Next starts at 9."
}
```

在这个 JavaScript 例子中，`regex.exec(str)` 的调用最终会触发 V8 内部的正则表达式执行逻辑，而 `RegExpBuiltinsAssembler` 中的相关函数（例如 `RegExpExecInternal`）会参与生成执行这段逻辑的机器码。`FastLoadLastIndex` 和 `FastStoreLastIndex` 可能会被用来高效地访问和更新 `regex.lastIndex` 属性。

**示例：`String.prototype.match()` 方法**

`RegExpBuiltinsAssembler` 中的 `RegExpMatchGlobal` 函数可能与全局正则表达式的 `match()` 方法的实现有关。

```javascript
const regex = /ab*/g;
const str = 'abbcdefabh';
const matches = str.match(regex);
console.log(matches); // 输出: [ 'abb', 'ab' ]
```

当调用 `str.match(regex)` 时，如果 `regex` 是全局的，V8 可能会使用类似 `RegExpMatchGlobal` 的内置函数来查找所有匹配项。

**代码逻辑推理 (假设输入与输出):**

假设我们调用了 `RegExp.prototype.exec()` 方法，并且进入了 `RegExpExecInternal_Single` 函数。

**假设输入:**

* `context`: 当前的 JavaScript 执行上下文。
* `regexp`: 一个 `JSRegExp` 对象，例如 `/w+/`.
* `string`: 要匹配的字符串，例如 `"hello world"`.
* `last_index`: 一个数字，表示从字符串的哪个位置开始匹配，例如 `0`。

**预期输出:**

* 如果匹配成功，`RegExpExecInternal_Single` 可能会返回一个 `JSRegExpResult` 对象，其中包含匹配的字符串、匹配的起始索引以及捕获组（如果有）。例如，对于输入 `/w+/`, `"hello world"`, `0`，输出可能是包含 `"hello"`，索引为 `0` 的结果对象。`regexp.lastIndex` 可能会被更新为 `5`（匹配结束后的下一个位置）。
* 如果匹配失败，`RegExpExecInternal_Single` 可能会返回 `null`，并且 `regexp.lastIndex` 会被重置为 `0` (如果正则表达式不是全局的) 或者保持不变 (如果正则表达式是全局的)。

**用户常见的编程错误及示例:**

1. **忘记处理 `lastIndex` 对于全局正则表达式的影响:**

```javascript
const regex = /a/g;
const str = 'aba';

console.log(regex.exec(str)); // 输出: ['a', index: 0, input: 'aba', groups: undefined]
console.log(regex.exec(str)); // 输出: ['a', index: 2, input: 'aba', groups: undefined]
console.log(regex.exec(str)); // 输出: null
console.log(regex.exec(str)); // 输出: ['a', index: 0, input: 'aba', groups: undefined] // 再次从头开始
```

错误：开发者可能没有意识到在循环中使用全局正则表达式时，需要注意 `lastIndex` 的变化。如果不小心，可能会导致无限循环或错过某些匹配项。

2. **在非全局正则表达式上错误地依赖 `lastIndex`:**

```javascript
const regex = /a/;
const str = 'aba';

console.log(regex.exec(str)); // 输出: ['a', index: 0, input: 'aba', groups: undefined]
console.log(regex.exec(str)); // 输出: ['a', index: 0, input: 'aba', groups: undefined] // 每次都从头开始
```

错误：开发者可能认为非全局正则表达式的 `lastIndex` 也会像全局正则表达式一样前进。事实上，非全局正则表达式的 `lastIndex` 始终为 `0`。

3. **修改 `RegExp.prototype` 导致意外行为:**

虽然不常见，但用户可能会尝试修改 `RegExp.prototype` 上的方法，这可能会导致 V8 的优化失效，甚至引发错误。`BranchIfFastRegExp` 等函数旨在检查这种情况。

```javascript
RegExp.prototype.exec = function() {
  console.log("My custom exec!");
  return null;
};

const regex = /a/;
const str = 'aba';
regex.exec(str); // 输出: "My custom exec!"
```

错误：直接修改内置对象的原型可能会导致不可预测的行为，并破坏 V8 的优化假设。

总结来说，`v8/src/builtins/builtins-regexp-gen.h` 是 V8 引擎中一个关键的头文件，它定义了用于生成高效正则表达式内置函数代码的构建块，并密切关系着 JavaScript 中 `RegExp` 对象的各种功能和用户可能遇到的编程错误。

### 提示词
```
这是目录为v8/src/builtins/builtins-regexp-gen.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-regexp-gen.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BUILTINS_BUILTINS_REGEXP_GEN_H_
#define V8_BUILTINS_BUILTINS_REGEXP_GEN_H_

#include <optional>

#include "src/codegen/code-stub-assembler.h"
#include "src/common/message-template.h"
#include "src/objects/string.h"
#include "src/regexp/regexp.h"

namespace v8 {
namespace internal {

class RegExpBuiltinsAssembler : public CodeStubAssembler {
 public:
  explicit RegExpBuiltinsAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<Smi> SmiZero();
  TNode<IntPtrT> IntPtrZero();

  // Allocate either a JSRegExpResult or a JSRegExpResultWithIndices (depending
  // on has_indices) with the given length (the number of captures, including
  // the match itself), index (the index where the match starts), and input
  // string.
  TNode<JSRegExpResult> AllocateRegExpResult(
      TNode<Context> context, TNode<Smi> length, TNode<Smi> index,
      TNode<String> input, TNode<JSRegExp> regexp, TNode<Number> last_index,
      TNode<BoolT> has_indices, TNode<FixedArray>* elements_out = nullptr);

  TNode<Object> FastLoadLastIndexBeforeSmiCheck(TNode<JSRegExp> regexp);
  TNode<Smi> FastLoadLastIndex(TNode<JSRegExp> regexp) {
    return CAST(FastLoadLastIndexBeforeSmiCheck(regexp));
  }
  TNode<Object> SlowLoadLastIndex(TNode<Context> context, TNode<Object> regexp);

  void FastStoreLastIndex(TNode<JSRegExp> regexp, TNode<Smi> value);
  void SlowStoreLastIndex(TNode<Context> context, TNode<Object> regexp,
                          TNode<Object> value);

  TNode<Smi> LoadCaptureCount(TNode<RegExpData> data);
  TNode<Smi> RegistersForCaptureCount(TNode<Smi> capture_count);

  // Loads {var_string_start} and {var_string_end} with the corresponding
  // offsets into the given {string_data}.
  void GetStringPointers(TNode<RawPtrT> string_data, TNode<IntPtrT> offset,
                         TNode<IntPtrT> last_index,
                         TNode<IntPtrT> string_length,
                         String::Encoding encoding,
                         TVariable<RawPtrT>* var_string_start,
                         TVariable<RawPtrT>* var_string_end);

  // Returns the vector and whether the returned vector was dynamically
  // allocated. Both must be passed to FreeRegExpResultVector when done,
  // even for exceptional control flow.
  std::pair<TNode<RawPtrT>, TNode<BoolT>> LoadOrAllocateRegExpResultVector(
      TNode<Smi> register_count);
  void FreeRegExpResultVector(TNode<RawPtrT> result_vector,
                              TNode<BoolT> is_dynamic);

  TNode<RegExpMatchInfo> InitializeMatchInfoFromRegisters(
      TNode<Context> context, TNode<RegExpMatchInfo> match_info,
      TNode<Smi> register_count, TNode<String> subject,
      TNode<RawPtrT> result_offsets_vector);

  // Low level logic around the actual call into pattern matching code.
  //
  // TODO(jgruber): Callers that either 1. don't need the RegExpMatchInfo, or
  // 2. need multiple matches, should switch to the new API which passes
  // results via an offsets vector and allows returning multiple matches per
  // call. See RegExpExecInternal_Batched.
  TNode<HeapObject> RegExpExecInternal_Single(TNode<Context> context,
                                              TNode<JSRegExp> regexp,
                                              TNode<String> string,
                                              TNode<Number> last_index);

  // This is the new API which makes it possible to use the global irregexp
  // execution mode from within CSA.
  //
  // - The result_offsets_vector must be managed by callers.
  // - This returns the number of matches. Callers must initialize the
  //   RegExpMatchInfo as needed.
  // - Subtle: The engine signals 'end of matches' (i.e. there is no further
  //   match in the string past the last match contained in the
  //   result_offsets_vector) by returning fewer matches than the
  //   result_offsets_vector capacity. For example, if the vector could fit 10
  //   matches, but we return '9', then all matches have been found.
  // - Subtle: The above point requires that all implementations ALWAYS return
  //   the maximum number of matches they can.
  // - Subtle: The regexp stack may grow, i.e. move, during irregexp execution.
  //   Since result_offsets_vector is allocated on it, it may also move. Reload
  //   it after irregexp execution.
  //
  // TODO(jgruber): Consider changing the irregexp signature s.t. it returns
  // the result_offsets_vector pointer on success. We would then no longer have
  // to reload it.
  TNode<UintPtrT> RegExpExecInternal(
      TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> string,
      TNode<Number> last_index, TNode<RawPtrT> result_offsets_vector,
      TNode<Int32T> result_offsets_vector_length);

  TNode<UintPtrT> RegExpExecAtom(TNode<Context> context,
                                 TNode<AtomRegExpData> data,
                                 TNode<String> string, TNode<Smi> last_index,
                                 TNode<RawPtrT> result_offsets_vector,
                                 TNode<Int32T> result_offsets_vector_length);

  // This is a wrapper around using the global irregexp mode, i.e. the mode in
  // which a single call into irregexp may return multiple matches.  The
  // once_per_batch function is called once after each irregexp call, and
  // once_per_match is called once per single match.
  using OncePerBatchFunction = std::function<void(TNode<IntPtrT>)>;
  using OncePerMatchFunction =
      std::function<void(TNode<RawPtrT>, TNode<Int32T>, TNode<Int32T>)>;
  TNode<IntPtrT> RegExpExecInternal_Batched(
      TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> subject,
      TNode<RegExpData> data, const VariableList& merge_vars,
      OncePerBatchFunction once_per_batch, OncePerMatchFunction once_per_match);

  TNode<JSRegExpResult> ConstructNewResultFromMatchInfo(
      TNode<Context> context, TNode<JSRegExp> regexp,
      TNode<RegExpMatchInfo> match_info, TNode<String> string,
      TNode<Number> last_index);

  // Fast path check logic.
  //
  // Are you afraid? If not, you should be.
  //
  // It's complicated. Fast path checks protect certain assumptions, e.g. that
  // relevant properties on the regexp prototype (such as exec, @@split, global)
  // are unmodified.
  //
  // These assumptions differ by callsite. For example, RegExpPrototypeExec
  // cares whether the exec property has been modified; but it's totally fine
  // to modify other prototype properties. On the other hand,
  // StringPrototypeSplit does care very much whether @@split has been changed.
  //
  // We want to keep regexp execution on the fast path as much as possible.
  // Ideally, we could simply check if the regexp prototype has been modified;
  // yet common web frameworks routinely mutate it for various reasons. But most
  // of these mutations should happen in a way that still allows us to remain
  // on the fast path. To support this, the fast path check logic necessarily
  // becomes more involved.
  //
  // There are multiple knobs to twiddle for regexp fast path checks. We support
  // checks that completely ignore the prototype, checks that verify specific
  // properties on the prototype (the caller must ensure it passes in the right
  // ones), and strict checks that additionally ensure the prototype is
  // unchanged (we use these when we'd have to check multiple properties we
  // don't care too much about, e.g. all individual flag getters).

  using DescriptorIndexNameValue =
      PrototypeCheckAssembler::DescriptorIndexNameValue;

  void BranchIfFastRegExp(
      TNode<Context> context, TNode<HeapObject> object, TNode<Map> map,
      PrototypeCheckAssembler::Flags prototype_check_flags,
      std::optional<DescriptorIndexNameValue> additional_property_to_check,
      Label* if_isunmodified, Label* if_ismodified);

  void BranchIfFastRegExpForSearch(TNode<Context> context,
                                   TNode<HeapObject> object,
                                   Label* if_isunmodified,
                                   Label* if_ismodified);
  void BranchIfFastRegExpForMatch(TNode<Context> context,
                                  TNode<HeapObject> object,
                                  Label* if_isunmodified, Label* if_ismodified);

  // Strict: Does not tolerate any changes to the prototype map.
  // Permissive: Allows changes to the prototype map except for the exec
  //             property.
  void BranchIfFastRegExp_Strict(TNode<Context> context,
                                 TNode<HeapObject> object,
                                 Label* if_isunmodified, Label* if_ismodified);
  void BranchIfFastRegExp_Permissive(TNode<Context> context,
                                     TNode<HeapObject> object,
                                     Label* if_isunmodified,
                                     Label* if_ismodified);

  // Performs fast path checks on the given object itself, but omits prototype
  // checks.
  TNode<BoolT> IsFastRegExpNoPrototype(TNode<Context> context,
                                       TNode<Object> object);
  TNode<BoolT> IsFastRegExpNoPrototype(TNode<Context> context,
                                       TNode<Object> object, TNode<Map> map);

  void BranchIfRegExpResult(const TNode<Context> context,
                            const TNode<Object> object, Label* if_isunmodified,
                            Label* if_ismodified);

  TNode<String> FlagsGetter(TNode<Context> context, TNode<Object> regexp,
                            const bool is_fastpath);

  TNode<BoolT> FastFlagGetter(TNode<JSRegExp> regexp, JSRegExp::Flag flag);
  TNode<BoolT> FastFlagGetterGlobal(TNode<JSRegExp> regexp) {
    return FastFlagGetter(regexp, JSRegExp::kGlobal);
  }
  TNode<BoolT> FastFlagGetterUnicode(TNode<JSRegExp> regexp) {
    return FastFlagGetter(regexp, JSRegExp::kUnicode);
  }
  TNode<BoolT> FastFlagGetterUnicodeSets(TNode<JSRegExp> regexp) {
    return FastFlagGetter(regexp, JSRegExp::kUnicodeSets);
  }
  TNode<BoolT> SlowFlagGetter(TNode<Context> context, TNode<Object> regexp,
                              JSRegExp::Flag flag);
  TNode<BoolT> FlagGetter(TNode<Context> context, TNode<Object> regexp,
                          JSRegExp::Flag flag, bool is_fastpath);

  TNode<Object> RegExpInitialize(const TNode<Context> context,
                                 const TNode<JSRegExp> regexp,
                                 const TNode<Object> maybe_pattern,
                                 const TNode<Object> maybe_flags);

  TNode<Number> AdvanceStringIndex(TNode<String> string, TNode<Number> index,
                                   TNode<BoolT> is_unicode, bool is_fastpath);

  TNode<Smi> AdvanceStringIndexFast(TNode<String> string, TNode<Smi> index,
                                    TNode<BoolT> is_unicode) {
    return CAST(AdvanceStringIndex(string, index, is_unicode, true));
  }

  TNode<Smi> AdvanceStringIndexSlow(TNode<String> string, TNode<Number> index,
                                    TNode<BoolT> is_unicode) {
    return CAST(AdvanceStringIndex(string, index, is_unicode, false));
  }

  TNode<JSArray> RegExpPrototypeSplitBody(TNode<Context> context,
                                          TNode<JSRegExp> regexp,
                                          TNode<String> string,
                                          TNode<Smi> limit);

  TNode<HeapObject> RegExpMatchGlobal(TNode<Context> context,
                                      TNode<JSRegExp> regexp,
                                      TNode<String> subject,
                                      TNode<RegExpData> data);
  TNode<String> AppendStringSlice(TNode<Context> context,
                                  TNode<String> to_string,
                                  TNode<String> from_string,
                                  TNode<Smi> slice_start, TNode<Smi> slice_end);
  TNode<String> RegExpReplaceGlobalSimpleString(TNode<Context> context,
                                                TNode<JSRegExp> regexp,
                                                TNode<String> subject,
                                                TNode<RegExpData> data,
                                                TNode<String> replace_string);
};

class RegExpMatchAllAssembler : public RegExpBuiltinsAssembler {
 public:
  explicit RegExpMatchAllAssembler(compiler::CodeAssemblerState* state)
      : RegExpBuiltinsAssembler(state) {}

  TNode<Object> CreateRegExpStringIterator(TNode<NativeContext> native_context,
                                           TNode<Object> regexp,
                                           TNode<String> string,
                                           TNode<BoolT> global,
                                           TNode<BoolT> full_unicode);
};

}  // namespace internal
}  // namespace v8

#endif  // V8_BUILTINS_BUILTINS_REGEXP_GEN_H_
```