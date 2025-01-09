Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick skim for recognizable keywords and structures. Things that jump out include:

* `// Copyright`, license information – indicates source code.
* `#include` – C++ header files. These give clues about the code's dependencies and purpose (e.g., `builtins-regexp-gen.h`, `code-stub-assembler-inl.h`, `js-regexp.h`).
* `namespace v8 { namespace internal {` – confirms this is part of the V8 JavaScript engine's internal implementation.
* `static void Builtins::Generate_...` – suggests functions that generate code or handle built-in functionalities. "RegExpInterpreterTrampoline" and "RegExpExperimentalTrampoline" are highly relevant.
* `TNode<...>` – indicates the use of V8's TurboFan intermediate representation (IR) nodes. This signifies low-level code generation or manipulation.
* `RegExpBuiltinsAssembler` – a class likely responsible for assembling built-in RegExp functionalities.
* Function names like `AllocateRegExpResult`, `FastLoadLastIndex`, `SlowStoreLastIndex`, `ConstructNewResultFromMatchInfo`, `RegExpExecInternal`, etc. – these are strongly indicative of regular expression operations.
* `Label`, `GotoIf`, `Bind`, `Branch`, `Loop` – control flow constructs common in code generation.
* `CallBuiltin`, `CallRuntime`, `CallCFunction` – calls to other V8 built-ins, runtime functions, and C/C++ functions.
* References to `JSRegExp`, `RegExpMatchInfo`, `RegExpData` – V8 internal objects related to regular expressions.
* Mentions of flags like `JSRegExp::kHasIndices`.

**2. Identifying the Core Functionality - Regular Expressions:**

The filename (`builtins-regexp-gen.cc`) and the repeated presence of "RegExp" strongly suggest this file deals with the implementation of regular expression functionalities within V8. The included header files like `js-regexp.h` and `regexp-match-info.h` further reinforce this.

**3. Analyzing Key Function Blocks:**

Now, focus on the functions that seem most important based on their names and initial observations:

* **Trampolines (`Generate_RegExpInterpreterTrampoline`, `Generate_RegExpExperimentalTrampoline`):**  The comments clearly state these tail-call the regular expression interpreter and the experimental engine. This indicates entry points for executing RegExp matching.

* **`RegExpBuiltinsAssembler` methods:** This class appears to be the central hub. Examine the purpose of each method:
    * `AllocateRegExpResult`:  Likely creates the result object for a RegExp match. The logic for handling the `has_indices` flag is interesting.
    * `FastLoadLastIndex`, `SlowLoadLastIndex`, `FastStoreLastIndex`, `SlowStoreLastIndex`: These deal with getting and setting the `lastIndex` property of RegExp objects, with fast and slow paths for optimization.
    * `LoadCaptureCount`, `RegistersForCaptureCount`:  Related to determining the number of capture groups in a RegExp.
    * `ConstructNewResultFromMatchInfo`:  This is a crucial function that builds the final result object from the raw match information. The complexity suggests it handles both simple matches and those with named capture groups and `/d` flag.
    * `GetStringPointers`:  A helper function to get pointers to the underlying string data, considering encoding.
    * `LoadOrAllocateRegExpResultVector`, `FreeRegExpResultVector`: Manages a temporary buffer used during RegExp execution. The static/dynamic allocation logic is an optimization.
    * `InitializeMatchInfoFromRegisters`: Populates the `RegExpMatchInfo` object with data from the temporary buffer.
    * `RegExpExecInternal_Single`, `RegExpExecInternal`: The core execution functions. They handle dispatching to the interpreter or compiled code, managing temporary buffers, and handling exceptions.

**4. Connecting to JavaScript:**

Consider how these low-level C++ functions relate to JavaScript. The comments mentioning "call from js" in the trampoline functions are a strong hint. Think about common JavaScript RegExp operations:

* `RegExp.prototype.exec()`:  This is the most obvious candidate. The code seems to be implementing the core logic behind this method.
* `String.prototype.match()`:  This method also uses regular expressions.
* `String.prototype.search()`, `String.prototype.replace()`, `String.prototype.split()`: While not explicitly detailed in this snippet, these methods likely rely on similar underlying RegExp matching mechanisms.

**5. Inferring Logic and Examples:**

Based on the function names and their parameters, start to infer the logic:

* **`AllocateRegExpResult`:** Takes match length, index, input string, and flags as input and creates a result array-like object. The `has_indices` flag determines the type of the result object. *JavaScript Example:*  A simple `exec()` call that returns an array with the match and captured groups.

* **`ConstructNewResultFromMatchInfo`:** Takes raw match data and constructs the structured result object, handling named capture groups and the `/d` flag. *JavaScript Example:*  An `exec()` call on a RegExp with named capture groups or the `/d` flag.

* **`RegExpExecInternal`:**  Takes the RegExp object, input string, and last index as input and performs the actual matching. It dispatches to the interpreter or compiled code. *JavaScript Example:*  Any `exec()` call.

**6. Identifying Potential Errors:**

Think about common mistakes developers make with regular expressions:

* **Incorrect `lastIndex`:**  Forgetting to reset `lastIndex` or setting it to an invalid value can lead to unexpected results.
* **Misunderstanding capture groups:**  Not knowing how capture groups are indexed or accessed.
* **Forgetting the `/g` flag:**  When iterating through all matches, forgetting the global flag leads to infinite loops.

**7. Structuring the Summary:**

Organize the findings into logical categories:

* **Core Functionality:**  Start with the main purpose of the file.
* **Key Components:**  List the important classes and functions.
* **Relationship to JavaScript:** Explain how the C++ code relates to JavaScript RegExp features.
* **Logic and Examples:** Provide concrete examples of how the C++ code is used in JavaScript.
* **Common Errors:**  Illustrate potential pitfalls for developers.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe this just handles RegExp creation."  **Correction:** The presence of `RegExpExecInternal` and match result construction indicates it's more about execution.
* **Uncertainty:** "What's the significance of the trampolines?" **Clarification:**  The comments explain they are entry points for different execution engines (interpreter vs. experimental).
* **Complexity of `ConstructNewResultFromMatchInfo`:**  Recognize the different paths for named captures and the `/d` flag and break down the logic.

By following these steps, iteratively exploring the code, and connecting it to JavaScript concepts, you can effectively analyze and summarize the functionality of a complex C++ source file like the one provided.
Let's break down the functionality of `v8/src/builtins/builtins-regexp-gen.cc` based on the provided code snippet.

**Core Functionality:**

This C++ source code file is a part of the V8 JavaScript engine and is responsible for generating code (likely using the CodeStubAssembler - CSA) for the built-in functionalities related to **JavaScript `RegExp` objects**. It handles the low-level details of regular expression execution and result creation within V8.

**Key Features and Operations:**

Based on the code, here's a breakdown of the specific functionalities implemented:

1. **Trampolines for RegExp Execution Engines:**
   - `Generate_RegExpInterpreterTrampoline`: Creates a jump target for calling the regular expression interpreter.
   - `Generate_RegExpExperimentalTrampoline`: Creates a jump target for calling an experimental regular expression engine. These act as entry points when JavaScript calls RegExp methods.

2. **Result Object Allocation (`AllocateRegExpResult`):**
   - Handles the allocation of `JSRegExpResult` objects, which are the objects returned when a regular expression match is found (e.g., by `RegExp.prototype.exec()`).
   - Takes into account whether the `/d` (indices) flag is present in the RegExp, allocating either a standard `JSRegExpResult` or a `JSRegExpResultWithIndices`.
   - Initializes the result object with information like the matched index, the input string, and placeholder for capture groups and named groups.

3. **`lastIndex` Management:**
   - `FastLoadLastIndexBeforeSmiCheck`, `SlowLoadLastIndex`:  Provide optimized and general ways to retrieve the `lastIndex` property of a `RegExp` object.
   - `FastStoreLastIndex`, `SlowStoreLastIndex`: Provide optimized and general ways to set the `lastIndex` property. The "fast" versions likely assume the `RegExp` object hasn't been modified in ways that would invalidate in-object field access.

4. **Capture Group Handling:**
   - `LoadCaptureCount`: Retrieves the number of capturing groups defined in the regular expression.
   - `RegistersForCaptureCount`: Calculates the number of registers needed to store the captured groups' start and end indices.

5. **Constructing the Match Result (`ConstructNewResultFromMatchInfo`):**
   - This is a core function that takes the raw match information (stored in a `RegExpMatchInfo` object) and constructs the final `JSRegExpResult` object.
   - It extracts the overall match and the captured substrings.
   - It handles named capture groups: if the RegExp has named captures, it creates a separate object to store them as properties.
   - It handles the `/d` (indices) flag: if present, it creates an "indices" array in the result object that contains the start and end indices of the matched groups.

6. **String Pointer Handling (`GetStringPointers`):**
   - A utility function to get raw pointers to the start and end of a substring within the subject string, taking into account the string's encoding (one-byte or two-byte).

7. **Managing Temporary Match Buffers (`LoadOrAllocateRegExpResultVector`, `FreeRegExpResultVector`):**
   - V8 uses a temporary buffer (`result_offsets_vector`) to store the start and end indices of the matched groups during the execution phase.
   - These functions handle allocating this buffer (either a static, pre-allocated one or a dynamically allocated one if the number of capture groups is large) and freeing it.

8. **Initializing Match Information (`InitializeMatchInfoFromRegisters`):**
   - Takes the raw match offsets from the temporary buffer and populates the `RegExpMatchInfo` object, which is then used to construct the final result.

9. **Core RegExp Execution (`RegExpExecInternal_Single`, `RegExpExecInternal`):**
   - `RegExpExecInternal_Single`:  A higher-level function that orchestrates a single RegExp execution. It allocates the temporary buffer, calls the internal execution engine, and then constructs the result.
   - `RegExpExecInternal`: The low-level function that actually calls the compiled regular expression code or the interpreter. It handles different RegExp types (IRRegExp, AtomRegExp, Experimental) and string encodings.

**Relationship to JavaScript (with JavaScript examples):**

This C++ code directly implements the behavior of JavaScript's `RegExp` methods. Here's how some of the functionalities relate:

* **`RegExp.prototype.exec()`:** The logic in `RegExpExecInternal_Single` and `ConstructNewResultFromMatchInfo` is what's executed when you call `exec()` on a regular expression.

   ```javascript
   const regex = /ab(c*)/;
   const str = 'abbcde';
   const result = regex.exec(str);
   console.log(result);
   // Expected output (something like):
   // [ 'abbc', 'bc', index: 0, input: 'abbcde', groups: undefined ]
   ```
   The `AllocateRegExpResult` function would be involved in creating the array-like `result` object. `ConstructNewResultFromMatchInfo` would populate it with the matched string, captured groups ('bc'), the `index`, and the `input` string.

* **`RegExp.prototype.test()`:** While not explicitly shown in detail, `RegExpExecInternal` would be the underlying function used. `test()` just needs to know if a match occurred, so the result construction might be skipped or simplified.

   ```javascript
   const regex = /world/;
   const str = 'Hello world!';
   const isMatch = regex.test(str);
   console.log(isMatch); // Output: true
   ```

* **`String.prototype.match()`:**  This method also uses the underlying RegExp execution mechanisms implemented here.

   ```javascript
   const str = 'The quick brown fox jumps over the lazy dog.';
   const regex = /[A-Z]/g;
   const matches = str.match(regex);
   console.log(matches); // Output: [ 'T' ]
   ```

* **`RegExp.prototype.lastIndex`:** The `FastLoadLastIndex`, `SlowLoadLastIndex`, `FastStoreLastIndex`, and `SlowStoreLastIndex` functions are used to get and set this property, which is crucial for global (`/g`) regular expressions.

   ```javascript
   const regex = /o/g;
   const str = 'foot';

   console.log(regex.lastIndex); // Output: 0
   regex.exec(str);
   console.log(regex.lastIndex); // Output: 2
   regex.exec(str);
   console.log(regex.lastIndex); // Output: 3
   ```

**Code Logic Inference (Hypothetical Example):**

Let's consider a simplified scenario for `ConstructNewResultFromMatchInfo`:

**Hypothetical Input:**

* `context`: The current V8 execution context.
* `regexp`: A `JSRegExp` object representing the regular expression `/a(b)/`.
* `match_info`: A `RegExpMatchInfo` object containing:
    * `number_of_capture_registers_`: 4 (for the full match start/end and the capture group start/end).
    * The actual register values (indices into the input string): `[0, 1, 1, 2]` (meaning the full match is from index 0 to 1, and the first capture group is from index 1 to 2).
* `string`: The input string "abc".
* `last_index`: The current `lastIndex` of the `regexp`.

**Expected Output:**

A `JSRegExpResult` object (an array-like object) with the following properties:

* `[0]`: "a" (the full match substring)
* `[1]`: "b" (the first captured group substring)
* `index`: 0
* `input`: "abc"
* `groups`: `undefined` (since there are no named capture groups)

**Explanation of the logic in `ConstructNewResultFromMatchInfo` for this case:**

1. It reads the `number_of_capture_registers_` from `match_info` and calculates the number of results (2 in this case: the full match and one capture group).
2. It extracts the start and end indices of the full match (0 and 1) from `match_info`.
3. It calls a built-in substring function to extract "a" from the input string "abc".
4. It allocates a `JSRegExpResult` object with a length of 2.
5. It stores "a" at index 0 of the result object.
6. It iterates through the remaining capture groups.
7. For the first capture group, it extracts the start and end indices (1 and 2) from `match_info`.
8. It calls a built-in substring function to extract "b" from "abc".
9. It stores "b" at index 1 of the result object.
10. It sets the `index` and `input` properties of the result object.
11. Since there are no named capture groups, the `groups` property remains `undefined`.

**User-Common Programming Errors:**

This code relates to the *implementation* of regular expressions, not directly to user-level programming errors. However, understanding how V8 handles regular expressions can help developers avoid certain pitfalls:

1. **Incorrectly relying on `lastIndex` without the `/g` flag:**  If a regex doesn't have the global flag (`/g`), `lastIndex` will only change if explicitly set by the user. This can lead to unexpected behavior if a developer assumes it automatically advances.

   ```javascript
   const regex = /o/; // No 'g' flag
   const str = 'foo';

   console.log(regex.lastIndex); // 0
   regex.exec(str);
   console.log(regex.lastIndex); // 0 (unchanged)
   regex.exec(str);
   console.log(regex.lastIndex); // 0 (unchanged)
   ```

2. **Misunderstanding capture group indexing:** Developers might make mistakes in counting or accessing captured groups, especially with nested or optional groups. V8's implementation ensures that captured groups are stored in the correct order in the result array.

   ```javascript
   const regex = /a(b(c)?)/;
   const str = 'ab';
   const result = regex.exec(str);
   console.log(result); // Output: [ 'ab', 'bc', 'c', index: 0, input: 'ab', groups: undefined ]
   // Note the indexing of the capture groups.
   ```

3. **Performance issues with complex regular expressions:** While this C++ code focuses on the mechanics, developers should be aware that complex regular expressions can have significant performance implications. Understanding how the interpreter and the compiled code work (as hinted by the trampoline functions) can motivate developers to write more efficient regex patterns.

**Summary of Functionality (Part 1):**

In essence, this first part of `v8/src/builtins/builtins-regexp-gen.cc` lays the foundation for executing JavaScript regular expressions within V8. It provides the mechanisms for:

* **Entering the RegExp execution engine (interpreter or experimental).**
* **Allocating and initializing the result object returned by `exec()` and similar methods.**
* **Managing the `lastIndex` property of `RegExp` objects.**
* **Handling capture groups and storing their matched substrings.**

This code works at a very low level, directly interacting with V8's internal data structures and code generation capabilities to provide the core functionality of JavaScript's regular expressions.

Prompt: 
```
这是目录为v8/src/builtins/builtins-regexp-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-regexp-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-regexp-gen.h"

#include <optional>

#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/builtins-string-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/builtins/growable-fixed-array-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/common/globals.h"
#include "src/execution/protectors.h"
#include "src/heap/factory-inl.h"
#include "src/logging/counters.h"
#include "src/objects/js-regexp-string-iterator.h"
#include "src/objects/js-regexp.h"
#include "src/objects/regexp-match-info.h"
#include "src/regexp/regexp-flags.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

// Tail calls the regular expression interpreter.
// static
void Builtins::Generate_RegExpInterpreterTrampoline(MacroAssembler* masm) {
  ExternalReference interpreter_code_entry =
      ExternalReference::re_match_for_call_from_js();
  masm->Jump(interpreter_code_entry);
}

// Tail calls the experimental regular expression engine.
// static
void Builtins::Generate_RegExpExperimentalTrampoline(MacroAssembler* masm) {
  ExternalReference interpreter_code_entry =
      ExternalReference::re_experimental_match_for_call_from_js();
  masm->Jump(interpreter_code_entry);
}

TNode<Smi> RegExpBuiltinsAssembler::SmiZero() { return SmiConstant(0); }

TNode<IntPtrT> RegExpBuiltinsAssembler::IntPtrZero() {
  return IntPtrConstant(0);
}

// -----------------------------------------------------------------------------
// ES6 section 21.2 RegExp Objects

TNode<JSRegExpResult> RegExpBuiltinsAssembler::AllocateRegExpResult(
    TNode<Context> context, TNode<Smi> length, TNode<Smi> index,
    TNode<String> input, TNode<JSRegExp> regexp, TNode<Number> last_index,
    TNode<BoolT> has_indices, TNode<FixedArray>* elements_out) {
  CSA_DCHECK(this, SmiLessThanOrEqual(
                       length, SmiConstant(JSArray::kMaxFastArrayLength)));
  CSA_DCHECK(this, SmiGreaterThan(length, SmiConstant(0)));

  // Allocate.

  Label result_has_indices(this), allocated(this);
  const ElementsKind elements_kind = PACKED_ELEMENTS;
  std::optional<TNode<AllocationSite>> no_gc_site = std::nullopt;
  TNode<IntPtrT> length_intptr = PositiveSmiUntag(length);
  // Note: The returned `var_elements` may be in young large object space, but
  // `var_array` is guaranteed to be in new space so we could skip write
  // barriers below.
  TVARIABLE(JSArray, var_array);
  TVARIABLE(FixedArrayBase, var_elements);

  GotoIf(has_indices, &result_has_indices);
  {
    TNode<Map> map = CAST(LoadContextElement(LoadNativeContext(context),
                                             Context::REGEXP_RESULT_MAP_INDEX));
    std::tie(var_array, var_elements) =
        AllocateUninitializedJSArrayWithElements(
            elements_kind, map, length, no_gc_site, length_intptr,
            AllocationFlag::kNone, JSRegExpResult::kSize);
    Goto(&allocated);
  }

  BIND(&result_has_indices);
  {
    TNode<Map> map =
        CAST(LoadContextElement(LoadNativeContext(context),
                                Context::REGEXP_RESULT_WITH_INDICES_MAP_INDEX));
    std::tie(var_array, var_elements) =
        AllocateUninitializedJSArrayWithElements(
            elements_kind, map, length, no_gc_site, length_intptr,
            AllocationFlag::kNone, JSRegExpResultWithIndices::kSize);
    Goto(&allocated);
  }

  BIND(&allocated);

  // Finish result initialization.

  TNode<JSRegExpResult> result =
      UncheckedCast<JSRegExpResult>(var_array.value());

  // Load undefined value once here to avoid multiple LoadRoots.
  TNode<Oddball> undefined_value = UncheckedCast<Oddball>(
      CodeAssembler::LoadRoot(RootIndex::kUndefinedValue));

  StoreObjectFieldNoWriteBarrier(result, JSRegExpResult::kIndexOffset, index);
  // TODO(jgruber,turbofan): Could skip barrier but the MemoryOptimizer
  // complains.
  StoreObjectField(result, JSRegExpResult::kInputOffset, input);
  StoreObjectFieldNoWriteBarrier(result, JSRegExpResult::kGroupsOffset,
                                 undefined_value);
  StoreObjectFieldNoWriteBarrier(result, JSRegExpResult::kNamesOffset,
                                 undefined_value);

  StoreObjectField(result, JSRegExpResult::kRegexpInputOffset, input);

  // If non-smi last_index then store an SmiZero instead.
  {
    TNode<Smi> last_index_smi = Select<Smi>(
        TaggedIsSmi(last_index), [=, this] { return CAST(last_index); },
        [=, this] { return SmiZero(); });
    StoreObjectField(result, JSRegExpResult::kRegexpLastIndexOffset,
                     last_index_smi);
  }

  Label finish_initialization(this);
  GotoIfNot(has_indices, &finish_initialization);
  {
    static_assert(
        std::is_base_of<JSRegExpResult, JSRegExpResultWithIndices>::value,
        "JSRegExpResultWithIndices is a subclass of JSRegExpResult");
    StoreObjectFieldNoWriteBarrier(
        result, JSRegExpResultWithIndices::kIndicesOffset, undefined_value);
    Goto(&finish_initialization);
  }

  BIND(&finish_initialization);

  // Finish elements initialization.

  FillFixedArrayWithValue(elements_kind, var_elements.value(), IntPtrZero(),
                          length_intptr, RootIndex::kUndefinedValue);

  if (elements_out) *elements_out = CAST(var_elements.value());
  return result;
}

TNode<Object> RegExpBuiltinsAssembler::FastLoadLastIndexBeforeSmiCheck(
    TNode<JSRegExp> regexp) {
  // Load the in-object field.
  static const int field_offset =
      JSRegExp::kHeaderSize + JSRegExp::kLastIndexFieldIndex * kTaggedSize;
  return LoadObjectField(regexp, field_offset);
}

TNode<Object> RegExpBuiltinsAssembler::SlowLoadLastIndex(TNode<Context> context,
                                                         TNode<Object> regexp) {
  return GetProperty(context, regexp, isolate()->factory()->lastIndex_string());
}

// The fast-path of StoreLastIndex when regexp is guaranteed to be an unmodified
// JSRegExp instance.
void RegExpBuiltinsAssembler::FastStoreLastIndex(TNode<JSRegExp> regexp,
                                                 TNode<Smi> value) {
  // Store the in-object field.
  static const int field_offset =
      JSRegExp::kHeaderSize + JSRegExp::kLastIndexFieldIndex * kTaggedSize;
  StoreObjectField(regexp, field_offset, value);
}

void RegExpBuiltinsAssembler::SlowStoreLastIndex(TNode<Context> context,
                                                 TNode<Object> regexp,
                                                 TNode<Object> value) {
  TNode<String> name =
      HeapConstantNoHole(isolate()->factory()->lastIndex_string());
  SetPropertyStrict(context, regexp, name, value);
}

TNode<Smi> RegExpBuiltinsAssembler::LoadCaptureCount(TNode<RegExpData> data) {
  return Select<Smi>(
      SmiEqual(LoadObjectField<Smi>(data, RegExpData::kTypeTagOffset),
               SmiConstant(RegExpData::Type::ATOM)),
      [=, this] { return SmiConstant(JSRegExp::kAtomCaptureCount); },
      [=, this] {
        return LoadObjectField<Smi>(data, IrRegExpData::kCaptureCountOffset);
      });
}

TNode<Smi> RegExpBuiltinsAssembler::RegistersForCaptureCount(
    TNode<Smi> capture_count) {
  // See also: JSRegExp::RegistersForCaptureCount.
  static_assert(Internals::IsValidSmi((JSRegExp::kMaxCaptures + 1) * 2));
  return SmiShl(SmiAdd(capture_count, SmiConstant(1)), 1);
}

TNode<JSRegExpResult> RegExpBuiltinsAssembler::ConstructNewResultFromMatchInfo(
    TNode<Context> context, TNode<JSRegExp> regexp,
    TNode<RegExpMatchInfo> match_info, TNode<String> string,
    TNode<Number> last_index) {
  Label named_captures(this), maybe_build_indices(this), out(this);

  TNode<IntPtrT> num_indices = PositiveSmiUntag(CAST(LoadObjectField(
      match_info, offsetof(RegExpMatchInfo, number_of_capture_registers_))));
  TNode<Smi> num_results = SmiTag(WordShr(num_indices, 1));
  TNode<Smi> start = LoadArrayElement(match_info, IntPtrConstant(0));
  TNode<Smi> end = LoadArrayElement(match_info, IntPtrConstant(1));

  // Calculate the substring of the first match before creating the result array
  // to avoid an unnecessary write barrier storing the first result.

  TNode<String> first =
      CAST(CallBuiltin(Builtin::kSubString, context, string, start, end));

  // Load flags and check if the result object needs to have indices.
  const TNode<Smi> flags =
      CAST(LoadObjectField(regexp, JSRegExp::kFlagsOffset));
  const TNode<BoolT> has_indices = IsSetSmi(flags, JSRegExp::kHasIndices);
  TNode<FixedArray> result_elements;
  TNode<JSRegExpResult> result =
      AllocateRegExpResult(context, num_results, start, string, regexp,
                           last_index, has_indices, &result_elements);

  UnsafeStoreFixedArrayElement(result_elements, 0, first);

  // If no captures exist we can skip named capture handling as well.
  GotoIf(SmiEqual(num_results, SmiConstant(1)), &maybe_build_indices);

  // Store all remaining captures.
  TNode<IntPtrT> limit = num_indices;

  TVARIABLE(IntPtrT, var_from_cursor, IntPtrConstant(2));
  TVARIABLE(IntPtrT, var_to_cursor, IntPtrConstant(1));

  Label loop(this, {&var_from_cursor, &var_to_cursor});

  Goto(&loop);
  BIND(&loop);
  {
    TNode<IntPtrT> from_cursor = var_from_cursor.value();
    TNode<IntPtrT> to_cursor = var_to_cursor.value();
    TNode<Smi> start_cursor = LoadArrayElement(match_info, from_cursor);

    Label next_iter(this);
    GotoIf(SmiEqual(start_cursor, SmiConstant(-1)), &next_iter);

    TNode<IntPtrT> from_cursor_plus1 =
        IntPtrAdd(from_cursor, IntPtrConstant(1));
    TNode<Smi> end_cursor = LoadArrayElement(match_info, from_cursor_plus1);

    TNode<String> capture = CAST(CallBuiltin(Builtin::kSubString, context,
                                             string, start_cursor, end_cursor));
    UnsafeStoreFixedArrayElement(result_elements, to_cursor, capture);
    Goto(&next_iter);

    BIND(&next_iter);
    var_from_cursor = IntPtrAdd(from_cursor, IntPtrConstant(2));
    var_to_cursor = IntPtrAdd(to_cursor, IntPtrConstant(1));
    Branch(UintPtrLessThan(var_from_cursor.value(), limit), &loop,
           &named_captures);
  }

  BIND(&named_captures);
  {
    CSA_DCHECK(this, SmiGreaterThan(num_results, SmiConstant(1)));

    // Preparations for named capture properties. Exit early if the result does
    // not have any named captures to minimize performance impact.

    TNode<RegExpData> data = CAST(LoadTrustedPointerFromObject(
        regexp, JSRegExp::kDataOffset, kRegExpDataIndirectPointerTag));

    // We reach this point only if captures exist, implying that the assigned
    // regexp engine must be able to handle captures.
    CSA_SBXCHECK(this, HasInstanceType(data, IR_REG_EXP_DATA_TYPE));

    // The names fixed array associates names at even indices with a capture
    // index at odd indices.
    TNode<Object> maybe_names =
        LoadObjectField(data, IrRegExpData::kCaptureNameMapOffset);
    GotoIf(TaggedEqual(maybe_names, SmiZero()), &maybe_build_indices);

    // One or more named captures exist, add a property for each one.

    TNode<FixedArray> names = CAST(maybe_names);
    TNode<IntPtrT> names_length = LoadAndUntagFixedArrayBaseLength(names);
    CSA_DCHECK(this, IntPtrGreaterThan(names_length, IntPtrZero()));

    // Stash names in case we need them to build the indices array later.
    StoreObjectField(result, JSRegExpResult::kNamesOffset, names);

    // Allocate a new object to store the named capture properties.
    // TODO(jgruber): Could be optimized by adding the object map to the heap
    // root list.

    TNode<IntPtrT> num_properties = WordSar(names_length, 1);
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> map = LoadSlowObjectWithNullPrototypeMap(native_context);
    TNode<HeapObject> properties;
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      properties = AllocateSwissNameDictionary(num_properties);
    } else {
      properties = AllocateNameDictionary(num_properties);
    }

    TNode<JSObject> group_object = AllocateJSObjectFromMap(map, properties);
    StoreObjectField(result, JSRegExpResult::kGroupsOffset, group_object);

    TVARIABLE(IntPtrT, var_i, IntPtrZero());

    Label inner_loop(this, &var_i);

    Goto(&inner_loop);
    BIND(&inner_loop);
    {
      TNode<IntPtrT> i = var_i.value();
      TNode<IntPtrT> i_plus_1 = IntPtrAdd(i, IntPtrConstant(1));
      TNode<IntPtrT> i_plus_2 = IntPtrAdd(i_plus_1, IntPtrConstant(1));

      TNode<String> name = CAST(LoadFixedArrayElement(names, i));
      TNode<Smi> index = CAST(LoadFixedArrayElement(names, i_plus_1));
      TNode<HeapObject> capture =
          CAST(LoadFixedArrayElement(result_elements, SmiUntag(index)));

      // TODO(v8:8213): For maintainability, we should call a CSA/Torque
      // implementation of CreateDataProperty instead.

      // At this point the spec says to call CreateDataProperty. However, we can
      // skip most of the steps and go straight to adding/updating a dictionary
      // entry because we know a bunch of useful facts:
      // - All keys are non-numeric internalized strings
      // - Receiver has no prototype
      // - Receiver isn't used as a prototype
      // - Receiver isn't any special object like a Promise intrinsic object
      // - Receiver is extensible
      // - Receiver has no interceptors
      Label add_dictionary_property_slow(this, Label::kDeferred);
      TVARIABLE(IntPtrT, var_name_index);
      Label add_name_entry(this, &var_name_index),
          duplicate_name(this, &var_name_index), next(this);
      NameDictionaryLookup<PropertyDictionary>(
          CAST(properties), name, &duplicate_name, &var_name_index,
          &add_name_entry, kFindExistingOrInsertionIndex);
      BIND(&duplicate_name);
      GotoIf(IsUndefined(capture), &next);
      CSA_DCHECK(this,
                 TaggedEqual(LoadValueByKeyIndex<PropertyDictionary>(
                                 CAST(properties), var_name_index.value()),
                             UndefinedConstant()));
      StoreValueByKeyIndex<PropertyDictionary>(CAST(properties),
                                               var_name_index.value(), capture);
      Goto(&next);

      BIND(&add_name_entry);
      AddToDictionary<PropertyDictionary>(CAST(properties), name, capture,
                                          &add_dictionary_property_slow,
                                          var_name_index.value());
      Goto(&next);

      BIND(&next);
      var_i = i_plus_2;
      Branch(IntPtrGreaterThanOrEqual(var_i.value(), names_length),
             &maybe_build_indices, &inner_loop);

      BIND(&add_dictionary_property_slow);
      // If the dictionary needs resizing, the above Add call will jump here
      // before making any changes. This shouldn't happen because we allocated
      // the dictionary with enough space above.
      Unreachable();
    }
  }

  // Build indices if needed (i.e. if the /d flag is present) after named
  // capture groups are processed.
  BIND(&maybe_build_indices);
  GotoIfNot(has_indices, &out);
  {
    const TNode<Object> maybe_names =
        LoadObjectField(result, JSRegExpResultWithIndices::kNamesOffset);
    const TNode<JSRegExpResultIndices> indices =
        UncheckedCast<JSRegExpResultIndices>(
            CallRuntime(Runtime::kRegExpBuildIndices, context, regexp,
                        match_info, maybe_names));
    StoreObjectField(result, JSRegExpResultWithIndices::kIndicesOffset,
                     indices);
    Goto(&out);
  }

  BIND(&out);
  return result;
}

void RegExpBuiltinsAssembler::GetStringPointers(
    TNode<RawPtrT> string_data, TNode<IntPtrT> offset,
    TNode<IntPtrT> last_index, TNode<IntPtrT> string_length,
    String::Encoding encoding, TVariable<RawPtrT>* var_string_start,
    TVariable<RawPtrT>* var_string_end) {
  DCHECK_EQ(var_string_start->rep(), MachineType::PointerRepresentation());
  DCHECK_EQ(var_string_end->rep(), MachineType::PointerRepresentation());

  const ElementsKind kind = (encoding == String::ONE_BYTE_ENCODING)
                                ? UINT8_ELEMENTS
                                : UINT16_ELEMENTS;

  TNode<IntPtrT> from_offset =
      ElementOffsetFromIndex(IntPtrAdd(offset, last_index), kind);
  *var_string_start =
      ReinterpretCast<RawPtrT>(IntPtrAdd(string_data, from_offset));

  TNode<IntPtrT> to_offset =
      ElementOffsetFromIndex(IntPtrAdd(offset, string_length), kind);
  *var_string_end = ReinterpretCast<RawPtrT>(IntPtrAdd(string_data, to_offset));
}

std::pair<TNode<RawPtrT>, TNode<BoolT>>
RegExpBuiltinsAssembler::LoadOrAllocateRegExpResultVector(
    TNode<Smi> register_count) {
  Label if_dynamic(this), out(this);
  TVARIABLE(BoolT, var_is_dynamic, Int32FalseConstant());
  TVARIABLE(RawPtrT, var_vector, UncheckedCast<RawPtrT>(IntPtrConstant(0)));

  // Too large?
  GotoIf(SmiAbove(register_count,
                  SmiConstant(Isolate::kJSRegexpStaticOffsetsVectorSize)),
         &if_dynamic);

  auto address_of_regexp_static_result_offsets_vector = ExternalConstant(
      ExternalReference::address_of_regexp_static_result_offsets_vector(
          isolate()));
  var_vector = UncheckedCast<RawPtrT>(Load(
      MachineType::Pointer(), address_of_regexp_static_result_offsets_vector));

  // Owned by someone else?
  GotoIf(WordEqual(var_vector.value(), IntPtrConstant(0)), &if_dynamic);

  // Take ownership of the static vector. See also:
  // RegExpResultVectorScope::Initialize.
  StoreNoWriteBarrier(MachineType::PointerRepresentation(),
                      address_of_regexp_static_result_offsets_vector,
                      IntPtrConstant(0));
  Goto(&out);

  BIND(&if_dynamic);
  var_is_dynamic = Int32TrueConstant();
  var_vector = UncheckedCast<RawPtrT>(CallCFunction(
      ExternalConstant(ExternalReference::allocate_regexp_result_vector()),
      MachineType::Pointer(),
      std::make_pair(MachineType::Uint32(), SmiToInt32(register_count))));
  Goto(&out);

  BIND(&out);
  return {var_vector.value(), var_is_dynamic.value()};
}

void RegExpBuiltinsAssembler::FreeRegExpResultVector(
    TNode<RawPtrT> result_vector, TNode<BoolT> is_dynamic) {
  Label if_dynamic(this), out(this);

  GotoIf(is_dynamic, &if_dynamic);

  // Was there a vector allocated?
  GotoIf(WordEqual(result_vector, IntPtrConstant(0)), &out);

  // Return ownership of the static vector.
  auto address_of_regexp_static_result_offsets_vector = ExternalConstant(
      ExternalReference::address_of_regexp_static_result_offsets_vector(
          isolate()));
  CSA_DCHECK(
      this, WordEqual(UncheckedCast<RawPtrT>(
                          Load(MachineType::Pointer(),
                               address_of_regexp_static_result_offsets_vector)),
                      IntPtrConstant(0)));
  StoreNoWriteBarrier(MachineType::PointerRepresentation(),
                      address_of_regexp_static_result_offsets_vector,
                      result_vector);
  Goto(&out);

  BIND(&if_dynamic);
  CallCFunction(
      ExternalConstant(ExternalReference::free_regexp_result_vector()),
      MachineType::Pointer() /* void */,
      std::make_pair(MachineType::Pointer(), result_vector));
  Goto(&out);

  BIND(&out);
}

namespace {

static constexpr int kInt32SizeLog2 = 2;
static_assert(kInt32Size == 1 << kInt32SizeLog2);

}  // namespace

TNode<RegExpMatchInfo>
RegExpBuiltinsAssembler::InitializeMatchInfoFromRegisters(
    TNode<Context> context, TNode<RegExpMatchInfo> match_info,
    TNode<Smi> register_count, TNode<String> subject,
    TNode<RawPtrT> result_offsets_vector) {
  TVARIABLE(RegExpMatchInfo, var_match_info, match_info);

  // Check that the last match info has space for the capture registers.
  {
    Label next(this);
    TNode<Smi> available_slots = LoadSmiArrayLength(var_match_info.value());
    GotoIf(SmiLessThanOrEqual(register_count, available_slots), &next);

    // Grow.
    var_match_info =
        CAST(CallRuntime(Runtime::kRegExpGrowRegExpMatchInfo, context,
                         var_match_info.value(), register_count));
    Goto(&next);

    BIND(&next);
  }

  // Fill match_info.
  StoreObjectField(var_match_info.value(),
                   offsetof(RegExpMatchInfo, number_of_capture_registers_),
                   register_count);
  StoreObjectField(var_match_info.value(),
                   offsetof(RegExpMatchInfo, last_subject_), subject);
  StoreObjectField(var_match_info.value(),
                   offsetof(RegExpMatchInfo, last_input_), subject);

  // Fill match and capture offsets in match_info. They are located in the
  // region:
  //
  //   result_offsets_vector + 0
  //   ...
  //   result_offsets_vector + register_count * kInt32Size.
  {
    // The offset within result_offsets_vector.
    TNode<IntPtrT> loop_start = UncheckedCast<IntPtrT>(result_offsets_vector);
    TNode<IntPtrT> loop_end =
        IntPtrAdd(loop_start, SmiUntag(SmiShl(register_count, kInt32SizeLog2)));
    // The offset within RegExpMatchInfo.
    TNode<IntPtrT> to_offset =
        OffsetOfElementAt<RegExpMatchInfo>(SmiConstant(0));
    TVARIABLE(IntPtrT, var_to_offset, to_offset);

    VariableList vars({&var_to_offset}, zone());
    BuildFastLoop<IntPtrT>(
        vars, loop_start, loop_end,
        [&](TNode<IntPtrT> current_register_address) {
          TNode<Int32T> value = UncheckedCast<Int32T>(
              Load(MachineType::Int32(), current_register_address));
          TNode<Smi> smi_value = SmiFromInt32(value);
          StoreNoWriteBarrier(MachineRepresentation::kTagged,
                              var_match_info.value(), var_to_offset.value(),
                              smi_value);
          Increment(&var_to_offset, kTaggedSize);
        },
        kInt32Size, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
  }

  return var_match_info.value();
}

TNode<HeapObject> RegExpBuiltinsAssembler::RegExpExecInternal_Single(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> string,
    TNode<Number> last_index) {
  Label out(this);
  TVARIABLE(HeapObject, var_result, NullConstant());
  TNode<RegExpData> data = CAST(LoadTrustedPointerFromObject(
      regexp, JSRegExp::kDataOffset, kRegExpDataIndirectPointerTag));
  TNode<Smi> register_count_per_match =
      RegistersForCaptureCount(LoadCaptureCount(data));
  // Allocate space for one match.
  TNode<Smi> result_offsets_vector_length = register_count_per_match;
  TNode<RawPtrT> result_offsets_vector;
  TNode<BoolT> result_offsets_vector_is_dynamic;
  std::tie(result_offsets_vector, result_offsets_vector_is_dynamic) =
      LoadOrAllocateRegExpResultVector(result_offsets_vector_length);

  // Exception handling is necessary to free any allocated memory.
  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred);

  {
    compiler::ScopedExceptionHandler handler(this, &if_exception,
                                             &var_exception);

    TNode<UintPtrT> num_matches = RegExpExecInternal(
        context, regexp, string, last_index, result_offsets_vector,
        SmiToInt32(result_offsets_vector_length));

    GotoIf(IntPtrEqual(num_matches, IntPtrConstant(0)), &out);

    CSA_DCHECK(this, IntPtrEqual(num_matches, IntPtrConstant(1)));
    CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
    TNode<RegExpMatchInfo> last_match_info = CAST(
        LoadContextElement(context, Context::REGEXP_LAST_MATCH_INFO_INDEX));
    var_result = InitializeMatchInfoFromRegisters(
        context, last_match_info, register_count_per_match, string,
        result_offsets_vector);
    Goto(&out);
  }

  BIND(&if_exception);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  CallRuntime(Runtime::kReThrow, context, var_exception.value());
  Unreachable();

  BIND(&out);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  return var_result.value();  // RegExpMatchInfo | Null.
}

TNode<UintPtrT> RegExpBuiltinsAssembler::RegExpExecInternal(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> string,
    TNode<Number> last_index, TNode<RawPtrT> result_offsets_vector,
    TNode<Int32T> result_offsets_vector_length) {
  ToDirectStringAssembler to_direct(state(), string);

  TVARIABLE(UintPtrT, var_result, UintPtrConstant(0));
  Label out(this), atom(this), runtime(this, Label::kDeferred),
      retry_experimental(this, Label::kDeferred);

  // External constants.
  TNode<ExternalReference> isolate_address =
      ExternalConstant(ExternalReference::isolate_address());

  // At this point, last_index is definitely a canonicalized non-negative
  // number, which implies that any non-Smi last_index is greater than
  // the maximal string length. If lastIndex > string.length then the matcher
  // must fail.

  CSA_DCHECK(this, IsNumberNormalized(last_index));
  CSA_DCHECK(this, IsNumberPositive(last_index));
  GotoIf(TaggedIsNotSmi(last_index), &out);

  TNode<IntPtrT> int_string_length = LoadStringLengthAsWord(string);
  TNode<IntPtrT> int_last_index = PositiveSmiUntag(CAST(last_index));

  GotoIf(UintPtrGreaterThan(int_last_index, int_string_length), &out);

  // Unpack the string. Note that due to SlicedString unpacking (which extracts
  // the parent string and offset), it's not valid to replace `string` with the
  // result of ToDirect here. Instead, we rely on in-place flattening done by
  // String::Flatten.
  // TODO(jgruber): Consider changing ToDirectStringAssembler behavior here
  // since this aspect is surprising. The result of `ToDirect` could always
  // equal the input in length and contents. SlicedString unpacking could
  // happen in `TryToSequential`.
  to_direct.ToDirect();

  // Since the RegExp has been compiled, data contains a RegExpData object.
  TNode<RegExpData> data = CAST(LoadTrustedPointerFromObject(
      regexp, JSRegExp::kDataOffset, kRegExpDataIndirectPointerTag));

  // Dispatch on the type of the RegExp.
  // Since the type tag is in trusted space, it is safe to interpret
  // RegExpData as IrRegExpData/AtomRegExpData in the respective branches
  // without checks.
  {
    Label next(this), unreachable(this, Label::kDeferred);
    TNode<Int32T> tag =
        SmiToInt32(LoadObjectField<Smi>(data, RegExpData::kTypeTagOffset));

    int32_t values[] = {
        static_cast<uint8_t>(RegExpData::Type::IRREGEXP),
        static_cast<uint8_t>(RegExpData::Type::ATOM),
        static_cast<uint8_t>(RegExpData::Type::EXPERIMENTAL),
    };
    Label* labels[] = {&next, &atom, &next};

    static_assert(arraysize(values) == arraysize(labels));
    Switch(tag, &unreachable, values, labels, arraysize(values));

    BIND(&unreachable);
    Unreachable();

    BIND(&next);
  }

  // Check (number_of_captures + 1) * 2 <= offsets vector size.
  CSA_DCHECK(
      this, SmiLessThanOrEqual(RegistersForCaptureCount(LoadCaptureCount(data)),
                               SmiFromInt32(result_offsets_vector_length)));

  // Load the irregexp code or bytecode object and offsets into the subject
  // string. Both depend on whether the string is one- or two-byte.

  TVARIABLE(RawPtrT, var_string_start);
  TVARIABLE(RawPtrT, var_string_end);
#ifdef V8_ENABLE_SANDBOX
  using kVarCodeT = IndirectPointerHandleT;
#else
  using kVarCodeT = Object;
#endif
  TVARIABLE(kVarCodeT, var_code);
  TVARIABLE(Object, var_bytecode);

  {
    TNode<RawPtrT> direct_string_data = to_direct.PointerToData(&runtime);

    Label next(this), if_isonebyte(this), if_istwobyte(this, Label::kDeferred);
    Branch(to_direct.IsOneByte(), &if_isonebyte, &if_istwobyte);

    BIND(&if_isonebyte);
    {
      GetStringPointers(direct_string_data, to_direct.offset(), int_last_index,
                        int_string_length, String::ONE_BYTE_ENCODING,
                        &var_string_start, &var_string_end);
      var_code =
          LoadObjectField<kVarCodeT>(data, IrRegExpData::kLatin1CodeOffset);
      var_bytecode = LoadObjectField(data, IrRegExpData::kLatin1BytecodeOffset);
      Goto(&next);
    }

    BIND(&if_istwobyte);
    {
      GetStringPointers(direct_string_data, to_direct.offset(), int_last_index,
                        int_string_length, String::TWO_BYTE_ENCODING,
                        &var_string_start, &var_string_end);
      var_code =
          LoadObjectField<kVarCodeT>(data, IrRegExpData::kUc16CodeOffset);
      var_bytecode = LoadObjectField(data, IrRegExpData::kUc16BytecodeOffset);
      Goto(&next);
    }

    BIND(&next);
  }

  // Check that the irregexp code has been generated for the actual string
  // encoding.

#ifdef V8_ENABLE_SANDBOX
  GotoIf(
      Word32Equal(var_code.value(), Int32Constant(kNullIndirectPointerHandle)),
      &runtime);
#else
  GotoIf(TaggedIsSmi(var_code.value()), &runtime);
#endif

  Label if_exception(this, Label::kDeferred);

  {
    IncrementCounter(isolate()->counters()->regexp_entry_native(), 1);

    // Set up args for the final call into generated Irregexp code.

    MachineType type_int32 = MachineType::Int32();
    MachineType type_tagged = MachineType::AnyTagged();
    MachineType type_ptr = MachineType::Pointer();

    // Result: A NativeRegExpMacroAssembler::Result return code.
    MachineType retval_type = type_int32;

    // Argument 0: Original subject string.
    MachineType arg0_type = type_tagged;
    TNode<String> arg0 = string;

    // Argument 1: Previous index.
    MachineType arg1_type = type_int32;
    TNode<Int32T> arg1 = TruncateIntPtrToInt32(int_last_index);

    // Argument 2: Start of string data. This argument is ignored in the
    // interpreter.
    MachineType arg2_type = type_ptr;
    TNode<RawPtrT> arg2 = var_string_start.value();

    // Argument 3: End of string data. This argument is ignored in the
    // interpreter.
    MachineType arg3_type = type_ptr;
    TNode<RawPtrT> arg3 = var_string_end.value();

    // Argument 4: result offsets vector.
    MachineType arg4_type = type_ptr;
    TNode<RawPtrT> arg4 = result_offsets_vector;

    // Argument 5: Number of capture registers.
    MachineType arg5_type = type_int32;
    TNode<Int32T> arg5 = result_offsets_vector_length;

    // Argument 6: Indicate that this is a direct call from JavaScript.
    MachineType arg6_type = type_int32;
    TNode<Int32T> arg6 = Int32Constant(RegExp::CallOrigin::kFromJs);

    // Argument 7: Pass current isolate address.
    MachineType arg7_type = type_ptr;
    TNode<ExternalReference> arg7 = isolate_address;

    // Argument 8: Regular expression data object. This argument is ignored in
    // native irregexp code.
    MachineType arg8_type = type_tagged;
    TNode<IrRegExpData> arg8 = CAST(data);

#ifdef V8_ENABLE_SANDBOX
    TNode<RawPtrT> code_entry = LoadCodeEntryFromIndirectPointerHandle(
        var_code.value(), kRegExpEntrypointTag);
#else
    TNode<Code> code = CAST(var_code.value());
    TNode<RawPtrT> code_entry =
        LoadCodeInstructionStart(code, kRegExpEntrypointTag);
#endif

    // AIX uses function descriptors on CFunction calls. code_entry in this case
    // may also point to a Regex interpreter entry trampoline which does not
    // have a function descriptor. This method is ineffective on other platforms
    // and is equivalent to CallCFunction.
    TNode<Int32T> result =
        UncheckedCast<Int32T>(CallCFunctionWithoutFunctionDescriptor(
            code_entry, retval_type, std::make_pair(arg0_type, arg0),
            std::make_pair(arg1_type, arg1), std::make_pair(arg2_type, arg2),
            std::make_pair(arg3_type, arg3), std::make_pair(arg4_type, arg4),
            std::make_pair(arg5_type, arg5), std::make_pair(arg6_type, arg6),
            std::make_pair(arg7_type, arg7), std::make_pair(arg8_type, arg8)));

    // Check the result.
    TNode<IntPtrT> int_result = ChangeInt32ToIntPtr(result);
    var_result = UncheckedCast<UintPtrT>(int_result);
    static_assert(RegExp::kInternalRegExpSuccess == 1);
    static_assert(RegExp::kInternalRegExpFailure == 0);
    GotoIf(IntPtrGreaterThanOrEqual(
               int_result, IntPtrConstant(RegExp::kInternalRegExpFailure)),
           &out);
    GotoIf(IntPtrEqual(int_result,
                       IntPtrConstant(RegExp::kInternalRegExpException)),
           &if_exception);
    GotoIf(IntPtrEqual(
               int_result,
               IntPtrConstant(RegExp::kInternalRegExpFallbackToExperimental)),
           &retry_experimental);

    CSA_DCHECK(this, IntPtrEqual(int_result,
                                 IntPt
"""


```