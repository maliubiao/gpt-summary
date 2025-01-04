Response: Let's break down the thought process for analyzing this C++ code and explaining its function and relation to JavaScript.

1. **Identify the Core Purpose:** The file name `regexp-macro-assembler.cc` immediately suggests its involvement in regular expression processing at a low level. The "macro assembler" part hints at code generation.

2. **Scan for Key Classes and Namespaces:** The code starts with includes and namespaces. `v8::internal` and `RegExpMacroAssembler` are prominent. This reinforces the idea that it's an internal V8 component related to regexps.

3. **Look for Core Functionality Indicators:**
    * **Constructor:** The `RegExpMacroAssembler` constructor takes an `Isolate` and `Zone`. `Isolate` is a fundamental V8 concept, representing an isolated JavaScript execution environment. `Zone` suggests memory management within that isolate.
    * **`CaseInsensitiveCompare*` functions:** These clearly deal with case-insensitive string comparisons, a common regexp operation. The presence of both `NonUnicode` and `Unicode` variants suggests handling different character sets.
    * **`IsCharacterInRangeArray`:** This function suggests efficient checking if a character belongs to a predefined set of ranges, another frequent regexp task.
    * **`LoadCurrentCharacter` and `CheckPosition`:**  These point to the mechanics of iterating through the input string during matching.
    * **`Match` and `Execute`:** These are the most likely entry points for actually performing regular expression matching. The arguments (`subject`, `offsets_vector`, etc.) strongly indicate a matching process.
    * **`GrowStack`:** This function suggests a stack used for backtracking in regexp matching, a common technique.
    * **`word_character_map`:** This constant array likely defines what constitutes a "word character" for `\w` and `\W` in regexps.

4. **Analyze Specific Code Blocks:**
    * **Case-Insensitive Comparisons:** Notice the use of `#ifdef V8_INTL_SUPPORT`. This indicates that V8 has different implementations depending on whether internationalization support is enabled. The code uses ICU (International Components for Unicode) when available. Without ICU, it has a simpler, likely less comprehensive, implementation.
    * **Range Array Caching:** The `GetOrAddRangeArray` function and the `range_array_cache_` member suggest an optimization: pre-computing and caching arrays representing character ranges for faster lookup. The `Hash` and `Equals` functions support this caching mechanism.
    * **Stack Guard:** The `CheckStackGuardState` function deals with stack overflow protection and interruption handling during regexp execution, crucial for preventing crashes and allowing for interrupts.

5. **Connect to JavaScript:**  The crucial connection lies in the purpose of V8 itself: executing JavaScript. Regular expressions are a core part of JavaScript. Therefore, this C++ code *must* be involved in implementing JavaScript's regular expression functionality.

6. **Formulate the Explanation:**  Based on the above analysis, construct a concise summary of the file's function: it's a low-level component within V8 responsible for the core logic of regular expression matching. It handles character comparisons, range lookups, backtracking, and interacts with the V8 isolate for memory management and stack handling.

7. **Create JavaScript Examples:** To illustrate the connection, think of common JavaScript regexp features that would rely on the functionality seen in the C++ code:
    * **Basic Matching:**  A simple `string.match(/pattern/)` demonstrates the core matching functionality.
    * **Case-Insensitive Matching:**  The `/pattern/i` flag directly relates to the `CaseInsensitiveCompare*` functions.
    * **Character Classes:**  Examples like `/[a-z0-9]/` or `/\w/` showcase the need for range checking and the `word_character_map`.
    * **Global Matching:** The `/pattern/g` flag connects to the `global_mode_` member.

8. **Refine and Organize:** Structure the explanation logically, starting with a general summary and then elaborating on specific features. Use clear language and avoid overly technical jargon where possible. Ensure the JavaScript examples are simple and directly illustrate the concepts. Emphasize the performance-critical nature of this code within the JavaScript engine.

Self-Correction/Refinement during the process:

* **Initial thought:** "It's just about compiling regexps."  **Correction:**  It's more than just compilation. It's about the *execution* of the compiled regexp code, as seen in the `Match` and `Execute` functions.
* **Overlooking details:**  Initially focusing only on the most obvious functions. **Refinement:**  Pay attention to smaller helper functions and data structures like the range array cache, as they reveal important implementation details and optimizations.
* **Vague JavaScript connection:**  Simply stating "it's used by JavaScript regexps." **Refinement:** Provide specific JavaScript examples to make the connection concrete and understandable.

By following this systematic approach, we can effectively analyze the C++ code and explain its role in the broader context of JavaScript execution.
这个C++源代码文件 `v8/src/regexp/regexp-macro-assembler.cc` 是 **V8 JavaScript 引擎** 中负责 **正则表达式匹配** 的一个核心组件。它的主要功能是提供一个 **宏汇编器** 的接口，用于生成和执行高效的机器码来实现正则表达式的匹配逻辑。

更具体地说，它的功能可以归纳为以下几点：

1. **提供抽象接口:**  `RegExpMacroAssembler` 类定义了一系列方法，这些方法抽象了不同处理器架构（如 x64、ARM 等）的底层指令，使得上层正则表达式编译器（如 Irregexp）可以生成与平台无关的中间表示，然后由 `RegExpMacroAssembler` 将其转化为特定平台的机器码。

2. **生成机器码:**  该文件中的类及其子类（如 `NativeRegExpMacroAssembler`）实现了这些抽象方法，负责生成实际的机器指令。这些指令直接操作寄存器、内存，用于快速地进行字符比较、状态转移、回溯等正则表达式匹配的核心操作。

3. **处理不同字符编码:**  代码中包含处理 Unicode 和非 Unicode 字符串的逻辑，例如 `CaseInsensitiveCompareNonUnicode` 和 `CaseInsensitiveCompareUnicode` 函数，用于进行大小写不敏感的比较。这反映了 JavaScript 正则表达式需要支持多种字符编码。

4. **优化匹配过程:**  代码中包含一些优化策略，例如：
    * **范围缓存 (`range_array_cache_`)**:  缓存字符范围，加速字符是否属于某个字符集的判断。
    * **栈管理 (`GrowStack`)**:  管理正则表达式匹配的回溯栈，当栈空间不足时进行扩展。
    * **特殊情况处理 (`special-case.h`)**:  可能包含对一些特殊正则表达式模式的优化处理。

5. **与 V8 引擎集成:**  该文件中的代码与 V8 引擎的其他组件紧密集成，例如：
    * **`Isolate`**:  用于访问 V8 引擎的隔离环境和堆。
    * **`Zone`**:  用于内存管理。
    * **`RegExpStack`**:  用于管理正则表达式匹配的回溯栈。
    * **`InstructionStream`**:  表示生成的机器码指令流。

**它与 JavaScript 的功能有密切关系。**  JavaScript 中的正则表达式功能，最终都是由 V8 引擎的底层实现来支撑的。`regexp-macro-assembler.cc` 生成的机器码，就是用来执行 JavaScript 正则表达式匹配的核心逻辑。

**JavaScript 举例说明:**

假设我们在 JavaScript 中执行以下正则表达式匹配：

```javascript
const str = "Hello World";
const regex = /o W/i; // 匹配 "o W"，忽略大小写
const result = str.match(regex);
console.log(result); // 输出: ["o W"]
```

当执行这段 JavaScript 代码时，V8 引擎会进行以下步骤（简化）：

1. **解析正则表达式:** V8 会解析 `/o W/i` 这个正则表达式。
2. **编译正则表达式:** V8 的正则表达式编译器（如 Irregexp）会根据解析结果生成一个中间表示，描述了匹配 "o W" 的状态转移和操作。
3. **生成机器码:**  `RegExpMacroAssembler` 会接收这个中间表示，并根据当前运行的 CPU 架构，生成对应的机器指令。例如，对于大小写不敏感的匹配，可能会调用类似于 `CaseInsensitiveCompareUnicode` 的底层函数生成的机器码。
4. **执行机器码:**  V8 会执行生成的机器码，在字符串 "Hello World" 中查找匹配项。这些机器指令会逐个比较字符，进行状态转移，直到找到匹配项 "o W"。
5. **返回结果:**  匹配成功后，V8 将匹配结果封装成 JavaScript 的数组返回给 JavaScript 代码。

**更具体的 JavaScript 例子，展示 `RegExpMacroAssembler` 中可能涉及的功能：**

* **大小写不敏感匹配:**

```javascript
const str = "hello world";
const regex = /HELLO/i; // 使用 'i' 标志进行大小写不敏感匹配
const result = str.test(regex); // true
```

  在这个例子中，`RegExpMacroAssembler` 会使用其内部的 case-insensitive 比较逻辑（可能通过调用 `CaseInsensitiveCompareUnicode` 或 `CaseInsensitiveCompareNonUnicode` 生成的机器码）来判断 "h" 和 "H" 是匹配的。

* **字符类匹配:**

```javascript
const str = "a1b";
const regex = /[a-z0-9]/; // 匹配字母或数字
const result1 = str.match(regex); // ["a"]
const result2 = str.match(/[0-9]/); // ["1"]
```

  当匹配 `/[a-z0-9]/` 时，`RegExpMacroAssembler` 可能会使用预先计算好的字符范围数据结构（例如通过 `GetOrAddRangeArray` 生成）来快速判断字符 'a' 是否属于 'a' 到 'z' 或 '0' 到 '9' 的范围。

* **边界匹配:**

```javascript
const str = "world";
const regex = /^w/; // 匹配以 'w' 开头的字符串
const result = str.test(regex); // true
```

  `RegExpMacroAssembler` 会生成机器码来检查当前匹配的位置是否是字符串的开头。

* **回溯:**

```javascript
const str = "abbc";
const regex = /ab*c/; // 匹配 'a' 后面跟着 0 个或多个 'b'，然后是 'c'
const result = str.test(regex); // true
```

  当匹配 `ab*c` 时，如果初始匹配了 "abb"，但后面的字符不是 "c"，`RegExpMacroAssembler` 生成的机器码会进行回溯，尝试匹配更少的 "b"。

总而言之，`v8/src/regexp/regexp-macro-assembler.cc` 是 V8 引擎中一个至关重要的底层组件，它负责将正则表达式的抽象匹配逻辑转化为高效的机器码，直接驱动着 JavaScript 中正则表达式功能的执行效率。理解这个文件的内容，可以更深入地了解 JavaScript 正则表达式的底层实现原理。

Prompt: 
```
这是目录为v8/src/regexp/regexp-macro-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/regexp/regexp-macro-assembler.h"

#include "src/codegen/assembler.h"
#include "src/codegen/label.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/pointer-authentication.h"
#include "src/execution/simulator.h"
#include "src/regexp/regexp-stack.h"
#include "src/regexp/special-case.h"
#include "src/strings/unicode-inl.h"

#ifdef V8_INTL_SUPPORT
#include "unicode/uchar.h"
#include "unicode/unistr.h"
#endif  // V8_INTL_SUPPORT

namespace v8 {
namespace internal {

RegExpMacroAssembler::RegExpMacroAssembler(Isolate* isolate, Zone* zone)
    : slow_safe_compiler_(false),
      backtrack_limit_(JSRegExp::kNoBacktrackLimit),
      global_mode_(NOT_GLOBAL),
      isolate_(isolate),
      zone_(zone) {}

bool RegExpMacroAssembler::has_backtrack_limit() const {
  return backtrack_limit_ != JSRegExp::kNoBacktrackLimit;
}

// static
int RegExpMacroAssembler::CaseInsensitiveCompareNonUnicode(Address byte_offset1,
                                                           Address byte_offset2,
                                                           size_t byte_length,
                                                           Isolate* isolate) {
#ifdef V8_INTL_SUPPORT
  // This function is not allowed to cause a garbage collection.
  // A GC might move the calling generated code and invalidate the
  // return address on the stack.
  DisallowGarbageCollection no_gc;
  DCHECK_EQ(0, byte_length % 2);
  size_t length = byte_length / 2;
  base::uc16* substring1 = reinterpret_cast<base::uc16*>(byte_offset1);
  base::uc16* substring2 = reinterpret_cast<base::uc16*>(byte_offset2);

  for (size_t i = 0; i < length; i++) {
    UChar32 c1 = RegExpCaseFolding::Canonicalize(substring1[i]);
    UChar32 c2 = RegExpCaseFolding::Canonicalize(substring2[i]);
    if (c1 != c2) {
      return 0;
    }
  }
  return 1;
#else
  return CaseInsensitiveCompareUnicode(byte_offset1, byte_offset2, byte_length,
                                       isolate);
#endif
}

// static
int RegExpMacroAssembler::CaseInsensitiveCompareUnicode(Address byte_offset1,
                                                        Address byte_offset2,
                                                        size_t byte_length,
                                                        Isolate* isolate) {
  // This function is not allowed to cause a garbage collection.
  // A GC might move the calling generated code and invalidate the
  // return address on the stack.
  DisallowGarbageCollection no_gc;
  DCHECK_EQ(0, byte_length % 2);

#ifdef V8_INTL_SUPPORT
  int32_t length = static_cast<int32_t>(byte_length >> 1);
  icu::UnicodeString uni_str_1(reinterpret_cast<const char16_t*>(byte_offset1),
                               length);
  return uni_str_1.caseCompare(reinterpret_cast<const char16_t*>(byte_offset2),
                               length, U_FOLD_CASE_DEFAULT) == 0;
#else
  base::uc16* substring1 = reinterpret_cast<base::uc16*>(byte_offset1);
  base::uc16* substring2 = reinterpret_cast<base::uc16*>(byte_offset2);
  size_t length = byte_length >> 1;
  DCHECK_NOT_NULL(isolate);
  unibrow::Mapping<unibrow::Ecma262Canonicalize>* canonicalize =
      isolate->regexp_macro_assembler_canonicalize();
  for (size_t i = 0; i < length; i++) {
    unibrow::uchar c1 = substring1[i];
    unibrow::uchar c2 = substring2[i];
    if (c1 != c2) {
      unibrow::uchar s1[1] = {c1};
      canonicalize->get(c1, '\0', s1);
      if (s1[0] != c2) {
        unibrow::uchar s2[1] = {c2};
        canonicalize->get(c2, '\0', s2);
        if (s1[0] != s2[0]) {
          return 0;
        }
      }
    }
  }
  return 1;
#endif  // V8_INTL_SUPPORT
}

namespace {

uint32_t Hash(const ZoneList<CharacterRange>* ranges) {
  size_t seed = 0;
  for (int i = 0; i < ranges->length(); i++) {
    const CharacterRange& r = ranges->at(i);
    seed = base::hash_combine(seed, r.from(), r.to());
  }
  return static_cast<uint32_t>(seed);
}

constexpr base::uc32 MaskEndOfRangeMarker(base::uc32 c) {
  // CharacterRanges may use 0x10ffff as the end-of-range marker irrespective
  // of whether the regexp IsUnicode or not; translate the marker value here.
  DCHECK_IMPLIES(c > kMaxUInt16, c == String::kMaxCodePoint);
  return c & 0xffff;
}

int RangeArrayLengthFor(const ZoneList<CharacterRange>* ranges) {
  const int ranges_length = ranges->length();
  return MaskEndOfRangeMarker(ranges->at(ranges_length - 1).to()) == kMaxUInt16
             ? ranges_length * 2 - 1
             : ranges_length * 2;
}

bool Equals(const ZoneList<CharacterRange>* lhs,
            const DirectHandle<FixedUInt16Array>& rhs) {
  const int rhs_length = rhs->length();
  if (rhs_length != RangeArrayLengthFor(lhs)) return false;
  for (int i = 0; i < lhs->length(); i++) {
    const CharacterRange& r = lhs->at(i);
    if (rhs->get(i * 2 + 0) != r.from()) return false;
    if (i * 2 + 1 == rhs_length) break;
    if (rhs->get(i * 2 + 1) != r.to() + 1) return false;
  }
  return true;
}

Handle<FixedUInt16Array> MakeRangeArray(
    Isolate* isolate, const ZoneList<CharacterRange>* ranges) {
  const int ranges_length = ranges->length();
  const int range_array_length = RangeArrayLengthFor(ranges);
  Handle<FixedUInt16Array> range_array =
      FixedUInt16Array::New(isolate, range_array_length);
  for (int i = 0; i < ranges_length; i++) {
    const CharacterRange& r = ranges->at(i);
    DCHECK_LE(r.from(), kMaxUInt16);
    range_array->set(i * 2 + 0, r.from());
    const base::uc32 to = MaskEndOfRangeMarker(r.to());
    if (i == ranges_length - 1 && to == kMaxUInt16) {
      DCHECK_EQ(range_array_length, ranges_length * 2 - 1);
      break;  // Avoid overflow by leaving the last range open-ended.
    }
    DCHECK_LT(to, kMaxUInt16);
    range_array->set(i * 2 + 1, to + 1);  // Exclusive.
  }
  return range_array;
}

}  // namespace

Handle<ByteArray> NativeRegExpMacroAssembler::GetOrAddRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  const uint32_t hash = Hash(ranges);

  if (range_array_cache_.count(hash) != 0) {
    Handle<FixedUInt16Array> range_array = range_array_cache_[hash];
    if (Equals(ranges, range_array)) return range_array;
  }

  Handle<FixedUInt16Array> range_array = MakeRangeArray(isolate(), ranges);
  range_array_cache_[hash] = range_array;
  return range_array;
}

// static
uint32_t RegExpMacroAssembler::IsCharacterInRangeArray(uint32_t current_char,
                                                       Address raw_byte_array) {
  // Use uint32_t to avoid complexity around bool return types (which may be
  // optimized to use only the least significant byte).
  static constexpr uint32_t kTrue = 1;
  static constexpr uint32_t kFalse = 0;

  Tagged<FixedUInt16Array> ranges =
      Cast<FixedUInt16Array>(Tagged<Object>(raw_byte_array));
  DCHECK_GE(ranges->length(), 1);

  // Shortcut for fully out of range chars.
  if (current_char < ranges->get(0)) return kFalse;
  if (current_char >= ranges->get(ranges->length() - 1)) {
    // The last range may be open-ended.
    return (ranges->length() % 2) == 0 ? kFalse : kTrue;
  }

  // Binary search for the matching range. `ranges` is encoded as
  // [from0, to0, from1, to1, ..., fromN, toN], or
  // [from0, to0, from1, to1, ..., fromN] (open-ended last interval).

  int mid, lower = 0, upper = ranges->length();
  do {
    mid = lower + (upper - lower) / 2;
    const base::uc16 elem = ranges->get(mid);
    if (current_char < elem) {
      upper = mid;
    } else if (current_char > elem) {
      lower = mid + 1;
    } else {
      DCHECK_EQ(current_char, elem);
      break;
    }
  } while (lower < upper);

  const bool current_char_ge_last_elem = current_char >= ranges->get(mid);
  const int current_range_start_index =
      current_char_ge_last_elem ? mid : mid - 1;

  // Ranges start at even indices and end at odd indices.
  return (current_range_start_index % 2) == 0 ? kTrue : kFalse;
}

void RegExpMacroAssembler::CheckNotInSurrogatePair(int cp_offset,
                                                   Label* on_failure) {
  Label ok;
  // Check that current character is not a trail surrogate.
  LoadCurrentCharacter(cp_offset, &ok);
  CheckCharacterNotInRange(kTrailSurrogateStart, kTrailSurrogateEnd, &ok);
  // Check that previous character is not a lead surrogate.
  LoadCurrentCharacter(cp_offset - 1, &ok);
  CheckCharacterInRange(kLeadSurrogateStart, kLeadSurrogateEnd, on_failure);
  Bind(&ok);
}

void RegExpMacroAssembler::CheckPosition(int cp_offset,
                                         Label* on_outside_input) {
  LoadCurrentCharacter(cp_offset, on_outside_input, true);
}

void RegExpMacroAssembler::LoadCurrentCharacter(int cp_offset,
                                                Label* on_end_of_input,
                                                bool check_bounds,
                                                int characters,
                                                int eats_at_least) {
  // By default, eats_at_least = characters.
  if (eats_at_least == kUseCharactersValue) {
    eats_at_least = characters;
  }

  LoadCurrentCharacterImpl(cp_offset, on_end_of_input, check_bounds, characters,
                           eats_at_least);
}

void NativeRegExpMacroAssembler::LoadCurrentCharacterImpl(
    int cp_offset, Label* on_end_of_input, bool check_bounds, int characters,
    int eats_at_least) {
  // It's possible to preload a small number of characters when each success
  // path requires a large number of characters, but not the reverse.
  DCHECK_GE(eats_at_least, characters);

  DCHECK(base::IsInRange(cp_offset, kMinCPOffset, kMaxCPOffset));
  if (check_bounds) {
    if (cp_offset >= 0) {
      CheckPosition(cp_offset + eats_at_least - 1, on_end_of_input);
    } else {
      CheckPosition(cp_offset, on_end_of_input);
    }
  }
  LoadCurrentCharacterUnchecked(cp_offset, characters);
}

bool NativeRegExpMacroAssembler::CanReadUnaligned() const {
  return v8_flags.enable_regexp_unaligned_accesses && !slow_safe();
}

#ifndef COMPILING_IRREGEXP_FOR_EXTERNAL_EMBEDDER

// This method may only be called after an interrupt.
// static
int NativeRegExpMacroAssembler::CheckStackGuardState(
    Isolate* isolate, int start_index, RegExp::CallOrigin call_origin,
    Address* return_address, Tagged<InstructionStream> re_code,
    Address* subject, const uint8_t** input_start, const uint8_t** input_end,
    uintptr_t gap) {
  DisallowGarbageCollection no_gc;
  Address old_pc = PointerAuthentication::AuthenticatePC(return_address, 0);
  DCHECK_LE(re_code->instruction_start(), old_pc);
  DCHECK_LE(old_pc, re_code->code(kAcquireLoad)->instruction_end());

  StackLimitCheck check(isolate);
  bool js_has_overflowed = check.JsHasOverflowed(gap);

  if (call_origin == RegExp::CallOrigin::kFromJs) {
    // Direct calls from JavaScript can be interrupted in two ways:
    // 1. A real stack overflow, in which case we let the caller throw the
    //    exception.
    // 2. The stack guard was used to interrupt execution for another purpose,
    //    forcing the call through the runtime system.

    // Bug(v8:9540) Investigate why this method is called from JS although no
    // stackoverflow or interrupt is pending on ARM64. We return 0 in this case
    // to continue execution normally.
    if (js_has_overflowed) {
      return EXCEPTION;
    } else if (check.InterruptRequested()) {
      return RETRY;
    } else {
      return 0;
    }
  }
  DCHECK(call_origin == RegExp::CallOrigin::kFromRuntime);

  // Prepare for possible GC.
  HandleScope handles(isolate);
  DirectHandle<InstructionStream> code_handle(re_code, isolate);
  DirectHandle<String> subject_handle(Cast<String>(Tagged<Object>(*subject)),
                                      isolate);
  bool is_one_byte = subject_handle->IsOneByteRepresentation();
  int return_value = 0;

  {
    DisableGCMole no_gc_mole;
    if (js_has_overflowed) {
      AllowGarbageCollection yes_gc;
      isolate->StackOverflow();
      return_value = EXCEPTION;
    } else if (check.InterruptRequested()) {
      AllowGarbageCollection yes_gc;
      Tagged<Object> result = isolate->stack_guard()->HandleInterrupts();
      if (IsException(result, isolate)) return_value = EXCEPTION;
    }

    // We are not using operator == here because it does a slow DCHECK
    // CheckObjectComparisonAllowed() which might crash when trying to access
    // the page header of the stale pointer.
    if (!code_handle->SafeEquals(re_code)) {  // Return address no longer valid
      // Overwrite the return address on the stack.
      intptr_t delta = code_handle->address() - re_code.address();
      Address new_pc = old_pc + delta;
      // TODO(v8:10026): avoid replacing a signed pointer.
      PointerAuthentication::ReplacePC(return_address, new_pc, 0);
    }
  }

  // If we continue, we need to update the subject string addresses.
  if (return_value == 0) {
    // String encoding might have changed.
    if (subject_handle->IsOneByteRepresentation() != is_one_byte) {
      // If we changed between an LATIN1 and an UC16 string, the specialized
      // code cannot be used, and we need to restart regexp matching from
      // scratch (including, potentially, compiling a new version of the code).
      return_value = RETRY;
    } else {
      *subject = subject_handle->ptr();
      intptr_t byte_length = *input_end - *input_start;
      *input_start = subject_handle->AddressOfCharacterAt(start_index, no_gc);
      *input_end = *input_start + byte_length;
    }
  }
  return return_value;
}

// Returns a {Result} sentinel, or the number of successful matches.
int NativeRegExpMacroAssembler::Match(DirectHandle<IrRegExpData> regexp_data,
                                      DirectHandle<String> subject,
                                      int* offsets_vector,
                                      int offsets_vector_length,
                                      int previous_index, Isolate* isolate) {
  DCHECK(subject->IsFlat());
  DCHECK_LE(0, previous_index);
  DCHECK_LE(previous_index, subject->length());

  // No allocations before calling the regexp, but we can't use
  // DisallowGarbageCollection, since regexps might be preempted, and another
  // thread might do allocation anyway.

  Tagged<String> subject_ptr = *subject;
  // Character offsets into string.
  int start_offset = previous_index;
  int char_length = subject_ptr->length() - start_offset;
  int slice_offset = 0;

  // The string has been flattened, so if it is a cons string it contains the
  // full string in the first part.
  if (StringShape(subject_ptr).IsCons()) {
    DCHECK_EQ(0, Cast<ConsString>(subject_ptr)->second()->length());
    subject_ptr = Cast<ConsString>(subject_ptr)->first();
  } else if (StringShape(subject_ptr).IsSliced()) {
    Tagged<SlicedString> slice = Cast<SlicedString>(subject_ptr);
    subject_ptr = slice->parent();
    slice_offset = slice->offset();
  }
  if (StringShape(subject_ptr).IsThin()) {
    subject_ptr = Cast<ThinString>(subject_ptr)->actual();
  }
  // Ensure that an underlying string has the same representation.
  bool is_one_byte = subject_ptr->IsOneByteRepresentation();
  DCHECK(IsExternalString(subject_ptr) || IsSeqString(subject_ptr));
  // String is now either Sequential or External
  int char_size_shift = is_one_byte ? 0 : 1;

  DisallowGarbageCollection no_gc;
  const uint8_t* input_start =
      subject_ptr->AddressOfCharacterAt(start_offset + slice_offset, no_gc);
  int byte_length = char_length << char_size_shift;
  const uint8_t* input_end = input_start + byte_length;
  return Execute(*subject, start_offset, input_start, input_end, offsets_vector,
                 offsets_vector_length, isolate, *regexp_data);
}

// static
int NativeRegExpMacroAssembler::ExecuteForTesting(
    Tagged<String> input, int start_offset, const uint8_t* input_start,
    const uint8_t* input_end, int* output, int output_size, Isolate* isolate,
    Tagged<JSRegExp> regexp) {
  Tagged<RegExpData> data = regexp->data(isolate);
  SBXCHECK(Is<IrRegExpData>(data));
  return Execute(input, start_offset, input_start, input_end, output,
                 output_size, isolate, Cast<IrRegExpData>(data));
}

// Returns a {Result} sentinel, or the number of successful matches.
int NativeRegExpMacroAssembler::Execute(
    Tagged<String>
        input,  // This needs to be the unpacked (sliced, cons) string.
    int start_offset, const uint8_t* input_start, const uint8_t* input_end,
    int* output, int output_size, Isolate* isolate,
    Tagged<IrRegExpData> regexp_data) {
  bool is_one_byte = input->IsOneByteRepresentation();
  Tagged<Code> code = regexp_data->code(isolate, is_one_byte);
  RegExp::CallOrigin call_origin = RegExp::CallOrigin::kFromRuntime;

  using RegexpMatcherSig =
      // NOLINTNEXTLINE(readability/casting)
      int(Address input_string, int start_offset, const uint8_t* input_start,
          const uint8_t* input_end, int* output, int output_size,
          int call_origin, Isolate* isolate, Address regexp_data);

  auto fn = GeneratedCode<RegexpMatcherSig>::FromCode(isolate, code);
  int result =
      fn.Call(input.ptr(), start_offset, input_start, input_end, output,
              output_size, call_origin, isolate, regexp_data.ptr());
  DCHECK_GE(result, SMALLEST_REGEXP_RESULT);

  if (result == EXCEPTION && !isolate->has_exception()) {
    // We detected a stack overflow (on the backtrack stack) in RegExp code,
    // but haven't created the exception yet. Additionally, we allow heap
    // allocation because even though it invalidates {input_start} and
    // {input_end}, we are about to return anyway.
    AllowGarbageCollection allow_allocation;
    isolate->StackOverflow();
  }
  return result;
}

#endif  // !COMPILING_IRREGEXP_FOR_EXTERNAL_EMBEDDER

// clang-format off
const uint8_t NativeRegExpMacroAssembler::word_character_map[] = {
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,

    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,  // '0' - '7'
    0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,  // '8' - '9'

    0x00u, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,  // 'A' - 'G'
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,  // 'H' - 'O'
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,  // 'P' - 'W'
    0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0xFFu,  // 'X' - 'Z', '_'

    0x00u, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,  // 'a' - 'g'
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,  // 'h' - 'o'
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,  // 'p' - 'w'
    0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,  // 'x' - 'z'
    // Latin-1 range
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,

    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,

    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,

    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
};
// clang-format on

// static
Address NativeRegExpMacroAssembler::GrowStack(Isolate* isolate) {
  DisallowGarbageCollection no_gc;

  RegExpStack* regexp_stack = isolate->regexp_stack();
  const size_t old_size = regexp_stack->memory_size();

#ifdef DEBUG
  const Address old_stack_top = regexp_stack->memory_top();
  const Address old_stack_pointer = regexp_stack->stack_pointer();
  CHECK_LE(old_stack_pointer, old_stack_top);
  CHECK_LE(static_cast<size_t>(old_stack_top - old_stack_pointer), old_size);
#endif  // DEBUG

  Address new_stack_base = regexp_stack->EnsureCapacity(old_size * 2);
  if (new_stack_base == kNullAddress) return kNullAddress;

  return regexp_stack->stack_pointer();
}

}  // namespace internal
}  // namespace v8

"""

```