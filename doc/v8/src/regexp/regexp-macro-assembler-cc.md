Response:
Let's break down the thought process for analyzing the provided C++ code snippet for `v8/src/regexp/regexp-macro-assembler.cc`.

**1. Initial Understanding and High-Level Goals:**

* **Identify the core purpose:** The file name strongly suggests it's about assembling regular expression matching logic at a low level (macro-assembler).
* **Determine the target audience:** V8 developers working on the regular expression engine.
* **Extract key functionalities:**  What actions does this code enable?
* **Relate to JavaScript (if applicable):** How does this low-level code connect to the JavaScript `RegExp` object?
* **Consider potential errors:** What common mistakes might a user make that relate to this code's functionality?
* **Check for Torque:** Scan the filename extension for `.tq`. In this case, it's `.cc`, so it's not Torque.

**2. Code Structure and Keyword Scanning:**

* **Copyright and Includes:** Notice the standard V8 copyright and the included headers. These headers (`assembler.h`, `label.h`, `isolate-inl.h`, etc.) provide clues about the code's interaction with the V8 architecture (assembly generation, memory management, etc.). The inclusion of `regexp-stack.h` and `special-case.h` reinforces the regex focus. `unicode-inl.h` and `unicode/uchar.h` (under `V8_INTL_SUPPORT`) point to Unicode handling.
* **Namespace:** The code is within `v8::internal`, indicating it's part of V8's internal implementation.
* **Class Definition:** The central class is `RegExpMacroAssembler`. This is the main subject of the analysis.
* **Method Analysis (Keyword/Pattern Recognition):** Go through the methods and look for recognizable patterns and keywords:
    * **`CaseInsensitiveCompareNonUnicode`, `CaseInsensitiveCompareUnicode`:**  Clearly about case-insensitive string comparison, with different handling for Unicode.
    * **`Hash`, `Equals`, `MakeRangeArray`, `GetOrAddRangeArray`:** These methods suggest the creation and management of data structures for character ranges (likely for character classes in regex).
    * **`IsCharacterInRangeArray`:** This confirms the previous point—checking if a character belongs to a defined range.
    * **`CheckNotInSurrogatePair`, `CheckPosition`, `LoadCurrentCharacter`:** These indicate low-level string traversal and validation during regex matching. The surrogate pair check is vital for Unicode correctness.
    * **`CanReadUnaligned`:** This hints at potential optimization using unaligned memory access.
    * **`CheckStackGuardState`, `Match`, `Execute`, `ExecuteForTesting`:** These are clearly about the core regex execution process, including stack management and interaction with the compiled regex code. The `Testing` variant is for internal V8 tests.
    * **`word_character_map`:**  A static array—likely a lookup table for determining word characters (`\w`).
    * **`GrowStack`:** Manages the runtime stack used by the regex engine.

**3. Functionality Deduction and Grouping:**

Based on the keyword analysis, group the methods by their likely purpose:

* **Initialization and Configuration:** `RegExpMacroAssembler` constructor, `has_backtrack_limit`.
* **Case-Insensitive Comparison:** `CaseInsensitiveCompareNonUnicode`, `CaseInsensitiveCompareUnicode`.
* **Character Range Handling:** `Hash`, `Equals`, `MakeRangeArray`, `GetOrAddRangeArray`, `IsCharacterInRangeArray`.
* **String Traversal and Character Access:** `CheckNotInSurrogatePair`, `CheckPosition`, `LoadCurrentCharacter`, `LoadCurrentCharacterImpl`.
* **Performance Optimization:** `CanReadUnaligned`.
* **Regex Execution Core:** `CheckStackGuardState`, `Match`, `Execute`, `ExecuteForTesting`.
* **Character Property Lookup:** `word_character_map`.
* **Stack Management:** `GrowStack`.

**4. Connecting to JavaScript:**

* The `RegExp` object in JavaScript is the user-facing interface. The `RegExpMacroAssembler` is part of the underlying *implementation* of how the V8 engine executes regular expressions.
* When a JavaScript regex method like `test()`, `exec()`, `match()`, `search()`, or `replace()` is called, V8 compiles the regex (potentially using this assembler) and then executes the compiled code against the input string.

**5. JavaScript Examples:**

Think of concrete JavaScript regex operations and how they might relate to the identified functionalities:

* **Case-insensitive matching (`/abc/i`):** Would likely use the `CaseInsensitiveCompare...` methods.
* **Character classes (`[a-z]`, `\w`):**  Involves the character range handling methods. `\w` directly relates to `word_character_map`.
* **Unicode characters (`\u{...}`):** Would use the Unicode-aware comparison and surrogate pair checks.
* **Anchors (`^`, `$`), word boundaries (`\b`):** Might use `CheckPosition`.
* **Quantifiers (`*`, `+`, `?`, `{}`):** Can lead to backtracking, and the `GrowStack` method might be involved if the backtracking stack needs to grow.

**6. Code Logic Inference and Examples:**

Focus on methods with clear input/output behavior:

* **`IsCharacterInRangeArray`:**  Think of a concrete range (e.g., `[0-9]`) and characters to test (e.g., '5', 'a').
* **Case-insensitive comparison:** Provide example strings that are the same ignoring case (e.g., "abc", "ABC").

**7. Common Programming Errors:**

Think about mistakes developers make when using regular expressions in JavaScript:

* **Incorrectly assuming case sensitivity/insensitivity:**  Forgetting the `i` flag.
* **Misunderstanding character classes:**  Expecting `[a-Z]` to work as intended (it includes characters between 'Z' and 'a').
* **Forgetting Unicode:** Not handling characters outside the basic ASCII range correctly.
* **Catastrophic backtracking:** Writing regexes that can take exponential time to execute (although the provided code snippet focuses on the *implementation*, understanding this error helps connect the low-level to the high-level).

**8. Refinement and Organization:**

Structure the analysis logically, using headings and bullet points for clarity. Ensure the explanations are concise and easy to understand. Review and refine the examples to be accurate and illustrative.

By following this systematic approach, you can effectively analyze a complex code snippet, extract its key functionalities, and relate it to its higher-level purpose and usage.好的，让我们来分析一下 `v8/src/regexp/regexp-macro-assembler.cc` 这个文件。

**功能概要**

`v8/src/regexp/regexp-macro-assembler.cc` 是 V8 引擎中用于构建正则表达式匹配器的核心组件。它的主要功能是提供一个抽象层，允许 V8 的正则表达式引擎生成与特定架构无关的底层指令序列，以便高效地执行正则表达式匹配。

**详细功能点**

1. **抽象汇编接口:**  `RegExpMacroAssembler` 类定义了一系列方法，这些方法代表了在正则表达式匹配过程中可能需要的各种操作，例如：
   - 加载和比较字符。
   - 跳转和标签定义（用于控制匹配流程）。
   - 栈操作（用于保存回溯信息和捕获组）。
   - 调用运行时函数（例如，用于处理 Unicode 字符或中断检查）。

2. **平台无关性:**  这个类的设计目标是平台无关性。它不直接生成特定 CPU 架构的机器码。相反，它生成一种中间表示，然后由底层的 `Assembler` 类将其转换为目标平台的机器码。

3. **支持不同的字符编码:**  代码中可以看到对 Unicode 和非 Unicode 字符的处理，以及对单字节和双字节字符的支持。

4. **处理特殊情况:**  例如，对大小写不敏感的比较、Unicode 字符的规范化等。

5. **栈管理:**  正则表达式匹配需要一个栈来存储状态信息，以便在匹配失败时进行回溯。`RegExpMacroAssembler` 提供了管理这个栈的方法，例如分配和释放栈空间。

6. **性能优化:**  这个类中的许多设计决策都考虑了性能，例如使用内联函数、避免不必要的内存分配等。

**关于文件扩展名和 Torque**

如果 `v8/src/regexp/regexp-macro-assembler.cc` 的文件扩展名是 `.tq`，那么它确实是使用 V8 的 Torque 语言编写的。Torque 是一种用于编写 V8 内部代码的领域特定语言，它旨在提供比 C++ 更高级别的抽象，并帮助提高代码的安全性和可维护性。但根据你提供的信息，该文件是 `.cc` 结尾，所以它是 C++ 源代码。

**与 JavaScript 的关系和示例**

`RegExpMacroAssembler` 直接服务于 JavaScript 的 `RegExp` 对象。当你在 JavaScript 中创建一个正则表达式并尝试用它匹配字符串时，V8 引擎会在幕后使用这个类来生成执行匹配的代码。

**JavaScript 示例：**

```javascript
const regex = /ab+c/i;
const text = "ABBC";
const match = text.match(regex);

if (match) {
  console.log("匹配成功:", match[0]); // 输出: 匹配成功: ABBC
} else {
  console.log("匹配失败");
}
```

在这个例子中，当你执行 `text.match(regex)` 时，V8 内部会执行以下步骤（简化）：

1. **解析正则表达式:**  V8 会解析 `/ab+c/i` 这个正则表达式。
2. **编译正则表达式:**  V8 会使用 `RegExpMacroAssembler` (或其相关的组件) 来生成用于执行匹配的机器码。大小写不敏感的 `i` 标志会影响 `RegExpMacroAssembler` 生成的比较指令。
3. **执行匹配:** 生成的机器码会在 `text` 中查找与正则表达式匹配的部分。
4. **返回结果:**  如果找到匹配，`match()` 方法会返回一个包含匹配信息的数组；否则返回 `null`。

**代码逻辑推理和示例**

让我们看一个与大小写不敏感比较相关的代码片段：

```c++
// static
int RegExpMacroAssembler::CaseInsensitiveCompareNonUnicode(Address byte_offset1,
                                                           Address byte_offset2,
                                                           size_t byte_length,
                                                           Isolate* isolate) {
  // ... (代码实现) ...
}
```

**假设输入：**

- `byte_offset1`: 指向内存中字符串 "hello" 的起始位置。
- `byte_offset2`: 指向内存中字符串 "HELLO" 的起始位置。
- `byte_length`: 10 (假设字符编码是每个字符 1 字节)。
- `isolate`: V8 引擎的隔离区指针。

**预期输出：**

- 返回值：`1` (表示两个字符串在忽略大小写的情况下是相等的)。

**代码逻辑推理：**

这段代码会逐个字符地比较两个内存区域的内容，并在比较之前将字符转换为规范形式（通常是小写或大写）。如果所有字符都相等（忽略大小写），则返回 `1`，否则返回 `0`。

**用户常见的编程错误**

涉及到正则表达式时，用户常常会犯以下错误，这些错误可能与 `RegExpMacroAssembler` 的某些功能相关：

1. **大小写敏感性问题:**  用户可能忘记使用 `i` 标志进行大小写不敏感的匹配，导致匹配失败。

   **错误示例：**

   ```javascript
   const regex = /abc/;
   const text = "ABC";
   const match = text.match(regex); // match 为 null，因为默认是大小写敏感的
   ```

2. **Unicode 字符处理错误:**  在处理包含 Unicode 字符的字符串时，可能会因为对 Unicode 的理解不足而导致正则表达式无法正确匹配。例如，认为一个 Unicode 字符始终占用一个字符的位置。

   **错误示例：**

   ```javascript
   const regex = /^.$/;
   const text = "你好";
   const match = text.match(regex); // match 为 null，因为 "." 默认不匹配换行符，且通常匹配单个“代码单元”而不是用户期望的字符
   ```

3. **回溯问题（Catastrophic Backtracking）:**  编写的正则表达式过于复杂，导致回溯次数过多，造成性能问题甚至浏览器卡死。虽然 `RegExpMacroAssembler` 负责执行，但错误的正则表达式是问题的根源。

   **错误示例：**

   ```javascript
   const regex = /a*b*c*/; // 这种模式在某些情况下可能导致大量回溯
   const text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
   const match = text.match(regex);
   ```

4. **不理解字符类的行为:**  例如，认为 `[a-Z]` 可以匹配所有字母，但实际上它还会匹配 `[`、`\`、`]`、`^`、`_` 和 `` ` `` 这些字符，因为它们的 ASCII 码介于 'Z' 和 'a' 之间。

   **错误示例：**

   ```javascript
   const regex = /[a-Z]/;
   const text = "_";
   const match = text.match(regex); // match 不为 null，因为 '_' 在 ASCII 码中介于 'Z' 和 'a' 之间
   ```

`RegExpMacroAssembler` 的存在是为了高效地执行正则表达式匹配，理解其功能有助于理解 V8 引擎是如何处理 JavaScript 中正则表达式的。虽然开发者不会直接与这个类交互，但了解其背后的机制可以帮助编写更有效和更准确的正则表达式。

### 提示词
```
这是目录为v8/src/regexp/regexp-macro-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-macro-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```