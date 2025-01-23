Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8's `runtime-regexp.cc` file. The summary should cover:

1. **Core Functions:** What does this code do?
2. **Torque Source Check:**  Determine if the file would be a Torque file if it ended in `.tq`.
3. **JavaScript Relationship:**  If related to JavaScript functionality, provide JavaScript examples.
4. **Code Logic Inference:** For any identifiable logic, provide hypothetical inputs and outputs.
5. **Common Programming Errors:** Identify potential user errors this code addresses or relates to.
6. **Overall Function (Part 1):**  Summarize the functionality covered in this specific part of the code.

**Thinking Process:**

1. **High-Level Overview:**  Skim the code for keywords and function names related to regular expressions and string manipulation (e.g., `RegExp`, `replace`, `split`, `match`, `CompiledReplacement`, `StringSearch`). This immediately suggests the code is involved in implementing JavaScript's string methods that interact with regular expressions.

2. **Torque Check:**  Look for any signs of Torque syntax (e.g., `builtin`, `macro`, type annotations). The absence of these suggests it's not Torque.

3. **JavaScript Mapping:**  Consider which JavaScript `String` methods use regular expressions. The presence of `StringReplaceGlobalRegExpWithString`, `StringReplaceGlobalAtomRegExpWithString`, `StringReplaceGlobalRegExpWithEmptyString`, and `Runtime_StringSplit` strongly point to the implementation of `String.prototype.replace()` and `String.prototype.split()`.

4. **Detailed Analysis of Key Components:**
    *   **`CompiledReplacement` Class:** This class seems crucial for handling the replacement string in `replace()`. The `Compile` method parses the replacement string, looking for special `$`-prefixed patterns. The `Apply` method uses the parsed structure to build the new string.
    *   **`FindStringIndicesDispatch` and related functions:** These appear to be implementing the core string searching logic used by `split()` to find occurrences of the separator.
    *   **`StringReplaceGlobal...` functions:** These functions handle the global `replace()` operation, iterating through matches and building the result.
    *   **`Runtime_StringSplit`:** This function directly implements the `split()` logic, using `FindStringIndicesDispatch` to locate separators.

5. **Code Logic Inference (with examples):**
    *   **`CompiledReplacement::Compile`:** If the replacement string is `"$1 - $2"`, and the regex has two capturing groups, this function would parse it into parts representing capture group 1, the literal " - ", and capture group 2.
    *   **`FindStringIndicesDispatch`:** If the subject is `"abcde"` and the pattern is `"c"`, the output would be a list containing the index `2`.

6. **Common Programming Errors:** Think about common mistakes developers make with `replace()` and `split()`:
    *   Incorrectly using capture groups in the replacement string.
    *   Not understanding the behavior of `split()` with a regular expression separator.
    *   Potential performance issues with complex regular expressions or large strings.

7. **Part 1 Scope:** Review the provided code to see what specific functionality is present in this segment. It appears to focus on the implementation details of `String.prototype.replace()` and the initial part of `String.prototype.split()`.

8. **Synthesize the Summary:** Combine the observations into a concise summary, addressing each of the user's requirements. Ensure the JavaScript examples are clear and relevant.

**(Self-Correction during the process):** Initially, I might have focused too heavily on the low-level details of memory management or specific V8 internals. However, the user's request is more about the *functional* aspects and their connection to JavaScript. Adjusting the focus to the higher-level logic and JavaScript equivalents is crucial. Also, remember the "Part 1" constraint and only summarize the functionality present in the provided snippet.
这是 `v8/src/runtime/runtime-regexp.cc` 的第一部分源代码，它主要负责实现与 JavaScript 正则表达式操作相关的运行时功能。

**功能归纳:**

1. **正则表达式替换 (`String.prototype.replace`) 的核心逻辑：**  这部分代码包含了实现 `String.prototype.replace` 方法的核心逻辑，特别是当使用全局正则表达式进行替换时。它处理了如何查找所有匹配项，以及如何根据替换字符串（可以是普通字符串或包含特殊替换模式的字符串）生成新的字符串。

2. **解析替换模式：** `CompiledReplacement` 类负责解析替换字符串中的特殊模式，例如 `$n` (捕获组)， `$&` (匹配的子字符串)， `` ` `` (匹配项之前的子字符串)， `'` (匹配项之后的子字符串)，以及 `$ <name> ` (命名捕获组)。它将替换模式分解成不同的部分，以便在实际替换时高效地应用。

3. **处理简单字符串替换：** 代码中也包含对简单字符串替换的优化，当替换字符串不包含特殊模式时，可以更快地执行替换操作。

4. **字符串分割 (`String.prototype.split`) 的初步实现：**  `Runtime_StringSplit` 函数是 `String.prototype.split` 方法的运行时实现。在这部分代码中，它实现了使用字符串作为分隔符进行分割的功能。它会查找所有分隔符出现的位置，并将原始字符串分割成子字符串数组。

5. **缓存机制 (split 部分)：** 对于使用字符串作为分隔符的 `split` 操作，代码中存在一个缓存机制，用于存储先前分割的结果。如果相同的字符串和分隔符再次被用于分割，可以直接从缓存中获取结果，提高性能。

**它不是 Torque 源代码:**

如果 `v8/src/runtime/runtime-regexp.cc` 以 `.tq` 结尾，那它才是一个 V8 Torque 源代码。当前是以 `.cc` 结尾，表明它是用 C++ 编写的。Torque 是一种 V8 内部使用的类型安全的高级语言，用于生成高效的 C++ 代码。

**与 Javascript 功能的关系 (附带 JavaScript 示例):**

这部分 C++ 代码直接实现了 JavaScript 中 `String.prototype.replace()` 和 `String.prototype.split()` 方法的部分功能。

**`String.prototype.replace()` 示例:**

```javascript
const str = 'The quick brown fox jumps over the lazy dog.';
const regex = /the/gi;
const newStr = str.replace(regex, 'a');
console.log(newStr); // 输出: "a quick brown fox jumps over a lazy dog."

const str2 = 'hello world';
const regex2 = /(hello) (world)/;
const newStr2 = str2.replace(regex2, '$2 $1');
console.log(newStr2); // 输出: "world hello"

const str3 = 'hello world';
const newStr3 = str3.replace('world', 'universe');
console.log(newStr3); // 输出: "hello universe"
```

`v8/src/runtime/runtime-regexp.cc` 中的代码处理了 `regex.replace()` 的情况，特别是全局替换和带有捕获组的替换。`CompiledReplacement` 类处理了像 `$1`, `$2` 这样的替换模式。

**`String.prototype.split()` 示例:**

```javascript
const str = "The quick brown fox";
const words = str.split(" ");
console.log(words); // 输出: [ 'The', 'quick', 'brown', 'fox' ]

const str2 = "apple,banana,orange";
const fruits = str2.split(",");
console.log(fruits); // 输出: [ 'apple', 'banana', 'orange' ]

const str3 = "1,2,3,4,5";
const numbers = str3.split(",", 3); // 指定 limit
console.log(numbers); // 输出: [ '1', '2', '3' ]
```

`Runtime_StringSplit` 函数（在这部分代码中）实现了使用字符串作为分隔符的 `split` 功能。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (对于 `CompiledReplacement::Compile`):**

*   `replacement`:  `"-$1-"`
*   `capture_count`: 1

**预期输出 (对于 `CompiledReplacement::Compile` 解析后的内部表示):**

内部会生成一个 `parts_` 数组，可能包含以下结构 (简化表示):

1. `REPLACEMENT_SUBSTRING`, data 指向 `"-"`
2. `SUBJECT_CAPTURE`, data: 1
3. `REPLACEMENT_SUBSTRING`, data 指向 `"-"`

**假设输入 (对于 `Runtime_StringSplit`):**

*   `subject`: `"a-b-c"`
*   `pattern`: `"-"`
*   `limit`: `0xFFFFFFFFu` (无限制)

**预期输出 (对于 `Runtime_StringSplit`):**

返回一个 JavaScript 数组 `["a", "b", "c"]`。

**用户常见的编程错误:**

1. **在 `String.prototype.replace` 中错误地使用替换模式:**

    ```javascript
    const str = "Price: $100";
    const newStr = str.replace(/\$(\d+)/, 'The price is $$1');
    console.log(newStr); // 错误地输出: "The price is $1" 而不是 "The price is $100"
    ```

    用户可能期望 `$$1` 输出 `$100`，但实际上 `$$` 会被转义成 `$`，而 `$1` 仍然表示第一个捕获组。正确的写法是 `$$$$1` 或者使用函数作为替换参数。

2. **在 `String.prototype.split` 中对 limit 参数的误解:**

    ```javascript
    const str = "apple,banana,orange,grape";
    const fruits = str.split(",", 2);
    console.log(fruits); // 输出: [ 'apple', 'banana' ]
    ```

    用户可能没有意识到 `limit` 参数限制的是返回数组的长度，而不是分割发生的次数。

3. **在正则表达式替换中忘记转义特殊字符:**

    ```javascript
    const str = "Is 1+1=2?";
    const newStr = str.replace("+", "-");
    console.log(newStr); // 输出: "Is 1 1=2?"  而不是 "Is 1-1=2?"
    ```

    用户忘记 `+` 在正则表达式中是特殊字符，需要转义 (`\+`) 才能匹配字面量。

**总结 (这部分代码的功能):**

这部分 `v8/src/runtime/runtime-regexp.cc` 代码主要实现了 JavaScript 中 `String.prototype.replace` 方法的全局替换功能（包括解析替换模式）以及 `String.prototype.split` 方法的初步功能（使用字符串作为分隔符）。它包含了用于解析替换字符串、查找匹配项和构建新字符串的关键逻辑，并初步实现了字符串分割的运行时支持，并带有简单的缓存机制来优化性能。

### 提示词
```
这是目录为v8/src/runtime/runtime-regexp.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-regexp.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <functional>

#include "src/base/small-vector.h"
#include "src/base/strings.h"
#include "src/common/message-template.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/logging/counters.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/regexp/regexp-utils.h"
#include "src/regexp/regexp.h"
#include "src/strings/string-builder-inl.h"
#include "src/strings/string-search.h"

namespace v8 {
namespace internal {

namespace {

// Fairly arbitrary, but intended to fit:
//
// - captures
// - results
// - parsed replacement pattern parts
//
// for small, common cases.
constexpr int kStaticVectorSlots = 8;

// Returns -1 for failure.
uint32_t GetArgcForReplaceCallable(uint32_t num_captures,
                                   bool has_named_captures) {
  const uint32_t kAdditionalArgsWithoutNamedCaptures = 2;
  const uint32_t kAdditionalArgsWithNamedCaptures = 3;
  if (num_captures > Code::kMaxArguments) return -1;
  uint32_t argc = has_named_captures
                      ? num_captures + kAdditionalArgsWithNamedCaptures
                      : num_captures + kAdditionalArgsWithoutNamedCaptures;
  static_assert(Code::kMaxArguments < std::numeric_limits<uint32_t>::max() -
                                          kAdditionalArgsWithNamedCaptures);
  return (argc > Code::kMaxArguments) ? -1 : argc;
}

// Looks up the capture of the given name. Returns the (1-based) numbered
// capture index or -1 on failure.
// The lookup starts at index |index_in_out|. On success |index_in_out| is set
// to the index after the entry was found (i.e. the start index to continue the
// search in the presence of duplicate group names).
int LookupNamedCapture(const std::function<bool(Tagged<String>)>& name_matches,
                       Tagged<FixedArray> capture_name_map, int* index_in_out) {
  DCHECK_GE(*index_in_out, 0);
  // TODO(jgruber): Sort capture_name_map and do binary search via
  // internalized strings.

  int maybe_capture_index = -1;
  const int named_capture_count = capture_name_map->length() >> 1;
  DCHECK_LE(*index_in_out, named_capture_count);
  for (int j = *index_in_out; j < named_capture_count; j++) {
    // The format of {capture_name_map} is documented at
    // JSRegExp::kIrregexpCaptureNameMapIndex.
    const int name_ix = j * 2;
    const int index_ix = j * 2 + 1;

    Tagged<String> capture_name = Cast<String>(capture_name_map->get(name_ix));
    if (!name_matches(capture_name)) continue;

    maybe_capture_index = Smi::ToInt(capture_name_map->get(index_ix));
    *index_in_out = j + 1;
    break;
  }

  return maybe_capture_index;
}

}  // namespace

class CompiledReplacement {
 public:
  // Return whether the replacement is simple.
  bool Compile(Isolate* isolate, DirectHandle<JSRegExp> regexp,
               DirectHandle<RegExpData> regexp_data, Handle<String> replacement,
               int capture_count, int subject_length);

  // Use Apply only if Compile returned false.
  void Apply(ReplacementStringBuilder* builder, int match_from, int match_to,
             int32_t* match);

  // Number of distinct parts of the replacement pattern.
  int parts() { return static_cast<int>(parts_.size()); }

 private:
  enum PartType {
    SUBJECT_PREFIX = 1,
    SUBJECT_SUFFIX,
    SUBJECT_CAPTURE,
    REPLACEMENT_SUBSTRING,
    REPLACEMENT_STRING,
    EMPTY_REPLACEMENT,
    NUMBER_OF_PART_TYPES
  };

  struct ReplacementPart {
    static inline ReplacementPart SubjectMatch() {
      return ReplacementPart(SUBJECT_CAPTURE, 0);
    }
    static inline ReplacementPart SubjectCapture(int capture_index) {
      return ReplacementPart(SUBJECT_CAPTURE, capture_index);
    }
    static inline ReplacementPart SubjectPrefix() {
      return ReplacementPart(SUBJECT_PREFIX, 0);
    }
    static inline ReplacementPart SubjectSuffix(int subject_length) {
      return ReplacementPart(SUBJECT_SUFFIX, subject_length);
    }
    static inline ReplacementPart ReplacementString() {
      return ReplacementPart(REPLACEMENT_STRING, 0);
    }
    static inline ReplacementPart EmptyReplacement() {
      return ReplacementPart(EMPTY_REPLACEMENT, 0);
    }
    static inline ReplacementPart ReplacementSubString(int from, int to) {
      DCHECK_LE(0, from);
      DCHECK_GT(to, from);
      return ReplacementPart(-from, to);
    }

    // If tag <= 0 then it is the negation of a start index of a substring of
    // the replacement pattern, otherwise it's a value from PartType.
    ReplacementPart(int tag, int data) : tag(tag), data(data) {
      // Must be non-positive or a PartType value.
      DCHECK(tag < NUMBER_OF_PART_TYPES);
    }
    // Either a value of PartType or a non-positive number that is
    // the negation of an index into the replacement string.
    int tag;
    // The data value's interpretation depends on the value of tag:
    // tag == SUBJECT_PREFIX ||
    // tag == SUBJECT_SUFFIX:  data is unused.
    // tag == SUBJECT_CAPTURE: data is the number of the capture.
    // tag == REPLACEMENT_SUBSTRING ||
    // tag == REPLACEMENT_STRING:    data is index into array of substrings
    //                               of the replacement string.
    // tag == EMPTY_REPLACEMENT: data is unused.
    // tag <= 0: Temporary representation of the substring of the replacement
    //           string ranging over -tag .. data.
    //           Is replaced by REPLACEMENT_{SUB,}STRING when we create the
    //           substring objects.
    int data;
  };

  template <typename Char>
  bool ParseReplacementPattern(base::Vector<Char> characters,
                               Tagged<FixedArray> capture_name_map,
                               int capture_count, int subject_length) {
    // Equivalent to String::GetSubstitution, except that this method converts
    // the replacement string into an internal representation that avoids
    // repeated parsing when used repeatedly.
    int length = characters.length();
    int last = 0;
    for (int i = 0; i < length; i++) {
      Char c = characters[i];
      if (c == '$') {
        int next_index = i + 1;
        if (next_index == length) {  // No next character!
          break;
        }
        Char c2 = characters[next_index];
        switch (c2) {
          case '$':
            if (i > last) {
              // There is a substring before. Include the first "$".
              parts_.emplace_back(
                  ReplacementPart::ReplacementSubString(last, next_index));
              last = next_index + 1;  // Continue after the second "$".
            } else {
              // Let the next substring start with the second "$".
              last = next_index;
            }
            i = next_index;
            break;
          case '`':
            if (i > last) {
              parts_.emplace_back(
                  ReplacementPart::ReplacementSubString(last, i));
            }
            parts_.emplace_back(ReplacementPart::SubjectPrefix());
            i = next_index;
            last = i + 1;
            break;
          case '\'':
            if (i > last) {
              parts_.emplace_back(
                  ReplacementPart::ReplacementSubString(last, i));
            }
            parts_.emplace_back(ReplacementPart::SubjectSuffix(subject_length));
            i = next_index;
            last = i + 1;
            break;
          case '&':
            if (i > last) {
              parts_.emplace_back(
                  ReplacementPart::ReplacementSubString(last, i));
            }
            parts_.emplace_back(ReplacementPart::SubjectMatch());
            i = next_index;
            last = i + 1;
            break;
          case '0':
          case '1':
          case '2':
          case '3':
          case '4':
          case '5':
          case '6':
          case '7':
          case '8':
          case '9': {
            int capture_ref = c2 - '0';
            if (capture_ref > capture_count) {
              i = next_index;
              continue;
            }
            int second_digit_index = next_index + 1;
            if (second_digit_index < length) {
              // Peek ahead to see if we have two digits.
              Char c3 = characters[second_digit_index];
              if ('0' <= c3 && c3 <= '9') {  // Double digits.
                int double_digit_ref = capture_ref * 10 + c3 - '0';
                if (double_digit_ref <= capture_count) {
                  next_index = second_digit_index;
                  capture_ref = double_digit_ref;
                }
              }
            }
            if (capture_ref > 0) {
              if (i > last) {
                parts_.emplace_back(
                    ReplacementPart::ReplacementSubString(last, i));
              }
              DCHECK(capture_ref <= capture_count);
              parts_.emplace_back(ReplacementPart::SubjectCapture(capture_ref));
              last = next_index + 1;
            }
            i = next_index;
            break;
          }
          case '<': {
            if (capture_name_map.is_null()) {
              i = next_index;
              break;
            }

            // Scan until the next '>', and let the enclosed substring be the
            // groupName.

            const int name_start_index = next_index + 1;
            int closing_bracket_index = -1;
            for (int j = name_start_index; j < length; j++) {
              if (characters[j] == '>') {
                closing_bracket_index = j;
                break;
              }
            }

            // If no closing bracket is found, '$<' is treated as a string
            // literal.
            if (closing_bracket_index == -1) {
              i = next_index;
              break;
            }

            if (i > last) {
              parts_.emplace_back(
                  ReplacementPart::ReplacementSubString(last, i));
            }

            base::Vector<Char> requested_name =
                characters.SubVector(name_start_index, closing_bracket_index);

            // If capture is undefined or does not exist, replace the text
            // through the following '>' with the empty string.
            // Otherwise, replace the text through the following '>' with
            // ? ToString(capture).
            // For duplicated capture group names we don't know which of them
            // matches at this point in time, so we create a seperate
            // replacement for each possible match. When applying the
            // replacement unmatched groups will be skipped.

            int capture_index = 0;
            int capture_name_map_index = 0;
            while (capture_index != -1) {
              capture_index = LookupNamedCapture(
                  [=](Tagged<String> capture_name) {
                    return capture_name->IsEqualTo(requested_name);
                  },
                  capture_name_map, &capture_name_map_index);
              DCHECK(capture_index == -1 ||
                     (1 <= capture_index && capture_index <= capture_count));

              parts_.emplace_back(
                  capture_index == -1
                      ? ReplacementPart::EmptyReplacement()
                      : ReplacementPart::SubjectCapture(capture_index));
            }

            last = closing_bracket_index + 1;
            i = closing_bracket_index;
            break;
          }
          default:
            i = next_index;
            break;
        }
      }
    }
    if (length > last) {
      if (last == 0) {
        // Replacement is simple.  Do not use Apply to do the replacement.
        return true;
      } else {
        parts_.emplace_back(
            ReplacementPart::ReplacementSubString(last, length));
      }
    }
    return false;
  }

  base::SmallVector<ReplacementPart, kStaticVectorSlots> parts_;
  base::SmallVector<Handle<String>, kStaticVectorSlots> replacement_substrings_;
};

bool CompiledReplacement::Compile(Isolate* isolate,
                                  DirectHandle<JSRegExp> regexp,
                                  DirectHandle<RegExpData> regexp_data,
                                  Handle<String> replacement, int capture_count,
                                  int subject_length) {
  {
    DisallowGarbageCollection no_gc;
    String::FlatContent content = replacement->GetFlatContent(no_gc);
    DCHECK(content.IsFlat());

    Tagged<FixedArray> capture_name_map;
    if (capture_count > 0) {
      // capture_count > 0 implies IrRegExpData. Since capture_count is in
      // trusted space, this is not a SBXCHECK.
      DCHECK(Is<IrRegExpData>(*regexp_data));
      Tagged<IrRegExpData> re_data = Cast<IrRegExpData>(*regexp_data);

      Tagged<Object> maybe_capture_name_map = re_data->capture_name_map();
      if (IsFixedArray(maybe_capture_name_map)) {
        capture_name_map = Cast<FixedArray>(maybe_capture_name_map);
      }
    }

    bool simple;
    if (content.IsOneByte()) {
      simple =
          ParseReplacementPattern(content.ToOneByteVector(), capture_name_map,
                                  capture_count, subject_length);
    } else {
      DCHECK(content.IsTwoByte());
      simple = ParseReplacementPattern(content.ToUC16Vector(), capture_name_map,
                                       capture_count, subject_length);
    }
    if (simple) return true;
  }

  // Find substrings of replacement string and create them as String objects.
  int substring_index = 0;
  for (ReplacementPart& part : parts_) {
    int tag = part.tag;
    if (tag <= 0) {  // A replacement string slice.
      int from = -tag;
      int to = part.data;
      replacement_substrings_.emplace_back(
          isolate->factory()->NewSubString(replacement, from, to));
      part.tag = REPLACEMENT_SUBSTRING;
      part.data = substring_index;
      substring_index++;
    } else if (tag == REPLACEMENT_STRING) {
      replacement_substrings_.emplace_back(replacement);
      part.data = substring_index;
      substring_index++;
    }
  }
  return false;
}

void CompiledReplacement::Apply(ReplacementStringBuilder* builder,
                                int match_from, int match_to, int32_t* match) {
  DCHECK_LT(0, parts_.size());
  for (ReplacementPart& part : parts_) {
    switch (part.tag) {
      case SUBJECT_PREFIX:
        if (match_from > 0) builder->AddSubjectSlice(0, match_from);
        break;
      case SUBJECT_SUFFIX: {
        int subject_length = part.data;
        if (match_to < subject_length) {
          builder->AddSubjectSlice(match_to, subject_length);
        }
        break;
      }
      case SUBJECT_CAPTURE: {
        int capture = part.data;
        int from = match[capture * 2];
        int to = match[capture * 2 + 1];
        if (from >= 0 && to > from) {
          builder->AddSubjectSlice(from, to);
        }
        break;
      }
      case REPLACEMENT_SUBSTRING:
      case REPLACEMENT_STRING:
        builder->AddString(replacement_substrings_[part.data]);
        break;
      case EMPTY_REPLACEMENT:
        break;
      default:
        UNREACHABLE();
    }
  }
}

void FindOneByteStringIndices(base::Vector<const uint8_t> subject,
                              uint8_t pattern, std::vector<int>* indices,
                              unsigned int limit) {
  DCHECK_LT(0, limit);
  // Collect indices of pattern in subject using memchr.
  // Stop after finding at most limit values.
  const uint8_t* subject_start = subject.begin();
  const uint8_t* subject_end = subject_start + subject.length();
  const uint8_t* pos = subject_start;
  while (limit > 0) {
    pos = reinterpret_cast<const uint8_t*>(
        memchr(pos, pattern, subject_end - pos));
    if (pos == nullptr) return;
    indices->push_back(static_cast<int>(pos - subject_start));
    pos++;
    limit--;
  }
}

void FindTwoByteStringIndices(const base::Vector<const base::uc16> subject,
                              base::uc16 pattern, std::vector<int>* indices,
                              unsigned int limit) {
  DCHECK_LT(0, limit);
  const base::uc16* subject_start = subject.begin();
  const base::uc16* subject_end = subject_start + subject.length();
  for (const base::uc16* pos = subject_start; pos < subject_end && limit > 0;
       pos++) {
    if (*pos == pattern) {
      indices->push_back(static_cast<int>(pos - subject_start));
      limit--;
    }
  }
}

template <typename SubjectChar, typename PatternChar>
void FindStringIndices(Isolate* isolate,
                       base::Vector<const SubjectChar> subject,
                       base::Vector<const PatternChar> pattern,
                       std::vector<int>* indices, unsigned int limit) {
  DCHECK_LT(0, limit);
  // Collect indices of pattern in subject.
  // Stop after finding at most limit values.
  int pattern_length = pattern.length();
  int index = 0;
  StringSearch<PatternChar, SubjectChar> search(isolate, pattern);
  while (limit > 0) {
    index = search.Search(subject, index);
    if (index < 0) return;
    indices->push_back(index);
    index += pattern_length;
    limit--;
  }
}

void FindStringIndicesDispatch(Isolate* isolate, Tagged<String> subject,
                               Tagged<String> pattern,
                               std::vector<int>* indices, unsigned int limit) {
  {
    DisallowGarbageCollection no_gc;
    String::FlatContent subject_content = subject->GetFlatContent(no_gc);
    String::FlatContent pattern_content = pattern->GetFlatContent(no_gc);
    DCHECK(subject_content.IsFlat());
    DCHECK(pattern_content.IsFlat());
    if (subject_content.IsOneByte()) {
      base::Vector<const uint8_t> subject_vector =
          subject_content.ToOneByteVector();
      if (pattern_content.IsOneByte()) {
        base::Vector<const uint8_t> pattern_vector =
            pattern_content.ToOneByteVector();
        if (pattern_vector.length() == 1) {
          FindOneByteStringIndices(subject_vector, pattern_vector[0], indices,
                                   limit);
        } else {
          FindStringIndices(isolate, subject_vector, pattern_vector, indices,
                            limit);
        }
      } else {
        FindStringIndices(isolate, subject_vector,
                          pattern_content.ToUC16Vector(), indices, limit);
      }
    } else {
      base::Vector<const base::uc16> subject_vector =
          subject_content.ToUC16Vector();
      if (pattern_content.IsOneByte()) {
        base::Vector<const uint8_t> pattern_vector =
            pattern_content.ToOneByteVector();
        if (pattern_vector.length() == 1) {
          FindTwoByteStringIndices(subject_vector, pattern_vector[0], indices,
                                   limit);
        } else {
          FindStringIndices(isolate, subject_vector, pattern_vector, indices,
                            limit);
        }
      } else {
        base::Vector<const base::uc16> pattern_vector =
            pattern_content.ToUC16Vector();
        if (pattern_vector.length() == 1) {
          FindTwoByteStringIndices(subject_vector, pattern_vector[0], indices,
                                   limit);
        } else {
          FindStringIndices(isolate, subject_vector, pattern_vector, indices,
                            limit);
        }
      }
    }
  }
}

namespace {
std::vector<int>* GetRewoundRegexpIndicesList(Isolate* isolate) {
  std::vector<int>* list = isolate->regexp_indices();
  list->clear();
  return list;
}

void TruncateRegexpIndicesList(Isolate* isolate) {
  // Same size as smallest zone segment, preserving behavior from the
  // runtime zone.
  // TODO(jgruber): Consider removing the reusable regexp_indices list and
  // simply allocating a new list each time. It feels like we're needlessly
  // optimizing an edge case.
  static const int kMaxRegexpIndicesListCapacity = 8 * KB / kIntSize;
  std::vector<int>* indices = isolate->regexp_indices();
  if (indices->capacity() > kMaxRegexpIndicesListCapacity) {
    // Throw away backing storage.
    indices->clear();
    indices->shrink_to_fit();
  }
}
}  // namespace

template <typename ResultSeqString>
V8_WARN_UNUSED_RESULT static Tagged<Object>
StringReplaceGlobalAtomRegExpWithString(
    Isolate* isolate, DirectHandle<String> subject,
    DirectHandle<JSRegExp> pattern_regexp, DirectHandle<String> replacement,
    Handle<RegExpMatchInfo> last_match_info,
    DirectHandle<AtomRegExpData> regexp_data) {
  DCHECK(subject->IsFlat());
  DCHECK(replacement->IsFlat());

  std::vector<int>* indices = GetRewoundRegexpIndicesList(isolate);

  Tagged<String> pattern = regexp_data->pattern();
  int subject_len = subject->length();
  int pattern_len = pattern->length();
  int replacement_len = replacement->length();

  FindStringIndicesDispatch(isolate, *subject, pattern, indices, 0xFFFFFFFF);

  if (indices->empty()) return *subject;

  // Detect integer overflow.
  int64_t result_len_64 = (static_cast<int64_t>(replacement_len) -
                           static_cast<int64_t>(pattern_len)) *
                              static_cast<int64_t>(indices->size()) +
                          static_cast<int64_t>(subject_len);
  int result_len;
  if (result_len_64 > static_cast<int64_t>(String::kMaxLength)) {
    static_assert(String::kMaxLength < kMaxInt);
    result_len = kMaxInt;  // Provoke exception.
  } else {
    result_len = static_cast<int>(result_len_64);
  }
  if (result_len == 0) {
    return ReadOnlyRoots(isolate).empty_string();
  }

  int subject_pos = 0;
  int result_pos = 0;

  MaybeHandle<SeqString> maybe_res;
  if (ResultSeqString::kHasOneByteEncoding) {
    maybe_res = isolate->factory()->NewRawOneByteString(result_len);
  } else {
    maybe_res = isolate->factory()->NewRawTwoByteString(result_len);
  }
  Handle<SeqString> untyped_res;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, untyped_res, maybe_res);
  Handle<ResultSeqString> result = Cast<ResultSeqString>(untyped_res);

  DisallowGarbageCollection no_gc;
  for (int index : *indices) {
    // Copy non-matched subject content.
    if (subject_pos < index) {
      String::WriteToFlat(*subject, result->GetChars(no_gc) + result_pos,
                          subject_pos, index - subject_pos);
      result_pos += index - subject_pos;
    }

    // Replace match.
    if (replacement_len > 0) {
      String::WriteToFlat(*replacement, result->GetChars(no_gc) + result_pos, 0,
                          replacement_len);
      result_pos += replacement_len;
    }

    subject_pos = index + pattern_len;
  }
  // Add remaining subject content at the end.
  if (subject_pos < subject_len) {
    String::WriteToFlat(*subject, result->GetChars(no_gc) + result_pos,
                        subject_pos, subject_len - subject_pos);
  }

  int32_t match_indices[] = {indices->back(), indices->back() + pattern_len};
  RegExp::SetLastMatchInfo(isolate, last_match_info, subject, 0, match_indices);

  TruncateRegexpIndicesList(isolate);

  return *result;
}

V8_WARN_UNUSED_RESULT static Tagged<Object> StringReplaceGlobalRegExpWithString(
    Isolate* isolate, Handle<String> subject, DirectHandle<JSRegExp> regexp,
    DirectHandle<RegExpData> regexp_data, Handle<String> replacement,
    Handle<RegExpMatchInfo> last_match_info) {
  DCHECK(subject->IsFlat());
  DCHECK(replacement->IsFlat());

  int capture_count = regexp_data->capture_count();
  int subject_length = subject->length();

  // Ensure the RegExp is compiled so we can access the capture-name map.
  if (!RegExp::EnsureFullyCompiled(isolate, regexp_data, subject)) {
    return ReadOnlyRoots(isolate).exception();
  }

  CompiledReplacement compiled_replacement;
  const bool simple_replace = compiled_replacement.Compile(
      isolate, regexp, regexp_data, replacement, capture_count, subject_length);

  // Shortcut for simple non-regexp global replacements.
  if (regexp_data->type_tag() == RegExpData::Type::ATOM && simple_replace) {
    if (subject->IsOneByteRepresentation() &&
        replacement->IsOneByteRepresentation()) {
      return StringReplaceGlobalAtomRegExpWithString<SeqOneByteString>(
          isolate, subject, regexp, replacement, last_match_info,
          Cast<AtomRegExpData>(regexp_data));
    } else {
      return StringReplaceGlobalAtomRegExpWithString<SeqTwoByteString>(
          isolate, subject, regexp, replacement, last_match_info,
          Cast<AtomRegExpData>(regexp_data));
    }
  }

  RegExpGlobalExecRunner runner(handle(*regexp_data, isolate), subject,
                                isolate);
  if (runner.HasException()) return ReadOnlyRoots(isolate).exception();

  int32_t* current_match = runner.FetchNext();
  if (current_match == nullptr) {
    if (runner.HasException()) return ReadOnlyRoots(isolate).exception();
    return *subject;
  }

  // Guessing the number of parts that the final result string is built
  // from. Global regexps can match any number of times, so we guess
  // conservatively.
  int expected_parts = (compiled_replacement.parts() + 1) * 4 + 1;
  // TODO(v8:12843): improve the situation where the expected_parts exceeds
  // the maximum size of the backing store.
  ReplacementStringBuilder builder(isolate->heap(), subject, expected_parts);

  int prev = 0;

  do {
    int start = current_match[0];
    int end = current_match[1];

    if (prev < start) {
      builder.AddSubjectSlice(prev, start);
    }

    if (simple_replace) {
      builder.AddString(replacement);
    } else {
      compiled_replacement.Apply(&builder, start, end, current_match);
    }
    prev = end;

    current_match = runner.FetchNext();
  } while (current_match != nullptr);

  if (runner.HasException()) return ReadOnlyRoots(isolate).exception();

  if (prev < subject_length) {
    builder.AddSubjectSlice(prev, subject_length);
  }

  RegExp::SetLastMatchInfo(isolate, last_match_info, subject, capture_count,
                           runner.LastSuccessfulMatch());

  RETURN_RESULT_OR_FAILURE(isolate, builder.ToString());
}

template <typename ResultSeqString>
V8_WARN_UNUSED_RESULT static Tagged<Object>
StringReplaceGlobalRegExpWithEmptyString(
    Isolate* isolate, Handle<String> subject, DirectHandle<JSRegExp> regexp,
    DirectHandle<RegExpData> regexp_data,
    Handle<RegExpMatchInfo> last_match_info) {
  DCHECK(subject->IsFlat());

  // Shortcut for simple non-regexp global replacements.
  if (regexp_data->type_tag() == RegExpData::Type::ATOM) {
    DirectHandle<String> empty_string = isolate->factory()->empty_string();
    if (subject->IsOneByteRepresentation()) {
      return StringReplaceGlobalAtomRegExpWithString<SeqOneByteString>(
          isolate, subject, regexp, empty_string, last_match_info,
          Cast<AtomRegExpData>(regexp_data));
    } else {
      return StringReplaceGlobalAtomRegExpWithString<SeqTwoByteString>(
          isolate, subject, regexp, empty_string, last_match_info,
          Cast<AtomRegExpData>(regexp_data));
    }
  }

  RegExpGlobalExecRunner runner(handle(*regexp_data, isolate), subject,
                                isolate);
  if (runner.HasException()) return ReadOnlyRoots(isolate).exception();

  int32_t* current_match = runner.FetchNext();
  if (current_match == nullptr) {
    if (runner.HasException()) return ReadOnlyRoots(isolate).exception();
    return *subject;
  }

  int start = current_match[0];
  int end = current_match[1];
  int capture_count = regexp_data->capture_count();
  int subject_length = subject->length();

  int new_length = subject_length - (end - start);
  if (new_length == 0) return ReadOnlyRoots(isolate).empty_string();

  Handle<ResultSeqString> answer;
  if (ResultSeqString::kHasOneByteEncoding) {
    answer = Cast<ResultSeqString>(
        isolate->factory()->NewRawOneByteString(new_length).ToHandleChecked());
  } else {
    answer = Cast<ResultSeqString>(
        isolate->factory()->NewRawTwoByteString(new_length).ToHandleChecked());
  }

  int prev = 0;
  int position = 0;

  DisallowGarbageCollection no_gc;
  do {
    start = current_match[0];
    end = current_match[1];
    if (prev < start) {
      // Add substring subject[prev;start] to answer string.
      String::WriteToFlat(*subject, answer->GetChars(no_gc) + position, prev,
                          start - prev);
      position += start - prev;
    }
    prev = end;

    current_match = runner.FetchNext();
  } while (current_match != nullptr);

  if (runner.HasException()) return ReadOnlyRoots(isolate).exception();

  RegExp::SetLastMatchInfo(isolate, last_match_info, subject, capture_count,
                           runner.LastSuccessfulMatch());

  if (prev < subject_length) {
    // Add substring subject[prev;length] to answer string.
    String::WriteToFlat(*subject, answer->GetChars(no_gc) + position, prev,
                        subject_length - prev);
    position += subject_length - prev;
  }

  if (position == 0) return ReadOnlyRoots(isolate).empty_string();

  // Shorten string and fill
  int string_size = ResultSeqString::SizeFor(position);
  int allocated_string_size = ResultSeqString::SizeFor(new_length);
  int delta = allocated_string_size - string_size;

  answer->set_length(position);
  if (delta == 0) return *answer;

  Address end_of_string = answer->address() + string_size;
  Heap* heap = isolate->heap();

  // The trimming is performed on a newly allocated object, which is on a
  // freshly allocated page or on an already swept page. Hence, the sweeper
  // thread can not get confused with the filler creation. No synchronization
  // needed.
  // TODO(hpayer): We should shrink the large object page if the size
  // of the object changed significantly.
  if (!heap->IsLargeObject(*answer)) {
    heap->CreateFillerObjectAt(end_of_string, delta);
  }
  return *answer;
}

RUNTIME_FUNCTION(Runtime_StringSplit) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<String> subject = args.at<String>(0);
  Handle<String> pattern = args.at<String>(1);
  uint32_t limit = NumberToUint32(args[2]);
  CHECK_LT(0, limit);

  int subject_length = subject->length();
  int pattern_length = pattern->length();
  CHECK_LT(0, pattern_length);

  if (limit == 0xFFFFFFFFu) {
    Tagged<FixedArray> last_match_cache_unused;
    Handle<Object> cached_answer(
        RegExpResultsCache::Lookup(isolate->heap(), *subject, *pattern,
                                   &last_match_cache_unused,
                                   RegExpResultsCache::STRING_SPLIT_SUBSTRINGS),
        isolate);
    if (*cached_answer != Smi::zero()) {
      // The cache FixedArray is a COW-array and can therefore be reused.
      DirectHandle<JSArray> result = isolate->factory()->NewJSArrayWithElements(
          Cast<FixedArray>(cached_answer));
      return *result;
    }
  }

  // The limit can be very large (0xFFFFFFFFu), but since the pattern
  // isn't empty, we can never create more parts than ~half the length
  // of the subject.

  subject = String::Flatten(isolate, subject);
  pattern = String::Flatten(isolate, pattern);

  std::vector<int>* indices = GetRewoundRegexpIndicesList(isolate);

  FindStringIndicesDispatch(isolate, *subject, *pattern, indices, limit);

  if (static_cast<uint32_t>(indices->size()) < limit) {
    indices->push_back(subject_length);
  }

  // The list indices now contains the end of each part to create.

  // Create JSArray of substrings separated by separator.
  int part_count = static_cast<int>(indices->size());

  DirectHandle<JSArray> result = isolate->factory()->NewJSArray(
      PACKED_ELEMENTS, part_count, part_count,
      ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);

  DCHECK(result->HasObjectElements());

  DirectHandle<FixedArray> elements(Cast<FixedArray>(result->elements()),
                                    isolate);

  if (part_count == 1 && indices->at(0) == subject_length) {
    elements->set(0, *subject);
  } else {
    int part_start = 0;
    FOR_WITH_HANDLE_SCOPE(isolate, int, i = 0, i, i < part_count, i++, {
      int part_end = indices->at(i);
      DirectHandle<String> substring =
          isolate->factory()->NewProperSubString(subject, part_start, part_end);
      elements->set(i, *substring);
      part_start = part_end + pattern_length;
    });
  }

  if (limit == 0xFFFFFFFFu) {
    if (result->HasObjectElements()) {
      RegExpResultsCache::Enter(isolate, subject, pattern, elements,
                                isolate->factory()->empty_fixed_array(),
                                RegExpResultsCache:
```