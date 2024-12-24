Response: My goal is to summarize the functionality of the provided C++ code snippet, which is part 1 of a larger file (`v8/src/runtime/runtime-regexp.cc`). I also need to illustrate its relationship with JavaScript functionalities using examples.

Here's my thought process:

1. **Identify the Core Purpose:** The file name itself, `runtime-regexp.cc`, strongly suggests that this code deals with regular expression (RegExp) operations within the V8 JavaScript engine's runtime environment.

2. **Scan for Key Data Structures and Classes:**  I looked for prominent class definitions. `CompiledReplacement` stands out. This class seems responsible for pre-processing replacement strings used in `String.prototype.replace()`. It parses the replacement pattern and identifies different parts (literal strings, captured groups, etc.) for efficient application later.

3. **Identify Key Functions and Operations:** I searched for function definitions and their names, especially those interacting with JavaScript concepts:
    * Functions starting with `Runtime_` are likely runtime functions callable from JavaScript. `Runtime_StringSplit`, `Runtime_RegExpExec`, `Runtime_RegExpReplace`, and `Runtime_RegExpExecMultiple` are prominent examples.
    * Functions related to finding string indices (`FindOneByteStringIndices`, `FindTwoByteStringIndices`, `FindStringIndices`, `FindStringIndicesDispatch`) are likely used in operations like `String.prototype.split()` and global `String.prototype.replace()`.
    * Functions related to match information (`RegExp::SetLastMatchInfo`) suggest interactions with storing and retrieving details about the most recent regular expression match.

4. **Analyze `CompiledReplacement` in Detail:** The `Compile` method's logic for parsing replacement strings (handling `$`, `&`, numbered captures, named captures) directly relates to how replacement strings work in JavaScript's `replace()` method. The `Apply` method indicates how these pre-parsed parts are used to construct the final replaced string.

5. **Connect C++ Code to JavaScript Functionality:** This is the crucial step. For each identified key function/operation, I tried to connect it to its corresponding JavaScript counterpart:
    * `CompiledReplacement`: Directly linked to the replacement string functionality in `String.prototype.replace()`.
    * `Runtime_StringSplit`:  Handles the logic for `String.prototype.split()`. The code iterates and finds split points based on the provided separator (which can be a regular expression).
    * `Runtime_RegExpExec`: Implements the core regular expression execution logic, likely used by methods like `RegExp.prototype.exec()` and when a RegExp is used with string methods.
    * `Runtime_RegExpReplace`:  Handles the `String.prototype.replace()` functionality, especially when a regular expression is used as the pattern. It differentiates between global and non-global replacements.
    * `Runtime_RegExpExecMultiple`:  Appears to be a helper for global replace operations, collecting multiple matches.
    * Index finding functions: Used internally by `String.prototype.split()` and global `String.prototype.replace()` to locate matches.

6. **Illustrate with JavaScript Examples:** For each connection made in the previous step, I constructed concise JavaScript examples demonstrating the behavior. This makes the relationship between the C++ code and JavaScript clear.

7. **Structure the Summary:** I organized the information into a coherent structure:
    * A general statement about the file's purpose.
    * Key functionalities grouped logically.
    * Detailed explanation of `CompiledReplacement` and its relevance to `replace()`.
    * Breakdown of runtime functions and their corresponding JavaScript methods, accompanied by examples.

8. **Review and Refine:** I reread the code and my summary to ensure accuracy and clarity. I checked that the JavaScript examples accurately reflect the described C++ functionality. I also made sure to mention any internal data structures or helpers used.

By following this process, I could systematically break down the C++ code and connect its intricate implementation details to the more abstract and user-facing features of JavaScript regular expressions. The focus was on identifying the core responsibilities and illustrating them with practical JavaScript use cases.
这个C++源代码文件 `v8/src/runtime/runtime-regexp.cc` 的主要功能是 **实现了 V8 JavaScript 引擎中与正则表达式相关的运行时（runtime）函数**。 这些运行时函数是 JavaScript 代码在执行过程中，需要调用 V8 引擎底层 C++ 代码来完成特定正则表达式操作的接口。

具体来说，从代码片段中可以看出，它涵盖了以下几个方面的功能：

1. **正则表达式替换 (`String.prototype.replace`) 的实现:**
   - 实现了使用字符串或函数作为替换值的全局和非全局替换逻辑。
   - 包含了 `CompiledReplacement` 类，用于编译和优化替换模式，特别是处理包含特殊字符（如 `$`, `&`, 反向引用等）的替换字符串。
   - 针对简单的全局替换场景（使用字面量字符串替换），进行了优化，例如 `StringReplaceGlobalAtomRegExpWithString` 函数。

2. **正则表达式分割 (`String.prototype.split`) 的实现:**
   - `Runtime_StringSplit` 函数实现了 `String.prototype.split()` 方法，根据提供的分隔符（可以是字符串或正则表达式）将字符串分割成数组。
   - 内部使用了 `FindStringIndicesDispatch` 等函数来查找分隔符的位置。
   - 考虑了 `limit` 参数，用于限制返回数组的大小。
   - 实现了结果缓存，以提高性能。

3. **正则表达式执行 (`RegExp.prototype.exec` 和相关操作) 的实现:**
   - `Runtime_RegExpExec` 函数实现了 `RegExp.prototype.exec()` 方法的核心逻辑，用于在字符串中执行正则表达式匹配，并返回匹配结果的相关信息（如匹配起始位置和捕获组信息）。
   - `Runtime_RegExpGrowRegExpMatchInfo` 用于动态扩展存储匹配信息的 `RegExpMatchInfo` 对象。
   - `Runtime_RegExpExperimentalOneshotExec` 可能是用于实验性的、更高效的单次匹配执行。
   - `Runtime_RegExpBuildIndices` 用于构建包含捕获组起始和结束索引信息的对象，这是 `RegExp.prototype.exec()` 返回结果的一部分，特别是当正则表达式带有 `d` (indices) flag 时。

4. **辅助函数和类:**
   - `CompiledReplacement` 类用于解析和编译替换字符串，使其能够高效地应用到匹配结果上。
   - `FindOneByteStringIndices`, `FindTwoByteStringIndices`, `FindStringIndices`, `FindStringIndicesDispatch` 等函数用于在字符串中查找子字符串的索引，这在 `split` 和 `replace` 的实现中被使用。
   - `RegExpGlobalExecRunner` 用于在全局匹配中迭代查找所有匹配项。

**与 JavaScript 功能的关系及举例说明:**

这个 C++ 文件中的函数直接支撑了 JavaScript 中 `String` 和 `RegExp` 对象的相关方法。

**1. `String.prototype.replace()`:**

```javascript
const str = 'hello world';
const newStr = str.replace('world', 'V8'); // 使用字符串替换
console.log(newStr); // 输出: hello V8

const str2 = 'The quick brown fox jumps over the lazy dog.';
const newStr2 = str2.replace(/the/gi, 'a'); // 使用正则表达式替换（全局，忽略大小写）
console.log(newStr2); // 输出: a quick brown fox jumps over a lazy dog.

const str3 = 'abc123def';
const newStr3 = str3.replace(/([a-z]+)(\d+)([a-z]+)/, '$3-$2-$1'); // 使用正则表达式和反向引用
console.log(newStr3); // 输出: def-123-abc

const str4 = 'abc';
const newStr4 = str4.replace(/a/, function(match, offset, string) {
  console.log('匹配到的字符串:', match); // 输出: 匹配到的字符串: a
  console.log('匹配到的位置:', offset); // 输出: 匹配到的位置: 0
  console.log('原始字符串:', string); // 输出: 原始字符串: abc
  return 'X';
});
console.log(newStr4); // 输出: Xbc
```

`CompiledReplacement` 类在处理类似 `$3-$2-$1` 这样的替换字符串时发挥作用，解析这些反向引用并将其应用到匹配的捕获组。`StringReplaceGlobalRegExpWithString` 和 `StringReplaceNonGlobalRegExpWithFunction` 等函数分别处理全局和非全局替换的逻辑。

**2. `String.prototype.split()`:**

```javascript
const str = 'apple,banana,orange';
const arr = str.split(',');
console.log(arr); // 输出: [ 'apple', 'banana', 'orange' ]

const str2 = 'one two three';
const arr2 = str2.split(/\s+/); // 使用正则表达式作为分隔符
console.log(arr2); // 输出: [ 'one', 'two', 'three' ]

const str3 = 'a-b-c-d';
const arr3 = str3.split('-', 2); // 使用 limit 参数
console.log(arr3); // 输出: [ 'a', 'b' ]
```

`Runtime_StringSplit` 函数负责实现这些分割逻辑，根据提供的分隔符（可以是字符串或正则表达式）找到分割点，并根据 `limit` 参数生成结果数组。

**3. `RegExp.prototype.exec()`:**

```javascript
const regex = /hello (\w+)/;
const str = 'hello world, hello V8';
let match = regex.exec(str);
console.log(match);
// 输出:
// [
//   'hello world',
//   'world',
//   index: 0,
//   input: 'hello world, hello V8',
//   groups: undefined
// ]

match = regex.exec(str); // 再次调用，因为 regex 不是全局的，所以从头开始匹配
console.log(match);
// 输出与上次相同

const globalRegex = /hello (\w+)/g;
let match2;
while ((match2 = globalRegex.exec(str)) !== null) {
  console.log(match2);
  console.log(`Found ${match2[0]} at ${match2.index}. Next starts at ${globalRegex.lastIndex}.`);
}
// 输出多次匹配结果
```

`Runtime_RegExpExec` 函数是 `regex.exec(str)` 的幕后功臣，它执行正则表达式的匹配，并将匹配到的字符串、捕获组、索引等信息存储在返回的数组中。

总而言之，`v8/src/runtime/runtime-regexp.cc` 是 V8 引擎中处理正则表达式操作的核心 C++ 代码，它为 JavaScript 开发者提供的正则表达式功能提供了底层的实现支持。这个文件中的代码效率和正确性直接影响着 JavaScript 中正则表达式相关操作的性能和行为。

Prompt: 
```
这是目录为v8/src/runtime/runtime-regexp.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
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
                                RegExpResultsCache::STRING_SPLIT_SUBSTRINGS);
    }
  }

  TruncateRegexpIndicesList(isolate);

  return *result;
}

namespace {

std::optional<int> RegExpExec(Isolate* isolate, DirectHandle<JSRegExp> regexp,
                              Handle<String> subject, int32_t index,
                              int32_t* result_offsets_vector,
                              uint32_t result_offsets_vector_length) {
  // Due to the way the JS calls are constructed this must be less than the
  // length of a string, i.e. it is always a Smi.  We check anyway for security.
  CHECK_LE(0, index);
  CHECK_GE(subject->length(), index);
  isolate->counters()->regexp_entry_runtime()->Increment();
  return RegExp::Exec(isolate, regexp, subject, index, result_offsets_vector,
                      result_offsets_vector_length);
}

std::optional<int> ExperimentalOneshotExec(
    Isolate* isolate, DirectHandle<JSRegExp> regexp,
    DirectHandle<String> subject, int32_t index, int32_t* result_offsets_vector,
    uint32_t result_offsets_vector_length) {
  CHECK_GE(result_offsets_vector_length,
           JSRegExp::RegistersForCaptureCount(
               regexp->data(isolate)->capture_count()));
  // Due to the way the JS calls are constructed this must be less than the
  // length of a string, i.e. it is always a Smi.  We check anyway for security.
  CHECK_LE(0, index);
  CHECK_GE(subject->length(), index);
  isolate->counters()->regexp_entry_runtime()->Increment();
  return RegExp::ExperimentalOneshotExec(isolate, regexp, subject, index,
                                         result_offsets_vector,
                                         result_offsets_vector_length);
}

}  // namespace

RUNTIME_FUNCTION(Runtime_RegExpExec) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  Handle<String> subject = args.at<String>(1);
  int32_t index = 0;
  CHECK(Object::ToInt32(args[2], &index));
  uint32_t result_offsets_vector_length = 0;
  CHECK(Object::ToUint32(args[3], &result_offsets_vector_length));

  // This untagged arg must be passed as an implicit arg.
  int32_t* result_offsets_vector = reinterpret_cast<int32_t*>(
      isolate->isolate_data()->regexp_exec_vector_argument());
  DCHECK_NOT_NULL(result_offsets_vector);

  std::optional<int> result =
      RegExpExec(isolate, regexp, subject, index, result_offsets_vector,
                 result_offsets_vector_length);
  DCHECK_EQ(!result, isolate->has_exception());
  if (!result) return ReadOnlyRoots(isolate).exception();
  return Smi::FromInt(result.value());
}

RUNTIME_FUNCTION(Runtime_RegExpGrowRegExpMatchInfo) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<RegExpMatchInfo> match_info = args.at<RegExpMatchInfo>(0);
  int32_t register_count;
  CHECK(Object::ToInt32(args[1], &register_count));

  // We never pass anything besides the global last_match_info.
  DCHECK_EQ(*match_info, *isolate->regexp_last_match_info());

  Handle<RegExpMatchInfo> result = RegExpMatchInfo::ReserveCaptures(
      isolate, match_info, JSRegExp::CaptureCountForRegisters(register_count));
  if (*result != *match_info) {
    isolate->native_context()->set_regexp_last_match_info(*result);
  }

  return *result;
}

RUNTIME_FUNCTION(Runtime_RegExpExperimentalOneshotExec) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  DirectHandle<String> subject = args.at<String>(1);
  int32_t index = 0;
  CHECK(Object::ToInt32(args[2], &index));
  uint32_t result_offsets_vector_length = 0;
  CHECK(Object::ToUint32(args[3], &result_offsets_vector_length));

  // This untagged arg must be passed as an implicit arg.
  int32_t* result_offsets_vector = reinterpret_cast<int32_t*>(
      isolate->isolate_data()->regexp_exec_vector_argument());
  DCHECK_NOT_NULL(result_offsets_vector);

  std::optional<int> result = ExperimentalOneshotExec(
      isolate, regexp, subject, index, result_offsets_vector,
      result_offsets_vector_length);
  DCHECK_EQ(!result, isolate->has_exception());
  if (!result) return ReadOnlyRoots(isolate).exception();
  return Smi::FromInt(result.value());
}

RUNTIME_FUNCTION(Runtime_RegExpBuildIndices) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  DirectHandle<RegExpMatchInfo> match_info = args.at<RegExpMatchInfo>(1);
  Handle<Object> maybe_names = args.at(2);
#ifdef DEBUG
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  DCHECK(regexp->flags() & JSRegExp::kHasIndices);
#endif

  return *JSRegExpResultIndices::BuildIndices(isolate, match_info, maybe_names);
}

namespace {

class MatchInfoBackedMatch : public String::Match {
 public:
  MatchInfoBackedMatch(Isolate* isolate, DirectHandle<JSRegExp> regexp,
                       DirectHandle<RegExpData> regexp_data,
                       Handle<String> subject,
                       Handle<RegExpMatchInfo> match_info)
      : isolate_(isolate), match_info_(match_info) {
    subject_ = String::Flatten(isolate, subject);

    if (RegExpData::TypeSupportsCaptures(regexp_data->type_tag())) {
      DCHECK(Is<IrRegExpData>(*regexp_data));
      Tagged<Object> o = Cast<IrRegExpData>(regexp_data)->capture_name_map();
      has_named_captures_ = IsFixedArray(o);
      if (has_named_captures_) {
        capture_name_map_ = handle(Cast<FixedArray>(o), isolate);
      }
    } else {
      has_named_captures_ = false;
    }
  }

  Handle<String> GetMatch() override {
    return RegExpUtils::GenericCaptureGetter(isolate_, match_info_, 0, nullptr);
  }

  Handle<String> GetPrefix() override {
    const int match_start = match_info_->capture(0);
    return isolate_->factory()->NewSubString(subject_, 0, match_start);
  }

  Handle<String> GetSuffix() override {
    const int match_end = match_info_->capture(1);
    return isolate_->factory()->NewSubString(subject_, match_end,
                                             subject_->length());
  }

  bool HasNamedCaptures() override { return has_named_captures_; }

  int CaptureCount() override {
    return match_info_->number_of_capture_registers() / 2;
  }

  MaybeHandle<String> GetCapture(int i, bool* capture_exists) override {
    Handle<Object> capture_obj = RegExpUtils::GenericCaptureGetter(
        isolate_, match_info_, i, capture_exists);
    return (*capture_exists) ? Object::ToString(isolate_, capture_obj)
                             : isolate_->factory()->empty_string();
  }

  MaybeHandle<String> GetNamedCapture(Handle<String> name,
                                      CaptureState* state) override {
    DCHECK(has_named_captures_);
    int capture_index = 0;
    int capture_name_map_index = 0;
    while (true) {
      capture_index = LookupNamedCapture(
          [=](Tagged<String> capture_name) {
            return capture_name->Equals(*name);
          },
          *capture_name_map_, &capture_name_map_index);
      if (capture_index == -1) {
        *state = UNMATCHED;
        return isolate_->factory()->empty_string();
      }
      if (RegExpUtils::IsMatchedCapture(*match_info_, capture_index)) {
        Handle<String> capture_value;
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate_, capture_value,
            Object::ToString(isolate_,
                             RegExpUtils::GenericCaptureGetter(
                                 isolate_, match_info_, capture_index)));
        *state = MATCHED;
        return capture_value;
      }
    }
  }

 private:
  Isolate* isolate_;
  Handle<String> subject_;
  Handle<RegExpMatchInfo> match_info_;

  bool has_named_captures_;
  Handle<FixedArray> capture_name_map_;
};

class VectorBackedMatch : public String::Match {
 public:
  VectorBackedMatch(Isolate* isolate, Handle<String> subject,
                    Handle<String> match, uint32_t match_position,
                    base::Vector<Handle<Object>> captures,
                    Handle<Object> groups_obj)
      : isolate_(isolate),
        match_(match),
        match_position_(match_position),
        captures_(captures) {
    subject_ = String::Flatten(isolate, subject);

    DCHECK(IsUndefined(*groups_obj, isolate) || IsJSReceiver(*groups_obj));
    has_named_captures_ = !IsUndefined(*groups_obj, isolate);
    if (has_named_captures_) groups_obj_ = Cast<JSReceiver>(groups_obj);
  }

  Handle<String> GetMatch() override { return match_; }

  Handle<String> GetPrefix() override {
    // match_position_ and match_ are user-controlled, hence we manually clamp
    // the index here.
    uint32_t end = std::min(subject_->length(), match_position_);
    return isolate_->factory()->NewSubString(subject_, 0, end);
  }

  Handle<String> GetSuffix() override {
    // match_position_ and match_ are user-controlled, hence we manually clamp
    // the index here.
    uint32_t start =
        std::min(subject_->length(), match_position_ + match_->length());
    return isolate_->factory()->NewSubString(subject_, start,
                                             subject_->length());
  }

  bool HasNamedCaptures() override { return has_named_captures_; }

  int CaptureCount() override { return captures_.length(); }

  MaybeHandle<String> GetCapture(int i, bool* capture_exists) override {
    Handle<Object> capture_obj = captures_[i];
    if (IsUndefined(*capture_obj, isolate_)) {
      *capture_exists = false;
      return isolate_->factory()->empty_string();
    }
    *capture_exists = true;
    return Object::ToString(isolate_, capture_obj);
  }

  MaybeHandle<String> GetNamedCapture(Handle<String> name,
                                      CaptureState* state) override {
    DCHECK(has_named_captures_);

    // Strings representing integer indices are not valid identifiers (and
    // therefore not valid capture names).
    {
      size_t unused;
      if (name->AsIntegerIndex(&unused)) {
        *state = UNMATCHED;
        return isolate_->factory()->empty_string();
      }
    }
    Handle<Object> capture_obj;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate_, capture_obj,
        Object::GetProperty(isolate_, groups_obj_, name));
    if (IsUndefined(*capture_obj, isolate_)) {
      *state = UNMATCHED;
      return isolate_->factory()->empty_string();
    } else {
      *state = MATCHED;
      return Object::ToString(isolate_, capture_obj);
    }
  }

 private:
  Isolate* isolate_;
  Handle<String> subject_;
  Handle<String> match_;
  const uint32_t match_position_;
  base::Vector<Handle<Object>> captures_;

  bool has_named_captures_;
  Handle<JSReceiver> groups_obj_;
};

// Create the groups object (see also the RegExp result creation in
// RegExpBuiltinsAssembler::ConstructNewResultFromMatchInfo).
// TODO(42203211): We cannot simply pass a std::function here, as the closure
// may contain direct handles and they cannot be stored off-stack.
template <typename FunctionType,
          typename = std::enable_if_t<std::is_function_v<Tagged<Object>(int)>>>
Handle<JSObject> ConstructNamedCaptureGroupsObject(
    Isolate* isolate, DirectHandle<FixedArray> capture_map,
    const FunctionType& f_get_capture) {
  Handle<JSObject> groups = isolate->factory()->NewJSObjectWithNullProto();

  const int named_capture_count = capture_map->length() >> 1;
  for (int i = 0; i < named_capture_count; i++) {
    const int name_ix = i * 2;
    const int index_ix = i * 2 + 1;

    Handle<String> capture_name(Cast<String>(capture_map->get(name_ix)),
                                isolate);
    const int capture_ix = Smi::ToInt(capture_map->get(index_ix));
    DCHECK_GE(capture_ix, 1);  // Explicit groups start at index 1.

    Handle<Object> capture_value(f_get_capture(capture_ix), isolate);
    DCHECK(IsUndefined(*capture_value, isolate) || IsString(*capture_value));

    LookupIterator it(isolate, groups, capture_name, groups,
                      LookupIterator::OWN_SKIP_INTERCEPTOR);
    if (it.IsFound()) {
      DCHECK(v8_flags.js_regexp_duplicate_named_groups);
      if (!IsUndefined(*capture_value, isolate)) {
        DCHECK(IsUndefined(*it.GetDataValue(), isolate));
        CHECK(Object::SetDataProperty(&it, capture_value).ToChecked());
      }
    } else {
      CHECK(Object::AddDataProperty(&it, capture_value, NONE,
                                    Just(ShouldThrow::kThrowOnError),
                                    StoreOrigin::kNamed)
                .IsJust());
    }
  }

  return groups;
}

// Only called from Runtime_RegExpExecMultiple so it doesn't need to maintain
// separate last match info.  See comment on that function.
template <bool has_capture>
static Tagged<Object> SearchRegExpMultiple(
    Isolate* isolate, Handle<String> subject, DirectHandle<JSRegExp> regexp,
    DirectHandle<RegExpData> regexp_data,
    Handle<RegExpMatchInfo> last_match_array) {
  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));
  DCHECK_NE(has_capture, regexp_data->capture_count() == 0);
  DCHECK_IMPLIES(has_capture, Is<IrRegExpData>(*regexp_data));
  DCHECK(subject->IsFlat());

  // Force tier up to native code for global replaces. The global replace is
  // implemented differently for native code and bytecode execution, where the
  // native code expects an array to store all the matches, and the bytecode
  // matches one at a time, so it's easier to tier-up to native code from the
  // start.
  if (v8_flags.regexp_tier_up &&
      regexp_data->type_tag() == RegExpData::Type::IRREGEXP) {
    Cast<IrRegExpData>(regexp_data)->MarkTierUpForNextExec();
    if (v8_flags.trace_regexp_tier_up) {
      PrintF("Forcing tier-up of JSRegExp object %p in SearchRegExpMultiple\n",
             reinterpret_cast<void*>(regexp->ptr()));
    }
  }

  int capture_count = regexp_data->capture_count();
  int subject_length = subject->length();

  static const int kMinLengthToCache = 0x1000;

  if (subject_length > kMinLengthToCache) {
    Tagged<FixedArray> last_match_cache;
    Tagged<Object> cached_answer = RegExpResultsCache::Lookup(
        isolate->heap(), *subject, regexp_data->wrapper(), &last_match_cache,
        RegExpResultsCache::REGEXP_MULTIPLE_INDICES);
    if (IsFixedArray(cached_answer)) {
      int capture_registers = JSRegExp::RegistersForCaptureCount(capture_count);
      std::unique_ptr<int32_t[]> last_match(new int32_t[capture_registers]);
      int32_t* raw_last_match = last_match.get();
      for (int i = 0; i < capture_registers; i++) {
        raw_last_match[i] = Smi::ToInt(last_match_cache->get(i));
      }
      DirectHandle<FixedArray> cached_fixed_array(
          Cast<FixedArray>(cached_answer), isolate);
      // The cache FixedArray is a COW-array and we need to return a copy.
      DirectHandle<FixedArray> copied_fixed_array =
          isolate->factory()->CopyFixedArrayWithMap(
              cached_fixed_array, isolate->factory()->fixed_array_map());
      RegExp::SetLastMatchInfo(isolate, last_match_array, subject,
                               capture_count, raw_last_match);
      return *copied_fixed_array;
    }
  }

  RegExpGlobalExecRunner runner(handle(*regexp_data, isolate), subject,
                                isolate);
  if (runner.HasException()) return ReadOnlyRoots(isolate).exception();

  FixedArrayBuilder builder = FixedArrayBuilder::Lazy(isolate);

  // Position to search from.
  int match_start = -1;
  int match_end = 0;
  bool first = true;

  // Two smis before and after the match, for very long strings.
  static const int kMaxBuilderEntriesPerRegExpMatch = 5;

  while (true) {
    int32_t* current_match = runner.FetchNext();
    if (current_match == nullptr) break;
    match_start = current_match[0];
    builder.EnsureCapacity(isolate, kMaxBuilderEntriesPerRegExpMatch);
    if (match_end < match_start) {
      ReplacementStringBuilder::AddSubjectSlice(&builder, match_end,
                                                match_start);
    }
    match_end = current_match[1];
    {
      // Avoid accumulating new handles inside loop.
      HandleScope temp_scope(isolate);
      DirectHandle<String> match;
      if (!first) {
        match = isolate->factory()->NewProperSubString(subject, match_start,
                                                       match_end);
      } else {
        match =
            isolate->factory()->NewSubString(subject, match_start, match_end);
        first = false;
      }

      if (has_capture) {
        // Arguments array to replace function is match, captures, index and
        // subject, i.e., 3 + capture count in total. If the RegExp contains
        // named captures, they are also passed as the last argument.

        // has_capture can only be true for IrRegExp.
        Tagged<IrRegExpData> re_data = Cast<IrRegExpData>(*regexp_data);
        Handle<Object> maybe_capture_map(re_data->capture_name_map(), isolate);
        const bool has_named_captures = IsFixedArray(*maybe_capture_map);

        const int argc =
            has_named_captures ? 4 + capture_count : 3 + capture_count;

        DirectHandle<FixedArray> elements =
            isolate->factory()->NewFixedArray(argc);
        int cursor = 0;

        elements->set(cursor++, *match);
        for (int i = 1; i <= capture_count; i++) {
          int start = current_match[i * 2];
          if (start >= 0) {
            int end = current_match[i * 2 + 1];
            DCHECK(start <= end);
            DirectHandle<String> substring =
                isolate->factory()->NewSubString(subject, start, end);
            elements->set(cursor++, *substring);
          } else {
            DCHECK_GT(0, current_match[i * 2 + 1]);
            elements->set(cursor++, ReadOnlyRoots(isolate).undefined_value());
          }
        }

        elements->set(cursor++, Smi::FromInt(match_start));
        elements->set(cursor++, *subject);

        if (has_named_captures) {
          Handle<FixedArray> capture_map = Cast<FixedArray>(maybe_capture_map);
          DirectHandle<JSObject> groups = ConstructNamedCaptureGroupsObject(
              isolate, capture_map, [=](int ix) { return elements->get(ix); });
          elements->set(cursor++, *groups);
        }

        DCHECK_EQ(cursor, argc);
        builder.Add(*isolate->factory()->NewJSArrayWithElements(elements));
      } else {
        builder.Add(*match);
      }
    }
  }

  if (runner.HasException()) return ReadOnlyRoots(isolate).exception();

  if (match_start >= 0) {
    // Finished matching, with at least one match.
    if (match_end < subject_length) {
      ReplacementStringBuilder::AddSubjectSlice(&builder, match_end,
                                                subject_length);
    }

    RegExp::SetLastMatchInfo(isolate, last_match_array, subject, capture_count,
                             runner.LastSuccessfulMatch());

    if (subject_length > kMinLengthToCache) {
      // Store the last successful match into the array for caching.
      int capture_registers = JSRegExp::RegistersForCaptureCount(capture_count);
      DirectHandle<FixedArray> last_match_cache =
          isolate->factory()->NewFixedArray(capture_registers);
      int32_t* last_match = runner.LastSuccessfulMatch();
      for (int i = 0; i < capture_registers; i++) {
        last_match_cache->set(i, Smi::FromInt(last_match[i]));
      }
      DirectHandle<FixedArray> result_fixed_array =
          FixedArray::RightTrimOrEmpty(
              isolate, indirect_handle(builder.array(), isolate),
              builder.length());
      // Cache the result and copy the FixedArray into a COW array.
      DirectHandle<FixedArray> copied_fixed_array =
          isolate->factory()->CopyFixedArrayWithMap(
              result_fixed_array, isolate->factory()->fixed_array_map());
      RegExpResultsCache::Enter(
          isolate, subject, handle(regexp->data(isolate)->wrapper(), isolate),
          copied_fixed_array, last_match_cache,
          RegExpResultsCache::REGEXP_MULTIPLE_INDICES);
    }
    return *builder.array();
  } else {
    return ReadOnlyRoots(isolate).null_value();  // No matches at all.
  }
}

// Legacy implementation of RegExp.prototype[Symbol.replace] which
// doesn't properly call the underlying exec method.
V8_WARN_UNUSED_RESULT MaybeHandle<String> RegExpReplace(
    Isolate* isolate, Handle<JSRegExp> regexp, Handle<String> string,
    Handle<String> replace) {
  // Functional fast-paths are dispatched directly by replace builtin.
  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));

  Factory* factory = isolate->factory();

  const int flags = regexp->flags();
  const bool global = (flags & JSRegExp::kGlobal) != 0;
  const bool sticky = (flags & JSRegExp::kSticky) != 0;

  replace = String::Flatten(isolate, replace);

  Handle<RegExpMatchInfo> last_match_info = isolate->regexp_last_match_info();
  DirectHandle<RegExpData> data = direct_handle(regexp->data(isolate), isolate);

  if (!global) {
    // Non-global regexp search, string replace.

    uint32_t last_index = 0;
    if (sticky) {
      Handle<Object> last_index_obj(regexp->last_index(), isolate);
      ASSIGN_RETURN_ON_EXCEPTION(isolate, last_index_obj,
                                 Object::ToLength(isolate, last_index_obj));
      last_index = PositiveNumberToUint32(*last_index_obj);
    }

    Handle<Object> match_indices_obj(ReadOnlyRoots(isolate).null_value(),
                                     isolate);

    // A lastIndex exceeding the string length always returns null (signalling
    // failure) in RegExpBuiltinExec, thus we can skip the call.
    if (last_index <= static_cast<uint32_t>(string->length())) {
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, match_indices_obj,
          RegExp::Exec_Single(isolate, regexp, string, last_index,
                              last_match_info));
    }

    if (IsNull(*match_indices_obj, isolate)) {
      if (sticky) regexp->set_last_index(Smi::zero(), SKIP_WRITE_BARRIER);
      return string;
    }

    auto match_indices = Cast<RegExpMatchInfo>(match_indices_obj);

    const int start_index = match_indices->capture(0);
    const int end_index = match_indices->capture(1);

    if (sticky) {
      regexp->set_last_index(Smi::FromInt(end_index), SKIP_WRITE_BARRIER);
    }

    IncrementalStringBuilder builder(isolate);
    builder.AppendString(factory->NewSubString(string, 0, start_index));

    if (replace->length() > 0) {
      MatchInfoBackedMatch m(isolate, regexp, data, string, match_indices);
      Handle<String> replacement;
      ASSIGN_RETURN_ON_EXCEPTION(isolate, replacement,
                                 String::GetSubstitution(isolate, &m, replace));
      builder.AppendString(replacement);
    }

    builder.AppendString(
        factory->NewSubString(string, end_index, string->length()));
    return indirect_handle(builder.Finish(), isolate);
  } else {
    // Global regexp search, string replace.
    DCHECK(global);
    RETURN_ON_EXCEPTION(isolate, RegExpUtils::SetLastIndex(isolate, regexp, 0));

    // Force tier up to native code for global replaces. The global replace is
    // implemented differently for native code and bytecode execution, where the
    // native code expects an array to store all the matches, and the bytecode
    // matches one at a time, so it's easier to tier-up to native code from the
    // start.
    if (v8_flags.regexp_tier_up &&
        data->type_tag() == RegExpData::Type::IRREGEXP) {
      Cast<IrRegExpData>(data)->MarkTierUpForNextExec();
      if (v8_flags.trace_regexp_tier_up) {
        PrintF("Forcing tier-up of JSRegExp object %p in RegExpReplace\n",
               reinterpret_cast<void*>(regexp->ptr()));
      }
    }

    if (replace->length() == 0) {
      if (string->IsOneByteRepresentation()) {
        Tagged<Object> result =
            StringReplaceGlobalRegExpWithEmptyString<SeqOneByteString>(
                isolate, string, regexp, data, last_match_info);
        return handle(Cast<String>(result), isolate);
      } else {
        Tagged<Object> result =
            StringReplaceGlobalRegExpWithEmptyString<SeqTwoByteString>(
                isolate, string, regexp, data, last_match_info);
        return handle(Cast<String>(result), isolate);
      }
    }

    Tagged<Object> result = StringReplaceGlobalRegExpWithString(
        isolate, string, regexp, data, replace, last_match_info);
    if (IsString(result)) {
      return handle(Cast<String>(result), isolate);
    } else {
      return MaybeHandle<String>();
    }
  }

  UNREACHABLE();
}

}  // namespace

// This is only called for StringReplaceGlobalRegExpWithFunction.
RUNTIME_FUNCTION(Runtime_RegExpExecMultiple) {
  HandleScope handles(isolate);
  DCHECK_EQ(3, args.length());

  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  Handle<String> subject = args.at<String>(1);
  Handle<RegExpMatchInfo> last_match_info = args.at<RegExpMatchInfo>(2);

  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));
  DirectHandle<RegExpData> regexp_data =
      direct_handle(regexp->data(isolate), isolate);

  subject = String::Flatten(isolate, subject);
  CHECK(regexp->flags() & JSRegExp::kGlobal);

  Tagged<Object> result;
  if (regexp_data->capture_count() == 0) {
    result = SearchRegExpMultiple<false>(isolate, subject, regexp, regexp_data,
                                         last_match_info);
  } else {
    result = SearchRegExpMultiple<true>(isolate, subject, regexp, regexp_data,
                                        last_match_info);
  }
  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));
  return result;
}

RUNTIME_FUNCTION(Runtime_StringReplaceNonGlobalRegExpWithFunction) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<String> subject = args.at<String>(0);
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(1);
  Handle<JSReceiver> replace_obj = args.at<JSReceiver>(2);

  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));
  DCHECK(replace_obj->map()->is_callable());

  Factory* factory = isolate->factory();
  Handle<RegExpMatchInfo> last_match_info = isolate->regexp_last_match_info();
  DirectHandle<RegExpData> data = direct_handle(regexp->data(isolate), isolate);

  const int flags = regexp->flags();
  DCHECK_EQ(flags & JSRegExp::kGlobal, 0);

  // TODO(jgruber): This should be an easy port to CSA with massive payback.

  const bool sticky = (flags & JSRegExp::kSticky) != 0;
  uint32_t last_index = 0;
  if (sticky) {
    Handle<Object> last_index_obj(regexp->last_index(), isolate);
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, last_index_obj, Object::ToLength(isolate, last_index_obj));
    last_index = PositiveNumberToUint32(*last_index_obj);
  }

  Handle<Object> match_indices_obj(ReadOnlyRoots(isolate).null_value(),
                                   isolate);

  // A lastIndex exceeding the string length always returns null (signalling
  // failure) in RegExpBuiltinExec, thus we can skip the call.
  if (last_index <= static_cast<uint32_t>(subject->length())) {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, match_indices_obj,
        RegExp::Exec_Single(isolate, regexp, subject, last_index,
                            last_match_info));
  }

  if (IsNull(*match_indices_obj, isolate)) {
    if (sticky) regexp->set_last_index(Smi::zero(), SKIP_WRITE_BARRIER);
    return *subject;
  }

  auto match_indices = Cast<RegExpMatchInfo>(match_indices_obj);

  const int index = match_indices->capture(0);
  const int end_of_match = match_indices->capture(1);

  if (sticky) {
    regexp->set_last_index(Smi::FromInt(end_of_match), SKIP_WRITE_BARRIER);
  }

  IncrementalStringBuilder builder(isolate);
  builder.AppendString(factory->NewSubString(subject, 0, index));

  // Compute the parameter list consisting of the match, captures, index,
  // and subject for the replace function invocation. If the RegExp contains
  // named captures, they are also passed as the last argument.

  // The number of captures plus one for the match.
  const int m = match_indices->number_of_capture_registers() / 2;

  bool has_named_captures = false;
  DirectHandle<FixedArray> capture_map;
  if (m > 1) {
    SBXCHECK(Is<IrRegExpData>(*data));

    Tagged<Object> maybe_capture_map =
        Cast<IrRegExpData>(data)->capture_name_map();
    if (IsFixedArray(maybe_capture_map)) {
      has_named_captures = true;
      capture_map = direct_handle(Cast<FixedArray>(maybe_capture_map), isolate);
    }
  }

  const uint32_t argc = GetArgcForReplaceCallable(m, has_named_captures);
  if (argc == static_cast<uint32_t>(-1)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kTooManyArguments));
  }
  // TODO(42203211): This vector ends up in InvokeParams which is potentially
  // used by generated code. It will be replaced, when generated code starts
  // using direct handles.
  base::ScopedVector<IndirectHandle<Object>> argv(argc);

  int cursor = 0;
  for (int j = 0; j < m; j++) {
    bool ok;
    Handle<String> capture =
        RegExpUtils::GenericCaptureGetter(isolate, match_indices, j, &ok);
    if (ok) {
      argv[cursor++] = capture;
    } else {
      argv[cursor++] = factory->undefined_value();
    }
  }

  argv[cursor++] = handle(Smi::FromInt(index), isolate);
  argv[cursor++] = subject;

  if (has_named_captures) {
    argv[cursor++] = ConstructNamedCaptureGroupsObject(
        isolate, capture_map, [&argv](int ix) { return *argv[ix]; });
  }

  DCHECK_EQ(cursor, argc);

  Handle<Object> replacement_obj;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, replacement_obj,
      Execution::Call(isolate, replace_obj, factory->undefined_value(), argc,
                      argv.begin()));

  Handle<String> replacement;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, replacement, Object::ToString(isolate, replacement_obj));

  builder.AppendString(replacement);
  builder.AppendString(
      factory->NewSubString(subject, end_of_match, subject->length()));

  RETURN_RESULT_OR_FAILURE(isolate, builder.Finish());
}

namespace {

V8_WARN_UNUSED_RESULT MaybeHandle<Object> ToUint32(Isolate* isolate,
                                                   Handle<Object> object,
                                                   uint32_t* out) {
  if (IsUndefined(*object, isolate)) {
    *out = kMaxUInt32;
    return object;
  }

  Handle<Object> number;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, number,
                             Object::ToNumber(isolate, object));
  *out = NumberToUint32(*number);
  return object;
}

Handle<JSArray> NewJSArrayWithElements(Isolate* isolate,
                                       Handle<FixedArray> elems,
                                       int num_elems) {
  return isolate->factory()->NewJSArrayWithElements(
      FixedArray::RightTrimOrEmpty(isolate, elems, num_elems));
}

}  // namespace

// Slow path for:
// ES#sec-regexp.prototype-@@replace
// RegExp.prototype [ @@split ] ( string, limit )
RUNTIME_FUNCTION(Runtime_RegExpSplit) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  Handle<JSReceiver> recv = args.at<JSReceiver>(0);
  Handle<String> string = args.at<String>(1);
  Handle<Object> limit_obj = args.at(2);

  Factory* factory = isolate->factory();

  Handle<JSFunction> regexp_fun = isolate->regexp_function();
  Handle<Object> ctor;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, ctor, Object::SpeciesConstructor(isolate, recv, regexp_fun));

  Handle<Object> flags_obj;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, flags_obj,
      JSObject::GetProperty(isolate, recv, factory->flags_string()));

  Handle<String> flags;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, flags,
                                     Object::ToString(isolate, flags_obj));

  Handle<String> u_str = factory->LookupSingleCharacterStringFromCode('u');
  const bool unicode = (String::IndexOf(isolate, flags, u_str, 0) >= 0);

  Handle<String> y_str = factory->LookupSingleCharacterStringFromCode('y');
  const bool sticky = (String::IndexOf(isolate, flags, y_str, 0) >= 0);

  Handle<String> new_flags = flags;
  if (!sticky) {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, new_flags,
                                       factory->NewConsString(flags, y_str));
  }

  Handle<JSReceiver> splitter;
  {
    constexpr int argc = 2;
    std::array<Handle<Object>, argc> argv = {recv, new_flags};

    Handle<Object> splitter_obj;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, splitter_obj,
        Execution::New(isolate, ctor, argc, argv.data()));

    splitter = Cast<JSReceiver>(splitter_obj);
  }

  uint32_t limit;
  RETURN_FAILURE_ON_EXCEPTION(isolate, ToUint32(isolate, limit_obj, &limit));

  const uint32_t length = string->length();

  if (limit == 0) return *factory->NewJSArray(0);

  if (length == 0) {
    Handle<Object> result;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        is
"""


```