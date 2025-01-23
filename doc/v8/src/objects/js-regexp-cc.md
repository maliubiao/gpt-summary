Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Understanding the Goal:** The request asks for a functional description of `v8/src/objects/js-regexp.cc`, specifically focusing on its relation to JavaScript Regular Expressions. It also wants examples, logic, and common errors.

2. **Initial Scan and Keywords:**  I first skimmed the code looking for obvious keywords and patterns. Things that jumped out were:
    * `JSRegExp`: This strongly suggests the code deals with the internal representation of JavaScript Regular Expression objects within V8.
    * `Flags`:  Likely related to RegExp flags (g, i, m, etc.).
    * `BuildIndices`:  Suggests creation of indices for capturing groups.
    * `RegExpMatchInfo`:  This hints at the data structure holding the results of a RegExp match.
    * `Compile`:  Indicates the compilation process of a RegExp.
    * `EscapeRegExpSource`: Suggests handling special characters in the RegExp source.
    * `TierUpTick`, `MarkedForTierUp`:  These are related to optimization and compilation tiers.

3. **High-Level Functionality - Core Purpose:**  Based on the keywords, I concluded the primary purpose of this file is to manage the internal structure and lifecycle of JavaScript RegExp objects. This includes:
    * Creating and initializing `JSRegExp` objects.
    * Handling RegExp flags.
    * Storing compiled RegExp code.
    * Managing capturing group information.
    * Implementing optimization strategies (tiering up).

4. **Detailed Function Analysis (Section by Section):** I went through the code section by section, function by function, to understand the specific actions.

    * **`JSRegExpResultIndices::BuildIndices`:** This function clearly constructs an object (`JSRegExpResultIndices`) that holds information about the indices of captured groups in a RegExp match. The nested arrays representing start and end offsets are key here. The handling of named capture groups using dictionaries (`PropertyDictionary`) is also important.

    * **`JSRegExp::FlagsFromString` and `JSRegExp::StringFromFlags`:** These handle the conversion between string representations of flags (e.g., "gi") and the internal `Flags` enum/bitmask. The error handling for invalid or duplicate flags is noted.

    * **`JSRegExp::New` and `JSRegExp::Initialize`:** These are responsible for creating new `JSRegExp` objects and setting their initial properties (source, flags, compiled code). The handling of the empty string case is interesting.

    * **`EscapeRegExpSource`:**  This function deals with escaping special characters within the RegExp source string to ensure it's a valid and correctly interpreted RegExp pattern. The different handling for one-byte and two-byte strings is a V8 optimization detail.

    * **`RegExpData`, `IrRegExpData`:** These structs and their associated methods handle the storage and management of the compiled RegExp code. The "tier-up" mechanism is the main focus here, which is an optimization technique to re-compile frequently used RegExp with more aggressive optimizations.

5. **Connecting to JavaScript:**  After understanding the internal workings, I linked it back to the JavaScript API. The functions relate directly to:
    * Creating RegExp objects (`new RegExp(...)`).
    * Accessing RegExp properties (`.flags`, `.source`).
    * The results of `String.prototype.match()`, `String.prototype.exec()`, and `String.prototype.matchAll()`, particularly the indices and named groups properties of the result.

6. **JavaScript Examples:** I crafted simple JavaScript examples to demonstrate the functionality of the C++ code. The examples focus on:
    * Creating RegExp with flags.
    * Using capturing groups and accessing the `indices` property.
    * Showing named capture groups.
    * Illustrating the need for escaping special characters.

7. **Logic and Input/Output:**  For `BuildIndices`, I devised a concrete example with a RegExp and a sample match result to illustrate how the indices are constructed.

8. **Common Programming Errors:** I considered common mistakes developers make with regular expressions, such as:
    * Forgetting to escape special characters.
    * Incorrectly assuming the structure of the match result's `indices` property.
    * Not understanding how named capture groups are accessed.

9. **Torque Check:**  I explicitly checked for the `.tq` extension as requested.

10. **Refinement and Organization:** Finally, I organized the information into clear sections, using headings and bullet points for readability. I reviewed the examples and explanations to ensure they were accurate and easy to understand. I made sure to address all the specific points in the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:** I initially focused heavily on the compilation aspect. I then realized the `BuildIndices` function is equally important for understanding the interaction with JavaScript match results.
* **Example Clarity:**  My first JavaScript example for `BuildIndices` was too basic. I expanded it to include accessing the nested index arrays.
* **Error Emphasis:** I initially just mentioned escaping. I then realized the importance of explicitly showing *what happens* when you don't escape.
* **Torque Check Placement:** I initially had the Torque check buried in the text. I brought it to the beginning to directly address that part of the prompt.

By following these steps and continuously refining my understanding, I arrived at the comprehensive answer provided previously.
好的，让我们来分析一下 `v8/src/objects/js-regexp.cc` 这个 V8 源代码文件的功能。

**文件功能概览**

`v8/src/objects/js-regexp.cc` 文件主要负责定义和实现 JavaScript `RegExp` 对象在 V8 引擎中的内部表示和相关操作。  它涉及到以下核心功能：

1. **`JSRegExp` 对象的创建和初始化:**  该文件包含了创建 `JSRegExp` 对象的函数，这些对象是 JavaScript 中 `RegExp` 类型的内部表示。初始化过程包括解析正则表达式模式、处理标志（flags）以及编译正则表达式。

2. **正则表达式标志（Flags）的处理:**  提供了将字符串形式的正则表达式标志（如 "gim"）转换为内部表示，以及将内部表示转换回字符串的方法。

3. **正则表达式编译:**  调用底层的正则表达式引擎（`src/regexp/regexp.h`）来编译正则表达式模式。

4. **正则表达式匹配结果索引的构建 (`JSRegExpResultIndices`):**  当正则表达式执行匹配操作后，此文件中的代码负责构建一个包含捕获组索引信息的对象。这包括每个捕获组的起始和结束位置，以及命名捕获组的处理。

5. **处理需要转义的正则表达式源字符串:**  提供了一种机制来转义正则表达式源字符串中的特殊字符，以便在内部存储和使用。

6. **正则表达式优化的相关逻辑 (Tier-Up):** 包含了与正则表达式优化相关的代码，例如 `IrRegExpData` 中的 `TierUpTick` 和 `MarkedForTierUp`，这涉及到将常用的正则表达式重新编译成更高效的代码。

**关于 .tq 结尾**

如果 `v8/src/objects/js-regexp.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**文件。 Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码。虽然当前给出的文件名是 `.cc`，但如果存在 `.tq` 版本，其功能会与 `.cc` 版本类似，但实现方式是通过 Torque 定义，然后生成 C++ 代码。

**与 JavaScript 功能的关系及举例**

`v8/src/objects/js-regexp.cc` 文件直接关联着 JavaScript 中 `RegExp` 对象的功能。以下是一些 JavaScript 例子，展示了该文件中代码所支持的功能：

```javascript
// 创建 RegExp 对象，对应 JSRegExp 的创建和初始化
const regex1 = new RegExp("ab+c");
const regex2 = /ab+c/g; // 带有 'g' 标志

// 获取正则表达式的标志，对应 JSRegExp::StringFromFlags
console.log(regex2.flags); // 输出 "g"

// 获取正则表达式的源字符串，对应 JSRegExp 的 source 属性
console.log(regex1.source); // 输出 "ab+c"

// 执行正则表达式匹配，对应 JSRegExpResultIndices 的构建
const str = 'cdabbbbbC';
const result = regex2.exec(str);
console.log(result); // 输出匹配结果，包含捕获组信息和索引

// 使用命名捕获组 (需要引擎支持)，对应 JSRegExpResultIndices 中 groups 的处理
const regex3 = /(?<name>ab+)c/;
const result3 = regex3.exec('abbc');
console.log(result3.groups); // 输出 { name: 'abb' }
console.log(result3.indices.groups); // 输出 { name: [0, 3] }
```

**代码逻辑推理及假设输入输出**

让我们聚焦在 `JSRegExpResultIndices::BuildIndices` 这个函数上进行逻辑推理。

**假设输入：**

* `isolate`: 当前 V8 引擎的隔离区。
* `match_info`: 一个 `RegExpMatchInfo` 对象，包含了正则表达式匹配的结果信息。假设它表示字符串 "test123test" 中正则表达式 `(test)(\d+)` 的匹配结果。
    * 捕获组数量：2
    * 捕获组 1 的起始位置：0，结束位置：4
    * 捕获组 2 的起始位置：4，结束位置：7
* `maybe_names`: 一个 `FixedArray`，如果正则表达式包含命名捕获组，则包含名称和索引的对应关系。假设这里没有命名捕获组，所以它是 `undefined`。

**代码逻辑：**

1. 创建一个新的 `JSRegExpResultIndices` 对象。
2. 根据 `match_info` 中的捕获组数量，创建一个 `FixedArray` 用于存储索引信息。
3. 遍历每个捕获组：
   - 获取捕获组的起始和结束偏移量。
   - 如果偏移量为 -1，表示该捕获组未匹配，则将对应索引设置为 `undefined`。
   - 否则，创建一个包含起始和结束偏移量的子数组，并将其设置为索引数组的对应位置。
4. 由于 `maybe_names` 是 `undefined`，跳过命名捕获组的处理。
5. 返回构建好的 `JSRegExpResultIndices` 对象。

**预期输出：**

一个 `JSRegExpResultIndices` 对象，其内部结构大致如下：

```
{
  length: 2, // 捕获组的数量
  0: [0, 4], // 第一个捕获组 "test" 的起始和结束索引
  1: [4, 7], // 第二个捕获组 "123" 的起始和结束索引
  groups: undefined // 没有命名捕获组
}
```

**涉及用户常见的编程错误**

1. **忘记转义正则表达式中的特殊字符：**

   ```javascript
   // 错误示例：尝试匹配字符串 "a.b"
   const regex = new RegExp("a.b"); // "." 在正则表达式中是特殊字符，匹配任意字符
   console.log(regex.test("acb")); // 输出 true (意料之外)

   // 正确示例：转义 "."
   const regexEscaped = new RegExp("a\\.b");
   console.log(regexEscaped.test("acb")); // 输出 false
   console.log(regexEscaped.test("a.b")); // 输出 true
   ```
   `EscapeRegExpSource` 函数在 V8 内部帮助处理这种情况，确保传递给底层引擎的正则表达式是正确的。

2. **错误地假设捕获组的索引：**

   ```javascript
   const regex = /(\d+)-(\w+)/;
   const result = regex.exec("123-abc");

   // 常见的错误是直接假设 result[1] 是第二个捕获组
   console.log(result[1]); // 输出 "123" (第一个捕获组)
   console.log(result[2]); // 输出 "abc" (第二个捕获组)
   ```
   开发者需要理解 `exec` 方法返回的数组结构，索引 0 是整个匹配项，后续索引对应捕获组。`JSRegExpResultIndices` 提供的 `indices` 属性可以更清晰地访问捕获组的起始和结束位置。

3. **不理解命名捕获组的使用方式：**

   ```javascript
   const regex = /(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})/;
   const result = regex.exec("2023-10-27");

   // 错误示例：尝试直接用索引访问命名捕获组
   // console.log(result[year]); // 报错：year 未定义

   // 正确示例：通过 groups 属性访问
   console.log(result.groups.year);   // 输出 "2023"
   console.log(result.groups.month);  // 输出 "10"
   console.log(result.groups.day);    // 输出 "27"
   ```
   `JSRegExpResultIndices` 中的代码负责构建 `groups` 属性，使得可以通过名称访问捕获组。

总而言之，`v8/src/objects/js-regexp.cc` 是 V8 引擎中处理 JavaScript 正则表达式的核心部分，它实现了 `RegExp` 对象的内部表示、编译、标志处理和匹配结果索引的构建等关键功能，并直接影响着 JavaScript 中正则表达式的行为。

### 提示词
```
这是目录为v8/src/objects/js-regexp.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-regexp.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/js-regexp.h"

#include <optional>

#include "src/base/strings.h"
#include "src/common/globals.h"
#include "src/objects/code.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/regexp/regexp.h"

namespace v8::internal {

Handle<JSRegExpResultIndices> JSRegExpResultIndices::BuildIndices(
    Isolate* isolate, DirectHandle<RegExpMatchInfo> match_info,
    Handle<Object> maybe_names) {
  Handle<JSRegExpResultIndices> indices(
      Cast<JSRegExpResultIndices>(isolate->factory()->NewJSObjectFromMap(
          isolate->regexp_result_indices_map())));

  // Initialize indices length to avoid having a partially initialized object
  // should GC be triggered by creating a NewFixedArray.
  indices->set_length(Smi::zero());

  // Build indices array from RegExpMatchInfo.
  int num_indices = match_info->number_of_capture_registers();
  int num_results = num_indices >> 1;
  Handle<FixedArray> indices_array =
      isolate->factory()->NewFixedArray(num_results);
  JSArray::SetContent(indices, indices_array);

  for (int i = 0; i < num_results; i++) {
    const int start_offset =
        match_info->capture(RegExpMatchInfo::capture_start_index(i));
    const int end_offset =
        match_info->capture(RegExpMatchInfo::capture_end_index(i));

    // Any unmatched captures are set to undefined, otherwise we set them to a
    // subarray of the indices.
    if (start_offset == -1) {
      indices_array->set(i, ReadOnlyRoots(isolate).undefined_value());
    } else {
      DirectHandle<FixedArray> indices_sub_array(
          isolate->factory()->NewFixedArray(2));
      indices_sub_array->set(0, Smi::FromInt(start_offset));
      indices_sub_array->set(1, Smi::FromInt(end_offset));
      DirectHandle<JSArray> indices_sub_jsarray =
          isolate->factory()->NewJSArrayWithElements(indices_sub_array,
                                                     PACKED_SMI_ELEMENTS, 2);
      indices_array->set(i, *indices_sub_jsarray);
    }
  }

  // If there are no capture groups, set the groups property to undefined.
  FieldIndex groups_index = FieldIndex::ForDescriptor(
      indices->map(), InternalIndex(kGroupsDescriptorIndex));
  if (IsUndefined(*maybe_names, isolate)) {
    indices->FastPropertyAtPut(groups_index,
                               ReadOnlyRoots(isolate).undefined_value());
    return indices;
  }

  // Create a groups property which returns a dictionary of named captures to
  // their corresponding capture indices.
  auto names = Cast<FixedArray>(maybe_names);
  int num_names = names->length() >> 1;
  Handle<HeapObject> group_names;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    group_names = isolate->factory()->NewSwissNameDictionary(num_names);
  } else {
    group_names = isolate->factory()->NewNameDictionary(num_names);
  }
  Handle<PropertyDictionary> group_names_dict =
      Cast<PropertyDictionary>(group_names);
  for (int i = 0; i < num_names; i++) {
    int base_offset = i * 2;
    int name_offset = base_offset;
    int index_offset = base_offset + 1;
    Handle<String> name(Cast<String>(names->get(name_offset)), isolate);
    Tagged<Smi> smi_index = Cast<Smi>(names->get(index_offset));
    Handle<Object> capture_indices(indices_array->get(smi_index.value()),
                                   isolate);
    if (!IsUndefined(*capture_indices, isolate)) {
      capture_indices = Cast<JSArray>(capture_indices);
    }
    InternalIndex group_entry = group_names_dict->FindEntry(isolate, name);
    // Duplicate group entries are possible if the capture groups are in
    // different alternatives, i.e. only one of them can actually match.
    // Therefore when we find a duplicate entry, either the current entry is
    // undefined (didn't match anything) or the indices for the current capture
    // are undefined. In the latter case we don't do anything, in the former
    // case we update the entry.
    if (group_entry.is_found()) {
      DCHECK(v8_flags.js_regexp_duplicate_named_groups);
      if (!IsUndefined(*capture_indices, isolate)) {
        DCHECK(IsUndefined(group_names_dict->ValueAt(group_entry), isolate));
        group_names_dict->ValueAtPut(group_entry, *capture_indices);
      }
    } else {
      group_names_dict =
          PropertyDictionary::Add(isolate, group_names_dict, name,
                                  capture_indices, PropertyDetails::Empty());
    }
  }

  // Convert group_names to a JSObject and store at the groups property of the
  // result indices.
  DirectHandle<FixedArrayBase> elements =
      isolate->factory()->empty_fixed_array();
  Handle<Null> null = isolate->factory()->null_value();
  DirectHandle<JSObject> js_group_names =
      isolate->factory()->NewSlowJSObjectWithPropertiesAndElements(
          null, group_names, elements);
  indices->FastPropertyAtPut(groups_index, *js_group_names);
  return indices;
}

// static
std::optional<JSRegExp::Flags> JSRegExp::FlagsFromString(Isolate* isolate,
                                                         Handle<String> flags) {
  const int length = flags->length();

  // A longer flags string cannot be valid.
  if (length > JSRegExp::kFlagCount) return {};

  RegExpFlags value;
  FlatStringReader reader(isolate, String::Flatten(isolate, flags));

  for (int i = 0; i < length; i++) {
    std::optional<RegExpFlag> flag = JSRegExp::FlagFromChar(reader.Get(i));
    if (!flag.has_value()) return {};
    if (value & flag.value()) return {};  // Duplicate.
    value |= flag.value();
  }

  return JSRegExp::AsJSRegExpFlags(value);
}

// static
Handle<String> JSRegExp::StringFromFlags(Isolate* isolate,
                                         JSRegExp::Flags flags) {
  FlagsBuffer buffer;
  return isolate->factory()->NewStringFromAsciiChecked(
      FlagsToString(flags, &buffer));
}

// static
MaybeHandle<JSRegExp> JSRegExp::New(Isolate* isolate, Handle<String> pattern,
                                    Flags flags, uint32_t backtrack_limit) {
  Handle<JSFunction> constructor = isolate->regexp_function();
  Handle<JSRegExp> regexp =
      Cast<JSRegExp>(isolate->factory()->NewJSObject(constructor));

  // Clear the data field, as a GC can be triggered before the field is set
  // during compilation.
  regexp->clear_data();

  return JSRegExp::Initialize(regexp, pattern, flags, backtrack_limit);
}

// static
MaybeHandle<JSRegExp> JSRegExp::Initialize(Handle<JSRegExp> regexp,
                                           Handle<String> source,
                                           Handle<String> flags_string) {
  Isolate* isolate = regexp->GetIsolate();
  std::optional<Flags> flags = JSRegExp::FlagsFromString(isolate, flags_string);
  if (!flags.has_value() ||
      !RegExp::VerifyFlags(JSRegExp::AsRegExpFlags(flags.value()))) {
    THROW_NEW_ERROR(
        isolate,
        NewSyntaxError(MessageTemplate::kInvalidRegExpFlags, flags_string));
  }
  return Initialize(regexp, source, flags.value());
}

namespace {

bool IsLineTerminator(int c) {
  // Expected to return true for '\n', '\r', 0x2028, and 0x2029.
  return unibrow::IsLineTerminator(static_cast<unibrow::uchar>(c));
}

// TODO(jgruber): Consider merging CountAdditionalEscapeChars and
// WriteEscapedRegExpSource into a single function to deduplicate dispatch logic
// and move related code closer to each other.
template <typename Char>
int CountAdditionalEscapeChars(DirectHandle<String> source,
                               bool* needs_escapes_out) {
  DisallowGarbageCollection no_gc;
  int escapes = 0;
  bool needs_escapes = false;
  bool in_character_class = false;
  base::Vector<const Char> src = source->GetCharVector<Char>(no_gc);
  for (int i = 0; i < src.length(); i++) {
    const Char c = src[i];
    if (c == '\\') {
      if (i + 1 < src.length() && IsLineTerminator(src[i + 1])) {
        // This '\' is ignored since the next character itself will be escaped.
        escapes--;
      } else {
        // Escape. Skip next character, which will be copied verbatim;
        i++;
      }
    } else if (c == '/' && !in_character_class) {
      // Not escaped forward-slash needs escape.
      needs_escapes = true;
      escapes++;
    } else if (c == '[') {
      in_character_class = true;
    } else if (c == ']') {
      in_character_class = false;
    } else if (c == '\n') {
      needs_escapes = true;
      escapes++;
    } else if (c == '\r') {
      needs_escapes = true;
      escapes++;
    } else if (static_cast<int>(c) == 0x2028) {
      needs_escapes = true;
      escapes += std::strlen("\\u2028") - 1;
    } else if (static_cast<int>(c) == 0x2029) {
      needs_escapes = true;
      escapes += std::strlen("\\u2029") - 1;
    } else {
      DCHECK(!IsLineTerminator(c));
    }
  }
  DCHECK(!in_character_class);
  DCHECK_GE(escapes, 0);
  DCHECK_IMPLIES(escapes != 0, needs_escapes);
  *needs_escapes_out = needs_escapes;
  return escapes;
}

template <typename Char>
void WriteStringToCharVector(base::Vector<Char> v, int* d, const char* string) {
  int s = 0;
  while (string[s] != '\0') v[(*d)++] = string[s++];
}

template <typename Char, typename StringType>
Handle<StringType> WriteEscapedRegExpSource(DirectHandle<String> source,
                                            Handle<StringType> result) {
  DisallowGarbageCollection no_gc;
  base::Vector<const Char> src = source->GetCharVector<Char>(no_gc);
  base::Vector<Char> dst(result->GetChars(no_gc), result->length());
  int s = 0;
  int d = 0;
  bool in_character_class = false;
  while (s < src.length()) {
    const Char c = src[s];
    if (c == '\\') {
      if (s + 1 < src.length() && IsLineTerminator(src[s + 1])) {
        // This '\' is ignored since the next character itself will be escaped.
        s++;
        continue;
      } else {
        // Escape. Copy this and next character.
        dst[d++] = src[s++];
      }
      if (s == src.length()) break;
    } else if (c == '/' && !in_character_class) {
      // Not escaped forward-slash needs escape.
      dst[d++] = '\\';
    } else if (c == '[') {
      in_character_class = true;
    } else if (c == ']') {
      in_character_class = false;
    } else if (c == '\n') {
      WriteStringToCharVector(dst, &d, "\\n");
      s++;
      continue;
    } else if (c == '\r') {
      WriteStringToCharVector(dst, &d, "\\r");
      s++;
      continue;
    } else if (static_cast<int>(c) == 0x2028) {
      WriteStringToCharVector(dst, &d, "\\u2028");
      s++;
      continue;
    } else if (static_cast<int>(c) == 0x2029) {
      WriteStringToCharVector(dst, &d, "\\u2029");
      s++;
      continue;
    } else {
      DCHECK(!IsLineTerminator(c));
    }
    dst[d++] = src[s++];
  }
  DCHECK_EQ(result->length(), d);
  DCHECK(!in_character_class);
  return result;
}

MaybeHandle<String> EscapeRegExpSource(Isolate* isolate,
                                       Handle<String> source) {
  DCHECK(source->IsFlat());
  if (source->length() == 0) return isolate->factory()->query_colon_string();
  bool one_byte = source->IsOneByteRepresentation();
  bool needs_escapes = false;
  int additional_escape_chars =
      one_byte ? CountAdditionalEscapeChars<uint8_t>(source, &needs_escapes)
               : CountAdditionalEscapeChars<base::uc16>(source, &needs_escapes);
  if (!needs_escapes) return source;
  int length = source->length() + additional_escape_chars;
  if (one_byte) {
    Handle<SeqOneByteString> result;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                               isolate->factory()->NewRawOneByteString(length));
    return WriteEscapedRegExpSource<uint8_t>(source, result);
  } else {
    Handle<SeqTwoByteString> result;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                               isolate->factory()->NewRawTwoByteString(length));
    return WriteEscapedRegExpSource<base::uc16>(source, result);
  }
}

}  // namespace

// static
MaybeHandle<JSRegExp> JSRegExp::Initialize(Handle<JSRegExp> regexp,
                                           Handle<String> source, Flags flags,
                                           uint32_t backtrack_limit) {
  Isolate* isolate = regexp->GetIsolate();
  Factory* factory = isolate->factory();
  // If source is the empty string we set it to "(?:)" instead as
  // suggested by ECMA-262, 5th, section 15.10.4.1.
  if (source->length() == 0) source = factory->query_colon_string();

  source = String::Flatten(isolate, source);

  RETURN_ON_EXCEPTION(isolate, RegExp::Compile(isolate, regexp, source,
                                               JSRegExp::AsRegExpFlags(flags),
                                               backtrack_limit));

  Handle<String> escaped_source;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, escaped_source,
                             EscapeRegExpSource(isolate, source));

  regexp->set_source(*escaped_source);
  regexp->set_flags(Smi::FromInt(flags));

  Tagged<Map> map = regexp->map();
  Tagged<Object> constructor = map->GetConstructor();
  if (IsJSFunction(constructor) &&
      Cast<JSFunction>(constructor)->initial_map() == map) {
    // If we still have the original map, set in-object properties directly.
    regexp->InObjectPropertyAtPut(JSRegExp::kLastIndexFieldIndex,
                                  Smi::FromInt(kInitialLastIndexValue),
                                  SKIP_WRITE_BARRIER);
  } else {
    // Map has changed, so use generic, but slower, method.
    RETURN_ON_EXCEPTION(
        isolate,
        Object::SetProperty(
            isolate, regexp, factory->lastIndex_string(),
            Handle<Smi>(Smi::FromInt(kInitialLastIndexValue), isolate)));
  }

  return regexp;
}

bool RegExpData::HasCompiledCode() const {
  if (type_tag() != Type::IRREGEXP) return false;
  Tagged<IrRegExpData> re_data = Cast<IrRegExpData>(*this);
  return re_data->has_latin1_code() || re_data->has_uc16_code();
}

// Only irregexps are subject to tier-up.
bool IrRegExpData::CanTierUp() {
  return v8_flags.regexp_tier_up && type_tag() == Type::IRREGEXP;
}

// An irregexp is considered to be marked for tier up if the tier-up ticks
// value reaches zero.
bool IrRegExpData::MarkedForTierUp() {
  if (!CanTierUp()) {
    return false;
  }

  return ticks_until_tier_up() == 0;
}

void IrRegExpData::ResetLastTierUpTick() {
  DCHECK(v8_flags.regexp_tier_up);
  int tier_up_ticks = ticks_until_tier_up();
  set_ticks_until_tier_up(tier_up_ticks + 1);
}

void IrRegExpData::TierUpTick() {
  int tier_up_ticks = ticks_until_tier_up();
  if (tier_up_ticks == 0) {
    return;
  }

  set_ticks_until_tier_up(tier_up_ticks - 1);
}

void IrRegExpData::MarkTierUpForNextExec() {
  DCHECK(v8_flags.regexp_tier_up);
  set_ticks_until_tier_up(0);
}

bool IrRegExpData::ShouldProduceBytecode() {
  return v8_flags.regexp_interpret_all ||
         (v8_flags.regexp_tier_up && !MarkedForTierUp());
}

void IrRegExpData::DiscardCompiledCodeForSerialization() {
  DCHECK(HasCompiledCode());
  clear_latin1_code();
  clear_uc16_code();
  clear_latin1_bytecode();
  clear_uc16_bytecode();
}

void IrRegExpData::SetBytecodeForExperimental(
    Isolate* isolate, Tagged<TrustedByteArray> bytecode) {
  set_latin1_bytecode(bytecode);
  set_uc16_bytecode(bytecode);

  Tagged<Code> trampoline =
      *BUILTIN_CODE(isolate, RegExpExperimentalTrampoline);
  set_latin1_code(trampoline);
  set_uc16_code(trampoline);
}

}  // namespace v8::internal
```