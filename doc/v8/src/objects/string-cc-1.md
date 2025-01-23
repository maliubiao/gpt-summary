Response:
Let's break down the thought process for analyzing this code snippet from `v8/src/objects/string.cc`.

**1. Initial Reading and Understanding the Context:**

The first step is to quickly read through the code to get a general idea of what it does. Keywords like `WriteUtf8`, `CalculateLineEnds`, `SlowEquals`, `Compare`, `IndexOf`, `LastIndexOf`, `GetSubstitution`, `HashString`, and `Truncate` immediately suggest string manipulation functionalities. The presence of template code and the `Isolate` object hint at low-level V8 internals.

**2. Identifying Key Function Blocks:**

After the initial read, I'd start to identify logical blocks of related functions. The code seems to naturally group around specific operations:

* **Writing to UTF-8:** The `WriteUtf8Impl` and `String::WriteUtf8` functions clearly deal with converting strings to UTF-8.
* **Calculating Line Endings:** The `CalculateLineEndsImpl` and `String::CalculateLineEndsVector`/`String::CalculateLineEnds` functions handle finding line breaks in strings.
* **Equality and Comparison:**  The `SlowEquals` and `Compare` functions are responsible for comparing string content.
* **Searching (IndexOf, LastIndexOf):**  The `IndexOf`, `LastIndexOf`, and their helper functions perform substring searches.
* **String Substitution:** The `GetSubstitution` function implements the logic for replacing substrings based on a match object (likely from regular expressions).
* **Hashing:** The `HashString` and `ComputeAndSetRawHash` functions calculate hash codes for strings.
* **Truncation:** The `Truncate` function modifies the length of a string.
* **Identifier Check:**  The `IsIdentifierVector` and `String::IsIdentifier` functions check if a string is a valid identifier.

**3. Analyzing Individual Function Blocks in Detail:**

Once the key blocks are identified, the next step is to analyze each block's functionality more deeply. For each block, consider:

* **Purpose:** What is the primary goal of these functions?
* **Input/Output:** What kind of data do they take and return?  Are there any specific types involved (e.g., `Handle<String>`, `Isolate*`)?
* **Core Logic:** What are the main steps involved in the computation? Look for loops, conditional statements, and calls to other V8 functions.
* **Edge Cases/Optimizations:** Are there any special cases handled (e.g., empty strings, thin strings, sliced strings)?  Are there any performance optimizations (like fast path checks based on length or hash)?

**4. Connecting to JavaScript Functionality (If Applicable):**

For functions that seem related to JavaScript string methods, the goal is to identify the corresponding JavaScript functionality. For example:

* `String::WriteUtf8` ->  Relates to encoding strings, although not a direct JavaScript method. Could be used internally for I/O or data transfer.
* `String::CalculateLineEnds` ->  Not directly exposed, but useful for debugging, source code analysis, or editor integration.
* `String::SlowEquals` ->  JavaScript's `===` (for string equality) and `String.prototype.localeCompare()`.
* `String::Compare` ->  JavaScript's `String.prototype.localeCompare()`.
* `String::IndexOf` ->  JavaScript's `String.prototype.indexOf()`.
* `String::LastIndexOf` -> JavaScript's `String.prototype.lastIndexOf()`.
* `String::GetSubstitution` -> JavaScript's `String.prototype.replace()` when using a function as the replacement.
* `String::IsIdentifier` -> Not a direct JavaScript method, but related to how variable and function names are formed.
* `String::Truncate` -> No direct equivalent, but related to how strings are handled internally.

**5. Considering `.tq` Files and Torque:**

The prompt mentions `.tq` files and Torque. If the file ended in `.tq`, the analysis would shift to understanding Torque's role in V8. Torque is V8's type-safe intermediate language used for implementing built-in functions. If this were a `.tq` file, the focus would be on the *implementation* of the JavaScript string methods at a lower level.

**6. Illustrating with JavaScript Examples:**

For the JavaScript connections, provide clear and concise examples demonstrating how the V8 code's functionality relates to the JavaScript API.

**7. Hypothetical Inputs and Outputs (Code Logic Reasoning):**

For functions with clear logical steps, construct simple hypothetical inputs and their corresponding outputs to illustrate the function's behavior. This helps to verify understanding.

**8. Identifying Common Programming Errors:**

Think about how developers might misuse or misunderstand the related JavaScript string methods and how the V8 code's behavior might lead to those errors. For example, forgetting that `indexOf` returns -1 if the substring is not found, or misinterpreting how regular expression replacements work.

**9. Structuring the Output:**

Finally, organize the analysis in a clear and logical manner, addressing all parts of the prompt. Use headings and bullet points to improve readability. Start with a general summary and then delve into specifics for each function block.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:**  Sometimes, the initial reading might lead to a slightly incorrect understanding. As you analyze the code more deeply, you might need to correct those initial assumptions. For example, you might initially think `WriteUtf8` is directly exposed to JavaScript but then realize it's an internal function.
* **Missing Connections:** You might not immediately see the connection to a specific JavaScript method. Further research or closer examination of the code might reveal the link.
* **Technical Details:**  Understanding the nuances of V8's string representation (e.g., flat strings, cons strings, thin strings) is crucial for accurately explaining the code's behavior. You might need to refer to V8 documentation or other source code files to clarify these details.

By following these steps, you can systematically analyze the provided C++ code snippet and extract its functionality, relating it to JavaScript and potential programming errors.
好的，让我们来归纳一下这段 `v8/src/objects/string.cc` 代码片段的功能。

**核心功能归纳:**

这段代码片段主要包含了 `v8::String` 类的一些底层操作，这些操作是为了高效地处理 JavaScript 中的字符串。 核心功能可以归纳为以下几点：

1. **将字符串写入 UTF-8 缓冲区 (`WriteUtf8`)**:
   - 提供了将 V8 内部表示的字符串转换为 UTF-8 编码并写入到指定缓冲区的能力。
   - 考虑了字符串的不同内部表示（如单字节、双字节），以及是否需要添加 null 终止符，以及如何处理无效的 UTF-8 字符。

2. **计算字符串中的行尾位置 (`CalculateLineEnds`, `CalculateLineEndsVector`)**:
   - 实现了高效地查找字符串中换行符 (`\n`, `\r`, `\r\n`) 的位置。
   - 可以选择是否包含字符串结尾的行尾位置，这对于源代码分析和处理非常有用。

3. **字符串的慢速相等性比较 (`SlowEquals`)**:
   - 提供了比较两个字符串是否相等的更全面的方法。
   - 除了直接的字符比较，还考虑了字符串的不同内部表示（如 `ThinString` 的解引用）以及预先检查哈希值以加速比较。

4. **字符串比较 (`Compare`)**:
   - 实现了比较两个字符串大小关系的功能。
   - 同样考虑了字符串的不同内部表示，并逐字符进行比较。

5. **查找子字符串 (`IndexOf`)**:
   - 提供了在字符串中查找指定子字符串首次出现位置的功能。
   - 考虑了起始搜索位置。

6. **字符串替换的辅助函数 (`GetSubstitution`)**:
   -  这个函数是字符串替换操作的核心，尤其是在使用正则表达式进行替换时。
   -  它处理替换字符串中的特殊占位符（如 `$n`, `$&`, `$` 等），这些占位符可以引用匹配到的子串或其周围的内容。

7. **反向查找子字符串 (`LastIndexOf`)**:
   - 提供了在字符串中从后向前查找指定子字符串的功能。
   - 可以指定起始的搜索位置。

8. **检查字符串是否以单字节字符作为前缀 (`HasOneBytePrefix`)**:
   - 提供了一个快速检查字符串是否以特定单字节字符序列开头的方法。

9. **判断字符串是否是合法的标识符 (`IsIdentifier`)**:
   -  判断字符串是否符合 JavaScript 标识符的规则（以字母、下划线或美元符号开头，后续字符可以是字母、数字、下划线或美元符号）。

10. **计算字符串哈希值 (`HashString`, `ComputeAndSetRawHash`)**:
    - 实现了计算字符串哈希值的功能，用于快速比较和存储字符串（例如在 `Set` 或 `Map` 中）。
    - 考虑了不同类型的字符串和优化的哈希算法。

11. **将字符串转换为数组索引 (`SlowAsArrayIndex`)**:
    - 尝试将字符串转换为无符号 32 位整数，用于数组索引。

12. **将字符串转换为整数索引 (`SlowAsIntegerIndex`)**:
    - 尝试将字符串转换为 `size_t` 类型的整数索引。

13. **字符串截断 (`Truncate`)**:
    - 允许修改字符串的长度，创建一个新的、更短的字符串。这通常用于优化内存使用。

**与 JavaScript 功能的关系:**

这段代码与许多 JavaScript 内置的字符串方法直接相关。 例如：

* **`String.prototype.indexOf()`**:  `String::IndexOf`  实现了 `indexOf` 的核心逻辑。
  ```javascript
  const str = "hello world";
  const index = str.indexOf("world"); // JavaScript 调用，底层可能用到 String::IndexOf
  console.log(index); // 输出 6
  ```

* **`String.prototype.lastIndexOf()`**: `String::LastIndexOf` 实现了 `lastIndexOf` 的核心逻辑。
  ```javascript
  const str = "hello world hello";
  const index = str.lastIndexOf("hello"); // JavaScript 调用，底层可能用到 String::LastIndexOf
  console.log(index); // 输出 12
  ```

* **`String.prototype.replace()`**: `String::GetSubstitution` 是 `replace` 方法在进行复杂替换（尤其是使用正则表达式时）的关键部分。
  ```javascript
  const str = "The quick brown fox";
  const newStr = str.replace(/quick|brown/, 'lazy'); // JavaScript 调用，底层可能用到 String::GetSubstitution
  console.log(newStr); // 输出 "The lazy lazy fox"

  const str2 = "John Smith";
  const newStr2 = str2.replace(/(\w+) (\w+)/, '$2, $1'); // 使用占位符，底层用到 String::GetSubstitution
  console.log(newStr2); // 输出 "Smith, John"
  ```

* **字符串比较 ( `<`, `>`, `===` 等)**:  `String::SlowEquals` 和 `String::Compare` 为 JavaScript 中的字符串比较运算符提供了基础。
  ```javascript
  const str1 = "apple";
  const str2 = "banana";
  console.log(str1 < str2); // JavaScript 调用，底层可能用到 String::Compare
  console.log(str1 === "apple"); // JavaScript 调用，底层可能用到 String::SlowEquals
  ```

**假设输入与输出 (代码逻辑推理):**

* **`WriteUtf8` 假设：**
   - **输入:** 一个 V8 字符串对象，内容为 "你好"，一个足够大的 char 缓冲区。
   - **输出:** 缓冲区将包含 "你好" 的 UTF-8 编码（例如，根据编码不同可能是 6 个字节），函数返回写入的字节数。

* **`CalculateLineEnds` 假设：**
   - **输入:** 一个 V8 字符串对象，内容为 "第一行\n第二行\r\n第三行"。
   - **输出:** 一个包含行尾位置的数组或向量，例如 `[2, 7, 12]`。

* **`IndexOf` 假设：**
   - **输入:** 一个 V8 字符串对象，内容为 "abcdefg"，搜索字符串 "cde"，起始位置 0。
   - **输出:** 返回索引 2。

* **`GetSubstitution` 假设：**
   - **输入:**  一个匹配对象（例如，匹配了 "world"），替换字符串 "$& is great"，原始字符串 "hello world"。
   - **输出:**  替换后的字符串 "world is great"。

**用户常见的编程错误:**

* **不理解 `indexOf` 和 `lastIndexOf` 返回 `-1` 的情况:** 当找不到子字符串时，这两个方法会返回 `-1`，初学者可能会忘记处理这种情况，导致错误。
  ```javascript
  const str = "hello";
  const index = str.indexOf("x");
  if (index > 0) { // 错误的判断，当 index 为 -1 时也会进入
    console.log("找到了");
  } else {
    console.log("未找到"); // 正确应该进入这里
  }
  ```

* **在字符串替换中错误使用占位符:**  不了解 `$n`, `$&` 等占位符的含义，导致替换结果不符合预期。
  ```javascript
  const str = "123 456";
  const newStr = str.replace(/(\d+) (\d+)/, '$3 $1'); // 错误使用 $3，因为只有两个捕获组
  console.log(newStr); // 输出 "$3 123"，而不是期望的结果
  ```

* **混淆字符串比较和数值比较:**  在比较字符串大小时，直接使用数值比较运算符可能会得到不期望的结果。应该使用字符串的比较方式。
  ```javascript
  const str1 = "10";
  const str2 = "2";
  console.log(str1 > str2); // 输出 true，因为字符串比较是按字典序
  console.log(parseInt(str1) > parseInt(str2)); // 输出 true，数值比较才是正确的
  ```

**总结:**

总而言之，这段 `v8/src/objects/string.cc` 代码片段是 V8 引擎中处理字符串的核心组成部分，它提供了各种底层的、高性能的操作，支撑着 JavaScript 中常用的字符串方法和操作。理解这些底层实现有助于更深入地理解 JavaScript 字符串的工作原理以及如何避免常见的编程错误。

### 提示词
```
这是目录为v8/src/objects/string.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/string.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
} else {
              WriteToFlat(second, sink + second_start, 0, second_length,
                          access_guard);
            }
            length -= second_length;
          }
          source = first;
        }
        if (length == 0) return;
        continue;
      }
      case kOneByteStringTag | kSlicedStringTag:
      case kTwoByteStringTag | kSlicedStringTag: {
        Tagged<SlicedString> slice = Cast<SlicedString>(source);
        uint32_t offset = slice->offset();
        source = slice->parent();
        start += offset;
        continue;
      }
      case kOneByteStringTag | kThinStringTag:
      case kTwoByteStringTag | kThinStringTag:
        source = Cast<ThinString>(source)->actual();
        continue;
    }
    UNREACHABLE();
  }
  UNREACHABLE();
}

namespace {

template <typename Char>
size_t WriteUtf8Impl(base::Vector<const Char> string, char* buffer,
                     size_t capacity, bool write_null,
                     bool replace_invalid_utf8) {
  constexpr bool kSourceIsOneByte = sizeof(Char) == 1;

  if constexpr (kSourceIsOneByte) {
    // Only 16-bit characters can contain invalid unicode.
    replace_invalid_utf8 = false;
  }

  size_t write_index = 0;
  const Char* characters = string.begin();
  size_t content_capacity = capacity - write_null;
  uint16_t last = unibrow::Utf16::kNoPreviousCharacter;
  for (size_t read_index = 0; read_index < string.size(); read_index++) {
    Char character = characters[read_index];

    size_t required_capacity;
    if constexpr (kSourceIsOneByte) {
      required_capacity = unibrow::Utf8::LengthOneByte(character);
    } else {
      required_capacity = unibrow::Utf8::Length(character, last);
    }
    size_t remaining_capacity = content_capacity - write_index;
    if (remaining_capacity < required_capacity) {
      // Not enough space left, so stop here.
      if (replace_invalid_utf8 && unibrow::Utf16::IsLeadSurrogate(last)) {
        DCHECK_GE(write_index, unibrow::Utf8::kSizeOfUnmatchedSurrogate);
        // We're in the middle of a surrogate pair. Delete the first part again.
        write_index -= unibrow::Utf8::kSizeOfUnmatchedSurrogate;
      }
      break;
    }

    if constexpr (kSourceIsOneByte) {
      write_index +=
          unibrow::Utf8::EncodeOneByte(buffer + write_index, character);
    } else {
      write_index += unibrow::Utf8::Encode(buffer + write_index, character,
                                           last, replace_invalid_utf8);
    }

    last = character;
  }
  DCHECK_LE(write_index, capacity);

  if (write_null) {
    DCHECK_LT(write_index, capacity);
    buffer[write_index++] = '\0';
  }

  return write_index;
}

}  // namespace

// static
size_t String::WriteUtf8(Isolate* isolate, Handle<String> string, char* buffer,
                         size_t capacity, Utf8EncodingFlags flags) {
  DCHECK_IMPLIES(flags & Utf8EncodingFlag::kNullTerminate, capacity > 0);
  DCHECK_IMPLIES(capacity > 0, buffer != nullptr);

  string = Flatten(isolate, string);

  DisallowGarbageCollection no_gc;
  FlatContent content = string->GetFlatContent(no_gc);
  DCHECK(content.IsFlat());
  if (content.IsOneByte()) {
    return WriteUtf8Impl<uint8_t>(content.ToOneByteVector(), buffer, capacity,
                                  flags & Utf8EncodingFlag::kNullTerminate,
                                  flags & Utf8EncodingFlag::kReplaceInvalid);
  } else {
    return WriteUtf8Impl<uint16_t>(content.ToUC16Vector(), buffer, capacity,
                                   flags & Utf8EncodingFlag::kNullTerminate,
                                   flags & Utf8EncodingFlag::kReplaceInvalid);
  }
}

template <typename SourceChar>
static void CalculateLineEndsImpl(String::LineEndsVector* line_ends,
                                  base::Vector<const SourceChar> src,
                                  bool include_ending_line) {
  const int src_len = src.length();
  for (int i = 0; i < src_len - 1; i++) {
    SourceChar current = src[i];
    SourceChar next = src[i + 1];
    if (IsLineTerminatorSequence(current, next)) line_ends->push_back(i);
  }

  if (src_len > 0 && IsLineTerminatorSequence(src[src_len - 1], 0)) {
    line_ends->push_back(src_len - 1);
  }
  if (include_ending_line) {
    // Include one character beyond the end of script. The rewriter uses that
    // position for the implicit return statement.
    line_ends->push_back(src_len);
  }
}

template <typename IsolateT>
String::LineEndsVector String::CalculateLineEndsVector(
    IsolateT* isolate, Handle<String> src, bool include_ending_line) {
  src = Flatten(isolate, src);
  // Rough estimate of line count based on a roughly estimated average
  // length of packed code. Most scripts have < 32 lines.
  int line_count_estimate = (src->length() >> 6) + 16;
  LineEndsVector line_ends;
  line_ends.reserve(line_count_estimate);
  {
    DisallowGarbageCollection no_gc;
    // Dispatch on type of strings.
    String::FlatContent content = src->GetFlatContent(no_gc);
    DCHECK(content.IsFlat());
    if (content.IsOneByte()) {
      CalculateLineEndsImpl(&line_ends, content.ToOneByteVector(),
                            include_ending_line);
    } else {
      CalculateLineEndsImpl(&line_ends, content.ToUC16Vector(),
                            include_ending_line);
    }
  }
  return line_ends;
}

template String::LineEndsVector String::CalculateLineEndsVector(
    Isolate* isolate, Handle<String> src, bool include_ending_line);
template String::LineEndsVector String::CalculateLineEndsVector(
    LocalIsolate* isolate, Handle<String> src, bool include_ending_line);

template <typename IsolateT>
Handle<FixedArray> String::CalculateLineEnds(IsolateT* isolate,
                                             Handle<String> src,
                                             bool include_ending_line) {
  LineEndsVector line_ends =
      CalculateLineEndsVector(isolate, src, include_ending_line);
  int line_count = static_cast<int>(line_ends.size());
  Handle<FixedArray> array =
      isolate->factory()->NewFixedArray(line_count, AllocationType::kOld);
  {
    DisallowGarbageCollection no_gc;
    Tagged<FixedArray> raw_array = *array;
    for (int i = 0; i < line_count; i++) {
      raw_array->set(i, Smi::FromInt(line_ends[i]));
    }
  }
  return array;
}

template Handle<FixedArray> String::CalculateLineEnds(Isolate* isolate,
                                                      Handle<String> src,
                                                      bool include_ending_line);
template Handle<FixedArray> String::CalculateLineEnds(LocalIsolate* isolate,
                                                      Handle<String> src,
                                                      bool include_ending_line);

bool String::SlowEquals(Tagged<String> other) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(other));
  return SlowEquals(other, SharedStringAccessGuardIfNeeded::NotNeeded());
}

bool String::SlowEquals(
    Tagged<String> other,
    const SharedStringAccessGuardIfNeeded& access_guard) const {
  DisallowGarbageCollection no_gc;
  // Fast check: negative check with lengths.
  uint32_t len = length();
  if (len != other->length()) return false;
  if (len == 0) return true;

  // Fast check: if at least one ThinString is involved, dereference it/them
  // and restart.
  if (IsThinString(this) || IsThinString(other)) {
    if (IsThinString(other)) other = Cast<ThinString>(other)->actual();
    if (IsThinString(this)) {
      return Cast<ThinString>(this)->actual()->Equals(other);
    } else {
      return this->Equals(other);
    }
  }

  // Fast check: if hash code is computed for both strings
  // a fast negative check can be performed.
  uint32_t this_hash;
  uint32_t other_hash;
  if (TryGetHash(&this_hash) && other->TryGetHash(&other_hash)) {
#ifdef ENABLE_SLOW_DCHECKS
    if (v8_flags.enable_slow_asserts) {
      if (this_hash != other_hash) {
        bool found_difference = false;
        for (uint32_t i = 0; i < len; i++) {
          if (Get(i) != other->Get(i)) {
            found_difference = true;
            break;
          }
        }
        DCHECK(found_difference);
      }
    }
#endif
    if (this_hash != other_hash) return false;
  }

  // We know the strings are both non-empty. Compare the first chars
  // before we try to flatten the strings.
  if (this->Get(0, access_guard) != other->Get(0, access_guard)) return false;

  if (IsSeqOneByteString(this) && IsSeqOneByteString(other)) {
    const uint8_t* str1 =
        Cast<SeqOneByteString>(this)->GetChars(no_gc, access_guard);
    const uint8_t* str2 =
        Cast<SeqOneByteString>(other)->GetChars(no_gc, access_guard);
    return CompareCharsEqual(str1, str2, len);
  }

  StringComparator comparator;
  return comparator.Equals(this, other, access_guard);
}

// static
bool String::SlowEquals(Isolate* isolate, Handle<String> one,
                        Handle<String> two) {
  // Fast check: negative check with lengths.
  const uint32_t one_length = one->length();
  if (one_length != two->length()) return false;
  if (one_length == 0) return true;

  // Fast check: if at least one ThinString is involved, dereference it/them
  // and restart.
  if (IsThinString(*one) || IsThinString(*two)) {
    if (IsThinString(*one)) {
      one = handle(Cast<ThinString>(*one)->actual(), isolate);
    }
    if (IsThinString(*two)) {
      two = handle(Cast<ThinString>(*two)->actual(), isolate);
    }
    return String::Equals(isolate, one, two);
  }

  // Fast check: if hash code is computed for both strings
  // a fast negative check can be performed.
  uint32_t one_hash;
  uint32_t two_hash;
  if (one->TryGetHash(&one_hash) && two->TryGetHash(&two_hash)) {
#ifdef ENABLE_SLOW_DCHECKS
    if (v8_flags.enable_slow_asserts) {
      if (one_hash != two_hash) {
        bool found_difference = false;
        for (uint32_t i = 0; i < one_length; i++) {
          if (one->Get(i) != two->Get(i)) {
            found_difference = true;
            break;
          }
        }
        DCHECK(found_difference);
      }
    }
#endif
    if (one_hash != two_hash) return false;
  }

  // We know the strings are both non-empty. Compare the first chars
  // before we try to flatten the strings.
  if (one->Get(0) != two->Get(0)) return false;

  one = String::Flatten(isolate, one);
  two = String::Flatten(isolate, two);

  DisallowGarbageCollection no_gc;
  String::FlatContent flat1 = one->GetFlatContent(no_gc);
  String::FlatContent flat2 = two->GetFlatContent(no_gc);

  if (flat1.IsOneByte() && flat2.IsOneByte()) {
    return CompareCharsEqual(flat1.ToOneByteVector().begin(),
                             flat2.ToOneByteVector().begin(), one_length);
  } else if (flat1.IsTwoByte() && flat2.IsTwoByte()) {
    return CompareCharsEqual(flat1.ToUC16Vector().begin(),
                             flat2.ToUC16Vector().begin(), one_length);
  } else if (flat1.IsOneByte() && flat2.IsTwoByte()) {
    return CompareCharsEqual(flat1.ToOneByteVector().begin(),
                             flat2.ToUC16Vector().begin(), one_length);
  } else if (flat1.IsTwoByte() && flat2.IsOneByte()) {
    return CompareCharsEqual(flat1.ToUC16Vector().begin(),
                             flat2.ToOneByteVector().begin(), one_length);
  }
  UNREACHABLE();
}

// static
ComparisonResult String::Compare(Isolate* isolate, Handle<String> x,
                                 Handle<String> y) {
  // A few fast case tests before we flatten.
  if (x.is_identical_to(y)) {
    return ComparisonResult::kEqual;
  } else if (y->length() == 0) {
    return x->length() == 0 ? ComparisonResult::kEqual
                            : ComparisonResult::kGreaterThan;
  } else if (x->length() == 0) {
    return ComparisonResult::kLessThan;
  }

  int const d = x->Get(0) - y->Get(0);
  if (d < 0) {
    return ComparisonResult::kLessThan;
  } else if (d > 0) {
    return ComparisonResult::kGreaterThan;
  }

  // Slow case.
  x = String::Flatten(isolate, x);
  y = String::Flatten(isolate, y);

  DisallowGarbageCollection no_gc;
  ComparisonResult result = ComparisonResult::kEqual;
  uint32_t prefix_length = x->length();
  if (y->length() < prefix_length) {
    prefix_length = y->length();
    result = ComparisonResult::kGreaterThan;
  } else if (y->length() > prefix_length) {
    result = ComparisonResult::kLessThan;
  }
  int r;
  String::FlatContent x_content = x->GetFlatContent(no_gc);
  String::FlatContent y_content = y->GetFlatContent(no_gc);
  if (x_content.IsOneByte()) {
    base::Vector<const uint8_t> x_chars = x_content.ToOneByteVector();
    if (y_content.IsOneByte()) {
      base::Vector<const uint8_t> y_chars = y_content.ToOneByteVector();
      r = CompareChars(x_chars.begin(), y_chars.begin(), prefix_length);
    } else {
      base::Vector<const base::uc16> y_chars = y_content.ToUC16Vector();
      r = CompareChars(x_chars.begin(), y_chars.begin(), prefix_length);
    }
  } else {
    base::Vector<const base::uc16> x_chars = x_content.ToUC16Vector();
    if (y_content.IsOneByte()) {
      base::Vector<const uint8_t> y_chars = y_content.ToOneByteVector();
      r = CompareChars(x_chars.begin(), y_chars.begin(), prefix_length);
    } else {
      base::Vector<const base::uc16> y_chars = y_content.ToUC16Vector();
      r = CompareChars(x_chars.begin(), y_chars.begin(), prefix_length);
    }
  }
  if (r < 0) {
    result = ComparisonResult::kLessThan;
  } else if (r > 0) {
    result = ComparisonResult::kGreaterThan;
  }
  return result;
}

namespace {

uint32_t ToValidIndex(Tagged<String> str, Tagged<Object> number) {
  uint32_t index = PositiveNumberToUint32(number);
  uint32_t length = str->length();
  if (index > length) return length;
  return index;
}

}  // namespace

Tagged<Object> String::IndexOf(Isolate* isolate, Handle<Object> receiver,
                               Handle<Object> search, Handle<Object> position) {
  if (IsNullOrUndefined(*receiver, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kCalledOnNullOrUndefined,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  "String.prototype.indexOf")));
  }
  Handle<String> receiver_string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver_string,
                                     Object::ToString(isolate, receiver));

  Handle<String> search_string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, search_string,
                                     Object::ToString(isolate, search));

  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, position,
                                     Object::ToInteger(isolate, position));

  uint32_t index = ToValidIndex(*receiver_string, *position);
  return Smi::FromInt(
      String::IndexOf(isolate, receiver_string, search_string, index));
}

namespace {

template <typename T>
int SearchString(Isolate* isolate, String::FlatContent receiver_content,
                 base::Vector<T> pat_vector, int start_index) {
  if (receiver_content.IsOneByte()) {
    return SearchString(isolate, receiver_content.ToOneByteVector(), pat_vector,
                        start_index);
  }
  return SearchString(isolate, receiver_content.ToUC16Vector(), pat_vector,
                      start_index);
}

}  // namespace

int String::IndexOf(Isolate* isolate, Handle<String> receiver,
                    Handle<String> search, uint32_t start_index) {
  DCHECK_LE(start_index, receiver->length());

  uint32_t search_length = search->length();
  if (search_length == 0) return start_index;

  uint32_t receiver_length = receiver->length();
  if (start_index + search_length > receiver_length) return -1;

  receiver = String::Flatten(isolate, receiver);
  search = String::Flatten(isolate, search);

  DisallowGarbageCollection no_gc;  // ensure vectors stay valid
  // Extract flattened substrings of cons strings before getting encoding.
  String::FlatContent receiver_content = receiver->GetFlatContent(no_gc);
  String::FlatContent search_content = search->GetFlatContent(no_gc);

  // dispatch on type of strings
  if (search_content.IsOneByte()) {
    base::Vector<const uint8_t> pat_vector = search_content.ToOneByteVector();
    return SearchString<const uint8_t>(isolate, receiver_content, pat_vector,
                                       start_index);
  }
  base::Vector<const base::uc16> pat_vector = search_content.ToUC16Vector();
  return SearchString<const base::uc16>(isolate, receiver_content, pat_vector,
                                        start_index);
}

MaybeHandle<String> String::GetSubstitution(Isolate* isolate, Match* match,
                                            Handle<String> replacement,
                                            uint32_t start_index) {
  Factory* factory = isolate->factory();

  const int replacement_length = replacement->length();
  const int captures_length = match->CaptureCount();

  replacement = String::Flatten(isolate, replacement);

  Handle<String> dollar_string =
      factory->LookupSingleCharacterStringFromCode('$');
  int next_dollar_ix =
      String::IndexOf(isolate, replacement, dollar_string, start_index);
  if (next_dollar_ix < 0) {
    return replacement;
  }

  IncrementalStringBuilder builder(isolate);

  if (next_dollar_ix > 0) {
    builder.AppendString(factory->NewSubString(replacement, 0, next_dollar_ix));
  }

  while (true) {
    const int peek_ix = next_dollar_ix + 1;
    if (peek_ix >= replacement_length) {
      builder.AppendCharacter('$');
      return indirect_handle(builder.Finish(), isolate);
    }

    int continue_from_ix = -1;
    const uint16_t peek = replacement->Get(peek_ix);
    switch (peek) {
      case '$':  // $$
        builder.AppendCharacter('$');
        continue_from_ix = peek_ix + 1;
        break;
      case '&':  // $& - match
        builder.AppendString(match->GetMatch());
        continue_from_ix = peek_ix + 1;
        break;
      case '`':  // $` - prefix
        builder.AppendString(match->GetPrefix());
        continue_from_ix = peek_ix + 1;
        break;
      case '\'':  // $' - suffix
        builder.AppendString(match->GetSuffix());
        continue_from_ix = peek_ix + 1;
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
        // Valid indices are $1 .. $9, $01 .. $09 and $10 .. $99
        int scaled_index = (peek - '0');
        int advance = 1;

        if (peek_ix + 1 < replacement_length) {
          const uint16_t next_peek = replacement->Get(peek_ix + 1);
          if (next_peek >= '0' && next_peek <= '9') {
            const int new_scaled_index = scaled_index * 10 + (next_peek - '0');
            if (new_scaled_index < captures_length) {
              scaled_index = new_scaled_index;
              advance = 2;
            }
          }
        }

        if (scaled_index == 0 || scaled_index >= captures_length) {
          builder.AppendCharacter('$');
          continue_from_ix = peek_ix;
          break;
        }

        bool capture_exists;
        Handle<String> capture;
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, capture, match->GetCapture(scaled_index, &capture_exists));
        if (capture_exists) builder.AppendString(capture);
        continue_from_ix = peek_ix + advance;
        break;
      }
      case '<': {  // $<name> - named capture
        using CaptureState = String::Match::CaptureState;

        if (!match->HasNamedCaptures()) {
          builder.AppendCharacter('$');
          continue_from_ix = peek_ix;
          break;
        }

        Handle<String> bracket_string =
            factory->LookupSingleCharacterStringFromCode('>');
        const int closing_bracket_ix =
            String::IndexOf(isolate, replacement, bracket_string, peek_ix + 1);

        if (closing_bracket_ix == -1) {
          // No closing bracket was found, treat '$<' as a string literal.
          builder.AppendCharacter('$');
          continue_from_ix = peek_ix;
          break;
        }

        Handle<String> capture_name =
            factory->NewSubString(replacement, peek_ix + 1, closing_bracket_ix);
        Handle<String> capture;
        CaptureState capture_state;
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, capture,
            match->GetNamedCapture(capture_name, &capture_state));

        if (capture_state == CaptureState::MATCHED) {
          builder.AppendString(capture);
        }

        continue_from_ix = closing_bracket_ix + 1;
        break;
      }
      default:
        builder.AppendCharacter('$');
        continue_from_ix = peek_ix;
        break;
    }

    // Go the the next $ in the replacement.
    // TODO(jgruber): Single-char lookups could be much more efficient.
    DCHECK_NE(continue_from_ix, -1);
    next_dollar_ix =
        String::IndexOf(isolate, replacement, dollar_string, continue_from_ix);

    // Return if there are no more $ characters in the replacement. If we
    // haven't reached the end, we need to append the suffix.
    if (next_dollar_ix < 0) {
      if (continue_from_ix < replacement_length) {
        builder.AppendString(factory->NewSubString(
            replacement, continue_from_ix, replacement_length));
      }
      return indirect_handle(builder.Finish(), isolate);
    }

    // Append substring between the previous and the next $ character.
    if (next_dollar_ix > continue_from_ix) {
      builder.AppendString(
          factory->NewSubString(replacement, continue_from_ix, next_dollar_ix));
    }
  }

  UNREACHABLE();
}

namespace {  // for String.Prototype.lastIndexOf

template <typename schar, typename pchar>
int StringMatchBackwards(base::Vector<const schar> subject,
                         base::Vector<const pchar> pattern, int idx) {
  int pattern_length = pattern.length();
  DCHECK_GE(pattern_length, 1);
  DCHECK(idx + pattern_length <= subject.length());

  if (sizeof(schar) == 1 && sizeof(pchar) > 1) {
    for (int i = 0; i < pattern_length; i++) {
      base::uc16 c = pattern[i];
      if (c > String::kMaxOneByteCharCode) {
        return -1;
      }
    }
  }

  pchar pattern_first_char = pattern[0];
  for (int i = idx; i >= 0; i--) {
    if (subject[i] != pattern_first_char) continue;
    int j = 1;
    while (j < pattern_length) {
      if (pattern[j] != subject[i + j]) {
        break;
      }
      j++;
    }
    if (j == pattern_length) {
      return i;
    }
  }
  return -1;
}

}  // namespace

Tagged<Object> String::LastIndexOf(Isolate* isolate, Handle<Object> receiver,
                                   Handle<Object> search,
                                   Handle<Object> position) {
  if (IsNullOrUndefined(*receiver, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kCalledOnNullOrUndefined,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  "String.prototype.lastIndexOf")));
  }
  Handle<String> receiver_string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver_string,
                                     Object::ToString(isolate, receiver));

  Handle<String> search_string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, search_string,
                                     Object::ToString(isolate, search));

  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, position,
                                     Object::ToNumber(isolate, position));

  uint32_t start_index;

  if (IsNaN(*position)) {
    start_index = receiver_string->length();
  } else {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, position,
                                       Object::ToInteger(isolate, position));
    start_index = ToValidIndex(*receiver_string, *position);
  }

  uint32_t pattern_length = search_string->length();
  uint32_t receiver_length = receiver_string->length();

  if (start_index + pattern_length > receiver_length) {
    start_index = receiver_length - pattern_length;
  }

  if (pattern_length == 0) {
    return Smi::FromInt(start_index);
  }

  receiver_string = String::Flatten(isolate, receiver_string);
  search_string = String::Flatten(isolate, search_string);

  int last_index = -1;
  DisallowGarbageCollection no_gc;  // ensure vectors stay valid

  String::FlatContent receiver_content = receiver_string->GetFlatContent(no_gc);
  String::FlatContent search_content = search_string->GetFlatContent(no_gc);

  if (search_content.IsOneByte()) {
    base::Vector<const uint8_t> pat_vector = search_content.ToOneByteVector();
    if (receiver_content.IsOneByte()) {
      last_index = StringMatchBackwards(receiver_content.ToOneByteVector(),
                                        pat_vector, start_index);
    } else {
      last_index = StringMatchBackwards(receiver_content.ToUC16Vector(),
                                        pat_vector, start_index);
    }
  } else {
    base::Vector<const base::uc16> pat_vector = search_content.ToUC16Vector();
    if (receiver_content.IsOneByte()) {
      last_index = StringMatchBackwards(receiver_content.ToOneByteVector(),
                                        pat_vector, start_index);
    } else {
      last_index = StringMatchBackwards(receiver_content.ToUC16Vector(),
                                        pat_vector, start_index);
    }
  }
  return Smi::FromInt(last_index);
}

bool String::HasOneBytePrefix(base::Vector<const char> str) {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return IsEqualToImpl<EqualityType::kPrefix>(
      str, SharedStringAccessGuardIfNeeded::NotNeeded());
}

namespace {

template <typename Char>
bool IsIdentifierVector(base::Vector<Char> vec) {
  if (vec.empty()) {
    return false;
  }
  if (!IsIdentifierStart(vec[0])) {
    return false;
  }
  for (size_t i = 1; i < vec.size(); ++i) {
    if (!IsIdentifierPart(vec[i])) {
      return false;
    }
  }
  return true;
}

}  // namespace

// static
bool String::IsIdentifier(Isolate* isolate, Handle<String> str) {
  str = String::Flatten(isolate, str);
  DisallowGarbageCollection no_gc;
  String::FlatContent flat = str->GetFlatContent(no_gc);
  return flat.IsOneByte() ? IsIdentifierVector(flat.ToOneByteVector())
                          : IsIdentifierVector(flat.ToUC16Vector());
}

namespace {

template <typename Char>
uint32_t HashString(Tagged<String> string, size_t start, uint32_t length,
                    uint64_t seed,
                    const SharedStringAccessGuardIfNeeded& access_guard) {
  DisallowGarbageCollection no_gc;

  if (length > String::kMaxHashCalcLength) {
    return StringHasher::GetTrivialHash(length);
  }

  std::unique_ptr<Char[]> buffer;
  const Char* chars;

  if (IsConsString(string)) {
    DCHECK_EQ(0, start);
    DCHECK(!string->IsFlat());
    buffer.reset(new Char[length]);
    String::WriteToFlat(string, buffer.get(), 0, length, access_guard);
    chars = buffer.get();
  } else {
    chars = string->GetDirectStringChars<Char>(no_gc, access_guard) + start;
  }

  return StringHasher::HashSequentialString<Char>(chars, length, seed);
}

}  // namespace

uint32_t String::ComputeAndSetRawHash() {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return ComputeAndSetRawHash(SharedStringAccessGuardIfNeeded::NotNeeded());
}

uint32_t String::ComputeAndSetRawHash(
    const SharedStringAccessGuardIfNeeded& access_guard) {
  DisallowGarbageCollection no_gc;
  // Should only be called if hash code has not yet been computed.
  //
  // If in-place internalizable strings are shared, there may be calls to
  // ComputeAndSetRawHash in parallel. Since only flat strings are in-place
  // internalizable and their contents do not change, the result hash is the
  // same. The raw hash field is stored with relaxed ordering.
  DCHECK_IMPLIES(!v8_flags.shared_string_table, !HasHashCode());

  // Store the hash code in the object.
  uint64_t seed = HashSeed(EarlyGetReadOnlyRoots());
  size_t start = 0;
  Tagged<String> string = this;
  StringShape shape(string);
  if (shape.IsSliced()) {
    Tagged<SlicedString> sliced = Cast<SlicedString>(string);
    start = sliced->offset();
    string = sliced->parent();
    shape = StringShape(string);
  }
  if (shape.IsCons() && string->IsFlat()) {
    string = Cast<ConsString>(string)->first();
    shape = StringShape(string);
  }
  if (shape.IsThin()) {
    string = Cast<ThinString>(string)->actual();
    shape = StringShape(string);
    if (length() == string->length()) {
      uint32_t raw_hash = string->RawHash();
      DCHECK(IsHashFieldComputed(raw_hash));
      set_raw_hash_field(raw_hash);
      return raw_hash;
    }
  }
  uint32_t raw_hash_field =
      shape.encoding_tag() == kOneByteStringTag
          ? HashString<uint8_t>(string, start, length(), seed, access_guard)
          : HashString<uint16_t>(string, start, length(), seed, access_guard);
  set_raw_hash_field_if_empty(raw_hash_field);
  // Check the hash code is there (or a forwarding index if the string was
  // internalized/externalized in parallel).
  DCHECK(HasHashCode() || HasForwardingIndex(kAcquireLoad));
  // Ensure that the hash value of 0 is never computed.
  DCHECK_NE(HashBits::decode(raw_hash_field), 0);
  return raw_hash_field;
}

bool String::SlowAsArrayIndex(uint32_t* index) {
  DisallowGarbageCollection no_gc;
  uint32_t length = this->length();
  if (length <= kMaxCachedArrayIndexLength) {
    uint32_t field = EnsureRawHash();  // Force computation of hash code.
    if (!IsIntegerIndex(field)) return false;
    *index = ArrayIndexValueBits::decode(field);
    return true;
  }
  if (length == 0 || length > kMaxArrayIndexSize) return false;
  StringCharacterStream stream(this);
  return StringToIndex(&stream, index);
}

bool String::SlowAsIntegerIndex(size_t* index) {
  DisallowGarbageCollection no_gc;
  uint32_t length = this->length();
  if (length <= kMaxCachedArrayIndexLength) {
    uint32_t field = EnsureRawHash();  // Force computation of hash code.
    if (!IsIntegerIndex(field)) return false;
    *index = ArrayIndexValueBits::decode(field);
    return true;
  }
  if (length == 0 || length > kMaxIntegerIndexSize) return false;
  StringCharacterStream stream(this);
  return StringToIndex<StringCharacterStream, size_t, kToIntegerIndex>(&stream,
                                                                       index);
}

void String::PrintOn(FILE* file) {
  uint32_t length = this->length();
  for (uint32_t i = 0; i < length; i++) {
    PrintF(file, "%c", Get(i));
  }
}

void String::PrintOn(std::ostream& ostream) {
  uint32_t length = this->length();
  for (uint32_t i = 0; i < length; i++) {
    ostream.put(Get(i));
  }
}

Handle<String> SeqString::Truncate(Isolate* isolate, Handle<SeqString> string,
                                   uint32_t new_length) {
  if (new_length == 0) return string->GetReadOnlyRoots().empty_string_handle();

  int new_size, old_size;
  uint32_t old_length = string->length();
  if (old_length <= new_length) return string;

  if (IsSeqOneByteString(*string)) {
    old_size = SeqOneByteString::SizeFor(old_length);
    new_size = SeqOneByteString::SizeFor(new_length);
  } else {
    DCHECK(IsSeqTwoByteString(*string));
    old_size = SeqTwoByteString::SizeFor(old_length);
    new_size = SeqTwoByteString::SizeFor(new_length);
  }

#if DEBUG
  Address start_of_string = (*string).address();
  DCHECK(IsAligned(start_of_string, kObjectAlignment));
  DCHECK(IsAligned(start_of_string + new_size, kObjectAlignment));
#endif

  Heap* heap = isolate->heap();
  if (!heap->IsLargeObject(*string)) {
    // Sizes are pointer size aligned, so that we can use filler objects
    // that are a multiple of pointer size.
    // No slot invalidation needed since this method is only used on freshly
    // allocated strings.
    heap->NotifyObjectSizeChange(*string, old_size, new_size,
                                 ClearRecordedSlots::kNo);
  }
  // We are storing the new length using release store after creating a filler
  // for the left-over space to avoid races with the sweeper thread.
  string->set_length(new_length, kReleaseStore);
  string->ClearPadding();

  return string;
}

SeqString::DataAndPaddingSizes SeqString::GetDataAndPaddingSizes() const {
  if (IsSeqOneByteString(this)) {
    return Cast<SeqOneByteString>(this)->GetDataAndPaddingSizes();
  }
  return Cast<SeqTwoByteString>(this)->GetDataAndPaddingSizes();
}

SeqString::DataAndPaddingSizes SeqOneByteString::GetDataAndPaddingSizes()
    const {
  int data_size = sizeof(SeqOneByteString) + length() * kOneByteSize;
  int padding_size = SizeFor(length()) - data_size;
  return
```