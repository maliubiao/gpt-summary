Response:
Let's break down the thought process for analyzing the given C++ header file.

**1. Initial Scan and Understanding the Purpose:**

The first thing I do is skim the file for keywords and structural elements. I see `#ifndef`, `#define`, `#include`, `namespace v8::internal`, `class`, `template`, and various methods. The filename itself, `string-search.h`, is a huge clue. Combined with the namespace, it strongly suggests this file deals with string searching algorithms within the V8 engine.

**2. Identifying Core Classes and Their Roles:**

I notice two main classes: `StringSearchBase` and `StringSearch`. `StringSearchBase` seems to hold common constants and utility functions used by different search strategies. The `StringSearch` template class appears to be the main entry point for performing searches, parameterized by the character types of the pattern and subject. The presence of `strategy_` and different search function pointers (`FailSearch`, `SingleCharSearch`, etc.) immediately indicates a strategy pattern is being employed.

**3. Deconstructing `StringSearchBase`:**

I look at the members of `StringSearchBase`. The `kBMMaxShift`, `kLatin1AlphabetSize`, `kUC16AlphabetSize`, and `kBMMinPatternLength` constants suggest optimizations and limitations related to the Boyer-Moore family of algorithms and handling different character encodings (Latin-1 and UTF-16). The `IsOneByteString` functions are clearly for checking string encoding.

**4. Deconstructing `StringSearch`:**

Here, the constructor is crucial. It takes an `Isolate` (V8's execution context) and the `pattern`. The logic inside the constructor decides which search `strategy_` to use based on the pattern length and character types. This branching logic (short patterns use linear search, single character uses a dedicated function, longer patterns start with an "InitialSearch" that can upgrade) is a key function.

The `Search` method simply delegates to the selected `strategy_`. The `AlphabetSize` method returns the size of the character alphabet based on the `PatternChar` type.

The private section lists various search strategies and helper functions. The names (`BoyerMooreSearch`, `BoyerMooreHorspoolSearch`, `LinearSearch`) point to well-known string searching algorithms. The presence of `PopulateBoyerMooreHorspoolTable` and `PopulateBoyerMooreTable` confirms the implementation of these algorithms. The `CharOccurrence` function handles looking up characters in the "bad character" table, considering different character encodings. The `bad_char_table`, `good_suffix_shift_table`, and `suffix_table` are clearly related to the Boyer-Moore algorithm's pre-computation steps.

**5. Identifying Key Concepts and Algorithms:**

Based on the class names, constants, and method names, I can identify the following key concepts:

* **String Searching Algorithms:** The core purpose of the file.
* **Boyer-Moore and Boyer-Moore-Horspool:**  The constants and associated methods clearly indicate these algorithms are implemented for efficient searching of longer patterns.
* **Linear Search:** Used for shorter patterns due to lower overhead.
* **Single Character Search:**  An optimized case for searching a single character.
* **Character Encoding Handling (Latin-1 and UTF-16):** The template parameters and the `IsOneByteString` functions demonstrate awareness of different character encodings.
* **Optimization Strategies:** The `kBMMaxShift` and the dynamic strategy selection highlight the focus on performance.
* **Strategy Pattern:**  The use of `strategy_` and the various search function pointers is a clear example of this design pattern.

**6. Connecting to JavaScript (If Applicable):**

Now, I consider how this relates to JavaScript. The most obvious connection is the `String.prototype.indexOf()` method. This JavaScript function performs string searching, and it's highly likely that V8's internal implementation leverages code like what's in this header file to provide that functionality efficiently. I can then construct a simple JavaScript example to illustrate the functionality.

**7. Inferring Logic and Providing Examples:**

With an understanding of the algorithms, I can start to infer the logic. For instance, the Boyer-Moore algorithm works by pre-processing the pattern to create "bad character" and "good suffix" shift tables. This allows it to potentially skip multiple characters in the subject string during the search.

To illustrate the logic, I create simple hypothetical input and output examples for different scenarios, like a successful search, a failed search, and how the algorithm might skip characters.

**8. Considering Common Programming Errors:**

I think about potential pitfalls users might encounter when dealing with string searching, even if they're not directly using this C++ code. Common errors include off-by-one errors in index calculations, assuming a character is present when it's not, and neglecting case sensitivity.

**9. Structure and Refinement:**

Finally, I organize my findings into a structured format, using headings and bullet points to clearly present the different aspects of the code. I review and refine the explanation to ensure clarity and accuracy.

This detailed breakdown shows the systematic approach to understanding a piece of complex code by starting with the big picture, identifying key components, understanding their interactions, and then connecting it to higher-level concepts and potential user applications.这个头文件 `v8/src/strings/string-search.h` 定义了 V8 引擎中用于字符串搜索的类和相关功能。 让我们详细列举一下它的功能：

**主要功能:**

1. **提供高效的字符串搜索算法实现:** 该头文件定义了一个 `StringSearch` 模板类，它封装了多种字符串搜索算法的实现，包括：
    * **线性搜索 (Linear Search):**  对于短小的模式串，简单的逐个字符比较。
    * **Boyer-Moore 算法 (Boyer-Moore Search):** 一种非常高效的字符串搜索算法，它利用预处理模式串的信息来跳过不匹配的字符，从而加速搜索过程。
    * **Boyer-Moore-Horspool 算法 (BoyerMooreHorspoolSearch):**  Boyer-Moore 算法的一个简化版本，通常在实践中也表现良好。
    * **单字符搜索 (SingleCharSearch):**  针对查找单个字符的优化。

2. **动态选择搜索策略:**  `StringSearch` 类会根据模式串的长度和字符类型（单字节或双字节）动态选择最合适的搜索算法。 例如：
    * 对于非常短的模式串，线性搜索可能是最优的，因为它避免了 Boyer-Moore 算法的预处理开销。
    * 对于较长的模式串，Boyer-Moore 或 Boyer-Moore-Horspool 算法通常会更快。

3. **处理不同字符编码:** 该类通过模板参数 `PatternChar` 和 `SubjectChar` 支持不同字符大小的模式串和目标串，例如单字节字符串 (Latin-1) 和双字节字符串 (UTF-16)。

4. **提供预处理步骤:** 对于 Boyer-Moore 系列算法，头文件中包含了预处理模式串以生成查找表（例如坏字符表和好后缀表）的方法，用于加速搜索过程。

5. **支持从指定索引开始搜索:** `Search` 方法接受一个 `index` 参数，允许从目标字符串的指定位置开始搜索。

6. **封装搜索逻辑:** `StringSearch` 类将复杂的搜索逻辑封装起来，为 V8 引擎的其他部分提供了一个简洁的接口来执行字符串搜索。

**关于 .tq 后缀:**

如果 `v8/src/strings/string-search.h` 的文件名以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码** 文件。 Torque 是 V8 使用的一种用于生成优化的 C++ 代码的领域特定语言。Torque 代码会被编译成 C++ 代码，然后与 V8 的其余部分一起编译。

**与 JavaScript 功能的关系和示例:**

`v8/src/strings/string-search.h` 中定义的功能与 JavaScript 中 `String` 对象的以下方法密切相关：

* **`String.prototype.indexOf(searchValue, fromIndex)`:**  此方法返回在调用它的 `String` 对象中第一次出现的指定值的索引，从 `fromIndex` 处开始搜索。 内部实现很可能使用此处定义的搜索算法。

* **`String.prototype.lastIndexOf(searchValue, fromIndex)`:** 此方法返回在调用它的字符串中指定值最后一次出现的索引，在一个字符串中的指定位置从后向前搜索。虽然此头文件主要关注前向搜索，但其概念和某些优化技术也可能被用于 `lastIndexOf` 的实现。

* **`String.prototype.includes(searchString, position)`:**  此方法判断一个字符串是否包含在另一个字符串中，根据情况返回 true 或 false。其内部实现可以使用类似的字符串搜索机制。

**JavaScript 示例：**

```javascript
const str = "Hello World! Hello JavaScript!";
const searchString = "Hello";

// 使用 indexOf 查找 "Hello" 第一次出现的位置
const index1 = str.indexOf(searchString);
console.log(index1); // 输出: 0

// 使用 indexOf 从指定位置开始查找
const index2 = str.indexOf(searchString, 1);
console.log(index2); // 输出: 13

// 使用 includes 判断是否包含 "JavaScript"
const includesJavaScript = str.includes("JavaScript");
console.log(includesJavaScript); // 输出: true
```

在上面的 JavaScript 例子中，当 JavaScript 引擎执行 `indexOf` 或 `includes` 方法时，V8 内部会调用相应的字符串搜索算法来查找子字符串。 `v8/src/strings/string-search.h` 中的代码就提供了这些算法的实现基础。

**代码逻辑推理与假设输入输出:**

假设我们使用 `StringSearch` 类来查找模式串 "abc" 在目标串 "abracadabra" 中的位置。

**假设输入：**

* **模式串 (pattern):** "abc"
* **目标串 (subject):** "abracadabra"
* **起始索引 (index):** 0

**代码逻辑推理：**

1. `StringSearch` 对象被创建，传入模式串 "abc"。
2. 由于模式串长度小于 `kBMMinPatternLength` (假设为 7)，构造函数可能会选择 `LinearSearch` 作为搜索策略。
3. `Search` 方法被调用，传入目标串 "abracadabra" 和起始索引 0。
4. `LinearSearch` 策略会从目标串的起始位置开始，逐个比较模式串和目标串的子串。
5. 第一次比较： "abc" 和 "abr" - 不匹配。
6. 第二次比较： "abc" 和 "bra" - 不匹配。
7. ...
8. 最终，由于 "abc" 没有在 "abracadabra" 中出现，`LinearSearch` 会返回 -1。

**假设输出：**

```
-1
```

**另一个例子，查找 "bra"：**

**假设输入：**

* **模式串 (pattern):** "bra"
* **目标串 (subject):** "abracadabra"
* **起始索引 (index):** 0

**代码逻辑推理：**

1. 步骤 1 和 2 同上，可能仍然选择 `LinearSearch`。
2. `LinearSearch` 会进行比较：
3. 第一次比较： "bra" 和 "abr" - 不匹配。
4. 第二次比较： "bra" 和 "bra" - 匹配！
5. `LinearSearch` 返回匹配的起始索引。

**假设输出：**

```
1
```

**用户常见的编程错误示例：**

1. **假设字符串包含某个子串但大小写不匹配：**

   ```javascript
   const text = "This is a Test";
   const searchTerm = "test";
   if (text.indexOf(searchTerm) !== -1) {
       console.log("Found!"); // 这不会被执行，因为大小写不匹配
   }
   ```
   **解决方法：** 在比较之前将字符串都转换为相同的大小写，例如使用 `toLowerCase()` 或 `toUpperCase()`。

   ```javascript
   const text = "This is a Test";
   const searchTerm = "test";
   if (text.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1) {
       console.log("Found!"); // 现在可以正确找到
   }
   ```

2. **`indexOf` 的起始索引超出字符串长度：**

   ```javascript
   const message = "Hello";
   const index = message.indexOf("e", 10);
   console.log(index); // 输出: -1，因为起始索引超出了字符串长度
   ```
   **解决方法：** 确保 `fromIndex` 参数在字符串的有效范围内。

3. **在循环中使用 `indexOf` 而没有正确更新起始索引，导致无限循环或错误的结果：**

   ```javascript
   const text = "abababa";
   let index = text.indexOf("aba");
   while (index !== -1) {
       console.log("Found at index:", index);
       // 错误：没有更新 index，会导致无限循环
   }
   ```
   **解决方法：** 在找到匹配后，需要更新起始索引以搜索下一个匹配项。

   ```javascript
   const text = "abababa";
   let index = text.indexOf("aba");
   while (index !== -1) {
       console.log("Found at index:", index);
       index = text.indexOf("aba", index + 1); // 正确更新起始索引
   }
   ```

4. **混淆 `indexOf` 和 `search` 方法：** `indexOf` 接受字符串作为参数，而 `search` 接受正则表达式。使用错误的参数类型会导致错误。

总而言之，`v8/src/strings/string-search.h` 是 V8 引擎中实现高效字符串搜索功能的核心组件，它通过多种算法和优化策略，为 JavaScript 的字符串操作提供了强大的支持。了解其功能有助于理解 V8 如何高效地处理字符串查找操作。

Prompt: 
```
这是目录为v8/src/strings/string-search.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/strings/string-search.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_STRINGS_STRING_SEARCH_H_
#define V8_STRINGS_STRING_SEARCH_H_

#include "src/base/strings.h"
#include "src/base/vector.h"
#include "src/execution/isolate.h"
#include "src/objects/string.h"

namespace v8 {
namespace internal {

//---------------------------------------------------------------------
// String Search object.
//---------------------------------------------------------------------

// Class holding constants and methods that apply to all string search variants,
// independently of subject and pattern char size.
class StringSearchBase {
 protected:
  // Cap on the maximal shift in the Boyer-Moore implementation. By setting a
  // limit, we can fix the size of tables. For a needle longer than this limit,
  // search will not be optimal, since we only build tables for a suffix
  // of the string, but it is a safe approximation.
  static const int kBMMaxShift = Isolate::kBMMaxShift;

  // Reduce alphabet to this size.
  // One of the tables used by Boyer-Moore and Boyer-Moore-Horspool has size
  // proportional to the input alphabet. We reduce the alphabet size by
  // equating input characters modulo a smaller alphabet size. This gives
  // a potentially less efficient searching, but is a safe approximation.
  // For needles using only characters in the same Unicode 256-code point page,
  // there is no search speed degradation.
  static const int kLatin1AlphabetSize = 256;
  static const int kUC16AlphabetSize = Isolate::kUC16AlphabetSize;

  // Bad-char shift table stored in the state. It's length is the alphabet size.
  // For patterns below this length, the skip length of Boyer-Moore is too short
  // to compensate for the algorithmic overhead compared to simple brute force.
  static const int kBMMinPatternLength = 7;

  static inline bool IsOneByteString(base::Vector<const uint8_t> string) {
    return true;
  }

  static inline bool IsOneByteString(base::Vector<const base::uc16> string) {
    return String::IsOneByte(string.begin(), string.length());
  }

  friend class Isolate;
};

template <typename PatternChar, typename SubjectChar>
class StringSearch : private StringSearchBase {
 public:
  StringSearch(Isolate* isolate, base::Vector<const PatternChar> pattern)
      : isolate_(isolate),
        pattern_(pattern),
        start_(std::max(0, pattern.length() - kBMMaxShift)) {
    if (sizeof(PatternChar) > sizeof(SubjectChar)) {
      if (!IsOneByteString(pattern_)) {
        strategy_ = &FailSearch;
        return;
      }
    }
    int pattern_length = pattern_.length();
    if (pattern_length < kBMMinPatternLength) {
      if (pattern_length == 1) {
        strategy_ = &SingleCharSearch;
        return;
      }
      strategy_ = &LinearSearch;
      return;
    }
    strategy_ = &InitialSearch;
  }

  int Search(base::Vector<const SubjectChar> subject, int index) {
    return strategy_(this, subject, index);
  }

  static inline int AlphabetSize() {
    if (sizeof(PatternChar) == 1) {
      // Latin1 needle.
      return kLatin1AlphabetSize;
    } else {
      DCHECK_EQ(sizeof(PatternChar), 2);
      // UC16 needle.
      return kUC16AlphabetSize;
    }
  }

 private:
  using SearchFunction = int (*)(StringSearch<PatternChar, SubjectChar>*,
                                 base::Vector<const SubjectChar>, int);

  static int FailSearch(StringSearch<PatternChar, SubjectChar>*,
                        base::Vector<const SubjectChar>, int) {
    return -1;
  }

  static int SingleCharSearch(StringSearch<PatternChar, SubjectChar>* search,
                              base::Vector<const SubjectChar> subject,
                              int start_index);

  static int LinearSearch(StringSearch<PatternChar, SubjectChar>* search,
                          base::Vector<const SubjectChar> subject,
                          int start_index);

  static int InitialSearch(StringSearch<PatternChar, SubjectChar>* search,
                           base::Vector<const SubjectChar> subject,
                           int start_index);

  static int BoyerMooreHorspoolSearch(
      StringSearch<PatternChar, SubjectChar>* search,
      base::Vector<const SubjectChar> subject, int start_index);

  static int BoyerMooreSearch(StringSearch<PatternChar, SubjectChar>* search,
                              base::Vector<const SubjectChar> subject,
                              int start_index);

  void PopulateBoyerMooreHorspoolTable();

  void PopulateBoyerMooreTable();

  static inline bool exceedsOneByte(uint8_t c) { return false; }

  static inline bool exceedsOneByte(uint16_t c) {
    return c > String::kMaxOneByteCharCodeU;
  }

  static inline int CharOccurrence(int* bad_char_occurrence,
                                   SubjectChar char_code) {
    if (sizeof(SubjectChar) == 1) {
      return bad_char_occurrence[static_cast<int>(char_code)];
    }
    if (sizeof(PatternChar) == 1) {
      if (exceedsOneByte(char_code)) {
        return -1;
      }
      return bad_char_occurrence[static_cast<unsigned int>(char_code)];
    }
    // Both pattern and subject are UC16. Reduce character to equivalence
    // class.
    int equiv_class = char_code % kUC16AlphabetSize;
    return bad_char_occurrence[equiv_class];
  }

  // The following tables are shared by all searches.
  // TODO(lrn): Introduce a way for a pattern to keep its tables
  // between searches (e.g., for an Atom RegExp).

  // Store for the BoyerMoore(Horspool) bad char shift table.
  // Return a table covering the last kBMMaxShift+1 positions of
  // pattern.
  int* bad_char_table() { return isolate_->bad_char_shift_table(); }

  // Store for the BoyerMoore good suffix shift table.
  int* good_suffix_shift_table() {
    // Return biased pointer that maps the range  [start_..pattern_.length()
    // to the kGoodSuffixShiftTable array.
    return isolate_->good_suffix_shift_table() - start_;
  }

  // Table used temporarily while building the BoyerMoore good suffix
  // shift table.
  int* suffix_table() {
    // Return biased pointer that maps the range  [start_..pattern_.length()
    // to the kSuffixTable array.
    return isolate_->suffix_table() - start_;
  }

  Isolate* isolate_;
  // The pattern to search for.
  base::Vector<const PatternChar> pattern_;
  // Pointer to implementation of the search.
  SearchFunction strategy_;
  // Cache value of max(0, pattern_length() - kBMMaxShift)
  int start_;
};

template <typename T, typename U>
inline T AlignDown(T value, U alignment) {
  return reinterpret_cast<T>(
      (reinterpret_cast<uintptr_t>(value) & ~(alignment - 1)));
}

inline uint8_t GetHighestValueByte(base::uc16 character) {
  return std::max(static_cast<uint8_t>(character & 0xFF),
                  static_cast<uint8_t>(character >> 8));
}

inline uint8_t GetHighestValueByte(uint8_t character) { return character; }

template <typename PatternChar, typename SubjectChar>
inline int FindFirstCharacter(base::Vector<const PatternChar> pattern,
                              base::Vector<const SubjectChar> subject,
                              int index) {
  const PatternChar pattern_first_char = pattern[0];
  const int max_n = (subject.length() - pattern.length() + 1);

  if (sizeof(SubjectChar) == 2 && pattern_first_char == 0) {
    // Special-case looking for the 0 char in other than one-byte strings.
    // memchr mostly fails in this case due to every other byte being 0 in text
    // that is mostly ascii characters.
    for (int i = index; i < max_n; ++i) {
      if (subject[i] == 0) return i;
    }
    return -1;
  }
  const uint8_t search_byte = GetHighestValueByte(pattern_first_char);
  const SubjectChar search_char = static_cast<SubjectChar>(pattern_first_char);
  int pos = index;
  do {
    DCHECK_GE(max_n - pos, 0);
    const SubjectChar* char_pos = reinterpret_cast<const SubjectChar*>(
        memchr(subject.begin() + pos, search_byte,
               (max_n - pos) * sizeof(SubjectChar)));
    if (char_pos == nullptr) return -1;
    char_pos = AlignDown(char_pos, sizeof(SubjectChar));
    pos = static_cast<int>(char_pos - subject.begin());
    if (subject[pos] == search_char) return pos;
  } while (++pos < max_n);

  return -1;
}

//---------------------------------------------------------------------
// Single Character Pattern Search Strategy
//---------------------------------------------------------------------

template <typename PatternChar, typename SubjectChar>
int StringSearch<PatternChar, SubjectChar>::SingleCharSearch(
    StringSearch<PatternChar, SubjectChar>* search,
    base::Vector<const SubjectChar> subject, int index) {
  DCHECK_EQ(1, search->pattern_.length());
  PatternChar pattern_first_char = search->pattern_[0];
  if (sizeof(PatternChar) > sizeof(SubjectChar)) {
    if (exceedsOneByte(pattern_first_char)) {
      return -1;
    }
  }
  return FindFirstCharacter(search->pattern_, subject, index);
}

//---------------------------------------------------------------------
// Linear Search Strategy
//---------------------------------------------------------------------

template <typename PatternChar, typename SubjectChar>
inline bool CharCompare(const PatternChar* pattern, const SubjectChar* subject,
                        int length) {
  DCHECK_GT(length, 0);
  int pos = 0;
  do {
    if (pattern[pos] != subject[pos]) {
      return false;
    }
    pos++;
  } while (pos < length);
  return true;
}

// Simple linear search for short patterns. Never bails out.
template <typename PatternChar, typename SubjectChar>
int StringSearch<PatternChar, SubjectChar>::LinearSearch(
    StringSearch<PatternChar, SubjectChar>* search,
    base::Vector<const SubjectChar> subject, int index) {
  base::Vector<const PatternChar> pattern = search->pattern_;
  DCHECK_GT(pattern.length(), 1);
  int pattern_length = pattern.length();
  int i = index;
  int n = subject.length() - pattern_length;
  while (i <= n) {
    i = FindFirstCharacter(pattern, subject, i);
    if (i == -1) return -1;
    DCHECK_LE(i, n);
    i++;
    // Loop extracted to separate function to allow using return to do
    // a deeper break.
    if (CharCompare(pattern.begin() + 1, subject.begin() + i,
                    pattern_length - 1)) {
      return i - 1;
    }
  }
  return -1;
}

//---------------------------------------------------------------------
// Boyer-Moore string search
//---------------------------------------------------------------------

template <typename PatternChar, typename SubjectChar>
int StringSearch<PatternChar, SubjectChar>::BoyerMooreSearch(
    StringSearch<PatternChar, SubjectChar>* search,
    base::Vector<const SubjectChar> subject, int start_index) {
  base::Vector<const PatternChar> pattern = search->pattern_;
  int subject_length = subject.length();
  int pattern_length = pattern.length();
  // Only preprocess at most kBMMaxShift last characters of pattern.
  int start = search->start_;

  int* bad_char_occurence = search->bad_char_table();
  int* good_suffix_shift = search->good_suffix_shift_table();

  PatternChar last_char = pattern[pattern_length - 1];
  int index = start_index;
  // Continue search from i.
  while (index <= subject_length - pattern_length) {
    int j = pattern_length - 1;
    int c;
    while (last_char != (c = subject[index + j])) {
      int shift = j - CharOccurrence(bad_char_occurence, c);
      index += shift;
      if (index > subject_length - pattern_length) {
        return -1;
      }
    }
    while (j >= 0 && pattern[j] == (c = subject[index + j])) j--;
    if (j < 0) {
      return index;
    } else if (j < start) {
      // we have matched more than our tables allow us to be smart about.
      // Fall back on BMH shift.
      index += pattern_length - 1 -
               CharOccurrence(bad_char_occurence,
                              static_cast<SubjectChar>(last_char));
    } else {
      int gs_shift = good_suffix_shift[j + 1];
      int bc_occ = CharOccurrence(bad_char_occurence, c);
      int shift = j - bc_occ;
      if (gs_shift > shift) {
        shift = gs_shift;
      }
      index += shift;
    }
  }

  return -1;
}

template <typename PatternChar, typename SubjectChar>
void StringSearch<PatternChar, SubjectChar>::PopulateBoyerMooreTable() {
  int pattern_length = pattern_.length();
  const PatternChar* pattern = pattern_.begin();
  // Only look at the last kBMMaxShift characters of pattern (from start_
  // to pattern_length).
  int start = start_;
  int length = pattern_length - start;

  // Biased tables so that we can use pattern indices as table indices,
  // even if we only cover the part of the pattern from offset start.
  int* shift_table = good_suffix_shift_table();
  int* suffix_table = this->suffix_table();

  // Initialize table.
  for (int i = start; i < pattern_length; i++) {
    shift_table[i] = length;
  }
  shift_table[pattern_length] = 1;
  suffix_table[pattern_length] = pattern_length + 1;

  if (pattern_length <= start) {
    return;
  }

  // Find suffixes.
  PatternChar last_char = pattern[pattern_length - 1];
  int suffix = pattern_length + 1;
  {
    int i = pattern_length;
    while (i > start) {
      PatternChar c = pattern[i - 1];
      while (suffix <= pattern_length && c != pattern[suffix - 1]) {
        if (shift_table[suffix] == length) {
          shift_table[suffix] = suffix - i;
        }
        suffix = suffix_table[suffix];
      }
      suffix_table[--i] = --suffix;
      if (suffix == pattern_length) {
        // No suffix to extend, so we check against last_char only.
        while ((i > start) && (pattern[i - 1] != last_char)) {
          if (shift_table[pattern_length] == length) {
            shift_table[pattern_length] = pattern_length - i;
          }
          suffix_table[--i] = pattern_length;
        }
        if (i > start) {
          suffix_table[--i] = --suffix;
        }
      }
    }
  }
  // Build shift table using suffixes.
  if (suffix < pattern_length) {
    for (int i = start; i <= pattern_length; i++) {
      if (shift_table[i] == length) {
        shift_table[i] = suffix - start;
      }
      if (i == suffix) {
        suffix = suffix_table[suffix];
      }
    }
  }
}

//---------------------------------------------------------------------
// Boyer-Moore-Horspool string search.
//---------------------------------------------------------------------

template <typename PatternChar, typename SubjectChar>
int StringSearch<PatternChar, SubjectChar>::BoyerMooreHorspoolSearch(
    StringSearch<PatternChar, SubjectChar>* search,
    base::Vector<const SubjectChar> subject, int start_index) {
  base::Vector<const PatternChar> pattern = search->pattern_;
  int subject_length = subject.length();
  int pattern_length = pattern.length();
  int* char_occurrences = search->bad_char_table();
  int badness = -pattern_length;

  // How bad we are doing without a good-suffix table.
  PatternChar last_char = pattern[pattern_length - 1];
  int last_char_shift =
      pattern_length - 1 -
      CharOccurrence(char_occurrences, static_cast<SubjectChar>(last_char));
  // Perform search
  int index = start_index;  // No matches found prior to this index.
  while (index <= subject_length - pattern_length) {
    int j = pattern_length - 1;
    int subject_char;
    while (last_char != (subject_char = subject[index + j])) {
      int bc_occ = CharOccurrence(char_occurrences, subject_char);
      int shift = j - bc_occ;
      index += shift;
      badness += 1 - shift;  // at most zero, so badness cannot increase.
      if (index > subject_length - pattern_length) {
        return -1;
      }
    }
    j--;
    while (j >= 0 && pattern[j] == (subject[index + j])) j--;
    if (j < 0) {
      return index;
    } else {
      index += last_char_shift;
      // Badness increases by the number of characters we have
      // checked, and decreases by the number of characters we
      // can skip by shifting. It's a measure of how we are doing
      // compared to reading each character exactly once.
      badness += (pattern_length - j) - last_char_shift;
      if (badness > 0) {
        search->PopulateBoyerMooreTable();
        search->strategy_ = &BoyerMooreSearch;
        return BoyerMooreSearch(search, subject, index);
      }
    }
  }
  return -1;
}

template <typename PatternChar, typename SubjectChar>
void StringSearch<PatternChar, SubjectChar>::PopulateBoyerMooreHorspoolTable() {
  int pattern_length = pattern_.length();

  int* bad_char_occurrence = bad_char_table();

  // Only preprocess at most kBMMaxShift last characters of pattern.
  int start = start_;
  // Run forwards to populate bad_char_table, so that *last* instance
  // of character equivalence class is the one registered.
  // Notice: Doesn't include the last character.
  int table_size = AlphabetSize();
  if (start == 0) {  // All patterns less than kBMMaxShift in length.
    memset(bad_char_occurrence, -1, table_size * sizeof(*bad_char_occurrence));
  } else {
    for (int i = 0; i < table_size; i++) {
      bad_char_occurrence[i] = start - 1;
    }
  }
  for (int i = start; i < pattern_length - 1; i++) {
    PatternChar c = pattern_[i];
    int bucket = (sizeof(PatternChar) == 1) ? c : c % AlphabetSize();
    bad_char_occurrence[bucket] = i;
  }
}

//---------------------------------------------------------------------
// Linear string search with bailout to BMH.
//---------------------------------------------------------------------

// Simple linear search for short patterns, which bails out if the string
// isn't found very early in the subject. Upgrades to BoyerMooreHorspool.
template <typename PatternChar, typename SubjectChar>
int StringSearch<PatternChar, SubjectChar>::InitialSearch(
    StringSearch<PatternChar, SubjectChar>* search,
    base::Vector<const SubjectChar> subject, int index) {
  base::Vector<const PatternChar> pattern = search->pattern_;
  int pattern_length = pattern.length();
  // Badness is a count of how much work we have done.  When we have
  // done enough work we decide it's probably worth switching to a better
  // algorithm.
  int badness = -10 - (pattern_length << 2);

  // We know our pattern is at least 2 characters, we cache the first so
  // the common case of the first character not matching is faster.
  for (int i = index, n = subject.length() - pattern_length; i <= n; i++) {
    badness++;
    if (badness <= 0) {
      i = FindFirstCharacter(pattern, subject, i);
      if (i == -1) return -1;
      DCHECK_LE(i, n);
      int j = 1;
      do {
        if (pattern[j] != subject[i + j]) {
          break;
        }
        j++;
      } while (j < pattern_length);
      if (j == pattern_length) {
        return i;
      }
      badness += j;
    } else {
      search->PopulateBoyerMooreHorspoolTable();
      search->strategy_ = &BoyerMooreHorspoolSearch;
      return BoyerMooreHorspoolSearch(search, subject, i);
    }
  }
  return -1;
}

// Perform a a single stand-alone search.
// If searching multiple times for the same pattern, a search
// object should be constructed once and the Search function then called
// for each search.
template <typename SubjectChar, typename PatternChar>
int SearchString(Isolate* isolate, base::Vector<const SubjectChar> subject,
                 base::Vector<const PatternChar> pattern, int start_index) {
  StringSearch<PatternChar, SubjectChar> search(isolate, pattern);
  return search.Search(subject, start_index);
}

// A wrapper function around SearchString that wraps raw pointers to the subject
// and pattern as vectors before calling SearchString. Used from the
// StringIndexOf builtin.
template <typename SubjectChar, typename PatternChar>
intptr_t SearchStringRaw(Isolate* isolate, const SubjectChar* subject_ptr,
                         int subject_length, const PatternChar* pattern_ptr,
                         int pattern_length, int start_index) {
  DisallowGarbageCollection no_gc;
  base::Vector<const SubjectChar> subject(subject_ptr, subject_length);
  base::Vector<const PatternChar> pattern(pattern_ptr, pattern_length);
  return SearchString(isolate, subject, pattern, start_index);
}

}  // namespace internal
}  // namespace v8

#endif  // V8_STRINGS_STRING_SEARCH_H_

"""

```