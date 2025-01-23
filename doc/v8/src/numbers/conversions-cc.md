Response:
The user wants a summary of the functionality of the C++ code provided. I need to analyze the code and identify its main purpose. Keywords like "conversions", `StringToDouble`, `StringToInt`, `StringToBigInt`, and `DoubleToCString` strongly suggest that this file deals with converting between strings and different number types (doubles, integers, and big integers).

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The filename and the presence of functions like `StringToDouble`, `StringToInt`, and `StringToBigInt` clearly indicate that the primary function is to perform string-to-number conversions.

2. **Analyze Included Headers:** The included headers provide further clues:
    * `<cmath>`:  Mathematical functions, likely used in floating-point conversions.
    * `<limits.h>`: Defines limits for integer types.
    * `<stdarg.h>`: Variable argument lists (though not directly used in the provided snippet, their presence might indicate related functionality elsewhere in the file or a more complete version).
    * `"src/base/numbers/dtoa.h"` and `"src/base/numbers/strtod.h"`:  These are crucial and explicitly indicate conversion functions between doubles and their string representations.
    * `"src/bigint/bigint.h"`: Confirms the presence of BigInt handling.
    * Other headers relate to V8's internal object representation and memory management, which are necessary for these conversions within the V8 engine.

3. **Examine Key Functions:**  Focus on the functions directly involved in conversions:
    * `StringToDouble`: Converts strings to double-precision floating-point numbers.
    * `StringToInt`: Converts strings to integers (within the limits of a double in this context).
    * `StringToBigInt`: Converts strings to arbitrary-precision integers (BigInts).
    * `DoubleToCString`: Converts double-precision floating-point numbers to C-style strings.
    * `InternalStringToIntDouble`: A lower-level helper function for converting strings to doubles, specifically for different radixes.
    * `InternalStringToDouble`: The core implementation for string-to-double conversion, likely using the `fast_float` library.
    * Helper classes like `StringToIntHelper` and `NumberParseIntHelper`: These encapsulate the logic for parsing strings into numbers, handling different radices and potential errors.

4. **Check for Torque:**  The prompt specifically asks about `.tq` files. The given code is `.cc`, so it's standard C++ and not Torque.

5. **Relate to JavaScript:** These conversion functions are the backbone of JavaScript's built-in type coercion when dealing with numbers. Operations like `parseInt()`, `parseFloat()`, and implicit type conversions rely on these underlying C++ implementations. Provide JavaScript examples to illustrate this connection.

6. **Identify Code Logic (with Assumptions):** While the provided snippet is mostly function definitions, there's logic in the `InternalStringToIntDouble` and `InternalStringToDouble` functions for parsing and handling different number formats, including radixes and scientific notation. Provide examples of input and expected output based on this logic. Since the full implementation isn't shown, assumptions need to be made about error handling (e.g., what happens with invalid input).

7. **Recognize Common Programming Errors:**  Think about how users might misuse these conversions in JavaScript. Examples include:
    * Incorrect radix in `parseInt()`.
    * Expecting `parseInt()` to handle floating-point numbers correctly.
    * Not understanding the behavior of implicit type coercion.
    * Issues with very large numbers exceeding the limits of standard JavaScript numbers.

8. **Summarize the Functionality:**  Combine the observations into a concise summary, highlighting the core responsibility of the file.

9. **Address Part 1 and Part 2:** Acknowledge that this is part 1 and prepare for the next part.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the individual functions. The key is to see the bigger picture – the file's role in the overall conversion process.
* I need to be careful not to over-interpret the code or make assumptions about functionality not explicitly present in the snippet. For example, error handling details might be in other parts of the codebase.
* When providing JavaScript examples, ensure they directly relate to the C++ functions being discussed.
* The explanation of code logic should be at a high level, focusing on the intent rather than getting bogged down in implementation details. Use simple examples to illustrate the concepts.
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/numbers/conversions.h"

// ... (rest of the code)
```

这是 `v8/src/numbers/conversions.cc` 文件的内容。

**功能列举:**

这个 C++ 源代码文件的主要功能是提供各种数字类型之间的转换，特别是字符串到数字以及数字到字符串的转换。具体来说，它包含了以下功能：

1. **字符串到双精度浮点数 (double) 的转换 (`StringToDouble`)**:
   - 能够解析包含小数点、正负号、指数的十进制字符串。
   - 可以选择性地支持非十进制前缀 (如 "0x" 表示十六进制, "0o" 表示八进制, "0b" 表示二进制)，通过 `ConversionFlag` 控制。
   - 可以处理 "Infinity" 和 "NaN" 字符串。
   - 可以处理空字符串，并返回指定的默认值。

2. **字符串到整数的转换 (`StringToInt`)**:
   - 将字符串解析为指定进制（radix）的整数。
   - 可以处理带有正负号的整数。
   - 支持识别 "0x"、"0o"、"0b" 前缀来自动确定进制。
   - 可以处理前导零。

3. **字符串到大整数 (BigInt) 的转换 (`StringToBigInt`)**:
   - 将字符串解析为任意精度的整数。
   - 支持指定进制，包括 2、8、10 和 16。
   - 可以处理带有正负号的整数。
   - 支持识别 "0x"、"0o"、"0b" 前缀。

4. **双精度浮点数到 C 风格字符串的转换 (`DoubleToCString`)**:
   - 将 `double` 类型的值转换为其字符串表示形式。
   - 可以处理 NaN、正负无穷大。
   - 对于可以表示为 32 位整数的 `double` 值，会调用 `IntToCString` 进行转换。
   - 使用 `base::DoubleToAscii` 进行核心的转换。

5. **内部辅助函数**:
   - `InternalStringToIntDouble`: 用于将二进制、四进制、八进制、十六进制和三十二进制的字符串转换为 `double`。
   - `InternalStringToDouble`:  `StringToDouble` 的核心实现，使用了 `fast_float` 库进行快速解析。
   - `SimpleStringBuilder`: 一个简单的字符串构建辅助类，用于在字符缓冲区中安全地构建字符串。
   - 其他一些内联辅助函数，如 `JunkStringValue`、`SignedZero`、`isDigit` 等。

6. **支持不同的进制 (radix)**: 这些转换函数通常允许指定输入字符串的进制，从而支持二进制、八进制、十进制和十六进制等。

**关于 .tq 后缀:**

如果 `v8/src/numbers/conversions.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**文件。Torque 是一种 V8 使用的类型化的中间语言，用于生成高效的 C++ 代码。然而，根据您提供的文件名，它是 `.cc` 文件，所以这是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系及举例:**

`v8/src/numbers/conversions.cc` 中的功能直接对应于 JavaScript 中与数字转换相关的内置功能。以下是一些 JavaScript 示例：

1. **`parseInt()` 和 `parseFloat()`**:
   ```javascript
   // 对应 StringToInt
   console.log(parseInt("123"));        // 输出 123
   console.log(parseInt("10", 2));       // 输出 2 (二进制转十进制)
   console.log(parseInt("0xFF"));       // 输出 255 (十六进制)

   // 对应 StringToDouble
   console.log(parseFloat("3.14"));      // 输出 3.14
   console.log(parseFloat("  -1.5e2  ")); // 输出 -150
   console.log(parseFloat("Infinity"));   // 输出 Infinity
   ```

2. **`Number()` 构造函数 (用于字符串到数字的转换)**:
   ```javascript
   // 对应 StringToDouble
   console.log(Number("123.45"));     // 输出 123.45
   console.log(Number("  0b101 "));   // 输出 5 (二进制)
   console.log(Number("0xFF"));      // 输出 255 (十六进制)
   console.log(Number(""));           // 输出 0
   console.log(Number(" "));          // 输出 0
   ```

3. **`BigInt()` 构造函数**:
   ```javascript
   // 对应 StringToBigInt
   console.log(BigInt("12345678901234567890")); // 输出 12345678901234567890n
   console.log(BigInt("0b101"));           // 输出 5n
   console.log(BigInt("-0xFF"));          // 输出 -255n
   ```

4. **`toString()` 方法 (数字到字符串的转换)**:
   ```javascript
   // 对应 DoubleToCString 和 IntToCString (在 DoubleToCString 中调用)
   console.log((123).toString());       // 输出 "123"
   console.log((3.14).toString());      // 输出 "3.14"
   console.log(NaN.toString());         // 输出 "NaN"
   console.log(Infinity.toString());    // 输出 "Infinity"
   console.log((255).toString(16));    // 输出 "ff" (十进制转十六进制字符串)
   ```

**代码逻辑推理 (假设输入与输出):**

假设我们调用了 `StringToInt` 函数，并且传入以下参数：

* **输入字符串:** `"  -0x1A  "`
* **进制 (radix):** `0` (表示自动检测进制)

**推理过程:**

1. `StringToInt` 会创建一个 `NumberParseIntHelper` 对象。
2. `NumberParseIntHelper::ParseInt()` 会被调用。
3. 代码会跳过前导空格。
4. 识别到负号，`sign_` 被设置为 `Sign::kNegative`。
5. 识别到 "0x" 前缀，进制被设置为 16。
6. 解析十六进制数字 "1A"，其十进制值为 26。
7. 最终结果是 -26。

**输出:** `-26` (作为 `double` 类型返回，因为 `StringToInt` 返回 `double`)

假设我们调用了 `StringToDouble` 函数，并且传入以下参数：

* **输入字符串:** `"  +1.23e2  "`
* **`ConversionFlag`:**  假设允许尾随空格 (`ALLOW_TRAILING_JUNK`)

**推理过程:**

1. `StringToDouble` 会调用 `InternalStringToDouble`。
2. 代码会跳过前导空格。
3. 识别到正号，但会被忽略。
4. 使用 `fast_float::from_chars` 解析 "1.23e2"。
5. "1.23e2" 等于 1.23 * 10^2 = 123。
6. 跳过尾随空格。

**输出:** `123.0`

**涉及用户常见的编程错误:**

1. **`parseInt()` 的进制混淆:**
   ```javascript
   console.log(parseInt("010")); // 输出 10 (通常认为是十进制，但在一些旧版本浏览器或特定环境下可能被解析为八进制)
   console.log(parseInt("010", 10)); // 明确指定十进制，避免歧义
   ```
   用户可能忘记或错误地指定 `parseInt()` 的第二个参数（进制），导致解析结果与预期不符。

2. **使用 `parseInt()` 解析浮点数:**
   ```javascript
   console.log(parseInt("3.14")); // 输出 3 (parseInt 只解析整数部分)
   console.log(parseFloat("3.14")); // 正确解析浮点数
   ```
   用户可能期望 `parseInt()` 返回浮点数，但它只会截断小数部分。

3. **字符串到数字的隐式转换错误:**
   ```javascript
   console.log("5" + 3);    // 输出 "53" (字符串拼接)
   console.log(5 + "3");    // 输出 "53" (字符串拼接)
   console.log(5 + Number("3")); // 输出 8 (显式转换为数字)
   ```
   JavaScript 在某些操作中会进行隐式类型转换，用户可能没有意识到这一点，导致字符串被拼接而不是进行数值运算。

4. **BigInt 的使用限制:**
   ```javascript
   console.log(BigInt(Number.MAX_SAFE_INTEGER) + BigInt(1)); // 可以正确计算
   console.log(Number(Number.MAX_SAFE_INTEGER) + 1);       // 可能丢失精度
   ```
   用户在处理超出 JavaScript `Number` 安全范围的大整数时，可能没有使用 `BigInt`，导致精度丢失。

**归纳一下它的功能 (第 1 部分):**

`v8/src/numbers/conversions.cc` 文件的主要功能是提供高效且准确的 C++ 代码来实现字符串和各种数字类型（包括双精度浮点数、整数和大整数）之间的相互转换。这些转换是 V8 引擎处理 JavaScript 中数字类型转换的基础，直接影响 `parseInt()`, `parseFloat()`, `Number()`, `BigInt()` 构造函数以及数字的 `toString()` 方法的行为。 该文件还包含一些内部辅助函数来支持这些转换过程，例如处理不同进制的字符串解析和安全的字符串构建。

### 提示词
```
这是目录为v8/src/numbers/conversions.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/numbers/conversions.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/numbers/conversions.h"

#include <limits.h>
#include <stdarg.h>

#include <cmath>
#include <optional>

#include "src/base/numbers/dtoa.h"
#include "src/base/numbers/strtod.h"
#include "src/base/small-vector.h"
#include "src/bigint/bigint.h"
#include "src/common/assert-scope.h"
#include "src/handles/handles.h"
#include "src/heap/factory.h"
#include "src/objects/bigint.h"
#include "src/objects/objects-inl.h"
#include "src/objects/string-inl.h"
#include "src/strings/char-predicates-inl.h"
#include "src/utils/allocation.h"

#define FASTFLOAT_ALLOWS_LEADING_PLUS

#include "third_party/fast_float/src/include/fast_float/fast_float.h"
#include "third_party/fast_float/src/include/fast_float/float_common.h"

#if defined(_STLP_VENDOR_CSTD)
// STLPort doesn't import fpclassify into the std namespace.
#define FPCLASSIFY_NAMESPACE
#else
#define FPCLASSIFY_NAMESPACE std
#endif

namespace v8 {
namespace internal {

// Helper class for building result strings in a character buffer. The
// purpose of the class is to use safe operations that checks the
// buffer bounds on all operations in debug mode.
// This simple base class does not allow formatted output.
class SimpleStringBuilder {
 public:
  // Create a string builder with a buffer of the given size. The
  // buffer is allocated through NewArray<char> and must be
  // deallocated by the caller of Finalize().
  explicit SimpleStringBuilder(int size) {
    buffer_ = base::Vector<char>::New(size);
    position_ = 0;
  }

  SimpleStringBuilder(char* buffer, int size)
      : buffer_(buffer, size), position_(0) {}

  ~SimpleStringBuilder() {
    if (!is_finalized()) Finalize();
  }

  // Get the current position in the builder.
  int position() const {
    DCHECK(!is_finalized());
    return position_;
  }

  // Add a single character to the builder. It is not allowed to add
  // 0-characters; use the Finalize() method to terminate the string
  // instead.
  void AddCharacter(char c) {
    DCHECK_NE(c, '\0');
    DCHECK(!is_finalized() && position_ < buffer_.length());
    buffer_[position_++] = c;
  }

  // Add an entire string to the builder. Uses strlen() internally to
  // compute the length of the input string.
  void AddString(const char* s) {
    size_t len = strlen(s);
    DCHECK_GE(kMaxInt, len);
    AddSubstring(s, static_cast<int>(len));
  }

  // Add the first 'n' characters of the given 0-terminated string 's' to the
  // builder. The input string must have enough characters.
  void AddSubstring(const char* s, int n) {
    DCHECK(!is_finalized() && position_ + n <= buffer_.length());
    DCHECK_LE(n, strlen(s));
    std::memcpy(&buffer_[position_], s, n * kCharSize);
    position_ += n;
  }

  // Add character padding to the builder. If count is non-positive,
  // nothing is added to the builder.
  void AddPadding(char c, int count) {
    for (int i = 0; i < count; i++) {
      AddCharacter(c);
    }
  }

  // Add the decimal representation of the value.
  void AddDecimalInteger(int value) {
    uint32_t number = static_cast<uint32_t>(value);
    if (value < 0) {
      AddCharacter('-');
      number = static_cast<uint32_t>(-value);
    }
    int digits = 1;
    for (uint32_t factor = 10; digits < 10; digits++, factor *= 10) {
      if (factor > number) break;
    }
    position_ += digits;
    for (int i = 1; i <= digits; i++) {
      buffer_[position_ - i] = '0' + static_cast<char>(number % 10);
      number /= 10;
    }
  }

  // Finalize the string by 0-terminating it and returning the buffer.
  char* Finalize() {
    DCHECK(!is_finalized() && position_ <= buffer_.length());
    // If there is no space for null termination, overwrite last character.
    if (position_ == buffer_.length()) {
      position_--;
      // Print ellipsis.
      for (int i = 3; i > 0 && position_ > i; --i) buffer_[position_ - i] = '.';
    }
    buffer_[position_] = '\0';
    // Make sure nobody managed to add a 0-character to the
    // buffer while building the string.
    DCHECK(strlen(buffer_.begin()) == static_cast<size_t>(position_));
    position_ = -1;
    DCHECK(is_finalized());
    return buffer_.begin();
  }

 protected:
  base::Vector<char> buffer_;
  int position_;

  bool is_finalized() const { return position_ < 0; }

 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(SimpleStringBuilder);
};

inline double JunkStringValue() {
  return base::bit_cast<double, uint64_t>(kQuietNaNMask);
}

inline double SignedZero(bool negative) {
  return negative ? base::uint64_to_double(base::Double::kSignMask) : 0.0;
}

inline bool isDigit(int x, int radix) {
  return (x >= '0' && x <= '9' && x < '0' + radix) ||
         (radix > 10 && x >= 'a' && x < 'a' + radix - 10) ||
         (radix > 10 && x >= 'A' && x < 'A' + radix - 10);
}

inline bool isBinaryDigit(int x) { return x == '0' || x == '1'; }

template <class Char>
bool SubStringEquals(const Char** current, const Char* end,
                     const char* substring) {
  DCHECK(**current == *substring);
  for (substring++; *substring != '\0'; substring++) {
    ++*current;
    if (*current == end || **current != *substring) return false;
  }
  ++*current;
  return true;
}

// Returns true if a nonspace character has been found and false if the
// end was been reached before finding a nonspace character.
template <class Char>
inline bool AdvanceToNonspace(const Char** current, const Char* end) {
  while (*current != end) {
    if (!IsWhiteSpaceOrLineTerminator(**current)) return true;
    ++*current;
  }
  return false;
}

// Parsing integers with radix 2, 4, 8, 16, 32. Assumes current != end.
template <int radix_log_2, class Char>
double InternalStringToIntDouble(const Char* start, const Char* end,
                                 bool negative, bool allow_trailing_junk) {
  const Char* current = start;
  DCHECK_NE(current, end);

  // Skip leading 0s.
  while (*current == '0') {
    ++current;
    if (current == end) return SignedZero(negative);
  }

  int64_t number = 0;
  int exponent = 0;
  constexpr int radix = (1 << radix_log_2);

  constexpr int lim_0 = '0' + (radix < 10 ? radix : 10);
  constexpr int lim_a = 'a' + (radix - 10);
  constexpr int lim_A = 'A' + (radix - 10);

  do {
    int digit;
    if (*current >= '0' && *current < lim_0) {
      digit = static_cast<char>(*current) - '0';
    } else if (*current >= 'a' && *current < lim_a) {
      digit = static_cast<char>(*current) - 'a' + 10;
    } else if (*current >= 'A' && *current < lim_A) {
      digit = static_cast<char>(*current) - 'A' + 10;
    } else {
      // We've not found any digits, this must be junk.
      if (current == start) return JunkStringValue();
      if (allow_trailing_junk || !AdvanceToNonspace(&current, end)) break;
      return JunkStringValue();
    }

    number = number * radix + digit;
    int overflow = static_cast<int>(number >> 53);
    if (overflow != 0) {
      // Overflow occurred. Need to determine which direction to round the
      // result.
      int overflow_bits_count = 1;
      while (overflow > 1) {
        overflow_bits_count++;
        overflow >>= 1;
      }

      int dropped_bits_mask = ((1 << overflow_bits_count) - 1);
      int dropped_bits = static_cast<int>(number) & dropped_bits_mask;
      number >>= overflow_bits_count;
      exponent = overflow_bits_count;

      bool zero_tail = true;
      while (true) {
        ++current;
        if (current == end || !isDigit(*current, radix)) break;
        zero_tail = zero_tail && *current == '0';
        exponent += radix_log_2;
      }

      if (!allow_trailing_junk && AdvanceToNonspace(&current, end)) {
        return JunkStringValue();
      }

      int middle_value = (1 << (overflow_bits_count - 1));
      if (dropped_bits > middle_value) {
        number++;  // Rounding up.
      } else if (dropped_bits == middle_value) {
        // Rounding to even to consistency with decimals: half-way case rounds
        // up if significant part is odd and down otherwise.
        if ((number & 1) != 0 || !zero_tail) {
          number++;  // Rounding up.
        }
      }

      // Rounding up may cause overflow.
      if ((number & (static_cast<int64_t>(1) << 53)) != 0) {
        exponent++;
        number >>= 1;
      }
      break;
    }
    ++current;
  } while (current != end);

  DCHECK(number < ((int64_t)1 << 53));
  DCHECK(static_cast<int64_t>(static_cast<double>(number)) == number);

  if (exponent == 0) {
    if (negative) {
      if (number == 0) return -0.0;
      number = -number;
    }
    return static_cast<double>(number);
  }

  DCHECK_NE(number, 0);
  return std::ldexp(static_cast<double>(negative ? -number : number), exponent);
}

namespace {

// Subclasses of StringToIntHelper get access to internal state:
enum class State { kRunning, kError, kJunk, kEmpty, kZero, kDone };

enum class Sign { kNegative, kPositive, kNone };

}  // namespace

// ES6 18.2.5 parseInt(string, radix) (with NumberParseIntHelper subclass);
// and BigInt parsing cases from https://tc39.github.io/proposal-bigint/
// (with StringToBigIntHelper subclass).
class StringToIntHelper {
 public:
  StringToIntHelper(Handle<String> subject, int radix)
      : subject_(subject), radix_(radix) {
    DCHECK(subject->IsFlat());
  }

  // Used for the NumberParseInt operation
  StringToIntHelper(const uint8_t* subject, int radix, int length)
      : raw_one_byte_subject_(subject), radix_(radix), length_(length) {}

  StringToIntHelper(const base::uc16* subject, int radix, int length)
      : raw_two_byte_subject_(subject), radix_(radix), length_(length) {}

  // Used for the StringToBigInt operation.
  explicit StringToIntHelper(Handle<String> subject) : subject_(subject) {
    DCHECK(subject->IsFlat());
  }

  // Used for parsing BigInt literals, where the input is a Zone-allocated
  // buffer of one-byte digits, along with an optional radix prefix.
  StringToIntHelper(const uint8_t* subject, int length)
      : raw_one_byte_subject_(subject), length_(length) {}
  virtual ~StringToIntHelper() = default;

 protected:
  // Subclasses must implement these:
  virtual void ParseOneByte(const uint8_t* start) = 0;
  virtual void ParseTwoByte(const base::uc16* start) = 0;

  // Subclasses must call this to do all the work.
  void ParseInt();

  // Subclass constructors should call these for configuration before calling
  // ParseInt().
  void set_allow_binary_and_octal_prefixes() {
    allow_binary_and_octal_prefixes_ = true;
  }
  void set_disallow_trailing_junk() { allow_trailing_junk_ = false; }
  bool allow_trailing_junk() { return allow_trailing_junk_; }

  bool IsOneByte() const {
    if (raw_two_byte_subject_ != nullptr) return false;
    return raw_one_byte_subject_ != nullptr ||
           subject_->IsOneByteRepresentation();
  }

  base::Vector<const uint8_t> GetOneByteVector(
      const DisallowGarbageCollection& no_gc) {
    if (raw_one_byte_subject_ != nullptr) {
      return base::Vector<const uint8_t>(raw_one_byte_subject_, length_);
    }
    return subject_->GetFlatContent(no_gc).ToOneByteVector();
  }

  base::Vector<const base::uc16> GetTwoByteVector(
      const DisallowGarbageCollection& no_gc) {
    if (raw_two_byte_subject_ != nullptr) {
      return base::Vector<const base::uc16>(raw_two_byte_subject_, length_);
    }
    return subject_->GetFlatContent(no_gc).ToUC16Vector();
  }

  int radix() { return radix_; }
  int cursor() { return cursor_; }
  int length() { return length_; }
  bool negative() { return sign_ == Sign::kNegative; }
  Sign sign() { return sign_; }
  State state() { return state_; }
  void set_state(State state) { state_ = state; }

 private:
  template <class Char>
  void DetectRadixInternal(const Char* current, int length);

  Handle<String> subject_;
  const uint8_t* raw_one_byte_subject_ = nullptr;
  const base::uc16* raw_two_byte_subject_ = nullptr;
  int radix_ = 0;
  int cursor_ = 0;
  int length_ = 0;
  Sign sign_ = Sign::kNone;
  bool leading_zero_ = false;
  bool allow_binary_and_octal_prefixes_ = false;
  bool allow_trailing_junk_ = true;
  State state_ = State::kRunning;
};

void StringToIntHelper::ParseInt() {
  DisallowGarbageCollection no_gc;
  if (IsOneByte()) {
    base::Vector<const uint8_t> vector = GetOneByteVector(no_gc);
    DetectRadixInternal(vector.begin(), vector.length());
    if (state_ != State::kRunning) return;
    ParseOneByte(vector.begin());
  } else {
    base::Vector<const base::uc16> vector = GetTwoByteVector(no_gc);
    DetectRadixInternal(vector.begin(), vector.length());
    if (state_ != State::kRunning) return;
    ParseTwoByte(vector.begin());
  }
}

template <class Char>
void StringToIntHelper::DetectRadixInternal(const Char* current, int length) {
  const Char* start = current;
  length_ = length;
  const Char* end = start + length;

  if (!AdvanceToNonspace(&current, end)) {
    return set_state(State::kEmpty);
  }

  if (*current == '+') {
    // Ignore leading sign; skip following spaces.
    ++current;
    if (current == end) {
      return set_state(State::kJunk);
    }
    sign_ = Sign::kPositive;
  } else if (*current == '-') {
    ++current;
    if (current == end) {
      return set_state(State::kJunk);
    }
    sign_ = Sign::kNegative;
  }

  if (radix_ == 0) {
    // Radix detection.
    radix_ = 10;
    if (*current == '0') {
      ++current;
      if (current == end) return set_state(State::kZero);
      if (*current == 'x' || *current == 'X') {
        radix_ = 16;
        ++current;
        if (current == end) return set_state(State::kJunk);
      } else if (allow_binary_and_octal_prefixes_ &&
                 (*current == 'o' || *current == 'O')) {
        radix_ = 8;
        ++current;
        if (current == end) return set_state(State::kJunk);
      } else if (allow_binary_and_octal_prefixes_ &&
                 (*current == 'b' || *current == 'B')) {
        radix_ = 2;
        ++current;
        if (current == end) return set_state(State::kJunk);
      } else {
        leading_zero_ = true;
      }
    }
  } else if (radix_ == 16) {
    if (*current == '0') {
      // Allow "0x" prefix.
      ++current;
      if (current == end) return set_state(State::kZero);
      if (*current == 'x' || *current == 'X') {
        ++current;
        if (current == end) return set_state(State::kJunk);
      } else {
        leading_zero_ = true;
      }
    }
  }
  // Skip leading zeros.
  while (*current == '0') {
    leading_zero_ = true;
    ++current;
    if (current == end) return set_state(State::kZero);
  }
  // Detect leading zeros with junk after them, if allowed.
  if (leading_zero_ && allow_trailing_junk_ && !isDigit(*current, radix_)) {
    return set_state(State::kZero);
  }

  if (!leading_zero_ && !isDigit(*current, radix_)) {
    return set_state(State::kJunk);
  }

  DCHECK(radix_ >= 2 && radix_ <= 36);
  static_assert(String::kMaxLength <= INT_MAX);
  cursor_ = static_cast<int>(current - start);
}

class NumberParseIntHelper : public StringToIntHelper {
 public:
  NumberParseIntHelper(Handle<String> string, int radix)
      : StringToIntHelper(string, radix) {}

  NumberParseIntHelper(const uint8_t* string, int radix, int length)
      : StringToIntHelper(string, radix, length) {}

  NumberParseIntHelper(const base::uc16* string, int radix, int length)
      : StringToIntHelper(string, radix, length) {}

  template <class Char>
  void ParseInternal(const Char* start) {
    const Char* current = start + cursor();
    const Char* end = start + length();

    if (radix() == 10) return HandleBaseTenCase(current, end);
    if (base::bits::IsPowerOfTwo(radix())) {
      result_ = HandlePowerOfTwoCase(current, end);
      set_state(State::kDone);
      return;
    }
    return HandleGenericCase(current, end);
  }
  void ParseOneByte(const uint8_t* start) final { return ParseInternal(start); }
  void ParseTwoByte(const base::uc16* start) final {
    return ParseInternal(start);
  }

  double GetResult() {
    ParseInt();
    switch (state()) {
      case State::kJunk:
      case State::kEmpty:
        return JunkStringValue();
      case State::kZero:
        return SignedZero(negative());
      case State::kDone:
        return negative() ? -result_ : result_;
      case State::kError:
      case State::kRunning:
        break;
    }
    UNREACHABLE();
  }

 private:
  template <class Char>
  void HandleGenericCase(const Char* current, const Char* end);

  template <class Char>
  double HandlePowerOfTwoCase(const Char* current, const Char* end) {
    const bool allow_trailing_junk = true;
    // GetResult() will take care of the sign bit, so ignore it for now.
    const bool negative = false;
    switch (radix()) {
      case 2:
        return InternalStringToIntDouble<1>(current, end, negative,
                                            allow_trailing_junk);
      case 4:
        return InternalStringToIntDouble<2>(current, end, negative,
                                            allow_trailing_junk);
      case 8:
        return InternalStringToIntDouble<3>(current, end, negative,
                                            allow_trailing_junk);

      case 16:
        return InternalStringToIntDouble<4>(current, end, negative,
                                            allow_trailing_junk);

      case 32:
        return InternalStringToIntDouble<5>(current, end, negative,
                                            allow_trailing_junk);
      default:
        UNREACHABLE();
    }
  }

  template <class Char>
  void HandleBaseTenCase(const Char* current, const Char* end) {
    // Parsing with strtod.
    const int kMaxSignificantDigits = 309;  // Doubles are less than 1.8e308.
    // The buffer may contain up to kMaxSignificantDigits + 1 digits and a zero
    // end.
    const int kBufferSize = kMaxSignificantDigits + 2;
    char buffer[kBufferSize];
    int buffer_pos = 0;
    while (*current >= '0' && *current <= '9') {
      if (buffer_pos <= kMaxSignificantDigits) {
        // If the number has more than kMaxSignificantDigits it will be parsed
        // as infinity.
        DCHECK_LT(buffer_pos, kBufferSize);
        buffer[buffer_pos++] = static_cast<char>(*current);
      }
      ++current;
      if (current == end) break;
    }

    SLOW_DCHECK(buffer_pos < kBufferSize);
    buffer[buffer_pos] = '\0';
    base::Vector<const char> buffer_vector(buffer, buffer_pos);
    result_ = Strtod(buffer_vector, 0);
    set_state(State::kDone);
  }

  double result_ = 0;
};

template <class Char>
void NumberParseIntHelper::HandleGenericCase(const Char* current,
                                             const Char* end) {
  // The following code causes accumulating rounding error for numbers greater
  // than ~2^56. It's explicitly allowed in the spec: "if R is not 2, 4, 8, 10,
  // 16, or 32, then mathInt may be an implementation-dependent approximation to
  // the mathematical integer value" (15.1.2.2).

  int lim_0 = '0' + (radix() < 10 ? radix() : 10);
  int lim_a = 'a' + (radix() - 10);
  int lim_A = 'A' + (radix() - 10);

  // NOTE: The code for computing the value may seem a bit complex at
  // first glance. It is structured to use 32-bit multiply-and-add
  // loops as long as possible to avoid losing precision.

  bool done = false;
  do {
    // Parse the longest part of the string starting at {current}
    // possible while keeping the multiplier, and thus the part
    // itself, within 32 bits.
    uint32_t part = 0, multiplier = 1;
    while (true) {
      uint32_t d;
      if (*current >= '0' && *current < lim_0) {
        d = *current - '0';
      } else if (*current >= 'a' && *current < lim_a) {
        d = *current - 'a' + 10;
      } else if (*current >= 'A' && *current < lim_A) {
        d = *current - 'A' + 10;
      } else {
        done = true;
        break;
      }

      // Update the value of the part as long as the multiplier fits
      // in 32 bits. When we can't guarantee that the next iteration
      // will not overflow the multiplier, we stop parsing the part
      // by leaving the loop.
      const uint32_t kMaximumMultiplier = 0xFFFFFFFFU / 36;
      uint32_t m = multiplier * static_cast<uint32_t>(radix());
      if (m > kMaximumMultiplier) break;
      part = part * radix() + d;
      multiplier = m;
      DCHECK(multiplier > part);

      ++current;
      if (current == end) {
        done = true;
        break;
      }
    }
    result_ = result_ * multiplier + part;
  } while (!done);

  if (!allow_trailing_junk() && AdvanceToNonspace(&current, end)) {
    return set_state(State::kJunk);
  }
  return set_state(State::kDone);
}

// Converts a string to a double value.
template <class Char>
double InternalStringToDouble(const Char* current, const Char* end,
                              ConversionFlag flag, double empty_string_val) {
  // To make sure that iterator dereferencing is valid the following
  // convention is used:
  // 1. Each '++current' statement is followed by check for equality to 'end'.
  // 2. If AdvanceToNonspace returned false then current == end.
  // 3. If 'current' becomes be equal to 'end' the function returns or goes to
  // 'parsing_done'.
  // 4. 'current' is not dereferenced after the 'parsing_done' label.
  // 5. Code before 'parsing_done' may rely on 'current != end'.
  if (!AdvanceToNonspace(&current, end)) {
    return empty_string_val;
  }

  // The non-decimal prefix has to be the first thing after any whitespace,
  // so check for this first.
  if (flag == ALLOW_NON_DECIMAL_PREFIX) {
    // Copy the current iterator, so that on a failure to find the prefix, we
    // rewind to the start.
    const Char* prefixed = current;
    if (*prefixed == '0') {
      ++prefixed;
      if (prefixed == end) return 0;

      if (*prefixed == 'x' || *prefixed == 'X') {
        ++prefixed;
        if (prefixed == end) return JunkStringValue();  // "0x".
        return InternalStringToIntDouble<4>(prefixed, end, false, false);
      } else if (*prefixed == 'o' || *prefixed == 'O') {
        ++prefixed;
        if (prefixed == end) return JunkStringValue();  // "0o".
        return InternalStringToIntDouble<3>(prefixed, end, false, false);
      } else if (*prefixed == 'b' || *prefixed == 'B') {
        ++prefixed;
        if (prefixed == end) return JunkStringValue();  // "0b".
        return InternalStringToIntDouble<1>(prefixed, end, false, false);
      }
    }
  }

  // From here we are parsing a StrDecimalLiteral, as per
  // https://tc39.es/ecma262/#sec-tonumber-applied-to-the-string-type
  const bool allow_trailing_junk = flag == ALLOW_TRAILING_JUNK;

  double value;
  // fast_float takes a char/char16_t instead of a uint8_t/uint16_t. Cast the
  // pointers to match.
  using UC = std::conditional_t<std::is_same_v<Char, uint8_t>, char, char16_t>;
  static_assert(sizeof(UC) == sizeof(Char));
  const UC* current_uc = reinterpret_cast<const UC*>(current);
  const UC* end_uc = reinterpret_cast<const UC*>(end);
  auto ret = fast_float::from_chars(current_uc, end_uc, value,
                                    static_cast<fast_float::chars_format>(
                                        fast_float::chars_format::general |
                                        fast_float::chars_format::no_infnan));
  if (ret.ptr == end_uc) return value;
  if (ret.ptr > current_uc) {
    current = reinterpret_cast<const Char*>(ret.ptr);
    if (!allow_trailing_junk && AdvanceToNonspace(&current, end)) {
      return JunkStringValue();
    }
    return value;
  }

  // Failed to parse any number -- handle ±Infinity before giving up.
  DCHECK_EQ(ret.ptr, current_uc);
  DCHECK_NE(current, end);
  static constexpr char kInfinityString[] = "Infinity";
  switch (*current) {
    case '+':
      // Ignore leading plus sign.
      ++current;
      if (current == end) return JunkStringValue();
      if (*current != kInfinityString[0]) return JunkStringValue();
      [[fallthrough]];
    case kInfinityString[0]:
      if (!SubStringEquals(&current, end, kInfinityString)) {
        return JunkStringValue();
      }
      if (!allow_trailing_junk && AdvanceToNonspace(&current, end)) {
        return JunkStringValue();
      }
      return V8_INFINITY;

    case '-':
      ++current;
      if (current == end) return JunkStringValue();
      if (*current != kInfinityString[0]) return JunkStringValue();
      if (!SubStringEquals(&current, end, kInfinityString)) {
        return JunkStringValue();
      }
      if (!allow_trailing_junk && AdvanceToNonspace(&current, end)) {
        return JunkStringValue();
      }
      return -V8_INFINITY;

    default:
      return JunkStringValue();
  }
}

double StringToDouble(const char* str, ConversionFlag flags,
                      double empty_string_val) {
  // We use {base::OneByteVector} instead of {base::CStrVector} to avoid
  // instantiating the InternalStringToDouble() template for {const char*} as
  // well.
  return StringToDouble(base::OneByteVector(str), flags, empty_string_val);
}

double StringToDouble(base::Vector<const uint8_t> str, ConversionFlag flags,
                      double empty_string_val) {
  return InternalStringToDouble(str.begin(), str.end(), flags,
                                empty_string_val);
}

double StringToDouble(base::Vector<const base::uc16> str, ConversionFlag flags,
                      double empty_string_val) {
  return InternalStringToDouble(str.begin(), str.end(), flags,
                                empty_string_val);
}

double BinaryStringToDouble(base::Vector<const uint8_t> str) {
  DCHECK_EQ(str[0], '0');
  DCHECK_EQ(tolower(str[1]), 'b');
  return InternalStringToIntDouble<1>(str.begin() + 2, str.end(), false, false);
}

double OctalStringToDouble(base::Vector<const uint8_t> str) {
  DCHECK_EQ(str[0], '0');
  DCHECK_EQ(tolower(str[1]), 'o');
  return InternalStringToIntDouble<3>(str.begin() + 2, str.end(), false, false);
}

double HexStringToDouble(base::Vector<const uint8_t> str) {
  DCHECK_EQ(str[0], '0');
  DCHECK_EQ(tolower(str[1]), 'x');
  return InternalStringToIntDouble<4>(str.begin() + 2, str.end(), false, false);
}

double ImplicitOctalStringToDouble(base::Vector<const uint8_t> str) {
  return InternalStringToIntDouble<3>(str.begin(), str.end(), false, false);
}

double StringToInt(Isolate* isolate, Handle<String> string, int radix) {
  NumberParseIntHelper helper(string, radix);
  return helper.GetResult();
}

template <typename IsolateT>
class StringToBigIntHelper : public StringToIntHelper {
 public:
  enum class Behavior { kStringToBigInt, kLiteral };

  // Used for StringToBigInt operation (BigInt constructor and == operator).
  StringToBigIntHelper(IsolateT* isolate, Handle<String> string)
      : StringToIntHelper(string),
        isolate_(isolate),
        behavior_(Behavior::kStringToBigInt) {
    set_allow_binary_and_octal_prefixes();
    set_disallow_trailing_junk();
  }

  // Used for parsing BigInt literals, where the input is a buffer of
  // one-byte ASCII digits, along with an optional radix prefix.
  StringToBigIntHelper(IsolateT* isolate, const uint8_t* string, int length)
      : StringToIntHelper(string, length),
        isolate_(isolate),
        behavior_(Behavior::kLiteral) {
    set_allow_binary_and_octal_prefixes();
  }

  void ParseOneByte(const uint8_t* start) final { return ParseInternal(start); }
  void ParseTwoByte(const base::uc16* start) final {
    return ParseInternal(start);
  }

  MaybeHandle<BigInt> GetResult() {
    ParseInt();
    if (behavior_ == Behavior::kStringToBigInt && sign() != Sign::kNone &&
        radix() != 10) {
      return MaybeHandle<BigInt>();
    }
    if (state() == State::kEmpty) {
      if (behavior_ == Behavior::kStringToBigInt) {
        set_state(State::kZero);
      } else {
        UNREACHABLE();
      }
    }
    switch (this->state()) {
      case State::kJunk:
      case State::kError:
        return MaybeHandle<BigInt>();
      case State::kZero:
        return BigInt::Zero(isolate(), allocation_type());
      case State::kDone:
        return BigInt::Allocate(isolate(), &accumulator_, negative(),
                                allocation_type());
      case State::kEmpty:
      case State::kRunning:
        break;
    }
    UNREACHABLE();
  }

  // Used for converting BigInt literals. The scanner has already checked
  // that the literal is valid and not too big, so this always succeeds.
  std::unique_ptr<char[]> DecimalString(bigint::Processor* processor) {
    DCHECK_EQ(behavior_, Behavior::kLiteral);
    ParseInt();
    if (state() == State::kZero) {
      // Input may have been "0x0" or similar.
      return std::unique_ptr<char[]>(new char[2]{'0', '\0'});
    }
    DCHECK_EQ(state(), State::kDone);
    int num_digits = accumulator_.ResultLength();
    base::SmallVector<bigint::digit_t, 8> digit_storage(num_digits);
    bigint::RWDigits digits(digit_storage.data(), num_digits);
    processor->FromString(digits, &accumulator_);
    uint32_t num_chars = bigint::ToStringResultLength(digits, 10, false);
    std::unique_ptr<char[]> out(new char[num_chars + 1]);
    processor->ToString(out.get(), &num_chars, digits, 10, false);
    out[num_chars] = '\0';
    return out;
  }
  IsolateT* isolate() { return isolate_; }

 private:
  template <class Char>
  void ParseInternal(const Char* start) {
    using Result = bigint::FromStringAccumulator::Result;
    const Char* current = start + cursor();
    const Char* end = start + length();
    current = accumulator_.Parse(current, end, radix());

    Result result = accumulator_.result();
    if (result == Result::kMaxSizeExceeded) {
      return set_state(State::kError);
    }
    if (!allow_trailing_junk() && AdvanceToNonspace(&current, end)) {
      return set_state(State::kJunk);
    }
    return set_state(State::kDone);
  }

  AllocationType allocation_type() {
    // For literals, we pretenure the allocated BigInt, since it's about
    // to be stored in the interpreter's constants array.
    return behavior_ == Behavior::kLiteral ? AllocationType::kOld
                                           : AllocationType::kYoung;
  }

  IsolateT* isolate_;
  bigint::FromStringAccumulator accumulator_{BigInt::kMaxLength};
  Behavior behavior_;
};

MaybeHandle<BigInt> StringToBigInt(Isolate* isolate, Handle<String> string) {
  string = String::Flatten(isolate, string);
  StringToBigIntHelper<Isolate> helper(isolate, string);
  return helper.GetResult();
}

template <typename IsolateT>
MaybeHandle<BigInt> BigIntLiteral(IsolateT* isolate, const char* string) {
  StringToBigIntHelper<IsolateT> helper(
      isolate, reinterpret_cast<const uint8_t*>(string),
      static_cast<int>(strlen(string)));
  return helper.GetResult();
}
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    MaybeHandle<BigInt> BigIntLiteral(Isolate* isolate, const char* string);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    MaybeHandle<BigInt> BigIntLiteral(LocalIsolate* isolate,
                                      const char* string);

std::unique_ptr<char[]> BigIntLiteralToDecimal(
    LocalIsolate* isolate, base::Vector<const uint8_t> literal) {
  StringToBigIntHelper<LocalIsolate> helper(nullptr, literal.begin(),
                                            literal.length());
  return helper.DecimalString(isolate->bigint_processor());
}

const char* DoubleToCString(double v, base::Vector<char> buffer) {
  switch (FPCLASSIFY_NAMESPACE::fpclassify(v)) {
    case FP_NAN:
      return "NaN";
    case FP_INFINITE:
      return (v < 0.0 ? "-Infinity" : "Infinity");
    case FP_ZERO:
      return "0";
    default: {
      if (IsInt32Double(v)) {
        // This will trigger if v is -0 and -0.0 is stringified to "0".
        // (see ES section 7.1.12.1 #sec-tostring-applied-to-the-number-type)
        return IntToCString(FastD2I(v), buffer);
      }
      SimpleStringBuilder builder(buffer.begin(), buffer.length());
      int decimal_point;
      int sign;
      const int kV8DtoaBufferCapacity = base::kBase10MaximalLength + 1;
      char decimal_rep[kV8DtoaBufferCapacity];
      int length;

      base::DoubleToAscii(
          v, base::DTOA_SHORTEST, 0,
          base::Vector<char>(decimal_rep, kV8DtoaBufferCapacity), &sign,
          &length, &decimal_point);

      if (sign) builder.AddCharacter('-');

      if (length <= decimal_point && decimal_point <= 21) {
        // ECMA-262 section 9.8.1 step 6.
        builder.AddString(decimal_rep);
        builder.AddPadding('0', decimal_point - length);

      } else if (0 < decimal_point && decimal_point <= 21) {
        // ECMA-262 section 9.8.1 step 7.
        builder.AddSubstring(decimal_re
```