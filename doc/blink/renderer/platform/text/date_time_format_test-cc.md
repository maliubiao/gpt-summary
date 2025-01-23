Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Identify the Core Purpose:** The filename `date_time_format_test.cc` immediately suggests this file is dedicated to testing the functionality of a `DateTimeFormat` class. The presence of `testing/gtest/include/gtest/gtest.h` confirms this is a unit test file using Google Test.

2. **Understand the Test Structure:**  The file defines a test fixture `DateTimeFormatTest` inheriting from `testing::Test`. This provides a common setup for the tests. Inside the fixture, there are helper functions like `Parse` and `Single` and a nested `TokenHandler` class. The actual tests are defined using `TEST_F`.

3. **Analyze Helper Functions:**
    * **`Parse(const String& format_string)`:**  This function takes a format string as input and uses `DateTimeFormat::Parse` (the function being tested) to break it down into tokens. The `TokenHandler` is used to collect these tokens. If parsing fails, it returns a special "failed" token. This function is crucial for validating how different format strings are interpreted.
    * **`Single(const char ch)`:** This function seems designed to test the parsing of single-character format specifiers. It calls `DateTimeFormat::Parse` with a single character and returns the identified `FieldType`.
    * **`TokenHandler`:** This nested class implements the `DateTimeFormat::TokenHandler` interface. It's responsible for collecting the parsed tokens (either literal strings or `FieldType` with a count). The `GetTokens` method returns the collected tokens.

4. **Examine the `Token` and `Tokens` Structures:**
    * **`Token`:** Represents a single parsed unit of the format string. It can be a literal string or a `FieldType` with a repetition count. The `ToString()` method is useful for debugging and comparing tokens.
    * **`Tokens`:**  A container for a sequence of `Token` objects. It provides convenient constructors for creating token sequences and an `operator==` for comparing them. The `ToString()` method is also for debugging.

5. **Study the Test Cases (the `TEST_F` blocks):**  These are the heart of the tests. Each test case focuses on a specific aspect of the `DateTimeFormat::Parse` function.
    * **`CommonPattern`:** Tests parsing of common date and time format strings (e.g., "yyyy-MM-dd", "kk:mm:ss").
    * **`MissingClosingQuote`:** Checks how the parser handles format strings with unterminated quotes.
    * **`Quote`:** Tests the handling of single and double quotes within format strings.
    * **`SingleLowerCaseCharacter` and `SingleUpperCaseCharacter`:**  These tests methodically verify the correct mapping of single lowercase and uppercase characters to their corresponding `FieldType` values.
    * **`SingleLowerCaseInvalid` and `SingleUpperCaseInvalid`:**  These explicitly test characters that *should not* be valid format specifiers.

6. **Infer Functionality of `DateTimeFormat::Parse`:** Based on the tests, we can infer that `DateTimeFormat::Parse`:
    * Takes a format string as input.
    * Breaks down the string into tokens representing literals and date/time fields.
    * Uses a `TokenHandler` to receive these tokens.
    * Has specific rules for interpreting single characters and sequences of characters.
    * Handles quoted literals.
    * Can fail if the format string is invalid (e.g., missing closing quote).

7. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The most direct connection is to JavaScript's `Intl.DateTimeFormat` API. The format strings used in the tests (e.g., "yyyy-MM-dd") are very similar to the patterns used in `Intl.DateTimeFormat`. Blink, as the rendering engine for Chromium, needs to implement the underlying logic for this JavaScript API.
    * **HTML:**  HTML5 introduced `<input type="date">`, `<input type="time">`, and `<input type="datetime-local">`. While this C++ code doesn't directly *render* these elements, it's part of the underlying system that would be used to format the values displayed in these input fields based on locale and user preferences.
    * **CSS:**  Less direct, but CSS might influence how date/time information is presented (e.g., styling the date picker). However, this C++ code deals with the *parsing* and *formatting* logic, not the visual presentation.

8. **Consider Logic and Assumptions:**  The tests implicitly assume that there's a defined mapping between format string characters and date/time fields. The tests are structured to verify this mapping. The `Parse` function likely iterates through the format string, identifying sequences of the same character and interpreting them as specific field types. Quoting introduces a special state where characters are treated literally.

9. **Think about User/Programming Errors:**
    * **Incorrect Format Strings:**  The "MissingClosingQuote" test highlights a common error users (or developers writing code that generates format strings) might make.
    * **Typos:**  Using an invalid character in the format string will likely lead to incorrect parsing. The `SingleLowerCaseInvalid` and `SingleUpperCaseInvalid` tests demonstrate this.
    * **Locale Mismatch:** Although not directly tested in this specific file, a potential issue is a mismatch between the format string and the expected locale. `Intl.DateTimeFormat` in JavaScript handles localization, and this C++ code is likely part of that underlying implementation.

By following these steps, we can systematically understand the purpose, functionality, and context of the provided C++ test file. The focus is on dissecting the code structure, analyzing the test cases, and making logical connections to related web technologies and potential errors.
这个文件 `date_time_format_test.cc` 是 Chromium Blink 引擎中用于测试 `DateTimeFormat` 类的单元测试文件。它的主要功能是验证 `DateTimeFormat` 类解析日期和时间格式字符串的功能是否正确。

以下是该文件的功能分解和相关说明：

**1. 主要功能：测试 `DateTimeFormat` 类的格式字符串解析**

   - **`DateTimeFormat::Parse(const String& format_string, TokenHandler& handler)`:** 这是被测试的核心函数。该函数接收一个日期时间格式字符串（例如 "yyyy-MM-dd"）和一个 `TokenHandler` 对象作为输入。它的作用是将格式字符串分解成一个个的“token”，每个 token 代表一个日期/时间字段（例如 年、月、日）或者一个字面量字符串（例如 "-"）。`TokenHandler` 负责接收这些解析出来的 token。

   - **测试用例 (`TEST_F` 宏定义):**  文件中定义了多个测试用例，每个用例针对 `DateTimeFormat::Parse` 函数的不同场景进行测试。这些测试用例覆盖了常见的日期时间格式、特殊字符处理、错误格式处理等情况。

**2. 辅助结构体和类**

   - **`DateTimeFormatTest::Token`:**  表示一个解析出来的 token。它可以是：
      - **字面量字符串 (`kFieldTypeLiteral`)**:  例如格式字符串中的 "-"。
      - **日期/时间字段 (`kFieldTypeYear`, `kFieldTypeMonth` 等)**: 例如格式字符串中的 "yyyy" 或 "MM"。它包含字段类型和重复次数（例如 "yyyy" 中 'y' 重复了 4 次）。

   - **`DateTimeFormatTest::Tokens`:**  表示一个 token 序列，用于方便地存储和比较解析出的所有 token。

   - **`DateTimeFormatTest::TokenHandler`:**  这是一个内部类，实现了 `DateTimeFormat::TokenHandler` 接口。它的作用是接收 `DateTimeFormat::Parse` 函数解析出的 token，并将它们存储起来供测试用例进行断言。

**3. 与 JavaScript, HTML, CSS 的关系**

   - **JavaScript (最密切相关):**  `DateTimeFormat` 类在 Blink 引擎中是实现 JavaScript `Intl.DateTimeFormat` API 的一部分。`Intl.DateTimeFormat` 允许 JavaScript 代码根据用户所在的地区和偏好格式化日期和时间。
      - **举例说明:**  JavaScript 代码可以使用类似 "yyyy-MM-dd" 的格式字符串来格式化日期。`DateTimeFormat` 类负责解析这个格式字符串，并知道 "yyyy" 代表四位数的年份，"MM" 代表两位数的月份。
      ```javascript
      const date = new Date();
      const formatter = new Intl.DateTimeFormat('en-US', { year: 'numeric', month: '2-digit', day: '2-digit' });
      console.log(formatter.format(date)); // 输出类似 "2023-10-27"
      ```
      `DateTimeFormat` 类的测试用例，例如 `TEST_F(DateTimeFormatTest, CommonPattern)` 中对 "yyyy-MM-dd" 的解析，直接关系到 JavaScript `Intl.DateTimeFormat` 的底层实现是否正确。

   - **HTML:**  HTML5 引入了 `<input type="date">`, `<input type="time">`, 和 `<input type="datetime-local">` 等表单控件，允许用户选择日期和时间。浏览器内部需要解析和格式化这些输入控件的值，`DateTimeFormat` 类可能会参与其中。
      - **举例说明:** 当用户在一个 `<input type="date">` 元素中输入日期时，浏览器可能使用 `DateTimeFormat` 类来验证输入的格式，并将其转换为内部表示。同样，在显示日期时，也可能使用 `DateTimeFormat` 根据用户的区域设置进行格式化。

   - **CSS:**  CSS 本身不直接处理日期和时间的格式化。但是，CSS 可以用于样式化包含日期和时间信息的 HTML 元素。`DateTimeFormat` 的功能发生在数据处理层面，与 CSS 的样式呈现是不同的关注点。

**4. 逻辑推理和假设输入输出**

   - **假设输入:**  格式字符串 "yyyy/MM/dd hh:mm:ss"
   - **预期输出 (基于测试用例的逻辑):**
     ```
     Tokens(Token(kFieldTypeYear, 4), "/", Token(kFieldTypeMonth, 2), "/", Token(kFieldTypeDayOfMonth, 2), " ", Token(kFieldTypeHour24, 2), ":", Token(kFieldTypeMinute, 2), ":", Token(kFieldTypeSecond, 2))
     ```
     **推理过程:**
     - "yyyy" 被解析为 `Token(kFieldTypeYear, 4)`，表示 4 位数的年份。
     - "/" 被解析为 `Token("/")`，表示字面量字符串 "/"。
     - "MM" 被解析为 `Token(kFieldTypeMonth, 2)`，表示 2 位数的月份。
     - "dd" 被解析为 `Token(kFieldTypeDayOfMonth, 2)`，表示 2 位数的日期。
     - " " 被解析为 `Token(" ")`，表示字面量空格。
     - "hh" 被解析为 `Token(kFieldTypeHour24, 2)`，表示 24 小时制的 2 位数小时。
     - "mm" 被解析为 `Token(kFieldTypeMinute, 2)`，表示 2 位数分钟。
     - "ss" 被解析为 `Token(kFieldTypeSecond, 2)`，表示 2 位数秒。

**5. 用户或编程常见的使用错误**

   - **格式字符串拼写错误:**  如果格式字符串中的字符不符合 `DateTimeFormat` 的规范，解析会失败。例如，使用 "yyy-MM-dd" (少了一个 'y') 或者 "yyyy-mm-dd" (小写的 'm' 代表分钟，大写的 'M' 代表月份)。测试用例 `TEST_F(DateTimeFormatTest, SingleLowerCaseInvalid)` 和 `TEST_F(DateTimeFormatTest, SingleUpperCaseInvalid)` 就是为了覆盖这种情况。
      - **举例:** 在 JavaScript 中，如果传递给 `Intl.DateTimeFormat` 的格式选项不正确，可能会得到意想不到的结果或者抛出错误。

   - **缺少闭合引号:**  在格式字符串中使用单引号括起来字面量时，如果忘记写闭合的单引号，会导致解析错误。测试用例 `TEST_F(DateTimeFormatTest, MissingClosingQuote)` 专门测试了这种情况。
      - **举例:**  JavaScript 中使用 `Intl.DateTimeFormat` 的 `formatToParts` 方法时，如果格式字符串中缺少闭合引号，可能会导致解析错误。

   - **混淆大小写:**  日期和时间格式字符串中的字符大小写通常有特定的含义。例如，'M' 代表月份，'m' 代表分钟。混淆大小写会导致解析结果不正确。测试用例 `TEST_F(DateTimeFormatTest, SingleLowerCaseCharacter)` 和 `TEST_F(DateTimeFormatTest, SingleUpperCaseCharacter)` 验证了各种大小写字符的含义。

   - **不理解格式字符串的规则:** 用户或开发者可能不熟悉各种格式字符的含义和用法，导致使用了不正确的格式字符串。例如，误以为 "YY" 代表四位数的年份，或者不清楚如何表示时区信息。

总而言之，`date_time_format_test.cc` 文件通过一系列的单元测试，确保 Blink 引擎中的 `DateTimeFormat` 类能够正确地解析各种日期和时间格式字符串，这对于正确实现 JavaScript 的 `Intl.DateTimeFormat` API 和处理 HTML 日期时间相关的表单元素至关重要。这些测试用例也揭示了用户和开发者在使用日期时间格式化时可能遇到的常见错误。

### 提示词
```
这是目录为blink/renderer/platform/text/date_time_format_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/text/date_time_format.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class DateTimeFormatTest : public testing::Test {
 public:
  using FieldType = DateTimeFormat::FieldType;

  struct Token {
    String string;
    int count;
    FieldType field_type;

    Token(FieldType field_type, int count = 1)
        : count(count), field_type(field_type) {
      DCHECK_NE(field_type, DateTimeFormat::kFieldTypeLiteral);
    }

    Token(const String& string)
        : string(string),
          count(0),
          field_type(DateTimeFormat::kFieldTypeLiteral) {}

    bool operator==(const Token& other) const {
      return field_type == other.field_type && count == other.count &&
             string == other.string;
    }

    String ToString() const {
      switch (field_type) {
        case DateTimeFormat::kFieldTypeInvalid:
          return "*invalid*";
        case DateTimeFormat::kFieldTypeLiteral: {
          StringBuilder builder;
          builder.Append('"');
          builder.Append(string);
          builder.Append('"');
          return builder.ToString();
        }
        default:
          return String::Format("Token(%d, %d)", field_type, count);
      }
    }
  };

  class Tokens {
   public:
    Tokens() = default;

    explicit Tokens(const Vector<Token> tokens) : tokens_(tokens) {}

    explicit Tokens(const String& string) { tokens_.push_back(Token(string)); }

    explicit Tokens(Token token1) { tokens_.push_back(token1); }

    Tokens(Token token1, Token token2) {
      tokens_.push_back(token1);
      tokens_.push_back(token2);
    }

    Tokens(Token token1, Token token2, Token token3) {
      tokens_.push_back(token1);
      tokens_.push_back(token2);
      tokens_.push_back(token3);
    }

    Tokens(Token token1, Token token2, Token token3, Token token4) {
      tokens_.push_back(token1);
      tokens_.push_back(token2);
      tokens_.push_back(token3);
      tokens_.push_back(token4);
    }

    Tokens(Token token1,
           Token token2,
           Token token3,
           Token token4,
           Token token5) {
      tokens_.push_back(token1);
      tokens_.push_back(token2);
      tokens_.push_back(token3);
      tokens_.push_back(token4);
      tokens_.push_back(token5);
    }

    Tokens(Token token1,
           Token token2,
           Token token3,
           Token token4,
           Token token5,
           Token token6) {
      tokens_.push_back(token1);
      tokens_.push_back(token2);
      tokens_.push_back(token3);
      tokens_.push_back(token4);
      tokens_.push_back(token5);
      tokens_.push_back(token6);
    }

    bool operator==(const Tokens& other) const {
      return tokens_ == other.tokens_;
    }

    String ToString() const {
      StringBuilder builder;
      builder.Append("Tokens(");
      for (unsigned index = 0; index < tokens_.size(); ++index) {
        if (index)
          builder.Append(',');
        builder.Append(tokens_[index].ToString());
      }
      builder.Append(')');
      return builder.ToString();
    }

   private:
    Vector<Token> tokens_;
  };

 protected:
  Tokens Parse(const String& format_string) {
    TokenHandler handler;
    if (!DateTimeFormat::Parse(format_string, handler))
      return Tokens(Token("*failed*"));
    return handler.GetTokens();
  }

  FieldType Single(const char ch) {
    char format_string[2];
    format_string[0] = ch;
    format_string[1] = 0;
    TokenHandler handler;
    if (!DateTimeFormat::Parse(format_string, handler))
      return DateTimeFormat::kFieldTypeInvalid;
    return handler.GetFieldType(0);
  }

 private:
  class TokenHandler : public DateTimeFormat::TokenHandler {
   public:
    ~TokenHandler() override = default;

    FieldType GetFieldType(int index) const {
      return index >= 0 && index < static_cast<int>(tokens_.size())
                 ? tokens_[index].field_type
                 : DateTimeFormat::kFieldTypeInvalid;
    }

    Tokens GetTokens() const { return Tokens(tokens_); }

   private:
    void VisitField(FieldType field_type, int count) override {
      tokens_.push_back(Token(field_type, count));
    }

    void VisitLiteral(const String& string) override {
      tokens_.push_back(Token(string));
    }

    Vector<Token> tokens_;
  };
};

std::ostream& operator<<(std::ostream& os,
                         const DateTimeFormatTest::Tokens& tokens) {
  return os << tokens.ToString();
}

TEST_F(DateTimeFormatTest, CommonPattern) {
  EXPECT_EQ(Tokens(), Parse(""));

  EXPECT_EQ(Tokens(Token(DateTimeFormat::kFieldTypeYear, 4), Token("-"),
                   Token(DateTimeFormat::kFieldTypeMonth, 2), Token("-"),
                   Token(DateTimeFormat::kFieldTypeDayOfMonth, 2)),
            Parse("yyyy-MM-dd"));

  EXPECT_EQ(Tokens(Token(DateTimeFormat::kFieldTypeHour24, 2), Token(":"),
                   Token(DateTimeFormat::kFieldTypeMinute, 2), Token(":"),
                   Token(DateTimeFormat::kFieldTypeSecond, 2)),
            Parse("kk:mm:ss"));

  EXPECT_EQ(Tokens(Token(DateTimeFormat::kFieldTypeHour12), Token(":"),
                   Token(DateTimeFormat::kFieldTypeMinute), Token(" "),
                   Token(DateTimeFormat::kFieldTypePeriod)),
            Parse("h:m a"));

  EXPECT_EQ(Tokens(Token(DateTimeFormat::kFieldTypeYear), Token("Nen "),
                   Token(DateTimeFormat::kFieldTypeMonth), Token("Getsu "),
                   Token(DateTimeFormat::kFieldTypeDayOfMonth), Token("Nichi")),
            Parse("y'Nen' M'Getsu' d'Nichi'"));
}

TEST_F(DateTimeFormatTest, MissingClosingQuote) {
  EXPECT_EQ(Tokens("*failed*"), Parse("'foo"));
  EXPECT_EQ(Tokens("*failed*"), Parse("fo'o"));
  EXPECT_EQ(Tokens("*failed*"), Parse("foo'"));
}

TEST_F(DateTimeFormatTest, Quote) {
  EXPECT_EQ(Tokens("FooBar"), Parse("'FooBar'"));
  EXPECT_EQ(Tokens("'"), Parse("''"));
  EXPECT_EQ(Tokens("'-'"), Parse("''-''"));
  EXPECT_EQ(Tokens("Foo'Bar"), Parse("'Foo''Bar'"));
  EXPECT_EQ(Tokens(Token(DateTimeFormat::kFieldTypeEra), Token("'s")),
            Parse("G'''s'"));
  EXPECT_EQ(Tokens(Token(DateTimeFormat::kFieldTypeEra), Token("'"),
                   Token(DateTimeFormat::kFieldTypeSecond)),
            Parse("G''s"));
}

TEST_F(DateTimeFormatTest, SingleLowerCaseCharacter) {
  EXPECT_EQ(DateTimeFormat::kFieldTypePeriodAmPmNoonMidnight, Single('b'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeLocalDayOfWeekStandAlon, Single('c'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeDayOfMonth, Single('d'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeLocalDayOfWeek, Single('e'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeModifiedJulianDay, Single('g'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeHour12, Single('h'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeHour24, Single('k'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeMinute, Single('m'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeQuaterStandAlone, Single('q'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeYearRelatedGregorian, Single('r'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeSecond, Single('s'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeExtendedYear, Single('u'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeNonLocationZone, Single('v'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeWeekOfMonth, Single('W'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeZoneIso8601, Single('x'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeYear, Single('y'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeZone, Single('z'));
}

TEST_F(DateTimeFormatTest, SingleLowerCaseInvalid) {
  EXPECT_EQ(DateTimeFormat::kFieldTypePeriod, Single('a'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('f'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('i'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('j'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('l'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('n'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('o'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('p'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('t'));
}

TEST_F(DateTimeFormatTest, SingleUpperCaseCharacter) {
  EXPECT_EQ(DateTimeFormat::kFieldTypeMillisecondsInDay, Single('A'));
  EXPECT_EQ(DateTimeFormat::kFieldTypePeriodFlexible, Single('B'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeDayOfYear, Single('D'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeDayOfWeek, Single('E'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeDayOfWeekInMonth, Single('F'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeEra, Single('G'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeHour23, Single('H'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeHour11, Single('K'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeMonthStandAlone, Single('L'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeMonth, Single('M'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeZoneLocalized, Single('O'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeQuater, Single('Q'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeFractionalSecond, Single('S'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeYearCyclicName, Single('U'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeZoneId, Single('V'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeWeekOfYear, Single('w'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeZoneIso8601Z, Single('X'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeYearOfWeekOfYear, Single('Y'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeRFC822Zone, Single('Z'));
}

TEST_F(DateTimeFormatTest, SingleUpperCaseInvalid) {
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('C'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('I'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('J'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('N'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('P'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('R'));
  EXPECT_EQ(DateTimeFormat::kFieldTypeInvalid, Single('T'));
}

}  // namespace blink
```