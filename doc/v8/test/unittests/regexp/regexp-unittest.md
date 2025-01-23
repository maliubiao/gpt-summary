Response: The user wants to understand the functionality of the C++ source code file `v8/test/unittests/regexp/regexp-unittest.cc`. Since this is part 1 of 2, the focus should be on the features covered in this part.

Based on the included headers and the test names, this file seems to be focused on **unit testing the regular expression parsing and compilation functionality within the V8 engine**.

Specifically, it covers:

1. **Testing the conversion of RegExp flags to strings:** This ensures the correctness of representing RegExp flags (like 'i', 'g', 'm', etc.) as string values.
2. **Testing the RegExp parser:**  This involves feeding various regular expression patterns to the parser and verifying:
    *   Successful parsing and the structure of the resulting parse tree.
    *   Expected parsing errors for invalid patterns.
    *   Whether a RegExp is considered "simple" (for optimization purposes).
    *   The minimum and maximum possible lengths of a match for a given RegExp.
3. **Testing character class escapes:**  Verifying that special character sequences within character classes (like `\d`, `\w`, `\s`) are correctly interpreted.
4. **Testing compilation:**  Checking the compilation process of regular expressions into an internal representation.
5. **Testing the native RegExp macro assembler:** This involves testing the low-level assembly code generation for RegExp execution. It covers:
    *   Basic success and failure scenarios.
    *   Handling of backreferences.
    *   Checking for the start of the input string.
    *   Case-insensitive matching.
    *   Register usage.
    *   Stack overflow scenarios.
6. **Testing the bytecode generator:**  Similar to the macro assembler tests, but focusing on the bytecode representation.
7. **Testing Unicode handling:** Specifically the parsing and compilation of Unicode escape sequences.
8. **Testing character range manipulation:**  This includes testing case independence of character ranges and utilities for working with Unicode ranges.
9. **Testing UseCounters:** Verifying that specific features of regular expressions trigger the intended usage counters for tracking.

The relationship with JavaScript is that this C++ code tests the underlying implementation of JavaScript's `RegExp` object and its related functionalities.

To illustrate with JavaScript examples, I can show how the tested C++ features correspond to JavaScript code.
这个C++源代码文件 `v8/test/unittests/regexp/regexp-unittest.cc` 的主要功能是**对V8引擎中正则表达式的解析、编译和执行过程进行单元测试**。

具体来说，这个文件包含了一系列的测试用例，用于验证以下与正则表达式相关的功能：

1. **正则表达式标志的字符串转换:** 测试将正则表达式的标志（例如 `i`, `g`, `m`, `s`, `u`, `y`, `d`）转换为字符串表示形式的功能是否正确。
2. **正则表达式的解析器:**  测试正则表达式解析器是否能够正确地将正则表达式字符串解析成内部的抽象语法树 (AST)。这包括：
    *   验证各种合法的正则表达式模式是否能被正确解析，并生成预期的AST结构。
    *   验证对于非法的正则表达式模式，解析器是否能正确地识别并报告错误。
    *   测试解析器是否能正确判断一个正则表达式是否是“简单”的，这对于某些优化是很重要的。
    *   测试解析器能否计算出正则表达式匹配的最小和最大长度。
3. **字符类转义:** 测试解析器是否能正确处理字符类中的转义字符，例如 `\d`, `\w`, `\s` 等。
4. **正则表达式的编译:**  测试将解析后的正则表达式编译成可执行代码的过程，包括基于宏汇编器和字节码的编译。
5. **原生正则表达式宏汇编器 (Macro Assembler):**  测试 V8 中用于生成高效原生代码的正则表达式宏汇编器的工作是否正确。这包括：
    *   测试匹配成功和失败的基本情况。
    *   测试反向引用的处理 (例如 `\1`, `\2` 等)。
    *   测试 `^` 和 `$` 锚点的处理。
    *   测试不区分大小写的匹配。
    *   测试寄存器的使用和管理。
    *   测试堆栈溢出的情况。
6. **正则表达式字节码生成器:**  测试将正则表达式编译成字节码的功能。
7. **Unicode 支持:** 测试对于包含 Unicode 字符和转义序列的正则表达式的处理是否正确。
8. **字符范围操作:** 测试字符范围的合并、规范化以及大小写不敏感处理等功能。
9. **使用计数器 (UseCounter):** 测试某些正则表达式特性是否触发了 V8 的使用计数器，用于统计特性使用情况。

**它与 JavaScript 的功能的关系:**

这个 C++ 文件中的测试用例直接关联到 JavaScript 中 `RegExp` 对象的功能。V8 引擎是 JavaScript 的运行时环境，它负责解释和执行 JavaScript 代码，包括正则表达式的处理。

例如，JavaScript 中创建和使用正则表达式的语法，以及正则表达式的各种标志，都在这个 C++ 文件中被测试。

**JavaScript 举例说明:**

1. **正则表达式标志的字符串转换:**

    ```javascript
    let regexp1 = /abc/ig;
    console.log(regexp1.flags); // 输出 "gi"

    let regexp2 = new RegExp("abc", "m");
    console.log(regexp2.flags); // 输出 "m"
    ```

    `ConvertRegExpFlagsToString` 等测试用例就是在验证 V8 内部能否正确地将正则表达式对象的标志转换为像 `"gi"` 或 `"m"` 这样的字符串。

2. **正则表达式的解析器:**

    ```javascript
    let regexp3 = /a[bc]+d/;
    // V8 的解析器会分析这个正则表达式的结构，例如 'a' 是一个字面量，'[bc]+' 是一个字符类重复一次或多次，'d' 是另一个字面量。

    try {
      let regexp4 = /(/; // 非法的正则表达式
    } catch (e) {
      console.error(e); // V8 的解析器会抛出 SyntaxError
    }
    ```

    `RegExpParser` 测试用例组就在验证 V8 的解析器对于合法和非法的正则表达式的解析行为。

3. **原生正则表达式宏汇编器 (Macro Assembler) 和字节码生成器:**

    当 JavaScript 引擎执行正则表达式匹配时，它通常会将正则表达式编译成机器码或字节码来提高执行效率。例如：

    ```javascript
    let str = "foobarbaz";
    let match = str.match(/^foo/); // 使用了锚点 '^'
    console.log(match); // 输出 ["foo"]

    let str2 = "AaBbCc";
    let match2 = str2.match(/abc/i); // 使用了 'i' 标志，不区分大小写
    console.log(match2); // 输出 ["AbC"]
    ```

    `MacroAssemblerNativeSuccess`, `MacroAssemblerNativeSimple`, `MacroAssemblerNativeBackReferenceLATIN1` 等测试用例就是在测试 V8 内部生成的机器码或字节码能否正确地执行这些匹配操作。

4. **Unicode 支持:**

    ```javascript
    let regexp5 = /\u{1F600}/u; // 使用 Unicode 码点
    console.log(regexp5.test("😀")); // 输出 true
    ```

    `CheckParseEq("\\u{12345}", "'\\ud808\\udf45'", true);` 这样的测试用例在验证 V8 能否正确解析和处理 Unicode 转义序列。

总而言之，`v8/test/unittests/regexp/regexp-unittest.cc` 这个 C++ 文件是 V8 引擎中用于确保 JavaScript 正则表达式功能正确实现的基石，它通过大量的单元测试覆盖了正则表达式处理的各个方面。

### 提示词
```
这是目录为v8/test/unittests/regexp/regexp-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "src/regexp/regexp.h"

#include <cstdlib>
#include <memory>
#include <sstream>

#include "include/v8-context.h"
#include "include/v8-initialization.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "src/api/api-inl.h"
#include "src/ast/ast.h"
#include "src/base/strings.h"
#include "src/codegen/assembler-arch.h"
#include "src/codegen/macro-assembler.h"
#include "src/init/v8.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/objects-inl.h"
#include "src/regexp/regexp-bytecode-generator.h"
#include "src/regexp/regexp-bytecodes.h"
#include "src/regexp/regexp-compiler.h"
#include "src/regexp/regexp-interpreter.h"
#include "src/regexp/regexp-macro-assembler-arch.h"
#include "src/regexp/regexp-parser.h"
#include "src/strings/char-predicates-inl.h"
#include "src/strings/string-stream.h"
#include "src/strings/unicode-inl.h"
#include "src/utils/ostreams.h"
#include "src/zone/zone-list-inl.h"
#include "test/common/flag-utils.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {

TEST_F(TestWithNativeContext, ConvertRegExpFlagsToString) {
  RunJS("let regexp = new RegExp(/ab+c/ig);");
  DirectHandle<JSRegExp> regexp = RunJS<JSRegExp>("regexp");
  Handle<String> flags = RunJS<String>("regexp.flags");
  Handle<String> converted_flags =
      JSRegExp::StringFromFlags(isolate(), regexp->flags());
  EXPECT_TRUE(String::Equals(isolate(), flags, converted_flags));
}

TEST_F(TestWithNativeContext, ConvertRegExpFlagsToStringNoFlags) {
  RunJS("let regexp = new RegExp(/ab+c/);");
  DirectHandle<JSRegExp> regexp = RunJS<JSRegExp>("regexp");
  Handle<String> flags = RunJS<String>("regexp.flags");
  Handle<String> converted_flags =
      JSRegExp::StringFromFlags(isolate(), regexp->flags());
  EXPECT_TRUE(String::Equals(isolate(), flags, converted_flags));
}

TEST_F(TestWithNativeContext, ConvertRegExpFlagsToStringAllFlags) {
  RunJS("let regexp = new RegExp(/ab+c/dgimsuy);");
  DirectHandle<JSRegExp> regexp = RunJS<JSRegExp>("regexp");
  Handle<String> flags = RunJS<String>("regexp.flags");
  Handle<String> converted_flags =
      JSRegExp::StringFromFlags(isolate(), regexp->flags());
  EXPECT_TRUE(String::Equals(isolate(), flags, converted_flags));
}

using RegExpTest = TestWithIsolate;

static bool CheckParse(const char* input) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  Zone zone(isolate->allocator(), ZONE_NAME);
  DirectHandle<String> str =
      isolate->factory()->NewStringFromAsciiChecked(input);
  RegExpCompileData result;
  return RegExpParser::ParseRegExpFromHeapString(isolate, &zone, str, {},
                                                 &result);
}

static void CheckParseEq(const char* input, const char* expected,
                         bool unicode = false) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  Zone zone(isolate->allocator(), ZONE_NAME);
  DirectHandle<String> str =
      isolate->factory()->NewStringFromAsciiChecked(input);
  RegExpCompileData result;
  RegExpFlags flags;
  if (unicode) flags |= RegExpFlag::kUnicode;
  CHECK(RegExpParser::ParseRegExpFromHeapString(isolate, &zone, str, flags,
                                                &result));
  CHECK_NOT_NULL(result.tree);
  CHECK_EQ(RegExpError::kNone, result.error);
  std::ostringstream os;
  result.tree->Print(os, &zone);
  if (strcmp(expected, os.str().c_str()) != 0) {
    printf("%s | %s\n", expected, os.str().c_str());
  }
  CHECK_EQ(0, strcmp(expected, os.str().c_str()));
}

static bool CheckSimple(const char* input) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  Zone zone(isolate->allocator(), ZONE_NAME);
  DirectHandle<String> str =
      isolate->factory()->NewStringFromAsciiChecked(input);
  RegExpCompileData result;
  CHECK(RegExpParser::ParseRegExpFromHeapString(isolate, &zone, str, {},
                                                &result));
  CHECK_NOT_NULL(result.tree);
  CHECK_EQ(RegExpError::kNone, result.error);
  return result.simple;
}

struct MinMaxPair {
  int min_match;
  int max_match;
};

static MinMaxPair CheckMinMaxMatch(const char* input) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  Zone zone(isolate->allocator(), ZONE_NAME);
  DirectHandle<String> str =
      isolate->factory()->NewStringFromAsciiChecked(input);
  RegExpCompileData result;
  CHECK(RegExpParser::ParseRegExpFromHeapString(isolate, &zone, str, {},
                                                &result));
  CHECK_NOT_NULL(result.tree);
  CHECK_EQ(RegExpError::kNone, result.error);
  int min_match = result.tree->min_match();
  int max_match = result.tree->max_match();
  MinMaxPair pair = {min_match, max_match};
  return pair;
}

#define CHECK_PARSE_ERROR(input) CHECK(!CheckParse(input))
#define CHECK_SIMPLE(input, simple) CHECK_EQ(simple, CheckSimple(input));
#define CHECK_MIN_MAX(input, min, max)            \
  {                                               \
    MinMaxPair min_max = CheckMinMaxMatch(input); \
    CHECK_EQ(min, min_max.min_match);             \
    CHECK_EQ(max, min_max.max_match);             \
  }

TEST_F(RegExpTest, RegExpParser) {
  CHECK_PARSE_ERROR("?");

  CheckParseEq("abc", "'abc'");
  CheckParseEq("", "%");
  CheckParseEq("abc|def", "(| 'abc' 'def')");
  CheckParseEq("abc|def|ghi", "(| 'abc' 'def' 'ghi')");
  CheckParseEq("^xxx$", "(: @^i 'xxx' @$i)");
  CheckParseEq("ab\\b\\d\\bcd", "(: 'ab' @b [0-9] @b 'cd')");
  CheckParseEq("\\w|\\d", "(| [0-9 A-Z _ a-z] [0-9])");
  CheckParseEq("a*", "(# 0 - g 'a')");
  CheckParseEq("a*?", "(# 0 - n 'a')");
  CheckParseEq("abc+", "(: 'ab' (# 1 - g 'c'))");
  CheckParseEq("abc+?", "(: 'ab' (# 1 - n 'c'))");
  CheckParseEq("xyz?", "(: 'xy' (# 0 1 g 'z'))");
  CheckParseEq("xyz??", "(: 'xy' (# 0 1 n 'z'))");
  CheckParseEq("xyz{0,1}", "(: 'xy' (# 0 1 g 'z'))");
  CheckParseEq("xyz{0,1}?", "(: 'xy' (# 0 1 n 'z'))");
  CheckParseEq("xyz{93}", "(: 'xy' (# 93 93 g 'z'))");
  CheckParseEq("xyz{93}?", "(: 'xy' (# 93 93 n 'z'))");
  CheckParseEq("xyz{1,32}", "(: 'xy' (# 1 32 g 'z'))");
  CheckParseEq("xyz{1,32}?", "(: 'xy' (# 1 32 n 'z'))");
  CheckParseEq("xyz{1,}", "(: 'xy' (# 1 - g 'z'))");
  CheckParseEq("xyz{1,}?", "(: 'xy' (# 1 - n 'z'))");
  CheckParseEq("a\\fb\\nc\\rd\\te\\vf", "'a\\x0cb\\x0ac\\x0dd\\x09e\\x0bf'");
  CheckParseEq("a\\nb\\bc", "(: 'a\\x0ab' @b 'c')");
  CheckParseEq("(?:foo)", "(?: 'foo')");
  CheckParseEq("(?: foo )", "(?: ' foo ')");
  CheckParseEq("(foo|bar|baz)", "(^ (| 'foo' 'bar' 'baz'))");
  CheckParseEq("foo|(bar|baz)|quux", "(| 'foo' (^ (| 'bar' 'baz')) 'quux')");
  CheckParseEq("foo(?=bar)baz", "(: 'foo' (-> + 'bar') 'baz')");
  CheckParseEq("foo(?!bar)baz", "(: 'foo' (-> - 'bar') 'baz')");
  CheckParseEq("foo(?<=bar)baz", "(: 'foo' (<- + 'bar') 'baz')");
  CheckParseEq("foo(?<!bar)baz", "(: 'foo' (<- - 'bar') 'baz')");
  CheckParseEq("()", "(^ %)");
  CheckParseEq("(?=)", "(-> + %)");
  CheckParseEq("[]", "^[\\x00-\\u{10ffff}]");  // Doesn't compile on windows
  CheckParseEq("[^]", "[\\x00-\\u{10ffff}]");  // \uffff isn't in codepage 1252
  CheckParseEq("[x]", "[x]");
  CheckParseEq("[xyz]", "[x y z]");
  CheckParseEq("[a-zA-Z0-9]", "[a-z A-Z 0-9]");
  CheckParseEq("[-123]", "[- 1 2 3]");
  CheckParseEq("[^123]", "^[1 2 3]");
  CheckParseEq("]", "']'");
  CheckParseEq("}", "'}'");
  CheckParseEq("[a-b-c]", "[a-b - c]");
  CheckParseEq("[\\d]", "[0-9]");
  CheckParseEq("[x\\dz]", "[x 0-9 z]");
  CheckParseEq("[\\d-z]", "[0-9 - z]");
  CheckParseEq("[\\d-\\d]", "[0-9 0-9 -]");
  CheckParseEq("[z-\\d]", "[0-9 z -]");
  // Control character outside character class.
  CheckParseEq("\\cj\\cJ\\ci\\cI\\ck\\cK", "'\\x0a\\x0a\\x09\\x09\\x0b\\x0b'");
  CheckParseEq("\\c!", "'\\c!'");
  CheckParseEq("\\c_", "'\\c_'");
  CheckParseEq("\\c~", "'\\c~'");
  CheckParseEq("\\c1", "'\\c1'");
  // Control character inside character class.
  CheckParseEq("[\\c!]", "[\\ c !]");
  CheckParseEq("[\\c_]", "[\\x1f]");
  CheckParseEq("[\\c~]", "[\\ c ~]");
  CheckParseEq("[\\ca]", "[\\x01]");
  CheckParseEq("[\\cz]", "[\\x1a]");
  CheckParseEq("[\\cA]", "[\\x01]");
  CheckParseEq("[\\cZ]", "[\\x1a]");
  CheckParseEq("[\\c1]", "[\\x11]");

  CheckParseEq("[a\\]c]", "[a ] c]");
  CheckParseEq("\\[\\]\\{\\}\\(\\)\\%\\^\\#\\ ", "'[]{}()%^# '");
  CheckParseEq("[\\[\\]\\{\\}\\(\\)\\%\\^\\#\\ ]", "[[ ] { } ( ) % ^ #  ]");
  CheckParseEq("\\0", "'\\x00'");
  CheckParseEq("\\8", "'8'");
  CheckParseEq("\\9", "'9'");
  CheckParseEq("\\11", "'\\x09'");
  CheckParseEq("\\11a", "'\\x09a'");
  CheckParseEq("\\011", "'\\x09'");
  CheckParseEq("\\00011", "'\\x0011'");
  CheckParseEq("\\118", "'\\x098'");
  CheckParseEq("\\111", "'I'");
  CheckParseEq("\\1111", "'I1'");
  CheckParseEq("(x)(x)(x)\\1", "(: (^ 'x') (^ 'x') (^ 'x') (<- 1))");
  CheckParseEq("(x)(x)(x)\\2", "(: (^ 'x') (^ 'x') (^ 'x') (<- 2))");
  CheckParseEq("(x)(x)(x)\\3", "(: (^ 'x') (^ 'x') (^ 'x') (<- 3))");
  CheckParseEq("(x)(x)(x)\\4", "(: (^ 'x') (^ 'x') (^ 'x') '\\x04')");
  CheckParseEq("(x)(x)(x)\\1*",
               "(: (^ 'x') (^ 'x') (^ 'x')"
               " (# 0 - g (<- 1)))");
  CheckParseEq("(x)(x)(x)\\2*",
               "(: (^ 'x') (^ 'x') (^ 'x')"
               " (# 0 - g (<- 2)))");
  CheckParseEq("(x)(x)(x)\\3*",
               "(: (^ 'x') (^ 'x') (^ 'x')"
               " (# 0 - g (<- 3)))");
  CheckParseEq("(x)(x)(x)\\4*",
               "(: (^ 'x') (^ 'x') (^ 'x')"
               " (# 0 - g '\\x04'))");
  CheckParseEq("(x)(x)(x)(x)(x)(x)(x)(x)(x)(x)\\10",
               "(: (^ 'x') (^ 'x') (^ 'x') (^ 'x') (^ 'x') (^ 'x')"
               " (^ 'x') (^ 'x') (^ 'x') (^ 'x') (<- 10))");
  CheckParseEq("(x)(x)(x)(x)(x)(x)(x)(x)(x)(x)\\11",
               "(: (^ 'x') (^ 'x') (^ 'x') (^ 'x') (^ 'x') (^ 'x')"
               " (^ 'x') (^ 'x') (^ 'x') (^ 'x') '\\x09')");
  CheckParseEq("(a)\\1", "(: (^ 'a') (<- 1))");
  CheckParseEq("(a\\1)", "(^ 'a')");
  CheckParseEq("(\\1a)", "(^ 'a')");
  CheckParseEq("(\\2)(\\1)", "(: (^ (<- 2)) (^ (<- 1)))");
  CheckParseEq("(?=a)?a", "'a'");
  CheckParseEq("(?=a){0,10}a", "'a'");
  CheckParseEq("(?=a){1,10}a", "(: (-> + 'a') 'a')");
  CheckParseEq("(?=a){9,10}a", "(: (-> + 'a') 'a')");
  CheckParseEq("(?!a)?a", "'a'");
  CheckParseEq("\\1(a)", "(: (<- 1) (^ 'a'))");
  CheckParseEq("(?!(a))\\1", "(: (-> - (^ 'a')) (<- 1))");
  CheckParseEq("(?!\\1(a\\1)\\1)\\1",
               "(: (-> - (: (<- 1) (^ 'a') (<- 1))) (<- 1))");
  CheckParseEq("\\1\\2(a(?:\\1(b\\1\\2))\\2)\\1",
               "(: (<- 1) (<- 2) (^ (: 'a' (?: (^ 'b')) (<- 2))) (<- 1))");
  CheckParseEq("\\1\\2(a(?<=\\1(b\\1\\2))\\2)\\1",
               "(: (<- 1) (<- 2) (^ (: 'a' (<- + (^ 'b')) (<- 2))) (<- 1))");
  CheckParseEq("[\\0]", "[\\x00]");
  CheckParseEq("[\\11]", "[\\x09]");
  CheckParseEq("[\\11a]", "[\\x09 a]");
  CheckParseEq("[\\011]", "[\\x09]");
  CheckParseEq("[\\00011]", "[\\x00 1 1]");
  CheckParseEq("[\\118]", "[\\x09 8]");
  CheckParseEq("[\\111]", "[I]");
  CheckParseEq("[\\1111]", "[I 1]");
  CheckParseEq("\\x34", "'\x34'");
  CheckParseEq("\\x60", "'\x60'");
  CheckParseEq("\\x3z", "'x3z'");
  CheckParseEq("\\c", "'\\c'");
  CheckParseEq("\\u0034", "'\x34'");
  CheckParseEq("\\u003z", "'u003z'");
  CheckParseEq("foo[z]*", "(: 'foo' (# 0 - g [z]))");
  CheckParseEq("^^^$$$\\b\\b\\b\\b", "(: @^i @^i @^i @$i @$i @$i @b @b @b @b)");
  CheckParseEq("\\b\\b\\b\\b\\B\\B\\B\\B\\b\\b\\b\\b",
               "(: @b @b @b @b @B @B @B @B @b @b @b @b)");
  CheckParseEq("\\b\\B\\b", "(: @b @B @b)");

  // Unicode regexps
  CheckParseEq("\\u{12345}", "'\\ud808\\udf45'", true);
  CheckParseEq("\\u{12345}\\u{23456}", "(! '\\ud808\\udf45' '\\ud84d\\udc56')",
               true);
  CheckParseEq("\\u{12345}|\\u{23456}", "(| '\\ud808\\udf45' '\\ud84d\\udc56')",
               true);
  CheckParseEq("\\u{12345}{3}", "(# 3 3 g '\\ud808\\udf45')", true);
  CheckParseEq("\\u{12345}*", "(# 0 - g '\\ud808\\udf45')", true);

  CheckParseEq("\\ud808\\udf45*", "(# 0 - g '\\ud808\\udf45')", true);
  CheckParseEq("[\\ud808\\udf45-\\ud809\\udccc]", "[\\u{012345}-\\u{0124cc}]",
               true);

  CHECK_SIMPLE("", false);
  CHECK_SIMPLE("a", true);
  CHECK_SIMPLE("a|b", false);
  CHECK_SIMPLE("a\\n", false);
  CHECK_SIMPLE("^a", false);
  CHECK_SIMPLE("a$", false);
  CHECK_SIMPLE("a\\b!", false);
  CHECK_SIMPLE("a\\Bb", false);
  CHECK_SIMPLE("a*", false);
  CHECK_SIMPLE("a*?", false);
  CHECK_SIMPLE("a?", false);
  CHECK_SIMPLE("a??", false);
  CHECK_SIMPLE("a{0,1}?", false);
  CHECK_SIMPLE("a{1,1}?", false);
  CHECK_SIMPLE("a{1,2}?", false);
  CHECK_SIMPLE("a+?", false);
  CHECK_SIMPLE("(a)", false);
  CHECK_SIMPLE("(a)\\1", false);
  CHECK_SIMPLE("(\\1a)", false);
  CHECK_SIMPLE("\\1(a)", false);
  CHECK_SIMPLE("a\\s", false);
  CHECK_SIMPLE("a\\S", false);
  CHECK_SIMPLE("a\\d", false);
  CHECK_SIMPLE("a\\D", false);
  CHECK_SIMPLE("a\\w", false);
  CHECK_SIMPLE("a\\W", false);
  CHECK_SIMPLE("a.", false);
  CHECK_SIMPLE("a\\q", false);
  CHECK_SIMPLE("a[a]", false);
  CHECK_SIMPLE("a[^a]", false);
  CHECK_SIMPLE("a[a-z]", false);
  CHECK_SIMPLE("a[\\q]", false);
  CHECK_SIMPLE("a(?:b)", false);
  CHECK_SIMPLE("a(?=b)", false);
  CHECK_SIMPLE("a(?!b)", false);
  CHECK_SIMPLE("\\x60", false);
  CHECK_SIMPLE("\\u0060", false);
  CHECK_SIMPLE("\\cA", false);
  CHECK_SIMPLE("\\q", false);
  CHECK_SIMPLE("\\1112", false);
  CHECK_SIMPLE("\\0", false);
  CHECK_SIMPLE("(a)\\1", false);
  CHECK_SIMPLE("(?=a)?a", false);
  CHECK_SIMPLE("(?!a)?a\\1", false);
  CHECK_SIMPLE("(?:(?=a))a\\1", false);

  CheckParseEq("a{}", "'a{}'");
  CheckParseEq("a{,}", "'a{,}'");
  CheckParseEq("a{", "'a{'");
  CheckParseEq("a{z}", "'a{z}'");
  CheckParseEq("a{1z}", "'a{1z}'");
  CheckParseEq("a{12z}", "'a{12z}'");
  CheckParseEq("a{12,", "'a{12,'");
  CheckParseEq("a{12,3b", "'a{12,3b'");
  CheckParseEq("{}", "'{}'");
  CheckParseEq("{,}", "'{,}'");
  CheckParseEq("{", "'{'");
  CheckParseEq("{z}", "'{z}'");
  CheckParseEq("{1z}", "'{1z}'");
  CheckParseEq("{12z}", "'{12z}'");
  CheckParseEq("{12,", "'{12,'");
  CheckParseEq("{12,3b", "'{12,3b'");

  CHECK_MIN_MAX("a", 1, 1);
  CHECK_MIN_MAX("abc", 3, 3);
  CHECK_MIN_MAX("a[bc]d", 3, 3);
  CHECK_MIN_MAX("a|bc", 1, 2);
  CHECK_MIN_MAX("ab|c", 1, 2);
  CHECK_MIN_MAX("a||bc", 0, 2);
  CHECK_MIN_MAX("|", 0, 0);
  CHECK_MIN_MAX("(?:ab)", 2, 2);
  CHECK_MIN_MAX("(?:ab|cde)", 2, 3);
  CHECK_MIN_MAX("(?:ab)|cde", 2, 3);
  CHECK_MIN_MAX("(ab)", 2, 2);
  CHECK_MIN_MAX("(ab|cde)", 2, 3);
  CHECK_MIN_MAX("(ab)\\1", 2, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(ab|cde)\\1", 2, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:ab)?", 0, 2);
  CHECK_MIN_MAX("(?:ab)*", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:ab)+", 2, RegExpTree::kInfinity);
  CHECK_MIN_MAX("a?", 0, 1);
  CHECK_MIN_MAX("a*", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("a+", 1, RegExpTree::kInfinity);
  CHECK_MIN_MAX("a??", 0, 1);
  CHECK_MIN_MAX("a*?", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("a+?", 1, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:a?)?", 0, 1);
  CHECK_MIN_MAX("(?:a*)?", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:a+)?", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:a?)+", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:a*)+", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:a+)+", 1, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:a?)*", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:a*)*", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:a+)*", 0, RegExpTree::kInfinity);
  CHECK_MIN_MAX("a{0}", 0, 0);
  CHECK_MIN_MAX("(?:a+){0}", 0, 0);
  CHECK_MIN_MAX("(?:a+){0,0}", 0, 0);
  CHECK_MIN_MAX("a*b", 1, RegExpTree::kInfinity);
  CHECK_MIN_MAX("a+b", 2, RegExpTree::kInfinity);
  CHECK_MIN_MAX("a*b|c", 1, RegExpTree::kInfinity);
  CHECK_MIN_MAX("a+b|c", 1, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:a{5,1000000}){3,1000000}", 15, RegExpTree::kInfinity);
  CHECK_MIN_MAX("(?:ab){4,7}", 8, 14);
  CHECK_MIN_MAX("a\\bc", 2, 2);
  CHECK_MIN_MAX("a\\Bc", 2, 2);
  CHECK_MIN_MAX("a\\sc", 3, 3);
  CHECK_MIN_MAX("a\\Sc", 3, 3);
  CHECK_MIN_MAX("a(?=b)c", 2, 2);
  CHECK_MIN_MAX("a(?=bbb|bb)c", 2, 2);
  CHECK_MIN_MAX("a(?!bbb|bb)c", 2, 2);

  CheckParseEq("(?<a>x)(?<b>x)(?<c>x)\\k<a>",
               "(: (^ 'x') (^ 'x') (^ 'x') (<- 1))", true);
  CheckParseEq("(?<a>x)(?<b>x)(?<c>x)\\k<b>",
               "(: (^ 'x') (^ 'x') (^ 'x') (<- 2))", true);
  CheckParseEq("(?<a>x)(?<b>x)(?<c>x)\\k<c>",
               "(: (^ 'x') (^ 'x') (^ 'x') (<- 3))", true);
  CheckParseEq("(?<a>a)\\k<a>", "(: (^ 'a') (<- 1))", true);
  CheckParseEq("(?<a>a\\k<a>)", "(^ 'a')", true);
  CheckParseEq("(?<a>\\k<a>a)", "(^ 'a')", true);
  CheckParseEq("(?<a>\\k<b>)(?<b>\\k<a>)", "(: (^ (<- 2)) (^ (<- 1)))", true);
  CheckParseEq("\\k<a>(?<a>a)", "(: (<- 1) (^ 'a'))", true);

  CheckParseEq("(?<\\u{03C0}>a)", "(^ 'a')", true);
  CheckParseEq("(?<\\u03C0>a)", "(^ 'a')", true);
}

TEST_F(RegExpTest, ParserRegression) {
  CheckParseEq("[A-Z$-][x]", "(! [A-Z $ -] [x])");
  CheckParseEq("a{3,4*}", "(: 'a{3,' (# 0 - g '4') '}')");
  CheckParseEq("{", "'{'");
  CheckParseEq("a|", "(| 'a' %)");
}

static void ExpectError(const char* input, const char* expected,
                        bool unicode = false) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  Zone zone(isolate->allocator(), ZONE_NAME);
  DirectHandle<String> str =
      isolate->factory()->NewStringFromAsciiChecked(input);
  RegExpCompileData result;
  RegExpFlags flags;
  if (unicode) flags |= RegExpFlag::kUnicode;
  CHECK(!RegExpParser::ParseRegExpFromHeapString(isolate, &zone, str, flags,
                                                 &result));
  CHECK_NULL(result.tree);
  CHECK_NE(RegExpError::kNone, result.error);
  CHECK_EQ(0, strcmp(expected, RegExpErrorString(result.error)));
}

TEST_F(RegExpTest, Errors) {
  const char* kEndBackslash = "\\ at end of pattern";
  ExpectError("\\", kEndBackslash);
  const char* kUnterminatedGroup = "Unterminated group";
  ExpectError("(foo", kUnterminatedGroup);
  const char* kInvalidGroup = "Invalid group";
  ExpectError("(?", kInvalidGroup);
  const char* kUnterminatedCharacterClass = "Unterminated character class";
  ExpectError("[", kUnterminatedCharacterClass);
  ExpectError("[a-", kUnterminatedCharacterClass);
  const char* kNothingToRepeat = "Nothing to repeat";
  ExpectError("*", kNothingToRepeat);
  ExpectError("?", kNothingToRepeat);
  ExpectError("+", kNothingToRepeat);
  ExpectError("{1}", kNothingToRepeat);
  ExpectError("{1,2}", kNothingToRepeat);
  ExpectError("{1,}", kNothingToRepeat);

  // Check that we don't allow more than kMaxCapture captures
  const int kMaxCaptures = 1 << 16;  // Must match RegExpParser::kMaxCaptures.
  const char* kTooManyCaptures = "Too many captures";
  std::ostringstream os;
  for (int i = 0; i <= kMaxCaptures; i++) {
    os << "()";
  }
  ExpectError(os.str().c_str(), kTooManyCaptures);

  const char* kInvalidCaptureName = "Invalid capture group name";
  ExpectError("(?<>.)", kInvalidCaptureName, true);
  ExpectError("(?<1>.)", kInvalidCaptureName, true);
  ExpectError("(?<_%>.)", kInvalidCaptureName, true);
  ExpectError("\\k<a", kInvalidCaptureName, true);
  const char* kDuplicateCaptureName = "Duplicate capture group name";
  ExpectError("(?<a>.)(?<a>.)", kDuplicateCaptureName, true);
  const char* kInvalidUnicodeEscape = "Invalid Unicode escape";
  ExpectError("(?<\\u{FISK}", kInvalidUnicodeEscape, true);
  const char* kInvalidCaptureReferenced = "Invalid named capture referenced";
  ExpectError("\\k<a>", kInvalidCaptureReferenced, true);
  ExpectError("(?<b>)\\k<a>", kInvalidCaptureReferenced, true);
  const char* kInvalidNamedReference = "Invalid named reference";
  ExpectError("\\ka", kInvalidNamedReference, true);
}

static bool IsDigit(base::uc32 c) { return ('0' <= c && c <= '9'); }

static bool NotDigit(base::uc32 c) { return !IsDigit(c); }

static bool NotWhiteSpaceNorLineTermiantor(base::uc32 c) {
  return !IsWhiteSpaceOrLineTerminator(c);
}

static bool NotWord(base::uc32 c) { return !IsRegExpWord(c); }

static bool NotLineTerminator(base::uc32 c) {
  return !unibrow::IsLineTerminator(c);
}

static void TestCharacterClassEscapes(StandardCharacterSet c,
                                      bool(pred)(base::uc32 c)) {
  Zone zone(
      reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent())->allocator(),
      ZONE_NAME);
  ZoneList<CharacterRange>* ranges =
      zone.New<ZoneList<CharacterRange>>(2, &zone);
  CharacterRange::AddClassEscape(c, ranges, false, &zone);
  for (base::uc32 i = 0; i < (1 << 16); i++) {
    bool in_class = false;
    for (int j = 0; !in_class && j < ranges->length(); j++) {
      CharacterRange& range = ranges->at(j);
      in_class = (range.from() <= i && i <= range.to());
    }
    CHECK_EQ(pred(i), in_class);
  }
}

TEST_F(RegExpTest, CharacterClassEscapes) {
  TestCharacterClassEscapes(StandardCharacterSet::kNotLineTerminator,
                            NotLineTerminator);
  TestCharacterClassEscapes(StandardCharacterSet::kDigit, IsDigit);
  TestCharacterClassEscapes(StandardCharacterSet::kNotDigit, NotDigit);
  TestCharacterClassEscapes(StandardCharacterSet::kWhitespace,
                            IsWhiteSpaceOrLineTerminator);
  TestCharacterClassEscapes(StandardCharacterSet::kNotWhitespace,
                            NotWhiteSpaceNorLineTermiantor);
  TestCharacterClassEscapes(StandardCharacterSet::kWord, IsRegExpWord);
  TestCharacterClassEscapes(StandardCharacterSet::kNotWord, NotWord);
}

static RegExpNode* Compile(const char* input, bool multiline, bool unicode,
                           bool is_one_byte, Zone* zone) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());
  DirectHandle<String> str =
      isolate->factory()->NewStringFromAsciiChecked(input);
  RegExpCompileData compile_data;
  compile_data.compilation_target = RegExpCompilationTarget::kNative;
  RegExpFlags flags;
  if (multiline) flags |= RegExpFlag::kMultiline;
  if (unicode) flags |= RegExpFlag::kUnicode;
  if (!RegExpParser::ParseRegExpFromHeapString(isolate, zone, str, flags,
                                               &compile_data)) {
    return nullptr;
  }
  Handle<String> pattern = isolate->factory()
                               ->NewStringFromUtf8(base::CStrVector(input))
                               .ToHandleChecked();
  Handle<String> sample_subject = isolate->factory()
                                      ->NewStringFromUtf8(base::CStrVector(""))
                                      .ToHandleChecked();
  RegExp::CompileForTesting(isolate, zone, &compile_data, flags, pattern,
                            sample_subject, is_one_byte);
  return compile_data.node;
}

static void Execute(const char* input, bool multiline, bool unicode,
                    bool is_one_byte, bool dot_output = false) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());
  Zone zone(
      reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent())->allocator(),
      ZONE_NAME);
  RegExpNode* node = Compile(input, multiline, unicode, is_one_byte, &zone);
  USE(node);
#ifdef DEBUG
  if (dot_output) RegExp::DotPrintForTesting(input, node);
#endif  // DEBUG
}

// Test of debug-only syntax.
#ifdef DEBUG

TEST_F(RegExpTest, ParsePossessiveRepetition) {
  bool old_flag_value = v8_flags.regexp_possessive_quantifier;

  // Enable possessive quantifier syntax.
  v8_flags.regexp_possessive_quantifier = true;

  CheckParseEq("a*+", "(# 0 - p 'a')");
  CheckParseEq("a++", "(# 1 - p 'a')");
  CheckParseEq("a?+", "(# 0 1 p 'a')");
  CheckParseEq("a{10,20}+", "(# 10 20 p 'a')");
  CheckParseEq("za{10,20}+b", "(: 'z' (# 10 20 p 'a') 'b')");

  // Disable possessive quantifier syntax.
  v8_flags.regexp_possessive_quantifier = false;

  CHECK_PARSE_ERROR("a*+");
  CHECK_PARSE_ERROR("a++");
  CHECK_PARSE_ERROR("a?+");
  CHECK_PARSE_ERROR("a{10,20}+");
  CHECK_PARSE_ERROR("a{10,20}+b");

  v8_flags.regexp_possessive_quantifier = old_flag_value;
}

#endif

// Tests of interpreter.

#if V8_TARGET_ARCH_IA32
using ArchRegExpMacroAssembler = RegExpMacroAssemblerIA32;
#elif V8_TARGET_ARCH_X64
using ArchRegExpMacroAssembler = RegExpMacroAssemblerX64;
#elif V8_TARGET_ARCH_ARM
using ArchRegExpMacroAssembler = RegExpMacroAssemblerARM;
#elif V8_TARGET_ARCH_ARM64
using ArchRegExpMacroAssembler = RegExpMacroAssemblerARM64;
#elif V8_TARGET_ARCH_S390X
using ArchRegExpMacroAssembler = RegExpMacroAssemblerS390;
#elif V8_TARGET_ARCH_PPC64
using ArchRegExpMacroAssembler = RegExpMacroAssemblerPPC;
#elif V8_TARGET_ARCH_MIPS64
using ArchRegExpMacroAssembler = RegExpMacroAssemblerMIPS;
#elif V8_TARGET_ARCH_LOONG64
using ArchRegExpMacroAssembler = RegExpMacroAssemblerLOONG64;
#elif V8_TARGET_ARCH_RISCV64
using ArchRegExpMacroAssembler = RegExpMacroAssemblerRISCV;
#elif V8_TARGET_ARCH_RISCV32
using ArchRegExpMacroAssembler = RegExpMacroAssemblerRISCV;
#endif

class ContextInitializer {
 public:
  ContextInitializer()
      : scope_(v8::Isolate::GetCurrent()),
        env_(v8::Context::New(v8::Isolate::GetCurrent())) {
    env_->Enter();
  }
  ~ContextInitializer() { env_->Exit(); }

 private:
  v8::HandleScope scope_;
  v8::Local<v8::Context> env_;
};

// Create new JSRegExp object with only necessary fields (for this tests)
// initialized.
static Handle<JSRegExp> CreateJSRegExp(DirectHandle<String> source,
                                       DirectHandle<Code> code,
                                       bool is_unicode = false) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());
  Factory* factory = isolate->factory();
  Handle<JSFunction> constructor = isolate->regexp_function();
  Handle<JSRegExp> regexp = Cast<JSRegExp>(factory->NewJSObject(constructor));
  regexp->set_source(*source);
  regexp->set_flags(Smi::FromInt(0));

  factory->SetRegExpIrregexpData(regexp, source, {}, 0,
                                 JSRegExp::kNoBacktrackLimit);
  Tagged<IrRegExpData> data = Cast<IrRegExpData>(regexp->data(isolate));
  const bool is_latin1 = !is_unicode;
  data->set_code(is_latin1, *code);

  return regexp;
}

static ArchRegExpMacroAssembler::Result Execute(
    Tagged<JSRegExp> regexp, Tagged<String> input, int start_offset,
    Address input_start, Address input_end, int* captures) {
  // For testing, we don't bother to pass in the `captures` size. This is okay
  // as long as the caller knows what they're doing, and avoids having the
  // engine write OOB or exiting a global execution loop early.
  static constexpr int kCapturesSize = 0;
  return static_cast<NativeRegExpMacroAssembler::Result>(
      NativeRegExpMacroAssembler::ExecuteForTesting(
          input, start_offset, reinterpret_cast<uint8_t*>(input_start),
          reinterpret_cast<uint8_t*>(input_end), captures, kCapturesSize,
          reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent()), regexp));
}

TEST_F(RegExpTest, MacroAssemblerNativeSuccess) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 4);

  m.Succeed();

  Handle<String> source = factory->NewStringFromStaticChars("");
  Handle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  int captures[4] = {42, 37, 87, 117};
  DirectHandle<String> input = factory->NewStringFromStaticChars("foofoo");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + seq_input->length(), captures);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(-1, captures[0]);
  CHECK_EQ(-1, captures[1]);
  CHECK_EQ(-1, captures[2]);
  CHECK_EQ(-1, captures[3]);
}

TEST_F(RegExpTest, MacroAssemblerNativeSimple) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 4);

  Label fail, backtrack;
  m.PushBacktrack(&fail);
  m.CheckNotAtStart(0, nullptr);
  m.LoadCurrentCharacter(2, nullptr);
  m.CheckNotCharacter('o', nullptr);
  m.LoadCurrentCharacter(1, nullptr, false);
  m.CheckNotCharacter('o', nullptr);
  m.LoadCurrentCharacter(0, nullptr, false);
  m.CheckNotCharacter('f', nullptr);
  m.WriteCurrentPositionToRegister(0, 0);
  m.WriteCurrentPositionToRegister(1, 3);
  m.AdvanceCurrentPosition(3);
  m.PushBacktrack(&backtrack);
  m.Succeed();
  m.BindJumpTarget(&backtrack);
  m.Backtrack();
  m.BindJumpTarget(&fail);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("^foo");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  int captures[4] = {42, 37, 87, 117};
  Handle<String> input = factory->NewStringFromStaticChars("foofoo");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), captures);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, captures[0]);
  CHECK_EQ(3, captures[1]);
  CHECK_EQ(-1, captures[2]);
  CHECK_EQ(-1, captures[3]);

  input = factory->NewStringFromStaticChars("barbarbar");
  seq_input = Cast<SeqOneByteString>(input);
  start_adr = seq_input->GetCharsAddress();

  result = Execute(*regexp, *input, 0, start_adr, start_adr + input->length(),
                   captures);

  CHECK_EQ(NativeRegExpMacroAssembler::FAILURE, result);
}

TEST_F(RegExpTest, MacroAssemblerNativeSimpleUC16) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::UC16, 4);

  Label fail, backtrack;
  m.PushBacktrack(&fail);
  m.CheckNotAtStart(0, nullptr);
  m.LoadCurrentCharacter(2, nullptr);
  m.CheckNotCharacter('o', nullptr);
  m.LoadCurrentCharacter(1, nullptr, false);
  m.CheckNotCharacter('o', nullptr);
  m.LoadCurrentCharacter(0, nullptr, false);
  m.CheckNotCharacter('f', nullptr);
  m.WriteCurrentPositionToRegister(0, 0);
  m.WriteCurrentPositionToRegister(1, 3);
  m.AdvanceCurrentPosition(3);
  m.PushBacktrack(&backtrack);
  m.Succeed();
  m.BindJumpTarget(&backtrack);
  m.Backtrack();
  m.BindJumpTarget(&fail);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("^foo");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code, true);

  int captures[4] = {42, 37, 87, 117};
  const base::uc16 input_data[6] = {'f', 'o', 'o',
                                    'f', 'o', static_cast<base::uc16>(0x2603)};
  Handle<String> input =
      factory
          ->NewStringFromTwoByte(base::Vector<const base::uc16>(input_data, 6))
          .ToHandleChecked();
  DirectHandle<SeqTwoByteString> seq_input = Cast<SeqTwoByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), captures);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, captures[0]);
  CHECK_EQ(3, captures[1]);
  CHECK_EQ(-1, captures[2]);
  CHECK_EQ(-1, captures[3]);

  const base::uc16 input_data2[9] = {
      'b', 'a', 'r', 'b', 'a', 'r', 'b', 'a', static_cast<base::uc16>(0x2603)};
  input =
      factory
          ->NewStringFromTwoByte(base::Vector<const base::uc16>(input_data2, 9))
          .ToHandleChecked();
  seq_input = Cast<SeqTwoByteString>(input);
  start_adr = seq_input->GetCharsAddress();

  result = Execute(*regexp, *input, 0, start_adr,
                   start_adr + input->length() * 2, captures);

  CHECK_EQ(NativeRegExpMacroAssembler::FAILURE, result);
}

TEST_F(RegExpTest, MacroAssemblerNativeBacktrack) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 0);

  Label fail;
  Label backtrack;
  m.LoadCurrentCharacter(10, &fail);
  m.Succeed();
  m.BindJumpTarget(&fail);
  m.PushBacktrack(&backtrack);
  m.LoadCurrentCharacter(10, nullptr);
  m.Succeed();
  m.BindJumpTarget(&backtrack);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("..........");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  DirectHandle<String> input = factory->NewStringFromStaticChars("foofoo");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), nullptr);

  CHECK_EQ(NativeRegExpMacroAssembler::FAILURE, result);
}

TEST_F(RegExpTest, MacroAssemblerNativeBackReferenceLATIN1) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 4);

  m.WriteCurrentPositionToRegister(0, 0);
  m.AdvanceCurrentPosition(2);
  m.WriteCurrentPositionToRegister(1, 0);
  Label nomatch;
  m.CheckNotBackReference(0, false, &nomatch);
  m.Fail();
  m.Bind(&nomatch);
  m.AdvanceCurrentPosition(2);
  Label missing_match;
  m.CheckNotBackReference(0, false, &missing_match);
  m.WriteCurrentPositionToRegister(2, 0);
  m.Succeed();
  m.Bind(&missing_match);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("^(..)..\1");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  DirectHandle<String> input = factory->NewStringFromStaticChars("fooofo");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int output[4];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), output);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, output[0]);
  CHECK_EQ(2, output[1]);
  CHECK_EQ(6, output[2]);
  CHECK_EQ(-1, output[3]);
}

TEST_F(RegExpTest, MacroAssemblerNativeBackReferenceUC16) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::UC16, 4);

  m.WriteCurrentPositionToRegister(0, 0);
  m.AdvanceCurrentPosition(2);
  m.WriteCurrentPositionToRegister(1, 0);
  Label nomatch;
  m.CheckNotBackReference(0, false, &nomatch);
  m.Fail();
  m.Bind(&nomatch);
  m.AdvanceCurrentPosition(2);
  Label missing_match;
  m.CheckNotBackReference(0, false, &missing_match);
  m.WriteCurrentPositionToRegister(2, 0);
  m.Succeed();
  m.Bind(&missing_match);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("^(..)..\1");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code, true);

  const base::uc16 input_data[6] = {'f', 0x2028, 'o', 'o', 'f', 0x2028};
  DirectHandle<String> input =
      factory
          ->NewStringFromTwoByte(base::Vector<const base::uc16>(input_data, 6))
          .ToHandleChecked();
  DirectHandle<SeqTwoByteString> seq_input = Cast<SeqTwoByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int output[4];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length() * 2, output);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, output[0]);
  CHECK_EQ(2, output[1]);
  CHECK_EQ(6, output[2]);
  CHECK_EQ(-1, output[3]);
}

TEST_F(RegExpTest, MacroAssemblernativeAtStart) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 0);

  Label not_at_start, newline, fail;
  m.CheckNotAtStart(0, &not_at_start);
  // Check that prevchar = '\n' and current = 'f'.
  m.CheckCharacter('\n', &newline);
  m.BindJumpTarget(&fail);
  m.Fail();
  m.Bind(&newline);
  m.LoadCurrentCharacter(0, &fail);
  m.CheckNotCharacter('f', &fail);
  m.Succeed();

  m.Bind(&not_at_start);
  // Check that prevchar = 'o' and current = 'b'.
  Label prevo;
  m.CheckCharacter('o', &prevo);
  m.Fail();
  m.Bind(&prevo);
  m.LoadCurrentCharacter(0, &fail);
  m.CheckNotCharacter('b', &fail);
  m.Succeed();

  Handle<String> source = factory->NewStringFromStaticChars("(^f|ob)");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  DirectHandle<String> input = factory->NewStringFromStaticChars("foobar");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), nullptr);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);

  result = Execute(*regexp, *input, 3, start_adr + 3,
                   start_adr + input->length(), nullptr);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
}

TEST_F(RegExpTest, MacroAssemblerNativeBackRefNoCase) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 4);

  Label fail, succ;

  m.WriteCurrentPositionToRegister(0, 0);
  m.WriteCurrentPositionToRegister(2, 0);
  m.AdvanceCurrentPosition(3);
  m.WriteCurrentPositionToRegister(3, 0);
  m.CheckNotBackReferenceIgnoreCase(2, false, false, &fail);  // Match "AbC".
  m.CheckNotBackReferenceIgnoreCase(2, false, false, &fail);  // Match "ABC".
  Label expected_fail;
  m.CheckNotBackReferenceIgnoreCase(2, false, false, &expected_fail);
  m.BindJumpTarget(&fail);
  m.Fail();

  m.Bind(&expected_fail);
  m.AdvanceCurrentPosition(3);  // Skip "xYz"
  m.CheckNotBackReferenceIgnoreCase(2, false, false, &succ);
  m.Fail();

  m.Bind(&succ);
  m.WriteCurrentPositionToRegister(1, 0);
  m.Succeed();

  Handle<String> source =
      factory->NewStringFromStaticChars("^(abc)\1\1(?!\1)...(?!\1)");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  DirectHandle<String> input =
      factory->NewStringFromStaticChars("aBcAbCABCxYzab");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int output[4];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), output);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, output[0]);
  CHECK_EQ(12, output[1]);
  CHECK_EQ(0, output[2]);
  CHECK_EQ(3, output[3]);
}

TEST_F(RegExpTest, MacroAssemblerNativeRegisters) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 6);

  base::uc16 foo_chars[3] = {'f', 'o', 'o'};
  base::Vector<const base::uc16> foo(foo_chars, 3);

  enum registers { out1, out2, out3, out4, out5, out6, sp, loop_cnt };
  Label fail;
  Label backtrack;
  m.WriteCurrentPositionToRegister(out1, 0);  // Output: [0]
  m.PushRegister(out1, RegExpMacroAssembler::kNoStackLimitCheck);
  m.PushBacktrack(&backtrack);
  m.WriteStackPointerToRegister(sp);
  // Fill stack and registers
  m.AdvanceCurrentPosition(2);
  m.WriteCurrentPositionToRegister(out1, 0);
  m.PushRegister(out1, RegExpMacroAssembler::kNoStackLimitCheck);
  m.PushBacktrack(&fail);
  // Drop backtrack stack frames.
  m.ReadStackPointerFromRegister(sp);
  // And take the first backtrack (to &backtrack)
  m.Backtrack();

  m.PushCurrentPosition();
  m.AdvanceCurrentPosition(2);
  m.PopCurrentPosition();

  m.BindJumpTarget(&backtrack);
  m.PopRegister(out1);
  m.ReadCurrentPositionFromRegister(out1);
  m.AdvanceCurrentPosition(3);
  m.WriteCurrentPositionToRegister(out2, 0);  // [0,3]

  Label loop;
  m.SetRegister(loop_cnt, 0);  // loop counter
  m.Bind(&loop);
  m.AdvanceRegister(loop_cnt, 1);
  m.AdvanceCurrentPosition(1);
  m.IfRegisterLT(loop_cnt, 3, &loop);
  m.WriteCurrentPositionToRegister(out3, 0);  // [0,3,6]

  Label loop2;
  m.SetRegister(loop_cnt, 2);  // loop counter
  m.Bind(&loop2);
  m.AdvanceRegister(loop_cnt, -1);
  m.AdvanceCurrentPosition(1);
  m.IfRegisterGE(loop_cnt, 0, &loop2);
  m.WriteCurrentPositionToRegister(out4, 0);  // [0,3,6,9]

  Label loop3;
  Label exit_loop3;
  m.PushRegister(out4, RegExpMacroAssembler::kNoStackLimitCheck);
  m.PushRegister(out4, RegExpMacroAssembler::kNoStackLimitCheck);
  m.ReadCurrentPositionFromRegister(out3);
  m.Bind(&loop3);
  m.AdvanceCurrentPosition(1);
  m.CheckGreedyLoop(&exit_loop3);
  m.GoTo(&loop3);
  m.Bind(&exit_loop3);
  m.PopCurrentPosition();
  m.WriteCurrentPositionToRegister(out5, 0);  // [0,3,6,9,9,-1]

  m.Succeed();

  m.BindJumpTarget(&fail);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("<loop test>");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  // String long enough for test (content doesn't matter).
  DirectHandle<String> input =
      factory->NewStringFromStaticChars("foofoofoofoofoo");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int output[6];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), output);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, output[0]);
  CHECK_EQ(3, output[1]);
  CHECK_EQ(6, output[2]);
  CHECK_EQ(9, output[3]);
  CHECK_EQ(9, output[4]);
  CHECK_EQ(-1, output[5]);
}

TEST_F(RegExpTest, MacroAssemblerStackOverflow) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 0);

  Label loop;
  m.Bind(&loop);
  m.PushBacktrack(&loop);
  m.GoTo(&loop);

  Handle<String> source =
      factory->NewStringFromStaticChars("<stack overflow test>");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  // String long enough for test (content doesn't matter).
  DirectHandle<String> input = factory->NewStringFromStaticChars("dummy");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), nullptr);

  CHECK_EQ(NativeRegExpMacroAssembler::EXCEPTION, result);
  CHECK(isolate()->has_exception());
  isolate()->clear_exception();
}

TEST_F(RegExpTest, MacroAssemblerNativeLotsOfRegisters) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 2);

  // At least 2048, to ensure the allocated space for registers
  // span one full page.
  const int large_number = 8000;
  m.WriteCurrentPositionToRegister(large_number, 42);
  m.WriteCurrentPositionToRegister(0, 0);
  m.WriteCurrentPositionToRegister(1, 1);
  Label done;
  m.CheckNotBackReference(0, false, &done);  // Performs a system-stack push.
  m.Bind(&done);
  m.PushRegister(large_number, RegExpMacroAssembler::kNoStackLimitCheck);
  m.PopRegister(1);
  m.Succeed();

  Handle<String> source =
      factory->NewStringFromStaticChars("<huge register space test>");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  // String long enough for test (content doesn't matter).
  DirectHandle<String> input = factory->NewStringFromStaticChars("sample text");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int captures[2];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), captures);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, captures[0]);
  CHECK_EQ(42, captures[1]);

  isolate()->clear_exception();
}

TEST_F(RegExpTest, MacroAssembler) {
  Zone zone(i_isolate()->allocator(), ZONE_NAME);
  RegExpBytecodeGenerator m(i_isolate(), &zone);
  // ^f(o)o.
  Label start, fail, backtrack;

  m.SetRegister(4, 42);
  m.PushRegister(4, RegExpMacroAssembler::kNoStackLimitCheck);
  m.AdvanceRegister(4, 42);
  m.GoTo(&start);
  m.Fail();
  m.Bind(&start);
  m.PushBacktrack(&fail);
  m.CheckNotAtStart(0, nullptr);
  m.LoadCurrentCharacter(0, nullptr);
  m.CheckNotCharacter('f', nullptr);
  m.LoadCurrentCharacter(1, nullptr);
  m.CheckNotCharacter('o', nullptr);
  m.LoadCurrentCharacter(2, nullptr);
  m.CheckNotCharacter('o', nullptr);
  m.WriteCurrentPositionToRegister(0, 0);
  m.WriteCurrentPositionToRegister(1, 3);
  m.WriteCurrentPositionToRegister(2, 1);
  m.WriteCurrentPositionToRegister(3, 2);
  m.AdvanceCurrentPosition(3);
  m.PushBacktrack(&backtrack);
  m.Succeed();
  m.BindJumpTarget(&backtrack);
  m.ClearRegisters(2, 3);
  m.Backtrack();
  m.BindJumpTarget(&fail);
  m.PopRegister(0);
  m.Fail();

  Factory* factory = i_isolate()->factory();
  HandleScope scope(i_isolate());

  Handle<String> source = factory->NewStringFromStaticChars("^f(o)o");
  DirectHandle<TrustedByteArray> array =
      Cast<TrustedByteArray>(m.GetCode(source, {}));
  int captures[5];
  std::memset(captures, 0, sizeof(captures));

  const base::uc16 str1[] = {'f', 'o', 'o', 'b', 'a', 'r'};
  DirectHandle<String> f1_16 =
      factory->NewStringFromTwoByte(base::Vector<const base::uc16>(str1, 6))
          .ToHandleChecked();

  {
    Tagged<TrustedByteArray> array_unhandlified = *array;
    Tagged<String> subject_unhandlified = *f1_16;
    CHECK_EQ(IrregexpInterpreter::SUCCESS,
             IrregexpInterpreter::MatchInternal(
                 isolate(), &array_unhandlified, &subject_unhandlified,
                 captures, 5, 5, 0, RegExp::CallOrigin::kFromRuntime,
                 JSRegExp::kNoBacktrackLimit));
    CHECK_EQ(0, captures[0]);
    CHECK_EQ(3, captures[1]);
    CHECK_EQ(1, captures[2]);
    CHECK_EQ(2, captures[3]);
    CHECK_EQ(84, captures[4]);
  }

  const base::uc16 str2[] = {'b', 'a', 'r', 'f', 'o', 'o'};
  DirectHandle<String> f2_16 =
      factory->NewStringFromTwoByte(base::Vector<const base::uc16>(str2, 6))
          .ToHandleChecked();

  {
    Tagged<TrustedByteArray> array_unhandlified = *array;
    Tagged<String> subject_unhandlified = *f2_16;
    std::memset(captures, 0, sizeof(captures));
    CHECK_EQ(IrregexpInterpreter::FAILURE,
             IrregexpInterpreter::MatchInternal(
                 isolate(), &array_unhandlified, &subject_unhandlified,
                 captures, 5, 5, 0, RegExp::CallOrigin::kFromRuntime,
                 JSRegExp::kNoBacktrackLimit));
    // Failed matches don't alter output registers.
    CHECK_EQ(0, captures[0]);
    CHECK_EQ(0, captures[1]);
    CHECK_EQ(0, captures[2]);
    CHECK_EQ(0, captures[3]);
    CHECK_EQ(0, captures[4]);
  }
}

#ifndef V8_INTL_SUPPORT
static base::uc32 canonicalize(base::uc32 c) {
  unibrow::uchar canon[unibrow::Ecma262Canonicalize::kMaxWidth];
  int count = unibrow::Ecma262Canonicalize::Convert(c, '\0', canon, nullptr);
  if (count == 0) {
    return c;
  } else {
    CHECK_EQ(1, count);
    return canon[0];
  }
}

TEST_F(RegExpTest, LatinCanonicalize) {
  unibrow::Mapping<unibrow::Ecma262UnCanonicalize> un_canonicalize;
  for (unibrow::uchar lower = 'a'; lower <= 'z'; lower++) {
    unibrow::uchar upper = lower + ('A' - 'a');
    CHECK_EQ(canonicalize(lower), canonicalize(upper));
    unibrow::uchar uncanon[unibrow::Ecma262UnCanonicalize::kMaxWidth];
    int length = un_canonicalize.get(lower, '\0', uncanon);
    CHECK_EQ(2, length);
    CHECK_EQ(upper, uncanon[0]);
    CHECK_EQ(lower, uncanon[1]);
  }
  for (base::uc32 c = 128; c < (1 << 21); c++) CHECK_GE(canonicalize(c), 128);
  unibrow::Mapping<unibrow::ToUppercase> to_upper;
  // Canonicalization is only defined for the Basic Multilingual Plane.
  for (base::uc32 c = 0; c < (1 << 16); c++) {
    unibrow::uchar upper[unibrow::ToUppercase::kMaxWidth];
    int length = to_upper.get(c, '\0', upper);
    if (length == 0) {
      length = 1;
      upper[0] = c;
    }
    base::uc32 u = upper[0];
    if (length > 1 || (c >= 128 && u < 128)) u = c;
    CHECK_EQ(u, canonicalize(c));
  }
}

static base::uc32 CanonRangeEnd(base::uc32 c) {
  unibrow::uchar canon[unibrow::CanonicalizationRange::kMaxWidth];
  int count = unibrow::CanonicalizationRange::Convert(c, '\0', canon, nullptr);
  if (count == 0) {
    return c;
  } else {
    CHECK_EQ(1, count);
    return canon[0];
  }
}

TEST_F(RegExpTest, RangeCanonicalization) {
  // Check that we arrive at the same result when using the basic
  // range canonicalization primitives as when using immediate
  // canonicalization.
  unibrow::Mapping<unibrow::Ecma262UnCanonicalize> un_canonicalize;
  int block_start = 0;
  while (block_start <= 0xFFFF) {
    base::uc32 block_end = CanonRangeEnd(block_start);
    unsigned block_length = block_end - block_start + 1;
    if (block_length > 1) {
      unibrow::uchar first[unibrow::Ecma262UnCanonicalize::kMaxWidth];
      int first_length = un_canonicalize.get(block_start, '\0', first);
      for (unsigned i = 1; i < block_length; i++) {
        unibrow::uchar succ[unibrow::Ecma262UnCanonicalize::kMaxWidth];
        int succ_length = un_canonicalize.get(block_start + i, '\0', succ);
        CHECK_EQ(first_length, succ_length);
        for (int j = 0; j < succ_length; j++) {
          int calc = first[j] + i;
          int found = succ[j];
          CHECK_EQ(calc, found);
        }
      }
    }
    block_start = block_start + block_length;
  }
}

TEST_F(RegExpTest, UncanonicalizeEquivalence) {
  unibrow::Mapping<unibrow::Ecma262UnCanonicalize> un_canonicalize;
  unibrow::uchar chars[unibrow::Ecma262UnCanonicalize::kMaxWidth];
  for (int i = 0; i < (1 << 16); i++) {
    int length = un_canonicalize.get(i, '\0', chars);
    for (int j = 0; j < length; j++) {
      unibrow::uchar chars2[unibrow::Ecma262UnCanonicalize::kMaxWidth];
      int length2 = un_canonicalize.get(chars[j], '\0', chars2);
      CHECK_EQ(length, length2);
      for (int k = 0; k < length; k++)
        CHECK_EQ(static_cast<int>(chars[k]), static_cast<int>(chars2[k]));
    }
  }
}

#endif

static void TestRangeCaseIndependence(Isolate* isolate, CharacterRange input,
                                      base::Vector<CharacterRange> expected) {
  Zone zone(
      reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent())->allocator(),
      ZONE_NAME);
  int count = expected.length();
  ZoneList<CharacterRange>* list =
      zone.New<ZoneList<CharacterRange>>(count, &zone);
  list->Add(input, &zone);
  CharacterRange::AddCaseEquivalents(isolate, &zone, list, false);
  list->Remove(0);  // Remove the input before checking results.
  CHECK_EQ(count, list->length());
  for (int i = 0; i < list->length(); i++) {
    CHECK_EQ(expected[i].from(), list->at(i).from());
    CHECK_EQ(expected[i].to(), list->at(i).to());
  }
}

static void TestSimpleRangeCaseIndependence(Isolate* isolate,
                                            CharacterRange input,
                                            CharacterRange expected) {
  base::EmbeddedVector<CharacterRange, 1> vector;
  vector[0] = expected;
  TestRangeCaseIndependence(isolate, input, vector);
}

TEST_F(RegExpTest, CharacterRangeCaseIndependence) {
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Singleton('a'),
                                  CharacterRange::Singleton('A'));
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Singleton('z'),
                                  CharacterRange::Singleton('Z'));
#ifndef V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('a', 'z'),
                                  CharacterRange::Range('A', 'Z'));
#endif  // !V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('c', 'f'),
                                  CharacterRange::Range('C', 'F'));
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('a', 'b'),
                                  CharacterRange::Range('A', 'B'));
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('y', 'z'),
                                  CharacterRange::Range('Y', 'Z'));
#ifndef V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(),
                                  CharacterRange::Range('a' - 1, 'z' + 1),
                                  CharacterRange::Range('A', 'Z'));
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('A', 'Z'),
                                  CharacterRange::Range('a', 'z'));
#endif  // !V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('C', 'F'),
                                  CharacterRange::Range('c', 'f'));
#ifndef V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(),
                                  CharacterRange::Range('A' - 1, 'Z' + 1),
                                  CharacterRange::Range('a', 'z'));
  // Here we need to add [l-z] to complete the case independence of
  // [A-Za-z] but we expect [a-z] to be added since we always add a
  // whole block at a time.
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('A', 'k'),
                                  CharacterRange::Range('a', 'z'));
#endif  // !V8_INTL_SUPPORT
}

static bool InClass(base::uc32 c,
                    const UnicodeRangeSplitter::CharacterRangeVector* ranges) {
  if (ranges == nullptr) return false;
  for (size_t i = 0; i < ranges->size(); i++) {
    CharacterRange range = ranges->at(i);
    if (range.from() <= c && c <= range.to()) return true;
  }
  return false;
}

TEST_F(RegExpTest, UnicodeRangeSplitter) {
  Zone zone(i_isolate()->allocator(), ZONE_NAME);
  ZoneList<CharacterRange>* base = zone.New<ZoneList<CharacterRange>>(1, &zone);
  base->Add(CharacterRange::Everything(), &zone);
  UnicodeRangeSplitter splitter(base);
  // BMP
  for (base::uc32 c = 0; c < 0xD800; c++) {
    CHECK(InClass(c, splitter.bmp()));
    CHECK(!InClass(c, splitter.lead_surrogates()));
    CHECK(!InClass(c, splitter.trail_surrogates()));
    CHECK(!InClass(c, splitter.non_bmp()));
  }
  // Lead surrogates
  for (base::uc32 c = 0xD800; c < 0xDBFF; c++) {
    CHECK(!InClass(c, splitter.bmp()));
    CHECK(InClass(c, splitter.lead_surrogates()));
    CHECK(!InClass(c, splitter.trail_surrogates()));
    CHECK(!InClass(c, splitter.non_bmp()));
  }
  // Trail surrogates
  for (base::uc32 c = 0xDC00; c < 0xDFFF; c++) {
    CHECK(!InClass(c, splitter.bmp()));
    CHECK(!InClass(c, splitter.lead_surrogates()));
    CHECK(InClass(c, splitter.trail_surrogates()));
    CHECK(!InClass(c, splitter.non_bmp()));
  }
  // BMP
  for (base::uc32 c = 0xE000; c < 0xFFFF; c++) {
    CHECK(InClass(c, splitter.bmp()));
    CHECK(!InClass(c, splitter.lead_surrogates()));
    CHECK(!InClass(c, splitter.trail_surrogates()));
    CHECK(!InClass(c, splitter.non_bmp()));
  }
  // Non-BMP
  for (base::uc32 c = 0x10000; c < 0x10FFFF; c++) {
    CHECK(!InClass(c, splitter.bmp()));
    CHECK(!InClass(c, splitter.lead_surrogates()));
    CHECK(!InClass(c, splitter.trail_surrogates()));
    CHECK(InClass(c, splitter.non_bmp()));
  }
}

TEST_F(RegExpTest, CanonicalizeCharacterSets) {
  Zone zone(i_isolate()->allocator(), ZONE_NAME);
  ZoneList<CharacterRange>* list = zone.New<ZoneList<CharacterRange>>(4, &zone);
  CharacterSet set(list);

  list->Add(CharacterRange::Range(10, 20), &zone);
  list->Add(CharacterRange::Range(30, 40), &zone);
  list->Add(CharacterRange::Range(50, 60), &zone);
  set.Canonicalize();
  CHECK_EQ(3, list->length());
  CHECK_EQ(10, list->at(0).from());
  CHECK_EQ(20, list->at(0).to());
  CHECK_EQ(30, list->at(1).from());
  CHECK_EQ(40, list->at(1).to());
  CHECK_EQ(50, list->at(2).from());
  CHECK_EQ(60, list->at(2).to());

  list->Rewind(0);
  list->Add(CharacterRange::Range(10, 20), &zone);
  list->Add(CharacterRange::Range(50, 60), &zone);
  list->Add(CharacterRange::Range(30, 40), &zone);
  set.Canonicalize();
  CHECK_EQ(3, list->length());
  CHECK_EQ(10, list->at(0).from());
  CHECK_EQ(20, list->at(0).to());
  CHECK_EQ(30, list->at(1).from());
  CHECK_EQ(40, list->at(1).to());
  CHECK_EQ(50, list->at(2).from());
  CHECK_EQ(60, list->at(2).to());

  list->Rewind(0);
  list->Add(CharacterRange::Range(30, 40), &zone);
  list->Add(CharacterRange::Range(10, 20), &zone);
  list->Add(CharacterRange::Range(25, 25), &zone);
  list->Add(CharacterRange::Range(100, 100), &zone);
  list->Add(CharacterRange::Range(1, 1), &zone);
  set.Canonicalize();
  CHECK_EQ(5, list->length());
  CHECK_EQ(1, list->at(0).from());
  CHECK_EQ(1, list->at(0).to());
  CHECK_EQ(10, list->at(1).from());
  CHECK_EQ(20, list->at(1).to());
  CHECK_EQ(25, list->at(2).from());
  CHECK_EQ(25, list->at(2).to());
  CHECK_EQ(30, list->at(3).from());
  CHECK_EQ(40, list->at(3).to());
  CHECK_EQ(100, list->at(4).from());
  CHECK_EQ(100, list->at(4).to());

  list->Rewind(0);
  list->Add(CharacterRange::Range(10, 19), &zone);
  list->Add(CharacterRange::Range(21, 30), &zone);
  list->Add(CharacterRange::Range(20, 20), &zone);
  set.Canonicalize();
  CHECK_EQ(1, list->length());
  CHECK_EQ(10, list->at(0).from());
  CHECK_EQ(30, list->at(0).to());
}

TEST_F(RegExpTest, CharacterRangeMerge) {
  Zone zone(i_isolate()->allocator(), ZONE_NAME);
  ZoneList<CharacterRange> l1(4, &zone);
  ZoneList<CharacterRange> l2(4, &zone);
  // Create all combinations of intersections of ranges, both singletons and
  // longer.

  int offset = 0;

  // The five kinds of singleton intersections:
  //     X
  //   Y      - outside before
  //    Y     - outside touching start
  //     Y    - overlap
  //      Y   - outside touching end
  //       Y  - outside after

  for (int i = 0; i < 5; i++) {
    l1.Add(CharacterRange::Singleton(offset + 2), &zone);
    l2.Add(CharacterRange::Singleton(offset + i), &zone);
    offset += 6;
  }

  // The seven kinds of singleton/non-singleton intersections:
  //    XXX
  //  Y        - outside before
  //   Y       - outside touching start
  //    Y      - inside touching start
  //     Y     - entirely inside
  //      Y    - inside touching end
  //       Y   - outside touching end
  //        Y  - disjoint after

  for (int i = 0; i < 7; i++) {
    l1.Add(CharacterRange::Range(offset + 2, offset + 4), &zone);
    l2.Add(CharacterRange::Singleton(offset + i), &zone);
    offset += 8;
  }

  // The eleven kinds of non-singleton intersections:
  //
  //       XXXXXXXX
  // YYYY                  - outside before.
  //   YYYY                - outside touching start.
  //     YYYY              - overlapping start
  //       YYYY            - inside touching start
  //         YYYY          - entirely inside
  //           YYYY        - inside touching end
  //             YYYY      - overlapping end
  //               YYYY    - outside touching end
  //                 YYYY  - outside after
  //       YYYYYYYY        - identical
  //     YYYYYYYYYYYY      - containing entirely.

  for (int i = 0; i < 9; i++) {
    l1.Add(CharacterRange::Range(offset + 6, offset + 15), &zone);  // Length 8.
    l2.Add(CharacterRange::Range(offset + 2 * i, offset + 2 * i + 3), &zone);
    offset += 22;
  }
  l1.Add(CharacterRange::Range(offset + 6, offset + 15), &zone);
  l2.Add(CharacterRange::Range(offset + 6, offset + 15), &zone);
  offset += 22;
  l1.Add(CharacterRange::Range(offset + 6, offset + 15), &zone);
  l2.Add(CharacterRange::Range(offset + 4, offset + 17), &zone);
  offset += 22;

  // Different kinds of multi-range overlap:
  // XXXXXXXXXXXXXXXXXXXXXX         XXXXXXXXXXXXXXXXXXXXXX
  //   YYYY  Y  YYYY  Y  YYYY  Y  YYYY  Y  YYYY  Y  YYYY  Y

  l1.Add(CharacterRange::Range(offset, offset + 21), &zone);
  l1.Add(CharacterRange::Range(offset + 31, offset + 52), &zone);
  for (int i = 0; i < 6; i++) {
    l2.Add(CharacterRange::Range(offset + 2, offset + 5), &zone);
    l2.Add(CharacterRange::Singleton(offset + 8), &zone);
    offset += 9;
  }

  CHECK(CharacterRange::IsCanonical(&l1));
  CHECK(CharacterRange::IsCanonical(&l2));

  ZoneList<CharacterRange> first_only(4, &zone);
  ZoneList<CharacterRange> second_only(4, &zone);
  ZoneList<CharacterRange> both(4, &zone);
}

TEST_F(RegExpTest, Graph) { Execute("\\b\\w+\\b", false, true, true); }

namespace {

int* global_use_counts = nullptr;

void MockUseCounterCallback(v8::Isolate* isolate,
                            v8::Isolate::UseCounterFeature feature) {
  ++global_use_counts[feature];
}

}  // namespace

using RegExpTestWithContext = TestWithContext;
// Test that ES2015+ RegExp compatibility fixes are in place, that they
// are not overly broad, and the appropriate UseCounters are incremented
TEST_F(RegExpTestWithContext, UseCountRegExp) {
  v8::HandleScope scope(isolate());
  int use_counts[v8::Isolate::kUseCounterFeatureCount] = {};
  global_use_counts = use_counts;
  isolate()->SetUseCounterCallback(MockUseCounterCallback);

  // Compat fix: RegExp.prototype.sticky == undefined; UseCounter tracks it
  v8::Local<v8::Value> resultSticky = RunJS("RegExp.prototype.sticky");
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(0, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultSticky->IsUndefined());

  // re.sticky has approriate value and doesn't touch UseCounter
  v8::Local<v8::Value> resultReSticky = RunJS("/a/.sticky");
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(0, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultReSticky->IsFalse());

  // When the getter is called on another object, throw an exception
  // and don't increment the UseCounter
  v8::Local<v8::Value> resultStickyError = RunJS(
      "var exception;"
      "try { "
      "  Object.getOwnPropertyDescriptor(RegExp.prototype, 'sticky')"
      "      .get.call(null);"
      "} catch (e) {"
      "  exception = e;"
      "}"
      "exception");
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(0, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultStickyError->IsObject());

  // RegExp.prototype.toString() returns '/(?:)/' as a compatibility fix;
  // a UseCounter is incremented to track it.
  v8::Local<v8::Value> resultToString =
      RunJS("RegExp.prototype.toString().length");
  CHECK_EQ(2, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultToString->IsInt32());
  CHECK_EQ(
      6, resultToString->Int32Value(isolate()->GetCurrentContext()).FromJust());

  // .toString() works on normal RegExps
  v8::Local<v8::Value> resultReToString = RunJS("/a/.toString().length");
  CHECK_EQ(2, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultReToString->IsInt32());
  CHECK_EQ(
      3,
      resultReT
```