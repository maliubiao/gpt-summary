Response:
The user wants to understand the functionality of the C++ source code file `v8/test/unittests/regexp/regexp-unittest.cc`. I need to analyze the code and provide a summary of its purpose.

Here's a breakdown of the request and how I'll address each part:

1. **List the functionalities:** I will identify the main actions performed by the code, focusing on what it tests and how.
2. **Check for `.tq` extension:** I'll examine the filename and confirm it's a `.cc` file, not `.tq`.
3. **Relate to JavaScript functionality:** I'll determine which JavaScript RegExp features are being tested and provide relevant examples.
4. **Provide code logic reasoning:** I will analyze specific test cases and explain the expected input and output based on the RegExp parsing and matching logic.
5. **Illustrate common programming errors:** I'll look for test cases that check for error handling related to incorrect RegExp syntax.
6. **Summarize the functionality:** I'll provide a concise overview of the file's purpose.

**High-level plan:**

*   Identify the core testing framework used (looks like Google Test).
*   Focus on the `TEST_F` and static functions, as these define the tests.
*   Analyze the different test categories (e.g., parsing, error handling, macro assembler).
*   Connect the tests to specific RegExp features.
这是名为 `v8/test/unittests/regexp/regexp-unittest.cc` 的 V8 源代码文件的功能列表：

1. **RegExp 标志转换测试:**
    *   测试 `JSRegExp::StringFromFlags` 函数，该函数将 RegExp 对象的标志位转换为字符串。
    *   测试了有标志位、无标志位和所有标志位的情况。

    **JavaScript 示例:**
    ```javascript
    let regexp1 = /abc/ig;
    console.log(regexp1.flags); // 输出 "gi"

    let regexp2 = /abc/;
    console.log(regexp2.flags); // 输出 ""

    let regexp3 = /abc/dgimsuy;
    console.log(regexp3.flags); // 输出 "dgimsuy"
    ```

2. **RegExp 解析器测试:**
    *   测试 `RegExpParser::ParseRegExpFromHeapString` 函数，该函数用于解析正则表达式字符串并构建抽象语法树 (AST)。
    *   包含了大量测试用例，涵盖了各种正则表达式语法，例如：
        *   基本字符匹配 (`abc`)
        *   选择 (`abc|def`)
        *   锚点 (`^xxx$`)
        *   转义字符 (`\\b`, `\\d`)
        *   字符类 (`[xyz]`, `[a-z]`)
        *   量词 (`a*`, `a+`, `a?`, `a{n,m}`)
        *   非捕获组 `(?:...)`
        *   捕获组 `(...)`
        *   前瞻断言 `(?=...)`, `(?!...)`
        *   后顾断言 `(?<=...)`, `(?<!...)`
        *   反向引用 `\\1`, `\\2`
        *   Unicode 字符和转义 (`\\u{...}`)
        *   命名捕获组 `(?<a>...)` 和命名反向引用 `\\k<a>`
    *   `CheckParseEq` 函数用于断言解析结果的 AST 结构是否与预期一致。
    *   `CheckSimple` 函数用于检查正则表达式是否被认为是“简单的”（可以进行某些优化）。
    *   `CheckMinMaxMatch` 函数用于检查正则表达式的最小和最大匹配长度。

    **JavaScript 示例 (与解析相关):**
    虽然不能直接在 JavaScript 中调用 V8 的解析器，但这些测试用例验证了 JavaScript 正则表达式引擎对各种语法的解析是否正确。例如，测试用例 `CheckParseEq("abc|def", "(| 'abc' 'def')")` 验证了 JavaScript 引擎应该能够正确解析包含选择符 `|` 的正则表达式。

3. **RegExp 解析错误测试:**
    *   测试 `RegExpParser::ParseRegExpFromHeapString` 函数的错误处理能力。
    *   `ExpectError` 函数用于断言解析特定错误的正则表达式字符串时，是否会抛出预期的错误信息。
    *   测试了各种常见的正则表达式语法错误，例如：
        *   尾部的反斜杠
        *   未闭合的分组或字符类
        *   重复操作符缺少操作数
        *   过多的捕获组
        *   无效的捕获组名称或反向引用

    **JavaScript 示例 (与错误相关):**
    ```javascript
    try {
      new RegExp("(?<>.)"); // 抛出 SyntaxError，因为捕获组名称无效
    } catch (e) {
      console.error(e);
    }

    try {
      new RegExp("\\"); // 抛出 SyntaxError，因为尾部有反斜杠
    } catch (e) {
      console.error(e);
    }
    ```

4. **字符类转义测试:**
    *   测试 `CharacterRange::AddClassEscape` 函数，该函数用于处理字符类中的转义字符（例如 `\d`, `\s`, `\w`）。
    *   `TestCharacterClassEscapes` 函数用于验证不同字符类转义符是否正确匹配了预期的字符集。

    **JavaScript 示例:**
    ```javascript
    /\d/.test("1"); // true
    /\d/.test("a"); // false

    /\s/.test(" "); // true
    /\s/.test("a"); // false

    /\w/.test("a"); // true
    /\w/.test("$"); // false
    ```

5. **RegExp 编译和执行测试 (基于 MacroAssembler):**
    *   测试使用 `RegExp::CompileForTesting` 函数编译正则表达式，并使用 `NativeRegExpMacroAssembler` 执行编译后的代码。
    *   这些测试更底层，涉及到 V8 内部的正则表达式引擎的实现细节。
    *   测试了在拉丁字符 (LATIN1) 和 Unicode 字符 (UC16) 上的匹配。
    *   `MacroAssemblerNativeSuccess` 测试了一个总是成功的简单正则表达式。
    *   `MacroAssemblerNativeSimple` 和 `MacroAssemblerNativeSimpleUC16` 测试了更复杂的匹配逻辑，并检查捕获组的结果。

    **JavaScript 示例 (与编译和执行相关):**
    这些测试模拟了 V8 内部执行 JavaScript 正则表达式的过程。当你在 JavaScript 中使用正则表达式进行匹配时，V8 内部会经历解析、编译和执行的阶段。

6. **调试专用语法测试 (带有 `#ifdef DEBUG`):**
    *   包含一些仅在 V8 的调试版本中启用的正则表达式语法测试，例如占有量词 (`*+`, `++`, `?+`, `{n,m}+`)。

    **JavaScript 示例:**
    在标准 JavaScript 中，没有占有量词的概念。这是 V8 内部为了更精细地控制匹配行为而引入的特性，通常不会暴露给最终用户。

**如果 `v8/test/unittests/regexp/regexp-unittest.cc` 以 `.tq` 结尾:**

根据您提供的信息，该文件以 `.cc` 结尾，因此它是一个 C++ 源代码文件，而不是 Torque 源代码文件。 Torque 文件通常用于定义 V8 的内置函数和对象。

**用户常见的编程错误示例:**

*   **忘记转义特殊字符:**
    ```javascript
    let str = "a.b";
    let regex = new RegExp("a.b"); // 错误：. 在正则表达式中是特殊字符，匹配任意字符
    console.log(regex.test(str)); // 输出 true，不是期望的结果

    let correctRegex = new RegExp("a\\.b"); // 正确：转义了 .
    console.log(correctRegex.test(str)); // 输出 true，期望的结果
    ```
*   **字符类中 `-` 的使用不当:**
    ```javascript
    let regex1 = /[a-z]/; // 匹配 a 到 z 之间的任意字符
    let regex2 = /[-az]/; // 匹配 -, a 或 z
    let regex3 = /[az-]/; // 匹配 a, z 或 -
    let regex4 = /[a\-z]/; // 匹配 a 到 z 之间的任意字符 (转义了 -)
    ```
*   **对反向引用的理解错误:**
    ```javascript
    let regex = /(\w+),\s+\1/; // 匹配形如 "word, word" 的字符串
    console.log(regex.test("hello, hello")); // true
    console.log(regex.test("hello, world")); // false
    ```
*   **量词的贪婪与非贪婪匹配理解不足:**
    ```javascript
    let str = "aaa";
    let greedyRegex = /a+/; // 贪婪匹配，匹配尽可能多的 "a"
    console.log(str.match(greedyRegex)[0]); // 输出 "aaa"

    let lazyRegex = /a+?/; // 非贪婪匹配，匹配尽可能少的 "a"
    console.log(str.match(lazyRegex)[0]); // 输出 "a"
    ```

**这是第1部分，共3部分，请归纳一下它的功能:**

总的来说，`v8/test/unittests/regexp/regexp-unittest.cc` 的主要功能是 **测试 V8 的正则表达式引擎的各个方面，包括正则表达式的解析、错误处理、字符类转义以及基于 MacroAssembler 的编译和执行**。它通过大量的单元测试用例来确保 V8 的正则表达式功能按照预期工作，并且能够正确处理各种合法的和非法的正则表达式语法。

Prompt: 
```
这是目录为v8/test/unittests/regexp/regexp-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/regexp/regexp-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
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

TEST_F(R
"""


```