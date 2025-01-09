Response:
Let's break down the thought process for analyzing the `v8/src/torque/utils.cc` file.

**1. Initial Understanding of the Request:**

The request asks for a functional breakdown of the C++ code, with specific connections to Torque, JavaScript, and potential programming errors. The ".tq" hint immediately signals Torque's involvement.

**2. High-Level Overview by Reading Comments and Includes:**

* **Copyright:**  Confirms it's V8 project code.
* **Includes:** These are crucial. They tell us what external functionalities this file relies on:
    * `<algorithm>`, `<fstream>`, `<iostream>`, etc.: Standard C++ utilities for string manipulation, file I/O, etc.
    * `"src/base/bits.h"`, `"src/base/logging.h"`: V8 base utilities, suggesting lower-level operations.
    * `"src/torque/ast.h"`, `"src/torque/constants.h"`, `"src/torque/declarable.h"`:  Explicitly links this to the Torque compiler. These headers deal with the Abstract Syntax Tree (AST) of Torque code, constants, and declared entities.
* **`EXPORT_CONTEXTUAL_VARIABLE`:**  Indicates a globally accessible variable related to Torque messages.
* **Namespace `v8::internal::torque`:**  Clearly places this code within the Torque component of V8.

**3. Function-by-Function Analysis and Categorization:**

Now, go through each function and try to understand its purpose.

* **String Literal Manipulation (`StringLiteralUnquote`, `StringLiteralQuote`):**  These are straightforward. They deal with adding and removing quotes and handling escape sequences in strings. Relate this to how strings are represented in programming languages, including JavaScript. *Initial thought: This is likely for parsing and generating Torque code.*

* **File URI Decoding (`FileUriDecode`):**  Recognize the standard "file://" URI format. The code handles decoding percent-encoded characters. *Initial thought: Torque might load files, and this is for handling file paths.*

* **Message Handling (`MessageBuilder`, `TorqueMessages`):**  This section deals with reporting errors and informational messages during Torque compilation. The `SpecializationRequester` logic suggests tracking the origin of complex type specializations. *Initial thought: This is crucial for providing helpful error messages to Torque developers.*

* **Naming Conventions (`ContainsUnderscore`, `ContainsUpperCase`, `IsKeywordLikeName`, `IsMachineType`, `IsLowerCamelCase`, `IsUpperCamelCase`, `IsSnakeCase`, `IsValidNamespaceConstName`, `IsValidTypeName`):** A significant portion of the code is dedicated to validating naming conventions. *Initial thought: Torque has strict style guidelines. This is likely enforced during compilation.*  Consider JavaScript naming conventions for comparison.

* **String Case Conversion (`CapifyStringWithUnderscores`, `CamelifyString`, `SnakeifyString`, `DashifyString`):** These are utilities for converting between different naming conventions (CamelCase, snake_case, etc.). *Initial thought:  This likely assists with code generation, where different parts of the V8 codebase might use different naming styles.*

* **Path Manipulation (`UnderlinifyPath`):**  Converts path strings into a specific format. *Initial thought: Perhaps for generating unique identifiers based on file paths.*

* **Other Utilities (`StartsWithSingleUnderscore`, `ReplaceFileContentsIfDifferent`):**  These seem like minor helpers for specific tasks.

* **Scope Management (`IfDefScope`, `NamespaceScope`, `IncludeGuardScope`, `IncludeObjectMacrosScope`):** These are RAII (Resource Acquisition Is Initialization) wrappers for managing preprocessor directives, namespaces, and include guards. *Initial thought:  Used to structure the generated C++ code.*

* **Residue Class:**  This looks more complex, dealing with modular arithmetic. *Initial thought: Might be related to memory alignment or layout optimizations during Torque compilation.*

**4. Connecting to Torque and JavaScript:**

* **Torque Link:**  The presence of `ast.h`, `constants.h`, and `declarable.h` strongly confirms that this file is part of the Torque compiler. The naming convention checks likely enforce Torque's style. The message handling is directly related to reporting errors in Torque code.

* **JavaScript Link:** The string literal functions relate to how JavaScript strings are parsed. The naming conventions, while stricter in Torque, have similarities to common JavaScript conventions. The concept of types and constants exists in both.

**5. Identifying Potential Programming Errors:**

Focus on the functions that manipulate strings and file paths, as these are common sources of errors. Think about what could go wrong with unquoting, quoting, URI decoding, and file I/O.

**6. Structuring the Answer:**

Organize the findings into clear sections as requested:

* **File Purpose:** Summarize the overall function.
* **Torque Connection:** Emphasize the direct involvement with the Torque compiler.
* **JavaScript Relationship:** Highlight similarities in string handling, naming, and the concept of types.
* **Code Logic Reasoning (with examples):** Provide concrete examples for string manipulation and URI decoding.
* **Common Programming Errors:** Give specific examples related to the functions' actions.

**7. Refinement and Review:**

Read through the generated answer. Ensure it's clear, concise, and addresses all aspects of the original request. Check for any inconsistencies or areas that need further clarification. For example, ensure the JavaScript examples accurately reflect the C++ function's behavior in a JavaScript context (even if it's conceptual).

This structured approach allows for a comprehensive understanding of the code and its role within the larger V8 and Torque projects. The iterative nature of analyzing each function and then connecting them to the broader context is key.
这个 `v8/src/torque/utils.cc` 文件是 V8 引擎中 Torque 编译器的实用工具代码。Torque 是一种用于生成高效 V8 代码的领域特定语言。

**主要功能列举：**

1. **字符串字面量处理:**
   - `StringLiteralUnquote(const std::string& s)`:  去除字符串字面量（用双引号或单引号括起来的字符串）的引号，并处理转义字符（如 `\n`, `\t`, `\"`, `\\` 等）。
   - `StringLiteralQuote(const std::string& s)`:  将字符串用双引号括起来，并在必要时添加转义字符。

2. **文件 URI 解码:**
   - `FileUriDecode(const std::string& uri)`:  解码以 `file://` 开头的 URI，将百分号编码的字符转换回原始字符。

3. **消息构建和报告:**
   - `MessageBuilder`:  用于构建和报告 Torque 编译过程中的消息（包括错误、警告等）。它会记录消息的位置信息，并可以追踪由于泛型特化引起的消息链。
   - `Report()`:  将构建的消息添加到全局的消息列表中。
   - `Throw()`:  抛出一个异常，中断 Torque 编译。

4. **命名约定检查:**
   - `ContainsUnderscore(const std::string& s)`:  检查字符串是否包含下划线。
   - `ContainsUpperCase(const std::string& s)`:  检查字符串是否包含大写字母。
   - `IsKeywordLikeName(const std::string& s)`:  检查字符串是否是类似关键字的常量名（如 "True", "False" 等）。
   - `IsMachineType(const std::string& s)`:  检查字符串是否是机器类型名称（如 "int32", "float64" 等）。
   - `IsLowerCamelCase(const std::string& s)`:  检查字符串是否符合小驼峰命名法。
   - `IsUpperCamelCase(const std::string& s)`:  检查字符串是否符合大驼峰命名法。
   - `IsSnakeCase(const std::string& s)`:  检查字符串是否符合蛇形命名法。
   - `IsValidNamespaceConstName(const std::string& s)`:  检查字符串是否是有效的命名空间常量名。
   - `IsValidTypeName(const std::string& s)`:  检查字符串是否是有效的类型名。

5. **字符串转换:**
   - `CapifyStringWithUnderscores(const std::string& camellified_string)`:  将驼峰命名的字符串转换为带下划线的大写字符串。
   - `CamelifyString(const std::string& underscore_string)`:  将带下划线的字符串转换为驼峰命名。
   - `SnakeifyString(const std::string& camel_string)`:  将驼峰命名的字符串转换为蛇形命名。
   - `DashifyString(const std::string& underscore_string)`:  将带下划线的字符串中的下划线替换为短横线。
   - `UnderlinifyPath(std::string path)`:  将路径字符串中的 `-`, `/`, `\` 和 `.` 替换为 `_` 并转换为大写。

6. **其他实用工具:**
   - `StartsWithSingleUnderscore(const std::string& str)`:  检查字符串是否以单个下划线开头。
   - `ReplaceFileContentsIfDifferent(const std::string& file_path, const std::string& contents)`:  如果文件内容与给定的内容不同，则替换文件的内容。
   - `IfDefScope`:  用于在代码中添加 `#ifdef` 和 `#endif` 块的 RAII 封装。
   - `NamespaceScope`:  用于在代码中添加 `namespace` 块的 RAII 封装。
   - `IncludeGuardScope`:  用于在头文件中添加 include guard 的 RAII 封装。
   - `IncludeObjectMacrosScope`:  用于包含和取消包含对象宏的 RAII 封装。
   - `ResidueClass`:  表示一个模运算后的剩余类，用于类型系统的对齐计算。

**关于 `.tq` 结尾的文件：**

如果 `v8/src/torque/utils.cc` 以 `.tq` 结尾，那么它确实是 **v8 Torque 源代码**。 `.cc` 后缀表示 C++ 源文件，而 `.tq` 后缀则明确表明这是 Torque 语言编写的源代码。 Torque 编译器会将 `.tq` 文件编译成 C++ 代码，然后与 V8 的其余部分一起编译。

**与 JavaScript 功能的关系 (以及 JavaScript 示例)：**

虽然这个 `utils.cc` 文件本身是用 C++ 编写的，并且是 Torque 编译器的组成部分，但它的某些功能与 JavaScript 的特性和编译过程息息相关：

1. **字符串字面量处理:** JavaScript 也需要处理字符串字面量及其转义字符。

   ```javascript
   // JavaScript 字符串字面量
   const str1 = "Hello, world!";
   const str2 = 'This is also a string.';
   const str3 = "This string has a newline: \nAnd a tab: \t";
   const str4 = 'This string has a single quote: \' and a backslash: \\';

   // 相当于 StringLiteralUnquote 的概念
   function unescapeString(str) {
     return str.replace(/\\([nrt'"]|\\)/g, function(match, p1) {
       switch (p1) {
         case 'n': return '\n';
         case 'r': return '\r';
         case 't': return '\t';
         case "'": return "'";
         case '"': return '"';
         case '\\': return '\\';
         default: return match; // 不应该发生
       }
     });
   }

   console.log(unescapeString('"Hello\\nWorld!"')); // 输出: Hello
                                                 //       World!

   // 相当于 StringLiteralQuote 的概念
   function escapeString(str) {
     return '"' + str.replace(/["\\\n\r\t]/g, function(match) {
       switch (match) {
         case '"': return '\\"';
         case '\\': return '\\\\';
         case '\n': return '\\n';
         case '\r': return '\\r';
         case '\t': return '\\t';
         default: return match;
       }
     }) + '"';
   }

   console.log(escapeString("Hello\nWorld!")); // 输出: "Hello\nWorld!"
   ```

2. **命名约定:** 虽然 JavaScript 的命名约定相对宽松，但 V8 内部的 C++ 代码（包括 Torque 生成的代码）通常遵循更严格的约定，例如驼峰命名法。 Torque 编译器的这些工具函数用于强制执行这些约定。

3. **类型系统:**  `IsValidTypeName` 和 `IsMachineType` 等函数与 Torque 的类型系统有关，而 Torque 的类型系统最终会映射到 JavaScript 的类型概念（尽管 JavaScript 是动态类型的）。

**代码逻辑推理 (假设输入与输出)：**

**例子 1: `StringLiteralUnquote`**

* **假设输入:** `s = "\"Hello\\nWorld!\""`
* **输出:** `"Hello\nWorld!"` (包含实际的换行符)

**例子 2: `FileUriDecode`**

* **假设输入:** `uri = "file:///path/to/%20file.txt"`
* **输出:** `"/path/to/ file.txt"` (空格被解码)

* **假设输入:** `uri = "file:///path/to/file.txt"`
* **输出:** `"/path/to/file.txt"` (没有需要解码的字符)

* **假设输入:** `uri = "https://example.com/file.txt"`
* **输出:** `std::nullopt` (不是 "file://" 开头的 URI)

**例子 3: `CapifyStringWithUnderscores`**

* **假设输入:** `camellified_string = "myAwesomeFunction"`
* **输出:** `"MY_AWESOME_FUNCTION"`

* **假设输入:** `camellified_string = "JSTypedArray"`
* **输出:** `"JS_TYPED_ARRAY"`

**涉及用户常见的编程错误 (与 JavaScript 的关联)：**

1. **字符串字面量转义错误:** 用户在编写 JavaScript 或 Torque 代码时，可能会忘记或错误地使用转义字符。

   ```javascript
   // 常见的错误：忘记转义反斜杠
   const filePath = "C:\path\to\file.txt"; // 错误：\p, \t, \f 被解释为转义序列

   // 正确的做法
   const filePath = "C:\\path\\to\\file.txt";
   ```

   Torque 的 `StringLiteralUnquote` 可以帮助处理这些转义，但如果 Torque 代码本身包含错误的转义，可能会导致编译错误或运行时问题。

2. **URI 编码/解码错误:** 在 Web 开发中，处理 URL 时需要正确地进行编码和解码。忘记解码 URI 中的特殊字符可能导致路径错误。虽然 `FileUriDecode` 针对的是本地文件 URI，但 URI 编码/解码的概念在 Web 开发中很常见。

   ```javascript
   // JavaScript 中使用 encodeURIComponent 和 decodeURIComponent
   const fileName = "my file.txt";
   const encodedFileName = encodeURIComponent(fileName);
   console.log(encodedFileName); // 输出: my%20file.txt

   const decodedFileName = decodeURIComponent(encodedFileName);
   console.log(decodedFileName); // 输出: my file.txt
   ```

3. **命名约定不一致:** 虽然 JavaScript 允许更灵活的命名，但在大型项目或团队合作中，保持一致的命名约定非常重要。 Torque 编译器的命名约定检查可以帮助开发者遵循 V8 内部的编码规范。用户在编写 Torque 代码时，如果命名不符合规范，编译器会报错。

总而言之，`v8/src/torque/utils.cc` 是 Torque 编译器的重要组成部分，提供了一系列用于字符串处理、消息报告、命名约定检查和代码生成的实用工具函数。虽然是用 C++ 编写的，但它的功能与 JavaScript 的特性和开发实践有着密切的联系。

Prompt: 
```
这是目录为v8/src/torque/utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/torque/utils.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>

#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/torque/ast.h"
#include "src/torque/constants.h"
#include "src/torque/declarable.h"

EXPORT_CONTEXTUAL_VARIABLE(v8::internal::torque::TorqueMessages)

namespace v8::internal::torque {

std::string StringLiteralUnquote(const std::string& s) {
  DCHECK(('"' == s.front() && '"' == s.back()) ||
         ('\'' == s.front() && '\'' == s.back()));
  std::stringstream result;
  for (size_t i = 1; i < s.length() - 1; ++i) {
    if (s[i] == '\\') {
      switch (s[++i]) {
        case 'n':
          result << '\n';
          break;
        case 'r':
          result << '\r';
          break;
        case 't':
          result << '\t';
          break;
        case '\'':
        case '"':
        case '\\':
          result << s[i];
          break;
        default:
          UNREACHABLE();
      }
    } else {
      result << s[i];
    }
  }
  return result.str();
}

std::string StringLiteralQuote(const std::string& s) {
  std::stringstream result;
  result << '"';
  for (size_t i = 0; i < s.length(); ++i) {
    switch (s[i]) {
      case '\n':
        result << "\\n";
        break;
      case '\r':
        result << "\\r";
        break;
      case '\t':
        result << "\\t";
        break;
      case '"':
      case '\\':
        result << "\\" << s[i];
        break;
      default:
        result << s[i];
    }
  }
  result << '"';
  return result.str();
}

#ifdef V8_OS_WIN
static const char kFileUriPrefix[] = "file:///";
#else
static const char kFileUriPrefix[] = "file://";
#endif
static const int kFileUriPrefixLength = sizeof(kFileUriPrefix) - 1;

static int HexCharToInt(unsigned char c) {
  if (isdigit(c)) return c - '0';
  if (isupper(c)) return c - 'A' + 10;
  DCHECK(islower(c));
  return c - 'a' + 10;
}

std::optional<std::string> FileUriDecode(const std::string& uri) {
  // Abort decoding of URIs that don't start with "file://".
  if (uri.rfind(kFileUriPrefix) != 0) return std::nullopt;

  const std::string path = uri.substr(kFileUriPrefixLength);
  std::ostringstream decoded;

  for (auto iter = path.begin(), end = path.end(); iter != end; ++iter) {
    std::string::value_type c = (*iter);

    // Normal characters are appended.
    if (c != '%') {
      decoded << c;
      continue;
    }

    // If '%' is not followed by at least two hex digits, we abort.
    if (std::distance(iter, end) <= 2) return std::nullopt;

    unsigned char first = (*++iter);
    unsigned char second = (*++iter);
    if (!isxdigit(first) || !isxdigit(second)) return std::nullopt;

    // An escaped hex value needs converting.
    unsigned char value = HexCharToInt(first) * 16 + HexCharToInt(second);
    decoded << value;
  }

  return decoded.str();
}

MessageBuilder::MessageBuilder(const std::string& message,
                               TorqueMessage::Kind kind) {
  std::optional<SourcePosition> position;
  if (CurrentSourcePosition::HasScope()) {
    position = CurrentSourcePosition::Get();
  }
  message_ = TorqueMessage{message, position, kind};
  if (CurrentScope::HasScope()) {
    // Traverse the parent scopes to find one that was created to represent a
    // specialization of something generic. If we find one, then log it and
    // continue walking the scope tree of the code that requested that
    // specialization. This allows us to collect the stack of locations that
    // caused a specialization.
    Scope* scope = CurrentScope::Get();
    while (scope) {
      SpecializationRequester requester = scope->GetSpecializationRequester();
      if (!requester.IsNone()) {
        extra_messages_.push_back(
            {"Note: in specialization " + requester.name + " requested here",
             requester.position, kind});
        scope = requester.scope;
      } else {
        scope = scope->ParentScope();
      }
    }
  }
}

void MessageBuilder::Report() const {
  TorqueMessages::Get().push_back(message_);
  for (const auto& message : extra_messages_) {
    TorqueMessages::Get().push_back(message);
  }
}

[[noreturn]] void MessageBuilder::Throw() const {
  throw TorqueAbortCompilation{};
}

namespace {

bool ContainsUnderscore(const std::string& s) {
  if (s.empty()) return false;
  return s.find("_") != std::string::npos;
}

bool ContainsUpperCase(const std::string& s) {
  if (s.empty()) return false;
  return std::any_of(s.begin(), s.end(), [](char c) { return isupper(c); });
}

// Torque has some namespace constants that are used like language level
// keywords, e.g.: 'True', 'Undefined', etc.
// These do not need to follow the default naming convention for constants.
bool IsKeywordLikeName(const std::string& s) {
  static const char* const keyword_like_constants[]{
      "True", "False", "TheHole", "PromiseHole", "Null", "Undefined"};

  return std::find(std::begin(keyword_like_constants),
                   std::end(keyword_like_constants),
                   s) != std::end(keyword_like_constants);
}

// Untagged/MachineTypes like 'int32', 'intptr' etc. follow a 'all-lowercase'
// naming convention and are those exempt from the normal type convention.
bool IsMachineType(const std::string& s) {
  static const char* const machine_types[]{VOID_TYPE_STRING,
                                           NEVER_TYPE_STRING,
                                           INT8_TYPE_STRING,
                                           UINT8_TYPE_STRING,
                                           INT16_TYPE_STRING,
                                           UINT16_TYPE_STRING,
                                           INT31_TYPE_STRING,
                                           UINT31_TYPE_STRING,
                                           INT32_TYPE_STRING,
                                           UINT32_TYPE_STRING,
                                           INT64_TYPE_STRING,
                                           UINT64_TYPE_STRING,
                                           INTPTR_TYPE_STRING,
                                           UINTPTR_TYPE_STRING,
                                           FLOAT16_RAW_BITS_TYPE_STRING,
                                           FLOAT32_TYPE_STRING,
                                           FLOAT64_TYPE_STRING,
                                           FLOAT64_OR_HOLE_TYPE_STRING,
                                           BOOL_TYPE_STRING,
                                           "string",
                                           BINT_TYPE_STRING,
                                           CHAR8_TYPE_STRING,
                                           CHAR16_TYPE_STRING};
  return std::find(std::begin(machine_types), std::end(machine_types), s) !=
         std::end(machine_types);
}

}  // namespace

bool IsLowerCamelCase(const std::string& s) {
  if (s.empty()) return false;
  size_t start = 0;
  if (s[0] == '_') start = 1;
  return islower(s[start]) && !ContainsUnderscore(s.substr(start));
}

bool IsUpperCamelCase(const std::string& s) {
  if (s.empty()) return false;
  size_t start = 0;
  if (s[0] == '_') start = 1;
  return isupper(s[start]);
}

bool IsSnakeCase(const std::string& s) {
  if (s.empty()) return false;
  return !ContainsUpperCase(s);
}

bool IsValidNamespaceConstName(const std::string& s) {
  if (s.empty()) return false;
  if (IsKeywordLikeName(s)) return true;

  return s[0] == 'k' && IsUpperCamelCase(s.substr(1));
}

bool IsValidTypeName(const std::string& s) {
  if (s.empty()) return false;
  if (IsMachineType(s)) return true;

  return IsUpperCamelCase(s);
}

std::string CapifyStringWithUnderscores(const std::string& camellified_string) {
  // Special case: JSAbc yields JS_ABC, not JSABC, for any Abc.
  size_t js_position = camellified_string.find("JS");

  std::string result;
  bool previousWasLowerOrDigit = false;
  for (size_t index = 0; index < camellified_string.size(); ++index) {
    char current = camellified_string[index];
    if ((previousWasLowerOrDigit && isupper(current)) ||
        (js_position != std::string::npos &&
         index == js_position + strlen("JS"))) {
      result += "_";
    }
    if (current == '.' || current == '-') {
      result += "_";
      previousWasLowerOrDigit = false;
      continue;
    }
    result += toupper(current);
    previousWasLowerOrDigit = islower(current) || isdigit(current);
  }
  return result;
}

std::string CamelifyString(const std::string& underscore_string) {
  std::string result;
  bool word_beginning = true;
  for (auto current : underscore_string) {
    if (current == '_' || current == '-') {
      word_beginning = true;
      continue;
    }
    if (word_beginning) {
      current = toupper(current);
    }
    result += current;
    word_beginning = false;
  }
  return result;
}

std::string SnakeifyString(const std::string& camel_string) {
  std::string result;
  bool previousWasLower = false;
  for (auto current : camel_string) {
    if (previousWasLower && isupper(current)) {
      result += "_";
    }
    result += tolower(current);
    previousWasLower = (islower(current));
  }
  return result;
}

std::string DashifyString(const std::string& underscore_string) {
  std::string result = underscore_string;
  std::replace(result.begin(), result.end(), '_', '-');
  return result;
}

std::string UnderlinifyPath(std::string path) {
  std::replace(path.begin(), path.end(), '-', '_');
  std::replace(path.begin(), path.end(), '/', '_');
  std::replace(path.begin(), path.end(), '\\', '_');
  std::replace(path.begin(), path.end(), '.', '_');
  transform(path.begin(), path.end(), path.begin(), ::toupper);
  return path;
}

bool StartsWithSingleUnderscore(const std::string& str) {
  return str.length() >= 2 && str[0] == '_' && str[1] != '_';
}

void ReplaceFileContentsIfDifferent(const std::string& file_path,
                                    const std::string& contents) {
  std::ifstream old_contents_stream(file_path.c_str());
  std::string old_contents;
  bool file_exists = false;
  if (old_contents_stream.good()) {
    file_exists = true;
    std::istreambuf_iterator<char> eos;
    old_contents =
        std::string(std::istreambuf_iterator<char>(old_contents_stream), eos);
    old_contents_stream.close();
  }
  if (!file_exists || old_contents != contents) {
    std::ofstream new_contents_stream;
    new_contents_stream.open(file_path.c_str());
    new_contents_stream << contents;
    new_contents_stream.close();
  }
}

IfDefScope::IfDefScope(std::ostream& os, std::string d)
    : os_(os), d_(std::move(d)) {
  os_ << "#ifdef " << d_ << "\n";
}
IfDefScope::~IfDefScope() { os_ << "#endif  // " << d_ << "\n"; }

NamespaceScope::NamespaceScope(std::ostream& os,
                               std::initializer_list<std::string> namespaces)
    : os_(os), d_(std::move(namespaces)) {
  for (const std::string& s : d_) {
    os_ << "namespace " << s << " {\n";
  }
}
NamespaceScope::~NamespaceScope() {
  for (auto i = d_.rbegin(); i != d_.rend(); ++i) {
    os_ << "}  // namespace " << *i << "\n";
  }
}

IncludeGuardScope::IncludeGuardScope(std::ostream& os, std::string file_name)
    : os_(os),
      d_("V8_GEN_TORQUE_GENERATED_" + CapifyStringWithUnderscores(file_name) +
         "_") {
  os_ << "#ifndef " << d_ << "\n";
  os_ << "#define " << d_ << "\n\n";
}
IncludeGuardScope::~IncludeGuardScope() { os_ << "#endif  // " << d_ << "\n"; }

IncludeObjectMacrosScope::IncludeObjectMacrosScope(std::ostream& os) : os_(os) {
  os_ << "\n// Has to be the last include (doesn't have include guards):\n"
         "#include \"src/objects/object-macros.h\"\n";
}
IncludeObjectMacrosScope::~IncludeObjectMacrosScope() {
  os_ << "\n#include \"src/objects/object-macros-undef.h\"\n";
}

size_t ResidueClass::AlignmentLog2() const {
  if (value_ == 0) return modulus_log_2_;
  return base::bits::CountTrailingZeros(value_);
}

const size_t ResidueClass::kMaxModulusLog2;

std::ostream& operator<<(std::ostream& os, const ResidueClass& a) {
  if (a.SingleValue().has_value()) return os << *a.SingleValue();
  return os << "[" << a.value_ << " mod 2^" << a.modulus_log_2_ << "]";
}

}  // namespace v8::internal::torque

"""

```