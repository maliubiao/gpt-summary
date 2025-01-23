Response:
Let's break down the thought process for analyzing the `v8/src/torque/utils.h` file.

**1. Initial Understanding of Header Files:**

The first thing to recognize is that this is a C++ header file (`.h`). Header files primarily declare interfaces (classes, functions, constants, etc.) that can be used by other C++ source files. They don't typically contain the *implementation* of most functions (with the exception of inline functions and templates).

**2. Identifying the Purpose:**

The filename `utils.h` strongly suggests that this file contains utility functions and data structures. The directory `torque` further narrows it down – these utilities are likely related to the Torque compiler within V8.

**3. High-Level Functionality Scan:**

Quickly scan through the code, looking for keywords, class names, and function names that give clues about the functionality. Keywords like `std::string`, `std::optional`, `std::vector`, `std::unordered_set`, `template`, `class`, `struct`, etc., provide insights into the types of data being handled.

**4. Categorization of Functionality:**

As you scan, start grouping related functions and structures together. This will help organize the analysis. For instance, you'll notice a cluster of functions dealing with string manipulation (`StringLiteralUnquote`, `StringLiteralQuote`, `CamelifyString`, etc.). Another group deals with error reporting (`TorqueMessage`, `MessageBuilder`, `Error`, `ReportError`). There's also something about a stack (`Stack`, `StackRange`, `BottomOffset`).

**5. Detailed Analysis of Key Components:**

Now, dive deeper into the more significant parts:

* **String Utilities:**  These are relatively straightforward. Functions for quoting/unquoting strings, decoding file URIs, and converting between different casing conventions (camelCase, snake_case). Think about *why* these would be needed in a compiler context. String manipulation is essential for processing code, file paths, and generating output.

* **Error Handling:** The `TorqueMessage` struct and `MessageBuilder` class clearly handle error and linting messages. The `DECLARE_CONTEXTUAL_VARIABLE` suggests these messages are stored in a context-specific way. The `Throw()` function and `TorqueAbortCompilation` structure point to how errors are propagated.

* **Name Validation:** Functions like `IsLowerCamelCase`, `IsValidTypeName`, etc., are likely used to enforce naming conventions in the Torque language or the generated C++ code.

* **Code Generation Helpers:** Functions like `ReplaceFileContentsIfDifferent`, `IfDefScope`, `NamespaceScope`, and `IncludeGuardScope` seem to assist in generating C++ code files. These are common patterns in code generators.

* **Deduplication:** The `Deduplicator` template is a standard technique for ensuring that only unique instances of objects are stored. This can optimize memory usage and potentially improve performance.

* **List Printing:** The `PrintList` family of templates provides a convenient way to format lists of items for output (e.g., debugging messages, generated code).

* **Stack Implementation:** The `Stack` class and related structures (`BottomOffset`, `StackRange`) represent a stack data structure. Consider where a stack might be used in a compiler – for managing local variables, intermediate results during code generation, etc.

* **ResidueClass:** This is a more specialized class for representing congruence classes. The comments explain its purpose related to offset and size validation for alignment constraints. This is a more advanced concept likely related to low-level memory layout.

* **Worklist:** This is a standard data structure used in graph algorithms and other situations where items need to be processed iteratively while ensuring each item is processed only once.

* **Templates:** Pay attention to the use of templates. They make the utility functions more general-purpose and reusable.

**6. Connecting to Javascript (where applicable):**

Think about how the utilities might relate to the functionality of Javascript. For example, string manipulation functions are used extensively in Javascript. Error reporting is also a core part of any language runtime. While the low-level details of memory management (like `ResidueClass`) are hidden from Javascript developers, the *results* of these operations (e.g., correct memory layout, preventing crashes) are crucial for Javascript's stability and performance.

**7. Code Logic and Examples:**

For functions where the logic is non-trivial (like the string case conversions or `ResidueClass` arithmetic), try to come up with simple input and output examples to illustrate their behavior.

**8. Common Programming Errors:**

Consider how the utilities might help prevent common programming errors in the context of Torque development or code generation. For instance, the naming validation functions can catch typos or violations of conventions. The error reporting mechanisms help pinpoint issues during compilation.

**9. Torque Context:**

Constantly keep in mind that this is part of the *Torque* compiler. The utilities are designed to facilitate the tasks involved in compiling Torque code into C++.

**Self-Correction/Refinement during the Process:**

* **Initial Overgeneralization:**  You might initially think a string utility function is just a generic string function. But then, realizing it's in the `torque` directory, you refine your understanding to its specific use within the compiler.
* **Focus on Declarations:** Remember that header files primarily *declare*. Don't get bogged down trying to figure out the exact implementation details of non-inline functions.
* **Leveraging Comments:**  Pay close attention to the comments in the code. They often provide valuable insights into the purpose and usage of different components.

By following these steps, combining a high-level overview with a detailed examination of key elements, and continually relating the code back to its context (the Torque compiler), you can effectively analyze and understand the functionality of a C++ header file like `v8/src/torque/utils.h`.
这个 `v8/src/torque/utils.h` 文件是 V8 JavaScript 引擎中 Torque 编译器的实用工具头文件。 Torque 是一种用于编写 V8 内部代码（如内置函数、运行时函数）的领域特定语言 (DSL)。

以下是该文件提供的各种功能的详细列表：

**1. 字符串处理:**

* **`StringLiteralUnquote(const std::string& s)`:**  移除字符串字面量周围的引号。例如，将 `"hello"` 转换为 `hello`。
* **`StringLiteralQuote(const std::string& s)`:**  将字符串用引号括起来，使其成为字符串字面量。例如，将 `hello` 转换为 `"hello"`。
* **`FileUriDecode(const std::string& s)`:**  将 "file://" URI 解码为标准的文件路径。
* **`CapifyStringWithUnderscores(const std::string& camellified_string)`:** 将驼峰命名的字符串转换为带下划线的字符串并首字母大写。例如，`myVariableName` 转换为 `My_Variable_Name`。
* **`CamelifyString(const std::string& underscore_string)`:** 将带下划线的字符串转换为驼峰命名。例如，`my_variable_name` 转换为 `myVariableName`。
* **`SnakeifyString(const std::string& camel_string)`:** 将驼峰命名的字符串转换为蛇形命名（小写，下划线分隔）。例如，`MyVariableName` 转换为 `my_variable_name`。
* **`DashifyString(const std::string& underscore_string)`:** 将带下划线的字符串转换为短横线分隔的字符串。例如，`my_variable_name` 转换为 `my-variable-name`。
* **`UnderlinifyPath(std::string path)`:** 将路径中的斜杠替换为下划线。
* **`StartsWithSingleUnderscore(const std::string& str)`:** 检查字符串是否以单个下划线开头。
* **`StringStartsWith(const std::string& s, const std::string& prefix)`:** 检查字符串是否以指定的前缀开头。
* **`StringEndsWith(const std::string& s, const std::string& suffix)`:** 检查字符串是否以指定的后缀结尾。

**与 Javascript 的关系和示例:**

这些字符串处理工具在 Torque 编译器中非常有用，因为 Torque 代码经常需要处理和生成字符串，例如：

* **生成 C++ 代码:** Torque 编译器将 Torque 代码转换为 C++ 代码，需要格式化字符串以生成正确的语法。
* **处理标识符和名称:**  JavaScript 中的变量名、函数名等需要在 Torque 中进行处理，可能需要进行格式转换以符合 C++ 的命名约定。

**Javascript 示例:**

```javascript
// 假设 Torque 代码中需要将 JavaScript 的变量名转换为 C++ 中的常量名（全部大写，下划线分隔）
const javascriptVariableName = "myAwesomeVariable";

// 在 Torque 编译器的实现中，可能会使用类似 CamelifyString 和 CapifyStringWithUnderscores 的函数
// 来进行转换（这里只是概念性的，实际 Torque 代码不会直接调用 JS）

// 1. 先将驼峰命名转换为下划线命名 (模拟 CamelifyString 的反向操作)
function unCamelify(str) {
  return str.replace(/([A-Z])/g, "_$1").toLowerCase();
}
const underscoredName = unCamelify(javascriptVariableName.charAt(0).toUpperCase() + javascriptVariableName.slice(1));
// "my_awesome_variable"

// 2. 将下划线命名转换为全部大写 (模拟 CapifyStringWithUnderscores)
function toUpperCaseWithUnderscores(str) {
  return str.toUpperCase();
}
const cppConstantName = toUpperCaseWithUnderscores(underscoredName);
// "MY_AWESOME_VARIABLE"

console.log(cppConstantName);
```

**2. 错误和消息处理:**

* **`TorqueMessage` 结构体:**  表示 Torque 编译器产生的消息，包括消息内容、可选的源代码位置和消息类型（错误或 lint）。
* **`DECLARE_CONTEXTUAL_VARIABLE(TorqueMessages, std::vector<TorqueMessage>)`:** 声明一个上下文相关的变量，用于存储编译期间产生的 `TorqueMessage` 列表。这意味着每个编译上下文都有自己独立的消息列表。
* **`MessageBuilder` 类:**  用于构建 `TorqueMessage` 对象，可以设置消息内容和位置。
* **`Throw()` 方法 (在 `MessageBuilder` 中):**  抛出一个异常，表明编译过程中发生了错误。
* **`Report()` 方法 (在 `MessageBuilder` 中):**  报告构建的 `TorqueMessage`，通常将其添加到上下文相关的消息列表中。
* **`TorqueAbortCompilation` 结构体:**  用作异常类型，用于中止 Torque 编译过程。
* **`Message(TorqueMessage::Kind kind, Args&&... args)`:**  创建一个 `MessageBuilder` 对象。
* **`Error(Args&&... args)`:**  创建一个表示错误的 `MessageBuilder` 对象。
* **`Lint(Args&&... args)`:**  创建一个表示 lint 警告的 `MessageBuilder` 对象。
* **`ReportError(Args&&... args)`:**  创建一个错误消息并立即抛出异常。

**与 Javascript 的关系和示例:**

当 Torque 编译器遇到语法错误、类型错误或其他问题时，它会使用这些机制来报告错误。这些错误最终会阻止 V8 编译 JavaScript 代码或生成有缺陷的机器代码。

**假设输入与输出（代码逻辑推理）：**

假设 Torque 代码中存在类型不匹配：

**假设输入 (Torque 代码片段):**

```torque
type A = int32;
type B = string;

var x: A = 10;
var y: B = x; // 类型不匹配，尝试将 int32 赋值给 string
```

**输出 (可能产生的 TorqueMessage):**

```
TorqueMessage {
  message: "Cannot assign value of type A to variable of type B",
  position: { file: "my_torque_file.tq", start: { line: 4, column: 10 }, end: { line: 4, column: 11 } }, // 假设错误发生在第 4 行，第 10 列
  kind: kError
}
```

**3. 命名约定检查:**

* **`IsLowerCamelCase(const std::string& s)`:** 检查字符串是否为小驼峰命名。
* **`IsUpperCamelCase(const std::string& s)`:** 检查字符串是否为大驼峰命名。
* **`IsSnakeCase(const std::string& s)`:** 检查字符串是否为蛇形命名。
* **`IsValidNamespaceConstName(const std::string& s)`:** 检查字符串是否为有效的命名空间常量名。
* **`IsValidTypeName(const std::string& s)`:** 检查字符串是否为有效的类型名。

**与 Javascript 的关系:**

虽然 JavaScript 的命名约定比较灵活，但 Torque 作为一种更底层的语言，对命名约定有更严格的要求，以确保生成的 C++ 代码符合 V8 的编码规范。

**用户常见的编程错误 (Torque 开发):**

使用不符合命名约定的标识符会导致 Torque 编译器报错。例如，尝试将一个变量命名为 `MyVariable` (大驼峰) 而期望它是小驼峰的。

**4. 文件内容替换:**

* **`ReplaceFileContentsIfDifferent(const std::string& file_path, const std::string& contents)`:** 仅当文件内容与给定的新内容不同时，才替换指定文件的内容。这可以避免不必要的写入操作。

**与 Javascript 的关系:**

在 Torque 编译过程中，可能需要生成或修改 C++ 代码文件。此函数用于确保只在必要时才进行文件写入，提高效率。

**5. 数据去重:**

* **`Deduplicator<class T>` 类:**  用于存储和管理一组唯一的对象。`Add()` 方法将对象添加到集合中，如果对象已存在，则返回现有对象的指针。

**与 Javascript 的关系:**

在 Torque 编译过程中，可能需要管理一组唯一的类型、函数或其他元素。`Deduplicator` 可以用来避免重复创建相同的对象，节省内存。

**6. 列表打印:**

* **`ListPrintAdaptor` 模板结构体:**  用于自定义列表的打印格式，可以指定分隔符和转换函数。
* **`PrintList` 函数模板:**  创建 `ListPrintAdaptor` 对象，方便地打印列表。
* **`PrintCommaSeparatedList` 函数模板:**  使用逗号作为分隔符打印列表。

**与 Javascript 的关系:**

在 Torque 编译器的调试输出或生成的代码中，可能需要以特定的格式打印列表。

**7. 栈数据结构:**

* **`BottomOffset` 结构体:**  表示栈中相对于栈底的偏移量。
* **`StackRange` 类:**  表示栈中的一个连续范围。
* **`Stack<class T>` 类:**  实现了一个通用的栈数据结构，提供了 `Push`、`Pop`、`Peek` 等操作。

**与 Javascript 的关系:**

在 Torque 编译器的内部实现中，可能需要使用栈来管理状态或临时数据。例如，在处理表达式或语句时。

**假设输入与输出（代码逻辑推理 - Stack）：**

假设我们有一个 `Stack<int>`：

**假设输入:**

```c++
Stack<int> myStack;
myStack.Push(1);
myStack.Push(2);
myStack.Push(3);
```

**输出 (调用 `Top()`):**

```
myStack.Top(); // 返回 3
```

**输出 (调用 `Pop()`):**

```c++
int poppedValue = myStack.Pop(); // poppedValue 为 3，myStack 变为 {1, 2}
```

**8. 其他实用工具:**

* **`CheckNotNull(T* x)`:** 检查指针是否为空，如果为空则触发断言。
* **`EraseIf(Container* container, F f)`:** 从容器中删除满足谓词 `f` 的元素。
* **`NullStreambuf` 和 `NullOStream` 类:**  用于创建一个丢弃所有输出的输出流。
* **`IfDefScope`、`NamespaceScope`、`IncludeGuardScope`、`IncludeObjectMacrosScope` 类:**  用于在生成 C++ 代码时管理 `#ifdef` 块、命名空间、头文件保护和对象宏。
* **`ResidueClass` 类:**  表示模 2 的幂的同余类，用于进行抽象解释，以验证对齐约束。
* **`Worklist<typename T>` 类:**  实现一个工作列表数据结构，用于存储待处理的元素并避免重复处理。
* **`TransformVector` 函数模板:**  对向量中的元素应用转换函数并返回新的向量。

**用户常见的编程错误 (Torque 开发):**

* **忘记添加头文件保护:**  可能导致重复定义错误。`IncludeGuardScope` 可以帮助避免这种情况。
* **在生成的代码中使用了错误的命名空间:**  `NamespaceScope` 可以确保生成的代码位于正确的命名空间中。

**总结:**

`v8/src/torque/utils.h` 提供了一组通用的实用工具，用于简化 Torque 编译器的开发，包括字符串处理、错误处理、命名约定检查、文件操作、数据结构和代码生成辅助功能。这些工具对于确保 Torque 编译器能够正确地将 Torque 代码转换为高效且符合 V8 规范的 C++ 代码至关重要。  虽然 JavaScript 开发者不会直接使用这些工具，但它们的存在和正确性直接影响着 V8 引擎的性能和稳定性，从而间接地影响 JavaScript 的执行效率。

### 提示词
```
这是目录为v8/src/torque/utils.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/utils.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TORQUE_UTILS_H_
#define V8_TORQUE_UTILS_H_

#include <algorithm>
#include <optional>
#include <ostream>
#include <queue>
#include <streambuf>
#include <string>
#include <unordered_set>

#include "src/base/contextual.h"
#include "src/base/functional.h"
#include "src/torque/source-positions.h"

namespace v8::internal::torque {

std::string StringLiteralUnquote(const std::string& s);
std::string StringLiteralQuote(const std::string& s);

// Decodes "file://" URIs into file paths which can then be used
// with the standard stream API.
V8_EXPORT_PRIVATE std::optional<std::string> FileUriDecode(
    const std::string& s);

struct TorqueMessage {
  enum class Kind { kError, kLint };

  std::string message;
  std::optional<SourcePosition> position;
  Kind kind;
};

DECLARE_CONTEXTUAL_VARIABLE(TorqueMessages, std::vector<TorqueMessage>);

template <class... Args>
std::string ToString(Args&&... args) {
  std::stringstream stream;
  USE((stream << std::forward<Args>(args))...);
  return stream.str();
}

class V8_EXPORT_PRIVATE MessageBuilder {
 public:
  MessageBuilder() = delete;
  MessageBuilder(const std::string& message, TorqueMessage::Kind kind);

  MessageBuilder& Position(SourcePosition position) {
    message_.position = position;
    return *this;
  }

  [[noreturn]] void Throw() const;

  ~MessageBuilder() {
    // This will also get called in case the error is thrown.
    Report();
  }

 private:
  void Report() const;

  TorqueMessage message_;
  std::vector<TorqueMessage> extra_messages_;
};

// Used for throwing exceptions. Retrieve TorqueMessage from the contextual
// for specific error information.
struct TorqueAbortCompilation {};

template <class... Args>
static MessageBuilder Message(TorqueMessage::Kind kind, Args&&... args) {
  return MessageBuilder(ToString(std::forward<Args>(args)...), kind);
}

template <class... Args>
MessageBuilder Error(Args&&... args) {
  return Message(TorqueMessage::Kind::kError, std::forward<Args>(args)...);
}
template <class... Args>
MessageBuilder Lint(Args&&... args) {
  return Message(TorqueMessage::Kind::kLint, std::forward<Args>(args)...);
}

bool IsLowerCamelCase(const std::string& s);
bool IsUpperCamelCase(const std::string& s);
bool IsSnakeCase(const std::string& s);
bool IsValidNamespaceConstName(const std::string& s);
bool IsValidTypeName(const std::string& s);

template <class... Args>
[[noreturn]] void ReportError(Args&&... args) {
  Error(std::forward<Args>(args)...).Throw();
}

std::string CapifyStringWithUnderscores(const std::string& camellified_string);
std::string CamelifyString(const std::string& underscore_string);
std::string SnakeifyString(const std::string& camel_string);
std::string DashifyString(const std::string& underscore_string);
std::string UnderlinifyPath(std::string path);

bool StartsWithSingleUnderscore(const std::string& str);

void ReplaceFileContentsIfDifferent(const std::string& file_path,
                                    const std::string& contents);

template <class T>
class Deduplicator {
 public:
  const T* Add(T x) { return &*(storage_.insert(std::move(x)).first); }

 private:
  std::unordered_set<T, base::hash<T>> storage_;
};

template <class T>
T& DereferenceIfPointer(T* x) {
  return *x;
}
template <class T>
T&& DereferenceIfPointer(T&& x) {
  return std::forward<T>(x);
}

template <class T, class L>
struct ListPrintAdaptor {
  const T& list;
  const std::string& separator;
  L transformer;

  friend std::ostream& operator<<(std::ostream& os, const ListPrintAdaptor& l) {
    bool first = true;
    for (auto& e : l.list) {
      if (first) {
        first = false;
      } else {
        os << l.separator;
      }
      os << DereferenceIfPointer(l.transformer(e));
    }
    return os;
  }
};

template <class T>
auto PrintList(const T& list, const std::string& separator = ", ") {
  using ElementType = decltype(*list.begin());
  auto id = [](ElementType el) { return el; };
  return ListPrintAdaptor<T, decltype(id)>{list, separator, id};
}

template <class T, class L>
auto PrintList(const T& list, const std::string& separator, L&& transformer) {
  return ListPrintAdaptor<T, L&&>{list, separator,
                                  std::forward<L>(transformer)};
}

template <class C, class T>
void PrintCommaSeparatedList(std::ostream& os, const T& list, C&& transform) {
  os << PrintList(list, ", ", std::forward<C>(transform));
}

template <class T>
void PrintCommaSeparatedList(std::ostream& os, const T& list) {
  os << PrintList(list, ", ");
}

struct BottomOffset {
  size_t offset;

  BottomOffset& operator=(std::size_t other_offset) {
    this->offset = other_offset;
    return *this;
  }
  BottomOffset& operator++() {
    ++offset;
    return *this;
  }
  BottomOffset operator+(size_t x) const { return BottomOffset{offset + x}; }
  BottomOffset operator-(size_t x) const {
    DCHECK_LE(x, offset);
    return BottomOffset{offset - x};
  }
  bool operator<(const BottomOffset& other) const {
    return offset < other.offset;
  }
  bool operator<=(const BottomOffset& other) const {
    return offset <= other.offset;
  }
  bool operator==(const BottomOffset& other) const {
    return offset == other.offset;
  }
  bool operator!=(const BottomOffset& other) const {
    return offset != other.offset;
  }
};

inline std::ostream& operator<<(std::ostream& out, BottomOffset from_bottom) {
  return out << "BottomOffset{" << from_bottom.offset << "}";
}

// An iterator-style range of stack slots.
class StackRange {
 public:
  StackRange(BottomOffset begin, BottomOffset end) : begin_(begin), end_(end) {
    DCHECK_LE(begin_, end_);
  }

  bool operator==(const StackRange& other) const {
    return begin_ == other.begin_ && end_ == other.end_;
  }

  void Extend(StackRange adjacent) {
    DCHECK_EQ(end_, adjacent.begin_);
    end_ = adjacent.end_;
  }

  size_t Size() const { return end_.offset - begin_.offset; }
  BottomOffset begin() const { return begin_; }
  BottomOffset end() const { return end_; }

 private:
  BottomOffset begin_;
  BottomOffset end_;
};

inline std::ostream& operator<<(std::ostream& out, StackRange range) {
  return out << "StackRange{" << range.begin() << ", " << range.end() << "}";
}

template <class T>
class Stack {
 public:
  using value_type = T;
  Stack() = default;
  Stack(std::initializer_list<T> initializer)
      : Stack(std::vector<T>(initializer)) {}
  explicit Stack(std::vector<T> v) : elements_(std::move(v)) {}
  size_t Size() const { return elements_.size(); }
  const T& Peek(BottomOffset from_bottom) const {
    return elements_.at(from_bottom.offset);
  }
  void Poke(BottomOffset from_bottom, T x) {
    elements_.at(from_bottom.offset) = std::move(x);
  }
  void Push(T x) {
    elements_.push_back(std::move(x));
  }
  StackRange TopRange(size_t slot_count) const {
    DCHECK_GE(Size(), slot_count);
    return StackRange{AboveTop() - slot_count, AboveTop()};
  }
  StackRange PushMany(const std::vector<T>& v) {
    for (const T& x : v) {
      Push(x);
    }
    return TopRange(v.size());
  }
  const T& Top() const { return Peek(AboveTop() - 1); }
  T Pop() {
    T result = std::move(elements_.back());
    elements_.pop_back();
    return result;
  }
  std::vector<T> PopMany(size_t count) {
    DCHECK_GE(elements_.size(), count);
    std::vector<T> result;
    result.reserve(count);
    for (auto it = elements_.end() - count; it != elements_.end(); ++it) {
      result.push_back(std::move(*it));
    }
    elements_.resize(elements_.size() - count);
    return result;
  }
  // The invalid offset above the top element. This is useful for StackRange.
  BottomOffset AboveTop() const { return BottomOffset{Size()}; }
  // Delete the slots in {range}, moving higher slots to fill the gap.
  void DeleteRange(StackRange range) {
    DCHECK_LE(range.end(), AboveTop());
    if (range.Size() == 0) return;
    for (BottomOffset i = range.end(); i < AboveTop(); ++i) {
      elements_[i.offset - range.Size()] = std::move(elements_[i.offset]);
    }
    elements_.resize(elements_.size() - range.Size());
  }

  bool operator==(const Stack& other) const {
    return elements_ == other.elements_;
  }
  bool operator!=(const Stack& other) const {
    return elements_ != other.elements_;
  }

  T* begin() { return elements_.data(); }
  T* end() { return begin() + elements_.size(); }
  const T* begin() const { return elements_.data(); }
  const T* end() const { return begin() + elements_.size(); }

 private:
  std::vector<T> elements_;
};

template <class T>
T* CheckNotNull(T* x) {
  CHECK_NOT_NULL(x);
  return x;
}

template <class T>
inline std::ostream& operator<<(std::ostream& os, const Stack<T>& t) {
  os << "Stack{";
  PrintCommaSeparatedList(os, t);
  os << "}";
  return os;
}

static const char* const kBaseNamespaceName = "base";
static const char* const kTestNamespaceName = "test";

// Erase elements of a container that has a constant-time erase function, like
// std::set or std::list. Calling this on std::vector would have quadratic
// complexity.
template <class Container, class F>
void EraseIf(Container* container, F f) {
  for (auto it = container->begin(); it != container->end();) {
    if (f(*it)) {
      it = container->erase(it);
    } else {
      ++it;
    }
  }
}

class NullStreambuf : public std::streambuf {
 public:
  int overflow(int c) override {
    setp(buffer_, buffer_ + sizeof(buffer_));
    return (c == traits_type::eof()) ? '\0' : c;
  }

 private:
  char buffer_[64];
};

class NullOStream : public std::ostream {
 public:
  NullOStream() : std::ostream(&buffer_) {}

 private:
  NullStreambuf buffer_;
};

inline bool StringStartsWith(const std::string& s, const std::string& prefix) {
  if (s.size() < prefix.size()) return false;
  return s.substr(0, prefix.size()) == prefix;
}
inline bool StringEndsWith(const std::string& s, const std::string& suffix) {
  if (s.size() < suffix.size()) return false;
  return s.substr(s.size() - suffix.size()) == suffix;
}

class V8_NODISCARD IfDefScope {
 public:
  IfDefScope(std::ostream& os, std::string d);
  ~IfDefScope();
  IfDefScope(const IfDefScope&) = delete;
  IfDefScope& operator=(const IfDefScope&) = delete;

 private:
  std::ostream& os_;
  std::string d_;
};

class V8_NODISCARD NamespaceScope {
 public:
  NamespaceScope(std::ostream& os,
                 std::initializer_list<std::string> namespaces);
  ~NamespaceScope();
  NamespaceScope(const NamespaceScope&) = delete;
  NamespaceScope& operator=(const NamespaceScope&) = delete;

 private:
  std::ostream& os_;
  std::vector<std::string> d_;
};

class V8_NODISCARD IncludeGuardScope {
 public:
  IncludeGuardScope(std::ostream& os, std::string file_name);
  ~IncludeGuardScope();
  IncludeGuardScope(const IncludeGuardScope&) = delete;
  IncludeGuardScope& operator=(const IncludeGuardScope&) = delete;

 private:
  std::ostream& os_;
  std::string d_;
};

class V8_NODISCARD IncludeObjectMacrosScope {
 public:
  explicit IncludeObjectMacrosScope(std::ostream& os);
  ~IncludeObjectMacrosScope();
  IncludeObjectMacrosScope(const IncludeObjectMacrosScope&) = delete;
  IncludeObjectMacrosScope& operator=(const IncludeObjectMacrosScope&) = delete;

 private:
  std::ostream& os_;
};

// A value of ResidueClass is a congruence class of integers modulo a power
// of 2.
// In contrast to common modulo arithmetic, we also allow addition and
// multiplication of congruence classes with different modulus. In this case, we
// do an abstract-interpretation style approximation to produce an as small as
// possible congruence class. ResidueClass is used to represent partial
// knowledge about offsets and sizes to validate alignment constraints.
// ResidueClass(x,m) = {y \in Z | x == y mod 2^m} = {x+k2^m | k \in Z} where Z
// is the set of all integers.
// Notation: 2^x is 2 to the power of x.
class ResidueClass {
 public:
  ResidueClass(size_t value, size_t modulus_log_2 =
                                 kMaxModulusLog2)  // NOLINT(runtime/explicit)
      : value_(value),
        modulus_log_2_(std::min(modulus_log_2, kMaxModulusLog2)) {
    if (modulus_log_2_ < kMaxModulusLog2) {
      value_ %= size_t{1} << modulus_log_2_;
    }
  }

  // 0 modulo 1, in other words, the class of all integers.
  static ResidueClass Unknown() { return ResidueClass{0, 0}; }

  // If the modulus corresponds to the size of size_t, it represents a concrete
  // value.
  std::optional<size_t> SingleValue() const {
    if (modulus_log_2_ == kMaxModulusLog2) return value_;
    return std::nullopt;
  }

  friend ResidueClass operator+(const ResidueClass& a, const ResidueClass& b) {
    return ResidueClass{a.value_ + b.value_,
                        std::min(a.modulus_log_2_, b.modulus_log_2_)};
  }

  // Reasoning for the choice of the new modulus:
  // {x+k2^a | k \in Z} * {y+l2^b | l \in Z}
  // = {xy + xl2^b + yk2^a + kl2^(a+b)| k,l \in Z},
  // which is a subset of {xy + k2^c | k \in Z}
  // if 2^c is a common divisor of x2^b, y2^a and hence also of 2^(a+b) since
  // x<2^a and y<2^b.
  // So we use the gcd of x2^b and y2^a as the new modulus.
  friend ResidueClass operator*(const ResidueClass& a, const ResidueClass& b) {
    return ResidueClass{a.value_ * b.value_,
                        std::min(a.modulus_log_2_ + b.AlignmentLog2(),
                                 b.modulus_log_2_ + a.AlignmentLog2())};
  }

  friend std::ostream& operator<<(std::ostream& os, const ResidueClass& a);

  ResidueClass& operator+=(const ResidueClass& other) {
    *this = *this + other;
    return *this;
  }

  ResidueClass& operator*=(const ResidueClass& other) {
    *this = *this * other;
    return *this;
  }

  // 2^AlignmentLog2() is the larget power of 2 that divides all elements of the
  // congruence class.
  size_t AlignmentLog2() const;
  size_t Alignment() const {
    DCHECK_LT(AlignmentLog2(), kMaxModulusLog2);
    return size_t{1} << AlignmentLog2();
  }

 private:
  // The value is the representative of the congruence class. It's always
  // smaller than 2^modulus_log_2_.
  size_t value_;
  // Base 2 logarithm of the modulus.
  size_t modulus_log_2_;

  // size_t values are modulo 2^kMaxModulusLog2, so we don't consider larger
  // modulus.
  static const size_t kMaxModulusLog2 = 8 * sizeof(size_t);
};

template <typename T>
class Worklist {
 public:
  bool IsEmpty() const {
    DCHECK_EQ(queue_.size(), contained_.size());
    return queue_.empty();
  }

  bool Enqueue(T value) {
    if (contained_.find(value) != contained_.end()) return false;
    queue_.push(value);
    contained_.insert(value);
    DCHECK_EQ(queue_.size(), contained_.size());
    return true;
  }

  T Dequeue() {
    DCHECK(!IsEmpty());
    T value = queue_.front();
    queue_.pop();
    contained_.erase(value);
    DCHECK_EQ(queue_.size(), contained_.size());
    return value;
  }

 private:
  std::queue<T> queue_;
  std::unordered_set<T> contained_;
};

template <class T, class U, class F>
std::vector<T> TransformVector(const std::vector<U>& v, F f) {
  std::vector<T> result;
  std::transform(v.begin(), v.end(), std::back_inserter(result), f);
  return result;
}
template <class T, class U>
std::vector<T> TransformVector(const std::vector<U>& v) {
  return TransformVector<T>(v, [](const U& x) -> T { return x; });
}

}  // namespace v8::internal::torque

#endif  // V8_TORQUE_UTILS_H_
```