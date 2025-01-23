Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Skim and Identification of Core Purpose:**  The file name "ast-source-ranges.h" immediately suggests a connection to Abstract Syntax Trees (ASTs) and the ranges of source code they represent. The copyright notice confirms it's part of the V8 project. A quick scan reveals structs and classes related to source code positions (start, end).

2. **Understanding `SourceRange`:** This is the foundational data structure.
    * `start` and `end`: Clearly represent the beginning and end of a source code segment. The comments clarify the 0-based and inclusive/exclusive nature.
    * `IsEmpty()`, `Empty()`, `OpenEnded()`, `ContinuationOf()`: These helper functions provide ways to create and manipulate `SourceRange` objects, handling special cases like empty ranges or ranges that extend from a previous one. This suggests a need to track contiguous source sections.
    * `kNoSourcePosition` and `kFunctionLiteralSourcePosition`: These constants hint at how V8 handles cases where a precise source position isn't available or for specific node types (function literals). The `static_assert` reinforces the relationship between these constants.
    * `FunctionLiteralMarkerRange()`: This method creates a special marker range for function literals, confirming the earlier deduction about special handling.

3. **Analyzing `AST_SOURCE_RANGE_LIST` Macro:**  This is a crucial element. The macro definition `#define AST_SOURCE_RANGE_LIST(V) ...` indicates a way to generate code for a list of AST node types. The `V(...)` calls within the macro suggest that this macro is used to define something for each of the listed node types. The comment "Note that this macro is not undefined at the end of this file" implies that its effect persists beyond the immediate context. Looking ahead, we'll see how it's used with `DEFINE_MAP_INSERT`.

4. **Exploring `SourceRangeKind` Enum:** This enum defines different *types* of source ranges associated with a given AST node (e.g., the body of a block, the `then` branch of an `if` statement). This indicates that a single AST node can have multiple associated source ranges for its different parts.

5. **Dissecting the `AstNodeSourceRanges` Class Hierarchy:** This is the core of the file's functionality.
    * **Base Class `AstNodeSourceRanges`:**  The virtual destructor and the pure virtual functions `GetRange()` and `HasRange()` establish this as an abstract base class. This signifies polymorphism and different ways of storing and accessing source ranges for different AST node types. `RemoveContinuationRange()` with `UNREACHABLE()` as the default suggests that not all node types have continuation ranges.
    * **Derived Classes (e.g., `BinaryOperationSourceRanges`, `BlockSourceRanges`):** Each derived class represents how source ranges are stored for a specific type of AST node. They override `GetRange()` and `HasRange()` to provide concrete implementations based on the structure of that node type. For instance, `BinaryOperationSourceRanges` stores the range of the right-hand operand. The constructors initialize the relevant source range members. Some classes inherit from others (like `BlockSourceRanges` inheriting from `ContinuationSourceRanges`), indicating shared characteristics.
    * **`ContinuationSourceRanges`:** This intermediate class seems to handle the concept of a "continuation" range, which is open-ended. The `RemoveContinuationRange()` method is implemented here, suggesting it's relevant for specific node types.

6. **Examining `SourceRangeMap`:** This class acts as a container to associate AST nodes with their corresponding `AstNodeSourceRanges` objects.
    * The `Find()` method allows retrieval of the source range information for a given node.
    * The `Insert()` method is the key to populating this map. The macro `DEFINE_MAP_INSERT` and its usage with `AST_SOURCE_RANGE_LIST` become clear here. For each node type listed in the macro, a specific `Insert` method is generated (e.g., `Insert(BinaryOperation* node, BinaryOperationSourceRanges* ranges)`). This ensures type safety during insertion.

7. **Connecting to JavaScript Functionality (and Potential Torque):** The question about JavaScript relevance comes in naturally after understanding the core functionality. ASTs are the intermediate representation of JavaScript code within V8. Therefore, this header file is directly related to how V8 tracks source code locations during parsing and compilation of JavaScript. The example demonstrates how different parts of a JavaScript statement (like the condition, `then`, and `else` blocks of an `if` statement) would have associated source ranges. The mention of ".tq" and Torque is a side note, as this particular file is a C++ header.

8. **Considering Code Logic and Examples:** The `ContinuationOf` function provides an opportunity to demonstrate a logic flow. By providing a starting `SourceRange`, we can show how a subsequent range is derived. The examples help solidify the understanding of how source ranges represent specific portions of code.

9. **Identifying Common Programming Errors:**  The concept of source ranges directly relates to debugging and error reporting. Providing an example of a syntax error and how these ranges would help locate the error is a relevant connection.

10. **Review and Refine:** After drafting the initial analysis, reviewing and refining the explanation for clarity and accuracy is crucial. Ensuring the connection to JavaScript is explicit and the purpose of each class is well-defined. The structure of the answer should follow the order of the file's content for logical flow.

This step-by-step approach, moving from the general purpose to specific details and then connecting back to the larger context (JavaScript, error handling), leads to a comprehensive understanding of the `ast-source-ranges.h` file.
这个文件 `v8/src/ast/ast-source-ranges.h` 的主要功能是**定义了用于存储和管理抽象语法树 (AST) 节点源代码范围的数据结构和类**。

让我们更详细地分解它的功能：

**1. `SourceRange` 结构体:**

*   **功能:** 表示源代码中的一个范围。它包含两个成员变量：
    *   `start`: 范围起始位置 (0-based, 包含)。
    *   `end`: 范围结束位置 (0-based, 不包含)。
*   **辅助方法:**
    *   `IsEmpty()`: 检查范围是否为空。
    *   `Empty()`: 返回一个空的 `SourceRange`。
    *   `OpenEnded(int32_t start)`: 创建一个起始位置已知，但结束位置未知的范围。
    *   `ContinuationOf(const SourceRange& that, int end = kNoSourcePosition)`: 创建一个紧随给定范围 `that` 之后的范围。
    *   `FunctionLiteralMarkerRange()`: 返回一个特殊标记的范围，用于标识函数字面量。
*   **特殊常量:**
    *   `kNoSourcePosition`:  表示没有源位置信息。
    *   `kFunctionLiteralSourcePosition`:  用于标记函数字面量的特殊源位置。

**2. `AST_SOURCE_RANGE_LIST` 宏:**

*   **功能:**  定义了一个包含各种 AST 节点类型的列表。这个宏用于生成代码，将源范围信息与特定的 AST 节点关联起来。

**3. `SourceRangeKind` 枚举:**

*   **功能:**  定义了不同类型源范围的枚举值。例如，对于一个 `if` 语句，可能有 `kThen` (then 代码块) 和 `kElse` (else 代码块) 两种类型的源范围。

**4. `AstNodeSourceRanges` 抽象基类:**

*   **功能:**  定义了存储 AST 节点源范围信息的抽象接口。
*   **虚函数:**
    *   `GetRange(SourceRangeKind kind)`:  获取指定类型的源范围。
    *   `HasRange(SourceRangeKind kind)`:  检查是否具有指定类型的源范围。
    *   `RemoveContinuationRange()`:  移除延续范围 (默认为不可达，子类可以实现)。

**5. 派生自 `AstNodeSourceRanges` 的具体类:**

*   **功能:**  每个具体的类都负责存储特定 AST 节点类型的源范围信息。它们实现了 `GetRange` 和 `HasRange` 方法，以根据节点的结构提供正确的源范围。
    *   `BinaryOperationSourceRanges`: 存储二元运算右操作数的范围。
    *   `ContinuationSourceRanges`:  存储延续位置，用于表示代码执行流的延续点。
    *   `BlockSourceRanges`:  存储代码块的延续位置。
    *   `CaseClauseSourceRanges`: 存储 `case` 子句的代码块范围。
    *   `ConditionalChainSourceRanges`:  存储条件链中 `then` 和 `else` 代码块的范围。
    *   `ConditionalSourceRanges`: 存储 `if` 语句中 `then` 和 `else` 代码块的范围。
    *   `FunctionLiteralSourceRanges`:  用于标记函数字面量的范围。
    *   `IfStatementSourceRanges`: 存储 `if` 语句的 `then` 和 `else` 代码块的范围，以及可能的延续范围。
    *   `IterationStatementSourceRanges`: 存储循环语句 (如 `for`, `while`) 的循环体范围，以及可能的延续范围。
    *   `JumpStatementSourceRanges`: 存储跳转语句 (如 `break`, `continue`) 的延续位置。
    *   `NaryOperationSourceRanges`: 存储 N 元运算 (如多个加法) 中各个操作数的范围。
    *   `ExpressionSourceRanges`: 存储表达式的范围。
    *   `SuspendSourceRanges`: 存储 `suspend` 语句的延续位置。
    *   `SwitchStatementSourceRanges`: 存储 `switch` 语句的延续位置。
    *   `ThrowSourceRanges`: 存储 `throw` 语句的延续位置。
    *   `TryCatchStatementSourceRanges`: 存储 `try...catch` 语句中 `catch` 代码块的范围，以及可能的延续范围。
    *   `TryFinallyStatementSourceRanges`: 存储 `try...finally` 语句中 `finally` 代码块的范围，以及可能的延续范围。

**6. `SourceRangeMap` 类:**

*   **功能:**  将 AST 节点指针映射到相应的 `AstNodeSourceRanges` 对象。这允许在编译过程中查找与特定 AST 节点关联的源范围信息。
*   **方法:**
    *   `Find(ZoneObject* node)`:  查找给定 AST 节点的源范围信息。
    *   `Insert(type* node, type##SourceRanges* ranges)`:  插入 AST 节点及其对应的源范围信息。`AST_SOURCE_RANGE_LIST` 宏在这里被用于生成针对不同 AST 节点类型的 `Insert` 方法。

**关于 .tq 结尾:**

你提出的问题中提到 "如果 v8/src/ast/ast-source-ranges.h 以 .tq 结尾，那它是个 v8 torque 源代码"。这是正确的。 **`.h` 结尾表示 C++ 头文件，而 `.tq` 结尾表示 V8 的 Torque 语言源代码。**  `v8/src/ast/ast-source-ranges.h`  本身是一个 C++ 头文件。

**与 JavaScript 功能的关系:**

`v8/src/ast/ast-source-ranges.h` 与 JavaScript 功能紧密相关，因为它负责存储 JavaScript 代码在解析后生成的抽象语法树 (AST) 中各个节点的源代码位置信息。 这些信息对于以下目的至关重要：

*   **错误报告:** 当 JavaScript 代码发生错误时，V8 可以利用这些源范围信息准确地指出错误发生的位置（行号、列号），帮助开发者快速定位问题。
*   **调试:** 调试器可以利用这些信息将断点与源代码的特定位置关联起来，并显示执行到哪个代码范围。
*   **代码覆盖率:**  工具可以使用这些范围信息来分析哪些代码被执行了，哪些没有被执行。
*   **性能分析:**  可以根据这些范围信息来分析代码的性能瓶颈。

**JavaScript 示例:**

```javascript
function add(a, b) { // 函数字面量的源范围
  if (a > 0) {     // if 语句的源范围，以及 then 代码块的源范围
    return a + b;   // return 语句的源范围，以及表达式 a + b 的源范围
  } else {         // else 代码块的源范围
    return b;       // return 语句的源范围
  }
}

try {             // try 语句的源范围
  console.log(add(1, 2));
} catch (e) {     // catch 子句的源范围
  console.error("Error occurred:", e);
} finally {       // finally 子句的源范围
  console.log("Finished");
}

let x = 5;         // 变量声明的源范围
x++;             // 表达式的源范围
```

在 V8 内部，当解析器解析这段 JavaScript 代码时，会为每个语法结构（函数、`if` 语句、`try...catch` 等）创建一个对应的 AST 节点，并使用 `SourceRange` 结构体和相关的类来记录这些结构在原始源代码中的起始和结束位置。

**代码逻辑推理和假设输入/输出:**

假设我们有以下简单的 JavaScript 代码片段：

```javascript
a + b;
```

1. **解析阶段:** V8 的解析器会识别这是一个二元加法运算。
2. **AST 构建:**  会创建一个 `BinaryOperation` 类型的 AST 节点。
3. **源范围记录:**
    *   `SourceRange` 结构体可能会记录 `a` 的源范围 (假设从位置 0 到 1)。
    *   `SourceRange` 结构体可能会记录 `b` 的源范围 (假设从位置 4 到 5)。
    *   `BinaryOperationSourceRanges` 对象会被创建，并可能存储 `b` 的源范围（作为 `right_range_`）。
    *   `SourceRangeMap` 会将 `BinaryOperation` 节点与 `BinaryOperationSourceRanges` 对象关联起来.

**假设输入:**  表示 "a" 的源代码位置为 start=0, end=1，表示 "+" 的源代码位置为 start=2, end=3，表示 "b" 的源代码位置为 start=4, end=5。

**假设输出:**

*   对于 `BinaryOperation` AST 节点，调用 `GetRange(SourceRangeKind::kRight)` 可能会返回 `SourceRange(4, 5)`，表示右操作数 "b" 的范围。
*   可以通过其他方式（可能在 AST 节点自身或其他关联信息中）获取运算符 "+" 的范围，或者整个二元运算 "a + b" 的范围 (可能需要组合子节点的范围)。

**用户常见的编程错误示例:**

源代码范围信息在错误报告中至关重要。 考虑以下 JavaScript 代码中的语法错误：

```javascript
function foo() {
  console.log("Hello"  // 缺少闭合括号
}
```

当 V8 尝试解析这段代码时，它会遇到语法错误。  没有 `ast-source-ranges.h` 中定义的机制，V8 只能知道代码中存在错误。  但是，有了源范围信息，V8 可以准确地报告：

*   **错误类型:**  "SyntaxError: Unexpected token '}'"
*   **错误位置:**  **行 3，列 1** (假设 "}" 在第三行的第一个字符)。

V8 通过跟踪每个 AST 节点的源范围，可以定位到导致解析失败的特定位置（在上面的例子中，是函数定义的闭合大括号，它发现之前缺少了 `console.log` 调用的闭合括号）。

**总结:**

`v8/src/ast/ast-source-ranges.h` 是 V8 引擎中一个关键的头文件，它定义了用于跟踪和管理 JavaScript 代码在抽象语法树中各个节点源代码位置的核心数据结构。这些信息对于错误报告、调试、代码覆盖率和性能分析等功能至关重要，极大地提升了开发者的体验。

### 提示词
```
这是目录为v8/src/ast/ast-source-ranges.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ast/ast-source-ranges.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_AST_AST_SOURCE_RANGES_H_
#define V8_AST_AST_SOURCE_RANGES_H_

#include "src/ast/ast.h"
#include "src/zone/zone-containers.h"

namespace v8 {
namespace internal {

// Specifies a range within the source code. {start} is 0-based and inclusive,
// {end} is 0-based and exclusive.
struct SourceRange {
  SourceRange() : SourceRange(kNoSourcePosition, kNoSourcePosition) {}
  SourceRange(int start, int end) : start(start), end(end) {}
  bool IsEmpty() const { return start == kNoSourcePosition; }
  static SourceRange Empty() { return SourceRange(); }
  static SourceRange OpenEnded(int32_t start) {
    return SourceRange(start, kNoSourcePosition);
  }
  static SourceRange ContinuationOf(const SourceRange& that,
                                    int end = kNoSourcePosition) {
    return that.IsEmpty() ? Empty() : SourceRange(that.end, end);
  }

  static constexpr int kFunctionLiteralSourcePosition = -2;
  static_assert(kFunctionLiteralSourcePosition == kNoSourcePosition - 1);

  // Source ranges associated with a function literal do not contain real
  // source positions; instead, they are created with special marker values.
  // These are later recognized and rewritten during processing in
  // Coverage::Collect().
  static SourceRange FunctionLiteralMarkerRange() {
    return {kFunctionLiteralSourcePosition, kFunctionLiteralSourcePosition};
  }

  int32_t start, end;
};

// The list of ast node kinds that have associated source ranges. Note that this
// macro is not undefined at the end of this file.
#define AST_SOURCE_RANGE_LIST(V) \
  V(BinaryOperation)             \
  V(Block)                       \
  V(CaseClause)                  \
  V(ConditionalChain)            \
  V(Conditional)                 \
  V(Expression)                  \
  V(FunctionLiteral)             \
  V(IfStatement)                 \
  V(IterationStatement)          \
  V(JumpStatement)               \
  V(NaryOperation)               \
  V(Suspend)                     \
  V(SwitchStatement)             \
  V(Throw)                       \
  V(TryCatchStatement)           \
  V(TryFinallyStatement)

enum class SourceRangeKind {
  kBody,
  kCatch,
  kContinuation,
  kElse,
  kFinally,
  kRight,
  kThen,
};

class AstNodeSourceRanges : public ZoneObject {
 public:
  virtual ~AstNodeSourceRanges() = default;
  virtual SourceRange GetRange(SourceRangeKind kind) = 0;
  virtual bool HasRange(SourceRangeKind kind) = 0;
  virtual void RemoveContinuationRange() { UNREACHABLE(); }
};

class BinaryOperationSourceRanges final : public AstNodeSourceRanges {
 public:
  explicit BinaryOperationSourceRanges(const SourceRange& right_range)
      : right_range_(right_range) {}

  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    return right_range_;
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kRight;
  }

 private:
  SourceRange right_range_;
};

class ContinuationSourceRanges : public AstNodeSourceRanges {
 public:
  explicit ContinuationSourceRanges(int32_t continuation_position)
      : continuation_position_(continuation_position) {}

  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    return SourceRange::OpenEnded(continuation_position_);
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kContinuation;
  }

  void RemoveContinuationRange() override {
    DCHECK(HasRange(SourceRangeKind::kContinuation));
    continuation_position_ = kNoSourcePosition;
  }

 private:
  int32_t continuation_position_;
};

class BlockSourceRanges final : public ContinuationSourceRanges {
 public:
  explicit BlockSourceRanges(int32_t continuation_position)
      : ContinuationSourceRanges(continuation_position) {}
};

class CaseClauseSourceRanges final : public AstNodeSourceRanges {
 public:
  explicit CaseClauseSourceRanges(const SourceRange& body_range)
      : body_range_(body_range) {}

  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    return body_range_;
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kBody;
  }

 private:
  SourceRange body_range_;
};

class ConditionalChainSourceRanges final : public AstNodeSourceRanges {
 public:
  explicit ConditionalChainSourceRanges(Zone* zone)
      : then_ranges_(zone), else_ranges_(zone) {}

  SourceRange GetRangeAtIndex(SourceRangeKind kind, size_t index) {
    if (kind == SourceRangeKind::kThen) {
      DCHECK_LT(index, then_ranges_.size());
      return then_ranges_[index];
    }
    DCHECK_EQ(kind, SourceRangeKind::kElse);
    DCHECK_LT(index, else_ranges_.size());
    return else_ranges_[index];
  }

  void AddThenRanges(const SourceRange& range) {
    then_ranges_.push_back(range);
  }

  void AddElseRange(const SourceRange& else_range) {
    else_ranges_.push_back(else_range);
  }

  size_t RangeCount() const { return then_ranges_.size(); }

  SourceRange GetRange(SourceRangeKind kind) override { UNREACHABLE(); }
  bool HasRange(SourceRangeKind kind) override { return false; }

 private:
  ZoneVector<SourceRange> then_ranges_;
  ZoneVector<SourceRange> else_ranges_;
};

class ConditionalSourceRanges final : public AstNodeSourceRanges {
 public:
  explicit ConditionalSourceRanges(const SourceRange& then_range,
                                   const SourceRange& else_range)
      : then_range_(then_range), else_range_(else_range) {}

  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    switch (kind) {
      case SourceRangeKind::kThen:
        return then_range_;
      case SourceRangeKind::kElse:
        return else_range_;
      default:
        UNREACHABLE();
    }
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kThen || kind == SourceRangeKind::kElse;
  }

 private:
  SourceRange then_range_;
  SourceRange else_range_;
};

class FunctionLiteralSourceRanges final : public AstNodeSourceRanges {
 public:
  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    return SourceRange::FunctionLiteralMarkerRange();
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kBody;
  }
};

class IfStatementSourceRanges final : public AstNodeSourceRanges {
 public:
  explicit IfStatementSourceRanges(const SourceRange& then_range,
                                   const SourceRange& else_range)
      : then_range_(then_range), else_range_(else_range) {}

  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    switch (kind) {
      case SourceRangeKind::kElse:
        return else_range_;
      case SourceRangeKind::kThen:
        return then_range_;
      case SourceRangeKind::kContinuation: {
        if (!has_continuation_) return SourceRange::Empty();
        const SourceRange& trailing_range =
            else_range_.IsEmpty() ? then_range_ : else_range_;
        return SourceRange::ContinuationOf(trailing_range);
      }
      default:
        UNREACHABLE();
    }
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kThen || kind == SourceRangeKind::kElse ||
           kind == SourceRangeKind::kContinuation;
  }

  void RemoveContinuationRange() override {
    DCHECK(HasRange(SourceRangeKind::kContinuation));
    has_continuation_ = false;
  }

 private:
  SourceRange then_range_;
  SourceRange else_range_;
  bool has_continuation_ = true;
};

class IterationStatementSourceRanges final : public AstNodeSourceRanges {
 public:
  explicit IterationStatementSourceRanges(const SourceRange& body_range)
      : body_range_(body_range) {}

  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    switch (kind) {
      case SourceRangeKind::kBody:
        return body_range_;
      case SourceRangeKind::kContinuation:
        if (!has_continuation_) return SourceRange::Empty();
        return SourceRange::ContinuationOf(body_range_);
      default:
        UNREACHABLE();
    }
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kBody ||
           kind == SourceRangeKind::kContinuation;
  }

  void RemoveContinuationRange() override {
    DCHECK(HasRange(SourceRangeKind::kContinuation));
    has_continuation_ = false;
  }

 private:
  SourceRange body_range_;
  bool has_continuation_ = true;
};

class JumpStatementSourceRanges final : public ContinuationSourceRanges {
 public:
  explicit JumpStatementSourceRanges(int32_t continuation_position)
      : ContinuationSourceRanges(continuation_position) {}
};

class NaryOperationSourceRanges final : public AstNodeSourceRanges {
 public:
  NaryOperationSourceRanges(Zone* zone, const SourceRange& range)
      : ranges_(zone) {
    AddRange(range);
  }

  SourceRange GetRangeAtIndex(size_t index) {
    DCHECK(index < ranges_.size());
    return ranges_[index];
  }

  void AddRange(const SourceRange& range) { ranges_.push_back(range); }
  size_t RangeCount() const { return ranges_.size(); }

  SourceRange GetRange(SourceRangeKind kind) override { UNREACHABLE(); }
  bool HasRange(SourceRangeKind kind) override { return false; }

 private:
  ZoneVector<SourceRange> ranges_;
};

class ExpressionSourceRanges final : public AstNodeSourceRanges {
 public:
  explicit ExpressionSourceRanges(const SourceRange& right_range)
      : right_range_(right_range) {}

  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    return right_range_;
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kRight;
  }

 private:
  SourceRange right_range_;
};

class SuspendSourceRanges final : public ContinuationSourceRanges {
 public:
  explicit SuspendSourceRanges(int32_t continuation_position)
      : ContinuationSourceRanges(continuation_position) {}
};

class SwitchStatementSourceRanges final : public ContinuationSourceRanges {
 public:
  explicit SwitchStatementSourceRanges(int32_t continuation_position)
      : ContinuationSourceRanges(continuation_position) {}
};

class ThrowSourceRanges final : public ContinuationSourceRanges {
 public:
  explicit ThrowSourceRanges(int32_t continuation_position)
      : ContinuationSourceRanges(continuation_position) {}
};

class TryCatchStatementSourceRanges final : public AstNodeSourceRanges {
 public:
  explicit TryCatchStatementSourceRanges(const SourceRange& catch_range)
      : catch_range_(catch_range) {}

  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    switch (kind) {
      case SourceRangeKind::kCatch:
        return catch_range_;
      case SourceRangeKind::kContinuation:
        if (!has_continuation_) return SourceRange::Empty();
        return SourceRange::ContinuationOf(catch_range_);
      default:
        UNREACHABLE();
    }
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kCatch ||
           kind == SourceRangeKind::kContinuation;
  }

  void RemoveContinuationRange() override {
    DCHECK(HasRange(SourceRangeKind::kContinuation));
    has_continuation_ = false;
  }

 private:
  SourceRange catch_range_;
  bool has_continuation_ = true;
};

class TryFinallyStatementSourceRanges final : public AstNodeSourceRanges {
 public:
  explicit TryFinallyStatementSourceRanges(const SourceRange& finally_range)
      : finally_range_(finally_range) {}

  SourceRange GetRange(SourceRangeKind kind) override {
    DCHECK(HasRange(kind));
    switch (kind) {
      case SourceRangeKind::kFinally:
        return finally_range_;
      case SourceRangeKind::kContinuation:
        if (!has_continuation_) return SourceRange::Empty();
        return SourceRange::ContinuationOf(finally_range_);
      default:
        UNREACHABLE();
    }
  }

  bool HasRange(SourceRangeKind kind) override {
    return kind == SourceRangeKind::kFinally ||
           kind == SourceRangeKind::kContinuation;
  }

  void RemoveContinuationRange() override {
    DCHECK(HasRange(SourceRangeKind::kContinuation));
    has_continuation_ = false;
  }

 private:
  SourceRange finally_range_;
  bool has_continuation_ = true;
};

// Maps ast node pointers to associated source ranges. The parser creates these
// mappings and the bytecode generator consumes them.
class SourceRangeMap final : public ZoneObject {
 public:
  explicit SourceRangeMap(Zone* zone) : map_(zone) {}

  AstNodeSourceRanges* Find(ZoneObject* node) {
    auto it = map_.find(node);
    if (it == map_.end()) return nullptr;
    return it->second;
  }

// Type-checked insertion.
#define DEFINE_MAP_INSERT(type)                         \
  void Insert(type* node, type##SourceRanges* ranges) { \
    DCHECK_NOT_NULL(node);                              \
    map_.emplace(node, ranges);                         \
  }
  AST_SOURCE_RANGE_LIST(DEFINE_MAP_INSERT)
#undef DEFINE_MAP_INSERT

 private:
  ZoneMap<ZoneObject*, AstNodeSourceRanges*> map_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_AST_AST_SOURCE_RANGES_H_
```