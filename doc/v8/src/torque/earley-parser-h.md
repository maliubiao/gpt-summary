Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The filename `earley-parser.h` and the namespace `v8::internal::torque` strongly suggest this code is related to parsing, specifically the Earley parsing algorithm, within the Torque compiler for V8.

2. **High-Level Structure Scan:**  Quickly skim through the code to get a sense of the main components. Keywords like `class`, `struct`, `enum`, `using`, and template declarations stand out. Notice the heavy use of templates and smart pointers (`std::unique_ptr`).

3. **Focus on Key Classes:** Identify the most important classes and understand their roles:
    * `ParseResultHolderBase`/`ParseResultHolder`:  These manage the results of parsing, holding values of different types. The `TypeId` enum indicates the variety of possible parse results.
    * `ParseResult`:  A wrapper around `ParseResultHolderBase`, providing type-safe access to the underlying parsed value.
    * `MatchedInput`:  Represents a segment of the input string that was successfully matched.
    * `ParseResultIterator`:  Iterates through multiple possible parse results for a given grammar rule.
    * `Rule`:  Represents a production rule in the grammar. It has a left-hand side, a right-hand side, and an associated action.
    * `Symbol`:  Represents a terminal or non-terminal symbol in the grammar. It contains the rules where it appears on the left-hand side.
    * `Item`: The core of the Earley algorithm, representing a partially parsed rule at a specific point in the input.
    * `Lexer`:  Responsible for breaking the input string into a sequence of tokens.
    * `Grammar`:  The overall container for the grammar rules, symbols, and the lexer.

4. **Understand Relationships Between Classes:** How do these classes interact?
    * The `Lexer` produces tokens (represented by `Symbol`s and `MatchedInput`).
    * The `EarleyAlgorithm` (implemented by the `RunEarleyAlgorithm` function) uses the tokens and the grammar rules (defined within `Symbol`s and `Rule`s) to create `Item`s.
    * When a rule is fully matched (an `Item` is complete), the associated `Action` in the `Rule` is executed, using a `ParseResultIterator` to access the results of its child items. This action produces a `ParseResult`.

5. **Examine Key Data Structures and Algorithms:**
    * **Earley Parsing:**  Recognize the concepts of items, prediction, scanning, and completion inherent in the class structure (`Item` and the `RunEarleyAlgorithm` function).
    * **Parse Result Handling:** The template-based `ParseResultHolder` and the `TypeId` enum provide a mechanism for storing and retrieving parsed values of different types safely.
    * **Lexing:** The `Lexer` class and its `PatternFunction` hint at a way to define lexical rules (regular expressions or similar).

6. **Consider the Context (Torque):** Remember that this is within the Torque compiler. This helps understand *why* certain features exist. Torque is used to generate C++ code for V8's internals. The grammar likely describes the syntax of Torque itself. The parsed results will be used to build an internal representation of the Torque code, which will then be used for code generation.

7. **Address Specific Questions:**  Now, address the specific prompts in the request:
    * **Functionality:** Summarize the roles of the main classes and the overall parsing process.
    * **`.tq` Extension:**  Explain that a `.tq` file likely contains Torque source code that this parser would process.
    * **Relationship to JavaScript:** Since Torque is used in V8, it has an indirect relationship to JavaScript. Give an example of a JavaScript feature that might be implemented using Torque (e.g., a built-in function). Emphasize that the *parser itself* doesn't directly execute JavaScript.
    * **Code Logic/Inference:** Choose a simple grammar rule and show how the parsing process would work for a given input, illustrating the creation of `Item`s and the execution of actions.
    * **Common Programming Errors:** Think about what kinds of errors users might make when writing Torque code that this parser would catch (syntax errors, type mismatches, etc.).

8. **Refine and Organize:**  Structure the explanation clearly, using headings and bullet points. Provide concrete examples where possible. Use precise terminology related to parsing and compilers.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** "This looks like a standard parser."
* **Correction:** "It's an *Earley* parser, which has specific characteristics."
* **Initial Thought:** "The `ParseResult` is just a pointer."
* **Correction:** "It's a wrapper around a type-erased holder to manage different result types."
* **Initial Thought:** "The lexer uses regular expressions."
* **Refinement:** "The lexer uses custom `PatternFunction`s, which could be based on regexes or other matching logic."
* **Considering the Javascript connection:** Avoid overstating the directness of the link. Focus on Torque's role in *implementing* JavaScript features.

By following this structured approach, and continually refining understanding, we can arrive at a comprehensive and accurate explanation of the provided header file.
## 功能列举

`v8/src/torque/earley-parser.h` 文件定义了一个 **Earley 解析器**，用于解析某种语言的语法。考虑到文件路径 `v8/src/torque/`，可以推断这个解析器是为 **Torque** 语言设计的。Torque 是 V8 引擎内部使用的一种领域特定语言 (DSL)，用于定义内置函数、类型系统以及其他底层操作。

**主要功能包括：**

1. **定义语法规则:**  提供了 `Rule` 类来表示上下文无关文法的产生式规则，包括左侧的非终结符和右侧的符号序列。
2. **表示语法符号:** 使用 `Symbol` 类来表示语法中的终结符和非终结符。非终结符包含可以推导出它的规则列表。
3. **实现 Earley 算法:** 实现了 Earley 算法的核心逻辑，用于高效地解析输入字符串，判断其是否符合定义的文法。主要体现在 `Item` 类和 `RunEarleyAlgorithm` 函数。
4. **词法分析 (Lexing):** 提供了 `Lexer` 类，用于将输入字符串分解成一个个的 Token (词法单元)。可以定义模式 (patterns) 和关键词 (keywords) 来识别不同的 Token 类型。
5. **解析结果处理:**
    * `ParseResultHolderBase` 和 `ParseResultHolder` 类用于存储解析结果，可以存储不同类型的值（例如，字符串、布尔值、整数、表达式等）。
    * `ParseResult` 类是 `ParseResultHolderBase` 的包装器，提供了类型安全的访问方式。
    * 可以为每个语法规则定义一个 `Action`，在规则匹配成功后执行，用于将匹配到的子结果组合成更高级别的抽象语法树节点。
6. **错误处理和歧义检测:** 虽然代码中没有明显的错误处理机制，但 Earley 算法本身能够处理歧义文法。 `Item::CheckAmbiguity` 方法暗示了对歧义性的检查。
7. **源代码位置追踪:** `MatchedInput` 结构体用于记录匹配到的输入片段的起始和结束位置，以及对应的源代码位置 (`SourcePosition`)，这对于错误报告和调试非常重要。

**总结来说，`v8/src/torque/earley-parser.h` 定义了一个用于解析 Torque 语言的框架，包括了语法规则的定义、词法分析、Earley 解析算法的实现以及解析结果的处理机制。**

## 关于 `.tq` 结尾的文件

如果 `v8/src/torque/earley-parser.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。这个文件本身是 C++ 头文件，用于定义 Torque 解析器的结构和功能。真正的 Torque 源代码文件通常以 `.tq` 结尾，包含了用 Torque 语言编写的类型定义、函数声明等。

## 与 JavaScript 的关系及示例

Torque 语言的主要目的是 **为 V8 引擎的内置功能提供更安全、更高效的实现方式**。它允许开发者以一种更接近底层的方式定义类型和操作，并能生成优化的 C++ 代码。

因此，`v8/src/torque/earley-parser.h` 定义的解析器用于解析 Torque 代码，而 Torque 代码最终会影响 JavaScript 的执行。

**JavaScript 示例：**

假设 Torque 中定义了一个用于实现 JavaScript 中 `Array.prototype.push` 方法的函数。

**Torque 代码 (假设的 .tq 文件内容片段):**

```torque
// v8/src/torque/builtins/array-push.tq

namespace runtime {
  builtin ArrayPush(Context, Object, ...Object) variadic {
    // ... 一些类型检查和操作 ...
    return result;
  }
}
```

这个 Torque 代码会被 `earley-parser.h` 中定义的解析器解析，然后 Torque 编译器会将其转换为 C++ 代码。

**JavaScript 调用：**

```javascript
const arr = [1, 2, 3];
arr.push(4); //  这个 push 方法的实现可能就是用 Torque 定义的
console.log(arr); // 输出: [1, 2, 3, 4]
```

当 JavaScript 引擎执行 `arr.push(4)` 时，实际上可能会调用由 Torque 代码生成的 C++ 函数。

**关键点：** `earley-parser.h` 中的代码本身不直接运行 JavaScript。它用于解析 Torque 代码，而 Torque 代码是 V8 引擎实现 JavaScript 功能的一部分。

## 代码逻辑推理及示例

假设我们有以下简单的 Torque 语法规则：

```
Expression ::= Number "+" Number
Number     ::= [0-9]+
```

并且我们有以下输入字符串： `"123 + 45"`

**假设输入:**

```
tokens.token_symbols = [Symbol("123"), Symbol("+"), Symbol("45")]
tokens.token_contents = [
  MatchedInput(begin="...", end="...", pos=SourcePosition(...), ToString()="123"),
  MatchedInput(begin="...", end="...", pos=SourcePosition(...), ToString()="+"),
  MatchedInput(begin="...", end="...", pos=SourcePosition(...), ToString()="45")
]
```

**Earley 解析器的执行过程 (简化描述):**

1. **扫描 "123":** 解析器会找到匹配 `Number` 规则的 Token "123"。
2. **扫描 "+":** 解析器会找到匹配 "+" 终结符的 Token "+"。
3. **扫描 "45":** 解析器会找到匹配 `Number` 规则的 Token "45"。
4. **完成 `Number "+" Number` 规则:** 当解析器看到 "45" 时，它会意识到已经匹配了 `Expression` 规则的右侧所有符号。
5. **执行 `Expression` 规则的 Action:**  假设 `Expression` 规则的 Action 是将两个 `Number` 的值转换为整数并相加。

**假设 `Expression` 规则的 Action:**

```c++
std::optional<ParseResult> AddNumbers(ParseResultIterator* child_results) {
  int left = std::stoi(child_results->NextAs<std::string>()); // 假设 Number 的解析结果是 string
  child_results->Next(); // skip the "+"
  int right = std::stoi(child_results->NextAs<std::string>());
  return ParseResult{left + right};
}
```

**预期输出 (ParseResult):**

```
ParseResult 包含一个 int 类型的值: 168
```

**代码逻辑推理：**

* 输入字符串被词法分析器分解成 Token 序列。
* Earley 解析器根据语法规则逐步匹配 Token。
* 当一个完整的规则被匹配时，其关联的 Action 被执行，将子结果组合成最终的解析结果。

## 用户常见的编程错误及示例

如果用户尝试编写 Torque 代码，可能会遇到以下一些常见的编程错误，而 `earley-parser.h` 中定义的解析器可以帮助检测这些错误：

1. **语法错误:**  不符合 Torque 语言的语法规则。

   **示例 Torque 代码错误：**

   ```torque
   // 缺少分号
   let x: int = 10
   ```

   **解析器行为:**  解析器会报告在预期的位置缺少分号的语法错误。

2. **类型错误:**  使用了不兼容的类型。

   **示例 Torque 代码错误：**

   ```torque
   let x: int = "hello"; // 尝试将字符串赋值给整数类型
   ```

   **解析器行为:** 解析器会根据 Torque 的类型系统检测到类型不匹配的错误。请注意，这里的 `earley-parser.h` 主要负责语法分析，类型检查可能在后续的语义分析阶段进行，但语法定义中也可能包含一些基本的类型相关的规则。

3. **未声明的标识符:**  使用了未声明的变量或函数。

   **示例 Torque 代码错误：**

   ```torque
   let y: int = z + 5; // 变量 z 未声明
   ```

   **解析器行为:** 解析器会报告 `z` 是一个未声明的标识符。

4. **错误的运算符使用:**  使用了不适用于特定类型的运算符。

   **示例 Torque 代码错误 (假设的):**

   ```torque
   let a: bool = true;
   let b: bool = false;
   let c: int = a * b; // 布尔值不能直接进行乘法运算 (假设)
   ```

   **解析器行为:** 解析器可能会根据语法规则判断出 `*` 运算符不适用于布尔类型，或者将错误传递到后续的语义分析阶段。

5. **关键词拼写错误:**  错误地拼写了 Torque 的关键词。

   **示例 Torque 代码错误：**

   ```torque
   flunction myFunction(x: int): void {
     // ...
   }
   ```

   **解析器行为:** 解析器会无法识别 `flunction` 关键词，并报告语法错误。

**总结:** `earley-parser.h` 中定义的解析器是 Torque 编译器的重要组成部分，它负责检查 Torque 代码的语法是否正确。通过定义语法规则和使用 Earley 算法，它可以有效地识别用户在编写 Torque 代码时可能犯的各种语法错误，为后续的编译和代码生成奠定基础。

### 提示词
```
这是目录为v8/src/torque/earley-parser.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/earley-parser.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TORQUE_EARLEY_PARSER_H_
#define V8_TORQUE_EARLEY_PARSER_H_

#include <map>
#include <memory>
#include <optional>
#include <vector>

#include "src/base/contextual.h"
#include "src/torque/source-positions.h"
#include "src/torque/utils.h"

namespace v8::internal::torque {

class Symbol;
class Item;

class ParseResultHolderBase {
 public:
  enum class TypeId;
  virtual ~ParseResultHolderBase() = default;
  template <class T>
  T& Cast();
  template <class T>
  const T& Cast() const;

 protected:
  explicit ParseResultHolderBase(TypeId type_id) : type_id_(type_id) {
    // MSVC wrongly complains about type_id_ being an unused private field.
    USE(type_id_);
  }

 private:
  const TypeId type_id_;
};

enum class ParseResultHolderBase::TypeId {
  kStdString,
  kBool,
  kInt32,
  kDouble,
  kIntegerLiteral,
  kStdVectorOfString,
  kExpressionPtr,
  kIdentifierPtr,
  kOptionalIdentifierPtr,
  kStatementPtr,
  kDeclarationPtr,
  kTypeExpressionPtr,
  kOptionalTypeExpressionPtr,
  kTryHandlerPtr,
  kNameAndTypeExpression,
  kEnumEntry,
  kStdVectorOfEnumEntry,
  kImplicitParameters,
  kOptionalImplicitParameters,
  kNameAndExpression,
  kAnnotation,
  kVectorOfAnnotation,
  kAnnotationParameter,
  kOptionalAnnotationParameter,
  kClassFieldExpression,
  kStructFieldExpression,
  kBitFieldDeclaration,
  kStdVectorOfNameAndTypeExpression,
  kStdVectorOfNameAndExpression,
  kStdVectorOfClassFieldExpression,
  kStdVectorOfStructFieldExpression,
  kStdVectorOfBitFieldDeclaration,
  kIncrementDecrementOperator,
  kOptionalStdString,
  kStdVectorOfStatementPtr,
  kStdVectorOfDeclarationPtr,
  kStdVectorOfStdVectorOfDeclarationPtr,
  kStdVectorOfExpressionPtr,
  kExpressionWithSource,
  kParameterList,
  kTypeList,
  kOptionalTypeList,
  kLabelAndTypes,
  kStdVectorOfLabelAndTypes,
  kStdVectorOfTryHandlerPtr,
  kOptionalStatementPtr,
  kOptionalExpressionPtr,
  kTypeswitchCase,
  kStdVectorOfTypeswitchCase,
  kStdVectorOfIdentifierPtr,
  kOptionalClassBody,
  kGenericParameter,
  kGenericParameters,

  kJsonValue,
  kJsonMember,
  kStdVectorOfJsonValue,
  kStdVectorOfJsonMember,
};

using ParseResultTypeId = ParseResultHolderBase::TypeId;

template <class T>
class ParseResultHolder : public ParseResultHolderBase {
 public:
  explicit ParseResultHolder(T value)
      : ParseResultHolderBase(id), value_(std::move(value)) {}

 private:
  V8_EXPORT_PRIVATE static const TypeId id;
  friend class ParseResultHolderBase;
  T value_;
};

template <class T>
T& ParseResultHolderBase::Cast() {
  CHECK_EQ(ParseResultHolder<T>::id, type_id_);
  return static_cast<ParseResultHolder<T>*>(this)->value_;
}

template <class T>
const T& ParseResultHolderBase::Cast() const {
  CHECK_EQ(ParseResultHolder<T>::id, type_id_);
  return static_cast<const ParseResultHolder<T>*>(this)->value_;
}

class ParseResult {
 public:
  template <class T>
  explicit ParseResult(T x) : value_(new ParseResultHolder<T>(std::move(x))) {}

  template <class T>
  const T& Cast() const& {
    return value_->Cast<T>();
  }
  template <class T>
  T& Cast() & {
    return value_->Cast<T>();
  }
  template <class T>
  T&& Cast() && {
    return std::move(value_->Cast<T>());
  }

 private:
  std::unique_ptr<ParseResultHolderBase> value_;
};

using InputPosition = const char*;

struct MatchedInput {
  MatchedInput(InputPosition begin, InputPosition end, SourcePosition pos)
      : begin(begin), end(end), pos(pos) {}
  InputPosition begin;
  InputPosition end;
  SourcePosition pos;
  std::string ToString() const { return {begin, end}; }
};

class ParseResultIterator {
 public:
  explicit ParseResultIterator(std::vector<ParseResult> results,
                               MatchedInput matched_input)
      : results_(std::move(results)), matched_input_(matched_input) {}

  ParseResultIterator(const ParseResultIterator&) = delete;
  ParseResultIterator& operator=(const ParseResultIterator&) = delete;

  ParseResult Next() {
    CHECK_LT(i_, results_.size());
    return std::move(results_[i_++]);
  }
  template <class T>
  T NextAs() {
    return std::move(Next().Cast<T>());
  }
  bool HasNext() const { return i_ < results_.size(); }

  const MatchedInput& matched_input() const { return matched_input_; }

 private:
  std::vector<ParseResult> results_;
  size_t i_ = 0;
  MatchedInput matched_input_;
};

struct LexerResult {
  std::vector<Symbol*> token_symbols;
  std::vector<MatchedInput> token_contents;
};

using Action =
    std::optional<ParseResult> (*)(ParseResultIterator* child_results);

inline std::optional<ParseResult> DefaultAction(
    ParseResultIterator* child_results) {
  if (!child_results->HasNext()) return std::nullopt;
  return child_results->Next();
}

template <class T, Action action>
inline Action AsSingletonVector() {
  return [](ParseResultIterator* child_results) -> std::optional<ParseResult> {
    auto result = action(child_results);
    if (!result) return result;
    return ParseResult{std::vector<T>{(*result).Cast<T>()}};
  };
}

// A rule of the context-free grammar. Each rule can have an action attached to
// it, which is executed after the parsing is finished.
class Rule final {
 public:
  explicit Rule(std::vector<Symbol*> right_hand_side,
                Action action = DefaultAction)
      : right_hand_side_(std::move(right_hand_side)), action_(action) {}

  Symbol* left() const {
    DCHECK_NOT_NULL(left_hand_side_);
    return left_hand_side_;
  }
  const std::vector<Symbol*>& right() const { return right_hand_side_; }

  void SetLeftHandSide(Symbol* left_hand_side) {
    DCHECK_NULL(left_hand_side_);
    left_hand_side_ = left_hand_side;
  }

  V8_EXPORT_PRIVATE std::optional<ParseResult> RunAction(
      const Item* completed_item, const LexerResult& tokens) const;

 private:
  Symbol* left_hand_side_ = nullptr;
  std::vector<Symbol*> right_hand_side_;
  Action action_;
};

// A Symbol represents a terminal or a non-terminal of the grammar.
// It stores the list of rules, which have this symbol as the
// left-hand side.
// Terminals have an empty list of rules, they are created by the Lexer
// instead of from rules.
// Symbols need to reside at stable memory addresses, because the addresses are
// used in the parser.
class Symbol {
 public:
  Symbol() = default;
  Symbol(std::initializer_list<Rule> rules) { *this = rules; }

  // Disallow copying and moving to ensure Symbol has a stable address.
  Symbol(const Symbol&) = delete;
  Symbol& operator=(const Symbol&) = delete;

  V8_EXPORT_PRIVATE Symbol& operator=(std::initializer_list<Rule> rules);

  bool IsTerminal() const { return rules_.empty(); }
  Rule* rule(size_t index) const { return rules_[index].get(); }
  size_t rule_number() const { return rules_.size(); }

  void AddRule(const Rule& rule) {
    rules_.push_back(std::make_unique<Rule>(rule));
    rules_.back()->SetLeftHandSide(this);
  }

  V8_EXPORT_PRIVATE std::optional<ParseResult> RunAction(
      const Item* item, const LexerResult& tokens);

 private:
  std::vector<std::unique_ptr<Rule>> rules_;
};

// Items are the core datastructure of Earley's algorithm.
// They consist of a (partially) matched rule, a marked position inside of the
// right-hand side of the rule (traditionally written as a dot) and an input
// range from {start} to {pos} that matches the symbols of the right-hand side
// that are left of the mark. In addition, they store a child and a left-sibling
// pointer to reconstruct the AST in the end.
class Item {
 public:
  Item(const Rule* rule, size_t mark, size_t start, size_t pos)
      : rule_(rule), mark_(mark), start_(start), pos_(pos) {
    DCHECK_LE(mark_, right().size());
  }

  // A complete item has the mark at the right end, which means the input range
  // matches the complete rule.
  bool IsComplete() const {
    DCHECK_LE(mark_, right().size());
    return mark_ == right().size();
  }

  // The symbol right after the mark is expected at {pos} for this item to
  // advance.
  Symbol* NextSymbol() const {
    DCHECK(!IsComplete());
    DCHECK_LT(mark_, right().size());
    return right()[mark_];
  }

  // We successfully parsed NextSymbol() between {pos} and {new_pos}.
  // If NextSymbol() was a non-terminal, then {child} is a pointer to a
  // completed item for this parse.
  // We create a new item, which moves the mark one forward.
  Item Advance(size_t new_pos, const Item* child = nullptr) const {
    if (child) {
      DCHECK(child->IsComplete());
      DCHECK_EQ(pos(), child->start());
      DCHECK_EQ(new_pos, child->pos());
      DCHECK_EQ(NextSymbol(), child->left());
    }
    Item result(rule_, mark_ + 1, start_, new_pos);
    result.prev_ = this;
    result.child_ = child;
    return result;
  }

  // Collect the items representing the AST children of this completed item.
  std::vector<const Item*> Children() const;
  // The matched input separated according to the next branching AST level.
  std::string SplitByChildren(const LexerResult& tokens) const;
  // Check if {other} results in the same AST as this Item.
  void CheckAmbiguity(const Item& other, const LexerResult& tokens) const;

  MatchedInput GetMatchedInput(const LexerResult& tokens) const {
    const MatchedInput& start = tokens.token_contents[start_];
    const MatchedInput& end = start_ == pos_ ? tokens.token_contents[start_]
                                             : tokens.token_contents[pos_ - 1];
    CHECK_EQ(start.pos.source, end.pos.source);
    SourcePosition combined{start.pos.source, start.pos.start, end.pos.end};

    return {start.begin, end.end, combined};
  }

  // We exclude {prev_} and {child_} from equality and hash computations,
  // because they are just globally unique data associated with an item.
  bool operator==(const Item& other) const {
    return rule_ == other.rule_ && mark_ == other.mark_ &&
           start_ == other.start_ && pos_ == other.pos_;
  }

  friend size_t hash_value(const Item& i) {
    return base::hash_combine(i.rule_, i.mark_, i.start_, i.pos_);
  }

  const Rule* rule() const { return rule_; }
  Symbol* left() const { return rule_->left(); }
  const std::vector<Symbol*>& right() const { return rule_->right(); }
  size_t pos() const { return pos_; }
  size_t start() const { return start_; }

 private:
  const Rule* rule_;
  size_t mark_;
  size_t start_;
  size_t pos_;

  const Item* prev_ = nullptr;
  const Item* child_ = nullptr;
};

inline std::optional<ParseResult> Symbol::RunAction(const Item* item,
                                                    const LexerResult& tokens) {
  DCHECK(item->IsComplete());
  DCHECK_EQ(item->left(), this);
  return item->rule()->RunAction(item, tokens);
}

V8_EXPORT_PRIVATE const Item* RunEarleyAlgorithm(
    Symbol* start, const LexerResult& tokens,
    std::unordered_set<Item, base::hash<Item>>* processed);

inline std::optional<ParseResult> ParseTokens(Symbol* start,
                                              const LexerResult& tokens) {
  std::unordered_set<Item, base::hash<Item>> table;
  const Item* final_item = RunEarleyAlgorithm(start, tokens, &table);
  return start->RunAction(final_item, tokens);
}

// The lexical syntax is dynamically defined while building the grammar by
// adding patterns and keywords to the Lexer.
// The term keyword here can stand for any fixed character sequence, including
// operators and parentheses.
// Each pattern or keyword automatically gets a terminal symbol associated with
// it. These symbols form the result of the lexing.
// Patterns and keywords are matched using the longest match principle. If the
// longest matching pattern coincides with a keyword, the keyword symbol is
// chosen instead of the pattern.
// In addition, there is a single whitespace pattern which is consumed but does
// not become part of the token list.
class Lexer {
 public:
  // Functions to define patterns. They try to match starting from {pos}. If
  // successful, they return true and advance {pos}. Otherwise, {pos} stays
  // unchanged.
  using PatternFunction = bool (*)(InputPosition* pos);

  void SetWhitespace(PatternFunction whitespace) {
    match_whitespace_ = whitespace;
  }

  Symbol* Pattern(PatternFunction pattern) { return &patterns_[pattern]; }
  Symbol* Token(const std::string& keyword) { return &keywords_[keyword]; }
  V8_EXPORT_PRIVATE LexerResult RunLexer(const std::string& input);

 private:
  PatternFunction match_whitespace_ = [](InputPosition*) { return false; };
  std::map<PatternFunction, Symbol> patterns_;
  std::map<std::string, Symbol> keywords_;
  Symbol* MatchToken(InputPosition* pos, InputPosition end);
};

// A grammar can have a result, which is the results of the start symbol.
// Grammar is intended to be subclassed, with Symbol members forming the
// mutually recursive rules of the grammar.
class Grammar {
 public:
  using PatternFunction = Lexer::PatternFunction;

  explicit Grammar(Symbol* start) : start_(start) {}

  std::optional<ParseResult> Parse(const std::string& input) {
    LexerResult tokens = lexer().RunLexer(input);
    return ParseTokens(start_, tokens);
  }

 protected:
  Symbol* Token(const std::string& s) { return lexer_.Token(s); }
  Symbol* Pattern(PatternFunction pattern) { return lexer_.Pattern(pattern); }
  void SetWhitespace(PatternFunction ws) { lexer_.SetWhitespace(ws); }

  // NewSymbol() allocates a fresh symbol and stores it in the current grammar.
  // This is necessary to define helpers that create new symbols.
  Symbol* NewSymbol(std::initializer_list<Rule> rules = {}) {
    auto symbol = std::make_unique<Symbol>(rules);
    Symbol* result = symbol.get();
    generated_symbols_.push_back(std::move(symbol));
    return result;
  }

  // Helper functions to define lexer patterns. If they match, they return true
  // and advance {pos}. Otherwise, {pos} is unchanged.
  V8_EXPORT_PRIVATE static bool MatchChar(int (*char_class)(int),
                                          InputPosition* pos);
  V8_EXPORT_PRIVATE static bool MatchChar(bool (*char_class)(char),
                                          InputPosition* pos);
  V8_EXPORT_PRIVATE static bool MatchAnyChar(InputPosition* pos);
  V8_EXPORT_PRIVATE static bool MatchString(const char* s, InputPosition* pos);

  // The action MatchInput() produces the input matched by the rule as
  // result.
  static std::optional<ParseResult> YieldMatchedInput(
      ParseResultIterator* child_results) {
    return ParseResult{child_results->matched_input().ToString()};
  }

  // Create a new symbol to parse the given sequence of symbols.
  // At most one of the symbols can return a result.
  Symbol* Sequence(std::vector<Symbol*> symbols) {
    return NewSymbol({Rule(std::move(symbols))});
  }

  template <class T, T value>
  static std::optional<ParseResult> YieldIntegralConstant(
      ParseResultIterator* child_results) {
    return ParseResult{value};
  }

  template <class T>
  static std::optional<ParseResult> YieldDefaultValue(
      ParseResultIterator* child_results) {
    return ParseResult{T{}};
  }

  template <class From, class To>
  static std::optional<ParseResult> CastParseResult(
      ParseResultIterator* child_results) {
    To result = child_results->NextAs<From>();
    return ParseResult{std::move(result)};
  }

  // Try to parse {s} and return the result of type {Result} casted to {T}.
  // Otherwise, the result is a default-constructed {T}.
  template <class T, class Result = T>
  Symbol* TryOrDefault(Symbol* s) {
    return NewSymbol({Rule({s}, CastParseResult<Result, T>),
                      Rule({}, YieldDefaultValue<T>)});
  }

  template <class T>
  static std::optional<ParseResult> MakeSingletonVector(
      ParseResultIterator* child_results) {
    T x = child_results->NextAs<T>();
    std::vector<T> result;
    result.push_back(std::move(x));
    return ParseResult{std::move(result)};
  }

  template <class T>
  static std::optional<ParseResult> MakeExtendedVector(
      ParseResultIterator* child_results) {
    std::vector<T> l = child_results->NextAs<std::vector<T>>();
    T x = child_results->NextAs<T>();
    l.push_back(std::move(x));
    return ParseResult{std::move(l)};
  }

  // For example, NonemptyList(Token("A"), Token(",")) parses any of
  // A or A,A or A,A,A and so on.
  template <class T>
  Symbol* NonemptyList(Symbol* element, std::optional<Symbol*> separator = {}) {
    Symbol* list = NewSymbol();
    *list = {Rule({element}, MakeSingletonVector<T>),
             separator
                 ? Rule({list, *separator, element}, MakeExtendedVector<T>)
                 : Rule({list, element}, MakeExtendedVector<T>)};
    return list;
  }

  template <class T>
  Symbol* List(Symbol* element, std::optional<Symbol*> separator = {}) {
    return TryOrDefault<std::vector<T>>(NonemptyList<T>(element, separator));
  }

  template <class T>
  Symbol* Optional(Symbol* x) {
    return TryOrDefault<std::optional<T>, T>(x);
  }

  Symbol* CheckIf(Symbol* x) {
    return NewSymbol({Rule({x}, YieldIntegralConstant<bool, true>),
                      Rule({}, YieldIntegralConstant<bool, false>)});
  }

  Lexer& lexer() { return lexer_; }

 private:
  Lexer lexer_;
  std::vector<std::unique_ptr<Symbol>> generated_symbols_;
  Symbol* start_;
};

}  // namespace v8::internal::torque

#endif  // V8_TORQUE_EARLEY_PARSER_H_
```