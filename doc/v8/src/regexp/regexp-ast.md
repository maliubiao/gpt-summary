Response: Let's break down the thought process for analyzing this C++ code and explaining its purpose in relation to JavaScript regular expressions.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan of the code, looking for recognizable keywords and patterns. I see:

* `Copyright 2016 the V8 project authors`: This immediately tells me it's part of the V8 JavaScript engine.
* `#include "src/regexp/regexp-ast.h"`:  This indicates it's dealing with the Abstract Syntax Tree (AST) of regular expressions within V8.
* `namespace v8 { namespace internal {`: This reinforces that it's internal V8 code.
* Classes with names like `RegExpDisjunction`, `RegExpAlternative`, `RegExpQuantifier`, `RegExpCapture`, etc.: These strongly suggest it's defining the structure of a regular expression.
* `Accept(RegExpVisitor* visitor, void* data)` and `Visit##Name`: This is the classic Visitor pattern, used for traversing the AST.
* `IsAnchoredAtStart`, `IsAnchoredAtEnd`: These are likely methods to determine if a part of the regex must match at the beginning or end of the string.
* `CaptureRegisters`:  This hints at managing capture groups within the regex.
* `RegExpUnparser`: This class seems responsible for converting the internal representation back into a human-readable format (or at least a simplified one).
* `FOR_EACH_REG_EXP_TREE_TYPE`: This macro suggests a set of common types for regular expression nodes.

**2. Identifying Core Functionality:**

Based on the keywords, I can deduce that the primary function of this file is to define the structure and behavior of the regular expression AST in V8. It's not about *executing* regular expressions but about representing their logical structure.

**3. Understanding the Data Structures (Classes):**

I then look at the classes defined and try to understand their relationships and purposes:

* **Base Class: `RegExpTree`:**  This is likely the abstract base class for all regex AST nodes. The `As##Name` and `Is##Name` methods are standard ways to perform downcasting and type checking in C++.
* **Concrete Node Types:**  The `RegExpDisjunction`, `RegExpAlternative`, `RegExpQuantifier`, `RegExpCapture`, etc., represent the different components of a regular expression (OR, sequence, repetition, capturing groups, etc.).
* **`RegExpVisitor` and `RegExpUnparser`:** The Visitor pattern suggests a way to operate on the AST without modifying its structure. `RegExpUnparser` is a specific visitor for converting the AST to a string representation.
* **`Interval`:** This likely represents a range of integers, probably used for tracking capture group registers.
* **`ZoneList`:**  This is probably a V8-specific dynamic array or list class, used to hold child nodes.

**4. Connecting to JavaScript Regular Expressions:**

Now, the crucial step is to link this internal C++ representation to the user-facing JavaScript regular expressions. I consider common JavaScript regex features and how they might be represented in this AST:

* **Alternation (`|`):**  Maps to `RegExpDisjunction`.
* **Sequences (e.g., `abc`):** Maps to `RegExpAlternative`.
* **Quantifiers (`*`, `+`, `?`, `{m,n}`):** Maps to `RegExpQuantifier`.
* **Capture Groups (`(...)`):** Maps to `RegExpCapture`.
* **Assertions (`^`, `$`, `\b`, `\B`):** Maps to `RegExpAssertion`.
* **Character Classes (`[a-z]`, `\d`, `\w`):** Maps to `RegExpClassRanges`, `RegExpClassSetOperand`, and `RegExpClassSetExpression` (for more complex classes).
* **Lookarounds (`(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`):** Maps to `RegExpLookaround`.
* **Backreferences (`\1`, `\2`):** Maps to `RegExpBackReference`.

**5. Providing JavaScript Examples:**

To make the explanation concrete, I need to provide JavaScript examples that correspond to the C++ structures:

* Show how `|` in JavaScript creates a `RegExpDisjunction`.
* Demonstrate how sequences of characters create `RegExpAlternative`.
* Illustrate the use of quantifiers and their mapping to `RegExpQuantifier`.
* Give examples of capturing groups and their relation to `RegExpCapture`.
* Provide examples of different assertion types and their corresponding `RegExpAssertion` types.

**6. Explaining the `RegExpUnparser`:**

The `RegExpUnparser` is an important detail. I need to explain that it's used for debugging and potentially other internal V8 tools to visualize the AST. The example output of `RegExpUnparser` is helpful to illustrate this.

**7. Summarizing the Functionality:**

Finally, I synthesize all the observations into a concise summary of the file's purpose: defining the AST for JavaScript regular expressions within V8.

**Self-Correction/Refinement during the process:**

* Initially, I might not immediately grasp the purpose of `RegExpClassSetOperand` and `RegExpClassSetExpression`. By looking at their usage and the different operation types (`kUnion`, `kIntersection`, `kSubtraction`), I can infer that they handle more complex character class scenarios beyond simple ranges.
* The `MAKE_ACCEPT` and `MAKE_TYPE_CASE` macros are a bit cryptic at first. Recognizing them as a form of code generation or boilerplate reduction helps in understanding their role. They simplify the implementation of the Visitor pattern and type checking.
* I need to be careful to distinguish between *representing* the regex and *executing* it. This file is focused on representation.

By following this structured approach, analyzing the code, identifying key patterns, and relating them to JavaScript concepts, I can arrive at a comprehensive and accurate explanation of the `regexp-ast.cc` file.
这个C++源代码文件 `regexp-ast.cc` 定义了 V8 引擎中用于表示正则表达式抽象语法树 (AST) 的各种类。它的主要功能是：

**1. 定义正则表达式的内部结构:**

该文件定义了一系列 C++ 类，每个类代表正则表达式语法中的一个特定组成部分。这些类构成了正则表达式的 AST，用于在 V8 引擎内部表示和操作正则表达式。这些类包括：

* **`RegExpTree`:**  所有正则表达式 AST 节点的基类。
* **`RegExpDisjunction`:**  表示正则表达式中的 "或" 运算 (`|`)，包含多个 `RegExpAlternative`。
* **`RegExpAlternative`:** 表示正则表达式中的一个分支，由一系列 `RegExpTree` 节点组成。
* **`RegExpAssertion`:** 表示正则表达式中的断言，如 `^` (行首)、`$` (行尾)、`\b` (单词边界) 等。
* **`RegExpAtom`:** 表示一个简单的字符或字符序列。
* **`RegExpText`:**  表示一个文本字符串。
* **`RegExpQuantifier`:** 表示量词，如 `*`、`+`、`?`、`{n,m}`，修饰其前面的 `RegExpTree` 节点。
* **`RegExpCapture`:** 表示捕获组 (`(...)`)。
* **`RegExpGroup`:** 表示非捕获组 (`(?:...)`) 或带有标志的组 (`(?flags:...)`)。
* **`RegExpLookaround`:** 表示前瞻断言 (`(?=...)`, `(?!...)`) 和后顾断言 (`(?<=...)`, `(?<!...)`)。
* **`RegExpBackReference`:** 表示反向引用 (`\1`, `\2` 等)。
* **`RegExpEmpty`:** 表示空匹配。
* **`RegExpClassRanges`:** 表示字符类，例如 `[a-z]` 或 `[0-9]`。
* **`RegExpClassSetOperand` 和 `RegExpClassSetExpression`:** 用于表示更复杂的字符类，包括集合运算（并、交、差）。

**2. 提供访问和操作 AST 节点的方法:**

每个类都提供了一些方法来访问其包含的数据和属性。例如，`RegExpQuantifier` 类有方法获取其最小和最大匹配次数。

**3. 实现 Visitor 模式:**

该文件使用了 Visitor 模式，通过 `RegExpVisitor` 抽象类和 `Accept` 方法，允许在不修改 AST 结构的情况下对 AST 进行各种操作。 `RegExpUnparser` 类就是一个具体的 Visitor，用于将 AST 转换回一种可读的字符串表示形式，这对于调试和理解正则表达式的结构很有用。

**4. 计算和管理捕获组:**

`CaptureRegisters()` 方法用于计算每个 AST 节点中涉及的捕获组寄存器范围。这对于正则表达式引擎在执行时正确管理捕获组至关重要。

**5. 判断是否锚定:**

`IsAnchoredAtStart()` 和 `IsAnchoredAtEnd()` 方法用于判断正则表达式的某个部分是否必须从字符串的开头或结尾开始匹配。这对于优化正则表达式的执行非常重要。

**与 JavaScript 功能的关系 (及 JavaScript 示例):**

这个 C++ 文件是 V8 引擎实现 JavaScript 正则表达式功能的基础。当你在 JavaScript 中创建一个正则表达式时，V8 引擎会解析这个正则表达式并构建一个由 `regexp-ast.cc` 中定义的类组成的 AST。这个 AST 随后会被用于正则表达式的编译和执行。

以下是一些 JavaScript 正则表达式功能与 `regexp-ast.cc` 中类的对应关系示例：

* **JavaScript 的 `|` (或) 对应 `RegExpDisjunction`:**
   ```javascript
   const regex = /a|b/;
   ```
   在 V8 内部，这个正则表达式会被表示为一个 `RegExpDisjunction` 节点，它包含两个 `RegExpAlternative` 节点，分别表示 "a" 和 "b"。

* **JavaScript 的 `(...)` (捕获组) 对应 `RegExpCapture`:**
   ```javascript
   const regex = /(\w+)\s(\w+)/;
   ```
   这个正则表达式包含两个捕获组，V8 会创建两个 `RegExpCapture` 节点来表示它们，并存储它们的索引。

* **JavaScript 的 `*`、`+`、`?` (量词) 对应 `RegExpQuantifier`:**
   ```javascript
   const regex = /a*/; // 零个或多个 'a'
   const regex2 = /b+/; // 一个或多个 'b'
   const regex3 = /c?/; // 零个或一个 'c'
   ```
   这些正则表达式中的 `*`、`+` 和 `?` 会被表示为 `RegExpQuantifier` 节点，并存储相应的最小和最大匹配次数。

* **JavaScript 的 `^` 和 `$` (行首/尾断言) 对应 `RegExpAssertion`:**
   ```javascript
   const regex = /^start/; // 匹配以 "start" 开头的字符串
   const regex2 = /end$/;   // 匹配以 "end" 结尾的字符串
   ```
   `^` 会被表示为 `RegExpAssertion`，类型为 `START_OF_INPUT`，`$` 会被表示为 `RegExpAssertion`，类型为 `END_OF_INPUT`。

* **JavaScript 的 `[a-z]` (字符类) 对应 `RegExpClassRanges`:**
   ```javascript
   const regex = /[a-z]/; // 匹配小写字母
   ```
   `[a-z]` 会被表示为一个 `RegExpClassRanges` 节点，其中包含字符范围 'a' 到 'z'。

* **JavaScript 的 `(?=...)` (正向前瞻断言) 对应 `RegExpLookaround`:**
   ```javascript
   const regex = /foo(?=bar)/; // 匹配后面跟着 "bar" 的 "foo"
   ```
   `(?=bar)` 会被表示为一个 `RegExpLookaround` 节点，类型为 `LOOKAHEAD` 且为 positive。

**总结:**

`v8/src/regexp/regexp-ast.cc` 文件是 V8 引擎中用于表示正则表达式内部结构的蓝图。它定义了构成正则表达式抽象语法树的各种 C++ 类，这些类与 JavaScript 中使用的正则表达式语法元素直接对应。理解这个文件的作用有助于深入理解 V8 引擎是如何处理和执行 JavaScript 正则表达式的。

### 提示词
```
这是目录为v8/src/regexp/regexp-ast.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/regexp/regexp-ast.h"

#include "src/utils/ostreams.h"
#include "src/zone/zone-list-inl.h"

namespace v8 {
namespace internal {

#define MAKE_ACCEPT(Name)                                          \
  void* RegExp##Name::Accept(RegExpVisitor* visitor, void* data) { \
    return visitor->Visit##Name(this, data);                       \
  }
FOR_EACH_REG_EXP_TREE_TYPE(MAKE_ACCEPT)
#undef MAKE_ACCEPT

#define MAKE_TYPE_CASE(Name)                               \
  RegExp##Name* RegExpTree::As##Name() { return nullptr; } \
  bool RegExpTree::Is##Name() { return false; }
FOR_EACH_REG_EXP_TREE_TYPE(MAKE_TYPE_CASE)
#undef MAKE_TYPE_CASE

#define MAKE_TYPE_CASE(Name)                              \
  RegExp##Name* RegExp##Name::As##Name() { return this; } \
  bool RegExp##Name::Is##Name() { return true; }
FOR_EACH_REG_EXP_TREE_TYPE(MAKE_TYPE_CASE)
#undef MAKE_TYPE_CASE

namespace {

Interval ListCaptureRegisters(ZoneList<RegExpTree*>* children) {
  Interval result = Interval::Empty();
  for (int i = 0; i < children->length(); i++)
    result = result.Union(children->at(i)->CaptureRegisters());
  return result;
}

}  // namespace

Interval RegExpAlternative::CaptureRegisters() {
  return ListCaptureRegisters(nodes());
}


Interval RegExpDisjunction::CaptureRegisters() {
  return ListCaptureRegisters(alternatives());
}


Interval RegExpLookaround::CaptureRegisters() {
  return body()->CaptureRegisters();
}


Interval RegExpCapture::CaptureRegisters() {
  Interval self(StartRegister(index()), EndRegister(index()));
  return self.Union(body()->CaptureRegisters());
}


Interval RegExpQuantifier::CaptureRegisters() {
  return body()->CaptureRegisters();
}


bool RegExpAssertion::IsAnchoredAtStart() {
  return assertion_type() == RegExpAssertion::Type::START_OF_INPUT;
}


bool RegExpAssertion::IsAnchoredAtEnd() {
  return assertion_type() == RegExpAssertion::Type::END_OF_INPUT;
}


bool RegExpAlternative::IsAnchoredAtStart() {
  ZoneList<RegExpTree*>* nodes = this->nodes();
  for (int i = 0; i < nodes->length(); i++) {
    RegExpTree* node = nodes->at(i);
    if (node->IsAnchoredAtStart()) {
      return true;
    }
    if (node->max_match() > 0) {
      return false;
    }
  }
  return false;
}


bool RegExpAlternative::IsAnchoredAtEnd() {
  ZoneList<RegExpTree*>* nodes = this->nodes();
  for (int i = nodes->length() - 1; i >= 0; i--) {
    RegExpTree* node = nodes->at(i);
    if (node->IsAnchoredAtEnd()) {
      return true;
    }
    if (node->max_match() > 0) {
      return false;
    }
  }
  return false;
}


bool RegExpDisjunction::IsAnchoredAtStart() {
  ZoneList<RegExpTree*>* alternatives = this->alternatives();
  for (int i = 0; i < alternatives->length(); i++) {
    if (!alternatives->at(i)->IsAnchoredAtStart()) return false;
  }
  return true;
}


bool RegExpDisjunction::IsAnchoredAtEnd() {
  ZoneList<RegExpTree*>* alternatives = this->alternatives();
  for (int i = 0; i < alternatives->length(); i++) {
    if (!alternatives->at(i)->IsAnchoredAtEnd()) return false;
  }
  return true;
}


bool RegExpLookaround::IsAnchoredAtStart() {
  return is_positive() && type() == LOOKAHEAD && body()->IsAnchoredAtStart();
}


bool RegExpCapture::IsAnchoredAtStart() { return body()->IsAnchoredAtStart(); }


bool RegExpCapture::IsAnchoredAtEnd() { return body()->IsAnchoredAtEnd(); }

namespace {

// Convert regular expression trees to a simple sexp representation.
// This representation should be different from the input grammar
// in as many cases as possible, to make it more difficult for incorrect
// parses to look as correct ones which is likely if the input and
// output formats are alike.
class RegExpUnparser final : public RegExpVisitor {
 public:
  RegExpUnparser(std::ostream& os, Zone* zone) : os_(os), zone_(zone) {}
  void VisitCharacterRange(CharacterRange that);
#define MAKE_CASE(Name) void* Visit##Name(RegExp##Name*, void* data) override;
  FOR_EACH_REG_EXP_TREE_TYPE(MAKE_CASE)
#undef MAKE_CASE
 private:
  std::ostream& os_;
  Zone* zone_;
};

}  // namespace

void* RegExpUnparser::VisitDisjunction(RegExpDisjunction* that, void* data) {
  os_ << "(|";
  for (int i = 0; i < that->alternatives()->length(); i++) {
    os_ << " ";
    that->alternatives()->at(i)->Accept(this, data);
  }
  os_ << ")";
  return nullptr;
}


void* RegExpUnparser::VisitAlternative(RegExpAlternative* that, void* data) {
  os_ << "(:";
  for (int i = 0; i < that->nodes()->length(); i++) {
    os_ << " ";
    that->nodes()->at(i)->Accept(this, data);
  }
  os_ << ")";
  return nullptr;
}


void RegExpUnparser::VisitCharacterRange(CharacterRange that) {
  os_ << AsUC32(that.from());
  if (!that.IsSingleton()) {
    os_ << "-" << AsUC32(that.to());
  }
}

void* RegExpUnparser::VisitClassRanges(RegExpClassRanges* that, void* data) {
  if (that->is_negated()) os_ << "^";
  os_ << "[";
  for (int i = 0; i < that->ranges(zone_)->length(); i++) {
    if (i > 0) os_ << " ";
    VisitCharacterRange(that->ranges(zone_)->at(i));
  }
  os_ << "]";
  return nullptr;
}

void* RegExpUnparser::VisitClassSetOperand(RegExpClassSetOperand* that,
                                           void* data) {
  os_ << "![";
  for (int i = 0; i < that->ranges()->length(); i++) {
    if (i > 0) os_ << " ";
    VisitCharacterRange(that->ranges()->at(i));
  }
  if (that->has_strings()) {
    for (auto iter : *that->strings()) {
      os_ << " '";
      os_ << std::string(iter.first.begin(), iter.first.end());
      os_ << "'";
    }
  }
  os_ << "]";
  return nullptr;
}

void* RegExpUnparser::VisitClassSetExpression(RegExpClassSetExpression* that,
                                              void* data) {
  switch (that->operation()) {
    case RegExpClassSetExpression::OperationType::kUnion:
      os_ << "++";
      break;
    case RegExpClassSetExpression::OperationType::kIntersection:
      os_ << "&&";
      break;
    case RegExpClassSetExpression::OperationType::kSubtraction:
      os_ << "--";
      break;
  }
  if (that->is_negated()) os_ << "^";
  os_ << "[";
  for (int i = 0; i < that->operands()->length(); i++) {
    if (i > 0) os_ << " ";
    that->operands()->at(i)->Accept(this, data);
  }
  os_ << "]";
  return nullptr;
}

void* RegExpUnparser::VisitAssertion(RegExpAssertion* that, void* data) {
  switch (that->assertion_type()) {
    case RegExpAssertion::Type::START_OF_INPUT:
      os_ << "@^i";
      break;
    case RegExpAssertion::Type::END_OF_INPUT:
      os_ << "@$i";
      break;
    case RegExpAssertion::Type::START_OF_LINE:
      os_ << "@^l";
      break;
    case RegExpAssertion::Type::END_OF_LINE:
      os_ << "@$l";
      break;
    case RegExpAssertion::Type::BOUNDARY:
      os_ << "@b";
      break;
    case RegExpAssertion::Type::NON_BOUNDARY:
      os_ << "@B";
      break;
  }
  return nullptr;
}


void* RegExpUnparser::VisitAtom(RegExpAtom* that, void* data) {
  os_ << "'";
  base::Vector<const base::uc16> chardata = that->data();
  for (int i = 0; i < chardata.length(); i++) {
    os_ << AsUC16(chardata[i]);
  }
  os_ << "'";
  return nullptr;
}


void* RegExpUnparser::VisitText(RegExpText* that, void* data) {
  if (that->elements()->length() == 1) {
    that->elements()->at(0).tree()->Accept(this, data);
  } else {
    os_ << "(!";
    for (int i = 0; i < that->elements()->length(); i++) {
      os_ << " ";
      that->elements()->at(i).tree()->Accept(this, data);
    }
    os_ << ")";
  }
  return nullptr;
}


void* RegExpUnparser::VisitQuantifier(RegExpQuantifier* that, void* data) {
  os_ << "(# " << that->min() << " ";
  if (that->max() == RegExpTree::kInfinity) {
    os_ << "- ";
  } else {
    os_ << that->max() << " ";
  }
  os_ << (that->is_greedy() ? "g " : that->is_possessive() ? "p " : "n ");
  that->body()->Accept(this, data);
  os_ << ")";
  return nullptr;
}


void* RegExpUnparser::VisitCapture(RegExpCapture* that, void* data) {
  os_ << "(^ ";
  that->body()->Accept(this, data);
  os_ << ")";
  return nullptr;
}

void* RegExpUnparser::VisitGroup(RegExpGroup* that, void* data) {
  os_ << "(?" << that->flags() << ": ";
  that->body()->Accept(this, data);
  os_ << ")";
  return nullptr;
}

void* RegExpUnparser::VisitLookaround(RegExpLookaround* that, void* data) {
  os_ << "(";
  os_ << (that->type() == RegExpLookaround::LOOKAHEAD ? "->" : "<-");
  os_ << (that->is_positive() ? " + " : " - ");
  that->body()->Accept(this, data);
  os_ << ")";
  return nullptr;
}


void* RegExpUnparser::VisitBackReference(RegExpBackReference* that,
                                         void* data) {
  os_ << "(<- " << that->captures()->first()->index();
  for (int i = 1; i < that->captures()->length(); ++i) {
    os_ << "," << that->captures()->at(i)->index();
  }
  os_ << ")";
  return nullptr;
}


void* RegExpUnparser::VisitEmpty(RegExpEmpty* that, void* data) {
  os_ << '%';
  return nullptr;
}

std::ostream& RegExpTree::Print(std::ostream& os, Zone* zone) {
  RegExpUnparser unparser(os, zone);
  Accept(&unparser, nullptr);
  return os;
}

RegExpDisjunction::RegExpDisjunction(ZoneList<RegExpTree*>* alternatives)
    : alternatives_(alternatives) {
  DCHECK_LT(1, alternatives->length());
  RegExpTree* first_alternative = alternatives->at(0);
  min_match_ = first_alternative->min_match();
  max_match_ = first_alternative->max_match();
  for (int i = 1; i < alternatives->length(); i++) {
    RegExpTree* alternative = alternatives->at(i);
    min_match_ = std::min(min_match_, alternative->min_match());
    max_match_ = std::max(max_match_, alternative->max_match());
  }
}

namespace {

int IncreaseBy(int previous, int increase) {
  if (RegExpTree::kInfinity - previous < increase) {
    return RegExpTree::kInfinity;
  } else {
    return previous + increase;
  }
}

}  // namespace

RegExpAlternative::RegExpAlternative(ZoneList<RegExpTree*>* nodes)
    : nodes_(nodes) {
  DCHECK_LT(1, nodes->length());
  min_match_ = 0;
  max_match_ = 0;
  for (int i = 0; i < nodes->length(); i++) {
    RegExpTree* node = nodes->at(i);
    int node_min_match = node->min_match();
    min_match_ = IncreaseBy(min_match_, node_min_match);
    int node_max_match = node->max_match();
    max_match_ = IncreaseBy(max_match_, node_max_match);
  }
}

RegExpClassSetOperand::RegExpClassSetOperand(ZoneList<CharacterRange>* ranges,
                                             CharacterClassStrings* strings)
    : ranges_(ranges), strings_(strings) {
  DCHECK_NOT_NULL(ranges);
  min_match_ = 0;
  max_match_ = 0;
  if (!ranges->is_empty()) {
    min_match_ = 1;
    max_match_ = 2;
  }
  if (has_strings()) {
    for (auto string : *strings) {
      min_match_ = std::min(min_match_, string.second->min_match());
      max_match_ = std::max(max_match_, string.second->max_match());
    }
  }
}

RegExpClassSetExpression::RegExpClassSetExpression(
    OperationType op, bool is_negated, bool may_contain_strings,
    ZoneList<RegExpTree*>* operands)
    : operation_(op),
      is_negated_(is_negated),
      may_contain_strings_(may_contain_strings),
      operands_(operands) {
  DCHECK_NOT_NULL(operands);
  if (is_negated) {
    DCHECK(!may_contain_strings_);
    // We don't know anything about max matches for negated classes.
    // As there are no strings involved, assume that we can match a unicode
    // character (2 code points).
    max_match_ = 2;
  } else {
    max_match_ = 0;
    for (auto op : *operands) {
      max_match_ = std::max(max_match_, op->max_match());
    }
  }
}

// static
RegExpClassSetExpression* RegExpClassSetExpression::Empty(Zone* zone,
                                                          bool is_negated) {
  ZoneList<CharacterRange>* ranges =
      zone->template New<ZoneList<CharacterRange>>(0, zone);
  RegExpClassSetOperand* op =
      zone->template New<RegExpClassSetOperand>(ranges, nullptr);
  ZoneList<RegExpTree*>* operands =
      zone->template New<ZoneList<RegExpTree*>>(1, zone);
  operands->Add(op, zone);
  return zone->template New<RegExpClassSetExpression>(
      RegExpClassSetExpression::OperationType::kUnion, is_negated, false,
      operands);
}

}  // namespace internal
}  // namespace v8
```