Response: Let's break down the thought process for analyzing this C++ code and generating the explanation, including the JavaScript examples.

**1. Initial Skim and Keyword Identification:**

The first step is a quick scan to identify key terms and structures. I'm looking for:

* **Namespaces:** `v8::internal`, `experimental`, `regexp`. This tells me the general area of the code within the V8 engine.
* **Classes:** `ExperimentalRegExpCompiler`, `CanBeHandledVisitor`, `BytecodeAssembler`, `FilterGroupsCompileVisitor`, `CompileVisitor`, `Label`. These are the main building blocks.
* **Methods:** `CanBeHandled`, `Compile`, `Visit...` (various visitor methods), `Accept`, `Fork`, `Jmp`, `ConsumeRange`, etc. These are the actions the code performs.
* **Data Structures:** `RegExpTree`, `RegExpFlags`, `RegExpInstruction`, `ZoneList`, `ZoneMap`, `Label`. These are the types the code manipulates.
* **Keywords related to Regular Expressions:**  "RegExp", "flags", "capture", "quantifier", "assertion", "atom", "text", "lookaround", "backreference", "disjunction", "alternative", "class", "unicode".
* **Keywords related to Compilation:** "compiler", "bytecode", "assemble", "bind", "label".
* **Keywords related to Limitations:** "TODO", "doesn't support", "not currently supported", "can't be implemented without backtracking".
* **Flags and Options:** `v8_flags.experimental_regexp_engine_capture_group_opt`. This indicates configurable behavior.

**2. Understanding the Core Functionality (`Compile` and `CanBeHandled`):**

The presence of `Compile` strongly suggests this code is involved in turning a regular expression representation into some form of executable code. `CanBeHandled` suggests a check for whether the compiler can process a given regular expression.

**3. Analyzing `CanBeHandledVisitor`:**

This class implements the logic for `CanBeHandled`. I go through each `Visit...` method:

* **`AreSuitableFlags`:**  Identifies the supported RegExp flags (global, sticky, multiline, dotAll, linear, and implicitly unicode).
* **`VisitDisjunction`, `VisitAlternative`:** These seem to traverse the structure of the regular expression.
* **`VisitClassRanges`, `VisitClassSetOperand`:**  Handles character classes. The comment about `has_strings` indicates a limitation.
* **`VisitClassSetExpression`:**  Explicitly marked as unsupported.
* **`VisitAssertion`, `VisitAtom`, `VisitText`:**  Appear to be basic supported elements.
* **`VisitQuantifier`:**  Complex logic. Notes limitations related to large repetitions and possessive quantifiers.
* **`VisitCapture`:**  Mentions limitations with capture groups inside positive lookbehinds.
* **`VisitGroup`:**  Deals with flag modifiers within groups.
* **`VisitLookaround`:**  Limitations with sticky/global flags and lookbehinds.
* **`VisitBackReference`:**  Clearly states it's not supported due to the need for backtracking.
* **`VisitEmpty`:**  A simple case.

**4. Analyzing `BytecodeAssembler`:**

This class is responsible for generating the "bytecode". I examine each method and infer its purpose based on the name and parameters:

* **`Accept`:** Likely marks the end of a successful match.
* **`Assertion`:** Emits an instruction for an assertion (e.g., `^`, `$`).
* **`ClearRegister`, `SetRegisterToCp`:**  Related to capturing groups and storing match positions.
* **`ConsumeRange`, `ConsumeAnyChar`:**  Matching characters.
* **`Fork`, `Jmp`:** Control flow instructions for branching.
* **`BeginLoop`, `EndLoop`:**  For handling quantifiers.
* **`WriteLookTable`, `ReadLookTable`:**  Specifically for lookbehind assertions.
* **`SetQuantifierToClock`, `FilterQuantifier`, `FilterGroup`, `FilterChild`:**  Relate to the capture group optimization.
* **`Bind`:**  Associates a label with a specific point in the bytecode.
* **`Fail`:**  Marks a failed match.

**5. Analyzing `FilterGroupsCompileVisitor`:**

This visitor seems to be responsible for generating extra bytecode for the capture group optimization. It focuses on `FILTER_GROUP`, `FILTER_QUANTIFIER`, and `FILTER_CHILD` instructions.

**6. Analyzing `CompileVisitor`:**

This is the main compiler. It uses the `BytecodeAssembler` to generate the bytecode. I look at the `Visit...` methods and how they translate RegExp tree nodes into bytecode instructions. I pay attention to:

* **Preamble for non-anchored regexps:**  The `.*?` logic.
* **Handling of disjunctions (OR):** The `FORK` and `JMP` pattern.
* **Character classes:**  Conversion to `ConsumeRange`.
* **Atoms (literal strings):**  Sequence of `ConsumeRange`.
* **Quantifiers (`*`, `+`, `?`, `{}`):** Complex logic involving `FORK`, `JMP`, `BEGIN_LOOP`, `END_LOOP`. Note the separate handling of greedy and non-greedy quantifiers.
* **Capturing groups:**  Using `SetRegisterToCp`.
* **Lookarounds:** Using `ReadLookTable` and the separate compilation of lookbehind bytecode.
* **Backreferences:**  Marked as unsupported.

**7. Identifying JavaScript Connections and Examples:**

As I understand the C++ code's function (compiling regexps), the connection to JavaScript becomes clear. The C++ code is part of V8, the JavaScript engine. The `ExperimentalRegExpCompiler` is a *potential* way V8 could handle regular expressions.

To create JavaScript examples, I consider the limitations and features mentioned in the C++ code:

* **Supported Flags:** I create examples with and without the supported flags.
* **Unsupported Features:** I create examples using backreferences and class set expressions to demonstrate what *won't* be handled by this experimental compiler.
* **Lookbehinds:** I illustrate lookbehinds, keeping in mind the restrictions (no sticky/global flags).
* **Capture Groups:**  I show basic capture groups.
* **Quantifiers:** I demonstrate basic usage of quantifiers.

**8. Structuring the Explanation:**

Finally, I organize the information into a clear and understandable explanation, starting with a high-level summary, then detailing the functionality of each class and relating it back to JavaScript. I also emphasize the "experimental" nature and the limitations. The JavaScript examples are crucial for making the explanation concrete.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This might be about directly executing the RegExp tree."  **Correction:** The `BytecodeAssembler` and the mention of "bytecode" indicate a compilation step to an intermediate representation.
* **Initial thought:** "All quantifiers are handled the same way." **Correction:**  The code shows distinct handling for greedy vs. non-greedy, and optimizations for non-nullable plus quantifiers.
* **Realization:**  The `FilterGroupsCompileVisitor` is not a core requirement but an *optimization*. This helps in understanding its purpose.
* **Emphasis on "Experimental":**  Constantly reminding myself and the reader that this is not the standard or necessarily complete regexp engine in V8 is important.

By following these steps, combining code analysis with an understanding of the context (V8, regular expressions, compilation), and using iterative refinement, I arrive at a comprehensive and accurate explanation with illustrative JavaScript examples.
这个C++源代码文件 `experimental-compiler.cc` 是 V8 JavaScript 引擎中一个**实验性的正则表达式编译器**的实现。它的主要功能是将一个正则表达式的抽象语法树 (AST) 转换为一种自定义的**字节码 (bytecode)**，这种字节码可以被 V8 引擎的实验性正则表达式执行器执行。

**核心功能归纳：**

1. **`CanBeHandled` 函数：**
   - 检查给定的正则表达式 (通过 `RegExpTree` 表示) 和标志 (`RegExpFlags`) 是否可以被这个实验性编译器处理。
   - 它通过 `CanBeHandledVisitor` 类遍历正则表达式的 AST，检查是否存在不支持的语法结构或标志。
   - 目前存在诸多限制，例如不支持 UTF-16、部分标志、某些量词类型、后向引用等。

2. **`Compile` 函数：**
   - 将一个可以被处理的正则表达式 AST 编译成字节码指令序列 (`ZoneList<RegExpInstruction>`)。
   - 它使用 `CompileVisitor` 类遍历 AST 并生成相应的字节码指令。
   - `BytecodeAssembler` 类用于构建字节码指令序列，提供诸如 `Fork` (分支)、`Jmp` (跳转)、`ConsumeRange` (匹配字符范围) 等指令。
   - 针对捕获组的优化，存在一个 `FilterGroupsCompileVisitor` 类，用于生成额外的字节码来过滤在量词迭代中未匹配的捕获组。

**与 JavaScript 功能的关系：**

这个文件直接关系到 JavaScript 中正则表达式的功能。当你在 JavaScript 中创建一个正则表达式（例如 `new RegExp()` 或使用字面量 `/.../`），V8 引擎需要将这个正则表达式编译成内部可以执行的形式。这个 `experimental-compiler.cc` 文件提供了一种**可选的、实验性的**编译策略。

**JavaScript 举例说明：**

假设这个实验性编译器在 V8 中被激活（通常需要通过命令行标志），以下是一些 JavaScript 正则表达式的例子，以及它们可能在这个编译器中如何被处理（注意：由于是实验性的，实际行为可能有所不同）：

**1. 支持的简单正则表达式：**

```javascript
const regex1 = /abc/; // 简单的字面量匹配
const regex2 = new RegExp("d+", "g"); // 匹配一个或多个 "d"，全局匹配
const regex3 = /e*f/m; // 匹配零个或多个 "e" 后跟 "f"，多行模式
```

这些正则表达式如果符合 `CanBeHandled` 的条件（例如没有不支持的特性），则 `Compile` 函数会将它们转换为字节码。例如，`/abc/` 可能会被编译成一系列 `ConsumeRange` 指令，分别匹配 'a'、'b' 和 'c'。

**2. 可能不支持的正则表达式 (取决于实验性编译器的当前限制)：**

```javascript
const regex4 = /(?<name>ghi)\k<name>/; // 命名捕获组的反向引用 (backreference)
const regex5 = /[\p{ASCII}]/; // Unicode 属性转义
const regex6 = /j{100}/; // 非常大的有限量词
```

- `regex4` 包含后向引用 (`\k<name>`)，根据代码注释，这可能是目前不支持的。`CanBeHandled` 会返回 `false`。
- `regex5` 使用 Unicode 属性转义，如果实验性编译器不支持完整的 Unicode 处理，则可能无法处理。
- `regex6` 包含一个非常大的有限量词，`CanBeHandledVisitor` 中有逻辑限制量词的最大重复次数。

**3. 包含支持的标志的正则表达式：**

```javascript
const regex7 = /klm/g; // 全局匹配
const regex8 = /nop/y; // 粘性匹配
const regex9 = /qrs/m; // 多行模式
const regex10 = /tuv/s; // dotAll 模式
```

这些使用了 `AreSuitableFlags` 中允许的标志，因此如果正则表达式的结构也支持，则可以被编译。

**总结：**

`experimental-compiler.cc` 是 V8 引擎中一个正在开发的组件，旨在提供一种新的正则表达式编译方法。它尝试将正则表达式转换为一种更低级的字节码表示，以便 V8 引擎能够执行匹配操作。然而，由于是实验性的，它存在许多限制，并非所有的 JavaScript 正则表达式都能被其处理。它的存在为 V8 引擎的正则表达式性能优化和新特性引入提供了探索的途径。当 V8 执行 JavaScript 代码中的正则表达式时，可能会选择使用这个实验性编译器（如果启用且正则表达式符合条件），或者使用其它的正则表达式编译和执行机制。

### 提示词
```
这是目录为v8/src/regexp/experimental/experimental-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/regexp/experimental/experimental-compiler.h"

#include "src/base/strings.h"
#include "src/flags/flags.h"
#include "src/regexp/experimental/experimental.h"
#include "src/regexp/regexp-flags.h"
#include "src/zone/zone-containers.h"
#include "src/zone/zone-list-inl.h"

namespace v8 {
namespace internal {

namespace {

// TODO(mbid, v8:10765): Currently the experimental engine doesn't support
// UTF-16, but this shouldn't be too hard to implement.
constexpr base::uc32 kMaxSupportedCodepoint = 0xFFFFu;
#ifdef DEBUG
constexpr base::uc32 kMaxCodePoint = 0x10ffff;
#endif  // DEBUG

class CanBeHandledVisitor final : private RegExpVisitor {
  // Visitor to implement `ExperimentalRegExp::CanBeHandled`.
 public:
  static bool Check(RegExpTree* tree, RegExpFlags flags, int capture_count) {
    if (!AreSuitableFlags(flags)) return false;
    CanBeHandledVisitor visitor{flags};
    tree->Accept(&visitor, nullptr);
    return visitor.result_;
  }

 private:
  explicit CanBeHandledVisitor(RegExpFlags flags) : flags_(flags) {}

  static bool AreSuitableFlags(RegExpFlags flags) {
    // TODO(mbid, v8:10765): We should be able to support all flags in the
    // future.
    static constexpr RegExpFlags kAllowedFlags =
        RegExpFlag::kGlobal | RegExpFlag::kSticky | RegExpFlag::kMultiline |
        RegExpFlag::kDotAll | RegExpFlag::kLinear;
    // We support Unicode iff kUnicode is among the supported flags.
    static_assert(ExperimentalRegExp::kSupportsUnicode ==
                  IsUnicode(kAllowedFlags));
    return (flags & ~kAllowedFlags) == 0;
  }

  void* VisitDisjunction(RegExpDisjunction* node, void*) override {
    for (RegExpTree* alt : *node->alternatives()) {
      alt->Accept(this, nullptr);
      if (!result_) {
        return nullptr;
      }
    }
    return nullptr;
  }

  void* VisitAlternative(RegExpAlternative* node, void*) override {
    for (RegExpTree* child : *node->nodes()) {
      child->Accept(this, nullptr);
      if (!result_) {
        return nullptr;
      }
    }
    return nullptr;
  }

  void* VisitClassRanges(RegExpClassRanges* node, void*) override {
    return nullptr;
  }

  void* VisitClassSetOperand(RegExpClassSetOperand* node, void*) override {
    result_ = !node->has_strings();
    return nullptr;
  }

  void* VisitClassSetExpression(RegExpClassSetExpression* node,
                                void*) override {
    result_ = false;
    return nullptr;
  }

  void* VisitAssertion(RegExpAssertion* node, void*) override {
    return nullptr;
  }

  void* VisitAtom(RegExpAtom* node, void*) override { return nullptr; }

  void* VisitText(RegExpText* node, void*) override {
    for (TextElement& el : *node->elements()) {
      el.tree()->Accept(this, nullptr);
      if (!result_) {
        return nullptr;
      }
    }
    return nullptr;
  }

  void* VisitQuantifier(RegExpQuantifier* node, void*) override {
    // Finite but large values of `min()` and `max()` are bad for the
    // breadth-first engine because finite (optional) repetition is dealt with
    // by replicating the bytecode of the body of the quantifier.  The number
    // of replications grows exponentially in how deeply quantifiers are nested.
    // `replication_factor_` keeps track of how often the current node will
    // have to be replicated in the generated bytecode, and we don't allow this
    // to exceed some small value.
    static constexpr int kMaxReplicationFactor = 16;

    // First we rule out values for min and max that are too big even before
    // taking into account the ambient replication_factor_.  This also guards
    // against overflows in `local_replication` or `replication_factor_`.
    if (node->min() > kMaxReplicationFactor ||
        (node->max() != RegExpTree::kInfinity &&
         node->max() > kMaxReplicationFactor)) {
      result_ = false;
      return nullptr;
    }

    // Save the current replication factor so that it can be restored if we
    // return with `result_ == true`.
    int before_replication_factor = replication_factor_;

    int local_replication;
    if (node->max() == RegExpTree::kInfinity) {
      if (node->min() > 0 && node->min_match() > 0) {
        // Quantifier can be reduced to a non nullable plus.
        local_replication = std::max(node->min(), 1);
      } else {
        local_replication = node->min() + 1;
      }
    } else {
      local_replication = node->max();
    }

    replication_factor_ *= local_replication;
    if (replication_factor_ > kMaxReplicationFactor) {
      result_ = false;
      return nullptr;
    }

    switch (node->quantifier_type()) {
      case RegExpQuantifier::GREEDY:
      case RegExpQuantifier::NON_GREEDY:
        break;
      case RegExpQuantifier::POSSESSIVE:
        // TODO(mbid, v8:10765): It's not clear to me whether this can be
        // supported in breadth-first mode. Re2 doesn't support it.
        result_ = false;
        return nullptr;
    }

    node->body()->Accept(this, nullptr);
    replication_factor_ = before_replication_factor;
    return nullptr;
  }

  void* VisitCapture(RegExpCapture* node, void*) override {
    if (inside_positive_lookbehind_) {
      // Positive lookbehinds with capture groups are not currently supported
      result_ = false;
    } else {
      node->body()->Accept(this, nullptr);
    }

    return nullptr;
  }

  void* VisitGroup(RegExpGroup* node, void*) override {
    if (flags() != node->flags()) {
      // Flags that aren't supported by the experimental engine at all, are not
      // supported via modifiers either.
      // TODO(pthier): Currently the only flag supported in modifiers and in
      // the experimental engine is multi-line, which is already handled in the
      // parser. If more flags are supported either by the experimental engine
      // or in modifiers we need to add general support for modifiers to the
      // experimental engine.
      if (!AreSuitableFlags(node->flags())) {
        result_ = false;
        return nullptr;
      }
    }
    node->body()->Accept(this, nullptr);
    return nullptr;
  }

  void* VisitLookaround(RegExpLookaround* node, void*) override {
    bool parent_is_positive_lookbehind = inside_positive_lookbehind_;
    inside_positive_lookbehind_ = node->is_positive();

    // The current lookbehind implementation does not support sticky or global
    // flags.
    if (node->type() == RegExpLookaround::Type::LOOKAHEAD ||
        IsGlobal(flags()) || IsSticky(flags())) {
      result_ = false;
    } else {
      node->body()->Accept(this, nullptr);
    }

    inside_positive_lookbehind_ = parent_is_positive_lookbehind;
    return nullptr;
  }

  void* VisitBackReference(RegExpBackReference* node, void*) override {
    // This can't be implemented without backtracking.
    result_ = false;
    return nullptr;
  }

  void* VisitEmpty(RegExpEmpty* node, void*) override { return nullptr; }

 private:
  RegExpFlags flags() const { return flags_; }

  // See comment in `VisitQuantifier`:
  int replication_factor_ = 1;

  // The current implementation does not support capture groups in positive
  // lookbehinds.
  bool inside_positive_lookbehind_ = false;

  bool result_ = true;
  RegExpFlags flags_;
};

}  // namespace

bool ExperimentalRegExpCompiler::CanBeHandled(RegExpTree* tree,
                                              RegExpFlags flags,
                                              int capture_count) {
  return CanBeHandledVisitor::Check(tree, flags, capture_count);
}

namespace {

// A label in bytecode which starts with no known address. The address *must*
// be bound with `Bind` before the label goes out of scope.
// Implemented as a linked list through the `payload.pc` of FORK and JMP
// instructions.
struct Label {
 public:
  Label() = default;
  ~Label() {
    DCHECK_EQ(state_, BOUND);
    DCHECK_GE(bound_index_, 0);
  }

  // Don't copy, don't move.  Moving could be implemented, but it's not
  // needed anywhere.
  Label(const Label&) = delete;
  Label& operator=(const Label&) = delete;

 private:
  friend class BytecodeAssembler;

  // UNBOUND implies unbound_patch_list_begin_.
  // BOUND implies bound_index_.
  enum { UNBOUND, BOUND } state_ = UNBOUND;
  union {
    int unbound_patch_list_begin_ = -1;
    int bound_index_;
  };
};

class BytecodeAssembler {
 public:
  // TODO(mbid,v8:10765): Use some upper bound for code_ capacity computed from
  // the `tree` size we're going to compile?
  explicit BytecodeAssembler(Zone* zone) : zone_(zone), code_(0, zone) {}

  ZoneList<RegExpInstruction> IntoCode() && { return std::move(code_); }

  void Accept() { code_.Add(RegExpInstruction::Accept(), zone_); }

  void Assertion(RegExpAssertion::Type t) {
    code_.Add(RegExpInstruction::Assertion(t), zone_);
  }

  void ClearRegister(int32_t register_index) {
    code_.Add(RegExpInstruction::ClearRegister(register_index), zone_);
  }

  void ConsumeRange(base::uc16 from, base::uc16 to) {
    code_.Add(RegExpInstruction::ConsumeRange(from, to), zone_);
  }

  void ConsumeAnyChar() {
    code_.Add(RegExpInstruction::ConsumeAnyChar(), zone_);
  }

  void Fork(Label& target) {
    LabelledInstrImpl(RegExpInstruction::Opcode::FORK, target);
  }

  void Jmp(Label& target) {
    LabelledInstrImpl(RegExpInstruction::Opcode::JMP, target);
  }

  void SetRegisterToCp(int32_t register_index) {
    code_.Add(RegExpInstruction::SetRegisterToCp(register_index), zone_);
  }

  void BeginLoop() { code_.Add(RegExpInstruction::BeginLoop(), zone_); }

  void EndLoop() { code_.Add(RegExpInstruction::EndLoop(), zone_); }

  void WriteLookTable(int index) {
    code_.Add(RegExpInstruction::WriteLookTable(index), zone_);
  }

  void ReadLookTable(int index, bool is_positive) {
    code_.Add(RegExpInstruction::ReadLookTable(index, is_positive), zone_);
  }

  void SetQuantifierToClock(int32_t quantifier_id) {
    code_.Add(RegExpInstruction::SetQuantifierToClock(quantifier_id), zone_);
  }

  void FilterQuantifier(int32_t quantifier_id) {
    code_.Add(RegExpInstruction::FilterQuantifier(quantifier_id), zone_);
  }

  void FilterGroup(int32_t group_id) {
    code_.Add(RegExpInstruction::FilterGroup(group_id), zone_);
  }

  void FilterChild(Label& target) {
    LabelledInstrImpl(RegExpInstruction::Opcode::FILTER_CHILD, target);
  }

  void Bind(Label& target) {
    DCHECK_EQ(target.state_, Label::UNBOUND);

    int index = code_.length();

    while (target.unbound_patch_list_begin_ != -1) {
      RegExpInstruction& inst = code_[target.unbound_patch_list_begin_];
      DCHECK(inst.opcode == RegExpInstruction::FORK ||
             inst.opcode == RegExpInstruction::JMP ||
             inst.opcode == RegExpInstruction::FILTER_CHILD);

      target.unbound_patch_list_begin_ = inst.payload.pc;
      inst.payload.pc = index;
    }

    target.state_ = Label::BOUND;
    target.bound_index_ = index;
  }

  void Fail() { code_.Add(RegExpInstruction::Fail(), zone_); }

 private:
  void LabelledInstrImpl(RegExpInstruction::Opcode op, Label& target) {
    RegExpInstruction result;
    result.opcode = op;

    if (target.state_ == Label::BOUND) {
      result.payload.pc = target.bound_index_;
    } else {
      DCHECK_EQ(target.state_, Label::UNBOUND);
      int new_list_begin = code_.length();
      DCHECK_GE(new_list_begin, 0);

      result.payload.pc = target.unbound_patch_list_begin_;

      target.unbound_patch_list_begin_ = new_list_begin;
    }

    code_.Add(result, zone_);
  }

  Zone* zone_;
  ZoneList<RegExpInstruction> code_;
};

class FilterGroupsCompileVisitor final : private RegExpVisitor {
 public:
  static void CompileFilter(Zone* zone, RegExpTree* tree,
                            BytecodeAssembler& assembler,
                            const ZoneMap<int, int>& quantifier_id_remapping) {
    /* To filter out groups that were not matched in the last iteration of a
     * quantifier, the regexp's AST is compiled using a special sets of
     * instructions: `FILTER_GROUP`, `FILTER_QUANTIFIER` and `FILTER_CHILD`.
     * They encode a simplified AST containing only the groups and quantifiers.
     * Each node is represented as either a `FILTER_GROUP` or a
     * `FILTER_QUANTIFIER` instruction, containing the index of the respective
     * group or quantifier, followed by a variable number of `FILTER_CHILD`
     * instructions each containing the index of their respective node in the
     * bytecode.
     *
     * The regexp's AST is traversed in breadth-first mode, compiling one node
     * at a time, while saving its children in a queue. */

    FilterGroupsCompileVisitor visitor(assembler, zone,
                                       quantifier_id_remapping);

    tree->Accept(&visitor, nullptr);

    while (!visitor.nodes_.empty()) {
      auto& entry = visitor.nodes_.front();

      visitor.assembler_.Bind(entry.label);
      visitor.compile_capture_or_quant_ = true;
      entry.node->Accept(&visitor, nullptr);

      visitor.nodes_.pop_front();
    }
  }

 private:
  FilterGroupsCompileVisitor(BytecodeAssembler& assembler, Zone* zone,
                             const ZoneMap<int, int>& quantifier_id_remapping)
      : zone_(zone),
        assembler_(assembler),
        nodes_(zone_),
        quantifier_id_remapping_(quantifier_id_remapping),
        compile_capture_or_quant_(false) {}

  void* VisitDisjunction(RegExpDisjunction* node, void*) override {
    for (RegExpTree* alt : *node->alternatives()) {
      alt->Accept(this, nullptr);
    }
    return nullptr;
  }

  void* VisitAlternative(RegExpAlternative* node, void*) override {
    for (RegExpTree* alt : *node->nodes()) {
      alt->Accept(this, nullptr);
    }
    return nullptr;
  }

  void* VisitClassRanges(RegExpClassRanges* node, void*) override {
    return nullptr;
  }

  void* VisitClassSetOperand(RegExpClassSetOperand* node, void*) override {
    return nullptr;
  }

  void* VisitClassSetExpression(RegExpClassSetExpression* node,
                                void*) override {
    return nullptr;
  }

  void* VisitAssertion(RegExpAssertion* node, void*) override {
    return nullptr;
  }

  void* VisitAtom(RegExpAtom* node, void*) override { return nullptr; }

  void* VisitText(RegExpText* node, void*) override { return nullptr; }

  void* VisitQuantifier(RegExpQuantifier* node, void*) override {
    if (compile_capture_or_quant_) {
      assembler_.FilterQuantifier(quantifier_id_remapping_.at(node->index()));
      compile_capture_or_quant_ = false;
      node->body()->Accept(this, nullptr);
    } else {
      if (node->CaptureRegisters().is_empty()) {
        return nullptr;
      }

      nodes_.emplace_back(node);
      assembler_.FilterChild(nodes_.back().label);
    }

    return nullptr;
  }

  void* VisitCapture(RegExpCapture* node, void*) override {
    if (compile_capture_or_quant_) {
      assembler_.FilterGroup(node->index());
      compile_capture_or_quant_ = false;
      node->body()->Accept(this, nullptr);
    } else {
      nodes_.emplace_back(node);
      assembler_.FilterChild(nodes_.back().label);
    }

    return nullptr;
  }

  void* VisitGroup(RegExpGroup* node, void*) override {
    node->body()->Accept(this, nullptr);
    return nullptr;
  }

  void* VisitLookaround(RegExpLookaround* node, void*) override {
    return nullptr;
  }

  void* VisitBackReference(RegExpBackReference* node, void*) override {
    return nullptr;
  }

  void* VisitEmpty(RegExpEmpty* node, void*) override { return nullptr; }

 private:
  // Entry in the nodes queue. Contains the node to compile and a label to bind
  // at the start of its bytecode.
  class BFEntry {
   public:
    explicit BFEntry(RegExpTree* node) : label(), node(node) {}

    Label label;
    RegExpTree* node;
  };

  Zone* zone_;

  BytecodeAssembler& assembler_;
  ZoneLinkedList<BFEntry> nodes_;

  const ZoneMap<int, int>& quantifier_id_remapping_;

  // Whether we can compile a capture group or quantifier. This is set to true
  // after popping an element from the queue, and false after having compiled
  // one. When false, encountered capture groups and quantifiers are pushed on
  // the queue.
  bool compile_capture_or_quant_;
};

class CompileVisitor : private RegExpVisitor {
 public:
  static ZoneList<RegExpInstruction> Compile(RegExpTree* tree,
                                             RegExpFlags flags, Zone* zone) {
    CompileVisitor compiler(zone);

    if (!IsSticky(flags) && !tree->IsAnchoredAtStart()) {
      // The match is not anchored, i.e. may start at any input position, so we
      // emit a preamble corresponding to /.*?/.  This skips an arbitrary
      // prefix in the input non-greedily.
      compiler.CompileNonGreedyStar(
          [&]() { compiler.assembler_.ConsumeAnyChar(); });
    }

    compiler.assembler_.SetRegisterToCp(0);
    tree->Accept(&compiler, nullptr);
    compiler.assembler_.SetRegisterToCp(1);
    compiler.assembler_.Accept();

    if (v8_flags.experimental_regexp_engine_capture_group_opt) {
      FilterGroupsCompileVisitor::CompileFilter(
          zone, tree, compiler.assembler_,
          compiler.quantifier_id_remapping_.value());
    }

    // To handle captureless lookbehinds, we run independent automata for each
    // lookbehind in lockstep with the main expression. To do so, we compile
    // each lookbehind to a separate bytecode that we append to the main
    // expression bytecode. At the end of each lookbehind, we add a
    // WriteLookTable instruction, writing to a truth table that the lookbehind
    // holds at the current position.
    //
    // This approach prevents the use of the sticky or global flags. In both
    // cases, when resuming the search, it starts at a non null index, while the
    // lookbehinds always need to start at the beginning of the string. A future
    // implementation for the global flag may store the active lookbehind
    // threads in the regexp to resume the execution of the lookbehinds
    // automata.
    compiler.inside_lookaround_ = true;
    while (!compiler.lookbehinds_.empty()) {
      auto node = compiler.lookbehinds_.front();

      // Lookbehinds are never anchored, i.e. may start at any input position,
      // so we emit a preamble corresponding to /.*?/.  This skips an arbitrary
      // prefix in the input.
      compiler.CompileNonGreedyStar(
          [&]() { compiler.assembler_.ConsumeAnyChar(); });

      node->body()->Accept(&compiler, nullptr);
      compiler.assembler_.WriteLookTable(node->index());
      compiler.lookbehinds_.pop_front();
    }

    return std::move(compiler.assembler_).IntoCode();
  }

 private:
  explicit CompileVisitor(Zone* zone)
      : zone_(zone),
        lookbehinds_(zone),
        quantifier_id_remapping_({}),
        assembler_(zone),
        inside_lookaround_(false) {
    if (v8_flags.experimental_regexp_engine_capture_group_opt) {
      quantifier_id_remapping_.emplace(zone_);
    }
  }

  // Generate a disjunction of code fragments compiled by a function `alt_gen`.
  // `alt_gen` is called repeatedly with argument `int i = 0, 1, ..., alt_num -
  // 1` and should build code corresponding to the ith alternative.
  template <class F>
  void CompileDisjunction(int alt_num, F&& gen_alt) {
    // An alternative a1 | ... | an is compiled into
    //
    //     FORK tail1
    //     <a1>
    //     JMP end
    //   tail1:
    //     FORK tail2
    //     <a2>
    //     JMP end
    //   tail2:
    //     ...
    //     ...
    //   tail{n -1}:
    //     <an>
    //   end:
    //
    // By the semantics of the FORK instruction (see above at definition and
    // semantics), a forked thread has lower priority than the thread that
    // spawned it.  This means that with the code we're generating here, the
    // thread matching the alternative a1 has indeed highest priority, followed
    // by the thread for a2 and so on.

    if (alt_num == 0) {
      // The empty disjunction.  This can never match.
      assembler_.Fail();
      return;
    }

    Label end;

    for (int i = 0; i != alt_num - 1; ++i) {
      Label tail;
      assembler_.Fork(tail);
      gen_alt(i);
      assembler_.Jmp(end);
      assembler_.Bind(tail);
    }

    gen_alt(alt_num - 1);

    assembler_.Bind(end);
  }

  void* VisitDisjunction(RegExpDisjunction* node, void*) override {
    ZoneList<RegExpTree*>& alts = *node->alternatives();
    CompileDisjunction(alts.length(),
                       [&](int i) { alts[i]->Accept(this, nullptr); });
    return nullptr;
  }

  void* VisitAlternative(RegExpAlternative* node, void*) override {
    for (RegExpTree* child : *node->nodes()) {
      child->Accept(this, nullptr);
    }
    return nullptr;
  }

  void* VisitAssertion(RegExpAssertion* node, void*) override {
    assembler_.Assertion(node->assertion_type());
    return nullptr;
  }

  void CompileCharacterRanges(ZoneList<CharacterRange>* ranges, bool negated) {
    // A character class is compiled as Disjunction over its `CharacterRange`s.
    CharacterRange::Canonicalize(ranges);
    if (negated) {
      // The complement of a disjoint, non-adjacent (i.e. `Canonicalize`d)
      // union of k intervals is a union of at most k + 1 intervals.
      ZoneList<CharacterRange>* negated =
          zone_->New<ZoneList<CharacterRange>>(ranges->length() + 1, zone_);
      CharacterRange::Negate(ranges, negated, zone_);
      DCHECK_LE(negated->length(), ranges->length() + 1);
      ranges = negated;
    }

    CompileDisjunction(ranges->length(), [&](int i) {
      // We don't support utf16 for now, so only ranges that can be specified
      // by (complements of) ranges with base::uc16 bounds.
      static_assert(kMaxSupportedCodepoint <=
                    std::numeric_limits<base::uc16>::max());

      base::uc32 from = (*ranges)[i].from();
      DCHECK_LE(from, kMaxSupportedCodepoint);
      base::uc16 from_uc16 = static_cast<base::uc16>(from);

      base::uc32 to = (*ranges)[i].to();
      DCHECK_IMPLIES(to > kMaxSupportedCodepoint, to == kMaxCodePoint);
      base::uc16 to_uc16 =
          static_cast<base::uc16>(std::min(to, kMaxSupportedCodepoint));

      assembler_.ConsumeRange(from_uc16, to_uc16);
    });
  }

  void* VisitClassRanges(RegExpClassRanges* node, void*) override {
    CompileCharacterRanges(node->ranges(zone_), node->is_negated());
    return nullptr;
  }

  void* VisitClassSetOperand(RegExpClassSetOperand* node, void*) override {
    // TODO(v8:11935): Support strings.
    DCHECK(!node->has_strings());
    CompileCharacterRanges(node->ranges(), false);
    return nullptr;
  }

  void* VisitClassSetExpression(RegExpClassSetExpression* node,
                                void*) override {
    // TODO(v8:11935): Add support.
    UNREACHABLE();
  }

  void* VisitAtom(RegExpAtom* node, void*) override {
    for (base::uc16 c : node->data()) {
      assembler_.ConsumeRange(c, c);
    }
    return nullptr;
  }

  void ClearRegisters(Interval indices) {
    if (indices.is_empty()) return;
    DCHECK_EQ(indices.from() % 2, 0);
    DCHECK_EQ(indices.to() % 2, 1);
    for (int i = indices.from(); i <= indices.to(); i += 2) {
      // It suffices to clear the register containing the `begin` of a capture
      // because this indicates that the capture is undefined, regardless of
      // the value in the `end` register.
      assembler_.ClearRegister(i);
    }
  }

  // Emit bytecode corresponding to /<emit_body>*/.
  template <class F>
  void CompileGreedyStar(F&& emit_body) {
    // This is compiled into
    //
    //   begin:
    //     FORK end
    //     BEGIN_LOOP
    //     <body>
    //     END_LOOP
    //     JMP begin
    //   end:
    //     ...
    //
    // This is greedy because a forked thread has lower priority than the
    // thread that spawned it.
    Label begin;
    Label end;

    assembler_.Bind(begin);
    assembler_.Fork(end);
    assembler_.BeginLoop();
    emit_body();
    assembler_.EndLoop();
    assembler_.Jmp(begin);

    assembler_.Bind(end);
  }

  // Emit bytecode corresponding to /<emit_body>*?/.
  template <class F>
  void CompileNonGreedyStar(F&& emit_body) {
    // This is compiled into
    //
    //     FORK body
    //     JMP end
    //   body:
    //     BEGIN_LOOP
    //     <body>
    //     END_LOOP
    //     FORK body
    //   end:
    //     ...

    Label body;
    Label end;

    assembler_.Fork(body);
    assembler_.Jmp(end);

    assembler_.Bind(body);
    assembler_.BeginLoop();
    emit_body();
    assembler_.EndLoop();
    assembler_.Fork(body);

    assembler_.Bind(end);
  }

  // Emit bytecode corresponding to /<emit_body>{0, max_repetition_num}/.
  template <class F>
  void CompileGreedyRepetition(F&& emit_body, int max_repetition_num) {
    // This is compiled into
    //
    //     FORK end
    //     BEGIN_LOOP
    //     <body>
    //     END_LOOP
    //     FORK end
    //     BEGIN_LOOP
    //     <body>
    //     END_LOOP
    //     ...
    //     ...
    //     FORK end
    //     <body>
    //   end:
    //     ...
    //
    // We add `BEGIN_LOOP` and `END_LOOP` instructions because these optional
    // repetitions of the body cannot match the empty string.

    Label end;
    for (int i = 0; i != max_repetition_num; ++i) {
      assembler_.Fork(end);
      assembler_.BeginLoop();
      emit_body();
      assembler_.EndLoop();
    }
    assembler_.Bind(end);
  }

  // Emit bytecode corresponding to /<emit_body>{0, max_repetition_num}?/.
  template <class F>
  void CompileNonGreedyRepetition(F&& emit_body, int max_repetition_num) {
    // This is compiled into
    //
    //     FORK body0
    //     JMP end
    //   body0:
    //     BEGIN_LOOP
    //     <body>
    //     END_LOOP
    //
    //     FORK body1
    //     JMP end
    //   body1:
    //     BEGIN_LOOP
    //     <body>
    //     END_LOOP
    //     ...
    //     ...
    //   body{max_repetition_num - 1}:
    //     BEGIN_LOOP
    //     <body>
    //     END_LOOP
    //   end:
    //     ...
    //
    // We add `BEGIN_LOOP` and `END_LOOP` instructions because these optional
    // repetitions of the body cannot match the empty string.

    Label end;
    for (int i = 0; i != max_repetition_num; ++i) {
      Label body;
      assembler_.Fork(body);
      assembler_.Jmp(end);

      assembler_.Bind(body);
      assembler_.BeginLoop();
      emit_body();
      assembler_.EndLoop();
    }
    assembler_.Bind(end);
  }

  // In the general case, the first repetition of <body>+ is different
  // from the following ones as it is allowed to match the empty string. This is
  // compiled by repeating <body>, but it can result in a bytecode that grows
  // quadratically with the size of the regex when nesting pluses or repetition
  // upper-bounded with infinity.
  //
  // In the particular case where <body> cannot match the empty string, the
  // plus can be compiled without duplicating the bytecode of <body>, resulting
  // in a bytecode linear in the size of the regex in case of nested
  // non-nullable pluses.
  //
  // E.g. `/.+/` will compile `/./` once, while `/(?:.?)+/` will be compiled as
  // `/(?:.?)(?:.?)*/`, resulting in two repetitions of the body.

  // Emit bytecode corresponding to /<emit_body>+/, with <emit_body> not
  // nullable.
  template <class F>
  void CompileNonNullableGreedyPlus(F&& emit_body) {
    // This is compiled into
    //
    //   begin:
    //     <body>
    //
    //     FORK end
    //     JMP begin
    //   end:
    //     ...
    Label begin, end;

    assembler_.Bind(begin);
    emit_body();

    assembler_.Fork(end);
    assembler_.Jmp(begin);
    assembler_.Bind(end);
  }

  // Emit bytecode corresponding to /<emit_body>+?/, with <emit_body> not
  // nullable.
  template <class F>
  void CompileNonNullableNonGreedyPlus(F&& emit_body) {
    // This is compiled into
    //
    //   begin:
    //     <body>
    //
    //     FORK begin
    //     ...
    Label begin;

    assembler_.Bind(begin);
    emit_body();

    assembler_.Fork(begin);
  }

  void* VisitQuantifier(RegExpQuantifier* node, void*) override {
    // If the quantifier must match nothing, we do not produce its body, but
    // still need the `SET_QUANTIFIER_TO_CLOCK` for the Nfa to be able to
    // correctly determine the number of quantifiers.
    if (v8_flags.experimental_regexp_engine_capture_group_opt &&
        node->max() == 0) {
      if (!node->CaptureRegisters().is_empty()) {
        assembler_.SetQuantifierToClock(RemapQuantifier(node->index()));
      }

      return nullptr;
    }

    // Emit the body, but clear registers occurring in body first.
    //
    // TODO(mbid,v8:10765): It's not always necessary to a) capture registers
    // and b) clear them. For example, we don't have to capture anything for
    // the first 4 repetitions if node->min() >= 5, and then we don't have to
    // clear registers in the first node->min() repetitions.
    // Later, and if node->min() == 0, we don't have to clear registers before
    // the first optional repetition.
    Interval body_registers = node->body()->CaptureRegisters();
    auto emit_body = [&]() {
      if (v8_flags.experimental_regexp_engine_capture_group_opt) {
        assembler_.SetQuantifierToClock(RemapQuantifier(node->index()));
      } else {
        ClearRegisters(body_registers);
      }

      node->body()->Accept(this, nullptr);
    };

    bool can_be_reduced_to_non_nullable_plus =
        node->min() > 0 && node->max() == RegExpTree::kInfinity &&
        node->min_match() > 0;

    if (can_be_reduced_to_non_nullable_plus) {
      // Compile <body>+ with an optimization allowing linear sized bytecode in
      // the case of nested pluses. Repetitions with infinite upperbound like
      // <body>{n,}, with n != 0, are compiled into <body>{n-1}<body+>, avoiding
      // one repetition, compared to <body>{n}<body>*.

      // Compile the mandatory repetitions. We repeat `min() - 1` times, such
      // that the last repetition, compiled later, can be reused in a loop.
      for (int i = 0; i < node->min() - 1; ++i) {
        emit_body();
      }

      // Compile the optional repetitions, using an optimized plus when
      // possible.
      switch (node->quantifier_type()) {
        case RegExpQuantifier::POSSESSIVE:
          UNREACHABLE();
        case RegExpQuantifier::GREEDY: {
          // Compile both last mandatory repetition and optional ones.
          CompileNonNullableGreedyPlus(emit_body);
          break;
        }
        case RegExpQuantifier::NON_GREEDY: {
          // Compile both last mandatory repetition and optional ones.
          CompileNonNullableNonGreedyPlus(emit_body);
          break;
        }
      }
    } else {
      // Compile <body>+ into <body><body>*, and <body>{n,}, with n != 0, into
      // <body>{n}<body>*.

      // Compile the first `min()` repetitions.
      for (int i = 0; i < node->min(); ++i) {
        emit_body();
      }

      // Compile the optional repetitions, using stars or repetitions.
      switch (node->quantifier_type()) {
        case RegExpQuantifier::POSSESSIVE:
          UNREACHABLE();
        case RegExpQuantifier::GREEDY: {
          if (node->max() == RegExpTree::kInfinity) {
            CompileGreedyStar(emit_body);
          } else {
            DCHECK_NE(node->max(), RegExpTree::kInfinity);
            CompileGreedyRepetition(emit_body, node->max() - node->min());
          }
          break;
        }
        case RegExpQuantifier::NON_GREEDY: {
          if (node->max() == RegExpTree::kInfinity) {
            CompileNonGreedyStar(emit_body);
          } else {
            DCHECK_NE(node->max(), RegExpTree::kInfinity);
            CompileNonGreedyRepetition(emit_body, node->max() - node->min());
          }
          break;
        }
      }
    }

    return nullptr;
  }

  void* VisitCapture(RegExpCapture* node, void*) override {
    // Only negative lookbehinds contain captures (enforced by the
    // `CanBeHandled` visitor). Capture groups inside negative lookarounds
    // always yield undefined, so we can avoid the SetRegister instructions.
    if (inside_lookaround_) {
      node->body()->Accept(this, nullptr);
    } else {
      int index = node->index();
      int start_register = RegExpCapture::StartRegister(index);
      int end_register = RegExpCapture::EndRegister(index);
      assembler_.SetRegisterToCp(start_register);
      node->body()->Accept(this, nullptr);
      assembler_.SetRegisterToCp(end_register);
    }

    return nullptr;
  }

  void* VisitGroup(RegExpGroup* node, void*) override {
    node->body()->Accept(this, nullptr);
    return nullptr;
  }

  void* VisitLookaround(RegExpLookaround* node, void*) override {
    assembler_.ReadLookTable(node->index(), node->is_positive());

    // Add the lookbehind to the queue of lookbehinds to be compiled.
    lookbehinds_.push_back(node);

    return nullptr;
  }

  void* VisitBackReference(RegExpBackReference* node, void*) override {
    UNREACHABLE();
  }

  void* VisitEmpty(RegExpEmpty* node, void*) override { return nullptr; }

  void* VisitText(RegExpText* node, void*) override {
    for (TextElement& text_el : *node->elements()) {
      text_el.tree()->Accept(this, nullptr);
    }
    return nullptr;
  }

  int RemapQuantifier(int id) {
    DCHECK(v8_flags.experimental_regexp_engine_capture_group_opt);
    DCHECK(quantifier_id_remapping_.has_value());
    auto& map = quantifier_id_remapping_.value();

    if (!map.contains(id)) {
      map[id] = static_cast<int>(map.size());
    }

    return map[id];
  }

 private:
  Zone* zone_;

  // Stores the AST of the lookbehinds encountered in a queue. They are compiled
  // after the main expression, in breadth-first order.
  ZoneLinkedList<RegExpLookaround*> lookbehinds_;

  std::optional<ZoneMap<int, int>> quantifier_id_remapping_;

  BytecodeAssembler assembler_;
  bool inside_lookaround_;
};

}  // namespace

ZoneList<RegExpInstruction> ExperimentalRegExpCompiler::Compile(
    RegExpTree* tree, RegExpFlags flags, Zone* zone) {
  return CompileVisitor::Compile(tree, flags, zone);
}

}  // namespace internal
}  // namespace v8
```