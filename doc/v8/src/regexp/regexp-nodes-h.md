Response:
Let's break down the thought process for analyzing the provided C++ header file.

**1. Initial Scan and Obvious Features:**

* **Copyright and License:**  The first few lines immediately indicate the origin (V8 project) and the licensing terms (BSD-style). This is standard for open-source projects.
* **Include Guards:** `#ifndef V8_REGEXP_REGEXP_NODES_H_` and `#define V8_REGEXP_REGEXP_NODES_H_` are classic include guards to prevent multiple inclusions and compilation errors.
* **Includes:**  The `#include` directives point to other V8-specific header files (`src/codegen/label.h`, `src/regexp/regexp-macro-assembler.h`, `src/zone/zone.h`). This suggests the file deals with some form of code generation related to regular expressions and uses V8's memory management (`Zone`).
* **Namespace:** The code is within the `v8::internal` namespace, clearly marking it as part of V8's internal implementation details.

**2. Core Data Structures - The "Nodes":**

* **`FOR_EACH_NODE_TYPE` Macro:** This is a strong indicator of a node-based design pattern. The macro lists various `VISIT`able types: `End`, `Action`, `Choice`, `LoopChoice`, etc. This immediately suggests a representation of a regular expression as a graph or tree of these nodes.
* **`FORWARD_DECLARE` Macro:**  This further confirms the existence of classes named like `EndNode`, `ActionNode`, etc., hinting at an inheritance hierarchy.
* **`RegExpNode` Base Class:**  This class seems to be the fundamental building block. It has methods like `Accept(NodeVisitor*)`, `Emit(RegExpCompiler*, Trace*)`, `EatsAtLeast()`, `GetQuickCheckDetails()`. These names strongly suggest the node participates in a process of traversal (`Accept`), code generation (`Emit`), and analysis for optimization (`EatsAtLeast`, `GetQuickCheckDetails`).

**3. Deeper Dive into `RegExpNode` and Related Structures:**

* **`NodeInfo` struct:** This struct stores metadata about each node: analysis flags (`being_analyzed`, `been_analyzed`), interest flags (`follows_word_interest`, etc.), and other state. This suggests the compiler performs some kind of static analysis on the RegExp node graph.
* **`EatsAtLeastInfo` struct:** This struct focuses on the minimum number of characters a node can consume. This is likely used for optimization, like early exit during matching.
* **Virtual Methods:** The numerous virtual methods in `RegExpNode` strongly imply polymorphism and a class hierarchy where different node types implement these methods in their own way.

**4. Specific Node Types - Guessing Functionality:**

* **`EndNode`:**  Likely represents the successful or unsuccessful end of a matching path.
* **`ActionNode`:**  Probably performs side effects during matching, such as capturing groups, setting registers for loops, etc. The `ActionType` enum confirms this.
* **`TextNode`:** Represents matching literal text or character classes.
* **`AssertionNode`:** Handles zero-width assertions like `^`, `$`, `\b`. The `AssertionType` enum confirms this.
* **`BackReferenceNode`:** Handles backreferences like `\1`.
* **`ChoiceNode` and `LoopChoiceNode`:**  Deal with alternation (`|`) and repetition (`*`, `+`, `{}`). The `LoopChoiceNode` is specifically for loops.
* **`NegativeLookaroundChoiceNode`:** Implements negative lookahead (`(?!...)`).

**5. Connecting to JavaScript (Hypothetical):**

Since it's part of V8, it's directly related to JavaScript's regular expression functionality. The thought process here involves imagining how JavaScript regex features are implemented internally:

* **`/.../` Syntax:** The C++ structures would represent the parsed form of a JavaScript regex.
* **Matching:** The `Emit` methods likely generate the low-level code (potentially assembly) that the V8 engine uses to perform the actual matching.
* **Capturing Groups:** The `ActionNode` with `STORE_POSITION` likely handles the capturing of substrings within parentheses.
* **Quantifiers:** `LoopChoiceNode` is the obvious candidate for implementing quantifiers.
* **Assertions:** `AssertionNode` directly corresponds to JavaScript's assertion syntax.

**6. Torque Consideration:**

The prompt mentions the `.tq` extension. Knowing that Torque is V8's domain-specific language for implementing built-in functions, the thinking is:

* If this file *were* a `.tq` file, it would be describing the *implementation* of the regex operations in a more high-level, type-safe way than raw C++. It would likely *use* the C++ classes defined in this header.

**7. Code Logic Inference (High Level):**

The structure suggests a graph traversal algorithm. The `Emit` methods on each node would contribute to generating the overall matching logic. The `EatsAtLeast` and `GetQuickCheckDetails` methods are for optimization, allowing the engine to potentially skip parts of the input or quickly determine a mismatch.

**8. Common Programming Errors (JavaScript Perspective):**

Thinking from a JavaScript developer's standpoint, common regex mistakes could relate to:

* **Greedy vs. Lazy Matching:** This might be related to how `LoopChoiceNode` is implemented.
* **Incorrect Backreferences:**  The `BackReferenceNode` implementation would need to ensure the referenced group exists and matches correctly.
* **Lookarounds:** Misunderstanding the behavior of lookaheads and lookbehinds. The `NegativeLookaroundChoiceNode` is directly relevant here.
* **Performance Issues:**  Complex regexes can be slow. The optimization efforts seen in `EatsAtLeast` and `GetQuickCheckDetails` are aimed at mitigating this.

**9. Summarization (Focusing on the "What"):**

The final summarization focuses on the *purpose* and *contents* of the header file, highlighting:

* Data structures for representing regexes.
* Node-based design.
* Information used for code generation and optimization.
* The relationship to JavaScript regex functionality.

This iterative process of scanning, identifying key patterns, making educated guesses, and connecting the pieces leads to a comprehensive understanding of the header file's role within the V8 project.这是v8源代码文件`v8/src/regexp/regexp-nodes.h`的功能归纳：

**核心功能：定义用于表示正则表达式的节点类和相关数据结构。**

这个头文件定义了一系列C++类，这些类是V8引擎在编译和执行正则表达式时，用于在内部表示正则表达式结构的 building blocks（构建块）。可以将这些类想象成正则表达式语法元素的软件模型。

**具体功能点:**

1. **定义正则表达式节点的抽象基类 `RegExpNode`:**
   - 提供了所有正则表达式节点共享的基础属性和方法。
   - 包含了用于代码生成 (`Emit`)、静态分析 (`EatsAtLeast`, `GetQuickCheckDetails`) 和优化 (`FillInBMInfo`, `FilterOneByte`) 的接口。
   - 维护了节点的状态信息，例如是否正在被分析、是否已被分析等 (`NodeInfo`)。
   - 提供了处理节点间连接和跳转的标签 (`label_`).

2. **定义各种具体的正则表达式节点类型:**
   - 使用宏 `FOR_EACH_NODE_TYPE` 列举了所有可能的节点类型，并通过 `FORWARD_DECLARE` 进行了前向声明。这些类型包括：
     - `EndNode`:  表示匹配成功或失败的终点。
     - `ActionNode`: 表示需要执行的特定动作，例如设置寄存器、存储位置、开始/结束子匹配等。
     - `ChoiceNode`: 表示多个可选的匹配路径 (类似正则表达式中的 `|`)。
     - `LoopChoiceNode`: 表示循环结构 (例如 `*`, `+`, `{}`).
     - `NegativeLookaroundChoiceNode`: 表示负向环视断言 (例如 `(?!...)`).
     - `BackReferenceNode`: 表示反向引用 (例如 `\1`).
     - `AssertionNode`: 表示零宽度断言 (例如 `^`, `$`, `\b`).
     - `TextNode`: 表示需要匹配的文本或字符类。

3. **定义辅助数据结构:**
   - `NodeInfo`: 存储了关于节点的分析信息，例如该节点是否依赖于前一个字符的类型（单词边界、换行符、字符串开始）。
   - `EatsAtLeastInfo`:  记录了从当前节点开始成功匹配至少需要消耗的字符数，用于性能优化。
   - `Guard`:  用于 `ChoiceNode`，表示某个分支被选中的条件 (例如，寄存器的值满足特定条件)。
   - `GuardedAlternative`:  将一个 `RegExpNode` 和一组 `Guard` 关联起来，表示一个带有条件的分支。
   - `QuickCheckDetails`: 用于存储快速检查的细节，允许在执行昂贵的匹配逻辑之前进行简单的预检查。
   - `BoyerMooreLookahead`:  用于 Boyer-Moore 字符串搜索优化。

**如果 `v8/src/regexp/regexp-nodes.h` 以 `.tq` 结尾:**

那么它的确是一个 **v8 Torque 源代码文件**。Torque 是 V8 自研的一种领域特定语言，用于更安全、更易于理解地编写 V8 的底层实现代码，特别是内置函数和运行时代码。在这种情况下，该文件将使用 Torque 的语法来定义正则表达式节点和相关逻辑，并最终会被编译成 C++ 代码。

**与 JavaScript 的功能关系及举例:**

`v8/src/regexp/regexp-nodes.h` 中定义的节点类是 V8 实现 JavaScript 正则表达式功能的 **核心数据结构**。当 JavaScript 引擎遇到一个正则表达式时，它会将其解析成由这些节点组成的内部表示形式。然后，V8 的正则表达式编译器会遍历这些节点，生成用于执行匹配操作的机器码或字节码。

**JavaScript 示例:**

```javascript
const regex = /ab*c/g;
const text = "abbbc abbbc";
const matches = text.match(regex);
console.log(matches); // 输出: ["abbbc", "abbbc"]
```

在这个例子中，正则表达式 `/ab*c/g` 在 V8 内部会被表示为一系列的 `RegExpNode` 对象，可能包括：

- 一个 `TextNode` 表示 'a'。
- 一个 `LoopChoiceNode` 表示 'b*' (零个或多个 'b')。
- 一个 `TextNode` 表示 'c'。
- 可能会有 `ActionNode` 来处理全局匹配标志 `g`。

**代码逻辑推理（假设输入与输出）：**

假设我们有一个简单的正则表达式 `/a/`:

**假设输入:**  一个表示正则表达式 `/a/` 的内部节点结构，包含一个 `TextNode`，其元素表示字符 'a'，并且其 `on_success` 指向一个 `EndNode` (表示匹配成功)。

**输出:**  `EatsAtLeast(false)` 方法应该返回 1，因为匹配成功至少需要消耗一个字符 'a'。`GetQuickCheckDetails` 方法可能会填充 `QuickCheckDetails` 结构，指示需要检查下一个字符是否为 'a'。

**用户常见的编程错误及举例:**

1. **正则表达式写得过于复杂，导致性能问题:** V8 的正则表达式引擎会尽力优化，但过于复杂的回溯或大量的分支可能会导致性能下降。
   ```javascript
   // 效率较低的正则表达式，可能导致大量的回溯
   const regex = /^(a+)+$/;
   const text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
   regex.test(text); // 可能需要较长时间
   ```
   V8 内部的 `ChoiceNode` 和 `LoopChoiceNode` 处理这类复杂情况时可能需要进行大量的状态探索。

2. **对环视断言的误解:**  负向环视断言 `(?!...)` 和正向环视断言 `(?=...)` 不消耗字符，但其匹配结果会影响后续匹配。不理解这一点可能导致意外的结果.
   ```javascript
   const regex = /a(?=[^b])/; // 匹配 'a' 后面不是 'b' 的情况
   const text = "abc";
   const match = text.match(regex);
   console.log(match); // 输出: ["a"]，因为 'a' 后面是 'b'，所以不匹配。
   ```
   `NegativeLookaroundChoiceNode` 在 V8 内部负责实现这类逻辑。

**功能归纳（第 1 部分）：**

`v8/src/regexp/regexp-nodes.h` 头文件是 V8 引擎中正则表达式功能的基石，它定义了用于在内部表示正则表达式语法结构的各种节点类和相关数据结构。这些类提供了代码生成、静态分析和优化的接口，使得 V8 能够高效地编译和执行 JavaScript 中的正则表达式。该文件定义了正则表达式的抽象语法树的节点类型，并为后续的编译和执行阶段提供了必要的抽象和信息。

Prompt: 
```
这是目录为v8/src/regexp/regexp-nodes.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-nodes.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_REGEXP_REGEXP_NODES_H_
#define V8_REGEXP_REGEXP_NODES_H_

#include "src/codegen/label.h"
#include "src/regexp/regexp-macro-assembler.h"
#include "src/zone/zone.h"

namespace v8 {
namespace internal {

class AlternativeGenerationList;
class BoyerMooreLookahead;
class GreedyLoopState;
class NodeVisitor;
class QuickCheckDetails;
class RegExpCompiler;
class SeqRegExpNode;
class Trace;
struct PreloadState;

#define FOR_EACH_NODE_TYPE(VISIT) \
  VISIT(End)                      \
  VISIT(Action)                   \
  VISIT(Choice)                   \
  VISIT(LoopChoice)               \
  VISIT(NegativeLookaroundChoice) \
  VISIT(BackReference)            \
  VISIT(Assertion)                \
  VISIT(Text)

#define FORWARD_DECLARE(type) class type##Node;
FOR_EACH_NODE_TYPE(FORWARD_DECLARE)
#undef FORWARD_DECLARE

struct NodeInfo final {
  NodeInfo()
      : being_analyzed(false),
        been_analyzed(false),
        follows_word_interest(false),
        follows_newline_interest(false),
        follows_start_interest(false),
        at_end(false),
        visited(false),
        replacement_calculated(false) {}

  // Returns true if the interests and assumptions of this node
  // matches the given one.
  bool Matches(NodeInfo* that) {
    return (at_end == that->at_end) &&
           (follows_word_interest == that->follows_word_interest) &&
           (follows_newline_interest == that->follows_newline_interest) &&
           (follows_start_interest == that->follows_start_interest);
  }

  // Updates the interests of this node given the interests of the
  // node preceding it.
  void AddFromPreceding(NodeInfo* that) {
    at_end |= that->at_end;
    follows_word_interest |= that->follows_word_interest;
    follows_newline_interest |= that->follows_newline_interest;
    follows_start_interest |= that->follows_start_interest;
  }

  bool HasLookbehind() {
    return follows_word_interest || follows_newline_interest ||
           follows_start_interest;
  }

  // Sets the interests of this node to include the interests of the
  // following node.
  void AddFromFollowing(NodeInfo* that) {
    follows_word_interest |= that->follows_word_interest;
    follows_newline_interest |= that->follows_newline_interest;
    follows_start_interest |= that->follows_start_interest;
  }

  void ResetCompilationState() {
    being_analyzed = false;
    been_analyzed = false;
  }

  bool being_analyzed : 1;
  bool been_analyzed : 1;

  // These bits are set of this node has to know what the preceding
  // character was.
  bool follows_word_interest : 1;
  bool follows_newline_interest : 1;
  bool follows_start_interest : 1;

  bool at_end : 1;
  bool visited : 1;
  bool replacement_calculated : 1;
};

struct EatsAtLeastInfo final {
  EatsAtLeastInfo() : EatsAtLeastInfo(0) {}
  explicit EatsAtLeastInfo(uint8_t eats)
      : eats_at_least_from_possibly_start(eats),
        eats_at_least_from_not_start(eats) {}
  void SetMin(const EatsAtLeastInfo& other) {
    if (other.eats_at_least_from_possibly_start <
        eats_at_least_from_possibly_start) {
      eats_at_least_from_possibly_start =
          other.eats_at_least_from_possibly_start;
    }
    if (other.eats_at_least_from_not_start < eats_at_least_from_not_start) {
      eats_at_least_from_not_start = other.eats_at_least_from_not_start;
    }
  }

  bool IsZero() const {
    return eats_at_least_from_possibly_start == 0 &&
           eats_at_least_from_not_start == 0;
  }

  // Any successful match starting from the current node will consume at least
  // this many characters. This does not necessarily mean that there is a
  // possible match with exactly this many characters, but we generally try to
  // get this number as high as possible to allow for early exit on failure.
  uint8_t eats_at_least_from_possibly_start;

  // Like eats_at_least_from_possibly_start, but with the additional assumption
  // that start-of-string assertions (^) can't match. This value is greater than
  // or equal to eats_at_least_from_possibly_start.
  uint8_t eats_at_least_from_not_start;
};

class RegExpNode : public ZoneObject {
 public:
  explicit RegExpNode(Zone* zone)
      : replacement_(nullptr),
        on_work_list_(false),
        trace_count_(0),
        zone_(zone) {
    bm_info_[0] = bm_info_[1] = nullptr;
  }
  virtual ~RegExpNode();
  virtual void Accept(NodeVisitor* visitor) = 0;
  // Generates a goto to this node or actually generates the code at this point.
  virtual void Emit(RegExpCompiler* compiler, Trace* trace) = 0;
  // How many characters must this node consume at a minimum in order to
  // succeed.  The not_at_start argument is used to indicate that we know we are
  // not at the start of the input.  In this case anchored branches will always
  // fail and can be ignored when determining how many characters are consumed
  // on success.  If this node has not been analyzed yet, EatsAtLeast returns 0.
  uint32_t EatsAtLeast(bool not_at_start);
  // Returns how many characters this node must consume in order to succeed,
  // given that this is a LoopChoiceNode whose counter register is in a
  // newly-initialized state at the current position in the generated code. For
  // example, consider /a{6,8}/. Absent any extra information, the
  // LoopChoiceNode for the repetition must report that it consumes at least
  // zero characters, because it may have already looped several times. However,
  // with a newly-initialized counter, it can report that it consumes at least
  // six characters.
  virtual EatsAtLeastInfo EatsAtLeastFromLoopEntry();
  // Emits some quick code that checks whether the preloaded characters match.
  // Falls through on certain failure, jumps to the label on possible success.
  // If the node cannot make a quick check it does nothing and returns false.
  bool EmitQuickCheck(RegExpCompiler* compiler, Trace* bounds_check_trace,
                      Trace* trace, bool preload_has_checked_bounds,
                      Label* on_possible_success,
                      QuickCheckDetails* details_return,
                      bool fall_through_on_failure, ChoiceNode* predecessor);
  // For a given number of characters this returns a mask and a value.  The
  // next n characters are anded with the mask and compared with the value.
  // A comparison failure indicates the node cannot match the next n characters.
  // A comparison success indicates the node may match.
  virtual void GetQuickCheckDetails(QuickCheckDetails* details,
                                    RegExpCompiler* compiler,
                                    int characters_filled_in,
                                    bool not_at_start) = 0;
  // Fills in quick check details for this node, given that this is a
  // LoopChoiceNode whose counter register is in a newly-initialized state at
  // the current position in the generated code. For example, consider /a{6,8}/.
  // Absent any extra information, the LoopChoiceNode for the repetition cannot
  // generate any useful quick check because a match might be the (empty)
  // continuation node. However, with a newly-initialized counter, it can
  // generate a quick check for several 'a' characters at once.
  virtual void GetQuickCheckDetailsFromLoopEntry(QuickCheckDetails* details,
                                                 RegExpCompiler* compiler,
                                                 int characters_filled_in,
                                                 bool not_at_start);
  static const int kNodeIsTooComplexForGreedyLoops = kMinInt;
  virtual int GreedyLoopTextLength() { return kNodeIsTooComplexForGreedyLoops; }
  // Only returns the successor for a text node of length 1 that matches any
  // character and that has no guards on it.
  virtual RegExpNode* GetSuccessorOfOmnivorousTextNode(
      RegExpCompiler* compiler) {
    return nullptr;
  }

  // Collects information on the possible code units (mod 128) that can match if
  // we look forward.  This is used for a Boyer-Moore-like string searching
  // implementation.  TODO(erikcorry):  This should share more code with
  // EatsAtLeast, GetQuickCheckDetails.  The budget argument is used to limit
  // the number of nodes we are willing to look at in order to create this data.
  static const int kRecursionBudget = 200;
  bool KeepRecursing(RegExpCompiler* compiler);
  virtual void FillInBMInfo(Isolate* isolate, int offset, int budget,
                            BoyerMooreLookahead* bm, bool not_at_start) {
    UNREACHABLE();
  }

  // If we know that the input is one-byte then there are some nodes that can
  // never match.  This method returns a node that can be substituted for
  // itself, or nullptr if the node can never match.
  virtual RegExpNode* FilterOneByte(int depth, RegExpCompiler* compiler) {
    return this;
  }
  // Helper for FilterOneByte.
  RegExpNode* replacement() {
    DCHECK(info()->replacement_calculated);
    return replacement_;
  }
  RegExpNode* set_replacement(RegExpNode* replacement) {
    info()->replacement_calculated = true;
    replacement_ = replacement;
    return replacement;  // For convenience.
  }

  // We want to avoid recalculating the lookahead info, so we store it on the
  // node.  Only info that is for this node is stored.  We can tell that the
  // info is for this node when offset == 0, so the information is calculated
  // relative to this node.
  void SaveBMInfo(BoyerMooreLookahead* bm, bool not_at_start, int offset) {
    if (offset == 0) set_bm_info(not_at_start, bm);
  }

  Label* label() { return &label_; }
  // If non-generic code is generated for a node (i.e. the node is not at the
  // start of the trace) then it cannot be reused.  This variable sets a limit
  // on how often we allow that to happen before we insist on starting a new
  // trace and generating generic code for a node that can be reused by flushing
  // the deferred actions in the current trace and generating a goto.
  static const int kMaxCopiesCodeGenerated = 10;

  bool on_work_list() { return on_work_list_; }
  void set_on_work_list(bool value) { on_work_list_ = value; }

  NodeInfo* info() { return &info_; }
  const EatsAtLeastInfo* eats_at_least_info() const { return &eats_at_least_; }
  void set_eats_at_least_info(const EatsAtLeastInfo& eats_at_least) {
    eats_at_least_ = eats_at_least;
  }

  // TODO(v8:10441): This is a hacky way to avoid exponential code size growth
  // for very large choice nodes that can be generated by unicode property
  // escapes. In order to avoid inlining (i.e. trace recursion), we pretend to
  // have generated the maximum count of code copies already.
  // We should instead fix this properly, e.g. by using the code size budget
  // (flush_budget) or by generating property escape matches as calls to a C
  // function.
  void SetDoNotInline() { trace_count_ = kMaxCopiesCodeGenerated; }

  BoyerMooreLookahead* bm_info(bool not_at_start) {
    return bm_info_[not_at_start ? 1 : 0];
  }

#define DECLARE_CAST(type) \
  virtual type##Node* As##type##Node() { return nullptr; }
  FOR_EACH_NODE_TYPE(DECLARE_CAST)
#undef DECLARE_CAST

  virtual SeqRegExpNode* AsSeqRegExpNode() { return nullptr; }

  Zone* zone() const { return zone_; }

 protected:
  enum LimitResult { DONE, CONTINUE };
  RegExpNode* replacement_;

  LimitResult LimitVersions(RegExpCompiler* compiler, Trace* trace);

  void set_bm_info(bool not_at_start, BoyerMooreLookahead* bm) {
    bm_info_[not_at_start ? 1 : 0] = bm;
  }

 private:
  static const int kFirstCharBudget = 10;
  Label label_;
  bool on_work_list_;
  NodeInfo info_;

  // Saved values for EatsAtLeast results, to avoid recomputation. Filled in
  // during analysis (valid if info_.been_analyzed is true).
  EatsAtLeastInfo eats_at_least_;

  // This variable keeps track of how many times code has been generated for
  // this node (in different traces).  We don't keep track of where the
  // generated code is located unless the code is generated at the start of
  // a trace, in which case it is generic and can be reused by flushing the
  // deferred operations in the current trace and generating a goto.
  int trace_count_;
  BoyerMooreLookahead* bm_info_[2];

  Zone* zone_;
};

class SeqRegExpNode : public RegExpNode {
 public:
  explicit SeqRegExpNode(RegExpNode* on_success)
      : RegExpNode(on_success->zone()), on_success_(on_success) {}
  RegExpNode* on_success() { return on_success_; }
  void set_on_success(RegExpNode* node) { on_success_ = node; }
  RegExpNode* FilterOneByte(int depth, RegExpCompiler* compiler) override;
  void FillInBMInfo(Isolate* isolate, int offset, int budget,
                    BoyerMooreLookahead* bm, bool not_at_start) override {
    on_success_->FillInBMInfo(isolate, offset, budget - 1, bm, not_at_start);
    if (offset == 0) set_bm_info(not_at_start, bm);
  }
  SeqRegExpNode* AsSeqRegExpNode() override { return this; }

 protected:
  RegExpNode* FilterSuccessor(int depth, RegExpCompiler* compiler);

 private:
  RegExpNode* on_success_;
};

class ActionNode : public SeqRegExpNode {
 public:
  enum ActionType {
    SET_REGISTER_FOR_LOOP,
    INCREMENT_REGISTER,
    STORE_POSITION,
    BEGIN_POSITIVE_SUBMATCH,
    BEGIN_NEGATIVE_SUBMATCH,
    POSITIVE_SUBMATCH_SUCCESS,
    EMPTY_MATCH_CHECK,
    CLEAR_CAPTURES,
    MODIFY_FLAGS
  };
  static ActionNode* SetRegisterForLoop(int reg, int val,
                                        RegExpNode* on_success);
  static ActionNode* IncrementRegister(int reg, RegExpNode* on_success);
  static ActionNode* StorePosition(int reg, bool is_capture,
                                   RegExpNode* on_success);
  static ActionNode* ClearCaptures(Interval range, RegExpNode* on_success);
  static ActionNode* BeginPositiveSubmatch(int stack_pointer_reg,
                                           int position_reg, RegExpNode* body,
                                           ActionNode* success_node);
  static ActionNode* BeginNegativeSubmatch(int stack_pointer_reg,
                                           int position_reg,
                                           RegExpNode* on_success);
  static ActionNode* PositiveSubmatchSuccess(int stack_pointer_reg,
                                             int restore_reg,
                                             int clear_capture_count,
                                             int clear_capture_from,
                                             RegExpNode* on_success);
  static ActionNode* EmptyMatchCheck(int start_register,
                                     int repetition_register,
                                     int repetition_limit,
                                     RegExpNode* on_success);
  static ActionNode* ModifyFlags(RegExpFlags flags, RegExpNode* on_success);
  ActionNode* AsActionNode() override { return this; }
  void Accept(NodeVisitor* visitor) override;
  void Emit(RegExpCompiler* compiler, Trace* trace) override;
  void GetQuickCheckDetails(QuickCheckDetails* details,
                            RegExpCompiler* compiler, int filled_in,
                            bool not_at_start) override;
  void FillInBMInfo(Isolate* isolate, int offset, int budget,
                    BoyerMooreLookahead* bm, bool not_at_start) override;
  ActionType action_type() const { return action_type_; }
  // TODO(erikcorry): We should allow some action nodes in greedy loops.
  int GreedyLoopTextLength() override {
    return kNodeIsTooComplexForGreedyLoops;
  }
  RegExpFlags flags() const {
    DCHECK_EQ(action_type(), MODIFY_FLAGS);
    return RegExpFlags{data_.u_modify_flags.flags};
  }
  ActionNode* success_node() const {
    DCHECK_EQ(action_type(), BEGIN_POSITIVE_SUBMATCH);
    return data_.u_submatch.success_node;
  }

 protected:
  ActionNode(ActionType action_type, RegExpNode* on_success)
      : SeqRegExpNode(on_success), action_type_(action_type) {}

 private:
  union {
    struct {
      int reg;
      int value;
    } u_store_register;
    struct {
      int reg;
    } u_increment_register;
    struct {
      int reg;
      bool is_capture;
    } u_position_register;
    struct {
      int stack_pointer_register;
      int current_position_register;
      int clear_register_count;
      int clear_register_from;
      ActionNode* success_node;  // Only used for positive submatch.
    } u_submatch;
    struct {
      int start_register;
      int repetition_register;
      int repetition_limit;
    } u_empty_match_check;
    struct {
      int range_from;
      int range_to;
    } u_clear_captures;
    struct {
      int flags;
    } u_modify_flags;
  } data_;

  ActionType action_type_;
  friend class DotPrinterImpl;
  friend Zone;
};

class TextNode : public SeqRegExpNode {
 public:
  TextNode(ZoneList<TextElement>* elms, bool read_backward,
           RegExpNode* on_success)
      : SeqRegExpNode(on_success), elms_(elms), read_backward_(read_backward) {}
  TextNode(RegExpClassRanges* that, bool read_backward, RegExpNode* on_success)
      : SeqRegExpNode(on_success),
        elms_(zone()->New<ZoneList<TextElement>>(1, zone())),
        read_backward_(read_backward) {
    elms_->Add(TextElement::ClassRanges(that), zone());
  }
  // Create TextNode for a single character class for the given ranges.
  static TextNode* CreateForCharacterRanges(Zone* zone,
                                            ZoneList<CharacterRange>* ranges,
                                            bool read_backward,
                                            RegExpNode* on_success);
  // Create TextNode for a surrogate pair (i.e. match a sequence of two uc16
  // code unit ranges).
  static TextNode* CreateForSurrogatePair(
      Zone* zone, CharacterRange lead, ZoneList<CharacterRange>* trail_ranges,
      bool read_backward, RegExpNode* on_success);
  static TextNode* CreateForSurrogatePair(Zone* zone,
                                          ZoneList<CharacterRange>* lead_ranges,
                                          CharacterRange trail,
                                          bool read_backward,
                                          RegExpNode* on_success);
  TextNode* AsTextNode() override { return this; }
  void Accept(NodeVisitor* visitor) override;
  void Emit(RegExpCompiler* compiler, Trace* trace) override;
  void GetQuickCheckDetails(QuickCheckDetails* details,
                            RegExpCompiler* compiler, int characters_filled_in,
                            bool not_at_start) override;
  ZoneList<TextElement>* elements() { return elms_; }
  bool read_backward() { return read_backward_; }
  void MakeCaseIndependent(Isolate* isolate, bool is_one_byte,
                           RegExpFlags flags);
  int GreedyLoopTextLength() override;
  RegExpNode* GetSuccessorOfOmnivorousTextNode(
      RegExpCompiler* compiler) override;
  void FillInBMInfo(Isolate* isolate, int offset, int budget,
                    BoyerMooreLookahead* bm, bool not_at_start) override;
  void CalculateOffsets();
  RegExpNode* FilterOneByte(int depth, RegExpCompiler* compiler) override;
  int Length();

 private:
  enum TextEmitPassType {
    NON_LATIN1_MATCH,            // Check for characters that can never match.
    SIMPLE_CHARACTER_MATCH,      // Case-dependent single character check.
    NON_LETTER_CHARACTER_MATCH,  // Check characters that have no case equivs.
    CASE_CHARACTER_MATCH,        // Case-independent single character check.
    CHARACTER_CLASS_MATCH        // Character class.
  };
  void TextEmitPass(RegExpCompiler* compiler, TextEmitPassType pass,
                    bool preloaded, Trace* trace, bool first_element_checked,
                    int* checked_up_to);
  ZoneList<TextElement>* elms_;
  bool read_backward_;
};

class AssertionNode : public SeqRegExpNode {
 public:
  enum AssertionType {
    AT_END,
    AT_START,
    AT_BOUNDARY,
    AT_NON_BOUNDARY,
    AFTER_NEWLINE
  };
  static AssertionNode* AtEnd(RegExpNode* on_success) {
    return on_success->zone()->New<AssertionNode>(AT_END, on_success);
  }
  static AssertionNode* AtStart(RegExpNode* on_success) {
    return on_success->zone()->New<AssertionNode>(AT_START, on_success);
  }
  static AssertionNode* AtBoundary(RegExpNode* on_success) {
    return on_success->zone()->New<AssertionNode>(AT_BOUNDARY, on_success);
  }
  static AssertionNode* AtNonBoundary(RegExpNode* on_success) {
    return on_success->zone()->New<AssertionNode>(AT_NON_BOUNDARY, on_success);
  }
  static AssertionNode* AfterNewline(RegExpNode* on_success) {
    return on_success->zone()->New<AssertionNode>(AFTER_NEWLINE, on_success);
  }
  AssertionNode* AsAssertionNode() override { return this; }
  void Accept(NodeVisitor* visitor) override;
  void Emit(RegExpCompiler* compiler, Trace* trace) override;
  void GetQuickCheckDetails(QuickCheckDetails* details,
                            RegExpCompiler* compiler, int filled_in,
                            bool not_at_start) override;
  void FillInBMInfo(Isolate* isolate, int offset, int budget,
                    BoyerMooreLookahead* bm, bool not_at_start) override;
  AssertionType assertion_type() { return assertion_type_; }

 private:
  friend Zone;

  void EmitBoundaryCheck(RegExpCompiler* compiler, Trace* trace);
  enum IfPrevious { kIsNonWord, kIsWord };
  void BacktrackIfPrevious(RegExpCompiler* compiler, Trace* trace,
                           IfPrevious backtrack_if_previous);
  AssertionNode(AssertionType t, RegExpNode* on_success)
      : SeqRegExpNode(on_success), assertion_type_(t) {}
  AssertionType assertion_type_;
};

class BackReferenceNode : public SeqRegExpNode {
 public:
  BackReferenceNode(int start_reg, int end_reg, bool read_backward,
                    RegExpNode* on_success)
      : SeqRegExpNode(on_success),
        start_reg_(start_reg),
        end_reg_(end_reg),
        read_backward_(read_backward) {}
  BackReferenceNode* AsBackReferenceNode() override { return this; }
  void Accept(NodeVisitor* visitor) override;
  int start_register() { return start_reg_; }
  int end_register() { return end_reg_; }
  bool read_backward() { return read_backward_; }
  void Emit(RegExpCompiler* compiler, Trace* trace) override;
  void GetQuickCheckDetails(QuickCheckDetails* details,
                            RegExpCompiler* compiler, int characters_filled_in,
                            bool not_at_start) override {
    return;
  }
  void FillInBMInfo(Isolate* isolate, int offset, int budget,
                    BoyerMooreLookahead* bm, bool not_at_start) override;

 private:
  int start_reg_;
  int end_reg_;
  bool read_backward_;
};

class EndNode : public RegExpNode {
 public:
  enum Action { ACCEPT, BACKTRACK, NEGATIVE_SUBMATCH_SUCCESS };
  EndNode(Action action, Zone* zone) : RegExpNode(zone), action_(action) {}
  EndNode* AsEndNode() override { return this; }
  void Accept(NodeVisitor* visitor) override;
  void Emit(RegExpCompiler* compiler, Trace* trace) override;
  void GetQuickCheckDetails(QuickCheckDetails* details,
                            RegExpCompiler* compiler, int characters_filled_in,
                            bool not_at_start) override {
    // Returning 0 from EatsAtLeast should ensure we never get here.
    UNREACHABLE();
  }
  void FillInBMInfo(Isolate* isolate, int offset, int budget,
                    BoyerMooreLookahead* bm, bool not_at_start) override {
    // Returning 0 from EatsAtLeast should ensure we never get here.
    UNREACHABLE();
  }

 private:
  Action action_;
};

class NegativeSubmatchSuccess : public EndNode {
 public:
  NegativeSubmatchSuccess(int stack_pointer_reg, int position_reg,
                          int clear_capture_count, int clear_capture_start,
                          Zone* zone)
      : EndNode(NEGATIVE_SUBMATCH_SUCCESS, zone),
        stack_pointer_register_(stack_pointer_reg),
        current_position_register_(position_reg),
        clear_capture_count_(clear_capture_count),
        clear_capture_start_(clear_capture_start) {}
  void Emit(RegExpCompiler* compiler, Trace* trace) override;

 private:
  int stack_pointer_register_;
  int current_position_register_;
  int clear_capture_count_;
  int clear_capture_start_;
};

class Guard : public ZoneObject {
 public:
  enum Relation { LT, GEQ };
  Guard(int reg, Relation op, int value) : reg_(reg), op_(op), value_(value) {}
  int reg() { return reg_; }
  Relation op() { return op_; }
  int value() { return value_; }

 private:
  int reg_;
  Relation op_;
  int value_;
};

class GuardedAlternative {
 public:
  explicit GuardedAlternative(RegExpNode* node)
      : node_(node), guards_(nullptr) {}
  void AddGuard(Guard* guard, Zone* zone);
  RegExpNode* node() { return node_; }
  void set_node(RegExpNode* node) { node_ = node; }
  ZoneList<Guard*>* guards() { return guards_; }

 private:
  RegExpNode* node_;
  ZoneList<Guard*>* guards_;
};

class AlternativeGeneration;

class ChoiceNode : public RegExpNode {
 public:
  explicit ChoiceNode(int expected_size, Zone* zone)
      : RegExpNode(zone),
        alternatives_(
            zone->New<ZoneList<GuardedAlternative>>(expected_size, zone)),
        not_at_start_(false),
        being_calculated_(false) {}
  ChoiceNode* AsChoiceNode() override { return this; }
  void Accept(NodeVisitor* visitor) override;
  void AddAlternative(GuardedAlternative node) {
    alternatives()->Add(node, zone());
  }
  ZoneList<GuardedAlternative>* alternatives() { return alternatives_; }
  void Emit(RegExpCompiler* compiler, Trace* trace) override;
  void GetQuickCheckDetails(QuickCheckDetails* details,
                            RegExpCompiler* compiler, int characters_filled_in,
                            bool not_at_start) override;
  void FillInBMInfo(Isolate* isolate, int offset, int budget,
                    BoyerMooreLookahead* bm, bool not_at_start) override;

  bool being_calculated() { return being_calculated_; }
  bool not_at_start() { return not_at_start_; }
  void set_not_at_start() { not_at_start_ = true; }
  void set_being_calculated(bool b) { being_calculated_ = b; }
  virtual bool try_to_emit_quick_check_for_alternative(bool is_first) {
    return true;
  }
  RegExpNode* FilterOneByte(int depth, RegExpCompiler* compiler) override;
  virtual bool read_backward() { return false; }

 protected:
  int GreedyLoopTextLengthForAlternative(GuardedAlternative* alternative);
  ZoneList<GuardedAlternative>* alternatives_;

 private:
  template <typename...>
  friend class Analysis;

  void GenerateGuard(RegExpMacroAssembler* macro_assembler, Guard* guard,
                     Trace* trace);
  int CalculatePreloadCharacters(RegExpCompiler* compiler, int eats_at_least);
  void EmitOutOfLineContinuation(RegExpCompiler* compiler, Trace* trace,
                                 GuardedAlternative alternative,
                                 AlternativeGeneration* alt_gen,
                                 int preload_characters,
                                 bool next_expects_preload);
  void SetUpPreLoad(RegExpCompiler* compiler, Trace* current_trace,
                    PreloadState* preloads);
  void AssertGuardsMentionRegisters(Trace* trace);
  int EmitOptimizedUnanchoredSearch(RegExpCompiler* compiler, Trace* trace);
  Trace* EmitGreedyLoop(RegExpCompiler* compiler, Trace* trace,
                        AlternativeGenerationList* alt_gens,
                        PreloadState* preloads,
                        GreedyLoopState* greedy_loop_state, int text_length);
  void EmitChoices(RegExpCompiler* compiler,
                   AlternativeGenerationList* alt_gens, int first_choice,
                   Trace* trace, PreloadState* preloads);

  // If true, this node is never checked at the start of the input.
  // Allows a new trace to start with at_start() set to false.
  bool not_at_start_;
  bool being_calculated_;
};

class NegativeLookaroundChoiceNode : public ChoiceNode {
 public:
  explicit NegativeLookaroundChoiceNode(GuardedAlternative this_must_fail,
                                        GuardedAlternative then_do_this,
                                        Zone* zone)
      : ChoiceNode(2, zone) {
    AddAlternative(this_must_fail);
    AddAlternative(then_do_this);
  }
  void GetQuickCheckDetails(QuickCheckDetails* details,
                            RegExpCompiler* compiler, int characters_filled_in,
                            bool not_at_start) override;
  void FillInBMInfo(Isolate* isolate, int offset, int budget,
                    BoyerMooreLookahead* bm, bool not_at_start) override {
    continue_node()->FillInBMInfo(isolate, offset, budget - 1, bm,
                                  not_at_start);
    if (offset == 0) set_bm_info(not_at_start, bm);
  }
  static constexpr int kLookaroundIndex = 0;
  static constexpr int kContinueIndex = 1;
  RegExpNode* lookaround_node() {
    return alternatives()->at(kLookaroundIndex).node();
  }
  RegExpNode* continue_node() {
    return alternatives()->at(kContinueIndex).node();
  }
  // For a negative lookahead we don't emit the quick check for the
  // alternative that is expected to fail.  This is because quick check code
  // starts by loading enough characters for the alternative that takes fewest
  // characters, but on a negative lookahead the negative branch did not take
  // part in that calculation (EatsAtLeast) so the assumptions don't hold.
  bool try_to_emit_quick_check_for_alternative(bool is_first) override {
    return !is_first;
  }
  NegativeLookaroundChoiceNode* AsNegativeLookaroundChoiceNode() override {
    return this;
  }
  void Accept(NodeVisitor* visitor) override;
  RegExpNode* FilterOneByte(int depth, RegExpCompiler* compiler) override;
};

class LoopChoiceNode : public ChoiceNode {
 public:
  LoopChoiceNode(bool body_can_be_zero_length, bool read_backward,
                 int min_loop_iterations, Zone* zone)
      : ChoiceNode(2, zone),
        loop_node_(nullptr),
        continue_node_(nullptr),
        body_can_be_zero_length_(body_can_be_zero_length),
        read_backward_(read_backward),
        traversed_loop_initialization_node_(false),
        min_loop_iterations_(min_loop_iterations) {}
  void AddLoopAlternative(GuardedAlternative alt);
  void AddContinueAlternative(GuardedAlternative alt);
  void Emit(RegExpCompiler* compiler, Trace* trace) override;
  void GetQuickCheckDetails(QuickCheckDetails* details,
                            RegExpCompiler* compiler, int characters_filled_in,
                            bool not_at_start) override;
  void GetQuickCheckDetailsFromLoopEntry(QuickCheckDetails* details,
                                         RegExpCompiler* compiler,
                                         int characters_filled_in,
                                         bool not_at_start) override;
  void FillInBMInfo(Isolate* isolate, int offset, int budget,
                    BoyerMooreLookahead* bm, bool not_at_start) override;
  EatsAtLeastInfo EatsAtLeastFromLoopEntry() override;
  RegExpNode* loop_node() { return loop_node_; }
  RegExpNode* continue_node() { return continue_node_; }
  bool body_can_be_zero_length() { return body_can_be_zero_length_; }
  int min_loop_iterations() const { return min_loop_iterations_; }
  bool read_backward() override { return read_backward_; }
  LoopChoiceNode* AsLoopChoiceNode() override { return this; }
  void Accept(NodeVisitor* visitor) override;
  RegExpNode* FilterOneByte(int depth, RegExpCompiler* compiler) override;

 private:
  // AddAlternative is made private for loop nodes because alternatives
  // should not be added freely, we need to keep track of which node
  // goes back to the node itself.
  void AddAlternative(GuardedAlternative node) {
    ChoiceNode::AddAlternative(node);
  }

  RegExpNode* loop_node_;
  RegExpNode* continue_node_;
  bool body_can_be_zero_length_;
  bool read_backward_;

  // Temporary marker set only while generating quick check details. Represents
  // whether GetQuickCheckDetails traversed the initialization node for this
  // loop's counter. If so, we may be able to generate stricter quick checks
  // because we know the loop node must match at least min_loop_iterations_
  // times before the continuation node can match.
  bool traversed_loop_initialization_node_;

  // The minimum number of times the loop_node_ must match before the
  // continue_node_ might be considered. This value can be temporarily decreased
  // while generating quick check details, to represent the remaining iterations
  // after the completed portion of the quick check details.
  int min_loop_iterations_;

  friend class It
"""


```