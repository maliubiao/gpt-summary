Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/regexp/regexp-compiler-tonode.cc`. This is part 2 of a 3-part request, implying that there's surrounding code in parts 1 and 3.

My plan is to:
1. **Identify the primary function:** The code seems to be involved in converting a higher-level representation of regular expressions (likely the AST) into a lower-level node-based representation that can be used for execution. The `ToNode` methods are key here.
2. **Analyze the individual functions:**  Break down the purpose of each function within the provided snippet.
3. **Relate to JavaScript:** Determine how the operations in this code connect to the behavior of JavaScript regular expressions.
4. **Illustrate with JavaScript examples:**  Provide concrete JavaScript regex examples to demonstrate the functionality.
5. **Consider edge cases and common errors:** Think about potential pitfalls or misunderstandings users might have when working with regular expressions that relate to the optimizations being performed.
6. **Summarize the overall functionality:** Condense the findings into a concise summary.
这是v8源代码文件 `v8/src/regexp/regexp-compiler-tonode.cc` 的一部分，主要负责将正则表达式的抽象语法树 (AST) 节点转换为用于执行的节点图 (node graph)。

**功能归纳：**

这段代码的主要功能是 **将正则表达式 AST 的一部分节点类型转换为用于执行的节点图，并进行一些优化，特别是针对 `RegExpDisjunction`（或 `|` 分隔的选择分支）和 `RegExpAlternative`（一个顺序的匹配项列表）。**  它专注于将高级的正则表达式结构转化为更底层的、可执行的指令序列。

以下是代码中各个部分功能的详细解释：

1. **`RegExpDisjunction::RationalizeConsecutiveAtoms(RegExpCompiler* compiler)`:**
   - **功能:**  优化连续的具有公共前缀的原子（`RegExpAtom`，通常代表字符串字面量）的或关系。
   - **目的:**  将 `abc|abd|abe` 优化为 `ab(c|d|e)`，从而减少状态数量和提高匹配效率。
   - **代码逻辑推理:**
     - **假设输入:**  一个 `RegExpDisjunction` 节点，其 `alternatives` 列表中包含多个 `RegExpAtom` 类型的子节点，例如代表字符串 "abcd", "abef", "abgh"。
     - **输出:** 修改后的 `alternatives` 列表，将共享前缀提取出来，形成类似 `ab(cd|ef|gh)` 的结构。具体来说，会创建一个新的 `RegExpAlternative` 节点，包含一个表示公共前缀的 `RegExpAtom` 节点和一个表示剩余部分的 `RegExpDisjunction` 节点。
   - **与 JavaScript 的关系:** 这对应于 JavaScript 正则表达式中 `|` 的优化，可以提高像 `/^(prefix1|prefix2|prefix3)suffix/` 这样的表达式的性能。

2. **`RegExpDisjunction::FixSingleCharacterDisjunctions(RegExpCompiler* compiler)`:**
   - **功能:**  优化单字符的或关系。
   - **目的:** 将 `a|b|c` 优化为字符集 `[abc]`，这通常在底层执行时更高效。
   - **代码逻辑推理:**
     - **假设输入:** 一个 `RegExpDisjunction` 节点，其 `alternatives` 列表中包含多个长度为 1 的 `RegExpAtom` 子节点，例如代表字符 'a', 'b', 'c'。
     - **输出:** 修改后的 `alternatives` 列表，将这些单字符原子替换为一个 `RegExpClassRanges` 节点，表示字符集 `[abc]`。
   - **与 JavaScript 的关系:** 这对应于 JavaScript 正则表达式中 `|` 的优化，尤其是在处理简单的字符选择时，例如 `/color|colour/` 在某些优化后可能会被视为 `/colo[u]r/` 的一部分。

3. **`RegExpDisjunction::ToNode(RegExpCompiler* compiler, RegExpNode* on_success)`:**
   - **功能:**  将 `RegExpDisjunction` 节点转换为执行节点图。
   - **流程:**
     - 先尝试进行 `RationalizeConsecutiveAtoms` 和 `FixSingleCharacterDisjunctions` 优化。
     - 如果优化后只剩一个分支，则直接转换该分支。
     - 否则，创建一个 `ChoiceNode`，表示一个选择点，然后递归地将每个 `alternative` 转换为执行节点，并添加到 `ChoiceNode` 中。
   - **与 JavaScript 的关系:** 这是 JavaScript 正则表达式 `|` 运算的核心转换过程。

4. **`RegExpQuantifier::ToNode(RegExpCompiler* compiler, RegExpNode* on_success)`:**
   - **功能:**  将量词 (`*`, `+`, `?`, `{m,n}`) 节点转换为执行节点。
   - **与 JavaScript 的关系:**  处理 JavaScript 正则表达式中的量词。

5. **`RegExpAssertion::ToNode(RegExpCompiler* compiler, RegExpNode* on_success)`:**
   - **功能:**  将断言 (`^`, `$`, `\b`, `\B`) 节点转换为执行节点。
   - **特殊处理 `\b` 和 `\B`:** 如果开启了 Unicode 感知的大小写等价 (NeedsUnicodeCaseEquivalents)，则将 `\b` 和 `\B` 转换为 lookaround 断言的组合，以正确处理 Unicode 字符边界。
   - **特殊处理 `$`:**  将多行模式下的 `$` 转换为一个选择，匹配换行符（带正向环视）或字符串结尾。
   - **与 JavaScript 的关系:** 处理 JavaScript 正则表达式中的各种断言。

6. **`RegExpBackReference::ToNode(RegExpCompiler* compiler, RegExpNode* on_success)`:**
   - **功能:**  将反向引用 (`\1`, `\2` 等) 节点转换为执行节点。
   - **处理未匹配的捕获组:**  对所有可能的捕获组创建反向引用节点，因为对未匹配的捕获组的反向引用被视为空字符串。
   - **与 JavaScript 的关系:** 处理 JavaScript 正则表达式中的反向引用。

7. **`RegExpEmpty::ToNode(RegExpCompiler* compiler, RegExpNode* on_success)`:**
   - **功能:**  将空节点转换为执行节点（直接返回 `on_success`，表示没有实际匹配发生）。
   - **与 JavaScript 的关系:**  对应于正则表达式中可能出现的空匹配情况。

8. **`RegExpGroup::ToNode(RegExpCompiler* compiler, RegExpNode* on_success)`:**
   - **功能:**  将分组 (`(...)`, `(?:...)`) 节点转换为执行节点。
   - **处理标志修改:** 如果分组修改了正则表达式的标志 (例如 `(?i)`)，则会插入 `ActionNode::ModifyFlags` 来在执行时切换标志。
   - **与 JavaScript 的关系:**  处理 JavaScript 正则表达式中的分组和标志修改。

9. **`RegExpLookaround::ToNode(RegExpCompiler* compiler, RegExpNode* on_success)` 和 `RegExpLookaround::Builder`:**
   - **功能:**  将环视断言 (`(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`) 节点转换为执行节点。
   - **使用 `ChoiceNode` 表示负向环视:**  负向环视使用 `ChoiceNode` 实现，第一个分支是尝试匹配的内容，如果匹配成功则回溯，否则尝试第二个分支（表示匹配失败，环视成立）。
   - **与 JavaScript 的关系:**  处理 JavaScript 正则表达式中的环视断言。

10. **`RegExpCapture::ToNode(RegExpCompiler* compiler, RegExpNode* on_success)`:**
    - **功能:** 将捕获组 (`(...)`) 节点转换为执行节点，会在匹配开始和结束时存储捕获的位置。
    - **与 JavaScript 的关系:**  处理 JavaScript 正则表达式中的捕获组，记录匹配到的子串。

11. **`AssertionSequenceRewriter::MaybeRewrite(ZoneList<RegExpTree*>* terms, Zone* zone)` 和 `AssertionSequenceRewriter::Rewrite(int from, int to)`:**
    - **功能:**  优化连续的断言序列。
    - **优化策略:**
        - **折叠重复断言:**  例如 `^^` 会被优化成 `^`。
        - **识别总是失败的组合:** 例如 `\b\B` 总是失败，整个序列会被替换为一个永远不匹配的节点。
    - **与 JavaScript 的关系:**  提高包含多个连续断言的正则表达式的效率。

12. **`RegExpAlternative::ToNode(RegExpCompiler* compiler, RegExpNode* on_success)`:**
    - **功能:** 将 `RegExpAlternative` 节点转换为执行节点。
    - **处理断言序列重写:** 在转换子节点之前，会调用 `AssertionSequenceRewriter::MaybeRewrite` 来优化连续的断言。
    - **根据读取方向构建节点链:**  根据正则表达式的读取方向（正向或反向），按顺序连接子节点的执行节点。
    - **与 JavaScript 的关系:**  处理正则表达式中一个顺序的匹配项列表。

13. **`CharacterRange::AddClassEscape(...)` 和相关的字符集处理函数:**
    - **功能:**  处理字符类转义符 (`\d`, `\w`, `\s` 等)。
    - **处理 Unicode 大小写等价:**  在 `/i` 模式下，会添加 Unicode 字符的大小写等价字符到字符集中。
    - **与 JavaScript 的关系:**  支持 JavaScript 正则表达式中的字符类。

**常见的编程错误示例:**

- **在不理解 Unicode 的情况下使用 `\b` 和 `\B`:**  在处理包含非 ASCII 字符的字符串时，`\b` 和 `\B` 的行为可能与预期不同，尤其是在没有正确配置 Unicode 支持的环境中。V8 的这段代码尝试通过转换为 lookaround 断言来解决这个问题。
  ```javascript
  // 错误示例：假设 \b 能正确处理所有 Unicode 单词边界
  const str = "你好世界";
  const regex = /\b世界\b/;
  console.log(regex.test(str)); // 可能不会像预期的那样工作，取决于具体的 Unicode 单词边界定义

  // 正确理解 Unicode 单词边界的用法可能需要更精细的控制
  ```
- **过度依赖反向引用进行性能敏感的操作:**  反向引用在某些情况下可能导致性能下降，因为引擎需要记住捕获组的内容。
  ```javascript
  // 性能敏感的错误示例：过度使用反向引用
  const regex = /^(a+)\1+$/; // 匹配 "aaaaaa" 等，性能可能随字符串长度增加而下降
  ```
- **在 `/i` 模式下期望字符集只包含 ASCII 字符:**  在忽略大小写模式下，字符集 `[a-z]` 实际上会匹配更多字符，包括非 ASCII 的大小写等价字符。
  ```javascript
  const regex = /[a-z]/i;
  console.log(regex.test('Ä')); // 输出 true，因为 Ä 是 a 的大小写等价字符
  ```

**总结:**

这段代码是 V8 正则表达式引擎的核心组成部分，它负责将正则表达式的抽象表示转换为底层的执行结构，并进行各种优化以提高匹配效率。它涵盖了选择分支、量词、断言、反向引用、分组和字符集等关键的正则表达式特性，并特别关注了 Unicode 支持和性能优化。

Prompt: 
```
这是目录为v8/src/regexp/regexp-compiler-tonode.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-compiler-tonode.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
= alt_atom->data().at(0);
      if (!Equals(ignore_case, canonicalize, new_prefix, common_prefix)) break;
#endif  // V8_INTL_SUPPORT
      prefix_length = std::min(prefix_length, alt_atom->length());
      i++;
    }
    if (i > first_with_prefix + 2) {
      // Found worthwhile run of alternatives with common prefix of at least one
      // character.  The sorting function above did not sort on more than one
      // character for reasons of correctness, but there may still be a longer
      // common prefix if the terms were similar or presorted in the input.
      // Find out how long the common prefix is.
      int run_length = i - first_with_prefix;
      RegExpAtom* const alt_atom =
          alternatives->at(first_with_prefix)->AsAtom();
      for (int j = 1; j < run_length && prefix_length > 1; j++) {
        RegExpAtom* old_atom =
            alternatives->at(j + first_with_prefix)->AsAtom();
        for (int k = 1; k < prefix_length; k++) {
#ifdef V8_INTL_SUPPORT
          if (!CharAtEquals(ignore_case, k, alt_atom, old_atom)) {
#else
          if (!CharAtEquals(ignore_case, canonicalize, k, alt_atom, old_atom)) {
#endif  // V8_INTL_SUPPORT
            prefix_length = k;
            break;
          }
        }
      }
      RegExpAtom* prefix =
          zone->New<RegExpAtom>(alt_atom->data().SubVector(0, prefix_length));
      ZoneList<RegExpTree*>* pair = zone->New<ZoneList<RegExpTree*>>(2, zone);
      pair->Add(prefix, zone);
      ZoneList<RegExpTree*>* suffixes =
          zone->New<ZoneList<RegExpTree*>>(run_length, zone);
      for (int j = 0; j < run_length; j++) {
        RegExpAtom* old_atom =
            alternatives->at(j + first_with_prefix)->AsAtom();
        int len = old_atom->length();
        if (len == prefix_length) {
          suffixes->Add(zone->New<RegExpEmpty>(), zone);
        } else {
          RegExpTree* suffix = zone->New<RegExpAtom>(
              old_atom->data().SubVector(prefix_length, old_atom->length()));
          suffixes->Add(suffix, zone);
        }
      }
      pair->Add(zone->New<RegExpDisjunction>(suffixes), zone);
      alternatives->at(write_posn++) = zone->New<RegExpAlternative>(pair);
    } else {
      // Just copy any non-worthwhile alternatives.
      for (int j = first_with_prefix; j < i; j++) {
        alternatives->at(write_posn++) = alternatives->at(j);
      }
    }
  }
  alternatives->Rewind(write_posn);  // Trim end of array.
}

// Optimizes b|c|z to [bcz].
void RegExpDisjunction::FixSingleCharacterDisjunctions(
    RegExpCompiler* compiler) {
  Zone* zone = compiler->zone();
  ZoneList<RegExpTree*>* alternatives = this->alternatives();
  int length = alternatives->length();

  int write_posn = 0;
  int i = 0;
  while (i < length) {
    RegExpTree* alternative = alternatives->at(i);
    if (!alternative->IsAtom()) {
      alternatives->at(write_posn++) = alternatives->at(i);
      i++;
      continue;
    }
    RegExpAtom* const atom = alternative->AsAtom();
    if (atom->length() != 1) {
      alternatives->at(write_posn++) = alternatives->at(i);
      i++;
      continue;
    }
    const RegExpFlags flags = compiler->flags();
    DCHECK_IMPLIES(IsEitherUnicode(flags),
                   !unibrow::Utf16::IsLeadSurrogate(atom->data().at(0)));
    bool contains_trail_surrogate =
        unibrow::Utf16::IsTrailSurrogate(atom->data().at(0));
    int first_in_run = i;
    i++;
    // Find a run of single-character atom alternatives that have identical
    // flags (case independence and unicode-ness).
    while (i < length) {
      alternative = alternatives->at(i);
      if (!alternative->IsAtom()) break;
      RegExpAtom* const alt_atom = alternative->AsAtom();
      if (alt_atom->length() != 1) break;
      DCHECK_IMPLIES(IsEitherUnicode(flags),
                     !unibrow::Utf16::IsLeadSurrogate(alt_atom->data().at(0)));
      contains_trail_surrogate |=
          unibrow::Utf16::IsTrailSurrogate(alt_atom->data().at(0));
      i++;
    }
    if (i > first_in_run + 1) {
      // Found non-trivial run of single-character alternatives.
      int run_length = i - first_in_run;
      ZoneList<CharacterRange>* ranges =
          zone->New<ZoneList<CharacterRange>>(2, zone);
      for (int j = 0; j < run_length; j++) {
        RegExpAtom* old_atom = alternatives->at(j + first_in_run)->AsAtom();
        DCHECK_EQ(old_atom->length(), 1);
        ranges->Add(CharacterRange::Singleton(old_atom->data().at(0)), zone);
      }
      RegExpClassRanges::ClassRangesFlags class_ranges_flags;
      if (IsEitherUnicode(flags) && contains_trail_surrogate) {
        class_ranges_flags = RegExpClassRanges::CONTAINS_SPLIT_SURROGATE;
      }
      alternatives->at(write_posn++) =
          zone->New<RegExpClassRanges>(zone, ranges, class_ranges_flags);
    } else {
      // Just copy any trivial alternatives.
      for (int j = first_in_run; j < i; j++) {
        alternatives->at(write_posn++) = alternatives->at(j);
      }
    }
  }
  alternatives->Rewind(write_posn);  // Trim end of array.
}

RegExpNode* RegExpDisjunction::ToNode(RegExpCompiler* compiler,
                                      RegExpNode* on_success) {
  compiler->ToNodeMaybeCheckForStackOverflow();

  ZoneList<RegExpTree*>* alternatives = this->alternatives();

  if (alternatives->length() > 2) {
    bool found_consecutive_atoms = SortConsecutiveAtoms(compiler);
    if (found_consecutive_atoms) RationalizeConsecutiveAtoms(compiler);
    FixSingleCharacterDisjunctions(compiler);
    if (alternatives->length() == 1) {
      return alternatives->at(0)->ToNode(compiler, on_success);
    }
  }

  int length = alternatives->length();

  ChoiceNode* result =
      compiler->zone()->New<ChoiceNode>(length, compiler->zone());
  for (int i = 0; i < length; i++) {
    GuardedAlternative alternative(
        alternatives->at(i)->ToNode(compiler, on_success));
    result->AddAlternative(alternative);
  }
  return result;
}

RegExpNode* RegExpQuantifier::ToNode(RegExpCompiler* compiler,
                                     RegExpNode* on_success) {
  return ToNode(min(), max(), is_greedy(), body(), compiler, on_success);
}

namespace {
// Desugar \b to (?<=\w)(?=\W)|(?<=\W)(?=\w) and
//         \B to (?<=\w)(?=\w)|(?<=\W)(?=\W)
RegExpNode* BoundaryAssertionAsLookaround(RegExpCompiler* compiler,
                                          RegExpNode* on_success,
                                          RegExpAssertion::Type type) {
  CHECK(NeedsUnicodeCaseEquivalents(compiler->flags()));
  Zone* zone = compiler->zone();
  ZoneList<CharacterRange>* word_range =
      zone->New<ZoneList<CharacterRange>>(2, zone);
  CharacterRange::AddClassEscape(StandardCharacterSet::kWord, word_range, true,
                                 zone);
  int stack_register = compiler->UnicodeLookaroundStackRegister();
  int position_register = compiler->UnicodeLookaroundPositionRegister();
  ChoiceNode* result = zone->New<ChoiceNode>(2, zone);
  // Add two choices. The (non-)boundary could start with a word or
  // a non-word-character.
  for (int i = 0; i < 2; i++) {
    bool lookbehind_for_word = i == 0;
    bool lookahead_for_word =
        (type == RegExpAssertion::Type::BOUNDARY) ^ lookbehind_for_word;
    // Look to the left.
    RegExpLookaround::Builder lookbehind(lookbehind_for_word, on_success,
                                         stack_register, position_register);
    RegExpNode* backward = TextNode::CreateForCharacterRanges(
        zone, word_range, true, lookbehind.on_match_success());
    // Look to the right.
    RegExpLookaround::Builder lookahead(lookahead_for_word,
                                        lookbehind.ForMatch(backward),
                                        stack_register, position_register);
    RegExpNode* forward = TextNode::CreateForCharacterRanges(
        zone, word_range, false, lookahead.on_match_success());
    result->AddAlternative(GuardedAlternative(lookahead.ForMatch(forward)));
  }
  return result;
}
}  // anonymous namespace

RegExpNode* RegExpAssertion::ToNode(RegExpCompiler* compiler,
                                    RegExpNode* on_success) {
  NodeInfo info;
  Zone* zone = compiler->zone();

  switch (assertion_type()) {
    case Type::START_OF_LINE:
      return AssertionNode::AfterNewline(on_success);
    case Type::START_OF_INPUT:
      return AssertionNode::AtStart(on_success);
    case Type::BOUNDARY:
      return NeedsUnicodeCaseEquivalents(compiler->flags())
                 ? BoundaryAssertionAsLookaround(compiler, on_success,
                                                 Type::BOUNDARY)
                 : AssertionNode::AtBoundary(on_success);
    case Type::NON_BOUNDARY:
      return NeedsUnicodeCaseEquivalents(compiler->flags())
                 ? BoundaryAssertionAsLookaround(compiler, on_success,
                                                 Type::NON_BOUNDARY)
                 : AssertionNode::AtNonBoundary(on_success);
    case Type::END_OF_INPUT:
      return AssertionNode::AtEnd(on_success);
    case Type::END_OF_LINE: {
      // Compile $ in multiline regexps as an alternation with a positive
      // lookahead in one side and an end-of-input on the other side.
      // We need two registers for the lookahead.
      int stack_pointer_register = compiler->AllocateRegister();
      int position_register = compiler->AllocateRegister();
      // The ChoiceNode to distinguish between a newline and end-of-input.
      ChoiceNode* result = zone->New<ChoiceNode>(2, zone);
      // Create a newline atom.
      ZoneList<CharacterRange>* newline_ranges =
          zone->New<ZoneList<CharacterRange>>(3, zone);
      CharacterRange::AddClassEscape(StandardCharacterSet::kLineTerminator,
                                     newline_ranges, false, zone);
      RegExpClassRanges* newline_atom =
          zone->New<RegExpClassRanges>(StandardCharacterSet::kLineTerminator);
      ActionNode* submatch_success = ActionNode::PositiveSubmatchSuccess(
          stack_pointer_register, position_register,
          0,   // No captures inside.
          -1,  // Ignored if no captures.
          on_success);
      TextNode* newline_matcher =
          zone->New<TextNode>(newline_atom, false, submatch_success);
      // Create an end-of-input matcher.
      RegExpNode* end_of_line = ActionNode::BeginPositiveSubmatch(
          stack_pointer_register, position_register, newline_matcher,
          submatch_success);
      // Add the two alternatives to the ChoiceNode.
      GuardedAlternative eol_alternative(end_of_line);
      result->AddAlternative(eol_alternative);
      GuardedAlternative end_alternative(AssertionNode::AtEnd(on_success));
      result->AddAlternative(end_alternative);
      return result;
    }
    default:
      UNREACHABLE();
  }
}

RegExpNode* RegExpBackReference::ToNode(RegExpCompiler* compiler,
                                        RegExpNode* on_success) {
  RegExpNode* backref_node = on_success;
  // Only one of the captures in the list can actually match. Since
  // back-references to unmatched captures are treated as empty, we can simply
  // create back-references to all possible captures.
  for (auto capture : *captures()) {
    backref_node = compiler->zone()->New<BackReferenceNode>(
        RegExpCapture::StartRegister(capture->index()),
        RegExpCapture::EndRegister(capture->index()), compiler->read_backward(),
        backref_node);
  }
  return backref_node;
}

RegExpNode* RegExpEmpty::ToNode(RegExpCompiler* compiler,
                                RegExpNode* on_success) {
  return on_success;
}

namespace {

class V8_NODISCARD ModifiersScope {
 public:
  ModifiersScope(RegExpCompiler* compiler, RegExpFlags flags)
      : compiler_(compiler), previous_flags_(compiler->flags()) {
    compiler->set_flags(flags);
  }
  ~ModifiersScope() { compiler_->set_flags(previous_flags_); }

 private:
  RegExpCompiler* compiler_;
  const RegExpFlags previous_flags_;
};

}  // namespace

RegExpNode* RegExpGroup::ToNode(RegExpCompiler* compiler,
                                RegExpNode* on_success) {
  // If no flags are modified, simply convert and return the body.
  if (flags() == compiler->flags()) {
    return body_->ToNode(compiler, on_success);
  }
  // Reset flags for successor node.
  const RegExpFlags old_flags = compiler->flags();
  on_success = ActionNode::ModifyFlags(old_flags, on_success);

  // Convert body using modifier.
  ModifiersScope modifiers_scope(compiler, flags());
  RegExpNode* body = body_->ToNode(compiler, on_success);

  // Wrap body into modifier node.
  RegExpNode* modified_body = ActionNode::ModifyFlags(flags(), body);
  return modified_body;
}

RegExpLookaround::Builder::Builder(bool is_positive, RegExpNode* on_success,
                                   int stack_pointer_register,
                                   int position_register,
                                   int capture_register_count,
                                   int capture_register_start)
    : is_positive_(is_positive),
      on_success_(on_success),
      stack_pointer_register_(stack_pointer_register),
      position_register_(position_register) {
  if (is_positive_) {
    on_match_success_ = ActionNode::PositiveSubmatchSuccess(
        stack_pointer_register, position_register, capture_register_count,
        capture_register_start, on_success_);
  } else {
    Zone* zone = on_success_->zone();
    on_match_success_ = zone->New<NegativeSubmatchSuccess>(
        stack_pointer_register, position_register, capture_register_count,
        capture_register_start, zone);
  }
}

RegExpNode* RegExpLookaround::Builder::ForMatch(RegExpNode* match) {
  if (is_positive_) {
    ActionNode* on_match_success = on_match_success_->AsActionNode();
    return ActionNode::BeginPositiveSubmatch(
        stack_pointer_register_, position_register_, match, on_match_success);
  } else {
    Zone* zone = on_success_->zone();
    // We use a ChoiceNode to represent the negative lookaround. The first
    // alternative is the negative match. On success, the end node backtracks.
    // On failure, the second alternative is tried and leads to success.
    // NegativeLookaroundChoiceNode is a special ChoiceNode that ignores the
    // first exit when calculating quick checks.
    ChoiceNode* choice_node = zone->New<NegativeLookaroundChoiceNode>(
        GuardedAlternative(match), GuardedAlternative(on_success_), zone);
    return ActionNode::BeginNegativeSubmatch(stack_pointer_register_,
                                             position_register_, choice_node);
  }
}

RegExpNode* RegExpLookaround::ToNode(RegExpCompiler* compiler,
                                     RegExpNode* on_success) {
  compiler->ToNodeMaybeCheckForStackOverflow();

  int stack_pointer_register = compiler->AllocateRegister();
  int position_register = compiler->AllocateRegister();

  const int registers_per_capture = 2;
  const int register_of_first_capture = 2;
  int register_count = capture_count_ * registers_per_capture;
  int register_start =
      register_of_first_capture + capture_from_ * registers_per_capture;

  RegExpNode* result;
  bool was_reading_backward = compiler->read_backward();
  compiler->set_read_backward(type() == LOOKBEHIND);
  Builder builder(is_positive(), on_success, stack_pointer_register,
                  position_register, register_count, register_start);
  RegExpNode* match = body_->ToNode(compiler, builder.on_match_success());
  result = builder.ForMatch(match);
  compiler->set_read_backward(was_reading_backward);
  return result;
}

RegExpNode* RegExpCapture::ToNode(RegExpCompiler* compiler,
                                  RegExpNode* on_success) {
  return ToNode(body(), index(), compiler, on_success);
}

RegExpNode* RegExpCapture::ToNode(RegExpTree* body, int index,
                                  RegExpCompiler* compiler,
                                  RegExpNode* on_success) {
  DCHECK_NOT_NULL(body);
  int start_reg = RegExpCapture::StartRegister(index);
  int end_reg = RegExpCapture::EndRegister(index);
  if (compiler->read_backward()) std::swap(start_reg, end_reg);
  RegExpNode* store_end = ActionNode::StorePosition(end_reg, true, on_success);
  RegExpNode* body_node = body->ToNode(compiler, store_end);
  return ActionNode::StorePosition(start_reg, true, body_node);
}

namespace {

class AssertionSequenceRewriter final {
 public:
  // TODO(jgruber): Consider moving this to a separate AST tree rewriter pass
  // instead of sprinkling rewrites into the AST->Node conversion process.
  static void MaybeRewrite(ZoneList<RegExpTree*>* terms, Zone* zone) {
    AssertionSequenceRewriter rewriter(terms, zone);

    static constexpr int kNoIndex = -1;
    int from = kNoIndex;

    for (int i = 0; i < terms->length(); i++) {
      RegExpTree* t = terms->at(i);
      if (from == kNoIndex && t->IsAssertion()) {
        from = i;  // Start a sequence.
      } else if (from != kNoIndex && !t->IsAssertion()) {
        // Terminate and process the sequence.
        if (i - from > 1) rewriter.Rewrite(from, i);
        from = kNoIndex;
      }
    }

    if (from != kNoIndex && terms->length() - from > 1) {
      rewriter.Rewrite(from, terms->length());
    }
  }

  // All assertions are zero width. A consecutive sequence of assertions is
  // order-independent. There's two ways we can optimize here:
  // 1. fold all identical assertions.
  // 2. if any assertion combinations are known to fail (e.g. \b\B), the entire
  //    sequence fails.
  void Rewrite(int from, int to) {
    DCHECK_GT(to, from + 1);

    // Bitfield of all seen assertions.
    uint32_t seen_assertions = 0;
    static_assert(static_cast<int>(RegExpAssertion::Type::LAST_ASSERTION_TYPE) <
                  kUInt32Size * kBitsPerByte);

    for (int i = from; i < to; i++) {
      RegExpAssertion* t = terms_->at(i)->AsAssertion();
      const uint32_t bit = 1 << static_cast<int>(t->assertion_type());

      if (seen_assertions & bit) {
        // Fold duplicates.
        terms_->Set(i, zone_->New<RegExpEmpty>());
      }

      seen_assertions |= bit;
    }

    // Collapse failures.
    const uint32_t always_fails_mask =
        1 << static_cast<int>(RegExpAssertion::Type::BOUNDARY) |
        1 << static_cast<int>(RegExpAssertion::Type::NON_BOUNDARY);
    if ((seen_assertions & always_fails_mask) == always_fails_mask) {
      ReplaceSequenceWithFailure(from, to);
    }
  }

  void ReplaceSequenceWithFailure(int from, int to) {
    // Replace the entire sequence with a single node that always fails.
    // TODO(jgruber): Consider adding an explicit Fail kind. Until then, the
    // negated '*' (everything) range serves the purpose.
    ZoneList<CharacterRange>* ranges =
        zone_->New<ZoneList<CharacterRange>>(0, zone_);
    RegExpClassRanges* cc = zone_->New<RegExpClassRanges>(zone_, ranges);
    terms_->Set(from, cc);

    // Zero out the rest.
    RegExpEmpty* empty = zone_->New<RegExpEmpty>();
    for (int i = from + 1; i < to; i++) terms_->Set(i, empty);
  }

 private:
  AssertionSequenceRewriter(ZoneList<RegExpTree*>* terms, Zone* zone)
      : zone_(zone), terms_(terms) {}

  Zone* zone_;
  ZoneList<RegExpTree*>* terms_;
};

}  // namespace

RegExpNode* RegExpAlternative::ToNode(RegExpCompiler* compiler,
                                      RegExpNode* on_success) {
  compiler->ToNodeMaybeCheckForStackOverflow();

  ZoneList<RegExpTree*>* children = nodes();

  AssertionSequenceRewriter::MaybeRewrite(children, compiler->zone());

  RegExpNode* current = on_success;
  if (compiler->read_backward()) {
    for (int i = 0; i < children->length(); i++) {
      current = children->at(i)->ToNode(compiler, current);
    }
  } else {
    for (int i = children->length() - 1; i >= 0; i--) {
      current = children->at(i)->ToNode(compiler, current);
    }
  }
  return current;
}

namespace {

void AddClass(const int* elmv, int elmc, ZoneList<CharacterRange>* ranges,
              Zone* zone) {
  elmc--;
  DCHECK_EQ(kRangeEndMarker, elmv[elmc]);
  for (int i = 0; i < elmc; i += 2) {
    DCHECK(elmv[i] < elmv[i + 1]);
    ranges->Add(CharacterRange::Range(elmv[i], elmv[i + 1] - 1), zone);
  }
}

void AddClassNegated(const int* elmv, int elmc,
                     ZoneList<CharacterRange>* ranges, Zone* zone) {
  elmc--;
  DCHECK_EQ(kRangeEndMarker, elmv[elmc]);
  DCHECK_NE(0x0000, elmv[0]);
  DCHECK_NE(kMaxCodePoint, elmv[elmc - 1]);
  base::uc16 last = 0x0000;
  for (int i = 0; i < elmc; i += 2) {
    DCHECK(last <= elmv[i] - 1);
    DCHECK(elmv[i] < elmv[i + 1]);
    ranges->Add(CharacterRange::Range(last, elmv[i] - 1), zone);
    last = elmv[i + 1];
  }
  ranges->Add(CharacterRange::Range(last, kMaxCodePoint), zone);
}

}  // namespace

void CharacterRange::AddClassEscape(StandardCharacterSet standard_character_set,
                                    ZoneList<CharacterRange>* ranges,
                                    bool add_unicode_case_equivalents,
                                    Zone* zone) {
  if (add_unicode_case_equivalents &&
      (standard_character_set == StandardCharacterSet::kWord ||
       standard_character_set == StandardCharacterSet::kNotWord)) {
    // See #sec-runtime-semantics-wordcharacters-abstract-operation
    // In case of unicode and ignore_case, we need to create the closure over
    // case equivalent characters before negating.
    ZoneList<CharacterRange>* new_ranges =
        zone->New<ZoneList<CharacterRange>>(2, zone);
    AddClass(kWordRanges, kWordRangeCount, new_ranges, zone);
    AddUnicodeCaseEquivalents(new_ranges, zone);
    if (standard_character_set == StandardCharacterSet::kNotWord) {
      ZoneList<CharacterRange>* negated =
          zone->New<ZoneList<CharacterRange>>(2, zone);
      CharacterRange::Negate(new_ranges, negated, zone);
      new_ranges = negated;
    }
    ranges->AddAll(*new_ranges, zone);
    return;
  }

  switch (standard_character_set) {
    case StandardCharacterSet::kWhitespace:
      AddClass(kSpaceRanges, kSpaceRangeCount, ranges, zone);
      break;
    case StandardCharacterSet::kNotWhitespace:
      AddClassNegated(kSpaceRanges, kSpaceRangeCount, ranges, zone);
      break;
    case StandardCharacterSet::kWord:
      AddClass(kWordRanges, kWordRangeCount, ranges, zone);
      break;
    case StandardCharacterSet::kNotWord:
      AddClassNegated(kWordRanges, kWordRangeCount, ranges, zone);
      break;
    case StandardCharacterSet::kDigit:
      AddClass(kDigitRanges, kDigitRangeCount, ranges, zone);
      break;
    case StandardCharacterSet::kNotDigit:
      AddClassNegated(kDigitRanges, kDigitRangeCount, ranges, zone);
      break;
    // This is the set of characters matched by the $ and ^ symbols
    // in multiline mode.
    case StandardCharacterSet::kLineTerminator:
      AddClass(kLineTerminatorRanges, kLineTerminatorRangeCount, ranges, zone);
      break;
    case StandardCharacterSet::kNotLineTerminator:
      AddClassNegated(kLineTerminatorRanges, kLineTerminatorRangeCount, ranges,
                      zone);
      break;
    // This is not a character range as defined by the spec but a
    // convenient shorthand for a character class that matches any
    // character.
    case StandardCharacterSet::kEverything:
      ranges->Add(CharacterRange::Everything(), zone);
      break;
  }
}

// static
// Only for /i, not for /ui or /vi.
void CharacterRange::AddCaseEquivalents(Isolate* isolate, Zone* zone,
                                        ZoneList<CharacterRange>* ranges,
                                        bool is_one_byte) {
  CharacterRange::Canonicalize(ranges);
  int range_count = ranges->length();
#ifdef V8_INTL_SUPPORT
  icu::UnicodeSet others;
  for (int i = 0; i < range_count; i++) {
    CharacterRange range = ranges->at(i);
    base::uc32 from = range.from();
    if (from > kMaxUtf16CodeUnit) continue;
    base::uc32 to = std::min({range.to(), kMaxUtf16CodeUnitU});
    // Nothing to be done for surrogates.
    if (from >= kLeadSurrogateStart && to <= kTrailSurrogateEnd) continue;
    if (is_one_byte && !RangeContainsLatin1Equivalents(range)) {
      if (from > String::kMaxOneByteCharCode) continue;
      if (to > String::kMaxOneByteCharCode) to = String::kMaxOneByteCharCode;
    }
    others.add(from, to);
  }

  // Compute the set of additional characters that should be added,
  // using UnicodeSet::closeOver. ECMA 262 defines slightly different
  // case-folding rules than Unicode, so some characters that are
  // added by closeOver do not match anything other than themselves in
  // JS. For example, 'ſ' (U+017F LATIN SMALL LETTER LONG S) is the
  // same case-insensitive character as 's' or 'S' according to
  // Unicode, but does not match any other character in JS. To handle
  // this case, we add such characters to the IgnoreSet and filter
  // them out. We filter twice: once before calling closeOver (to
  // prevent 'ſ' from adding 's'), and once after calling closeOver
  // (to prevent 's' from adding 'ſ'). See regexp/special-case.h for
  // more information.
  icu::UnicodeSet already_added(others);
  others.removeAll(RegExpCaseFolding::IgnoreSet());
  others.closeOver(USET_CASE_INSENSITIVE);
  others.removeAll(RegExpCaseFolding::IgnoreSet());
  others.removeAll(already_added);

  // Add others to the ranges
  for (int32_t i = 0; i < others.getRangeCount(); i++) {
    UChar32 from = others.getRangeStart(i);
    UChar32 to = others.getRangeEnd(i);
    if (from == to) {
      ranges->Add(CharacterRange::Singleton(from), zone);
    } else {
      ranges->Add(CharacterRange::Range(from, to), zone);
    }
  }
#else
  for (int i = 0; i < range_count; i++) {
    CharacterRange range = ranges->at(i);
    base::uc32 bottom = range.from();
    if (bottom > kMaxUtf16CodeUnit) continue;
    base::uc32 top = std::min({range.to(), kMaxUtf16CodeUnitU});
    // Nothing to be done for surrogates.
    if (bottom >= kLeadSurrogateStart && top <= kTrailSurrogateEnd) continue;
    if (is_one_byte && !RangeContainsLatin1Equivalents(range)) {
      if (bottom > String::kMaxOneByteCharCode) continue;
      if (top > String::kMaxOneByteCharCode) top = String::kMaxOneByteCharCode;
    }
    unibrow::uchar chars[unibrow::Ecma262UnCanonicalize::kMaxWidth];
    if (top == bottom) {
      // If this is a singleton we just expand the one character.
      int length = isolate->jsregexp_uncanonicalize()->get(bottom, '\0', chars);
      for (int i = 0; i < length; i++) {
        base::uc32 chr = chars[i];
        if (chr != bottom) {
          ranges->Add(CharacterRange::Singleton(chars[i]), zone);
        }
      }
    } else {
      // If this is a range we expand the characters block by block, expanding
      // contiguous subranges (blocks) one at a time.  The approach is as
      // follows.  For a given start character we look up the remainder of the
      // block that contains it (represented by the end point), for instance we
      // find 'z' if the character is 'c'.  A block is characterized by the
      // property that all characters uncanonicalize in the same way, except
      // that each entry in the result is incremented by the distance from the
      // first element.  So a-z is a block because 'a' uncanonicalizes to ['a',
      // 'A'] and the k'th letter uncanonicalizes to ['a' + k, 'A' + k].  Once
      // we've found the end point we look up its uncanonicalization and
      // produce a range for each element.  For instance for [c-f] we look up
      // ['z', 'Z'] and produce [c-f] and [C-F].  We then only add a range if
      // it is not already contained in the input, so [c-f] will be skipped but
      // [C-F] will be added.  If this range is not completely contained in a
      // block we do this for all the blocks covered by the range (handling
      // characters that is not in a block as a "singleton block").
      unibrow::uchar equivalents[unibrow::Ecma262UnCanonicalize::kMaxWidth];
      base::uc32 pos = bottom;
      while (pos <= top) {
        int length =
            isolate->jsregexp_canonrange()->get(pos, '\0', equivalents);
        base::uc32 block_end;
        if (length == 0) {
          block_end = pos;
        } else {
          DCHECK_EQ(1, length);
          block_end = equivalents[0];
        }
        int end = (block_end > top) ? top : block_end;
        length = isolate->jsregexp_uncanonicalize()->get(block_end, '\0',
                                                         equivalents);
        for (int i = 0; i < length; i++) {
          base::uc32 c = equivalents[i];
          base::uc32 range_from = c - (block_end - pos);
          base::uc32 range_to = c - (block_end - end);
          if (!(bottom <= range_from && range_to <= top)) {
            ranges->Add(CharacterRange::Range(range_from, range_to), zone);
          }
        }
        pos = end + 1;
      }
    }
  }
#endif  // V8_INTL_SUPPORT
}

bool CharacterRange::IsCanonical(const ZoneList<CharacterRange>* ranges) {
  DCHECK_NOT_NULL(ranges);
  int n = ranges->length();
  if (n <= 1) return true;
  base::uc32 max = ranges->at(0).to();
  for (int i = 1; i < n; i++) {
    CharacterRange next_range = ranges->at(i);
    if (next_range.from() <= max + 1) return false;
    max = next_range.to();
  }
  return true;
}

ZoneList<CharacterRange>* CharacterSet::ranges(Zone* zone) {
  if (ranges_ == nullptr) {
    ranges_ = zone->New<ZoneList<CharacterRange>>(2, zone);
    CharacterRange::AddClassEscape(standard_set_type_.value(), ranges_, false,
                                   zone);
  }
  return ranges_;
}

namespace {

// Move a number of elements in a zonelist to another position
// in the same list. Handles overlapping source and target areas.
void MoveRanges(ZoneList<CharacterRange>* list, int from, int to, int count) {
  // Ranges are potentially overlapping.
  if (from < to) {
    for (int i = count - 1; i >= 0; i--) {
      list->at(to + i) = list->at(from + i);
    }
  } else {
    for (int i = 0; i < count; i++) {
      list->at(to + i) = list->at(from + i);
    }
  }
}

int InsertRangeInCanonicalList(ZoneList<CharacterRange>* list, int count,
                               CharacterRange insert) {
  // Inserts a range into list[0..count[, which must be sorted
  // by from value and non-overlapping and non-adjacent, using at most
  // list[0..count] for the result. Returns the number of resulting
  // canonicalized ranges. Inserting a range may collapse existing ranges into
  // fewer ranges, so the return value can be anything in the range 1..count+1.
  base::uc32 from = insert.from();
  base::uc32 to = insert.to();
  int start_pos = 0;
  int end_pos = count;
  for (int i = count - 1; i >= 0; i--) {
    CharacterRange current = list->at(i);
    if (current.from() > to + 1) {
      end_pos = i;
    } else if (current.to() + 1 < from) {
      start_pos = i + 1;
      break;
    }
  }

  // Inserted range overlaps, or is adjacent to, ranges at positions
  // [start_pos..end_pos[. Ranges before start_pos or at or after end_pos are
  // not affected by the insertion.
  // If start_pos == end_pos, the range must be inserted before start_pos.
  // if start_pos < end_pos, the entire range from start_pos to end_pos
  // must be merged with the insert range.

  if (start_pos == end_pos) {
    // Insert between existing ranges at position start_pos.
    if (start_pos < count) {
      MoveRanges(list, start_pos, start_pos + 1, count - start_pos);
    }
    list->at(start_pos) = insert;
    return count + 1;
  }
  if (start_pos + 1 == end_pos) {
    // Replace single existing range at position start_pos.
    CharacterRange to_replace = list->at(start_pos);
    int new_from = std::min(to_replace.from(), from);
    int new_to = std::max(to_replace.to(), to);
    list->at(start_pos) = CharacterRange::Range(new_from, new_to);
    return count;
  }
  // Replace a number of existing ranges from start_pos to end_pos - 1.
  // Move the remaining ranges down.

  int new_from = std::min(list->at(start_pos).from(), from);
  int new_to = std::max(list->at(end_pos - 1).to(), to);
  if (end_pos < count) {
    MoveRanges(list, end_pos, start_pos + 1, count - end_pos);
  }
  list->at(start_pos) = CharacterRange::Range(new_from, new_to);
  return count - (end_pos - start_pos) + 1;
}

}  // namespace

void CharacterSet::Canonicalize() {
  // Special/default classes are always considered canonical. The result
  // of calling ranges() will be sorted.
  if (ranges_ == nullptr) return;
  CharacterRange::Canonicalize(ranges_);
}

// static
void CharacterRange::Canonicalize(ZoneList<CharacterRange>* character_ranges) {
  if (character_ranges->length() <= 1) return;
  // Check whether ranges are already canonical (increasing, non-overlapping,
  // non-adjacent).
 
"""


```