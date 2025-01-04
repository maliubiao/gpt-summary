Response: The user wants a summary of the C++ source code file `v8/src/regexp/regexp-compiler.cc`. This is the third part of a three-part summary request. I need to focus on the functionality within this specific code snippet and consider any connections to JavaScript regular expression features.

The code snippet contains several methods related to the compilation and execution of regular expressions in V8. Key areas include:

1. **Boyer-Moore Optimization:** Code related to `BoyerMooreLookahead` suggests an optimization technique for quickly skipping characters that cannot match a certain pattern.
2. **Choice Node Emission:** The `ChoiceNode::EmitChoices` method handles the generation of code for alternatives within a regular expression (the `|` operator). It includes logic for quick checks and full checks, potentially optimizing for common cases.
3. **Action Node Emission:** `ActionNode::Emit` deals with actions like capturing groups, setting registers, and checking for empty matches. These correspond to various aspects of regular expression syntax and execution.
4. **Backreference Handling:** `BackReferenceNode::Emit` generates code to handle backreferences (`\1`, `\2`, etc.), including case-insensitive matching in Unicode.
5. **Text Node Optimization:** `TextNode::CalculateOffsets` precomputes offsets within a sequence of literal characters or character classes.
6. **Analysis and Optimization Passes:** The code includes classes like `AssertionPropagator` and `EatsAtLeastPropagator`, which perform analysis passes on the regular expression to optimize the generated code.
7. **Preprocessing:** The `RegExpCompiler::PreprocessRegExp` function performs initial transformations on the regular expression tree, such as adding the `.*?` prefix for non-anchored expressions and handling Unicode surrogate pairs.

Connections to JavaScript regular expressions are evident throughout:

- **Alternation (`|`)**: The `ChoiceNode` logic directly relates to how JavaScript handles different possibilities in a regex.
- **Capturing Groups (`(...)`)**: The `ActionNode` with `STORE_POSITION` is used for capturing matched substrings.
- **Backreferences (`\1`)**: The `BackReferenceNode` handles these.
- **Anchors (`^`, `$`)**: While not explicitly in this snippet, the `PreprocessRegExp` mentions handling of anchored expressions.
- **Quantifiers (`*`, `+`, `?`, `{}`)**: The `PreprocessRegExp` demonstrates handling of `.*?`.
- **Character Classes (`[a-z]`, `\d`, `\w`)**: The `TextNode` and `RegExpClassRanges` deal with these.
- **Flags (`i`, `g`, `u`, `y`)**:  The code references `IsIgnoreCase`, `IsEitherUnicode`, `IsGlobal`, `IsSticky`, showing the integration of regex flags.

I will now construct the summary and JavaScript examples.
这个C++源代码文件 `v8/src/regexp/regexp-compiler.cc` 的第3部分主要负责以下功能：

**1. 正则表达式节点的代码生成（Code Emission for RegExp Nodes）：**

   -  **`ChoiceNode::EmitChoices`:**  负责为正则表达式中的选择分支（`|`）生成代码。它尝试进行快速检查以优化性能，如果快速检查不适用，则生成完整的检查代码。它还处理了在不同分支之间传递预加载的字符信息。
   -  **`ChoiceNode::EmitOutOfLineContinuation`:**  处理选择分支的非内联延续，当快速检查成功但需要执行完整检查时使用。
   -  **`ActionNode::Emit`:** 负责为正则表达式中的各种动作生成代码，例如：
      -  存储匹配位置 (STORE_POSITION)
      -  递增寄存器 (INCREMENT_REGISTER)
      -  为循环设置寄存器 (SET_REGISTER_FOR_LOOP)
      -  清除捕获组 (CLEAR_CAPTURES)
      -  标记肯定/否定子匹配的开始 (BEGIN_POSITIVE_SUBMATCH, BEGIN_NEGATIVE_SUBMATCH)
      -  检查是否为空匹配 (EMPTY_MATCH_CHECK)
      -  标记肯定子匹配成功 (POSITIVE_SUBMATCH_SUCCESS)
      -  修改正则表达式的标志 (MODIFY_FLAGS)
   -  **`BackReferenceNode::Emit`:**  负责为反向引用（例如 `\1`, `\2`）生成代码，包括处理大小写不敏感的情况和 Unicode 字符。
   -  **`TextNode::CalculateOffsets`:**  计算 `TextNode` 中各个元素相对于起始位置的偏移量。

**2. 正则表达式的分析和优化（RegExp Analysis and Optimization）：**

   -  **`AssertionPropagator`:**  一个分析器，用于将断言（例如 `\b`）的信息传播到受影响的节点。这有助于后续的优化。
   -  **`EatsAtLeastPropagator`:** 一个分析器，用于传播成功匹配的最小长度信息。这可以用于 Boyer-Moore 优化等。
   -  **`Analysis` 模板类和 `AnalyzeRegExp` 函数:**  使用访问者模式，遍历正则表达式的节点图，并允许分析器设置依赖于后续节点的值。这用于执行静态分析，例如上述的 `AssertionPropagator` 和 `EatsAtLeastPropagator`。

**3. Boyer-Moore 优化（Boyer-Moore Optimization）：**

   -  `eat` 方法和 `ChoiceNode::bm_info` 与 Boyer-Moore 字符串搜索算法相关，这是一种用于快速跳过不可能匹配的字符的优化技术。`FillInBMInfo` 方法用于填充 Boyer-Moore 算法所需的信息。

**4. 正则表达式的预处理（RegExp Preprocessing）：**

   -  **`RegExpCompiler::PreprocessRegExp`:**  在编译正则表达式之前执行一些预处理步骤，包括：
      -  将整个正则表达式体包裹在捕获组 0 中。
      -  如果正则表达式没有锚定在开头且不是粘性匹配，则在开头添加 `.*?`。
      -  在 Unicode 模式下，对于全局或粘性匹配，可能会添加回退到前导代理项的逻辑。
   -  **`RegExpCompiler::OptionallyStepBackToLeadSurrogate`:**  在 Unicode 模式下，为了正确处理代理对，可能会在正则表达式开头添加一个可选的回退步骤。

**与 JavaScript 的功能关系及示例：**

这些 C++ 代码直接对应于 JavaScript 中正则表达式的功能。以下是一些 JavaScript 示例说明：

**1. 选择分支 (`|`)：**

```javascript
const regex = /a|b/;
const str1 = "a";
const str2 = "b";
const str3 = "c";

console.log(regex.test(str1)); // true
console.log(regex.test(str2)); // true
console.log(regex.test(str3)); // false
```

`ChoiceNode::EmitChoices` 负责生成类似于上述 JavaScript 代码中 `a|b` 的执行逻辑。

**2. 捕获组 (`(...)`)：**

```javascript
const regex = /(hello) world/;
const str = "hello world";
const match = str.match(regex);

console.log(match[0]); // "hello world"
console.log(match[1]); // "hello"
```

`ActionNode::Emit` 中 `STORE_POSITION` 的逻辑用于记录捕获组的起始和结束位置，以便 JavaScript 可以访问捕获到的子字符串。

**3. 反向引用 (`\1`)：**

```javascript
const regex = /(\w+),\s\1/;
const str1 = "test, test";
const str2 = "test, case";

console.log(regex.test(str1)); // true
console.log(regex.test(str2)); // false
```

`BackReferenceNode::Emit` 负责生成检查反向引用是否匹配之前捕获到的内容的逻辑。

**4. Boyer-Moore 优化：**

虽然在 JavaScript 代码中看不到直接的体现，但 V8 在幕后使用类似 Boyer-Moore 的优化来加速正则表达式的匹配过程。例如，对于长的、非锚定的正则表达式，这种优化可以显著提高性能。

**5. 预处理 (`.*?`)：**

```javascript
const regex1 = /world/;
const regex2 = /^world/;
const str = "hello world";

console.log(regex1.test(str)); // true
console.log(regex2.test(str)); // false
```

对于 `regex1`，由于没有锚定在开头，V8 可能会在内部添加类似 `.*?` 的逻辑，以便在字符串中找到 "world" 的任何出现。 `RegExpCompiler::PreprocessRegExp` 就负责执行这样的转换。

**总结:**

总而言之，这个代码片段是 V8 JavaScript 引擎中用于编译和执行正则表达式的核心部分。它涵盖了从正则表达式语法树到机器码生成的关键步骤，并包含了多种优化技术以提高正则表达式的执行效率。 代码中的各种节点类型和发射方法直接对应于 JavaScript 正则表达式的语法结构和语义。

Prompt: 
```
这是目录为v8/src/regexp/regexp-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
 eat
  // any character one at a time.  Any non-anchored regexp has such a
  // loop prepended to it in order to find where it starts.  We look for
  // a pattern of the form ...abc... where we can look 6 characters ahead
  // and step forwards 3 if the character is not one of abc.  Abc need
  // not be atoms, they can be any reasonably limited character class or
  // small alternation.
  BoyerMooreLookahead* bm = bm_info(false);
  if (bm == nullptr) {
    eats_at_least = std::min(kMaxLookaheadForBoyerMoore, EatsAtLeast(false));
    if (eats_at_least >= 1) {
      bm = zone()->New<BoyerMooreLookahead>(eats_at_least, compiler, zone());
      GuardedAlternative alt0 = alternatives_->at(0);
      alt0.node()->FillInBMInfo(isolate, 0, kRecursionBudget, bm, false);
    }
  }
  if (bm != nullptr) {
    bm->EmitSkipInstructions(macro_assembler);
  }
  return eats_at_least;
}

void ChoiceNode::EmitChoices(RegExpCompiler* compiler,
                             AlternativeGenerationList* alt_gens,
                             int first_choice, Trace* trace,
                             PreloadState* preload) {
  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  SetUpPreLoad(compiler, trace, preload);

  // For now we just call all choices one after the other.  The idea ultimately
  // is to use the Dispatch table to try only the relevant ones.
  int choice_count = alternatives_->length();

  int new_flush_budget = trace->flush_budget() / choice_count;

  for (int i = first_choice; i < choice_count; i++) {
    bool is_last = i == choice_count - 1;
    bool fall_through_on_failure = !is_last;
    GuardedAlternative alternative = alternatives_->at(i);
    AlternativeGeneration* alt_gen = alt_gens->at(i);
    alt_gen->quick_check_details.set_characters(preload->preload_characters_);
    ZoneList<Guard*>* guards = alternative.guards();
    int guard_count = (guards == nullptr) ? 0 : guards->length();
    Trace new_trace(*trace);
    new_trace.set_characters_preloaded(
        preload->preload_is_current_ ? preload->preload_characters_ : 0);
    if (preload->preload_has_checked_bounds_) {
      new_trace.set_bound_checked_up_to(preload->preload_characters_);
    }
    new_trace.quick_check_performed()->Clear();
    if (not_at_start_) new_trace.set_at_start(Trace::FALSE_VALUE);
    if (!is_last) {
      new_trace.set_backtrack(&alt_gen->after);
    }
    alt_gen->expects_preload = preload->preload_is_current_;
    bool generate_full_check_inline = false;
    if (v8_flags.regexp_optimization &&
        try_to_emit_quick_check_for_alternative(i == 0) &&
        alternative.node()->EmitQuickCheck(
            compiler, trace, &new_trace, preload->preload_has_checked_bounds_,
            &alt_gen->possible_success, &alt_gen->quick_check_details,
            fall_through_on_failure, this)) {
      // Quick check was generated for this choice.
      preload->preload_is_current_ = true;
      preload->preload_has_checked_bounds_ = true;
      // If we generated the quick check to fall through on possible success,
      // we now need to generate the full check inline.
      if (!fall_through_on_failure) {
        macro_assembler->Bind(&alt_gen->possible_success);
        new_trace.set_quick_check_performed(&alt_gen->quick_check_details);
        new_trace.set_characters_preloaded(preload->preload_characters_);
        new_trace.set_bound_checked_up_to(preload->preload_characters_);
        generate_full_check_inline = true;
      }
    } else if (alt_gen->quick_check_details.cannot_match()) {
      if (!fall_through_on_failure) {
        macro_assembler->GoTo(trace->backtrack());
      }
      continue;
    } else {
      // No quick check was generated.  Put the full code here.
      // If this is not the first choice then there could be slow checks from
      // previous cases that go here when they fail.  There's no reason to
      // insist that they preload characters since the slow check we are about
      // to generate probably can't use it.
      if (i != first_choice) {
        alt_gen->expects_preload = false;
        new_trace.InvalidateCurrentCharacter();
      }
      generate_full_check_inline = true;
    }
    if (generate_full_check_inline) {
      if (new_trace.actions() != nullptr) {
        new_trace.set_flush_budget(new_flush_budget);
      }
      for (int j = 0; j < guard_count; j++) {
        GenerateGuard(macro_assembler, guards->at(j), &new_trace);
      }
      alternative.node()->Emit(compiler, &new_trace);
      preload->preload_is_current_ = false;
    }
    macro_assembler->Bind(&alt_gen->after);
  }
}

void ChoiceNode::EmitOutOfLineContinuation(RegExpCompiler* compiler,
                                           Trace* trace,
                                           GuardedAlternative alternative,
                                           AlternativeGeneration* alt_gen,
                                           int preload_characters,
                                           bool next_expects_preload) {
  if (!alt_gen->possible_success.is_linked()) return;

  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  macro_assembler->Bind(&alt_gen->possible_success);
  Trace out_of_line_trace(*trace);
  out_of_line_trace.set_characters_preloaded(preload_characters);
  out_of_line_trace.set_quick_check_performed(&alt_gen->quick_check_details);
  if (not_at_start_) out_of_line_trace.set_at_start(Trace::FALSE_VALUE);
  ZoneList<Guard*>* guards = alternative.guards();
  int guard_count = (guards == nullptr) ? 0 : guards->length();
  if (next_expects_preload) {
    Label reload_current_char;
    out_of_line_trace.set_backtrack(&reload_current_char);
    for (int j = 0; j < guard_count; j++) {
      GenerateGuard(macro_assembler, guards->at(j), &out_of_line_trace);
    }
    alternative.node()->Emit(compiler, &out_of_line_trace);
    macro_assembler->Bind(&reload_current_char);
    // Reload the current character, since the next quick check expects that.
    // We don't need to check bounds here because we only get into this
    // code through a quick check which already did the checked load.
    macro_assembler->LoadCurrentCharacter(trace->cp_offset(), nullptr, false,
                                          preload_characters);
    macro_assembler->GoTo(&(alt_gen->after));
  } else {
    out_of_line_trace.set_backtrack(&(alt_gen->after));
    for (int j = 0; j < guard_count; j++) {
      GenerateGuard(macro_assembler, guards->at(j), &out_of_line_trace);
    }
    alternative.node()->Emit(compiler, &out_of_line_trace);
  }
}

void ActionNode::Emit(RegExpCompiler* compiler, Trace* trace) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();
  LimitResult limit_result = LimitVersions(compiler, trace);
  if (limit_result == DONE) return;
  DCHECK(limit_result == CONTINUE);

  RecursionCheck rc(compiler);

  switch (action_type_) {
    case STORE_POSITION: {
      Trace::DeferredCapture new_capture(data_.u_position_register.reg,
                                         data_.u_position_register.is_capture,
                                         trace);
      Trace new_trace = *trace;
      new_trace.add_action(&new_capture);
      on_success()->Emit(compiler, &new_trace);
      break;
    }
    case INCREMENT_REGISTER: {
      Trace::DeferredIncrementRegister new_increment(
          data_.u_increment_register.reg);
      Trace new_trace = *trace;
      new_trace.add_action(&new_increment);
      on_success()->Emit(compiler, &new_trace);
      break;
    }
    case SET_REGISTER_FOR_LOOP: {
      Trace::DeferredSetRegisterForLoop new_set(data_.u_store_register.reg,
                                                data_.u_store_register.value);
      Trace new_trace = *trace;
      new_trace.add_action(&new_set);
      on_success()->Emit(compiler, &new_trace);
      break;
    }
    case CLEAR_CAPTURES: {
      Trace::DeferredClearCaptures new_capture(Interval(
          data_.u_clear_captures.range_from, data_.u_clear_captures.range_to));
      Trace new_trace = *trace;
      new_trace.add_action(&new_capture);
      on_success()->Emit(compiler, &new_trace);
      break;
    }
    case BEGIN_POSITIVE_SUBMATCH:
    case BEGIN_NEGATIVE_SUBMATCH:
      if (!trace->is_trivial()) {
        trace->Flush(compiler, this);
      } else {
        assembler->WriteCurrentPositionToRegister(
            data_.u_submatch.current_position_register, 0);
        assembler->WriteStackPointerToRegister(
            data_.u_submatch.stack_pointer_register);
        on_success()->Emit(compiler, trace);
      }
      break;
    case EMPTY_MATCH_CHECK: {
      int start_pos_reg = data_.u_empty_match_check.start_register;
      int stored_pos = 0;
      int rep_reg = data_.u_empty_match_check.repetition_register;
      bool has_minimum = (rep_reg != RegExpCompiler::kNoRegister);
      bool know_dist = trace->GetStoredPosition(start_pos_reg, &stored_pos);
      if (know_dist && !has_minimum && stored_pos == trace->cp_offset()) {
        // If we know we haven't advanced and there is no minimum we
        // can just backtrack immediately.
        assembler->GoTo(trace->backtrack());
      } else if (know_dist && stored_pos < trace->cp_offset()) {
        // If we know we've advanced we can generate the continuation
        // immediately.
        on_success()->Emit(compiler, trace);
      } else if (!trace->is_trivial()) {
        trace->Flush(compiler, this);
      } else {
        Label skip_empty_check;
        // If we have a minimum number of repetitions we check the current
        // number first and skip the empty check if it's not enough.
        if (has_minimum) {
          int limit = data_.u_empty_match_check.repetition_limit;
          assembler->IfRegisterLT(rep_reg, limit, &skip_empty_check);
        }
        // If the match is empty we bail out, otherwise we fall through
        // to the on-success continuation.
        assembler->IfRegisterEqPos(data_.u_empty_match_check.start_register,
                                   trace->backtrack());
        assembler->Bind(&skip_empty_check);
        on_success()->Emit(compiler, trace);
      }
      break;
    }
    case POSITIVE_SUBMATCH_SUCCESS: {
      if (!trace->is_trivial()) {
        trace->Flush(compiler, this);
        return;
      }
      assembler->ReadCurrentPositionFromRegister(
          data_.u_submatch.current_position_register);
      assembler->ReadStackPointerFromRegister(
          data_.u_submatch.stack_pointer_register);
      int clear_register_count = data_.u_submatch.clear_register_count;
      if (clear_register_count == 0) {
        on_success()->Emit(compiler, trace);
        return;
      }
      int clear_registers_from = data_.u_submatch.clear_register_from;
      Label clear_registers_backtrack;
      Trace new_trace = *trace;
      new_trace.set_backtrack(&clear_registers_backtrack);
      on_success()->Emit(compiler, &new_trace);

      assembler->Bind(&clear_registers_backtrack);
      int clear_registers_to = clear_registers_from + clear_register_count - 1;
      assembler->ClearRegisters(clear_registers_from, clear_registers_to);

      DCHECK(trace->backtrack() == nullptr);
      assembler->Backtrack();
      return;
    }
    case MODIFY_FLAGS: {
      compiler->set_flags(flags());
      on_success()->Emit(compiler, trace);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void BackReferenceNode::Emit(RegExpCompiler* compiler, Trace* trace) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();
  if (!trace->is_trivial()) {
    trace->Flush(compiler, this);
    return;
  }

  LimitResult limit_result = LimitVersions(compiler, trace);
  if (limit_result == DONE) return;
  DCHECK(limit_result == CONTINUE);

  RecursionCheck rc(compiler);

  DCHECK_EQ(start_reg_ + 1, end_reg_);
  if (IsIgnoreCase(compiler->flags())) {
    bool unicode = IsEitherUnicode(compiler->flags());
    assembler->CheckNotBackReferenceIgnoreCase(start_reg_, read_backward(),
                                               unicode, trace->backtrack());
  } else {
    assembler->CheckNotBackReference(start_reg_, read_backward(),
                                     trace->backtrack());
  }
  // We are going to advance backward, so we may end up at the start.
  if (read_backward()) trace->set_at_start(Trace::UNKNOWN);

  // Check that the back reference does not end inside a surrogate pair.
  if (IsEitherUnicode(compiler->flags()) && !compiler->one_byte()) {
    assembler->CheckNotInSurrogatePair(trace->cp_offset(), trace->backtrack());
  }
  on_success()->Emit(compiler, trace);
}

void TextNode::CalculateOffsets() {
  int element_count = elements()->length();
  // Set up the offsets of the elements relative to the start.  This is a fixed
  // quantity since a TextNode can only contain fixed-width things.
  int cp_offset = 0;
  for (int i = 0; i < element_count; i++) {
    TextElement& elm = elements()->at(i);
    elm.set_cp_offset(cp_offset);
    cp_offset += elm.length();
  }
}

namespace {

// Assertion propagation moves information about assertions such as
// \b to the affected nodes.  For instance, in /.\b./ information must
// be propagated to the first '.' that whatever follows needs to know
// if it matched a word or a non-word, and to the second '.' that it
// has to check if it succeeds a word or non-word.  In this case the
// result will be something like:
//
//   +-------+        +------------+
//   |   .   |        |      .     |
//   +-------+  --->  +------------+
//   | word? |        | check word |
//   +-------+        +------------+
class AssertionPropagator : public AllStatic {
 public:
  static void VisitText(TextNode* that) {}

  static void VisitAction(ActionNode* that) {
    // If the next node is interested in what it follows then this node
    // has to be interested too so it can pass the information on.
    that->info()->AddFromFollowing(that->on_success()->info());
  }

  static void VisitChoice(ChoiceNode* that, int i) {
    // Anything the following nodes need to know has to be known by
    // this node also, so it can pass it on.
    that->info()->AddFromFollowing(that->alternatives()->at(i).node()->info());
  }

  static void VisitLoopChoiceContinueNode(LoopChoiceNode* that) {
    that->info()->AddFromFollowing(that->continue_node()->info());
  }

  static void VisitLoopChoiceLoopNode(LoopChoiceNode* that) {
    that->info()->AddFromFollowing(that->loop_node()->info());
  }

  static void VisitNegativeLookaroundChoiceLookaroundNode(
      NegativeLookaroundChoiceNode* that) {
    VisitChoice(that, NegativeLookaroundChoiceNode::kLookaroundIndex);
  }

  static void VisitNegativeLookaroundChoiceContinueNode(
      NegativeLookaroundChoiceNode* that) {
    VisitChoice(that, NegativeLookaroundChoiceNode::kContinueIndex);
  }

  static void VisitBackReference(BackReferenceNode* that) {}

  static void VisitAssertion(AssertionNode* that) {}
};

// Propagates information about the minimum size of successful matches from
// successor nodes to their predecessors. Note that all eats_at_least values
// are initialized to zero before analysis.
class EatsAtLeastPropagator : public AllStatic {
 public:
  static void VisitText(TextNode* that) {
    // The eats_at_least value is not used if reading backward.
    if (!that->read_backward()) {
      // We are not at the start after this node, and thus we can use the
      // successor's eats_at_least_from_not_start value.
      uint8_t eats_at_least = base::saturated_cast<uint8_t>(
          that->Length() + that->on_success()
                               ->eats_at_least_info()
                               ->eats_at_least_from_not_start);
      that->set_eats_at_least_info(EatsAtLeastInfo(eats_at_least));
    }
  }

  static void VisitAction(ActionNode* that) {
    switch (that->action_type()) {
      case ActionNode::BEGIN_POSITIVE_SUBMATCH: {
        // For a begin positive submatch we propagate the eats_at_least
        // data from the successor of the success node, ignoring the body of
        // the lookahead, which eats nothing, since it is a zero-width
        // assertion.
        // TODO(chromium:42201836) This is better than discarding all
        // information when there is a positive lookahead, but it loses some
        // information that could be useful, since the body of the lookahead
        // could tell us something about how close to the end of the string we
        // are.
        that->set_eats_at_least_info(
            *that->success_node()->on_success()->eats_at_least_info());
        break;
      }
      case ActionNode::POSITIVE_SUBMATCH_SUCCESS:
        // We do not propagate eats_at_least data through positive submatch
        // success because it rewinds input.
        DCHECK(that->eats_at_least_info()->IsZero());
        break;
      case ActionNode::SET_REGISTER_FOR_LOOP:
        // SET_REGISTER_FOR_LOOP indicates a loop entry point, which means the
        // loop body will run at least the minimum number of times before the
        // continuation case can run.
        that->set_eats_at_least_info(
            that->on_success()->EatsAtLeastFromLoopEntry());
        break;
      case ActionNode::BEGIN_NEGATIVE_SUBMATCH:
      default:
        // Otherwise, the current node eats at least as much as its successor.
        // Note: we can propagate eats_at_least data for BEGIN_NEGATIVE_SUBMATCH
        // because NegativeLookaroundChoiceNode ignores its lookaround successor
        // when computing eats-at-least and quick check information.
        that->set_eats_at_least_info(*that->on_success()->eats_at_least_info());
        break;
    }
  }

  static void VisitChoice(ChoiceNode* that, int i) {
    // The minimum possible match from a choice node is the minimum of its
    // successors.
    EatsAtLeastInfo eats_at_least =
        i == 0 ? EatsAtLeastInfo(UINT8_MAX) : *that->eats_at_least_info();
    eats_at_least.SetMin(
        *that->alternatives()->at(i).node()->eats_at_least_info());
    that->set_eats_at_least_info(eats_at_least);
  }

  static void VisitLoopChoiceContinueNode(LoopChoiceNode* that) {
    if (!that->read_backward()) {
      that->set_eats_at_least_info(
          *that->continue_node()->eats_at_least_info());
    }
  }

  static void VisitLoopChoiceLoopNode(LoopChoiceNode* that) {}

  static void VisitNegativeLookaroundChoiceLookaroundNode(
      NegativeLookaroundChoiceNode* that) {}

  static void VisitNegativeLookaroundChoiceContinueNode(
      NegativeLookaroundChoiceNode* that) {
    that->set_eats_at_least_info(*that->continue_node()->eats_at_least_info());
  }

  static void VisitBackReference(BackReferenceNode* that) {
    if (!that->read_backward()) {
      that->set_eats_at_least_info(*that->on_success()->eats_at_least_info());
    }
  }

  static void VisitAssertion(AssertionNode* that) {
    EatsAtLeastInfo eats_at_least = *that->on_success()->eats_at_least_info();
    if (that->assertion_type() == AssertionNode::AT_START) {
      // If we know we are not at the start and we are asked "how many
      // characters will you match if you succeed?" then we can answer anything
      // since false implies false.  So let's just set the max answer
      // (UINT8_MAX) since that won't prevent us from preloading a lot of
      // characters for the other branches in the node graph.
      eats_at_least.eats_at_least_from_not_start = UINT8_MAX;
    }
    that->set_eats_at_least_info(eats_at_least);
  }
};

}  // namespace

// -------------------------------------------------------------------
// Analysis

// Iterates the node graph and provides the opportunity for propagators to set
// values that depend on successor nodes.
template <typename... Propagators>
class Analysis : public NodeVisitor {
 public:
  Analysis(Isolate* isolate, bool is_one_byte, RegExpFlags flags)
      : isolate_(isolate),
        is_one_byte_(is_one_byte),
        flags_(flags),
        error_(RegExpError::kNone) {}

  void EnsureAnalyzed(RegExpNode* that) {
    StackLimitCheck check(isolate());
    if (check.HasOverflowed()) {
      if (v8_flags.correctness_fuzzer_suppressions) {
        FATAL("Analysis: Aborting on stack overflow");
      }
      fail(RegExpError::kAnalysisStackOverflow);
      return;
    }
    if (that->info()->been_analyzed || that->info()->being_analyzed) return;
    that->info()->being_analyzed = true;
    that->Accept(this);
    that->info()->being_analyzed = false;
    that->info()->been_analyzed = true;
  }

  bool has_failed() { return error_ != RegExpError::kNone; }
  RegExpError error() {
    DCHECK(error_ != RegExpError::kNone);
    return error_;
  }
  void fail(RegExpError error) { error_ = error; }

  Isolate* isolate() const { return isolate_; }

  void VisitEnd(EndNode* that) override {
    // nothing to do
  }

// Used to call the given static function on each propagator / variadic template
// argument.
#define STATIC_FOR_EACH(expr)       \
  do {                              \
    int dummy[] = {((expr), 0)...}; \
    USE(dummy);                     \
  } while (false)

  void VisitText(TextNode* that) override {
    that->MakeCaseIndependent(isolate(), is_one_byte_, flags());
    EnsureAnalyzed(that->on_success());
    if (has_failed()) return;
    that->CalculateOffsets();
    STATIC_FOR_EACH(Propagators::VisitText(that));
  }

  void VisitAction(ActionNode* that) override {
    if (that->action_type() == ActionNode::MODIFY_FLAGS) {
      set_flags(that->flags());
    }
    EnsureAnalyzed(that->on_success());
    if (has_failed()) return;
    STATIC_FOR_EACH(Propagators::VisitAction(that));
  }

  void VisitChoice(ChoiceNode* that) override {
    for (int i = 0; i < that->alternatives()->length(); i++) {
      EnsureAnalyzed(that->alternatives()->at(i).node());
      if (has_failed()) return;
      STATIC_FOR_EACH(Propagators::VisitChoice(that, i));
    }
  }

  void VisitLoopChoice(LoopChoiceNode* that) override {
    DCHECK_EQ(that->alternatives()->length(), 2);  // Just loop and continue.

    // First propagate all information from the continuation node.
    EnsureAnalyzed(that->continue_node());
    if (has_failed()) return;
    STATIC_FOR_EACH(Propagators::VisitLoopChoiceContinueNode(that));

    // Check the loop last since it may need the value of this node
    // to get a correct result.
    EnsureAnalyzed(that->loop_node());
    if (has_failed()) return;
    STATIC_FOR_EACH(Propagators::VisitLoopChoiceLoopNode(that));
  }

  void VisitNegativeLookaroundChoice(
      NegativeLookaroundChoiceNode* that) override {
    DCHECK_EQ(that->alternatives()->length(), 2);  // Lookaround and continue.

    EnsureAnalyzed(that->lookaround_node());
    if (has_failed()) return;
    STATIC_FOR_EACH(
        Propagators::VisitNegativeLookaroundChoiceLookaroundNode(that));

    EnsureAnalyzed(that->continue_node());
    if (has_failed()) return;
    STATIC_FOR_EACH(
        Propagators::VisitNegativeLookaroundChoiceContinueNode(that));
  }

  void VisitBackReference(BackReferenceNode* that) override {
    EnsureAnalyzed(that->on_success());
    if (has_failed()) return;
    STATIC_FOR_EACH(Propagators::VisitBackReference(that));
  }

  void VisitAssertion(AssertionNode* that) override {
    EnsureAnalyzed(that->on_success());
    if (has_failed()) return;
    STATIC_FOR_EACH(Propagators::VisitAssertion(that));
  }

#undef STATIC_FOR_EACH

 private:
  RegExpFlags flags() const { return flags_; }
  void set_flags(RegExpFlags flags) { flags_ = flags; }

  Isolate* isolate_;
  const bool is_one_byte_;
  RegExpFlags flags_;
  RegExpError error_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(Analysis);
};

RegExpError AnalyzeRegExp(Isolate* isolate, bool is_one_byte, RegExpFlags flags,
                          RegExpNode* node) {
  Analysis<AssertionPropagator, EatsAtLeastPropagator> analysis(
      isolate, is_one_byte, flags);
  DCHECK_EQ(node->info()->been_analyzed, false);
  analysis.EnsureAnalyzed(node);
  DCHECK_IMPLIES(analysis.has_failed(), analysis.error() != RegExpError::kNone);
  return analysis.has_failed() ? analysis.error() : RegExpError::kNone;
}

void BackReferenceNode::FillInBMInfo(Isolate* isolate, int offset, int budget,
                                     BoyerMooreLookahead* bm,
                                     bool not_at_start) {
  // Working out the set of characters that a backreference can match is too
  // hard, so we just say that any character can match.
  bm->SetRest(offset);
  SaveBMInfo(bm, not_at_start, offset);
}

static_assert(BoyerMoorePositionInfo::kMapSize ==
              RegExpMacroAssembler::kTableSize);

void ChoiceNode::FillInBMInfo(Isolate* isolate, int offset, int budget,
                              BoyerMooreLookahead* bm, bool not_at_start) {
  ZoneList<GuardedAlternative>* alts = alternatives();
  budget = (budget - 1) / alts->length();
  for (int i = 0; i < alts->length(); i++) {
    GuardedAlternative& alt = alts->at(i);
    if (alt.guards() != nullptr && alt.guards()->length() != 0) {
      bm->SetRest(offset);  // Give up trying to fill in info.
      SaveBMInfo(bm, not_at_start, offset);
      return;
    }
    alt.node()->FillInBMInfo(isolate, offset, budget, bm, not_at_start);
  }
  SaveBMInfo(bm, not_at_start, offset);
}

void TextNode::FillInBMInfo(Isolate* isolate, int initial_offset, int budget,
                            BoyerMooreLookahead* bm, bool not_at_start) {
  if (initial_offset >= bm->length()) return;
  if (read_backward()) return;
  int offset = initial_offset;
  int max_char = bm->max_char();
  for (int i = 0; i < elements()->length(); i++) {
    if (offset >= bm->length()) {
      if (initial_offset == 0) set_bm_info(not_at_start, bm);
      return;
    }
    TextElement text = elements()->at(i);
    if (text.text_type() == TextElement::ATOM) {
      RegExpAtom* atom = text.atom();
      for (int j = 0; j < atom->length(); j++, offset++) {
        if (offset >= bm->length()) {
          if (initial_offset == 0) set_bm_info(not_at_start, bm);
          return;
        }
        base::uc16 character = atom->data()[j];
        if (IsIgnoreCase(bm->compiler()->flags())) {
          unibrow::uchar chars[4];
          int length = GetCaseIndependentLetters(isolate, character,
                                                 bm->compiler(), chars, 4);
          for (int k = 0; k < length; k++) {
            bm->Set(offset, chars[k]);
          }
        } else {
          if (character <= max_char) bm->Set(offset, character);
        }
      }
    } else {
      DCHECK_EQ(TextElement::CLASS_RANGES, text.text_type());
      RegExpClassRanges* class_ranges = text.class_ranges();
      ZoneList<CharacterRange>* ranges = class_ranges->ranges(zone());
      if (class_ranges->is_negated()) {
        bm->SetAll(offset);
      } else {
        for (int k = 0; k < ranges->length(); k++) {
          CharacterRange& range = ranges->at(k);
          if (static_cast<int>(range.from()) > max_char) continue;
          int to = std::min(max_char, static_cast<int>(range.to()));
          bm->SetInterval(offset, Interval(range.from(), to));
        }
      }
      offset++;
    }
  }
  if (offset >= bm->length()) {
    if (initial_offset == 0) set_bm_info(not_at_start, bm);
    return;
  }
  on_success()->FillInBMInfo(isolate, offset, budget - 1, bm,
                             true);  // Not at start after a text node.
  if (initial_offset == 0) set_bm_info(not_at_start, bm);
}

RegExpNode* RegExpCompiler::OptionallyStepBackToLeadSurrogate(
    RegExpNode* on_success) {
  DCHECK(!read_backward());
  ZoneList<CharacterRange>* lead_surrogates = CharacterRange::List(
      zone(), CharacterRange::Range(kLeadSurrogateStart, kLeadSurrogateEnd));
  ZoneList<CharacterRange>* trail_surrogates = CharacterRange::List(
      zone(), CharacterRange::Range(kTrailSurrogateStart, kTrailSurrogateEnd));

  ChoiceNode* optional_step_back = zone()->New<ChoiceNode>(2, zone());

  int stack_register = UnicodeLookaroundStackRegister();
  int position_register = UnicodeLookaroundPositionRegister();
  RegExpNode* step_back = TextNode::CreateForCharacterRanges(
      zone(), lead_surrogates, true, on_success);
  RegExpLookaround::Builder builder(true, step_back, stack_register,
                                    position_register);
  RegExpNode* match_trail = TextNode::CreateForCharacterRanges(
      zone(), trail_surrogates, false, builder.on_match_success());

  optional_step_back->AddAlternative(
      GuardedAlternative(builder.ForMatch(match_trail)));
  optional_step_back->AddAlternative(GuardedAlternative(on_success));

  return optional_step_back;
}

RegExpNode* RegExpCompiler::PreprocessRegExp(RegExpCompileData* data,
                                             bool is_one_byte) {
  // Wrap the body of the regexp in capture #0.
  RegExpNode* captured_body =
      RegExpCapture::ToNode(data->tree, 0, this, accept());
  RegExpNode* node = captured_body;
  if (!data->tree->IsAnchoredAtStart() && !IsSticky(flags())) {
    // Add a .*? at the beginning, outside the body capture, unless
    // this expression is anchored at the beginning or sticky.
    RegExpNode* loop_node = RegExpQuantifier::ToNode(
        0, RegExpTree::kInfinity, false,
        zone()->New<RegExpClassRanges>(StandardCharacterSet::kEverything), this,
        captured_body, data->contains_anchor);

    if (data->contains_anchor) {
      // Unroll loop once, to take care of the case that might start
      // at the start of input.
      ChoiceNode* first_step_node = zone()->New<ChoiceNode>(2, zone());
      first_step_node->AddAlternative(GuardedAlternative(captured_body));
      first_step_node->AddAlternative(GuardedAlternative(zone()->New<TextNode>(
          zone()->New<RegExpClassRanges>(StandardCharacterSet::kEverything),
          false, loop_node)));
      node = first_step_node;
    } else {
      node = loop_node;
    }
  }
  if (is_one_byte) {
    node = node->FilterOneByte(RegExpCompiler::kMaxRecursion, this);
    // Do it again to propagate the new nodes to places where they were not
    // put because they had not been calculated yet.
    if (node != nullptr) {
      node = node->FilterOneByte(RegExpCompiler::kMaxRecursion, this);
    }
  } else if (IsEitherUnicode(flags()) &&
             (IsGlobal(flags()) || IsSticky(flags()))) {
    node = OptionallyStepBackToLeadSurrogate(node);
  }

  if (node == nullptr) node = zone()->New<EndNode>(EndNode::BACKTRACK, zone());
  return node;
}

void RegExpCompiler::ToNodeCheckForStackOverflow() {
  if (StackLimitCheck{isolate()}.HasOverflowed()) {
    V8::FatalProcessOutOfMemory(isolate(), "RegExpCompiler");
  }
}

}  // namespace v8::internal

"""


```