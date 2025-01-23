Response: The user wants me to summarize the functionality of the C++ code snippet provided. This code is a part of the `regexp-compiler.cc` file in the V8 JavaScript engine. It seems to be focused on optimizing regular expression matching, specifically using techniques like "quick check" and "Boyer-Moore lookahead".

I need to identify the main actions and data structures involved and explain what they do. Also, the user wants an example in JavaScript to illustrate the connection to JavaScript functionality.
This C++ code snippet is part of the regular expression compiler in V8, the JavaScript engine. Its primary function is to implement **optimizations for regular expression matching**, specifically focusing on a technique called **"quick check"**.

Here's a breakdown of the functionality:

**1. Quick Check Optimization:**

*   The code aims to determine quickly, without executing the full regular expression matching logic, whether a potential match is possible at a given position in the input string.
*   It does this by analyzing parts of the regular expression and pre-calculating masks and values. These masks and values are then compared against characters in the input string.
*   The `QuickCheckDetails` class is central to this. It stores information about these pre-calculated masks, values, and whether a check "determines perfectly" (meaning it guarantees a match or no match).
*   The code iterates through `TextElement`s (which can be either literal characters or character classes) within the regular expression.
*   For literal characters, it checks if the character (or its case-insensitive variants) matches the input. It uses bitwise operations (`mask` and `value`) to efficiently check for matches.
*   For character classes, it calculates masks and values based on the ranges of characters in the class. It attempts to create a mask and value that can definitively determine if the input character belongs to the class. If the character class is complex (e.g., multiple ranges), the quick check might only be approximate.
*   The `GetQuickCheckDetails` function is responsible for populating the `QuickCheckDetails` structure.
*   The `Merge` function combines quick check information from different branches of a regular expression (e.g., in an "or" condition).

**2. Relationship to JavaScript:**

This code directly impacts the performance of regular expressions used in JavaScript. When a JavaScript regular expression is executed, V8 compiles it into an internal representation, and this code is involved in adding optimizations.

**JavaScript Example:**

```javascript
const regex1 = /abc/;
const text1 = "xyzabcdef";
console.log(regex1.test(text1)); // Output: true

const regex2 = /a[bd]c/;
const text2 = "xyzabc";
const text3 = "xyzadc";
const text4 = "xyzacc";
console.log(regex2.test(text2)); // Output: false
console.log(regex2.test(text3)); // Output: true
console.log(regex2.test(text4)); // Output: false

const regex3 = /aBc/i; // Case-insensitive
const text5 = "xyzabc";
const text6 = "xyzAbC";
console.log(regex3.test(text5)); // Output: true
console.log(regex3.test(text6)); // Output: true
```

**Explanation of the connection to the C++ code:**

*   When JavaScript executes `regex1.test(text1)`, V8's regular expression engine might use the "quick check" logic to quickly scan `text1` for the literal sequence "abc". The C++ code you provided would be involved in setting up the mask and value for this literal check.
*   For `regex2`, which includes a character class `[bd]`, the C++ code would try to create an efficient mask and value to check if the middle character is either 'b' or 'd'. The complexity of the character class affects whether the quick check can be a "perfect" determination.
*   For `regex3`, the `IsIgnoreCase` checks in the C++ code are relevant. The code would handle the case-insensitive matching by considering both 'B' and 'b'.

**In essence, this C++ code is a low-level implementation detail within V8 that optimizes the execution of JavaScript regular expressions by performing fast preliminary checks to avoid unnecessary full matching attempts.** It contributes to making JavaScript's regular expression engine efficient.
### 提示词
```
这是目录为v8/src/regexp/regexp-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
quarks = elm.atom()->data();
      for (int i = 0; i < characters && i < quarks.length(); i++) {
        QuickCheckDetails::Position* pos =
            details->positions(characters_filled_in);
        base::uc16 c = quarks[i];
        if (IsIgnoreCase(compiler->flags())) {
          unibrow::uchar chars[4];
          int length =
              GetCaseIndependentLetters(isolate, c, compiler, chars, 4);
          if (length == 0) {
            // This can happen because all case variants are non-Latin1, but we
            // know the input is Latin1.
            details->set_cannot_match();
            pos->determines_perfectly = false;
            return;
          }
          if (length == 1) {
            // This letter has no case equivalents, so it's nice and simple
            // and the mask-compare will determine definitely whether we have
            // a match at this character position.
            pos->mask = char_mask;
            pos->value = chars[0];
            pos->determines_perfectly = true;
          } else {
            uint32_t common_bits = char_mask;
            uint32_t bits = chars[0];
            for (int j = 1; j < length; j++) {
              uint32_t differing_bits = ((chars[j] & common_bits) ^ bits);
              common_bits ^= differing_bits;
              bits &= common_bits;
            }
            // If length is 2 and common bits has only one zero in it then
            // our mask and compare instruction will determine definitely
            // whether we have a match at this character position.  Otherwise
            // it can only be an approximate check.
            uint32_t one_zero = (common_bits | ~char_mask);
            if (length == 2 && ((~one_zero) & ((~one_zero) - 1)) == 0) {
              pos->determines_perfectly = true;
            }
            pos->mask = common_bits;
            pos->value = bits;
          }
        } else {
          // Don't ignore case.  Nice simple case where the mask-compare will
          // determine definitely whether we have a match at this character
          // position.
          if (c > char_mask) {
            details->set_cannot_match();
            pos->determines_perfectly = false;
            return;
          }
          pos->mask = char_mask;
          pos->value = c;
          pos->determines_perfectly = true;
        }
        characters_filled_in++;
        DCHECK(characters_filled_in <= details->characters());
        if (characters_filled_in == details->characters()) {
          return;
        }
      }
    } else {
      QuickCheckDetails::Position* pos =
          details->positions(characters_filled_in);
      RegExpClassRanges* tree = elm.class_ranges();
      ZoneList<CharacterRange>* ranges = tree->ranges(zone());
      if (tree->is_negated() || ranges->is_empty()) {
        // A quick check uses multi-character mask and compare.  There is no
        // useful way to incorporate a negative char class into this scheme
        // so we just conservatively create a mask and value that will always
        // succeed.
        // Likewise for empty ranges (empty ranges can occur e.g. when
        // compiling for one-byte subjects and impossible (non-one-byte) ranges
        // have been removed).
        pos->mask = 0;
        pos->value = 0;
      } else {
        int first_range = 0;
        while (ranges->at(first_range).from() > char_mask) {
          first_range++;
          if (first_range == ranges->length()) {
            details->set_cannot_match();
            pos->determines_perfectly = false;
            return;
          }
        }
        CharacterRange range = ranges->at(first_range);
        const base::uc32 first_from = range.from();
        const base::uc32 first_to =
            (range.to() > char_mask) ? char_mask : range.to();
        const uint32_t differing_bits = (first_from ^ first_to);
        // A mask and compare is only perfect if the differing bits form a
        // number like 00011111 with one single block of trailing 1s.
        if ((differing_bits & (differing_bits + 1)) == 0 &&
            first_from + differing_bits == first_to) {
          pos->determines_perfectly = true;
        }
        uint32_t common_bits = ~SmearBitsRight(differing_bits);
        uint32_t bits = (first_from & common_bits);
        for (int i = first_range + 1; i < ranges->length(); i++) {
          range = ranges->at(i);
          const base::uc32 from = range.from();
          if (from > char_mask) continue;
          const base::uc32 to =
              (range.to() > char_mask) ? char_mask : range.to();
          // Here we are combining more ranges into the mask and compare
          // value.  With each new range the mask becomes more sparse and
          // so the chances of a false positive rise.  A character class
          // with multiple ranges is assumed never to be equivalent to a
          // mask and compare operation.
          pos->determines_perfectly = false;
          uint32_t new_common_bits = (from ^ to);
          new_common_bits = ~SmearBitsRight(new_common_bits);
          common_bits &= new_common_bits;
          bits &= new_common_bits;
          uint32_t new_differing_bits = (from & common_bits) ^ bits;
          common_bits ^= new_differing_bits;
          bits &= common_bits;
        }
        pos->mask = common_bits;
        pos->value = bits;
      }
      characters_filled_in++;
      DCHECK(characters_filled_in <= details->characters());
      if (characters_filled_in == details->characters()) return;
    }
  }
  DCHECK(characters_filled_in != details->characters());
  if (!details->cannot_match()) {
    on_success()->GetQuickCheckDetails(details, compiler, characters_filled_in,
                                       true);
  }
}

void QuickCheckDetails::Clear() {
  for (int i = 0; i < characters_; i++) {
    positions_[i].mask = 0;
    positions_[i].value = 0;
    positions_[i].determines_perfectly = false;
  }
  characters_ = 0;
}

void QuickCheckDetails::Advance(int by, bool one_byte) {
  if (by >= characters_ || by < 0) {
    DCHECK_IMPLIES(by < 0, characters_ == 0);
    Clear();
    return;
  }
  DCHECK_LE(characters_ - by, 4);
  DCHECK_LE(characters_, 4);
  for (int i = 0; i < characters_ - by; i++) {
    positions_[i] = positions_[by + i];
  }
  for (int i = characters_ - by; i < characters_; i++) {
    positions_[i].mask = 0;
    positions_[i].value = 0;
    positions_[i].determines_perfectly = false;
  }
  characters_ -= by;
  // We could change mask_ and value_ here but we would never advance unless
  // they had already been used in a check and they won't be used again because
  // it would gain us nothing.  So there's no point.
}

void QuickCheckDetails::Merge(QuickCheckDetails* other, int from_index) {
  DCHECK(characters_ == other->characters_);
  if (other->cannot_match_) {
    return;
  }
  if (cannot_match_) {
    *this = *other;
    return;
  }
  for (int i = from_index; i < characters_; i++) {
    QuickCheckDetails::Position* pos = positions(i);
    QuickCheckDetails::Position* other_pos = other->positions(i);
    if (pos->mask != other_pos->mask || pos->value != other_pos->value ||
        !other_pos->determines_perfectly) {
      // Our mask-compare operation will be approximate unless we have the
      // exact same operation on both sides of the alternation.
      pos->determines_perfectly = false;
    }
    pos->mask &= other_pos->mask;
    pos->value &= pos->mask;
    other_pos->value &= pos->mask;
    uint32_t differing_bits = (pos->value ^ other_pos->value);
    pos->mask &= ~differing_bits;
    pos->value &= pos->mask;
  }
}

class VisitMarker {
 public:
  explicit VisitMarker(NodeInfo* info) : info_(info) {
    DCHECK(!info->visited);
    info->visited = true;
  }
  ~VisitMarker() { info_->visited = false; }

 private:
  NodeInfo* info_;
};

// Temporarily sets traversed_loop_initialization_node_.
class LoopInitializationMarker {
 public:
  explicit LoopInitializationMarker(LoopChoiceNode* node) : node_(node) {
    DCHECK(!node_->traversed_loop_initialization_node_);
    node_->traversed_loop_initialization_node_ = true;
  }
  ~LoopInitializationMarker() {
    DCHECK(node_->traversed_loop_initialization_node_);
    node_->traversed_loop_initialization_node_ = false;
  }
  LoopInitializationMarker(const LoopInitializationMarker&) = delete;
  LoopInitializationMarker& operator=(const LoopInitializationMarker&) = delete;

 private:
  LoopChoiceNode* node_;
};

// Temporarily decrements min_loop_iterations_.
class IterationDecrementer {
 public:
  explicit IterationDecrementer(LoopChoiceNode* node) : node_(node) {
    DCHECK_GT(node_->min_loop_iterations_, 0);
    --node_->min_loop_iterations_;
  }
  ~IterationDecrementer() { ++node_->min_loop_iterations_; }
  IterationDecrementer(const IterationDecrementer&) = delete;
  IterationDecrementer& operator=(const IterationDecrementer&) = delete;

 private:
  LoopChoiceNode* node_;
};

RegExpNode* SeqRegExpNode::FilterOneByte(int depth, RegExpCompiler* compiler) {
  if (info()->replacement_calculated) return replacement();
  if (depth < 0) return this;
  DCHECK(!info()->visited);
  VisitMarker marker(info());
  return FilterSuccessor(depth - 1, compiler);
}

RegExpNode* SeqRegExpNode::FilterSuccessor(int depth,
                                           RegExpCompiler* compiler) {
  RegExpNode* next = on_success_->FilterOneByte(depth - 1, compiler);
  if (next == nullptr) return set_replacement(nullptr);
  on_success_ = next;
  return set_replacement(this);
}

// We need to check for the following characters: 0x39C 0x3BC 0x178.
bool RangeContainsLatin1Equivalents(CharacterRange range) {
  // TODO(dcarney): this could be a lot more efficient.
  return range.Contains(0x039C) || range.Contains(0x03BC) ||
         range.Contains(0x0178);
}

namespace {

bool RangesContainLatin1Equivalents(ZoneList<CharacterRange>* ranges) {
  for (int i = 0; i < ranges->length(); i++) {
    // TODO(dcarney): this could be a lot more efficient.
    if (RangeContainsLatin1Equivalents(ranges->at(i))) return true;
  }
  return false;
}

}  // namespace

RegExpNode* TextNode::FilterOneByte(int depth, RegExpCompiler* compiler) {
  RegExpFlags flags = compiler->flags();
  if (info()->replacement_calculated) return replacement();
  if (depth < 0) return this;
  DCHECK(!info()->visited);
  VisitMarker marker(info());
  int element_count = elements()->length();
  for (int i = 0; i < element_count; i++) {
    TextElement elm = elements()->at(i);
    if (elm.text_type() == TextElement::ATOM) {
      base::Vector<const base::uc16> quarks = elm.atom()->data();
      for (int j = 0; j < quarks.length(); j++) {
        base::uc16 c = quarks[j];
        if (!IsIgnoreCase(flags)) {
          if (c > String::kMaxOneByteCharCode) return set_replacement(nullptr);
        } else {
          unibrow::uchar chars[4];
          int length = GetCaseIndependentLetters(compiler->isolate(), c,
                                                 compiler, chars, 4);
          if (length == 0 || chars[0] > String::kMaxOneByteCharCode) {
            return set_replacement(nullptr);
          }
        }
      }
    } else {
      // A character class can also be impossible to match in one-byte mode.
      DCHECK(elm.text_type() == TextElement::CLASS_RANGES);
      RegExpClassRanges* cr = elm.class_ranges();
      ZoneList<CharacterRange>* ranges = cr->ranges(zone());
      CharacterRange::Canonicalize(ranges);
      // Now they are in order so we only need to look at the first.
      // If we are in non-Unicode case independent mode then we need
      // to be a bit careful here, because the character classes have
      // not been case-desugared yet, but there are characters and ranges
      // that can become Latin-1 when case is considered.
      int range_count = ranges->length();
      if (cr->is_negated()) {
        if (range_count != 0 && ranges->at(0).from() == 0 &&
            ranges->at(0).to() >= String::kMaxOneByteCharCode) {
          bool case_complications = !IsEitherUnicode(flags) &&
                                    IsIgnoreCase(flags) &&
                                    RangesContainLatin1Equivalents(ranges);
          if (!case_complications) {
            return set_replacement(nullptr);
          }
        }
      } else {
        if (range_count == 0 ||
            ranges->at(0).from() > String::kMaxOneByteCharCode) {
          bool case_complications = !IsEitherUnicode(flags) &&
                                    IsIgnoreCase(flags) &&
                                    RangesContainLatin1Equivalents(ranges);
          if (!case_complications) {
            return set_replacement(nullptr);
          }
        }
      }
    }
  }
  return FilterSuccessor(depth - 1, compiler);
}

RegExpNode* LoopChoiceNode::FilterOneByte(int depth, RegExpCompiler* compiler) {
  if (info()->replacement_calculated) return replacement();
  if (depth < 0) return this;
  if (info()->visited) return this;
  {
    VisitMarker marker(info());

    RegExpNode* continue_replacement =
        continue_node_->FilterOneByte(depth - 1, compiler);
    // If we can't continue after the loop then there is no sense in doing the
    // loop.
    if (continue_replacement == nullptr) return set_replacement(nullptr);
  }

  return ChoiceNode::FilterOneByte(depth - 1, compiler);
}

RegExpNode* ChoiceNode::FilterOneByte(int depth, RegExpCompiler* compiler) {
  if (info()->replacement_calculated) return replacement();
  if (depth < 0) return this;
  if (info()->visited) return this;
  VisitMarker marker(info());
  int choice_count = alternatives_->length();

  for (int i = 0; i < choice_count; i++) {
    GuardedAlternative alternative = alternatives_->at(i);
    if (alternative.guards() != nullptr &&
        alternative.guards()->length() != 0) {
      set_replacement(this);
      return this;
    }
  }

  int surviving = 0;
  RegExpNode* survivor = nullptr;
  for (int i = 0; i < choice_count; i++) {
    GuardedAlternative alternative = alternatives_->at(i);
    RegExpNode* replacement =
        alternative.node()->FilterOneByte(depth - 1, compiler);
    DCHECK(replacement != this);  // No missing EMPTY_MATCH_CHECK.
    if (replacement != nullptr) {
      alternatives_->at(i).set_node(replacement);
      surviving++;
      survivor = replacement;
    }
  }
  if (surviving < 2) return set_replacement(survivor);

  set_replacement(this);
  if (surviving == choice_count) {
    return this;
  }
  // Only some of the nodes survived the filtering.  We need to rebuild the
  // alternatives list.
  ZoneList<GuardedAlternative>* new_alternatives =
      zone()->New<ZoneList<GuardedAlternative>>(surviving, zone());
  for (int i = 0; i < choice_count; i++) {
    RegExpNode* replacement =
        alternatives_->at(i).node()->FilterOneByte(depth - 1, compiler);
    if (replacement != nullptr) {
      alternatives_->at(i).set_node(replacement);
      new_alternatives->Add(alternatives_->at(i), zone());
    }
  }
  alternatives_ = new_alternatives;
  return this;
}

RegExpNode* NegativeLookaroundChoiceNode::FilterOneByte(
    int depth, RegExpCompiler* compiler) {
  if (info()->replacement_calculated) return replacement();
  if (depth < 0) return this;
  if (info()->visited) return this;
  VisitMarker marker(info());
  // Alternative 0 is the negative lookahead, alternative 1 is what comes
  // afterwards.
  RegExpNode* node = continue_node();
  RegExpNode* replacement = node->FilterOneByte(depth - 1, compiler);
  if (replacement == nullptr) return set_replacement(nullptr);
  alternatives_->at(kContinueIndex).set_node(replacement);

  RegExpNode* neg_node = lookaround_node();
  RegExpNode* neg_replacement = neg_node->FilterOneByte(depth - 1, compiler);
  // If the negative lookahead is always going to fail then
  // we don't need to check it.
  if (neg_replacement == nullptr) return set_replacement(replacement);
  alternatives_->at(kLookaroundIndex).set_node(neg_replacement);
  return set_replacement(this);
}

void LoopChoiceNode::GetQuickCheckDetails(QuickCheckDetails* details,
                                          RegExpCompiler* compiler,
                                          int characters_filled_in,
                                          bool not_at_start) {
  if (body_can_be_zero_length_ || info()->visited) return;
  not_at_start = not_at_start || this->not_at_start();
  DCHECK_EQ(alternatives_->length(), 2);  // There's just loop and continue.
  if (traversed_loop_initialization_node_ && min_loop_iterations_ > 0 &&
      loop_node_->EatsAtLeast(not_at_start) >
          continue_node_->EatsAtLeast(true)) {
    // Loop body is guaranteed to execute at least once, and consume characters
    // when it does, meaning the only possible quick checks from this point
    // begin with the loop body. We may recursively visit this LoopChoiceNode,
    // but we temporarily decrease its minimum iteration counter so we know when
    // to check the continue case.
    IterationDecrementer next_iteration(this);
    loop_node_->GetQuickCheckDetails(details, compiler, characters_filled_in,
                                     not_at_start);
  } else {
    // Might not consume anything in the loop body, so treat it like a normal
    // ChoiceNode (and don't recursively visit this node again).
    VisitMarker marker(info());
    ChoiceNode::GetQuickCheckDetails(details, compiler, characters_filled_in,
                                     not_at_start);
  }
}

void LoopChoiceNode::GetQuickCheckDetailsFromLoopEntry(
    QuickCheckDetails* details, RegExpCompiler* compiler,
    int characters_filled_in, bool not_at_start) {
  if (traversed_loop_initialization_node_) {
    // We already entered this loop once, exited via its continuation node, and
    // followed an outer loop's back-edge to before the loop entry point. We
    // could try to reset the minimum iteration count to its starting value at
    // this point, but that seems like more trouble than it's worth. It's safe
    // to keep going with the current (possibly reduced) minimum iteration
    // count.
    GetQuickCheckDetails(details, compiler, characters_filled_in, not_at_start);
  } else {
    // We are entering a loop via its counter initialization action, meaning we
    // are guaranteed to run the loop body at least some minimum number of times
    // before running the continuation node. Set a flag so that this node knows
    // (now and any times we visit it again recursively) that it was entered
    // from the top.
    LoopInitializationMarker marker(this);
    GetQuickCheckDetails(details, compiler, characters_filled_in, not_at_start);
  }
}

void LoopChoiceNode::FillInBMInfo(Isolate* isolate, int offset, int budget,
                                  BoyerMooreLookahead* bm, bool not_at_start) {
  if (body_can_be_zero_length_ || budget <= 0) {
    bm->SetRest(offset);
    SaveBMInfo(bm, not_at_start, offset);
    return;
  }
  ChoiceNode::FillInBMInfo(isolate, offset, budget - 1, bm, not_at_start);
  SaveBMInfo(bm, not_at_start, offset);
}

void ChoiceNode::GetQuickCheckDetails(QuickCheckDetails* details,
                                      RegExpCompiler* compiler,
                                      int characters_filled_in,
                                      bool not_at_start) {
  not_at_start = (not_at_start || not_at_start_);
  int choice_count = alternatives_->length();
  DCHECK_LT(0, choice_count);
  alternatives_->at(0).node()->GetQuickCheckDetails(
      details, compiler, characters_filled_in, not_at_start);
  for (int i = 1; i < choice_count; i++) {
    QuickCheckDetails new_details(details->characters());
    RegExpNode* node = alternatives_->at(i).node();
    node->GetQuickCheckDetails(&new_details, compiler, characters_filled_in,
                               not_at_start);
    // Here we merge the quick match details of the two branches.
    details->Merge(&new_details, characters_filled_in);
  }
}

namespace {

// Check for [0-9A-Z_a-z].
void EmitWordCheck(RegExpMacroAssembler* assembler, Label* word,
                   Label* non_word, bool fall_through_on_word) {
  if (assembler->CheckSpecialClassRanges(
          fall_through_on_word ? StandardCharacterSet::kWord
                               : StandardCharacterSet::kNotWord,
          fall_through_on_word ? non_word : word)) {
    // Optimized implementation available.
    return;
  }
  assembler->CheckCharacterGT('z', non_word);
  assembler->CheckCharacterLT('0', non_word);
  assembler->CheckCharacterGT('a' - 1, word);
  assembler->CheckCharacterLT('9' + 1, word);
  assembler->CheckCharacterLT('A', non_word);
  assembler->CheckCharacterLT('Z' + 1, word);
  if (fall_through_on_word) {
    assembler->CheckNotCharacter('_', non_word);
  } else {
    assembler->CheckCharacter('_', word);
  }
}

// Emit the code to check for a ^ in multiline mode (1-character lookbehind
// that matches newline or the start of input).
void EmitHat(RegExpCompiler* compiler, RegExpNode* on_success, Trace* trace) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();

  // We will load the previous character into the current character register.
  Trace new_trace(*trace);
  new_trace.InvalidateCurrentCharacter();

  // A positive (> 0) cp_offset means we've already successfully matched a
  // non-empty-width part of the pattern, and thus cannot be at or before the
  // start of the subject string. We can thus skip both at-start and
  // bounds-checks when loading the one-character lookbehind.
  const bool may_be_at_or_before_subject_string_start =
      new_trace.cp_offset() <= 0;

  Label ok;
  if (may_be_at_or_before_subject_string_start) {
    // The start of input counts as a newline in this context, so skip to ok if
    // we are at the start.
    assembler->CheckAtStart(new_trace.cp_offset(), &ok);
  }

  // If we've already checked that we are not at the start of input, it's okay
  // to load the previous character without bounds checks.
  const bool can_skip_bounds_check = !may_be_at_or_before_subject_string_start;
  assembler->LoadCurrentCharacter(new_trace.cp_offset() - 1,
                                  new_trace.backtrack(), can_skip_bounds_check);
  if (!assembler->CheckSpecialClassRanges(StandardCharacterSet::kLineTerminator,
                                          new_trace.backtrack())) {
    // Newline means \n, \r, 0x2028 or 0x2029.
    if (!compiler->one_byte()) {
      assembler->CheckCharacterAfterAnd(0x2028, 0xFFFE, &ok);
    }
    assembler->CheckCharacter('\n', &ok);
    assembler->CheckNotCharacter('\r', new_trace.backtrack());
  }
  assembler->Bind(&ok);
  on_success->Emit(compiler, &new_trace);
}

}  // namespace

// Emit the code to handle \b and \B (word-boundary or non-word-boundary).
void AssertionNode::EmitBoundaryCheck(RegExpCompiler* compiler, Trace* trace) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();
  Isolate* isolate = assembler->isolate();
  Trace::TriBool next_is_word_character = Trace::UNKNOWN;
  bool not_at_start = (trace->at_start() == Trace::FALSE_VALUE);
  BoyerMooreLookahead* lookahead = bm_info(not_at_start);
  if (lookahead == nullptr) {
    int eats_at_least =
        std::min(kMaxLookaheadForBoyerMoore, EatsAtLeast(not_at_start));
    if (eats_at_least >= 1) {
      BoyerMooreLookahead* bm =
          zone()->New<BoyerMooreLookahead>(eats_at_least, compiler, zone());
      FillInBMInfo(isolate, 0, kRecursionBudget, bm, not_at_start);
      if (bm->at(0)->is_non_word()) next_is_word_character = Trace::FALSE_VALUE;
      if (bm->at(0)->is_word()) next_is_word_character = Trace::TRUE_VALUE;
    }
  } else {
    if (lookahead->at(0)->is_non_word())
      next_is_word_character = Trace::FALSE_VALUE;
    if (lookahead->at(0)->is_word()) next_is_word_character = Trace::TRUE_VALUE;
  }
  bool at_boundary = (assertion_type_ == AssertionNode::AT_BOUNDARY);
  if (next_is_word_character == Trace::UNKNOWN) {
    Label before_non_word;
    Label before_word;
    if (trace->characters_preloaded() != 1) {
      assembler->LoadCurrentCharacter(trace->cp_offset(), &before_non_word);
    }
    // Fall through on non-word.
    EmitWordCheck(assembler, &before_word, &before_non_word, false);
    // Next character is not a word character.
    assembler->Bind(&before_non_word);
    Label ok;
    BacktrackIfPrevious(compiler, trace, at_boundary ? kIsNonWord : kIsWord);
    assembler->GoTo(&ok);

    assembler->Bind(&before_word);
    BacktrackIfPrevious(compiler, trace, at_boundary ? kIsWord : kIsNonWord);
    assembler->Bind(&ok);
  } else if (next_is_word_character == Trace::TRUE_VALUE) {
    BacktrackIfPrevious(compiler, trace, at_boundary ? kIsWord : kIsNonWord);
  } else {
    DCHECK(next_is_word_character == Trace::FALSE_VALUE);
    BacktrackIfPrevious(compiler, trace, at_boundary ? kIsNonWord : kIsWord);
  }
}

void AssertionNode::BacktrackIfPrevious(
    RegExpCompiler* compiler, Trace* trace,
    AssertionNode::IfPrevious backtrack_if_previous) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();
  Trace new_trace(*trace);
  new_trace.InvalidateCurrentCharacter();

  Label fall_through;
  Label* non_word = backtrack_if_previous == kIsNonWord ? new_trace.backtrack()
                                                        : &fall_through;
  Label* word = backtrack_if_previous == kIsNonWord ? &fall_through
                                                    : new_trace.backtrack();

  // A positive (> 0) cp_offset means we've already successfully matched a
  // non-empty-width part of the pattern, and thus cannot be at or before the
  // start of the subject string. We can thus skip both at-start and
  // bounds-checks when loading the one-character lookbehind.
  const bool may_be_at_or_before_subject_string_start =
      new_trace.cp_offset() <= 0;

  if (may_be_at_or_before_subject_string_start) {
    // The start of input counts as a non-word character, so the question is
    // decided if we are at the start.
    assembler->CheckAtStart(new_trace.cp_offset(), non_word);
  }

  // If we've already checked that we are not at the start of input, it's okay
  // to load the previous character without bounds checks.
  const bool can_skip_bounds_check = !may_be_at_or_before_subject_string_start;
  assembler->LoadCurrentCharacter(new_trace.cp_offset() - 1, non_word,
                                  can_skip_bounds_check);
  EmitWordCheck(assembler, word, non_word, backtrack_if_previous == kIsNonWord);

  assembler->Bind(&fall_through);
  on_success()->Emit(compiler, &new_trace);
}

void AssertionNode::GetQuickCheckDetails(QuickCheckDetails* details,
                                         RegExpCompiler* compiler,
                                         int filled_in, bool not_at_start) {
  if (assertion_type_ == AT_START && not_at_start) {
    details->set_cannot_match();
    return;
  }
  return on_success()->GetQuickCheckDetails(details, compiler, filled_in,
                                            not_at_start);
}

void AssertionNode::Emit(RegExpCompiler* compiler, Trace* trace) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();
  switch (assertion_type_) {
    case AT_END: {
      Label ok;
      assembler->CheckPosition(trace->cp_offset(), &ok);
      assembler->GoTo(trace->backtrack());
      assembler->Bind(&ok);
      break;
    }
    case AT_START: {
      if (trace->at_start() == Trace::FALSE_VALUE) {
        assembler->GoTo(trace->backtrack());
        return;
      }
      if (trace->at_start() == Trace::UNKNOWN) {
        assembler->CheckNotAtStart(trace->cp_offset(), trace->backtrack());
        Trace at_start_trace = *trace;
        at_start_trace.set_at_start(Trace::TRUE_VALUE);
        on_success()->Emit(compiler, &at_start_trace);
        return;
      }
    } break;
    case AFTER_NEWLINE:
      EmitHat(compiler, on_success(), trace);
      return;
    case AT_BOUNDARY:
    case AT_NON_BOUNDARY: {
      EmitBoundaryCheck(compiler, trace);
      return;
    }
  }
  on_success()->Emit(compiler, trace);
}

namespace {

bool DeterminedAlready(QuickCheckDetails* quick_check, int offset) {
  if (quick_check == nullptr) return false;
  if (offset >= quick_check->characters()) return false;
  return quick_check->positions(offset)->determines_perfectly;
}

void UpdateBoundsCheck(int index, int* checked_up_to) {
  if (index > *checked_up_to) {
    *checked_up_to = index;
  }
}

}  // namespace

// We call this repeatedly to generate code for each pass over the text node.
// The passes are in increasing order of difficulty because we hope one
// of the first passes will fail in which case we are saved the work of the
// later passes.  for example for the case independent regexp /%[asdfghjkl]a/
// we will check the '%' in the first pass, the case independent 'a' in the
// second pass and the character class in the last pass.
//
// The passes are done from right to left, so for example to test for /bar/
// we will first test for an 'r' with offset 2, then an 'a' with offset 1
// and then a 'b' with offset 0.  This means we can avoid the end-of-input
// bounds check most of the time.  In the example we only need to check for
// end-of-input when loading the putative 'r'.
//
// A slight complication involves the fact that the first character may already
// be fetched into a register by the previous node.  In this case we want to
// do the test for that character first.  We do this in separate passes.  The
// 'preloaded' argument indicates that we are doing such a 'pass'.  If such a
// pass has been performed then subsequent passes will have true in
// first_element_checked to indicate that that character does not need to be
// checked again.
//
// In addition to all this we are passed a Trace, which can
// contain an AlternativeGeneration object.  In this AlternativeGeneration
// object we can see details of any quick check that was already passed in
// order to get to the code we are now generating.  The quick check can involve
// loading characters, which means we do not need to recheck the bounds
// up to the limit the quick check already checked.  In addition the quick
// check can have involved a mask and compare operation which may simplify
// or obviate the need for further checks at some character positions.
void TextNode::TextEmitPass(RegExpCompiler* compiler, TextEmitPassType pass,
                            bool preloaded, Trace* trace,
                            bool first_element_checked, int* checked_up_to) {
  RegExpMacroAssembler* assembler = compiler->macro_assembler();
  Isolate* isolate = assembler->isolate();
  bool one_byte = compiler->one_byte();
  Label* backtrack = trace->backtrack();
  QuickCheckDetails* quick_check = trace->quick_check_performed();
  int element_count = elements()->length();
  int backward_offset = read_backward() ? -Length() : 0;
  for (int i = preloaded ? 0 : element_count - 1; i >= 0; i--) {
    TextElement elm = elements()->at(i);
    int cp_offset = trace->cp_offset() + elm.cp_offset() + backward_offset;
    if (elm.text_type() == TextElement::ATOM) {
      base::Vector<const base::uc16> quarks = elm.atom()->data();
      for (int j = preloaded ? 0 : quarks.length() - 1; j >= 0; j--) {
        if (first_element_checked && i == 0 && j == 0) continue;
        if (DeterminedAlready(quick_check, elm.cp_offset() + j)) continue;
        base::uc16 quark = quarks[j];
        bool needs_bounds_check =
            *checked_up_to < cp_offset + j || read_backward();
        bool bounds_checked = false;
        switch (pass) {
          case NON_LATIN1_MATCH: {
            DCHECK(one_byte);  // This pass is only done in one-byte mode.
            if (IsIgnoreCase(compiler->flags())) {
              // We are compiling for a one-byte subject, case independent mode.
              // We have to check whether any of the case alternatives are in
              // the one-byte range.
              unibrow::uchar chars[4];
              // Only returns characters that are in the one-byte range.
              int length =
                  GetCaseIndependentLetters(isolate, quark, compiler, chars, 4);
              if (length == 0) {
                assembler->GoTo(backtrack);
                return;
              }
            } else {
              // Case-dependent mode.
              if (quark > String::kMaxOneByteCharCode) {
                assembler->GoTo(backtrack);
                return;
              }
            }
            break;
          }
          case NON_LETTER_CHARACTER_MATCH:
            bounds_checked =
                EmitAtomNonLetter(isolate, compiler, quark, backtrack,
                                  cp_offset + j, needs_bounds_check, preloaded);
            break;
          case SIMPLE_CHARACTER_MATCH:
            bounds_checked = EmitSimpleCharacter(isolate, compiler, quark,
                                                 backtrack, cp_offset + j,
                                                 needs_bounds_check, preloaded);
            break;
          case CASE_CHARACTER_MATCH:
            bounds_checked =
                EmitAtomLetter(isolate, compiler, quark, backtrack,
                               cp_offset + j, needs_bounds_check, preloaded);
            break;
          default:
            break;
        }
        if (bounds_checked) UpdateBoundsCheck(cp_offset + j, checked_up_to);
      }
    } else {
      DCHECK_EQ(TextElement::CLASS_RANGES, elm.text_type());
      if (pass == CHARACTER_CLASS_MATCH) {
        if (first_element_checked && i == 0) continue;
        if (DeterminedAlready(quick_check, elm.cp_offset())) continue;
        RegExpClassRanges* cr = elm.class_ranges();
        bool bounds_check = *checked_up_to < cp_offset || read_backward();
        EmitClassRanges(assembler, cr, one_byte, backtrack, cp_offset,
                        bounds_check, preloaded, zone());
        UpdateBoundsCheck(cp_offset, checked_up_to);
      }
    }
  }
}

int TextNode::Length() {
  TextElement elm = elements()->last();
  DCHECK_LE(0, elm.cp_offset());
  return elm.cp_offset() + elm.length();
}

TextNode* TextNode::CreateForCharacterRanges(Zone* zone,
                                             ZoneList<CharacterRange>* ranges,
                                             bool read_backward,
                                             RegExpNode* on_success) {
  DCHECK_NOT_NULL(ranges);
  // TODO(jgruber): There's no fundamental need to create this
  // RegExpClassRanges; we could refactor to avoid the allocation.
  return zone->New<TextNode>(zone->New<RegExpClassRanges>(zone, ranges),
                             read_backward, on_success);
}

TextNode* TextNode::CreateForSurrogatePair(
    Zone* zone, CharacterRange lead, ZoneList<CharacterRange>* trail_ranges,
    bool read_backward, RegExpNode* on_success) {
  ZoneList<TextElement>* elms = zone->New<ZoneList<TextElement>>(2, zone);
  if (lead.from() == lead.to()) {
    ZoneList<base::uc16> lead_surrogate(1, zone);
    lead_surrogate.Add(lead.from(), zone);
    RegExpAtom* atom = zone->New<RegExpAtom>(lead_surrogate.ToConstVector());
    elms->Add(TextElement::Atom(atom), zone);
  } else {
    ZoneList<CharacterRange>* lead_ranges = CharacterRange::List(zone, lead);
    elms->Add(TextElement::ClassRanges(
                  zone->New<RegExpClassRanges>(zone, lead_ranges)),
              zone);
  }
  elms->Add(TextElement::ClassRanges(
                zone->New<RegExpClassRanges>(zone, trail_ranges)),
            zone);
  return zone->New<TextNode>(elms, read_backward, on_success);
}

TextNode* TextNode::CreateForSurrogatePair(
    Zone* zone, ZoneList<CharacterRange>* lead_ranges, CharacterRange trail,
    bool read_backward, RegExpNode* on_success) {
  ZoneList<CharacterRange>* trail_ranges = CharacterRange::List(zone, trail);
  ZoneList<TextElement>* elms = zone->New<ZoneList<TextElement>>(2, zone);
  elms->Add(
      TextElement::ClassRanges(zone->New<RegExpClassRanges>(zone, lead_ranges)),
      zone);
  elms->Add(TextElement::ClassRanges(
                zone->New<RegExpClassRanges>(zone, trail_ranges)),
            zone);
  return zone->New<TextNode>(elms, read_backward, on_success);
}

// This generates the code to match a text node.  A text node can contain
// straight character sequences (possibly to be matched in a case-independent
// way) and character classes.  For efficiency we do not do this in a single
// pass from left to right.  Instead we pass over the text node several times,
// emitting code for some character positions every time.  See the comment on
// TextEmitPass for details.
void TextNode::Emit(RegExpCompiler* compiler, Trace* trace) {
  LimitResult limit_result = LimitVersions(compiler, trace);
  if (limit_result == DONE) return;
  DCHECK(limit_result == CONTINUE);

  if (trace->cp_offset() + Length() > RegExpMacroAssembler::kMaxCPOffset) {
    compiler->SetRegExpTooBig();
    return;
  }

  if (compiler->one_byte()) {
    int dummy = 0;
    TextEmitPass(compiler, NON_LATIN1_MATCH, false, trace, false, &dummy);
  }

  bool first_elt_done = false;
  int bound_checked_to = trace->cp_offset() - 1;
  bound_checked_to += trace->bound_checked_up_to();

  // If a character is preloaded into the current character register then
  // check that first to save reloading it.
  for (int twice = 0; twice < 2; twice++) {
    bool is_preloaded_pass = twice == 0;
    if (is_preloaded_pass && trace->characters_preloaded() != 1) continue;
    if (IsIgnoreCase(compiler->flags())) {
      TextEmitPass(compiler, NON_LETTER_CHARACTER_MATCH, is_preloaded_pass,
                   trace, first_elt_done, &bound_checked_to);
      TextEmitPass(compiler, CASE_CHARACTER_MATCH, is_preloaded_pass, trace,
                   first_elt_done, &bound_checked_to);
    } else {
      TextEmitPass(compiler, SIMPLE_CHARACTER_MATCH, is_preloaded_pass, trace,
                   first_elt_done, &bound_checked_to);
    }
    TextEmitPass(compiler, CHARACTER_CLASS_MATCH, is_preloaded_pass, trace,
                 first_elt_done, &bound_checked_to);
    first_elt_done = true;
  }

  Trace successor_trace(*trace);
  // If we advance backward, we may end up at the start.
  successor_trace.AdvanceCurrentPositionInTrace(
      read_backward() ? -Length() : Length(), compiler);
  successor_trace.set_at_start(read_backward() ? Trace::UNKNOWN
                                               : Trace::FALSE_VALUE);
  RecursionCheck rc(compiler);
  on_success()->Emit(compiler, &successor_trace);
}

void Trace::InvalidateCurrentCharacter() { characters_preloaded_ = 0; }

void Trace::AdvanceCurrentPositionInTrace(int by, RegExpCompiler* compiler) {
  // We don't have an instruction for shifting the current character register
  // down or for using a shifted value for anything so lets just forget that
  // we preloaded any characters into it.
  characters_preloaded_ = 0;
  // Adjust the offsets of the quick check performed information.  This
  // information is used to find out what we already determined about the
  // characters by means of mask and compare.
  quick_check_performed_.Advance(by, compiler->one_byte());
  cp_offset_ += by;
  if (cp_offset_ > RegExpMacroAssembler::kMaxCPOffset) {
    compiler->SetRegExpTooBig();
    cp_offset_ = 0;
  }
  bound_checked_up_to_ = std::max(0, bound_checked_up_to_ - by);
}

void TextNode::MakeCaseIndependent(Isolate* isolate, bool is_one_byte,
                                   RegExpFlags flags) {
  if (!IsIgnoreCase(flags)) return;
#ifdef V8_INTL_SUPPORT
  // This is done in an earlier step when generating the nodes from the AST
  // because we may have to split up into separate nodes.
  if (NeedsUnicodeCaseEquivalents(flags)) return;
#endif

  int element_count = elements()->length();
  for (int i = 0; i < element_count; i++) {
    TextElement elm = elements()->at(i);
    if (elm.text_type() == TextElement::CLASS_RANGES) {
      RegExpClassRanges* cr = elm.class_ranges();
      // None of the standard character classes is different in the case
      // independent case and it slows us down if we don't know that.
      if (cr->is_standard(zone())) continue;
      ZoneList<CharacterRange>* ranges = cr->ranges(zone());
      CharacterRange::AddCaseEquivalents(isolate, zone(), ranges, is_one_byte);
    }
  }
}

int TextNode::GreedyLoopTextLength() { return Length(); }

RegExpNode* TextNode::GetSuccessorOfOmnivorousTextNode(
    RegExpCompiler* compiler) {
  if (read_backward()) return nullptr;
  if (elements()->length() != 1) return nullptr;
  TextElement elm = elements()->at(0);
  if (elm.text_type() != TextElement::CLASS_RANGES) return nullptr;
  RegExpClassRanges* node = elm.class_ranges();
  ZoneList<CharacterRange>* ranges = node->ranges(zone());
  CharacterRange::Canonicalize(ranges);
  if (node->is_negated()) {
    return ranges->length() == 0 ? on_success() : nullptr;
  }
  if (ranges->length() != 1) return nullptr;
  const base::uc32 max_char = MaxCodeUnit(compiler->one_byte());
  return ranges->at(0).IsEverything(max_char) ? on_success() : nullptr;
}

// Finds the fixed match length of a sequence of nodes that goes from
// this alternative and back to this choice node.  If there are variable
// length nodes or other complications in the way then return a sentinel
// value indicating that a greedy loop cannot be constructed.
int ChoiceNode::GreedyLoopTextLengthForAlternative(
    GuardedAlternative* alternative) {
  int length = 0;
  RegExpNode* node = alternative->node();
  // Later we will generate code for all these text nodes using recursion
  // so we have to limit the max number.
  int recursion_depth = 0;
  while (node != this) {
    if (recursion_depth++ > RegExpCompiler::kMaxRecursion) {
      return kNodeIsTooComplexForGreedyLoops;
    }
    int node_length = node->GreedyLoopTextLength();
    if (node_length == kNodeIsTooComplexForGreedyLoops) {
      return kNodeIsTooComplexForGreedyLoops;
    }
    length += node_length;
    node = node->AsSeqRegExpNode()->on_success();
  }
  if (read_backward()) {
    length = -length;
  }
  // Check that we can jump by the whole text length. If not, return sentinel
  // to indicate the we can't construct a greedy loop.
  if (length < RegExpMacroAssembler::kMinCPOffset ||
      length > RegExpMacroAssembler::kMaxCPOffset) {
    return kNodeIsTooComplexForGreedyLoops;
  }
  return length;
}

void LoopChoiceNode::AddLoopAlternative(GuardedAlternative alt) {
  DCHECK_NULL(loop_node_);
  AddAlternative(alt);
  loop_node_ = alt.node();
}

void LoopChoiceNode::AddContinueAlternative(GuardedAlternative alt) {
  DCHECK_NULL(continue_node_);
  AddAlternative(alt);
  continue_node_ = alt.node();
}

void LoopChoiceNode::Emit(RegExpCompiler* compiler, Trace* trace) {
  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  if (trace->stop_node() == this) {
    // Back edge of greedy optimized loop node graph.
    int text_length =
        GreedyLoopTextLengthForAlternative(&(alternatives_->at(0)));
    DCHECK_NE(kNodeIsTooComplexForGreedyLoops, text_length);
    // Update the counter-based backtracking info on the stack.  This is an
    // optimization for greedy loops (see below).
    DCHECK(trace->cp_offset() == text_length);
    macro_assembler->AdvanceCurrentPosition(text_length);
    macro_assembler->GoTo(trace->loop_label());
    return;
  }
  DCHECK_NULL(trace->stop_node());
  if (!trace->is_trivial()) {
    trace->Flush(compiler, this);
    return;
  }
  ChoiceNode::Emit(compiler, trace);
}

int ChoiceNode::CalculatePreloadCharacters(RegExpCompiler* compiler,
                                           int eats_at_least) {
  int preload_characters = std::min(4, eats_at_least);
  DCHECK_LE(preload_characters, 4);
  if (compiler->macro_assembler()->CanReadUnaligned()) {
    bool one_byte = compiler->one_byte();
    if (one_byte) {
      // We can't preload 3 characters because there is no machine instruction
      // to do that.  We can't just load 4 because we could be reading
      // beyond the end of the string, which could cause a memory fault.
      if (preload_characters == 3) preload_characters = 2;
    } else {
      if (preload_characters > 2) preload_characters = 2;
    }
  } else {
    if (preload_characters > 1) preload_characters = 1;
  }
  return preload_characters;
}

// This class is used when generating the alternatives in a choice node.  It
// records the way the alternative is being code generated.
class AlternativeGeneration : public Malloced {
 public:
  AlternativeGeneration()
      : possible_success(),
        expects_preload(false),
        after(),
        quick_check_details() {}
  Label possible_success;
  bool expects_preload;
  Label after;
  QuickCheckDetails quick_check_details;
};

// Creates a list of AlternativeGenerations.  If the list has a reasonable
// size then it is on the stack, otherwise the excess is on the heap.
class AlternativeGenerationList {
 public:
  AlternativeGenerationList(int count, Zone* zone) : alt_gens_(count, zone) {
    for (int i = 0; i < count && i < kAFew; i++) {
      alt_gens_.Add(a_few_alt_gens_ + i, zone);
    }
    for (int i = kAFew; i < count; i++) {
      alt_gens_.Add(new AlternativeGeneration(), zone);
    }
  }
  ~AlternativeGenerationList() {
    for (int i = kAFew; i < alt_gens_.length(); i++) {
      delete alt_gens_[i];
      alt_gens_[i] = nullptr;
    }
  }

  AlternativeGeneration* at(int i) { return alt_gens_[i]; }

 private:
  static const int kAFew = 10;
  ZoneList<AlternativeGeneration*> alt_gens_;
  AlternativeGeneration a_few_alt_gens_[kAFew];
};

void BoyerMoorePositionInfo::Set(int character) {
  SetInterval(Interval(character, character));
}

namespace {

ContainedInLattice AddRange(ContainedInLattice containment, const int* ranges,
                            int ranges_length, Interval new_range) {
  DCHECK_EQ(1, ranges_length & 1);
  DCHECK_EQ(String::kMaxCodePoint + 1, ranges[ranges_length - 1]);
  if (containment == kLatticeUnknown) return containment;
  bool inside = false;
  int last = 0;
  for (int i = 0; i < ranges_length; inside = !inside, last = ranges[i], i++) {
    // Consider the range from last to ranges[i].
    // We haven't got to the new range yet.
    if (ranges[i] <= new_range.from()) continue;
    // New range is wholly inside last-ranges[i].  Note that new_range.to() is
    // inclusive, but the values in ranges are not.
    if (last <= new_range.from() && new_range.to() < ranges[i]) {
      return Combine(containment, inside ? kLatticeIn : kLatticeOut);
    }
    return kLatticeUnknown;
  }
  return containment;
}

int BitsetFirstSetBit(BoyerMoorePositionInfo::Bitset bitset) {
  static_assert(BoyerMoorePositionInfo::kMapSize ==
                2 * kInt64Size * kBitsPerByte);

  // Slight fiddling is needed here, since the bitset is of length 128 while
  // CountTrailingZeros requires an integral type and std::bitset can only
  // convert to unsigned long long. So we handle the most- and least-significant
  // bits separately.

  {
    static constexpr BoyerMoorePositionInfo::Bitset mask(~uint64_t{0});
    BoyerMoorePositionInfo::Bitset masked_bitset = bitset & mask;
    static_assert(kInt64Size >= sizeof(decltype(masked_bitset.to_ullong())));
    uint64_t lsb = masked_bitset.to_ullong();
    if (lsb != 0) return base::bits::CountTrailingZeros(lsb);
  }

  {
    BoyerMoorePositionInfo::Bitset masked_bitset = bitset >> 64;
    uint64_t msb = masked_bitset.to_ullong();
    if (msb != 0) return 64 + base::bits::CountTrailingZeros(msb);
  }

  return -1;
}

}  // namespace

void BoyerMoorePositionInfo::SetInterval(const Interval& interval) {
  w_ = AddRange(w_, kWordRanges, kWordRangeCount, interval);

  if (interval.size() >= kMapSize) {
    map_count_ = kMapSize;
    map_.set();
    return;
  }

  for (int i = interval.from(); i <= interval.to(); i++) {
    int mod_character = (i & kMask);
    if (!map_[mod_character]) {
      map_count_++;
      map_.set(mod_character);
    }
    if (map_count_ == kMapSize) return;
  }
}

void BoyerMoorePositionInfo::SetAll() {
  w_ = kLatticeUnknown;
  if (map_count_ != kMapSize) {
    map_count_ = kMapSize;
    map_.set();
  }
}

BoyerMooreLookahead::BoyerMooreLookahead(int length, RegExpCompiler* compiler,
                                         Zone* zone)
    : length_(length),
      compiler_(compiler),
      max_char_(MaxCodeUnit(compiler->one_byte())) {
  bitmaps_ = zone->New<ZoneList<BoyerMoorePositionInfo*>>(length, zone);
  for (int i = 0; i < length; i++) {
    bitmaps_->Add(zone->New<BoyerMoorePositionInfo>(), zone);
  }
}

// Find the longest range of lookahead that has the fewest number of different
// characters that can occur at a given position.  Since we are optimizing two
// different parameters at once this is a tradeoff.
bool BoyerMooreLookahead::FindWorthwhileInterval(int* from, int* to) {
  int biggest_points = 0;
  // If more than 32 characters out of 128 can occur it is unlikely that we can
  // be lucky enough to step forwards much of the time.
  const int kMaxMax = 32;
  for (int max_number_of_chars = 4; max_number_of_chars < kMaxMax;
       max_number_of_chars *= 2) {
    biggest_points =
        FindBestInterval(max_number_of_chars, biggest_points, from, to);
  }
  if (biggest_points == 0) return false;
  return true;
}

// Find the highest-points range between 0 and length_ where the character
// information is not too vague.  'Too vague' means that there are more than
// max_number_of_chars that can occur at this position.  Calculates the number
// of points as the product of width-of-the-range and
// probability-of-finding-one-of-the-characters, where the probability is
// calculated using the frequency distribution of the sample subject string.
int BoyerMooreLookahead::FindBestInterval(int max_number_of_chars,
                                          int old_biggest_points, int* from,
                                          int* to) {
  int biggest_points = old_biggest_points;
  static const int kSize = RegExpMacroAssembler::kTableSize;
  for (int i = 0; i < length_;) {
    while (i < length_ && Count(i) > max_number_of_chars) i++;
    if (i == length_) break;
    int remembered_from = i;

    BoyerMoorePositionInfo::Bitset union_bitset;
    for (; i < length_ && Count(i) <= max_number_of_chars; i++) {
      union_bitset |= bitmaps_->at(i)->raw_bitset();
    }

    int frequency = 0;

    // Iterate only over set bits.
    int j;
    while ((j = BitsetFirstSetBit(union_bitset)) != -1) {
      DCHECK(union_bitset[j]);  // Sanity check.
      // Add 1 to the frequency to give a small per-character boost for
      // the cases where our sampling is not good enough and many
      // characters have a frequency of zero.  This means the frequency
      // can theoretically be up to 2*kSize though we treat it mostly as
      // a fraction of kSize.
      frequency += compiler_->frequency_collator()->Frequency(j) + 1;
      union_bitset.reset(j);
    }

    // We use the probability of skipping times the distance we are skipping to
    // judge the effectiveness of this.  Actually we have a cut-off:  By
    // dividing by 2 we switch off the skipping if the probability of skipping
    // is less than 50%.  This is because the multibyte mask-and-compare
    // skipping in quickcheck is more likely to do well on this case.
    bool in_quickcheck_range =
        ((i - remembered_from < 4) ||
         (compiler_->one_byte() ? remembered_from <= 4 : remembered_from <= 2));
    // Called 'probability' but it is only a rough estimate and can actually
    // be outside the 0-kSize range.
    int probability = (in_quickcheck_range ? kSize / 2 : kSize) - frequency;
    int points = (i - remembered_from) * probability;
    if (points > biggest_points) {
      *from = remembered_from;
      *to = i - 1;
      biggest_points = points;
    }
  }
  return biggest_points;
}

// Take all the characters that will not prevent a successful match if they
// occur in the subject string in the range between min_lookahead and
// max_lookahead (inclusive) measured from the current position.  If the
// character at max_lookahead offset is not one of these characters, then we
// can safely skip forwards by the number of characters in the range.
// nibble_table is only used for SIMD variants and encodes the same information
// as boolean_skip_table but in only 128 bits. It contains 16 bytes where the
// index into the table represent low nibbles of a character, and the stored
// byte is a bitset representing matching high nibbles. E.g. to store the
// character 'b' (0x62) in the nibble table, we set the 6th bit in row 2.
int BoyerMooreLookahead::GetSkipTable(
    int min_lookahead, int max_lookahead,
    DirectHandle<ByteArray> boolean_skip_table,
    DirectHandle<ByteArray> nibble_table) {
  const int kSkipArrayEntry = 0;
  const int kDontSkipArrayEntry = 1;

  std::memset(boolean_skip_table->begin(), kSkipArrayEntry,
              boolean_skip_table->length());
  const bool fill_nibble_table = !nibble_table.is_null();
  if (fill_nibble_table) {
    std::memset(nibble_table->begin(), 0, nibble_table->length());
  }

  for (int i = max_lookahead; i >= min_lookahead; i--) {
    BoyerMoorePositionInfo::Bitset bitset = bitmaps_->at(i)->raw_bitset();

    // Iterate only over set bits.
    int j;
    while ((j = BitsetFirstSetBit(bitset)) != -1) {
      DCHECK(bitset[j]);  // Sanity check.
      boolean_skip_table->set(j, kDontSkipArrayEntry);
      if (fill_nibble_table) {
        int lo_nibble = j & 0x0f;
        int hi_nibble = (j >> 4) & 0x07;
        int row = nibble_table->get(lo_nibble);
        row |= 1 << hi_nibble;
        nibble_table->set(lo_nibble, row);
      }
      bitset.reset(j);
    }
  }

  const int skip = max_lookahead + 1 - min_lookahead;
  return skip;
}

// See comment above on the implementation of GetSkipTable.
void BoyerMooreLookahead::EmitSkipInstructions(RegExpMacroAssembler* masm) {
  const int kSize = RegExpMacroAssembler::kTableSize;

  int min_lookahead = 0;
  int max_lookahead = 0;

  if (!FindWorthwhileInterval(&min_lookahead, &max_lookahead)) return;

  // Check if we only have a single non-empty position info, and that info
  // contains precisely one character.
  bool found_single_character = false;
  int single_character = 0;
  for (int i = max_lookahead; i >= min_lookahead; i--) {
    BoyerMoorePositionInfo* map = bitmaps_->at(i);
    if (map->map_count() == 0) continue;

    if (found_single_character || map->map_count() > 1) {
      found_single_character = false;
      break;
    }

    DCHECK(!found_single_character);
    DCHECK_EQ(map->map_count(), 1);

    found_single_character = true;
    single_character = BitsetFirstSetBit(map->raw_bitset());

    DCHECK_NE(single_character, -1);
  }

  int lookahead_width = max_lookahead + 1 - min_lookahead;

  if (found_single_character && lookahead_width == 1 && max_lookahead < 3) {
    // The mask-compare can probably handle this better.
    return;
  }

  if (found_single_character) {
    // TODO(pthier): Add vectorized version.
    Label cont, again;
    masm->Bind(&again);
    masm->LoadCurrentCharacter(max_lookahead, &cont, true);
    if (max_char_ > kSize) {
      masm->CheckCharacterAfterAnd(single_character,
                                   RegExpMacroAssembler::kTableMask, &cont);
    } else {
      masm->CheckCharacter(single_character, &cont);
    }
    masm->AdvanceCurrentPosition(lookahead_width);
    masm->GoTo(&again);
    masm->Bind(&cont);
    return;
  }

  Factory* factory = masm->isolate()->factory();
  Handle<ByteArray> boolean_skip_table =
      factory->NewByteArray(kSize, AllocationType::kOld);
  Handle<ByteArray> nibble_table;
  const int skip_distance = max_lookahead + 1 - min_lookahead;
  if (masm->SkipUntilBitInTableUseSimd(skip_distance)) {
    // The current implementation is tailored specifically for 128-bit tables.
    static_assert(kSize == 128);
    nibble_table =
        factory->NewByteArray(kSize / kBitsPerByte, AllocationType::kOld);
  }
  GetSkipTable(min_lookahead, max_lookahead, boolean_skip_table, nibble_table);
  DCHECK_NE(0, skip_distance);

  masm->SkipUntilBitInTable(max_lookahead, boolean_skip_table, nibble_table,
                            skip_distance);
}

/* Code generation for choice nodes.
 *
 * We generate quick checks that do a mask and compare to eliminate a
 * choice.  If the quick check succeeds then it jumps to the continuation to
 * do slow checks and check subsequent nodes.  If it fails (the common case)
 * it falls through to the next choice.
 *
 * Here is the desired flow graph.  Nodes directly below each other imply
 * fallthrough.  Alternatives 1 and 2 have quick checks.  Alternative
 * 3 doesn't have a quick check so we have to call the slow check.
 * Nodes are marked Qn for quick checks and Sn for slow checks.  The entire
 * regexp continuation is generated directly after the Sn node, up to the
 * next GoTo if we decide to reuse some already generated code.  Some
 * nodes expect preload_characters to be preloaded into the current
 * character register.  R nodes do this preloading.  Vertices are marked
 * F for failures and S for success (possible success in the case of quick
 * nodes).  L, V, < and > are used as arrow heads.
 *
 * ----------> R
 *             |
 *             V
 *            Q1 -----> S1
 *             |   S   /
 *            F|      /
 *             |    F/
 *             |    /
 *             |   R
 *             |  /
 *             V L
 *            Q2 -----> S2
 *             |   S   /
 *            F|      /
 *             |    F/
 *             |    /
 *             |   R
 *             |  /
 *             V L
 *            S3
 *             |
 *            F|
 *             |
 *             R
 *             |
 * backtrack   V
 * <----------Q4
 *   \    F    |
 *    \        |S
 *     \   F   V
 *      \-----S4
 *
 * For greedy loops we push the current position, then generate the code that
 * eats the input specially in EmitGreedyLoop.  The other choice (the
 * continuation) is generated by the normal code in EmitChoices, and steps back
 * in the input to the starting position when it fails to match.  The loop code
 * looks like this (U is the unwind code that steps back in the greedy loop).
 *
 *              _____
 *             /     \
 *             V     |
 * ----------> S1    |
 *            /|     |
 *           / |S    |
 *         F/  \_____/
 *         /
 *        |<-----
 *        |      \
 *        V       |S
 *        Q2 ---> U----->backtrack
 *        |  F   /
 *       S|     /
 *        V  F /
 *        S2--/
 */

GreedyLoopState::GreedyLoopState(bool not_at_start) {
  counter_backtrack_trace_.set_backtrack(&label_);
  if (not_at_start) counter_backtrack_trace_.set_at_start(Trace::FALSE_VALUE);
}

void ChoiceNode::AssertGuardsMentionRegisters(Trace* trace) {
#ifdef DEBUG
  int choice_count = alternatives_->length();
  for (int i = 0; i < choice_count - 1; i++) {
    GuardedAlternative alternative = alternatives_->at(i);
    ZoneList<Guard*>* guards = alternative.guards();
    int guard_count = (guards == nullptr) ? 0 : guards->length();
    for (int j = 0; j < guard_count; j++) {
      DCHECK(!trace->mentions_reg(guards->at(j)->reg()));
    }
  }
#endif
}

void ChoiceNode::SetUpPreLoad(RegExpCompiler* compiler, Trace* current_trace,
                              PreloadState* state) {
  if (state->eats_at_least_ == PreloadState::kEatsAtLeastNotYetInitialized) {
    // Save some time by looking at most one machine word ahead.
    state->eats_at_least_ =
        EatsAtLeast(current_trace->at_start() == Trace::FALSE_VALUE);
  }
  state->preload_characters_ =
      CalculatePreloadCharacters(compiler, state->eats_at_least_);

  state->preload_is_current_ =
      (current_trace->characters_preloaded() == state->preload_characters_);
  state->preload_has_checked_bounds_ = state->preload_is_current_;
}

void ChoiceNode::Emit(RegExpCompiler* compiler, Trace* trace) {
  int choice_count = alternatives_->length();

  if (choice_count == 1 && alternatives_->at(0).guards() == nullptr) {
    alternatives_->at(0).node()->Emit(compiler, trace);
    return;
  }

  AssertGuardsMentionRegisters(trace);

  LimitResult limit_result = LimitVersions(compiler, trace);
  if (limit_result == DONE) return;
  DCHECK(limit_result == CONTINUE);

  // For loop nodes we already flushed (see LoopChoiceNode::Emit), but for
  // other choice nodes we only flush if we are out of code size budget.
  if (trace->flush_budget() == 0 && trace->actions() != nullptr) {
    trace->Flush(compiler, this);
    return;
  }

  RecursionCheck rc(compiler);

  PreloadState preload;
  preload.init();
  GreedyLoopState greedy_loop_state(not_at_start());

  int text_length = GreedyLoopTextLengthForAlternative(&alternatives_->at(0));
  AlternativeGenerationList alt_gens(choice_count, zone());

  if (choice_count > 1 && text_length != kNodeIsTooComplexForGreedyLoops) {
    trace = EmitGreedyLoop(compiler, trace, &alt_gens, &preload,
                           &greedy_loop_state, text_length);
  } else {
    preload.eats_at_least_ = EmitOptimizedUnanchoredSearch(compiler, trace);

    EmitChoices(compiler, &alt_gens, 0, trace, &preload);
  }

  // At this point we need to generate slow checks for the alternatives where
  // the quick check was inlined.  We can recognize these because the associated
  // label was bound.
  int new_flush_budget = trace->flush_budget() / choice_count;
  for (int i = 0; i < choice_count; i++) {
    AlternativeGeneration* alt_gen = alt_gens.at(i);
    Trace new_trace(*trace);
    // If there are actions to be flushed we have to limit how many times
    // they are flushed.  Take the budget of the parent trace and distribute
    // it fairly amongst the children.
    if (new_trace.actions() != nullptr) {
      new_trace.set_flush_budget(new_flush_budget);
    }
    bool next_expects_preload =
        i == choice_count - 1 ? false : alt_gens.at(i + 1)->expects_preload;
    EmitOutOfLineContinuation(compiler, &new_trace, alternatives_->at(i),
                              alt_gen, preload.preload_characters_,
                              next_expects_preload);
  }
}

Trace* ChoiceNode::EmitGreedyLoop(RegExpCompiler* compiler, Trace* trace,
                                  AlternativeGenerationList* alt_gens,
                                  PreloadState* preload,
                                  GreedyLoopState* greedy_loop_state,
                                  int text_length) {
  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  // Here we have special handling for greedy loops containing only text nodes
  // and other simple nodes.  These are handled by pushing the current
  // position on the stack and then incrementing the current position each
  // time around the switch.  On backtrack we decrement the current position
  // and check it against the pushed value.  This avoids pushing backtrack
  // information for each iteration of the loop, which could take up a lot of
  // space.
  DCHECK(trace->stop_node() == nullptr);
  macro_assembler->PushCurrentPosition();
  Label greedy_match_failed;
  Trace greedy_match_trace;
  if (not_at_start()) greedy_match_trace.set_at_start(Trace::FALSE_VALUE);
  greedy_match_trace.set_backtrack(&greedy_match_failed);
  Label loop_label;
  macro_assembler->Bind(&loop_label);
  greedy_match_trace.set_stop_node(this);
  greedy_match_trace.set_loop_label(&loop_label);
  alternatives_->at(0).node()->Emit(compiler, &greedy_match_trace);
  macro_assembler->Bind(&greedy_match_failed);

  Label second_choice;  // For use in greedy matches.
  macro_assembler->Bind(&second_choice);

  Trace* new_trace = greedy_loop_state->counter_backtrack_trace();

  EmitChoices(compiler, alt_gens, 1, new_trace, preload);

  macro_assembler->Bind(greedy_loop_state->label());
  // If we have unwound to the bottom then backtrack.
  macro_assembler->CheckGreedyLoop(trace->backtrack());
  // Otherwise try the second priority at an earlier position.
  macro_assembler->AdvanceCurrentPosition(-text_length);
  macro_assembler->GoTo(&second_choice);
  return new_trace;
}

int ChoiceNode::EmitOptimizedUnanchoredSearch(RegExpCompiler* compiler,
                                              Trace* trace) {
  int eats_at_least = PreloadState::kEatsAtLeastNotYetInitialized;
  if (alternatives_->length() != 2) return eats_at_least;

  GuardedAlternative alt1 = alternatives_->at(1);
  if (alt1.guards() != nullptr && alt1.guards()->length() != 0) {
    return eats_at_least;
  }
  RegExpNode* eats_anything_node = alt1.node();
  if (eats_anything_node->GetSuccessorOfOmnivorousTextNode(compiler) != this) {
    return eats_at_least;
  }

  // Really we should be creating a new trace when we execute this function,
  // but there is no need, because the code it generates cannot backtrack, and
  // we always arrive here with a trivial trace (since it's the entry to a
  // loop.  That also implies that there are no preloaded characters, which is
  // good, because it means we won't be violating any assumptions by
  // overwriting those characters with new load instructions.
  DCHECK(trace->is_trivial());

  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  Isolate* isolate = macro_assembler->isolate();
  // At this point we know that we are at a non-greedy loop that will
```