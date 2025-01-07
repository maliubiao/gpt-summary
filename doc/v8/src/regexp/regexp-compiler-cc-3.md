Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/regexp/regexp-compiler.cc`. I need to identify the core responsibilities of this code. It appears to be involved in compiling regular expressions, specifically handling the matching of text segments within the input string.

Here's a breakdown of my thought process:

1. **Identify the Class:** The code primarily focuses on the `TextNode` and `ChoiceNode` classes and their associated helper classes and functions.

2. **`TextNode` Functionality:**
    * **Matching Text:** The `Emit` method seems crucial. It describes a multi-pass approach (`TextEmitPass`) for efficiently matching characters and character classes. The passes suggest optimization strategies for different character types (simple, case-insensitive, character classes).
    * **Text Representation:**  The `CreateForCharacterRanges` and `CreateForSurrogatePair` methods indicate how `TextNode`s are constructed to represent different kinds of text patterns (character ranges, surrogate pairs).
    * **Case-Insensitive Matching:** The `MakeCaseIndependent` method shows how `TextNode`s are modified to handle case-insensitive matching by adding case equivalents to character ranges.
    * **Greedy Loop Length:** The `GreedyLoopTextLength` and `GetSuccessorOfOmnivorousTextNode` methods suggest involvement in optimizing greedy loops in regular expressions.

3. **`ChoiceNode` Functionality:**
    * **Handling Alternatives:**  The `Emit` method, along with `EmitChoices` and `EmitOutOfLineContinuation`, clearly deals with processing alternative matching paths in a regular expression.
    * **Quick Checks:** The comments and the structure of `EmitChoices` suggest the use of "quick checks" (mask and compare operations) to efficiently eliminate failing alternatives.
    * **Preloading Characters:**  The `CalculatePreloadCharacters` method and the logic within `EmitChoices` indicate an optimization where characters are preloaded to avoid redundant loading.
    * **Greedy Loops:** The `EmitGreedyLoop` method implements a specialized handling for greedy loops to optimize performance by managing the current position efficiently.
    * **Optimized Unanchored Search:** The `EmitOptimizedUnanchoredSearch` method indicates a specific optimization for unanchored searches (finding a match anywhere in the string) involving an "omnivorous" text node.

4. **Helper Classes and Functions:**
    * **`TextElement`:** Seems to represent individual components within a `TextNode` (atoms, character ranges).
    * **`RegExpClassRanges`:**  Represents a set of character ranges.
    * **`Trace`:** Appears to track the state of the compilation process, including the current position, preloaded characters, and backtrack information.
    * **`BoyerMooreLookahead`:**  Implements the Boyer-Moore string searching algorithm to potentially optimize matching by skipping ahead.
    * **`AlternativeGeneration`:**  Manages information about how each alternative in a `ChoiceNode` is being compiled.
    * **`GreedyLoopState`:** Manages the state for compiling greedy loops.
    * **`PreloadState`:** Manages the state for preloading characters.

5. **Inferring High-Level Functionality:** Based on the individual components, the overall purpose of `regexp-compiler.cc` (or this part of it) is to take a representation of a regular expression (likely after parsing) and generate low-level instructions (presumably for a virtual machine or directly for the processor) to perform the matching efficiently. It incorporates various optimization techniques like quick checks, preloading, and special handling for greedy loops and unanchored searches.

6. **Considering the `.tq` Extension:** The prompt mentions the `.tq` extension, indicating Torque. While the provided snippet is `.cc`, the instruction is to consider *if* it were `.tq`. If so, it would be a Torque source file, which is a domain-specific language used in V8 for generating C++ code. This implies that some of the code might be auto-generated from higher-level Torque specifications.

7. **JavaScript Relevance:** Regular expressions are a core feature of JavaScript. The C++ code directly implements the underlying matching logic for JavaScript's `RegExp` objects.

8. **Code Logic Inference:** The code demonstrates conditional logic based on the type of text element, whether case-insensitivity is required, and optimization strategies. The `Emit` methods recursively call each other to process the structure of the regular expression.

9. **Common Programming Errors:**  While the C++ code itself is not directly written by users, understanding its function helps identify potential issues in user-written regular expressions that could lead to performance problems (e.g., overly complex expressions, inefficient use of alternatives).

By combining these observations, I can synthesize a summary of the code's functionality.
这是 `v8/src/regexp/regexp-compiler.cc` 源代码的第 4 部分，它主要关注于正则表达式中 **文本节点 (`TextNode`)** 和 **选择节点 (`ChoiceNode`)** 的编译过程，并涉及一些优化策略。

**主要功能归纳:**

1. **文本节点 (`TextNode`) 的编译:**
   - `TextNode` 代表正则表达式中的一段文本，可以是单个字符、字符序列或字符类。
   - `Emit` 方法是 `TextNode` 的核心，负责生成匹配这段文本的代码。它采用了多趟 (multi-pass) 的编译策略，以提高效率：
     - **预加载字符 (Preloading):**  优化了首字符的匹配，如果前一个操作已经加载了字符，则可以避免重复加载。
     - **不同类型的匹配 (TextEmitPass):** 针对不同的字符匹配类型（简单字符、大小写不敏感字符、字符类）生成不同的代码。
     - **边界检查 (Bounds Check):**  确保不会读取超出输入字符串的范围。
   - `CreateForCharacterRanges` 和 `CreateForSurrogatePair` 等方法用于创建不同类型的 `TextNode`。
   - `MakeCaseIndependent` 方法用于处理大小写不敏感的匹配，会将字符范围扩展到包含其大小写变体。
   - `GreedyLoopTextLength` 和 `GetSuccessorOfOmnivorousTextNode` 用于支持贪婪循环的优化。

2. **选择节点 (`ChoiceNode`) 的编译:**
   - `ChoiceNode` 代表正则表达式中的多个可选匹配路径（例如 `a|b|c`）。
   - `Emit` 方法负责生成处理这些可选路径的代码。
   - **快速检查 (Quick Check):**  使用了“快速检查”机制，通过位掩码和比较快速排除不太可能匹配的分支，提高匹配效率。
   - **预加载 (Preload):** 在选择节点中也会考虑预加载字符以优化性能。
   - **贪婪循环 (Greedy Loop):** `EmitGreedyLoop` 方法专门处理包含文本节点的贪婪循环，通过栈操作和位置调整来优化性能，避免为每次循环迭代都保存回溯信息。
   - **优化的非锚定搜索 (Optimized Unanchored Search):** `EmitOptimizedUnanchoredSearch` 针对非锚定的搜索（在字符串中任意位置匹配）进行优化，特别是当存在一个可以匹配任何字符的“万能”节点时。

3. **辅助类和优化策略:**
   - `TextElement`: 表示 `TextNode` 中的单个元素，例如一个原子字符或一个字符类范围。
   - `RegExpClassRanges`: 用于表示字符类的范围。
   - `Trace`: 用于跟踪编译过程中的状态，例如当前匹配位置、预加载的字符等，用于指导代码生成。
   - `BoyerMooreLookahead`: 实现了 Boyer-Moore 字符串查找算法，用于在编译时分析可能的跳跃机会，以优化匹配性能。
   - `AlternativeGeneration`: 用于记录选择节点中每个备选项的代码生成方式。
   - `GreedyLoopState`: 用于管理贪婪循环的状态。
   - `PreloadState`: 用于管理预加载字符的状态。

**关于 `.tq` 结尾:**

如果 `v8/src/regexp/regexp-compiler.cc` 以 `.tq` 结尾，那么它将是一个 **v8 Torque 源代码**。 Torque 是 V8 使用的一种领域特定语言，用于生成 C++ 代码。  这通常用于实现一些核心的 VM 功能，包括正则表达式引擎。在这种情况下，提供的是 `.cc` 文件，所以它是直接的 C++ 代码。

**与 JavaScript 功能的关系:**

`v8/src/regexp/regexp-compiler.cc` 直接参与了 **JavaScript 中正则表达式 (`RegExp`) 功能的实现**。  当你在 JavaScript 中使用正则表达式进行匹配时，V8 的正则表达式引擎会解析你的正则表达式，并使用类似 `regexp-compiler.cc` 中的代码将其编译成可执行的指令。

**JavaScript 示例:**

```javascript
const regex = /ab[cd]e/i; // 包含文本节点 (ab, e) 和字符类节点 ([cd])，以及忽略大小写标志 i
const text = "AbcDeF";
const match = regex.exec(text);

if (match) {
  console.log("匹配成功:", match[0]); // 输出: "AbcDe"
}
```

在这个例子中，`regexp-compiler.cc` 中的代码负责生成高效地匹配 "ab"，字符 'c' 或 'd' (忽略大小写)，然后匹配 "e" 的指令。

**代码逻辑推理 (假设输入与输出):**

假设有一个简单的 `TextNode`，表示要匹配的字符串 "hello"。

**假设输入:**

- `TextNode` 包含 `TextElement` 列表，每个元素代表 "h", "e", "l", "l", "o" 这五个字符。
- `compiler`: 一个 `RegExpCompiler` 对象，包含了编译时的上下文信息。
- `trace`: 一个 `Trace` 对象，记录了当前的编译状态。

**可能输出 (简化的伪代码):**

`Emit` 方法可能会生成类似以下的指令：

```assembly
  // 尝试匹配 'h'
  LoadCurrentCharacter(0);
  CheckCharacter('h', fail_label);

  // 尝试匹配 'e'
  LoadCurrentCharacter(1);
  CheckCharacter('e', fail_label);

  // 尝试匹配 'l'
  LoadCurrentCharacter(2);
  CheckCharacter('l', fail_label);

  // 尝试匹配 'l'
  LoadCurrentCharacter(3);
  CheckCharacter('l', fail_label);

  // 尝试匹配 'o'
  LoadCurrentCharacter(4);
  CheckCharacter('o', fail_label);

  // 匹配成功，跳转到 success_label
  GoTo(success_label);

fail_label:
  // 匹配失败，执行回溯
  GoTo(trace->backtrack());
```

**用户常见的编程错误:**

用户在编写正则表达式时可能会犯一些导致性能下降的错误，而 `regexp-compiler.cc` 的优化策略正是为了应对这些问题：

- **过度使用或不必要的选择 (`|`)**:  例如 `/a|b|c|d.../`，会导致 `ChoiceNode` 的分支过多，如果没有有效的快速检查，会导致效率下降。编译器会尝试使用快速检查来优化这种情况。
- **复杂的重复模式**:  例如 `a*b*c*`，如果没有好的优化，可能会导致大量的回溯。 贪婪循环的优化旨在提高这类模式的性能。
- **在循环中使用复杂的模式**: 例如 `(verylongpattern)*`，这可能会导致编译后的代码非常庞大。

**总结:**

`v8/src/regexp/regexp-compiler.cc` 的第 4 部分主要负责将正则表达式中的文本匹配和选择逻辑转换为高效的机器指令。它通过多趟编译、预加载、快速检查、贪婪循环优化等技术来提高正则表达式的匹配性能。理解这部分代码的功能有助于理解 V8 如何高效地执行 JavaScript 中的正则表达式。

Prompt: 
```
这是目录为v8/src/regexp/regexp-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
eds_bounds_check, preloaded);
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
"""


```