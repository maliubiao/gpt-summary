Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/regexp/regexp-compiler.cc`. The summary should cover:

1. **General Functionality:** What does this code do?
2. **Torque Source Check:** Does it look like a Torque file (ends in `.tq`)?
3. **JavaScript Relation:** If it's related to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:**  Give an example of input and output based on the code logic.
5. **Common Programming Errors:**  Point out potential user errors related to this code.
6. **Overall Function Summary:** A concise summary of the code's purpose.

Let's break down the provided code:

* **`QuickCheckDetails` Class:** This class seems to be involved in pre-computation or optimization for regular expression matching. It stores information about potential quick checks that can be performed to see if a match is possible at a given position.
* **`VisitMarker` and `LoopInitializationMarker` Classes:** These appear to be utility classes for tracking visited nodes during graph traversal, likely related to handling loops in the regular expression.
* **`IterationDecrementer` Class:**  This is used to temporarily decrease a loop counter, probably during analysis of loop behavior.
* **`FilterOneByte` Methods:** These methods (defined for different `RegExpNode` types) suggest a process of filtering or optimizing the regular expression for one-byte string matching. They seem to be determining if a part of the regex can potentially match within the one-byte character range.
* **`GetQuickCheckDetails` Methods:** These methods (also defined for different `RegExpNode` types) seem to be populating the `QuickCheckDetails` object with information about potential quick checks.
* **`FillInBMInfo` Method:** This method is likely related to the Boyer-Moore string searching algorithm, which is often used for optimizing string matching.
* **`EmitWordCheck` Function:** This function appears to generate code to check if a character is a "word" character (alphanumeric or underscore).
* **`EmitHat` Function:** This function seems to generate code to handle the `^` anchor in multiline mode, checking for the start of the input or a newline character before the current position.
* **`AssertionNode::EmitBoundaryCheck`, `AssertionNode::BacktrackIfPrevious`, `AssertionNode::GetQuickCheckDetails`, `AssertionNode::Emit`:** These methods handle the logic for different types of assertions in regular expressions (like `\b`, `\B`, `^`, `$`).
* **`TextNode::TextEmitPass`:** This method seems to be responsible for generating the actual machine code for matching literal text within the regular expression. It iterates through the text elements and performs character comparisons.

**Plan for the summary:**

1. State the core functionality:  The code is part of the V8 regular expression compiler, focusing on optimization techniques like quick checks and one-byte string filtering.
2. Torque check: Explicitly state it's not a Torque file.
3. JavaScript relation: Explain that regular expressions are a core JavaScript feature and this code is part of their implementation. Provide a simple example.
4. Code Logic Inference: Focus on the `QuickCheckDetails` and how it might determine whether a simple character check is sufficient for a potential match. Provide an example with case sensitivity.
5. Common Programming Errors: Explain that while this code is internal, incorrect regex patterns can lead to performance issues that this code aims to mitigate.
6. Overall Summary:  Reiterate that this code is for optimizing regular expression compilation in V8.
这是v8源代码文件 `v8/src/regexp/regexp-compiler.cc` 的第 3 部分，主要负责 **正则表达式编译过程中的优化和代码生成**，特别是针对 **快速检查 (Quick Check)** 和 **单字节字符串 (One-Byte String)** 的优化。

**功能列举:**

1. **快速检查 (Quick Check) 机制的实现:**
   -  定义了 `QuickCheckDetails` 类，用于存储关于可以快速检查的字符位置的信息，例如掩码 (mask)、值 (value) 以及是否能确定性匹配 (`determines_perfectly`)。
   -  `GetQuickCheckDetails` 方法在不同的 `RegExpNode` 子类中实现，用于分析正则表达式结构，并填充 `QuickCheckDetails` 对象，指出哪些位置可以通过简单的掩码和比较操作进行快速检查。
   -  `Merge` 方法用于合并不同分支的快速检查信息，例如在 `ChoiceNode` 中合并多个选择项的快速检查结果。
   -  快速检查的目标是在执行完整的正则表达式匹配之前，通过一些廉价的操作快速排除不匹配的可能性，从而提高性能。

2. **单字节字符串过滤 (One-Byte String Filtering):**
   -  定义了 `FilterOneByte` 方法在不同的 `RegExpNode` 子类中实现。
   -  `FilterOneByte` 的目的是判断正则表达式的某个部分是否有可能匹配单字节字符串。如果确定不可能匹配，则可以将其替换为 `nullptr`，从而在后续的编译和执行过程中跳过这部分，提高效率。
   -  这个过程会考虑字符编码、大小写敏感性等因素。

3. **循环节点的优化处理:**
   -  定义了 `LoopChoiceNode`，专门处理循环结构（例如 `*`, `+`, `{n,m}`）。
   -  `GetQuickCheckDetails` 和 `FillInBMInfo` 方法在 `LoopChoiceNode` 中有特殊的处理逻辑，以考虑到循环可能执行多次的特性。
   -  引入了 `VisitMarker` 和 `LoopInitializationMarker` 等辅助类，用于在图遍历过程中标记节点状态，防止无限循环和重复处理。

4. **断言节点的处理:**
   -  定义了 `AssertionNode`，用于处理正则表达式中的断言，例如 `^` (行首), `$` (行尾), `\b` (单词边界), `\B` (非单词边界)。
   -  `Emit` 方法用于生成断言节点的代码。
   -  `EmitBoundaryCheck` 和 `BacktrackIfPrevious` 方法用于生成单词边界断言的代码，这涉及到检查当前和前一个字符是否为单词字符。
   -  `GetQuickCheckDetails` 方法也为断言节点提供了快速检查的可能性。

5. **文本节点的代码生成:**
   -  定义了 `TextNode`，用于处理正则表达式中的字面量文本和字符类。
   -  `TextEmitPass` 方法负责生成匹配文本节点的代码，它会根据不同的优化策略和字符类型生成相应的机器码指令。

**关于是否是 Torque 源代码:**

`v8/src/regexp/regexp-compiler.cc` 以 `.cc` 结尾，表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`v8/src/regexp/regexp-compiler.cc` 直接关系到 JavaScript 中正则表达式的功能。当你在 JavaScript 中使用正则表达式时，V8 引擎会编译这个正则表达式，而 `regexp-compiler.cc` 中的代码就是负责这个编译过程的关键部分。

**JavaScript 示例:**

```javascript
const regex1 = /abc/i; // 一个简单的正则表达式，忽略大小写
const text1 = "AbCde";
console.log(regex1.test(text1)); // 输出: true

const regex2 = /^hello/; // 匹配以 "hello" 开头的字符串
const text2 = "hello world";
const text3 = "world hello";
console.log(regex2.test(text2)); // 输出: true
console.log(regex2.test(text3)); // 输出: false

const regex3 = /\bworld\b/; // 匹配独立的 "world" 单词
const text4 = "hello world!";
const text5 = "helloworld!";
console.log(regex3.test(text4)); // 输出: true
console.log(regex3.test(text5)); // 输出: false
```

当 V8 引擎编译 `regex1`, `regex2`, `regex3` 这些正则表达式时，`regexp-compiler.cc` 中的代码就会参与其中，例如：

- 对于 `regex1` 中的 `/abc/`，`TextNode::TextEmitPass` 可能会生成代码来逐个比较字符 'a', 'b', 'c'。由于有 `i` 标志，`GetCaseIndependentLetters` 等函数会被调用来处理大小写不敏感的匹配。
- 对于 `regex2` 中的 `^hello`，`AssertionNode::Emit` 会生成代码来检查是否位于字符串的开头。
- 对于 `regex3` 中的 `\bworld\b`，`AssertionNode::EmitBoundaryCheck` 会生成代码来检查 "world" 前后是否是单词边界。
- `QuickCheckDetails` 可能会被用来预先判断是否有可能匹配，例如，如果字符串很短，可能直接就能排除匹配的可能性。
- 如果目标字符串是单字节字符串，`FilterOneByte` 可能会优化编译过程，避免不必要的双字节字符处理。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下正则表达式和输入：

**正则表达式:** `/a/` (大小写敏感)
**输入字符串:** "b"

1. **`FilterOneByte` (可能):**  由于正则表达式只包含 'a'，`FilterOneByte` 可能会判断这个正则表达式可以匹配单字节字符串。
2. **`GetQuickCheckDetails`:**
   - 输入：`TextNode` 代表字符 'a'
   - 输出：`QuickCheckDetails` 对象，其中 `positions[0].mask` 可能被设置为一个能提取字符的掩码，`positions[0].value` 被设置为 'a' 的 ASCII 值，`positions[0].determines_perfectly` 被设置为 `true`，因为单个字符的匹配是确定的。
3. **代码生成 (`TextNode::TextEmitPass`):**
   - 输入：字符 'a' 的 `TextNode`，当前字符的偏移量等。
   - 输出：生成的机器码指令，大致逻辑是：加载当前字符，将其与 'a' 的 ASCII 值进行比较，如果相等则跳转到成功分支，否则跳转到回溯分支。

**用户常见的编程错误:**

虽然用户不会直接与 `regexp-compiler.cc` 交互，但用户编写的正则表达式的效率会受到这个编译器的影响。一些常见的编程错误可能导致编译器无法进行有效优化，从而降低正则表达式的匹配性能：

1. **过度使用回溯:**  复杂的正则表达式，尤其是包含大量嵌套的可选或重复部分，可能导致大量的回溯，使匹配效率急剧下降（例如，灾难性回溯）。
   - **例子:**  `/a*b*c*/(.*d)*/` 在某些输入下可能导致大量回溯。
2. **不必要的字符类或分组:**  使用过于宽泛的字符类或不必要的分组可能会阻止编译器进行更精细的优化。
   - **例子:**  `/[a-zA-Z0-9_]/` 可以用 `/\w/` 代替。
3. **在循环中使用复杂的子模式:**  在循环结构中使用复杂的子模式可能会降低性能。
   - **例子:**  `/(very )*\w+/`。
4. **忘记锚定正则表达式:**  对于需要匹配字符串开头或结尾的情况，忘记使用 `^` 或 `$` 可能会导致不必要的搜索。
   - **例子:**  要匹配以 "start" 开头的字符串，应该使用 `/^start/` 而不是 `/start/`。

**功能归纳:**

`v8/src/regexp/regexp-compiler.cc` 的这一部分主要负责 V8 引擎中 **正则表达式的编译优化和代码生成**。它通过实现 **快速检查机制** 和 **单字节字符串过滤** 等技术，以及对 **循环节点** 和 **断言节点** 的特殊处理，来提升正则表达式的匹配性能。最终，它会将正则表达式转化为高效的机器码指令，供 V8 引擎执行。 这段代码是 JavaScript 正则表达式功能高效运行的核心组成部分。

### 提示词
```
这是目录为v8/src/regexp/regexp-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                                  cp_offset + j, ne
```