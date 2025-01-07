Response:
Let's break down the request and the provided C++ code. The goal is to understand the functionality of the given code snippet, which is part of the V8 JavaScript engine's regular expression compilation process.

**Understanding the Request:**

The request asks for a functional description of the provided C++ code. It also includes specific instructions based on properties of a potential source file (`.tq` extension for Torque) and its relationship to JavaScript. The prompt also asks for examples, logical reasoning (input/output), common programming errors, and finally, a summary of the functionality as part 3 of a series.

**Analyzing the C++ Code:**

The code deals with `CharacterRange` objects and operations on lists of these ranges. These ranges represent sets of Unicode code points. The functions provided are:

1. **`Canonicalize`**:  Takes a list of `CharacterRange`s and makes it "canonical". Canonicalization likely means merging overlapping and adjacent ranges into single, non-overlapping ranges and ensuring they are sorted.
2. **`Negate`**:  Calculates the complement of a set of `CharacterRange`s within the entire Unicode code point space. Given a set of included characters, it produces the set of excluded characters.
3. **`Intersect`**: Finds the intersection of two canonicalized lists of `CharacterRange`s.
4. **`Subtract`**:  Calculates the difference between two canonicalized lists of `CharacterRange`s (set subtraction).
5. **`ClampToOneByte`**:  Modifies a list of `CharacterRange`s to only include code points that fit within a single byte (0-255).
6. **`Equals`**:  Checks if two canonicalized lists of `CharacterRange`s are equal.
7. **`RegExpQuantifier::ToNode`**:  This is a more complex function related to regular expression quantifiers (like `*`, `+`, `{n,m}`). It seems to transform a quantifier and its associated body into a graph of `RegExpNode` objects, which represent the compiled regular expression. This involves handling loops and optional parts of the pattern.

**Addressing the Prompt's Instructions:**

*   **Functionality:** The core functionality is manipulating sets of Unicode code points represented by `CharacterRange`s. The `RegExpQuantifier::ToNode` function deals with the compilation of regex quantifiers.
*   **`.tq` extension:** The prompt correctly identifies that a `.tq` extension would indicate a Torque file. The provided code is C++, so this condition is false.
*   **Relationship to JavaScript:**  Regular expressions are a fundamental part of JavaScript. This C++ code is directly involved in how the V8 engine implements and optimizes regular expression matching.
*   **JavaScript Examples:** I need to create examples demonstrating how JavaScript regular expressions use character sets and quantifiers, and how V8's internal mechanisms (represented by this code) would process them.
*   **Code Logic Reasoning:** I need to pick one of the functions (likely one of the `CharacterRange` manipulation functions) and provide example inputs (lists of ranges) and the expected output after the function is executed.
*   **Common Programming Errors:** I should think about common mistakes developers make when working with regular expressions that relate to character sets and quantifiers.
*   **Part 3 Summary:** The summary should tie together the functionalities described in the code.

**Pre-computation and Pre-analysis:**

*   **Canonicalization:** I need to clearly explain what canonicalization is and why it's important for efficient set operations.
*   **Quantifier Compilation:** The `ToNode` function is complex. I should focus on the general idea of how it translates repetition into a state machine or a graph of nodes.
*   **Unicode:**  Emphasize that these functions operate on Unicode code points, which can be greater than 255.

**Constraint Checklist & Confidence Score:**

*   List functionality: Yes.
*   `.tq` check: Yes.
*   Relationship to JavaScript: Yes.
*   JavaScript examples: Yes.
*   Code logic reasoning: Yes.
*   Input/output: Yes (for logic reasoning).
*   Common errors: Yes.
*   Part 3 summary: Yes.

Confidence Score: 5/5 - I understand the request and the code well enough to address all parts of the prompt.

**Strategizing the Response:**

I'll structure the response to follow the prompt's order. I'll start by listing the functionalities, then address the `.tq` extension point, followed by the JavaScript relationship and examples. I'll choose a relatively simple function (like `Intersect` or `Negate`) for the code logic reasoning. Then, I'll provide common programming errors related to regex and character sets. Finally, I'll summarize the overall functionality.

Okay, the strategizing is complete. I'm ready to generate the response.

这是对 `v8/src/regexp/regexp-compiler-tonode.cc` 源代码功能的归纳总结。从您提供的代码片段来看，这个文件主要负责将正则表达式语法树中的节点（特别是量词节点 `RegExpQuantifier`）转换为用于执行的节点图（`RegExpNode`）。此外，它还包含一些用于操作字符范围 (`CharacterRange`) 的实用工具函数。

**功能归纳：**

1. **正则表达式量词的编译：**  `RegExpQuantifier::ToNode` 函数是核心功能。它将正则表达式中的量词（例如 `*`, `+`, `?`, `{n,m}`）转换为一个由 `RegExpNode` 对象组成的子图。这个子图表示了量词的匹配逻辑，包括循环、条件判断等。该函数会考虑贪婪/非贪婪匹配、最小/最大匹配次数，以及可能的优化策略（例如展开循环）。

2. **字符范围操作：**  代码中定义了 `CharacterRange` 类以及相关的静态方法，用于表示和操作 Unicode 字符的范围。这些操作包括：
    *   **规范化 (`Canonicalize`)：** 将一系列字符范围合并成一组不重叠、有序的规范化范围。
    *   **取反 (`Negate`)：** 计算给定字符范围集合的补集，即不在这些范围内的所有字符范围。
    *   **求交集 (`Intersect`)：** 计算两个字符范围集合的交集。
    *   **求差集 (`Subtract`)：** 从一个字符范围集合中移除另一个集合中的字符范围。
    *   **限制到单字节 (`ClampToOneByte`)：** 将字符范围限制在单字节字符范围内 (0-255)。
    *   **比较相等 (`Equals`)：** 判断两个字符范围集合是否相等。

**关于 `.tq` 扩展名：**

您是对的。如果 `v8/src/regexp/regexp-compiler-tonode.cc` 的文件名以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于 V8 内部实现的高级类型化语言，用于生成 C++ 代码。然而，根据您提供的代码内容来看，这是一个 **C++** 源文件 (`.cc`)，而不是 Torque 文件。

**与 JavaScript 的关系及示例：**

`v8/src/regexp/regexp-compiler-tonode.cc` 中的代码直接参与了 JavaScript 中正则表达式的编译和执行过程。当 JavaScript 引擎遇到一个正则表达式时，V8 会将其解析成语法树，然后使用类似 `RegExpQuantifier::ToNode` 这样的函数将语法树转换为用于匹配的内部表示。

**JavaScript 示例：**

```javascript
const regex1 = /a+/;  // 匹配一个或多个 'a'
const regex2 = /b{2,4}/; // 匹配 2 到 4 个 'b'
const regex3 = /[0-9]+/; // 匹配一个或多个数字
const regex4 = /[^abc]+/; // 匹配一个或多个非 'a', 'b', 'c' 的字符
```

*   `regex1` 使用了 `+` 量词，对应 `RegExpQuantifier::ToNode` 中 `min = 1`, `max = Infinity` 的情况。
*   `regex2` 使用了 `{2,4}` 量词，对应 `RegExpQuantifier::ToNode` 中 `min = 2`, `max = 4` 的情况。
*   `regex3` 使用了字符范围 `[0-9]`，内部会用 `CharacterRange` 表示。
*   `regex4` 使用了反义字符范围 `[^abc]`，内部会使用 `CharacterRange::Negate` 来计算。

**代码逻辑推理（以 `CharacterRange::Intersect` 为例）：**

**假设输入：**

*   `lhs` (List A):  包含两个规范化的字符范围: `[48, 57]` (表示 '0' 到 '9') 和 `[65, 90]` (表示 'A' 到 'Z')
*   `rhs` (List B):  包含两个规范化的字符范围: `[50, 52]` (表示 '2' 到 '4') 和 `[88, 92]` (表示 'X' 到 '\')

**预期输出 (`intersection`)：**

*   包含两个字符范围: `[50, 52]` (List A 的 `[48, 57]` 和 List B 的 `[50, 52]` 的交集) 和 `[88, 90]` (List A 的 `[65, 90]` 和 List B 的 `[88, 92]` 的交集，注意实际字符范围到 'Z')

**推理过程：**

1. 初始化 `lhs_index = 0`, `rhs_index = 0`，`intersection` 为空。
2. 比较 `lhs[0]` (`[48, 57]`) 和 `rhs[0]` (`[50, 52]`)：存在重叠，交集为 `[50, 52]`，添加到 `intersection`。由于 `to` 相等 (`52 == rhs[0].to()`)，`rhs_index++`。
3. 比较 `lhs[0]` (`[48, 57]`) 和 `rhs[1]` (`[88, 92]`)：没有重叠 (`lhs[0].to()` `<` `rhs[1].from()`)，`lhs_index++`。
4. 比较 `lhs[1]` (`[65, 90]`) 和 `rhs[1]` (`[88, 92]`)：存在重叠，交集为 `[88, 90]`，添加到 `intersection`。由于 `to` 相等 (`90 == lhs[1].to()`)，`lhs_index++`。
5. `lhs_index` 超出 `lhs` 长度，循环结束。
6. `intersection` 包含 `[50, 52]` 和 `[88, 90]`。

**用户常见的编程错误（与正则表达式和字符范围相关）：**

1. **忘记转义特殊字符：**  例如，想匹配字面意义的点号 `.`，却写成 `/./`，这将匹配任何字符。正确的写法是 `/\./`。
2. **字符范围的顺序错误：**  在字符范围中，起始字符的 ASCII 值必须小于或等于结束字符。例如，`/[z-a]/` 是无效的，应该写成 `/[a-z]/`。
3. **对量词的贪婪性理解不足：**  默认情况下，量词是贪婪的，会尽可能多地匹配。例如，对于字符串 `"aaab"` 和正则表达式 `/a+/`，会匹配 `"aaa"` 而不是 `"a"`。有时需要使用非贪婪量词 `?`，如 `/a+?/`。
4. **意外匹配换行符：**  `.` 默认情况下不匹配换行符。如果需要匹配包括换行符在内的所有字符，可以使用 `[\s\S]` 或启用 `s` (dotAll) 标志 `/./s`。
5. **字符类和字符范围的混淆：**  例如，`/[abc]/` 表示匹配 'a' 或 'b' 或 'c' 中的任意一个字符，而 `/[a-c]/` 的含义相同。但对于更复杂的集合，例如数字和字母，需要区分 `/[0-9a-zA-Z]/` 和可能的错误写法。
6. **在反义字符类中包含不希望排除的字符：** 例如，`/[^0-9]/` 匹配任何非数字字符，包括空格、标点符号等。用户可能只想排除数字，但没有考虑到其他字符。

**总结（第 3 部分）：**

总而言之，`v8/src/regexp/regexp-compiler-tonode.cc` 文件在 V8 引擎的正则表达式编译过程中扮演着关键角色。它负责将正则表达式中的量词结构转换为可执行的节点图，并提供了一组用于高效操作字符范围的工具函数。这些功能对于 JavaScript 正则表达式的正确编译和高效执行至关重要。您提供的代码片段主要展示了字符范围操作的实用工具以及量词的节点转换逻辑。

Prompt: 
```
这是目录为v8/src/regexp/regexp-compiler-tonode.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-compiler-tonode.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
 int n = character_ranges->length();
  base::uc32 max = character_ranges->at(0).to();
  int i = 1;
  while (i < n) {
    CharacterRange current = character_ranges->at(i);
    if (current.from() <= max + 1) {
      break;
    }
    max = current.to();
    i++;
  }
  // Canonical until the i'th range. If that's all of them, we are done.
  if (i == n) return;

  // The ranges at index i and forward are not canonicalized. Make them so by
  // doing the equivalent of insertion sort (inserting each into the previous
  // list, in order).
  // Notice that inserting a range can reduce the number of ranges in the
  // result due to combining of adjacent and overlapping ranges.
  int read = i;           // Range to insert.
  int num_canonical = i;  // Length of canonicalized part of list.
  do {
    num_canonical = InsertRangeInCanonicalList(character_ranges, num_canonical,
                                               character_ranges->at(read));
    read++;
  } while (read < n);
  character_ranges->Rewind(num_canonical);

  DCHECK(CharacterRange::IsCanonical(character_ranges));
}

// static
void CharacterRange::Negate(const ZoneList<CharacterRange>* ranges,
                            ZoneList<CharacterRange>* negated_ranges,
                            Zone* zone) {
  DCHECK(CharacterRange::IsCanonical(ranges));
  DCHECK_EQ(0, negated_ranges->length());
  int range_count = ranges->length();
  base::uc32 from = 0;
  int i = 0;
  if (range_count > 0 && ranges->at(0).from() == 0) {
    from = ranges->at(0).to() + 1;
    i = 1;
  }
  while (i < range_count) {
    CharacterRange range = ranges->at(i);
    negated_ranges->Add(CharacterRange::Range(from, range.from() - 1), zone);
    from = range.to() + 1;
    i++;
  }
  if (from < kMaxCodePoint) {
    negated_ranges->Add(CharacterRange::Range(from, kMaxCodePoint), zone);
  }
}

// static
void CharacterRange::Intersect(const ZoneList<CharacterRange>* lhs,
                               const ZoneList<CharacterRange>* rhs,
                               ZoneList<CharacterRange>* intersection,
                               Zone* zone) {
  DCHECK(CharacterRange::IsCanonical(lhs));
  DCHECK(CharacterRange::IsCanonical(rhs));
  DCHECK_EQ(0, intersection->length());
  int lhs_index = 0;
  int rhs_index = 0;
  while (lhs_index < lhs->length() && rhs_index < rhs->length()) {
    // Skip non-overlapping ranges.
    if (lhs->at(lhs_index).to() < rhs->at(rhs_index).from()) {
      lhs_index++;
      continue;
    }
    if (rhs->at(rhs_index).to() < lhs->at(lhs_index).from()) {
      rhs_index++;
      continue;
    }

    base::uc32 from =
        std::max(lhs->at(lhs_index).from(), rhs->at(rhs_index).from());
    base::uc32 to = std::min(lhs->at(lhs_index).to(), rhs->at(rhs_index).to());
    intersection->Add(CharacterRange::Range(from, to), zone);
    if (to == lhs->at(lhs_index).to()) {
      lhs_index++;
    } else {
      rhs_index++;
    }
  }

  DCHECK(IsCanonical(intersection));
}

namespace {

// Advance |index| and set |from| and |to| to the new range, if not out of
// bounds of |range|, otherwise |from| is set to a code point beyond the legal
// unicode character range.
void SafeAdvanceRange(const ZoneList<CharacterRange>* range, int* index,
                      base::uc32* from, base::uc32* to) {
  ++(*index);
  if (*index < range->length()) {
    *from = range->at(*index).from();
    *to = range->at(*index).to();
  } else {
    *from = kMaxCodePoint + 1;
  }
}

}  // namespace

// static
void CharacterRange::Subtract(const ZoneList<CharacterRange>* src,
                              const ZoneList<CharacterRange>* to_remove,
                              ZoneList<CharacterRange>* result, Zone* zone) {
  DCHECK(CharacterRange::IsCanonical(src));
  DCHECK(CharacterRange::IsCanonical(to_remove));
  DCHECK_EQ(0, result->length());

  if (src->is_empty()) return;

  int src_index = 0;
  int to_remove_index = 0;
  base::uc32 from = src->at(src_index).from();
  base::uc32 to = src->at(src_index).to();
  while (src_index < src->length() && to_remove_index < to_remove->length()) {
    CharacterRange remove_range = to_remove->at(to_remove_index);
    if (remove_range.to() < from) {
      // (a) Non-overlapping case, ignore current to_remove range.
      //            |-------|
      // |-------|
      to_remove_index++;
    } else if (to < remove_range.from()) {
      // (b) Non-overlapping case, add full current range to result.
      // |-------|
      //            |-------|
      result->Add(CharacterRange::Range(from, to), zone);
      SafeAdvanceRange(src, &src_index, &from, &to);
    } else if (from >= remove_range.from() && to <= remove_range.to()) {
      // (c) Current to_remove range fully covers current range.
      //   |---|
      // |-------|
      SafeAdvanceRange(src, &src_index, &from, &to);
    } else if (from < remove_range.from() && to > remove_range.to()) {
      // (d) Split current range.
      // |-------|
      //   |---|
      result->Add(CharacterRange::Range(from, remove_range.from() - 1), zone);
      from = remove_range.to() + 1;
      to_remove_index++;
    } else if (from < remove_range.from()) {
      // (e) End current range.
      // |-------|
      //    |-------|
      to = remove_range.from() - 1;
      result->Add(CharacterRange::Range(from, to), zone);
      SafeAdvanceRange(src, &src_index, &from, &to);
    } else if (to > remove_range.to()) {
      // (f) Modify start of current range.
      //    |-------|
      // |-------|
      from = remove_range.to() + 1;
      to_remove_index++;
    } else {
      UNREACHABLE();
    }
  }
  // The last range needs special treatment after |to_remove| is exhausted, as
  // |from| might have been modified by the last |to_remove| range and |to| was
  // not yet known (i.e. cases d and f).
  if (from <= to) {
    result->Add(CharacterRange::Range(from, to), zone);
  }
  src_index++;

  // Add remaining ranges after |to_remove| is exhausted.
  for (; src_index < src->length(); src_index++) {
    result->Add(src->at(src_index), zone);
  }

  DCHECK(IsCanonical(result));
}

// static
void CharacterRange::ClampToOneByte(ZoneList<CharacterRange>* ranges) {
  DCHECK(IsCanonical(ranges));

  // Drop all ranges that don't contain one-byte code units, and clamp the last
  // range s.t. it likewise only contains one-byte code units. Note this relies
  // on `ranges` being canonicalized, i.e. sorted and non-overlapping.

  static constexpr base::uc32 max_char = String::kMaxOneByteCharCodeU;
  int n = ranges->length();
  for (; n > 0; n--) {
    CharacterRange& r = ranges->at(n - 1);
    if (r.from() <= max_char) {
      r.to_ = std::min(r.to_, max_char);
      break;
    }
  }

  ranges->Rewind(n);
}

// static
bool CharacterRange::Equals(const ZoneList<CharacterRange>* lhs,
                            const ZoneList<CharacterRange>* rhs) {
  DCHECK(IsCanonical(lhs));
  DCHECK(IsCanonical(rhs));
  if (lhs->length() != rhs->length()) return false;

  for (int i = 0; i < lhs->length(); i++) {
    if (lhs->at(i) != rhs->at(i)) return false;
  }

  return true;
}

namespace {

// Scoped object to keep track of how much we unroll quantifier loops in the
// regexp graph generator.
class RegExpExpansionLimiter {
 public:
  static const int kMaxExpansionFactor = 6;
  RegExpExpansionLimiter(RegExpCompiler* compiler, int factor)
      : compiler_(compiler),
        saved_expansion_factor_(compiler->current_expansion_factor()),
        ok_to_expand_(saved_expansion_factor_ <= kMaxExpansionFactor) {
    DCHECK_LT(0, factor);
    if (ok_to_expand_) {
      if (factor > kMaxExpansionFactor) {
        // Avoid integer overflow of the current expansion factor.
        ok_to_expand_ = false;
        compiler->set_current_expansion_factor(kMaxExpansionFactor + 1);
      } else {
        int new_factor = saved_expansion_factor_ * factor;
        ok_to_expand_ = (new_factor <= kMaxExpansionFactor);
        compiler->set_current_expansion_factor(new_factor);
      }
    }
  }

  ~RegExpExpansionLimiter() {
    compiler_->set_current_expansion_factor(saved_expansion_factor_);
  }

  bool ok_to_expand() { return ok_to_expand_; }

 private:
  RegExpCompiler* compiler_;
  int saved_expansion_factor_;
  bool ok_to_expand_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(RegExpExpansionLimiter);
};

}  // namespace

RegExpNode* RegExpQuantifier::ToNode(int min, int max, bool is_greedy,
                                     RegExpTree* body, RegExpCompiler* compiler,
                                     RegExpNode* on_success,
                                     bool not_at_start) {
  // x{f, t} becomes this:
  //
  //             (r++)<-.
  //               |     `
  //               |     (x)
  //               v     ^
  //      (r=0)-->(?)---/ [if r < t]
  //               |
  //   [if r >= f] \----> ...
  //

  // 15.10.2.5 RepeatMatcher algorithm.
  // The parser has already eliminated the case where max is 0.  In the case
  // where max_match is zero the parser has removed the quantifier if min was
  // > 0 and removed the atom if min was 0.  See AddQuantifierToAtom.

  // If we know that we cannot match zero length then things are a little
  // simpler since we don't need to make the special zero length match check
  // from step 2.1.  If the min and max are small we can unroll a little in
  // this case.
  static const int kMaxUnrolledMinMatches = 3;  // Unroll (foo)+ and (foo){3,}
  static const int kMaxUnrolledMaxMatches = 3;  // Unroll (foo)? and (foo){x,3}
  if (max == 0) return on_success;  // This can happen due to recursion.
  bool body_can_be_empty = (body->min_match() == 0);
  int body_start_reg = RegExpCompiler::kNoRegister;
  Interval capture_registers = body->CaptureRegisters();
  bool needs_capture_clearing = !capture_registers.is_empty();
  Zone* zone = compiler->zone();

  if (body_can_be_empty) {
    body_start_reg = compiler->AllocateRegister();
  } else if (compiler->optimize() && !needs_capture_clearing) {
    // Only unroll if there are no captures and the body can't be
    // empty.
    {
      RegExpExpansionLimiter limiter(compiler, min + ((max != min) ? 1 : 0));
      if (min > 0 && min <= kMaxUnrolledMinMatches && limiter.ok_to_expand()) {
        int new_max = (max == kInfinity) ? max : max - min;
        // Recurse once to get the loop or optional matches after the fixed
        // ones.
        RegExpNode* answer =
            ToNode(0, new_max, is_greedy, body, compiler, on_success, true);
        // Unroll the forced matches from 0 to min.  This can cause chains of
        // TextNodes (which the parser does not generate).  These should be
        // combined if it turns out they hinder good code generation.
        for (int i = 0; i < min; i++) {
          answer = body->ToNode(compiler, answer);
        }
        return answer;
      }
    }
    if (max <= kMaxUnrolledMaxMatches && min == 0) {
      DCHECK_LT(0, max);  // Due to the 'if' above.
      RegExpExpansionLimiter limiter(compiler, max);
      if (limiter.ok_to_expand()) {
        // Unroll the optional matches up to max.
        RegExpNode* answer = on_success;
        for (int i = 0; i < max; i++) {
          ChoiceNode* alternation = zone->New<ChoiceNode>(2, zone);
          if (is_greedy) {
            alternation->AddAlternative(
                GuardedAlternative(body->ToNode(compiler, answer)));
            alternation->AddAlternative(GuardedAlternative(on_success));
          } else {
            alternation->AddAlternative(GuardedAlternative(on_success));
            alternation->AddAlternative(
                GuardedAlternative(body->ToNode(compiler, answer)));
          }
          answer = alternation;
          if (not_at_start && !compiler->read_backward()) {
            alternation->set_not_at_start();
          }
        }
        return answer;
      }
    }
  }
  bool has_min = min > 0;
  bool has_max = max < RegExpTree::kInfinity;
  bool needs_counter = has_min || has_max;
  int reg_ctr = needs_counter ? compiler->AllocateRegister()
                              : RegExpCompiler::kNoRegister;
  LoopChoiceNode* center = zone->New<LoopChoiceNode>(
      body->min_match() == 0, compiler->read_backward(), min, zone);
  if (not_at_start && !compiler->read_backward()) center->set_not_at_start();
  RegExpNode* loop_return =
      needs_counter ? static_cast<RegExpNode*>(
                          ActionNode::IncrementRegister(reg_ctr, center))
                    : static_cast<RegExpNode*>(center);
  if (body_can_be_empty) {
    // If the body can be empty we need to check if it was and then
    // backtrack.
    loop_return =
        ActionNode::EmptyMatchCheck(body_start_reg, reg_ctr, min, loop_return);
  }
  RegExpNode* body_node = body->ToNode(compiler, loop_return);
  if (body_can_be_empty) {
    // If the body can be empty we need to store the start position
    // so we can bail out if it was empty.
    body_node = ActionNode::StorePosition(body_start_reg, false, body_node);
  }
  if (needs_capture_clearing) {
    // Before entering the body of this loop we need to clear captures.
    body_node = ActionNode::ClearCaptures(capture_registers, body_node);
  }
  GuardedAlternative body_alt(body_node);
  if (has_max) {
    Guard* body_guard = zone->New<Guard>(reg_ctr, Guard::LT, max);
    body_alt.AddGuard(body_guard, zone);
  }
  GuardedAlternative rest_alt(on_success);
  if (has_min) {
    Guard* rest_guard = compiler->zone()->New<Guard>(reg_ctr, Guard::GEQ, min);
    rest_alt.AddGuard(rest_guard, zone);
  }
  if (is_greedy) {
    center->AddLoopAlternative(body_alt);
    center->AddContinueAlternative(rest_alt);
  } else {
    center->AddContinueAlternative(rest_alt);
    center->AddLoopAlternative(body_alt);
  }
  if (needs_counter) {
    return ActionNode::SetRegisterForLoop(reg_ctr, 0, center);
  } else {
    return center;
  }
}

}  // namespace internal
}  // namespace v8

"""


```