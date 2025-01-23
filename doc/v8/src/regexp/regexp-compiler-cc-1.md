Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `v8/src/regexp/regexp-compiler.cc` file.

Here's a breakdown of the request and how to address it:

1. **Identify the code's purpose:** The code is related to regular expression compilation within the V8 JavaScript engine. It appears to deal with generating machine code instructions for matching specific characters or character classes in a string.

2. **List functionalities:**  Go through the functions and code blocks in the snippet and describe what they do. Focus on the core actions and their impact on the regex matching process.

3. **Check for Torque source:** The prompt asks if the file ends with `.tq`. The snippet is from a `.cc` file, so it's C++, not Torque.

4. **Relate to JavaScript (if applicable):**  Since this code is part of V8, it directly influences how JavaScript regular expressions are executed. Provide a JavaScript example that would trigger the type of operations seen in the C++ code.

5. **Provide code logic reasoning (input/output):**  For specific functions, describe a hypothetical input and the expected output or behavior based on the code.

6. **Illustrate common programming errors:** Consider what mistakes a user might make in their JavaScript regex that would relate to the functionality in this C++ code.

7. **Summarize the overall function:** Combine the individual functionalities into a concise summary of what the `regexp-compiler.cc` (or at least this part of it) is responsible for.

**Mental Sandbox:**

* **`EmitAtom...` functions:**  These seem to generate code to check if the current character matches a specific atom (character or sequence). They handle case sensitivity and different character encodings.
* **`ShortCutEmitCharacterPair`:**  This looks like an optimization for matching one of two characters that differ by a small amount.
* **`EmitBoundaryTest`, `EmitDoubleBoundaryTest`:** These functions appear to generate code to check if the current character is within or outside specific ranges, likely for character classes.
* **`EmitUseLookupTable`:**  This suggests the use of a lookup table for efficient character class matching, especially for large sets of characters.
* **`CutOutRange`:**  This function modifies the character ranges, potentially for optimization during compilation.
* **`SplitSearchSpace`:** This deals with dividing the search space for more complex character classes, probably related to the table lookup approach.
* **`GenerateBranches`:** This seems like the central function for generating the actual conditional jumps based on character ranges.
* **`EmitClassRanges`:** This function orchestrates the process of generating code for matching character classes.
* **The rest of the code (starting with `RegExpNode`):** This seems to be part of a node-based representation of the regular expression and deals with optimizations like "quick checks" to fail early and avoid unnecessary backtracking.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果v8/src/regexp/regexp-compiler.cc以.tq结尾：Addressed, it's `.cc`.
* 如果它与javascript的功能有关系：Yes
* 请用javascript举例说明: Yes
* 如果有代码逻辑推理：Yes
* 请给出假设输入与输出：Yes
* 如果涉及用户常见的编程错误：Yes
* 这是第2部分，共5部分：Acknowledged, but doesn't change the response for *this* part.
* 请归纳一下它的功能: Yes

Confidence Score: 5/5 - I'm confident I can address all parts of the request based on the provided code.

Strategizing complete. Proceeding with response generation.
这是v8源代码文件 `v8/src/regexp/regexp-compiler.cc` 的一部分，它负责将正则表达式（RegExp）编译成可以在V8引擎中执行的机器码。由于文件以 `.cc` 结尾，它是一个 C++ 源代码文件，而不是 Torque 源代码（Torque 文件以 `.tq` 结尾）。

**功能归纳:**

这段代码的主要功能是生成用于在字符串中查找匹配项的低级指令。它专注于处理正则表达式中的**原子**（单个字符）和**字符类**的匹配。代码中包含了多种优化策略，以提高正则表达式的执行效率。

**具体功能列表:**

1. **原子匹配的生成:**
   - `EmitAtomNonLetter`: 为非字母字符生成匹配指令，主要用于不区分大小写的匹配。
   - `EmitAtomLetter`: 为字母字符生成匹配指令，主要用于不区分大小写的匹配。
   - `ShortCutEmitCharacterPair`:  针对两个仅有一位不同的字符进行优化的匹配指令生成。

2. **边界测试指令的生成:**
   - `EmitBoundaryTest`: 生成检查当前字符是否小于或大于某个边界值的指令，用于字符类匹配。
   - `EmitDoubleBoundaryTest`: 生成检查当前字符是否在两个边界值之间的指令，用于字符类匹配。

3. **使用查找表进行字符类匹配:**
   - `EmitUseLookupTable`:  对于较大的字符类，生成使用查找表（`ByteArray`）进行快速匹配的指令。这是一种提高效率的手段，避免生成大量的比较指令。

4. **优化字符类范围:**
   - `CutOutRange`:  在字符类匹配中，通过修改范围数组来优化匹配过程。
   - `SplitSearchSpace`:  对于Unicode字符类，将搜索空间分割成更小的部分，以便递归处理，利用查找表进行优化。

5. **生成字符类匹配分支:**
   - `GenerateBranches`:  核心函数，根据字符类的范围生成一系列条件分支指令，判断当前字符是否属于该字符类。它会根据字符类的大小和复杂性选择不同的生成策略，例如直接比较、范围比较或使用查找表。

6. **处理正则表达式字符类:**
   - `EmitClassRanges`:  接收一个 `RegExpClassRanges` 对象，并生成相应的机器码来匹配该字符类。它会进行范围的规范化、裁剪，并根据范围的数量和类型选择不同的匹配策略，包括使用内置的特殊字符类检查（例如 `\d`, `\w`）。

7. **正则表达式节点处理:**
   - `RegExpNode::LimitVersions`:  控制为正则表达式节点生成的代码版本数量，避免代码膨胀和无限递归。
   - `RegExpNode::KeepRecursing`:  判断是否继续递归生成特定版本的代码。

8. **动作节点处理 (例如，捕获组，标志修改):**
   - `ActionNode::FillInBMInfo`:  为 Boyer-Moore 搜索算法提供信息。
   - `ActionNode::GetQuickCheckDetails`:  收集快速检查的信息。

9. **断言节点处理 (例如，`^`, `$`, `\b`):**
   - `AssertionNode::FillInBMInfo`: 为 Boyer-Moore 搜索算法提供信息。

10. **否定前瞻选择节点处理:**
    - `NegativeLookaroundChoiceNode::GetQuickCheckDetails`: 收集快速检查的信息。

11. **快速检查优化:**
    - `QuickCheckDetails::Rationalize`:  整理和优化快速检查所需的信息。
    - `RegExpNode::EatsAtLeast`:  计算一个节点至少消耗多少字符。
    - `RegExpNode::EmitQuickCheck`:  生成快速检查的代码，用于提前判断是否可能匹配失败，避免不必要的回溯。

12. **循环选择节点处理:**
    - `LoopChoiceNode::EatsAtLeastFromLoopEntry`:  计算循环结构至少消耗多少字符。

13. **文本节点处理:**
    - `TextNode::GetQuickCheckDetails`: 收集文本节点的快速检查信息。

**与 JavaScript 功能的关系及示例:**

这段代码直接影响 JavaScript 中正则表达式的执行效率。当你在 JavaScript 中使用正则表达式时，V8 引擎会使用 `regexp-compiler.cc` 中的代码将你的正则表达式编译成机器码。

**JavaScript 示例:**

```javascript
const regex1 = /abc/; // 简单的原子匹配
const regex2 = /[a-z]/; // 简单的字符类匹配
const regex3 = /[a-zA-Z]/i; // 不区分大小写的字符类匹配
const regex4 = /[0-9a-fA-F]/; // 包含多个范围的字符类
const regex5 = /[\u4E00-\u9FA5]/; // 匹配中文字符的字符类
```

当 V8 编译这些正则表达式时，`regexp-compiler.cc` 中的代码会被调用，根据正则表达式的结构生成相应的机器码。例如：

- 对于 `regex1`，`EmitAtomNonLetter` (可能在内部调用) 会生成检查 'a', 'b', 'c' 字符的指令。
- 对于 `regex2`，`GenerateBranches` 和 `EmitClassRanges` 会生成检查字符是否在 'a' 到 'z' 范围内的指令。
- 对于 `regex3`，由于使用了 `i` 标志，`EmitAtomLetter` 或类似的函数会被调用，生成不区分大小写的匹配指令。
- 对于 `regex4` 和 `regex5` 这样包含多个范围的字符类，`EmitUseLookupTable` 可能会被使用，生成使用查找表进行匹配的指令。

**代码逻辑推理 (假设输入与输出):**

**示例函数：`ShortCutEmitCharacterPair`**

**假设输入:**

- `macro_assembler`: 一个 `RegExpMacroAssembler` 实例，用于生成机器码。
- `one_byte`: `true` (假设目标字符串是单字节编码)。
- `c1`: 97 (字符 'a' 的 ASCII 码)。
- `c2`: 98 (字符 'b' 的 ASCII 码)。
- `on_failure`: 一个标签，如果匹配失败则跳转到该标签。

**预期输出:**

由于 'a' 和 'b' 仅有一位不同 (二进制分别为 `01100001` 和 `01100010`)，`ShortCutEmitCharacterPair` 会生成一条优化后的机器码指令，类似于 "检查当前字符与 `97` 进行按位异或后，结果是否为 `1`"。如果不是，则跳转到 `on_failure` 标签。

**用户常见的编程错误举例:**

1. **在不区分大小写匹配时混淆大小写字符:** 例如，使用 `/[A-Z]/i`，用户可能期望只匹配大写字母，但由于 `i` 标志，它也会匹配小写字母。这段代码中的 `EmitAtomLetter` 就是为了处理这种情况。

2. **在字符类中使用过大的范围:** 例如，使用包含大量不连续字符的字符类，可能会导致编译器生成效率较低的匹配代码。`EmitUseLookupTable` 的目标就是优化这种情况。

3. **不理解 Unicode 字符类的匹配行为:** 例如，期望 `/\w/` 匹配所有语言的单词字符，但实际上它的行为可能受到 locale 或引擎实现的影响。这段代码中的 Unicode 处理部分就是为了正确处理这些情况。

**总结这段代码的功能:**

这段代码是 V8 正则表达式编译器中负责将正则表达式中的原子和字符类编译成高效机器码的关键部分。它包含了多种优化策略，例如针对特定字符对的快捷匹配、使用查找表进行字符类匹配，以及针对 Unicode 字符类的特殊处理。其目标是提高 JavaScript 中正则表达式的执行速度。

### 提示词
```
这是目录为v8/src/regexp/regexp-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
on_failure, check);
    bound_checked = true;
  }
  assembler->CheckNotCharacter(c, on_failure);
  return bound_checked;
}

// Only emits non-letters (things that don't have case).  Only used for case
// independent matches.
inline bool EmitAtomNonLetter(Isolate* isolate, RegExpCompiler* compiler,
                              base::uc16 c, Label* on_failure, int cp_offset,
                              bool check, bool preloaded) {
  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  bool one_byte = compiler->one_byte();
  unibrow::uchar chars[4];
  int length = GetCaseIndependentLetters(isolate, c, compiler, chars, 4);
  if (length < 1) {
    // This can't match.  Must be an one-byte subject and a non-one-byte
    // character.  We do not need to do anything since the one-byte pass
    // already handled this.
    CHECK(one_byte);
    return false;  // Bounds not checked.
  }
  bool checked = false;
  // We handle the length > 1 case in a later pass.
  if (length == 1) {
    // GetCaseIndependentLetters promises not to return characters that can't
    // match because of the subject encoding.  This case is already handled by
    // the one-byte pass.
    CHECK_IMPLIES(one_byte, chars[0] <= String::kMaxOneByteCharCodeU);
    if (!preloaded) {
      macro_assembler->LoadCurrentCharacter(cp_offset, on_failure, check);
      checked = check;
    }
    macro_assembler->CheckNotCharacter(chars[0], on_failure);
  }
  return checked;
}

bool ShortCutEmitCharacterPair(RegExpMacroAssembler* macro_assembler,
                               bool one_byte, base::uc16 c1, base::uc16 c2,
                               Label* on_failure) {
  const uint32_t char_mask = CharMask(one_byte);
  base::uc16 exor = c1 ^ c2;
  // Check whether exor has only one bit set.
  if (((exor - 1) & exor) == 0) {
    // If c1 and c2 differ only by one bit.
    // Ecma262UnCanonicalize always gives the highest number last.
    DCHECK(c2 > c1);
    base::uc16 mask = char_mask ^ exor;
    macro_assembler->CheckNotCharacterAfterAnd(c1, mask, on_failure);
    return true;
  }
  DCHECK(c2 > c1);
  base::uc16 diff = c2 - c1;
  if (((diff - 1) & diff) == 0 && c1 >= diff) {
    // If the characters differ by 2^n but don't differ by one bit then
    // subtract the difference from the found character, then do the or
    // trick.  We avoid the theoretical case where negative numbers are
    // involved in order to simplify code generation.
    base::uc16 mask = char_mask ^ diff;
    macro_assembler->CheckNotCharacterAfterMinusAnd(c1 - diff, diff, mask,
                                                    on_failure);
    return true;
  }
  return false;
}

// Only emits letters (things that have case).  Only used for case independent
// matches.
inline bool EmitAtomLetter(Isolate* isolate, RegExpCompiler* compiler,
                           base::uc16 c, Label* on_failure, int cp_offset,
                           bool check, bool preloaded) {
  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  bool one_byte = compiler->one_byte();
  unibrow::uchar chars[4];
  int length = GetCaseIndependentLetters(isolate, c, compiler, chars, 4);
  // The 0 and 1 case are handled by earlier passes.
  if (length <= 1) return false;
  // We may not need to check against the end of the input string
  // if this character lies before a character that matched.
  if (!preloaded) {
    macro_assembler->LoadCurrentCharacter(cp_offset, on_failure, check);
  }
  Label ok;
  switch (length) {
    case 2: {
      if (ShortCutEmitCharacterPair(macro_assembler, one_byte, chars[0],
                                    chars[1], on_failure)) {
      } else {
        macro_assembler->CheckCharacter(chars[0], &ok);
        macro_assembler->CheckNotCharacter(chars[1], on_failure);
        macro_assembler->Bind(&ok);
      }
      break;
    }
    case 4:
      macro_assembler->CheckCharacter(chars[3], &ok);
      [[fallthrough]];
    case 3:
      macro_assembler->CheckCharacter(chars[0], &ok);
      macro_assembler->CheckCharacter(chars[1], &ok);
      macro_assembler->CheckNotCharacter(chars[2], on_failure);
      macro_assembler->Bind(&ok);
      break;
    default:
      UNREACHABLE();
  }
  return true;
}

void EmitBoundaryTest(RegExpMacroAssembler* masm, int border,
                      Label* fall_through, Label* above_or_equal,
                      Label* below) {
  if (below != fall_through) {
    masm->CheckCharacterLT(border, below);
    if (above_or_equal != fall_through) masm->GoTo(above_or_equal);
  } else {
    masm->CheckCharacterGT(border - 1, above_or_equal);
  }
}

void EmitDoubleBoundaryTest(RegExpMacroAssembler* masm, int first, int last,
                            Label* fall_through, Label* in_range,
                            Label* out_of_range) {
  if (in_range == fall_through) {
    if (first == last) {
      masm->CheckNotCharacter(first, out_of_range);
    } else {
      masm->CheckCharacterNotInRange(first, last, out_of_range);
    }
  } else {
    if (first == last) {
      masm->CheckCharacter(first, in_range);
    } else {
      masm->CheckCharacterInRange(first, last, in_range);
    }
    if (out_of_range != fall_through) masm->GoTo(out_of_range);
  }
}

// even_label is for ranges[i] to ranges[i + 1] where i - start_index is even.
// odd_label is for ranges[i] to ranges[i + 1] where i - start_index is odd.
void EmitUseLookupTable(RegExpMacroAssembler* masm,
                        ZoneList<base::uc32>* ranges, uint32_t start_index,
                        uint32_t end_index, base::uc32 min_char,
                        Label* fall_through, Label* even_label,
                        Label* odd_label) {
  static const uint32_t kSize = RegExpMacroAssembler::kTableSize;
  static const uint32_t kMask = RegExpMacroAssembler::kTableMask;

  base::uc32 base = (min_char & ~kMask);
  USE(base);

  // Assert that everything is on one kTableSize page.
  for (uint32_t i = start_index; i <= end_index; i++) {
    DCHECK_EQ(ranges->at(i) & ~kMask, base);
  }
  DCHECK(start_index == 0 || (ranges->at(start_index - 1) & ~kMask) <= base);

  char templ[kSize];
  Label* on_bit_set;
  Label* on_bit_clear;
  int bit;
  if (even_label == fall_through) {
    on_bit_set = odd_label;
    on_bit_clear = even_label;
    bit = 1;
  } else {
    on_bit_set = even_label;
    on_bit_clear = odd_label;
    bit = 0;
  }
  for (uint32_t i = 0; i < (ranges->at(start_index) & kMask) && i < kSize;
       i++) {
    templ[i] = bit;
  }
  uint32_t j = 0;
  bit ^= 1;
  for (uint32_t i = start_index; i < end_index; i++) {
    for (j = (ranges->at(i) & kMask); j < (ranges->at(i + 1) & kMask); j++) {
      templ[j] = bit;
    }
    bit ^= 1;
  }
  for (uint32_t i = j; i < kSize; i++) {
    templ[i] = bit;
  }
  Factory* factory = masm->isolate()->factory();
  // TODO(erikcorry): Cache these.
  Handle<ByteArray> ba = factory->NewByteArray(kSize, AllocationType::kOld);
  for (uint32_t i = 0; i < kSize; i++) {
    ba->set(i, templ[i]);
  }
  masm->CheckBitInTable(ba, on_bit_set);
  if (on_bit_clear != fall_through) masm->GoTo(on_bit_clear);
}

void CutOutRange(RegExpMacroAssembler* masm, ZoneList<base::uc32>* ranges,
                 uint32_t start_index, uint32_t end_index, uint32_t cut_index,
                 Label* even_label, Label* odd_label) {
  bool odd = (((cut_index - start_index) & 1) == 1);
  Label* in_range_label = odd ? odd_label : even_label;
  Label dummy;
  EmitDoubleBoundaryTest(masm, ranges->at(cut_index),
                         ranges->at(cut_index + 1) - 1, &dummy, in_range_label,
                         &dummy);
  DCHECK(!dummy.is_linked());
  // Cut out the single range by rewriting the array.  This creates a new
  // range that is a merger of the two ranges on either side of the one we
  // are cutting out.  The oddity of the labels is preserved.
  for (uint32_t j = cut_index; j > start_index; j--) {
    ranges->at(j) = ranges->at(j - 1);
  }
  for (uint32_t j = cut_index + 1; j < end_index; j++) {
    ranges->at(j) = ranges->at(j + 1);
  }
}

// Unicode case.  Split the search space into kSize spaces that are handled
// with recursion.
void SplitSearchSpace(ZoneList<base::uc32>* ranges, uint32_t start_index,
                      uint32_t end_index, uint32_t* new_start_index,
                      uint32_t* new_end_index, base::uc32* border) {
  static const uint32_t kSize = RegExpMacroAssembler::kTableSize;
  static const uint32_t kMask = RegExpMacroAssembler::kTableMask;

  base::uc32 first = ranges->at(start_index);
  base::uc32 last = ranges->at(end_index) - 1;

  *new_start_index = start_index;
  *border = (ranges->at(start_index) & ~kMask) + kSize;
  while (*new_start_index < end_index) {
    if (ranges->at(*new_start_index) > *border) break;
    (*new_start_index)++;
  }
  // new_start_index is the index of the first edge that is beyond the
  // current kSize space.

  // For very large search spaces we do a binary chop search of the non-Latin1
  // space instead of just going to the end of the current kSize space.  The
  // heuristics are complicated a little by the fact that any 128-character
  // encoding space can be quickly tested with a table lookup, so we don't
  // wish to do binary chop search at a smaller granularity than that.  A
  // 128-character space can take up a lot of space in the ranges array if,
  // for example, we only want to match every second character (eg. the lower
  // case characters on some Unicode pages).
  uint32_t binary_chop_index = (end_index + start_index) / 2;
  // The first test ensures that we get to the code that handles the Latin1
  // range with a single not-taken branch, speeding up this important
  // character range (even non-Latin1 charset-based text has spaces and
  // punctuation).
  if (*border - 1 > String::kMaxOneByteCharCode &&  // Latin1 case.
      end_index - start_index > (*new_start_index - start_index) * 2 &&
      last - first > kSize * 2 && binary_chop_index > *new_start_index &&
      ranges->at(binary_chop_index) >= first + 2 * kSize) {
    uint32_t scan_forward_for_section_border = binary_chop_index;
    uint32_t new_border = (ranges->at(binary_chop_index) | kMask) + 1;

    while (scan_forward_for_section_border < end_index) {
      if (ranges->at(scan_forward_for_section_border) > new_border) {
        *new_start_index = scan_forward_for_section_border;
        *border = new_border;
        break;
      }
      scan_forward_for_section_border++;
    }
  }

  DCHECK(*new_start_index > start_index);
  *new_end_index = *new_start_index - 1;
  if (ranges->at(*new_end_index) == *border) {
    (*new_end_index)--;
  }
  if (*border >= ranges->at(end_index)) {
    *border = ranges->at(end_index);
    *new_start_index = end_index;  // Won't be used.
    *new_end_index = end_index - 1;
  }
}

// Gets a series of segment boundaries representing a character class.  If the
// character is in the range between an even and an odd boundary (counting from
// start_index) then go to even_label, otherwise go to odd_label.  We already
// know that the character is in the range of min_char to max_char inclusive.
// Either label can be nullptr indicating backtracking.  Either label can also
// be equal to the fall_through label.
void GenerateBranches(RegExpMacroAssembler* masm, ZoneList<base::uc32>* ranges,
                      uint32_t start_index, uint32_t end_index,
                      base::uc32 min_char, base::uc32 max_char,
                      Label* fall_through, Label* even_label,
                      Label* odd_label) {
  DCHECK_LE(min_char, String::kMaxUtf16CodeUnit);
  DCHECK_LE(max_char, String::kMaxUtf16CodeUnit);

  base::uc32 first = ranges->at(start_index);
  base::uc32 last = ranges->at(end_index) - 1;

  DCHECK_LT(min_char, first);

  // Just need to test if the character is before or on-or-after
  // a particular character.
  if (start_index == end_index) {
    EmitBoundaryTest(masm, first, fall_through, even_label, odd_label);
    return;
  }

  // Another almost trivial case:  There is one interval in the middle that is
  // different from the end intervals.
  if (start_index + 1 == end_index) {
    EmitDoubleBoundaryTest(masm, first, last, fall_through, even_label,
                           odd_label);
    return;
  }

  // It's not worth using table lookup if there are very few intervals in the
  // character class.
  if (end_index - start_index <= 6) {
    // It is faster to test for individual characters, so we look for those
    // first, then try arbitrary ranges in the second round.
    static uint32_t kNoCutIndex = -1;
    uint32_t cut = kNoCutIndex;
    for (uint32_t i = start_index; i < end_index; i++) {
      if (ranges->at(i) == ranges->at(i + 1) - 1) {
        cut = i;
        break;
      }
    }
    if (cut == kNoCutIndex) cut = start_index;
    CutOutRange(masm, ranges, start_index, end_index, cut, even_label,
                odd_label);
    DCHECK_GE(end_index - start_index, 2);
    GenerateBranches(masm, ranges, start_index + 1, end_index - 1, min_char,
                     max_char, fall_through, even_label, odd_label);
    return;
  }

  // If there are a lot of intervals in the regexp, then we will use tables to
  // determine whether the character is inside or outside the character class.
  static const int kBits = RegExpMacroAssembler::kTableSizeBits;

  if ((max_char >> kBits) == (min_char >> kBits)) {
    EmitUseLookupTable(masm, ranges, start_index, end_index, min_char,
                       fall_through, even_label, odd_label);
    return;
  }

  if ((min_char >> kBits) != first >> kBits) {
    masm->CheckCharacterLT(first, odd_label);
    GenerateBranches(masm, ranges, start_index + 1, end_index, first, max_char,
                     fall_through, odd_label, even_label);
    return;
  }

  uint32_t new_start_index = 0;
  uint32_t new_end_index = 0;
  base::uc32 border = 0;

  SplitSearchSpace(ranges, start_index, end_index, &new_start_index,
                   &new_end_index, &border);

  Label handle_rest;
  Label* above = &handle_rest;
  if (border == last + 1) {
    // We didn't find any section that started after the limit, so everything
    // above the border is one of the terminal labels.
    above = (end_index & 1) != (start_index & 1) ? odd_label : even_label;
    DCHECK(new_end_index == end_index - 1);
  }

  DCHECK_LE(start_index, new_end_index);
  DCHECK_LE(new_start_index, end_index);
  DCHECK_LT(start_index, new_start_index);
  DCHECK_LT(new_end_index, end_index);
  DCHECK(new_end_index + 1 == new_start_index ||
         (new_end_index + 2 == new_start_index &&
          border == ranges->at(new_end_index + 1)));
  DCHECK_LT(min_char, border - 1);
  DCHECK_LT(border, max_char);
  DCHECK_LT(ranges->at(new_end_index), border);
  DCHECK(border < ranges->at(new_start_index) ||
         (border == ranges->at(new_start_index) &&
          new_start_index == end_index && new_end_index == end_index - 1 &&
          border == last + 1));
  DCHECK(new_start_index == 0 || border >= ranges->at(new_start_index - 1));

  masm->CheckCharacterGT(border - 1, above);
  Label dummy;
  GenerateBranches(masm, ranges, start_index, new_end_index, min_char,
                   border - 1, &dummy, even_label, odd_label);
  if (handle_rest.is_linked()) {
    masm->Bind(&handle_rest);
    bool flip = (new_start_index & 1) != (start_index & 1);
    GenerateBranches(masm, ranges, new_start_index, end_index, border, max_char,
                     &dummy, flip ? odd_label : even_label,
                     flip ? even_label : odd_label);
  }
}

void EmitClassRanges(RegExpMacroAssembler* macro_assembler,
                     RegExpClassRanges* cr, bool one_byte, Label* on_failure,
                     int cp_offset, bool check_offset, bool preloaded,
                     Zone* zone) {
  ZoneList<CharacterRange>* ranges = cr->ranges(zone);
  CharacterRange::Canonicalize(ranges);

  // Now that all processing (like case-insensitivity) is done, clamp the
  // ranges to the set of ranges that may actually occur in the subject string.
  if (one_byte) CharacterRange::ClampToOneByte(ranges);

  const int ranges_length = ranges->length();
  if (ranges_length == 0) {
    if (!cr->is_negated()) {
      macro_assembler->GoTo(on_failure);
    }
    if (check_offset) {
      macro_assembler->CheckPosition(cp_offset, on_failure);
    }
    return;
  }

  const base::uc32 max_char = MaxCodeUnit(one_byte);
  if (ranges_length == 1 && ranges->at(0).IsEverything(max_char)) {
    if (cr->is_negated()) {
      macro_assembler->GoTo(on_failure);
    } else {
      // This is a common case hit by non-anchored expressions.
      if (check_offset) {
        macro_assembler->CheckPosition(cp_offset, on_failure);
      }
    }
    return;
  }

  if (!preloaded) {
    macro_assembler->LoadCurrentCharacter(cp_offset, on_failure, check_offset);
  }

  if (cr->is_standard(zone) && macro_assembler->CheckSpecialClassRanges(
                                   cr->standard_type(), on_failure)) {
    return;
  }

  static constexpr int kMaxRangesForInlineBranchGeneration = 16;
  if (ranges_length > kMaxRangesForInlineBranchGeneration) {
    // For large range sets, emit a more compact instruction sequence to avoid
    // a potentially problematic increase in code size.
    // Note the flipped logic below (we check InRange if negated, NotInRange if
    // not negated); this is necessary since the method falls through on
    // failure whereas we want to fall through on success.
    if (cr->is_negated()) {
      if (macro_assembler->CheckCharacterInRangeArray(ranges, on_failure)) {
        return;
      }
    } else {
      if (macro_assembler->CheckCharacterNotInRangeArray(ranges, on_failure)) {
        return;
      }
    }
  }

  // Generate a flat list of range boundaries for consumption by
  // GenerateBranches. See the comment on that function for how the list should
  // be structured
  ZoneList<base::uc32>* range_boundaries =
      zone->New<ZoneList<base::uc32>>(ranges_length * 2, zone);

  bool zeroth_entry_is_failure = !cr->is_negated();

  for (int i = 0; i < ranges_length; i++) {
    CharacterRange& range = ranges->at(i);
    if (range.from() == 0) {
      DCHECK_EQ(i, 0);
      zeroth_entry_is_failure = !zeroth_entry_is_failure;
    } else {
      range_boundaries->Add(range.from(), zone);
    }
    // `+ 1` to convert from inclusive to exclusive `to`.
    // [from, to] == [from, to+1[.
    range_boundaries->Add(range.to() + 1, zone);
  }
  int end_index = range_boundaries->length() - 1;
  if (range_boundaries->at(end_index) > max_char) {
    end_index--;
  }

  Label fall_through;
  GenerateBranches(macro_assembler, range_boundaries,
                   0,  // start_index.
                   end_index,
                   0,  // min_char.
                   max_char, &fall_through,
                   zeroth_entry_is_failure ? &fall_through : on_failure,
                   zeroth_entry_is_failure ? on_failure : &fall_through);
  macro_assembler->Bind(&fall_through);
}

}  // namespace

RegExpNode::~RegExpNode() = default;

RegExpNode::LimitResult RegExpNode::LimitVersions(RegExpCompiler* compiler,
                                                  Trace* trace) {
  // If we are generating a greedy loop then don't stop and don't reuse code.
  if (trace->stop_node() != nullptr) {
    return CONTINUE;
  }

  RegExpMacroAssembler* macro_assembler = compiler->macro_assembler();
  if (trace->is_trivial()) {
    if (label_.is_bound() || on_work_list() || !KeepRecursing(compiler)) {
      // If a generic version is already scheduled to be generated or we have
      // recursed too deeply then just generate a jump to that code.
      macro_assembler->GoTo(&label_);
      // This will queue it up for generation of a generic version if it hasn't
      // already been queued.
      compiler->AddWork(this);
      return DONE;
    }
    // Generate generic version of the node and bind the label for later use.
    macro_assembler->Bind(&label_);
    return CONTINUE;
  }

  // We are being asked to make a non-generic version.  Keep track of how many
  // non-generic versions we generate so as not to overdo it.
  trace_count_++;
  if (KeepRecursing(compiler) && compiler->optimize() &&
      trace_count_ < kMaxCopiesCodeGenerated) {
    return CONTINUE;
  }

  // If we get here code has been generated for this node too many times or
  // recursion is too deep.  Time to switch to a generic version.  The code for
  // generic versions above can handle deep recursion properly.
  bool was_limiting = compiler->limiting_recursion();
  compiler->set_limiting_recursion(true);
  trace->Flush(compiler, this);
  compiler->set_limiting_recursion(was_limiting);
  return DONE;
}

bool RegExpNode::KeepRecursing(RegExpCompiler* compiler) {
  return !compiler->limiting_recursion() &&
         compiler->recursion_depth() <= RegExpCompiler::kMaxRecursion;
}

void ActionNode::FillInBMInfo(Isolate* isolate, int offset, int budget,
                              BoyerMooreLookahead* bm, bool not_at_start) {
  std::optional<RegExpFlags> old_flags;
  if (action_type_ == MODIFY_FLAGS) {
    // It is not guaranteed that we hit the resetting modify flags node, due to
    // recursion budget limitation for filling in BMInfo. Therefore we reset the
    // flags manually to the previous state after recursing.
    old_flags = bm->compiler()->flags();
    bm->compiler()->set_flags(flags());
  }
  if (action_type_ == BEGIN_POSITIVE_SUBMATCH) {
    // We use the node after the lookaround to fill in the eats_at_least info
    // so we have to use the same node to fill in the Boyer-Moore info.
    success_node()->on_success()->FillInBMInfo(isolate, offset, budget - 1, bm,
                                               not_at_start);
  } else if (action_type_ != POSITIVE_SUBMATCH_SUCCESS) {
    // We don't use the node after a positive submatch success because it
    // rewinds the position.  Since we returned 0 as the eats_at_least value for
    // this node, we don't need to fill in any data.
    on_success()->FillInBMInfo(isolate, offset, budget - 1, bm, not_at_start);
  }
  SaveBMInfo(bm, not_at_start, offset);
  if (old_flags.has_value()) {
    bm->compiler()->set_flags(*old_flags);
  }
}

void ActionNode::GetQuickCheckDetails(QuickCheckDetails* details,
                                      RegExpCompiler* compiler, int filled_in,
                                      bool not_at_start) {
  if (action_type_ == SET_REGISTER_FOR_LOOP) {
    on_success()->GetQuickCheckDetailsFromLoopEntry(details, compiler,
                                                    filled_in, not_at_start);
  } else if (action_type_ == BEGIN_POSITIVE_SUBMATCH) {
    // We use the node after the lookaround to fill in the eats_at_least info
    // so we have to use the same node to fill in the QuickCheck info.
    success_node()->on_success()->GetQuickCheckDetails(details, compiler,
                                                       filled_in, not_at_start);
  } else if (action_type() != POSITIVE_SUBMATCH_SUCCESS) {
    // We don't use the node after a positive submatch success because it
    // rewinds the position.  Since we returned 0 as the eats_at_least value
    // for this node, we don't need to fill in any data.
    if (action_type() == MODIFY_FLAGS) {
      compiler->set_flags(flags());
    }
    on_success()->GetQuickCheckDetails(details, compiler, filled_in,
                                       not_at_start);
  }
}

void AssertionNode::FillInBMInfo(Isolate* isolate, int offset, int budget,
                                 BoyerMooreLookahead* bm, bool not_at_start) {
  // Match the behaviour of EatsAtLeast on this node.
  if (assertion_type() == AT_START && not_at_start) return;
  on_success()->FillInBMInfo(isolate, offset, budget - 1, bm, not_at_start);
  SaveBMInfo(bm, not_at_start, offset);
}

void NegativeLookaroundChoiceNode::GetQuickCheckDetails(
    QuickCheckDetails* details, RegExpCompiler* compiler, int filled_in,
    bool not_at_start) {
  RegExpNode* node = continue_node();
  return node->GetQuickCheckDetails(details, compiler, filled_in, not_at_start);
}

namespace {

// Takes the left-most 1-bit and smears it out, setting all bits to its right.
inline uint32_t SmearBitsRight(uint32_t v) {
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  return v;
}

}  // namespace

bool QuickCheckDetails::Rationalize(bool asc) {
  bool found_useful_op = false;
  const uint32_t char_mask = CharMask(asc);
  mask_ = 0;
  value_ = 0;
  int char_shift = 0;
  for (int i = 0; i < characters_; i++) {
    Position* pos = &positions_[i];
    if ((pos->mask & String::kMaxOneByteCharCode) != 0) {
      found_useful_op = true;
    }
    mask_ |= (pos->mask & char_mask) << char_shift;
    value_ |= (pos->value & char_mask) << char_shift;
    char_shift += asc ? 8 : 16;
  }
  return found_useful_op;
}

uint32_t RegExpNode::EatsAtLeast(bool not_at_start) {
  return not_at_start ? eats_at_least_.eats_at_least_from_not_start
                      : eats_at_least_.eats_at_least_from_possibly_start;
}

EatsAtLeastInfo RegExpNode::EatsAtLeastFromLoopEntry() {
  // SET_REGISTER_FOR_LOOP is only used to initialize loop counters, and it
  // implies that the following node must be a LoopChoiceNode. If we need to
  // set registers to constant values for other reasons, we could introduce a
  // new action type SET_REGISTER that doesn't imply anything about its
  // successor.
  UNREACHABLE();
}

void RegExpNode::GetQuickCheckDetailsFromLoopEntry(QuickCheckDetails* details,
                                                   RegExpCompiler* compiler,
                                                   int characters_filled_in,
                                                   bool not_at_start) {
  // See comment in RegExpNode::EatsAtLeastFromLoopEntry.
  UNREACHABLE();
}

EatsAtLeastInfo LoopChoiceNode::EatsAtLeastFromLoopEntry() {
  DCHECK_EQ(alternatives_->length(), 2);  // There's just loop and continue.

  if (read_backward()) {
    // The eats_at_least value is not used if reading backward. The
    // EatsAtLeastPropagator should've zeroed it as well.
    DCHECK_EQ(eats_at_least_info()->eats_at_least_from_possibly_start, 0);
    DCHECK_EQ(eats_at_least_info()->eats_at_least_from_not_start, 0);
    return {};
  }

  // Figure out how much the loop body itself eats, not including anything in
  // the continuation case. In general, the nodes in the loop body should report
  // that they eat at least the number eaten by the continuation node, since any
  // successful match in the loop body must also include the continuation node.
  // However, in some cases involving positive lookaround, the loop body under-
  // reports its appetite, so use saturated math here to avoid negative numbers.
  // For this to work correctly, we explicitly need to use signed integers here.
  uint8_t loop_body_from_not_start = base::saturated_cast<uint8_t>(
      static_cast<int>(loop_node_->EatsAtLeast(true)) -
      static_cast<int>(continue_node_->EatsAtLeast(true)));
  uint8_t loop_body_from_possibly_start = base::saturated_cast<uint8_t>(
      static_cast<int>(loop_node_->EatsAtLeast(false)) -
      static_cast<int>(continue_node_->EatsAtLeast(true)));

  // Limit the number of loop iterations to avoid overflow in subsequent steps.
  int loop_iterations = base::saturated_cast<uint8_t>(min_loop_iterations());

  EatsAtLeastInfo result;
  result.eats_at_least_from_not_start =
      base::saturated_cast<uint8_t>(loop_iterations * loop_body_from_not_start +
                                    continue_node_->EatsAtLeast(true));
  if (loop_iterations > 0 && loop_body_from_possibly_start > 0) {
    // First loop iteration eats at least one, so all subsequent iterations
    // and the after-loop chunk are guaranteed to not be at the start.
    result.eats_at_least_from_possibly_start = base::saturated_cast<uint8_t>(
        loop_body_from_possibly_start +
        (loop_iterations - 1) * loop_body_from_not_start +
        continue_node_->EatsAtLeast(true));
  } else {
    // Loop body might eat nothing, so only continue node contributes.
    result.eats_at_least_from_possibly_start =
        continue_node_->EatsAtLeast(false);
  }
  return result;
}

bool RegExpNode::EmitQuickCheck(RegExpCompiler* compiler,
                                Trace* bounds_check_trace, Trace* trace,
                                bool preload_has_checked_bounds,
                                Label* on_possible_success,
                                QuickCheckDetails* details,
                                bool fall_through_on_failure,
                                ChoiceNode* predecessor) {
  DCHECK_NOT_NULL(predecessor);
  if (details->characters() == 0) return false;
  GetQuickCheckDetails(details, compiler, 0,
                       trace->at_start() == Trace::FALSE_VALUE);
  if (details->cannot_match()) return false;
  if (!details->Rationalize(compiler->one_byte())) return false;
  DCHECK(details->characters() == 1 ||
         compiler->macro_assembler()->CanReadUnaligned());
  uint32_t mask = details->mask();
  uint32_t value = details->value();

  RegExpMacroAssembler* assembler = compiler->macro_assembler();

  if (trace->characters_preloaded() != details->characters()) {
    DCHECK(trace->cp_offset() == bounds_check_trace->cp_offset());
    // The bounds check is performed using the minimum number of characters
    // any choice would eat, so if the bounds check fails, then none of the
    // choices can succeed, so we can just immediately backtrack, rather
    // than go to the next choice. The number of characters preloaded may be
    // less than the number used for the bounds check.
    int eats_at_least = predecessor->EatsAtLeast(
        bounds_check_trace->at_start() == Trace::FALSE_VALUE);
    DCHECK_GE(eats_at_least, details->characters());
    assembler->LoadCurrentCharacter(
        trace->cp_offset(), bounds_check_trace->backtrack(),
        !preload_has_checked_bounds, details->characters(), eats_at_least);
  }

  bool need_mask = true;

  if (details->characters() == 1) {
    // If number of characters preloaded is 1 then we used a byte or 16 bit
    // load so the value is already masked down.
    const uint32_t char_mask = CharMask(compiler->one_byte());
    if ((mask & char_mask) == char_mask) need_mask = false;
    mask &= char_mask;
  } else {
    // For 2-character preloads in one-byte mode or 1-character preloads in
    // two-byte mode we also use a 16 bit load with zero extend.
    static const uint32_t kTwoByteMask = 0xFFFF;
    static const uint32_t kFourByteMask = 0xFFFFFFFF;
    if (details->characters() == 2 && compiler->one_byte()) {
      if ((mask & kTwoByteMask) == kTwoByteMask) need_mask = false;
    } else if (details->characters() == 1 && !compiler->one_byte()) {
      if ((mask & kTwoByteMask) == kTwoByteMask) need_mask = false;
    } else {
      if (mask == kFourByteMask) need_mask = false;
    }
  }

  if (fall_through_on_failure) {
    if (need_mask) {
      assembler->CheckCharacterAfterAnd(value, mask, on_possible_success);
    } else {
      assembler->CheckCharacter(value, on_possible_success);
    }
  } else {
    if (need_mask) {
      assembler->CheckNotCharacterAfterAnd(value, mask, trace->backtrack());
    } else {
      assembler->CheckNotCharacter(value, trace->backtrack());
    }
  }
  return true;
}

// Here is the meat of GetQuickCheckDetails (see also the comment on the
// super-class in the .h file).
//
// We iterate along the text object, building up for each character a
// mask and value that can be used to test for a quick failure to match.
// The masks and values for the positions will be combined into a single
// machine word for the current character width in order to be used in
// generating a quick check.
void TextNode::GetQuickCheckDetails(QuickCheckDetails* details,
                                    RegExpCompiler* compiler,
                                    int characters_filled_in,
                                    bool not_at_start) {
  // Do not collect any quick check details if the text node reads backward,
  // since it reads in the opposite direction than we use for quick checks.
  if (read_backward()) return;
  Isolate* isolate = compiler->macro_assembler()->isolate();
  DCHECK(characters_filled_in < details->characters());
  int characters = details->characters();
  const uint32_t char_mask = CharMask(compiler->one_byte());
  for (int k = 0; k < elements()->length(); k++) {
    TextElement elm = elements()->at(k);
    if (elm.text_type() == TextElement::ATOM) {
      base::Vector<const base::uc16>
```