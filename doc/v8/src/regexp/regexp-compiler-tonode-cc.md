Response:
My thinking process to arrive at the summary of `regexp-compiler-tonode.cc` goes like this:

1. **Understand the Request:** The request asks for a summary of the C++ source code file `v8/src/regexp/regexp-compiler-tonode.cc`. It provides some basic context about V8, regular expressions, and Torque (which isn't relevant here as the file doesn't end in `.tq`). The prompt also asks for examples if the code relates to JavaScript functionality and mentions common programming errors.

2. **Initial Scan for Keywords and Structures:** I would first scan the code for prominent keywords and structures to get a high-level overview. I'd look for:
    * `#include` directives: These indicate dependencies and the areas the code interacts with (e.g., `string.h`, `regexp-compiler.h`, `regexp.h`, `unicode-inl.h`). The presence of `V8_INTL_SUPPORT` is also notable.
    * Class names:  `RegExpNode`, `RegExpAtom`, `RegExpText`, `RegExpClassRanges`, `UnicodeRangeSplitter`, `RegExpClassSetOperand`, `RegExpClassSetExpression`, `RegExpDisjunction`. These are the main building blocks of the code.
    * Method names like `ToNode`, `AddRange`, `AddUnicodeCaseEquivalents`, `Union`, `Intersect`, `Subtract`, `ComputeExpression`, `SortConsecutiveAtoms`, `RationalizeConsecutiveAtoms`. These suggest the actions and transformations being performed.
    * Namespaces: `v8::internal`.
    * Constants: `kMaxCodePoint`, `kMaxUtf16CodeUnit`, surrogate-related constants.
    * Comments:  These often provide valuable insights into the purpose of specific sections.

3. **Identify the Core Functionality - `ToNode`:** The presence of multiple `ToNode` methods across different `RegExp` classes strongly suggests that the primary function of this file is to convert a higher-level representation of a regular expression (likely the abstract syntax tree) into a lower-level representation suitable for execution. This "lower-level representation" seems to involve `RegExpNode` and its subclasses.

4. **Focus on Key Classes and Their Interactions:**  I would then delve deeper into the purpose of the key classes:
    * `RegExpAtom` and `RegExpText`: Represent literal strings in the regex. Their `ToNode` methods create `TextNode` instances.
    * `RegExpClassRanges`: Represents character classes (e.g., `[a-z]`, `\d`). The `ToNode` method is more complex, involving handling case-insensitivity, Unicode, and surrogate pairs. The `is_standard` method suggests optimization for common character classes.
    * `UnicodeRangeSplitter`: This class clearly deals with the complexities of Unicode, specifically splitting ranges into BMP characters, non-BMP surrogate pairs, and lone surrogates. This is crucial for correct handling of Unicode in regular expressions.
    * `RegExpClassSetOperand` and `RegExpClassSetExpression`: These classes handle the more advanced features of Unicode property escapes and set operations (union, intersection, subtraction) within character classes. `ComputeExpression` is the key method here.
    * `RegExpDisjunction`: Represents the `|` operator (OR). The methods `SortConsecutiveAtoms` and `RationalizeConsecutiveAtoms` indicate optimizations for sequences of literal atoms within an OR group.

5. **Trace the Data Flow (Mentally):** I'd mentally trace how these classes interact, especially within the `ToNode` methods. For example, `RegExpClassRanges::ToNode` uses `UnicodeRangeSplitter` to handle Unicode intricacies. `RegExpClassSetExpression::ToNode` calls `ComputeExpression`, which recursively processes the operands.

6. **Infer the Overall Goal:** Based on the class names and methods, the overall goal of this file is to take a parsed representation of a regular expression and transform it into a graph-like structure of `RegExpNode` objects. This transformation involves:
    * Handling literal text.
    * Expanding character classes, including handling Unicode and case-insensitivity.
    * Optimizing common patterns (like consecutive atoms in a disjunction).
    * Correctly dealing with the intricacies of Unicode surrogate pairs and lone surrogates.

7. **Address Specific Points from the Prompt:**
    * **`.tq` extension:** The code clearly isn't Torque.
    * **Relationship to JavaScript:** Regular expressions are a fundamental part of JavaScript. The code directly contributes to how JavaScript regular expressions are compiled and executed within V8. I would think of simple JavaScript regex examples that would trigger the logic in this file (e.g., `/[a-z]/`, `/[^a-z]/u`, `/ab|ac/`).
    * **Code logic inference:** The sections dealing with Unicode range splitting and class set operations offer opportunities for logical inference. I would consider how input character ranges are transformed and combined.
    * **Common programming errors:**  While the C++ code itself is about *implementing* regex, I would consider the common errors users make *when writing* regular expressions that this code needs to handle correctly (e.g., not accounting for case, incorrect handling of Unicode characters).

8. **Structure the Summary:** Finally, I would organize my understanding into a clear and concise summary, highlighting the key functionalities and their relationships. I would use bullet points to make the information easier to read. I would also include a concluding summary that ties everything together.

By following these steps, I can systematically analyze the code and produce a comprehensive summary that addresses the prompt's requirements. The key is to start with a broad overview and gradually drill down into the details, focusing on the main actors (classes) and their actions (methods).
This is the first part of a three-part analysis of the V8 source code file `v8/src/regexp/regexp-compiler-tonode.cc`. Based on the provided code snippet, here's a breakdown of its functionality:

**Core Functionality:**

The primary function of `regexp-compiler-tonode.cc` is to **translate a high-level representation of a regular expression into a lower-level graph-like structure of `RegExpNode` objects.** This process is crucial for the V8 regular expression engine as it prepares the regular expression for efficient execution.

**Key Operations and Concepts:**

* **`ToNode` Methods:** The file contains multiple `ToNode` methods associated with different regular expression tree node types (like `RegExpAtom`, `RegExpText`, `RegExpClassRanges`, `RegExpClassSetOperand`, `RegExpClassSetExpression`, `RegExpDisjunction`). Each `ToNode` method is responsible for converting its specific tree node type into a corresponding `RegExpNode` structure. This suggests a traversal of the regular expression's abstract syntax tree (AST).
* **`RegExpNode` Hierarchy:** The resulting `RegExpNode` objects likely form a directed graph representing the different matching possibilities within the regular expression. Different types of `RegExpNode` likely handle different matching operations (e.g., matching specific characters, character ranges, or sub-expressions).
* **Text Matching (`RegExpAtom`, `RegExpText`, `TextNode`):**  The code handles the conversion of literal text within the regular expression into `TextNode` objects. This involves considering the direction of matching (`compiler->read_backward()`).
* **Character Class Handling (`RegExpClassRanges`, `UnicodeRangeSplitter`):**  A significant portion of the code deals with character classes (e.g., `[a-z]`, `\d`, `[^0-9]`).
    * `RegExpClassRanges` represents a set of character ranges. It includes logic for checking if a range is "standard" (corresponding to predefined character classes like `\s`, `\w`, etc.).
    * `UnicodeRangeSplitter` is crucial for handling Unicode characters correctly, especially surrogate pairs (characters outside the Basic Multilingual Plane). It splits character ranges into BMP characters, lead surrogates, trail surrogates, and non-BMP characters. This ensures accurate matching in Unicode regular expressions.
* **Unicode Case Folding:** The code includes functionality (`CharacterRange::AddUnicodeCaseEquivalents`) to handle case-insensitive matching for Unicode characters, leveraging ICU (International Components for Unicode) if `V8_INTL_SUPPORT` is enabled.
* **Unicode Property Escapes and Set Operations (`RegExpClassSetOperand`, `RegExpClassSetExpression`):** These classes handle more complex character classes involving Unicode property escapes (like `\p{ASCII}`) and set operations (union, intersection, subtraction) within character classes. The `ComputeExpression` method recursively evaluates these set operations.
* **Disjunction Optimization (`RegExpDisjunction`):** The code includes optimization techniques for disjunctions (the `|` operator), such as:
    * `SortConsecutiveAtoms`: Sorting consecutive literal atoms to group similar prefixes together.
    * `RationalizeConsecutiveAtoms`:  Transforming patterns like `ab|ac|az` into `a(?:b|c|z)` for better efficiency.
* **Lookarounds (Implicit):** While not explicitly named as a class here, the code involving `NegativeLookaroundAgainstReadDirectionAndMatch` and `MatchAndNegativeLookaroundInReadDirection` suggests the handling of negative lookahead and lookbehind assertions, especially in the context of matching lone surrogates.
* **Unanchored Advance:** The `UnanchoredAdvance` function seems to implement the logic for advancing the string index during a regular expression search when no specific pattern is matched at the current position.

**If `v8/src/regexp/regexp-compiler-tonode.cc` ended with `.tq`:**

It would be a V8 Torque source code file. Torque is a V8-specific language used for implementing performance-critical parts of the JavaScript standard library and V8 internals. Torque code is statically typed and compiles to C++.

**Relationship to JavaScript Functionality (with JavaScript Examples):**

This code is directly responsible for how JavaScript regular expressions are compiled within the V8 engine. Here are some JavaScript examples that would involve the functionality in this file:

```javascript
// Literal text matching:
const regex1 = /hello/;
const text1 = "hello world";
regex1.test(text1); // This would involve RegExpAtom and TextNode

// Character class matching:
const regex2 = /[a-z]/;
const text2 = "abc";
regex2.test(text2); // This would involve RegExpClassRanges

// Unicode character matching:
const regex3 = /\u{1F600}/u; // Grinning Face Emoji
const text3 = "😀";
regex3.test(text3); // This would involve UnicodeRangeSplitter

// Case-insensitive matching:
const regex4 = /abc/i;
const text4 = "ABC";
regex4.test(text4); // This would involve CharacterRange::AddUnicodeCaseEquivalents

// Unicode property escapes (requires /u flag):
const regex5 = /\p{Uppercase}/u;
const text5 = "A";
regex5.test(text5); // This would involve RegExpClassSetOperand and RegExpClassSetExpression

// Disjunction (OR):
const regex6 = /cat|dog/;
const text6 = "I have a cat";
regex6.test(text6); // This would involve RegExpDisjunction

// Negative lookahead (for lone surrogates, though not directly exposed in simple JS):
//  While users don't directly write lookarounds for lone surrogates, the engine
//  uses them internally to ensure correct Unicode matching.
```

**Code Logic Inference (Hypothetical):**

**Hypothetical Input:**  A `RegExpClassRanges` object representing the character class `[a-zA-C]`.

**Processing:**

1. The `ToNode` method for `RegExpClassRanges` is called.
2. The ranges are canonicalized (sorted and merged): `[a-c]`.
3. If case-insensitive matching is enabled, `CharacterRange::AddUnicodeCaseEquivalents` might be called (though for this simple ASCII range, it wouldn't do much).
4. Since it's a simple range and not Unicode-specific, `UnicodeRangeSplitter` might not be heavily involved in this particular case.
5. A `TextNode` would likely be created to represent this character class, internally storing the range `[a-c]`.

**Hypothetical Output:** A `TextNode` object configured to match any character within the range 'a' to 'c'.

**Common Programming Errors (Related to this Code's Functionality):**

While this C++ code *implements* the regex engine, it's influenced by and designed to handle common user errors in *writing* regular expressions:

1. **Incorrectly handling case sensitivity:** Forgetting the `i` flag when case-insensitive matching is desired. The `CharacterRange::AddUnicodeCaseEquivalents` function is designed to address this.
2. **Assuming ASCII for all characters:** Not accounting for Unicode characters, especially those outside the Basic Multilingual Plane. The `UnicodeRangeSplitter` is crucial for handling surrogate pairs correctly, which users might not be aware of when writing regexes. For example, a simple `.` won't match a surrogate pair as two individual characters in a non-unicode aware regex.
3. **Overly complex or inefficient disjunctions:** Writing patterns like `a|b|c|d...` when a character class `[abcd...]` would be more efficient. The `RationalizeConsecutiveAtoms` optimization in `RegExpDisjunction` aims to mitigate some of the performance impact of such patterns.
4. **Misunderstanding Unicode property escapes:** Using incorrect or unsupported Unicode property escapes. The `RegExpClassSetOperand` and `RegExpClassSetExpression` classes are responsible for correctly interpreting these escapes.
5. **Forgetting the `u` flag for Unicode features:**  Trying to use Unicode property escapes or expecting correct handling of surrogate pairs without the `u` flag in JavaScript regexes. This would lead to different behavior as the regex engine would treat the input as a sequence of UTF-16 code units rather than Unicode code points.

**归纳一下它的功能 (Summary of its Functionality):**

This part of the V8 regular expression compiler is responsible for **transforming a high-level representation of a regular expression into a lower-level, executable graph of `RegExpNode` objects.** This involves handling various regular expression components, including literal text, character classes (with special attention to Unicode and case folding), Unicode property escapes and set operations, and optimizations for disjunctions. It bridges the gap between the parsed regular expression and the actual matching process within the V8 engine. It ensures that JavaScript regular expressions, including those with advanced Unicode features, are compiled into an efficient and correct internal representation.

Prompt: 
```
这是目录为v8/src/regexp/regexp-compiler-tonode.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-compiler-tonode.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/objects/string.h"
#include "src/regexp/regexp-compiler.h"
#include "src/regexp/regexp.h"
#include "src/strings/unicode-inl.h"
#include "src/zone/zone-list-inl.h"

#ifdef V8_INTL_SUPPORT
#include "src/base/strings.h"
#include "src/regexp/special-case.h"
#include "unicode/locid.h"
#include "unicode/uniset.h"
#include "unicode/utypes.h"
#endif  // V8_INTL_SUPPORT

namespace v8 {
namespace internal {

using namespace regexp_compiler_constants;  // NOLINT(build/namespaces)

constexpr base::uc32 kMaxCodePoint = 0x10ffff;
constexpr int kMaxUtf16CodeUnit = 0xffff;
constexpr uint32_t kMaxUtf16CodeUnitU = 0xffff;

// -------------------------------------------------------------------
// Tree to graph conversion

RegExpNode* RegExpAtom::ToNode(RegExpCompiler* compiler,
                               RegExpNode* on_success) {
  ZoneList<TextElement>* elms =
      compiler->zone()->New<ZoneList<TextElement>>(1, compiler->zone());
  elms->Add(TextElement::Atom(this), compiler->zone());
  return compiler->zone()->New<TextNode>(elms, compiler->read_backward(),
                                         on_success);
}

RegExpNode* RegExpText::ToNode(RegExpCompiler* compiler,
                               RegExpNode* on_success) {
  return compiler->zone()->New<TextNode>(elements(), compiler->read_backward(),
                                         on_success);
}

namespace {

bool CompareInverseRanges(ZoneList<CharacterRange>* ranges,
                          const int* special_class, int length) {
  length--;  // Remove final marker.

  DCHECK_EQ(kRangeEndMarker, special_class[length]);
  DCHECK_NE(0, ranges->length());
  DCHECK_NE(0, length);
  DCHECK_NE(0, special_class[0]);

  if (ranges->length() != (length >> 1) + 1) return false;

  CharacterRange range = ranges->at(0);
  if (range.from() != 0) return false;

  for (int i = 0; i < length; i += 2) {
    if (static_cast<base::uc32>(special_class[i]) != (range.to() + 1)) {
      return false;
    }
    range = ranges->at((i >> 1) + 1);
    if (static_cast<base::uc32>(special_class[i + 1]) != range.from()) {
      return false;
    }
  }

  return range.to() == kMaxCodePoint;
}

bool CompareRanges(ZoneList<CharacterRange>* ranges, const int* special_class,
                   int length) {
  length--;  // Remove final marker.

  DCHECK_EQ(kRangeEndMarker, special_class[length]);
  if (ranges->length() * 2 != length) return false;

  for (int i = 0; i < length; i += 2) {
    CharacterRange range = ranges->at(i >> 1);
    if (range.from() != static_cast<base::uc32>(special_class[i]) ||
        range.to() != static_cast<base::uc32>(special_class[i + 1] - 1)) {
      return false;
    }
  }
  return true;
}

}  // namespace

bool RegExpClassRanges::is_standard(Zone* zone) {
  // TODO(lrn): Remove need for this function, by not throwing away information
  // along the way.
  if (is_negated()) {
    return false;
  }
  if (set_.is_standard()) {
    return true;
  }
  if (CompareRanges(set_.ranges(zone), kSpaceRanges, kSpaceRangeCount)) {
    set_.set_standard_set_type(StandardCharacterSet::kWhitespace);
    return true;
  }
  if (CompareInverseRanges(set_.ranges(zone), kSpaceRanges, kSpaceRangeCount)) {
    set_.set_standard_set_type(StandardCharacterSet::kNotWhitespace);
    return true;
  }
  if (CompareInverseRanges(set_.ranges(zone), kLineTerminatorRanges,
                           kLineTerminatorRangeCount)) {
    set_.set_standard_set_type(StandardCharacterSet::kNotLineTerminator);
    return true;
  }
  if (CompareRanges(set_.ranges(zone), kLineTerminatorRanges,
                    kLineTerminatorRangeCount)) {
    set_.set_standard_set_type(StandardCharacterSet::kLineTerminator);
    return true;
  }
  if (CompareRanges(set_.ranges(zone), kWordRanges, kWordRangeCount)) {
    set_.set_standard_set_type(StandardCharacterSet::kWord);
    return true;
  }
  if (CompareInverseRanges(set_.ranges(zone), kWordRanges, kWordRangeCount)) {
    set_.set_standard_set_type(StandardCharacterSet::kNotWord);
    return true;
  }
  return false;
}

UnicodeRangeSplitter::UnicodeRangeSplitter(ZoneList<CharacterRange>* base) {
  // The unicode range splitter categorizes given character ranges into:
  // - Code points from the BMP representable by one code unit.
  // - Code points outside the BMP that need to be split into
  // surrogate pairs.
  // - Lone lead surrogates.
  // - Lone trail surrogates.
  // Lone surrogates are valid code points, even though no actual characters.
  // They require special matching to make sure we do not split surrogate pairs.

  for (int i = 0; i < base->length(); i++) AddRange(base->at(i));
}

void UnicodeRangeSplitter::AddRange(CharacterRange range) {
  static constexpr base::uc32 kBmp1Start = 0;
  static constexpr base::uc32 kBmp1End = kLeadSurrogateStart - 1;
  static constexpr base::uc32 kBmp2Start = kTrailSurrogateEnd + 1;
  static constexpr base::uc32 kBmp2End = kNonBmpStart - 1;

  // Ends are all inclusive.
  static_assert(kBmp1Start == 0);
  static_assert(kBmp1Start < kBmp1End);
  static_assert(kBmp1End + 1 == kLeadSurrogateStart);
  static_assert(kLeadSurrogateStart < kLeadSurrogateEnd);
  static_assert(kLeadSurrogateEnd + 1 == kTrailSurrogateStart);
  static_assert(kTrailSurrogateStart < kTrailSurrogateEnd);
  static_assert(kTrailSurrogateEnd + 1 == kBmp2Start);
  static_assert(kBmp2Start < kBmp2End);
  static_assert(kBmp2End + 1 == kNonBmpStart);
  static_assert(kNonBmpStart < kNonBmpEnd);

  static constexpr base::uc32 kStarts[] = {
      kBmp1Start, kLeadSurrogateStart, kTrailSurrogateStart,
      kBmp2Start, kNonBmpStart,
  };

  static constexpr base::uc32 kEnds[] = {
      kBmp1End, kLeadSurrogateEnd, kTrailSurrogateEnd, kBmp2End, kNonBmpEnd,
  };

  CharacterRangeVector* const kTargets[] = {
      &bmp_, &lead_surrogates_, &trail_surrogates_, &bmp_, &non_bmp_,
  };

  static constexpr int kCount = arraysize(kStarts);
  static_assert(kCount == arraysize(kEnds));
  static_assert(kCount == arraysize(kTargets));

  for (int i = 0; i < kCount; i++) {
    if (kStarts[i] > range.to()) break;
    const base::uc32 from = std::max(kStarts[i], range.from());
    const base::uc32 to = std::min(kEnds[i], range.to());
    if (from > to) continue;
    kTargets[i]->emplace_back(CharacterRange::Range(from, to));
  }
}

namespace {

// Translates between new and old V8-isms (SmallVector, ZoneList).
ZoneList<CharacterRange>* ToCanonicalZoneList(
    const UnicodeRangeSplitter::CharacterRangeVector* v, Zone* zone) {
  if (v->empty()) return nullptr;

  ZoneList<CharacterRange>* result =
      zone->New<ZoneList<CharacterRange>>(static_cast<int>(v->size()), zone);
  for (size_t i = 0; i < v->size(); i++) {
    result->Add(v->at(i), zone);
  }

  CharacterRange::Canonicalize(result);
  return result;
}

void AddBmpCharacters(RegExpCompiler* compiler, ChoiceNode* result,
                      RegExpNode* on_success, UnicodeRangeSplitter* splitter) {
  ZoneList<CharacterRange>* bmp =
      ToCanonicalZoneList(splitter->bmp(), compiler->zone());
  if (bmp == nullptr) return;
  result->AddAlternative(GuardedAlternative(TextNode::CreateForCharacterRanges(
      compiler->zone(), bmp, compiler->read_backward(), on_success)));
}

using UC16Range = uint32_t;  // {from, to} packed into one uint32_t.
constexpr UC16Range ToUC16Range(base::uc16 from, base::uc16 to) {
  return (static_cast<uint32_t>(from) << 16) | to;
}
constexpr base::uc16 ExtractFrom(UC16Range r) {
  return static_cast<base::uc16>(r >> 16);
}
constexpr base::uc16 ExtractTo(UC16Range r) {
  return static_cast<base::uc16>(r);
}

void AddNonBmpSurrogatePairs(RegExpCompiler* compiler, ChoiceNode* result,
                             RegExpNode* on_success,
                             UnicodeRangeSplitter* splitter) {
  DCHECK(!compiler->one_byte());
  Zone* const zone = compiler->zone();
  ZoneList<CharacterRange>* non_bmp =
      ToCanonicalZoneList(splitter->non_bmp(), zone);
  if (non_bmp == nullptr) return;

  // Translate each 32-bit code point range into the corresponding 16-bit code
  // unit representation consisting of the lead- and trail surrogate.
  //
  // The generated alternatives are grouped by the leading surrogate to avoid
  // emitting excessive code. For example, for
  //
  //  { \ud800[\udc00-\udc01]
  //  , \ud800[\udc05-\udc06]
  //  }
  //
  // there's no need to emit matching code for the leading surrogate \ud800
  // twice. We also create a dedicated grouping for full trailing ranges, i.e.
  // [dc00-dfff].
  ZoneUnorderedMap<UC16Range, ZoneList<CharacterRange>*> grouped_by_leading(
      zone);
  ZoneList<CharacterRange>* leading_with_full_trailing_range =
      zone->New<ZoneList<CharacterRange>>(1, zone);
  const auto AddRange = [&](base::uc16 from_l, base::uc16 to_l,
                            base::uc16 from_t, base::uc16 to_t) {
    const UC16Range leading_range = ToUC16Range(from_l, to_l);
    if (grouped_by_leading.count(leading_range) == 0) {
      if (from_t == kTrailSurrogateStart && to_t == kTrailSurrogateEnd) {
        leading_with_full_trailing_range->Add(
            CharacterRange::Range(from_l, to_l), zone);
        return;
      }
      grouped_by_leading[leading_range] =
          zone->New<ZoneList<CharacterRange>>(2, zone);
    }
    grouped_by_leading[leading_range]->Add(CharacterRange::Range(from_t, to_t),
                                           zone);
  };

  // First, create the grouped ranges.
  CharacterRange::Canonicalize(non_bmp);
  for (int i = 0; i < non_bmp->length(); i++) {
    // Match surrogate pair.
    // E.g. [\u10005-\u11005] becomes
    //      \ud800[\udc05-\udfff]|
    //      [\ud801-\ud803][\udc00-\udfff]|
    //      \ud804[\udc00-\udc05]
    base::uc32 from = non_bmp->at(i).from();
    base::uc32 to = non_bmp->at(i).to();
    base::uc16 from_l = unibrow::Utf16::LeadSurrogate(from);
    base::uc16 from_t = unibrow::Utf16::TrailSurrogate(from);
    base::uc16 to_l = unibrow::Utf16::LeadSurrogate(to);
    base::uc16 to_t = unibrow::Utf16::TrailSurrogate(to);

    if (from_l == to_l) {
      // The lead surrogate is the same.
      AddRange(from_l, to_l, from_t, to_t);
      continue;
    }

    if (from_t != kTrailSurrogateStart) {
      // Add [from_l][from_t-\udfff].
      AddRange(from_l, from_l, from_t, kTrailSurrogateEnd);
      from_l++;
    }
    if (to_t != kTrailSurrogateEnd) {
      // Add [to_l][\udc00-to_t].
      AddRange(to_l, to_l, kTrailSurrogateStart, to_t);
      to_l--;
    }
    if (from_l <= to_l) {
      // Add [from_l-to_l][\udc00-\udfff].
      AddRange(from_l, to_l, kTrailSurrogateStart, kTrailSurrogateEnd);
    }
  }

  // Create the actual TextNode now that ranges are fully grouped.
  if (!leading_with_full_trailing_range->is_empty()) {
    CharacterRange::Canonicalize(leading_with_full_trailing_range);
    result->AddAlternative(GuardedAlternative(TextNode::CreateForSurrogatePair(
        zone, leading_with_full_trailing_range,
        CharacterRange::Range(kTrailSurrogateStart, kTrailSurrogateEnd),
        compiler->read_backward(), on_success)));
  }
  for (const auto& it : grouped_by_leading) {
    CharacterRange leading_range =
        CharacterRange::Range(ExtractFrom(it.first), ExtractTo(it.first));
    ZoneList<CharacterRange>* trailing_ranges = it.second;
    CharacterRange::Canonicalize(trailing_ranges);
    result->AddAlternative(GuardedAlternative(TextNode::CreateForSurrogatePair(
        zone, leading_range, trailing_ranges, compiler->read_backward(),
        on_success)));
  }
}

RegExpNode* NegativeLookaroundAgainstReadDirectionAndMatch(
    RegExpCompiler* compiler, ZoneList<CharacterRange>* lookbehind,
    ZoneList<CharacterRange>* match, RegExpNode* on_success,
    bool read_backward) {
  Zone* zone = compiler->zone();
  RegExpNode* match_node = TextNode::CreateForCharacterRanges(
      zone, match, read_backward, on_success);
  int stack_register = compiler->UnicodeLookaroundStackRegister();
  int position_register = compiler->UnicodeLookaroundPositionRegister();
  RegExpLookaround::Builder lookaround(false, match_node, stack_register,
                                       position_register);
  RegExpNode* negative_match = TextNode::CreateForCharacterRanges(
      zone, lookbehind, !read_backward, lookaround.on_match_success());
  return lookaround.ForMatch(negative_match);
}

RegExpNode* MatchAndNegativeLookaroundInReadDirection(
    RegExpCompiler* compiler, ZoneList<CharacterRange>* match,
    ZoneList<CharacterRange>* lookahead, RegExpNode* on_success,
    bool read_backward) {
  Zone* zone = compiler->zone();
  int stack_register = compiler->UnicodeLookaroundStackRegister();
  int position_register = compiler->UnicodeLookaroundPositionRegister();
  RegExpLookaround::Builder lookaround(false, on_success, stack_register,
                                       position_register);
  RegExpNode* negative_match = TextNode::CreateForCharacterRanges(
      zone, lookahead, read_backward, lookaround.on_match_success());
  return TextNode::CreateForCharacterRanges(
      zone, match, read_backward, lookaround.ForMatch(negative_match));
}

void AddLoneLeadSurrogates(RegExpCompiler* compiler, ChoiceNode* result,
                           RegExpNode* on_success,
                           UnicodeRangeSplitter* splitter) {
  ZoneList<CharacterRange>* lead_surrogates =
      ToCanonicalZoneList(splitter->lead_surrogates(), compiler->zone());
  if (lead_surrogates == nullptr) return;
  Zone* zone = compiler->zone();
  // E.g. \ud801 becomes \ud801(?![\udc00-\udfff]).
  ZoneList<CharacterRange>* trail_surrogates = CharacterRange::List(
      zone, CharacterRange::Range(kTrailSurrogateStart, kTrailSurrogateEnd));

  RegExpNode* match;
  if (compiler->read_backward()) {
    // Reading backward. Assert that reading forward, there is no trail
    // surrogate, and then backward match the lead surrogate.
    match = NegativeLookaroundAgainstReadDirectionAndMatch(
        compiler, trail_surrogates, lead_surrogates, on_success, true);
  } else {
    // Reading forward. Forward match the lead surrogate and assert that
    // no trail surrogate follows.
    match = MatchAndNegativeLookaroundInReadDirection(
        compiler, lead_surrogates, trail_surrogates, on_success, false);
  }
  result->AddAlternative(GuardedAlternative(match));
}

void AddLoneTrailSurrogates(RegExpCompiler* compiler, ChoiceNode* result,
                            RegExpNode* on_success,
                            UnicodeRangeSplitter* splitter) {
  ZoneList<CharacterRange>* trail_surrogates =
      ToCanonicalZoneList(splitter->trail_surrogates(), compiler->zone());
  if (trail_surrogates == nullptr) return;
  Zone* zone = compiler->zone();
  // E.g. \udc01 becomes (?<![\ud800-\udbff])\udc01
  ZoneList<CharacterRange>* lead_surrogates = CharacterRange::List(
      zone, CharacterRange::Range(kLeadSurrogateStart, kLeadSurrogateEnd));

  RegExpNode* match;
  if (compiler->read_backward()) {
    // Reading backward. Backward match the trail surrogate and assert that no
    // lead surrogate precedes it.
    match = MatchAndNegativeLookaroundInReadDirection(
        compiler, trail_surrogates, lead_surrogates, on_success, true);
  } else {
    // Reading forward. Assert that reading backward, there is no lead
    // surrogate, and then forward match the trail surrogate.
    match = NegativeLookaroundAgainstReadDirectionAndMatch(
        compiler, lead_surrogates, trail_surrogates, on_success, false);
  }
  result->AddAlternative(GuardedAlternative(match));
}

RegExpNode* UnanchoredAdvance(RegExpCompiler* compiler,
                              RegExpNode* on_success) {
  // This implements ES2015 21.2.5.2.3, AdvanceStringIndex.
  DCHECK(!compiler->read_backward());
  Zone* zone = compiler->zone();
  // Advance any character. If the character happens to be a lead surrogate and
  // we advanced into the middle of a surrogate pair, it will work out, as
  // nothing will match from there. We will have to advance again, consuming
  // the associated trail surrogate.
  ZoneList<CharacterRange>* range =
      CharacterRange::List(zone, CharacterRange::Range(0, kMaxUtf16CodeUnit));
  return TextNode::CreateForCharacterRanges(zone, range, false, on_success);
}

}  // namespace

// static
// Only for /ui and /vi, not for /i regexps.
void CharacterRange::AddUnicodeCaseEquivalents(ZoneList<CharacterRange>* ranges,
                                               Zone* zone) {
#ifdef V8_INTL_SUPPORT
  DCHECK(IsCanonical(ranges));

  // Micro-optimization to avoid passing large ranges to UnicodeSet::closeOver.
  // See also https://crbug.com/v8/6727.
  // TODO(jgruber): This only covers the special case of the {0,0x10FFFF} range,
  // which we use frequently internally. But large ranges can also easily be
  // created by the user. We might want to have a more general caching mechanism
  // for such ranges.
  if (ranges->length() == 1 && ranges->at(0).IsEverything(kNonBmpEnd)) return;

  // Use ICU to compute the case fold closure over the ranges.
  icu::UnicodeSet set;
  for (int i = 0; i < ranges->length(); i++) {
    set.add(ranges->at(i).from(), ranges->at(i).to());
  }
  // Clear the ranges list without freeing the backing store.
  ranges->Rewind(0);
  set.closeOver(USET_SIMPLE_CASE_INSENSITIVE);
  for (int i = 0; i < set.getRangeCount(); i++) {
    ranges->Add(Range(set.getRangeStart(i), set.getRangeEnd(i)), zone);
  }
  // No errors and everything we collected have been ranges.
  Canonicalize(ranges);
#endif  // V8_INTL_SUPPORT
}

RegExpNode* RegExpClassRanges::ToNode(RegExpCompiler* compiler,
                                      RegExpNode* on_success) {
  set_.Canonicalize();
  Zone* const zone = compiler->zone();
  ZoneList<CharacterRange>* ranges = this->ranges(zone);

  const bool needs_case_folding =
      NeedsUnicodeCaseEquivalents(compiler->flags()) && !is_case_folded();
  if (needs_case_folding) {
    CharacterRange::AddUnicodeCaseEquivalents(ranges, zone);
  }

  if (!IsEitherUnicode(compiler->flags()) || compiler->one_byte() ||
      contains_split_surrogate()) {
    return zone->New<TextNode>(this, compiler->read_backward(), on_success);
  }

  if (is_negated()) {
    // With /v, character classes are never negated.
    // https://tc39.es/ecma262/#sec-compileatom
    // Atom :: CharacterClass
    //   4. Assert: cc.[[Invert]] is false.
    // Instead the complement is created when evaluating the class set.
    // The only exception is the "nothing range" (negated everything), which is
    // internally created for an empty set.
    DCHECK_IMPLIES(
        IsUnicodeSets(compiler->flags()),
        ranges->length() == 1 && ranges->first().IsEverything(kMaxCodePoint));
    ZoneList<CharacterRange>* negated =
        zone->New<ZoneList<CharacterRange>>(2, zone);
    CharacterRange::Negate(ranges, negated, zone);
    ranges = negated;
  }

  if (ranges->length() == 0) {
    // The empty character class is used as a 'fail' node.
    RegExpClassRanges* fail = zone->New<RegExpClassRanges>(zone, ranges);
    return zone->New<TextNode>(fail, compiler->read_backward(), on_success);
  }

  if (set_.is_standard() &&
      standard_type() == StandardCharacterSet::kEverything) {
    return UnanchoredAdvance(compiler, on_success);
  }

  // Split ranges in order to handle surrogates correctly:
  // - Surrogate pairs: translate the 32-bit code point into two uc16 code
  //   units (irregexp operates only on code units).
  // - Lone surrogates: these require lookarounds to ensure we don't match in
  //   the middle of a surrogate pair.
  ChoiceNode* result = zone->New<ChoiceNode>(2, zone);
  UnicodeRangeSplitter splitter(ranges);
  AddBmpCharacters(compiler, result, on_success, &splitter);
  AddNonBmpSurrogatePairs(compiler, result, on_success, &splitter);
  AddLoneLeadSurrogates(compiler, result, on_success, &splitter);
  AddLoneTrailSurrogates(compiler, result, on_success, &splitter);

  static constexpr int kMaxRangesToInline = 32;  // Arbitrary.
  if (ranges->length() > kMaxRangesToInline) result->SetDoNotInline();

  return result;
}

RegExpNode* RegExpClassSetOperand::ToNode(RegExpCompiler* compiler,
                                          RegExpNode* on_success) {
  Zone* zone = compiler->zone();
  const int size = (has_strings() ? static_cast<int>(strings()->size()) : 0) +
                   (ranges()->is_empty() ? 0 : 1);
  if (size == 0) {
    // If neither ranges nor strings are present, the operand is equal to an
    // empty range (matching nothing).
    ZoneList<CharacterRange>* empty =
        zone->template New<ZoneList<CharacterRange>>(0, zone);
    return zone->template New<RegExpClassRanges>(zone, empty)
        ->ToNode(compiler, on_success);
  }
  ZoneList<RegExpTree*>* alternatives =
      zone->template New<ZoneList<RegExpTree*>>(size, zone);
  // Strings are sorted by length first (larger strings before shorter ones).
  // See the comment on CharacterClassStrings.
  // Empty strings (if present) are added after character ranges.
  RegExpTree* empty_string = nullptr;
  if (has_strings()) {
    for (auto string : *strings()) {
      if (string.second->IsEmpty()) {
        empty_string = string.second;
      } else {
        alternatives->Add(string.second, zone);
      }
    }
  }
  if (!ranges()->is_empty()) {
    // In unicode sets mode case folding has to be done at precise locations
    // (e.g. before building complements).
    // It is therefore the parsers responsibility to case fold (sub-) ranges
    // before creating ClassSetOperands.
    alternatives->Add(zone->template New<RegExpClassRanges>(
                          zone, ranges(), RegExpClassRanges::IS_CASE_FOLDED),
                      zone);
  }
  if (empty_string != nullptr) {
    alternatives->Add(empty_string, zone);
  }

  RegExpTree* node = nullptr;
  if (size == 1) {
    DCHECK_EQ(alternatives->length(), 1);
    node = alternatives->first();
  } else {
    node = zone->template New<RegExpDisjunction>(alternatives);
  }
  return node->ToNode(compiler, on_success);
}

RegExpNode* RegExpClassSetExpression::ToNode(RegExpCompiler* compiler,
                                             RegExpNode* on_success) {
  Zone* zone = compiler->zone();
  ZoneList<CharacterRange>* temp_ranges =
      zone->template New<ZoneList<CharacterRange>>(4, zone);
  RegExpClassSetOperand* root = ComputeExpression(this, temp_ranges, zone);
  return root->ToNode(compiler, on_success);
}

void RegExpClassSetOperand::Union(RegExpClassSetOperand* other, Zone* zone) {
  ranges()->AddAll(*other->ranges(), zone);
  if (other->has_strings()) {
    if (strings_ == nullptr) {
      strings_ = zone->template New<CharacterClassStrings>(zone);
    }
    strings()->insert(other->strings()->begin(), other->strings()->end());
  }
}

void RegExpClassSetOperand::Intersect(RegExpClassSetOperand* other,
                                      ZoneList<CharacterRange>* temp_ranges,
                                      Zone* zone) {
  CharacterRange::Intersect(ranges(), other->ranges(), temp_ranges, zone);
  std::swap(*ranges(), *temp_ranges);
  temp_ranges->Rewind(0);
  if (has_strings()) {
    if (!other->has_strings()) {
      strings()->clear();
    } else {
      for (auto iter = strings()->begin(); iter != strings()->end();) {
        if (other->strings()->find(iter->first) == other->strings()->end()) {
          iter = strings()->erase(iter);
        } else {
          iter++;
        }
      }
    }
  }
}

void RegExpClassSetOperand::Subtract(RegExpClassSetOperand* other,
                                     ZoneList<CharacterRange>* temp_ranges,
                                     Zone* zone) {
  CharacterRange::Subtract(ranges(), other->ranges(), temp_ranges, zone);
  std::swap(*ranges(), *temp_ranges);
  temp_ranges->Rewind(0);
  if (has_strings() && other->has_strings()) {
    for (auto iter = strings()->begin(); iter != strings()->end();) {
      if (other->strings()->find(iter->first) != other->strings()->end()) {
        iter = strings()->erase(iter);
      } else {
        iter++;
      }
    }
  }
}

// static
RegExpClassSetOperand* RegExpClassSetExpression::ComputeExpression(
    RegExpTree* root, ZoneList<CharacterRange>* temp_ranges, Zone* zone) {
  DCHECK(temp_ranges->is_empty());
  if (root->IsClassSetOperand()) {
    return root->AsClassSetOperand();
  }
  DCHECK(root->IsClassSetExpression());
  RegExpClassSetExpression* node = root->AsClassSetExpression();
  RegExpClassSetOperand* result =
      ComputeExpression(node->operands()->at(0), temp_ranges, zone);
  switch (node->operation()) {
    case OperationType::kUnion: {
      for (int i = 1; i < node->operands()->length(); i++) {
        RegExpClassSetOperand* op =
            ComputeExpression(node->operands()->at(i), temp_ranges, zone);
        result->Union(op, zone);
      }
      CharacterRange::Canonicalize(result->ranges());
      break;
    }
    case OperationType::kIntersection: {
      for (int i = 1; i < node->operands()->length(); i++) {
        RegExpClassSetOperand* op =
            ComputeExpression(node->operands()->at(i), temp_ranges, zone);
        result->Intersect(op, temp_ranges, zone);
      }
      break;
    }
    case OperationType::kSubtraction: {
      for (int i = 1; i < node->operands()->length(); i++) {
        RegExpClassSetOperand* op =
            ComputeExpression(node->operands()->at(i), temp_ranges, zone);
        result->Subtract(op, temp_ranges, zone);
      }
      break;
    }
  }
  if (node->is_negated()) {
    DCHECK(!result->has_strings());
    CharacterRange::Negate(result->ranges(), temp_ranges, zone);
    std::swap(*result->ranges(), *temp_ranges);
    temp_ranges->Rewind(0);
    node->is_negated_ = false;
  }
  // Store the result as single operand of the current node.
  node->operands()->Set(0, result);
  node->operands()->Rewind(1);

  return result;
}

namespace {

int CompareFirstChar(RegExpTree* const* a, RegExpTree* const* b) {
  RegExpAtom* atom1 = (*a)->AsAtom();
  RegExpAtom* atom2 = (*b)->AsAtom();
  base::uc16 character1 = atom1->data().at(0);
  base::uc16 character2 = atom2->data().at(0);
  if (character1 < character2) return -1;
  if (character1 > character2) return 1;
  return 0;
}

#ifdef V8_INTL_SUPPORT

int CompareCaseInsensitive(const icu::UnicodeString& a,
                           const icu::UnicodeString& b) {
  return a.caseCompare(b, U_FOLD_CASE_DEFAULT);
}

int CompareFirstCharCaseInsensitive(RegExpTree* const* a,
                                    RegExpTree* const* b) {
  RegExpAtom* atom1 = (*a)->AsAtom();
  RegExpAtom* atom2 = (*b)->AsAtom();
  return CompareCaseInsensitive(icu::UnicodeString{atom1->data().at(0)},
                                icu::UnicodeString{atom2->data().at(0)});
}

bool Equals(bool ignore_case, const icu::UnicodeString& a,
            const icu::UnicodeString& b) {
  if (a == b) return true;
  if (ignore_case) return CompareCaseInsensitive(a, b) == 0;
  return false;  // Case-sensitive equality already checked above.
}

bool CharAtEquals(bool ignore_case, int index, const RegExpAtom* a,
                  const RegExpAtom* b) {
  return Equals(ignore_case, a->data().at(index), b->data().at(index));
}

#else

unibrow::uchar Canonical(
    unibrow::Mapping<unibrow::Ecma262Canonicalize>* canonicalize,
    unibrow::uchar c) {
  unibrow::uchar chars[unibrow::Ecma262Canonicalize::kMaxWidth];
  int length = canonicalize->get(c, '\0', chars);
  DCHECK_LE(length, 1);
  unibrow::uchar canonical = c;
  if (length == 1) canonical = chars[0];
  return canonical;
}

int CompareCaseInsensitive(
    unibrow::Mapping<unibrow::Ecma262Canonicalize>* canonicalize,
    unibrow::uchar a, unibrow::uchar b) {
  if (a == b) return 0;
  if (a >= 'a' || b >= 'a') {
    a = Canonical(canonicalize, a);
    b = Canonical(canonicalize, b);
  }
  return static_cast<int>(a) - static_cast<int>(b);
}

int CompareFirstCharCaseInsensitive(
    unibrow::Mapping<unibrow::Ecma262Canonicalize>* canonicalize,
    RegExpTree* const* a, RegExpTree* const* b) {
  RegExpAtom* atom1 = (*a)->AsAtom();
  RegExpAtom* atom2 = (*b)->AsAtom();
  return CompareCaseInsensitive(canonicalize, atom1->data().at(0),
                                atom2->data().at(0));
}

bool Equals(bool ignore_case,
            unibrow::Mapping<unibrow::Ecma262Canonicalize>* canonicalize,
            unibrow::uchar a, unibrow::uchar b) {
  if (a == b) return true;
  if (ignore_case) {
    return CompareCaseInsensitive(canonicalize, a, b) == 0;
  }
  return false;  // Case-sensitive equality already checked above.
}

bool CharAtEquals(bool ignore_case,
                  unibrow::Mapping<unibrow::Ecma262Canonicalize>* canonicalize,
                  int index, const RegExpAtom* a, const RegExpAtom* b) {
  return Equals(ignore_case, canonicalize, a->data().at(index),
                b->data().at(index));
}

#endif  // V8_INTL_SUPPORT

}  // namespace

// We can stable sort runs of atoms, since the order does not matter if they
// start with different characters.
// Returns true if any consecutive atoms were found.
bool RegExpDisjunction::SortConsecutiveAtoms(RegExpCompiler* compiler) {
  ZoneList<RegExpTree*>* alternatives = this->alternatives();
  int length = alternatives->length();
  bool found_consecutive_atoms = false;
  for (int i = 0; i < length; i++) {
    while (i < length) {
      RegExpTree* alternative = alternatives->at(i);
      if (alternative->IsAtom()) break;
      i++;
    }
    // i is length or it is the index of an atom.
    if (i == length) break;
    int first_atom = i;
    i++;
    while (i < length) {
      RegExpTree* alternative = alternatives->at(i);
      if (!alternative->IsAtom()) break;
      i++;
    }
    // Sort atoms to get ones with common prefixes together.
    // This step is more tricky if we are in a case-independent regexp,
    // because it would change /is|I/ to /I|is/, and order matters when
    // the regexp parts don't match only disjoint starting points. To fix
    // this we have a version of CompareFirstChar that uses case-
    // independent character classes for comparison.
    DCHECK_LT(first_atom, alternatives->length());
    DCHECK_LE(i, alternatives->length());
    DCHECK_LE(first_atom, i);
    if (IsIgnoreCase(compiler->flags())) {
#ifdef V8_INTL_SUPPORT
      alternatives->StableSort(CompareFirstCharCaseInsensitive, first_atom,
                               i - first_atom);
#else
      unibrow::Mapping<unibrow::Ecma262Canonicalize>* canonicalize =
          compiler->isolate()->regexp_macro_assembler_canonicalize();
      auto compare_closure = [canonicalize](RegExpTree* const* a,
                                            RegExpTree* const* b) {
        return CompareFirstCharCaseInsensitive(canonicalize, a, b);
      };
      alternatives->StableSort(compare_closure, first_atom, i - first_atom);
#endif  // V8_INTL_SUPPORT
    } else {
      alternatives->StableSort(CompareFirstChar, first_atom, i - first_atom);
    }
    if (i - first_atom > 1) found_consecutive_atoms = true;
  }
  return found_consecutive_atoms;
}

// Optimizes ab|ac|az to a(?:b|c|d).
void RegExpDisjunction::RationalizeConsecutiveAtoms(RegExpCompiler* compiler) {
  Zone* zone = compiler->zone();
  ZoneList<RegExpTree*>* alternatives = this->alternatives();
  int length = alternatives->length();
  const bool ignore_case = IsIgnoreCase(compiler->flags());

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
#ifdef V8_INTL_SUPPORT
    icu::UnicodeString common_prefix(atom->data().at(0));
#else
    unibrow::Mapping<unibrow::Ecma262Canonicalize>* const canonicalize =
        compiler->isolate()->regexp_macro_assembler_canonicalize();
    unibrow::uchar common_prefix = atom->data().at(0);
    if (ignore_case) {
      common_prefix = Canonical(canonicalize, common_prefix);
    }
#endif  // V8_INTL_SUPPORT
    int first_with_prefix = i;
    int prefix_length = atom->length();
    i++;
    while (i < length) {
      alternative = alternatives->at(i);
      if (!alternative->IsAtom()) break;
      RegExpAtom* const alt_atom = alternative->AsAtom();
#ifdef V8_INTL_SUPPORT
      icu::UnicodeString new_prefix(alt_atom->data().at(0));
      if (!Equals(ignore_case, new_prefix, common_prefix)) break;
#else
      unibrow::uchar new_prefix 
"""


```