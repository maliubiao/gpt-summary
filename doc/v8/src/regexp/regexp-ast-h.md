Response:
Let's break down the thought process for analyzing this C++ header file and answering the user's request.

**1. Understanding the Request:**

The user wants to know the functionality of `v8/src/regexp/regexp-ast.h`. They also have specific follow-up questions related to Torque, JavaScript interaction, code logic examples, and common programming errors. This means we need to go beyond a simple summary and look for clues within the code itself.

**2. Initial Scan and Keyword Identification:**

A quick scan reveals several key terms and patterns:

* `#ifndef`, `#define`, `#include`: Standard C++ header file guards.
* `namespace v8::internal`:  Confirms it's part of the V8 engine.
* `RegExp`:  The most frequent prefix, strongly suggesting this is related to regular expressions.
* `AST`:  Stands for Abstract Syntax Tree, a common data structure for representing code or expressions.
* `Visitor`:  Suggests a design pattern for traversing the AST.
* `Interval`, `CharacterRange`, `CharacterSet`:  Types related to defining character groups.
* `RegExpDisjunction`, `RegExpAlternative`, `RegExpAssertion`, etc.:  Classes with names that resemble common regex concepts (OR, AND, `^`, `$`, etc.).
* `Quantifier`, `Capture`, `Group`, `Lookaround`, `BackReference`:  More regex-specific terms.
* `min_match`, `max_match`:  Attributes likely related to how many times a part of the regex can match.
* `ToNode`: A method suggesting compilation or transformation into an internal representation.

**3. Inferring the Core Functionality:**

Based on the keywords, the core functionality is clearly the definition of an Abstract Syntax Tree for regular expressions within V8. This header file provides the building blocks for representing the structure of a regex. It defines:

* **Nodes:**  Different types of regex components (disjunction, alternative, atom, etc.) as C++ classes.
* **Relationships:** How these components can be nested and combined (e.g., an `Alternative` contains a list of `RegExpTree` nodes).
* **Properties:**  Attributes of each node type (e.g., `min_match`, `max_match` for quantifiers).
* **Operations:** Actions you can perform on the AST (e.g., `Accept` for the visitor pattern).

**4. Addressing Specific Questions:**

* **Torque:** The file ends with `.h`, not `.tq`. Therefore, it's not a Torque file. Mention this explicitly.

* **JavaScript Relationship:**  Since this is a regex AST, it's directly related to JavaScript's `RegExp` object and its methods (`match`, `exec`, `search`, `replace`, `split`). Provide concrete JavaScript examples to illustrate how different regex syntax elements map to the AST nodes defined in the header. For instance, `|` maps to `RegExpDisjunction`, `()` to `RegExpGroup` or `RegExpCapture`, etc.

* **Code Logic and Examples:** Look for methods that suggest some internal logic. `Interval::Union`, `CharacterRange::Contains`, `CharacterRange::Canonicalize`, and the various `Intersect`, `Subtract`, and `Negate` methods on `CharacterRange` are good candidates. Choose a simple example like `Interval::Union` and provide a clear input and expected output to demonstrate its behavior.

* **Common Programming Errors:** Think about how users typically misuse regular expressions. Common mistakes include:
    * **Greedy vs. Non-Greedy Matching:** Explain the difference and give an example of unexpected behavior with greedy matching.
    * **Forgetting to Escape Special Characters:**  Show how a special character used literally can lead to unexpected results.
    * **Incorrect Use of Anchors (`^`, `$`)**: Illustrate how the absence or incorrect placement of anchors can affect matching.
    * **Overly Complex Regex (for less experienced users):** Briefly mention that overly complex regex can be hard to debug.

**5. Structuring the Answer:**

Organize the information logically:

* **Introduction:** Briefly state the file's purpose.
* **Key Functionalities (Bulleted List):**  Summarize the main roles of the header file.
* **Torque:** Directly answer the Torque question.
* **JavaScript Relationship (with Examples):** Explain the connection and provide illustrative JavaScript code.
* **Code Logic Example:** Choose a clear example with input and output.
* **Common Programming Errors (with Examples):**  Provide relevant and understandable error scenarios.
* **Conclusion:** Briefly summarize the importance of the file.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus only on the class definitions.
* **Correction:** Realize that the request asks for *functionality*, so explaining the relationships between classes and the overall purpose of an AST is important.
* **Initial thought:**  Provide very technical C++ examples for code logic.
* **Correction:** Choose simpler examples and focus on the *behavior* rather than low-level implementation details to make it more accessible.
* **Initial thought:** List all possible regex errors.
* **Correction:** Select the most *common* and easily understandable errors for novice to intermediate programmers.

By following these steps, combining code analysis with an understanding of the user's request, and refining the answer along the way, we can generate a comprehensive and helpful response.
This header file, `v8/src/regexp/regexp-ast.h`, defines the Abstract Syntax Tree (AST) for regular expressions within the V8 JavaScript engine. It provides the data structures and interfaces to represent the parsed structure of a regular expression.

Here's a breakdown of its functionalities:

**Core Functionality: Defining the Regular Expression Abstract Syntax Tree (AST)**

The primary purpose of `regexp-ast.h` is to define the building blocks for representing regular expressions in a tree-like structure. Each class in this file represents a different component or construct found in regular expressions. This AST is a crucial intermediate representation used during the compilation and execution of regular expressions in V8.

Here's a breakdown of the key classes and what they represent:

* **`RegExpTree` (Base Class):**  The abstract base class for all nodes in the regular expression AST. It defines common methods like `Accept` (for the visitor pattern), `ToNode` (likely for generating bytecode or other internal representations), `min_match`, and `max_match`.

* **Concrete Node Classes (derived from `RegExpTree`):**  Each of these classes represents a specific type of regular expression construct:
    * **`RegExpDisjunction`:** Represents the `|` (OR) operator, combining multiple alternative patterns.
    * **`RegExpAlternative`:** Represents a sequence of elements that must match in order (e.g., `abc`).
    * **`RegExpAssertion`:** Represents zero-width assertions like `^` (start of line), `$` (end of line), `\b` (word boundary), `\B` (non-word boundary).
    * **`RegExpClassRanges`:** Represents character classes defined using square brackets `[]`, like `[a-z0-9]`.
    * **`RegExpClassSetOperand`, `RegExpClassSetExpression`:** Used for more complex character class operations, especially in Unicode sets mode.
    * **`RegExpAtom`:** Represents a literal sequence of characters.
    * **`RegExpQuantifier`:** Represents repetition operators like `*`, `+`, `?`, and `{m,n}`.
    * **`RegExpCapture`:** Represents capturing groups enclosed in parentheses `()`.
    * **`RegExpGroup`:** Represents non-capturing groups using `(?:...)`.
    * **`RegExpLookaround`:** Represents lookahead (`(?=...)`, `(?!...)`) and lookbehind (`(?<=...)`, `(?<!...)`) assertions.
    * **`RegExpBackReference`:** Represents backreferences like `\1`, `\2` that refer to previously captured groups.
    * **`RegExpEmpty`:** Represents an empty expression.
    * **`RegExpText`:**  Represents a contiguous sequence of literal characters or character classes.

* **Helper Classes:**
    * **`Interval`:** Represents a range of integers, likely used for capture group indices or quantifier ranges.
    * **`CharacterRange`:** Represents a range of Unicode code points.
    * **`CharacterSet`:**  Manages a set of `CharacterRange` objects, used for representing character classes.

* **Visitor Pattern (`RegExpVisitor`):**  Defines an interface for traversing the AST. Concrete visitor implementations can perform operations on the AST nodes, such as code generation or analysis.

**Is `v8/src/regexp/regexp-ast.h` a Torque Source File?**

No, `v8/src/regexp/regexp-ast.h` does **not** end with `.tq`. Therefore, it is **not** a V8 Torque source file. It's a standard C++ header file. Torque files use the `.tq` extension.

**Relationship with JavaScript Functionality and Examples**

This header file is directly and fundamentally related to the functionality of JavaScript's `RegExp` object and its associated methods (`match`, `exec`, `test`, `search`, `replace`, `split`). When a JavaScript engine encounters a regular expression, it needs to parse it and create an internal representation before it can be executed. `regexp-ast.h` defines the structure of that internal representation (the AST).

Here are some JavaScript examples and how they relate to the AST node types:

* **`/abc/`:** This simple literal regex would likely result in an `RegExpAlternative` containing a single `RegExpAtom` representing the string "abc".

* **`/a|b/`:** This regex with the OR operator would be represented by a `RegExpDisjunction` with two alternatives, each containing a `RegExpAtom` ('a' and 'b').

* **`/a*/`:**  The quantifier `*` would be represented by a `RegExpQuantifier` node with `min = 0`, `max = infinity`, and the body being a `RegExpAtom` for 'a'.

* **`/(ab)+/`:** The capturing group `(ab)` would be a `RegExpCapture` node, and the `+` quantifier would be a `RegExpQuantifier` wrapping the `RegExpCapture`. The `RegExpCapture` itself would contain an `RegExpAlternative` with `RegExpAtom`s for 'a' and 'b'.

* **`/[0-9]+/`:** The character class `[0-9]` would be represented by a `RegExpClassRanges` node containing the range of characters from '0' to '9'. The `+` would be a `RegExpQuantifier`.

* **`/^start/`:** The `^` assertion would be a `RegExpAssertion` node of type `START_OF_LINE` or `START_OF_INPUT`.

**Code Logic Inference with Assumptions**

Let's consider the `Interval::Union` method:

**Assumption:** We have two intervals representing ranges of capture group indices used within different parts of a regular expression. We want to find the overall range of capture group indices used.

**Input 1:** `interval1` with `from_ = 2`, `to_ = 5` (representing capture groups 2, 3, 4, and 5)
**Input 2:** `interval2` with `from_ = 7`, `to_ = 9` (representing capture groups 7, 8, and 9)

**Call:** `interval1.Union(interval2)`

**Logic:** The `Union` method checks if either interval is empty. If not, it calculates the new interval by taking the minimum of the `from` values and the maximum of the `to` values.

**Output:** A new `Interval` object with `from_ = 2`, `to_ = 9`. This represents the combined range of capture groups used (2, 3, 4, 5, 7, 8, 9).

**Another Example: `CharacterRange::Contains`**

**Assumption:** We want to check if a specific Unicode code point belongs to a defined character range.

**Input:** `range` with `from_ = 'a'`, `to_ = 'z'` (representing lowercase letters)
**Input Value:** `value = 'c'` (ASCII value of 'c')

**Call:** `range.Contains(value)`

**Logic:** The `Contains` method checks if the input `value` is greater than or equal to `from_` and less than or equal to `to_`.

**Output:** `true` because 'c' falls within the range 'a' to 'z'.

**Common Programming Errors Related to Regular Expressions (and how this file relates)**

While this header file doesn't directly *cause* user programming errors, understanding its structure can help diagnose issues. Common mistakes that manifest in how the AST is constructed include:

1. **Incorrect use of Quantifiers (Greedy vs. Non-Greedy):**
   * **Example:**  A user might write `/a.*b/` expecting it to match the shortest string starting with "a" and ending with "b". However, the `.*` is greedy and will match as much as possible.
   * **How it relates to the AST:** The `RegExpQuantifier` node for `*` has a `quantifier_type_` (GREEDY, NON_GREEDY). Misunderstanding this type leads to unexpected matching behavior.

   ```javascript
   const str = "axxxbbyyyb";
   const greedyMatch = str.match(/a.*b/); // ["axxxbbyyyb"] - Matches the entire string
   const nonGreedyMatch = str.match(/a.*?b/); // ["axxxb"] - Matches the shortest substring
   ```

2. **Forgetting to Escape Special Characters:**
   * **Example:** A user might intend to match a literal dot `.` but writes `/a.b/`, which matches any character between 'a' and 'b'.
   * **How it relates to the AST:** The parser would create an `RegExpAtom` for the literal characters, but the unescaped `.` would be interpreted as a wildcard in the context of parsing, not as a literal dot character.

   ```javascript
   const str = "a.b";
   const regexWithoutEscape = /a.b/;
   const regexWithEscape = /a\.b/;

   console.log(str.match(regexWithoutEscape)); // ["a.b"]
   console.log(str.match(regexWithEscape));  // ["a.b"]

   const otherStr = "axb";
   console.log(otherStr.match(regexWithoutEscape)); // ["axb"]
   console.log(otherStr.match(regexWithEscape));  // null
   ```

3. **Incorrectly Nested or Unbalanced Parentheses:**
   * **Example:**  `/((abc)/` has an opening parenthesis but no matching closing one.
   * **How it relates to the AST:** The parser, which eventually builds the AST defined in this header, will detect this syntax error and fail. The structures defined here expect balanced and correctly nested components.

   ```javascript
   try {
     const regex = /((abc)/; // This will throw a SyntaxError in JavaScript
   } catch (e) {
     console.error(e); // SyntaxError: Invalid regular expression: /((abc)/: Unmatched '('
   }
   ```

4. **Misunderstanding Character Classes:**
   * **Example:**  `/a[bcd]e/` matches "abe", "ace", or "ade". A user might mistakenly think it matches "abcde".
   * **How it relates to the AST:** The `RegExpClassRanges` node clearly defines a set of individual characters that can match at that position, not a sequence.

   ```javascript
   const str = "abcde";
   const regex = /a[bcd]e/;
   console.log(str.match(regex)); // null

   const str2 = "ace";
   console.log(str2.match(regex)); // ["ace"]
   ```

In summary, `v8/src/regexp/regexp-ast.h` is a fundamental header file in V8 that lays the groundwork for how regular expressions are internally represented and processed. Understanding its structure can provide valuable insight into the inner workings of JavaScript's regular expression engine.

Prompt: 
```
这是目录为v8/src/regexp/regexp-ast.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-ast.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_REGEXP_REGEXP_AST_H_
#define V8_REGEXP_REGEXP_AST_H_

#include <optional>

#include "src/base/strings.h"
#include "src/regexp/regexp-flags.h"
#include "src/zone/zone-containers.h"
#include "src/zone/zone-list.h"
#include "src/zone/zone.h"

#ifdef V8_INTL_SUPPORT
#include "unicode/uniset.h"
#endif  // V8_INTL_SUPPORT

namespace v8::internal {

#define FOR_EACH_REG_EXP_TREE_TYPE(VISIT) \
  VISIT(Disjunction)                      \
  VISIT(Alternative)                      \
  VISIT(Assertion)                        \
  VISIT(ClassRanges)                      \
  VISIT(ClassSetOperand)                  \
  VISIT(ClassSetExpression)               \
  VISIT(Atom)                             \
  VISIT(Quantifier)                       \
  VISIT(Capture)                          \
  VISIT(Group)                            \
  VISIT(Lookaround)                       \
  VISIT(BackReference)                    \
  VISIT(Empty)                            \
  VISIT(Text)

#define FORWARD_DECLARE(Name) class RegExp##Name;
FOR_EACH_REG_EXP_TREE_TYPE(FORWARD_DECLARE)
#undef FORWARD_DECLARE

class RegExpCompiler;
class RegExpNode;
class RegExpTree;

class RegExpVisitor {
 public:
  virtual ~RegExpVisitor() = default;
#define MAKE_CASE(Name) \
  virtual void* Visit##Name(RegExp##Name*, void* data) = 0;
  FOR_EACH_REG_EXP_TREE_TYPE(MAKE_CASE)
#undef MAKE_CASE
};

// A simple closed interval.
class Interval {
 public:
  Interval() : from_(kNone), to_(kNone - 1) {}  // '- 1' for branchless size().
  Interval(int from, int to) : from_(from), to_(to) {}
  Interval Union(Interval that) {
    if (that.from_ == kNone) return *this;
    if (from_ == kNone) return that;
    return Interval(std::min(from_, that.from_), std::max(to_, that.to_));
  }

  static Interval Empty() { return Interval(); }

  bool Contains(int value) const { return (from_ <= value) && (value <= to_); }
  bool is_empty() const { return from_ == kNone; }
  int from() const { return from_; }
  int to() const { return to_; }
  int size() const { return to_ - from_ + 1; }

  static constexpr int kNone = -1;

 private:
  int from_;
  int to_;
};

// Named standard character sets.
enum class StandardCharacterSet : char {
  kWhitespace = 's',         // Like /\s/.
  kNotWhitespace = 'S',      // Like /\S/.
  kWord = 'w',               // Like /\w/.
  kNotWord = 'W',            // Like /\W/.
  kDigit = 'd',              // Like /\d/.
  kNotDigit = 'D',           // Like /\D/.
  kLineTerminator = 'n',     // The inverse of /./.
  kNotLineTerminator = '.',  // Like /./.
  kEverything = '*',         // Matches every character, like /./s.
};

// Represents code points (with values up to 0x10FFFF) in the range from from_
// to to_, both ends are inclusive.
class CharacterRange {
 public:
  CharacterRange() = default;
  // For compatibility with the CHECK_OK macro.
  CharacterRange(void* null) { DCHECK_NULL(null); }  // NOLINT

  static inline CharacterRange Singleton(base::uc32 value) {
    return CharacterRange(value, value);
  }
  static inline CharacterRange Range(base::uc32 from, base::uc32 to) {
    DCHECK(0 <= from && to <= kMaxCodePoint);
    DCHECK(static_cast<uint32_t>(from) <= static_cast<uint32_t>(to));
    return CharacterRange(from, to);
  }
  static inline CharacterRange Everything() {
    return CharacterRange(0, kMaxCodePoint);
  }

  static inline ZoneList<CharacterRange>* List(Zone* zone,
                                               CharacterRange range) {
    ZoneList<CharacterRange>* list =
        zone->New<ZoneList<CharacterRange>>(1, zone);
    list->Add(range, zone);
    return list;
  }

  // Add class escapes. Add case equivalent closure for \w and \W if necessary.
  V8_EXPORT_PRIVATE static void AddClassEscape(
      StandardCharacterSet standard_character_set,
      ZoneList<CharacterRange>* ranges, bool add_unicode_case_equivalents,
      Zone* zone);
  // Add case equivalents to ranges. Only used for /i, not for /ui or /vi, as
  // the semantics for unicode mode are slightly different.
  // See https://tc39.es/ecma262/#sec-runtime-semantics-canonicalize-ch Note 4.
  V8_EXPORT_PRIVATE static void AddCaseEquivalents(
      Isolate* isolate, Zone* zone, ZoneList<CharacterRange>* ranges,
      bool is_one_byte);
  // Add case equivalent code points to ranges. Only used for /ui and /vi, not
  // for /i, as the semantics for non-unicode mode are slightly different.
  // See https://tc39.es/ecma262/#sec-runtime-semantics-canonicalize-ch Note 4.
  static void AddUnicodeCaseEquivalents(ZoneList<CharacterRange>* ranges,
                                        Zone* zone);

  bool Contains(base::uc32 i) const { return from_ <= i && i <= to_; }
  base::uc32 from() const { return from_; }
  base::uc32 to() const { return to_; }
  bool IsEverything(base::uc32 max) const { return from_ == 0 && to_ >= max; }
  bool IsSingleton() const { return from_ == to_; }

  // Whether a range list is in canonical form: Ranges ordered by from value,
  // and ranges non-overlapping and non-adjacent.
  V8_EXPORT_PRIVATE static bool IsCanonical(
      const ZoneList<CharacterRange>* ranges);
  // Convert range list to canonical form. The characters covered by the ranges
  // will still be the same, but no character is in more than one range, and
  // adjacent ranges are merged. The resulting list may be shorter than the
  // original, but cannot be longer.
  static void Canonicalize(ZoneList<CharacterRange>* ranges);
  // Negate the contents of a character range in canonical form.
  static void Negate(const ZoneList<CharacterRange>* src,
                     ZoneList<CharacterRange>* dst, Zone* zone);
  // Intersect the contents of two character ranges in canonical form.
  static void Intersect(const ZoneList<CharacterRange>* lhs,
                        const ZoneList<CharacterRange>* rhs,
                        ZoneList<CharacterRange>* dst, Zone* zone);
  // Subtract the contents of |to_remove| from the contents of |src|.
  static void Subtract(const ZoneList<CharacterRange>* src,
                       const ZoneList<CharacterRange>* to_remove,
                       ZoneList<CharacterRange>* dst, Zone* zone);
  // Remove all ranges outside the one-byte range.
  static void ClampToOneByte(ZoneList<CharacterRange>* ranges);
  // Checks if two ranges (both need to be canonical) are equal.
  static bool Equals(const ZoneList<CharacterRange>* lhs,
                     const ZoneList<CharacterRange>* rhs);

 private:
  CharacterRange(base::uc32 from, base::uc32 to) : from_(from), to_(to) {}

  static constexpr int kMaxCodePoint = 0x10ffff;

  base::uc32 from_ = 0;
  base::uc32 to_ = 0;
};

inline bool operator==(const CharacterRange& lhs, const CharacterRange& rhs) {
  return lhs.from() == rhs.from() && lhs.to() == rhs.to();
}
inline bool operator!=(const CharacterRange& lhs, const CharacterRange& rhs) {
  return !operator==(lhs, rhs);
}

#define DECL_BOILERPLATE(Name)                                         \
  void* Accept(RegExpVisitor* visitor, void* data) override;           \
  RegExpNode* ToNode(RegExpCompiler* compiler, RegExpNode* on_success) \
      override;                                                        \
  RegExp##Name* As##Name() override;                                   \
  bool Is##Name() override

class RegExpTree : public ZoneObject {
 public:
  static const int kInfinity = kMaxInt;
  virtual ~RegExpTree() = default;
  virtual void* Accept(RegExpVisitor* visitor, void* data) = 0;
  virtual RegExpNode* ToNode(RegExpCompiler* compiler,
                             RegExpNode* on_success) = 0;
  virtual bool IsTextElement() { return false; }
  virtual bool IsAnchoredAtStart() { return false; }
  virtual bool IsAnchoredAtEnd() { return false; }
  virtual int min_match() = 0;
  virtual int max_match() = 0;
  // Returns the interval of registers used for captures within this
  // expression.
  virtual Interval CaptureRegisters() { return Interval::Empty(); }
  virtual void AppendToText(RegExpText* text, Zone* zone);
  V8_EXPORT_PRIVATE std::ostream& Print(std::ostream& os, Zone* zone);
#define MAKE_ASTYPE(Name)           \
  virtual RegExp##Name* As##Name(); \
  virtual bool Is##Name();
  FOR_EACH_REG_EXP_TREE_TYPE(MAKE_ASTYPE)
#undef MAKE_ASTYPE
};

class RegExpDisjunction final : public RegExpTree {
 public:
  explicit RegExpDisjunction(ZoneList<RegExpTree*>* alternatives);

  DECL_BOILERPLATE(Disjunction);

  Interval CaptureRegisters() override;
  bool IsAnchoredAtStart() override;
  bool IsAnchoredAtEnd() override;
  int min_match() override { return min_match_; }
  int max_match() override { return max_match_; }
  ZoneList<RegExpTree*>* alternatives() const { return alternatives_; }

 private:
  bool SortConsecutiveAtoms(RegExpCompiler* compiler);
  void RationalizeConsecutiveAtoms(RegExpCompiler* compiler);
  void FixSingleCharacterDisjunctions(RegExpCompiler* compiler);
  ZoneList<RegExpTree*>* alternatives_;
  int min_match_;
  int max_match_;
};

class RegExpAlternative final : public RegExpTree {
 public:
  explicit RegExpAlternative(ZoneList<RegExpTree*>* nodes);

  DECL_BOILERPLATE(Alternative);

  Interval CaptureRegisters() override;
  bool IsAnchoredAtStart() override;
  bool IsAnchoredAtEnd() override;
  int min_match() override { return min_match_; }
  int max_match() override { return max_match_; }
  ZoneList<RegExpTree*>* nodes() const { return nodes_; }

 private:
  ZoneList<RegExpTree*>* nodes_;
  int min_match_;
  int max_match_;
};

class RegExpAssertion final : public RegExpTree {
 public:
  enum class Type {
    START_OF_LINE = 0,
    START_OF_INPUT = 1,
    END_OF_LINE = 2,
    END_OF_INPUT = 3,
    BOUNDARY = 4,
    NON_BOUNDARY = 5,
    LAST_ASSERTION_TYPE = NON_BOUNDARY,
  };
  explicit RegExpAssertion(Type type) : assertion_type_(type) {}

  DECL_BOILERPLATE(Assertion);

  bool IsAnchoredAtStart() override;
  bool IsAnchoredAtEnd() override;
  int min_match() override { return 0; }
  int max_match() override { return 0; }
  Type assertion_type() const { return assertion_type_; }

 private:
  const Type assertion_type_;
};

class CharacterSet final {
 public:
  explicit CharacterSet(StandardCharacterSet standard_set_type)
      : standard_set_type_(standard_set_type) {}
  explicit CharacterSet(ZoneList<CharacterRange>* ranges) : ranges_(ranges) {}

  ZoneList<CharacterRange>* ranges(Zone* zone);
  StandardCharacterSet standard_set_type() const {
    return standard_set_type_.value();
  }
  void set_standard_set_type(StandardCharacterSet standard_set_type) {
    standard_set_type_ = standard_set_type;
  }
  bool is_standard() const { return standard_set_type_.has_value(); }
  V8_EXPORT_PRIVATE void Canonicalize();

 private:
  ZoneList<CharacterRange>* ranges_ = nullptr;
  std::optional<StandardCharacterSet> standard_set_type_;
};

class RegExpClassRanges final : public RegExpTree {
 public:
  // NEGATED: The character class is negated and should match everything but
  //     the specified ranges.
  // CONTAINS_SPLIT_SURROGATE: The character class contains part of a split
  //     surrogate and should not be unicode-desugared (crbug.com/641091).
  // IS_CASE_FOLDED: If case folding is required (/i), it was already
  //     performed on individual ranges and should not be applied again.
  enum Flag {
    NEGATED = 1 << 0,
    CONTAINS_SPLIT_SURROGATE = 1 << 1,
    IS_CASE_FOLDED = 1 << 2,
  };
  using ClassRangesFlags = base::Flags<Flag>;

  RegExpClassRanges(Zone* zone, ZoneList<CharacterRange>* ranges,
                    ClassRangesFlags class_ranges_flags = ClassRangesFlags())
      : set_(ranges), class_ranges_flags_(class_ranges_flags) {
    // Convert the empty set of ranges to the negated Everything() range.
    if (ranges->is_empty()) {
      ranges->Add(CharacterRange::Everything(), zone);
      class_ranges_flags_ ^= NEGATED;
    }
  }
  explicit RegExpClassRanges(StandardCharacterSet standard_set_type)
      : set_(standard_set_type), class_ranges_flags_() {}

  DECL_BOILERPLATE(ClassRanges);

  bool IsTextElement() override { return true; }
  int min_match() override { return 1; }
  // The character class may match two code units for unicode regexps.
  // TODO(yangguo): we should split this class for usage in TextElement, and
  //                make max_match() dependent on the character class content.
  int max_match() override { return 2; }

  void AppendToText(RegExpText* text, Zone* zone) override;

  // TODO(lrn): Remove need for complex version if is_standard that
  // recognizes a mangled standard set and just do { return set_.is_special(); }
  bool is_standard(Zone* zone);
  // Returns a value representing the standard character set if is_standard()
  // returns true.
  StandardCharacterSet standard_type() const {
    return set_.standard_set_type();
  }

  CharacterSet character_set() const { return set_; }
  ZoneList<CharacterRange>* ranges(Zone* zone) { return set_.ranges(zone); }

  bool is_negated() const { return (class_ranges_flags_ & NEGATED) != 0; }
  bool contains_split_surrogate() const {
    return (class_ranges_flags_ & CONTAINS_SPLIT_SURROGATE) != 0;
  }
  bool is_case_folded() const {
    return (class_ranges_flags_ & IS_CASE_FOLDED) != 0;
  }

 private:
  CharacterSet set_;
  ClassRangesFlags class_ranges_flags_;
};

struct CharacterClassStringLess {
  bool operator()(base::Vector<const base::uc32> lhs,
                  base::Vector<const base::uc32> rhs) const {
    // Longer strings first so we generate matches for the largest string
    // possible.
    if (lhs.length() != rhs.length()) {
      return lhs.length() > rhs.length();
    }
    for (int i = 0; i < lhs.length(); i++) {
      if (lhs[i] != rhs[i]) {
        return lhs[i] < rhs[i];
      }
    }
    return false;
  }
};

// A type used for strings as part of character classes (only possible in
// unicode sets mode).
// We use a ZoneMap instead of an UnorderedZoneMap because we need to match
// the longest alternatives first. By using a ZoneMap with the custom comparator
// we can avoid sorting before assembling the code.
// Strings are likely short (the largest string in current unicode properties
// consists of 10 code points).
using CharacterClassStrings = ZoneMap<base::Vector<const base::uc32>,
                                      RegExpTree*, CharacterClassStringLess>;

// TODO(pthier): If we are sure we don't want to use icu::UnicodeSets
// (performance evaluation pending), this class can be merged with
// RegExpClassRanges.
class RegExpClassSetOperand final : public RegExpTree {
 public:
  RegExpClassSetOperand(ZoneList<CharacterRange>* ranges,
                        CharacterClassStrings* strings);

  DECL_BOILERPLATE(ClassSetOperand);

  bool IsTextElement() override { return true; }
  int min_match() override { return min_match_; }
  int max_match() override { return max_match_; }

  void Union(RegExpClassSetOperand* other, Zone* zone);
  void Intersect(RegExpClassSetOperand* other,
                 ZoneList<CharacterRange>* temp_ranges, Zone* zone);
  void Subtract(RegExpClassSetOperand* other,
                ZoneList<CharacterRange>* temp_ranges, Zone* zone);

  bool has_strings() const { return strings_ != nullptr && !strings_->empty(); }
  ZoneList<CharacterRange>* ranges() { return ranges_; }
  CharacterClassStrings* strings() {
    DCHECK_NOT_NULL(strings_);
    return strings_;
  }

 private:
  ZoneList<CharacterRange>* ranges_;
  CharacterClassStrings* strings_;
  int min_match_;
  int max_match_;
};

class RegExpClassSetExpression final : public RegExpTree {
 public:
  enum class OperationType { kUnion, kIntersection, kSubtraction };

  RegExpClassSetExpression(OperationType op, bool is_negated,
                           bool may_contain_strings,
                           ZoneList<RegExpTree*>* operands);

  DECL_BOILERPLATE(ClassSetExpression);

  // Create an empty class set expression (matches everything if |is_negated|,
  // nothing otherwise).
  static RegExpClassSetExpression* Empty(Zone* zone, bool is_negated);

  bool IsTextElement() override { return true; }
  int min_match() override { return 0; }
  int max_match() override { return max_match_; }

  OperationType operation() const { return operation_; }
  bool is_negated() const { return is_negated_; }
  bool may_contain_strings() const { return may_contain_strings_; }
  const ZoneList<RegExpTree*>* operands() const { return operands_; }
  ZoneList<RegExpTree*>* operands() { return operands_; }

 private:
  // Recursively evaluates the tree rooted at |root|, computing the valid
  // CharacterRanges and strings after applying all set operations.
  // The original tree will be modified by this method, so don't store pointers
  // to inner nodes of the tree somewhere else!
  // Modifying the tree in-place saves memory and speeds up multiple calls of
  // the method (e.g. when unrolling quantifiers).
  // |temp_ranges| is used for intermediate results, passed as parameter to
  // avoid allocating new lists all the time.
  static RegExpClassSetOperand* ComputeExpression(
      RegExpTree* root, ZoneList<CharacterRange>* temp_ranges, Zone* zone);

  const OperationType operation_;
  bool is_negated_;
  const bool may_contain_strings_;
  ZoneList<RegExpTree*>* operands_ = nullptr;
  int max_match_;
};

class RegExpAtom final : public RegExpTree {
 public:
  explicit RegExpAtom(base::Vector<const base::uc16> data) : data_(data) {}

  DECL_BOILERPLATE(Atom);

  bool IsTextElement() override { return true; }
  int min_match() override { return data_.length(); }
  int max_match() override { return data_.length(); }
  void AppendToText(RegExpText* text, Zone* zone) override;

  base::Vector<const base::uc16> data() const { return data_; }
  int length() const { return data_.length(); }

 private:
  base::Vector<const base::uc16> data_;
};

class TextElement final {
 public:
  enum TextType { ATOM, CLASS_RANGES };

  static TextElement Atom(RegExpAtom* atom);
  static TextElement ClassRanges(RegExpClassRanges* class_ranges);

  int cp_offset() const { return cp_offset_; }
  void set_cp_offset(int cp_offset) { cp_offset_ = cp_offset; }
  int length() const;

  TextType text_type() const { return text_type_; }

  RegExpTree* tree() const { return tree_; }

  RegExpAtom* atom() const {
    DCHECK(text_type() == ATOM);
    return reinterpret_cast<RegExpAtom*>(tree());
  }

  RegExpClassRanges* class_ranges() const {
    DCHECK(text_type() == CLASS_RANGES);
    return reinterpret_cast<RegExpClassRanges*>(tree());
  }

 private:
  TextElement(TextType text_type, RegExpTree* tree)
      : cp_offset_(-1), text_type_(text_type), tree_(tree) {}

  int cp_offset_;
  TextType text_type_;
  RegExpTree* tree_;
};

class RegExpText final : public RegExpTree {
 public:
  explicit RegExpText(Zone* zone) : elements_(2, zone) {}

  DECL_BOILERPLATE(Text);

  bool IsTextElement() override { return true; }
  int min_match() override { return length_; }
  int max_match() override { return length_; }
  void AppendToText(RegExpText* text, Zone* zone) override;
  void AddElement(TextElement elm, Zone* zone) {
    elements_.Add(elm, zone);
    length_ += elm.length();
  }
  ZoneList<TextElement>* elements() { return &elements_; }

 private:
  ZoneList<TextElement> elements_;
  int length_ = 0;
};

class RegExpQuantifier final : public RegExpTree {
 public:
  enum QuantifierType { GREEDY, NON_GREEDY, POSSESSIVE };
  RegExpQuantifier(int min, int max, QuantifierType type, int index,
                   RegExpTree* body)
      : body_(body),
        min_(min),
        max_(max),
        quantifier_type_(type),
        index_(index) {
    if (min > 0 && body->min_match() > kInfinity / min) {
      min_match_ = kInfinity;
    } else {
      min_match_ = min * body->min_match();
    }
    if (max > 0 && body->max_match() > kInfinity / max) {
      max_match_ = kInfinity;
    } else {
      max_match_ = max * body->max_match();
    }
  }

  DECL_BOILERPLATE(Quantifier);

  static RegExpNode* ToNode(int min, int max, bool is_greedy, RegExpTree* body,
                            RegExpCompiler* compiler, RegExpNode* on_success,
                            bool not_at_start = false);
  Interval CaptureRegisters() override;
  int min_match() override { return min_match_; }
  int max_match() override { return max_match_; }
  int min() const { return min_; }
  int max() const { return max_; }
  QuantifierType quantifier_type() const { return quantifier_type_; }
  int index() const { return index_; }
  bool is_possessive() const { return quantifier_type_ == POSSESSIVE; }
  bool is_non_greedy() const { return quantifier_type_ == NON_GREEDY; }
  bool is_greedy() const { return quantifier_type_ == GREEDY; }
  RegExpTree* body() const { return body_; }

 private:
  RegExpTree* body_;
  int min_;
  int max_;
  int min_match_;
  int max_match_;
  QuantifierType quantifier_type_;
  int index_;
};

class RegExpCapture final : public RegExpTree {
 public:
  explicit RegExpCapture(int index)
      : body_(nullptr),
        index_(index),
        min_match_(0),
        max_match_(0),
        name_(nullptr) {}

  DECL_BOILERPLATE(Capture);

  static RegExpNode* ToNode(RegExpTree* body, int index,
                            RegExpCompiler* compiler, RegExpNode* on_success);
  bool IsAnchoredAtStart() override;
  bool IsAnchoredAtEnd() override;
  Interval CaptureRegisters() override;
  int min_match() override { return min_match_; }
  int max_match() override { return max_match_; }
  RegExpTree* body() { return body_; }
  void set_body(RegExpTree* body) {
    body_ = body;
    min_match_ = body->min_match();
    max_match_ = body->max_match();
  }
  int index() const { return index_; }
  const ZoneVector<base::uc16>* name() const { return name_; }
  void set_name(const ZoneVector<base::uc16>* name) { name_ = name; }
  static int StartRegister(int index) { return index * 2; }
  static int EndRegister(int index) { return index * 2 + 1; }

 private:
  RegExpTree* body_ = nullptr;
  int index_;
  int min_match_ = 0;
  int max_match_ = 0;
  const ZoneVector<base::uc16>* name_ = nullptr;
};

class RegExpGroup final : public RegExpTree {
 public:
  explicit RegExpGroup(RegExpTree* body, RegExpFlags flags)
      : body_(body),
        flags_(flags),
        min_match_(body->min_match()),
        max_match_(body->max_match()) {}

  DECL_BOILERPLATE(Group);

  bool IsAnchoredAtStart() override { return body_->IsAnchoredAtStart(); }
  bool IsAnchoredAtEnd() override { return body_->IsAnchoredAtEnd(); }
  int min_match() override { return min_match_; }
  int max_match() override { return max_match_; }
  Interval CaptureRegisters() override { return body_->CaptureRegisters(); }
  RegExpTree* body() const { return body_; }
  RegExpFlags flags() const { return flags_; }

 private:
  RegExpTree* body_;
  const RegExpFlags flags_;
  int min_match_;
  int max_match_;
};

class RegExpLookaround final : public RegExpTree {
 public:
  enum Type { LOOKAHEAD, LOOKBEHIND };

  RegExpLookaround(RegExpTree* body, bool is_positive, int capture_count,
                   int capture_from, Type type, int index)
      : body_(body),
        is_positive_(is_positive),
        capture_count_(capture_count),
        capture_from_(capture_from),
        type_(type),
        index_(index) {}

  DECL_BOILERPLATE(Lookaround);

  Interval CaptureRegisters() override;
  bool IsAnchoredAtStart() override;
  int min_match() override { return 0; }
  int max_match() override { return 0; }
  RegExpTree* body() const { return body_; }
  bool is_positive() const { return is_positive_; }
  int capture_count() const { return capture_count_; }
  int capture_from() const { return capture_from_; }
  Type type() const { return type_; }
  int index() const { return index_; }

  class Builder {
   public:
    Builder(bool is_positive, RegExpNode* on_success,
            int stack_pointer_register, int position_register,
            int capture_register_count = 0, int capture_register_start = 0);
    RegExpNode* on_match_success() const { return on_match_success_; }
    RegExpNode* ForMatch(RegExpNode* match);

   private:
    bool is_positive_;
    RegExpNode* on_match_success_;
    RegExpNode* on_success_;
    int stack_pointer_register_;
    int position_register_;
  };

 private:
  RegExpTree* body_;
  bool is_positive_;
  int capture_count_;
  int capture_from_;
  Type type_;
  int index_;
};

class RegExpBackReference final : public RegExpTree {
 public:
  explicit RegExpBackReference(Zone* zone) : captures_(1, zone) {}
  explicit RegExpBackReference(RegExpCapture* capture, Zone* zone)
      : captures_(1, zone) {
    captures_.Add(capture, zone);
  }

  DECL_BOILERPLATE(BackReference);

  int min_match() override { return 0; }
  // The back reference may be recursive, e.g. /(\2)(\1)/. To avoid infinite
  // recursion, we give up. Ignorance is bliss.
  int max_match() override { return kInfinity; }
  const ZoneList<RegExpCapture*>* captures() const { return &captures_; }
  void add_capture(RegExpCapture* capture, Zone* zone) {
    captures_.Add(capture, zone);
  }
  const ZoneVector<base::uc16>* name() const { return name_; }
  void set_name(const ZoneVector<base::uc16>* name) { name_ = name; }

 private:
  ZoneList<RegExpCapture*> captures_;
  const ZoneVector<base::uc16>* name_ = nullptr;
};

class RegExpEmpty final : public RegExpTree {
 public:
  DECL_BOILERPLATE(Empty);
  int min_match() override { return 0; }
  int max_match() override { return 0; }
};

}  // namespace v8::internal

#undef DECL_BOILERPLATE

#endif  // V8_REGEXP_REGEXP_AST_H_

"""

```