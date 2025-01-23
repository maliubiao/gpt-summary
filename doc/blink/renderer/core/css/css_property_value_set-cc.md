Response:
My thinking process to answer the request about `css_property_value_set.cc` went something like this:

1. **Understand the Core Request:** The user wants to understand the functionality of this specific Chromium/Blink source code file. They are particularly interested in its relationship to HTML, CSS, and JavaScript, as well as potential usage errors and debugging.

2. **Initial Skim and Keyword Identification:** I quickly skimmed the code, looking for prominent classes, methods, and data structures. Keywords like `CSSPropertyValueSet`, `MutableCSSPropertyValueSet`, `ImmutableCSSPropertyValueSet`, `CSSPropertyID`, `CSSValue`, `CSSParser`, `Serialize`, `Remove`, `Set`, and `Hash` immediately jumped out. These give strong hints about the file's purpose.

3. **Identify the Main Classes:** The presence of `CSSPropertyValueSet`, and its mutable and immutable variations, suggests this is the central data structure. This likely represents a collection of CSS properties and their values.

4. **Deduce Core Functionality:** Based on the keywords and class names, I inferred the primary functions:
    * **Storage:**  Holding CSS properties and their values.
    * **Parsing:** Converting CSS text into the internal representation.
    * **Serialization:** Converting the internal representation back to CSS text.
    * **Modification:** Adding, removing, and updating properties.
    * **Querying:**  Retrieving property values and metadata.
    * **Comparison:** Checking for equality between property sets.
    * **Immutability:** Supporting both mutable and immutable versions for performance or data integrity.

5. **Analyze Relationships with HTML, CSS, and JavaScript:**
    * **CSS:** This file is fundamentally about CSS. It directly deals with CSS properties, values, parsing, and serialization. The examples of setting properties like `color`, `font-size`, and custom properties illustrate this.
    * **HTML:**  The file is part of the rendering engine, which processes HTML to determine the structure and content of web pages. CSS styles are applied to HTML elements. The connection is that this file manages the *styling information* that affects how HTML is displayed. The example of inline styles (`<div style="...">`) shows a direct link.
    * **JavaScript:** JavaScript can interact with CSS in various ways:
        * Reading and modifying inline styles (`element.style`).
        * Accessing computed styles (`getComputedStyle`).
        * Manipulating CSS classes.
        The `EnsureCSSStyleDeclaration` method hints at the creation of a JavaScript-accessible `CSSStyleDeclaration` object, forming a bridge between the C++ rendering engine and JavaScript.

6. **Consider Logic and Assumptions:**  I looked for areas where the code made decisions or had specific logic:
    * **Importance:** The handling of `!important` flags is evident in methods like `ParseAndSetProperty` and `PropertyIsImportant`.
    * **Shorthands:** The code handles CSS shorthand properties (e.g., `margin`). The `SerializeShorthand` and `RemoveShorthandProperty` methods are key here.
    * **Custom Properties:**  The code explicitly supports CSS custom properties (variables).
    * **Logical Properties:** The `may_have_logical_properties_` flag and related logic suggest handling of properties like `marginStart` which map differently based on writing direction.
    * **Immutability:**  The distinction between mutable and immutable sets and the `ImmutableCopyIfNeeded` method is a significant piece of logic.
    * **Hashing:** The `ComputeHash` method suggests this data structure is used in scenarios where efficient comparisons or lookups are needed (e.g., caching).

7. **Think About User/Programming Errors:**  I considered common mistakes developers might make when working with CSS:
    * **Invalid CSS Syntax:**  Trying to set a property to an invalid value. The parser would handle this.
    * **Incorrect Property Names:**  Typing a CSS property name wrong. The parser would likely ignore it.
    * **Overriding Styles:** Understanding how CSS specificity and the cascade work is crucial to avoid unexpected results. While this file doesn't *enforce* the cascade, it manages the properties that participate in it.
    * **Misunderstanding Shorthands:**  Not realizing that setting a longhand property after a shorthand can override parts of the shorthand.

8. **Construct Debugging Scenarios:** I thought about how a developer might end up examining this code:
    * **Investigating Styling Issues:** If an element isn't styled as expected, a developer might inspect the computed styles in the browser's DevTools. This would lead back to the code responsible for managing those styles.
    * **Performance Analysis:** If rendering performance is slow, a developer might profile the code and find hotspots in CSS processing.
    * **Debugging Layout Issues:**  Incorrect styles can lead to layout problems, prompting developers to examine the CSSOM.
    * **Contributing to Blink:** Someone working on the rendering engine itself would naturally encounter this code.

9. **Structure the Answer:** Finally, I organized the information logically, using headings and bullet points to make it easy to read. I started with a general overview of the file's functionality and then delved into specific aspects like its relationship to HTML, CSS, JavaScript, potential errors, and debugging. I made sure to include concrete examples to illustrate the concepts. I also tried to mimic the request's structure by including sections on functionality, relationships, logic/assumptions, errors, and debugging.

By following these steps, I was able to generate a comprehensive and informative answer that addresses the user's request in detail. The process involved understanding the code's purpose, identifying key components, inferring functionality, and connecting it to the broader web development context.
This C++ source file, `blink/renderer/core/css/css_property_value_set.cc`, is a core component of the Blink rendering engine responsible for **managing a set of CSS properties and their corresponding values** for a specific element or style rule. It's essentially a container that holds the styling information.

Here's a breakdown of its functionalities:

**Core Functionalities:**

* **Storing CSS Properties and Values:**  The central purpose is to hold key-value pairs where the key is a CSS property (e.g., `color`, `font-size`, `margin-left`) and the value is the parsed CSS value (e.g., `red`, `16px`, `10px`). It supports both standard CSS properties and custom CSS properties (variables).
* **Representing Mutability and Immutability:**  It provides two main classes:
    * `MutableCSSPropertyValueSet`:  Allows modification of the stored properties and values. This is used when styles are being actively parsed, applied, or changed.
    * `ImmutableCSSPropertyValueSet`: Represents a read-only set of properties and values. This is often used for performance optimization when the style information doesn't need to be changed.
* **Parsing CSS:** It integrates with the CSS parsing logic (`CSSParser`) to take CSS text (from stylesheets or inline styles) and populate the property-value set.
* **Serialization of CSS:** It can serialize the stored properties and values back into CSS text format. This is used for things like getting the computed style of an element or generating CSS strings.
* **Handling Property Importance (`!important`):**  It keeps track of whether a property has the `!important` flag set.
* **Managing Shorthand Properties:** It understands CSS shorthand properties (like `margin`, `padding`, `background`) and can expand them into their longhand equivalents. It also provides mechanisms to remove shorthand properties, which implicitly removes their constituent longhand properties.
* **Looking up Properties:**  It provides efficient ways to find a specific property by its ID or name.
* **Comparing Property Sets:** It allows for comparing two `CSSPropertyValueSet` instances to check if they have the same properties and values.
* **Hashing:** It can compute a hash value for the property set, which is useful for caching and optimization.
* **Handling Logical Properties:**  It has logic to deal with CSS logical properties (like `marginStart`, `borderInlineStart`) that map to physical properties based on writing direction.
* **Supporting Custom Properties (CSS Variables):** It can store and retrieve custom properties.

**Relationship with JavaScript, HTML, and CSS:**

This file is deeply intertwined with the core functionality of how web browsers process HTML and CSS, and how JavaScript can interact with them.

* **CSS:** This file is *the* central representation of CSS styles within the Blink rendering engine. It's where the parsed CSS rules ultimately reside before being used to determine the visual appearance of HTML elements. Every CSS property and value you can define in a stylesheet or inline style will eventually be represented within a `CSSPropertyValueSet` (or one of its subclasses).

    * **Example:** When the browser encounters the CSS rule `p { color: blue; font-size: 16px; }`, the parser will create a `CSSPropertyValueSet` containing the properties `color` with the value `blue` and `font-size` with the value `16px`.

* **HTML:** When the browser parses an HTML document, it encounters style information in various places:
    * **`<style>` tags:**  CSS rules within these tags are parsed and their properties and values are stored in `CSSPropertyValueSet` objects associated with the stylesheet.
    * **`<link>` tags (external stylesheets):**  The content of linked CSS files is parsed similarly.
    * **`style` attribute (inline styles):**  The CSS declarations within the `style` attribute of an HTML element are parsed and stored in a `CSSPropertyValueSet` directly attached to that element.

    * **Example:** For the HTML snippet `<div style="background-color: red;"></div>`, a `MutableCSSPropertyValueSet` would be created for this `div` element, containing the property `background-color` with the value `red`.

* **JavaScript:** JavaScript can interact with the styles of HTML elements through the Document Object Model (DOM).

    * **`element.style`:** Accessing the `style` property of an HTML element in JavaScript returns a `CSSStyleDeclaration` object. Internally, this `CSSStyleDeclaration` often wraps a `MutableCSSPropertyValueSet`. JavaScript can then read and modify individual CSS properties:
        ```javascript
        const myDiv = document.getElementById('myDiv');
        myDiv.style.color = 'green'; // Internally modifies the CSSPropertyValueSet
        console.log(myDiv.style.fontSize); // Reads from the CSSPropertyValueSet
        ```
    * **`window.getComputedStyle(element)`:** This method returns a `CSSStyleDeclaration` object representing the *final* computed styles of an element after applying all relevant stylesheets and inline styles. This computed style is often derived from an `ImmutableCSSPropertyValueSet`.
    * **Manipulating CSS classes:** Adding or removing CSS classes using JavaScript can indirectly lead to changes in the `CSSPropertyValueSet` associated with an element, as different CSS rules become applicable.

**Logical Reasoning (Hypothetical Input & Output):**

Let's imagine the following CSS rule being processed:

**Hypothetical Input (CSS Text):**

```css
.my-element {
  color: purple !important;
  font-size: 18px;
  margin: 10px 20px;
}
```

**Processing Steps:**

1. The CSS parser encounters this rule.
2. A `MutableCSSPropertyValueSet` is created for the `.my-element` rule.
3. The parser processes `color: purple !important;`:
   * The property ID for `color` is determined.
   * The value `purple` is parsed.
   * The `important` flag is set to `true`.
   * A `CSSPropertyValue` object is created and added to the set.
4. The parser processes `font-size: 18px;`:
   * The property ID for `font-size` is determined.
   * The value `18px` is parsed.
   * A `CSSPropertyValue` object is created and added.
5. The parser processes `margin: 10px 20px;`:
   * The property ID for `margin` (a shorthand) is determined.
   * The values `10px` and `20px` are parsed.
   * The shorthand is expanded into its longhand properties: `margin-top`, `margin-bottom` (both with `10px`), `margin-right`, and `margin-left` (both with `20px`).
   * Corresponding `CSSPropertyValue` objects for each longhand property are created and added.

**Hypothetical Output (Internal Representation in `MutableCSSPropertyValueSet`):**

The `MutableCSSPropertyValueSet` would contain (the order might not be strictly guaranteed):

* `color`: `purple` (important: true)
* `font-size`: `18px`
* `margin-top`: `10px`
* `margin-right`: `20px`
* `margin-bottom`: `10px`
* `margin-left`: `20px`

**User or Programming Common Usage Errors:**

* **Setting an invalid CSS value:** If a user (or JavaScript code) tries to set a CSS property to a syntactically incorrect value, the parsing process might fail, or the value might be ignored.
    * **Example:** `element.style.width = 'abc';`  The CSS parser within Blink would likely reject 'abc' as an invalid width value.
* **Misspelling CSS property names:** If a property name is misspelled, the browser will treat it as an unknown property and ignore it. This won't typically cause an error in the `CSSPropertyValueSet` itself, but the intended style won't be applied.
    * **Example:** `element.style.collor = 'red';` (incorrect spelling of `color`).
* **Not understanding CSS specificity:** Developers might set a style expecting it to apply, but it gets overridden by another rule with higher specificity. While `CSSPropertyValueSet` stores the properties, it doesn't directly handle the cascade or specificity rules. That's handled in other parts of the rendering engine.
* **Incorrectly manipulating shorthand properties:**  Setting a longhand property after a shorthand can sometimes lead to unexpected results if the developer doesn't understand how shorthands expand.
    * **Example:**
        ```css
        .my-element {
          margin: 10px; /* Sets all margins to 10px */
          margin-top: 20px; /* Overrides the margin-top set by the shorthand */
        }
        ```
* **Forgetting `px` or other units:**  Many CSS properties require units. Omitting them can lead to the style being ignored.
    * **Example:** `element.style.fontSize = '16';` (missing `px`).

**User Operation Steps to Reach This Code (Debugging Clues):**

A developer might end up looking at this code for various reasons during debugging:

1. **Inspecting Computed Styles:** A developer notices an element isn't styled as expected and uses the browser's developer tools to inspect the "Computed" style panel. This panel shows the final styles applied to the element. To generate this information, the browser internally uses the `CSSPropertyValueSet` to collect all relevant styles.
2. **Debugging a Layout Issue:**  Incorrect CSS styles can lead to layout problems. A developer might investigate the computed styles or the CSS rules applying to an element to understand why it's not positioned or sized correctly.
3. **Investigating JavaScript Style Manipulation:** If JavaScript code that manipulates `element.style` isn't working as intended, a developer might step through the JavaScript code and then want to understand how those changes are reflected internally, potentially leading them to the `CSSPropertyValueSet`.
4. **Performance Profiling:** If the browser is experiencing performance issues related to rendering, a developer might use profiling tools. These tools might highlight the time spent in CSS parsing, style calculation, or property access, potentially leading them to investigate `CSSPropertyValueSet` as a key data structure involved in these processes.
5. **Contributing to the Blink Rendering Engine:** A developer working on the Blink engine itself would need to understand this code to modify or extend its functionality.
6. **Examining a Crash or Bug Report:** A bug report might point to issues related to style application or inheritance. To understand the root cause, developers might examine the code responsible for managing CSS properties and values.

In essence, any situation where a developer needs to understand how CSS styles are applied to an HTML element, how JavaScript interacts with those styles, or needs to debug issues related to rendering or performance might lead them to explore the code within `css_property_value_set.cc`.

### 提示词
```
这是目录为blink/renderer/core/css/css_property_value_set.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * (C) 1999-2003 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012, 2013 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2011 Research In Motion Limited. All rights reserved.
 * Copyright (C) 2013 Intel Corporation. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
#include "third_party/blink/renderer/core/css/css_property_value_set.h"

#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/property_bitsets.h"
#include "third_party/blink/renderer/core/css/style_property_serializer.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

#ifndef NDEBUG
#include <stdio.h>
#endif

namespace blink {

static AdditionalBytes
AdditionalBytesForImmutableCSSPropertyValueSetWithPropertyCount(
    unsigned count) {
  return AdditionalBytes(
      base::bits::AlignUp(sizeof(Member<CSSValue>) * count,
                          alignof(CSSPropertyValueMetadata)) +
      sizeof(CSSPropertyValueMetadata) * count);
}

ImmutableCSSPropertyValueSet* ImmutableCSSPropertyValueSet::Create(
    base::span<const CSSPropertyValue> properties,
    CSSParserMode css_parser_mode,
    bool contains_cursor_hand) {
  DCHECK_LE(properties.size(), static_cast<unsigned>(kMaxArraySize));
  return MakeGarbageCollected<ImmutableCSSPropertyValueSet>(
      AdditionalBytesForImmutableCSSPropertyValueSetWithPropertyCount(
          properties.size()),
      PassKey(), properties, css_parser_mode, contains_cursor_hand);
}

ImmutableCSSPropertyValueSet* CSSPropertyValueSet::ImmutableCopyIfNeeded()
    const {
  auto* immutable_property_set = DynamicTo<ImmutableCSSPropertyValueSet>(
      const_cast<CSSPropertyValueSet*>(this));
  if (immutable_property_set) {
    return immutable_property_set;
  }

  const auto* mutable_this = To<MutableCSSPropertyValueSet>(this);
  return ImmutableCSSPropertyValueSet::Create(
      base::span(mutable_this->property_vector_), CssParserMode());
}

unsigned CSSPropertyValueSet::ComputeHash() const {
  unsigned hash = 3141592653;

  const unsigned num_properties = PropertyCount();
  for (unsigned i = 0; i < num_properties; ++i) {
    const PropertyReference property = PropertyAt(i);

    if (property.Id() == CSSPropertyID::kVariable) {
      WTF::AddIntToHash(hash, property.Name().ToAtomicString().Hash());
    } else {
      WTF::AddIntToHash(hash, static_cast<unsigned>(property.Id()));
    }
    WTF::AddIntToHash(hash, property.IsImportant());
    WTF::AddIntToHash(hash, property.Value().Hash());
  }

  static_assert((WTF::HashTraits<unsigned>::EmptyValue() ^ 0x80000000) !=
                    WTF::HashTraits<unsigned>::DeletedValue(),
                "We assume below that flipping the top bit will not turn "
                "EmptyValue into DeletedValue or vice versa");
  if (hash == WTF::HashTraits<unsigned>::EmptyValue() ||
      hash == WTF::HashTraits<unsigned>::DeletedValue()) {
    hash ^= 0x80000000;
  }

  return hash;
}

bool CSSPropertyValueSet::ContentsEqual(
    const CSSPropertyValueSet& other) const {
  const unsigned num_properties = PropertyCount();
  if (num_properties != other.PropertyCount()) {
    return false;
  }

  for (unsigned i = 0; i < num_properties; ++i) {
    if (!(PropertyAt(i) == other.PropertyAt(i))) {
      return false;
    }
  }

  return true;
}

MutableCSSPropertyValueSet::MutableCSSPropertyValueSet(
    CSSParserMode css_parser_mode)
    : CSSPropertyValueSet(css_parser_mode) {}

MutableCSSPropertyValueSet::MutableCSSPropertyValueSet(
    base::span<const CSSPropertyValue> properties)
    : CSSPropertyValueSet(kHTMLStandardMode) {
  property_vector_.ReserveInitialCapacity(properties.size());
  for (const CSSPropertyValue& property : properties) {
    property_vector_.UncheckedAppend(property);
    may_have_logical_properties_ |= kLogicalGroupProperties.Has(property.Id());
  }
}

ImmutableCSSPropertyValueSet::ImmutableCSSPropertyValueSet(
    PassKey,
    base::span<const CSSPropertyValue> properties,
    CSSParserMode css_parser_mode,
    bool contains_query_hand)
    : CSSPropertyValueSet(css_parser_mode,
                          properties.size(),
                          contains_query_hand) {
  if (array_size_ > 0) {
    // SAFETY: By funneling all allocation of ImmutableCSSPropertyValueSet
    // through Create(), we guarantee that the arrays will have storage where we
    // expect.
    UNSAFE_BUFFERS(base::span<CSSPropertyValueMetadata> metadata_array(
        const_cast<CSSPropertyValueMetadata*>(MetadataArrayBase()),
        array_size_));
    UNSAFE_BUFFERS(base::span<Member<const CSSValue>> value_array(
        const_cast<Member<const CSSValue>*>(ValueArrayBase()), array_size_));
    for (unsigned i = 0; i < array_size_; ++i) {
      new (&metadata_array[i]) CSSPropertyValueMetadata();
      metadata_array[i] = properties[i].Metadata();
      value_array[i] = properties[i].Value();
    }
  }
}

// Convert property into an uint16_t for comparison with metadata's property id
// to avoid the compiler converting it to an int multiple times in a loop.
static uint16_t GetConvertedCSSPropertyID(CSSPropertyID property_id) {
  return static_cast<uint16_t>(property_id);
}

static uint16_t GetConvertedCSSPropertyID(const AtomicString&) {
  return static_cast<uint16_t>(CSSPropertyID::kVariable);
}

static uint16_t GetConvertedCSSPropertyID(AtRuleDescriptorID descriptor_id) {
  return static_cast<uint16_t>(
      AtRuleDescriptorIDAsCSSPropertyID(descriptor_id));
}

static bool IsPropertyMatch(const CSSPropertyValueMetadata& metadata,
                            uint16_t id,
                            CSSPropertyID property_id) {
  DCHECK_EQ(id, static_cast<uint16_t>(property_id));
  bool result = static_cast<uint16_t>(metadata.PropertyID()) == id;
// Only enabled properties except kInternalFontSizeDelta should be part of the
// style.
// TODO(hjkim3323@gmail.com): Remove kInternalFontSizeDelta bypassing hack
#if DCHECK_IS_ON()
  DCHECK(!result || property_id == CSSPropertyID::kInternalFontSizeDelta ||
         CSSProperty::Get(ResolveCSSPropertyID(property_id)).IsWebExposed());
#endif
  return result;
}

static bool IsPropertyMatch(const CSSPropertyValueMetadata& metadata,
                            uint16_t id,
                            const AtomicString& custom_property_name) {
  DCHECK_EQ(id, static_cast<uint16_t>(CSSPropertyID::kVariable));
  return metadata.Name() == CSSPropertyName(custom_property_name);
}

static bool IsPropertyMatch(const CSSPropertyValueMetadata& metadata,
                            uint16_t id,
                            AtRuleDescriptorID descriptor_id) {
  return IsPropertyMatch(metadata, id,
                         AtRuleDescriptorIDAsCSSPropertyID(descriptor_id));
}

template <typename T>
int ImmutableCSSPropertyValueSet::FindPropertyIndex(const T& property) const {
  uint16_t id = GetConvertedCSSPropertyID(property);
  const base::span<const CSSPropertyValueMetadata> metadata = MetadataArray();
  for (size_t n = array_size_; n; --n) {
    if (IsPropertyMatch(metadata[n - 1], id, property)) {
      return static_cast<int>(n - 1);
    }
  }

  return -1;
}
template CORE_EXPORT int ImmutableCSSPropertyValueSet::FindPropertyIndex(
    const CSSPropertyID&) const;
template CORE_EXPORT int ImmutableCSSPropertyValueSet::FindPropertyIndex(
    const AtomicString&) const;
template CORE_EXPORT int ImmutableCSSPropertyValueSet::FindPropertyIndex(
    const AtRuleDescriptorID&) const;

void ImmutableCSSPropertyValueSet::TraceAfterDispatch(
    blink::Visitor* visitor) const {
  for (const auto value : ValueArray()) {
    visitor->Trace(value);
  }
  CSSPropertyValueSet::TraceAfterDispatch(visitor);
}

MutableCSSPropertyValueSet::MutableCSSPropertyValueSet(
    const CSSPropertyValueSet& other)
    : CSSPropertyValueSet(other.CssParserMode()) {
  if (auto* other_mutable_property_set =
          DynamicTo<MutableCSSPropertyValueSet>(other)) {
    property_vector_ = other_mutable_property_set->property_vector_;
    may_have_logical_properties_ =
        other_mutable_property_set->may_have_logical_properties_;
  } else {
    property_vector_.ReserveInitialCapacity(other.PropertyCount());
    for (unsigned i = 0; i < other.PropertyCount(); ++i) {
      PropertyReference property = other.PropertyAt(i);
      property_vector_.UncheckedAppend(
          CSSPropertyValue(property.PropertyMetadata(), property.Value()));
      may_have_logical_properties_ |=
          kLogicalGroupProperties.Has(property.Id());
    }
  }
}

static String SerializeShorthand(const CSSPropertyValueSet& property_set,
                                 CSSPropertyID property_id) {
  StylePropertyShorthand shorthand = shorthandForProperty(property_id);
  if (!shorthand.length()) {
    return String();
  }

  return StylePropertySerializer(property_set).SerializeShorthand(property_id);
}

static String SerializeShorthand(const CSSPropertyValueSet&,
                                 const AtomicString& custom_property_name) {
  // Custom properties are never shorthands.
  return String();
}

static String SerializeShorthand(const CSSPropertyValueSet& property_set,
                                 AtRuleDescriptorID atrule_id) {
  // Descriptor shorthands aren't handled yet.
  return String();
}

template <typename T>
String CSSPropertyValueSet::GetPropertyValue(const T& property) const {
  String shorthand_serialization = SerializeShorthand(*this, property);
  if (!shorthand_serialization.IsNull()) {
    return shorthand_serialization;
  }
  const CSSValue* value = GetPropertyCSSValue(property);
  if (value) {
    return value->CssText();
  }
  return g_empty_string;
}
template CORE_EXPORT String
CSSPropertyValueSet::GetPropertyValue<CSSPropertyID>(
    const CSSPropertyID&) const;
template CORE_EXPORT String
CSSPropertyValueSet::GetPropertyValue<AtRuleDescriptorID>(
    const AtRuleDescriptorID&) const;
template CORE_EXPORT String
CSSPropertyValueSet::GetPropertyValue<AtomicString>(const AtomicString&) const;

String CSSPropertyValueSet::GetPropertyValueWithHint(
    const AtomicString& property_name,
    unsigned index) const {
  const CSSValue* value = GetPropertyCSSValueWithHint(property_name, index);
  if (value) {
    return value->CssText();
  }
  return g_empty_string;
}

template <typename T>
const CSSValue* CSSPropertyValueSet::GetPropertyCSSValue(
    const T& property) const {
  int found_property_index = FindPropertyIndex(property);
  if (found_property_index == -1) {
    return nullptr;
  }
  return &PropertyAt(found_property_index).Value();
}
template CORE_EXPORT const CSSValue* CSSPropertyValueSet::GetPropertyCSSValue<
    CSSPropertyID>(const CSSPropertyID&) const;
template CORE_EXPORT const CSSValue* CSSPropertyValueSet::GetPropertyCSSValue<
    AtRuleDescriptorID>(const AtRuleDescriptorID&) const;
template CORE_EXPORT const CSSValue* CSSPropertyValueSet::GetPropertyCSSValue<
    AtomicString>(const AtomicString&) const;

const CSSValue* CSSPropertyValueSet::GetPropertyCSSValueWithHint(
    const AtomicString& property_name,
    unsigned index) const {
  DCHECK_EQ(property_name, PropertyAt(index).Name().ToAtomicString());
  return &PropertyAt(index).Value();
}

void CSSPropertyValueSet::Trace(Visitor* visitor) const {
  if (is_mutable_) {
    To<MutableCSSPropertyValueSet>(this)->TraceAfterDispatch(visitor);
  } else {
    To<ImmutableCSSPropertyValueSet>(this)->TraceAfterDispatch(visitor);
  }
}

void CSSPropertyValueSet::FinalizeGarbageCollectedObject() {
  if (is_mutable_) {
    To<MutableCSSPropertyValueSet>(this)->~MutableCSSPropertyValueSet();
  } else {
    To<ImmutableCSSPropertyValueSet>(this)->~ImmutableCSSPropertyValueSet();
  }
}

bool MutableCSSPropertyValueSet::RemoveShorthandProperty(
    CSSPropertyID property_id) {
  StylePropertyShorthand shorthand = shorthandForProperty(property_id);
  if (!shorthand.length()) {
    return false;
  }

  return RemovePropertiesInSet(shorthand.properties());
}

bool MutableCSSPropertyValueSet::RemovePropertyAtIndex(int property_index,
                                                       String* return_text) {
  if (property_index == -1) {
    if (return_text) {
      *return_text = "";
    }
    return false;
  }

  if (return_text) {
    *return_text = PropertyAt(property_index).Value().CssText();
  }

  // A more efficient removal strategy would involve marking entries as empty
  // and sweeping them when the vector grows too big.
  property_vector_.EraseAt(property_index);

  InvalidateHashIfComputed();

  return true;
}

template <typename T>
bool MutableCSSPropertyValueSet::RemoveProperty(const T& property,
                                                String* return_text) {
  if (RemoveShorthandProperty(property)) {
    // FIXME: Return an equivalent shorthand when possible.
    if (return_text) {
      *return_text = "";
    }
    return true;
  }

  int found_property_index = FindPropertyIndex(property);
  return RemovePropertyAtIndex(found_property_index, return_text);
}
template CORE_EXPORT bool MutableCSSPropertyValueSet::RemoveProperty(
    const CSSPropertyID&,
    String*);
template CORE_EXPORT bool MutableCSSPropertyValueSet::RemoveProperty(
    const AtomicString&,
    String*);

template <typename T>
bool CSSPropertyValueSet::PropertyIsImportant(const T& property) const {
  int found_property_index = FindPropertyIndex(property);
  if (found_property_index != -1) {
    return PropertyAt(found_property_index).IsImportant();
  }
  return ShorthandIsImportant(property);
}
template CORE_EXPORT bool CSSPropertyValueSet::PropertyIsImportant<
    CSSPropertyID>(const CSSPropertyID&) const;
template bool CSSPropertyValueSet::PropertyIsImportant<AtomicString>(
    const AtomicString&) const;

bool CSSPropertyValueSet::PropertyIsImportantWithHint(
    const AtomicString& property_name,
    unsigned index) const {
  DCHECK_EQ(property_name, PropertyAt(index).Name().ToAtomicString());
  return PropertyAt(index).IsImportant();
}

bool CSSPropertyValueSet::ShorthandIsImportant(
    CSSPropertyID property_id) const {
  StylePropertyShorthand shorthand = shorthandForProperty(property_id);
  const StylePropertyShorthand::Properties longhands = shorthand.properties();
  if (longhands.empty()) {
    return false;
  }

  for (const CSSProperty* const longhand : longhands) {
    if (!PropertyIsImportant(longhand->PropertyID())) {
      return false;
    }
  }
  return true;
}

CSSPropertyID CSSPropertyValueSet::GetPropertyShorthand(
    CSSPropertyID property_id) const {
  int found_property_index = FindPropertyIndex(property_id);
  if (found_property_index == -1) {
    return CSSPropertyID::kInvalid;
  }
  return PropertyAt(found_property_index).ShorthandID();
}

bool CSSPropertyValueSet::IsPropertyImplicit(CSSPropertyID property_id) const {
  int found_property_index = FindPropertyIndex(property_id);
  if (found_property_index == -1) {
    return false;
  }
  return PropertyAt(found_property_index).IsImplicit();
}

MutableCSSPropertyValueSet::SetResult
MutableCSSPropertyValueSet::ParseAndSetProperty(
    CSSPropertyID unresolved_property,
    StringView value,
    bool important,
    SecureContextMode secure_context_mode,
    StyleSheetContents* context_style_sheet) {
  DCHECK_GE(unresolved_property, kFirstCSSProperty);

  // Setting the value to an empty string just removes the property in both IE
  // and Gecko. Setting it to null seems to produce less consistent results, but
  // we treat it just the same.
  if (value.empty()) {
    return RemoveProperty(ResolveCSSPropertyID(unresolved_property))
               ? kChangedPropertySet
               : kUnchanged;
  }

  // When replacing an existing property value, this moves the property to the
  // end of the list. Firefox preserves the position, and MSIE moves the
  // property to the beginning.
  return CSSParser::ParseValue(this, unresolved_property, value, important,
                               secure_context_mode, context_style_sheet);
}

MutableCSSPropertyValueSet::SetResult
MutableCSSPropertyValueSet::ParseAndSetCustomProperty(
    const AtomicString& custom_property_name,
    StringView value,
    bool important,
    SecureContextMode secure_context_mode,
    StyleSheetContents* context_style_sheet,
    bool is_animation_tainted) {
  if (value.empty()) {
    return RemoveProperty(custom_property_name) ? kChangedPropertySet
                                                : kUnchanged;
  }
  return CSSParser::ParseValueForCustomProperty(
      this, custom_property_name, value, important, secure_context_mode,
      context_style_sheet, is_animation_tainted);
}

void MutableCSSPropertyValueSet::SetProperty(const CSSPropertyName& name,
                                             const CSSValue& value,
                                             bool important) {
  if (name.Id() == CSSPropertyID::kVariable) {
    SetLonghandProperty(CSSPropertyValue(name, value, important));
  } else {
    SetProperty(name.Id(), value, important);
  }
}

void MutableCSSPropertyValueSet::SetProperty(CSSPropertyID property_id,
                                             const CSSValue& value,
                                             bool important) {
  DCHECK_NE(property_id, CSSPropertyID::kVariable);
  DCHECK_NE(property_id, CSSPropertyID::kWhiteSpace);
  StylePropertyShorthand shorthand = shorthandForProperty(property_id);
  if (!shorthand.length()) {
    SetLonghandProperty(
        CSSPropertyValue(CSSPropertyName(property_id), value, important));
    return;
  }

  RemovePropertiesInSet(shorthand.properties());

  // The simple shorthand expansion below doesn't work for `white-space`.
  DCHECK_NE(property_id, CSSPropertyID::kWhiteSpace);
  for (const CSSProperty* const longhand : shorthand.properties()) {
    CSSPropertyName longhand_name(longhand->PropertyID());
    property_vector_.push_back(
        CSSPropertyValue(longhand_name, value, important));
  }
  InvalidateHashIfComputed();
}

ALWAYS_INLINE CSSPropertyValue*
MutableCSSPropertyValueSet::FindInsertionPointForID(CSSPropertyID property_id) {
  CSSPropertyValue* to_replace =
      const_cast<CSSPropertyValue*>(FindPropertyPointer(property_id));
  if (to_replace == nullptr) {
    return nullptr;
  }
  if (may_have_logical_properties_) {
    const CSSProperty& prop = CSSProperty::Get(property_id);
    if (prop.IsInLogicalPropertyGroup()) {
      DCHECK(property_vector_.Contains(*to_replace));
      int to_replace_index =
          static_cast<int>(to_replace - property_vector_.data());
      for (int n = property_vector_.size() - 1; n > to_replace_index; --n) {
        if (prop.IsInSameLogicalPropertyGroupWithDifferentMappingLogic(
                PropertyAt(n).Id())) {
          RemovePropertyAtIndex(to_replace_index, nullptr);
          return nullptr;
        }
      }
    }
  }
  return to_replace;
}

MutableCSSPropertyValueSet::SetResult
MutableCSSPropertyValueSet::SetLonghandProperty(CSSPropertyValue property) {
  const CSSPropertyID id = property.Id();
  DCHECK_EQ(shorthandForProperty(id).length(), 0u)
      << CSSProperty::Get(id).GetPropertyNameString() << " is a shorthand";
  CSSPropertyValue* to_replace;
  if (id == CSSPropertyID::kVariable) {
    to_replace = const_cast<CSSPropertyValue*>(
        FindPropertyPointer(property.Name().ToAtomicString()));
  } else {
    to_replace = FindInsertionPointForID(id);
  }
  if (to_replace) {
    if (*to_replace == property) {
      return kUnchanged;
    }
    *to_replace = std::move(property);
    InvalidateHashIfComputed();
    return kModifiedExisting;
  } else {
    may_have_logical_properties_ |= kLogicalGroupProperties.Has(id);
  }
  property_vector_.push_back(std::move(property));
  InvalidateHashIfComputed();
  return kChangedPropertySet;
}

void MutableCSSPropertyValueSet::SetLonghandProperty(CSSPropertyID property_id,
                                                     const CSSValue& value) {
  DCHECK_EQ(shorthandForProperty(property_id).length(), 0u)
      << CSSProperty::Get(property_id).GetPropertyNameString()
      << " is a shorthand";
  CSSPropertyValue* to_replace = FindInsertionPointForID(property_id);
  if (to_replace) {
    *to_replace = CSSPropertyValue(CSSPropertyName(property_id), value);
  } else {
    may_have_logical_properties_ |= kLogicalGroupProperties.Has(property_id);
    property_vector_.emplace_back(CSSPropertyName(property_id), value);
  }
  InvalidateHashIfComputed();
}

MutableCSSPropertyValueSet::SetResult
MutableCSSPropertyValueSet::SetLonghandProperty(CSSPropertyID property_id,
                                                CSSValueID identifier,
                                                bool important) {
  CSSPropertyName name(property_id);
  return SetLonghandProperty(CSSPropertyValue(
      name, *CSSIdentifierValue::Create(identifier), important));
}

void MutableCSSPropertyValueSet::ParseDeclarationList(
    const String& style_declaration,
    SecureContextMode secure_context_mode,
    StyleSheetContents* context_style_sheet) {
  property_vector_.clear();
  InvalidateHashIfComputed();

  CSSParserContext* context;
  if (context_style_sheet) {
    context = MakeGarbageCollected<CSSParserContext>(
        context_style_sheet->ParserContext(), context_style_sheet);
    context->SetMode(CssParserMode());
  } else {
    context = MakeGarbageCollected<CSSParserContext>(CssParserMode(),
                                                     secure_context_mode);
  }

  CSSParser::ParseDeclarationList(context, this, style_declaration);
}

MutableCSSPropertyValueSet::SetResult
MutableCSSPropertyValueSet::AddParsedProperties(
    const HeapVector<CSSPropertyValue, 64>& properties) {
  SetResult changed = kUnchanged;
  property_vector_.reserve(property_vector_.size() + properties.size());
  for (unsigned i = 0; i < properties.size(); ++i) {
    changed = std::max(changed, SetLonghandProperty(properties[i]));
  }
  return changed;
}

bool MutableCSSPropertyValueSet::AddRespectingCascade(
    const CSSPropertyValue& property) {
  // Only add properties that have no !important counterpart present
  if (!PropertyIsImportant(property.Id()) || property.IsImportant()) {
    return SetLonghandProperty(property);
  }
  return false;
}

String CSSPropertyValueSet::AsText() const {
  return StylePropertySerializer(*this).AsText();
}

void MutableCSSPropertyValueSet::MergeAndOverrideOnConflict(
    const CSSPropertyValueSet* other) {
  unsigned size = other->PropertyCount();
  for (unsigned n = 0; n < size; ++n) {
    PropertyReference to_merge = other->PropertyAt(n);
    SetLonghandProperty(
        CSSPropertyValue(to_merge.PropertyMetadata(), to_merge.Value()));
  }
}

bool CSSPropertyValueSet::HasFailedOrCanceledSubresources() const {
  unsigned size = PropertyCount();
  for (unsigned i = 0; i < size; ++i) {
    if (PropertyAt(i).Value().HasFailedOrCanceledSubresources()) {
      return true;
    }
  }
  return false;
}

void MutableCSSPropertyValueSet::Clear() {
  property_vector_.clear();
  InvalidateHashIfComputed();
  may_have_logical_properties_ = false;
}

inline bool ContainsId(const base::span<const CSSProperty* const>& set,
                       CSSPropertyID id) {
  for (const CSSProperty* const property : set) {
    if (property->IDEquals(id)) {
      return true;
    }
  }
  return false;
}

bool MutableCSSPropertyValueSet::RemovePropertiesInSet(
    base::span<const CSSProperty* const> set) {
  if (property_vector_.empty()) {
    return false;
  }

  base::span<CSSPropertyValue> properties(property_vector_);
  unsigned old_size = property_vector_.size();
  unsigned new_index = 0;
  for (unsigned old_index = 0; old_index < old_size; ++old_index) {
    const CSSPropertyValue& property = properties[old_index];
    if (ContainsId(set, property.Id())) {
      continue;
    }
    // Modify property_vector_ in-place since this method is
    // performance-sensitive.
    properties[new_index++] = properties[old_index];
  }
  if (new_index != old_size) {
    property_vector_.Shrink(new_index);
    InvalidateHashIfComputed();
    return true;
  }
  return false;
}

CSSPropertyValue* MutableCSSPropertyValueSet::FindCSSPropertyWithName(
    const CSSPropertyName& name) {
  return const_cast<CSSPropertyValue*>(
      name.IsCustomProperty() ? FindPropertyPointer(name.ToAtomicString())
                              : FindPropertyPointer(name.Id()));
}

bool CSSPropertyValueSet::PropertyMatches(
    CSSPropertyID property_id,
    const CSSValue& property_value) const {
  int found_property_index = FindPropertyIndex(property_id);
  if (found_property_index == -1) {
    return false;
  }
  return PropertyAt(found_property_index).Value() == property_value;
}

void MutableCSSPropertyValueSet::RemoveEquivalentProperties(
    const CSSPropertyValueSet* style) {
  Vector<CSSPropertyID> properties_to_remove;
  unsigned size = property_vector_.size();
  for (unsigned i = 0; i < size; ++i) {
    PropertyReference property = PropertyAt(i);
    if (style->PropertyMatches(property.Id(), property.Value())) {
      properties_to_remove.push_back(property.Id());
    }
  }
  // FIXME: This should use mass removal.
  for (unsigned i = 0; i < properties_to_remove.size(); ++i) {
    RemoveProperty(properties_to_remove[i]);
  }
}

void MutableCSSPropertyValueSet::RemoveEquivalentProperties(
    const CSSStyleDeclaration* style) {
  Vector<CSSPropertyID> properties_to_remove;
  unsigned size = property_vector_.size();
  for (unsigned i = 0; i < size; ++i) {
    PropertyReference property = PropertyAt(i);
    if (style->CssPropertyMatches(property.Id(), property.Value())) {
      properties_to_remove.push_back(property.Id());
    }
  }
  // FIXME: This should use mass removal.
  for (unsigned i = 0; i < properties_to_remove.size(); ++i) {
    RemoveProperty(properties_to_remove[i]);
  }
}

MutableCSSPropertyValueSet* CSSPropertyValueSet::MutableCopy() const {
  return MakeGarbageCollected<MutableCSSPropertyValueSet>(*this);
}

MutableCSSPropertyValueSet* CSSPropertyValueSet::CopyPropertiesInSet(
    const Vector<const CSSProperty*>& properties) const {
  HeapVector<CSSPropertyValue, 64> list;
  list.ReserveInitialCapacity(properties.size());
  for (const CSSProperty* property : properties) {
    CSSPropertyName name(property->PropertyID());
    const CSSValue* value = GetPropertyCSSValue(name.Id());
    if (value) {
      list.push_back(CSSPropertyValue(name, *value, false));
    }
  }
  return MakeGarbageCollected<MutableCSSPropertyValueSet>(list);
}

CSSStyleDeclaration* MutableCSSPropertyValueSet::EnsureCSSStyleDeclaration(
    ExecutionContext* execution_context) {
  // FIXME: get rid of this weirdness of a CSSStyleDeclaration inside of a
  // style property set.
  if (cssom_wrapper_) {
    DCHECK(
        !static_cast<CSSStyleDeclaration*>(cssom_wrapper_.Get())->parentRule());
    DCHECK(!cssom_wrapper_->ParentElement());
    return cssom_wrapper_.Get();
  }
  cssom_wrapper_ = MakeGarbageCollected<PropertySetCSSStyleDeclaration>(
      execution_context, *this);
  return cssom_wrapper_.Get();
}

template <typename T>
int MutableCSSPropertyValueSet::FindPropertyIndex(const T& property) const {
  const CSSPropertyValue* begin = property_vector_.data();
  const CSSPropertyValue* it = FindPropertyPointer(property);
  return (it == nullptr) ? -1 : static_cast<int>(it - begin);
}
template CORE_EXPORT int MutableCSSPropertyValueSet::FindPropertyIndex(
    const CSSPropertyID&) const;
template CORE_EXPORT int MutableCSSPropertyValueSet::FindPropertyIndex(
    const AtomicString&) const;

template <typename T>
const CSSPropertyValue* MutableCSSPropertyValueSet::FindPropertyPointer(
    const T& property) const {
  uint16_t id = GetConvertedCSSPropertyID(property);

  auto it = std::find_if(
      property_vector_.begin(), property_vector_.end(),
      [property, id](const CSSPropertyValue& css_property) -> bool {
        return IsPropertyMatch(css_property.Metadata(), id, property);
      });
  return (it == property_vector_.end()) ? nullptr : &*it;
}

void MutableCSSPropertyValueSet::TraceAfterDispatch(
    blink::Visitor* visitor) const {
  visitor->Trace(cssom_wrapper_);
  visitor->Trace(property_vector_);
  CSSPropertyValueSet::TraceAfterDispatch(visitor);
}

unsigned CSSPropertyValueSet::AverageSizeInBytes() {
  // Please update this if the storage scheme changes so that this longer
  // reflects the actual size.
  return sizeof(ImmutableCSSPropertyValueSet) +
         static_cast<wtf_size_t>(
             AdditionalBytesForImmutableCSSPropertyValueSetWithPropertyCount(4)
                 .value);
}

// See the function above if you need to update this.
struct SameSizeAsCSSPropertyValueSet final
    : public GarbageCollected<SameSizeAsCSSPropertyValueSet> {
  uint32_t bitfield;
  unsigned hash;
};
ASSERT_SIZE(CSSPropertyValueSet, SameSizeAsCSSPropertyValueSet);

#ifndef NDEBUG
void CSSPropertyValueSet::ShowStyle() {
  fprintf(stderr, "%s\n", AsText().Ascii().c_str());
}
#endif

void CSSLazyPropertyParser::Trace(Visitor* visitor) const {}

}  // namespace blink
```