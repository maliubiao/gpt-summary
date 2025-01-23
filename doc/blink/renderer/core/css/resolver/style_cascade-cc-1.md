Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. The focus should be on how this code relates to CSS, HTML, and JavaScript, with examples, potential errors, debugging hints, and a final summary of its role.

**Breakdown of the Code Snippet:**

The code snippet primarily deals with resolving and applying CSS property values, especially in the context of custom properties (`--variable`), `var()`, `env()`, `attr()`, and custom CSS functions. It involves:

1. **Looking up and applying styles:**  `LookupAndApply` and `LookupAndApplyInterpolation` handle retrieving and applying CSS values based on priority and origin.
2. **Handling default values:**  The code interacts with explicit default values for CSS properties.
3. **Resolving variable references:**  `ResolveVariableReference` is key for handling `var()` functions, including fallback values and cycle detection.
4. **Resolving environment variables:** `ResolveEnvInto` deals with `env()` functions.
5. **Resolving attribute values:** `ResolveAttrInto` handles `attr()` functions.
6. **Resolving CSS functions:** `ResolveFunctionInto` and `ResolveFunctionExpression` are responsible for custom CSS functions.
7. **Handling `revert` and `revert-layer`:**  The code includes logic for these CSS keywords to reset styles.
8. **Handling `flip-revert`:** Logic for reverting to a potentially flipped value based on writing direction.
9. **Handling math functions:**  `ResolveMathFunction` specifically deals with `calc()` and its potential invalidity due to anchor functions.
10. **Token processing:**  `ResolveTokensInto` is a central function for recursively resolving tokens within CSS values, particularly when dealing with variables and functions.
11. **Cycle detection:** The code incorporates mechanisms to prevent infinite loops when resolving nested variable references.
12. **Animation tainting:** The `is_animation_tainted_` flag is relevant for determining if a custom property is involved in animations.
13. **Token sequence manipulation:** The `TokenSequence` class helps in building up the resolved value by appending tokens.

**Planning the Response:**

I will structure the response as follows:

1. **Overall Function:**  A concise summary of the code's primary role.
2. **Relationship to CSS:**  Provide examples of how the code interacts with core CSS features like variables, functions, and keywords.
3. **Relationship to HTML:**  Explain how the `attr()` function and the element's style are involved.
4. **Relationship to JavaScript:** Briefly mention how JavaScript can interact with CSS variables and potentially trigger re-resolutions.
5. **Logical Reasoning (Example):** Demonstrate the resolution process for a simple `var()` scenario.
6. **Common Usage Errors:**  Highlight mistakes users or developers might make that lead to this code being executed (e.g., syntax errors in `var()`).
7. **User Operation Debugging:** Describe a user action and the steps the browser takes to reach this code.
8. **Summary of Functionality (Part 2):**  Reiterate the main purpose of this code based on the provided snippet.
```
这是目录为blink/renderer/core/css/resolver/style_cascade.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

基于提供的代码片段（第二部分），我们可以归纳出 `StyleCascade` 类在处理 CSS 属性值解析和应用方面的以下功能：

**主要功能归纳 (基于第二部分代码片段):**

1. **处理 CSS 属性的查找和应用，包括插值 (Interpolation):**
   - `LookupAndApplyInterpolation` 函数负责查找并应用 CSS 属性的插值值。它会检查属性是否已经在本代应用过，并从 `interpolations_` 数据结构中提取相应的插值值进行应用。
   - 特别地，它会跳过 `-internal-visited` 属性的插值，因为这些属性的插值会通过其对应的非 visited 属性来处理。

2. **管理和操作 CSS 变量的 Token 序列 (`TokenSequence`):**
   - `TokenSequence` 类用于构建和操作 CSS 变量值的 token 序列。
   - `AppendFallback`：追加 fallback 值到当前的 token 序列，会进行长度限制的检查，并处理 `attr()` 函数可能引入的 "taint" token。
   - `Append`：追加字符串或 CSSValue 到 token 序列，也会进行长度限制的检查，并负责解析和记录 token 的类型信息（例如是否包含 font units 或 line height units）。
   - `BuildVariableData`：将构建的 token 序列转换为 `CSSVariableData` 对象。

3. **解析和处理 CSS 值的各种情况:**
   - `Resolve`：是核心的解析函数，用于解析 CSS 属性的特定值。它会处理以下情况：
     - **`revert` 关键字:** 调用 `ResolveRevert` 来处理 `revert` 关键字，根据优先级回退到更低优先级的样式。
     - **`revert-layer` 关键字:** 调用 `ResolveRevertLayer` 来处理 `revert-layer` 关键字，根据层叠层级回退样式。
     - **`flip-revert` 函数:** 调用 `ResolveFlipRevert` 来处理 `flip-revert()` 函数，这涉及到根据书写方向翻转回退的值。
     - **数学函数 (`calc()`, `anchor()` 等):** 调用 `ResolveMathFunction` 来处理数学函数，特别是处理 `anchor()` 函数可能导致的无效情况。
     - **变量引用和替换:** 调用 `ResolveSubstitutions` 来处理变量引用（`var()`）和待替换的值。

4. **处理 CSS 变量的解析 (`ResolveVariableReference`, `ResolveCustomProperty`, `ResolvePendingSubstitution`):**
   - `ResolveVariableReference`：解析 `var()` 函数，从样式表中查找变量的值并进行替换。
   - `ResolveCustomProperty`：处理自定义 CSS 属性，包括检测循环依赖。
   - `ResolvePendingSubstitution`：处理简写属性中包含变量的情况，需要展开简写属性并找到对应的长属性值。

5. **解析和处理 CSS 函数 (`ResolveFunctionInto`, `ResolveFunctionExpression`):**
   - `ResolveFunctionInto`：处理自定义 CSS 函数的调用，包括解析参数和执行函数体。
   - `ResolveFunctionExpression`：解析函数表达式，用于处理函数参数或返回值，并进行类型转换。

6. **解析和处理 `env()` 和 `attr()` 函数:**
   - `ResolveEnvInto`：处理 `env()` 函数，用于获取环境变量的值。
   - `ResolveAttrInto`：处理 `attr()` 函数，用于获取 HTML 属性的值。

7. **循环依赖检测:** 在处理 CSS 变量时，会进行循环依赖检测，防止无限递归。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** 这是代码的核心，负责处理 CSS 属性值的解析、计算和应用。
    - **示例 (CSS 变量):**  当 CSS 中有类似 `--main-color: blue;` 和 `color: var(--main-color);` 时，`ResolveVariableReference` 会被调用来查找 `--main-color` 的值并将其替换到 `color` 属性中。
    - **示例 (revert):**  如果 CSS 中有 `color: revert;`，`ResolveRevert` 会被调用，它会查找当前属性在更低优先级层级的值。
    - **示例 (自定义 CSS 函数):** 如果定义了 `@property --my-angle { syntax: "<angle>"; initial-value: 0deg; inherits: false; }` 和 `@function double-angle($angle) { return calc(2 * $angle); }`，然后在 CSS 中使用 `transform: rotate(double-angle(45deg));`，`ResolveFunctionInto` 和 `ResolveFunctionExpression` 会处理 `double-angle` 函数的解析和执行。

* **HTML:** `attr()` 函数直接与 HTML 属性相关。
    - **示例:**  如果 CSS 中有 `content: attr(data-label);`，`ResolveAttrInto` 会被调用来获取当前 HTML 元素的 `data-label` 属性值并将其作为 `content` 的值。

* **JavaScript:** JavaScript 可以通过修改元素的 style 属性或添加/删除 CSS 类来影响 CSS 的解析。
    - **示例:** JavaScript 代码 `element.style.setProperty('--theme-color', 'red');` 会导致与 `--theme-color` 相关的 CSS 规则重新解析和应用，这可能会触发 `ResolveVariableReference` 的执行。

**逻辑推理的假设输入与输出:**

假设输入一段 CSS 规则：

```css
:root {
  --base-size: 10px;
}
.element {
  font-size: calc(var(--base-size) * 2);
}
```

当浏览器处理 `.element` 的 `font-size` 属性时：

1. **输入:**  `property` 为 `CSSProperty::kFontSize`, `value` 为 `CSSCalcValue` (表示 `calc(var(--base-size) * 2)`), `origin` 为样式表的来源。
2. **`Resolve` 函数被调用。**
3. **`ResolveSubstitutions` 被调用，发现 `value` 是 `CSSCalcValue`。**
4. **`ResolveMathFunction` 被调用，检测到内部包含 `var()`。**
5. **`ResolveVariableReference` 被调用来解析 `var(--base-size)`。**
6. **查找 `:root` 上的 `--base-size` 属性，得到值 `10px`。**
7. **输出 (中间结果):**  `calc(10px * 2)`。
8. **`ResolveMathFunction` 继续计算，得到最终值 `20px`。**
9. **输出 (最终结果):** `CSSPrimitiveValue`，值为 `20px`。

**用户或编程常见的使用错误:**

1. **`var()` 函数中引用了不存在的变量:**  例如 `color: var(--non-existent-color);`。这会导致 `ResolveVariableReference` 找不到变量，通常会使用 `unset` 或 fallback 值。
2. **`var()` 函数中存在循环引用:** 例如：
   ```css
   :root {
     --color-a: var(--color-b);
     --color-b: var(--color-a);
   }
   .element {
     color: var(--color-a);
   }
   ```
   `ResolveVariableReference` 会检测到循环依赖，并通常将变量值设置为初始值或特定的错误值。
3. **`attr()` 函数引用了不存在的属性:** 例如 `content: attr(non-existent-attr);`。`ResolveAttrInto` 会返回空字符串或默认值。
4. **自定义 CSS 函数语法错误:**  函数定义或调用时参数不匹配，会导致 `ResolveFunctionInto` 解析失败。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中加载一个包含 CSS 规则的网页。**
2. **Blink 渲染引擎开始解析 HTML 和 CSS。**
3. **当解析到需要计算样式值的元素时，例如 `.element` 的 `font-size` 属性。**
4. **`StyleResolver` 负责解析和计算样式。**
5. **对于包含 `var()` 或 `calc()` 等复杂值的属性，会调用 `StyleCascade` 中的相关方法进行解析。**
6. **如果涉及到 `var()`，则会调用 `ResolveVariableReference`。**
7. **如果涉及到 `attr()`，则会调用 `ResolveAttrInto`。**
8. **如果涉及到自定义 CSS 函数，则会调用 `ResolveFunctionInto`。**

**调试线索:** 如果在调试器中看到程序执行到 `StyleCascade::ResolveVariableReference` 或其他相关函数，可以推断当前正在处理包含 CSS 变量、`attr()` 函数或自定义 CSS 函数的样式规则。检查当前的 CSS 规则、HTML 结构以及相关的 JavaScript 代码，可以帮助定位问题。

**总结 (基于第二部分代码片段):**

这部分 `StyleCascade` 代码的核心功能是**处理 CSS 属性值中可能包含的各种复杂情况，特别是与 CSS 变量、`revert` 和 `revert-layer` 关键字、`flip-revert` 函数、数学函数、自定义 CSS 函数、`env()` 函数以及 `attr()` 函数相关的解析和计算。** 它负责将这些复杂的值解析为最终可以应用到元素上的具体值，并处理可能出现的循环依赖和错误情况。`TokenSequence` 类则辅助完成了 CSS 变量值的构建和管理。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_cascade.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
are used for explicit defaulting,
  // see StyleCascade::AddExplicitDefaults.
  const CSSValue* value = (origin == CascadeOrigin::kNone)
                              ? cssvalue::CSSUnsetValue::Create()
                              : ValueAt(match_result_, priority->GetPosition());
  DCHECK(value);
  value = Resolve(property, *value, *priority, origin, resolver);
  DCHECK(IsA<CustomProperty>(property) || !value->IsUnparsedDeclaration());
  DCHECK(!value->IsPendingSubstitutionValue());
  value = EnsureScopedValue(GetDocument(), match_result_, *priority, value);
  StyleBuilder::ApplyPhysicalProperty(property, state_, *value);
}

void StyleCascade::LookupAndApplyInterpolation(const CSSProperty& property,
                                               CascadePriority* priority,
                                               CascadeResolver& resolver) {
  if (priority->GetGeneration() >= resolver.generation_) {
    // Already applied this generation.
    return;
  }
  *priority = CascadePriority(*priority, resolver.generation_);

  DCHECK(!property.IsSurrogate());

  // Interpolations for -internal-visited properties are applied via the
  // interpolation for the main (unvisited) property, so we don't need to
  // apply it twice.
  // TODO(crbug.com/1062217): Interpolate visited colors separately
  if (property.IsVisited()) {
    return;
  }
  DCHECK(priority->GetOrigin() >= CascadeOrigin::kAnimation);
  wtf_size_t index = DecodeInterpolationIndex(priority->GetPosition());
  DCHECK_LE(index, interpolations_.GetEntries().size());
  const ActiveInterpolationsMap& map = *interpolations_.GetEntries()[index].map;
  PropertyHandle handle = ToPropertyHandle(property, *priority);
  const auto& entry = map.find(handle);
  CHECK_NE(entry, map.end(), base::NotFatalUntil::M130);
  ApplyInterpolation(property, *priority, *entry->value, resolver);
}

bool StyleCascade::IsRootElement() const {
  return &state_.GetElement() == state_.GetDocument().documentElement();
}

StyleCascade::TokenSequence::TokenSequence(const CSSVariableData* data)
    : is_animation_tainted_(data->IsAnimationTainted()),
      has_font_units_(data->HasFontUnits()),
      has_root_font_units_(data->HasRootFontUnits()),
      has_line_height_units_(data->HasLineHeightUnits()) {}

bool StyleCascade::TokenSequence::AppendFallback(const TokenSequence& sequence,
                                                 wtf_size_t byte_limit) {
  // https://drafts.csswg.org/css-variables/#long-variables
  if (original_text_.length() + sequence.original_text_.length() > byte_limit) {
    return false;
  }

  String new_text;

  StringView other_text = sequence.original_text_;
  StringView stripped_text =
      CSSVariableParser::StripTrailingWhitespaceAndComments(other_text);

  StringView trailer = StringView(other_text, stripped_text.length());
  if (IsAttrTainted(trailer)) {
    // We stripped away the taint token from the fallback value,
    // so add it back here. This is a somewhat slower path,
    // but should be rare.
    StringBuilder sb;
    sb.Append(stripped_text);
    sb.Append(GetCSSAttrTaintToken());
    new_text = sb.ReleaseString();
    stripped_text = new_text;
  }

  CSSTokenizer tokenizer(stripped_text);
  CSSParserToken first_token = tokenizer.TokenizeSingleWithComments();

  if (NeedsInsertedComment(last_token_, first_token)) {
    original_text_.Append("/**/");
  }
  original_text_.Append(stripped_text);
  last_token_ = last_non_whitespace_token_ =
      sequence.last_non_whitespace_token_;

  is_animation_tainted_ |= sequence.is_animation_tainted_;
  has_font_units_ |= sequence.has_font_units_;
  has_root_font_units_ |= sequence.has_root_font_units_;
  has_line_height_units_ |= sequence.has_line_height_units_;
  return true;
}

static bool IsNonWhitespaceToken(const CSSParserToken& token) {
  return token.GetType() != kWhitespaceToken &&
         token.GetType() != kCommentToken;
}

bool StyleCascade::TokenSequence::Append(StringView str,
                                         wtf_size_t byte_limit) {
  // https://drafts.csswg.org/css-variables/#long-variables
  if (original_text_.length() + str.length() > byte_limit) {
    return false;
  }
  CSSTokenizer tokenizer(str);
  const CSSParserToken first_token = tokenizer.TokenizeSingleWithComments();
  if (first_token.GetType() != kEOFToken) {
    CSSVariableData::ExtractFeatures(first_token, has_font_units_,
                                     has_root_font_units_,
                                     has_line_height_units_);
    if (NeedsInsertedComment(last_token_, first_token)) {
      original_text_.Append("/**/");
    }
    last_token_ = first_token.CopyWithoutValue();
    if (IsNonWhitespaceToken(first_token)) {
      last_non_whitespace_token_ = first_token;
    }
    while (true) {
      const CSSParserToken token = tokenizer.TokenizeSingleWithComments();
      if (token.GetType() == kEOFToken) {
        break;
      } else {
        CSSVariableData::ExtractFeatures(token, has_font_units_,
                                         has_root_font_units_,
                                         has_line_height_units_);
        last_token_ = token.CopyWithoutValue();
        if (IsNonWhitespaceToken(token)) {
          last_non_whitespace_token_ = token;
        }
      }
    }
  }
  original_text_.Append(str);
  return true;
}

bool StyleCascade::TokenSequence::Append(const CSSValue* value,
                                         wtf_size_t byte_limit) {
  return Append(value->CssText(), byte_limit);
}

bool StyleCascade::TokenSequence::Append(CSSVariableData* data,
                                         wtf_size_t byte_limit) {
  if (!Append(data->OriginalText(), byte_limit)) {
    return false;
  }
  is_animation_tainted_ |= data->IsAnimationTainted();
  return true;
}

void StyleCascade::TokenSequence::Append(const CSSParserToken& token,
                                         StringView original_text) {
  CSSVariableData::ExtractFeatures(token, has_font_units_, has_root_font_units_,
                                   has_line_height_units_);
  if (NeedsInsertedComment(last_token_, token)) {
    original_text_.Append("/**/");
  }
  last_token_ = token.CopyWithoutValue();
  if (IsNonWhitespaceToken(token)) {
    last_non_whitespace_token_ = token;
  }
  original_text_.Append(original_text);
}

CSSVariableData* StyleCascade::TokenSequence::BuildVariableData() {
  return CSSVariableData::Create(original_text_, is_animation_tainted_,
                                 /*needs_variable_resolution=*/false,
                                 has_font_units_, has_root_font_units_,
                                 has_line_height_units_);
}

const CSSValue* StyleCascade::Resolve(const CSSProperty& property,
                                      const CSSValue& value,
                                      CascadePriority priority,
                                      CascadeOrigin& origin,
                                      CascadeResolver& resolver) {
  DCHECK(!property.IsSurrogate());

  const CSSValue* result = ResolveSubstitutions(property, value, resolver);
  DCHECK(result);

  if (result->IsRevertValue()) {
    return ResolveRevert(property, *result, origin, resolver);
  }
  if (result->IsRevertLayerValue() || TreatAsRevertLayer(priority)) {
    return ResolveRevertLayer(property, priority, origin, resolver);
  }
  if (const auto* v = DynamicTo<CSSFlipRevertValue>(result)) {
    return ResolveFlipRevert(property, *v, priority, origin, resolver);
  }
  if (const auto* v = DynamicTo<CSSMathFunctionValue>(result)) {
    return ResolveMathFunction(property, *v, priority);
  }

  resolver.CollectFlags(property, origin);

  return result;
}

const CSSValue* StyleCascade::ResolveSubstitutions(const CSSProperty& property,
                                                   const CSSValue& value,
                                                   CascadeResolver& resolver) {
  if (const auto* v = DynamicTo<CSSUnparsedDeclarationValue>(value)) {
    if (property.GetCSSPropertyName().IsCustomProperty()) {
      return ResolveCustomProperty(property, *v, resolver);
    } else {
      return ResolveVariableReference(property, *v, resolver);
    }
  }
  if (const auto* v = DynamicTo<cssvalue::CSSPendingSubstitutionValue>(value)) {
    return ResolvePendingSubstitution(property, *v, resolver);
  }
  return &value;
}

const CSSValue* StyleCascade::ResolveCustomProperty(
    const CSSProperty& property,
    const CSSUnparsedDeclarationValue& decl,
    CascadeResolver& resolver) {
  DCHECK(!property.IsSurrogate());

  DCHECK(!resolver.IsLocked(property));
  CascadeResolver::AutoLock lock(property, resolver);

  CSSVariableData* data = decl.VariableDataValue();

  if (data->NeedsVariableResolution()) {
    data = ResolveVariableData(data, *GetParserContext(decl), resolver);
  }

  if (HasFontSizeDependency(To<CustomProperty>(property), data)) {
    resolver.DetectCycle(GetCSSPropertyFontSize());
  }

  if (HasLineHeightDependency(To<CustomProperty>(property), data)) {
    resolver.DetectCycle(GetCSSPropertyLineHeight());
  }

  if (resolver.InCycle()) {
    return CSSCyclicVariableValue::Create();
  }

  if (!data) {
    return CSSInvalidVariableValue::Create();
  }

  if (data == decl.VariableDataValue()) {
    return &decl;
  }

  // If a declaration, once all var() functions are substituted in, contains
  // only a CSS-wide keyword (and possibly whitespace), its value is determined
  // as if that keyword were its specified value all along.
  //
  // https://drafts.csswg.org/css-variables/#substitute-a-var
  {
    CSSParserTokenStream stream(data->OriginalText());
    stream.ConsumeWhitespace();
    CSSValue* value = css_parsing_utils::ConsumeCSSWideKeyword(stream);
    if (value && stream.AtEnd()) {
      return value;
    }
  }

  return MakeGarbageCollected<CSSUnparsedDeclarationValue>(
      data, decl.ParserContext());
}

const CSSValue* StyleCascade::ResolveVariableReference(
    const CSSProperty& property,
    const CSSUnparsedDeclarationValue& value,
    CascadeResolver& resolver) {
  DCHECK(!property.IsSurrogate());
  DCHECK(!resolver.IsLocked(property));
  CascadeResolver::AutoLock lock(property, resolver);

  const CSSVariableData* data = value.VariableDataValue();
  const CSSParserContext* context = GetParserContext(value);

  MarkHasVariableReference(property);

  DCHECK(data);
  DCHECK(context);

  TokenSequence sequence;

  CSSParserTokenStream stream(data->OriginalText());
  if (ResolveTokensInto(stream, resolver, *context, FunctionContext{},
                        /* stop_type */ kEOFToken, sequence)) {
    // TODO(sesse): It would be nice if we had some way of combining
    // ResolveTokensInto() and the re-tokenization. This is basically
    // what we pay by using the streaming parser everywhere; we tokenize
    // everything involving variable references twice.
    CSSParserTokenStream stream2(sequence.OriginalText());
    if (const auto* parsed = Parse(property, stream2, context)) {
      return parsed;
    }
  }

  return cssvalue::CSSUnsetValue::Create();
}

const CSSValue* StyleCascade::ResolvePendingSubstitution(
    const CSSProperty& property,
    const cssvalue::CSSPendingSubstitutionValue& value,
    CascadeResolver& resolver) {
  DCHECK(!property.IsSurrogate());
  DCHECK(!resolver.IsLocked(property));
  CascadeResolver::AutoLock lock(property, resolver);

  CascadePriority priority = map_.At(property.GetCSSPropertyName());
  DCHECK_NE(property.PropertyID(), CSSPropertyID::kVariable);
  DCHECK_NE(priority.GetOrigin(), CascadeOrigin::kNone);

  MarkHasVariableReference(property);

  // If the previous call to ResolvePendingSubstitution parsed 'value', then
  // we don't need to do it again.
  bool is_cached = resolver.shorthand_cache_.value == &value;

  if (!is_cached) {
    CSSUnparsedDeclarationValue* shorthand_value = value.ShorthandValue();
    const auto* shorthand_data = shorthand_value->VariableDataValue();
    CSSPropertyID shorthand_property_id = value.ShorthandPropertyId();

    TokenSequence sequence;

    CSSParserTokenStream stream(shorthand_data->OriginalText());
    if (!ResolveTokensInto(
            stream, resolver, *GetParserContext(*shorthand_value),
            FunctionContext{}, /* stop_type */ kEOFToken, sequence)) {
      return cssvalue::CSSUnsetValue::Create();
    }

    HeapVector<CSSPropertyValue, 64> parsed_properties;

    // NOTE: We don't actually need the original text to be comment-stripped,
    // since we're not storing it in a custom property anywhere.
    CSSParserTokenStream stream2(sequence.OriginalText());
    if (!CSSPropertyParser::ParseValue(
            shorthand_property_id, /*allow_important_annotation=*/false,
            stream2, shorthand_value->ParserContext(), parsed_properties,
            StyleRule::RuleType::kStyle)) {
      return cssvalue::CSSUnsetValue::Create();
    }

    resolver.shorthand_cache_.value = &value;
    resolver.shorthand_cache_.parsed_properties = std::move(parsed_properties);
  }

  const auto& parsed_properties = resolver.shorthand_cache_.parsed_properties;

  // For -internal-visited-properties with CSSPendingSubstitutionValues,
  // the inner 'shorthand_property_id' will expand to a set of longhands
  // containing the unvisited equivalent. Hence, when parsing the
  // CSSPendingSubstitutionValue, we look for the unvisited property in
  // parsed_properties.
  const CSSProperty* unvisited_property =
      property.IsVisited() ? property.GetUnvisitedProperty() : &property;

  unsigned parsed_properties_count = parsed_properties.size();
  for (unsigned i = 0; i < parsed_properties_count; ++i) {
    const CSSProperty& longhand = CSSProperty::Get(parsed_properties[i].Id());
    const CSSValue* parsed = parsed_properties[i].Value();

    // When using var() in a css-logical shorthand (e.g. margin-inline),
    // the longhands here will also be logical.
    if (unvisited_property == &ResolveSurrogate(longhand)) {
      return parsed;
    }
  }

  NOTREACHED();
}

const CSSValue* StyleCascade::ResolveRevert(const CSSProperty& property,
                                            const CSSValue& value,
                                            CascadeOrigin& origin,
                                            CascadeResolver& resolver) {
  MaybeUseCountRevert(value);

  CascadeOrigin target_origin = TargetOriginForRevert(origin);

  switch (target_origin) {
    case CascadeOrigin::kTransition:
    case CascadeOrigin::kNone:
      return cssvalue::CSSUnsetValue::Create();
    case CascadeOrigin::kUserAgent:
    case CascadeOrigin::kUser:
    case CascadeOrigin::kAuthorPresentationalHint:
    case CascadeOrigin::kAuthor:
    case CascadeOrigin::kAnimation: {
      const CascadePriority* p =
          map_.Find(property.GetCSSPropertyName(), target_origin);
      if (!p || !p->HasOrigin()) {
        origin = CascadeOrigin::kNone;
        return cssvalue::CSSUnsetValue::Create();
      }
      origin = p->GetOrigin();
      return Resolve(property, *ValueAt(match_result_, p->GetPosition()), *p,
                     origin, resolver);
    }
  }
}

const CSSValue* StyleCascade::ResolveRevertLayer(const CSSProperty& property,
                                                 CascadePriority priority,
                                                 CascadeOrigin& origin,
                                                 CascadeResolver& resolver) {
  const CascadePriority* p = map_.FindRevertLayer(
      property.GetCSSPropertyName(), priority.ForLayerComparison());
  if (!p) {
    origin = CascadeOrigin::kNone;
    return cssvalue::CSSUnsetValue::Create();
  }
  origin = p->GetOrigin();
  return Resolve(property, *ValueAt(match_result_, p->GetPosition()), *p,
                 origin, resolver);
}

const CSSValue* StyleCascade::ResolveFlipRevert(const CSSProperty& property,
                                                const CSSFlipRevertValue& value,
                                                CascadePriority priority,
                                                CascadeOrigin& origin,
                                                CascadeResolver& resolver) {
  const CSSProperty& to_property =
      ResolveSurrogate(CSSProperty::Get(value.PropertyID()));
  const CSSValue* unflipped =
      ResolveRevertLayer(to_property, priority, origin, resolver);
  // Note: the value is transformed *from* the property we're reverting *to*.
  const CSSValue* flipped = TryValueFlips::FlipValue(
      /* from_property */ to_property.PropertyID(), unflipped,
      value.Transform(), state_.StyleBuilder().GetWritingDirection());
  return Resolve(property, *flipped, priority, origin, resolver);
}

// Math functions can become invalid at computed-value time. Currently, this
// is only possible for invalid anchor*() functions.
//
// https://drafts.csswg.org/css-anchor-position-1/#anchor-valid
// https://drafts.csswg.org/css-anchor-position-1/#anchor-size-valid
const CSSValue* StyleCascade::ResolveMathFunction(
    const CSSProperty& property,
    const CSSMathFunctionValue& math_value,
    CascadePriority priority) {
  if (!math_value.HasAnchorFunctions()) {
    return &math_value;
  }

  const CSSLengthResolver& length_resolver = state_.CssToLengthConversionData();

  // Calling HasInvalidAnchorFunctions evaluates the anchor*() functions
  // inside the CSSMathFunctionValue. Evaluating anchor*() requires that we
  // have the correct AnchorEvaluator::Mode, so we need to set that just like
  // we do for during e.g. Left::ApplyValue, Right::ApplyValue, etc.
  AnchorScope anchor_scope(property.PropertyID(),
                           length_resolver.GetAnchorEvaluator());
  // HasInvalidAnchorFunctions actually evaluates any anchor*() queries
  // within the CSSMathFunctionValue, and this requires the TreeScope to
  // be populated.
  const auto* scoped_math_value = To<CSSMathFunctionValue>(
      EnsureScopedValue(GetDocument(), match_result_, priority, &math_value));
  if (scoped_math_value->HasInvalidAnchorFunctions(length_resolver)) {
    return cssvalue::CSSUnsetValue::Create();
  }
  return scoped_math_value;
}

CSSVariableData* StyleCascade::ResolveVariableData(
    CSSVariableData* data,
    const CSSParserContext& context,
    CascadeResolver& resolver) {
  DCHECK(data && data->NeedsVariableResolution());

  TokenSequence sequence(data);

  CSSParserTokenStream stream(data->OriginalText());
  if (!ResolveTokensInto(stream, resolver, context, FunctionContext{},
                         /* stop_type */ kEOFToken, sequence)) {
    return nullptr;
  }

  return sequence.BuildVariableData();
}

bool StyleCascade::ResolveTokensInto(CSSParserTokenStream& stream,
                                     CascadeResolver& resolver,
                                     const CSSParserContext& context,
                                     const FunctionContext& function_context,
                                     CSSParserTokenType stop_type,
                                     TokenSequence& out) {
  bool success = true;
  int nesting_level = 0;
  while (true) {
    const CSSParserToken& token = stream.Peek();
    if (token.IsEOF()) {
      break;
    } else if (token.GetType() == stop_type && nesting_level == 0) {
      break;
    } else if (token.FunctionId() == CSSValueID::kVar) {
      CSSParserTokenStream::BlockGuard guard(stream);
      success &= ResolveVarInto(stream, resolver, context, out);
    } else if (token.FunctionId() == CSSValueID::kEnv) {
      CSSParserTokenStream::BlockGuard guard(stream);
      success &= ResolveEnvInto(stream, resolver, context, out);
    } else if (token.FunctionId() == CSSValueID::kArg &&
               RuntimeEnabledFeatures::CSSFunctionsEnabled()) {
      CSSParserTokenStream::BlockGuard guard(stream);
      success &=
          ResolveArgInto(stream, resolver, context, function_context, out);
    } else if (token.FunctionId() == CSSValueID::kAttr &&
               RuntimeEnabledFeatures::CSSAdvancedAttrFunctionEnabled()) {
      CSSParserTokenStream::BlockGuard guard(stream);
      state_.StyleBuilder().SetHasAttrFunction();
      success &= ResolveAttrInto(stream, resolver, context, out);
    } else if (token.FunctionId() ==
               CSSValueID::kInternalAppearanceAutoBaseSelect) {
      CSSParserTokenStream::BlockGuard guard(stream);
      success &=
          ResolveAppearanceAutoBaseSelectInto(stream, resolver, context, out);
    } else if (token.GetType() == kFunctionToken &&
               CSSVariableParser::IsValidVariableName(token.Value()) &&
               RuntimeEnabledFeatures::CSSFunctionsEnabled()) {
      // User-defined CSS function.
      CSSParserTokenStream::BlockGuard guard(stream);
      success &= ResolveFunctionInto(token.Value(), stream, resolver, context,
                                     function_context, out);
    } else {
      if (token.GetBlockType() == CSSParserToken::kBlockStart) {
        ++nesting_level;
      } else if (token.GetBlockType() == CSSParserToken::kBlockEnd) {
        if (nesting_level == 0) {
          // Attempting to go outside our block.
          break;
        }
        --nesting_level;
      }
      wtf_size_t start = stream.Offset();
      stream.ConsumeRaw();
      wtf_size_t end = stream.Offset();

      // NOTE: This will include any comment tokens that ConsumeRaw()
      // skipped over; i.e., any comment will be attributed to the
      // token after it and any trailing comments will be skipped.
      // This is fine, because trailing comments (sans whitespace)
      // should be skipped anyway.
      out.Append(token, stream.StringRangeAt(start, end - start));
    }
  }
  return success;
}

bool StyleCascade::ResolveVarInto(CSSParserTokenStream& stream,
                                  CascadeResolver& resolver,
                                  const CSSParserContext& context,
                                  TokenSequence& out) {
  CustomProperty property(ConsumeVariableName(stream), state_.GetDocument());
  DCHECK(stream.AtEnd() || (stream.Peek().GetType() == kCommaToken));

  // Any custom property referenced (by anything, even just once) in the
  // document can currently not be animated on the compositor. Hence we mark
  // properties that have been referenced.
  DCHECK(resolver.CurrentProperty());
  MarkIsReferenced(*resolver.CurrentProperty(), property);

  if (!resolver.DetectCycle(property)) {
    // We are about to substitute var(property). In order to do that, we must
    // know the computed value of 'property', hence we Apply it.
    //
    // We can however not do this if we're in a cycle. If a cycle is detected
    // here, it means we are already resolving 'property', and have discovered
    // a reference to 'property' during that resolution.
    LookupAndApply(property, resolver);
  }

  // Note that even if we are in a cycle, we must proceed in order to discover
  // secondary cycles via the var() fallback.

  CSSVariableData* data = GetVariableData(property);

  // If substitution is not allowed, treat the value as
  // invalid-at-computed-value-time.
  //
  // https://drafts.csswg.org/css-variables/#animation-tainted
  if (!resolver.AllowSubstitution(data)) {
    data = nullptr;
  }

  // If we have a fallback, we must process it to look for cycles,
  // even if we aren't going to use the fallback.
  //
  // https://drafts.csswg.org/css-variables/#cycles
  if (ConsumeComma(stream)) {
    stream.ConsumeWhitespace();

    TokenSequence fallback;
    bool success =
        ResolveTokensInto(stream, resolver, context, FunctionContext{},
                          /* stop_type */ kEOFToken, fallback);
    // The fallback must match the syntax of the referenced custom property.
    // https://drafts.css-houdini.org/css-properties-values-api-1/#fallbacks-in-var-references
    //
    // TODO(sesse): Do we need the token range here anymore?
    if (!ValidateFallback(property, fallback.OriginalText())) {
      return false;
    }
    if (!data) {
      return success &&
             out.AppendFallback(fallback, CSSVariableData::kMaxVariableBytes);
    }
  }

  if (!data || resolver.InCycle()) {
    return false;
  }

  return out.Append(data, CSSVariableData::kMaxVariableBytes);
}

bool StyleCascade::ResolveFunctionInto(StringView function_name,
                                       CSSParserTokenStream& stream,
                                       CascadeResolver& resolver,
                                       const CSSParserContext& context,
                                       const FunctionContext& function_context,
                                       TokenSequence& out) {
  state_.StyleBuilder().SetAffectedByCSSFunction();

  // TODO(sesse): Deal with tree-scoped references.
  StyleRuleFunction* function = nullptr;
  if (GetDocument().GetScopedStyleResolver()) {
    function =
        GetDocument().GetScopedStyleResolver()->FunctionForName(function_name);
  }
  if (!function) {
    return false;
  }

  // Parse and resolve function arguments.
  HeapHashMap<String, Member<const CSSValue>> function_arguments;

  bool first_parameter = true;
  for (const StyleRuleFunction::Parameter& parameter :
       function->GetParameters()) {
    stream.ConsumeWhitespace();
    if (!first_parameter) {
      if (stream.Peek().GetType() != kCommaToken) {
        return false;
      }
      stream.ConsumeIncludingWhitespace();
    }
    first_parameter = false;

    wtf_size_t value_start_offset = stream.LookAheadOffset();
    stream.SkipUntilPeekedTypeIs<kCommaToken, kRightParenthesisToken>();
    wtf_size_t value_end_offset = stream.LookAheadOffset();
    StringView argument_string = stream.StringRangeAt(
        value_start_offset, value_end_offset - value_start_offset);

    // We need to resolve the argument in the context of this function,
    // so that we can do type coercion on the resolved value before the call.
    // In particular, we want any arg() within the argument to be resolved
    // in our context; e.g., --foo(arg(--a)) should be our a, not foo's a
    // (if that even exists).
    //
    // Note that if this expression comes from directly a function call,
    // as in the example above (and if the return and argument types are the
    // same), we will effectively do type parsing of exactly the same data
    // twice. This is wasteful, and it's possible that we should do something
    // about it if it proves to be a common case.
    const CSSValue* argument_value = ResolveFunctionExpression(
        argument_string, parameter.type, resolver, context, function_context);
    if (argument_value == nullptr) {
      return false;
    }

    function_arguments.insert(parameter.name, argument_value);
  }

  const CSSValue* ret_value = ResolveFunctionExpression(
      function->GetFunctionBody().OriginalText(), function->GetReturnType(),
      resolver, context, FunctionContext{function_arguments});
  if (ret_value == nullptr) {
    return false;
  }
  // Urggg
  String ret_string = ret_value->CssText();
  CSSParserTokenStream ret_value_stream(ret_string);
  return ResolveTokensInto(ret_value_stream, resolver, context,
                           FunctionContext{}, /* stop_type */ kEOFToken, out);
}

// Resolves an expression within a function; in practice, either a function
// argument or its return value. In practice, this is about taking a string
// and coercing it into the given type -- and then the caller will convert it
// right back to a string again. This is pretty suboptimal, but it's the way
// registered properties also work, and crucially, without such a resolve step
// (which needs a type), we would not be able to collapse calc() expressions
// and similar, which could cause massive blowup as the values are passed
// through a large tree of function calls.
const CSSValue* StyleCascade::ResolveFunctionExpression(
    StringView expr,
    const StyleRuleFunction::Type& type,
    CascadeResolver& resolver,
    const CSSParserContext& context,
    const FunctionContext& function_context) {
  TokenSequence resolved_expr;

  // See documentation on should_add_implicit_calc.
  if (type.should_add_implicit_calc) {
    static const char kCalcToken[] = "calc";
    static const char kCalcStart[] = "calc(";
    resolved_expr.Append(
        CSSParserToken(kFunctionToken, kCalcToken, CSSParserToken::kBlockStart),
        kCalcStart);
  }

  CSSParserTokenStream argument_stream(expr);
  if (!ResolveTokensInto(argument_stream, resolver, context, function_context,
                         /* stop_type */ kEOFToken, resolved_expr)) {
    return nullptr;
  }

  if (type.should_add_implicit_calc) {
    static const char kCalcEnd[] = ")";
    resolved_expr.Append(
        CSSParserToken(kRightParenthesisToken, CSSParserToken::kBlockEnd),
        kCalcEnd);
  }

  const CSSValue* value = type.syntax.Parse(
      resolved_expr.OriginalText(), context, /*is_animation_tainted=*/false);
  if (!value) {
    return nullptr;
  }

  // Resolve the value as if it were a registered property, to get rid of
  // extraneous calc(), resolve lengths and so on.
  return &StyleBuilderConverter::ConvertRegisteredPropertyValue(state_, *value,
                                                                &context);
}

bool StyleCascade::ResolveEnvInto(CSSParserTokenStream& stream,
                                  CascadeResolver& resolver,
                                  const CSSParserContext& context,
                                  TokenSequence& out) {
  state_.StyleBuilder().SetHasEnv();
  AtomicString variable_name = ConsumeVariableName(stream);
  DCHECK(stream.AtEnd() || (stream.Peek().GetType() == kCommaToken) ||
         (stream.Peek().GetType() == kNumberToken));

  WTF::Vector<unsigned> indices;
  if (!stream.AtEnd() && stream.Peek().GetType() != kCommaToken) {
    do {
      const CSSParserToken& token = stream.ConsumeIncludingWhitespaceRaw();
      DCHECK(token.GetNumericValueType() == kIntegerValueType);
      DCHECK(token.NumericValue() >= 0.);
      indices.push_back(static_cast<unsigned>(token.NumericValue()));
    } while (stream.Peek().GetType() == kNumberToken);
  }

  DCHECK(stream.AtEnd() || (stream.Peek().GetType() == kCommaToken));

  CSSVariableData* data =
      GetEnvironmentVariable(variable_name, std::move(indices));

  if (!data) {
    if (ConsumeComma(stream)) {
      return ResolveTokensInto(stream, resolver, context, FunctionContext{},
                               /* stop_type */ kEOFToken, out);
    }
    return false;
  }

  return out.Append(data);
}

bool StyleCascade::ResolveArgInto(CSSParserTokenStream& stream,
                                  CascadeResolver& resolver,
                                  const CSSParserContext& context,
                                  const FunctionContext& function_context,
                                  TokenSequence& out) {
  AtomicString argument_name = ConsumeVariableName(stream);
  DCHECK(stream.AtEnd());

  const auto it = function_context.arguments.find(argument_name);
  if (it == function_context.arguments.end()) {
    // Argument not found.
    return false;
  }

  String arg_value = it->value->CssText();
  CSSParserTokenStream arg_value_stream(arg_value);
  return ResolveTokensInto(arg_value_stream, resolver, context,
                           FunctionContext{}, /* stop_type */ kEOFToken, out);
}

// Mark the value as tainted, so that ConsumeUrl() and similar can check
// that they should not create URLs from it. Note that we do this _after_
// the value, not before, so that we are sure that lookahead does not
// accidentally consume it.
void StyleCascade::AppendTaintToken(TokenSequence& out) {
  out.Append(CSSParserToken(kCommentToken), GetCSSAttrTaintToken());
}

bool StyleCascade::ResolveAttrInto(CSSParserTokenStream& stream,
                                   CascadeResolver& resolver,
                                   const CSSParserContext& context,
                                   TokenSequence& out) {
  AtomicString attribute_name = ConsumeVariableName(stream);
  std::optional<CSSAttrType> attr_type = CSSAttrType::Consume(stream);
  if (!attr_type.has_value()) {
    attr_type = CSSAttrType::GetDefaultValue();
  }
  DCHECK(stream.AtEnd() || stream.Peek().GetType() == kCommaToken);

  const String& attribute_value =
      state_.GetUltimateOriginatingElementOrSelf().getAttribute(attribute_name);

  const CSSValue* substitution_value =
      attribute_value.IsNull() ? nullptr
                               : attr_type->Parse(attribute_value, context);

  // Validate fallback value.
  if (ConsumeComma(stream)) {
    stream.ConsumeWhitespace();

    TokenSequence fallback;
    if (!ResolveTokensInto(stream, resolver, context, Functio
```