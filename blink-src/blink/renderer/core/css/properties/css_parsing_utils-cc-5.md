Response:
The user wants a summary of the functionality of the provided C++ code snippet from the `css_parsing_utils.cc` file in the Chromium Blink engine. Specifically, they're interested in:

1. **General Functionality:** What does this code do?
2. **Relation to Web Technologies:** How does it connect to JavaScript, HTML, and CSS? Provide examples.
3. **Logic and Reasoning:** If the code makes decisions, show input and output examples.
4. **Common User/Programming Errors:**  Illustrate potential mistakes when using or interacting with this functionality.
5. **User Path to Trigger:**  Explain how a user's actions in a web browser could lead to this code being executed (as a debugging clue).
6. **Functionality Summary:** A concise recap of the code's purpose.

Given that this is part 6 of 9, it's likely this file contains a collection of utility functions related to parsing CSS properties. The naming conventions (`Parse...`, `Consume...`) strongly suggest this.

**Plan:**

1. **Identify Core Functionality:** Analyze the function names and their parameters to understand their individual purposes (parsing specific CSS values like `mask-size`, `background-size`, `border-image`, `box-shadow`, etc.).
2. **Relate to CSS:**  Explain how these parsing functions directly correspond to CSS properties and their possible values. Provide CSS code examples that would trigger these functions.
3. **Connect to HTML:**  Show how these CSS properties are applied to HTML elements.
4. **Consider JavaScript Interaction (if any):** While this is C++, the parsing results are used by the rendering engine, which interacts with the DOM manipulated by JavaScript. Briefly mention this indirect relationship.
5. **Illustrate Logic with Examples:**  For functions like `ParseBackgroundOrMask`, show how different CSS values (e.g., multiple background layers, different combinations of properties) would be parsed. Provide assumed input (CSS tokens) and output (parsed CSS values).
6. **Identify Potential Errors:**  Focus on common mistakes in CSS syntax that would lead to parsing failures (e.g., invalid values, incorrect ordering, missing commas).
7. **Describe User Actions:** Trace back from parsing to user actions like typing CSS in developer tools, loading a webpage with specific stylesheets, or JavaScript modifying element styles.
8. **Synthesize a Concise Summary:** Combine the key findings into a brief description of the code's role.
这是 Chromium Blink 引擎源代码文件 `blink/renderer/core/css/properties/css_parsing_utils.cc` 的一部分，主要功能是提供用于解析 CSS 属性值的实用工具函数。

**功能归纳 (基于提供的代码片段):**

这段代码主要负责解析与背景 (`background`) 和遮罩 (`mask`) 相关的 CSS 属性值，以及一些其他的边框和阴影相关的属性。更具体地说，它包含了以下功能：

* **解析 `mask-size` 和 `background-size`:** `ParseMaskSize` 和 `ParseBackgroundSize` 函数使用 `ConsumeCommaSeparatedList` 结合 `ConsumeBackgroundSize` 来解析逗号分隔的 `mask-size` 和 `background-size` 值列表。
* **解析 `clip-path` 的坐标盒子或 `no-clip` 关键字:** `ConsumeCoordBoxOrNoClip` 函数用于解析 `clip-path` 属性中可能出现的 `no-clip` 关键字或坐标盒子 (`coord-box`)。
* **解析背景和遮罩的各个组成部分:** `ConsumeBackgroundComponent` 函数根据传入的 `CSSPropertyID`，调用不同的 `Consume...` 函数来解析背景或遮罩的各个组成部分，例如 `background-clip`、`background-attachment`、`background-origin`、`background-image`、`background-position`、`background-size`、`background-color`、`background-repeat` 以及对应的遮罩属性。
* **解析 `background` 和 `mask` 缩写属性:** `ParseBackgroundOrMask` 函数处理 `background` 和 `mask` 这两个缩写属性的解析。它会逐层解析背景或遮罩的各个属性值，并处理逗号分隔的多层情况。
* **解析 `repeat-style` 值:** `ConsumeRepeatStyleIdent` 和 `ConsumeRepeatStyleValue` 函数用于解析 `background-repeat` 和 `mask-repeat` 属性的关键字值（例如 `repeat`, `no-repeat`, `round`, `space`, `repeat-x`, `repeat-y`）。`ParseRepeatStyle` 用于解析逗号分隔的 `repeat-style` 值列表。
* **解析 `-webkit-border-image` 属性:** `ConsumeWebkitBorderImage` 和 `ConsumeBorderImageComponents` 函数用于解析 `-webkit-border-image` 缩写属性的各个组成部分，例如 `border-image-source`、`border-image-slice`、`border-image-width`、`border-image-outset` 和 `border-image-repeat`。
* **解析 `border-image-repeat`、`border-image-slice`、`border-image-width` 和 `border-image-outset`:**  相应的 `ConsumeBorderImage...` 函数用于解析这些 `border-image` 属性的详细值。
* **解析 `border-radius` 的角:** `ParseBorderRadiusCorner` 函数用于解析 `border-radius` 属性中表示角的长度或百分比值。
* **解析 `border-width`:** `ParseBorderWidthSide` 函数用于解析边框宽度的值。
* **解析 `gap` 相关的属性值 (实验性):** `ConsumeGapDecorationPropertyValue`, `ConsumeGapDecorationRepeatFunction`, `ConsumeGapDecorationPropertyList` 这组函数似乎与网格布局或多列布局中 `gap` 属性的装饰效果相关，可能涉及到颜色、宽度和重复模式的解析。
* **解析 `box-shadow` 和 `text-shadow`:** `ConsumeShadow` 和 `ParseSingleShadow` 函数用于解析 `box-shadow` 和 `text-shadow` 属性的值，包括偏移量、模糊半径、扩展半径、颜色和 `inset` 关键字。
* **解析列相关的属性:** `ConsumeColumnCount` 和 `ConsumeColumnWidth` 用于解析多列布局中 `column-count` 和 `column-width` 属性的值。`ConsumeColumnWidthOrCount` 用于尝试解析二者之一。
* **解析 `gap` 长度:** `ConsumeGapLength` 用于解析网格布局或多列布局中 `row-gap` 和 `column-gap` 属性的值。
* **解析计数器相关属性:** `ConsumeCounter` 用于解析与 CSS 计数器相关的属性值。
* **解析数学深度:** `ConsumeMathDepth` 函数用于解析与数学公式渲染深度相关的属性值。
* **解析 `font-size` 和 `line-height`:** `ConsumeFontSize` 和 `ConsumeLineHeight` 函数分别用于解析字体大小和行高的值。
* **解析调色板混合函数:** `ConsumePaletteMixFunction` 和 `ConsumeFontPalette` 用于解析 CSS 调色板混合函数 `palette-mix()` 和相关的调色板标识符。
* **解析 `font-family`:** `ConsumeFontFamily` 和 `ConsumeNonGenericFamilyNameList` 用于解析字体族名称列表。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件中的代码是 CSS 解析器的一部分，它负责理解浏览器从 CSS 样式表或 HTML `<style>` 标签中读取的 CSS 规则。

* **CSS:** 这是最直接的关系。这些函数负责解析各种 CSS 属性的值。例如：
    * CSS 代码: `background-size: cover;` 会调用 `ParseBackgroundSize` 和 `ConsumeBackgroundSize` 来解析 `cover` 关键字。
    * CSS 代码: `mask-size: 50% auto, 100px;` 会调用 `ParseMaskSize` 和 `ConsumeBackgroundSize` 来解析逗号分隔的两个 `mask-size` 值。
    * CSS 代码: `border-image: url(border.png) 20% fill repeat;` 会调用 `ConsumeWebkitBorderImage` 和相关的 `ConsumeBorderImage...` 函数来解析边框图像的各个属性。
    * CSS 代码: `box-shadow: 5px 5px 10px black, inset 2px 2px red;` 会调用 `ConsumeShadow` 和 `ParseSingleShadow` 来解析两个阴影效果。

* **HTML:**  HTML 提供了承载 CSS 的方式。浏览器解析 HTML 时，会遇到 `<link>` 标签引入的外部 CSS 文件或 `<style>` 标签内的内联 CSS。这些 CSS 代码最终会被传递给这里的解析器进行处理。
    * HTML 代码:
    ```html
    <div style="background-size: contain;"></div>
    ```
    当浏览器渲染这个 `div` 元素时，会解析 `style` 属性中的 CSS，`background-size: contain;` 就会触发相关的解析函数。

* **JavaScript:** JavaScript 可以通过 DOM API 操作元素的样式。当 JavaScript 设置或修改元素的 CSS 属性时，浏览器需要重新解析这些样式。
    * JavaScript 代码:
    ```javascript
    element.style.backgroundSize = '100px 200px';
    ```
    这行代码会触发浏览器重新解析 `background-size` 属性，最终会调用到这里的解析函数。

**逻辑推理的假设输入与输出:**

假设输入是 `ParseBackgroundOrMask` 函数接收到的一个表示 `background` 属性的 CSS token 流：

**假设输入:**

```
Token(IDENT, "url"), Token(OPEN_PAREN), Token(STRING, "image.png"), Token(CLOSE_PAREN),
Token(IDENT, "center"), Token(KEYWORD, "/"), Token(LENGHT, "50px"),
Token(COMMA),
Token(COLOR, "red")
```

**假设输出 (简化的表示，实际输出会是 CSSValue 对象的结构):**

一个包含两个背景层的结构：

* **第一层:**
    * `background-image`: `url("image.png")`
    * `background-position-x`: `center`
    * `background-position-y`: `center` (假设默认值)
    * `background-size`: `50px`
    * 其他属性为初始值或默认值
* **第二层:**
    * `background-color`: `red`
    * 其他属性为初始值或默认值

**涉及用户或者编程常见的使用错误及举例说明:**

* **CSS 语法错误:** 用户在编写 CSS 时可能会犯语法错误，导致解析失败。
    * 错误示例: `background-size: 100px200px;` (缺少空格) - 解析器无法识别这是一个长度对，可能返回错误或使用默认值。
    * 错误示例: `mask-size: , 50%;` (多余的逗号) - 会导致解析逗号分隔列表时出错。
    * 错误示例: `border-image-slice: 20% filll;` (拼写错误) - 解析器无法识别 `filll` 关键字。

* **类型不匹配:** 提供了不符合属性值类型的参数。
    * 错误示例: `background-size: blue;` (颜色值用于长度) -  `ConsumeBackgroundSize` 期望的是长度或关键字，解析颜色会失败。

* **属性值顺序错误 (在缩写属性中):** 缩写属性对值的顺序有严格的要求。
    * 错误示例: `background: red url(image.png);` (颜色应该在图像之前) - 虽然某些浏览器可能容错，但规范上是不正确的，可能导致解析结果不符合预期。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编辑 CSS:** 用户直接在开发者工具的 "Styles" 面板中修改元素的 CSS 属性，或者编辑本地的 CSS 文件。例如，用户修改了某个元素的 `background-size` 属性。
2. **浏览器接收到 CSS:** 浏览器（更具体地说是渲染引擎）接收到这些修改后的 CSS 规则。
3. **样式计算:** 渲染引擎需要计算出元素的最终样式。这涉及到解析 CSS 规则。
4. **CSS 解析:** 当遇到 `background-size` 属性时，渲染引擎会调用相应的 CSS 解析代码，即这个 `css_parsing_utils.cc` 文件中的 `ParseBackgroundSize` 函数。
5. **Tokenization:** 在解析之前，CSS 字符串会被分解成一个个的 token (例如 `IDENT`, `LENGHT`, `KEYWORD` 等)。
6. **解析函数执行:**  `ParseBackgroundSize` 函数会读取 token 流，并根据语法规则调用更底层的 `Consume...` 函数来识别和提取属性值。
7. **生成 CSSValue 对象:** 解析成功后，会生成表示 `background-size` 值的 `CSSValue` 对象，供后续的布局和绘制阶段使用。

如果开发者在调试样式问题，例如 `background-size` 没有生效，那么他们可能会在渲染引擎的 CSS 解析部分设置断点，查看 `ParseBackgroundSize` 函数的输入 token 流和解析过程，以确定是否是 CSS 语法错误或者解析器的问题。

**第6部分功能归纳:**

这部分代码主要集中在 **解析与背景、遮罩、边框图像、阴影以及一些布局相关的 CSS 属性值**。它提供了一系列工具函数，用于从 CSS token 流中提取并转换成内部表示 (CSSValue 对象)。这些函数是 CSS 解析器的核心组成部分，负责将 CSS 文本转化为浏览器可以理解和使用的结构化数据。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/css_parsing_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共9部分，请归纳一下它的功能

"""
,
      stream, context, negative_size,
      local_context.UseAliasParsing() ? ParsingStyle::kLegacy
                                      : ParsingStyle::kNotLegacy);
}

CSSValue* ParseMaskSize(CSSParserTokenStream& stream,
                        const CSSParserContext& context,
                        const CSSParserLocalContext& local_context,
                        std::optional<WebFeature> negative_size) {
  return ConsumeCommaSeparatedList(
      static_cast<CSSValue* (*)(CSSParserTokenStream&, const CSSParserContext&,
                                std::optional<WebFeature>, ParsingStyle)>(
          ConsumeBackgroundSize),
      stream, context, negative_size, ParsingStyle::kNotLegacy);
}

CSSValue* ConsumeCoordBoxOrNoClip(CSSParserTokenStream& stream) {
  if (stream.Peek().Id() == CSSValueID::kNoClip) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeCoordBox(stream);
}

namespace {

CSSValue* ConsumeBackgroundComponent(CSSPropertyID resolved_property,
                                     CSSParserTokenStream& stream,
                                     const CSSParserContext& context,
                                     bool use_alias_parsing) {
  switch (resolved_property) {
    case CSSPropertyID::kBackgroundClip:
      if (RuntimeEnabledFeatures::CSSBackgroundClipUnprefixEnabled()) {
        return ConsumeBackgroundBoxOrText(stream);
      } else {
        return ConsumeBackgroundBox(stream);
      }
    case CSSPropertyID::kBackgroundAttachment:
      return ConsumeBackgroundAttachment(stream);
    case CSSPropertyID::kBackgroundOrigin:
      return ConsumeBackgroundBox(stream);
    case CSSPropertyID::kBackgroundImage:
    case CSSPropertyID::kMaskImage:
      return ConsumeImageOrNone(stream, context);
    case CSSPropertyID::kBackgroundPositionX:
    case CSSPropertyID::kWebkitMaskPositionX:
      return ConsumePositionLonghand<CSSValueID::kLeft, CSSValueID::kRight>(
          stream, context);
    case CSSPropertyID::kBackgroundPositionY:
    case CSSPropertyID::kWebkitMaskPositionY:
      return ConsumePositionLonghand<CSSValueID::kTop, CSSValueID::kBottom>(
          stream, context);
    case CSSPropertyID::kBackgroundSize:
      return ConsumeBackgroundSize(stream, context,
                                   WebFeature::kNegativeBackgroundSize,
                                   ParsingStyle::kNotLegacy);
    case CSSPropertyID::kMaskSize:
      return ConsumeBackgroundSize(stream, context,
                                   WebFeature::kNegativeMaskSize,
                                   ParsingStyle::kNotLegacy);
    case CSSPropertyID::kBackgroundColor:
      return ConsumeColor(stream, context);
    case CSSPropertyID::kMaskClip:
      return use_alias_parsing
                 ? ConsumePrefixedBackgroundBox(stream, AllowTextValue::kAllow)
                 : ConsumeCoordBoxOrNoClip(stream);
    case CSSPropertyID::kMaskOrigin:
      return use_alias_parsing
                 ? ConsumePrefixedBackgroundBox(stream, AllowTextValue::kForbid)
                 : ConsumeCoordBox(stream);
    case CSSPropertyID::kBackgroundRepeat:
    case CSSPropertyID::kMaskRepeat:
      return ConsumeRepeatStyleValue(stream);
    case CSSPropertyID::kMaskComposite:
      return ConsumeMaskComposite(stream);
    case CSSPropertyID::kMaskMode:
      return ConsumeMaskMode(stream);
    default:
      return nullptr;
  };
}

}  // namespace

// Note: this assumes y properties (e.g. background-position-y) follow the x
// properties in the shorthand array.
// TODO(jiameng): this is used by background and -webkit-mask, hence we
// need local_context as an input that contains shorthand id. We will consider
// remove local_context as an input after
//   (i). StylePropertyShorthand is refactored and
//   (ii). we split parsing logic of background and -webkit-mask into
//   different property classes.
bool ParseBackgroundOrMask(bool important,
                           CSSParserTokenStream& stream,
                           const CSSParserContext& context,
                           const CSSParserLocalContext& local_context,
                           HeapVector<CSSPropertyValue, 64>& properties) {
  CSSPropertyID shorthand_id = local_context.CurrentShorthand();
  DCHECK(shorthand_id == CSSPropertyID::kBackground ||
         shorthand_id == CSSPropertyID::kMask);
  const StylePropertyShorthand& shorthand =
      shorthand_id == CSSPropertyID::kBackground ? backgroundShorthand()
                                                 : maskShorthand();

  const unsigned longhand_count = shorthand.length();
  std::array<HeapVector<Member<const CSSValue>, 4>, 10> longhands;
  CHECK_LE(longhand_count, 10u);

  bool implicit = false;
  bool previous_layer_had_background_color = false;
  do {
    std::array<bool, 10> parsed_longhand = {false};
    CSSValue* origin_value = nullptr;
    bool found_property;
    bool found_any = false;
    do {
      found_property = false;
      bool bg_position_parsed_in_current_layer = false;
      for (unsigned i = 0; i < longhand_count; ++i) {
        if (parsed_longhand[i]) {
          continue;
        }

        CSSValue* value = nullptr;
        CSSValue* value_y = nullptr;
        const CSSProperty& property = *shorthand.properties()[i];
        if (property.IDEquals(CSSPropertyID::kBackgroundPositionX) ||
            property.IDEquals(CSSPropertyID::kWebkitMaskPositionX)) {
          if (!ConsumePosition(stream, context, UnitlessQuirk::kForbid,
                               WebFeature::kThreeValuedPositionBackground,
                               value, value_y)) {
            continue;
          }
          if (value) {
            bg_position_parsed_in_current_layer = true;
          }
        } else if (property.IDEquals(CSSPropertyID::kBackgroundSize) ||
                   property.IDEquals(CSSPropertyID::kMaskSize)) {
          if (!ConsumeSlashIncludingWhitespace(stream)) {
            continue;
          }
          value = ConsumeBackgroundSize(
              stream, context,
              property.IDEquals(CSSPropertyID::kBackgroundSize)
                  ? WebFeature::kNegativeBackgroundSize
                  : WebFeature::kNegativeMaskSize,
              ParsingStyle::kNotLegacy);
          if (!value || !bg_position_parsed_in_current_layer) {
            return false;
          }
        } else if (property.IDEquals(CSSPropertyID::kBackgroundPositionY) ||
                   property.IDEquals(CSSPropertyID::kWebkitMaskPositionY)) {
          continue;
        } else {
          value =
              ConsumeBackgroundComponent(property.PropertyID(), stream, context,
                                         local_context.UseAliasParsing());
        }
        if (value) {
          if (property.IDEquals(CSSPropertyID::kBackgroundOrigin) ||
              property.IDEquals(CSSPropertyID::kMaskOrigin)) {
            origin_value = value;
          }
          parsed_longhand[i] = true;
          found_property = true;
          found_any = true;
          longhands[i].push_back(value);
          if (value_y) {
            parsed_longhand[i + 1] = true;
            longhands[i + 1].push_back(value_y);
          }
        }
      }
    } while (found_property && !stream.AtEnd() &&
             stream.Peek().GetType() != kCommaToken);

    if (!found_any) {
      return false;
    }
    if (previous_layer_had_background_color) {
      // Colors are only allowed in the last layer; previous layer had
      // a background color and we now know for sure it was not the last one,
      // so return parse failure.
      return false;
    }

    // TODO(timloh): This will make invalid longhands, see crbug.com/386459
    for (unsigned i = 0; i < longhand_count; ++i) {
      const CSSProperty& property = *shorthand.properties()[i];

      if (property.IDEquals(CSSPropertyID::kBackgroundColor)) {
        if (parsed_longhand[i]) {
          previous_layer_had_background_color = true;
        }
      }
      if (!parsed_longhand[i]) {
        if ((property.IDEquals(CSSPropertyID::kBackgroundClip) ||
             property.IDEquals(CSSPropertyID::kMaskClip)) &&
            origin_value) {
          longhands[i].push_back(origin_value);
          continue;
        }

        if (shorthand_id == CSSPropertyID::kMask) {
          longhands[i].push_back(To<Longhand>(property).InitialValue());
        } else {
          longhands[i].push_back(CSSInitialValue::Create());
        }
      }
    }
  } while (ConsumeCommaIncludingWhitespace(stream));

  for (unsigned i = 0; i < longhand_count; ++i) {
    const CSSProperty& property = *shorthand.properties()[i];

    const CSSValue* longhand;
    if (property.IDEquals(CSSPropertyID::kBackgroundColor)) {
      // There can only be one background-color (we've verified this earlier,
      // by means of previous_layer_had_background_color), so pick out only
      // the last one (any others will just be “initial” over and over again).
      longhand = longhands[i].back().Get();
    } else {
      // To conserve memory we don't wrap a single value in a list.
      longhand = GetSingleValueOrMakeList(CSSValue::kCommaSeparator,
                                          std::move(longhands[i]));
    }

    AddProperty(property.PropertyID(), shorthand.id(), *longhand, important,
                implicit ? IsImplicitProperty::kImplicit
                         : IsImplicitProperty::kNotImplicit,
                properties);
  }
  return true;
}

CSSIdentifierValue* ConsumeRepeatStyleIdent(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kRepeat, CSSValueID::kNoRepeat,
                      CSSValueID::kRound, CSSValueID::kSpace>(stream);
}

CSSRepeatStyleValue* ConsumeRepeatStyleValue(CSSParserTokenStream& stream) {
  if (auto* id = ConsumeIdent<CSSValueID::kRepeatX>(stream)) {
    return MakeGarbageCollected<CSSRepeatStyleValue>(id);
  }

  if (auto* id = ConsumeIdent<CSSValueID::kRepeatY>(stream)) {
    return MakeGarbageCollected<CSSRepeatStyleValue>(id);
  }

  if (auto* id1 = ConsumeRepeatStyleIdent(stream)) {
    if (auto* id2 = ConsumeRepeatStyleIdent(stream)) {
      return MakeGarbageCollected<CSSRepeatStyleValue>(id1, id2);
    }

    return MakeGarbageCollected<CSSRepeatStyleValue>(id1);
  }

  return nullptr;
}

CSSValueList* ParseRepeatStyle(CSSParserTokenStream& stream) {
  return ConsumeCommaSeparatedList(ConsumeRepeatStyleValue, stream);
}

CSSValue* ConsumeWebkitBorderImage(CSSParserTokenStream& stream,
                                   const CSSParserContext& context) {
  CSSValue* source = nullptr;
  CSSValue* slice = nullptr;
  CSSValue* width = nullptr;
  CSSValue* outset = nullptr;
  CSSValue* repeat = nullptr;
  if (ConsumeBorderImageComponents(stream, context, source, slice, width,
                                   outset, repeat, DefaultFill::kFill)) {
    return CreateBorderImageValue(source, slice, width, outset, repeat);
  }
  return nullptr;
}

bool ConsumeBorderImageComponents(CSSParserTokenStream& stream,
                                  const CSSParserContext& context,
                                  CSSValue*& source,
                                  CSSValue*& slice,
                                  CSSValue*& width,
                                  CSSValue*& outset,
                                  CSSValue*& repeat,
                                  DefaultFill default_fill) {
  do {
    if (!source) {
      source = ConsumeImageOrNone(stream, context);
      if (source) {
        continue;
      }
    }
    if (!repeat) {
      repeat = ConsumeBorderImageRepeat(stream);
      if (repeat) {
        continue;
      }
    }
    if (!slice) {
      CSSParserSavePoint savepoint(stream);
      slice = ConsumeBorderImageSlice(stream, context, default_fill);
      if (slice) {
        DCHECK(!width);
        DCHECK(!outset);
        if (ConsumeSlashIncludingWhitespace(stream)) {
          width = ConsumeBorderImageWidth(stream, context);
          if (ConsumeSlashIncludingWhitespace(stream)) {
            outset = ConsumeBorderImageOutset(stream, context);
            if (!outset) {
              break;
            }
          } else if (!width) {
            break;
          }
        }
      } else {
        break;
      }
      savepoint.Release();
    } else {
      break;
    }
  } while (!stream.AtEnd());
  if (!source && !repeat && !slice) {
    return false;
  }
  return true;
}

CSSValue* ConsumeBorderImageRepeat(CSSParserTokenStream& stream) {
  CSSIdentifierValue* horizontal = ConsumeBorderImageRepeatKeyword(stream);
  if (!horizontal) {
    return nullptr;
  }
  CSSIdentifierValue* vertical = ConsumeBorderImageRepeatKeyword(stream);
  if (!vertical) {
    vertical = horizontal;
  }
  return MakeGarbageCollected<CSSValuePair>(horizontal, vertical,
                                            CSSValuePair::kDropIdenticalValues);
}

CSSValue* ConsumeBorderImageSlice(CSSParserTokenStream& stream,
                                  const CSSParserContext& context,
                                  DefaultFill default_fill) {
  bool fill = ConsumeIdent<CSSValueID::kFill>(stream);
  std::array<CSSValue*, 4> slices = {nullptr};

  for (size_t index = 0; index < 4; ++index) {
    CSSPrimitiveValue* value = ConsumePercent(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!value) {
      value = ConsumeNumber(stream, context,
                            CSSPrimitiveValue::ValueRange::kNonNegative);
    }
    if (!value) {
      break;
    }
    slices[index] = value;
  }
  if (!slices[0]) {
    return nullptr;
  }
  if (ConsumeIdent<CSSValueID::kFill>(stream)) {
    if (fill) {
      return nullptr;
    }
    fill = true;
  }
  Complete4Sides(slices);
  if (default_fill == DefaultFill::kFill) {
    fill = true;
  }
  return MakeGarbageCollected<cssvalue::CSSBorderImageSliceValue>(
      MakeGarbageCollected<CSSQuadValue>(slices[0], slices[1], slices[2],
                                         slices[3],
                                         CSSQuadValue::kSerializeAsQuad),
      fill);
}

CSSValue* ConsumeBorderImageWidth(CSSParserTokenStream& stream,
                                  const CSSParserContext& context) {
  std::array<CSSValue*, 4> widths = {nullptr};

  CSSValue* value = nullptr;
  for (size_t index = 0; index < 4; ++index) {
    value = ConsumeNumber(stream, context,
                          CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!value) {
      CSSParserContext::ParserModeOverridingScope scope(context,
                                                        kHTMLStandardMode);
      value = ConsumeLengthOrPercent(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
          UnitlessQuirk::kForbid);
    }
    if (!value) {
      value = ConsumeIdent<CSSValueID::kAuto>(stream);
    }
    if (!value) {
      break;
    }
    widths[index] = value;
  }
  if (!widths[0]) {
    return nullptr;
  }
  Complete4Sides(widths);
  return MakeGarbageCollected<CSSQuadValue>(widths[0], widths[1], widths[2],
                                            widths[3],
                                            CSSQuadValue::kSerializeAsQuad);
}

CSSValue* ConsumeBorderImageOutset(CSSParserTokenStream& stream,
                                   const CSSParserContext& context) {
  std::array<CSSValue*, 4> outsets = {nullptr};

  CSSValue* value = nullptr;
  for (size_t index = 0; index < 4; ++index) {
    value = ConsumeNumber(stream, context,
                          CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!value) {
      CSSParserContext::ParserModeOverridingScope scope(context,
                                                        kHTMLStandardMode);
      value = ConsumeLength(stream, context,
                            CSSPrimitiveValue::ValueRange::kNonNegative);
    }
    if (!value) {
      break;
    }
    outsets[index] = value;
  }
  if (!outsets[0]) {
    return nullptr;
  }
  Complete4Sides(outsets);
  return MakeGarbageCollected<CSSQuadValue>(outsets[0], outsets[1], outsets[2],
                                            outsets[3],
                                            CSSQuadValue::kSerializeAsQuad);
}

CSSValue* ParseBorderRadiusCorner(CSSParserTokenStream& stream,
                                  const CSSParserContext& context) {
  CSSValue* parsed_value1 = ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (!parsed_value1) {
    return nullptr;
  }
  CSSValue* parsed_value2 = ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (!parsed_value2) {
    parsed_value2 = parsed_value1;
  }
  return MakeGarbageCollected<CSSValuePair>(parsed_value1, parsed_value2,
                                            CSSValuePair::kDropIdenticalValues);
}

CSSValue* ParseBorderWidthSide(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               const CSSParserLocalContext& local_context) {
  CSSPropertyID shorthand = local_context.CurrentShorthand();
  bool allow_quirky_lengths = IsQuirksModeBehavior(context.Mode()) &&
                              (shorthand == CSSPropertyID::kInvalid ||
                               shorthand == CSSPropertyID::kBorderWidth);
  UnitlessQuirk unitless =
      allow_quirky_lengths ? UnitlessQuirk::kAllow : UnitlessQuirk::kForbid;
  return ConsumeBorderWidth(stream, context, unitless);
}

const CSSValue* ParseBorderStyleSide(CSSParserTokenStream& stream,
                                     const CSSParserContext& context) {
  return ParseLonghand(CSSPropertyID::kBorderLeftStyle, CSSPropertyID::kBorder,
                       context, stream);
}

CSSValue* ConsumeGapDecorationPropertyValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    CSSGapDecorationPropertyType property_type) {
  switch (property_type) {
    case CSSGapDecorationPropertyType::kColor:
      return ConsumeColor(stream, context);
    case CSSGapDecorationPropertyType::kWidth:
      return ConsumeLineWidth(stream, context,
                              css_parsing_utils::UnitlessQuirk::kForbid);
      // TODO(crbug.com/357648037): Add kStyle when implemented.
  }
}

cssvalue::CSSRepeatValue* ConsumeGapDecorationRepeatFunction(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSGapDecorationPropertyType property_type) {
  DCHECK_EQ(stream.Peek().GetType(), kFunctionToken);
  CSSParserTokenStream::RestoringBlockGuard guard(stream);

  stream.ConsumeWhitespace();

  CSSPrimitiveValue* repetition_value = nullptr;

  if (IdentMatches<CSSValueID::kAuto>(stream.Peek().Id())) {
    CHECK(stream.ConsumeIncludingWhitespace().Id() == CSSValueID::kAuto);
  } else {
    // Means it's an integer repetition.
    repetition_value = ConsumeIntegerOrNumberCalc(
        stream, context, CSSPrimitiveValue::ValueRange::kPositiveInteger);
    if (!repetition_value) {
      return nullptr;
    }
  }

  // After auto/integer we expect a comma.
  if (!ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }

  CSSValueList* repeated_values = CSSValueList::CreateSpaceSeparated();
  while (!stream.AtEnd()) {
    CSSValue* value =
        ConsumeGapDecorationPropertyValue(stream, context, property_type);
    if (!value) {
      return nullptr;
    }
    repeated_values->Append(*value);
  }

  if (repeated_values->length() == 0) {
    return nullptr;
  }

  guard.Release();
  stream.ConsumeWhitespace();

  return MakeGarbageCollected<cssvalue::CSSRepeatValue>(repetition_value,
                                                        *repeated_values);
}

CSSValue* ConsumeGapDecorationPropertyList(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSGapDecorationPropertyType property_type) {
  // Consume single value if the Gap decoration feature flag is not
  // enabled.
  if (!RuntimeEnabledFeatures::CSSGapDecorationEnabled()) {
    return ConsumeGapDecorationPropertyValue(stream, context, property_type);
  }

  if (stream.AtEnd()) {
    return nullptr;
  }

  // Flag to limit to one auto-repeat.
  bool seen_auto_repeat = false;

  CSSValueList* values = CSSValueList::CreateSpaceSeparated();
  do {
    if (stream.Peek().FunctionId() == CSSValueID::kRepeat) {
      auto* repeat_value =
          ConsumeGapDecorationRepeatFunction(stream, context, property_type);
      if (!repeat_value) {
        return nullptr;
      }
      if (repeat_value->IsAutoRepeatValue()) {
        if (seen_auto_repeat) {
          return nullptr;
        }
        seen_auto_repeat = true;
      }
      values->Append(*repeat_value);
    } else {
      CSSValue* value =
          ConsumeGapDecorationPropertyValue(stream, context, property_type);
      if (!value) {
        break;
      }
      values->Append(*value);
    }
  } while (!stream.AtEnd());

  // If there are no values, return nullptr rather than an empty list so that we
  // use the default value for the property.
  if (values->length() == 0) {
    return nullptr;
  }

  return values;
}

CSSValue* ConsumeShadow(CSSParserTokenStream& stream,
                        const CSSParserContext& context,
                        AllowInsetAndSpread inset_and_spread) {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return ConsumeIdent(stream);
  }
  return ConsumeCommaSeparatedList(ParseSingleShadow, stream, context,
                                   inset_and_spread);
}

CSSShadowValue* ParseSingleShadow(CSSParserTokenStream& stream,
                                  const CSSParserContext& context,
                                  AllowInsetAndSpread inset_and_spread) {
  CSSIdentifierValue* style = nullptr;
  CSSValue* color = nullptr;

  if (stream.AtEnd()) {
    return nullptr;
  }

  color = ConsumeColor(stream, context);
  if (stream.Peek().Id() == CSSValueID::kInset) {
    if (inset_and_spread != AllowInsetAndSpread::kAllow) {
      return nullptr;
    }
    style = ConsumeIdent(stream);
    if (!color) {
      color = ConsumeColor(stream, context);
    }
  }

  CSSPrimitiveValue* horizontal_offset =
      ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (!horizontal_offset) {
    return nullptr;
  }

  CSSPrimitiveValue* vertical_offset =
      ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (!vertical_offset) {
    return nullptr;
  }

  CSSPrimitiveValue* blur_radius = ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  CSSPrimitiveValue* spread_distance = nullptr;
  if (blur_radius) {
    if (inset_and_spread == AllowInsetAndSpread::kAllow) {
      spread_distance =
          ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll);
    }
  }

  if (!stream.AtEnd()) {
    if (!color) {
      color = ConsumeColor(stream, context);
    }
    if (stream.Peek().Id() == CSSValueID::kInset) {
      if (inset_and_spread != AllowInsetAndSpread::kAllow || style) {
        return nullptr;
      }
      style = ConsumeIdent(stream);
      if (!color) {
        color = ConsumeColor(stream, context);
      }
    }
  }
  return MakeGarbageCollected<CSSShadowValue>(horizontal_offset,
                                              vertical_offset, blur_radius,
                                              spread_distance, style, color);
}

CSSValue* ConsumeColumnCount(CSSParserTokenStream& stream,
                             const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return ConsumeIdent(stream);
  }
  return ConsumePositiveInteger(stream, context);
}

CSSValue* ConsumeColumnWidth(CSSParserTokenStream& stream,
                             const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return ConsumeIdent(stream);
  }
  // Always parse lengths in strict mode here, since it would be ambiguous
  // otherwise when used in the 'columns' shorthand property.
  CSSParserContext::ParserModeOverridingScope scope(context, kHTMLStandardMode);
  CSSPrimitiveValue* column_width = ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (!column_width) {
    return nullptr;
  }
  return column_width;
}

bool ConsumeColumnWidthOrCount(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               CSSValue*& column_width,
                               CSSValue*& column_count) {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    ConsumeIdent(stream);
    return true;
  }
  if (!column_width) {
    column_width = ConsumeColumnWidth(stream, context);
    if (column_width) {
      return true;
    }
  }
  if (!column_count) {
    column_count = ConsumeColumnCount(stream, context);
  }
  return column_count;
}

CSSValue* ConsumeGapLength(CSSParserTokenStream& stream,
                           const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return ConsumeIdent(stream);
  }
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative);
}

CSSValue* ConsumeCounter(CSSParserTokenStream& stream,
                         const CSSParserContext& context,
                         int default_value) {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return ConsumeIdent(stream);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  do {
    CSSCustomIdentValue* counter_name = ConsumeCustomIdent(stream, context);
    if (!counter_name) {
      break;
    }
    CSSPrimitiveValue* value = CSSNumericLiteralValue::Create(
        default_value, CSSPrimitiveValue::UnitType::kInteger);
    if (CSSPrimitiveValue* counter_value = ConsumeInteger(stream, context)) {
      value = counter_value;
    }
    list->Append(*MakeGarbageCollected<CSSValuePair>(
        counter_name, value, CSSValuePair::kDropIdenticalValues));
  } while (!stream.AtEnd());
  if (list->length() == 0) {
    return nullptr;
  }
  return list;
}

CSSValue* ConsumeMathDepth(CSSParserTokenStream& stream,
                           const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kAutoAdd) {
    return ConsumeIdent(stream);
  }

  if (CSSPrimitiveValue* integer_value = ConsumeInteger(stream, context)) {
    return integer_value;
  }

  CSSValueID function_id = stream.Peek().FunctionId();
  if (function_id == CSSValueID::kAdd) {
    CSSValue* value;
    bool at_end;
    {
      CSSParserTokenStream::BlockGuard guard(stream);
      stream.ConsumeWhitespace();
      value = ConsumeInteger(stream, context);
      at_end = stream.AtEnd();
    }
    stream.ConsumeWhitespace();
    if (value && at_end) {
      auto* add_value = MakeGarbageCollected<CSSFunctionValue>(function_id);
      add_value->Append(*value);
      return add_value;
    }
  }

  return nullptr;
}

CSSValue* ConsumeFontSize(CSSParserTokenStream& stream,
                          const CSSParserContext& context,
                          UnitlessQuirk unitless) {
  if (stream.Peek().Id() == CSSValueID::kWebkitXxxLarge) {
    context.Count(WebFeature::kFontSizeWebkitXxxLarge);
  }
  if ((stream.Peek().Id() >= CSSValueID::kXxSmall &&
       stream.Peek().Id() <= CSSValueID::kWebkitXxxLarge) ||
      stream.Peek().Id() == CSSValueID::kMath) {
    return ConsumeIdent(stream);
  }
  return ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative, unitless);
}

CSSValue* ConsumeLineHeight(CSSParserTokenStream& stream,
                            const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return ConsumeIdent(stream);
  }

  CSSPrimitiveValue* line_height = ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (line_height) {
    return line_height;
  }
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative);
}

CSSValue* ConsumePaletteMixFunction(CSSParserTokenStream& stream,
                                    const CSSParserContext& context) {
  // Grammar proposal in: https://github.com/w3c/csswg-drafts/issues/8922
  //
  // palette-mix() = palette-mix(<color-interpolation-method> , [ [normal |
  // light | dark | <palette-identifier> | <palette-mix()>] && <percentage
  // [0,100]>? ]#{2})
  if (stream.Peek().FunctionId() != CSSValueID::kPaletteMix) {
    return nullptr;
  }

  Color::HueInterpolationMethod hue_interpolation_method =
      Color::HueInterpolationMethod::kShorter;
  Color::ColorSpace color_space;
  CSSValue* palette1;
  CSSValue* palette2;
  CSSPrimitiveValue* percentage1;
  CSSPrimitiveValue* percentage2;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    if (!ConsumeColorInterpolationSpace(stream, color_space,
                                        hue_interpolation_method)) {
      return nullptr;
    }

    auto consume_endpoint_palette_with_percentage =
        [](CSSParserTokenStream& stream, const CSSParserContext& context)
        -> std::pair<CSSValue*, CSSPrimitiveValue*> {
      if (!ConsumeCommaIncludingWhitespace(stream)) {
        return std::make_pair(nullptr, nullptr);
      }

      CSSValue* palette = ConsumeFontPalette(stream, context);
      CSSPrimitiveValue* percentage =
          ConsumePercent(stream, context, CSSPrimitiveValue::ValueRange::kAll);
      // Percentage can be followed by a palette.
      if (!palette) {
        palette = ConsumeFontPalette(stream, context);
        if (!palette) {
          return std::make_pair(nullptr, nullptr);
        }
      }
      // Reject negative values and values > 100%, but not calc() values.
      if (percentage && percentage->IsNumericLiteralValue() &&
          (To<CSSNumericLiteralValue>(percentage)->ComputePercentage() < 0.0 ||
           To<CSSNumericLiteralValue>(percentage)->ComputePercentage() >
               100.0)) {
        return std::make_pair(nullptr, nullptr);
      }
      return std::make_pair(palette, percentage);
    };

    auto palette_with_percentage_1 =
        consume_endpoint_palette_with_percentage(stream, context);
    auto palette_with_percentage_2 =
        consume_endpoint_palette_with_percentage(stream, context);
    palette1 = palette_with_percentage_1.first;
    palette2 = palette_with_percentage_2.first;
    percentage1 = palette_with_percentage_1.second;
    percentage2 = palette_with_percentage_2.second;

    if (!palette1 || !palette2) {
      return nullptr;
    }
    // If both values are literally zero (and not calc()) reject at parse time.
    if (percentage1 && percentage2 && percentage1->IsNumericLiteralValue() &&
        To<CSSNumericLiteralValue>(percentage1)->ComputePercentage() == 0.0f &&
        percentage2->IsNumericLiteralValue() &&
        To<CSSNumericLiteralValue>(percentage2)->ComputePercentage() == 0.0) {
      return nullptr;
    }

    if (!stream.AtEnd()) {
      return nullptr;
    }

    guard.Release();
  }
  stream.ConsumeWhitespace();

  return MakeGarbageCollected<cssvalue::CSSPaletteMixValue>(
      palette1, palette2, percentage1, percentage2, color_space,
      hue_interpolation_method);
}

CSSValue* ConsumeFontPalette(CSSParserTokenStream& stream,
                             const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNormal ||
      stream.Peek().Id() == CSSValueID::kLight ||
      stream.Peek().Id() == CSSValueID::kDark) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  if (stream.Peek().FunctionId() == CSSValueID::kPaletteMix) {
    return ConsumePaletteMixFunction(stream, context);
  }

  return ConsumeDashedIdent(stream, context);
}

CSSValueList* ConsumeFontFamily(CSSParserTokenStream& stream) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  do {
    CSSValue* parsed_value = ConsumeGenericFamily(stream);
    if (parsed_value) {
      list->Append(*parsed_value);
    } else {
      parsed_value = ConsumeFamilyName(stream);
      if (parsed_value) {
        list->Append(*parsed_value);
      } else {
        return nullptr;
      }
    }
  } while (ConsumeCommaIncludingWhitespace(stream));
  return list;
}

CSSValueList* ConsumeNonGenericFamilyNameList(CSSParserTokenStream& stream) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  do {
    CSSValue* parsed_value = ConsumeGenericFamily(stream);
    // Consume only if all families in the list are regular family names and
    // none of them are generic ones.
    if (parsed_value) {
      return nullptr;
    }
    parsed_va
"""


```