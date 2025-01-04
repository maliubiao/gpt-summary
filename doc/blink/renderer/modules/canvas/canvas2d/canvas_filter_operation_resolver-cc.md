Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionalities of the `canvas_filter_operation_resolver.cc` file within the Blink rendering engine. It also asks about its relationship to web technologies (JavaScript, HTML, CSS), examples, potential errors, and debugging tips.

2. **Initial Code Scan and Keyword Spotting:** Quickly read through the code, looking for recognizable keywords and patterns. Things that jump out:

    * `#include`:  Indicates dependencies on other parts of the Blink/Chromium codebase. The included headers like `canvas2d`, `css`, `dom`, `style`, `platform/graphics/filters`, `bindings/core/v8`,  `mojom/devtools` are crucial hints about the file's purpose.
    * `namespace blink`:  Confirms it's within the Blink rendering engine.
    * Function names like `ResolveColorMatrix`, `GetKernelMatrix`, `ResolveConvolveMatrix`, `ResolveBlur`, `ResolveDropShadow`, `ResolveTurbulence`:  These strongly suggest the file's core responsibility is processing and interpreting different filter types.
    * Class name `CanvasFilterOperationResolver`: Explicitly states the file's function.
    * Function `CreateFilterOperationsFromList`: Takes a `HeapVector<ScriptValue>` as input, suggesting it processes data coming from JavaScript.
    * Function `CreateFilterOperationsFromCSSFilter`: Takes a `String` as input, named `filter_string`, pointing to CSS filters.
    * `Dictionary`:  Repeatedly used to access properties, likely representing JavaScript objects passed to the native code.
    * `ExceptionState`:  Indicates error handling and communication back to the JavaScript environment.
    * `mojom::blink::ConsoleMessage`: Suggests logging or reporting issues to the browser's developer console.
    * `FilterOperation`, `FilterOperations`: Core data structures for representing and managing filter effects.

3. **Inferring Core Functionality:** Based on the keywords and function names, the primary function of this file is to **take descriptions of canvas filters (likely from JavaScript or CSS) and convert them into a format that the graphics rendering pipeline can understand and apply.** This involves parsing the filter parameters, validating them, and creating the appropriate `FilterOperation` objects.

4. **Connecting to Web Technologies:**

    * **JavaScript:** The `CreateFilterOperationsFromList` function accepting `ScriptValue` strongly ties this to the `<canvas>` API in JavaScript. The examples provided in the prompt directly use the `filter` property of the Canvas 2D rendering context.
    * **HTML:** The `<canvas>` element in HTML is the target where these filters are applied. The example shows how a canvas is created and its 2D context is accessed.
    * **CSS:**  The `CreateFilterOperationsFromCSSFilter` function clearly handles CSS `filter` property values. This allows applying the same kinds of visual effects to other HTML elements beyond just the canvas.

5. **Illustrative Examples (Input/Output):**  Think about how the JavaScript and CSS filter strings map to the C++ code.

    * **Input (JavaScript):**  A JavaScript object like `{ name: 'blur', stdDeviation: 5 }` is passed in.
    * **Processing:** The `CreateFilterOperationsFromList` function iterates, identifies "blur", calls `ResolveBlur`, which extracts "stdDeviation" and creates a `BlurFilterOperation`.
    * **Output (Internal):** A `BlurFilterOperation` object with the specified blur radius.

    Do the same for other filter types like `colorMatrix` and `dropShadow`.

    * **Input (CSS):** A CSS string like `filter: blur(5px);`
    * **Processing:** `CreateFilterOperationsFromCSSFilter` parses the string, identifies the `blur` function and its argument, and creates the corresponding `BlurFilterOperation`.

6. **Identifying Potential User/Programming Errors:** Consider common mistakes users might make when specifying filters:

    * **Incorrect filter name:**  Typos in `'gaussianBlur'` vs. `'blur'`.
    * **Missing required properties:** Forgetting the `'values'` array for `colorMatrix`.
    * **Invalid values:** Providing a string for `stdDeviation` or an array of the wrong size for `kernelMatrix`.
    * **Out-of-range values:** Negative `stdDeviation` or `numOctaves`.

7. **Debugging Steps (User Operations to Code Execution):**  Trace the user interaction back to the C++ code.

    1. User edits HTML/JavaScript/CSS.
    2. Browser parses the HTML/CSS, and the JavaScript engine executes the JavaScript.
    3. If the user uses the Canvas API, the `ctx.filter = ...` line triggers the browser to process the filter string or array of filter objects.
    4. The Blink rendering engine receives this filter information.
    5. For Canvas API calls, `CreateFilterOperationsFromList` in `canvas_filter_operation_resolver.cc` is invoked.
    6. For CSS `filter` properties, `CreateFilterOperationsFromCSSFilter` is called.
    7. The relevant `Resolve...` function is called based on the filter type.
    8. Errors are potentially caught by the `ExceptionState` and reported to the console.

8. **Refine and Organize:** Structure the information logically with clear headings and bullet points. Use precise terminology. Ensure the examples are clear and directly related to the code. Explain the role of each key function.

9. **Review and Enhance:** Read through the explanation to make sure it's accurate, comprehensive, and easy to understand. Add any missing details or clarify any ambiguities. For instance, explicitly mention the validation and parsing aspects.

This systematic approach, combining code analysis, knowledge of web technologies, and reasoning about user behavior, allows for a detailed and accurate explanation of the code's functionality.
好的， 让我们来分析一下 `blink/renderer/modules/canvas/canvas2d/canvas_filter_operation_resolver.cc` 这个文件的功能。

**核心功能:**

这个文件的核心功能是**解析和转换 Canvas 2D API 中 `filter` 属性设置的滤镜操作，以及 CSS `filter` 属性设置的滤镜操作，将其转换为 Blink 渲染引擎可以理解和应用的 `FilterOperations` 对象。**  换句话说，它负责将用户在 JavaScript 或 CSS 中描述的视觉效果指令转化为实际的图形处理操作。

**具体功能点:**

1. **解析 JavaScript Canvas `filter` 属性:**
   - `CreateFilterOperationsFromList` 函数接收一个 `ScriptValue` 类型的列表，这个列表通常来自于 JavaScript 中 Canvas 2D 渲染上下文的 `filter` 属性。
   - 它会遍历这个列表，每个元素代表一个滤镜操作，通常是一个包含 `name` 属性的对象（例如：`{ name: 'blur', stdDeviation: 5 }`）。
   - 根据 `name` 属性的值，调用相应的 `Resolve...` 函数来解析该滤镜的具体参数。
   - 支持的 Canvas 滤镜类型包括:
     - `gaussianBlur`: 高斯模糊
     - `colorMatrix`: 颜色矩阵变换 (包括 `hueRotate`, `saturate`, `luminanceToAlpha`)
     - `convolveMatrix`: 卷积矩阵
     - `componentTransfer`: 分量传输（调整颜色通道）
     - `dropShadow`: 阴影
     - `turbulence`: 湍流效果
   - 如果遇到不支持的滤镜名称，会在控制台输出警告信息。

2. **解析 CSS `filter` 属性:**
   - `CreateFilterOperationsFromCSSFilter` 函数接收一个字符串 `filter_string`，这个字符串通常是 CSS `filter` 属性的值（例如：`filter: blur(5px) saturate(80%);`）。
   - 它使用 CSS 解析器 (`CSSParser`) 来解析这个字符串。
   - 如果解析成功，并且存在关联的 `Element` (用于样式解析)，则会调用 `StyleResolver` 来计算滤镜操作。
   - 如果没有关联的 `Element` (例如在无框架的文档中)，则会调用 `FilterOperationResolver::CreateOffscreenFilterOperations` 进行解析。

3. **滤镜参数解析 (`Resolve...` 函数):**
   - 针对每种支持的滤镜类型，都有一组 `Resolve...` 函数负责解析其特定的参数。
   - 这些函数会从 `Dictionary` 对象中提取参数值，进行类型检查和验证，并将参数转换为 Blink 内部表示。
   - 例如：
     - `ResolveBlur` 解析 `stdDeviation` (标准差) 参数。
     - `ResolveColorMatrix` 解析 `values` (颜色矩阵值) 参数。
     - `ResolveDropShadow` 解析 `dx`, `dy`, `stdDeviation`, `floodColor`, `floodOpacity` 等参数。
     - `ResolveTurbulence` 解析 `baseFrequency`, `seed`, `numOctaves`, `stitchTiles`, `type` 等参数。

4. **错误处理和控制台输出:**
   - 在解析过程中，如果遇到参数错误（例如类型不匹配，缺少必需的参数，值超出范围），会通过 `ExceptionState` 抛出类型错误 (TypeError)，这些错误会反映到 JavaScript 的异常中。
   - 对于不支持的 Canvas 滤镜类型，会在控制台输出警告信息，并限制输出错误的次数，避免刷屏。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript (Canvas API):**
   - **关系:** 这个文件主要负责处理通过 JavaScript 的 Canvas 2D API 设置的 `filter` 属性。
   - **示例:**
     ```javascript
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('2d');

     // 设置高斯模糊滤镜
     ctx.filter = 'blur(5px)';
     ctx.fillRect(10, 10, 100, 100);

     // 设置多个滤镜
     ctx.filter = 'blur(3px) saturate(150%)';
     ctx.drawImage(image, 0, 0);

     // 使用 CanvasFilter 对象数组
     ctx.filter = [
       { name: 'gaussianBlur', stdDeviation: 5 },
       { name: 'dropShadow', dx: 5, dy: 5, blur: 3, color: 'rgba(0,0,0,0.5)' }
     ];
     ctx.fillText('Hello', 20, 50);
     ```
     当 JavaScript 代码执行到 `ctx.filter = ...` 时，传递的字符串或对象数组会被传递到 Blink 渲染引擎，最终由 `CanvasFilterOperationResolver` 来解析。

* **HTML (`<canvas>` 元素):**
   - **关系:**  `<canvas>` 元素是应用这些滤镜的目标。
   - **示例:**  上述 JavaScript 示例中的 `<canvas id="myCanvas"></canvas>`。

* **CSS (`filter` 属性):**
   - **关系:** 这个文件也处理通过 CSS 的 `filter` 属性设置的滤镜效果。
   - **示例:**
     ```css
     .element {
       filter: blur(10px);
     }

     .image {
       filter: grayscale(100%) contrast(200%);
     }
     ```
     当浏览器渲染带有 `filter` 属性的元素时，CSS 的 `filter` 值会被 `CanvasFilterOperationResolver::CreateFilterOperationsFromCSSFilter` 解析。

**逻辑推理 (假设输入与输出):**

假设输入一个 JavaScript 对象：

```javascript
{ name: 'colorMatrix', type: 'saturate', values: 0.5 }
```

* **假设输入:**  一个 `Dictionary` 对象，其内容对应于上述 JavaScript 对象。
* **处理过程:**
    1. `CreateFilterOperationsFromList` 函数被调用。
    2. 检测到 `name` 为 "colorMatrix"。
    3. 检测到 `type` 为 "saturate"。
    4. `ResolveColorMatrix` (或者更具体地说是处理 `type` 为 "saturate" 的逻辑) 被调用。
    5. 从 `Dictionary` 中获取 `values` 的值 `0.5`。
    6. 创建一个 `BasicColorMatrixFilterOperation` 对象，其类型为 `kSaturate`，值为 `0.5`。
* **输出:** 一个包含一个 `BasicColorMatrixFilterOperation` 对象的 `FilterOperations` 对象。

假设输入一个 CSS 字符串：

```css
filter: drop-shadow(4px 4px 8px blue);
```

* **假设输入:**  一个 `String` 对象，其值为 `"drop-shadow(4px 4px 8px blue)"`。
* **处理过程:**
    1. `CreateFilterOperationsFromCSSFilter` 函数被调用。
    2. 使用 `CSSParser` 解析该字符串。
    3. 解析出 `drop-shadow` 滤镜及其参数 `4px 4px 8px blue`。
    4. 创建一个 `DropShadowFilterOperation` 对象，其 `dx` 为 4px, `dy` 为 4px, `blur` 为 8px, `color` 为蓝色。
* **输出:** 一个包含一个 `DropShadowFilterOperation` 对象的 `FilterOperations` 对象。

**用户或编程常见的使用错误:**

1. **拼写错误的滤镜名称:**
   - **错误示例 (JavaScript):** `{ name: 'guasainBlur', stdDeviation: 5 }` (拼写错误 "gaussianBlur")
   - **结果:** 控制台会输出警告信息，该滤镜会被忽略。

2. **缺少必需的参数:**
   - **错误示例 (JavaScript):** `{ name: 'colorMatrix' }` (缺少 `values` 属性)
   - **结果:**  `ResolveColorMatrix` 会抛出 `TypeError`，JavaScript 代码会捕获到异常。

3. **参数类型错误:**
   - **错误示例 (JavaScript):** `{ name: 'blur', stdDeviation: 'not a number' }`
   - **结果:** `ResolveBlur` 在尝试将字符串转换为数字时会失败，抛出 `TypeError`。

4. **参数值超出范围:**
   - **错误示例 (JavaScript):** `{ name: 'gaussianBlur', stdDeviation: -1 }` (标准差不能为负数)
   - **结果:**  虽然代码中对 `stdDeviation` 进行了 `std::max(0.0f, ...)` 的处理，但某些滤镜可能有其他值限制，可能会导致非预期的效果或被忽略。 例如 `numOctaves` 必须是正数。

5. **CSS `filter` 语法错误:**
   - **错误示例 (CSS):** `filter: blur(10);` (缺少单位)
   - **结果:** CSS 解析器会解析失败，整个 `filter` 属性可能被忽略。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户编辑 HTML, CSS 或 JavaScript 代码。**
2. **浏览器加载并解析 HTML 和 CSS。** 如果 CSS 中包含了 `filter` 属性，解析器会尝试解析它。
3. **JavaScript 代码执行。** 如果 JavaScript 中操作了 Canvas 2D 上下文的 `filter` 属性，例如 `ctx.filter = ...;`。
4. **Blink 渲染引擎接收到 Canvas 或 CSS 的滤镜信息。**
5. **对于 Canvas API 设置的滤镜:**
   - 当 Canvas 内容需要绘制时，渲染流程会检查 `filter` 属性。
   - `CanvasFilterOperationResolver::CreateFilterOperationsFromList` 函数会被调用，传入 JavaScript 传递的 `ScriptValue` 列表。
   - 相应的 `Resolve...` 函数会被调用来解析每个滤镜对象。
6. **对于 CSS `filter` 属性:**
   - 在样式计算阶段，`StyleResolver::ComputeFilterOperations` (或 `FilterOperationResolver::CreateOffscreenFilterOperations`) 会被调用来解析 CSS `filter` 值。
   - `CanvasFilterOperationResolver::CreateFilterOperationsFromCSSFilter` 函数会被调用。
7. **在 `Resolve...` 函数中，会进行参数提取、类型检查和转换。** 如果发生错误，会抛出异常或记录控制台消息。
8. **最终生成的 `FilterOperations` 对象会被用于后续的图形渲染管线中，以应用实际的视觉效果。**

**调试线索:**

* **检查浏览器的开发者工具控制台:**  查看是否有关于 Canvas 滤镜的警告或错误信息。
* **在 JavaScript 代码中设置断点:**  在设置 `ctx.filter` 的代码行设置断点，查看传递给 `filter` 属性的值是否正确。
* **在 Blink 源代码中设置断点:** 如果需要深入调试，可以在 `CanvasFilterOperationResolver::CreateFilterOperationsFromList` 或相关的 `Resolve...` 函数中设置断点，查看参数解析的过程。
* **检查 CSS `filter` 属性的语法:**  确保 CSS 语法的正确性，例如单位、括号等。
* **使用浏览器的性能分析工具:**  查看滤镜操作是否影响了渲染性能。

希望以上分析能够帮助你理解 `canvas_filter_operation_resolver.cc` 文件的功能和它在 Web 技术栈中的作用。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_filter_operation_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_filter_operation_resolver.h"

#include <stdint.h>

#include <algorithm>
#include <optional>
#include <string>
#include <utility>

#include "base/types/expected.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_mode.h"
#include "third_party/blink/renderer/core/css/resolver/filter_operation_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/style/filter_operation.h"
#include "third_party/blink/renderer/core/style/filter_operations.h"
#include "third_party/blink/renderer/core/style/shadow_data.h"
#include "third_party/blink/renderer/core/svg/svg_enumeration.h"
#include "third_party/blink/renderer/core/svg/svg_enumeration_map.h"
#include "third_party/blink/renderer/core/svg/svg_fe_turbulence_element.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_style.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/filters/fe_component_transfer.h"
#include "third_party/blink/renderer/platform/graphics/filters/fe_convolve_matrix.h"
#include "third_party/blink/renderer/platform/graphics/filters/fe_turbulence.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/geometry/vector2d_f.h"

namespace blink {
class Font;

namespace {
int num_canvas_filter_errors_to_console_allowed_ = 64;

ColorMatrixFilterOperation* ResolveColorMatrix(
    const Dictionary& dict,
    ExceptionState& exception_state) {
  std::optional<Vector<float>> values =
      dict.Get<IDLSequence<IDLFloat>>("values", exception_state);

  if (!values.has_value()) {
    exception_state.ThrowTypeError(
        "Failed to construct color matrix filter, 'values' array required.");
    return nullptr;
  }

  if (values->size() != 20) {
    exception_state.ThrowTypeError(
        "Failed to construct color matrix filter, 'values' must be an array "
        "of 20 numbers.");
    return nullptr;
  }

  return MakeGarbageCollected<ColorMatrixFilterOperation>(
      *std::move(values), FilterOperation::OperationType::kColorMatrix);
}

struct KernelMatrix {
  Vector<float> values;
  uint32_t width;
  uint32_t height;
};

// For resolving feConvolveMatrix type filters
std::optional<KernelMatrix> GetKernelMatrix(const Dictionary& dict,
                                            ExceptionState& exception_state) {
  std::optional<Vector<Vector<float>>> km_input =
      dict.Get<IDLSequence<IDLSequence<IDLFloat>>>("kernelMatrix",
                                                   exception_state);
  if (!km_input.has_value() || km_input->size() == 0 ||
      (km_input->size() >= 2 && km_input->at(0).size() == 0)) {
    exception_state.ThrowTypeError(
        "Failed to construct convolve matrix filter. 'kernelMatrix' must be an "
        "array of arrays of numbers representing an n by m matrix.");
    return std::nullopt;
  }
  KernelMatrix result;
  result.height = km_input->size();
  result.width = km_input->at(0).size();

  for (const Vector<float>& row : *km_input) {
    if (row.size() != result.width) {
      exception_state.ThrowTypeError(
          "Failed to construct convolve matrix filter. All rows of the "
          "'kernelMatrix' must be the same length.");
      return std::nullopt;
    }

    result.values.AppendVector(row);
  }

  return result;
}

ConvolveMatrixFilterOperation* ResolveConvolveMatrix(
    const Dictionary& dict,
    ExceptionState& exception_state) {
  std::optional<KernelMatrix> kernel_matrix =
      GetKernelMatrix(dict, exception_state);

  if (!kernel_matrix.has_value()) {
    return nullptr;
  }

  gfx::Size kernel_size(kernel_matrix->width, kernel_matrix->height);
  double divisor = dict.Get<IDLDouble>("divisor", exception_state).value_or(1);
  double bias = dict.Get<IDLDouble>("bias", exception_state).value_or(0);
  gfx::Point target_offset =
      gfx::Point(dict.Get<IDLShort>("targetX", exception_state)
                     .value_or(kernel_matrix->width / 2),
                 dict.Get<IDLShort>("targetY", exception_state)
                     .value_or(kernel_matrix->height / 2));

  String edge_mode_string =
      dict.Get<IDLString>("edgeMode", exception_state).value_or("duplicate");
  FEConvolveMatrix::EdgeModeType edge_mode =
      static_cast<FEConvolveMatrix::EdgeModeType>(
          GetEnumerationMap<FEConvolveMatrix::EdgeModeType>().ValueFromName(
              edge_mode_string));

  bool preserve_alpha =
      dict.Get<IDLBoolean>("preserveAlpha", exception_state).value_or(false);

  return MakeGarbageCollected<ConvolveMatrixFilterOperation>(
      kernel_size, divisor, bias, target_offset, edge_mode, preserve_alpha,
      kernel_matrix->values);
}

ComponentTransferFunction GetComponentTransferFunction(
    const StringView& key,
    const Dictionary& filter,
    ExceptionState& exception_state) {
  ComponentTransferFunction result;
  // An earlier stage threw an error
  if (exception_state.HadException())
    return result;
  Dictionary transfer_dict;
  filter.Get(key, transfer_dict);

  result.slope =
      transfer_dict.Get<IDLDouble>("slope", exception_state).value_or(1);
  result.intercept =
      transfer_dict.Get<IDLDouble>("intercept", exception_state).value_or(0);
  result.amplitude =
      transfer_dict.Get<IDLDouble>("amplitude", exception_state).value_or(1);
  result.exponent =
      transfer_dict.Get<IDLDouble>("exponent", exception_state).value_or(1);
  result.offset =
      transfer_dict.Get<IDLDouble>("offset", exception_state).value_or(0);

  String type = transfer_dict.Get<IDLString>("type", exception_state)
                    .value_or("identity");
  if (type == "identity")
    result.type = FECOMPONENTTRANSFER_TYPE_IDENTITY;
  else if (type == "linear")
    result.type = FECOMPONENTTRANSFER_TYPE_LINEAR;
  else if (type == "gamma")
    result.type = FECOMPONENTTRANSFER_TYPE_GAMMA;
  else if (type == "table")
    result.type = FECOMPONENTTRANSFER_TYPE_TABLE;
  else if (type == "discrete")
    result.type = FECOMPONENTTRANSFER_TYPE_DISCRETE;

  std::optional<Vector<float>> table_values =
      transfer_dict.Get<IDLSequence<IDLFloat>>("tableValues", exception_state);
  if (table_values.has_value()) {
    result.table_values.AppendVector(*table_values);
  }

  return result;
}

ComponentTransferFilterOperation* ResolveComponentTransfer(
    const Dictionary& dict,
    ExceptionState& exception_state) {
  return MakeGarbageCollected<ComponentTransferFilterOperation>(
      GetComponentTransferFunction("funcR", dict, exception_state),
      GetComponentTransferFunction("funcG", dict, exception_state),
      GetComponentTransferFunction("funcB", dict, exception_state),
      GetComponentTransferFunction("funcA", dict, exception_state));
}

StyleColor ResolveFloodColor(ExecutionContext& execution_context,
                             const Dictionary& dict,
                             ExceptionState& exception_state) {
  NonThrowableExceptionState no_throw;
  if (!dict.HasProperty("floodColor", no_throw)) {
    return StyleColor(Color::kBlack);
  }

  // TODO(crbug.com/1430532): CurrentColor and system colors dependeing on
  // the color-scheme should be stored unresolved, and resolved only when the
  // filter is associated with a context.
  std::optional<String> flood_color =
      dict.Get<IDLString>("floodColor", exception_state);
  Color parsed_color;
  if (exception_state.HadException() || !flood_color.has_value() ||
      !ParseCanvasColorString(*flood_color, parsed_color)) {
    exception_state.ThrowTypeError(
        "Invalid color value for \"floodColor\" property.");
    return StyleColor(Color::kBlack);
  }

  return StyleColor(parsed_color);
}

base::expected<gfx::PointF, String> ResolveFloatOrVec2f(
    const String property_name,
    const Dictionary& dict,
    ExceptionState& exception_state) {
  {
    v8::TryCatch try_catch(dict.GetIsolate());
    // First try to get stdDeviation as a float.
    std::optional<float> single_float = dict.Get<IDLFloat>(
        property_name, PassThroughException(dict.GetIsolate()));
    if (!try_catch.HasCaught() && single_float.has_value()) {
      return gfx::PointF(*single_float, *single_float);
    }
  }
  // Try again as a vector.
  std::optional<Vector<float>> two_floats =
      dict.Get<IDLSequence<IDLFloat>>(property_name, exception_state);
  if (exception_state.HadException() || !two_floats.has_value() ||
      two_floats->size() != 2) {
    return base::unexpected(String::Format(
        "\"%s\" must either be a number or an array of two numbers",
        property_name.Ascii().c_str()));
  }
  return gfx::PointF(two_floats->at(0), two_floats->at(1));
}

BlurFilterOperation* ResolveBlur(const Dictionary& blur_dict,
                                 ExceptionState& exception_state) {
  base::expected<gfx::PointF, String> blur_xy =
      ResolveFloatOrVec2f("stdDeviation", blur_dict, exception_state);

  if (exception_state.HadException() || !blur_xy.has_value()) {
    exception_state.ThrowTypeError(
        String::Format("Failed to construct blur filter. %s.",
                       blur_xy.error().Utf8().c_str()));
    return nullptr;
  }

  return MakeGarbageCollected<BlurFilterOperation>(
      Length::Fixed(std::max(0.0f, blur_xy->x())),
      Length::Fixed(std::max(0.0f, blur_xy->y())));
}

DropShadowFilterOperation* ResolveDropShadow(
    ExecutionContext& execution_context,
    const Dictionary& dict,
    ExceptionState& exception_state) {
  // For checking the presence of keys.
  NonThrowableExceptionState no_throw;

  float dx = 2.0f;
  if (dict.HasProperty("dx", no_throw)) {
    std::optional<float> input = dict.Get<IDLFloat>("dx", exception_state);
    if (exception_state.HadException() || !input.has_value()) {
      exception_state.ThrowTypeError(
          "Failed to construct dropShadow filter, \"dx\" must be a number.");
      return nullptr;
    }
    dx = *input;
  }

  float dy = 2.0f;
  if (dict.HasProperty("dy", no_throw)) {
    std::optional<float> input = dict.Get<IDLFloat>("dy", exception_state);
    if (exception_state.HadException() || !input.has_value()) {
      exception_state.ThrowTypeError(
          "Failed to construct dropShadow filter, \"dy\" must be a number.");
      return nullptr;
    }
    dy = *input;
  }

  // The shadow blur can have different standard deviations in the X and Y
  // directions. `stdDeviation` can be specified as either a single number
  // (same X & Y blur) or a vector of two numbers (different X & Y blurs).
  gfx::PointF blur = {2.0f, 2.0f};
  if (dict.HasProperty("stdDeviation", no_throw)) {
    base::expected<gfx::PointF, String> std_deviation =
        ResolveFloatOrVec2f("stdDeviation", dict, exception_state);
    if (exception_state.HadException() || !std_deviation.has_value()) {
      exception_state.ThrowTypeError(
          String::Format("Failed to construct dropShadow filter, %s.",
                         std_deviation.error().Utf8().c_str()));
      return nullptr;
    }
    blur = *std_deviation;
    blur.SetToMax({0.0f, 0.0f});
  }

  StyleColor flood_color =
      ResolveFloodColor(execution_context, dict, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  float opacity = 1.0f;
  if (dict.HasProperty("floodOpacity", no_throw)) {
    std::optional<float> input =
        dict.Get<IDLFloat>("floodOpacity", exception_state);
    if (exception_state.HadException() || !input.has_value()) {
      exception_state.ThrowTypeError(
          "Failed to construct dropShadow filter, \"floodOpacity\" must be a "
          "number.");
      return nullptr;
    }
    opacity = *input;
  }

  return MakeGarbageCollected<DropShadowFilterOperation>(
      ShadowData(gfx::Vector2dF(dx, dy), blur, /*spread=*/0,
                 ShadowStyle::kNormal, std::move(flood_color), opacity));
}

// https://drafts.fxtf.org/filter-effects/#feTurbulenceElement
TurbulenceFilterOperation* ResolveTurbulence(const Dictionary& dict,
                                             ExceptionState& exception_state) {
  // Default values for all parameters per spec.
  float base_frequency_x = 0;
  float base_frequency_y = 0;
  float seed = 1;
  int num_octaves = 1;
  SVGStitchOptions stitch_tiles = kSvgStitchtypeNostitch;
  TurbulenceType type = FETURBULENCE_TYPE_TURBULENCE;

  // For checking the presence of keys.
  NonThrowableExceptionState no_throw;

  // baseFrequency can be either a number or a list of numbers.
  if (dict.HasProperty("baseFrequency", no_throw)) {
    base::expected<gfx::PointF, String> base_frequency =
        ResolveFloatOrVec2f("baseFrequency", dict, exception_state);
    if (exception_state.HadException() || !base_frequency.has_value()) {
      exception_state.ThrowTypeError(
          String::Format("Failed to construct turbulence filter, %s.",
                         base_frequency.error().Utf8().c_str()));
      return nullptr;
    }
    base_frequency_x = base_frequency->x();
    base_frequency_y = base_frequency->y();

    if (base_frequency_x < 0 || base_frequency_y < 0) {
      exception_state.ThrowTypeError(
          "Failed to construct turbulence filter, negative values for "
          "\"baseFrequency\" are unsupported.");
      return nullptr;
    }
  }

  if (dict.HasProperty("seed", no_throw)) {
    std::optional<float> seed_input =
        dict.Get<IDLFloat>("seed", exception_state);
    if (exception_state.HadException() || !seed_input.has_value()) {
      exception_state.ThrowTypeError(
          "Failed to construct turbulence filter, \"seed\" must be a number.");
      return nullptr;
    }
    seed = *seed_input;
  }

  if (dict.HasProperty("numOctaves", no_throw)) {
    // Get numOctaves as a float and then cast to int so that we throw for
    // inputs like undefined, NaN and Infinity.
    std::optional<float> num_octaves_input =
        dict.Get<IDLFloat>("numOctaves", exception_state);
    if (exception_state.HadException() || !num_octaves_input.has_value() ||
        *num_octaves_input < 0) {
      exception_state.ThrowTypeError(
          "Failed to construct turbulence filter, \"numOctaves\" must be a "
          "positive number.");
      return nullptr;
    }
    num_octaves = static_cast<int>(*num_octaves_input);
  }

  if (dict.HasProperty("stitchTiles", no_throw)) {
    std::optional<String> stitch_tiles_input =
        dict.Get<IDLString>("stitchTiles", exception_state);
    if (exception_state.HadException() || !stitch_tiles_input.has_value() ||
        (stitch_tiles = static_cast<SVGStitchOptions>(
             GetEnumerationMap<SVGStitchOptions>().ValueFromName(
                 *stitch_tiles_input))) == 0) {
      exception_state.ThrowTypeError(
          "Failed to construct turbulence filter, \"stitchTiles\" must be "
          "either \"stitch\" or \"noStitch\".");
      return nullptr;
    }
  }

  if (dict.HasProperty("type", no_throw)) {
    std::optional<String> type_input =
        dict.Get<IDLString>("type", exception_state);
    if (exception_state.HadException() || !type_input.has_value() ||
        (type = static_cast<TurbulenceType>(
             GetEnumerationMap<TurbulenceType>().ValueFromName(*type_input))) ==
            0) {
      exception_state.ThrowTypeError(
          "Failed to construct turbulence filter, \"type\" must be either "
          "\"turbulence\" or \"fractalNoise\".");
      return nullptr;
    }
  }

  return MakeGarbageCollected<TurbulenceFilterOperation>(
      type, base_frequency_x, base_frequency_y, num_octaves, seed,
      stitch_tiles == kSvgStitchtypeStitch ? true : false);
}

}  // namespace

FilterOperations CanvasFilterOperationResolver::CreateFilterOperationsFromList(
    const HeapVector<ScriptValue>& filters,
    ExecutionContext& execution_context,
    ExceptionState& exception_state) {
  FilterOperations operations;
  for (auto filter : filters) {
    Dictionary filter_dict = Dictionary(filter);
    std::optional<String> name =
        filter_dict.Get<IDLString>("name", exception_state);
    if (name == "gaussianBlur") {
      if (auto* blur_operation = ResolveBlur(filter_dict, exception_state)) {
        operations.Operations().push_back(blur_operation);
      }
    } else if (name == "colorMatrix") {
      String type = filter_dict.Get<IDLString>("type", exception_state)
                        .value_or("matrix");
      if (type == "hueRotate") {
        double amount =
            filter_dict.Get<IDLDouble>("values", exception_state).value_or(0);
        operations.Operations().push_back(
            MakeGarbageCollected<BasicColorMatrixFilterOperation>(
                amount, FilterOperation::OperationType::kHueRotate));
      } else if (type == "saturate") {
        double amount =
            filter_dict.Get<IDLDouble>("values", exception_state).value_or(0);
        operations.Operations().push_back(
            MakeGarbageCollected<BasicColorMatrixFilterOperation>(
                amount, FilterOperation::OperationType::kSaturate));
      } else if (type == "luminanceToAlpha") {
        operations.Operations().push_back(
            MakeGarbageCollected<BasicColorMatrixFilterOperation>(
                0, FilterOperation::OperationType::kLuminanceToAlpha));
      } else if (auto* color_matrix_operation =
                     ResolveColorMatrix(filter_dict, exception_state)) {
        operations.Operations().push_back(color_matrix_operation);
      }
    } else if (name == "convolveMatrix") {
      if (auto* convolve_operation =
              ResolveConvolveMatrix(filter_dict, exception_state)) {
        operations.Operations().push_back(convolve_operation);
      }
    } else if (name == "componentTransfer") {
      if (auto* component_transfer_operation =
              ResolveComponentTransfer(filter_dict, exception_state)) {
        operations.Operations().push_back(component_transfer_operation);
      }
    } else if (name == "dropShadow") {
      if (FilterOperation* drop_shadow_operation = ResolveDropShadow(
              execution_context, filter_dict, exception_state)) {
        operations.Operations().push_back(drop_shadow_operation);
      }
    } else if (name == "turbulence") {
      if (auto* turbulence_operation =
              ResolveTurbulence(filter_dict, exception_state)) {
        operations.Operations().push_back(turbulence_operation);
      }
    } else {
      num_canvas_filter_errors_to_console_allowed_--;
      if (num_canvas_filter_errors_to_console_allowed_ < 0)
        continue;
      {
        const String& message =
            (!name.has_value())
                ? "Canvas filter require key 'name' to specify filter type."
                : String::Format(
                      "\"%s\" is not among supported canvas filter types.",
                      name->Utf8().c_str());
        execution_context.AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kRendering,
                mojom::blink::ConsoleMessageLevel::kWarning, message));
      }
      if (num_canvas_filter_errors_to_console_allowed_ == 0) {
        const String& message =
            "Canvas filter: too many errors, no more errors will be reported "
            "to the console for this process.";
        execution_context.AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kRendering,
                mojom::blink::ConsoleMessageLevel::kWarning, message));
      }
    }
  }

  return operations;
}

FilterOperations
CanvasFilterOperationResolver::CreateFilterOperationsFromCSSFilter(
    const String& filter_string,
    const ExecutionContext& execution_context,
    Element* style_resolution_host,
    const Font& font) {
  FilterOperations operations;
  const CSSValue* css_value = CSSParser::ParseSingleValue(
      CSSPropertyID::kFilter, filter_string,
      MakeGarbageCollected<CSSParserContext>(
          kHTMLStandardMode, execution_context.GetSecureContextMode()));
  if (!css_value || css_value->IsCSSWideKeyword()) {
    return operations;
  }
  // The style resolution for fonts is not available in frame-less documents.
  if (style_resolution_host != nullptr &&
      style_resolution_host->GetDocument().GetFrame() != nullptr) {
    return style_resolution_host->GetDocument()
        .GetStyleResolver()
        .ComputeFilterOperations(style_resolution_host, font, *css_value);
  } else {
    return FilterOperationResolver::CreateOffscreenFilterOperations(*css_value,
                                                                    font);
  }
}

}  // namespace blink

"""

```