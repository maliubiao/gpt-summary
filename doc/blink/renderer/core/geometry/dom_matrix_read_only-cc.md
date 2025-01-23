Response:
Let's break down the thought process for analyzing this code.

1. **Understanding the Core Request:** The request asks for the functionality of `DOMMatrixReadOnly.cc`, its relation to web technologies (JS/HTML/CSS), logical reasoning with input/output, common user errors, and a debugging scenario.

2. **Initial Code Scan - Identifying Key Areas:**  The first step is to skim the code, looking for recognizable keywords and patterns. I see:
    * Includes for `DOMMatrix`, `DOMPoint`, `CSSParser`, `TransformBuilder`. This immediately suggests the file deals with transformations and how they are represented in the browser.
    * Functions like `Create`, `fromFloat32Array`, `fromMatrix2D`, `multiply`, `translate`, `rotate`, `scale`, `inverse`, `transformPoint`, `toString`, `toJSONForBinding`. These are the core operations supported by this class.
    * Validation functions like `ValidateAndFixup2D` and `ValidateAndFixup`. This indicates a concern for data integrity.
    * Use of `gfx::Transform`. This points to the underlying graphics library used by Blink to perform the actual matrix calculations.
    * References to `ExceptionState`. This signals error handling and type checking.
    * Mentions of `is2D` and logic to determine if a matrix is 2D or 3D.

3. **Categorizing Functionality:** Based on the initial scan, I can start categorizing the functions:
    * **Creation/Initialization:** `Create` (various overloads), `fromFloat32Array`, `fromFloat64Array`, `fromMatrix2D`, `fromMatrix`. These functions are responsible for creating instances of `DOMMatrixReadOnly`.
    * **Validation/Sanitization:** `ValidateAndFixup2D`, `ValidateAndFixup`. These ensure the input data is correct and fill in defaults.
    * **Matrix Operations (returning new `DOMMatrix`):** `multiply`, `translate`, `scale` (various overloads), `rotate` (various overloads), `skewX`, `skewY`, `flipX`, `flipY`, `inverse`. These perform transformations on the matrix, returning a *mutable* `DOMMatrix`. Crucially, they *don't* modify the `DOMMatrixReadOnly` instance.
    * **Point Transformation:** `transformPoint`. This applies the matrix transformation to a given point.
    * **Serialization/Stringification:** `toString`, `toJSONForBinding`, `toFloat32Array`, `toFloat64Array`. These convert the matrix into different representations for use in JavaScript or for internal storage.
    * **Internal Helpers:** `SetDictionaryMembers`, `SetMatrixValueFromString`, `GetAffineTransform`. These are used internally by the class.

4. **Relating to Web Technologies:**  Now, I consider how these functionalities connect to JavaScript, HTML, and CSS:
    * **JavaScript:** The `DOMMatrixReadOnly` class is directly exposed to JavaScript. The `toString` and `toJSONForBinding` methods are key for interaction. The static `from...` methods provide ways to construct matrices from JavaScript data. The various transformation methods are also accessible.
    * **HTML:**  While not directly manipulating HTML elements, the resulting transformations are applied to elements, affecting their rendering on the page. For instance, a `transform` style in CSS leads to the creation and application of `DOMMatrixReadOnly` objects.
    * **CSS:** The `transform` CSS property is the primary driver for using `DOMMatrixReadOnly`. The `SetMatrixValueFromString` function parses CSS transform values.

5. **Logical Reasoning and Examples:** For each key area, I try to create a simple input/output example:
    * **Creation:**  Provide examples of creating a matrix from an array or a string.
    * **Validation:**  Illustrate what happens when there's a mismatch in the initialization data.
    * **Transformation:** Show how applying a translation or rotation changes the matrix values and how it affects a point.
    * **Serialization:** Give examples of the `toString` output for 2D and 3D matrices.

6. **Identifying User Errors:** Think about common mistakes developers might make:
    * Providing the wrong number of elements to `fromFloat...Array`.
    * Mismatched properties when initializing from an object (addressed by the validation logic).
    * Providing non-absolute lengths in CSS transform strings.
    * Trying to construct a matrix from a string in a worker context.

7. **Debugging Scenario:**  The key here is to trace a user action that ultimately involves `DOMMatrixReadOnly`. A good example is setting the `transform` style via JavaScript. This involves multiple steps within the browser's rendering pipeline, eventually leading to the creation and use of `DOMMatrixReadOnly`.

8. **Structuring the Answer:** Finally, organize the information logically:
    * Start with a clear summary of the file's purpose.
    * List the functionalities with brief explanations.
    * Provide detailed explanations of the relationship with JS/HTML/CSS with concrete examples.
    * Offer logical reasoning examples with clear inputs and outputs.
    * Describe common user errors.
    * Present a step-by-step debugging scenario.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on the low-level matrix operations. **Correction:**  Shift focus to the *purpose* of these operations within the context of web rendering.
* **Oversimplification:**  Just listing the function names. **Correction:**  Explain *what* each function does and *why* it's important.
* **Lack of concrete examples:** Describing the functionality in abstract terms. **Correction:** Provide specific code snippets for JavaScript/CSS interactions and input/output examples for logical reasoning.
* **Ignoring error handling:** Not mentioning the `ExceptionState`. **Correction:**  Highlight the validation and error-throwing mechanisms.
* **Weak debugging scenario:**  A vague description of the rendering process. **Correction:**  Provide a more concrete, step-by-step user action and trace the code flow.

By following this thought process, including initial exploration, categorization, connection to web technologies, illustrative examples, error analysis, and a practical debugging scenario, we can generate a comprehensive and helpful answer to the original request.
这个文件 `dom_matrix_read_only.cc` 是 Chromium Blink 渲染引擎中 `DOMMatrixReadOnly` 接口的实现。`DOMMatrixReadOnly` 代表一个**不可变的** 4x4 或 3x2 的变换矩阵，主要用于描述 2D 或 3D 空间中的几何变换，例如平移、旋转、缩放和倾斜。

以下是该文件的主要功能：

**1. 创建 `DOMMatrixReadOnly` 对象:**

* **从不同的数据源创建:** 提供了多种静态方法来创建 `DOMMatrixReadOnly` 对象：
    * `Create(ExecutionContext*, ExceptionState&)`: 创建一个单位矩阵。
    * `Create(ExecutionContext*, const V8UnionStringOrUnrestrictedDoubleSequence*, ExceptionState&)`:  可以从表示矩阵的字符串（例如 CSS `matrix()` 或 `matrix3d()` 函数）或数字序列创建。
    * `CreateForSerialization(base::span<const double>)`:  用于序列化目的创建。
    * `fromFloat32Array(NotShared<DOMFloat32Array>, ExceptionState&)` 和 `fromFloat64Array(NotShared<DOMFloat64Array>, ExceptionState&)`: 从 JavaScript 的 `Float32Array` 或 `Float64Array` 创建。
    * `fromMatrix2D(DOMMatrix2DInit*, ExceptionState&)` 和 `fromMatrix(DOMMatrixInit*, ExceptionState&)`: 从 JavaScript 中符合 `DOMMatrix2DInit` 或 `DOMMatrixInit` 字典的对象创建。

* **内部构造函数:**  提供私有构造函数，直接使用 `gfx::Transform` 对象或数字序列来创建，`gfx::Transform` 是 Blink 内部用于表示变换的类。

**2. 数据校验与修正:**

* `ValidateAndFixup2D(DOMMatrix2DInit*)`: 验证并修正 2D 矩阵初始化字典 `DOMMatrix2DInit` 中的属性。如果同时设置了 `a` 和 `m11` 等等，会检查其值是否一致。如果只设置了部分属性，会填充默认值。
* `ValidateAndFixup(DOMMatrixInit*, ExceptionState&)`: 扩展了 2D 验证，并处理 3D 矩阵的验证。检查 `is2D` 属性与实际矩阵值的维度是否一致。

**3. 属性访问 (只读):**

* 实现了 `DOMMatrixReadOnly` 接口的各种只读属性，例如 `a`, `b`, `c`, `d`, `e`, `f` (对于 2D 矩阵) 和 `m11` 到 `m44` (对于 3D 矩阵)。这些属性直接映射到内部 `gfx::Transform` 对象的值。
* `is2D()`: 返回矩阵是否是 2D 的。
* `isIdentity()`: 返回矩阵是否是单位矩阵。

**4. 矩阵运算 (返回新的可变 `DOMMatrix` 对象):**

由于 `DOMMatrixReadOnly` 是不可变的，所以所有的矩阵运算方法都会返回一个新的可变的 `DOMMatrix` 对象（`blink::DOMMatrix`），该对象是 `DOMMatrixReadOnly` 的子类。

* `multiply(DOMMatrixInit*, ExceptionState&)`:  与另一个矩阵相乘。
* `translate(double tx, double ty, double tz)`:  创建一个平移变换矩阵并与当前矩阵相乘。
* `scale(...)`: 创建缩放变换矩阵并与当前矩阵相乘 (提供多种重载以支持不同维度的缩放和中心点)。
* `rotate(...)`: 创建旋转变换矩阵并与当前矩阵相乘 (提供多种重载以支持不同轴的旋转)。
* `skewX(double sx)` 和 `skewY(double sy)`: 创建沿 X 或 Y 轴的倾斜变换矩阵并与当前矩阵相乘。
* `flipX()` 和 `flipY()`: 创建沿 X 或 Y 轴翻转的变换矩阵。
* `inverse()`: 创建当前矩阵的逆矩阵。

**5. 点变换:**

* `transformPoint(const DOMPointInit*)`:  将一个点（`DOMPointInit` 对象）应用当前矩阵的变换，并返回一个新的 `DOMPoint` 对象。

**6. 序列化和字符串表示:**

* `toFloat32Array()` 和 `toFloat64Array()`:  将矩阵转换为 `Float32Array` 或 `Float64Array`，方便在 JavaScript 中使用。
* `toString(ExceptionState&)`: 将矩阵转换为 CSS `matrix()` 或 `matrix3d()` 格式的字符串。如果矩阵包含 `NaN` 或 `Infinity` 值，则会抛出异常。
* `toJSONForBinding(ScriptState*)`:  将矩阵转换为 JSON 对象，方便在 JavaScript 中序列化。

**7. 从 CSS 字符串设置矩阵值:**

* `SetMatrixValueFromString(const ExecutionContext*, const String&, ExceptionState&)`:  从 CSS `transform` 属性值（例如 "matrix(1, 0, 0, 1, 10, 20)") 解析并设置矩阵的值。这使得可以通过 CSS 字符串来创建 `DOMMatrixReadOnly` 对象。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:** `DOMMatrixReadOnly` 是一个可以直接在 JavaScript 中使用的接口。
    * **创建:**  可以使用 `new DOMMatrix([a, b, c, d, e, f])` 或 `DOMMatrix.fromFloat32Array(...)` 等方法创建。
    * **访问属性:** 可以通过 `.a`, `.b`, `.m11`, `.m12` 等属性访问矩阵的值。
    * **进行变换:** 可以调用 `.multiply()`, `.translate()`, `.rotate()` 等方法进行矩阵运算。
    * **应用变换到元素:**  通常会与 HTML 元素的 `style.transform` 属性结合使用，例如：
      ```javascript
      const element = document.getElementById('myElement');
      const matrix = new DOMMatrix().translate(10, 20);
      element.style.transform = matrix.toString();
      ```

* **HTML:**  `DOMMatrixReadOnly` 本身不直接操作 HTML 结构，但其表示的变换会影响 HTML 元素的渲染位置和外观。

* **CSS:**  CSS 的 `transform` 属性是 `DOMMatrixReadOnly` 最重要的关联。
    * **解析 CSS `transform` 值:**  `SetMatrixValueFromString` 函数负责解析 CSS 中的 `matrix()`, `matrix3d()`, `translate()`, `rotate()` 等变换函数，并将它们转换为 `DOMMatrixReadOnly` 对象。
    * **应用 CSS 变换:** 当浏览器解析带有 `transform` 属性的 CSS 规则时，会创建 `DOMMatrixReadOnly` 对象来表示这些变换，并将其应用于相应的 HTML 元素进行渲染。
    * **例如:**
      ```css
      .my-element {
        transform: matrix(1, 0, 0, 1, 50, 50) rotate(45deg);
      }
      ```
      浏览器会解析这个 CSS 规则，创建表示平移和旋转的 `DOMMatrixReadOnly` 对象，并将它们组合起来应用到 `.my-element`。

**逻辑推理、假设输入与输出:**

**假设输入:**  一个 `DOMMatrix2DInit` 对象 ` { a: 2, b: 0, e: 10 } `

**`ValidateAndFixup2D` 的逻辑推理和输出:**

1. 检查 `a` 和 `m11`，发现只设置了 `a`，将 `m11` 设置为 `a` 的值 `2`。
2. 检查 `b` 和 `m12`，发现只设置了 `b`，将 `m12` 设置为 `b` 的值 `0`。
3. 检查 `c` 和 `m21`，没有设置，将 `m21` 设置为默认值 `0`。
4. 检查 `d` 和 `m22`，没有设置，将 `m22` 设置为默认值 `1`。
5. 检查 `e` 和 `m41`，发现只设置了 `e`，将 `m41` 设置为 `e` 的值 `10`。
6. 检查 `f` 和 `m42`，没有设置，将 `m42` 设置为默认值 `0`。

**输出 (修正后的 `DOMMatrix2DInit` 对象):** ` { a: 2, b: 0, c: 0, d: 1, e: 10, f: 0, m11: 2, m12: 0, m21: 0, m22: 1, m41: 10, m42: 0 } `

**假设输入:** 一个 `DOMPointInit` 对象 ` { x: 1, y: 1 } ` 和一个 `DOMMatrixReadOnly` 对象表示平移 `matrix(1, 0, 0, 1, 10, 20)`。

**`transformPoint` 的逻辑推理和输出:**

1. `is2D()` 为真，`point->z()` 为默认值 `0`，`point->w()` 为默认值 `1`，进入 2D 变换的计算。
2. 计算新的 `x` 坐标: `point->x() * m11() + point->y() * m21() + m41()` = `1 * 1 + 1 * 0 + 10` = `11`。
3. 计算新的 `y` 坐标: `point->x() * m12() + point->y() * m22() + m42()` = `1 * 0 + 1 * 1 + 20` = `21`。
4. 返回一个新的 `DOMPoint` 对象。

**输出 (变换后的 `DOMPoint` 对象):** ` { x: 11, y: 21, z: 0, w: 1 } `

**用户或编程常见的使用错误:**

1. **初始化矩阵时属性冲突:**  同时设置了 `a` 和 `m11`，但它们的值不一致。例如：
   ```javascript
   const matrix = new DOMMatrix({ a: 1, m11: 2 }); // 这会导致类型错误
   ```
   **错误原因:**  `ValidateAndFixup` 方法会检测到这种不一致并抛出 `TypeError`。

2. **为 `fromFloat32Array` 或 `fromFloat64Array` 提供错误数量的元素:**  2D 矩阵需要 6 个元素，3D 矩阵需要 16 个元素。
   ```javascript
   const invalidArray = new Float32Array([1, 2, 3, 4, 5]);
   const matrix = DOMMatrix.fromFloat32Array(invalidArray); // 这会导致类型错误
   ```
   **错误原因:**  `fromFloat32Array` 和 `fromFloat64Array` 方法会检查数组的长度，不符合要求会抛出 `TypeError`。

3. **在不支持字符串构造函数的环境中创建矩阵:** 在 Web Workers 中尝试使用字符串创建 `DOMMatrixReadOnly` 会失败。
   ```javascript
   // 在 Web Worker 中
   const matrix = new DOMMatrix('matrix(1, 0, 0, 1, 0, 0)'); // 这会导致类型错误
   ```
   **错误原因:** `DOMMatrixReadOnly::Create` 方法会检查 `ExecutionContext` 是否是 Window 环境。

4. **在 CSS `transform` 中使用相对长度:**  `SetMatrixValueFromString` 不支持相对长度单位 (例如 `em`, `rem`, `%`)。
   ```css
   .element {
     transform: translateX(10%); // 这会被解析为语法错误
   }
   ```
   **错误原因:** `SetMatrixValueFromString` 会检查 `TransformBuilder::HasRelativeLengths` 并抛出 `DOMExceptionCode::kSyntaxError`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问了一个网页，并且该网页包含以下 JavaScript 代码：

```javascript
const element = document.getElementById('myElement');
element.style.transform = 'translate(50px, 100px) rotate(45deg)';
const computedStyle = window.getComputedStyle(element);
const transformValue = computedStyle.transform;
const matrix = new DOMMatrix(transformValue);
console.log(matrix);
```

**调试线索和代码执行流程:**

1. **用户访问网页:**  浏览器开始加载和解析 HTML、CSS 和 JavaScript。
2. **CSS 解析和渲染树构建:** 浏览器解析 CSS 规则，包括 `.myElement` 的 `transform` 属性。
3. **JavaScript 执行:**  当 JavaScript 代码执行到 `element.style.transform = ...` 时，浏览器会：
   * **解析 CSS `transform` 值:**  Blink 的 CSS 解析器会调用 `CSSParser::ParseSingleValue` 来解析 `'translate(50px, 100px) rotate(45deg)'` 字符串。
   * **创建变换操作:** `TransformBuilder::CreateTransformOperations` 会将解析后的值转换为一系列变换操作。
   * **应用变换操作:**  在渲染过程中，这些变换操作会被转换为内部的 `gfx::Transform` 对象，最终会影响元素的布局和绘制。
4. **`window.getComputedStyle(element)`:**  当执行到这行代码时，浏览器会计算元素的最终样式，包括 `transform` 属性。
5. **`computedStyle.transform`:**  浏览器会返回计算后的 `transform` 值，这通常是一个 `matrix()` 或 `matrix3d()` 形式的字符串。
6. **`new DOMMatrix(transformValue)`:**  当使用 `new DOMMatrix()` 构造函数并传入一个字符串时，会调用 `DOMMatrixReadOnly::Create` 方法，最终会调用 `DOMMatrixReadOnly::SetMatrixValueFromString`。
   * **`DOMMatrixReadOnly::SetMatrixValueFromString`:**  该方法会再次使用 CSS 解析器 (`CSSParser::ParseSingleValue`) 来解析 `transformValue` 字符串。
   * **创建 `DOMMatrixReadOnly` 对象:**  根据解析后的值，创建一个新的 `DOMMatrixReadOnly` 对象。
7. **`console.log(matrix)`:**  最终会将创建的 `DOMMatrixReadOnly` 对象的信息输出到控制台。

**作为调试线索:**  如果在这个过程中出现问题，例如矩阵值不正确，可以按照以下步骤调试：

* **检查 CSS `transform` 属性值:** 确认 CSS 中设置的变换是否正确。
* **断点调试 JavaScript:**  在 JavaScript 代码的关键位置设置断点，例如在 `element.style.transform = ...` 之后，以及在 `new DOMMatrix(transformValue)` 之前和之后，查看变量的值。
* **检查 `getComputedStyle().transform`:**  确认计算后的 `transform` 值是否符合预期，这有助于了解浏览器如何解析和组合 CSS 变换。
* **查看 `DOMMatrixReadOnly::SetMatrixValueFromString` 的执行过程:** 如果怀疑是字符串解析的问题，可以在该函数内部设置断点，查看解析过程中的中间值。
* **使用开发者工具的 "Computed" 面板:**  查看元素的计算样式，可以直接看到 `transform` 属性的值。
* **使用开发者工具的 "Layers" 面板:**  查看元素的层叠上下文和变换应用情况，有助于理解变换对渲染的影响。

通过以上分析，我们可以清晰地理解 `dom_matrix_read_only.cc` 文件的功能，它与 Web 技术的关系，以及在开发过程中可能遇到的问题和调试方法。

### 提示词
```
这是目录为blink/renderer/core/geometry/dom_matrix_read_only.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/geometry/dom_matrix_read_only.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix_2d_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_unrestricteddoublesequence.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/resolver/transform_builder.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix.h"
#include "third_party/blink/renderer/core/geometry/dom_point.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {
namespace {

void SetDictionaryMembers(DOMMatrix2DInit* other) {
  if (!other->hasM11())
    other->setM11(other->hasA() ? other->a() : 1);

  if (!other->hasM12())
    other->setM12(other->hasB() ? other->b() : 0);

  if (!other->hasM21())
    other->setM21(other->hasC() ? other->c() : 0);

  if (!other->hasM22())
    other->setM22(other->hasD() ? other->d() : 1);

  if (!other->hasM41())
    other->setM41(other->hasE() ? other->e() : 0);

  if (!other->hasM42())
    other->setM42(other->hasF() ? other->f() : 0);
}

}  // namespace

bool DOMMatrixReadOnly::ValidateAndFixup2D(DOMMatrix2DInit* other) {
  if (other->hasA() && other->hasM11() && other->a() != other->m11() &&
      !(std::isnan(other->a()) && std::isnan(other->m11()))) {
    return false;
  }
  if (other->hasB() && other->hasM12() && other->b() != other->m12() &&
      !(std::isnan(other->b()) && std::isnan(other->m12()))) {
    return false;
  }
  if (other->hasC() && other->hasM21() && other->c() != other->m21() &&
      !(std::isnan(other->c()) && std::isnan(other->m21()))) {
    return false;
  }
  if (other->hasD() && other->hasM22() && other->d() != other->m22() &&
      !(std::isnan(other->d()) && std::isnan(other->m22()))) {
    return false;
  }
  if (other->hasE() && other->hasM41() && other->e() != other->m41() &&
      !(std::isnan(other->e()) && std::isnan(other->m41()))) {
    return false;
  }
  if (other->hasF() && other->hasM42() && other->f() != other->m42() &&
      !(std::isnan(other->f()) && std::isnan(other->m42()))) {
    return false;
  }

  SetDictionaryMembers(other);
  return true;
}

bool DOMMatrixReadOnly::ValidateAndFixup(DOMMatrixInit* other,
                                         ExceptionState& exception_state) {
  if (!ValidateAndFixup2D(other)) {
    exception_state.ThrowTypeError(
        "Property mismatch on matrix initialization.");
    return false;
  }

  if (other->hasIs2D() && other->is2D() &&
      (other->m31() || other->m32() || other->m13() || other->m23() ||
       other->m43() || other->m14() || other->m24() || other->m34() ||
       other->m33() != 1 || other->m44() != 1)) {
    exception_state.ThrowTypeError(
        "The is2D member is set to true but the input matrix is a 3d matrix.");
    return false;
  }

  if (!other->hasIs2D()) {
    bool is2d =
        !(other->m31() || other->m32() || other->m13() || other->m23() ||
          other->m43() || other->m14() || other->m24() || other->m34() ||
          other->m33() != 1 || other->m44() != 1);
    other->setIs2D(is2d);
  }
  return true;
}

DOMMatrixReadOnly* DOMMatrixReadOnly::Create(
    ExecutionContext* execution_context,
    ExceptionState& exception_state) {
  return MakeGarbageCollected<DOMMatrixReadOnly>(gfx::Transform());
}

DOMMatrixReadOnly* DOMMatrixReadOnly::Create(
    ExecutionContext* execution_context,
    const V8UnionStringOrUnrestrictedDoubleSequence* init,
    ExceptionState& exception_state) {
  DCHECK(init);

  switch (init->GetContentType()) {
    case V8UnionStringOrUnrestrictedDoubleSequence::ContentType::kString: {
      if (!execution_context->IsWindow()) {
        exception_state.ThrowTypeError(
            "DOMMatrix can't be constructed with strings on workers.");
        return nullptr;
      }

      DOMMatrixReadOnly* matrix =
          MakeGarbageCollected<DOMMatrixReadOnly>(gfx::Transform());
      matrix->SetMatrixValueFromString(execution_context, init->GetAsString(),
                                       exception_state);
      return matrix;
    }
    case V8UnionStringOrUnrestrictedDoubleSequence::ContentType::
        kUnrestrictedDoubleSequence: {
      const Vector<double>& sequence = init->GetAsUnrestrictedDoubleSequence();
      if (sequence.size() != 6 && sequence.size() != 16) {
        exception_state.ThrowTypeError(
            "The sequence must contain 6 elements for a 2D matrix or 16 "
            "elements "
            "for a 3D matrix.");
        return nullptr;
      }
      return MakeGarbageCollected<DOMMatrixReadOnly>(base::span(sequence));
    }
  }

  NOTREACHED();
}

DOMMatrixReadOnly* DOMMatrixReadOnly::CreateForSerialization(
    base::span<const double> sequence) {
  return MakeGarbageCollected<DOMMatrixReadOnly>(sequence);
}

DOMMatrixReadOnly* DOMMatrixReadOnly::fromFloat32Array(
    NotShared<DOMFloat32Array> float32_array,
    ExceptionState& exception_state) {
  if (float32_array->length() != 6 && float32_array->length() != 16) {
    exception_state.ThrowTypeError(
        "The sequence must contain 6 elements for a 2D matrix or 16 elements a "
        "for 3D matrix.");
    return nullptr;
  }
  base::span<const float> sequence = float32_array->AsSpan();
  return MakeGarbageCollected<DOMMatrixReadOnly>(sequence);
}

DOMMatrixReadOnly* DOMMatrixReadOnly::fromFloat64Array(
    NotShared<DOMFloat64Array> float64_array,
    ExceptionState& exception_state) {
  if (float64_array->length() != 6 && float64_array->length() != 16) {
    exception_state.ThrowTypeError(
        "The sequence must contain 6 elements for a 2D matrix or 16 elements "
        "for a 3D matrix.");
    return nullptr;
  }
  base::span<const double> sequence = float64_array->AsSpan();
  return MakeGarbageCollected<DOMMatrixReadOnly>(sequence);
}

DOMMatrixReadOnly* DOMMatrixReadOnly::fromMatrix2D(
    DOMMatrix2DInit* other,
    ExceptionState& exception_state) {
  if (!ValidateAndFixup2D(other)) {
    exception_state.ThrowTypeError(
        "Property mismatch on matrix initialization.");
    return nullptr;
  }
  const std::array<double, 6> args = {other->m11(), other->m12(), other->m21(),
                                      other->m22(), other->m41(), other->m42()};
  return MakeGarbageCollected<DOMMatrixReadOnly>(base::span(args));
}

DOMMatrixReadOnly* DOMMatrixReadOnly::fromMatrix(
    DOMMatrixInit* other,
    ExceptionState& exception_state) {
  if (!ValidateAndFixup(other, exception_state)) {
    DCHECK(exception_state.HadException());
    return nullptr;
  }
  if (other->is2D()) {
    const std::array<double, 6> args = {other->m11(), other->m12(),
                                        other->m21(), other->m22(),
                                        other->m41(), other->m42()};
    return MakeGarbageCollected<DOMMatrixReadOnly>(base::span(args));
  }

  const std::array<double, 16> args = {
      other->m11(), other->m12(), other->m13(), other->m14(),
      other->m21(), other->m22(), other->m23(), other->m24(),
      other->m31(), other->m32(), other->m33(), other->m34(),
      other->m41(), other->m42(), other->m43(), other->m44()};
  return MakeGarbageCollected<DOMMatrixReadOnly>(base::span(args));
}

DOMMatrixReadOnly::~DOMMatrixReadOnly() = default;

bool DOMMatrixReadOnly::is2D() const {
  return is2d_;
}

bool DOMMatrixReadOnly::isIdentity() const {
  return matrix_.IsIdentity();
}

DOMMatrix* DOMMatrixReadOnly::multiply(DOMMatrixInit* other,
                                       ExceptionState& exception_state) {
  return DOMMatrix::Create(this)->multiplySelf(other, exception_state);
}

DOMMatrix* DOMMatrixReadOnly::translate(double tx, double ty, double tz) {
  return DOMMatrix::Create(this)->translateSelf(tx, ty, tz);
}

DOMMatrix* DOMMatrixReadOnly::scale(double sx) {
  return scale(sx, sx);
}

DOMMatrix* DOMMatrixReadOnly::scale(double sx,
                                    double sy,
                                    double sz,
                                    double ox,
                                    double oy,
                                    double oz) {
  return DOMMatrix::Create(this)->scaleSelf(sx, sy, sz, ox, oy, oz);
}

DOMMatrix* DOMMatrixReadOnly::scale3d(double scale,
                                      double ox,
                                      double oy,
                                      double oz) {
  return DOMMatrix::Create(this)->scale3dSelf(scale, ox, oy, oz);
}

DOMMatrix* DOMMatrixReadOnly::scaleNonUniform(double sx, double sy) {
  return DOMMatrix::Create(this)->scaleSelf(sx, sy, 1, 0, 0, 0);
}

DOMMatrix* DOMMatrixReadOnly::rotate(double rot_x) {
  return DOMMatrix::Create(this)->rotateSelf(rot_x);
}

DOMMatrix* DOMMatrixReadOnly::rotate(double rot_x, double rot_y) {
  return DOMMatrix::Create(this)->rotateSelf(rot_x, rot_y);
}

DOMMatrix* DOMMatrixReadOnly::rotate(double rot_x, double rot_y, double rot_z) {
  return DOMMatrix::Create(this)->rotateSelf(rot_x, rot_y, rot_z);
}

DOMMatrix* DOMMatrixReadOnly::rotateFromVector(double x, double y) {
  return DOMMatrix::Create(this)->rotateFromVectorSelf(x, y);
}

DOMMatrix* DOMMatrixReadOnly::rotateAxisAngle(double x,
                                              double y,
                                              double z,
                                              double angle) {
  return DOMMatrix::Create(this)->rotateAxisAngleSelf(x, y, z, angle);
}

DOMMatrix* DOMMatrixReadOnly::skewX(double sx) {
  return DOMMatrix::Create(this)->skewXSelf(sx);
}

DOMMatrix* DOMMatrixReadOnly::skewY(double sy) {
  return DOMMatrix::Create(this)->skewYSelf(sy);
}

DOMMatrix* DOMMatrixReadOnly::flipX() {
  DOMMatrix* flip_x = DOMMatrix::Create(this);
  flip_x->setM11(-m11());
  flip_x->setM12(-m12());
  flip_x->setM13(-m13());
  flip_x->setM14(-m14());
  return flip_x;
}

DOMMatrix* DOMMatrixReadOnly::flipY() {
  DOMMatrix* flip_y = DOMMatrix::Create(this);
  flip_y->setM21(-m21());
  flip_y->setM22(-m22());
  flip_y->setM23(-m23());
  flip_y->setM24(-m24());
  return flip_y;
}

DOMMatrix* DOMMatrixReadOnly::inverse() {
  return DOMMatrix::Create(this)->invertSelf();
}

DOMPoint* DOMMatrixReadOnly::transformPoint(const DOMPointInit* point) {
  if (is2D() && point->z() == 0 && point->w() == 1) {
    double x = point->x() * m11() + point->y() * m21() + m41();
    double y = point->x() * m12() + point->y() * m22() + m42();
    return DOMPoint::Create(x, y, 0, 1);
  }

  double x = point->x() * m11() + point->y() * m21() + point->z() * m31() +
             point->w() * m41();
  double y = point->x() * m12() + point->y() * m22() + point->z() * m32() +
             point->w() * m42();
  double z = point->x() * m13() + point->y() * m23() + point->z() * m33() +
             point->w() * m43();
  double w = point->x() * m14() + point->y() * m24() + point->z() * m34() +
             point->w() * m44();
  return DOMPoint::Create(x, y, z, w);
}

DOMMatrixReadOnly::DOMMatrixReadOnly(const gfx::Transform& matrix, bool is2d)
    : matrix_(matrix), is2d_(is2d) {}

NotShared<DOMFloat32Array> DOMMatrixReadOnly::toFloat32Array() const {
  float array[16];
  matrix_.GetColMajorF(array);
  return NotShared<DOMFloat32Array>(DOMFloat32Array::Create(array));
}

NotShared<DOMFloat64Array> DOMMatrixReadOnly::toFloat64Array() const {
  double array[16];
  matrix_.GetColMajor(array);
  return NotShared<DOMFloat64Array>(DOMFloat64Array::Create(array));
}

const String DOMMatrixReadOnly::toString(
    ExceptionState& exception_state) const {
  constexpr const char* kComma = ", ";
  StringBuilder result;

  if (is2D()) {
    if (!std::isfinite(a()) || !std::isfinite(b()) || !std::isfinite(c()) ||
        !std::isfinite(d()) || !std::isfinite(e()) || !std::isfinite(f())) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "DOMMatrix cannot be serialized with NaN or Infinity values.");
      return String();
    }

    result.Append("matrix(");
    result.Append(String::NumberToStringECMAScript(a()));
    result.Append(kComma);
    result.Append(String::NumberToStringECMAScript(b()));
    result.Append(kComma);
    result.Append(String::NumberToStringECMAScript(c()));
    result.Append(kComma);
    result.Append(String::NumberToStringECMAScript(d()));
    result.Append(kComma);
    result.Append(String::NumberToStringECMAScript(e()));
    result.Append(kComma);
    result.Append(String::NumberToStringECMAScript(f()));
    result.Append(")");
    return result.ToString();
  }

  if (!std::isfinite(m11()) || !std::isfinite(m12()) || !std::isfinite(m13()) ||
      !std::isfinite(m14()) || !std::isfinite(m21()) || !std::isfinite(m22()) ||
      !std::isfinite(m23()) || !std::isfinite(m24()) || !std::isfinite(m31()) ||
      !std::isfinite(m32()) || !std::isfinite(m33()) || !std::isfinite(m34()) ||
      !std::isfinite(m41()) || !std::isfinite(m42()) || !std::isfinite(m43()) ||
      !std::isfinite(m44())) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "DOMMatrix cannot be serialized with NaN or Infinity values.");
    return String();
  }

  result.Append("matrix3d(");
  result.Append(String::NumberToStringECMAScript(m11()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m12()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m13()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m14()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m21()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m22()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m23()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m24()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m31()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m32()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m33()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m34()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m41()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m42()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m43()));
  result.Append(kComma);
  result.Append(String::NumberToStringECMAScript(m44()));
  result.Append(")");

  return result.ToString();
}

ScriptValue DOMMatrixReadOnly::toJSONForBinding(
    ScriptState* script_state) const {
  V8ObjectBuilder result(script_state);
  result.AddNumber("a", a());
  result.AddNumber("b", b());
  result.AddNumber("c", c());
  result.AddNumber("d", d());
  result.AddNumber("e", e());
  result.AddNumber("f", f());
  result.AddNumber("m11", m11());
  result.AddNumber("m12", m12());
  result.AddNumber("m13", m13());
  result.AddNumber("m14", m14());
  result.AddNumber("m21", m21());
  result.AddNumber("m22", m22());
  result.AddNumber("m23", m23());
  result.AddNumber("m24", m24());
  result.AddNumber("m31", m31());
  result.AddNumber("m32", m32());
  result.AddNumber("m33", m33());
  result.AddNumber("m34", m34());
  result.AddNumber("m41", m41());
  result.AddNumber("m42", m42());
  result.AddNumber("m43", m43());
  result.AddNumber("m44", m44());
  result.AddBoolean("is2D", is2D());
  result.AddBoolean("isIdentity", isIdentity());
  return result.GetScriptValue();
}

AffineTransform DOMMatrixReadOnly::GetAffineTransform() const {
  return AffineTransform(a(), b(), c(), d(), e(), f());
}

void DOMMatrixReadOnly::SetMatrixValueFromString(
    const ExecutionContext* execution_context,
    const String& input_string,
    ExceptionState& exception_state) {
  DEFINE_STATIC_LOCAL(String, identity_matrix2d, ("matrix(1, 0, 0, 1, 0, 0)"));
  String string = input_string;
  if (string.empty())
    string = identity_matrix2d;

  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kTransform, string,
      StrictCSSParserContext(execution_context->GetSecureContextMode()));

  if (!value || value->IsCSSWideKeyword()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Failed to parse '" + input_string + "'.");
    return;
  }

  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK(identifier_value->GetValueID() == CSSValueID::kNone);
    matrix_.MakeIdentity();
    is2d_ = true;
    return;
  }

  if (TransformBuilder::HasRelativeLengths(To<CSSValueList>(*value))) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Lengths must be absolute, not relative");
    return;
  }

  TransformOperations operations = TransformBuilder::CreateTransformOperations(
      *value, CSSToLengthConversionData(/*element=*/nullptr));

  if (operations.BoxSizeDependencies()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Lengths must be absolute, not depend on the box size");
    return;
  }

  matrix_.MakeIdentity();
  operations.Apply(gfx::SizeF(0, 0), matrix_);

  is2d_ = !operations.Has3DOperation();

  return;
}

}  // namespace blink
```