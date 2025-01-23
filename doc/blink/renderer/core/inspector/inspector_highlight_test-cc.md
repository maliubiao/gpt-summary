Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the `inspector_highlight_test.cc` file, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common user/programming errors.

2. **Identify the Core Subject:** The filename `inspector_highlight_test.cc` and the included header `inspector_highlight.h` immediately suggest that this file is testing the *highlighting* functionality within the Chromium DevTools inspector. This is the central theme around which all other observations will revolve.

3. **Examine the Includes:**  The included headers provide valuable clues about the functionalities being tested:
    * `inspector_highlight.h`:  Defines the classes and functions being tested.
    * `base/test/values_test_util.h`, `base/values.h`: Indicate interaction with JSON-like data structures, likely for representing highlight information.
    * `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`: Confirm that this is a unit test file using Google Test and Google Mock.
    * `accessibility/ax_context.h`: Suggests that accessibility information might be related to highlighting (though not a primary focus in these tests).
    * `frame/local_frame_view.h`: Implies interaction with the rendering process.
    * `html/html_element.h`:  Confirms interaction with HTML elements, which are the targets of highlighting.
    * `testing/dummy_page_holder.h`:  Indicates the use of a test environment simulating a web page.
    * `platform/testing/task_environment.h`:  Relates to asynchronous operations in the test environment (though not explicitly tested in these snippets).
    * `third_party/inspector_protocol/crdtp/json.h`, `third_party/inspector_protocol/crdtp/span.h`:  Reinforce the use of the Chrome DevTools Protocol (CDP) for exchanging highlight information as JSON.

4. **Analyze the Test Structure:** The `InspectorHighlightTest` class inherits from `testing::Test`, which is standard practice for Google Test. The `SetUp` method initializes a `DummyPageHolder`, creating a basic test environment. Each `TEST_F` macro defines an individual test case.

5. **Deconstruct Individual Test Cases:**  Go through each `TEST_F` and identify its purpose:
    * **`BuildSnapContainerInfoNoSnapAreas`:** Tests the case where a target element is *not* a snap container. The expectation is that `BuildSnapContainerInfo` returns `false` (or a null pointer wrapped in an optional-like structure).
    * **`BuildSnapContainerInfoSnapAreas`:** Tests the case where an element *is* a snap container. It verifies the structure of the output of `BuildSnapContainerInfo`, including `snapAreas`, `snapport`, and `paddingBox`, represented as JSON paths. This is directly related to CSS `scroll-snap-type` and `scroll-snap-align`.
    * **`BuildSnapContainerInfoTopLevelSnapAreas`:**  Similar to the previous test but specifically targets the `documentElement` (the `<html>` tag) as a snap container.
    * **`BuildContainerQueryContainerInfoWithoutDescendants`:** Tests highlighting for container queries when no descendant elements trigger the query. It focuses on the `containerBorder`. This relates to the CSS `container-type` property.
    * **`BuildContainerQueryContainerInfoWithDescendants`:** Tests highlighting when descendant elements *do* trigger a container query. It checks the `descendantBorder` in the output, demonstrating the ability to highlight elements affected by container queries.
    * **`BuildIsolatedElementInfo`:** Tests highlighting for isolated elements (likely related to CSS containment or similar features). It verifies the presence and values of various resizer borders and sizing information.
    * **`BuildElementInfo_Colors`:** Focuses specifically on how different CSS color formats (lab, color(), hex, rgb, variables) are represented in the highlight information.
    * **`GridLineNames`:** Tests the extraction and representation of grid line names defined using bracket notation in `grid-template-columns` and `grid-template-rows`, including subgrids.
    * **`GridAreaNames`:** Tests the extraction and representation of grid area names defined in `grid-template-areas`, including subgrids.

6. **Identify Connections to Web Technologies:**
    * **HTML:** The tests manipulate the DOM using `setInnerHTML` and `getElementById`, directly interacting with HTML elements. Highlighting is intrinsically linked to HTML elements.
    * **CSS:**  Many tests directly involve CSS properties: `scroll-snap-type`, `scroll-snap-align`, `container-type`, container queries (`@container`), grid layout properties (`display: grid`, `grid-template-columns`, `grid-template-rows`, `grid-template-areas`, `grid-column`, `grid-row`). The tests verify how highlighting reflects these CSS styles.
    * **JavaScript:** While this specific test file doesn't *execute* JavaScript, the highlighting functionality being tested is used by the DevTools, which is a JavaScript application running in the browser. The inspector uses the information generated by this C++ code to visually highlight elements in the browser.

7. **Look for Logical Reasoning:** Identify test cases where specific inputs (HTML/CSS) are expected to produce specific outputs (highlight information in JSON format). The assertions (`EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`) demonstrate this reasoning. For example, if an element has `scroll-snap-type: y mandatory`, the `BuildSnapContainerInfo` function *should* produce a JSON object with `snapAreas`.

8. **Consider User/Programming Errors:** Think about common mistakes developers make when working with the features being tested:
    * **Incorrect CSS Syntax:** The tests implicitly check that the highlighting logic correctly interprets valid CSS. Errors in CSS syntax could lead to unexpected highlighting or no highlighting.
    * **Misunderstanding CSS Properties:**  If a developer doesn't understand how `scroll-snap-type` or container queries work, the highlighting might appear incorrect to them.
    * **Forgetting Units:**  While not explicitly tested here, forgetting units in CSS values could lead to rendering issues that might affect highlighting.
    * **Incorrect Element Selection:** In the DevTools UI, a user might try to highlight an element that doesn't exist or is not visible, which could lead to errors or no highlighting.
    * **Z-index Issues:**  Elements hidden behind others due to `z-index` might still be highlighted, which could be confusing to the user.

9. **Synthesize and Organize:**  Structure the findings into the requested categories: functionality, relationship to web technologies, logical reasoning, and user/programming errors, providing concrete examples from the code. Use clear and concise language.

10. **Review and Refine:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check if all parts of the request have been addressed. For instance, ensure that the examples of logical reasoning include both the input (HTML/CSS) and the expected output (JSON).
这个文件 `blink/renderer/core/inspector/inspector_highlight_test.cc` 是 Chromium Blink 渲染引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `blink::InspectorHighlight` 类及其相关功能**。`InspectorHighlight` 负责生成在 Chrome DevTools 的 Elements 面板中高亮显示网页元素所需的信息。

更具体地说，这个文件中的测试用例主要验证了以下功能：

**1. 构建元素高亮信息 (`BuildElementInfo`)**:
   - 测试针对不同 CSS 属性，特别是颜色相关的属性，`BuildElementInfo` 能否正确生成高亮信息。
   - **与 CSS 的关系**:
     - **例子**: `TEST_F(InspectorHighlightTest, BuildElementInfo_Colors)` 测试了 `background-color` 属性的不同取值（`lab`, `color`, `hex`, `rgb`, CSS 变量），并验证了 `BuildElementInfo` 能否正确解析和返回这些颜色值。例如，当 `<div id="lab" style="background-color: lab(100% 0 0);"></div>` 时，预期 `GetBackgroundColorFromElementInfo` 返回 `"lab(100 0 0)"`。
   - **假设输入与输出**:
     - **假设输入**: 一个设置了 `background-color: #ff00ff;` 的 HTML 元素。
     - **预期输出**:  `BuildElementInfo` 生成的 JSON 数据中，`style` 字段包含 `"background-color-css-text": "#FF00FFFF"` (或类似的表示)。

**2. 构建滚动捕捉容器信息 (`BuildSnapContainerInfo`)**:
   - 测试当元素是滚动捕捉容器时，能否正确识别捕捉区域（snap areas）和捕捉视口（snapport）。
   - **与 CSS 的关系**:
     - **例子**: `TEST_F(InspectorHighlightTest, BuildSnapContainerInfoSnapAreas)` 测试了当一个 `div` 设置了 `scroll-snap-type: y mandatory;` 并包含定义了 `scroll-snap-align: center;` 的子元素时，能否正确计算并返回捕捉区域的边界信息。这些信息以路径的形式表示，用于在 DevTools 中高亮显示。
   - **假设输入与输出**:
     - **假设输入**: 一个设置了 `scroll-snap-type: y mandatory;` 的 div 容器和两个设置了 `scroll-snap-align: center;` 的子 div。
     - **预期输出**: `BuildSnapContainerInfo` 返回的 JSON 数据包含一个 `snapAreas` 数组，每个元素描述一个捕捉区域的路径信息（例如 `path":["M",18,18,"L",113,18,"L",113,113,"L",18,113,"Z"]`）。

**3. 构建容器查询容器信息 (`BuildContainerQueryContainerInfo`)**:
   - 测试当元素是容器查询容器时，能否正确识别容器边界和受容器查询影响的后代元素。
   - **与 CSS 的关系**:
     - **例子**: `TEST_F(InspectorHighlightTest, BuildContainerQueryContainerInfoWithDescendants)` 测试了当一个 `div` 设置了 `container-type: inline-size;` 并且内部的元素受 `@container (min-width: 100px)` 查询影响时，能否正确高亮显示容器的边界以及受影响后代的边界。
   - **假设输入与输出**:
     - **假设输入**: 一个设置了 `container-type: inline-size;` 的 div 容器和一个受其容器查询影响的子元素。
     - **预期输出**: `BuildContainerQueryContainerInfo` 返回的 JSON 数据包含 `containerBorder` 描述容器边界，以及 `queryingDescendants` 数组，其中包含了受影响后代的边界信息 (`descendantBorder`)。

**4. 构建隔离元素信息 (`BuildIsolatedElementInfo`)**:
   - 测试对于被隔离的元素，能否正确生成用于在 DevTools 中进行大小调整和高亮显示的信息。
   - **与 CSS 的关系**:  虽然代码中没有直接展示 CSS 属性，但“隔离元素”的概念通常与 CSS 的 `contain` 属性或者 shadow DOM 等特性相关。这个测试主要关注的是高亮显示和交互相关的边界信息。
   - **假设输入与输出**:
     - **假设输入**: 一个简单的 div 元素。
     - **预期输出**: `BuildIsolatedElementInfo` 返回的 JSON 数据包含各种边界信息，如 `bidirectionResizerBorder`, `widthResizerBorder`, `heightResizerBorder`，以及元素的当前尺寸和位置。

**5. 构建网格高亮信息 (`InspectorGridHighlight`)**:
   - 测试对于 CSS Grid 布局的元素，能否正确提取和返回网格线名称和网格区域名称。
   - **与 CSS 的关系**:
     - **例子**: `TEST_F(InspectorHighlightTest, GridLineNames)` 测试了定义了网格线名称的 Grid 布局 (`grid-template-columns: [a] 1fr [b] 1fr [c] 1fr;`)，以及包含 subgrid 的情况，能否正确提取这些名称。
     - **例子**: `TEST_F(InspectorHighlightTest, GridAreaNames)` 测试了使用 `grid-template-areas` 定义了网格区域名称的 Grid 布局，包括 subgrid，能否正确提取这些区域名称。
   - **假设输入与输出**:
     - **假设输入**: 一个定义了命名网格线和网格区域的 Grid 容器。
     - **预期输出**: `InspectorGridHighlight` 返回的 JSON 数据包含 `rowLineNameOffsets` 和 `columnLineNameOffsets` 数组，列出所有命名的网格线及其偏移量，以及 `areaNames` 对象，包含所有命名的网格区域。

**涉及的 JavaScript, HTML, CSS 的功能举例说明:**

* **HTML**: 测试代码通过 `GetDocument().body()->setInnerHTML()` 方法动态创建 HTML 结构，并使用 `GetDocument().getElementById()` 获取特定元素进行测试。这些操作直接关联到 HTML 文档的构建和元素选择。
* **CSS**:  大量的测试用例直接涉及到 CSS 属性的解析和高亮显示。例如：
    * **颜色**: 测试了 `background-color` 的各种颜色表示方法。
    * **滚动捕捉**: 测试了 `scroll-snap-type` 和 `scroll-snap-align` 如何影响高亮显示的捕捉区域。
    * **容器查询**: 测试了 `@container` 查询如何影响容器和受影响后代的边界高亮。
    * **Grid 布局**: 测试了 `display: grid`, `grid-template-columns`, `grid-template-rows`, `grid-template-areas` 等属性定义的网格线和网格区域名称的提取。
* **JavaScript**: 虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的功能是 Chrome DevTools 的一部分，而 DevTools 本身是用 JavaScript 构建的。DevTools 使用 `InspectorHighlight` 生成的信息来在 Elements 面板中动态地高亮显示网页元素，以便开发者调试和审查网页布局和样式。

**逻辑推理的假设输入与输出举例:**

* **测试 `BuildSnapContainerInfoNoSnapAreas`**:
    * **假设输入**: 一个简单的 `<div>test</div>` 元素，没有设置任何滚动捕捉相关的 CSS 属性。
    * **预期输出**: `BuildSnapContainerInfo(target)` 返回 `false`，因为该元素不是滚动捕捉容器。

**涉及用户或者编程常见的使用错误举例说明:**

虽然这个测试文件本身是针对引擎内部逻辑的，但它测试的功能与用户在开发过程中可能遇到的错误息息相关：

* **CSS 语法错误导致高亮不准确**: 如果开发者在 CSS 中错误地定义了 `scroll-snap-type` 或 `@container` 查询，`InspectorHighlight` 可能会生成不符合预期的信息，导致 DevTools 中的高亮显示不准确或缺失。例如，拼写错误的 CSS 属性名。
* **误解 CSS 属性的影响**: 开发者可能不理解 `scroll-snap-align: center` 会如何影响捕捉区域的计算。测试确保了 `InspectorHighlight` 能够正确地基于 CSS 规范计算这些区域，帮助开发者理解其代码的行为。
* **Grid 布局命名错误**:  开发者在定义 Grid 布局时，可能会错误地命名网格线或网格区域。`InspectorHighlight` 能够提取这些名称，帮助开发者验证其命名的正确性。如果提取的名称与开发者预期不符，则说明 CSS 定义可能存在错误。
* **容器查询条件错误**:  开发者可能设置了错误的容器查询条件 (例如 `min-width` 的值)，导致某些元素本应受到影响却没有被影响。`InspectorHighlight` 能够高亮显示受容器查询影响的元素，帮助开发者调试这些问题。

总而言之，`inspector_highlight_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎能够正确地生成用于在 Chrome DevTools 中高亮显示网页元素的信息，这对于开发者调试和理解网页结构、样式和布局至关重要。它涵盖了多种 CSS 特性，特别是那些影响元素布局和渲染的高级特性。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_highlight_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/inspector_highlight.h"

#include "base/test/values_test_util.h"
#include "base/values.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/accessibility/ax_context.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/inspector_protocol/crdtp/json.h"
#include "third_party/inspector_protocol/crdtp/span.h"

namespace blink {

namespace {

using base::test::ParseJson;
using testing::ByRef;
using testing::Eq;
using testing::UnorderedElementsAre;

void AssertValueEqualsJSON(const std::unique_ptr<protocol::Value>& actual_value,
                           const std::string& json_expected) {
  std::string json_actual;
  auto status_to_json = crdtp::json::ConvertCBORToJSON(
      crdtp::SpanFrom(actual_value->Serialize()), &json_actual);
  EXPECT_TRUE(status_to_json.ok());
  base::Value parsed_json_actual = ParseJson(json_actual);
  base::Value parsed_json_expected = ParseJson(json_expected);
  EXPECT_THAT(parsed_json_actual, Eq(ByRef(parsed_json_expected)));
}

}  // namespace

class InspectorHighlightTest : public testing::Test {
 protected:
  void SetUp() override;

  Document& GetDocument() { return dummy_page_holder_->GetDocument(); }

 private:
  test::TaskEnvironment task_environment_;

  std::unique_ptr<DummyPageHolder> dummy_page_holder_;
};

void InspectorHighlightTest::SetUp() {
  dummy_page_holder_ = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
}

TEST_F(InspectorHighlightTest, BuildSnapContainerInfoNoSnapAreas) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="target">test</div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_FALSE(BuildSnapContainerInfo(target));
}

TEST_F(InspectorHighlightTest, BuildSnapContainerInfoSnapAreas) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #snap {
        background-color: white;
        scroll-snap-type: y mandatory;
        overflow-x: hidden;
        overflow-y: scroll;
        width: 150px;
        height: 150px;
      }
      #snap > div {
        width: 75px;
        height: 75px;
        scroll-snap-align: center;
        margin: 10px;
        padding: 10px;
      }
    </style>
    <div id="snap"><div>A</div><div>B</div></div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  Element* container = GetDocument().getElementById(AtomicString("snap"));
  auto info = BuildSnapContainerInfo(container);
  EXPECT_TRUE(info);

  EXPECT_EQ(2u, info->getArray("snapAreas")->size());
  protocol::ErrorSupport errors;
  std::string expected_container = R"JSON(
    {
      "snapport":["M",8,8,"L",158,8,"L",158,158,"L",8,158,"Z"],
      "paddingBox":["M",8,8,"L",158,8,"L",158,158,"L",8,158,"Z"],
      "snapAreas": [
        {
          "path":["M",18,18,"L",113,18,"L",113,113,"L",18,113,"Z"],
          "borderBox":["M",18,18,"L",113,18,"L",113,113,"L",18,113,"Z"],
          "alignBlock":"center"
        },
        {
          "path":["M",18,123,"L",113,123,"L",113,218,"L",18,218,"Z"],
          "borderBox":["M",18,123,"L",113,123,"L",113,218,"L",18,218,"Z"],
          "alignBlock":"center"
        }
      ]
    }
  )JSON";
  AssertValueEqualsJSON(protocol::ValueConversions<protocol::Value>::fromValue(
                            info.get(), &errors),
                        expected_container);
}

TEST_F(InspectorHighlightTest, BuildSnapContainerInfoTopLevelSnapAreas) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      :root {
        scroll-snap-type: y mandatory;
        overflow-x: hidden;
        overflow-y: scroll;
      }
      div {
        width: 100%;
        height: 100vh;
        scroll-snap-align: start;
      }
    </style>
    <div>A</div><div>B</div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  Element* container = GetDocument().documentElement();
  auto info = BuildSnapContainerInfo(container);
  EXPECT_TRUE(info);

  EXPECT_EQ(2u, info->getArray("snapAreas")->size());
  protocol::ErrorSupport errors;
  std::string expected_container = R"JSON(
    {
      "paddingBox": [ "M", 0, 0, "L", 800, 0, "L", 800, 600, "L", 0, 600, "Z" ],
      "snapAreas": [ {
          "alignBlock": "start",
          "borderBox": [ "M", 8, 0, "L", 792, 0, "L", 792, 600, "L", 8, 600, "Z" ],
          "path": [ "M", 8, 0, "L", 792, 0, "L", 792, 600, "L", 8, 600, "Z" ]
      }, {
          "alignBlock": "start",
          "borderBox": [ "M", 8, 600, "L", 792, 600, "L", 792, 1200, "L", 8, 1200, "Z" ],
          "path": [ "M", 8, 600, "L", 792, 600, "L", 792, 1200, "L", 8, 1200, "Z" ]
      } ],
      "snapport": [ "M", 0, 0, "L", 800, 0, "L", 800, 600, "L", 0, 600, "Z" ]
    }
  )JSON";
  AssertValueEqualsJSON(protocol::ValueConversions<protocol::Value>::fromValue(
                            info.get(), &errors),
                        expected_container);
}

TEST_F(InspectorHighlightTest,
       BuildContainerQueryContainerInfoWithoutDescendants) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #container {
        width: 400px;
        height: 500px;
        container-type: inline-size;
      }
    </style>
    <div id="container"></div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  Element* container = GetDocument().getElementById(AtomicString("container"));
  auto info = BuildContainerQueryContainerInfo(
      container, InspectorContainerQueryContainerHighlightConfig(), 1.0f);
  EXPECT_TRUE(info);

  protocol::ErrorSupport errors;
  std::string expected_container = R"JSON(
    {
      "containerBorder":["M",8,8,"L",408,8,"L",408,508,"L",8,508,"Z"],
      "containerQueryContainerHighlightConfig": {}
    }
  )JSON";
  AssertValueEqualsJSON(protocol::ValueConversions<protocol::Value>::fromValue(
                            info.get(), &errors),
                        expected_container);
}

TEST_F(InspectorHighlightTest,
       BuildContainerQueryContainerInfoWithDescendants) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #container {
        width: 400px;
        height: 500px;
        container-type: inline-size;
      }
      @container (min-width: 100px) {
        .item {
          width: 100px;
          height: 100px;
        }
      }
    </style>
    <div id="container"><div class="item"></div></div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  Element* container = GetDocument().getElementById(AtomicString("container"));

  LineStyle line_style;
  line_style.color = Color(1, 1, 1);
  InspectorContainerQueryContainerHighlightConfig highlight_config;
  highlight_config.descendant_border = line_style;
  auto info =
      BuildContainerQueryContainerInfo(container, highlight_config, 1.0f);
  EXPECT_TRUE(info);

  protocol::ErrorSupport errors;
  std::string expected_container = R"JSON(
    {
      "containerBorder":["M",8,8,"L",408,8,"L",408,508,"L",8,508,"Z"],
      "containerQueryContainerHighlightConfig": {
        "descendantBorder": {
          "color": "rgb(1, 1, 1)",
          "pattern": ""
        }
      },
      "queryingDescendants": [ {
          "descendantBorder": [ "M", 8, 8, "L", 108, 8, "L", 108, 108, "L", 8, 108, "Z" ]
      } ]
    }
  )JSON";
  AssertValueEqualsJSON(protocol::ValueConversions<protocol::Value>::fromValue(
                            info.get(), &errors),
                        expected_container);
}

TEST_F(InspectorHighlightTest, BuildIsolatedElementInfo) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #element {
        width: 400px;
        height: 500px;
      }
    </style>
    <div id="element"></div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  Element* element = GetDocument().getElementById(AtomicString("element"));
  auto info = BuildIsolatedElementInfo(
      *element, InspectorIsolationModeHighlightConfig(), 1.0f);
  EXPECT_TRUE(info);

  protocol::ErrorSupport errors;
  std::string expected_isolated_element = R"JSON(
    {
      "bidirectionResizerBorder": [ "M", 408, 508, "L", 428, 508, "L", 428, 528, "L", 408, 528, "Z" ],
      "currentHeight": 500,
      "currentWidth": 400,
      "currentX": 8,
      "currentY": 8,
      "heightResizerBorder": [ "M", 8, 508, "L", 408, 508, "L", 408, 528, "L", 8, 528, "Z" ],
      "isolationModeHighlightConfig": {
          "maskColor": "rgba(0, 0, 0, 0)",
          "resizerColor": "rgba(0, 0, 0, 0)",
          "resizerHandleColor": "rgba(0, 0, 0, 0)"
      },
      "widthResizerBorder": [ "M", 408, 8, "L", 428, 8, "L", 428, 508, "L", 408, 508, "Z" ]
    }
  )JSON";
  AssertValueEqualsJSON(protocol::ValueConversions<protocol::Value>::fromValue(
                            info.get(), &errors),
                        expected_isolated_element);
}

static std::string GetBackgroundColorFromElementInfo(Element* element) {
  EXPECT_TRUE(element);
  AXContext ax_context(element->GetDocument(), ui::kAXModeBasic);
  element->GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  auto info = BuildElementInfo(element);
  EXPECT_TRUE(info);
  AppendStyleInfo(element, info.get(), {}, {});

  protocol::ErrorSupport errors;
  auto actual_value = protocol::ValueConversions<protocol::Value>::fromValue(
      info.get(), &errors);
  EXPECT_TRUE(actual_value);

  std::string json_actual;
  auto status_to_json = crdtp::json::ConvertCBORToJSON(
      crdtp::SpanFrom(actual_value->Serialize()), &json_actual);
  EXPECT_TRUE(status_to_json.ok());
  base::Value::Dict parsed_json_actual = ParseJson(json_actual).TakeDict();
  auto* style = parsed_json_actual.FindDict("style");
  EXPECT_TRUE(style);
  auto* background_color = style->FindString("background-color-css-text");
  if (!background_color) {
    background_color = style->FindString("background-color");
  }
  EXPECT_TRUE(background_color);
  return std::move(*background_color);
}

TEST_F(InspectorHighlightTest, BuildElementInfo_Colors) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      div {
        width: 400px;
        height: 500px;
      }
      #lab {
        background-color: lab(100% 0 0);
      }
      #color {
        background-color: color(display-p3 50% 50% 50%);
      }
      #hex {
        background-color: #ff00ff;
      }
      #rgb {
        background-color: rgb(128 128 128);
      }
      #var {
        background-color: Var(--lab);
      }
      :root {
        --lab: lab(20% -10 -10);
      }
    </style>
    <div id="lab"></div>
    <div id="color"></div>
    <div id="hex"></div>
    <div id="rgb"></div>
    <div id="var"></div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetBackgroundColorFromElementInfo(
                  GetDocument().getElementById(AtomicString("lab"))),
              Eq("lab(100 0 0)"));
  EXPECT_THAT(GetBackgroundColorFromElementInfo(
                  GetDocument().getElementById(AtomicString("color"))),
              Eq("color(display-p3 0.5 0.5 0.5)"));
  EXPECT_THAT(GetBackgroundColorFromElementInfo(
                  GetDocument().getElementById(AtomicString("hex"))),
              Eq("#FF00FFFF"));
  EXPECT_THAT(GetBackgroundColorFromElementInfo(
                  GetDocument().getElementById(AtomicString("rgb"))),
              Eq("#808080FF"));
  EXPECT_THAT(GetBackgroundColorFromElementInfo(
                  GetDocument().getElementById(AtomicString("var"))),
              Eq("lab(20 -10 -10)"));
}

TEST_F(InspectorHighlightTest, GridLineNames) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
    #grid {
      display: grid;
      grid-template-columns: [a] 1fr [b] 1fr [c] 1fr;
      grid-template-rows: [d] 1fr [e] 1fr [f] 1fr;
    }
    #subgrid {
      display: grid;
      grid-column: 1 / 4;
      grid-row: 1 / 4;
      grid-template-columns: subgrid [a_sub] [b_sub] [c_sub];
      grid-template-rows: subgrid [d_sub] [e_sub] [f_sub];
    }
    </style>
    <div id="grid">
      <div id="subgrid">
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
      </div>
    </div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  Node* subgrid = GetDocument().getElementById(AtomicString("subgrid"));
  EXPECT_TRUE(subgrid);
  auto info =
      InspectorGridHighlight(subgrid, InspectorHighlight::DefaultGridConfig());
  EXPECT_TRUE(info);

  auto GetLineNames = [](protocol::ListValue* row_or_column_list) {
    Vector<String> ret;
    for (wtf_size_t i = 0; i < row_or_column_list->size(); ++i) {
      protocol::DictionaryValue* current_value =
          static_cast<protocol::DictionaryValue*>(row_or_column_list->at(i));

      WTF::String string_value;
      EXPECT_TRUE(current_value->getString("name", &string_value));
      ret.push_back(string_value);
    }
    return ret;
  };

  EXPECT_THAT(GetLineNames(info->getArray("rowLineNameOffsets")),
              UnorderedElementsAre("d", "d_sub", "e", "e_sub", "f", "f_sub"));
  EXPECT_THAT(GetLineNames(info->getArray("columnLineNameOffsets")),
              UnorderedElementsAre("a", "a_sub", "b", "b_sub", "c", "c_sub"));
}

TEST_F(InspectorHighlightTest, GridAreaNames) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
    #grid {
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      grid-template-rows: 1fr 1fr 1fr;
      grid-template-areas:
            "a a a"
            "b b b"
            "c c c";
    }
    #subgrid {
      display: grid;
      grid-column: 1 / 4;
      grid-row: 1 / 4;
      grid-template-columns: subgrid;
      grid-template-rows: subgrid;
      grid-template-areas:
            "d d d"
            "e e e"
            "f f f";
    }
    </style>
    <div id="grid">
      <div id="subgrid">
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
        <div class="griditem"></div>
      </div>
    </div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  auto CompareAreaNames = [](protocol::DictionaryValue* area_names,
                             WTF::Vector<WTF::String>& expected_names) -> void {
    for (WTF::String& name : expected_names) {
      EXPECT_TRUE(area_names->get(name));
    }
  };

  Node* grid = GetDocument().getElementById(AtomicString("grid"));
  EXPECT_TRUE(grid);
  auto grid_info =
      InspectorGridHighlight(grid, InspectorHighlight::DefaultGridConfig());
  EXPECT_TRUE(grid_info);
  protocol::DictionaryValue* grid_area_names =
      grid_info->getObject("areaNames");
  EXPECT_EQ(grid_area_names->size(), 3u);

  WTF::Vector<WTF::String> expected_grid_area_names = {"a", "b", "c"};
  CompareAreaNames(grid_area_names, expected_grid_area_names);

  Node* subgrid = GetDocument().getElementById(AtomicString("subgrid"));
  EXPECT_TRUE(subgrid);
  auto subgrid_info =
      InspectorGridHighlight(subgrid, InspectorHighlight::DefaultGridConfig());
  EXPECT_TRUE(subgrid_info);

  protocol::DictionaryValue* subgrid_area_names =
      subgrid_info->getObject("areaNames");
  EXPECT_EQ(subgrid_area_names->size(), 6u);

  WTF::Vector<WTF::String> expected_subgrid_area_names = {"a", "b", "c",
                                                          "d", "e", "f"};
  CompareAreaNames(subgrid_area_names, expected_subgrid_area_names);
}

}  // namespace blink
```