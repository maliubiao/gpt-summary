Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The first step is to recognize that this is a *test file*. Its purpose isn't to implement a feature, but to *verify* that a specific piece of code works correctly. The filename `paint_worklet_style_property_map_test.cc` strongly suggests it's testing the `PaintWorkletStylePropertyMap` class.

**2. Identifying Key Components:**

Scanning the `#include` directives and the namespace declaration (`namespace blink`) provides crucial context:

* **`PaintWorkletStylePropertyMap.h`:** This is the core class being tested. We can infer its role is related to managing style properties within a Paint Worklet.
* **`testing/gtest/include/gtest/gtest.h`:** This confirms it's using the Google Test framework for unit testing. We know to look for `TEST_F` macros.
* **Various `renderer/core/css/...` headers:** These indicate interaction with the CSS Object Model (CSSOM) and specific CSS value types (e.g., `CSSUnitValue`, `CSSKeywordValue`, `CSSUnparsedValue`). This is a strong signal that the class handles CSS properties.
* **`renderer/core/dom/element.h`:** This means the tests will involve manipulating DOM elements and their styles.
* **`renderer/platform/...` headers:**  These suggest interactions with lower-level Blink platform features, particularly threading (`NonMainThread`, `PostCrossThreadTask`). This hints that the `PaintWorkletStylePropertyMap` might be involved in cross-thread communication.

**3. Analyzing the Test Fixture (`PaintWorkletStylePropertyMapTest`):**

This class sets up the testing environment:

* **`PageTestBase`:** Inheriting from this likely provides a basic browser environment for running tests.
* **`SetUp()`:** This is standard Google Test setup, implying initialization of the test environment.
* **`PageNode()`:** A helper function to get the document element, indicating DOM manipulation.
* **`ShutDown()` and `ShutDownThread()`:**  These functions, along with the `thread_` member, strongly suggest testing asynchronous or cross-thread behavior. The use of `WaitableEvent` confirms synchronization.
* **`CheckUnregisteredProperty()` and `CheckCrossThreadData()`:**  These are specific test helper functions. Their names clearly indicate what they are testing: handling unregistered custom properties and verifying cross-thread data transfer.

**4. Examining Individual Tests (`TEST_F` blocks):**

Each `TEST_F` block represents a specific test case:

* **`UnregisteredCustomProperty`:**
    * Sets up a custom property without explicit registration.
    * Applies a style with this unregistered property to a DOM element.
    * Uses `PaintWorkletStylePropertyMap::BuildCrossThreadData` to create data for a Paint Worklet.
    * Sends this data to a separate thread.
    * The `CheckUnregisteredProperty` function asserts that the property is treated as an `CSSUnparsedValue` with the correct string value.
* **`SupportedCrossThreadData`:**
    * Registers several custom properties with specific syntax definitions.
    * Applies styles using these registered properties.
    * Creates cross-thread data.
    * The `CheckCrossThreadData` function verifies that the data is correctly serialized and contains the expected CSS value types (`CSSUnitValue`, `CSSKeywordValue`, `CSSUnsupportedColor`).
* **`UnsupportedCrossThreadData`:**
    * Tests scenarios where cross-thread data creation might fail.
    * Includes cases with unsupported CSS value types (`<url>`) and native properties that might not be transferable.
    * Asserts that `BuildCrossThreadData` returns an empty optional (`!data.has_value()`).

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Based on the code, we can make the following connections:

* **CSS Custom Properties (Variables):** The tests heavily feature `--*` properties, clearly linking to CSS Custom Properties (CSS Variables).
* **CSS Paint API (Paint Worklets):** The class name `PaintWorkletStylePropertyMap` and the use of `CSSPaintWorkletInput` directly connect to the CSS Paint API. This API allows JavaScript to define custom image rendering logic.
* **HTML Styling:** The tests manipulate the `style` attribute of HTML elements, demonstrating how these properties are applied.
* **JavaScript Interaction (Implicit):** While there's no explicit JavaScript code in the *test file*, the very existence of Paint Worklets implies that JavaScript would be used to register and invoke these worklets. The `CSSPaintWorkletInput` likely represents data passed from the main thread (where JavaScript executes) to the worklet running on a separate thread.

**6. Logical Reasoning and Assumptions:**

* **Assumption:** The `BuildCrossThreadData` function is responsible for preparing style property data to be sent to a Paint Worklet running in a separate thread.
* **Assumption:** The `PaintWorkletStylePropertyMap` on the worker thread receives this data and provides an interface to access the style properties.
* **Reasoning:**  If a custom property is not registered, it's treated as a raw string (unparsed value). If it *is* registered, the system knows its type and can serialize it accordingly (e.g., as a `CSSUnitValue` for lengths). Certain complex types (like `url`) might not be serializable for cross-thread transfer.

**7. User and Programming Errors:**

* **Incorrect CSS Syntax:**  If a user writes invalid CSS for a custom property, the test with `UnregisteredCustomProperty` shows how it might be handled (as an unparsed string).
* **Using Unsupported CSS Value Types in Paint Worklets:** The `UnsupportedCrossThreadData` test highlights that not all CSS value types can be directly passed to a Paint Worklet. This would be a programming error when defining the input properties for a worklet.
* **Forgetting to Register Custom Properties:**  If a developer intends to use a custom property with a specific type in a Paint Worklet, they need to register it using `@property`. Forgetting this would lead to the property being treated as an unparsed string.

**8. Debugging Scenario:**

Imagine a developer is creating a Paint Worklet and expects a registered custom property (e.g., `--my-length: 10px`) to be available as a length value inside the worklet. However, within the worklet's `paint()` function, they see it as just the string "10px".

* **Possible Cause:** The custom property was not registered correctly (or at all).
* **Debugging Steps:**
    1. **Inspect the CSS:**  Check if the `@property` rule for `--my-length` exists in the stylesheet.
    2. **Check the `inputProperties`:** Verify that `--my-length` is included in the `inputProperties` array when registering the Paint Worklet.
    3. **Look at DevTools:** The browser's developer tools can often show computed styles and registered properties.
    4. **Consider Cross-Thread Issues:** If the data is being passed to a worklet, ensure the value is being correctly serialized. This test file provides insights into how Blink handles this serialization. Specifically, it tests scenarios where serialization might fail.

This thought process, moving from the general purpose of the file to the specifics of each test and then connecting it back to web technologies and potential errors, allows for a comprehensive understanding of the code's functionality.
这个文件 `paint_worklet_style_property_map_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `PaintWorkletStylePropertyMap` 类的功能。这个类在 CSS Paint API (也称为 CSS Custom Paint) 的上下文中扮演着重要的角色。

**功能概述：**

该测试文件的主要功能是验证 `PaintWorkletStylePropertyMap` 类在不同场景下，特别是与 CSS 自定义属性和跨线程数据传递相关的行为是否正确。 具体来说，它测试了以下方面：

1. **未注册的 CSS 自定义属性的处理:** 验证当 Paint Worklet 尝试访问一个未通过 `@property` 规则注册的自定义属性时，`PaintWorkletStylePropertyMap` 如何处理和返回该属性的值。
2. **跨线程数据传递的正确性:** 验证 `PaintWorkletStylePropertyMap` 能否正确地将 CSS 属性值（包括内置属性和自定义属性）序列化并传递到 Paint Worklet 运行的独立线程。 这包括测试不同类型的 CSS 值，例如长度单位、关键字、颜色等。
3. **不支持的 CSS 值的处理:** 验证当尝试传递不支持跨线程传递的 CSS 值类型时，`PaintWorkletStylePropertyMap` 的行为，例如 `url()`。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关系到 CSS Paint API，这是一个允许开发者使用 JavaScript 定义自定义图像渲染逻辑的 CSS 特性。

* **CSS:**
    * **自定义属性 (CSS Variables):**  测试中大量使用了以 `--` 开头的自定义属性，例如 `--x`, `--foo`, `--bar` 等。 这直接关联到 CSS 自定义属性的定义和使用。
    * **`@property` 规则:**  测试中使用了 `css_test_helpers::RegisterProperty` 来模拟使用 `@property` 规则注册自定义属性的行为。 `@property` 允许开发者定义自定义属性的语法、继承行为和初始值。
    * **Paint Worklet:**  `PaintWorkletStylePropertyMap` 是为 Paint Worklet 设计的，用于访问元素的样式属性。 Paint Worklet 通过 `registerPaint()` 方法在 JavaScript 中注册，然后在 CSS 中通过 `paint()` 函数调用。
* **JavaScript:**
    * **Paint Worklet API:** 虽然测试文件是 C++ 代码，但它测试的 `PaintWorkletStylePropertyMap` 类是 Paint Worklet API 的一部分，这个 API 主要通过 JavaScript 进行交互。 JavaScript 代码会注册 Paint Worklet，并在 CSS 中使用它。 当 Paint Worklet 的 `paint()` 方法被调用时，`PaintWorkletStylePropertyMap` 会被用来获取元素的样式属性。
* **HTML:**
    * **`style` 属性:** 测试中通过设置 HTML 元素的 `style` 属性来设置 CSS 属性的值，例如 `<div id='target' style='--x:50'></div>`。  这些样式属性的值会被 `PaintWorkletStylePropertyMap` 读取。

**举例说明：**

1. **未注册的 CSS 自定义属性:**
   * **HTML:** `<div id='target' style='--x:50'></div>`
   * **CSS (可能没有):**  没有 `@property --x { ... }` 这样的注册规则。
   * **JavaScript (Paint Worklet):**  在 Paint Worklet 的 `paint()` 方法中，尝试通过 `properties.get('--x')` 获取 `--x` 的值。
   * **C++ (测试):** `CheckUnregisteredProperty` 函数验证了在这种情况下，`PaintWorkletStylePropertyMap` 会将 `--x` 的值作为未解析的字符串 "50" 返回。
   * **假设输入:**  一个 HTML 元素，其 `style` 属性中包含一个未注册的自定义属性 `--x` 且值为 "50"。
   * **假设输出:** `PaintWorkletStylePropertyMap` 返回一个表示未解析值的对象，其字符串值为 "50"。

2. **跨线程数据传递:**
   * **HTML:** `<div id='target' style='--foo:10px; --bar:15; --gar:rgb(255, 0, 0)'></div>`
   * **CSS:**
     ```css
     @property --foo {
       syntax: '<length>';
       inherits: false;
       initial-value: 134px;
     }
     @property --bar {
       syntax: '<number>';
       inherits: false;
       initial-value: 42;
     }
     @property --loo {
       syntax: '*';
       inherits: false;
       initial-value: test;
     }
     @property --gar {
       syntax: '<color>';
       inherits: false;
       initial-value: rgb(0, 255, 0);
     }
     ```
   * **JavaScript (Paint Worklet):**  在 Paint Worklet 的 `paint()` 方法中，尝试通过 `properties.get('--foo')`, `properties.get('--bar')` 等获取这些属性的值。
   * **C++ (测试):** `CheckCrossThreadData` 函数验证了 `PaintWorkletStylePropertyMap` 能否将 `--foo` (长度值), `--bar` (数值), `--loo` (关键字), `--gar` (颜色值) 正确地传递到另一个线程，并且在另一个线程中可以正确地访问这些值及其类型。
   * **假设输入:** 一个 HTML 元素，其 `style` 属性中包含已注册的自定义属性 `--foo`, `--bar`, `--gar` 及其对应的值。
   * **假设输出:** 在另一个线程中，`PaintWorkletStylePropertyMap` 能够返回类型正确的 CSS 值对象，例如 `CSSUnitValue` 对象表示 `--foo` 的长度值，`CSSKeywordValue` 对象表示 `--loo` 的关键字值等。

3. **不支持的 CSS 值的处理:**
   * **HTML:** `<div id='target' style='--foo:url(https://crbug.com/); --bar:15;'></div>`
   * **CSS:**
     ```css
     @property --foo {
       syntax: '<url>';
       inherits: false;
       initial-value: url(https://google.com);
     }
     @property --bar {
       syntax: '<number>';
       inherits: false;
       initial-value: 42;
     }
     ```
   * **JavaScript (Paint Worklet):**  在 Paint Worklet 的 `paint()` 方法中，尝试访问 `--foo` 和 `--bar` 的值。
   * **C++ (测试):** `UnsupportedCrossThreadData` 函数验证了由于 `<url>` 类型的值不能直接跨线程传递，`PaintWorkletStylePropertyMap::BuildCrossThreadData` 会返回一个空的可选值 (`!data1.has_value()`)。
   * **假设输入:**  一个 HTML 元素，其 `style` 属性中包含一个已注册的自定义属性 `--foo`，其语法为 `<url>`。
   * **假设输出:**  尝试构建跨线程数据时失败，`BuildCrossThreadData` 返回空值。

**用户或编程常见的使用错误：**

1. **忘记注册自定义属性:**  用户在 CSS 中使用了自定义属性，但在使用前忘记通过 `@property` 规则进行注册。这会导致 Paint Worklet 接收到的值是未解析的字符串，而不是具有特定类型的 CSS 值。
   * **举例:** 用户在 CSS 中使用了 `--my-color: red;`，但在 JavaScript Paint Worklet 中，`properties.get('--my-color')` 返回的是字符串 "red"，而不是一个颜色对象。
2. **尝试在 Paint Worklet 中访问不支持的 CSS 值类型:** 用户尝试传递像 `url()` 这样的复杂类型到 Paint Worklet。由于这些类型可能包含对主线程资源的引用，直接跨线程传递会导致问题。
   * **举例:** 用户定义了一个自定义属性 `--my-image: url('image.png');`，并在 Paint Worklet 中尝试获取这个值。这可能会导致错误或不可预测的行为。
3. **拼写错误或大小写不匹配:**  在 CSS 中设置自定义属性或在 JavaScript 中访问时，拼写错误或大小写不匹配会导致属性无法被正确识别。
   * **举例:** CSS 中定义了 `--main-color: blue;`，但在 JavaScript 中尝试通过 `properties.get('--mainColor')` 访问（注意大小写差异）。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者在使用 CSS Paint API 时遇到了问题，Paint Worklet 无法正确获取或解析元素的样式属性。以下是可能的操作步骤和调试线索：

1. **编写 HTML 和 CSS:** 开发者创建一个 HTML 文件，并在 CSS 中定义了要使用 Paint Worklet 绘制的元素，以及相关的样式属性，包括自定义属性。
   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <style>
       #my-element {
         width: 100px;
         height: 100px;
         background-image: paint(myPainter);
         --my-custom-size: 50px;
       }
       @property --my-custom-size {
         syntax: '<length>';
         inherits: false;
         initial-value: 0px;
       }
     </style>
   </head>
   <body>
     <div id="my-element"></div>
     <script>
       CSS.paintWorklet.addModule('painter.js');
     </script>
   </body>
   </html>
   ```
2. **编写 Paint Worklet (JavaScript):** 开发者编写一个 JavaScript 文件 `painter.js`，其中定义了 `myPainter` Paint Worklet，并在 `paint()` 方法中尝试获取 `--my-custom-size` 的值。
   ```javascript
   class MyPainter {
     static get inputProperties() { return ['--my-custom-size']; }
     paint(ctx, geom, properties) {
       const size = properties.get('--my-custom-size').value; // 或者 properties.get('--my-custom-size').toString()
       console.log(size);
       // ... 使用 size 进行绘制 ...
     }
   }
   registerPaint('myPainter', MyPainter);
   ```
3. **遇到问题并开始调试:** 开发者发现 `console.log(size)` 输出的结果不是预期的数值（例如 50），或者类型不对。
4. **检查 CSS 注册:** 开发者会首先检查是否正确地通过 `@property` 注册了自定义属性 `--my-custom-size`，以及 `syntax` 是否正确。
5. **检查 `inputProperties`:** 开发者会检查 Paint Worklet 的 `inputProperties` 静态 getter 是否包含了需要访问的自定义属性。
6. **查看浏览器开发者工具:** 开发者会打开浏览器的开发者工具，查看元素的计算样式，确认 `--my-custom-size` 的值是否正确设置。
7. **搜索相关错误和文档:** 开发者可能会搜索关于 Paint Worklet 和自定义属性的错误信息或文档，了解到 `PaintWorkletStylePropertyMap` 的作用以及跨线程数据传递的限制。
8. **查看 Blink 源代码 (可能):**  如果开发者对 Blink 引擎的内部机制感兴趣，或者遇到非常奇怪的问题，可能会查阅 Blink 的源代码，例如 `paint_worklet_style_property_map_test.cc`，以了解 `PaintWorkletStylePropertyMap` 的具体实现和测试用例，从而找到问题的原因或验证其假设。 这个测试文件可以帮助开发者理解 Blink 引擎是如何处理不同类型的 CSS 属性值以及跨线程传递的。

总而言之，`paint_worklet_style_property_map_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎中处理 Paint Worklet 样式属性的核心组件 `PaintWorkletStylePropertyMap` 的功能正确可靠。它涵盖了自定义属性、跨线程通信以及对不支持类型的处理等关键方面，为开发者使用 CSS Paint API 提供了保障。

### 提示词
```
这是目录为blink/renderer/core/css/cssom/paint_worklet_style_property_map_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/cssom/paint_worklet_style_property_map.h"

#include <memory>
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/cssom/css_keyword_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_paint_worklet_input.h"
#include "third_party/blink/renderer/core/css/cssom/css_unit_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_unparsed_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_unsupported_color.h"
#include "third_party/blink/renderer/core/css/properties/longhands/custom_property.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

class PaintWorkletStylePropertyMapTest : public PageTestBase {
 public:
  PaintWorkletStylePropertyMapTest() = default;

  void SetUp() override { PageTestBase::SetUp(gfx::Size()); }

  Node* PageNode() { return GetDocument().documentElement(); }

  void ShutDown(base::WaitableEvent* waitable_event) {
    DCHECK(!IsMainThread());
    waitable_event->Signal();
  }

  void ShutDownThread() {
    base::WaitableEvent waitable_event;
    PostCrossThreadTask(
        *thread_->GetTaskRunner(), FROM_HERE,
        CrossThreadBindOnce(&PaintWorkletStylePropertyMapTest::ShutDown,
                            CrossThreadUnretained(this),
                            CrossThreadUnretained(&waitable_event)));
    waitable_event.Wait();
  }

  void CheckUnregisteredProperty(base::WaitableEvent* waitable_event,
                                 scoped_refptr<CSSPaintWorkletInput> input) {
    ASSERT_TRUE(!IsMainThread());

    PaintWorkletStylePropertyMap* map =
        MakeGarbageCollected<PaintWorkletStylePropertyMap>(
            input->StyleMapData());
    ASSERT_TRUE(map);

    const PaintWorkletStylePropertyMap::CrossThreadData& data =
        map->StyleMapDataForTest();
    EXPECT_EQ(data.size(), 1u);
    EXPECT_EQ(data.at("--x")->GetType(),
              CrossThreadStyleValue::StyleValueType::kUnparsedType);
    CSSStyleValue* style_value = data.at("--x")->ToCSSStyleValue();
    EXPECT_EQ(style_value->GetType(),
              CSSStyleValue::StyleValueType::kUnparsedType);
    EXPECT_EQ(static_cast<CSSUnparsedValue*>(style_value)->ToUnparsedString(),
              "50");
    waitable_event->Signal();
  }

  void CheckCrossThreadData(base::WaitableEvent* waitable_event,
                            scoped_refptr<CSSPaintWorkletInput> input) {
    DCHECK(!IsMainThread());

    PaintWorkletStylePropertyMap* map =
        MakeGarbageCollected<PaintWorkletStylePropertyMap>(
            input->StyleMapData());
    DCHECK(map);

    const PaintWorkletStylePropertyMap::CrossThreadData& data =
        map->StyleMapDataForTest();
    EXPECT_EQ(data.size(), 5u);
    EXPECT_EQ(data.at("--foo")->ToCSSStyleValue()->GetType(),
              CSSStyleValue::StyleValueType::kUnitType);
    EXPECT_EQ(To<CSSUnitValue>(data.at("--foo")->ToCSSStyleValue())->value(),
              10);
    EXPECT_EQ(To<CSSUnitValue>(data.at("--foo")->ToCSSStyleValue())->unit(),
              "px");
    EXPECT_EQ(data.at("--bar")->ToCSSStyleValue()->GetType(),
              CSSStyleValue::StyleValueType::kUnitType);
    EXPECT_EQ(To<CSSUnitValue>(data.at("--bar")->ToCSSStyleValue())->value(),
              15);
    EXPECT_EQ(data.at("--loo")->ToCSSStyleValue()->GetType(),
              CSSStyleValue::StyleValueType::kKeywordType);
    EXPECT_EQ(To<CSSKeywordValue>(data.at("--loo")->ToCSSStyleValue())->value(),
              "test");
    EXPECT_EQ(data.at("--gar")->ToCSSStyleValue()->GetType(),
              CSSStyleValue::StyleValueType::kUnsupportedColorType);
    EXPECT_EQ(
        To<CSSUnsupportedColor>(data.at("--gar")->ToCSSStyleValue())->Value(),
        Color(255, 0, 0));
    EXPECT_EQ(data.at("display")->ToCSSStyleValue()->GetType(),
              CSSStyleValue::StyleValueType::kKeywordType);
    waitable_event->Signal();
  }

 protected:
  std::unique_ptr<blink::NonMainThread> thread_;
};

TEST_F(PaintWorkletStylePropertyMapTest, UnregisteredCustomProperty) {
  CustomProperty property(AtomicString("--x"), GetDocument());
  Vector<CSSPropertyID> native_properties;
  Vector<AtomicString> custom_properties({AtomicString("--x")});

  GetDocument().documentElement()->setInnerHTML(
      "<div id='target' style='--x:50'></div>");
  UpdateAllLifecyclePhasesForTest();

  Element* node = GetDocument().getElementById(AtomicString("target"));
  node->GetLayoutObject()->GetMutableForPainting().EnsureId();
  CompositorPaintWorkletInput::PropertyKeys input_property_keys;
  auto data = PaintWorkletStylePropertyMap::BuildCrossThreadData(
      GetDocument(), node->GetLayoutObject()->UniqueId(),
      node->ComputedStyleRef(), native_properties, custom_properties,
      input_property_keys);
  EXPECT_TRUE(data.has_value());

  Vector<std::unique_ptr<CrossThreadStyleValue>> input_arguments;
  std::vector<cc::PaintWorkletInput::PropertyKey> property_keys;
  scoped_refptr<CSSPaintWorkletInput> input =
      base::MakeRefCounted<CSSPaintWorkletInput>(
          "test", gfx::SizeF(100, 100), 1.0f, 1, std::move(data.value()),
          std::move(input_arguments), std::move(property_keys));
  ASSERT_TRUE(input);

  thread_ = blink::NonMainThread::CreateThread(
      ThreadCreationParams(ThreadType::kTestThread).SetSupportsGC(true));
  base::WaitableEvent waitable_event;
  PostCrossThreadTask(
      *thread_->GetTaskRunner(), FROM_HERE,
      CrossThreadBindOnce(
          &PaintWorkletStylePropertyMapTest::CheckUnregisteredProperty,
          CrossThreadUnretained(this), CrossThreadUnretained(&waitable_event),
          std::move(input)));
  waitable_event.Wait();

  ShutDownThread();
}

TEST_F(PaintWorkletStylePropertyMapTest, SupportedCrossThreadData) {
  Vector<CSSPropertyID> native_properties({CSSPropertyID::kDisplay});
  Vector<AtomicString> custom_properties(
      {AtomicString("--foo"), AtomicString("--bar"), AtomicString("--loo"),
       AtomicString("--gar")});
  css_test_helpers::RegisterProperty(GetDocument(), "--foo", "<length>",
                                     "134px", false);
  css_test_helpers::RegisterProperty(GetDocument(), "--bar", "<number>", "42",
                                     false);
  css_test_helpers::RegisterProperty(GetDocument(), "--loo", "test", "test",
                                     false);
  css_test_helpers::RegisterProperty(GetDocument(), "--gar", "<color>",
                                     "rgb(0, 255, 0)", false);

  GetDocument().documentElement()->setInnerHTML(
      "<div id='target' style='--foo:10px; --bar:15; --gar:rgb(255, 0, "
      "0)'></div>");
  UpdateAllLifecyclePhasesForTest();

  Element* node = GetDocument().getElementById(AtomicString("target"));
  node->GetLayoutObject()->GetMutableForPainting().EnsureId();
  Vector<std::unique_ptr<CrossThreadStyleValue>> input_arguments;
  CompositorPaintWorkletInput::PropertyKeys input_property_keys;
  auto data = PaintWorkletStylePropertyMap::BuildCrossThreadData(
      GetDocument(), node->GetLayoutObject()->UniqueId(),
      node->ComputedStyleRef(), native_properties, custom_properties,
      input_property_keys);

  EXPECT_TRUE(data.has_value());
  std::vector<cc::PaintWorkletInput::PropertyKey> property_keys;
  scoped_refptr<CSSPaintWorkletInput> input =
      base::MakeRefCounted<CSSPaintWorkletInput>(
          "test", gfx::SizeF(100, 100), 1.0f, 1, std::move(data.value()),
          std::move(input_arguments), std::move(property_keys));
  DCHECK(input);

  thread_ = blink::NonMainThread::CreateThread(
      ThreadCreationParams(ThreadType::kTestThread).SetSupportsGC(true));
  base::WaitableEvent waitable_event;
  PostCrossThreadTask(
      *thread_->GetTaskRunner(), FROM_HERE,
      CrossThreadBindOnce(
          &PaintWorkletStylePropertyMapTest::CheckCrossThreadData,
          CrossThreadUnretained(this), CrossThreadUnretained(&waitable_event),
          std::move(input)));
  waitable_event.Wait();

  ShutDownThread();
}

TEST_F(PaintWorkletStylePropertyMapTest, UnsupportedCrossThreadData) {
  Vector<CSSPropertyID> native_properties1;
  Vector<AtomicString> custom_properties1(
      {AtomicString("--foo"), AtomicString("--bar"), AtomicString("--loo")});
  css_test_helpers::RegisterProperty(GetDocument(), "--foo", "<url>",
                                     "url(https://google.com)", false);
  css_test_helpers::RegisterProperty(GetDocument(), "--bar", "<number>", "42",
                                     false);
  css_test_helpers::RegisterProperty(GetDocument(), "--loo", "test", "test",
                                     false);

  GetDocument().documentElement()->setInnerHTML(
      "<div id='target' style='--foo:url(https://crbug.com/); "
      "--bar:15;'></div>");
  UpdateAllLifecyclePhasesForTest();

  Element* node = GetDocument().getElementById(AtomicString("target"));
  node->GetLayoutObject()->GetMutableForPainting().EnsureId();

  Vector<std::unique_ptr<CrossThreadStyleValue>> input_arguments;
  CompositorPaintWorkletInput::PropertyKeys input_property_keys;
  auto data1 = PaintWorkletStylePropertyMap::BuildCrossThreadData(
      GetDocument(), node->GetLayoutObject()->UniqueId(),
      node->ComputedStyleRef(), native_properties1, custom_properties1,
      input_property_keys);

  EXPECT_FALSE(data1.has_value());

  Vector<CSSPropertyID> native_properties2(
      {CSSPropertyID::kDisplay, CSSPropertyID::kColor});
  Vector<AtomicString> custom_properties2;

  auto data2 = PaintWorkletStylePropertyMap::BuildCrossThreadData(
      GetDocument(), node->GetLayoutObject()->UniqueId(),
      node->ComputedStyleRef(), native_properties2, custom_properties2,
      input_property_keys);

  EXPECT_FALSE(data2.has_value());
}

}  // namespace blink
```