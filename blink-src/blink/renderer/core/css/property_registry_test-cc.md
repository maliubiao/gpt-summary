Response:
Let's break down the thought process for analyzing the `property_registry_test.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of the test file and its relationship to CSS properties in the Blink rendering engine. This involves identifying what aspects of the `PropertyRegistry` are being tested.

2. **Initial Scan for Keywords:** Quickly scan the file for keywords and common testing patterns. Keywords like `TEST_F`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `RegisterProperty`, `DeclareProperty`, `AllRegistrations`, etc., immediately indicate this is a unit test file. The class name `PropertyRegistryTest` and the inclusion of `property_registry.h` strongly suggest the focus is on testing the `PropertyRegistry` class.

3. **Identify the Class Under Test:** The core of the file is testing the `PropertyRegistry` class. The setup uses `PageTestBase`, providing a simulated browser environment. The `Registry()` method provides access to the `PropertyRegistry` instance associated with the document.

4. **Analyze Helper Functions:**  The `PropertyRegistryTest` class has several helper functions. Understanding these is crucial:
    * `Registry()`: Accesses the `PropertyRegistry`.
    * `Registration(const char* name)`: Retrieves a `PropertyRegistration` by name. This hints at how properties are stored and accessed.
    * `MaybeParseInitialValue()`: Parses CSS values, suggesting interaction with the CSS parsing system.
    * `RegisterProperty()`: Registers a property, hinting at a mechanism for making custom properties available. The default syntax and initial value are important details.
    * `DeclareProperty()`: Declares a property, potentially before it's fully registered. This suggests a two-stage process or different ways of defining properties.
    * `AllRegistrations()`:  Returns a collection of registered properties, useful for testing enumeration.

5. **Examine Individual Tests:**  Go through each `TEST_F` function and decipher its purpose:
    * `EnsurePropertyRegistry`: Checks if the registry is created and accessed correctly.
    * `RegisterProperty`, `DeclareProperty`: Basic tests for registering and declaring.
    * `DeclareThenRegisterProperty`, `RegisterThenDeclareProperty`: Tests the order of declaration and registration.
    * `RegisterAndDeclarePropertyNonOverlapping`: Checks handling of different properties.
    * `DeclareTwice`: Tests redeclaration.
    * `IsInRegisteredPropertySet`: Checks if a property is in the registered set.
    * `EmptyIterator`, `IterateSingleRegistration`, etc.: Tests the iteration over registered properties. These tests cover various scenarios of adding and removing properties.
    * `IsEmptyUntilRegisterProperty`, `IsEmptyUntilDeclareProperty`: Tests when the registry is considered empty.
    * `Version`: Tests a version counter that increments with registration/declaration changes.
    * `RemoveDeclaredProperties`: Tests the removal of declared properties.
    * `MarkReferencedRegisterProperty`, `MarkReferencedAtProperty`: Tests how properties are marked as referenced when used in CSS rules (including `@property`). This links to actual CSS parsing and usage.
    * `GetViewportUnitFlagsRegistered`, `GetViewportUnitFlagsDeclared`, `GetViewportUnitFlagsRegistry`: Tests the extraction of viewport unit information (`vh`, `svh`, `lvh`, `dvh`) from property definitions. This is a more specific feature related to responsive design.

6. **Identify Relationships to Web Technologies (HTML, CSS, JavaScript):**
    * **CSS:** The file heavily revolves around CSS properties, especially custom properties (CSS variables). The parsing of syntax and initial values directly relates to CSS syntax. The `@property` rule is explicitly tested.
    * **HTML:** The tests use `GetDocument().documentElement()->setInnerHTML(...)` to inject HTML and CSS, simulating a web page. This shows how the property registry interacts with the DOM. The example of using `var(--x)` in a style demonstrates the connection.
    * **JavaScript:** While this specific test file doesn't directly execute JavaScript, the functionality it tests is crucial for JavaScript's interaction with CSS. JavaScript can read and set CSS variables, and this registry is where those variables are managed within the rendering engine.

7. **Infer Functionality:** Based on the tests, deduce the core responsibilities of the `PropertyRegistry`:
    * Stores and manages CSS custom properties.
    * Differentiates between declaring and registering properties (potentially for different stages of processing).
    * Provides a way to check if a property is registered.
    * Allows iterating over registered properties.
    * Tracks a version number for changes.
    * Can remove declared properties.
    * Tracks whether a property has been referenced in the stylesheet.
    * Extracts information about viewport units used in property definitions.

8. **Consider Error Scenarios and User Mistakes:**  Think about how developers might misuse custom properties and how the `PropertyRegistry` handles those situations. For example:
    * Declaring the same property multiple times.
    * Registering a property after declaring it.
    * Referencing a property that hasn't been declared or registered. (While this test doesn't *directly* test this failure, it sets up the groundwork for how such scenarios would be handled elsewhere in the engine).

9. **Trace User Actions:** Imagine the steps a user takes that lead to this code being executed. The process starts with writing HTML and CSS, including custom properties. The browser parses this code, and the `PropertyRegistry` is involved in managing the defined properties. Debugging scenarios might involve inspecting the registry's contents to understand why a custom property isn't working as expected.

10. **Structure the Answer:** Organize the findings into logical sections like "Functionality," "Relationship to Web Technologies," "Logic and Assumptions," "Common Errors," and "Debugging." Provide specific examples and code snippets where possible to illustrate the points.

By following these steps, we can systematically analyze the code and generate a comprehensive explanation of its purpose and implications. The key is to move from the specific details of the tests to the broader context of how the `PropertyRegistry` fits into the Blink rendering engine and web development.
这个文件 `property_registry_test.cc` 是 Chromium Blink 引擎中用于测试 `PropertyRegistry` 类的单元测试文件。`PropertyRegistry` 负责管理 CSS 自定义属性（也称为 CSS 变量）的注册和声明。

**功能:**

该文件的主要功能是验证 `PropertyRegistry` 类的各种方法和行为是否符合预期。它通过一系列的测试用例来覆盖以下方面：

1. **创建和获取 PropertyRegistry 实例:**
   - 测试 `EnsurePropertyRegistry()` 方法是否能正确地创建和返回文档关联的 `PropertyRegistry` 实例。

2. **注册属性 (`RegisterProperty`)：**
   - 测试 `RegisterProperty()` 方法是否能成功地注册一个新的 CSS 自定义属性。
   - 验证注册后可以通过属性名获取到注册信息。

3. **声明属性 (`DeclareProperty`)：**
   - 测试 `DeclareProperty()` 方法是否能成功地声明一个新的 CSS 自定义属性。
   - 验证声明后可以通过属性名获取到声明信息。

4. **注册和声明的顺序和冲突处理：**
   - 测试先声明后注册，以及先注册后声明的情况，验证 `PropertyRegistry` 如何处理这些场景。
   - 测试注册和声明相同属性名的情况，以及注册和声明不同属性名的情况。

5. **多次声明：**
   - 测试多次声明同一个属性名，验证 `PropertyRegistry` 的行为。

6. **判断属性是否已注册 (`IsInRegisteredPropertySet`)：**
   - 测试 `IsInRegisteredPropertySet()` 方法是否能正确判断一个属性是否已经被注册。

7. **迭代已注册的属性：**
   - 测试迭代器功能，验证可以遍历所有已注册的属性。
   - 涵盖了注册和声明的不同组合情况下迭代器的行为。
   - 测试完全重叠的注册和声明情况下的迭代器行为。

8. **判断 PropertyRegistry 是否为空 (`IsEmpty`)：**
   - 测试在注册或声明属性之前和之后，`IsEmpty()` 方法的返回值是否正确。

9. **版本号 (`Version`)：**
   - 测试每次注册或声明属性时，`PropertyRegistry` 的版本号是否会递增。
   - 测试 `RemoveDeclaredProperties()` 方法调用后版本号是否会递增。

10. **移除声明的属性 (`RemoveDeclaredProperties`)：**
   - 测试 `RemoveDeclaredProperties()` 方法是否能正确地移除所有已声明的属性，而保留已注册的属性。

11. **标记属性被引用 (`MarkReferenced`)：**
   - 测试当 CSS 样式中使用了自定义属性（通过 `var()` 函数）时，`PropertyRegistry` 能否正确地标记该属性已被引用。
   - 测试通过 `@property` 规则声明的自定义属性是否也会被标记为引用。
   - 验证即使通过 `RegisterProperty` 覆盖了 `@property` 声明，引用状态依然保持。

12. **获取视口单位标志 (`GetViewportUnitFlags`)：**
   - 测试在注册和声明属性时，如果初始值中包含视口单位（如 `vh`, `svh`, `lvh`, `dvh`），`PropertyRegistry` 能否正确地提取出相应的标志。
   - 测试在 `PropertyRegistry` 层面获取所有已注册/声明属性的视口单位标志的聚合结果。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

`PropertyRegistry` 直接关联着 CSS 的自定义属性功能。

* **CSS:**  该测试文件模拟了 CSS 自定义属性的注册和声明过程，这与 CSS `@property` 规则以及 JavaScript 操作 CSS 变量密切相关。
    * **例子 (CSS @property):**
      ```css
      @property --my-color {
        syntax: '<color>';
        inherits: false;
        initial-value: red;
      }

      div {
        background-color: var(--my-color);
      }
      ```
      `DeclareProperty` 方法模拟了 `@property` 规则的效果，允许开发者定义自定义属性的语法、继承性和初始值。测试用例 `MarkReferencedAtProperty` 就验证了这种情况。

    * **例子 (CSS var()):**
      ```css
      :root {
        --main-bg-color: blue;
      }

      body {
        background-color: var(--main-bg-color);
      }
      ```
      `RegisterProperty` 方法可以模拟通过其他方式（例如，Blink 内部或扩展）注册的自定义属性。测试用例 `MarkReferencedRegisterProperty` 验证了当 CSS 中使用 `var()` 引用已注册的属性时，该属性会被标记为引用。

* **JavaScript:** JavaScript 可以通过 DOM API (`element.style.setProperty('--my-var', 'value')` 和 `getComputedStyle(element).getPropertyValue('--my-var')`) 来读写 CSS 自定义属性。`PropertyRegistry` 负责管理这些属性的元数据，以便 Blink 引擎正确地处理它们。虽然此测试文件不直接测试 JavaScript 代码，但它测试的底层机制支持 JavaScript 与 CSS 变量的交互。

* **HTML:** HTML 结构提供了 CSS 应用的上下文。测试用例中会创建简单的 HTML 结构来应用 CSS 样式，从而触发对自定义属性的引用，例如：
    ```html
    <div style="--my-font-size: 16px;">Hello</div>
    ```
    或者通过 `<style>` 标签引入 CSS 规则。

**逻辑推理及假设输入与输出:**

以 `TEST_F(PropertyRegistryTest, DeclareThenRegisterProperty)` 为例：

* **假设输入:**
    1. 调用 `DeclareProperty("--x")` 声明一个名为 `--x` 的属性。
    2. 调用 `RegisterProperty("--x")` 注册一个名为 `--x` 的属性。

* **逻辑推理:**  `PropertyRegistry` 应该能够处理先声明后注册的情况，并且最终注册的属性信息应该能被获取到。

* **预期输出:**
    1. `DeclareProperty("--x")` 返回的 `PropertyRegistration` 指针应该与 `Registration("--x")` 返回的指针相同。
    2. `RegisterProperty("--x")` 返回的 `PropertyRegistration` 指针应该与 `Registration("--x")` 返回的指针相同。
    3. 在此测试用例中，由于后注册会覆盖先声明，最终 `Registration("--x")` 返回的指针应该指向注册时的 `PropertyRegistration` 对象。

**用户或编程常见的使用错误及举例说明:**

1. **在 CSS 中引用未声明或未注册的自定义属性:**
   - **错误示例 (CSS):**
     ```css
     div {
       color: var(--undefined-color); /* --undefined-color 未声明或注册 */
     }
     ```
   - `PropertyRegistry` 的测试覆盖了注册和声明的机制，确保了在引用属性之前，引擎能够正确地管理这些属性的状态。如果用户犯了这个错误，浏览器会使用自定义属性的默认回退值（如果提供了），或者使用继承值/初始值。

2. **多次声明同名的自定义属性，期望所有声明都生效:**
   - **错误示例 (JavaScript 或 CSS):**  多次使用 `@property --my-var { ... }` 或者多次调用 `DeclareProperty("--my-var")`。
   - `PropertyRegistry` 的测试（例如 `DeclareTwice`）表明后声明会覆盖之前的声明。用户可能会误以为所有的声明都会合并或累积效果，但实际上只有一个声明会生效。

3. **注册和声明的语法、初始值不一致，导致难以预测的结果:**
   - 虽然测试中可以模拟这种情况，但实际开发中，用户可能会在 `@property` 声明和后续的注册（如果存在）中使用不同的语法或初始值。`PropertyRegistry` 的行为是后注册会覆盖先声明，理解这一点对于避免混淆很重要。

**用户操作如何一步步到达这里 (作为调试线索):**

当开发者在编写和调试涉及到 CSS 自定义属性的代码时，可能会触发与 `PropertyRegistry` 相关的代码执行。以下是一些步骤：

1. **编写 HTML 文件:** 用户创建一个 HTML 文件，其中包含使用自定义属性的 CSS 样式。
   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <style>
       :root {
         --main-text-color: #333;
       }
       body {
         color: var(--main-text-color);
       }
     </style>
   </head>
   <body>
     <p>Hello World!</p>
   </body>
   </html>
   ```

2. **浏览器加载和解析 HTML:** 当浏览器加载这个 HTML 文件时，Blink 渲染引擎开始解析 HTML 和 CSS。

3. **解析 CSS:**  在解析 CSS 过程中，当遇到自定义属性的声明（例如 `:root { --main-text-color: ... }`）或 `@property` 规则时，相关的处理逻辑会与 `PropertyRegistry` 交互。`DeclareProperty` 方法可能会被调用来记录属性的声明信息。

4. **应用样式:** 当浏览器需要计算元素的最终样式时，如果遇到 `var()` 函数，会查询 `PropertyRegistry` 来获取自定义属性的值。`Registration` 方法会被调用来查找已注册或声明的属性。

5. **使用 JavaScript 操作 CSS 变量:** 如果 JavaScript 代码修改了 CSS 变量的值，例如：
   ```javascript
   document.documentElement.style.setProperty('--main-text-color', 'blue');
   ```
   这也会涉及到 `PropertyRegistry`，可能触发属性值的更新和样式的重新计算。

6. **调试自定义属性问题:** 当开发者发现自定义属性没有按预期工作时，他们可能会使用浏览器的开发者工具来检查元素的计算样式，查看自定义属性的值是否正确。在 Blink 内部调试时，开发人员可能会断点在 `PropertyRegistry` 的相关方法上，例如 `Registration` 或 `WasReferenced`，来追踪属性的注册、声明和引用情况，从而找到问题的原因。例如，如果一个自定义属性没有生效，可能是因为没有被正确注册或声明，或者在 CSS 中引用时的名称拼写错误。

因此，`property_registry_test.cc` 文件中的测试用例覆盖了这些核心场景，确保了 `PropertyRegistry` 在处理各种用户可能创建的 CSS 自定义属性时能够正确运行。通过这些测试，可以验证 Blink 引擎对 CSS 变量的支持是否符合规范，并且能够稳定可靠地工作。

Prompt: 
```
这是目录为blink/renderer/core/css/property_registry_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class PropertyRegistryTest : public PageTestBase {
 public:
  PropertyRegistry& Registry() {
    return GetDocument().EnsurePropertyRegistry();
  }

  const PropertyRegistration* Registration(const char* name) {
    return Registry().Registration(AtomicString(name));
  }

  const CSSValue* MaybeParseInitialValue(String syntax, String value) {
    if (value.IsNull()) {
      DCHECK_EQ(syntax, "*");
      return nullptr;
    }
    return css_test_helpers::ParseValue(GetDocument(), syntax, value);
  }

  const PropertyRegistration* RegisterProperty(
      const char* name,
      String syntax = "*",
      String initial_value = g_null_atom) {
    auto* registration = css_test_helpers::CreatePropertyRegistration(
        name, syntax, MaybeParseInitialValue(syntax, initial_value));
    Registry().RegisterProperty(AtomicString(name), *registration);
    return registration;
  }

  const PropertyRegistration* DeclareProperty(
      const char* name,
      String syntax = "*",
      String initial_value = g_null_atom) {
    auto* registration = css_test_helpers::CreatePropertyRegistration(
        name, syntax, MaybeParseInitialValue(syntax, initial_value));
    Registry().DeclareProperty(AtomicString(name), *registration);
    return registration;
  }

  HeapVector<Member<const PropertyRegistration>> AllRegistrations() {
    HeapVector<Member<const PropertyRegistration>> vector;
    for (auto entry : Registry()) {
      vector.push_back(entry.value);
    }
    return vector;
  }
};

TEST_F(PropertyRegistryTest, EnsurePropertyRegistry) {
  EXPECT_FALSE(GetDocument().GetPropertyRegistry());
  PropertyRegistry* registry = &GetDocument().EnsurePropertyRegistry();
  EXPECT_EQ(registry, GetDocument().GetPropertyRegistry());
}

TEST_F(PropertyRegistryTest, RegisterProperty) {
  EXPECT_FALSE(Registration("--x"));

  auto* registered = RegisterProperty("--x");
  EXPECT_EQ(registered, Registration("--x"));
}

TEST_F(PropertyRegistryTest, DeclareProperty) {
  EXPECT_FALSE(Registration("--x"));

  auto* declared = DeclareProperty("--x");
  EXPECT_EQ(declared, Registration("--x"));
}

TEST_F(PropertyRegistryTest, DeclareThenRegisterProperty) {
  auto* declared = DeclareProperty("--x");
  EXPECT_EQ(declared, Registration("--x"));

  auto* registered = RegisterProperty("--x");
  EXPECT_EQ(registered, Registration("--x"));
}

TEST_F(PropertyRegistryTest, RegisterThenDeclareProperty) {
  auto* registered = RegisterProperty("--x");
  EXPECT_EQ(registered, Registration("--x"));

  DeclareProperty("--x");
  EXPECT_EQ(registered, Registration("--x"));
}

TEST_F(PropertyRegistryTest, RegisterAndDeclarePropertyNonOverlapping) {
  auto* registered = RegisterProperty("--x");
  EXPECT_EQ(registered, Registration("--x"));

  auto* declared = DeclareProperty("--y");
  EXPECT_EQ(declared, Registration("--y"));
  EXPECT_EQ(registered, Registration("--x"));
}

TEST_F(PropertyRegistryTest, DeclareTwice) {
  auto* declared1 = DeclareProperty("--x");
  EXPECT_EQ(declared1, Registration("--x"));

  auto* declared2 = DeclareProperty("--x");
  EXPECT_EQ(declared2, Registration("--x"));
}

TEST_F(PropertyRegistryTest, IsInRegisteredPropertySet) {
  AtomicString x_string("--x");
  AtomicString y_string("--y");
  EXPECT_FALSE(Registry().IsInRegisteredPropertySet(x_string));

  RegisterProperty("--x");
  EXPECT_TRUE(Registry().IsInRegisteredPropertySet(x_string));
  EXPECT_FALSE(Registry().IsInRegisteredPropertySet(y_string));

  DeclareProperty("--y");
  EXPECT_TRUE(Registry().IsInRegisteredPropertySet(x_string));
  EXPECT_FALSE(Registry().IsInRegisteredPropertySet(y_string));

  RegisterProperty("--y");
  EXPECT_TRUE(Registry().IsInRegisteredPropertySet(y_string));
}

TEST_F(PropertyRegistryTest, EmptyIterator) {
  EXPECT_EQ(0u, AllRegistrations().size());
}

TEST_F(PropertyRegistryTest, IterateSingleRegistration) {
  auto* reg1 = RegisterProperty("--x");
  auto registrations = AllRegistrations();
  EXPECT_EQ(1u, registrations.size());
  EXPECT_TRUE(registrations.Contains(reg1));
}

TEST_F(PropertyRegistryTest, IterateDoubleRegistration) {
  auto* reg1 = RegisterProperty("--x");
  auto* reg2 = RegisterProperty("--y");

  auto registrations = AllRegistrations();
  EXPECT_EQ(2u, registrations.size());
  EXPECT_TRUE(registrations.Contains(reg1));
  EXPECT_TRUE(registrations.Contains(reg2));
}

TEST_F(PropertyRegistryTest, IterateSingleDeclaration) {
  auto* reg1 = DeclareProperty("--x");
  auto registrations = AllRegistrations();
  EXPECT_EQ(1u, registrations.size());
  EXPECT_TRUE(registrations.Contains(reg1));
}

TEST_F(PropertyRegistryTest, IterateDoubleDeclaration) {
  auto* reg1 = DeclareProperty("--x");
  auto* reg2 = DeclareProperty("--y");

  auto registrations = AllRegistrations();
  EXPECT_EQ(2u, registrations.size());
  EXPECT_TRUE(registrations.Contains(reg1));
  EXPECT_TRUE(registrations.Contains(reg2));
}

TEST_F(PropertyRegistryTest, IterateRegistrationAndDeclaration) {
  auto* reg1 = RegisterProperty("--x");
  auto* reg2 = DeclareProperty("--y");

  auto registrations = AllRegistrations();
  EXPECT_EQ(2u, registrations.size());
  EXPECT_TRUE(registrations.Contains(reg1));
  EXPECT_TRUE(registrations.Contains(reg2));
}

TEST_F(PropertyRegistryTest, IterateRegistrationAndDeclarationConflict) {
  auto* reg1 = RegisterProperty("--x");
  auto* reg2 = RegisterProperty("--y");
  auto* reg3 = DeclareProperty("--y");
  auto* reg4 = DeclareProperty("--z");

  auto registrations = AllRegistrations();
  EXPECT_EQ(3u, registrations.size());
  EXPECT_TRUE(registrations.Contains(reg1));
  EXPECT_TRUE(registrations.Contains(reg2));
  EXPECT_FALSE(registrations.Contains(reg3));
  EXPECT_TRUE(registrations.Contains(reg4));
}

TEST_F(PropertyRegistryTest, IterateFullOverlapSingle) {
  auto* reg1 = DeclareProperty("--x");
  auto* reg2 = RegisterProperty("--x");

  auto registrations = AllRegistrations();
  EXPECT_EQ(1u, registrations.size());
  EXPECT_FALSE(registrations.Contains(reg1));
  EXPECT_TRUE(registrations.Contains(reg2));
}

TEST_F(PropertyRegistryTest, IterateFullOverlapMulti) {
  auto* reg1 = DeclareProperty("--x");
  auto* reg2 = DeclareProperty("--y");
  auto* reg3 = RegisterProperty("--x");
  auto* reg4 = RegisterProperty("--y");

  auto registrations = AllRegistrations();
  EXPECT_EQ(2u, registrations.size());
  EXPECT_FALSE(registrations.Contains(reg1));
  EXPECT_FALSE(registrations.Contains(reg2));
  EXPECT_TRUE(registrations.Contains(reg3));
  EXPECT_TRUE(registrations.Contains(reg4));
}

TEST_F(PropertyRegistryTest, IsEmptyUntilRegisterProperty) {
  EXPECT_TRUE(Registry().IsEmpty());
  RegisterProperty("--x");
  EXPECT_FALSE(Registry().IsEmpty());
}

TEST_F(PropertyRegistryTest, IsEmptyUntilDeclareProperty) {
  EXPECT_TRUE(Registry().IsEmpty());
  DeclareProperty("--x");
  EXPECT_FALSE(Registry().IsEmpty());
}

TEST_F(PropertyRegistryTest, Version) {
  EXPECT_EQ(0u, Registry().Version());

  RegisterProperty("--a");
  EXPECT_EQ(1u, Registry().Version());

  RegisterProperty("--b");
  EXPECT_EQ(2u, Registry().Version());

  DeclareProperty("--c");
  EXPECT_EQ(3u, Registry().Version());

  DeclareProperty("--c");
  EXPECT_EQ(4u, Registry().Version());

  DeclareProperty("--d");
  EXPECT_EQ(5u, Registry().Version());

  Registry().RemoveDeclaredProperties();
  EXPECT_EQ(6u, Registry().Version());

  Registry().RemoveDeclaredProperties();
  EXPECT_EQ(6u, Registry().Version());
}

TEST_F(PropertyRegistryTest, RemoveDeclaredProperties) {
  DeclareProperty("--a");
  DeclareProperty("--b");
  RegisterProperty("--c");
  RegisterProperty("--d");

  EXPECT_TRUE(Registration("--a"));
  EXPECT_TRUE(Registration("--b"));
  EXPECT_TRUE(Registration("--c"));
  EXPECT_TRUE(Registration("--d"));

  Registry().RemoveDeclaredProperties();

  EXPECT_FALSE(Registration("--a"));
  EXPECT_FALSE(Registration("--b"));
  EXPECT_TRUE(Registration("--c"));
  EXPECT_TRUE(Registration("--d"));
}

TEST_F(PropertyRegistryTest, MarkReferencedRegisterProperty) {
  css_test_helpers::RegisterProperty(GetDocument(), "--x", "<length>", "0px",
                                     false);

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(Registry().WasReferenced(AtomicString("--x")));

  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      :root {
        --x: 10px;
      }
      div {
        width: var(--x);
      }
    </style>
    <div id="div">Test</div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(Registry().WasReferenced(AtomicString("--x")));
}

TEST_F(PropertyRegistryTest, MarkReferencedAtProperty) {
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(Registry().WasReferenced(AtomicString("--x")));

  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      @property --x {
        syntax: "<length>";
        inherits: false;
        initial-value: 0px;
      }
      :root {
        --x: 10px;
      }
      div {
        width: var(--x);
      }
    </style>
    <div id="div">Test</div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(Registry().WasReferenced(AtomicString("--x")));

  css_test_helpers::RegisterProperty(GetDocument(), "--x", "<length>", "1px",
                                     false);

  // Check that the registration was successful, and did overwrite the
  // declaration.
  ASSERT_TRUE(Registration("--x"));
  ASSERT_TRUE(Registration("--x")->Initial());
  EXPECT_EQ("1px", Registration("--x")->Initial()->CssText());

  // --x should still be marked as referenced, even though RegisterProperty
  // now takes precedence over @property.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(Registry().WasReferenced(AtomicString("--x")));
}

TEST_F(PropertyRegistryTest, GetViewportUnitFlagsRegistered) {
  EXPECT_EQ(
      0u, RegisterProperty("--px", "<length>", "1px")->GetViewportUnitFlags());
  EXPECT_EQ(
      static_cast<unsigned>(ViewportUnitFlag::kStatic),
      RegisterProperty("--vh", "<length>", "1vh")->GetViewportUnitFlags());
  EXPECT_EQ(
      static_cast<unsigned>(ViewportUnitFlag::kStatic),
      RegisterProperty("--svh", "<length>", "1svh")->GetViewportUnitFlags());
  EXPECT_EQ(
      static_cast<unsigned>(ViewportUnitFlag::kStatic),
      RegisterProperty("--lvh", "<length>", "1lvh")->GetViewportUnitFlags());
  EXPECT_EQ(
      static_cast<unsigned>(ViewportUnitFlag::kDynamic),
      RegisterProperty("--dvh", "<length>", "1dvh")->GetViewportUnitFlags());
  EXPECT_EQ(static_cast<unsigned>(ViewportUnitFlag::kStatic) |
                static_cast<unsigned>(ViewportUnitFlag::kDynamic),
            RegisterProperty("--mixed", "<length>", "calc(1dvh + 1svh)")
                ->GetViewportUnitFlags());
}

TEST_F(PropertyRegistryTest, GetViewportUnitFlagsDeclared) {
  EXPECT_EQ(0u,
            DeclareProperty("--px", "<length>", "1px")->GetViewportUnitFlags());
  EXPECT_EQ(static_cast<unsigned>(ViewportUnitFlag::kStatic),
            DeclareProperty("--vh", "<length>", "1vh")->GetViewportUnitFlags());
  EXPECT_EQ(
      static_cast<unsigned>(ViewportUnitFlag::kStatic),
      DeclareProperty("--svh", "<length>", "1svh")->GetViewportUnitFlags());
  EXPECT_EQ(
      static_cast<unsigned>(ViewportUnitFlag::kStatic),
      DeclareProperty("--lvh", "<length>", "1lvh")->GetViewportUnitFlags());
  EXPECT_EQ(
      static_cast<unsigned>(ViewportUnitFlag::kDynamic),
      DeclareProperty("--dvh", "<length>", "1dvh")->GetViewportUnitFlags());
  EXPECT_EQ(static_cast<unsigned>(ViewportUnitFlag::kStatic) |
                static_cast<unsigned>(ViewportUnitFlag::kDynamic),
            DeclareProperty("--mixed", "<length>", "calc(1dvh + 1svh)")
                ->GetViewportUnitFlags());
}

TEST_F(PropertyRegistryTest, GetViewportUnitFlagsRegistry) {
  EXPECT_EQ(0u, Registry().GetViewportUnitFlags());

  RegisterProperty("--vh", "<length>", "1vh");
  EXPECT_EQ(static_cast<unsigned>(ViewportUnitFlag::kStatic),
            Registry().GetViewportUnitFlags());

  DeclareProperty("--dvh", "<length>", "1dvh");
  EXPECT_EQ(static_cast<unsigned>(ViewportUnitFlag::kStatic) |
                static_cast<unsigned>(ViewportUnitFlag::kDynamic),
            Registry().GetViewportUnitFlags());

  Registry().RemoveDeclaredProperties();
  EXPECT_EQ(static_cast<unsigned>(ViewportUnitFlag::kStatic),
            Registry().GetViewportUnitFlags());
}

}  // namespace blink

"""

```