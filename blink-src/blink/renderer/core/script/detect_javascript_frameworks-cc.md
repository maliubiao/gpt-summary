Response:
Let's break down the thought process for analyzing this code and generating the answer.

1. **Understand the Goal:** The primary goal is to understand what the `detect_javascript_frameworks.cc` file does within the Blink rendering engine. The prompt also requests details about its relation to web technologies (JavaScript, HTML, CSS), logic, common errors, and how execution reaches this code.

2. **High-Level Overview (Skimming the Code):**  A quick skim reveals keywords like "JavaScriptFrameworkDetectionResult", "JavaScriptFramework", and checks for specific variables and attributes. This strongly suggests the file's purpose is to identify JavaScript frameworks used on a webpage.

3. **Core Functionality - Focus on the `TraverseTreeForFrameworks` function:** This function seems to be the central logic. It iterates through elements in the DOM, checks attributes and properties, and then calls `CheckGlobalPropertyMatches` and `DetectFrameworkVersions`. This provides a good structure for describing the functionality.

4. **Detailed Analysis of Key Functions:**  Go through each significant function mentioned in `TraverseTreeForFrameworks`:
    * **`CheckAttributeMatches`:**  Looks for specific attributes like `data-reactroot`, `ng-version`, and class names starting with `svelte-`. This links directly to HTML attributes.
    * **`CheckPropertyMatches`:** Examines JavaScript object properties of DOM elements like `__vue__`, `_reactRootContainer`. This connects to how JavaScript frameworks attach data to DOM nodes.
    * **`CheckIdMatches`:** Checks for specific HTML element IDs.
    * **`CheckGlobalPropertyMatches`:** Looks for global JavaScript variables like `Vue`, `React`, `next`. This is a common way frameworks expose themselves.
    * **`DetectFrameworkVersions`:**  Attempts to extract version information from global variables or meta tags. This adds a layer of detail beyond just detection.

5. **Relating to Web Technologies:**
    * **JavaScript:** The entire purpose is to detect *JavaScript* frameworks. Examples include checking global variables and object properties which are core JavaScript concepts.
    * **HTML:**  It examines HTML attributes (`data-reactroot`, `ng-version`), IDs, and meta tags. This is direct interaction with the HTML structure.
    * **CSS:** While the code doesn't directly manipulate CSS, the detection might influence later rendering or behavior. The presence of a specific framework *might* imply certain CSS frameworks are also in use (though this isn't explicitly checked here). The class name check for Svelte is the closest direct link.

6. **Logic and Examples (Input/Output):** Think about specific scenarios:
    * **Input:** A simple HTML page with a `<div id="react-root"></div>`.
    * **Output:** Detection of React.
    * **Input:** A page with `<meta name="generator" content="WordPress 6.2">`.
    * **Output:** Detection of WordPress version 6.2.
    * **Input:** A page where a JavaScript sets `window.Vue = { version: '3.2.0' };`.
    * **Output:** Detection of Vue version 3.2.0.

7. **Common User/Programming Errors:** Consider how the detection might fail or be affected by errors:
    * **Framework not fully loaded:**  If the code runs before the framework initializes its global variables, detection might fail.
    * **Obfuscation/Customization:** If the framework's identifiers are changed, detection might be inaccurate.
    * **Error handling in the code:** Notice the use of `TryCatch` blocks, indicating potential exceptions when accessing JavaScript properties.

8. **Debugging Clues and User Operations:**  Think about how a developer might end up looking at this file:
    * **Performance issues:**  Framework detection might be a factor in page load time.
    * **Feature implementation:**  A new browser feature might depend on knowing the framework being used.
    * **Bug investigation:**  A rendering bug might be specific to a certain framework.
    * **User operations:**  The user simply browsing to a website triggers this code. The steps involve the browser requesting the page, parsing the HTML, executing JavaScript, and then the framework detection logic running.

9. **Structure and Refine:** Organize the information into clear sections as requested by the prompt. Use headings and bullet points for readability. Provide concise examples. Ensure the language is clear and avoids jargon where possible (or explains it).

10. **Review and Verify:** Read through the generated answer to ensure accuracy and completeness. Double-check the code snippets and explanations.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file also handles CSS framework detection. **Correction:**  The code focuses primarily on JavaScript and some HTML aspects related to framework identification. CSS isn't a primary focus.
* **Initial thought:** Focus heavily on the technical details of V8 APIs. **Correction:**  While mentioning V8 is necessary, the explanation should be understandable to someone with a general understanding of web development, not just Blink internals. Explain *what* the V8 calls are doing, not necessarily *how* at a low level.
* **Ensure connection to user actions:** Emphasize how typical user browsing leads to this code being executed. This provides context.

By following this structured approach and incorporating self-correction, we can generate a comprehensive and accurate answer to the prompt.
这个文件 `blink/renderer/core/script/detect_javascript_frameworks.cc` 的主要功能是**检测网页上正在使用的 JavaScript 框架及其版本**。

下面详细列举其功能，并结合 JavaScript, HTML, CSS 进行举例说明：

**核心功能:**

1. **识别 JavaScript 框架:**  通过多种方式来判断页面是否使用了特定的 JavaScript 框架。
    * **检测全局 JavaScript 变量:** 查找特定框架常用的全局变量。
    * **检测特定的 HTML 元素 ID:** 查找与框架相关的特定 ID 的 HTML 元素。
    * **检测特定的 HTML 元素属性:** 查找包含特定属性（如 `data-reactroot`, `ng-version`）的 HTML 元素。
    * **检测 DOM 元素的 JavaScript 属性:** 查找附加在 DOM 元素上的特定 JavaScript 属性（通常是框架注入的）。
    * **检测 `<meta>` 标签的 `generator` 属性:**  某些 CMS 或框架会在 `<meta>` 标签中声明其名称。

2. **提取框架版本信息 (如果可能):**  对于某些框架，代码会尝试提取其版本信息。这通常通过检查特定的全局变量或 `<meta>` 标签的内容来实现。

3. **报告检测结果:** 将检测到的框架及其版本信息封装成 `JavaScriptFrameworkDetectionResult` 对象，并通过 `document.Loader()->DidObserveJavaScriptFrameworks(result)` 将结果传递给 Blink 的加载器。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **检测全局变量:**
        * **例子:**  如果页面使用了 React，代码会检查全局变量 `window.React` 是否存在。如果存在，则认为检测到了 React。
        * **代码片段:**
          ```c++
          if (IsFrameworkVariableUsed(context, kReactData)) {
            result.detected_versions[JavaScriptFramework::kReact] =
                kNoFrameworkVersionDetected;
          }
          ```
    * **检测 DOM 元素的 JavaScript 属性:**
        * **例子:** Vue.js 会在 DOM 元素上添加 `__vue__` 或 `__vue_app__` 属性。代码会检查是否存在这些属性来判断是否使用了 Vue.js。
        * **代码片段:**
          ```c++
          if (key_value == vue_string || key_value == vue_app_string) {
            result.detected_versions[JavaScriptFramework::kVue] =
                kNoFrameworkVersionDetected;
          }
          ```

* **HTML:**
    * **检测 HTML 元素 ID:**
        * **例子:** Gatsby 常用的根元素 ID 是 `___gatsby`，React 常用的根元素 ID 是 `react-root`。代码会尝试通过 `document.getElementById()` 获取这些元素。
        * **代码片段:**
          ```c++
          if (IsFrameworkIDUsed(document, AtomicString(kGatsbyId))) {
            result.detected_versions[JavaScriptFramework::kGatsby] =
                kNoFrameworkVersionDetected;
          }
          ```
    * **检测 HTML 元素属性:**
        * **例子:** React 渲染的根元素通常会带有 `data-reactroot` 属性。Angular 的元素可能会有 `ng-version` 属性。Svelte 渲染的元素的 class 属性会以 `svelte-` 开头。
        * **代码片段:**
          ```c++
          if (element.FastHasAttribute(data_reactroot)) {
            result.detected_versions[JavaScriptFramework::kReact] =
                kNoFrameworkVersionDetected;
          }
          if (element.FastHasAttribute(ng_version)) {
            result.detected_versions[JavaScriptFramework::kAngular] =
                kNoFrameworkVersionDetected;
            detected_ng_version = element.FastGetAttribute(ng_version);
          }
          ```
    * **检测 `<meta>` 标签:**
        * **例子:** 某些 CMS（如 WordPress, Drupal）会在 `<head>` 中添加一个 `<meta name="generator" content="WordPress 6.2">` 这样的标签。代码会解析这个标签的内容来识别 CMS 和版本。
        * **代码片段:**
          ```c++
          if (generator_meta) {
            const AtomicString& content = generator_meta->Content();
            if (!content.empty()) {
              if (content.StartsWith("WordPress ")) {
                String version_string =
                    String(content).Substring(wordpress_prefix_length);
                result.detected_versions[JavaScriptFramework::kWordPress] =
                    ExtractVersion(version_regexp, context,
                                   V8String(isolate, version_string));
              }
            }
          }
          ```

* **CSS:**  这个文件本身不直接与 CSS 交互，但其检测到的框架信息可能会被 Blink 的其他模块用于优化渲染或应用特定的样式处理。例如，如果检测到使用了某个特定的 CSS-in-JS 库，可能会有相应的优化策略。**这个文件主要关注 JavaScript 的框架，而不是 CSS 框架。**

**逻辑推理及假设输入与输出:**

**假设输入:** 一个包含以下 HTML 和 JavaScript 的网页:

```html
<!DOCTYPE html>
<html>
<head>
  <title>React App</title>
</head>
<body>
  <div id="root"></div>
  <script>
    window.React = { version: '17.0.2' };
    document.getElementById('root').setAttribute('data-reactroot', '');
  </script>
</body>
</html>
```

**逻辑推理:**

1. `DetectJavascriptFrameworksOnLoad` 函数会被调用。
2. `TraverseTreeForFrameworks` 函数会遍历 DOM 树。
3. `CheckIdMatches` 函数会检查是否存在 `id="root"`，但这不是 React 的默认 ID，所以不会匹配。
4. `CheckAttributeMatches` 函数会检查到 `div` 元素包含 `data-reactroot` 属性，因此会标记检测到 React。
5. `CheckGlobalPropertyMatches` 函数会检查到全局变量 `window.React` 存在，也会标记检测到 React。
6. `DetectFrameworkVersions` 函数会尝试从 `window.React.version` 中提取版本信息。

**预期输出 (`JavaScriptFrameworkDetectionResult`):**

```
{
  detected_versions: {
    JavaScriptFramework::kReact: 0x1102 // 代表版本 17.2 (major << 8 | minor)
  }
}
```

**涉及用户或编程常见的使用错误及举例说明:**

1. **框架未完全加载就执行检测:** 如果 `DetectJavascriptFrameworksOnLoad` 在框架完全初始化之前运行，可能无法检测到全局变量或 DOM 属性。
    * **用户操作:** 用户访问一个加载缓慢的网页。
    * **调试线索:**  如果检测结果不一致，有时能检测到，有时不能，可能是加载时序问题。
2. **框架使用了自定义的全局变量名或属性名:** 如果开发者修改了框架默认的全局变量名或属性名，检测可能会失败。
    * **编程错误:** 开发者为了避免命名冲突或进行代码混淆，修改了框架的默认设置。
    * **调试线索:**  需要分析目标网站的源代码，查看是否有自定义的全局变量或属性。
3. **错误的正则表达式版本提取:** 在 `DetectFrameworkVersions` 中，如果用于提取版本号的正则表达式不正确，可能导致版本提取失败或提取到错误的版本。
    * **编程错误:**  修改了版本号的格式，但没有更新正则表达式。
    * **调试线索:**  查看 `ExtractVersion` 函数的逻辑和正则表达式是否与目标框架的版本号格式匹配。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入网址或点击链接。**
2. **浏览器发起 HTTP 请求获取网页资源 (HTML, CSS, JavaScript 等)。**
3. **浏览器开始解析 HTML 文档，构建 DOM 树。**
4. **浏览器下载并执行 JavaScript 代码。**  JavaScript 代码可能会加载和初始化各种框架。
5. **在文档加载完成的某个阶段 (通常是 `DOMContentLoaded` 或 `load` 事件触发后)，Blink 引擎会调用 `DetectJavascriptFrameworksOnLoad` 函数。**  具体的触发时机可能与 Blink 的内部实现有关。
6. **`DetectJavascriptFrameworksOnLoad` 函数获取当前文档和主 Frame 的 JavaScript 上下文。**
7. **`TraverseTreeForFrameworks` 函数开始遍历 DOM 树，并执行各种检测逻辑。**
8. **检测结果通过 `document.Loader()->DidObserveJavaScriptFrameworks(result)` 传递给 Blink 的其他模块。**

**作为调试线索:**

* **如果需要调试框架检测功能，可以设置断点在 `DetectJavascriptFrameworksOnLoad` 或 `TraverseTreeForFrameworks` 等关键函数中。**
* **检查 `IsFrameworkVariableUsed`, `IsFrameworkIDUsed`, `CheckAttributeMatches`, `CheckPropertyMatches` 等函数的执行情况，看是否正确识别了框架的特征。**
* **查看 `DetectFrameworkVersions` 函数中版本提取的逻辑是否正确，特别是正则表达式是否匹配目标框架的版本号格式。**
* **可以使用 Blink 提供的调试工具 (如 Chrome DevTools) 查看网页的 DOM 结构和全局变量，以便理解框架是如何在页面上呈现的。**
* **如果怀疑是加载时序问题，可以尝试在不同的生命周期阶段进行检测，或者在 JavaScript 代码中手动触发检测逻辑进行测试。**

总而言之，`detect_javascript_frameworks.cc` 是 Blink 引擎中一个重要的组成部分，它通过分析网页的 HTML 结构和 JavaScript 环境来识别正在使用的 JavaScript 框架，为浏览器的其他功能提供有价值的信息。

Prompt: 
```
这是目录为blink/renderer/core/script/detect_javascript_frameworks.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/script/detect_javascript_frameworks.h"

#include "base/feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/javascript_framework_detection.h"
#include "third_party/blink/public/common/loader/loading_behavior_flag.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

constexpr char kGatsbyId[] = "___gatsby";
constexpr char kNextjsData[] = "next";
constexpr char kNuxtjsData[] = "__NUXT__";
constexpr char kSapperData[] = "__SAPPER__";
constexpr char kVuepressData[] = "__VUEPRESS__";
constexpr char kShopify[] = "Shopify";
constexpr char kSquarespace[] = "Squarespace";

bool IsFrameworkVariableUsed(v8::Local<v8::Context> context,
                             const String& framework_variable_name) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::Object> global = context->Global();
  v8::TryCatch try_catch(isolate);
  bool has_property;
  bool succeeded =
      global
          ->HasRealNamedProperty(
              context, V8AtomicString(isolate, framework_variable_name))
          .To(&has_property);
  DCHECK(succeeded && !try_catch.HasCaught());
  return has_property;
}

bool IsFrameworkIDUsed(Document& document, const AtomicString& framework_id) {
  if (document.getElementById(framework_id)) {
    return true;
  }
  return false;
}

inline void CheckIdMatches(Document& document,
                           JavaScriptFrameworkDetectionResult& result) {
  DEFINE_STATIC_LOCAL(AtomicString, kReactId, ("react-root"));
  if (IsFrameworkIDUsed(document, AtomicString(kGatsbyId))) {
    result.detected_versions[JavaScriptFramework::kGatsby] =
        kNoFrameworkVersionDetected;
  }
  if (IsFrameworkIDUsed(document, kReactId)) {
    result.detected_versions[JavaScriptFramework::kReact] =
        kNoFrameworkVersionDetected;
  }
}

inline void CheckAttributeMatches(const Element& element,
                                  JavaScriptFrameworkDetectionResult& result,
                                  AtomicString& detected_ng_version) {
  DEFINE_STATIC_LOCAL(QualifiedName, ng_version, (AtomicString("ng-version")));
  DEFINE_STATIC_LOCAL(QualifiedName, data_reactroot,
                      (AtomicString("data-reactroot")));
  static constexpr char kSvelte[] = "svelte-";
  if (element.FastHasAttribute(data_reactroot)) {
    result.detected_versions[JavaScriptFramework::kReact] =
        kNoFrameworkVersionDetected;
  }
  if (element.GetClassAttribute().StartsWith(kSvelte)) {
    result.detected_versions[JavaScriptFramework::kSvelte] =
        kNoFrameworkVersionDetected;
  }
  if (element.FastHasAttribute(ng_version)) {
    result.detected_versions[JavaScriptFramework::kAngular] =
        kNoFrameworkVersionDetected;
    detected_ng_version = element.FastGetAttribute(ng_version);
  }
}

inline void CheckPropertyMatches(Element& element,
                                 DOMDataStore& dom_data_store,
                                 v8::Local<v8::Context> context,
                                 v8::Isolate* isolate,
                                 JavaScriptFrameworkDetectionResult& result) {
  v8::Local<v8::Object> v8_element;
  if (!dom_data_store.Get(isolate, &element).ToLocal(&v8_element)) {
    return;
  }
  v8::Local<v8::Array> property_names;
  if (!v8_element->GetOwnPropertyNames(context).ToLocal(&property_names)) {
    return;
  }

  DEFINE_STATIC_LOCAL(AtomicString, vue_string, ("__vue__"));
  DEFINE_STATIC_LOCAL(AtomicString, vue_app_string, ("__vue_app__"));
  DEFINE_STATIC_LOCAL(AtomicString, k_string, ("__k"));
  DEFINE_STATIC_LOCAL(AtomicString, reactRootContainer_string,
                      ("_reactRootContainer"));
  DEFINE_STATIC_LOCAL(AtomicString, reactListening_string, ("_reactListening"));
  DEFINE_STATIC_LOCAL(AtomicString, reactFiber_string, ("__reactFiber"));
  for (uint32_t i = 0; i < property_names->Length(); ++i) {
    v8::Local<v8::Value> key;
    if (!property_names->Get(context, i).ToLocal(&key) || !key->IsString()) {
      continue;
    }
    AtomicString key_value = ToCoreAtomicString(isolate, key.As<v8::String>());
    if (key_value == vue_string || key_value == vue_app_string) {
      result.detected_versions[JavaScriptFramework::kVue] =
          kNoFrameworkVersionDetected;
    } else if (key_value == k_string) {
      result.detected_versions[JavaScriptFramework::kPreact] =
          kNoFrameworkVersionDetected;
    } else if (key_value == reactRootContainer_string) {
      result.detected_versions[JavaScriptFramework::kReact] =
          kNoFrameworkVersionDetected;
    } else if (key_value.StartsWith(reactListening_string) ||
               key_value.StartsWith(reactFiber_string)) {
      result.detected_versions[JavaScriptFramework::kReact] =
          kNoFrameworkVersionDetected;
    }
  }
}

inline void CheckGlobalPropertyMatches(
    v8::Local<v8::Context> context,
    v8::Isolate* isolate,
    JavaScriptFrameworkDetectionResult& result) {
  static constexpr char kVueData[] = "Vue";
  static constexpr char kVue3Data[] = "__VUE__";
  static constexpr char kReactData[] = "React";
  if (IsFrameworkVariableUsed(context, kNextjsData)) {
    result.detected_versions[JavaScriptFramework::kNext] =
        kNoFrameworkVersionDetected;
  }
  if (IsFrameworkVariableUsed(context, kNuxtjsData)) {
    result.detected_versions[JavaScriptFramework::kNuxt] =
        kNoFrameworkVersionDetected;
  }
  if (IsFrameworkVariableUsed(context, kSapperData)) {
    result.detected_versions[JavaScriptFramework::kSapper] =
        kNoFrameworkVersionDetected;
  }
  if (IsFrameworkVariableUsed(context, kVuepressData)) {
    result.detected_versions[JavaScriptFramework::kVuePress] =
        kNoFrameworkVersionDetected;
  }
  if (IsFrameworkVariableUsed(context, kVueData) ||
      IsFrameworkVariableUsed(context, kVue3Data)) {
    result.detected_versions[JavaScriptFramework::kVue] =
        kNoFrameworkVersionDetected;
  }
  // TODO(npm): Add check for window.React.Component, not just window.React.
  if (IsFrameworkVariableUsed(context, kReactData)) {
    result.detected_versions[JavaScriptFramework::kReact] =
        kNoFrameworkVersionDetected;
  }
  if (IsFrameworkVariableUsed(context, kShopify)) {
    result.detected_versions[JavaScriptFramework::kShopify] =
        kNoFrameworkVersionDetected;
  }
  if (IsFrameworkVariableUsed(context, kSquarespace)) {
    result.detected_versions[JavaScriptFramework::kSquarespace] =
        kNoFrameworkVersionDetected;
  }
}

int64_t ExtractVersion(v8::Local<v8::RegExp> regexp,
                       v8::Local<v8::Context> context,
                       v8::Local<v8::Value> version) {
  v8::Local<v8::Object> groups;
  v8::Local<v8::Value> major;
  v8::Local<v8::Value> minor;
  bool success =
      regexp->Exec(context, version.As<v8::String>()).ToLocal(&groups);
  if (!success || !groups->IsArray()) {
    return kNoFrameworkVersionDetected;
  }
  v8::Local<v8::Array> groups_array = groups.As<v8::Array>();
  if (!groups_array->Get(context, 1).ToLocal(&major) ||
      !groups_array->Get(context, 2).ToLocal(&minor) || !major->IsString() ||
      !minor->IsString()) {
    return kNoFrameworkVersionDetected;
  }

  v8::Local<v8::Value> major_number;
  v8::Local<v8::Value> minor_number;
  if (!major->ToNumber(context).ToLocal(&major_number) ||
      !minor->ToNumber(context).ToLocal(&minor_number)) {
    return kNoFrameworkVersionDetected;
  }

  // Major & minor versions are clamped to 8bits to avoid using this as a
  // vector to identify users.
  return ((major_number->IntegerValue(context).FromMaybe(0) & 0xff) << 8) |
         (minor_number->IntegerValue(context).FromMaybe(0) & 0xff);
}

void DetectFrameworkVersions(Document& document,
                             v8::Local<v8::Context> context,
                             v8::Isolate* isolate,
                             JavaScriptFrameworkDetectionResult& result,
                             const AtomicString& detected_ng_version) {
  v8::Local<v8::Object> global = context->Global();
  static constexpr char kVersionPattern[] = "([0-9]+)\\.([0-9]+)";
  v8::Local<v8::RegExp> version_regexp;

  if (!v8::RegExp::New(context, V8AtomicString(isolate, kVersionPattern),
                       v8::RegExp::kNone)
           .ToLocal(&version_regexp)) {
    return;
  }

  auto SafeGetProperty = [&](v8::Local<v8::Value> object,
                             const char* prop_name) -> v8::Local<v8::Value> {
    if (object.IsEmpty() || !object->IsObject()) {
      return v8::Undefined(isolate);
    }

    v8::Local<v8::Value> value;
    if (!object.As<v8::Object>()
             ->GetRealNamedProperty(context, V8AtomicString(isolate, prop_name))
             .ToLocal(&value)) {
      return v8::Undefined(isolate);
    }

    return value;
  };

  if (result.detected_versions.contains(JavaScriptFramework::kNext)) {
    static constexpr char kNext[] = "next";
    static constexpr char kVersion[] = "version";
    int64_t version = kNoFrameworkVersionDetected;
    v8::Local<v8::Value> version_string =
        SafeGetProperty(SafeGetProperty(global, kNext), kVersion);
    if (!version_string.IsEmpty() && version_string->IsString()) {
      version = ExtractVersion(version_regexp, context, version_string);
    }

    result.detected_versions[JavaScriptFramework::kNext] = version;
  }

  if (!detected_ng_version.IsNull()) {
    result.detected_versions[JavaScriptFramework::kAngular] = ExtractVersion(
        version_regexp, context,
        v8::String::NewFromUtf8(isolate,
                                detected_ng_version.GetString().Utf8().c_str())
            .FromMaybe(v8::String::Empty(isolate)));
  }

  if (result.detected_versions.contains(JavaScriptFramework::kVue)) {
    static constexpr char kVue2[] = "Vue";
    static constexpr char kVersion[] = "version";
    if (global->HasRealNamedProperty(context, V8AtomicString(isolate, kVue2))
            .FromMaybe(false)) {
      v8::Local<v8::Value> version_string =
          SafeGetProperty(SafeGetProperty(global, kVue2), kVersion);
      if (!version_string.IsEmpty() && version_string->IsString()) {
        result.detected_versions[JavaScriptFramework::kVue] =
            ExtractVersion(version_regexp, context, version_string);
      }
    } else {
      static constexpr char kVue3[] = "__VUE__";
      bool vue3 = false;
      if (global->HasRealNamedProperty(context, V8AtomicString(isolate, kVue3))
              .To(&vue3) &&
          vue3) {
        result.detected_versions[JavaScriptFramework::kVue] = 0x300;
      }
    }
  }

  HTMLMetaElement* generator_meta = nullptr;

  if (document.head()) {
    for (HTMLMetaElement& meta_element :
         Traversal<HTMLMetaElement>::DescendantsOf(*document.head())) {
      if (EqualIgnoringASCIICase(meta_element.GetName(), "generator")) {
        generator_meta = &meta_element;
        break;
      }
    }
  }

  if (generator_meta) {
    const AtomicString& content = generator_meta->Content();
    if (!content.empty()) {
      if (content.StartsWith("Wix")) {
        result.detected_versions[JavaScriptFramework::kWix] =
            kNoFrameworkVersionDetected;
      } else if (content.StartsWith("Joomla")) {
        result.detected_versions[JavaScriptFramework::kJoomla] =
            kNoFrameworkVersionDetected;
      } else {
        constexpr char wordpress_prefix[] = "WordPress ";
        constexpr size_t wordpress_prefix_length =
            std::char_traits<char>::length(wordpress_prefix);

        if (content.StartsWith(wordpress_prefix)) {
          String version_string =
              String(content).Substring(wordpress_prefix_length);
          result.detected_versions[JavaScriptFramework::kWordPress] =
              ExtractVersion(version_regexp, context,
                             V8String(isolate, version_string));
        }

        constexpr char drupal_prefix[] = "Drupal ";
        constexpr size_t drupal_prefix_length =
            std::char_traits<char>::length(drupal_prefix);

        if (content.StartsWith(drupal_prefix)) {
          String version_string =
              String(content).Substring(drupal_prefix_length);
          String trimmed =
              version_string.Substring(0, version_string.Find(" "));
          bool ok = true;
          int version = trimmed.ToInt(&ok);
          result.detected_versions[JavaScriptFramework::kDrupal] =
              ok ? ((version & 0xff) << 8) : kNoFrameworkVersionDetected;
        }
      }
    }
  }
}

void TraverseTreeForFrameworks(Document& document,
                               v8::Isolate* isolate,
                               v8::Local<v8::Context> context) {
  v8::TryCatch try_catch(isolate);
  JavaScriptFrameworkDetectionResult result;
  AtomicString detected_ng_version;
  if (!document.documentElement())
    return;
  DOMDataStore& dom_data_store =
      DOMWrapperWorld::MainWorld(isolate).DomDataStore();
  for (Element& element :
       ElementTraversal::InclusiveDescendantsOf(*document.documentElement())) {
    CheckAttributeMatches(element, result, detected_ng_version);
    CheckPropertyMatches(element, dom_data_store, context, isolate, result);
  }
  CheckIdMatches(document, result);
  CheckGlobalPropertyMatches(context, isolate, result);
  DetectFrameworkVersions(document, context, isolate, result,
                          detected_ng_version);
  DCHECK(!try_catch.HasCaught());
  document.Loader()->DidObserveJavaScriptFrameworks(result);
}

}  // namespace

void DetectJavascriptFrameworksOnLoad(Document& document) {
  LocalFrame* const frame = document.GetFrame();
  if (!frame || !frame->IsOutermostMainFrame() ||
      !document.Url().ProtocolIsInHTTPFamily() ||
      !document.BaseURL().ProtocolIsInHTTPFamily()) {
    return;
  }

  v8::Isolate* const isolate = ToIsolate(frame);
  // It would be simpler to call `ToScriptStateForMainWorld()`; however, this
  // forces WindowProxy initialization, which is somewhat expensive.  If the
  // WindowProxy isn't already initialized, there are no JS frameworks by
  // definition. As a bonus, this also helps preserve a historical quirk for Gin
  // Java Bridge in Android WebView:
  // https://docs.google.com/document/d/1R5170is5vY425OO2Ru-HJBEraEKu0HjQEakcYldcSzM/edit?usp=sharing
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context =
      ToV8ContextMaybeEmpty(frame, DOMWrapperWorld::MainWorld(isolate));
  if (context.IsEmpty()) {
    return;
  }

  ScriptState* script_state = ScriptState::From(isolate, context);
  DCHECK(script_state && script_state->ContextIsValid());

  ScriptState::Scope scope(script_state);
  TraverseTreeForFrameworks(document, isolate, context);
}

}  // namespace blink

"""

```