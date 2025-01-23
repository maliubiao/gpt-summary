Response:
My thinking process to analyze the provided C++ code snippet and answer the user's request follows these steps:

1. **Understand the Goal:** The primary goal is to understand the functionality of the `import_map.cc` file within the Chromium Blink rendering engine. The request specifically asks about its relationship to JavaScript, HTML, and CSS, requests examples of its logic, potential user errors, how a user might reach this code, and finally, a summary of its function.

2. **Initial Code Scan (Keywords and Structure):** I first scan the code for prominent keywords and the overall structure. Keywords like `import`, `map`, `specifier`, `resolve`, `normalize`, `parse`, `JSON`, `URL`, `console`, `warning`, and data structures like `SpecifierMap`, `ScopesMap`, and `IntegrityMap` stand out. The `#include` directives indicate dependencies on other Blink components related to scripting, URLs, JSON parsing, and console logging. The namespace `blink` and the class `ImportMap` are immediately apparent as the core focus.

3. **Identify Core Functionality - Import Maps:** The file name and the repeated use of "import map" strongly suggest that this code handles the processing and application of import maps. Import maps are a JavaScript feature that allows developers to control how module specifiers (like `'lodash'`) are resolved to actual URLs.

4. **Analyze Key Functions and Data Structures:**
    * **`ImportMap::Parse()`:** This function is clearly responsible for taking a string (presumably from a `<script type="importmap">` tag) and converting it into an internal representation (`ImportMap` object). It involves JSON parsing and validation of the import map structure ("imports", "scopes", "integrity"). This directly links to HTML, as the import map is defined within HTML.
    * **`ImportMap::SpecifierMap` and `ImportMap::ScopesMap`:** These data structures (likely `WTF::HashMap`) store the parsed import and scope mappings. The `SpecifierMap` maps specifiers to URLs, and `ScopesMap` maps scope prefixes to `SpecifierMap` instances, allowing for context-specific mappings.
    * **`ImportMap::IntegrityMap`:** This stores integrity metadata (likely for Subresource Integrity - SRI) associated with module URLs.
    * **`ImportMap::SortAndNormalizeSpecifierMap()`:** This function takes the "imports" section of the parsed JSON and normalizes the keys (specifiers) and values (URLs). Normalization involves URL parsing and validation, ensuring consistency.
    * **`ImportMap::NormalizeSpecifierKey()` and `ImportMap::NormalizeValue()`:** These helper functions handle the individual normalization steps for keys and values, ensuring they conform to the import map specification.
    * **`ImportMap::Resolve()` and `ImportMap::ResolveImportsMatch()`:** These functions are at the heart of import map functionality. They take a module specifier and the current base URL and use the parsed import map to resolve it to a concrete URL. This is crucial for JavaScript module loading.
    * **`ImportMap::MergeExistingAndNewImportMaps()`:** This function handles the merging of multiple import maps, which can occur when inline and external import maps are used.

5. **Connect to JavaScript, HTML, and CSS:**
    * **JavaScript:** The entire purpose of import maps is to influence how JavaScript modules are loaded. The `Resolve()` function is directly involved in this process. The code interacts with `ParsedSpecifier`, indicating it's dealing with JavaScript module specifiers.
    * **HTML:** Import maps are defined using `<script type="importmap">` tags in HTML. The `Parse()` function handles the content of these tags.
    * **CSS:**  While import maps themselves don't directly affect CSS, JavaScript modules loaded via import maps *can* manipulate CSS (e.g., through the DOM or CSSOM). However, the `import_map.cc` file itself doesn't have direct CSS-related logic.

6. **Infer Logic and Examples:**  Based on the function names and code, I can infer the input and output of key functions. For example, `NormalizeSpecifierKey` takes a string and a base URL and returns a normalized specifier or an empty string if invalid. `Resolve()` takes a specifier and base URL and returns a resolved URL or `std::nullopt`.

7. **Consider User Errors:**  The code includes console warnings for various invalid import map entries (empty keys, invalid URLs, incorrect types). These point to common user mistakes when writing import maps.

8. **Trace User Interaction:**  To reach this code, a developer would include a `<script type="importmap">` tag in their HTML. The browser's HTML parser would identify this tag and pass its content to the Blink rendering engine, eventually reaching the `ImportMap::Parse()` function.

9. **Synthesize the Summary:**  Based on the analysis, I can summarize the core functionality: parsing, validating, storing, resolving, and merging import maps, all to control JavaScript module loading based on the rules defined in HTML.

10. **Structure the Answer:** I organize the findings into the categories requested by the user: functionality, relationship to web technologies, logic examples, user errors, debugging clues, and a summary. I use code snippets and clear explanations to illustrate the points.
这是 `blink/renderer/core/script/import_map.cc` 文件的功能分析，作为第 1 部分的归纳。

**功能归纳:**

`import_map.cc` 文件的主要功能是**解析、规范化和管理 HTML 中的 `<script type="importmap">` 元素中定义的 import maps 数据，并用于解析 JavaScript 模块说明符 (module specifiers)。**  更具体地说，它负责：

1. **解析 Import Map 字符串:**  将 `<script type="importmap">` 标签中的 JSON 字符串解析成内部的数据结构。
2. **规范化说明符键 (Specifier Keys):**  将 import map 中的键 (specifier keys) 转换为规范化的形式，以便后续的匹配和解析。这包括处理空字符串键和 URL 形式的键。
3. **规范化说明符值 (Specifier Values):** 将 import map 中的值 (specifier values，即模块地址) 转换为规范化的绝对 URL。这包括验证 URL 的有效性，并处理尾部斜杠的情况。
4. **存储和管理 Import Map 数据:**  使用 `SpecifierMap` 和 `ScopesMap` 存储解析和规范化后的 imports 和 scopes 信息。
5. **解析模块说明符 (Module Specifier Resolution):**  根据当前脚本的 base URL 和已解析的 import map，将 JavaScript 代码中的模块说明符解析为具体的模块 URL。这涉及到精确匹配和前缀匹配。
6. **处理 Scopes:**  允许根据不同的作用域 (scopes) 定义不同的模块映射规则。
7. **处理 Integrity (如果启用):**  支持 import map 的完整性 (integrity) 属性，用于验证模块的完整性。
8. **合并 Import Maps:**  提供合并多个 import maps 的功能，例如合并内联和外部的 import maps。
9. **提供调试信息:**  在解析和解析过程中，会向控制台输出警告信息，帮助开发者识别 import map 中的错误。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

* **JavaScript:**  `import_map.cc` 的核心功能是为 JavaScript 的模块导入机制提供支持。
    * **举例:** 当 JavaScript 代码中出现 `import 'lodash'` 这样的语句时，Blink 引擎会使用已解析的 import map 来查找 `'lodash'` 对应的实际 URL，例如 `https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js`。 `import_map.cc` 中的 `Resolve` 函数就负责这个查找过程。
    * **假设输入与输出:**
        * **假设输入:**
            * Import Map: `{"imports": {"lodash": "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"}}`
            * JavaScript 代码中的模块说明符: `'lodash'`
            * Base URL: 当前 HTML 页面的 URL
        * **输出:** `https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js`

* **HTML:** Import maps 是通过 HTML 的 `<script type="importmap">` 元素定义的。
    * **举例:**  HTML 中可以包含如下代码：
        ```html
        <script type="importmap">
        {
          "imports": {
            "my-module": "/modules/my-module.js"
          }
        }
        </script>
        <script type="module">
          import('/modules/my-module.js'); // 或者 import 'my-module';
        </script>
        ```
        `import_map.cc` 中的 `Parse` 函数负责解析 `<script type="importmap">` 标签中的 JSON 数据。

* **CSS:**  `import_map.cc` 本身与 CSS 的功能没有直接关系。但是，JavaScript 模块加载后可能会动态地操作 CSS，例如通过 DOM API 修改样式。import map 间接地影响了这些 JavaScript 模块的加载。

**逻辑推理的假设输入与输出:**

* **假设输入 (NormalizeSpecifierKey):**
    * `key_string`: `"./my-module"`
    * `base_url`: `https://example.com/path/`
* **输出 (NormalizeSpecifierKey):** `"https://example.com/path/my-module"` (假设 `./my-module` 可以解析为这个 URL)

* **假设输入 (NormalizeValue):**
    * `key`: `"my-module"`
    * `value_string`: `"/another/module.js"`
    * `base_url`: `https://example.com/path/`
* **输出 (NormalizeValue):** `https://example.com/another/module.js`

* **假设输入 (Resolve):**
    * `parsed_specifier`: 已解析的模块说明符对象，例如表示 `"my-module"`
    * `base_url`: `https://example.com/current-page.html`
    * `import_map`:  包含 `{"imports": {"my-module": "/modules/actual-module.js"}}`
* **输出 (Resolve):** `https://example.com/modules/actual-module.js`

**涉及用户或编程常见的使用错误 (举例说明):**

1. **JSON 格式错误:**  用户在 `<script type="importmap">` 中编写了无效的 JSON。
    * **例子:**  `{ imports: { "lodash": "..." } }` (缺少引号)
    * **后果:** `Parse` 函数会失败，并向控制台输出语法错误警告。

2. **无效的 URL:**  import map 中的值不是有效的 URL。
    * **例子:** `{"imports": {"lodash": "not a valid url"}}`
    * **后果:** `NormalizeValue` 函数会识别出无效的 URL，并向控制台输出警告，该映射会被忽略。

3. **空字符串作为键:**  import map 的 "imports" 或 "scopes" 中使用了空字符串作为键。
    * **例子:** `{"imports": {"": "..."}}`
    * **后果:** `NormalizeSpecifierKey` 会识别出空字符串键，并向控制台输出警告，该映射会被忽略。

4. **Scope 前缀不是有效的 URL:** "scopes" 中的键（scope 前缀）不是有效的 URL。
    * **例子:** `{"scopes": {"not a url/": {"lodash": "..."}}}`
    * **后果:** `Parse` 函数在处理 scopes 时会识别出无效的 URL 前缀，并向控制台输出警告，该 scope 会被忽略。

5. **循环依赖或回溯:**  import map 的配置导致模块解析时出现循环依赖或回溯到父目录的情况。
    * **例子:** `{"imports": {"a/": "b/", "b/": "a/"}}`，当尝试解析 `a/c` 时。
    * **后果:** `ResolveImportsMatchInternal` 会检测到回溯，并抛出 `TypeError`。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者在 HTML 文件中添加了 `<script type="importmap">` 标签，并在其中定义了 import map 的 JSON 数据。**
2. **浏览器加载 HTML 文件，解析 HTML 结构。**
3. **当解析到 `<script type="importmap">` 标签时，浏览器会提取标签内的 JSON 字符串。**
4. **Blink 渲染引擎的 HTML 解析器会将这个 JSON 字符串传递给 `core/script/import_map.cc` 中的 `ImportMap::Parse` 函数。**
5. **`Parse` 函数会执行 JSON 解析、规范化等操作，将 import map 数据存储在内部数据结构中。**
6. **当 JavaScript 代码执行到 `import` 语句时，Blink 引擎的模块加载器会调用 `ImportMap::Resolve` 函数，根据当前的 base URL 和已解析的 import map，尝试解析模块说明符。**

**调试线索:**

* 如果模块加载失败，并且怀疑是 import map 配置问题，可以检查浏览器的开发者工具的控制台，查看是否有与 import map 相关的警告或错误信息。这些信息通常由 `import_map.cc` 中的 `AddIgnoredKeyMessage` 和 `AddIgnoredValueMessage` 等函数生成。
* 可以使用浏览器的 "Network" 面板，查看模块加载的实际 URL 是否符合预期，这有助于判断 import map 的解析是否正确。
* 在 Blink 的调试版本中，可以设置断点在 `import_map.cc` 的关键函数 (如 `Parse`, `NormalizeSpecifierKey`, `NormalizeValue`, `Resolve`) 中，逐步跟踪 import map 的解析和解析过程。

**总结 `import_map.cc` 的功能 (针对第 1 部分):**

总而言之，`blink/renderer/core/script/import_map.cc` 的第一部分主要负责**解析和规范化 HTML 中定义的 import maps 数据**。它将 JSON 字符串转换为内部表示，并对 import map 中的键和值进行规范化处理，为后续的 JavaScript 模块说明符解析奠定基础。 这个过程涉及到 HTML 解析以及对 URL 规范的理解和应用。

### 提示词
```
这是目录为blink/renderer/core/script/import_map.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/script/import_map.h"

#include <memory>
#include <utility>

#include "base/metrics/histogram_macros.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/script/import_map_error.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/script/parsed_specifier.h"
#include "third_party/blink/renderer/platform/json/json_parser.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/loader/fetch/console_logger.h"
#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

// TODO(https://crbug.com/928549): Audit and improve error messages throughout
// this file.

void AddIgnoredKeyMessage(ConsoleLogger& logger,
                          const String& key,
                          const String& reason) {
  logger.AddConsoleMessage(
      mojom::ConsoleMessageSource::kOther, mojom::ConsoleMessageLevel::kWarning,
      "Ignored an import map key \"" + key + "\": " + reason);
}

void AddIgnoredValueMessage(ConsoleLogger& logger,
                            const String& key,
                            const String& reason) {
  logger.AddConsoleMessage(
      mojom::ConsoleMessageSource::kOther, mojom::ConsoleMessageLevel::kWarning,
      "Ignored an import map value of \"" + key + "\": " + reason);
}

// <specdef
// href="https://html.spec.whatwg.org/C#normalizing-a-specifier-key">
AtomicString NormalizeSpecifierKey(const String& key_string,
                                   const KURL& base_url,
                                   ConsoleLogger& logger) {
  // <spec step="1">If specifierKey is the empty string, then:</spec>
  if (key_string.empty()) {
    // <spec step="1.1">Report a warning to the console that specifier keys
    // cannot be the empty string.</spec>
    AddIgnoredKeyMessage(logger, key_string,
                         "specifier keys cannot be the empty string.");

    // <spec step="1.2">Return null.</spec>
    return g_empty_atom;
  }

  // <spec step="2">Let url be the result of parsing a URL-like import
  // specifier, given specifierKey and baseURL.</spec>
  ParsedSpecifier key = ParsedSpecifier::Create(key_string, base_url);

  switch (key.GetType()) {
    case ParsedSpecifier::Type::kInvalid:
    case ParsedSpecifier::Type::kBare:
      // <spec step="4">Return specifierKey.</spec>
      return AtomicString(key_string);

    case ParsedSpecifier::Type::kURL:
      // <spec step="3">If url is not null, then return the serialization of
      // url.</spec>
      return key.GetImportMapKeyString();
  }
}

// Step 2.4-2.7 of
// <specdef
// href="https://html.spec.whatwg.org/C#sorting-and-normalizing-a-module-specifier-map">
KURL NormalizeValue(const String& key,
                    const String& value_string,
                    const KURL& base_url,
                    ConsoleLogger& logger) {
  // <spec step="2.4">Let addressURL be the result of parsing a URL-like import
  // specifier given value and baseURL.</spec>
  ParsedSpecifier value = ParsedSpecifier::Create(value_string, base_url);

  switch (value.GetType()) {
    case ParsedSpecifier::Type::kInvalid:
      // <spec step="2.5">If addressURL is null, then:</spec>
      //
      // <spec step="2.5.1">Report a warning to the console that the address was
      // invalid.</spec>
      AddIgnoredValueMessage(logger, key, "Invalid URL: " + value_string);

      // <spec step="2.5.2">Set normalized[specifierKey] to null.</spec>
      //
      // <spec step="2.5.3">Continue.</spec>
      return NullURL();

    case ParsedSpecifier::Type::kBare:
      AddIgnoredValueMessage(logger, key, "Bare specifier: " + value_string);
      return NullURL();

    case ParsedSpecifier::Type::kURL:
      // <spec step="2.6">If specifierKey ends with U+002F (/), and the
      // serialization of addressURL does not end with U+002F (/), then:</spec>
      if (key.EndsWith("/") && !value.GetUrl().GetString().EndsWith("/")) {
        // <spec step="2.6.1">Report a warning to the console that an invalid
        // address was given for the specifier key specifierKey; since
        // specifierKey ended in a slash, so must the address.</spec>
        AddIgnoredValueMessage(
            logger, key,
            "Since specifierKey ended in a slash, so must the address: " +
                value_string);

        // <spec step="2.6.2">Set normalized[specifierKey] to null.</spec>
        //
        // <spec step="2.6.3">Continue.</spec>
        return NullURL();
      }

      DCHECK(value.GetUrl().IsValid());
      return value.GetUrl();
  }
}

// https://html.spec.whatwg.org/C#merge-module-specifier-maps
void MergeModuleSpecifierMaps(ImportMap::SpecifierMap& old_map,
                              const ImportMap::SpecifierMap& new_map,
                              ConsoleLogger& logger) {
  // Instead of copying the maps and returning the copy, we're modifying the
  // maps in place.
  // 2. For each specifier → url of newMap:
  for (auto specifier : new_map.Keys()) {
    // 2.1. If specifier exists in oldMap, then:
    if (old_map.Contains(specifier)) {
      // 2.1.1. The user agent may report the removed rule as a warning to the
      // developer console.
      auto* message = MakeGarbageCollected<ConsoleMessage>(
          ConsoleMessage::Source::kJavaScript, ConsoleMessage::Level::kWarning,
          "An import map rule for specifier '" + specifier +
              "' was removed, as it conflicted with an existing rule.");
      logger.AddConsoleMessage(message,
                               /*discard_duplicates=*/true);
      // 2.1.2. Continue.
      continue;
    }
    auto url = new_map.at(specifier);
    // 2.2. Set mergedMap[specifier] to url.
    old_map.insert(specifier, url);
  }
}

void SpecifierMapToStringForTesting(
    StringBuilder& builder,
    const ImportMap::SpecifierMap& specifier_map) {
  builder.Append("{");
  bool is_first_key = true;
  for (const auto& it : specifier_map) {
    if (!is_first_key) {
      builder.Append(",");
    }
    is_first_key = false;
    builder.Append(it.key.GetString().EncodeForDebugging());
    builder.Append(":");
    if (it.value.IsValid()) {
      builder.Append(it.value.GetString().GetString().EncodeForDebugging());
    } else {
      builder.Append("null");
    }
  }
  builder.Append("}");
}

}  // namespace

// <specdef
// href="https://html.spec.whatwg.org/C#parse-an-import-map-string">
//
// Parse |input| as an import map. Errors (e.g. json parsing error, invalid
// keys/values, etc.) are basically ignored, except that they are reported to
// the console |logger|.
ImportMap* ImportMap::Parse(const String& input,
                            const KURL& base_url,
                            ExecutionContext& context,
                            std::optional<ImportMapError>* error_to_rethrow) {
  DCHECK(error_to_rethrow);

  // <spec step="1">Let parsed be the result of parsing JSON into Infra values
  // given input.</spec>
  std::unique_ptr<JSONValue> parsed = ParseJSON(input);

  if (!parsed) {
    *error_to_rethrow =
        ImportMapError(ImportMapError::Type::kSyntaxError,
                       "Failed to parse import map: invalid JSON");
    return MakeGarbageCollected<ImportMap>();
  }

  // <spec step="2">If parsed is not a map, then throw a TypeError indicating
  // that the top-level value must be a JSON object.</spec>
  std::unique_ptr<JSONObject> parsed_map = JSONObject::From(std::move(parsed));
  if (!parsed_map) {
    *error_to_rethrow =
        ImportMapError(ImportMapError::Type::kTypeError,
                       "Failed to parse import map: not an object");
    return MakeGarbageCollected<ImportMap>();
  }

  // <spec step="3">Let sortedAndNormalizedImports be an empty map.</spec>
  SpecifierMap sorted_and_normalized_imports;

  // <spec step="4">If parsed["imports"] exists, then:</spec>
  if (parsed_map->Get("imports")) {
    // <spec step="4.1">If parsed["imports"] is not a map, then throw a
    // TypeError indicating that the "imports" top-level key must be a JSON
    // object.</spec>
    JSONObject* imports = parsed_map->GetJSONObject("imports");
    if (!imports) {
      *error_to_rethrow =
          ImportMapError(ImportMapError::Type::kTypeError,
                         "Failed to parse import map: \"imports\" "
                         "top-level key must be a JSON object.");
      return MakeGarbageCollected<ImportMap>();
    }

    // <spec step="4.2">Set sortedAndNormalizedImports to the result of sorting
    // and normalizing a specifier map given parsed["imports"] and
    // baseURL.</spec>
    sorted_and_normalized_imports =
        SortAndNormalizeSpecifierMap(imports, base_url, context);
  }

  // <spec step="5">Let sortedAndNormalizedScopes be an empty map.</spec>
  ScopesMap normalized_scopes_map;

  // <spec step="6">If parsed["scopes"] exists, then:</spec>
  if (parsed_map->Get("scopes")) {
    // <spec step="6.1">If parsed["scopes"] is not a map, then throw a TypeError
    // indicating that the "scopes" top-level key must be a JSON object.</spec>
    JSONObject* scopes = parsed_map->GetJSONObject("scopes");
    if (!scopes) {
      *error_to_rethrow =
          ImportMapError(ImportMapError::Type::kTypeError,
                         "Failed to parse import map: \"scopes\" "
                         "top-level key must be a JSON object.");
      return MakeGarbageCollected<ImportMap>();
    }

    // <spec step="6.2">Set sortedAndNormalizedScopes to the result of sorting
    // and normalizing scopes given parsed["scopes"] and baseURL.</spec>

    // <specdef label="sort-and-normalize-scopes"
    // href="https://html.spec.whatwg.org/C#sorting-and-normalizing-scopes">

    // <spec label="sort-and-normalize-scopes" step="1">Let normalized be an
    // empty map.</spec>

    // <spec label="sort-and-normalize-scopes" step="2">For each scopePrefix →
    // potentialSpecifierMap of originalMap,</spec>
    for (wtf_size_t i = 0; i < scopes->size(); ++i) {
      const JSONObject::Entry& entry = scopes->at(i);

      JSONObject* specifier_map = scopes->GetJSONObject(entry.first);
      if (!specifier_map) {
        // <spec label="sort-and-normalize-scopes" step="2.1">If
        // potentialSpecifierMap is not a map, then throw a TypeError indicating
        // that the value of the scope with prefix scopePrefix must be a JSON
        // object.</spec>
        *error_to_rethrow = ImportMapError(
            ImportMapError::Type::kTypeError,
            "Failed to parse import map: the value of the scope with prefix "
            "\"" +
                entry.first + "\" must be a JSON object.");
        return MakeGarbageCollected<ImportMap>();
      }

      // <spec label="sort-and-normalize-scopes" step="2.2">Let scopePrefixURL
      // be the result of parsing scopePrefix with baseURL as the base
      // URL.</spec>
      const KURL prefix_url(base_url, entry.first);

      // <spec label="sort-and-normalize-scopes" step="2.3">If scopePrefixURL is
      // failure, then:</spec>
      if (!prefix_url.IsValid()) {
        // <spec label="sort-and-normalize-scopes" step="2.3.1">Report a warning
        // to the console that the scope prefix URL was not parseable.</spec>
        context.AddConsoleMessage(
            mojom::ConsoleMessageSource::kOther,
            mojom::ConsoleMessageLevel::kWarning,
            "Ignored scope \"" + entry.first + "\": not parsable as a URL.");

        // <spec label="sort-and-normalize-scopes" step="2.3.2">Continue.</spec>
        continue;
      }

      // <spec label="sort-and-normalize-scopes" step="2.4">Let
      // normalizedScopePrefix be the serialization of scopePrefixURL.</spec>
      //
      // <spec label="sort-and-normalize-scopes" step="2.5">Set
      // normalized[normalizedScopePrefix] to the result of sorting and
      // normalizing a specifier map given potentialSpecifierMap and
      // baseURL.</spec>
      auto prefix_url_string = prefix_url.GetString();
      if (normalized_scopes_map.find(prefix_url_string) !=
          normalized_scopes_map.end()) {
        // Later instances of a prefix override earlier ones. An explicit
        // `erase` is needed because WTF HashMaps behave differently than spec
        // infra ones, and do nothing if a key already exists.
        normalized_scopes_map.erase(prefix_url_string);
      }
      normalized_scopes_map.insert(
          prefix_url_string,
          SortAndNormalizeSpecifierMap(specifier_map, base_url, context));
    }
  }
  // <spec step="7">Let normalizedIntegrity be an empty map.</spec>
  IntegrityMap normalized_integrity_map;

  // <spec step="8">If parsed["integrity"] exists, then:</spec>
  if (RuntimeEnabledFeatures::ImportMapIntegrityEnabled() &&
      parsed_map->Get("integrity")) {
    context.CountUse(WebFeature::kImportMapIntegrity);
    // <spec step="8.1">If parsed["integrity"] is not a map, then throw a
    // TypeError indicating that the "scopes" top-level key must be a JSON
    // object.</spec>
    JSONObject* integrity = parsed_map->GetJSONObject("integrity");
    if (!integrity) {
      *error_to_rethrow =
          ImportMapError(ImportMapError::Type::kTypeError,
                         "Failed to parse import map: \"integrity\" "
                         "top-level key must be a JSON object.");
      return MakeGarbageCollected<ImportMap>();
    }

    // <spec step="8.2">Set normalizedIntegrity to the result of sorting and
    // normalizing integrity given parsed["integrity"] and baseURL.</spec>

    // <specdef label="normalize-a-module-integrity-map"
    // href="https://html.spec.whatwg.org/C#normalizing-a-module-integrity-map">

    // <spec label="normalize-a-module-integrity-map" step="1">Let
    // normalized be an empty map.</spec>
    // Skipping as we can set `normalized_integrity_map` directly.

    // <spec label="normalize-a-module-integrity-map" step="2">For each
    // integrity → hash,</spec>
    for (wtf_size_t i = 0; i < integrity->size(); ++i) {
      const JSONObject::Entry& entry = integrity->at(i);

      // <spec label="normalize-a-module-integrity-map" step="2.1">
      // Let normalizedSpecifierKey be the result of resolving a URL-like module
      // specifier given specifierKey and baseURL. integrity → hash,</spec>
      ParsedSpecifier parsed_specifier =
          ParsedSpecifier::Create(entry.first, base_url);
      KURL resolved_url = parsed_specifier.GetUrl();

      // <spec label="normalize-a-module-integrity-map" step="2.2">
      // If normalizedSpecifierKey is null, then continue.
      if (resolved_url.IsNull()) {
        AddIgnoredValueMessage(
            context, entry.first,
            "Integrity key is not a valid absolute URL or relative URL "
            "starting with '/', './', or '../'");
        continue;
      }

      // <spec label="normalize-a-module-integrity-map" step="2.3">
      // If value is not a string, then continue.</spec>
      if (entry.second->GetType() != JSONValue::ValueType::kTypeString) {
        AddIgnoredValueMessage(context, entry.first,
                               "Integrity value is not a string.");
        continue;
      }

      // <spec label="normalize-a-module-integrity-map" step="2.4">
      // Set normalized[resolvedURL] to value.</spec>
      // Here we also turn the string into IntegrityMetadataSet.
      String value_string;
      if (integrity->GetString(entry.first, &value_string)) {
        normalized_integrity_map.Set(resolved_url, value_string);
      } else {
        AddIgnoredValueMessage(context, entry.first,
                               "Internal error in GetString().");
      }
    }
  }

  // TODO(hiroshige): Implement Step 9.
  // <spec step="9"> If parsed's keys contains any items besides "imports",
  // "scopes" and "integrity", then the user agent should report a warning to
  // the console indicating that an invalid top-level key was present in the
  // import map.</spec>

  // <spec step="10">Return the import map whose imports are
  // sortedAndNormalizedImports and whose scopes scopes are
  // sortedAndNormalizedScopes.</spec>
  return MakeGarbageCollected<ImportMap>(
      std::move(sorted_and_normalized_imports),
      std::move(normalized_scopes_map), std::move(normalized_integrity_map));
}

// <specdef
// href="https://html.spec.whatwg.org/C#sorting-and-normalizing-a-module-specifier-map">
ImportMap::SpecifierMap ImportMap::SortAndNormalizeSpecifierMap(
    const JSONObject* imports,
    const KURL& base_url,
    ConsoleLogger& logger) {
  // <spec step="1">Let normalized be an empty map.</spec>
  SpecifierMap normalized;

  // <spec step="2">For each specifierKey → value of originalMap,</spec>
  for (wtf_size_t i = 0; i < imports->size(); ++i) {
    const JSONObject::Entry& entry = imports->at(i);

    // <spec step="2.1">Let normalizedSpecifierKey be the result of normalizing
    // a specifier key given specifierKey and baseURL.</spec>
    const AtomicString normalized_specifier_key =
        NormalizeSpecifierKey(entry.first, base_url, logger);

    // <spec step="2.2">If normalizedSpecifierKey is null, then continue.</spec>
    if (normalized_specifier_key.empty())
      continue;

    switch (entry.second->GetType()) {
      case JSONValue::ValueType::kTypeString: {
        // Steps 2.4-2.6 are implemented in NormalizeValue().
        String value_string;
        if (!imports->GetString(entry.first, &value_string)) {
          AddIgnoredValueMessage(logger, entry.first,
                                 "Internal error in GetString().");
          normalized.Set(normalized_specifier_key, NullURL());
          break;
        }

        normalized.Set(
            normalized_specifier_key,
            NormalizeValue(entry.first, value_string, base_url, logger));
        break;
      }

      case JSONValue::ValueType::kTypeNull:
      case JSONValue::ValueType::kTypeBoolean:
      case JSONValue::ValueType::kTypeInteger:
      case JSONValue::ValueType::kTypeDouble:
      case JSONValue::ValueType::kTypeObject:
      case JSONValue::ValueType::kTypeArray:
        // <spec step="2.3">If value is not a string, then:</spec>
        //
        // <spec step="2.3.1">Report a warning to the console that addresses
        // must be strings.</spec>
        AddIgnoredValueMessage(logger, entry.first, "Invalid value type.");

        // <spec step="2.3.2">Set normalized[specifierKey] to null.</spec>
        normalized.Set(normalized_specifier_key, NullURL());

        // <spec step="2.3.3">Continue.</spec>
        break;
    }

  }

  return normalized;
}

// <specdef href="https://html.spec.whatwg.org/C#resolving-an-imports-match">
std::optional<ImportMap::MatchResult> ImportMap::MatchPrefix(
    const ParsedSpecifier& parsed_specifier,
    const SpecifierMap& specifier_map) const {
  const String key = parsed_specifier.GetImportMapKeyString();

  // Prefix match, i.e. "Packages" via trailing slashes.
  // https://github.com/WICG/import-maps#packages-via-trailing-slashes
  //
  // TODO(hiroshige): optimize this if necessary. See
  // https://github.com/WICG/import-maps/issues/73#issuecomment-439327758
  // for some candidate implementations.

  // "most-specific wins", i.e. when there are multiple matching keys,
  // choose the longest.
  // https://github.com/WICG/import-maps/issues/102
  std::optional<MatchResult> best_match;

  // <spec step="1">For each specifierKey → resolutionResult of
  // specifierMap,</spec>
  for (auto it = specifier_map.begin(); it != specifier_map.end(); ++it) {
    // <spec step="1.2">If specifierKey ends with U+002F (/) and
    // normalizedSpecifier starts with specifierKey, then:</spec>
    if (!it->key.EndsWith('/'))
      continue;

    if (!key.StartsWith(it->key))
      continue;

    // https://wicg.github.io/import-maps/#longer-or-code-unit-less-than
    // We omit code unit comparison, because there can be at most one
    // prefix-matching entry with the same length.
    if (best_match && it->key.length() < (*best_match)->key.length())
      continue;

    best_match = it;
  }
  return best_match;
}

ImportMap::ImportMap() = default;

ImportMap::ImportMap(SpecifierMap&& imports,
                     ScopesMap&& scopes_map,
                     IntegrityMap&& integrity)
    : imports_(std::move(imports)),
      scopes_map_(std::move(scopes_map)),
      integrity_(std::move(integrity)) {
  InitializeScopesVector();
}

// <specdef
// href="https://https://html.spec.whatwg.org/C#resolve-a-module-specifier">
std::optional<KURL> ImportMap::Resolve(const ParsedSpecifier& parsed_specifier,
                                       const KURL& base_url,
                                       String* debug_message) const {
  DCHECK(debug_message);

  // <spec step="8">For each scopePrefix → scopeImports of importMap’s
  // scopes,</spec>
  for (const auto& scope : scopes_vector_) {
    const auto& specifier_map = scopes_map_.at(scope);
    // <spec step="8.1">If scopePrefix is baseURLString, or if scopePrefix ends
    // with U+002F (/) and baseURLString starts with scopePrefix, then:</spec>
    if (scope == base_url.GetString() ||
        (scope.EndsWith("/") && base_url.GetString().StartsWith(scope))) {
      // <spec step="8.1.1">Let scopeImportsMatch be the result of resolving an
      // imports match given normalizedSpecifier and scopeImports.</spec>
      std::optional<KURL> scope_match =
          ResolveImportsMatch(parsed_specifier, specifier_map, debug_message);

      // <spec step="8.1.2">If scopeImportsMatch is not null, then return
      // scopeImportsMatch.</spec>
      if (scope_match)
        return scope_match;
    }
  }

  // <spec step="9">Let topLevelImportsMatch be the result of resolving an
  // imports match given normalizedSpecifier and importMap’s imports.</spec>
  //
  // <spec step="10">If topLevelImportsMatch is not null, then return
  // topLevelImportsMatch.</spec>
  return ResolveImportsMatch(parsed_specifier, imports_, debug_message);
}

// <specdef href="https://html.spec.whatwg.org/C#resolving-an-imports-match">
std::optional<KURL> ImportMap::ResolveImportsMatch(
    const ParsedSpecifier& parsed_specifier,
    const SpecifierMap& specifier_map,
    String* debug_message) const {
  DCHECK(debug_message);
  const AtomicString key = parsed_specifier.GetImportMapKeyString();

  // <spec step="1.1">If specifierKey is normalizedSpecifier, then:</spec>
  MatchResult exact = specifier_map.find(key);
  if (exact != specifier_map.end()) {
    return ResolveImportsMatchInternal(key, exact, debug_message);
  }

  // <spec step="1.2">... either asURL is null, or asURL is special</spec>
  if (parsed_specifier.GetType() == ParsedSpecifier::Type::kURL &&
      !SchemeRegistry::IsSpecialScheme(parsed_specifier.GetUrl().Protocol())) {
    *debug_message = "Import Map: \"" + key +
                     "\" skips prefix match because of non-special URL scheme";

    return std::nullopt;
  }

  // Step 1.2.
  if (auto prefix_match = MatchPrefix(parsed_specifier, specifier_map)) {
    return ResolveImportsMatchInternal(key, *prefix_match, debug_message);
  }

  // <spec step="2">Return null.</spec>
  *debug_message = "Import Map: \"" + key +
                   "\" matches with no entries and thus is not mapped.";
  return std::nullopt;
}

// <specdef href="https://html.spec.whatwg.org/C#resolving-an-imports-match">
KURL ImportMap::ResolveImportsMatchInternal(const String& key,
                                            const MatchResult& matched,
                                            String* debug_message) const {
  // <spec step="1.2.3">Let afterPrefix be the portion of normalizedSpecifier
  // after the initial specifierKey prefix.</spec>
  const String after_prefix = key.Substring(matched->key.length());

  // <spec step="1.1.1">If resolutionResult is null, then throw a TypeError
  // indicating that resolution of specifierKey was blocked by a null
  // entry.</spec>
  //
  // <spec step="1.2.1">If resolutionResult is null, then throw a TypeError
  // indicating that resolution of specifierKey was blocked by a null
  // entry.</spec>
  if (!matched->value.IsValid()) {
    *debug_message = "Import Map: \"" + key + "\" matches with \"" +
                     matched->key + "\" but is blocked by a null value";
    return NullURL();
  }

  // <spec step="1.1">If specifierKey is normalizedSpecifier, then:</spec>
  //
  // <spec step="1.2">If specifierKey ends with U+002F (/) and
  // normalizedSpecifier starts with specifierKey, then:</spec>
  //
  // <spec step="1.2.5">Let url be the result of parsing afterPrefix relative
  // to the base URL resolutionResult.</spec>
  const KURL url = after_prefix.empty() ? matched->value
                                        : KURL(matched->value, after_prefix);

  // <spec step="1.2.6">If url is failure, then throw a TypeError indicating
  // that resolution of specifierKey was blocked due to a URL parse
  // failure.</spec>
  if (!url.IsValid()) {
    *debug_message = "Import Map: \"" + key + "\" matches with \"" +
                     matched->key +
                     "\" but is blocked due to relative URL parse failure";
    return NullURL();
  }

  // <spec step="1.2.8">If the serialization of url does not start with the
  // serialization of resolutionResult, then throw a TypeError indicating that
  // resolution of normalizedSpecifier was blocked due to it backtracking above
  // its prefix specifierKey.</spec>
  if (!url.GetString().StartsWith(matched->value.GetString())) {
    *debug_message = "Import Map: \"" + key + "\" matches with \"" +
                     matched->key + "\" but is blocked due to backtracking";
    return NullURL();
  }

  // <spec step="1.2.9">Return url.</spec>
  *debug_message = "Import Map: \"" + key + "\" matches with \"" +
                   matched->key + "\" and is mapped to " + url.ElidedString();
  return url;
}

String ImportMap::ToStringForTesting() const {
  StringBuilder builder;
  builder.Append("{\"imports\":");
  SpecifierMapToStringForTesting(builder, imports_);

  builder.Append(",\"scopes\":{");

  bool is_first = true;
  for (const auto& scope : scopes_vector_) {
    const auto& specifier_map = scopes_map_.at(scope);
    if (!is_first) {
      builder.Append(",");
    }
    is_first = false;
    builder.Append(scope.GetString().EncodeForDebugging());
    builder.Append(":");
    SpecifierMapToStringForTesting(builder, specifier_map);
  }

  builder.Append("},\"integrity\": {");

  is_first = true;
  for (const auto& it : integrity_) {
    if (!is_first) {
      builder.Append(",");
    }
    is_first = false;
    builder.Append("\"");
    builder.Append(it.key.GetString());
    builder.Append("\"");
    builder.Append(":");
    builder.Append("\"");
    builder.Append(it.value);
    builder.Append("\"");
  }

  builder.Append("}}");

  return builder.ToString();
}

String ImportMap::ResolveIntegrity(const KURL& module_url) const {
  IntegrityMap::const_iterator it = integrity_.find(module_url);
  return it != integrity_.end() ? it->value : String();
}

// https://html.spec.whatwg.org/C/#merge-existing-and-new-import-maps
void ImportMap::MergeExistingAndNewImportMaps(
    ImportMap* new_import_map,
    const HashMap<AtomicString, HashSet<AtomicString>>&
        scoped_resolved_module_map,
    const HashSet<AtomicString>& toplevel_resolved_module_set,
    ConsoleLogger& logger) {
  // 1. Let newImportMapScopes be a deep copy of newImportMap's scopes.
  // 2. Let newImportMapImports be a deep copy of newImportMap's imports.
  //
  // Instead of copying we have moved the new_import_map here and are performing
  // the algorithm's mutations directly on them. That's fine because the move
  // guarantees that no one will use this map for anything else.
  ImportMap::ScopesMap& new_import_map_scopes = new_import_map->scopes_map_;
  ImportMap::SpecifierMap& new_import_map_imports = new_import_map->imports_;
  ImportMap::IntegrityMap& new_import_map_integrity =
      new_import_map->integrity_;

  // 3. For each scopePrefix → scopeImports of newImportMapScopes:
  for (auto scope : new_import_map_scopes) {
    ImportMap::SpecifierMap& scope_imports = scope.value;
    // 3.1. For each pair of global's resolved module set:
    //
    // 3.1.1. If pair's referring script does not start with scopePrefix,
    // continue.
    //
    // 3.1.2. For each specifier → url of scopeImports:
    //
    // 3.1.2.1. If pair's specifier starts with specifier, then:
    //
    //
    // We are using a different algorithm here, where instead of a resolved
    // module set, we have a scoped resolved module map. The map's keys are
    // scope prefixes, and its values are a set of specifier prefixes that
    // already exist in that scope. We grab the set of specifier prefixes using
    // the current scope and then iterate over the scope's imports, removing any
    // specifiers whose prefix is in the set.
    const auto& current_set_it = scoped_resolved_module_map.find(scope.key);
    if (current_set_it != scoped_resolved_module_map.end()) {
      const auto current_resolved_set = current_set_it->value;
      Vector<AtomicString> specifiers_to_remove;
      for (auto specifier : scope_imports.Keys()) {
        if (current_resolved_set.find(specifier) !=
            current_resolved_set.end()) {
          specifiers_to_remove.push_back(specifier);
        }
      }
      for (auto specifier : specifiers_to_remove) {
        // 3.1.2.1.1. The user agent may report the removed rule as a warning to
        // the developer console.
        auto* message = MakeGarbageCollected<ConsoleMessage>(
            ConsoleMessage::Source::kJavaScript,
            ConsoleMessage::Level::kWarning,
            "An import map scope rule for specifier '" + specifier +
                "' was removed, as it conflicted with already resolved module "
                "specifiers.");
        logger.AddConsoleMessage(message, /*discard_duplicates=*/true);
        // 3.1.2.1.2. Remove scopeImports[specifier].
        scope_imports.erase(specifier);
      }
    }

    // 3.2 If scopePrefix exists in oldImportMap's scopes, then set
    // oldImportMap's scopes[scopePrefix] to the result of merging module
    // specifier maps, given scopeImports and oldImportMap's
    // scopes[scopePrefix].
    const auto old_scope_specifier_map_it = scopes_map_.find(scope.key);
    if (old_scope_specifier_map_it != scopes_map_.end()) {
      ImportMap::SpecifierMap& old_scope_specifier_map =
          old_scope_specifier_map_it->value;
      MergeModuleSpecifierMaps(old_scope_specifier_map, scope_imports, logger);
    } else {
      // 3.3 Otherwise, set oldImportMap's scopes[scopePrefix] to
      // scopeImports.
      scopes_map_.insert(scope.key, scope_imports);
      scopes_vector_.push_back(scope.key);
    }
  }

  // 4. For each url → integrity of newImportMap's integrity:
  for (auto url : new_import_map_integrity.Keys()) {
    auto new_integrity_value = new_import_map_integrity.at(url);
    // 4.1 If url exists in oldImportMap's integrity, then:
    if (integrity_.Contains(url)) {
      // 4.1.1. The user agent may report the removed rule as a warning to the
      // developer console.
      auto* message = MakeGarbageCollected<ConsoleMessage>(
          ConsoleMessage::Source::kJavaScript, ConsoleMessage::Level::kWarning,
          "An import map integrity rule for url '" + url.GetString() +
              "' was removed, as it conflicted with already defined integrity "
              "rules.");
      logger.AddConsoleMessage(message, /*discard_duplicates=*/true);
      // 4.1.2 Continue.
      continue;
    }
    // 4.2 Set oldImportMap's integrity[url] to integrity.
    integrity_.insert(url, new_integrity_value);
  }
  // 5. For each pair of global's resolved module set:

  // 5.1. For each specifier → url of newImportMapImports:
```