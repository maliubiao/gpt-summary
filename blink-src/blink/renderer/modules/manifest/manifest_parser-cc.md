Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. They are particularly interested in:

1. **Core Functionality:** What does this code do?
2. **Relationship to Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logic and Data Flow:**  Can I infer the input and output of specific operations?
4. **Potential Errors:** What common mistakes might users or developers make?
5. **Debugging Context:** How does a user's action lead to this code being executed?
6. **Summary (for Part 1):** A concise overview of the code's purpose based on the provided snippet.

**Plan:**

1. **High-Level Function:** Identify the primary goal of `manifest_parser.cc`. The name strongly suggests it's responsible for parsing web app manifest files.
2. **Key Components:**  Look for data structures and function calls that reveal the parsing process. The use of JSON parsing and the `mojom::blink::Manifest` structure are key indicators.
3. **Web Technology Integration:** Analyze how the parsed manifest data relates to HTML (linking the manifest), CSS (styling based on manifest properties like theme color), and JavaScript (accessing manifest data via APIs).
4. **Input/Output Analysis:** Examine functions like `ParseStartURL`, `ParseId`, `ParseScope`, etc., and infer the expected input (JSON data) and output (corresponding `mojom::blink::Manifest` fields).
5. **Error Handling:** Identify patterns of error checking and reporting (e.g., `AddErrorInfo`). Consider common manifest errors (invalid URLs, incorrect data types, etc.).
6. **User Interaction:**  Think about the steps a user takes that would trigger manifest parsing (e.g., navigating to a webpage with a manifest link).
7. **Synthesize Part 1 Summary:** Condense the findings into a concise description of the code's role.
```
这是目录为blink/renderer/modules/manifest/manifest_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

**blink/renderer/modules/manifest/manifest_parser.cc 的功能：**

1. **解析 Web App Manifest 文件:**  该文件的核心功能是解析 Web App Manifest 文件。Manifest 文件是一个 JSON 文件，用于描述 Web 应用程序的元数据，例如名称、图标、启动 URL、显示模式等。

2. **将 JSON 数据转换为内部数据结构:**  解析过程会将 Manifest 文件中的 JSON 数据读取并转换为 Blink 引擎内部使用的 `mojom::blink::Manifest` 数据结构。这个数据结构包含了 Manifest 文件中定义的各种属性。

3. **验证 Manifest 文件的内容:**  在解析过程中，代码会对 Manifest 文件中的各种属性进行验证，例如：
    * **URL 的有效性:** 检查 `start_url`, `scope`, `icons` 等属性中的 URL 是否有效。
    * **数据类型:** 确保属性的值是期望的数据类型（字符串、数组、布尔值等）。
    * **枚举值的合法性:**  例如，`display` 属性的值是否是预定义的显示模式之一。
    * **大小限制:** 检查某些数组（如 `url_handlers`, `scope_extensions`, `shortcuts`）的大小是否超过限制。
    * **MIME 类型:** 验证文件处理 API 中指定的 MIME 类型是否合法。

4. **处理 Manifest 文件中的各种属性:**  代码包含了针对 Manifest 文件中各种属性的解析逻辑，例如：
    * `name`, `short_name`, `description`:  解析应用的名称、短名称和描述。
    * `start_url`: 解析应用的启动 URL。
    * `scope`: 解析应用的导航范围。
    * `display`: 解析应用的显示模式（`fullscreen`, `standalone`, `minimal-ui`, `browser`）。
    * `icons`: 解析应用的图标信息，包括 URL、大小和类型。
    * `screenshots`: 解析应用的屏幕截图信息。
    * `share_target`: 解析应用作为共享目标的信息。
    * `protocol_handlers`: 解析应用可以处理的协议。
    * `url_handlers`: 解析应用可以处理的 URL 模式。
    * `scope_extensions`: 解析扩展应用导航范围的 URL 模式。
    * `file_handlers`: 解析应用可以处理的文件类型。
    * 等等。

5. **记录解析过程中的错误:**  如果 Manifest 文件中存在错误或不符合规范的地方，代码会生成错误信息并存储在 `errors_` 成员变量中。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**
    * **`<link rel="manifest" href="manifest.json">`:** HTML 文件通过 `<link>` 标签声明 Manifest 文件。浏览器会加载并解析此文件。`manifest_parser.cc` 就负责解析这个 `manifest.json` 文件。
    * **启动 URL:** Manifest 中的 `start_url` 定义了 Web 应用启动时加载的 HTML 页面。

* **JavaScript:**
    * **`navigator.mozApps.install(manifestURL)` (已废弃):**  早期安装 PWA 的 JavaScript API 会使用 Manifest URL。
    * **Web App Manifest API (未来可能存在):**  虽然目前没有直接的 JavaScript API 来获取已解析的 Manifest 对象，但浏览器内部解析的 Manifest 数据会被用于支持各种 Web Platform 功能，未来可能提供相关的 JavaScript API。

* **CSS:**
    * **`theme_color`:** Manifest 中的 `theme_color` 属性可以定义 Web 应用的颜色主题，浏览器可能会使用这个颜色来设置浏览器工具栏或操作系统的界面元素颜色。
    * **`background_color`:** Manifest 中的 `background_color` 属性可以定义在 Web 应用加载时或作为占位符显示的背景颜色。

**逻辑推理（假设输入与输出）：**

**假设输入：** 以下是一个简单的 `manifest.json` 文件内容：

```json
{
  "name": "My Awesome App",
  "short_name": "Awesome App",
  "start_url": "/index.html",
  "display": "standalone",
  "icons": [
    {
      "src": "/images/icon-192x192.png",
      "sizes": "192x192",
      "type": "image/png"
    }
  ]
}
```

**假设输出：** `ManifestParser` 解析后生成的 `mojom::blink::Manifest` 对象将包含以下信息（部分）：

* `manifest_url`:  指向 `manifest.json` 文件的 URL。
* `name`: "My Awesome App"
* `short_name`: "Awesome App"
* `start_url`:  指向 `/index.html` 的完整 URL (相对于 Manifest 文件的 URL)。
* `display`: `mojom::blink::DisplayMode::kStandalone`
* `icons`:  一个包含一个 `mojom::blink::ManifestImageResource` 对象的 Vector，该对象包含：
    * `src`: 指向 `/images/icon-192x192.png` 的完整 URL。
    * `sizes`: 一个包含 `gfx::Size(192, 192)` 的 Vector。
    * `type`: "image/png"。

**用户或编程常见的使用错误：**

1. **JSON 格式错误:** Manifest 文件必须是有效的 JSON。例如，缺少引号、逗号或大括号未闭合。
    * **错误示例:**
      ```json
      {
        name: "My App" // 缺少引号
      }
      ```
    * **`manifest_parser.cc` 会报告类似 "root element must be a valid JSON object." 的错误。**

2. **无效的 URL:** `start_url`, `scope`, `icons` 等属性中的 URL 可能拼写错误或指向不存在的资源。
    * **错误示例:**
      ```json
      {
        "start_url": "invalidadress"
      }
      ```
    * **`manifest_parser.cc` 会报告类似 "property 'start_url' ignored, URL is invalid." 的错误。**

3. **`display` 属性值错误:**  `display` 属性的值必须是预定义的字符串之一 (`fullscreen`, `standalone`, `minimal-ui`, `browser`)。
    * **错误示例:**
      ```json
      {
        "display": "new-window"
      }
      ```
    * **`manifest_parser.cc` 会报告类似 "unknown 'display' value ignored." 的错误。**

4. **`icons` 属性中的 `sizes` 格式错误:** `sizes` 属性的值应该是一个以空格分隔的尺寸列表，例如 "192x192 512x512"。
    * **错误示例:**
      ```json
      {
        "icons": [
          {
            "src": "/icon.png",
            "sizes": "invalid-size"
          }
        ]
      }
      ```
    * **`manifest_parser.cc` 会报告类似 "found icon with no valid size." 的错误。**

5. **`scope` 超出限制:** `start_url` 必须在 `scope` 的范围内。
    * **错误示例:**
      ```json
      {
        "start_url": "/app/",
        "scope": "/other/"
      }
      ```
    * **`manifest_parser.cc` 会报告类似 "property 'scope' ignored. Start url should be within scope of scope URL." 的错误。**

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中输入网址或点击链接导航到一个网页。**
2. **浏览器加载该网页的 HTML 内容。**
3. **浏览器解析 HTML 内容，并找到 `<link rel="manifest" href="manifest.json">` 标签。**
4. **浏览器发起对 `manifest.json` 文件的网络请求。**
5. **一旦 `manifest.json` 文件下载完成，Blink 渲染引擎会接收到文件内容。**
6. **Blink 渲染引擎会创建 `ManifestParser` 对象，并将 `manifest.json` 的内容、文件 URL 和文档 URL 传递给它。**
7. **调用 `ManifestParser::Parse()` 方法开始解析过程。**
8. **在解析过程中，`manifest_parser.cc` 中的代码会被逐步执行，读取 JSON 数据，进行验证，并填充 `mojom::blink::Manifest` 对象。**
9. **如果解析过程中发现错误，错误信息会被记录。**
10. **解析完成后，`mojom::blink::Manifest` 对象会被传递给 Blink 引擎的其他组件，用于实现 PWA 的各种功能。**

**归纳一下它的功能 (第 1 部分)：**

`manifest_parser.cc` 文件的主要功能是**解析 Web App Manifest 文件**，将 Manifest 文件中的 JSON 数据转换为 Blink 引擎内部使用的 `mojom::blink::Manifest` 数据结构，并对 Manifest 文件中的各种属性进行**验证**，同时记录解析过程中遇到的**错误**。这是浏览器理解和处理 Web App Manifest 的关键步骤，为后续 PWA 功能的实现提供了必要的数据基础。

Prompt: 
```
这是目录为blink/renderer/modules/manifest/manifest_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/manifest/manifest_parser.h"

#include <string>

#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "net/base/mime_util.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/manifest/manifest.h"
#include "third_party/blink/public/common/manifest/manifest_util.h"
#include "third_party/blink/public/common/mime_util/mime_util.h"
#include "third_party/blink/public/common/permissions_policy/origin_with_possible_wildcards.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/common/safe_url_pattern.h"
#include "third_party/blink/public/common/security/protocol_handler_security_level.h"
#include "third_party/blink/public/mojom/manifest/manifest.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/manifest/manifest.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/url_conversion.h"
#include "third_party/blink/public/platform/web_icon_sizes_parser.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/core/css/media_list.h"
#include "third_party/blink/renderer/core/css/media_query_evaluator.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/media_values_cached.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.h"
#include "third_party/blink/renderer/modules/navigatorcontentutils/navigator_content_utils.h"
#include "third_party/blink/renderer/platform/json/json_parser.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/liburlpattern/parse.h"
#include "third_party/liburlpattern/pattern.h"
#include "third_party/liburlpattern/utils.h"
#include "url/gurl.h"
#include "url/url_constants.h"
#include "url/url_util.h"

namespace blink {

namespace {

static constexpr char kOriginWildcardPrefix[] = "%2A.";
// Keep in sync with web_app_origin_association_task.cc.
static wtf_size_t kMaxUrlHandlersSize = 10;
static wtf_size_t kMaxScopeExtensionsSize = 10;
static wtf_size_t kMaxShortcutsSize = 10;
static wtf_size_t kMaxOriginLength = 2000;

// The max number of file extensions an app can handle via the File Handling
// API.
const int kFileHandlerExtensionLimit = 300;
int g_file_handler_extension_limit_for_testing = 0;

bool IsValidMimeType(const String& mime_type) {
  if (mime_type.StartsWith('.')) {
    return true;
  }
  return net::ParseMimeTypeWithoutParameter(mime_type.Utf8(), nullptr, nullptr);
}

bool VerifyFiles(const Vector<mojom::blink::ManifestFileFilterPtr>& files) {
  for (const auto& file : files) {
    for (const auto& accept_type : file->accept) {
      if (!IsValidMimeType(accept_type.LowerASCII())) {
        return false;
      }
    }
  }
  return true;
}

// Determines whether |url| is within scope of |scope|.
bool URLIsWithinScope(const KURL& url, const KURL& scope) {
  return SecurityOrigin::AreSameOrigin(url, scope) &&
         url.GetPath().ToString().StartsWith(scope.GetPath());
}

bool IsHostValidForScopeExtension(String host) {
  if (url::HostIsIPAddress(host.Utf8())) {
    return true;
  }

  const size_t registry_length =
      net::registry_controlled_domains::PermissiveGetHostRegistryLength(
          host.Utf8(),
          // Reject unknown registries (registries that don't have any matches
          // in effective TLD names).
          net::registry_controlled_domains::EXCLUDE_UNKNOWN_REGISTRIES,
          // Skip matching private registries that allow external users to
          // specify sub-domains, e.g. glitch.me, as this is allowed.
          net::registry_controlled_domains::EXCLUDE_PRIVATE_REGISTRIES);

  // Host cannot be a TLD or invalid.
  if (registry_length == 0 || registry_length == std::string::npos ||
      registry_length >= host.length()) {
    return false;
  }

  return true;
}

static bool IsCrLfOrTabChar(UChar c) {
  return c == '\n' || c == '\r' || c == '\t';
}

std::optional<mojom::blink::ManifestFileHandler::LaunchType>
FileHandlerLaunchTypeFromString(const std::string& launch_type) {
  if (WTF::EqualIgnoringASCIICase(String(launch_type), "single-client")) {
    return mojom::blink::ManifestFileHandler::LaunchType::kSingleClient;
  }
  if (WTF::EqualIgnoringASCIICase(String(launch_type), "multiple-clients")) {
    return mojom::blink::ManifestFileHandler::LaunchType::kMultipleClients;
  }
  return std::nullopt;
}

bool IsDefaultManifest(const mojom::blink::Manifest& manifest,
                       const KURL& document_url) {
  if (manifest.has_custom_id || manifest.has_valid_specified_start_url) {
    return false;
  }
  auto default_manifest = mojom::blink::Manifest::New();
  default_manifest->start_url = document_url;
  KURL default_id = document_url;
  default_id.RemoveFragmentIdentifier();
  default_manifest->id = default_id;
  default_manifest->scope = KURL(document_url.BaseAsString().ToString());
  return manifest == *default_manifest;
}

static const char kUMAIdParseResult[] = "Manifest.ParseIdResult";

// Record that the Manifest was successfully parsed. If it is a default
// Manifest, it will recorded as so and nothing will happen. Otherwise, the
// presence of each properties will be recorded.
void ParseSucceeded(const mojom::blink::ManifestPtr& manifest,
                    const KURL& document_url) {
  if (IsDefaultManifest(*manifest, document_url)) {
    return;
  }

  base::UmaHistogramBoolean("Manifest.HasProperty.name",
                            !manifest->name.empty());
  base::UmaHistogramBoolean("Manifest.HasProperty.short_name",
                            !manifest->short_name.empty());
  base::UmaHistogramBoolean("Manifest.HasProperty.description",
                            !manifest->description.empty());
  base::UmaHistogramBoolean("Manifest.HasProperty.start_url",
                            !manifest->start_url.IsEmpty());
  base::UmaHistogramBoolean(
      "Manifest.HasProperty.display",
      manifest->display != blink::mojom::DisplayMode::kUndefined);
  base::UmaHistogramBoolean(
      "Manifest.HasProperty.orientation",
      manifest->orientation !=
          device::mojom::blink::ScreenOrientationLockType::DEFAULT);
  base::UmaHistogramBoolean("Manifest.HasProperty.icons",
                            !manifest->icons.empty());
  base::UmaHistogramBoolean("Manifest.HasProperty.screenshots",
                            !manifest->screenshots.empty());
  base::UmaHistogramBoolean("Manifest.HasProperty.share_target",
                            manifest->share_target.get());
  base::UmaHistogramBoolean("Manifest.HasProperty.protocol_handlers",
                            !manifest->protocol_handlers.empty());
  base::UmaHistogramBoolean("Manifest.HasProperty.gcm_sender_id",
                            !manifest->gcm_sender_id.empty());
}

// Returns a liburlpattern::Part list obtained from running
// liburlpattern::Parse on a UrlPatternInit field. The list will be empty if the
// field is empty. Returns std::nullopt if the field should be rejected or the
// parse failed, e.g. if it contains custom (or ill-formed) regex.
std::optional<std::vector<liburlpattern::Part>> ParsePatternInitField(
    const std::optional<String>& field,
    const String default_field_value) {
  const String value = field.has_value() ? field.value() : default_field_value;
  if (value.empty()) {
    return std::vector<liburlpattern::Part>();
  }

  StringUTF8Adaptor utf8(value);
  auto parse_result = liburlpattern::Parse(
      utf8.AsStringView(),
      [](std::string_view input) { return std::string(input); });

  if (parse_result.ok()) {
    std::vector<liburlpattern::Part> part_list;
    for (auto& part : parse_result.value().PartList()) {
      // We don't allow custom regex for security reasons as this will be
      // used in the browser process.
      if (part.type == liburlpattern::PartType::kRegex) {
        return std::nullopt;
      }

      part_list.push_back(std::move(part));
    }
    return part_list;
  }
  return std::nullopt;
}

String EscapePatternString(const StringView& input) {
  std::string result;
  result.reserve(input.length());
  StringUTF8Adaptor utf8(input);
  liburlpattern::EscapePatternStringAndAppend(utf8.AsStringView(), result);
  return String(result);
}

// Utility function to determine if a pathname is absolute or not. We do some
// additional checking for escaped or grouped slashes.
//
// Note: This is partially copied from
// third_party/blink/renderer/core/url_pattern/url_pattern.cc
bool IsAbsolutePathname(String pathname) {
  if (pathname.empty()) {
    return false;
  }

  if (pathname[0] == '/') {
    return true;
  }

  if (pathname.length() < 2) {
    return false;
  }

  // Patterns treat escaped slashes and slashes within an explicit grouping as
  // valid leading slashes.  For example, "\/foo" or "{/foo}".  Patterns do
  // not consider slashes within a custom regexp group as valid for the leading
  // pathname slash for now.  To support that we would need to be able to
  // detect things like ":name_123(/foo)" as a valid leading group in a pattern,
  // but that is considered too complex for now.
  if ((pathname[0] == '\\' || pathname[0] == '{') && pathname[1] == '/') {
    return true;
  }

  return false;
}

String ResolveRelativePathnamePattern(const KURL& base_url, String pathname) {
  if (base_url.IsStandard() && !IsAbsolutePathname(pathname)) {
    String base_path = EscapePatternString(base_url.GetPath());
    auto slash_index = base_path.ReverseFind('/');
    if (slash_index != WTF::kNotFound) {
      // Extract the base_url path up to and including the last slash. Append
      // the relative pathname to it.
      base_path.Truncate(slash_index + 1);
      base_path = base_path + pathname;
      return base_path;
    }
  }
  return pathname;
}

}  // anonymous namespace

ManifestParser::ManifestParser(const String& data,
                               const KURL& manifest_url,
                               const KURL& document_url,
                               ExecutionContext* execution_context)
    : data_(data),
      manifest_url_(manifest_url),
      document_url_(document_url),
      execution_context_(execution_context),
      failed_(false) {}

ManifestParser::~ManifestParser() {}

// static
void ManifestParser::SetFileHandlerExtensionLimitForTesting(int limit) {
  g_file_handler_extension_limit_for_testing = limit;
}

bool ManifestParser::Parse() {
  DCHECK(!manifest_);

  // TODO(crbug.com/1264024): Deprecate JSON comments here, if possible.
  JSONParseError error;

  bool has_comments = false;
  std::unique_ptr<JSONValue> root =
      ParseJSONWithCommentsDeprecated(data_, &error, &has_comments);
  manifest_ = mojom::blink::Manifest::New();
  if (!root) {
    AddErrorInfo(error.message, true, error.line, error.column);
    failed_ = true;
    return false;
  }

  std::unique_ptr<JSONObject> root_object = JSONObject::From(std::move(root));
  if (!root_object) {
    AddErrorInfo("root element must be a valid JSON object.", true);
    failed_ = true;
    return false;
  }

  manifest_->manifest_url = manifest_url_;
  manifest_->dir = ParseDir(root_object.get());
  manifest_->name = ParseName(root_object.get());
  manifest_->short_name = ParseShortName(root_object.get());
  manifest_->description = ParseDescription(root_object.get());
  const auto& [start_url, start_url_parse_result] =
      ParseStartURL(root_object.get(), document_url_);
  manifest_->start_url = start_url;
  manifest_->has_valid_specified_start_url =
      start_url_parse_result == ParseStartUrlResult::kParsedFromJson;

  const auto& [id, id_parse_result] =
      ParseId(root_object.get(), manifest_->start_url);
  manifest_->id = id;
  manifest_->has_custom_id = id_parse_result == ParseIdResultType::kSucceed;

  manifest_->scope = ParseScope(root_object.get(), manifest_->start_url);
  manifest_->display = ParseDisplay(root_object.get());
  manifest_->display_override = ParseDisplayOverride(root_object.get());
  manifest_->orientation = ParseOrientation(root_object.get());
  manifest_->icons = ParseIcons(root_object.get());
  manifest_->screenshots = ParseScreenshots(root_object.get());

  auto share_target = ParseShareTarget(root_object.get());
  if (share_target.has_value()) {
    manifest_->share_target = std::move(*share_target);
  }

  manifest_->file_handlers = ParseFileHandlers(root_object.get());
  manifest_->protocol_handlers = ParseProtocolHandlers(root_object.get());
  manifest_->url_handlers = ParseUrlHandlers(root_object.get());
  manifest_->scope_extensions = ParseScopeExtensions(root_object.get());
  manifest_->lock_screen = ParseLockScreen(root_object.get());
  manifest_->note_taking = ParseNoteTaking(root_object.get());
  manifest_->related_applications = ParseRelatedApplications(root_object.get());
  manifest_->prefer_related_applications =
      ParsePreferRelatedApplications(root_object.get());

  std::optional<RGBA32> theme_color = ParseThemeColor(root_object.get());
  manifest_->has_theme_color = theme_color.has_value();
  if (manifest_->has_theme_color) {
    manifest_->theme_color = *theme_color;
  }

  std::optional<RGBA32> background_color =
      ParseBackgroundColor(root_object.get());
  manifest_->has_background_color = background_color.has_value();
  if (manifest_->has_background_color) {
    manifest_->background_color = *background_color;
  }

  manifest_->gcm_sender_id = ParseGCMSenderID(root_object.get());
  manifest_->shortcuts = ParseShortcuts(root_object.get());

  manifest_->permissions_policy =
      ParseIsolatedAppPermissions(root_object.get());

  manifest_->launch_handler = ParseLaunchHandler(root_object.get());

  if (RuntimeEnabledFeatures::WebAppTranslationsEnabled(execution_context_)) {
    manifest_->translations = ParseTranslations(root_object.get());
  }

  if (RuntimeEnabledFeatures::WebAppTabStripCustomizationsEnabled(
          execution_context_)) {
    manifest_->tab_strip = ParseTabStrip(root_object.get());
  }

  manifest_->version = ParseVersion(root_object.get());

  ParseSucceeded(manifest_, document_url_);
  base::UmaHistogramEnumeration(kUMAIdParseResult, id_parse_result);

  return has_comments;
}

mojom::blink::ManifestPtr ManifestParser::TakeManifest() {
  return std::move(manifest_);
}

void ManifestParser::TakeErrors(
    Vector<mojom::blink::ManifestErrorPtr>* errors) {
  errors->clear();
  errors->swap(errors_);
}

bool ManifestParser::failed() const {
  return failed_;
}

ManifestParser::PatternInit::PatternInit(std::optional<String> protocol,
                                         std::optional<String> username,
                                         std::optional<String> password,
                                         std::optional<String> hostname,
                                         std::optional<String> port,
                                         std::optional<String> pathname,
                                         std::optional<String> search,
                                         std::optional<String> hash,
                                         KURL base_url)
    : protocol(std::move(protocol)),
      username(std::move(username)),
      password(std::move(password)),
      hostname(std::move(hostname)),
      port(std::move(port)),
      pathname(std::move(pathname)),
      search(std::move(search)),
      hash(std::move(hash)),
      base_url(base_url) {}
ManifestParser::PatternInit::~PatternInit() = default;
ManifestParser::PatternInit::PatternInit(PatternInit&&) = default;
ManifestParser::PatternInit& ManifestParser::PatternInit::operator=(
    PatternInit&&) = default;

bool ManifestParser::PatternInit::IsAbsolute() const {
  return protocol.has_value() || hostname.has_value() || port.has_value();
}

bool ManifestParser::ParseBoolean(const JSONObject* object,
                                  const String& key,
                                  bool default_value) {
  JSONValue* json_value = object->Get(key);
  if (!json_value) {
    return default_value;
  }

  bool value;
  if (!json_value->AsBoolean(&value)) {
    AddErrorInfo("property '" + key + "' ignored, type " + "boolean expected.");
    return default_value;
  }

  return value;
}

std::optional<String> ManifestParser::ParseString(const JSONObject* object,
                                                  const String& key,
                                                  Trim trim) {
  JSONValue* json_value = object->Get(key);
  if (!json_value) {
    return std::nullopt;
  }

  String value;
  if (!json_value->AsString(&value) || value.IsNull()) {
    AddErrorInfo("property '" + key + "' ignored, type " + "string expected.");
    return std::nullopt;
  }

  if (trim) {
    value = value.StripWhiteSpace();
  }
  return value;
}

std::optional<String> ManifestParser::ParseStringForMember(
    const JSONObject* object,
    const String& member_name,
    const String& key,
    bool required,
    Trim trim) {
  JSONValue* json_value = object->Get(key);
  if (!json_value) {
    if (required) {
      AddErrorInfo("property '" + key + "' of '" + member_name +
                   "' not present.");
    }

    return std::nullopt;
  }

  String value;
  if (!json_value->AsString(&value)) {
    AddErrorInfo("property '" + key + "' of '" + member_name +
                 "' ignored, type string expected.");
    return std::nullopt;
  }
  if (trim) {
    value = value.StripWhiteSpace();
  }

  if (value == "") {
    AddErrorInfo("property '" + key + "' of '" + member_name +
                 "' is an empty string.");
    if (required) {
      return std::nullopt;
    }
  }

  return value;
}

std::optional<RGBA32> ManifestParser::ParseColor(const JSONObject* object,
                                                 const String& key) {
  std::optional<String> parsed_color = ParseString(object, key, Trim(true));
  if (!parsed_color.has_value()) {
    return std::nullopt;
  }

  Color color;
  if (!CSSParser::ParseColor(color, *parsed_color, true)) {
    AddErrorInfo("property '" + key + "' ignored, '" + *parsed_color +
                 "' is not a " + "valid color.");
    return std::nullopt;
  }

  return color.Rgb();
}

KURL ManifestParser::ParseURL(const JSONObject* object,
                              const String& key,
                              const KURL& base_url,
                              ParseURLRestrictions origin_restriction,
                              bool ignore_empty_string) {
  std::optional<String> url_str = ParseString(object, key, Trim(false));
  if (!url_str.has_value()) {
    return KURL();
  }
  if (ignore_empty_string && url_str.value() == "") {
    return KURL();
  }

  KURL resolved = KURL(base_url, *url_str);
  if (!resolved.IsValid()) {
    AddErrorInfo("property '" + key + "' ignored, URL is invalid.");
    return KURL();
  }

  switch (origin_restriction) {
    case ParseURLRestrictions::kNoRestrictions:
      return resolved;
    case ParseURLRestrictions::kSameOriginOnly:
      if (!SecurityOrigin::AreSameOrigin(resolved, document_url_)) {
        AddErrorInfo("property '" + key +
                     "' ignored, should be same origin as document.");
        return KURL();
      }
      return resolved;
    case ParseURLRestrictions::kWithinScope:
      if (!URLIsWithinScope(resolved, manifest_->scope)) {
        AddErrorInfo("property '" + key +
                     "' ignored, should be within scope of the manifest.");
        return KURL();
      }

      // Within scope implies same origin as document URL.
      DCHECK(SecurityOrigin::AreSameOrigin(resolved, document_url_));

      return resolved;
  }

  NOTREACHED();
}

template <typename Enum>
Enum ManifestParser::ParseFirstValidEnum(const JSONObject* object,
                                         const String& key,
                                         Enum (*parse_enum)(const std::string&),
                                         Enum invalid_value) {
  const JSONValue* value = object->Get(key);
  if (!value) {
    return invalid_value;
  }

  String string_value;
  if (value->AsString(&string_value)) {
    Enum enum_value = parse_enum(string_value.Utf8());
    if (enum_value == invalid_value) {
      AddErrorInfo(key + " value '" + string_value +
                   "' ignored, unknown value.");
    }
    return enum_value;
  }

  const JSONArray* list = JSONArray::Cast(value);
  if (!list) {
    AddErrorInfo("property '" + key +
                 "' ignored, type string or array of strings expected.");
    return invalid_value;
  }

  for (wtf_size_t i = 0; i < list->size(); ++i) {
    const JSONValue* item = list->at(i);
    if (!item->AsString(&string_value)) {
      AddErrorInfo(key + " value '" + item->ToJSONString() +
                   "' ignored, string expected.");
      continue;
    }

    Enum enum_value = parse_enum(string_value.Utf8());
    if (enum_value != invalid_value) {
      return enum_value;
    }

    AddErrorInfo(key + " value '" + string_value + "' ignored, unknown value.");
  }

  return invalid_value;
}

mojom::blink::Manifest::TextDirection ManifestParser::ParseDir(
    const JSONObject* object) {
  using TextDirection = mojom::blink::Manifest::TextDirection;

  std::optional<String> dir = ParseString(object, "dir", Trim(true));
  if (!dir.has_value()) {
    return TextDirection::kAuto;
  }

  std::optional<TextDirection> textDirection =
      TextDirectionFromString(dir->Utf8());
  if (!textDirection.has_value()) {
    AddErrorInfo("unknown 'dir' value ignored.");
    return TextDirection::kAuto;
  }

  return *textDirection;
}

String ManifestParser::ParseName(const JSONObject* object) {
  std::optional<String> name = ParseString(object, "name", Trim(true));
  if (name.has_value()) {
    name = name->RemoveCharacters(IsCrLfOrTabChar);
    if (name->length() == 0) {
      name = std::nullopt;
    }
  }
  return name.has_value() ? *name : String();
}

String ManifestParser::ParseShortName(const JSONObject* object) {
  std::optional<String> short_name =
      ParseString(object, "short_name", Trim(true));
  if (short_name.has_value()) {
    short_name = short_name->RemoveCharacters(IsCrLfOrTabChar);
    if (short_name->length() == 0) {
      short_name = std::nullopt;
    }
  }
  return short_name.has_value() ? *short_name : String();
}

String ManifestParser::ParseDescription(const JSONObject* object) {
  std::optional<String> description =
      ParseString(object, "description", Trim(true));
  return description.has_value() ? *description : String();
}

std::pair<KURL, ManifestParser::ParseIdResultType> ManifestParser::ParseId(
    const JSONObject* object,
    const KURL& start_url) {
  if (!start_url.IsValid()) {
    return {KURL(), ParseIdResultType::kInvalidStartUrl};
  }
  KURL start_url_origin = KURL(SecurityOrigin::Create(start_url)->ToString());

  KURL id = ParseURL(object, "id", start_url_origin,
                     ParseURLRestrictions::kSameOriginOnly,
                     /*ignore_empty_string=*/true);
  ParseIdResultType parse_result;
  if (id.IsValid()) {
    parse_result = ParseIdResultType::kSucceed;
  } else {
    // If id is not specified, sets to start_url
    parse_result = ParseIdResultType::kDefaultToStartUrl;
    id = start_url;
  }
  id.RemoveFragmentIdentifier();
  return {id, parse_result};
}

std::pair<KURL, ManifestParser::ParseStartUrlResult>
ManifestParser::ParseStartURL(const JSONObject* object,
                              const KURL& document_url) {
  KURL start_url = ParseURL(object, "start_url", manifest_url_,
                            ParseURLRestrictions::kSameOriginOnly);
  if (start_url.IsEmpty()) {
    return std::make_pair(document_url,
                          ParseStartUrlResult::kDefaultDocumentUrl);
  }
  return std::make_pair(start_url, ParseStartUrlResult::kParsedFromJson);
}

KURL ManifestParser::ParseScope(const JSONObject* object,
                                const KURL& start_url) {
  KURL scope = ParseURL(object, "scope", manifest_url_,
                        ParseURLRestrictions::kNoRestrictions);
  const KURL& default_value = start_url;
  DCHECK(default_value.IsValid());

  if (scope.IsEmpty()) {
    return KURL(default_value.BaseAsString().ToString());
  }

  if (!URLIsWithinScope(default_value, scope)) {
    AddErrorInfo(
        "property 'scope' ignored. Start url should be within scope "
        "of scope URL.");
    return KURL(default_value.BaseAsString().ToString());
  }

  scope.RemoveFragmentIdentifier();
  scope.SetQuery(String());

  DCHECK(scope.IsValid());
  DCHECK(SecurityOrigin::AreSameOrigin(scope, document_url_));
  return scope;
}

blink::mojom::DisplayMode ManifestParser::ParseDisplay(
    const JSONObject* object) {
  std::optional<String> display = ParseString(object, "display", Trim(true));
  if (!display.has_value()) {
    return blink::mojom::DisplayMode::kUndefined;
  }

  blink::mojom::DisplayMode display_enum =
      DisplayModeFromString(display->Utf8());

  if (display_enum == mojom::blink::DisplayMode::kUndefined) {
    AddErrorInfo("unknown 'display' value ignored.");
    return display_enum;
  }

  // Ignore "enhanced" display modes.
  if (!IsBasicDisplayMode(display_enum)) {
    display_enum = mojom::blink::DisplayMode::kUndefined;
    AddErrorInfo("inapplicable 'display' value ignored.");
  }

  return display_enum;
}

Vector<mojom::blink::DisplayMode> ManifestParser::ParseDisplayOverride(
    const JSONObject* object) {
  Vector<mojom::blink::DisplayMode> display_override;

  JSONValue* json_value = object->Get("display_override");
  if (!json_value) {
    return display_override;
  }

  JSONArray* display_override_list = object->GetArray("display_override");
  if (!display_override_list) {
    AddErrorInfo("property 'display_override' ignored, type array expected.");
    return display_override;
  }

  for (wtf_size_t i = 0; i < display_override_list->size(); ++i) {
    String display_enum_string;
    // AsString will return an empty string if a type error occurs,
    // which will cause DisplayModeFromString to return kUndefined,
    // resulting in this entry being ignored.
    display_override_list->at(i)->AsString(&display_enum_string);
    display_enum_string = display_enum_string.StripWhiteSpace();
    mojom::blink::DisplayMode display_enum =
        DisplayModeFromString(display_enum_string.Utf8());

    if (!RuntimeEnabledFeatures::WebAppTabStripEnabled(execution_context_) &&
        display_enum == mojom::blink::DisplayMode::kTabbed) {
      display_enum = mojom::blink::DisplayMode::kUndefined;
    }

    if (!base::FeatureList::IsEnabled(blink::features::kWebAppBorderless) &&
        display_enum == mojom::blink::DisplayMode::kBorderless) {
      display_enum = mojom::blink::DisplayMode::kUndefined;
    }

    if (display_enum != mojom::blink::DisplayMode::kUndefined) {
      display_override.push_back(display_enum);
    }
  }

  return display_override;
}

device::mojom::blink::ScreenOrientationLockType
ManifestParser::ParseOrientation(const JSONObject* object) {
  std::optional<String> orientation =
      ParseString(object, "orientation", Trim(true));

  if (!orientation.has_value()) {
    return device::mojom::blink::ScreenOrientationLockType::DEFAULT;
  }

  device::mojom::blink::ScreenOrientationLockType orientation_enum =
      WebScreenOrientationLockTypeFromString(orientation->Utf8());
  if (orientation_enum ==
      device::mojom::blink::ScreenOrientationLockType::DEFAULT) {
    AddErrorInfo("unknown 'orientation' value ignored.");
  }
  return orientation_enum;
}

KURL ManifestParser::ParseIconSrc(const JSONObject* icon) {
  return ParseURL(icon, "src", manifest_url_,
                  ParseURLRestrictions::kNoRestrictions);
}

String ManifestParser::ParseIconType(const JSONObject* icon) {
  std::optional<String> type = ParseString(icon, "type", Trim(true));
  return type.has_value() ? *type : String("");
}

Vector<gfx::Size> ManifestParser::ParseIconSizes(const JSONObject* icon) {
  std::optional<String> sizes_str = ParseString(icon, "sizes", Trim(false));
  if (!sizes_str.has_value()) {
    return Vector<gfx::Size>();
  }

  WebVector<gfx::Size> web_sizes =
      WebIconSizesParser::ParseIconSizes(WebString(*sizes_str));
  Vector<gfx::Size> sizes;
  for (auto& size : web_sizes) {
    sizes.push_back(size);
  }

  if (sizes.empty()) {
    AddErrorInfo("found icon with no valid size.");
  }
  return sizes;
}

std::optional<Vector<mojom::blink::ManifestImageResource::Purpose>>
ManifestParser::ParseIconPurpose(const JSONObject* icon) {
  std::optional<String> purpose_str = ParseString(icon, "purpose", Trim(false));
  Vector<mojom::blink::ManifestImageResource::Purpose> purposes;

  if (!purpose_str.has_value()) {
    purposes.push_back(mojom::blink::ManifestImageResource::Purpose::ANY);
    return purposes;
  }

  Vector<String> keywords;
  purpose_str.value().Split(/*separator=*/" ", /*allow_empty_entries=*/false,
                            keywords);

  // "any" is the default if there are no other keywords.
  if (keywords.empty()) {
    purposes.push_back(mojom::blink::ManifestImageResource::Purpose::ANY);
    return purposes;
  }

  bool unrecognised_purpose = false;
  for (auto& keyword : keywords) {
    keyword = keyword.StripWhiteSpace();
    if (keyword.empty()) {
      continue;
    }

    if (EqualIgnoringASCIICase(keyword, "any")) {
      purposes.push_back(mojom::blink::ManifestImageResource::Purpose::ANY);
    } else if (EqualIgnoringASCIICase(keyword, "monochrome")) {
      purposes.push_back(
          mojom::blink::ManifestImageResource::Purpose::MONOCHROME);
    } else if (EqualIgnoringASCIICase(keyword, "maskable")) {
      purposes.push_back(
          mojom::blink::ManifestImageResource::Purpose::MASKABLE);
    } else {
      unrecognised_purpose = true;
    }
  }

  // This implies there was at least one purpose given, but none recognised.
  // Instead of defaulting to "any" (which would not be future proof),
  // invalidate the whole icon.
  if (purposes.empty()) {
    AddErrorInfo("found icon with no valid purpose; ignoring it.");
    return std::nullopt;
  }

  if (unrecognised_purpose) {
    AddErrorInfo(
        "found icon with one or more invalid purposes; those purposes are "
        "ignored.");
  }

  return purposes;
}

mojom::blink::ManifestScreenshot::FormFactor
ManifestParser::ParseScreenshotFormFactor(const JSONObject* screenshot) {
  std::optional<String> form_factor_str =
      ParseString(screenshot, "form_factor", Trim(false));

  if (!form_factor_str.has_value()) {
    return mojom::blink::ManifestScreenshot::FormFactor::kUnknown;
  }

  String form_factor = form_factor_str.value();

  if (EqualIgnoringASCIICase(form_factor, "wide")) {
    return mojom::blink::ManifestScreenshot::FormFactor::kWide;
  } else if (EqualIgnoringASCIICase(form_factor, "narrow")) {
    return mojom::blink::ManifestScreenshot::FormFactor::kNarrow;
  }

  AddErrorInfo(
      "property 'form_factor' on screenshots has an invalid value, ignoring "
      "it.");

  return mojom::blink::ManifestScreenshot::FormFactor::kUnknown;
}

String ManifestParser::ParseScreenshotLabel(const JSONObject* object) {
  std::optional<String> label = ParseString(object, "label", Trim(true));
  return label.has_value() ? *label : String();
}

Vector<mojom::blink::ManifestImageResourcePtr> ManifestParser::ParseIcons(
    const JSONObject* object) {
  return ParseImageResourceArray("icons", object);
}

Vector<mojom::blink::ManifestScreenshotPtr> ManifestParser::ParseScreenshots(
    const JSONObject* object) {
  Vector<mojom::blink::ManifestScreenshotPtr> screenshots;
  JSONVal
"""


```