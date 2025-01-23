Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the third part of a larger file. The request asks to:

1. **List the functions:** Identify the purpose of each function in the snippet.
2. **Relate to web technologies:** Explain how the code interacts with JavaScript, HTML, and CSS, providing examples.
3. **Illustrate logic:** Give examples of input and output for functions with logical operations.
4. **Highlight usage errors:** Point out common mistakes users or programmers might make when using this code.
5. **Explain the user journey:** Describe how a user's actions could lead to this code being executed, as a debugging aid.
6. **Summarize overall functionality:** Provide a concise overview of the code's purpose.

**Plan:**

1. **Iterate through each function:** Analyze each function's name, parameters, and logic to understand its role.
2. **Identify web technology connections:**  Based on the function names and the data they parse (like "manifest", "icons", "URL"), determine the relationship with web technologies. For example, parsing URLs directly relates to HTML and navigation.
3. **Construct input/output examples:**  For functions like `ParseNoteTakingNewNoteUrl` or `ParseRelatedApplications`, create hypothetical JSON inputs and the corresponding parsed output.
4. **Pinpoint potential errors:** Consider how incorrect or missing data in the manifest file could lead to errors during parsing. Focus on common mistakes like invalid URLs, incorrect data types, or missing required fields.
5. **Trace the user's path:**  Think about the typical user interaction with a web application that uses a manifest file, like installing a PWA or loading a website with a manifest.
6. **Synthesize the summary:** Combine the individual function descriptions and the identified relationships into a concise summary of the file's purpose.
这是 `blink/renderer/modules/manifest/manifest_parser.cc` 文件的第三部分，主要负责解析 Web App Manifest 文件的各个属性。延续前两部分，这部分继续解析 manifest 中与应用功能和行为相关的属性，并处理一些更复杂的结构。

**功能列举:**

* **`ParseNoteTakingNewNoteUrl(const JSONObject* note_taking)`:** 解析 `note_taking` 对象中的 `new_note_url` 属性，用于指定创建新笔记的 URL。
* **`ParseNoteTaking(const JSONObject* manifest)`:** 解析 manifest 中的 `note_taking` 属性，该属性是一个对象，包含与笔记功能相关的配置。目前只解析了 `new_note_url`。
* **`ParseRelatedApplicationPlatform(const JSONObject* application)`:** 解析相关应用（related applications）对象中的 `platform` 属性，指示应用的目标平台（如 "play", "itunes"）。
* **`ParseRelatedApplicationURL(const JSONObject* application)`:** 解析相关应用对象中的 `url` 属性，指向应用在商店或网站上的链接。
* **`ParseRelatedApplicationId(const JSONObject* application)`:** 解析相关应用对象中的 `id` 属性，应用在特定平台上的 ID。
* **`ParseRelatedApplications(const JSONObject* object)`:** 解析 manifest 中的 `related_applications` 属性，该属性是一个数组，包含一系列相关应用的描述信息。
* **`ParsePreferRelatedApplications(const JSONObject* object)`:** 解析 manifest 中的 `prefer_related_applications` 属性，一个布尔值，指示是否优先使用相关应用而不是当前 Web 应用。
* **`ParseThemeColor(const JSONObject* object)`:** 解析 manifest 中的 `theme_color` 属性，定义应用的整体主题颜色。
* **`ParseBackgroundColor(const JSONObject* object)`:** 解析 manifest 中的 `background_color` 属性，定义应用启动时的背景颜色。
* **`ParseGCMSenderID(const JSONObject* object)`:** 解析 manifest 中的 `gcm_sender_id` 属性，用于 Firebase Cloud Messaging (FCM) 的发送者 ID。
* **`ParseIsolatedAppPermissions(const JSONObject* object)`:** 解析 manifest 中的 `permissions_policy` 属性，用于定义独立 Web 应用的权限策略。
* **`ParseOriginAllowlist(const JSONArray* json_allowlist, const String& feature)`:** 解析权限策略中特定功能的允许来源列表。
* **`ParseLaunchHandler(const JSONObject* object)`:** 解析 manifest 中的 `launch_handler` 属性，配置应用启动时的行为，例如客户端模式。
* **`ParseTranslations(const JSONObject* object)`:** 解析 manifest 中的 `translations` 属性，一个包含不同语言翻译的 locale 到翻译条目的映射。
* **`ParseTabStrip(const JSONObject* object)`:** 解析 manifest 中的 `tab_strip` 属性，配置应用标签栏的行为和外观。
* **`ParseTabStripMemberVisibility(const JSONValue* json_value)`:** 解析标签栏成员的可见性设置。
* **`ParseScopePatterns(const JSONObject* object)`:** 解析 `scope_patterns` 属性，用于定义应用的作用域模式，支持更精细的控制。
* **`ParseScopePattern(const PatternInit& init, const KURL& base_url)`:** 解析单个作用域模式对象。
* **`MaybeCreatePatternInit(const JSONObject* pattern_object)`:** 从 JSON 对象中创建 `PatternInit` 结构体，用于作用域模式的解析。
* **`ParseVersion(const JSONObject* object)`:** 解析 manifest 中的 `version` 属性，表示应用的版本号。
* **`AddErrorInfo(const String& error_msg, bool critical, int error_line, int error_column)`:** 添加解析过程中遇到的错误信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **`note_taking.new_note_url`:**  JavaScript 可以通过 `navigator.appManifest` API 获取解析后的 `new_note_url`，然后在用户尝试创建新笔记时使用该 URL 发起请求。
        * **假设输入 (manifest.json):**
          ```json
          {
            "note_taking": {
              "new_note_url": "/new_note"
            }
          }
          ```
        * **输出 (C++):** `note_taking->new_note_url` 将会是 KURL 对象，其 URL 为应用的基准 URL 加上 "/new_note"。
        * **JavaScript 代码:**
          ```javascript
          navigator.appManifest.then(manifest => {
            if (manifest.note_taking && manifest.note_taking.new_note_url) {
              const newNoteUrl = manifest.note_taking.new_note_url;
              // 使用 newNoteUrl 创建新笔记
            }
          });
          ```
* **HTML:**
    * **`related_applications`:** 浏览器可以使用此信息向用户推荐安装相关的原生应用。
        * **假设输入 (manifest.json):**
          ```json
          {
            "related_applications": [
              {
                "platform": "play",
                "url": "https://play.google.com/store/apps/details?id=com.example.app1"
              }
            ]
          }
          ```
        * **输出 (C++):** `applications` 向量会包含一个 `ManifestRelatedApplicationPtr` 对象，其 `platform` 为 "play"，`url` 为 "https://play.google.com/store/apps/details?id=com.example.app1"。
        * **HTML 元素 (浏览器可能生成或开发者手动添加):**  浏览器可能会在某个界面上展示一个链接，提示用户安装此应用。
* **CSS:**
    * **`theme_color` 和 `background_color`:** 这些属性直接影响应用的视觉外观。`theme_color` 可以被浏览器用于自定义用户界面的颜色，而 `background_color` 用于启动时的 splash 屏幕。
        * **假设输入 (manifest.json):**
          ```json
          {
            "theme_color": "#4285f4",
            "background_color": "#ffffff"
          }
          ```
        * **输出 (C++):** `theme_color_` 将会是 `RGBA32` 类型的颜色值，代表蓝色；`background_color_` 也将是 `RGBA32` 类型的颜色值，代表白色。
        * **浏览器行为:**  浏览器的用户界面元素（如地址栏在某些情况下）可能会变为蓝色，应用的启动画面会是白色。

**逻辑推理的假设输入与输出:**

* **`ParseRelatedApplications`:**
    * **假设输入 (manifest.json):**
      ```json
      {
        "related_applications": [
          { "platform": "play", "url": "...", "id": "com.example.app1" },
          { "platform": "itunes", "url": "..." },
          { "url": "..." }, // 缺少 platform，会被忽略
          { "platform": "play" } // 缺少 url 和 id，会被忽略
        ]
      }
      ```
    * **输出 (C++):** `applications` 向量将包含两个 `ManifestRelatedApplicationPtr` 对象，分别对应第一个和第二个有效的应用描述。后两个因为缺少必要信息会被忽略，并产生错误信息。
* **`ParseLaunchHandler`:**
    * **假设输入 (manifest.json):**
      ```json
      {
        "launch_handler": {
          "client_mode": "navigate-existing"
        }
      }
      ```
    * **输出 (C++):** `launch_handler` 将会是一个 `ManifestLaunchHandlerPtr` 对象，其 `client_mode` 值为 `mojom::blink::ManifestLaunchHandler::ClientMode::kNavigateExisting`。

**用户或编程常见的使用错误:**

* **`related_applications` 中缺少 `platform`:**  这是最常见的错误。如果 `platform` 字段缺失，整个相关应用的条目会被忽略。
    * **示例 (manifest.json):**
      ```json
      {
        "related_applications": [
          { "url": "https://play.google.com/store/apps/details?id=com.example.app1" } // 缺少 "platform"
        ]
      }
      ```
    * **错误信息:** "'platform' is a required field, related application ignored."
* **`related_applications` 中同时缺少 `url` 和 `id`:**  必须提供至少一个用于识别应用的标识符。
    * **示例 (manifest.json):**
      ```json
      {
        "related_applications": [
          { "platform": "play" } // 缺少 "url" 和 "id"
        ]
      }
      ```
    * **错误信息:** "one of 'url' or 'id' is required, related application ignored."
* **`permissions_policy` 中允许列表的类型错误:** 权限策略中的允许来源列表必须是字符串数组。
    * **示例 (manifest.json):**
      ```json
      {
        "permissions_policy": {
          "geolocation": "self" // 应该是 ["self"]
        }
      }
      ```
    * **错误信息:** "permission 'geolocation' ignored, invalid allowlist: type array expected."
* **`translations` 中 locale 为空字符串:**  每个翻译条目必须关联到一个非空的 locale 字符串。
    * **示例 (manifest.json):**
      ```json
      {
        "translations": {
          "": { "name": "My App" } // locale 为空
        }
      }
      ```
    * **错误信息:** "skipping translation, non-empty locale string expected."
* **`tab_strip` 中 `home_tab` 不是对象或 "absent" 字符串:** `home_tab` 必须是一个对象来配置其图标和作用域模式，或者是一个字符串 "absent" 来表示不显示。
    * **示例 (manifest.json):**
      ```json
      {
        "tab_strip": {
          "home_tab": true // 错误的类型
        }
      }
      ```
    * **错误信息:** "property 'tab_strip' ignored, object expected." （因为整个 `tab_strip` 解析失败）

**用户操作到达这里的调试线索:**

1. **用户在浏览器中访问一个包含 Web App Manifest 文件的网页。** 浏览器会尝试下载并解析该 manifest 文件。
2. **用户尝试将该网页添加到主屏幕或安装为 PWA。** 浏览器需要解析 manifest 文件以获取应用的名称、图标、启动 URL 等信息。
3. **开发者在网页的 `<head>` 标签中使用了 `<link rel="manifest" href="manifest.json">` 声明了 manifest 文件。** 浏览器会根据这个声明去加载和解析 manifest。
4. **浏览器内部的服务或模块需要获取 Web 应用的元数据。** 例如，Service Worker 可能需要访问 manifest 中的 scope 信息。
5. **在开发过程中，开发者可能会检查或调试 manifest 文件的解析过程。**  他们可能会使用浏览器的开发者工具来查看 manifest 的解析结果和错误信息。

当以上操作发生时，Blink 引擎会加载 manifest 文件，并调用 `ManifestParser` 的相关方法来解析其内容。如果 manifest 文件中包含 `note_taking`、`related_applications`、`permissions_policy`、`launch_handler`、`translations`、`tab_strip` 等属性，那么这段代码就会被执行来解析这些特定的部分。如果解析过程中遇到错误，`AddErrorInfo` 会记录这些错误，开发者可以通过浏览器的开发者工具看到这些信息。

**功能归纳:**

这部分 `manifest_parser.cc` 代码主要负责解析 Web App Manifest 文件中与应用功能和行为相关的更高级和复杂的属性，例如：

* **增强应用功能:**  解析与笔记功能 (`note_taking`) 相关的配置。
* **应用推广:**  解析相关应用信息 (`related_applications`)，用于推广原生应用。
* **安全与权限:** 解析独立应用的权限策略 (`permissions_policy`)。
* **启动行为定制:** 解析应用启动时的处理方式 (`launch_handler`)。
* **多语言支持:** 解析应用的翻译信息 (`translations`)，实现本地化。
* **用户界面定制:** 解析标签栏的配置 (`tab_strip`)。
* **作用域控制:** 解析更细粒度的作用域模式 (`scope_patterns`)。
* **版本控制:** 解析应用的版本号 (`version`)。

总而言之，这部分代码在 Web App Manifest 解析过程中扮演着关键角色，它负责提取和处理那些定义了 Web 应用行为、外观以及与其他应用集成方式的关键信息。

### 提示词
```
这是目录为blink/renderer/modules/manifest/manifest_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ew_note_url")) {
    return KURL();
  }
  KURL new_note_url = ParseURL(note_taking, "new_note_url", manifest_url_,
                               ParseURLRestrictions::kWithinScope);
  if (!new_note_url.IsValid()) {
    // Error already reported by ParseURL.
    return KURL();
  }

  return new_note_url;
}

mojom::blink::ManifestNoteTakingPtr ManifestParser::ParseNoteTaking(
    const JSONObject* manifest) {
  if (!manifest->Get("note_taking")) {
    return nullptr;
  }

  const JSONObject* note_taking_object = manifest->GetJSONObject("note_taking");
  if (!note_taking_object) {
    AddErrorInfo("property 'note_taking' ignored, type object expected.");
    return nullptr;
  }
  auto note_taking = mojom::blink::ManifestNoteTaking::New();
  note_taking->new_note_url = ParseNoteTakingNewNoteUrl(note_taking_object);

  return note_taking;
}

String ManifestParser::ParseRelatedApplicationPlatform(
    const JSONObject* application) {
  std::optional<String> platform =
      ParseString(application, "platform", Trim(true));
  return platform.has_value() ? *platform : String();
}

std::optional<KURL> ManifestParser::ParseRelatedApplicationURL(
    const JSONObject* application) {
  return ParseURL(application, "url", manifest_url_,
                  ParseURLRestrictions::kNoRestrictions);
}

String ManifestParser::ParseRelatedApplicationId(
    const JSONObject* application) {
  std::optional<String> id = ParseString(application, "id", Trim(true));
  return id.has_value() ? *id : String();
}

Vector<mojom::blink::ManifestRelatedApplicationPtr>
ManifestParser::ParseRelatedApplications(const JSONObject* object) {
  Vector<mojom::blink::ManifestRelatedApplicationPtr> applications;

  JSONValue* value = object->Get("related_applications");
  if (!value) {
    return applications;
  }

  JSONArray* applications_list = object->GetArray("related_applications");
  if (!applications_list) {
    AddErrorInfo(
        "property 'related_applications' ignored,"
        " type array expected.");
    return applications;
  }

  for (wtf_size_t i = 0; i < applications_list->size(); ++i) {
    const JSONObject* application_object =
        JSONObject::Cast(applications_list->at(i));
    if (!application_object) {
      continue;
    }

    auto application = mojom::blink::ManifestRelatedApplication::New();
    application->platform = ParseRelatedApplicationPlatform(application_object);
    // "If platform is undefined, move onto the next item if any are left."
    if (application->platform.empty()) {
      AddErrorInfo(
          "'platform' is a required field, related application"
          " ignored.");
      continue;
    }

    application->id = ParseRelatedApplicationId(application_object);
    application->url = ParseRelatedApplicationURL(application_object);
    // "If both id and url are undefined, move onto the next item if any are
    // left."
    if ((!application->url.has_value() || !application->url->IsValid()) &&
        application->id.empty()) {
      AddErrorInfo(
          "one of 'url' or 'id' is required, related application"
          " ignored.");
      continue;
    }

    applications.push_back(std::move(application));
  }

  return applications;
}

bool ManifestParser::ParsePreferRelatedApplications(const JSONObject* object) {
  return ParseBoolean(object, "prefer_related_applications", false);
}

std::optional<RGBA32> ManifestParser::ParseThemeColor(
    const JSONObject* object) {
  return ParseColor(object, "theme_color");
}

std::optional<RGBA32> ManifestParser::ParseBackgroundColor(
    const JSONObject* object) {
  return ParseColor(object, "background_color");
}

String ManifestParser::ParseGCMSenderID(const JSONObject* object) {
  std::optional<String> gcm_sender_id =
      ParseString(object, "gcm_sender_id", Trim(true));
  return gcm_sender_id.has_value() ? *gcm_sender_id : String();
}

Vector<blink::ParsedPermissionsPolicyDeclaration>
ManifestParser::ParseIsolatedAppPermissions(const JSONObject* object) {
  PermissionsPolicyParser::Node policy{
      OriginWithPossibleWildcards::NodeType::kHeader};

  JSONValue* json_value = object->Get("permissions_policy");
  if (!json_value) {
    return Vector<blink::ParsedPermissionsPolicyDeclaration>();
  }

  JSONObject* permissions_dict = object->GetJSONObject("permissions_policy");
  if (!permissions_dict) {
    AddErrorInfo(
        "property 'permissions_policy' ignored, type object expected.");
    return Vector<blink::ParsedPermissionsPolicyDeclaration>();
  }

  for (wtf_size_t i = 0; i < permissions_dict->size(); ++i) {
    const JSONObject::Entry& entry = permissions_dict->at(i);
    String feature(entry.first);

    JSONArray* origin_allowlist = JSONArray::Cast(entry.second);
    if (!origin_allowlist) {
      AddErrorInfo("permission '" + feature +
                   "' ignored, invalid allowlist: type array expected.");
      continue;
    }

    Vector<String> allowlist = ParseOriginAllowlist(origin_allowlist, feature);
    if (!allowlist.size()) {
      continue;
    }
    PermissionsPolicyParser::Declaration new_policy;
    new_policy.feature_name = feature;
    for (const auto& origin : allowlist) {
      // PermissionsPolicyParser expects 4 types of origin strings:
      // - "self": wrapped in single quotes (as in a header)
      // - "none": wrapped in single quotes (as in a header)
      // - "*" (asterisk): not wrapped
      // - "<origin>": actual origin names should not be wrapped in single
      //        quotes
      // The "src" origin string type can be ignored here as it's only used in
      // the iframe "allow" attribute.
      //
      // Sidenote: Actual origin names ("<origin>") are parsed using
      // OriginWithPossibleWildcards::Parse() which fails if the origin string
      // contains any non-alphanumeric characters, such as a single quote. For
      // this reason, actual origin names must not be wrapped since the parser
      // will just drop them as being improperly formatted (i.e. they would be
      // the equivalent to some manifest containing an origin wrapped in single
      // quotes, which is invalid).
      String wrapped_origin = origin;
      if (EqualIgnoringASCIICase(origin, "self") ||
          EqualIgnoringASCIICase(origin, "none")) {
        wrapped_origin = "'" + origin + "'";
      }
      new_policy.allowlist.push_back(wrapped_origin);
    }
    policy.declarations.push_back(new_policy);
  }

  PolicyParserMessageBuffer logger(
      "Error with permissions_policy manifest field: ");
  blink::ParsedPermissionsPolicy parsed_policy =
      PermissionsPolicyParser::ParsePolicyFromNode(
          policy, SecurityOrigin::Create(manifest_url_), logger,
          execution_context_);

  Vector<blink::ParsedPermissionsPolicyDeclaration> out;
  for (const auto& decl : parsed_policy) {
    out.push_back(std::move(decl));
  }
  return out;
}

Vector<String> ManifestParser::ParseOriginAllowlist(
    const JSONArray* json_allowlist,
    const String& feature) {
  Vector<String> out;
  for (wtf_size_t i = 0; i < json_allowlist->size(); ++i) {
    JSONValue* json_value = json_allowlist->at(i);
    if (!json_value) {
      AddErrorInfo(
          "permissions_policy entry ignored, required property 'origin' is "
          "invalid.");
      return Vector<String>();
    }

    String origin_string;
    if (!json_value->AsString(&origin_string) || origin_string.IsNull()) {
      AddErrorInfo(
          "permissions_policy entry ignored, required property 'origin' "
          "contains "
          "an invalid element: type string expected.");
      return Vector<String>();
    }

    if (!origin_string.length()) {
      AddErrorInfo(
          "permissions_policy entry ignored, required property 'origin' is "
          "contains an empty string.");
      return Vector<String>();
    }

    if (origin_string.length() > kMaxOriginLength) {
      AddErrorInfo(
          "permissions_policy entry ignored, 'origin' exceeds maximum "
          "character length "
          "of " +
          String::Number(kMaxOriginLength) + " .");
      return Vector<String>();
    }
    out.push_back(origin_string);
  }

  return out;
}

mojom::blink::ManifestLaunchHandlerPtr ManifestParser::ParseLaunchHandler(
    const JSONObject* object) {
  const JSONValue* launch_handler_value = object->Get("launch_handler");
  if (!launch_handler_value) {
    return nullptr;
  }

  const JSONObject* launch_handler_object =
      JSONObject::Cast(launch_handler_value);
  if (!launch_handler_object) {
    AddErrorInfo("launch_handler value ignored, object expected.");
    return nullptr;
  }

  using ClientMode = mojom::blink::ManifestLaunchHandler::ClientMode;
  return mojom::blink::ManifestLaunchHandler::New(
      ParseFirstValidEnum<std::optional<ClientMode>>(
          launch_handler_object, "client_mode", &ClientModeFromString,
          /*invalid_value=*/std::nullopt)
          .value_or(ClientMode::kAuto));
}

HashMap<String, mojom::blink::ManifestTranslationItemPtr>
ManifestParser::ParseTranslations(const JSONObject* object) {
  HashMap<String, mojom::blink::ManifestTranslationItemPtr> result;

  if (!object->Get("translations")) {
    return result;
  }

  JSONObject* translations_map = object->GetJSONObject("translations");
  if (!translations_map) {
    AddErrorInfo("property 'translations' ignored, object expected.");
    return result;
  }

  for (wtf_size_t i = 0; i < translations_map->size(); ++i) {
    JSONObject::Entry entry = translations_map->at(i);
    String locale = entry.first;
    if (locale == "") {
      AddErrorInfo("skipping translation, non-empty locale string expected.");
      continue;
    }
    JSONObject* translation = JSONObject::Cast(entry.second);
    if (!translation) {
      AddErrorInfo("skipping translation, object expected.");
      continue;
    }

    auto translation_item = mojom::blink::ManifestTranslationItem::New();

    std::optional<String> name = ParseStringForMember(
        translation, "translations", "name", false, Trim(true));
    translation_item->name =
        name.has_value() && name->length() != 0 ? *name : String();

    std::optional<String> short_name = ParseStringForMember(
        translation, "translations", "short_name", false, Trim(true));
    translation_item->short_name =
        short_name.has_value() && short_name->length() != 0 ? *short_name
                                                            : String();

    std::optional<String> description = ParseStringForMember(
        translation, "translations", "description", false, Trim(true));
    translation_item->description =
        description.has_value() && description->length() != 0 ? *description
                                                              : String();

    // A translation may be specified for any combination of translatable fields
    // in the manifest. If no translations are supplied, we skip this item.
    if (!translation_item->name && !translation_item->short_name &&
        !translation_item->description) {
      continue;
    }

    result.Set(locale, std::move(translation_item));
  }
  return result;
}

mojom::blink::ManifestTabStripPtr ManifestParser::ParseTabStrip(
    const JSONObject* object) {
  if (!object->Get("tab_strip")) {
    return nullptr;
  }

  JSONObject* tab_strip_object = object->GetJSONObject("tab_strip");
  if (!tab_strip_object) {
    AddErrorInfo("property 'tab_strip' ignored, object expected.");
    return nullptr;
  }

  auto result = mojom::blink::ManifestTabStrip::New();

  JSONValue* home_tab_value = tab_strip_object->Get("home_tab");
  if (home_tab_value && home_tab_value->GetType() == JSONValue::kTypeObject) {
    JSONObject* home_tab_object = tab_strip_object->GetJSONObject("home_tab");
    auto home_tab_params = mojom::blink::HomeTabParams::New();

    JSONValue* home_tab_icons = home_tab_object->Get("icons");
    String string_value;
    if (home_tab_icons && !(home_tab_icons->AsString(&string_value) &&
                            EqualIgnoringASCIICase(string_value, "auto"))) {
      home_tab_params->icons = ParseIcons(home_tab_object);
    }

    home_tab_params->scope_patterns = ParseScopePatterns(home_tab_object);

    result->home_tab =
        mojom::blink::HomeTabUnion::NewParams(std::move(home_tab_params));
  } else {
    result->home_tab = mojom::blink::HomeTabUnion::NewVisibility(
        ParseTabStripMemberVisibility(home_tab_value));
  }

  auto new_tab_button_params = mojom::blink::NewTabButtonParams::New();

  JSONObject* new_tab_button_object =
      tab_strip_object->GetJSONObject("new_tab_button");
  if (new_tab_button_object) {
    JSONValue* new_tab_button_url = new_tab_button_object->Get("url");

    String string_value;
    if (new_tab_button_url && !(new_tab_button_url->AsString(&string_value) &&
                                EqualIgnoringASCIICase(string_value, "auto"))) {
      KURL url = ParseURL(new_tab_button_object, "url", manifest_url_,
                          ParseURLRestrictions::kWithinScope);
      if (!url.IsNull()) {
        new_tab_button_params->url = url;
      }
    }
  }
  result->new_tab_button = std::move(new_tab_button_params);

  return result;
}

mojom::blink::TabStripMemberVisibility
ManifestParser::ParseTabStripMemberVisibility(const JSONValue* json_value) {
  if (!json_value) {
    return mojom::blink::TabStripMemberVisibility::kAuto;
  }

  String string_value;
  if (json_value->AsString(&string_value) &&
      EqualIgnoringASCIICase(string_value, "absent")) {
    return mojom::blink::TabStripMemberVisibility::kAbsent;
  }

  return mojom::blink::TabStripMemberVisibility::kAuto;
}

Vector<SafeUrlPattern> ManifestParser::ParseScopePatterns(
    const JSONObject* object) {
  Vector<SafeUrlPattern> result;

  if (!object->Get("scope_patterns")) {
    return result;
  }

  JSONArray* scope_patterns_list = object->GetArray("scope_patterns");
  if (!scope_patterns_list) {
    return result;
  }

  for (wtf_size_t i = 0; i < scope_patterns_list->size(); ++i) {
    // TODO(b/330640840): allow strings to be passed through here and parsed via
    // liburlpattern::ConstructorStringParser. The result of the parse can then
    // be used to create a PatternInit object for the rest of the process.
    JSONObject* pattern_object = JSONObject::Cast(scope_patterns_list->at(i));
    if (!pattern_object) {
      continue;
    }

    std::optional<PatternInit> init = MaybeCreatePatternInit(pattern_object);
    if (init.has_value()) {
      auto base_url = init->base_url.IsValid() ? init->base_url : manifest_url_;
      std::optional<SafeUrlPattern> pattern =
          ParseScopePattern(init.value(), base_url);
      if (pattern.has_value()) {
        result.push_back(std::move(pattern.value()));
      }
    }
  }

  return result;
}

std::optional<SafeUrlPattern> ManifestParser::ParseScopePattern(
    const PatternInit& init,
    const KURL& base_url) {
  auto url_pattern = std::make_optional<SafeUrlPattern>();

  {
    // https://urlpattern.spec.whatwg.org/#process-a-urlpatterninit
    // Always fall back to baseURL protocol if init does not contain protocol.
    std::optional<std::vector<liburlpattern::Part>> part_list =
        ParsePatternInitField(init.protocol, base_url.Protocol());
    if (!part_list.has_value()) {
      AddErrorInfo(
          "property 'protocol in home tab scope pattern could not be parsed or "
          "contains banned regex.");
      return std::nullopt;
    }
    url_pattern->protocol = std::move(part_list.value());
  }

  {
    // https://urlpattern.spec.whatwg.org/#process-a-urlpatterninit
    // Only fall back to baseURL username if init does not contain any of
    // protocol, hostname, or port.
    String default_username;
    if (!init.IsAbsolute()) {
      default_username = base_url.User().ToString();
    }
    std::optional<std::vector<liburlpattern::Part>> part_list =
        ParsePatternInitField(init.username, default_username);
    if (!part_list.has_value()) {
      AddErrorInfo(
          "property 'username'in home tab scope pattern could not be parsed or "
          "contains banned regex.");
      return std::nullopt;
    }
    url_pattern->username = std::move(part_list.value());
  }

  {
    // https://urlpattern.spec.whatwg.org/#process-a-urlpatterninit
    // Only fall back to baseURL password if init does not contain any of
    // protocol, hostname, port, or username.
    String default_password;
    if (!init.IsAbsolute() && !init.username.has_value()) {
      default_password = base_url.Pass().ToString();
    }
    std::optional<std::vector<liburlpattern::Part>> part_list =
        ParsePatternInitField(init.password, default_password);
    if (!part_list.has_value()) {
      AddErrorInfo(
          "property 'password' in home tab scope pattern could not be parsed "
          "or contains banned regex.");
      return std::nullopt;
    }
    url_pattern->password = std::move(part_list.value());
  }

  {
    // https://urlpattern.spec.whatwg.org/#process-a-urlpatterninit
    // Only fall back to baseURL hostname if init does not contain protocol.
    String default_hostname;
    if (!init.protocol.has_value()) {
      default_hostname = base_url.Host().ToString();
    }
    std::optional<std::vector<liburlpattern::Part>> part_list =
        ParsePatternInitField(init.hostname, default_hostname);
    if (!part_list.has_value()) {
      AddErrorInfo(
          "property 'hostname' in home tab scope pattern could not be parsed "
          "or contains banned regex.");
      return std::nullopt;
    }
    url_pattern->hostname = std::move(part_list.value());
  }

  {
    // https://urlpattern.spec.whatwg.org/#process-a-urlpatterninit
    // Only fall back to baseURL port if init does not contain any of
    // protocol, hostname, or port, and the baseURL port exists.
    String default_port;
    if (!init.IsAbsolute() && base_url.HasPort()) {
      default_port = String::Number(base_url.Port());
    }
    std::optional<std::vector<liburlpattern::Part>> part_list =
        ParsePatternInitField(init.port, default_port);
    if (!part_list.has_value()) {
      AddErrorInfo(
          "property 'port'in home tab scope pattern could not be parsed or "
          "contains banned regex.");
      return std::nullopt;
    }
    url_pattern->port = std::move(part_list.value());
  }

  {
    String default_path;
    if (init.pathname.has_value()) {
      // A possibly-relative path is given; resolve it against base URL's path.
      default_path =
          ResolveRelativePathnamePattern(base_url, init.pathname.value());
    } else if (!init.IsAbsolute()) {
      // No path, protocol, host or port is given; use the base URL's path.
      default_path = EscapePatternString(base_url.GetPath());
    }
    // else: no path, but a protocol, host or port was given, making this
    // pattern absolute, so treat the path as empty.

    std::optional<std::vector<liburlpattern::Part>> part_list =
        ParsePatternInitField(std::nullopt, default_path);
    if (!part_list.has_value()) {
      AddErrorInfo(
          "property 'pathname'in home tab scope pattern could not be parsed or "
          "contains banned regex.");
      return std::nullopt;
    }
    url_pattern->pathname = std::move(part_list.value());
  }

  {
    // https://urlpattern.spec.whatwg.org/#process-a-urlpatterninit
    // Only fall back to baseURL search if init does not contain any of
    // protocol, hostname, port, or pathname.
    String default_search;
    if (!init.IsAbsolute() && !init.pathname.has_value()) {
      default_search = base_url.Query().ToString();
    }
    std::optional<std::vector<liburlpattern::Part>> part_list =
        ParsePatternInitField(init.search, default_search);
    if (!part_list.has_value()) {
      AddErrorInfo(
          "property 'search' in home tab scope pattern could not be parsed "
          "or contains banned regex.");
      return std::nullopt;
    }
    url_pattern->search = std::move(part_list.value());
  }

  {
    // https://urlpattern.spec.whatwg.org/#process-a-urlpatterninit
    // Only fall back to baseURL hash if init does not contain any of
    // protocol, hostname, port, pathname, or search.
    String default_hash;
    if (!init.IsAbsolute() && !init.pathname.has_value() &&
        !init.search.has_value()) {
      default_hash = base_url.FragmentIdentifier().ToString();
    }
    std::optional<std::vector<liburlpattern::Part>> part_list =
        ParsePatternInitField(init.hash, default_hash);
    if (!part_list.has_value()) {
      AddErrorInfo(
          "property 'hash' in home tab scope pattern could not be parsed "
          "or contains banned regex.");
      return std::nullopt;
    }
    url_pattern->hash = std::move(part_list.value());
  }

  return url_pattern;
}

std::optional<ManifestParser::PatternInit>
ManifestParser::MaybeCreatePatternInit(const JSONObject* pattern_object) {
  std::optional<String> protocol = ParseStringForMember(
      pattern_object, "scope_patterns", "protocol", false, Trim(true));
  std::optional<String> username = ParseStringForMember(
      pattern_object, "scope_patterns", "username", false, Trim(true));
  std::optional<String> password = ParseStringForMember(
      pattern_object, "scope_patterns", "password", false, Trim(true));
  std::optional<String> hostname = ParseStringForMember(
      pattern_object, "scope_patterns", "hostname", false, Trim(true));
  std::optional<String> port = ParseStringForMember(
      pattern_object, "scope_patterns", "port", false, Trim(true));
  std::optional<String> pathname = ParseStringForMember(
      pattern_object, "scope_patterns", "pathname", false, Trim(true));
  std::optional<String> search = ParseStringForMember(
      pattern_object, "scope_patterns", "search", false, Trim(true));
  std::optional<String> hash = ParseStringForMember(
      pattern_object, "scope_patterns", "hash", false, Trim(true));

  KURL base_url;

  if (pattern_object->Get("baseURL")) {
    base_url = ParseURL(pattern_object, "baseURL", KURL(),
                        ParseURLRestrictions::kNoRestrictions);
    if (!base_url.IsValid()) {
      return std::nullopt;
    }
  }

  return std::make_optional<PatternInit>(
      std::move(protocol), std::move(username), std::move(password),
      std::move(hostname), std::move(port), std::move(pathname),
      std::move(search), std::move(hash), base_url);
}

String ManifestParser::ParseVersion(const JSONObject* object) {
  return ParseString(object, "version", Trim(false)).value_or(String());
}

void ManifestParser::AddErrorInfo(const String& error_msg,
                                  bool critical,
                                  int error_line,
                                  int error_column) {
  mojom::blink::ManifestErrorPtr error = mojom::blink::ManifestError::New(
      error_msg, critical, error_line, error_column);
  errors_.push_back(std::move(error));
}

}  // namespace blink
```