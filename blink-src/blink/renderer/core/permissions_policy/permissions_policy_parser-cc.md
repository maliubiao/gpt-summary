Response:
Let's break down the thought process for analyzing the provided code.

**1. Initial Understanding and Goal:**

The first step is to recognize the file's name and location: `blink/renderer/core/permissions_policy/permissions_policy_parser.cc`. This immediately tells us it's part of Chromium's Blink rendering engine, specifically dealing with the Permissions Policy (formerly Feature Policy). The `.cc` extension signifies a C++ source file. The goal, as requested, is to understand its functionality, its relation to web technologies (HTML, CSS, JavaScript), its logic, potential errors, and its place in the user's interaction flow.

**2. Core Functionality Identification:**

Reading the initial comments and includes provides clues. Keywords like "permissions policy," "parser," and includes like `net/http/structured_headers.h` and `third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h` point towards parsing and data structures related to permissions.

Skimming through the code reveals key classes and functions:

*   `PermissionsPolicyParser`: The main class.
*   `ParsingContext`:  A helper class to manage the parsing state.
*   `ParseHeader`, `ParseAttribute`, `ParsePolicyFromNode`:  Different entry points for parsing.
*   `ParseFeaturePolicyToIR`, `ParsePermissionsPolicyToIR`: Functions converting policy strings into an intermediate representation (IR).
*   `ParseAllowlist`: Handles parsing the allowed origins for a feature.
*   `ParseFeatureName`:  Looks up the internal representation of a feature name.

From these, it becomes clear that the file's primary function is to **parse strings representing Permissions Policies (and the older Feature Policy) into a structured representation that the browser can understand and enforce.**

**3. Relationship to Web Technologies (HTML, CSS, JavaScript):**

The code mentions parsing from headers (`ParseHeader`) and attributes (`ParseAttribute`). This directly links it to how Permissions Policies are specified in:

*   **HTTP Headers:**  The `Permissions-Policy` and the older `Feature-Policy` headers.
*   **HTML `iframe` `allow` Attribute:**  Specifying permissions for embedded iframes.

JavaScript's involvement is indirect. JavaScript code doesn't *directly* call these parsing functions. Instead, the browser uses the parsed policy to determine what APIs and features are allowed within a given context. So, if a Permissions Policy disallows the microphone, a JavaScript call to `navigator.mediaDevices.getUserMedia()` might be blocked.

CSS is less directly involved. While some experimental features might have been controlled by Feature Policy in the past, Permissions Policy primarily governs JavaScript APIs and browser features, not CSS styling rules.

**4. Logic and Examples (Assumptions and Outputs):**

To understand the logic, it's essential to focus on the parsing functions. Let's consider `ParseFeaturePolicyToIR`:

*   **Assumption:** The input is a string like `"camera 'self'; microphone=()` or `"geolocation *;"`.
*   **Processing:**
    *   Splits the string by commas (for combined headers) and then by semicolons to separate individual feature declarations.
    *   For each declaration, it extracts the feature name and the allowlist (origins).
    *   It uses `SplitOnASCIIWhitespace` to break down the allowlist.
    *   It builds an intermediate representation (`PermissionsPolicyParser::Node`) containing this information.
*   **Output:** A structured representation of the policy, like a vector of declarations, where each declaration has a feature name and a list of allowed origins.

Similarly, `ParsePermissionsPolicyToIR` handles the newer structured header format.

**5. User/Programming Errors:**

Common mistakes in writing Permissions Policies are:

*   **Typos in Feature Names:**  The parser logs a warning for "Unrecognized feature."
*   **Invalid Origins:**  Incorrect URL syntax or missing schemes. The parser logs a warning.
*   **Mixing Feature Policy and Permissions Policy:** The code explicitly handles this, prioritizing Permissions Policy and warning about overlaps.
*   **Incorrect Syntax in Headers/Attributes:** The structured header parser will log errors.

**6. User Operation to Reach the Code (Debugging Clues):**

This requires tracing the path from user action to this specific parser. Here's a possible flow:

1. **User Action:** A user navigates to a webpage (either by typing the URL or clicking a link).
2. **Server Response:** The server sends the HTML content and HTTP headers, including `Permissions-Policy` or `Feature-Policy`.
3. **Network Layer:** Chromium's network stack receives the response.
4. **Resource Loading:**  The headers are processed as the HTML resource is loaded.
5. **HTML Parsing:** The HTML parser encounters iframes or other elements that might have `allow` attributes.
6. **Permissions Policy Enforcement:** Before allowing access to certain features (like camera or microphone), the browser needs to parse the relevant policy.
7. **Calling the Parser:**  Functions like `ParseHeader` or `ParseAttribute` within `permissions_policy_parser.cc` are called to process the policy string.

**Self-Correction/Refinement During Analysis:**

Initially, I might focus heavily on the string manipulation. However, realizing the importance of the `ParsingContext` and its role in managing state (like the logger and security origins) is crucial for a deeper understanding. Also, recognizing the two parsing paths (for headers and attributes) is essential. Understanding the intermediate representation (`PermissionsPolicyParser::Node`) helps in visualizing the parsing process. Finally, connecting the parsing stage to the actual enforcement of the policy in other parts of the Blink engine is the ultimate goal of this analysis.
好的，让我们来详细分析一下 `blink/renderer/core/permissions_policy/permissions_policy_parser.cc` 文件的功能。

**文件功能概述**

`permissions_policy_parser.cc` 文件的核心功能是**解析权限策略 (Permissions Policy) 和旧版的特性策略 (Feature Policy) 的字符串，并将其转换为浏览器可以理解和执行的数据结构。**  它负责处理从 HTTP 头部或 HTML 属性中提取的策略字符串，并将其分解成一个个具体的权限声明。

**与 JavaScript, HTML, CSS 的关系**

此文件与 Web 前端技术（JavaScript, HTML, CSS）有着密切的关系，因为它处理的权限策略直接影响这些技术在浏览器中的行为。

1. **HTML:**
    *   **`iframe` 标签的 `allow` 属性:**  权限策略可以直接在 `iframe` 标签的 `allow` 属性中声明。`permissions_policy_parser.cc` 中的 `ParseAttribute` 函数就是用来解析这个属性值的。
        *   **举例:** `<iframe src="https://example.com" allow="camera 'self'; geolocation 'none'"></iframe>`。  当浏览器解析这个 HTML 时，会调用 `ParseAttribute` 来解析 `allow` 属性中的 `"camera 'self'; geolocation 'none'"` 字符串。
    *   **HTTP `Permissions-Policy` 头部和旧版的 `Feature-Policy` 头部:**  网页的服务器可以通过 HTTP 头部来声明权限策略。`permissions_policy_parser.cc` 中的 `ParseHeader` 函数负责解析这些头部的值。
        *   **举例:**  服务器返回的 HTTP 响应头可能包含：
            ```
            Permissions-Policy: camera 'self', microphone=()
            ```
            或者旧版的：
            ```
            Feature-Policy: geolocation 'none'; camera 'self'
            ```
            浏览器接收到这些头部后，会调用 `ParseHeader` 来解析这些策略字符串。

2. **JavaScript:**
    *   **权限策略的执行影响 JavaScript API 的行为:**  解析后的权限策略会被浏览器用于限制某些 JavaScript API 的访问。例如，如果权限策略禁止了地理位置 API，那么 JavaScript 代码调用 `navigator.geolocation.getCurrentPosition()` 将会失败。
        *   **举例:** 如果上面 `iframe` 的 `allow` 属性设置了 `geolocation 'none'`，那么在 `https://example.com` 这个 `iframe` 内部的 JavaScript 代码调用 `navigator.geolocation` 相关的 API 将会受到限制。

3. **CSS:**
    *   **关系较弱:** 权限策略主要关注影响 JavaScript API 和浏览器特性的权限控制，与 CSS 的关系相对较弱。早期版本的特性策略可能对某些 CSS 功能有影响，但当前的权限策略主要集中在 Web API 层面。

**逻辑推理 (假设输入与输出)**

假设我们有以下输入：

**场景 1: 解析 HTTP `Permissions-Policy` 头部**

*   **假设输入 ( `ParseHeader` 函数的参数 ):**
    *   `feature_policy_header`: 空字符串 (假设没有旧版的 Feature-Policy 头部)
    *   `permissions_policy_header`: `"camera 'self', microphone=(self \"https://example.com\")"`
    *   `origin`: 指向当前文档的安全源 (例如 `https://currentdomain.com`)
    *   `feature_policy_logger`, `permissions_policy_logger`: 用于记录解析过程中的警告或错误
    *   `execution_context`: 当前的执行上下文

*   **逻辑推理:**
    1. `ParseHeader` 函数会调用 `ParsingContext` 的 `ParsePermissionsPolicy` 方法来解析 `permissions_policy_header`。
    2. `ParsePermissionsPolicy` 会调用 `ParsePermissionsPolicyToIR` 将字符串解析成中间表示 (IR)。
    3. `ParsePermissionsPolicyToIR` 会使用 `net::structured_headers::ParseDictionary` 来解析结构化头部。
    4. 对于 `"camera 'self'"` 部分，会解析出 `camera` 特性，并允许当前域 (`'self'`) 访问。
    5. 对于 `"microphone=(self \"https://example.com\")"` 部分，会解析出 `microphone` 特性，并允许当前域和 `https://example.com` 访问。
    6. 最终，解析结果会存储在 `ParsedPermissionsPolicy` 对象中。

*   **假设输出 ( `ParseHeader` 函数的返回值 ):**
    ```c++
    ParsedPermissionsPolicy {
      { mojom::blink::PermissionsPolicyFeature::kCamera, // 假设 kCamera 代表 camera
        allowed_origins: { "https://currentdomain.com" },
        self_if_matches: "https://currentdomain.com",
        matches_all_origins: false,
        matches_opaque_src: false,
        reporting_endpoint: nullopt
      },
      { mojom::blink::PermissionsPolicyFeature::kMicrophone, // 假设 kMicrophone 代表 microphone
        allowed_origins: { "https://currentdomain.com", "https://example.com" },
        self_if_matches: "https://currentdomain.com",
        matches_all_origins: false,
        matches_opaque_src: false,
        reporting_endpoint: nullopt
      }
    }
    ```

**场景 2: 解析 `iframe` 的 `allow` 属性**

*   **假设输入 ( `ParseAttribute` 函数的参数 ):**
    *   `policy`: `"geolocation *; camera 'src'"`
    *   `self_origin`: 指向包含 `iframe` 的文档的安全源 (例如 `https://parent.com`)
    *   `src_origin`: 指向 `iframe` 的安全源 (例如 `https://example.com`)
    *   `logger`: 用于记录解析过程中的警告或错误
    *   `execution_context`: 当前的执行上下文

*   **逻辑推理:**
    1. `ParseAttribute` 函数会调用 `ParsingContext` 的 `ParseFeaturePolicy` 方法。
    2. `ParseFeaturePolicy` 会调用 `ParseFeaturePolicyToIR` 将属性值解析成中间表示。
    3. 对于 `"geolocation *"` 部分，会解析出 `geolocation` 特性，并允许所有源 (`*`) 访问。
    4. 对于 `"camera 'src'"` 部分，会解析出 `camera` 特性，并允许 `iframe` 自身的源 (`'src'`, 即 `https://example.com`) 访问。
    5. 最终，解析结果会存储在 `ParsedPermissionsPolicy` 对象中。

*   **假设输出 ( `ParseAttribute` 函数的返回值 ):**
    ```c++
    ParsedPermissionsPolicy {
      { mojom::blink::PermissionsPolicyFeature::kGeolocation, // 假设 kGeolocation 代表 geolocation
        allowed_origins: {},
        self_if_matches: nullopt,
        matches_all_origins: true,
        matches_opaque_src: true,
        reporting_endpoint: nullopt
      },
      { mojom::blink::PermissionsPolicyFeature::kCamera, // 假设 kCamera 代表 camera
        allowed_origins: { "https://example.com" },
        self_if_matches: nullopt,
        matches_all_origins: false,
        matches_opaque_src: false,
        reporting_endpoint: nullopt
      }
    }
    ```

**用户或编程常见的使用错误**

1. **拼写错误的特性名称:**  用户在 HTTP 头部或 `allow` 属性中使用了不存在或拼写错误的特性名称。
    *   **举例:**  `Permissions-Policy: cammera 'self'` (正确的应该是 `camera`)。
    *   **结果:** `ParseFeatureName` 函数会返回 `std::nullopt`，并可能记录一个警告日志："Unrecognized feature: 'cammera'."，该策略声明会被忽略。

2. **无效的源地址格式:**  用户在允许列表中使用了格式不正确的源地址。
    *   **举例:** `Permissions-Policy: geolocation 'htps://example.com'` (缺少一个 `/`)。
    *   **结果:** `ParseAllowlist` 函数在解析时会失败，并可能记录一个警告日志："Unrecognized origin: 'htps://example.com'."，该源地址会被忽略。

3. **在 `iframe` 的 `allow` 属性中错误使用 `'self'` 关键字:**  `'self'` 关键字在 `iframe` 的 `allow` 属性中通常没有意义，因为它指的是父文档的源，而不是 `iframe` 自身的源。应该使用 `'src'` 来指代 `iframe` 的源。
    *   **举例:** `<iframe src="https://example.com" allow="camera 'self'"></iframe>`
    *   **结果:**  解析器会尝试将 `'self'` 解析为父文档的源，可能不是用户期望的行为。最佳实践是使用 `'src'`。

4. **在 HTTP 头部和 `allow` 属性中同时声明同一个特性，但策略不同:**  虽然浏览器会处理这种情况（通常以 HTTP 头部为准），但这可能导致混淆。
    *   **举例:**
        *   HTTP 头部: `Permissions-Policy: camera 'none'`
        *   `iframe` 属性: `<iframe src="https://example.com" allow="camera 'self'"></iframe>`
    *   **结果:** `ParseHeader` 函数会检测到重复的特性声明，并发出警告，最终会使用 HTTP 头部定义的策略。

**用户操作是如何一步步的到达这里，作为调试线索**

以下是一个用户操作导致代码被执行的典型流程，可以作为调试线索：

1. **用户在浏览器地址栏输入网址或点击链接:** 例如 `https://example.com`。
2. **浏览器发送 HTTP 请求到服务器:** 请求 `https://example.com` 的资源。
3. **服务器响应包含 `Permissions-Policy` 头部:**  服务器返回的 HTTP 响应头中包含 `Permissions-Policy: camera 'self'`.
4. **浏览器接收并解析 HTTP 响应头:**  Chromium 的网络层接收到响应头。
5. **HTML 解析器开始解析 HTML 内容:**  如果响应的是 HTML 文件，HTML 解析器会开始工作。
6. **遇到需要权限策略的上下文:**  例如，JavaScript 代码尝试调用 `navigator.mediaDevices.getUserMedia()` 来访问摄像头。
7. **查询权限策略:** 浏览器会查找适用于当前上下文的权限策略。
8. **调用 `PermissionsPolicyParser::ParseHeader`:**  如果权限策略是通过 HTTP 头部声明的，则会调用 `ParseHeader` 函数来解析之前接收到的 `Permissions-Policy` 头部。
9. **解析策略字符串并生成内部表示:**  `ParseHeader` 内部会调用其他函数，如 `ParsePermissionsPolicy` 和 `ParsePermissionsPolicyToIR`，将 `"camera 'self'"` 字符串解析成浏览器可以理解的数据结构。
10. **权限检查:**  当 JavaScript 代码尝试访问摄像头时，浏览器会根据解析后的权限策略来判断是否允许这次操作。在本例中，由于策略允许当前域访问摄像头，因此操作可能会成功（取决于用户是否授予了摄像头权限）。

**调试线索:**

*   **查看 Network 面板的 Response Headers:**  确认服务器返回的 `Permissions-Policy` 或 `Feature-Policy` 头部内容是否正确。
*   **使用 `chrome://policy/` 查看当前生效的策略:**  虽然这个页面主要显示管理员设置的策略，但有时也能提供一些关于页面自身策略的信息。
*   **在开发者工具的 Console 中查看警告信息:**  `PolicyParserMessageBuffer` 可能会记录解析过程中的警告或错误信息，例如拼写错误的特性名称或无效的源地址。
*   **断点调试:**  在 `permissions_policy_parser.cc` 相关的函数中设置断点，可以逐步跟踪策略字符串的解析过程，查看中间变量的值，帮助理解解析逻辑和发现问题。

希望以上分析能够帮助你更好地理解 `blink/renderer/core/permissions_policy/permissions_policy_parser.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/permissions_policy/permissions_policy_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.h"

#include <bitset>
#include <utility>

#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/metrics/histogram_macros.h"
#include "net/http/structured_headers.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/permissions_policy/origin_with_possible_wildcards.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/platform/allow_discouraged_type.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "url/origin.h"

namespace blink {
namespace {

class ParsedFeaturePolicies final
    : public GarbageCollected<ParsedFeaturePolicies>,
      public Supplement<ExecutionContext> {
 public:
  static const char kSupplementName[];

  static ParsedFeaturePolicies& From(ExecutionContext& context) {
    ParsedFeaturePolicies* policies =
        Supplement<ExecutionContext>::From<ParsedFeaturePolicies>(context);
    if (!policies) {
      policies = MakeGarbageCollected<ParsedFeaturePolicies>(context);
      Supplement<ExecutionContext>::ProvideTo(context, policies);
    }
    return *policies;
  }

  explicit ParsedFeaturePolicies(ExecutionContext& context)
      : Supplement<ExecutionContext>(context),
        policies_(static_cast<size_t>(
                      mojom::blink::PermissionsPolicyFeature::kMaxValue) +
                  1) {}

  bool Observed(mojom::blink::PermissionsPolicyFeature feature) {
    wtf_size_t feature_index = static_cast<wtf_size_t>(feature);
    if (policies_[feature_index]) {
      return true;
    }
    policies_[feature_index] = true;
    return false;
  }

 private:
  // Tracks which permissions policies have already been parsed, so as not to
  // count them multiple times.
  Vector<bool> policies_;
};

const char ParsedFeaturePolicies::kSupplementName[] = "ParsedFeaturePolicies";

class FeatureObserver {
 public:
  // Returns whether the feature has been observed before or not.
  bool FeatureObserved(mojom::blink::PermissionsPolicyFeature feature);

 private:
  std::bitset<static_cast<size_t>(
                  mojom::blink::PermissionsPolicyFeature::kMaxValue) +
              1>
      features_specified_;
};

class ParsingContext {
  STACK_ALLOCATED();

 public:
  ParsingContext(PolicyParserMessageBuffer& logger,
                 scoped_refptr<const SecurityOrigin> self_origin,
                 scoped_refptr<const SecurityOrigin> src_origin,
                 const FeatureNameMap& feature_names,
                 ExecutionContext* execution_context)
      : logger_(logger),
        self_origin_(self_origin),
        src_origin_(src_origin),
        feature_names_(feature_names),
        execution_context_(execution_context) {}

  ~ParsingContext() = default;

  ParsedPermissionsPolicy ParseFeaturePolicy(const String& policy);
  ParsedPermissionsPolicy ParsePermissionsPolicy(const String& policy);
  ParsedPermissionsPolicy ParsePolicyFromNode(
      const PermissionsPolicyParser::Node& root);

 private:
  PermissionsPolicyParser::Node ParseFeaturePolicyToIR(const String& policy);
  PermissionsPolicyParser::Node ParsePermissionsPolicyToIR(
      const String& policy);

  // normally 1 char = 1 byte
  // max length to parse = 2^16 = 64 kB
  static constexpr wtf_size_t MAX_LENGTH_PARSE = 1 << 16;

  std::optional<ParsedPermissionsPolicyDeclaration> ParseFeature(
      const PermissionsPolicyParser::Declaration& declaration_node,
      const OriginWithPossibleWildcards::NodeType type);

  struct ParsedAllowlist {
    std::vector<blink::OriginWithPossibleWildcards> allowed_origins
        ALLOW_DISCOURAGED_TYPE("Permission policy uses STL for code sharing");
    std::optional<url::Origin> self_if_matches;
    bool matches_all_origins{false};
    bool matches_opaque_src{false};

    ParsedAllowlist() : allowed_origins({}) {}
  };

  std::optional<mojom::blink::PermissionsPolicyFeature> ParseFeatureName(
      const String& feature_name);

  // Parse allowlist for feature.
  ParsedAllowlist ParseAllowlist(
      const Vector<String>& origin_strings,
      const OriginWithPossibleWildcards::NodeType type);

  void ReportFeatureUsage(mojom::blink::PermissionsPolicyFeature feature);
  void ReportFeatureUsageLegacy(mojom::blink::PermissionsPolicyFeature feature);

  // This function should be called after Allowlist Histograms related flags
  // have been captured.
  void RecordAllowlistTypeUsage(size_t origin_count);

  PolicyParserMessageBuffer& logger_;
  scoped_refptr<const SecurityOrigin> self_origin_;
  scoped_refptr<const SecurityOrigin> src_origin_;
  const FeatureNameMap& feature_names_;
  // `execution_context_` is used for reporting various WebFeatures
  // during the parsing process.
  // `execution_context_` should only be `nullptr` in tests.
  ExecutionContext* execution_context_;

  FeatureObserver feature_observer_;
};

bool FeatureObserver::FeatureObserved(
    mojom::blink::PermissionsPolicyFeature feature) {
  if (features_specified_[static_cast<size_t>(feature)]) {
    return true;
  } else {
    features_specified_.set(static_cast<size_t>(feature));
    return false;
  }
}

// TODO: Remove this function once we verified the new histogram counts
// are consistent with old ones.
void ParsingContext::ReportFeatureUsageLegacy(
    mojom::blink::PermissionsPolicyFeature feature) {
  if (!src_origin_) {
    UMA_HISTOGRAM_ENUMERATION("Blink.UseCounter.FeaturePolicy.Header", feature);
  }
}

void ParsingContext::ReportFeatureUsage(
    mojom::blink::PermissionsPolicyFeature feature) {
  if (!execution_context_ || !execution_context_->IsWindow()) {
    return;
  }

  LocalDOMWindow* local_dom_window = To<LocalDOMWindow>(execution_context_);

  auto usage_type =
      src_origin_ ? UseCounterImpl::PermissionsPolicyUsageType::kIframeAttribute
                  : UseCounterImpl::PermissionsPolicyUsageType::kHeader;

  local_dom_window->CountPermissionsPolicyUsage(feature, usage_type);
}

std::optional<mojom::blink::PermissionsPolicyFeature>
ParsingContext::ParseFeatureName(const String& feature_name) {
  DCHECK(!feature_name.empty());
  if (!feature_names_.Contains(feature_name)) {
    logger_.Warn("Unrecognized feature: '" + feature_name + "'.");
    return std::nullopt;
  }
  if (DisabledByOriginTrial(feature_name, execution_context_)) {
    logger_.Warn("Origin trial controlled feature not enabled: '" +
                 feature_name + "'.");
    return std::nullopt;
  }
  mojom::blink::PermissionsPolicyFeature feature =
      feature_names_.at(feature_name);

  if (feature == mojom::blink::PermissionsPolicyFeature::kUnload) {
    UseCounter::Count(execution_context_, WebFeature::kPermissionsPolicyUnload);
  }
  return feature;
}

ParsingContext::ParsedAllowlist ParsingContext::ParseAllowlist(
    const Vector<String>& origin_strings,
    const OriginWithPossibleWildcards::NodeType type) {
  // The source of the PermissionsPolicyParser::Node must have an explicit
  // source so that we know which wildcards can be enabled.
  DCHECK_NE(OriginWithPossibleWildcards::NodeType::kUnknown, type);
  ParsedAllowlist allowlist;
  if (origin_strings.empty()) {
    // If a policy entry has no listed origins (e.g. "feature_name1" in
    // allow="feature_name1; feature_name2 value"), enable the feature for:
    //     a. |self_origin|, if we are parsing a header policy (i.e.,
    //       |src_origin| is null);
    //     b. |src_origin|, if we are parsing an allow attribute (i.e.,
    //       |src_origin| is not null), |src_origin| is not opaque; or
    //     c. the opaque origin of the frame, if |src_origin| is opaque.
    if (!src_origin_) {
      allowlist.self_if_matches = self_origin_->ToUrlOrigin();
    } else if (!src_origin_->IsOpaque()) {
      std::optional<OriginWithPossibleWildcards>
          maybe_origin_with_possible_wildcards =
              OriginWithPossibleWildcards::FromOrigin(
                  src_origin_->ToUrlOrigin());
      if (maybe_origin_with_possible_wildcards.has_value()) {
        allowlist.allowed_origins.emplace_back(
            *maybe_origin_with_possible_wildcards);
      }
    } else {
      allowlist.matches_opaque_src = true;
    }
  } else {
    for (const String& origin_string : origin_strings) {
      DCHECK(!origin_string.empty());

      if (!origin_string.ContainsOnlyASCIIOrEmpty()) {
        logger_.Warn("Non-ASCII characters in origin.");
        continue;
      }

      // Determine the target of the declaration. This may be a specific
      // origin, either explicitly written, or one of the special keywords
      // 'self' or 'src'. ('src' can only be used in the iframe allow
      // attribute.) Also determine if this target has a subdomain wildcard
      // (e.g., https://*.google.com).
      OriginWithPossibleWildcards origin_with_possible_wildcards;

      // If the iframe will have an opaque origin (for example, if it is
      // sandboxed, or has a data: URL), then 'src' needs to refer to the
      // opaque origin of the frame, which is not known yet. In this case,
      // the |matches_opaque_src| flag on the declaration is set, rather than
      // adding an origin to the allowlist.
      bool target_is_opaque = false;
      bool target_is_all = false;
      bool target_is_self = false;
      url::Origin self;

      // 'self' origin is used if the origin is exactly 'self'.
      if (EqualIgnoringASCIICase(origin_string, "'self'")) {
        target_is_self = true;
        self = self_origin_->ToUrlOrigin();
      }
      // 'src' origin is used if |src_origin| is available and the
      // origin is a match for 'src'. |src_origin| is only set
      // when parsing an iframe allow attribute.
      else if (src_origin_ && EqualIgnoringASCIICase(origin_string, "'src'")) {
        if (!src_origin_->IsOpaque()) {
          std::optional<OriginWithPossibleWildcards>
              maybe_origin_with_possible_wildcards =
                  OriginWithPossibleWildcards::FromOrigin(
                      src_origin_->ToUrlOrigin());
          if (maybe_origin_with_possible_wildcards.has_value()) {
            origin_with_possible_wildcards =
                *maybe_origin_with_possible_wildcards;
          } else {
            continue;
          }
        } else {
          target_is_opaque = true;
        }
      } else if (EqualIgnoringASCIICase(origin_string, "'none'")) {
        continue;
      } else if (origin_string == "*") {
        target_is_all = true;
      }
      // Otherwise, parse the origin string and verify that the result is
      // valid. Invalid strings will produce an opaque origin, which will
      // result in an error message.
      else {
        std::optional<OriginWithPossibleWildcards>
            maybe_origin_with_possible_wildcards =
                OriginWithPossibleWildcards::Parse(origin_string.Utf8(), type);
        if (maybe_origin_with_possible_wildcards.has_value()) {
          origin_with_possible_wildcards =
              *maybe_origin_with_possible_wildcards;
        } else {
          logger_.Warn("Unrecognized origin: '" + origin_string + "'.");
          continue;
        }
      }

      if (target_is_all) {
        allowlist.matches_all_origins = true;
        allowlist.matches_opaque_src = true;
      } else if (target_is_opaque) {
        allowlist.matches_opaque_src = true;
      } else if (target_is_self) {
        allowlist.self_if_matches = self;
      } else {
        allowlist.allowed_origins.emplace_back(origin_with_possible_wildcards);
      }
    }
  }

  // Size reduction: remove all items in the allowlist if target is all.
  if (allowlist.matches_all_origins) {
    allowlist.allowed_origins.clear();
  }

  // Sort |allowed_origins| in alphabetical order.
  std::sort(allowlist.allowed_origins.begin(), allowlist.allowed_origins.end());

  return allowlist;
}

std::optional<ParsedPermissionsPolicyDeclaration> ParsingContext::ParseFeature(
    const PermissionsPolicyParser::Declaration& declaration_node,
    const OriginWithPossibleWildcards::NodeType type) {
  std::optional<mojom::blink::PermissionsPolicyFeature> feature =
      ParseFeatureName(declaration_node.feature_name);
  if (!feature) {
    return std::nullopt;
  }

  ParsedAllowlist parsed_allowlist =
      ParseAllowlist(declaration_node.allowlist, type);

  // If same feature appeared more than once, only the first one counts.
  if (feature_observer_.FeatureObserved(*feature)) {
    return std::nullopt;
  }

  ParsedPermissionsPolicyDeclaration parsed_feature(*feature);
  parsed_feature.allowed_origins = std::move(parsed_allowlist.allowed_origins);
  parsed_feature.self_if_matches = parsed_allowlist.self_if_matches;
  parsed_feature.matches_all_origins = parsed_allowlist.matches_all_origins;
  parsed_feature.matches_opaque_src = parsed_allowlist.matches_opaque_src;
  if (declaration_node.endpoint.IsNull()) {
    parsed_feature.reporting_endpoint = std::nullopt;
  } else {
    parsed_feature.reporting_endpoint = declaration_node.endpoint.Ascii();
  }

  return parsed_feature;
}

ParsedPermissionsPolicy ParsingContext::ParseFeaturePolicy(
    const String& policy) {
  return ParsePolicyFromNode(ParseFeaturePolicyToIR(policy));
}

ParsedPermissionsPolicy ParsingContext::ParsePermissionsPolicy(
    const String& policy) {
  return ParsePolicyFromNode(ParsePermissionsPolicyToIR(policy));
}

ParsedPermissionsPolicy ParsingContext::ParsePolicyFromNode(
    const PermissionsPolicyParser::Node& root) {
  ParsedPermissionsPolicy parsed_policy;
  for (const PermissionsPolicyParser::Declaration& declaration_node :
       root.declarations) {
    std::optional<ParsedPermissionsPolicyDeclaration> parsed_feature =
        ParseFeature(declaration_node, root.type);
    if (parsed_feature) {
      ReportFeatureUsage(parsed_feature->feature);
      ReportFeatureUsageLegacy(parsed_feature->feature);
      parsed_policy.push_back(*parsed_feature);
    }
  }
  return parsed_policy;
}

PermissionsPolicyParser::Node ParsingContext::ParseFeaturePolicyToIR(
    const String& policy) {
  PermissionsPolicyParser::Node root{
      OriginWithPossibleWildcards::NodeType::kAttribute};

  if (policy.length() > MAX_LENGTH_PARSE) {
    logger_.Error("Feature policy declaration exceeds size limit(" +
                  String::Number(policy.length()) + ">" +
                  String::Number(MAX_LENGTH_PARSE) + ")");
    return {};
  }

  Vector<String> policy_items;

  if (src_origin_) {
    // Attribute parsing.
    policy_items.push_back(policy);
  } else {
    // Header parsing.
    // RFC2616, section 4.2 specifies that headers appearing multiple times can
    // be combined with a comma. Walk the header string, and parse each comma
    // separated chunk as a separate header.
    // policy_items = [ policy *( "," [ policy ] ) ]
    policy.Split(',', policy_items);
  }

  if (policy_items.size() > 1) {
    UseCounter::Count(
        execution_context_,
        mojom::blink::WebFeature::kFeaturePolicyCommaSeparatedDeclarations);
  }

  for (const String& item : policy_items) {
    Vector<String> feature_entries;
    // feature_entries = [ feature_entry *( ";" [ feature_entry ] ) ]
    item.Split(';', feature_entries);

    if (feature_entries.size() > 1) {
      UseCounter::Count(execution_context_,
                        mojom::blink::WebFeature::
                            kFeaturePolicySemicolonSeparatedDeclarations);
    }

    for (const String& feature_entry : feature_entries) {
      Vector<String> tokens = SplitOnASCIIWhitespace(feature_entry);

      if (tokens.empty()) {
        continue;
      }

      PermissionsPolicyParser::Declaration declaration_node;
      // Break tokens into head & tail, where
      // head = feature_name
      // tail = allowlist
      // After feature_name has been set, take tail of tokens vector by
      // erasing the first element.
      declaration_node.feature_name = std::move(tokens.front());
      tokens.erase(tokens.begin());
      declaration_node.allowlist = std::move(tokens);
      root.declarations.push_back(declaration_node);
    }
  }

  return root;
}

PermissionsPolicyParser::Node ParsingContext::ParsePermissionsPolicyToIR(
    const String& policy) {
  if (policy.length() > MAX_LENGTH_PARSE) {
    logger_.Error("Permissions policy declaration exceeds size limit(" +
                  String::Number(policy.length()) + ">" +
                  String::Number(MAX_LENGTH_PARSE) + ")");
    return {};
  }

  auto root = net::structured_headers::ParseDictionary(policy.Utf8());
  if (!root) {
    logger_.Error(
        "Parse of permissions policy failed because of errors reported by "
        "structured header parser.");
    return {};
  }

  PermissionsPolicyParser::Node ir_root{
      OriginWithPossibleWildcards::NodeType::kHeader};
  for (const auto& feature_entry : root.value()) {
    const auto& key = feature_entry.first;
    const char* feature_name = key.c_str();
    const auto& value = feature_entry.second;
    String endpoint;

    if (!value.params.empty()) {
      for (const auto& param : value.params) {
        if (param.first == "report-to" && param.second.is_token()) {
          endpoint = String(param.second.GetString());
        }
      }
    }

    Vector<String> allowlist;
    for (const auto& parameterized_item : value.member) {
      if (!parameterized_item.params.empty()) {
        logger_.Warn(String::Format("Feature %s's parameters are ignored.",
                                    feature_name));
      }

      String allowlist_item;
      if (parameterized_item.item.is_token()) {
        // All special keyword appears as token, i.e. self, src and *.
        const std::string& token_value = parameterized_item.item.GetString();
        if (token_value != "*" && token_value != "self") {
          logger_.Warn(String::Format(
              "Invalid allowlist item(%s) for feature %s. Allowlist item "
              "must be *, self or quoted url.",
              token_value.c_str(), feature_name));
          continue;
        }

        if (token_value == "*") {
          allowlist_item = "*";
        } else {
          allowlist_item = String::Format("'%s'", token_value.c_str());
        }
      } else if (parameterized_item.item.is_string()) {
        allowlist_item = parameterized_item.item.GetString().c_str();
      } else {
        logger_.Warn(
            String::Format("Invalid allowlist item for feature %s. Allowlist "
                           "item must be *, self, or quoted url.",
                           feature_name));
        continue;
      }
      if (!allowlist_item.empty()) {
        allowlist.push_back(allowlist_item);
      }
    }

    if (allowlist.empty()) {
      allowlist.push_back("'none'");
    }

    ir_root.declarations.push_back(PermissionsPolicyParser::Declaration{
        feature_name, std::move(allowlist), endpoint});
  }

  return ir_root;
}

}  // namespace

ParsedPermissionsPolicy PermissionsPolicyParser::ParseHeader(
    const String& feature_policy_header,
    const String& permissions_policy_header,
    scoped_refptr<const SecurityOrigin> origin,
    PolicyParserMessageBuffer& feature_policy_logger,
    PolicyParserMessageBuffer& permissions_policy_logger,
    ExecutionContext* execution_context) {
  bool is_isolated_context =
      execution_context && execution_context->IsIsolatedContext();
  ParsedPermissionsPolicy permissions_policy =
      ParsingContext(permissions_policy_logger, origin, nullptr,
                     GetDefaultFeatureNameMap(is_isolated_context),
                     execution_context)
          .ParsePermissionsPolicy(permissions_policy_header);
  ParsedPermissionsPolicy feature_policy =
      ParsingContext(feature_policy_logger, origin, nullptr,
                     GetDefaultFeatureNameMap(is_isolated_context),
                     execution_context)
          .ParseFeaturePolicy(feature_policy_header);

  FeatureObserver observer;
  for (const auto& policy_declaration : permissions_policy) {
    bool feature_observed =
        observer.FeatureObserved(policy_declaration.feature);
    DCHECK(!feature_observed);
  }

  std::vector<std::string> overlap_features;

  for (const auto& policy_declaration : feature_policy) {
    if (!observer.FeatureObserved(policy_declaration.feature)) {
      permissions_policy.push_back(policy_declaration);
    } else {
      overlap_features.push_back(
          GetNameForFeature(policy_declaration.feature, is_isolated_context)
              .Ascii()
              .c_str());
    }
  }

  if (!overlap_features.empty()) {
    std::ostringstream features_stream;
    std::copy(overlap_features.begin(), overlap_features.end() - 1,
              std::ostream_iterator<std::string>(features_stream, ", "));
    features_stream << overlap_features.back();

    feature_policy_logger.Warn(String::Format(
        "Some features are specified in both Feature-Policy and "
        "Permissions-Policy header: %s. Values defined in Permissions-Policy "
        "header will be used.",
        features_stream.str().c_str()));
  }
  return permissions_policy;
}

ParsedPermissionsPolicy PermissionsPolicyParser::ParseAttribute(
    const String& policy,
    scoped_refptr<const SecurityOrigin> self_origin,
    scoped_refptr<const SecurityOrigin> src_origin,
    PolicyParserMessageBuffer& logger,
    ExecutionContext* execution_context) {
  bool is_isolated_context =
      execution_context && execution_context->IsIsolatedContext();
  return ParsingContext(logger, self_origin, src_origin,
                        GetDefaultFeatureNameMap(is_isolated_context),
                        execution_context)
      .ParseFeaturePolicy(policy);
}

ParsedPermissionsPolicy PermissionsPolicyParser::ParsePolicyFromNode(
    PermissionsPolicyParser::Node& policy,
    scoped_refptr<const SecurityOrigin> origin,
    PolicyParserMessageBuffer& logger,
    ExecutionContext* execution_context) {
  bool is_isolated_context =
      execution_context && execution_context->IsIsolatedContext();
  return ParsingContext(logger, origin, /*src_origin=*/nullptr,
                        GetDefaultFeatureNameMap(is_isolated_context),
                        execution_context)
      .ParsePolicyFromNode(policy);
}

ParsedPermissionsPolicy PermissionsPolicyParser::ParseFeaturePolicyForTest(
    const String& policy,
    scoped_refptr<const SecurityOrigin> self_origin,
    scoped_refptr<const SecurityOrigin> src_origin,
    PolicyParserMessageBuffer& logger,
    const FeatureNameMap& feature_names,
    ExecutionContext* execution_context) {
  return ParsingContext(logger, self_origin, src_origin, feature_names,
                        execution_context)
      .ParseFeaturePolicy(policy);
}

ParsedPermissionsPolicy PermissionsPolicyParser::ParsePermissionsPolicyForTest(
    const String& policy,
    scoped_refptr<const SecurityOrigin> self_origin,
    scoped_refptr<const SecurityOrigin> src_origin,
    PolicyParserMessageBuffer& logger,
    const FeatureNameMap& feature_names,
    ExecutionContext* execution_context) {
  return ParsingContext(logger, self_origin, src_origin, feature_names,
                        execution_context)
      .ParsePermissionsPolicy(policy);
}

bool IsFeatureDeclared(mojom::blink::PermissionsPolicyFeature feature,
                       const ParsedPermissionsPolicy& policy) {
  return base::Contains(policy, feature,
                        &ParsedPermissionsPolicyDeclaration::feature);
}

bool RemoveFeatureIfPresent(mojom::blink::PermissionsPolicyFeature feature,
                            ParsedPermissionsPolicy& policy) {
  auto new_end = std::remove_if(policy.begin(), policy.end(),
                                [feature](const auto& declaration) {
                                  return declaration.feature == feature;
                                });
  if (new_end == policy.end()) {
    return false;
  }
  policy.erase(new_end, policy.end());
  return true;
}

bool DisallowFeatureIfNotPresent(mojom::blink::PermissionsPolicyFeature feature,
                                 ParsedPermissionsPolicy& policy) {
  if (IsFeatureDeclared(feature, policy)) {
    return false;
  }
  ParsedPermissionsPolicyDeclaration allowlist(feature);
  policy.push_back(allowlist);
  return true;
}

bool AllowFeatureEverywhereIfNotPresent(
    mojom::blink::PermissionsPolicyFeature feature,
    ParsedPermissionsPolicy& policy) {
  if (IsFeatureDeclared(feature, policy)) {
    return false;
  }
  ParsedPermissionsPolicyDeclaration allowlist(feature);
  allowlist.matches_all_origins = true;
  allowlist.matches_opaque_src = true;
  policy.push_back(allowlist);
  return true;
}

void DisallowFeature(mojom::blink::PermissionsPolicyFeature feature,
                     ParsedPermissionsPolicy& policy) {
  RemoveFeatureIfPresent(feature, policy);
  DisallowFeatureIfNotPresent(feature, policy);
}

bool IsFeatureForMeasurementOnly(
    mojom::blink::PermissionsPolicyFeature feature) {
  return feature == mojom::blink::PermissionsPolicyFeature::kWebShare;
}

void AllowFeatureEverywhere(mojom::blink::PermissionsPolicyFeature feature,
                            ParsedPermissionsPolicy& policy) {
  RemoveFeatureIfPresent(feature, policy);
  AllowFeatureEverywhereIfNotPresent(feature, policy);
}

const Vector<String> GetAvailableFeatures(ExecutionContext* execution_context) {
  Vector<String> available_features;
  bool is_isolated_context =
      execution_context && execution_context->IsIsolatedContext();
  for (const auto& feature : GetDefaultFeatureNameMap(is_isolated_context)) {
    if (!DisabledByOriginTrial(feature.key, execution_context) &&
        !IsFeatureForMeasurementOnly(feature.value)) {
      available_features.push_back(feature.key);
    }
  }
  return available_features;
}

const String GetNameForFeature(mojom::blink::PermissionsPolicyFeature feature,
                               bool is_isolated_context) {
  for (const auto& entry : GetDefaultFeatureNameMap(is_isolated_context)) {
    if (entry.value == feature) {
      return entry.key;
    }
  }
  return g_empty_string;
}

}  // namespace blink

"""

```