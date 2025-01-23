Response: Let's break down the request and the provided code to generate the response.

**1. Understanding the Goal:**

The core request is to understand the functionality of `address_space_feature.cc` within the Chromium Blink engine. Specifically, I need to:

* **Summarize the core purpose.**
* **Explain its relationship to JavaScript, HTML, and CSS (if any).** This requires connecting the low-level security concepts to the web developer's perspective.
* **Provide examples of logical inference with inputs and outputs.**  This involves understanding the decision-making process within the code.
* **Identify potential user/programmer errors.** This requires thinking about how the system could be misused or misinterpreted.

**2. Analyzing the Code:**

* **Copyright and Headers:**  Standard boilerplate. The inclusion of `third_party/blink/public/common/security/address_space_feature.h` hints at this being part of a security mechanism.
* **Namespaces:** `blink` and the anonymous namespace suggest internal Blink functionality.
* **Type Aliases:** `AddressSpace` and `Feature` are defined using `network::mojom::IPAddressSpace` and `mojom::WebFeature`. This immediately tells us we're dealing with network security concepts (IP address spaces) and some internal Blink feature enumeration. The `mojom` namespace suggests this might involve inter-process communication (IPC), but that's not directly relevant to the user-facing features.
* **`FeatureKey` struct:** This is a crucial data structure. It combines the client's address space, whether the client is in a secure context, and the response's address space. This strongly indicates that the code is about making decisions based on the network locations and security context of requests.
* **`operator==` for `FeatureKey`:**  Simple equality comparison, necessary for using `FeatureKey` as a lookup key.
* **`FeatureEntry` struct:**  This links a `FeatureKey` to two `Feature` values: one for subresources and one for navigations. This tells us the decision-making might differ based on the type of request.
* **`kNonSecureContext` and `kSecureContext`:**  Constants that make the `kFeatureMap` more readable.
* **`kFeatureMap` array:**  This is the heart of the logic. It's a lookup table that maps combinations of client address space, client security context, and response address space to specific `Feature` enums. Each entry has distinct `Feature` values for subresource and navigation fetches. The naming convention of the `Feature` enums (e.g., `kAddressSpacePrivateNonSecureContextEmbeddedLocal`) is very descriptive and helps understand the purpose.
* **`FindFeatureEntry` function:** A simple linear search through `kFeatureMap` to find a matching entry.
* **`AddressSpaceFeature` function:** This is the public interface. It takes the fetch type, client address space, client secure context, and response address space as input. It constructs a `FeatureKey`, looks it up in the map, and returns the corresponding `Feature` based on the fetch type.

**3. Connecting to Web Technologies:**

* **Address Spaces:** The concepts of "Public," "Private," and "Local" address spaces directly relate to how web pages can access resources. A "Local" address might refer to a resource on the user's own machine (e.g., `localhost`). "Private" refers to internal networks. "Public" is the general internet.
* **Secure Context:**  This is fundamental to web security. HTTPS establishes a secure context. Features and behaviors can be gated based on whether the browsing context is secure.
* **Subresources:** These are the resources embedded within a web page (images, scripts, stylesheets, etc.).
* **Navigations:**  These are when the user navigates to a new page.

**4. Formulating the Response:**

Based on the code analysis, I can now construct the response, ensuring I cover all the required points:

* **Functionality:** Describe the purpose of the code as a security mechanism to determine and enable/disable features based on the network address spaces and security context of requests.
* **Relationship to Web Technologies:** Explain how the address spaces and secure context relate to JavaScript, HTML, and CSS. Give concrete examples of how this might affect things like fetching images from a local server or using certain JavaScript APIs in an insecure context.
* **Logical Inference:** Create example scenarios with different inputs (address spaces, secure context, fetch type) and show the corresponding output (the `Feature` enum).
* **User/Programmer Errors:** Think about how developers might misuse or misunderstand this system. For example, a developer might assume a local resource will always be accessible, regardless of the requesting page's context.

**5. Refinement and Clarity:**

Review the generated response to ensure clarity, accuracy, and conciseness. Use clear and simple language, avoiding overly technical jargon where possible. Make sure the examples are easy to understand and directly illustrate the points being made.

By following this thought process, I can arrive at a comprehensive and accurate explanation of the provided code and its role within the Chromium Blink engine.
```cpp
/*
 * Copyright (C) 2020 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/public/common/security/address_space_feature.h"

#include <tuple>

namespace blink {
namespace {

using AddressSpace = network::mojom::IPAddressSpace;
using Feature = mojom::WebFeature;

// A key in |kFeatureMap|.
//
// Mirrors the arguments to |AddressSpaceFeature()| except for |fetch_type|.
struct FeatureKey {
  AddressSpace client_address_space;
  bool client_is_secure_context;
  AddressSpace response_address_space;
};

// FeatureKey instances are comparable for equality.
bool operator==(const FeatureKey& lhs, const FeatureKey& rhs) {
  return std::tie(lhs.client_address_space, lhs.client_is_secure_context,
                  lhs.response_address_space) ==
         std::tie(rhs.client_address_space, rhs.client_is_secure_context,
                  rhs.response_address_space);
}

// An entry in |kFeatureMap|.
//
// A single key maps to features for all |fetch_type| values. We could instead
// have two maps, one for subresources and one for navigations, but they would
// have the exact same set of keys. Hence it is simpler to have a single map.
struct FeatureEntry {
  // The key to this entry.
  FeatureKey key;

  // The corresponding feature for |kSubresource| fetch types.
  Feature subresource_feature;

  // The corresponding feature for |kNavigation| fetch types.
  Feature navigation_feature;
};

constexpr bool kNonSecureContext = false;
constexpr bool kSecureContext = true;

constexpr struct FeatureEntry kFeatureMap[] = {
    {
        {AddressSpace::kPrivate, kNonSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpacePrivateNonSecureContextEmbeddedLocal,
        Feature::kAddressSpacePrivateNonSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kPrivate, kSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpacePrivateSecureContextEmbeddedLocal,
        Feature::kAddressSpacePrivateSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kPublic, kNonSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpacePublicNonSecureContextEmbeddedLocal,
        Feature::kAddressSpacePublicNonSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kPublic, kSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpacePublicSecureContextEmbeddedLocal,
        Feature::kAddressSpacePublicSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kPublic, kNonSecureContext, AddressSpace::kPrivate},
        Feature::kAddressSpacePublicNonSecureContextEmbeddedPrivate,
        Feature::kAddressSpacePublicNonSecureContextNavigatedToPrivate,
    },
    {
        {AddressSpace::kPublic, kSecureContext, AddressSpace::kPrivate},
        Feature::kAddressSpacePublicSecureContextEmbeddedPrivate,
        Feature::kAddressSpacePublicSecureContextNavigatedToPrivate,
    },
    {
        {AddressSpace::kUnknown, kNonSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpaceUnknownNonSecureContextEmbeddedLocal,
        Feature::kAddressSpaceUnknownNonSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kUnknown, kSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpaceUnknownSecureContextEmbeddedLocal,
        Feature::kAddressSpaceUnknownSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kUnknown, kNonSecureContext, AddressSpace::kPrivate},
        Feature::kAddressSpaceUnknownNonSecureContextEmbeddedPrivate,
        Feature::kAddressSpaceUnknownNonSecureContextNavigatedToPrivate,
    },
    {
        {AddressSpace::kUnknown, kSecureContext, AddressSpace::kPrivate},
        Feature::kAddressSpaceUnknownSecureContextEmbeddedPrivate,
        Feature::kAddressSpaceUnknownSecureContextNavigatedToPrivate,
    },
};

// Attempts to find an entry matching |key| in |kFeatureMap|.
// Returns a pointer to the entry if successful, nullptr otherwise.
const FeatureEntry* FindFeatureEntry(const FeatureKey& key) {
  for (const FeatureEntry& entry : kFeatureMap) {
    if (key == entry.key) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace

std::optional<Feature> AddressSpaceFeature(
    FetchType fetch_type,
    AddressSpace client_address_space,
    bool client_is_secure_context,
    AddressSpace response_address_space) {
  FeatureKey key;
  key.client_address_space = client_address_space;
  key.client_is_secure_context = client_is_secure_context;
  key.response_address_space = response_address_space;

  const FeatureEntry* entry = FindFeatureEntry(key);
  if (!entry) {
    return std::nullopt;
  }

  switch (fetch_type) {
    case FetchType::kSubresource:
      return entry->subresource_feature;
    case FetchType::kNavigation:
      return entry->navigation_feature;
  }
}

}  // namespace blink
```

### 功能列举

`blink/common/security/address_space_feature.cc` 文件的主要功能是：

1. **定义和实现了一个用于确定特定 Web 功能是否应该启用的机制，该机制基于请求的发起方（客户端）和目标资源（响应）的网络地址空间以及客户端的安全上下文。**  它本质上是一个策略查找表。

2. **维护了一个映射表 `kFeatureMap`，该表存储了不同场景下（客户端地址空间、客户端是否安全上下文、响应地址空间的不同组合）对应的 `WebFeature` 枚举值。** 这些 `WebFeature` 枚举值代表了可能需要根据安全策略启用或禁用的具体浏览器功能。

3. **提供了一个公共函数 `AddressSpaceFeature`，该函数接受四个参数：**
    * `fetch_type`:  指示请求类型，例如是加载子资源 (`kSubresource`) 还是导航 (`kNavigation`)。
    * `client_address_space`:  请求发起方的网络地址空间（例如，公共网络、私有网络、本地网络或未知）。
    * `client_is_secure_context`:  一个布尔值，指示请求是否从安全上下文（例如，HTTPS 页面）发起。
    * `response_address_space`:  目标资源的网络地址空间。
    **该函数根据这四个参数，在 `kFeatureMap` 中查找对应的 `WebFeature`，并将其作为 `std::optional<Feature>` 返回。** 如果找不到匹配的条目，则返回 `std::nullopt`。

**核心思想是通过限制不同安全级别的上下文访问特定网络位置的资源，来增强 Web 安全性。**  例如，防止公共网络上的不安全页面访问本地网络上的资源。

### 与 JavaScript, HTML, CSS 的关系及举例说明

虽然此 C++ 代码本身不直接涉及 JavaScript, HTML, 或 CSS 的语法，但它 **直接影响** 这些技术的功能和行为。它决定了在特定场景下，浏览器是否允许执行某些操作，而这些操作通常由 JavaScript 发起，并作用于 HTML 和 CSS 资源。

**举例说明：**

1. **JavaScript `fetch()` API 和 `XMLHttpRequest`：** 当 JavaScript 代码使用 `fetch()` 或 `XMLHttpRequest` 发起网络请求时，浏览器会调用类似 `AddressSpaceFeature` 的机制来检查请求是否应该被允许。

   * **假设输入：**
      * `fetch_type`: `FetchType::kSubresource` (加载图片)
      * `client_address_space`: `AddressSpace::kPublic` (来自公共网络的页面)
      * `client_is_secure_context`: `kNonSecureContext` (页面是通过 HTTP 加载的)
      * `response_address_space`: `AddressSpace::kLocal` (请求本地服务器上的图片 `http://localhost/image.png`)
   * **可能输出 (根据 `kFeatureMap`):** `Feature::kAddressSpacePublicNonSecureContextEmbeddedLocal`
   * **结果：**  浏览器可能会根据配置，禁用或限制这种跨越地址空间的请求。例如，可能阻止加载图片，并在开发者控制台中抛出错误。这可以防止公共网络上的不安全页面探测用户本地网络的服务。

2. **HTML `<img>` 标签：**  当 HTML 中使用 `<img>` 标签加载图片时，浏览器也会进行类似的检查。

   * **假设输入：**
      * `fetch_type`: `FetchType::kSubresource` (加载图片)
      * `client_address_space`: `AddressSpace::kPrivate` (来自内网的页面)
      * `client_is_secure_context`: `kSecureContext` (页面是通过 HTTPS 加载的)
      * `response_address_space`: `AddressSpace::kLocal` (请求本地服务器上的图片)
   * **可能输出 (根据 `kFeatureMap`):** `Feature::kAddressSpacePrivateSecureContextEmbeddedLocal`
   * **结果：**  浏览器可能会允许这种请求，因为来自私有网络的 HTTPS 页面访问本地资源通常被认为是安全的。

3. **CSS `@import` 和 `url()`：**  CSS 中使用 `@import` 引入其他样式表或 `url()` 引用资源时，同样会受到地址空间策略的影响。

   * **假设输入：**
      * `fetch_type`: `FetchType::kSubresource` (加载 CSS)
      * `client_address_space`: `AddressSpace::kPublic` (来自公共网络的页面)
      * `client_is_secure_context`: `kNonSecureContext`
      * `response_address_space`: `AddressSpace::kPrivate` (尝试加载内网服务器上的 CSS 文件)
   * **可能输出 (根据 `kFeatureMap`):** `Feature::kAddressSpacePublicNonSecureContextEmbeddedPrivate`
   * **结果：**  浏览器可能会阻止加载该 CSS 文件，从而影响页面的样式。

**总结：**  `address_space_feature.cc` 中定义的策略决定了浏览器对于不同来源的页面加载不同目标的资源的行为。这直接影响了 Web 开发中资源加载、跨域请求等行为，开发者需要理解这些限制才能构建安全可靠的 Web 应用。

### 逻辑推理与假设输入输出

`AddressSpaceFeature` 函数的核心逻辑是查找 `kFeatureMap`。

**假设输入 1 (子资源请求):**

* `fetch_type`: `FetchType::kSubresource`
* `client_address_space`: `AddressSpace::kPublic`
* `client_is_secure_context`: `false`
* `response_address_space`: `AddressSpace::kLocal`

**逻辑推理:** 函数会创建一个 `FeatureKey`  `{AddressSpace::kPublic, false, AddressSpace::kLocal}`。然后在 `kFeatureMap` 中查找匹配的 `FeatureEntry`。找到匹配项：

```c++
{
    {AddressSpace::kPublic, kNonSecureContext, AddressSpace::kLocal},
    Feature::kAddressSpacePublicNonSecureContextEmbeddedLocal,
    Feature::kAddressSpacePublicNonSecureContextNavigatedToLocal,
},
```

由于 `fetch_type` 是 `kSubresource`，函数会返回 `entry->subresource_feature`。

**输出 1:** `std::optional<Feature>(Feature::kAddressSpacePublicNonSecureContextEmbeddedLocal)`

**假设输入 2 (导航请求):**

* `fetch_type`: `FetchType::kNavigation`
* `client_address_space`: `AddressSpace::kPrivate`
* `client_is_secure_context`: `true`
* `response_address_space`: `AddressSpace::kLocal`

**逻辑推理:** 函数会创建一个 `FeatureKey` `{AddressSpace::kPrivate, true, AddressSpace::kLocal}`。然后在 `kFeatureMap` 中查找匹配的 `FeatureEntry`。找到匹配项：

```c++
{
    {AddressSpace::kPrivate, kSecureContext, AddressSpace::kLocal},
    Feature::kAddressSpacePrivateSecureContextEmbeddedLocal,
    Feature::kAddressSpacePrivateSecureContextNavigatedToLocal,
},
```

由于 `fetch_type` 是 `kNavigation`，函数会返回 `entry->navigation_feature`。

**输出 2:** `std::optional<Feature>(Feature::kAddressSpacePrivateSecureContextNavigatedToLocal)`

**假设输入 3 (找不到匹配项):**

* `fetch_type`: `FetchType::kSubresource`
* `client_address_space`: `AddressSpace::kPublic`
* `client_is_secure_context`: `true`
* `response_address_space`: `AddressSpace::kUnknown`

**逻辑推理:** 函数会创建一个 `FeatureKey` `{AddressSpace::kPublic, true, AddressSpace::kUnknown}`。在 `kFeatureMap` 中没有直接匹配的条目。

**输出 3:** `std::nullopt`

### 用户或编程常见的使用错误

由于这个文件是 Chromium 内部的实现，普通用户不会直接与之交互。然而，Web 开发者可能会因为不理解其背后的逻辑而犯一些错误，导致他们的网站或应用出现意外的行为。

1. **假设所有本地资源都可访问：** 开发者可能会认为，只要资源位于 `localhost` 或内网，就可以从任何页面访问。但 `AddressSpaceFeature` 的策略可能会阻止公共网络上的非安全页面访问本地或私有网络资源。

   * **错误示例：**  一个通过 HTTP 提供的公共网站试图加载本地服务器上的一个 API (`http://localhost:8080/api/data`). 由于安全策略，这个请求可能被阻止，导致网站功能异常。

2. **忽略安全上下文的重要性：** 开发者可能没有意识到 HTTPS 对于某些跨域或跨地址空间请求的重要性。

   * **错误示例：**  一个通过 HTTP 提供的页面试图加载来自私有网络的敏感信息。即使目标资源允许跨域请求，但由于发起请求的页面不是 HTTPS，浏览器可能会阻止该请求。

3. **不理解不同 `fetch_type` 的影响：**  开发者可能没有意识到，对于相同的地址空间组合，子资源请求和导航请求可能适用不同的策略。

   * **错误示例：**  一个公共的 HTTP 页面可能无法使用 `<img>` 标签加载本地图片，但可能允许通过 `window.location.href` 导航到本地的 HTML 文件（虽然这通常不是一个好的做法）。

4. **配置错误导致地址空间判断错误：**  在某些复杂的网络配置中，服务器或客户端的地址空间可能被错误地识别。这可能会导致 `AddressSpaceFeature` 返回意外的结果。

   * **错误示例：**  如果一个内网应用被错误地配置为暴露在公网上，浏览器可能会将其来源地址空间判断为 `Public`，从而应用更严格的安全策略，导致一些原本应该允许的内网资源请求被阻止。

**最佳实践：**

* **始终使用 HTTPS：**  使用 HTTPS 可以提高页面的安全级别，从而在某些情况下允许访问更多资源。
* **遵循同源策略和 CORS：**  理解并正确配置跨域资源共享 (CORS) 可以控制哪些外部域可以访问你的资源。
* **避免从公共网络上的非安全页面访问本地或私有网络资源：**  这通常是安全风险，浏览器会采取措施阻止此类行为。
* **测试不同安全上下文和网络环境下的应用：**  确保应用在不同的场景下都能正常工作，特别是涉及到跨域或跨地址空间资源访问时。

### 提示词
```
这是目录为blink/common/security/address_space_feature.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2020 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/public/common/security/address_space_feature.h"

#include <tuple>

namespace blink {
namespace {

using AddressSpace = network::mojom::IPAddressSpace;
using Feature = mojom::WebFeature;

// A key in |kFeatureMap|.
//
// Mirrors the arguments to |AddressSpaceFeature()| except for |fetch_type|.
struct FeatureKey {
  AddressSpace client_address_space;
  bool client_is_secure_context;
  AddressSpace response_address_space;
};

// FeatureKey instances are comparable for equality.
bool operator==(const FeatureKey& lhs, const FeatureKey& rhs) {
  return std::tie(lhs.client_address_space, lhs.client_is_secure_context,
                  lhs.response_address_space) ==
         std::tie(rhs.client_address_space, rhs.client_is_secure_context,
                  rhs.response_address_space);
}

// An entry in |kFeatureMap|.
//
// A single key maps to features for all |fetch_type| values. We could instead
// have two maps, one for subresources and one for navigations, but they would
// have the exact same set of keys. Hence it is simpler to have a single map.
struct FeatureEntry {
  // The key to this entry.
  FeatureKey key;

  // The corresponding feature for |kSubresource| fetch types.
  Feature subresource_feature;

  // The corresponding feature for |kNavigation| fetch types.
  Feature navigation_feature;
};

constexpr bool kNonSecureContext = false;
constexpr bool kSecureContext = true;

constexpr struct FeatureEntry kFeatureMap[] = {
    {
        {AddressSpace::kPrivate, kNonSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpacePrivateNonSecureContextEmbeddedLocal,
        Feature::kAddressSpacePrivateNonSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kPrivate, kSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpacePrivateSecureContextEmbeddedLocal,
        Feature::kAddressSpacePrivateSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kPublic, kNonSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpacePublicNonSecureContextEmbeddedLocal,
        Feature::kAddressSpacePublicNonSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kPublic, kSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpacePublicSecureContextEmbeddedLocal,
        Feature::kAddressSpacePublicSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kPublic, kNonSecureContext, AddressSpace::kPrivate},
        Feature::kAddressSpacePublicNonSecureContextEmbeddedPrivate,
        Feature::kAddressSpacePublicNonSecureContextNavigatedToPrivate,
    },
    {
        {AddressSpace::kPublic, kSecureContext, AddressSpace::kPrivate},
        Feature::kAddressSpacePublicSecureContextEmbeddedPrivate,
        Feature::kAddressSpacePublicSecureContextNavigatedToPrivate,
    },
    {
        {AddressSpace::kUnknown, kNonSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpaceUnknownNonSecureContextEmbeddedLocal,
        Feature::kAddressSpaceUnknownNonSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kUnknown, kSecureContext, AddressSpace::kLocal},
        Feature::kAddressSpaceUnknownSecureContextEmbeddedLocal,
        Feature::kAddressSpaceUnknownSecureContextNavigatedToLocal,
    },
    {
        {AddressSpace::kUnknown, kNonSecureContext, AddressSpace::kPrivate},
        Feature::kAddressSpaceUnknownNonSecureContextEmbeddedPrivate,
        Feature::kAddressSpaceUnknownNonSecureContextNavigatedToPrivate,
    },
    {
        {AddressSpace::kUnknown, kSecureContext, AddressSpace::kPrivate},
        Feature::kAddressSpaceUnknownSecureContextEmbeddedPrivate,
        Feature::kAddressSpaceUnknownSecureContextNavigatedToPrivate,
    },
};

// Attempts to find an entry matching |key| in |kFeatureMap|.
// Returns a pointer to the entry if successful, nullptr otherwise.
const FeatureEntry* FindFeatureEntry(const FeatureKey& key) {
  for (const FeatureEntry& entry : kFeatureMap) {
    if (key == entry.key) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace

std::optional<Feature> AddressSpaceFeature(
    FetchType fetch_type,
    AddressSpace client_address_space,
    bool client_is_secure_context,
    AddressSpace response_address_space) {
  FeatureKey key;
  key.client_address_space = client_address_space;
  key.client_is_secure_context = client_is_secure_context;
  key.response_address_space = response_address_space;

  const FeatureEntry* entry = FindFeatureEntry(key);
  if (!entry) {
    return std::nullopt;
  }

  switch (fetch_type) {
    case FetchType::kSubresource:
      return entry->subresource_feature;
    case FetchType::kNavigation:
      return entry->navigation_feature;
  }
}

}  // namespace blink
```