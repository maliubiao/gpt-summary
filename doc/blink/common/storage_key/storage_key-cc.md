Response: Let's break down the thought process for analyzing this C++ source code and fulfilling the request.

**1. Understanding the Core Request:**

The central request is to understand the functionality of `storage_key.cc` within the Chromium Blink engine. This involves identifying its purpose, its relation to web technologies (JavaScript, HTML, CSS), providing examples, explaining logical reasoning, and pointing out common usage errors.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code, looking for key terms and patterns. Some immediate observations:

* **Namespace `blink`:** This confirms it's part of the Blink rendering engine.
* **Class `StorageKey`:** This is the central entity, so understanding its members and methods is crucial.
* **`Deserialize`, `Serialize`, `DeserializeForLocalStorage`:** These methods suggest handling the conversion of `StorageKey` objects to and from string representations, likely for storage or transmission.
* **`url::Origin`, `net::SchemefulSite`, `base::UnguessableToken`:** These types hint at the components of a `StorageKey`: the origin of the request, the top-level site (for partitioning), and a potential nonce (for unique identification).
* **`blink::mojom::AncestorChainBit`:** This strongly suggests the involvement of site isolation and tracking whether the ancestor frames are same-site or cross-site.
* **`IsThirdPartyStoragePartitioningEnabled()`:** This function indicates that the behavior of `StorageKey` is influenced by a feature flag related to third-party storage partitioning.
* **Comments:** The comments are incredibly helpful in understanding the purpose of different code sections, especially the serialization formats. Pay close attention to these!

**3. Deciphering the Functionality - Top-Down Approach:**

Start with the main class and its public interface.

* **Constructors:**  Analyze the different constructors to understand how a `StorageKey` can be created. Notice the variations involving origin, top-level site, nonce, and ancestor chain bit.
* **`Serialize()` and `Deserialize()`:** These are critical. The comments in `Serialize()` clearly outline the different serialization formats based on the presence of a nonce, third-party partitioning, and the relationship between the origin and top-level site. The `Deserialize()` method then attempts to parse these different formats. This section is key to understanding the core purpose of the class.
* **`DeserializeForLocalStorage()`:**  Recognize this as a specific deserialization method for local storage, highlighting a potential variation in how `StorageKey` is represented in that context.
* **`Create...` methods:** These static factory methods offer convenient ways to create `StorageKey` objects with specific configurations.
* **`WithOrigin()`:** This method shows how to create a new `StorageKey` by modifying the origin while considering the implications for top-level site and ancestor chain bit.
* **Getter methods (implicitly identified by usage):** While not explicit getter methods, the code shows how to access the internal components (origin, top-level site, nonce, ancestor chain bit) through direct member access within the same class or through carefully designed logic.
* **Comparison operators (`==`, `!=`, `<`):** These define how `StorageKey` objects are compared, which is important for using them in sets, maps, or when checking for equality.
* **`IsValid()`:**  This is crucial for ensuring the internal consistency of a `StorageKey` object. Analyze the conditions checked to understand the rules governing valid `StorageKey` states.

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

This requires connecting the internal functionality to the user-facing aspects of the web.

* **Storage (Local Storage, Cookies, etc.):** The names of the methods (`DeserializeForLocalStorage`, `ToCookiePartitionKey`) strongly link `StorageKey` to browser storage mechanisms. Explain how these keys are used to partition and identify storage associated with different origins and top-level sites.
* **Site Isolation and Security:** The `AncestorChainBit` is a direct indicator of site isolation. Explain how this concept affects cross-origin interactions and security boundaries.
* **Third-Party Context and Partitioning:** The feature flag and related logic directly address the concept of third-party cookies and storage partitioning. Explain how this mechanism restricts access to storage based on the top-level site.

**5. Logical Reasoning and Examples:**

Based on the understanding of `Serialize()` and `Deserialize()`, construct specific examples of input strings and the corresponding `StorageKey` objects. Cover the different serialization formats:

* First-party (just the origin).
* Third-party with top-level site.
* Third-party with ancestor chain bit.
* Keys with nonces.
* Opaque top-level sites.

For each example, explicitly state the input and the expected output (the components of the `StorageKey`).

**6. Identifying Common Usage Errors:**

Think about how developers might misuse or misunderstand the `StorageKey`.

* **Incorrect Serialization/Deserialization:**  Highlight issues like missing trailing slashes in specific deserialization contexts or providing malformed serialized strings.
* **Assuming First-Party Behavior in Third-Party Contexts:** Explain the implications of storage partitioning and how a key that looks like a first-party key might behave differently in a third-party context.
* **Misunderstanding Nonces:** Explain that nonces create unique keys even for the same origin and how this impacts storage access and identification.
* **Ignoring `IsValid()`:** Emphasize the importance of ensuring `StorageKey` objects are valid and the potential consequences of using invalid keys.

**7. Structuring the Response:**

Organize the information logically. A good structure might be:

* **Overview of Functionality:** A concise summary of the purpose of the file.
* **Relationship to Web Technologies:**  Explicitly link `StorageKey` to JavaScript, HTML, and CSS functionalities related to storage and security.
* **Logical Reasoning and Examples:** Provide concrete input/output examples for serialization and deserialization.
* **Common Usage Errors:** List potential mistakes developers might make.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:** During the initial scan, one might focus too much on specific details before grasping the overall purpose. Stepping back and looking at the bigger picture is important.
* **Clarifying Terminology:**  Ensure clear definitions of terms like "origin," "top-level site," "nonce," and "ancestor chain bit."
* **Ensuring Coverage of All Serialization Formats:** Double-check that the examples cover all the different cases outlined in the `Serialize()` method.
* **Adding Nuance:**  For example, when discussing the relationship to web technologies, be specific about *how* the `StorageKey` is used (e.g., partitioning storage, identifying origins for security).

By following this systematic approach, combining code analysis with an understanding of web concepts, one can effectively explain the functionality of a complex piece of code like `storage_key.cc`.
这是 `blink/common/storage_key/storage_key.cc` 文件的功能列表和相关说明：

**核心功能:**

1. **表示和操作存储键 (Storage Key):**  `StorageKey` 类是用来表示 Blink 引擎中存储相关操作的键。它封装了用于标识特定存储区域的信息，例如：
    * **Origin (来源):**  存储操作发生的源 URL 的 Origin (协议, 主机名, 端口)。
    * **Top-Level Site (顶级站点):** 用于存储隔离的顶级站点的 `SchemefulSite`。这在启用了第三方存储分区时尤其重要。
    * **Nonce (随机数):** 一个可选的 `UnguessableToken`，用于进一步隔离存储，即使在相同的 Origin 和 Top-Level Site 下。
    * **Ancestor Chain Bit (祖先链位):**  一个枚举值，指示祖先 frame 是否与当前 frame 同源 (`kSameSite`) 或跨域 (`kCrossSite`)。这用于确定是否应应用存储分区。

2. **序列化和反序列化存储键:**  提供了将 `StorageKey` 对象转换为字符串表示形式 (`Serialize()`, `SerializeForLocalStorage()`) 以及从字符串恢复 `StorageKey` 对象 (`Deserialize()`, `DeserializeForLocalStorage()`) 的功能。这对于在不同的组件之间传递和持久化存储键至关重要。

3. **支持存储分区 (Storage Partitioning):**  代码中大量涉及 `top_level_site_` 和 `ancestor_chain_bit_`，以及 `IsThirdPartyStoragePartitioningEnabled()` 函数，表明 `StorageKey` 类是 Blink 存储分区机制的核心部分。存储分区旨在隔离不同顶级站点下的第三方存储，防止跨站跟踪。

4. **与网络层交互:**  提供了将 `StorageKey` 转换为 `net::SiteForCookies` 和 `net::IsolationInfo` 的方法 (`ToNetSiteForCookies()`, `ToPartialNetIsolationInfo()`)，以便与 Chromium 的网络层进行集成，例如用于 Cookie 管理和网络隔离。

5. **提供调试信息:**  `GetDebugString()` 和 `GetMemoryDumpString()` 方法用于生成易于理解的 `StorageKey` 对象的字符串表示，用于调试和内存分析。

6. **比较操作:**  重载了比较运算符 (`==`, `!=`, `<`)，允许对 `StorageKey` 对象进行比较。

7. **校验 `StorageKey` 的有效性:**  `IsValid()` 方法用于检查 `StorageKey` 对象内部状态的一致性，确保其包含的 Origin、Top-Level Site、Nonce 和 Ancestor Chain Bit 的组合是有效的。

**与 JavaScript, HTML, CSS 的功能关系 (及举例说明):**

`StorageKey` 本身是一个 C++ 内部结构，JavaScript, HTML 和 CSS 无法直接操作它。但是，它直接影响了这些 Web 技术的功能，尤其是在涉及存储的方面：

* **JavaScript 的 Web Storage API (localStorage, sessionStorage):**
    * **功能关系:** 当 JavaScript 代码使用 `localStorage.setItem('key', 'value')` 时，浏览器内部会根据当前页面的 Origin 和 Top-Level Site (如果启用了存储分区) 创建一个 `StorageKey`，用于确定将数据存储在哪里。
    * **举例说明:**
        * **假设输入:** 一个在 `https://example.com` 页面中运行的脚本调用 `localStorage.setItem('data', 'test')`。
        * **内部逻辑推理:** 如果未启用第三方存储分区，则 `StorageKey` 的 Origin 将是 `https://example.com`，Top-Level Site 也将是 `https://example.com`。如果是在 `https://another-site.com` 嵌入的 iframe 中运行的，且启用了第三方存储分区，则 `StorageKey` 的 Origin 将是 iframe 的 Origin，但 Top-Level Site 将是 `https://another-site.com`。
        * **输出:**  存储的数据会关联到根据这些信息生成的特定 `StorageKey`。

* **HTTP Cookie:**
    * **功能关系:** 当浏览器接收到服务器设置的 Cookie 时，会根据 Cookie 的属性 (Domain, Path, SameSite 等) 和当前页面的 Origin 和 Top-Level Site 来决定是否接受和存储 Cookie。`StorageKey` 的 `ToNetSiteForCookies()` 方法用于生成 `net::SiteForCookies` 对象，这在 Cookie 匹配和访问控制中起着关键作用。
    * **举例说明:**
        * **假设输入:** 一个页面位于 `https://parent.com`，其中嵌入了一个来自 `https://thirdparty.com` 的 iframe。服务器在 iframe 的响应头中设置了一个 Cookie，Domain 属性设置为 `thirdparty.com`。
        * **内部逻辑推理:** 浏览器会为该 iframe 创建一个 `StorageKey`，其 Origin 为 `https://thirdparty.com`，Top-Level Site 为 `https://parent.com` (如果启用了分区)。然后，`StorageKey` 会被转换为 `net::SiteForCookies`，用于判断该 Cookie 是否可以被存储和后续访问。如果启用了第三方 Cookie 拦截或者存储分区，这个 `StorageKey` 的信息会影响 Cookie 的处理。

* **IndexedDB:**
    * **功能关系:** 与 `localStorage` 类似，当 JavaScript 使用 IndexedDB API 创建或访问数据库时，`StorageKey` 用于标识存储 IndexedDB 数据的位置。
    * **举例说明:**  与 `localStorage` 的例子类似，只是 API 不同。IndexedDB 的数据库也会根据 `StorageKey` 进行隔离。

* **Cache API:**
    * **功能关系:**  浏览器使用 `StorageKey` 来隔离不同 Origin 和 Top-Level Site 的 Cache API 存储。
    * **举例说明:**  一个来自 `https://cdn.example.com` 的脚本缓存了一个资源。这个缓存条目会关联到基于 `https://cdn.example.com` 的 Origin 和当前页面的 Top-Level Site 生成的 `StorageKey`。

**逻辑推理的假设输入与输出:**

假设我们调用 `StorageKey::Deserialize()` 函数来反序列化一个字符串：

* **假设输入 1:** `"https://example.com/"`
    * **内部逻辑推理:**  字符串中没有分隔符 '^'，因此会被解析为只包含 Origin 的 `StorageKey`。Top-Level Site 会隐式地与 Origin 相同，Ancestor Chain Bit 为 `kSameSite`。
    * **输出:**  一个 `StorageKey` 对象，其 `origin_` 为 `https://example.com`, `top_level_site_` 为 `https://example.com`, `nonce_` 为空, `ancestor_chain_bit_` 为 `blink::mojom::AncestorChainBit::kSameSite`。

* **假设输入 2:** `"https://origin.com/^0https://toplevel.com"`
    * **内部逻辑推理:** 字符串包含分隔符 '^0'，表示这是一个启用了存储分区的第三方存储键，Top-Level Site 为 `https://toplevel.com`。
    * **输出:** 一个 `StorageKey` 对象，其 `origin_` 为 `https://origin.com`, `top_level_site_` 为 `https://toplevel.com`, `nonce_` 为空, `ancestor_chain_bit_` 为 `blink::mojom::AncestorChainBit::kCrossSite`。

* **假设输入 3:** `"https://example.com/^112345^267890"`
    * **内部逻辑推理:** 字符串包含分隔符 '^1' 和 '^2'，表示这是一个带有 Nonce 的存储键。
    * **输出:** 一个 `StorageKey` 对象，其 `origin_` 为 `https://example.com`, `top_level_site_` 为 `https://example.com`, `nonce_` 为一个由 `12345` 和 `67890` 组成的 `UnguessableToken`, `ancestor_chain_bit_` 为 `blink::mojom::AncestorChainBit::kCrossSite`。

**用户或编程常见的使用错误 (举例说明):**

1. **在需要完整序列化时使用了 `SerializeForLocalStorage()`:**  `SerializeForLocalStorage()` 针对 Local Storage 进行了优化，可能省略了某些信息 (例如，在第一方上下文中)。如果在需要包含所有分区信息的场景下使用，可能会导致反序列化失败或得到错误的 `StorageKey`。

2. **手动构造序列化字符串时格式错误:**  `StorageKey` 的序列化格式是特定的，如果开发者尝试手动创建序列化字符串，很容易出错，例如分隔符使用错误、属性顺序错误或缺少必要的属性。这会导致 `Deserialize()` 返回 `std::nullopt`。

    * **举例:**  如果一个开发者错误地构造了字符串 `"https://example.com|^0https://toplevel.com"` (使用 '|' 代替 '^')，`Deserialize()` 将无法正确解析。

3. **假设在所有情况下 Top-Level Site 都等于 Origin:**  在未启用存储分区或处理第一方存储时，这可能是正确的。但是，在第三方上下文中，Top-Level Site 可能与 Origin 不同。错误地假设它们相等可能会导致在存储访问或隔离方面出现问题。

4. **不理解 Nonce 的作用:**  开发者可能不理解 Nonce 会创建更细粒度的存储隔离，即使 Origin 和 Top-Level Site 相同。这可能导致意外的数据隔离或无法访问预期的数据。

5. **在禁用存储分区的情况下尝试反序列化包含分区信息的字符串:**  如果第三方存储分区被禁用，尝试反序列化包含 Top-Level Site 或 Ancestor Chain Bit 信息的字符串可能会失败，因为 `Deserialize()` 中会进行检查。

    * **举例:** 如果启用了第三方存储分区并序列化了一个 `StorageKey` 为 `"https://origin.com/^0https://toplevel.com"`，然后在禁用第三方存储分区的情况下尝试反序列化，`Deserialize()` 将返回 `std::nullopt`。

总而言之，`blink/common/storage_key/storage_key.cc` 文件定义了 `StorageKey` 类，它是 Blink 引擎中用于标识和管理存储的关键抽象。它包含了 Origin、Top-Level Site、Nonce 和 Ancestor Chain Bit 等信息，支持存储分区，并提供了序列化、反序列化以及与其他网络层组件交互的功能。理解 `StorageKey` 的工作原理对于理解 Blink 的存储隔离机制至关重要。

### 提示词
```
这是目录为blink/common/storage_key/storage_key.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/storage_key/storage_key.h"

#include <memory>
#include <ostream>
#include <string>
#include <string_view>
#include <tuple>

#include "base/feature_list.h"
#include "base/ranges/algorithm.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/types/optional_util.h"
#include "net/base/features.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "third_party/abseil-cpp/absl/strings/ascii.h"
#include "url/gurl.h"

namespace {

// This enum represents the different type of encodable partitioning
// attributes. These values are persisted to disk. Entries should not be
// renumbered and numeric values should never be reused.
enum class EncodedAttribute : uint8_t {
  kTopLevelSite = 0,
  kNonceHigh = 1,
  kNonceLow = 2,
  kAncestorChainBit = 3,
  kTopLevelSiteOpaqueNonceHigh = 4,
  kTopLevelSiteOpaqueNonceLow = 5,
  kTopLevelSiteOpaquePrecursor = 6,
  kMaxValue = kTopLevelSiteOpaquePrecursor,
};

// Converts the attribute type into the separator + uint8_t byte
// serialization. E.x.: kTopLevelSite becomes "^0"
std::string SerializeAttributeSeparator(const EncodedAttribute type) {
  // Create a size 2 string, we'll overwrite the second char later.
  std::string ret(2, '^');
  char digit = static_cast<uint8_t>(type) + '0';
  ret[1] = digit;
  return ret;
}

// Converts the serialized separator into an EncodedAttribute enum.
// E.x.: "^0" becomes kTopLevelSite.
// Expects `in` to have a length of 2.
std::optional<EncodedAttribute> DeserializeAttributeSeparator(
    const std::string_view& in) {
  DCHECK_EQ(in.size(), 2U);
  uint8_t number = in[1] - '0';

  if (number > static_cast<uint8_t>(EncodedAttribute::kMaxValue)) {
    // Bad input, return std::nullopt to indicate an issue.
    return std::nullopt;
  }

  return static_cast<EncodedAttribute>(number);
}

// Returns true if there are at least 2 chars after the '^' in `in` and the
// second char is not '^'. Meaning that the substring is syntactically valid.
// This is to indicate that there is a valid separator with both a '^' and a
// uint8_t and some amount of encoded data. I.e.: "^09" has both a "^0" as the
// separator and '9' as the encoded data.
bool ValidSeparatorWithData(std::string_view in, size_t pos_of_caret) {
  if (in.length() > pos_of_caret + 2 && in[pos_of_caret + 2] != '^')
    return true;

  return false;
}

}  // namespace

namespace blink {

// static
std::optional<StorageKey> StorageKey::Deserialize(std::string_view in) {
  // As per the Serialize() call, we have to expect one of the following
  // structures:
  // <StorageKey `key`.origin> + "/" + "^1" + <StorageKey
  // `key`.nonce.High64Bits> + "^2" + <StorageKey `key`.nonce.Low64Bits>
  // - or -
  // <StorageKey `key`.origin> + "/"
  // - or -
  // <StorageKey `key`.origin> + "/" + "^3" + <StorageKey
  // `key`.ancestor_chain_bit>
  // - or -
  // <StorageKey `key`.origin> + "/" + "^0" + <StorageKey `key`.top_level_site>
  // - or -
  // <StorageKey `key`.origin> + "/" + ^4" + <StorageKey
  // `key`.top_level_site.nonce.High64Bits> + "^5" + <StorageKey
  // `key`.top_level_site.nonce.Low64Bits>  + "^6" + <StorageKey
  // `key`.top_level_site.precursor>
  //
  // See Serialize() for more information.

  // Let's check for a delimiting caret. The presence of a caret means this key
  // is partitioned.

  // More than three encoded attributes (delimited by carets) indicates a
  // malformed input.
  if (base::ranges::count(in, '^') > 3) {
    return std::nullopt;
  }

  const size_t pos_first_caret = in.find_first_of('^');
  const size_t pos_second_caret =
      pos_first_caret == std::string::npos
          ? std::string::npos
          : in.find_first_of('^', pos_first_caret + 1);
  const size_t pos_third_caret =
      pos_second_caret == std::string::npos
          ? std::string::npos
          : in.find_first_of('^', pos_second_caret + 1);

  url::Origin key_origin;
  net::SchemefulSite key_top_level_site;
  std::optional<base::UnguessableToken> nonce;
  blink::mojom::AncestorChainBit ancestor_chain_bit;

  if (pos_first_caret == std::string::npos) {
    // Only the origin is serialized.

    key_origin = url::Origin::Create(GURL(in));

    // In this case the top_level_site is implicitly the same site as the
    // origin.
    key_top_level_site = net::SchemefulSite(key_origin);

    // There is no nonce.

    // The origin should not be opaque and the serialization should be
    // reversible.
    if (key_origin.opaque() || key_origin.GetURL().spec() != in) {
      return std::nullopt;
    }

    return StorageKey(key_origin, key_top_level_site, nullptr,
                      blink::mojom::AncestorChainBit::kSameSite,
                      /*third_party_partitioning_allowed=*/false);
  }

  if (!ValidSeparatorWithData(in, pos_first_caret))
    return std::nullopt;

  // Otherwise the key is partitioned, let's see what it's partitioned by.
  std::optional<EncodedAttribute> first_attribute =
      DeserializeAttributeSeparator(in.substr(pos_first_caret, 2));
  if (!first_attribute.has_value())
    return std::nullopt;

  switch (first_attribute.value()) {
    case EncodedAttribute::kTopLevelSite: {
      // Cross-Origin keys cannot be read if partitioning is off.
      if (!IsThirdPartyStoragePartitioningEnabled()) {
        return std::nullopt;
      }

      // A top-level site is serialized and has only one encoded attribute.
      if (pos_second_caret != std::string::npos) {
        return std::nullopt;
      }

      // The origin is the portion up to, but not including, the caret
      // separator.
      const std::string_view origin_substr = in.substr(0, pos_first_caret);
      key_origin = url::Origin::Create(GURL(origin_substr));

      // The origin should not be opaque and the serialization should be
      // reversible.
      if (key_origin.opaque() || key_origin.GetURL().spec() != origin_substr) {
        return std::nullopt;
      }

      // The top_level_site is the portion beyond the first separator.
      int length_of_site = pos_second_caret - (pos_first_caret + 2);
      const std::string_view top_level_site_substr =
          in.substr(pos_first_caret + 2, length_of_site);
      key_top_level_site = net::SchemefulSite(GURL(top_level_site_substr));

      // The top level site should not be opaque and the serialization should be
      // reversible.
      if (key_top_level_site.opaque() ||
          key_top_level_site.Serialize() != top_level_site_substr) {
        return std::nullopt;
      }

      // There is no nonce or ancestor chain bit.

      // Neither should be opaque and they cannot match as that would mean
      // we should have simply encoded the origin and the input is malformed.
      if (key_origin.opaque() || key_top_level_site.opaque() ||
          net::SchemefulSite(key_origin) == key_top_level_site) {
        return std::nullopt;
      }

      // The ancestor chain bit must be CrossSite as that's an invariant
      // when the origin and top level site don't match.
      // TODO(crbug.com/1199077): Deserialize should always be able to make 3p
      // keys and shouldn't depend on the state of partitioning (because we
      // don't want to inadvertently turn two 3p keys into the same 1p key).
      // Unfortunately, some tests (and potentially code) depend on this. Here,
      // and below, should be changed to true and the dependencies on this
      // behavior should be removed.
      return StorageKey(key_origin, key_top_level_site, nullptr,
                        blink::mojom::AncestorChainBit::kCrossSite,
                        IsThirdPartyStoragePartitioningEnabled());
    }
    case EncodedAttribute::kAncestorChainBit: {
      // Same-Origin kCrossSite keys cannot be read if partitioning is off.
      if (!IsThirdPartyStoragePartitioningEnabled()) {
        return std::nullopt;
      }

      // An ancestor chain bit is serialized and has only one encoded attribute.
      if (pos_second_caret != std::string::npos) {
        return std::nullopt;
      }

      // The origin is the portion up to, but not including, the caret
      // separator.
      const std::string_view origin_substr = in.substr(0, pos_first_caret);
      key_origin = url::Origin::Create(GURL(origin_substr));

      // The origin should not be opaque and the serialization should be
      // reversible.
      if (key_origin.opaque() || key_origin.GetURL().spec() != origin_substr) {
        return std::nullopt;
      }

      // The ancestor_chain_bit is the portion beyond the first separator.
      int raw_bit;
      const std::string_view raw_bit_substr =
          in.substr(pos_first_caret + 2, std::string::npos);
      if (!base::StringToInt(raw_bit_substr, &raw_bit)) {
        return std::nullopt;
      }

      // If the integer conversion results in a value outside the enumerated
      // indices of [0,1] or trimmed leading 0s we must reject the key.
      if (raw_bit < 0 || raw_bit > 1 || raw_bit_substr.size() > 1) {
        return std::nullopt;
      }
      ancestor_chain_bit = static_cast<blink::mojom::AncestorChainBit>(raw_bit);

      // There is no nonce or top level site.

      // The origin shouldn't be opaque and ancestor chain bit must be CrossSite
      // as otherwise should have simply encoded the origin and the input is
      // malformed.
      if (ancestor_chain_bit != blink::mojom::AncestorChainBit::kCrossSite) {
        return std::nullopt;
      }

      // This format indicates the top level site matches the origin.
      return StorageKey(key_origin, net::SchemefulSite(key_origin), nullptr,
                        ancestor_chain_bit,
                        IsThirdPartyStoragePartitioningEnabled());
    }
    case EncodedAttribute::kNonceHigh: {
      // A nonce is serialized and has only two encoded attributes.
      if (pos_third_caret != std::string::npos) {
        return std::nullopt;
      }

      // Make sure we found the next separator, it's valid, that it's the
      // correct attribute.
      if (pos_second_caret == std::string::npos ||
          !ValidSeparatorWithData(in, pos_second_caret))
        return std::nullopt;

      std::optional<EncodedAttribute> second_attribute =
          DeserializeAttributeSeparator(in.substr(pos_second_caret, 2));
      if (!second_attribute.has_value() ||
          second_attribute.value() != EncodedAttribute::kNonceLow)
        return std::nullopt;

      // The origin is the portion up to, but not including, the first
      // separator.
      const std::string_view origin_substr = in.substr(0, pos_first_caret);
      key_origin = url::Origin::Create(GURL(origin_substr));

      // The origin should not be opaque and the serialization should be
      // reversible.
      if (key_origin.opaque() || key_origin.GetURL().spec() != origin_substr) {
        return std::nullopt;
      }

      // The first high 64 bits of the nonce are next, between the two
      // separators.
      int length_of_high = pos_second_caret - (pos_first_caret + 2);
      std::string_view high_digits =
          in.substr(pos_first_caret + 2, length_of_high);
      // The low 64 bits are last, after the second separator.
      std::string_view low_digits = in.substr(pos_second_caret + 2);

      uint64_t nonce_high = 0;
      uint64_t nonce_low = 0;

      if (!base::StringToUint64(high_digits, &nonce_high))
        return std::nullopt;

      if (!base::StringToUint64(low_digits, &nonce_low))
        return std::nullopt;

      // The key is corrupted if there are extra 0s in front of the nonce.
      if (base::NumberToString(nonce_high) != high_digits ||
          base::NumberToString(nonce_low) != low_digits) {
        return std::nullopt;
      }

      nonce = base::UnguessableToken::Deserialize(nonce_high, nonce_low);

      if (!nonce.has_value()) {
        return std::nullopt;
      }

      // This constructor makes a copy of the nonce, so getting the raw pointer
      // is safe.
      // Note: The partitioning allowed value is irrelevant with a nonce,
      // `false` was chosen arbitrarily.
      return StorageKey(key_origin, net::SchemefulSite(key_origin),
                        &nonce.value(),
                        blink::mojom::AncestorChainBit::kCrossSite,
                        /*third_party_partitioning_allowed=*/false);
    }
    case EncodedAttribute::kTopLevelSiteOpaqueNonceHigh: {
      // An opaque `top_level_site` is serialized.

      // Cross-Origin keys cannot be read if partitioning is off.
      if (!IsThirdPartyStoragePartitioningEnabled()) {
        return std::nullopt;
      }

      // Make sure we found the next separator, it's valid, that it's the
      // correct attribute.
      if (pos_second_caret == std::string::npos ||
          !ValidSeparatorWithData(in, pos_second_caret)) {
        return std::nullopt;
      }

      std::optional<EncodedAttribute> second_attribute =
          DeserializeAttributeSeparator(in.substr(pos_second_caret, 2));
      if (!second_attribute.has_value() ||
          second_attribute.value() !=
              EncodedAttribute::kTopLevelSiteOpaqueNonceLow) {
        return std::nullopt;
      }

      // The origin is the portion up to, but not including, the first
      // separator.
      const std::string_view origin_substr = in.substr(0, pos_first_caret);
      key_origin = url::Origin::Create(GURL(origin_substr));

      // The origin should not be opaque and the serialization should be
      // reversible.
      if (key_origin.opaque() || key_origin.GetURL().spec() != origin_substr) {
        return std::nullopt;
      }

      // The first high 64 bits of the sites's nonce are next, between the first
      // separators.
      int length_of_high = pos_second_caret - (pos_first_caret + 2);
      std::string_view high_digits =
          in.substr(pos_first_caret + 2, length_of_high);
      // The low 64 bits are next, after the second separator.
      int length_of_low = pos_third_caret - (pos_second_caret + 2);
      std::string_view low_digits =
          in.substr(pos_second_caret + 2, length_of_low);

      uint64_t nonce_high = 0;
      uint64_t nonce_low = 0;

      if (!base::StringToUint64(high_digits, &nonce_high)) {
        return std::nullopt;
      }

      if (!base::StringToUint64(low_digits, &nonce_low)) {
        return std::nullopt;
      }

      // The key is corrupted if there are extra 0s in front of the nonce.
      if (base::NumberToString(nonce_high) != high_digits ||
          base::NumberToString(nonce_low) != low_digits) {
        return std::nullopt;
      }

      const std::optional<base::UnguessableToken> site_nonce =
          base::UnguessableToken::Deserialize(nonce_high, nonce_low);

      // The nonce must have content.
      if (!site_nonce) {
        return std::nullopt;
      }

      // Make sure we found the final separator, it's valid, that it's the
      // correct attribute.
      if (pos_third_caret == std::string::npos ||
          (in.size() - pos_third_caret) < 2) {
        return std::nullopt;
      }

      std::optional<EncodedAttribute> third_attribute =
          DeserializeAttributeSeparator(in.substr(pos_third_caret, 2));
      if (!third_attribute.has_value() ||
          third_attribute.value() !=
              EncodedAttribute::kTopLevelSiteOpaquePrecursor) {
        return std::nullopt;
      }

      // The precursor is the rest of the input.
      const std::string_view url_precursor_substr =
          in.substr(pos_third_caret + 2);
      const GURL url_precursor(url_precursor_substr);
      const url::SchemeHostPort tuple_precursor(url_precursor);

      // The precursor must be empry or valid, and the serialization should be
      // reversible.
      if ((!url_precursor.is_empty() && !tuple_precursor.IsValid()) ||
          tuple_precursor.Serialize() != url_precursor_substr) {
        return std::nullopt;
      }

      // This constructor makes a copy of the site's nonce, so getting the raw
      // pointer is safe.
      return StorageKey(
          key_origin,
          net::SchemefulSite(url::Origin(url::Origin::Nonce(site_nonce.value()),
                                         tuple_precursor)),
          nullptr, blink::mojom::AncestorChainBit::kCrossSite,
          IsThirdPartyStoragePartitioningEnabled());
    }
    default: {
      // Malformed input case. We saw a separator that we don't understand
      // or one in the wrong order.
      return std::nullopt;
    }
  }
}

// static
std::optional<StorageKey> StorageKey::DeserializeForLocalStorage(
    std::string_view in) {
  // We have to support the local storage specific variant that lacks the
  // trailing slash.
  const url::Origin maybe_origin = url::Origin::Create(GURL(in));
  if (!maybe_origin.opaque()) {
    if (maybe_origin.Serialize() == in) {
      return StorageKey(maybe_origin, net::SchemefulSite(maybe_origin), nullptr,
                        blink::mojom::AncestorChainBit::kSameSite,
                        /*third_party_partitioning_allowed=*/false);
    } else if (maybe_origin.GetURL().spec() == in) {
      // This first party key was passed in with a trailing slash. This is
      // required in Deserialize() but improper for DeserializeForLocalStorage()
      // and must be rejected.
      return std::nullopt;
    }
  }

  // Otherwise we fallback on base deserialization.
  return Deserialize(in);
}

// static
StorageKey StorageKey::CreateFromStringForTesting(const std::string& origin) {
  return CreateFirstParty(url::Origin::Create(GURL(origin)));
}

// static
// Keep consistent with BlinkStorageKey::FromWire().
bool StorageKey::FromWire(
    const url::Origin& origin,
    const net::SchemefulSite& top_level_site,
    const net::SchemefulSite& top_level_site_if_third_party_enabled,
    const std::optional<base::UnguessableToken>& nonce,
    blink::mojom::AncestorChainBit ancestor_chain_bit,
    blink::mojom::AncestorChainBit ancestor_chain_bit_if_third_party_enabled,
    StorageKey& out) {
  // We need to build a different key to prevent overriding `out` if the result
  // isn't valid.
  StorageKey maybe_out;
  maybe_out.origin_ = origin;
  maybe_out.top_level_site_ = top_level_site;
  maybe_out.top_level_site_if_third_party_enabled_ =
      top_level_site_if_third_party_enabled;
  maybe_out.nonce_ = nonce;
  maybe_out.ancestor_chain_bit_ = ancestor_chain_bit;
  maybe_out.ancestor_chain_bit_if_third_party_enabled_ =
      ancestor_chain_bit_if_third_party_enabled;
  if (maybe_out.IsValid()) {
    out = maybe_out;
    return true;
  }
  return false;
}

// static
bool StorageKey::IsThirdPartyStoragePartitioningEnabled() {
  return base::FeatureList::IsEnabled(
      net::features::kThirdPartyStoragePartitioning);
}

// static
StorageKey StorageKey::CreateFirstParty(const url::Origin& origin) {
  return StorageKey(origin, net::SchemefulSite(origin), nullptr,
                    origin.opaque() ? blink::mojom::AncestorChainBit::kCrossSite
                                    : blink::mojom::AncestorChainBit::kSameSite,
                    /*third_party_partitioning_allowed=*/false);
}

// static
StorageKey StorageKey::CreateWithNonce(const url::Origin& origin,
                                       const base::UnguessableToken& nonce) {
  // The AncestorChainBit is not applicable to StorageKeys with a non-empty
  // nonce, so they are initialized to be kCrossSite.
  // Note: The partitioning allowed value is irrelevant with a nonce, `false`
  // was chosen arbitrarily.
  return StorageKey(origin, net::SchemefulSite(origin), &nonce,
                    blink::mojom::AncestorChainBit::kCrossSite,
                    /*third_party_partitioning_allowed=*/false);
}

// static
StorageKey StorageKey::Create(const url::Origin& origin,
                              const net::SchemefulSite& top_level_site,
                              blink::mojom::AncestorChainBit ancestor_chain_bit,
                              bool third_party_partitioning_allowed) {
  return StorageKey(origin, top_level_site, nullptr, ancestor_chain_bit,
                    third_party_partitioning_allowed);
}

// static
StorageKey StorageKey::CreateFromOriginAndIsolationInfo(
    const url::Origin& origin,
    const net::IsolationInfo& isolation_info) {
  if (isolation_info.nonce()) {
    // If the nonce is set we can use the simpler construction path.
    return CreateWithNonce(origin, *isolation_info.nonce());
  }

  blink::mojom::AncestorChainBit ancestor_chain_bit =
      blink::mojom::AncestorChainBit::kCrossSite;
  net::SchemefulSite top_level_site =
      net::SchemefulSite(isolation_info.top_frame_origin().value());
  // If the origin or top_level_site is opaque the ancestor chain bit will be
  // CrossSite. Otherwise if the top level site matches the new origin and the
  // site for cookies isn't empty it must be SameSite.
  if (!origin.opaque() && !top_level_site.opaque() &&
      net::SchemefulSite(origin) == top_level_site &&
      !isolation_info.site_for_cookies().IsNull()) {
    ancestor_chain_bit = blink::mojom::AncestorChainBit::kSameSite;
  }
  return Create(origin, top_level_site, ancestor_chain_bit,
                IsThirdPartyStoragePartitioningEnabled());
}

StorageKey StorageKey::WithOrigin(const url::Origin& origin) const {
  net::SchemefulSite top_level_site = top_level_site_;
  net::SchemefulSite top_level_site_if_third_party_enabled =
      top_level_site_if_third_party_enabled_;
  blink::mojom::AncestorChainBit ancestor_chain_bit = ancestor_chain_bit_;
  blink::mojom::AncestorChainBit ancestor_chain_bit_if_third_party_enabled =
      ancestor_chain_bit_if_third_party_enabled_;

  if (nonce_) {
    // If the nonce is set we have to update the top level site to match origin
    // as that's an invariant.
    top_level_site = net::SchemefulSite(origin);
    top_level_site_if_third_party_enabled = top_level_site;
  } else if (!top_level_site_.opaque()) {
    // If `top_level_site_` is opaque then so is
    // `top_level_site_if_third_party_enabled` and we don't need to explicitly
    // check it. The ancestor chain bit also doesn't need to be changed in this
    // case.

    // Only adjust the ancestor chain bit if it's currently kSameSite but the
    // new origin and top level site don't match. Note that the ACB might not
    // necessarily be kSameSite if the TLS and origin do match, so we won't
    // adjust the other way.
    if (ancestor_chain_bit == blink::mojom::AncestorChainBit::kSameSite &&
        net::SchemefulSite(origin) != top_level_site_) {
      ancestor_chain_bit = blink::mojom::AncestorChainBit::kCrossSite;
    }

    if (ancestor_chain_bit_if_third_party_enabled ==
            blink::mojom::AncestorChainBit::kSameSite &&
        net::SchemefulSite(origin) != top_level_site_if_third_party_enabled) {
      ancestor_chain_bit_if_third_party_enabled =
          blink::mojom::AncestorChainBit::kCrossSite;
    }
  }

  StorageKey out = *this;
  out.origin_ = origin;
  out.top_level_site_ = top_level_site;
  out.top_level_site_if_third_party_enabled_ =
      top_level_site_if_third_party_enabled;
  out.ancestor_chain_bit_ = ancestor_chain_bit;
  out.ancestor_chain_bit_if_third_party_enabled_ =
      ancestor_chain_bit_if_third_party_enabled;
  DCHECK(out.IsValid());
  return out;
}

StorageKey::StorageKey(const url::Origin& origin,
                       const net::SchemefulSite& top_level_site,
                       const base::UnguessableToken* nonce,
                       blink::mojom::AncestorChainBit ancestor_chain_bit,
                       bool third_party_partitioning_allowed)
    : origin_(origin),
      top_level_site_(third_party_partitioning_allowed
                          ? top_level_site
                          : net::SchemefulSite(origin)),
      top_level_site_if_third_party_enabled_(top_level_site),
      nonce_(base::OptionalFromPtr(nonce)),
      ancestor_chain_bit_(third_party_partitioning_allowed ? ancestor_chain_bit
                          : (nonce || origin.opaque())
                              ? blink::mojom::AncestorChainBit::kCrossSite
                              : blink::mojom::AncestorChainBit::kSameSite),
      ancestor_chain_bit_if_third_party_enabled_(ancestor_chain_bit) {
  DCHECK(IsValid());
}

std::string StorageKey::Serialize() const {
  DCHECK(!origin_.opaque());

  // If the storage key has a nonce, implying the top_level_site is the same as
  // origin and ancestor_chain_bit is kCrossSite, then we need to serialize the
  // key to fit the following scheme:
  //
  // Case 0: <StorageKey `key`.origin> + "/" + "^1" + <StorageKey
  // `key`.nonce.High64Bits> + "^2" + <StorageKey `key`.nonce.Low64Bits>
  //
  // Note that we intentionally do not include the AncestorChainBit in
  // serialization with nonce formats as that information is not applicable
  // (similar to top-level-site).
  if (nonce_.has_value()) {
    return origin_.GetURL().spec() +
           SerializeAttributeSeparator(EncodedAttribute::kNonceHigh) +
           base::NumberToString(nonce_->GetHighForSerialization()) +
           SerializeAttributeSeparator(EncodedAttribute::kNonceLow) +
           base::NumberToString(nonce_->GetLowForSerialization());
  }

  // Else if storage partitioning is enabled we need to serialize the key to fit
  // one of the following schemes:
  //
  // Case 1: If the ancestor_chain_bit is kSameSite or partitioning is disabled:
  //
  // <StorageKey `key`.origin> + "/"
  //
  // Case 2: If the origin matches top_level_site and the ancestor_chain_bit is
  // kCrossSite:
  //
  // <StorageKey `key`.origin> + "/" + "^3" + <StorageKey
  // `key`.ancestor_chain_bit>
  //
  // Case 3: If the origin doesn't match top_level_site (implying
  // ancestor_chain_bit is kCrossSite):
  //
  // <StorageKey `key`.origin> + "/" + "^0" + <StorageKey `key`.top_level_site>
  //
  // Case 4: If the top_level_site is opaque (implying ancestor_chain_bit is
  // kCrossSite):
  //
  // <StorageKey `key`.origin> + "/" + ^4" + <StorageKey
  // `key`.top_level_site.nonce.High64Bits> + "^5" + <StorageKey
  // `key`.top_level_site.nonce.Low64Bits>  + "^6" + <StorageKey
  // `key`.top_level_site.precursor>
  if (IsThirdPartyStoragePartitioningEnabled() &&
      ancestor_chain_bit_ == blink::mojom::AncestorChainBit::kCrossSite) {
    if (top_level_site_.opaque()) {
      // Case 4.
      return base::StrCat({
          origin_.GetURL().spec(),
          SerializeAttributeSeparator(
              EncodedAttribute::kTopLevelSiteOpaqueNonceHigh),
          base::NumberToString(top_level_site_.internal_value()
                                   .GetNonceForSerialization()
                                   ->GetHighForSerialization()),
          SerializeAttributeSeparator(
              EncodedAttribute::kTopLevelSiteOpaqueNonceLow),
          base::NumberToString(top_level_site_.internal_value()
                                   .GetNonceForSerialization()
                                   ->GetLowForSerialization()),
          SerializeAttributeSeparator(
              EncodedAttribute::kTopLevelSiteOpaquePrecursor),
          top_level_site_.internal_value()
              .GetTupleOrPrecursorTupleIfOpaque()
              .Serialize(),
      });
    } else if (top_level_site_ == net::SchemefulSite(origin_)) {
      // Case 2.
      return base::StrCat({
          origin_.GetURL().spec(),
          SerializeAttributeSeparator(EncodedAttribute::kAncestorChainBit),
          base::NumberToString(static_cast<int>(ancestor_chain_bit_)),
      });
    } else {
      // Case 3.
      return base::StrCat({
          origin_.GetURL().spec(),
          SerializeAttributeSeparator(EncodedAttribute::kTopLevelSite),
          top_level_site_.Serialize(),
      });
    }
  }

  // Case 1.
  return origin_.GetURL().spec();
}

std::string StorageKey::SerializeForLocalStorage() const {
  DCHECK(!origin_.opaque());

  // If this is a third-party StorageKey we'll use the standard serialization
  // scheme when partitioning is enabled or if there is a nonce.
  if (IsThirdPartyContext()) {
    return Serialize();
  }

  // Otherwise localStorage expects a slightly different scheme, so call that.
  return origin_.Serialize();
}

std::string StorageKey::GetDebugString() const {
  return base::StrCat(
      {"{ origin: ", origin_.GetDebugString(),
       ", top-level site: ", top_level_site_.Serialize(),
       ", nonce: ", nonce_.has_value() ? nonce_->ToString() : "<null>",
       ", ancestor chain bit: ",
       ancestor_chain_bit_ == blink::mojom::AncestorChainBit::kSameSite
           ? "Same-Site"
           : "Cross-Site",
       " }"});
}

std::string StorageKey::GetMemoryDumpString(size_t max_length) const {
  std::string memory_dump_str = origin_.Serialize().substr(0, max_length);

  if (max_length > memory_dump_str.length()) {
    memory_dump_str.append(top_level_site_.Serialize().substr(
        0, max_length - memory_dump_str.length()));
  }

  if (nonce_.has_value() && max_length > memory_dump_str.length()) {
    memory_dump_str.append(
        nonce_->ToString().substr(0, max_length - memory_dump_str.length()));
  }

  if (max_length > memory_dump_str.length()) {
    std::string ancestor_full_string =
        ancestor_chain_bit_ == blink::mojom::AncestorChainBit::kSameSite
            ? "Same-Site"
            : "Cross-Site";
    memory_dump_str.append(
        ancestor_full_string.substr(0, max_length - memory_dump_str.length()));
  }

  base::ranges::replace_if(
      memory_dump_str.begin(), memory_dump_str.end(),
      [](char c) {
        return !absl::ascii_isalnum(static_cast<unsigned char>(c));
      },
      '_');
  return memory_dump_str;
}

const net::SiteForCookies StorageKey::ToNetSiteForCookies() const {
  if (IsThirdPartyContext()) {
    // If any of the ancestor frames are cross-site to `origin_` then the
    // SiteForCookies should be null. The existence of `nonce_` means the same
    // thing.
    return net::SiteForCookies();
  }

  // Otherwise we are in a first party context.
  return net::SiteForCookies(top_level_site_);
}

const net::IsolationInfo StorageKey::ToPartialNetIsolationInfo() const {
  url::Origin top_frame_origin =
      IsFirstPartyContext() ? origin_
                            : url::Origin::Create(top_level_site_.GetURL());
  return net::IsolationInfo::Create(net::IsolationInfo::RequestType::kOther,
                                    top_frame_origin, origin_,
                                    ToNetSiteForCookies(), nonce_);
}

// static
bool StorageKey::ShouldSkipKeyDueToPartitioning(
    const std::string& reg_key_string) {
  // Don't skip anything if storage partitioning is enabled.
  if (IsThirdPartyStoragePartitioningEnabled())
    return false;

  // Determine if there is a valid attribute encoded with a caret
  size_t pos_first_caret = reg_key_string.find_first_of('^');
  if (pos_first_caret != std::string::npos &&
      ValidSeparatorWithData(reg_key_string, pos_first_caret)) {
    std::optional<EncodedAttribute> attribute = DeserializeAttributeSeparator(
        reg_key_string.substr(pos_first_caret, 2));
    // Do skip if partitioning is disabled and we detect a top-level site
    // serialization scheme (opaque or otherwise) or an ancestor chain bit:
    if (attribute.has_value() &&
        (attribute == EncodedAttribute::kTopLevelSite ||
         attribute == EncodedAttribute::kAncestorChainBit ||
         attribute == EncodedAttribute::kTopLevelSiteOpaqueNonceHigh)) {
      return true;
    }
  }
  // If otherwise first-party, nonce, or corrupted, don't skip.
  return false;
}

const std::optional<net::CookiePartitionKey> StorageKey::ToCookiePartitionKey()
    const {
  return net::CookiePartitionKey::FromStorageKeyComponents(
      top_level_site_,
      net::CookiePartitionKey::BoolToAncestorChainBit(IsThirdPartyContext()),
      nonce_);
}

bool StorageKey::MatchesOriginForTrustedStorageDeletion(
    const url::Origin& origin) const {
  // TODO(crbug.com/1382138): Address wss:// and https:// resulting in different
  // SchemefulSites.
  // TODO(crbug.com/1410196): Test that StorageKeys corresponding to anonymous
  // iframes are handled appropriately here.
  return IsFirstPartyContext()
             ? (origin_ == origin)
             : (top_level_site_ == net::SchemefulSite(origin));
}

bool StorageKey::MatchesRegistrableDomainForTrustedStorageDeletion(
    std::string_view domain) const {
  // TODO(crbug.com/1410196): Test that StorageKeys corresponding to anonymous
  // iframes are handled appropriately here.
  return top_level_site_.registrable_domain_or_host() == domain;
}

bool StorageKey::ExactMatchForTesting(const StorageKey& other) const {
  return *this == other &&
         this->ancestor_chain_bit_if_third_party_enabled_ ==
             other.ancestor_chain_bit_if_third_party_enabled_ &&
         this->top_level_site_if_third_party_enabled_ ==
             other.top_level_site_if_third_party_enabled_;
}

bool operator==(const StorageKey& lhs, const StorageKey& rhs) {
  return std::tie(lhs.origin_, lhs.top_level_site_, lhs.nonce_,
                  lhs.ancestor_chain_bit_) ==
         std::tie(rhs.origin_, rhs.top_level_site_, rhs.nonce_,
                  rhs.ancestor_chain_bit_);
}

bool operator!=(const StorageKey& lhs, const StorageKey& rhs) {
  return !(lhs == rhs);
}

bool operator<(const StorageKey& lhs, const StorageKey& rhs) {
  return std::tie(lhs.origin_, lhs.top_level_site_, lhs.nonce_,
                  lhs.ancestor_chain_bit_) <
         std::tie(rhs.origin_, rhs.top_level_site_, rhs.nonce_,
                  rhs.ancestor_chain_bit_);
}

std::ostream& operator<<(std::ostream& ostream, const StorageKey& sk) {
  return ostream << sk.GetDebugString();
}

bool StorageKey::IsValid() const {
  // If the key's origin is opaque ancestor_chain_bit* is always kCrossSite
  // no matter the value of the other members.
  if (origin_.opaque()) {
    if (ancestor_chain_bit_ != blink::mojom::AncestorChainBit::kCrossSite) {
      return false;
    }
    if (ancestor_chain_bit_if_third_party_enabled_ !=
        blink::mojom::AncestorChainBit::kCrossSite) {
      return false;
    }
  }

  // If this key's "normal" members indicate a 3p key, then the
  // *_if_third_party_enabled counterparts must match them.
  if (!origin_.opaque() &&
      (top_level_site_ != net::SchemefulSite(origin_) ||
       ancestor_chain_bit_ != blink::mojom::AncestorChainBit::kSameSite)) {
    if (top_level_site_ != top_level_site_if_third_party_enabled_) {
      return false;
    }
    if (ancestor_chain_bit_ != ancestor_chain_bit_if_third_party_enabled_) {
      return false;
    }
  }

  // If top_level_site* is cross-site to origin, then ancestor_chain_bit* must
  // indicate that. An opaque top_level_site* must have a cross-site
  // ancestor_chain_bit*.
  if (top_level_site_ != net::SchemefulSite(origin_)) {
    if (ancestor_chain_bit_ != blink::mojom::AncestorChainBit::kCrossSite) {
      return false;
    }
  }

  if (top_level_site_if_third_party_enabled_ != net::SchemefulSite(origin_)) {
    if (ancestor_chain_bit_if_third_party_enabled_ !=
        blink::mojom::AncestorChainBit::kCrossSite) {
      return false;
    }
  }

  // If there is a nonce, all other values must indicate same-site to origin.
  if (nonce_) {
    if (nonce_->is_empty()) {
      return false;
    }
    if (top_level_site_ != net::SchemefulSite(origin_)) {
      return false;
    }

    if (top_level_site_if_third_party_enabled_ != net::SchemefulSite(origin_)) {
      return false;
    }

    if (ancestor_chain_bit_ != blink::mojom::AncestorChainBit::kCrossSite) {
      return false;
    }

    if (ancestor_chain_bit_if_third_party_enabled_ !=
        blink::mojom::AncestorChainBit::kCrossSite) {
      return false;
    }
  }

  // If the state is not invalid, it must be valid!
  return true;
}

}  // namespace blink
```