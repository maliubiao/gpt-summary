Response:
Let's break down the request and the provided code to construct a comprehensive answer.

**1. Understanding the Goal:**

The core request is to understand the functionality of `security_origin.cc` within the Chromium Blink engine. Specifically, the request asks for:

* **General Functionality:** What does this file do?
* **Relation to Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
* **Logical Reasoning:**  Provide examples of input and output based on the code's logic.
* **Common Usage Errors:**  Illustrate potential mistakes developers might make.

**2. Initial Code Scan and Keyword Recognition:**

I'll start by skimming the code and noting down key terms and concepts:

* **`SecurityOrigin`:**  This is the central class. The file is clearly about defining and managing security origins.
* **URLs (`KURL`, `url::Origin`, `GURL`):**  Security origins are derived from URLs.
* **Protocols/Schemes:**  `http`, `https`, `file`, `blob`, `data`, etc. are mentioned, indicating the file handles different types of web resources.
* **Host, Port, Domain:**  Components of a security origin.
* **Opaque Origins:**  A special kind of origin, often for security reasons.
* **Same-Origin Policy:** The functions `IsSameOriginWith`, `IsSameOriginDomainWith`, `IsSameSiteWith`, and the comments around `document.domain` clearly point to this.
* **Cross-Origin Access:** Functions like `CanAccess`, `CanRequest`, `CanReadContent`, `CanDisplay` are related to allowing or denying access between different origins.
* **`document.domain`:** A JavaScript mechanism for relaxing the same-origin policy.
* **`blob:` URLs:**  Special URLs for binary data.
* **`data:` URLs:** URLs that embed data directly.
* **Trustworthy Origins:** The `IsPotentiallyTrustworthy` function and related error message.
* **Local Resources:** The `can_load_local_resources_` flag and related functions.
* **Agent Clusters:** The `agent_cluster_id_` and related access control.
* **Isolation:**  The `IsolatedCopy` methods.
* **Permissions/Privileges:** `GrantLoadLocalResources`, `GrantUniversalAccess`, etc.
* **Error Handling:**  Although not explicit error *handling*, the checks and return values (like `false` for access denied) constitute a form of it.

**3. Categorizing Functionality:**

Based on the keywords, I can group the functionalities:

* **Creation and Representation of Security Origins:**  Constructors, `Create` methods, `ToString`, `ToAtomicString`, etc.
* **Same-Origin Policy Implementation:** The `IsSameOrigin*` family of functions.
* **Cross-Origin Access Control:** `CanAccess`, `CanRequest`, etc.
* **Handling Opaque Origins:** Creation and comparison of opaque origins.
* **Special URL Handling:**  `blob:`, `data:`, `file:` URLs.
* **Trustworthiness:**  Determining if an origin is secure.
* **Privilege Management:** Granting and managing access rights.
* **`document.domain` Logic:** Implementing the nuances of this JavaScript feature.
* **Agent Cluster Integration:**  Handling access based on agent clusters.

**4. Relating to Web Technologies:**

Now, I'll connect the functionalities to JavaScript, HTML, and CSS:

* **JavaScript:**  The same-origin policy directly affects JavaScript's ability to make requests (like `fetch` or `XMLHttpRequest`), access properties of iframes or other windows, and manipulate the DOM of cross-origin resources. `document.domain` is a JavaScript property.
* **HTML:**  The same-origin policy governs whether an iframe can access its parent or vice-versa. It affects embedding resources like images, scripts, and stylesheets from different origins.
* **CSS:**  CSS is generally less restricted by the same-origin policy than JavaScript, but there are limitations on accessing cross-origin images for canvas manipulation, for example. The file is more about fundamental security boundaries than fine-grained resource access control within CSS.

**5. Constructing Logical Reasoning Examples (Input/Output):**

I'll think of common scenarios and trace the code flow (mentally or with a quick debug if needed) to predict the output.

* **Simple Same-Origin:** Two URLs with the same protocol, host, and port.
* **Different Ports:** Two URLs with the same protocol and host but different ports.
* **`document.domain` Scenarios:**  Setting `document.domain` to match or not match.
* **Opaque Origins:**  How `blob:` and `data:` URLs behave.
* **Local Files:** Accessing local files.

**6. Identifying Common Usage Errors:**

I'll consider mistakes developers often make related to security origins:

* **Assuming `document.domain` solves all CORS issues:** It has limitations and security implications.
* **Misunderstanding Opaque Origins:** Trying to access properties of resources with opaque origins.
* **Incorrectly handling `blob:` URLs:**  Forgetting about the origin of the blob.
* **Not understanding the implications of local file access.**

**7. Structuring the Answer:**

Finally, I will organize the information logically, starting with a high-level overview of the file's purpose, then diving into specific functionalities, providing examples, and addressing potential pitfalls. I'll use clear headings and bullet points to enhance readability. I'll make sure to tie the technical details back to the user-facing aspects of web development.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the code structure. **Correction:** The request emphasizes *functionality* and its relation to web technologies, so the focus should be on what the code *does* and *how it impacts developers*.
* **Initial thought:**  Provide very technical details about the internal data structures. **Correction:** Keep the explanation at a level understandable to a web developer, focusing on the observable behavior.
* **Initial thought:**  Only give trivial examples. **Correction:** Include more complex scenarios involving `document.domain` and opaque origins to demonstrate deeper understanding.

By following this structured thought process, I can generate a comprehensive and accurate answer that addresses all aspects of the request.
This C++ file, `security_origin.cc`, within the Chromium Blink engine is responsible for defining and managing the concept of a **security origin**. A security origin is a fundamental security mechanism in web browsers that determines the boundaries of trust and access control between web resources.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Representation of a Security Origin:**
   - It defines the `SecurityOrigin` class, which encapsulates the components of a security origin: protocol (scheme), host, and port.
   - It provides constructors and static factory methods (`Create`, `CreateFromString`, `CreateFromUrlOrigin`) to instantiate `SecurityOrigin` objects from URLs or origin strings.
   - It stores the origin's components (`protocol_`, `host_`, `port_`).
   - It handles opaque origins, which don't have a traditional scheme/host/port structure, by using a unique nonce (`nonce_if_opaque_`).

2. **Same-Origin Policy Implementation:**
   - It implements the core logic of the same-origin policy, which restricts how documents or scripts loaded from one origin can interact with resources from a different origin.
   - The `IsSameOriginWith()` method checks if two security origins are the same, considering protocol, host, and port.
   - The `IsSameOriginDomainWith()` method implements the more relaxed same-origin check affected by `document.domain` in JavaScript.
   - The `IsSameSiteWith()` method checks if two origins are considered "same-site".

3. **Cross-Origin Access Control:**
   - It provides methods to determine if a security origin can access resources from another origin:
     - `CanAccess()`: Checks if one origin can access the DOM of a document from another origin.
     - `CanRequest()`: Checks if an origin can make network requests to a given URL.
     - `CanReadContent()`:  Checks if an origin can read the content of a given URL.
     - `CanDisplay()`: Checks if an origin can display content from a given URL.
   - These methods take into account the same-origin policy, `document.domain`, and explicitly granted cross-origin permissions (like via CORS headers, although this file doesn't directly handle CORS header parsing).

4. **Handling Different URL Types:**
   - It has specific logic for handling different types of URLs and how their origins are determined:
     - **`blob:` URLs:**  It extracts the origin of the inner URL for security origin determination.
     - **`filesystem:` URLs:** Similar to `blob:`, it uses the inner URL.
     - **`data:` URLs:** These are treated as having a unique opaque origin.
     - **`file:` URLs:** Handled specially, often treated as more privileged.

5. **Opaque Origins:**
   - It manages the creation and comparison of opaque origins, which are used for URLs like `data:` URLs or when a URL parsing error occurs.
   - Opaque origins are only considered the same if they are the exact same instance or if both have the same nonce.

6. **`document.domain` Support:**
   - It implements the logic for `document.domain`, allowing scripts to relax the same-origin policy by setting `document.domain` to a shared superdomain.
   - The `SetDomainFromDOM()` method updates the `domain_` and `domain_was_set_in_dom_` flags.

7. **Trustworthy Origins:**
   - The `IsPotentiallyTrustworthy()` method determines if an origin is considered secure (e.g., HTTPS).

8. **Privilege Management:**
   - It provides methods to grant certain privileges to a security origin:
     - `GrantLoadLocalResources()`: Allows the origin to load local files.
     - `GrantUniversalAccess()`: Disables same-origin restrictions for this origin (primarily for testing).
     - `GrantCrossAgentClusterAccess()`: Allows cross-origin access within the same agent cluster.
     - `BlockLocalAccessFromLocalOrigin()`: Restricts a local origin from accessing other local resources.

9. **Agent Clusters:**
   - It incorporates the concept of agent clusters (`agent_cluster_id_`) for further isolation and access control.

**Relationship to JavaScript, HTML, and CSS:**

This file is deeply intertwined with the functionality of JavaScript, HTML, and CSS because it enforces the security model that governs how these technologies interact:

* **JavaScript:**
    - **Same-Origin Policy Enforcement:**  When JavaScript code tries to access properties of another window or iframe, or makes an `XMLHttpRequest` or `fetch` request to a different origin, the `SecurityOrigin` class is used to determine if the access is allowed.
    - **`document.domain`:**  JavaScript code can read and set the `document.domain` property. This file's logic handles the implications of setting `document.domain` for same-origin checks.
    - **`window.open()` and `<iframe>`:**  When new browsing contexts are created, their security origins are determined by the URL being loaded, which relies on the logic in this file.
    - **`postMessage()`:** While `postMessage()` allows cross-origin communication, the browser still uses the security origin to identify the source and target of the message.

   **Example:**
   ```javascript
   // Assuming the current page is on http://example.com:8080
   fetch('http://different-example.com') // This will likely be blocked by the same-origin policy.
   ```
   The `CanRequest()` method in `security_origin.cc` would be invoked to determine if the request from `http://example.com:8080` to `http://different-example.com` is permitted.

* **HTML:**
    - **`<iframe>`, `<script>`, `<img>`, `<link>`:** When embedding resources from different origins, the browser checks the security origins to determine if loading and executing these resources is allowed.
    - **Forms:** The `action` attribute of a `<form>` element points to a URL. The security origin of the form's document is checked against the target URL's origin.

   **Example:**
   ```html
   <!-- Assuming the current page is on https://secure.example.com -->
   <img src="http://insecure.example.com/image.png"> <!-- May trigger mixed content warnings/blocking -->
   <iframe src="http://another-domain.com"></iframe> <!-- Content within the iframe will have a different origin. -->
   ```
   The `SecurityOrigin` of the HTML document will be compared to the origins of the embedded resources to enforce security policies.

* **CSS:**
    - **`url()` in stylesheets:** When referencing external resources like fonts or images in CSS, the same-origin policy (or CORS) comes into play.
    - **`@font-face`:** Loading fonts from a different origin requires CORS headers on the font resource.

   **Example:**
   ```css
   /* Assuming the current page is on https://example.com */
   .my-element {
     background-image: url('http://cdn.example.net/image.jpg'); // May require CORS.
   }
   ```
   While CSS itself has some relaxations regarding cross-origin resource loading compared to JavaScript, the underlying security origin mechanism still plays a role in determining if the resource can be loaded.

**Logical Reasoning Examples:**

**Assumption:**  We have two `SecurityOrigin` objects, `origin1` representing `http://example.com:80` and `origin2` representing `http://example.com:8080`.

**Input:**  Calling `origin1->IsSameOriginWith(origin2)`

**Output:** `false`

**Reasoning:**  While the protocol and host are the same, the ports are different (80 vs. 8080). The `IsSameOriginWith()` method checks all three components.

**Input:** Calling `origin1->IsSameOriginDomainWith(origin2, detail)` before any `document.domain` manipulation.

**Output:** `false`, and `detail` would likely be `AccessResultDomainDetail::kDomainNotSet`.

**Reasoning:**  Since neither origin has set `document.domain`, the check falls back to a strict same-origin comparison, and the ports don't match.

**Input:**  JavaScript code on `http://example.com` executes `document.domain = "example.com"`. Then, we compare the `SecurityOrigin` of this document with the `SecurityOrigin` of a document on `http://sub.example.com` after the latter also executes `document.domain = "example.com"`. Calling `origin1->IsSameOriginDomainWith(origin2, detail)`.

**Output:** `true`, and `detail` would be `AccessResultDomainDetail::kDomainMatchNecessary`.

**Reasoning:** Both documents have set `document.domain` to the same value. The `IsSameOriginDomainWith()` method allows access in this case, even if the subdomains differ, as long as the protocol matches.

**Common Usage Errors:**

1. **Misunderstanding the Nuances of `document.domain`:**
   - **Error:**  Assuming setting `document.domain` will magically solve all cross-origin issues without understanding its limitations and security implications.
   - **Example:**  Setting `document.domain` on an HTTPS site to a non-HTTPS superdomain might not work or introduce security vulnerabilities.
   - **Consequence:**  Scripts might fail to interact with each other, or security vulnerabilities could be introduced.

2. **Incorrectly Handling Opaque Origins:**
   - **Error:**  Trying to access the protocol, host, or port of an opaque origin (like that of a `data:` URL).
   - **Example:**  `SecurityOrigin::Create(KURL("data:text/plain,hello"))->host()` would likely return an empty string or a special value indicating opacity.
   - **Consequence:**  Code might make incorrect assumptions about the origin, leading to logic errors.

3. **Assuming Local File Access is Always Allowed:**
   - **Error:**  Assuming JavaScript in a local HTML file can always access other local files.
   - **Example:** Modern browsers often restrict local file access for security reasons. The `block_local_access_from_local_origin_` flag in this file plays a role in that restriction.
   - **Consequence:**  AJAX requests to local files might be blocked, or security errors might occur.

4. **Not Understanding the Implications of Different Protocols and Ports:**
   - **Error:**  Thinking that `http://example.com` and `https://example.com` are the same origin.
   - **Consequence:**  Cross-origin requests between these will be blocked unless explicitly allowed (e.g., via CORS).

5. **Over-reliance on `GrantUniversalAccess()` in Production:**
   - **Error:**  Using `GrantUniversalAccess()` (which disables same-origin restrictions) in production code.
   - **Consequence:**  This completely bypasses the browser's security model and opens up significant security vulnerabilities. This is primarily meant for testing and development.

In summary, `security_origin.cc` is a crucial component of the Chromium Blink engine, responsible for defining and enforcing the security boundaries that protect users from malicious web content and ensure the integrity of the web platform. It directly impacts how JavaScript, HTML, and CSS interact with resources from different locations.

Prompt: 
```
这是目录为blink/renderer/platform/weborigin/security_origin.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2007 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "base/containers/contains.h"
#include "net/base/url_util.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/blob/blob_url.h"
#include "third_party/blink/renderer/platform/blob/blob_url_null_origin_map.h"
#include "third_party/blink/renderer/platform/weborigin/known_ports.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/origin_access_entry.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "url/scheme_host_port.h"
#include "url/url_canon.h"
#include "url/url_canon_ip.h"
#include "url/url_constants.h"
#include "url/url_util.h"

namespace blink {

namespace {

const String& EnsureNonNull(const String& string) {
  if (string.IsNull())
    return g_empty_string;
  return string;
}

}  // namespace

bool SecurityOrigin::ShouldUseInnerURL(const KURL& url) {
  // FIXME: Blob URLs don't have inner URLs. Their form is
  // "blob:<inner-origin>/<UUID>", so treating the part after "blob:" as a URL
  // is incorrect.
  if (url.ProtocolIs("blob"))
    return true;
  if (url.ProtocolIs("filesystem"))
    return true;
  return false;
}

// In general, extracting the inner URL varies by scheme. It just so happens
// that all the URL schemes we currently support that use inner URLs for their
// security origin can be parsed using this algorithm.
KURL SecurityOrigin::ExtractInnerURL(const KURL& url) {
  if (url.InnerURL())
    return *url.InnerURL();
  // FIXME: Update this callsite to use the innerURL member function when
  // we finish implementing it.
  return KURL(url.GetPath().ToString());
}

// Note: When changing ShouldTreatAsOpaqueOrigin, consider also updating
// IsValidInput in //url/scheme_host_port.cc (there might be existing
// differences in behavior between these 2 layers, but we should avoid
// introducing new differences).
static bool ShouldTreatAsOpaqueOrigin(const KURL& url) {
  if (!url.IsValid())
    return true;

  KURL relevant_url;
  if (SecurityOrigin::ShouldUseInnerURL(url)) {
    relevant_url = SecurityOrigin::ExtractInnerURL(url);
    if (!relevant_url.IsValid())
      return true;
    // If the inner URL is also wrapped, the URL is invalid, so treat as opqaue.
    if (SecurityOrigin::ShouldUseInnerURL(relevant_url))
      return true;
  } else {
    relevant_url = url;
  }

  // URLs with schemes that require an authority, but which don't have one,
  // will have failed the isValid() test; e.g. valid HTTP URLs must have a
  // host.
  DCHECK(!((relevant_url.ProtocolIsInHTTPFamily() ||
            relevant_url.ProtocolIs("ftp")) &&
           relevant_url.Host().empty()));

  if (base::Contains(url::GetNoAccessSchemes(),
                     relevant_url.Protocol().Ascii()))
    return true;

  // Nonstandard schemes and unregistered schemes are placed in opaque origins.
  if (!relevant_url.IsStandard()) {
    // A temporary exception is made for non-standard local schemes.
    // TODO: Migrate "content:" and "externalfile:" to be standard schemes, and
    // remove the local scheme exception.
    if (base::Contains(url::GetLocalSchemes(), relevant_url.Protocol().Ascii()))
      return false;

    // Otherwise, treat non-standard origins as opaque, unless the Android
    // WebView workaround is enabled. If the workaround is enabled, return false
    // so that the scheme is retained, to avoid breaking XHRs on custom schemes,
    // et cetera.
    return !url::AllowNonStandardSchemesForAndroidWebView();
  }

  // This is the common case.
  return false;
}

scoped_refptr<SecurityOrigin> SecurityOrigin::CreateInternal(const KURL& url) {
  if (url::SchemeHostPort::ShouldDiscardHostAndPort(url.Protocol().Ascii())) {
    return base::AdoptRef(
        new SecurityOrigin(url.Protocol(), g_empty_string, 0));
  }

  // This mimics the logic in url::SchemeHostPort(const GURL&). In
  // particular, it ensures a URL with a port of 0 will translate into
  // an origin with an effective port of 0.
  uint16_t port = (url.HasPort() || !url.IsValid() || !url.IsStandard())
                      ? url.Port()
                      : DefaultPortForProtocol(url.Protocol());
  return base::AdoptRef(new SecurityOrigin(EnsureNonNull(url.Protocol()),
                                           EnsureNonNull(url.Host().ToString()),
                                           port));
}

SecurityOrigin::SecurityOrigin(const String& protocol,
                               const String& host,
                               uint16_t port)
    : protocol_(protocol), host_(host), domain_(host_), port_(port) {
  DCHECK(url::SchemeHostPort(protocol.Utf8(), host.Utf8(), port,
                             url::SchemeHostPort::CHECK_CANONICALIZATION)
             .IsValid());
  DCHECK(!IsOpaque());
  // By default, only local SecurityOrigins can load local resources.
  can_load_local_resources_ = IsLocal();
}

SecurityOrigin::SecurityOrigin(const url::Origin::Nonce& nonce,
                               const SecurityOrigin* precursor)
    : nonce_if_opaque_(nonce), precursor_origin_(precursor) {}

SecurityOrigin::SecurityOrigin(NewUniqueOpaque, const SecurityOrigin* precursor)
    : nonce_if_opaque_(std::in_place), precursor_origin_(precursor) {}

SecurityOrigin::SecurityOrigin(const SecurityOrigin* other,
                               ConstructIsolatedCopy)
    : protocol_(other->protocol_),
      host_(other->host_),
      domain_(other->domain_),
      port_(other->port_),
      nonce_if_opaque_(other->nonce_if_opaque_),
      universal_access_(other->universal_access_),
      domain_was_set_in_dom_(other->domain_was_set_in_dom_),
      can_load_local_resources_(other->can_load_local_resources_),
      block_local_access_from_local_origin_(
          other->block_local_access_from_local_origin_),
      is_opaque_origin_potentially_trustworthy_(
          other->is_opaque_origin_potentially_trustworthy_),
      cross_agent_cluster_access_(other->cross_agent_cluster_access_),
      agent_cluster_id_(other->agent_cluster_id_),
      precursor_origin_(other->precursor_origin_
                            ? other->precursor_origin_->IsolatedCopy()
                            : nullptr) {}

SecurityOrigin::SecurityOrigin(const SecurityOrigin* other,
                               ConstructSameThreadCopy)
    : protocol_(other->protocol_),
      host_(other->host_),
      domain_(other->domain_),
      port_(other->port_),
      nonce_if_opaque_(other->nonce_if_opaque_),
      universal_access_(other->universal_access_),
      domain_was_set_in_dom_(other->domain_was_set_in_dom_),
      can_load_local_resources_(other->can_load_local_resources_),
      block_local_access_from_local_origin_(
          other->block_local_access_from_local_origin_),
      is_opaque_origin_potentially_trustworthy_(
          other->is_opaque_origin_potentially_trustworthy_),
      cross_agent_cluster_access_(other->cross_agent_cluster_access_),
      agent_cluster_id_(other->agent_cluster_id_),
      precursor_origin_(other->precursor_origin_) {}

scoped_refptr<SecurityOrigin> SecurityOrigin::CreateWithReferenceOrigin(
    const KURL& url,
    const SecurityOrigin* reference_origin) {
  if (url.ProtocolIs("blob") && BlobURL::GetOrigin(url) == "null") {
    if (scoped_refptr<SecurityOrigin> origin =
            BlobURLNullOriginMap::GetInstance()->Get(url))
      return origin;
  }

  if (url.IsAboutBlankURL()) {
    if (!reference_origin)
      return CreateUniqueOpaque();
    return reference_origin->IsolatedCopy();
  }

  if (ShouldTreatAsOpaqueOrigin(url)) {
    if (!reference_origin)
      return CreateUniqueOpaque();
    return reference_origin->DeriveNewOpaqueOrigin();
  }

  if (ShouldUseInnerURL(url))
    return CreateInternal(ExtractInnerURL(url));

  return CreateInternal(url);
}

scoped_refptr<SecurityOrigin> SecurityOrigin::Create(const KURL& url) {
  return CreateWithReferenceOrigin(url, nullptr);
}

scoped_refptr<SecurityOrigin> SecurityOrigin::CreateUniqueOpaque() {
  scoped_refptr<SecurityOrigin> origin = base::AdoptRef(
      new SecurityOrigin(NewUniqueOpaque::kWithLazyInitNonce, nullptr));
  DCHECK(origin->IsOpaque());
  DCHECK(!origin->precursor_origin_);
  return origin;
}

scoped_refptr<SecurityOrigin> SecurityOrigin::CreateOpaque(
    const url::Origin::Nonce& nonce,
    const SecurityOrigin* precursor) {
  scoped_refptr<SecurityOrigin> origin =
      base::AdoptRef(new SecurityOrigin(nonce, precursor));
  DCHECK(origin->IsOpaque());
  return origin;
}

scoped_refptr<SecurityOrigin> SecurityOrigin::CreateFromUrlOrigin(
    const url::Origin& origin) {
  const url::SchemeHostPort& tuple = origin.GetTupleOrPrecursorTupleIfOpaque();
  DCHECK(String::FromUTF8(tuple.scheme()).ContainsOnlyASCIIOrEmpty());
  DCHECK(String::FromUTF8(tuple.host()).ContainsOnlyASCIIOrEmpty());

  scoped_refptr<SecurityOrigin> tuple_origin;
  if (tuple.IsValid()) {
    tuple_origin =
        CreateFromValidTuple(String::FromUTF8(tuple.scheme()),
                             String::FromUTF8(tuple.host()), tuple.port());
  }
  const base::UnguessableToken* nonce_if_opaque =
      origin.GetNonceForSerialization();
  DCHECK_EQ(!!nonce_if_opaque, origin.opaque());
  if (nonce_if_opaque) {
    return base::AdoptRef(new SecurityOrigin(
        url::Origin::Nonce(*nonce_if_opaque), tuple_origin.get()));
  }
  CHECK(tuple_origin);
  return tuple_origin;
}

url::Origin SecurityOrigin::ToUrlOrigin() const {
  const SecurityOrigin* unmasked = GetOriginOrPrecursorOriginIfOpaque();
  std::string scheme = unmasked->protocol_.Utf8();
  std::string host = unmasked->host_.Utf8();
  uint16_t port = unmasked->port_;
  if (nonce_if_opaque_) {
    url::Origin result = url::Origin::CreateOpaqueFromNormalizedPrecursorTuple(
        std::move(scheme), std::move(host), port, *nonce_if_opaque_);
    CHECK(result.opaque());
    return result;
  }
  url::Origin result = url::Origin::CreateFromNormalizedTuple(
      std::move(scheme), std::move(host), port);
  CHECK(!result.opaque());
  return result;
}

scoped_refptr<SecurityOrigin> SecurityOrigin::IsolatedCopy() const {
  return base::AdoptRef(new SecurityOrigin(
      this, ConstructIsolatedCopy::kConstructIsolatedCopyBit));
}

void SecurityOrigin::SetDomainFromDOM(const String& new_domain) {
  domain_was_set_in_dom_ = true;
  domain_ = new_domain;
}

String SecurityOrigin::RegistrableDomain() const {
  if (IsOpaque())
    return String();

  OriginAccessEntry entry(
      *this, network::mojom::CorsDomainMatchMode::kAllowRegistrableDomains);
  String domain = entry.registrable_domain();
  return domain.empty() ? String() : domain;
}

const base::UnguessableToken* SecurityOrigin::GetNonceForSerialization() const {
  // The call to token() forces initialization of the |nonce_if_opaque_| if
  // not already initialized.
  return nonce_if_opaque_ ? &nonce_if_opaque_->token() : nullptr;
}

bool SecurityOrigin::CanAccess(const SecurityOrigin* other,
                               AccessResultDomainDetail& detail) const {
  if (universal_access_) {
    detail = AccessResultDomainDetail::kDomainNotRelevant;
    return true;
  }

  bool can_access = IsSameOriginDomainWith(other, detail);

  // Compare that the clusters are the same.
  if (can_access && !cross_agent_cluster_access_ &&
      !agent_cluster_id_.is_empty() && !other->agent_cluster_id_.is_empty() &&
      agent_cluster_id_ != other->agent_cluster_id_) {
    detail = AccessResultDomainDetail::kDomainNotRelevantAgentClusterMismatch;
    can_access = false;
  }

  return can_access;
}

bool SecurityOrigin::PassesFileCheck(const SecurityOrigin* other) const {
  DCHECK(IsLocal());
  DCHECK(other->IsLocal());

  return !block_local_access_from_local_origin_ &&
         !other->block_local_access_from_local_origin_;
}

bool SecurityOrigin::CanRequest(const KURL& url) const {
  if (universal_access_)
    return true;

  if (SerializesAsNull()) {
    // Allow the request if the URL is blob and it has the same "null" origin
    // with |this|.
    if (!url.ProtocolIs("blob") || BlobURL::GetOrigin(url) != "null")
      return false;
    if (BlobURLNullOriginMap::GetInstance()->Get(url) == this)
      return true;
    // BlobURLNullOriginMap doesn't work for cross-thread blob URL loading
    // (e.g., top-level worker script loading) because SecurityOrigin and
    // BlobURLNullOriginMap are thread-specific. For the case, check
    // BlobURLOpaqueOriginNonceMap.
    const base::UnguessableToken* nonce = GetNonceForSerialization();
    if (nonce && BlobURLOpaqueOriginNonceMap::GetInstance().Get(url) == *nonce)
      return true;
    return false;
  }

  scoped_refptr<const SecurityOrigin> target_origin =
      SecurityOrigin::Create(url);

  if (target_origin->IsOpaque())
    return false;

  // We call IsSameOriginWith here instead of canAccess because we want to
  // ignore `document.domain` effects.
  if (IsSameOriginWith(target_origin.get()))
    return true;

  if (SecurityPolicy::IsOriginAccessAllowed(this, target_origin.get()))
    return true;

  return false;
}

bool SecurityOrigin::CanReadContent(const KURL& url) const {
  if (CanRequest(url))
    return true;

  // This function exists because we treat data URLs as having a unique opaque
  // origin, see https://fetch.spec.whatwg.org/#main-fetch.
  // TODO(dcheng): If we plumb around the 'precursor' origin, then maybe we
  // don't need this?
  if (url.ProtocolIsData())
    return true;

  return false;
}

bool SecurityOrigin::CanDisplay(const KURL& url) const {
  if (universal_access_)
    return true;

  // Data URLs can always be displayed.
  if (base::FeatureList::IsEnabled(features::kOptimizeLoadingDataUrls) &&
      url.ProtocolIsData()) {
    return true;
  }

  String protocol = url.Protocol();
  if (SchemeRegistry::CanDisplayOnlyIfCanRequest(protocol))
    return CanRequest(url);

  if (SchemeRegistry::ShouldTreatURLSchemeAsDisplayIsolated(protocol)) {
    return protocol_ == protocol ||
           SecurityPolicy::IsOriginAccessToURLAllowed(this, url);
  }

  if (base::Contains(url::GetLocalSchemes(), protocol.Ascii())) {
    return CanLoadLocalResources() ||
           SecurityPolicy::IsOriginAccessToURLAllowed(this, url);
  }

  return true;
}

bool SecurityOrigin::IsPotentiallyTrustworthy() const {
  // TODO(https://crbug.com/1153336): The code below can hopefully be eventually
  // deleted and IsOriginPotentiallyTrustworthy can be used instead (from
  // //services/network/public/cpp/is_potentially_trustworthy.h).

  DCHECK_NE(protocol_, "data");
  if (IsOpaque())
    return is_opaque_origin_potentially_trustworthy_;
  return network::IsOriginPotentiallyTrustworthy(ToUrlOrigin());
}

// static
String SecurityOrigin::IsPotentiallyTrustworthyErrorMessage() {
  return "Only secure origins are allowed (see: https://goo.gl/Y0ZkNV).";
}

void SecurityOrigin::GrantLoadLocalResources() {
  // Granting privileges to some, but not all, documents in a SecurityOrigin
  // is a security hazard because the documents without the privilege can
  // obtain the privilege by injecting script into the documents that have
  // been granted the privilege.
  can_load_local_resources_ = true;
}

void SecurityOrigin::GrantUniversalAccess() {
  universal_access_ = true;
}

void SecurityOrigin::GrantCrossAgentClusterAccess() {
  cross_agent_cluster_access_ = true;
}

void SecurityOrigin::BlockLocalAccessFromLocalOrigin() {
  DCHECK(IsLocal());
  block_local_access_from_local_origin_ = true;
}

bool SecurityOrigin::IsLocal() const {
  return base::Contains(url::GetLocalSchemes(), protocol_.Ascii());
}

bool SecurityOrigin::IsLocalhost() const {
  // We special-case "[::1]" here because `net::HostStringIsLocalhost` expects a
  // canonicalization that excludes the braces; a simple string comparison is
  // simpler than trying to adjust Blink's canonicalization.
  return host_ == "[::1]" || net::HostStringIsLocalhost(host_.Ascii());
}

String SecurityOrigin::ToString() const {
  if (SerializesAsNull())
    return "null";
  return ToRawString();
}

AtomicString SecurityOrigin::ToAtomicString() const {
  if (SerializesAsNull())
    return AtomicString("null");

  if (protocol_ == "file")
    return AtomicString("file://");

  StringBuilder result;
  BuildRawString(result);
  return result.ToAtomicString();
}

String SecurityOrigin::ToRawString() const {
  if (protocol_ == "file")
    return "file://";

  StringBuilder result;
  BuildRawString(result);
  return result.ToString();
}

void SecurityOrigin::BuildRawString(StringBuilder& builder) const {
  builder.Append(protocol_);
  builder.Append("://");
  builder.Append(host_);

  if (DefaultPortForProtocol(protocol_) &&
      port_ != DefaultPortForProtocol(protocol_)) {
    builder.Append(':');
    builder.AppendNumber(port_);
  }
}

String SecurityOrigin::ToTokenForFastCheck() const {
  CHECK(!agent_cluster_id_.is_empty());
  if (SerializesAsNull())
    return String();

  StringBuilder result;
  BuildRawString(result);
  // Append the agent cluster id to the generated token to prevent
  // access from two contexts that have the same origin but are
  // in different agent clusters.
  result.Append(agent_cluster_id_.ToString().c_str());
  return result.ToString();
}

scoped_refptr<SecurityOrigin> SecurityOrigin::CreateFromString(
    const String& origin_string) {
  return SecurityOrigin::Create(KURL(NullURL(), origin_string));
}

scoped_refptr<SecurityOrigin> SecurityOrigin::CreateFromValidTuple(
    const String& protocol,
    const String& host,
    uint16_t port) {
  return base::AdoptRef(new SecurityOrigin(protocol, host, port));
}

bool SecurityOrigin::IsSameOriginWith(const SecurityOrigin* other) const {
  // This is needed to ensure a local origin considered to have the same scheme,
  // host, and port to itself.
  // TODO(tzik): Make the local origin unique but not opaque, and remove this
  // condition.
  if (this == other)
    return true;

  if (IsOpaque() || other->IsOpaque())
    return nonce_if_opaque_ == other->nonce_if_opaque_;

  if (host_ != other->host_)
    return false;

  if (protocol_ != other->protocol_)
    return false;

  if (port_ != other->port_)
    return false;

  if (IsLocal() && !PassesFileCheck(other))
    return false;

  return true;
}

bool SecurityOrigin::AreSameOrigin(const KURL& a, const KURL& b) {
  scoped_refptr<const SecurityOrigin> origin_a = SecurityOrigin::Create(a);
  scoped_refptr<const SecurityOrigin> origin_b = SecurityOrigin::Create(b);
  return origin_b->IsSameOriginWith(origin_a.get());
}

bool SecurityOrigin::IsSameOriginDomainWith(
    const SecurityOrigin* other,
    AccessResultDomainDetail& detail) const {
  // This is needed to ensure an origin can access to itself under nullified
  // document.domain.
  // TODO(tzik): Update the nulled domain handling and remove this condition.
  if (this == other) {
    detail = AccessResultDomainDetail::kDomainNotRelevant;
    return true;
  }

  if (IsOpaque() || other->IsOpaque()) {
    detail = AccessResultDomainDetail::kDomainNotRelevant;
    return nonce_if_opaque_ == other->nonce_if_opaque_;
  }

  // document.domain handling, as per
  // https://html.spec.whatwg.org/C/#dom-document-domain:
  //
  // 1) Neither document has set document.domain. In this case, we insist
  //    that the scheme, host, and port of the URLs match.
  //
  // 2) Both documents have set document.domain. In this case, we insist
  //    that the documents have set document.domain to the same value and
  //    that the scheme of the URLs match. Ports do not need to match.
  bool can_access = false;
  if (protocol_ == other->protocol_) {
    if (!domain_was_set_in_dom_ && !other->domain_was_set_in_dom_) {
      detail = AccessResultDomainDetail::kDomainNotSet;
      if (host_ == other->host_ && port_ == other->port_)
        can_access = true;
    } else if (domain_was_set_in_dom_ && other->domain_was_set_in_dom_) {
      if (domain_ == other->domain_) {
        can_access = true;
        detail = (host_ == other->host_ && port_ == other->port_)
                     ? AccessResultDomainDetail::kDomainMatchUnnecessary
                     : AccessResultDomainDetail::kDomainMatchNecessary;
      } else {
        detail = (host_ == other->host_ && port_ == other->port_)
                     ? AccessResultDomainDetail::kDomainMismatch
                     : AccessResultDomainDetail::kDomainNotRelevant;
      }
    } else {
      detail = (host_ == other->host_ && port_ == other->port_)
                   ? AccessResultDomainDetail::kDomainSetByOnlyOneOrigin
                   : AccessResultDomainDetail::kDomainNotRelevant;
    }
  } else {
    detail = AccessResultDomainDetail::kDomainNotRelevant;
  }

  if (can_access && IsLocal() && !PassesFileCheck(other)) {
    detail = AccessResultDomainDetail::kDomainNotRelevant;
    can_access = false;
  }

  return can_access;
}

bool SecurityOrigin::IsSameSiteWith(const SecurityOrigin* other) const {
  // "A and B are either both opaque origins, or both tuple origins with the
  // same scheme"
  if (IsOpaque() != other->IsOpaque())
    return false;
  if (!IsOpaque() && Protocol() != other->Protocol())
    return false;

  // Schemelessly same site check.
  // https://html.spec.whatwg.org/#schemelessly-same-site
  if (IsOpaque())
    return IsSameOriginWith(other);
  String registrable_domain = RegistrableDomain();
  if (registrable_domain.IsNull()) {
    return Host() == other->Host();
  }
  return registrable_domain == other->RegistrableDomain();
}

const KURL& SecurityOrigin::UrlWithUniqueOpaqueOrigin() {
  DCHECK(IsMainThread());
  DEFINE_STATIC_LOCAL(const KURL, url, ("data:,"));
  return url;
}

std::unique_ptr<SecurityOrigin::PrivilegeData>
SecurityOrigin::CreatePrivilegeData() const {
  std::unique_ptr<PrivilegeData> privilege_data =
      std::make_unique<PrivilegeData>();
  privilege_data->universal_access_ = universal_access_;
  privilege_data->can_load_local_resources_ = can_load_local_resources_;
  privilege_data->block_local_access_from_local_origin_ =
      block_local_access_from_local_origin_;
  return privilege_data;
}

void SecurityOrigin::TransferPrivilegesFrom(
    std::unique_ptr<PrivilegeData> privilege_data) {
  universal_access_ = privilege_data->universal_access_;
  can_load_local_resources_ = privilege_data->can_load_local_resources_;
  block_local_access_from_local_origin_ =
      privilege_data->block_local_access_from_local_origin_;
}

void SecurityOrigin::SetOpaqueOriginIsPotentiallyTrustworthy(
    bool is_opaque_origin_potentially_trustworthy) {
  DCHECK(!is_opaque_origin_potentially_trustworthy || IsOpaque());
  is_opaque_origin_potentially_trustworthy_ =
      is_opaque_origin_potentially_trustworthy;
}

scoped_refptr<SecurityOrigin> SecurityOrigin::DeriveNewOpaqueOrigin() const {
  return base::AdoptRef(
      new SecurityOrigin(NewUniqueOpaque::kWithLazyInitNonce,
                         GetOriginOrPrecursorOriginIfOpaque()));
}

const SecurityOrigin* SecurityOrigin::GetOriginOrPrecursorOriginIfOpaque()
    const {
  if (!precursor_origin_)
    return this;

  DCHECK(IsOpaque());
  return precursor_origin_.get();
}

String SecurityOrigin::CanonicalizeSpecialHost(const String& host,
                                               bool* success) {
  url::Component out_host;
  url::RawCanonOutputT<char> canon_output;
  if (host.Is8Bit()) {
    StringUTF8Adaptor utf8(host);
    *success = url::CanonicalizeSpecialHost(
        utf8.data(), url::Component(0, utf8.size()), canon_output, out_host);
  } else {
    *success = url::CanonicalizeSpecialHost(host.Characters16(),
                                            url::Component(0, host.length()),
                                            canon_output, out_host);
  }
  return String::FromUTF8(canon_output.view());
}

String SecurityOrigin::CanonicalizeHost(const String& host,
                                        const String& scheme,
                                        bool* success) {
  if (scheme != url::kFileScheme) {
    return CanonicalizeSpecialHost(host, success);
  }

  url::Component out_host;
  url::RawCanonOutputT<char> canon_output;
  if (host.Is8Bit()) {
    StringUTF8Adaptor utf8(host);
    *success = url::CanonicalizeFileHost(
        utf8.data(), url::Component(0, utf8.size()), canon_output, out_host);
  } else {
    *success = url::CanonicalizeFileHost(host.Characters16(),
                                         url::Component(0, host.length()),
                                         canon_output, out_host);
  }
  return String::FromUTF8(canon_output.view());
}

scoped_refptr<SecurityOrigin> SecurityOrigin::GetOriginForAgentCluster(
    const base::UnguessableToken& agent_cluster_id) {
  if (agent_cluster_id_ == agent_cluster_id)
    return this;
  auto result = base::AdoptRef(new SecurityOrigin(
      this, ConstructSameThreadCopy::kConstructSameThreadCopyBit));
  result->agent_cluster_id_ = agent_cluster_id;
  return result;
}

bool SecurityOrigin::SerializesAsNull() const {
  if (IsOpaque())
    return true;

  if (IsLocal() && block_local_access_from_local_origin_)
    return true;

  return false;
}

}  // namespace blink

"""

```