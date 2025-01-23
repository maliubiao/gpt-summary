Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

**1. Initial Understanding: What is the File About?**

The filename `storage_access_handle.cc` and the namespace `blink::storage_access` immediately suggest this code manages access to different storage mechanisms within the Blink rendering engine (used by Chromium). The `#include` directives confirm this, referencing various storage-related classes like `StorageArea`, `IDBFactory`, `CacheStorage`, `FileSystemDirectoryHandle`, `Blob`, `BroadcastChannel`, and `SharedWorker`.

**2. Core Functionality - The `StorageAccessHandle` Class:**

The central element is the `StorageAccessHandle` class. The constructor takes a `LocalDOMWindow` and a `StorageAccessTypes` object. This suggests that the handle is associated with a specific browsing context (the window) and is configured to allow access to certain storage types.

**3. Analyzing Member Functions - Identifying Capabilities:**

The class has several public member functions like `sessionStorage()`, `localStorage()`, `indexedDB()`, `locks()`, `caches()`, `getDirectory()`, `estimate()`, `createObjectURL()`, `revokeObjectURL()`, `BroadcastChannel()`, and `SharedWorker()`. These names strongly indicate the different storage APIs the handle can grant access to.

**4. Connecting to Web Standards (JavaScript, HTML, CSS):**

Now the crucial step: linking these C++ functions to their corresponding web APIs.

* **`sessionStorage()` and `localStorage()`:**  These directly correspond to the `sessionStorage` and `localStorage` JavaScript properties on the `window` object. They are used for storing key-value pairs client-side.
* **`indexedDB()`:** This relates to the IndexedDB API in JavaScript for more structured, transactional client-side storage.
* **`locks()`:** This corresponds to the Web Locks API, allowing scripts to acquire and release locks to coordinate access to shared resources.
* **`caches()`:** This relates to the Cache API, often used by Service Workers to cache network requests for offline access.
* **`getDirectory()`:** This points to the Origin Private File System (OPFS) API, allowing access to a private file system for the origin.
* **`estimate()`:** This is about the `navigator.storage.estimate()` method, providing information about storage usage and quota.
* **`createObjectURL()` and `revokeObjectURL()`:** These are methods on the `URL` object (though often accessed via `window.URL`), used for creating and revoking URLs that represent `Blob` or `File` objects in memory.
* **`BroadcastChannel()`:** This is the JavaScript Broadcast Channel API, enabling communication between browsing contexts (tabs, windows, iframes) from the same origin.
* **`SharedWorker()`:** This corresponds to the `SharedWorker` JavaScript constructor, allowing scripts from different browsing contexts of the same origin to run in a single worker thread.

**5. Examining Error Handling and Pre-Initialization:**

The code has several static `const char` variables that are error messages (e.g., `kSessionStorageNotRequested`). These are used in the member functions to throw `SecurityError` exceptions if the corresponding storage type wasn't requested when the `StorageAccessHandle` was created. This immediately suggests a key mechanism: the `StorageAccessTypes` configuration determines which storage APIs are accessible.

The constructor also includes logic to preemptively fetch resources (like `SessionStorageArea`, `LocalStorageArea`, etc.) if the corresponding storage type is requested. This optimization aims to reduce latency when these storage APIs are actually used.

**6. Logic Inference (Assumptions and Outputs):**

Consider the `sessionStorage()` function as an example:

* **Input (Implicit):**  A `StorageAccessHandle` object where `storage_access_types_->sessionStorage()` is true.
* **Input (Explicit):**  An `ExceptionState` object.
* **Logic:** The function retrieves the `SessionStorageArea`. It checks if the window's origin is local (for file access tracking). It also checks `CanAccessStorage()` on the `SessionStorageArea`.
* **Output (Success):**  A pointer to the `StorageArea` for session storage.
* **Output (Failure):** `nullptr` and a `SecurityError` in the `ExceptionState` if session storage wasn't requested or access is denied.

**7. Identifying Common Usage Errors:**

The error messages themselves point to common mistakes:

* Trying to use `sessionStorage()` when it wasn't requested during handle creation.
* Similar errors for other storage types.

**8. Tracing User Actions (Debugging Clues):**

To understand how execution reaches this code, consider the typical flow of the Storage Access API:

1. **User Interaction/Script Execution:** A script in a cross-site iframe might call `document.requestStorageAccess()`.
2. **Permission Check/Prompt:** The browser checks if the request is allowed (potentially showing a permission prompt to the user).
3. **`requestStorageAccess()` Resolution:** If permission is granted, the promise returned by `requestStorageAccess()` resolves.
4. **`StorageAccessHandle` Creation:** The resolution of the promise likely involves creating a `StorageAccessHandle` instance on the iframe's window, based on the requested storage types.
5. **Accessing Storage:** The script in the iframe then uses methods on the `StorageAccessHandle` (like `.sessionStorage`, `.indexedDB`, etc.) to interact with the granted storage.

Therefore, debugging might involve:

* **Checking the `requestStorageAccess()` call:**  Was it called? Did it succeed?
* **Inspecting the `StorageAccessTypes`:** What storage types were requested?
* **Setting breakpoints:** Inside the `StorageAccessHandle` constructor and its member functions to see if they are being called and why they might be failing.

**9. Structuring the Explanation:**

Finally, organize the findings into a clear and structured explanation covering:

* **Purpose of the file:**  High-level overview.
* **Functionality:**  Detailed description of the `StorageAccessHandle` and its methods.
* **Relationship to web technologies:**  Connecting C++ functions to JavaScript APIs and related HTML/CSS concepts.
* **Logic inference:**  Providing concrete examples of function behavior.
* **Common errors:**  Highlighting potential pitfalls for developers.
* **User action tracing:**  Outlining the steps leading to this code for debugging.

This detailed breakdown reflects a systematic approach to understanding and explaining complex code. It involves reading the code, understanding the domain (web storage), making connections to higher-level concepts, and thinking about potential use cases and error scenarios.
This C++ source code file, `storage_access_handle.cc`, defines the `StorageAccessHandle` class within the Blink rendering engine. This class is a crucial part of the **Storage Access API**, which allows embedded (cross-site) iframes to request access to their top-level site's storage (cookies and other storage mechanisms).

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Encapsulates Granted Storage Access:** The primary function of `StorageAccessHandle` is to act as a **capabilities handle**. When a cross-site iframe successfully requests storage access (typically via `document.requestStorageAccess()`), an instance of `StorageAccessHandle` is provided to that iframe. This handle grants access to specific storage mechanisms based on what was requested.

2. **Provides Access to Various Storage APIs:** The class offers methods that return interfaces to different storage mechanisms:
   - `sessionStorage()`: Returns a `StorageArea` object for accessing session storage.
   - `localStorage()`: Returns a `StorageArea` object for accessing local storage.
   - `indexedDB()`: Returns an `IDBFactory` object for interacting with IndexedDB.
   - `locks()`: Returns a `LockManager` object for using the Web Locks API.
   - `caches()`: Returns a `CacheStorage` object for accessing the Cache API.
   - `getDirectory()`: Returns a `FileSystemDirectoryHandle` for accessing the Origin Private File System (OPFS).
   - `estimate()`: Returns a `Promise` that resolves with storage usage and quota estimates.
   - `createObjectURL()`: Allows creating object URLs for `Blob` objects.
   - `revokeObjectURL()`: Allows revoking previously created object URLs.
   - `BroadcastChannel()`: Returns a `BroadcastChannel` object for inter-context communication.
   - `SharedWorker()`: Allows creating `SharedWorker` instances.

3. **Enforces Requested Permissions:**  A key aspect is that the `StorageAccessHandle` is initialized with a `StorageAccessTypes` object. This object specifies which storage mechanisms were actually requested during the `requestStorageAccess()` call. The `StorageAccessHandle`'s methods **enforce** these permissions. If an iframe tries to access a storage mechanism that wasn't explicitly requested, a `SecurityError` is thrown.

4. **Tracks Feature Usage:** The constructor of `StorageAccessHandle` includes code to track the usage of different features within the Storage Access API using `WebFeature::kStorageAccessAPI_...`. This is for internal Chromium telemetry.

5. **Pre-fetches Resources:**  The constructor also preemptively retrieves underlying storage resources (like `SessionStorageArea`, `LocalStorageArea`, `IDBFactory`, etc.) if they were requested. This can improve performance by reducing latency when these resources are actually needed.

**Relationship to JavaScript, HTML, CSS:**

This C++ code directly underpins JavaScript APIs related to storage. Here's how the methods map:

* **`sessionStorage()` and `localStorage()`:** These correspond directly to the `sessionStorage` and `localStorage` properties available on the `window` object in JavaScript. When JavaScript code in an iframe accesses `window.sessionStorage` or `window.localStorage` after obtaining a `StorageAccessHandle`, the underlying C++ implementation in this file is involved.

   **Example:**
   ```javascript
   // Inside an iframe that has a StorageAccessHandle
   const handle = ...; // Assume this holds the StorageAccessHandle

   // Accessing session storage (if requested)
   if (handle) {
     const storage = handle.sessionStorage;
     storage.setItem('myKey', 'myValue');
     console.log(storage.getItem('myKey'));
   }
   ```

* **`indexedDB()`:** This maps to the `indexedDB` property on the `window` object, providing access to the Indexed Database API in JavaScript.

   **Example:**
   ```javascript
   // Inside an iframe with a StorageAccessHandle
   if (handle) {
     const request = handle.indexedDB.open('myDatabase', 1);
     // ... proceed with IndexedDB operations
   }
   ```

* **`locks()`:**  This relates to the `navigator.locks` property, allowing access to the Web Locks API.

   **Example:**
   ```javascript
   // Inside an iframe with a StorageAccessHandle
   if (handle) {
     navigator.locks.request('my_resource', () => {
       console.log('Lock acquired!');
       // ... perform actions while holding the lock
     });
   }
   ```

* **`caches()`:** This corresponds to the `caches` property, primarily used within Service Workers but also accessible in other contexts, providing access to the Cache API.

   **Example:**
   ```javascript
   // Inside an iframe with a StorageAccessHandle
   if (handle) {
     caches.open('my-cache').then(cache => {
       // ... use the cache
     });
   }
   ```

* **`getDirectory()`:** This is related to the File System Access API, specifically the Origin Private File System (OPFS). The JavaScript would use methods on `navigator.storage` to access this.

   **Example:**
   ```javascript
   // Inside an iframe with a StorageAccessHandle
   if (handle) {
     navigator.storage.getDirectory().then(rootDirectory => {
       // ... work with the directory handle
     });
   }
   ```

* **`estimate()`:** This corresponds to the `navigator.storage.estimate()` method, allowing JavaScript to query storage usage and quota.

   **Example:**
   ```javascript
   // Inside an iframe with a StorageAccessHandle
   if (handle) {
     navigator.storage.estimate().then(estimate => {
       console.log('Usage:', estimate.usage);
       console.log('Quota:', estimate.quota);
     });
   }
   ```

* **`createObjectURL()` and `revokeObjectURL()`:** These are methods on the `URL` object (often accessed via `window.URL`) in JavaScript and are used for creating and revoking URLs representing `Blob` or `File` objects.

   **Example:**
   ```javascript
   // Inside an iframe with a StorageAccessHandle
   if (handle) {
     const blob = new Blob(['Hello, world!'], { type: 'text/plain' });
     const url = URL.createObjectURL(blob);
     console.log(url); // Output: blob:https://example.com/some-unique-id
     URL.revokeObjectURL(url);
   }
   ```

* **`BroadcastChannel()`:** This maps to the `BroadcastChannel` constructor in JavaScript, allowing for simple communication between different browsing contexts (tabs, windows, iframes) from the same origin.

   **Example:**
   ```javascript
   // Inside an iframe with a StorageAccessHandle
   if (handle) {
     const bc = new BroadcastChannel('my_channel');
     bc.postMessage('Hello from the iframe!');
   }
   ```

* **`SharedWorker()`:** This corresponds to the `SharedWorker` constructor in JavaScript, enabling the creation of worker threads that can be accessed by multiple browsing contexts from the same origin.

   **Example:**
   ```javascript
   // Inside an iframe with a StorageAccessHandle
   if (handle) {
     const worker = new SharedWorker('worker.js');
     worker.port.start();
     worker.port.postMessage('Hello from the iframe!');
   }
   ```

CSS has no direct functional relationship with this specific C++ file. CSS styling might be affected by data stored using these storage APIs (e.g., a user preference stored in `localStorage` affecting the theme), but the `StorageAccessHandle` itself doesn't interact directly with CSS. HTML elements trigger the JavaScript that eventually interacts with the storage APIs.

**Logical Inference (Hypothetical Input and Output):**

**Scenario 1: Requesting and Accessing Session Storage**

* **Hypothetical Input (JavaScript in the iframe):**
  ```javascript
  document.requestStorageAccess({ sessionStorage: true }).then(handle => {
    if (handle) {
      const storage = handle.sessionStorage;
      storage.setItem('myKey', 'myValue');
      console.log(storage.getItem('myKey')); // Expected output: "myValue"
    }
  });
  ```
* **Corresponding C++ Logic:**
    - The `requestStorageAccess()` call (handled in other Blink code) would result in a `StorageAccessHandle` being created with `storage_access_types_->sessionStorage()` being true.
    - When `handle.sessionStorage` is accessed in JavaScript, the `StorageAccessHandle::sessionStorage()` method in C++ is called.
    - This method would pass the security check (since `sessionStorage` was requested).
    - It would retrieve and return the appropriate `StorageArea` object for session storage.
    - Subsequent calls to `storage.setItem()` and `storage.getItem()` would interact with this `StorageArea` object.

* **Hypothetical Output (from C++):** The `StorageArea` object, allowing JavaScript to manipulate session storage.

**Scenario 2: Trying to Access Local Storage When Not Requested**

* **Hypothetical Input (JavaScript in the iframe):**
  ```javascript
  document.requestStorageAccess({ sessionStorage: true }).then(handle => {
    if (handle) {
      try {
        const storage = handle.localStorage; // Attempt to access localStorage
      } catch (e) {
        console.error(e.name, e.message); // Expected output: "SecurityError" "Local storage not requested..."
      }
    }
  });
  ```
* **Corresponding C++ Logic:**
    - The `StorageAccessHandle` is created with `storage_access_types_->localStorage()` being false.
    - When `handle.localStorage` is accessed in JavaScript, the `StorageAccessHandle::localStorage()` method in C++ is called.
    - This method would detect that `storage_access_types_->localStorage()` is false.
    - It would throw a `SecurityError` exception with the message "Local storage not requested when storage access handle was initialized."

* **Hypothetical Output (from C++):** A `nullptr` is returned, and a `SecurityError` is set in the `ExceptionState`, which is then propagated to the JavaScript as an exception.

**Common Usage Errors and Examples:**

1. **Accessing Unrequested Storage:**
   - **Error:** Trying to use `handle.localStorage` when only `sessionStorage` was requested.
   - **Example (JavaScript):**
     ```javascript
     document.requestStorageAccess({ sessionStorage: true }).then(handle => {
       if (handle) {
         handle.localStorage.setItem('key', 'value'); // This will throw a SecurityError
       }
     });
     ```
   - **C++ Consequence:** The `StorageAccessHandle::localStorage()` method throws a `SecurityError`.

2. **Incorrectly Assuming Access:**
   - **Error:**  Not checking if `requestStorageAccess()` resolved successfully before trying to use the handle.
   - **Example (JavaScript):**
     ```javascript
     document.requestStorageAccess({ sessionStorage: true }).then(handle => {
       // The promise might resolve with null if access is denied
       if (handle) {
         handle.sessionStorage.setItem('key', 'value');
       } else {
         console.log("Storage access was not granted.");
       }
     });
     ```
   - **C++ Consequence:** If `handle` is `null`, trying to access its properties will lead to JavaScript errors, not directly involving this C++ file in that specific error scenario. However, if `requestStorageAccess()` resolves with a handle but without the requested permissions, the C++ enforcement will trigger.

**User Operations Leading to This Code (Debugging Clues):**

To reach the code in `storage_access_handle.cc`, the following sequence of user and browser actions typically occurs:

1. **A user navigates to a website (the top-level site).**
2. **This top-level site embeds a cross-site iframe.**
3. **JavaScript code within the iframe calls `document.requestStorageAccess(options)`.** The `options` object specifies which storage mechanisms the iframe is requesting access to (e.g., `{ sessionStorage: true, localStorage: true }`).
4. **The browser evaluates the storage access request.** This involves checking browser settings, user permissions, and potentially prompting the user for permission.
5. **If the request is granted:**
   - Blink (the rendering engine) creates a `StorageAccessHandle` object.
   - The `StorageAccessHandle` is initialized with a `StorageAccessTypes` object reflecting the granted permissions.
   - The promise returned by `document.requestStorageAccess()` resolves with this `StorageAccessHandle` object.
6. **JavaScript code in the iframe then accesses properties (like `sessionStorage`, `indexedDB`, etc.) on the `StorageAccessHandle` object.** This triggers the corresponding methods in `storage_access_handle.cc`.

**Debugging Steps:**

- **Set breakpoints in the `StorageAccessHandle` constructor:**  To see when a handle is created and what storage types are being requested.
- **Set breakpoints in the `StorageAccessHandle::sessionStorage()`, `localStorage()`, etc. methods:** To see if these methods are being called and if the permission checks are passing or failing.
- **Inspect the `storage_access_types_` member:** To verify which storage mechanisms were actually requested and granted.
- **Check the output of `console.log` statements in the JavaScript:** To understand the flow of execution in the iframe's code and the results of the `requestStorageAccess()` call.
- **Use the browser's developer tools (Network tab, Application tab):** To examine storage contents and network requests related to storage access.
- **Look for `SecurityError` exceptions in the JavaScript console:** These often indicate permission issues related to the Storage Access API.

In summary, `storage_access_handle.cc` is a critical component in Blink's implementation of the Storage Access API, acting as a gatekeeper for cross-site iframe access to various storage mechanisms, enforcing permissions, and providing the necessary interfaces for JavaScript interaction.

### 提示词
```
这是目录为blink/renderer/modules/storage_access/storage_access_handle.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/storage_access/storage_access_handle.h"

#include "base/types/pass_key.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_storage_estimate.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_storage_usage_details.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/workers/shared_worker.h"
#include "third_party/blink/renderer/modules/broadcastchannel/broadcast_channel.h"
#include "third_party/blink/renderer/modules/file_system_access/storage_manager_file_system_access.h"
#include "third_party/blink/renderer/modules/storage_access/global_storage_access_handle.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

using PassKey = base::PassKey<StorageAccessHandle>;

// static
const char StorageAccessHandle::kSupplementName[] = "StorageAccessHandle";

// static
const char StorageAccessHandle::kSessionStorageNotRequested[] =
    "Session storage not requested when storage access handle was initialized.";

// static
const char StorageAccessHandle::kLocalStorageNotRequested[] =
    "Local storage not requested when storage access handle was initialized.";

// static
const char StorageAccessHandle::kIndexedDBNotRequested[] =
    "IndexedDB not requested when storage access handle was initialized.";

// static
const char StorageAccessHandle::kLocksNotRequested[] =
    "Web Locks not requested when storage access handle was initialized.";

// static
const char StorageAccessHandle::kCachesNotRequested[] =
    "Cache Storage not requested when storage access handle was initialized.";

// static
const char StorageAccessHandle::kGetDirectoryNotRequested[] =
    "Origin Private File System not requested when storage access handle was "
    "initialized.";

// static
const char StorageAccessHandle::kEstimateNotRequested[] =
    "The estimate function for Quota was not requested when storage access "
    "handle was initialized.";

// static
const char StorageAccessHandle::kCreateObjectURLNotRequested[] =
    "The createObjectURL function for Blob Stoage was not requested when "
    "storage access handle was initialized.";

// static
const char StorageAccessHandle::kRevokeObjectURLNotRequested[] =
    "The revokeObjectURL function for Blob Stoage was not requested when "
    "storage access handle was initialized.";

// static
const char StorageAccessHandle::kBroadcastChannelNotRequested[] =
    "Broadcast Channel was not requested when storage access handle was "
    "initialized.";

// static
const char StorageAccessHandle::kSharedWorkerNotRequested[] =
    "Shared Worker was not requested when storage access handle was "
    "initialized.";

namespace {

void EstimateImplAfterRemoteEstimate(
    ScriptPromiseResolver<StorageEstimate>* resolver,
    int64_t current_usage,
    int64_t current_quota,
    bool success) {
  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid()) {
    return;
  }
  ScriptState::Scope scope(script_state);

  if (!success) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kUnknownError,
        "Unknown error occurred while getting estimate."));
    return;
  }

  StorageEstimate* estimate = StorageEstimate::Create();
  estimate->setUsage(current_usage);
  estimate->setQuota(current_quota);
  estimate->setUsageDetails(StorageUsageDetails::Create());
  resolver->Resolve(estimate);
}

}  // namespace

StorageAccessHandle::StorageAccessHandle(
    LocalDOMWindow& window,
    const StorageAccessTypes* storage_access_types)
    : Supplement<LocalDOMWindow>(window),
      storage_access_types_(storage_access_types) {
  window.CountUse(
      WebFeature::kStorageAccessAPI_requestStorageAccess_BeyondCookies);
  if (storage_access_types_->all()) {
    window.CountUse(
        WebFeature::kStorageAccessAPI_requestStorageAccess_BeyondCookies_all);
  }
  if (storage_access_types_->cookies()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_cookies);
  }
  if (storage_access_types_->sessionStorage()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_sessionStorage);
  }
  if (storage_access_types_->localStorage()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_localStorage);
  }
  if (storage_access_types_->indexedDB()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_indexedDB);
  }
  if (storage_access_types_->locks()) {
    window.CountUse(
        WebFeature::kStorageAccessAPI_requestStorageAccess_BeyondCookies_locks);
  }
  if (storage_access_types_->caches()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_caches);
  }
  if (storage_access_types_->getDirectory()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_getDirectory);
  }
  if (storage_access_types_->estimate()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_estimate);
  }
  if (storage_access_types_->createObjectURL()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_createObjectURL);
  }
  if (storage_access_types_->revokeObjectURL()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_revokeObjectURL);
  }
  if (storage_access_types_->broadcastChannel()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_BroadcastChannel);
  }
  if (storage_access_types_->sharedWorker()) {
    window.CountUse(
        WebFeature::
            kStorageAccessAPI_requestStorageAccess_BeyondCookies_SharedWorker);
  }
  // StorageAccessHandle is constructed in a promise, so while we are 'awaiting'
  // we should preempt the IPC we know we will need (and let local/session
  // storage have a chance to load from disk if needed) to ensure the latency of
  // synchronous methods stays low.
  if (storage_access_types_->all() || storage_access_types_->sessionStorage()) {
    GlobalStorageAccessHandle::From(window).GetSessionStorageArea();
  }
  if (storage_access_types_->all() || storage_access_types_->localStorage()) {
    GlobalStorageAccessHandle::From(window).GetLocalStorageArea();
  }
  if (storage_access_types_->all() || storage_access_types_->indexedDB()) {
    GlobalStorageAccessHandle::From(window).GetIDBFactory();
  }
  if (storage_access_types_->all() || storage_access_types_->locks()) {
    GlobalStorageAccessHandle::From(window).GetLockManager();
  }
  if (storage_access_types_->all() || storage_access_types_->caches()) {
    GlobalStorageAccessHandle::From(window).GetCacheStorage();
  }
  if (storage_access_types_->all() || storage_access_types_->getDirectory()) {
    GlobalStorageAccessHandle::From(window).GetRemote();
  }
  if (storage_access_types_->all() || storage_access_types_->estimate()) {
    GlobalStorageAccessHandle::From(window).GetRemote();
  }
  if (storage_access_types_->all() ||
      storage_access_types_->createObjectURL() ||
      storage_access_types_->revokeObjectURL() ||
      storage_access_types_->sharedWorker()) {
    GlobalStorageAccessHandle::From(window).GetPublicURLManager();
  }
  if (storage_access_types_->all() ||
      storage_access_types_->broadcastChannel()) {
    GlobalStorageAccessHandle::From(window).GetBroadcastChannelProvider();
  }
  if (storage_access_types_->all() || storage_access_types_->sharedWorker()) {
    GlobalStorageAccessHandle::From(window).GetSharedWorkerConnector();
  }
}

void StorageAccessHandle::Trace(Visitor* visitor) const {
  visitor->Trace(storage_access_types_);
  ScriptWrappable::Trace(visitor);
  Supplement<LocalDOMWindow>::Trace(visitor);
}

StorageArea* StorageAccessHandle::sessionStorage(
    ExceptionState& exception_state) const {
  if (!storage_access_types_->all() &&
      !storage_access_types_->sessionStorage()) {
    exception_state.ThrowSecurityError(kSessionStorageNotRequested);
    return nullptr;
  }
  LocalDOMWindow* window = GetSupplementable();
  window->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_sessionStorage_Use);
  StorageArea* session_storage_area =
      GlobalStorageAccessHandle::From(*window).GetSessionStorageArea();
  if (!session_storage_area) {
    return nullptr;
  }
  if (window->GetSecurityOrigin()->IsLocal()) {
    window->CountUse(WebFeature::kFileAccessedSessionStorage);
  }
  if (!session_storage_area->CanAccessStorage()) {
    exception_state.ThrowSecurityError(StorageArea::kAccessDeniedMessage);
    return nullptr;
  }
  return session_storage_area;
}

StorageArea* StorageAccessHandle::localStorage(
    ExceptionState& exception_state) const {
  if (!storage_access_types_->all() && !storage_access_types_->localStorage()) {
    exception_state.ThrowSecurityError(kLocalStorageNotRequested);
    return nullptr;
  }
  LocalDOMWindow* window = GetSupplementable();
  window->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_localStorage_Use);
  StorageArea* local_storage_area =
      GlobalStorageAccessHandle::From(*window).GetLocalStorageArea();
  if (!local_storage_area) {
    return nullptr;
  }
  if (window->GetSecurityOrigin()->IsLocal()) {
    window->CountUse(WebFeature::kFileAccessedLocalStorage);
  }
  if (!local_storage_area->CanAccessStorage()) {
    exception_state.ThrowSecurityError(StorageArea::kAccessDeniedMessage);
    return nullptr;
  }
  return local_storage_area;
}

IDBFactory* StorageAccessHandle::indexedDB(
    ExceptionState& exception_state) const {
  if (!storage_access_types_->all() && !storage_access_types_->indexedDB()) {
    exception_state.ThrowSecurityError(kIndexedDBNotRequested);
    return nullptr;
  }
  GetSupplementable()->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_indexedDB_Use);
  return GlobalStorageAccessHandle::From(*GetSupplementable()).GetIDBFactory();
}

LockManager* StorageAccessHandle::locks(ExceptionState& exception_state) const {
  if (!storage_access_types_->all() && !storage_access_types_->locks()) {
    exception_state.ThrowSecurityError(kLocksNotRequested);
    return nullptr;
  }
  GetSupplementable()->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_locks_Use);
  return GlobalStorageAccessHandle::From(*GetSupplementable()).GetLockManager();
}

CacheStorage* StorageAccessHandle::caches(
    ExceptionState& exception_state) const {
  if (!storage_access_types_->all() && !storage_access_types_->caches()) {
    exception_state.ThrowSecurityError(kCachesNotRequested);
    return nullptr;
  }
  GetSupplementable()->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_caches_Use);
  return GlobalStorageAccessHandle::From(*GetSupplementable())
      .GetCacheStorage();
}

ScriptPromise<FileSystemDirectoryHandle> StorageAccessHandle::getDirectory(
    ScriptState* script_state,
    ExceptionState& exception_state) const {
  if (!storage_access_types_->all() && !storage_access_types_->getDirectory()) {
    auto* resolver =
        MakeGarbageCollected<ScriptPromiseResolver<FileSystemDirectoryHandle>>(
            script_state, exception_state.GetContext());
    auto promise = resolver->Promise();
    resolver->RejectWithSecurityError(kGetDirectoryNotRequested,
                                      kGetDirectoryNotRequested);
    return promise;
  }
  GetSupplementable()->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_getDirectory_Use);
  return StorageManagerFileSystemAccess::CheckStorageAccessIsAllowed(
      script_state, exception_state,
      WTF::BindOnce(&StorageAccessHandle::GetDirectoryImpl,
                    WrapWeakPersistent(this)));
}

void StorageAccessHandle::GetDirectoryImpl(
    ScriptPromiseResolver<FileSystemDirectoryHandle>* resolver) const {
  HeapMojoRemote<mojom::blink::StorageAccessHandle>& remote =
      GlobalStorageAccessHandle::From(*GetSupplementable()).GetRemote();
  if (!remote) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError));
    return;
  }
  remote->GetDirectory(
      WTF::BindOnce(&StorageManagerFileSystemAccess::DidGetSandboxedFileSystem,
                    WrapPersistent(resolver)));
}

ScriptPromise<StorageEstimate> StorageAccessHandle::estimate(
    ScriptState* script_state,
    ExceptionState& exception_state) const {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<StorageEstimate>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  if (!storage_access_types_->all() && !storage_access_types_->estimate()) {
    resolver->RejectWithSecurityError(kEstimateNotRequested,
                                      kEstimateNotRequested);
    return promise;
  }
  GetSupplementable()->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_estimate_Use);
  HeapMojoRemote<mojom::blink::StorageAccessHandle>& remote =
      GlobalStorageAccessHandle::From(*GetSupplementable()).GetRemote();
  if (!remote) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError));
    return promise;
  }
  remote->Estimate(WTF::BindOnce(&EstimateImplAfterRemoteEstimate,
                                 WrapPersistent(resolver)));
  return promise;
}

String StorageAccessHandle::createObjectURL(
    Blob* blob,
    ExceptionState& exception_state) const {
  if (!storage_access_types_->all() &&
      !storage_access_types_->createObjectURL()) {
    exception_state.ThrowSecurityError(kCreateObjectURLNotRequested);
    return "";
  }
  PublicURLManager* public_url_manager =
      GlobalStorageAccessHandle::From(*GetSupplementable())
          .GetPublicURLManager();
  if (!public_url_manager) {
    return "";
  }
  GetSupplementable()->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_createObjectURL_Use);
  GetSupplementable()->CountUse(WebFeature::kCreateObjectURLBlob);
  CHECK(blob);
  return public_url_manager->RegisterURL(blob);
}

void StorageAccessHandle::revokeObjectURL(
    const String& url,
    ExceptionState& exception_state) const {
  if (!storage_access_types_->all() &&
      !storage_access_types_->revokeObjectURL()) {
    exception_state.ThrowSecurityError(kRevokeObjectURLNotRequested);
    return;
  }
  PublicURLManager* public_url_manager =
      GlobalStorageAccessHandle::From(*GetSupplementable())
          .GetPublicURLManager();
  if (!public_url_manager) {
    return;
  }
  GetSupplementable()->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_revokeObjectURL_Use);
  KURL resolved_url(NullURL(), url);
  GetSupplementable()->GetExecutionContext()->RemoveURLFromMemoryCache(
      resolved_url);
  public_url_manager->Revoke(resolved_url);
}

BroadcastChannel* StorageAccessHandle::BroadcastChannel(
    ExecutionContext* execution_context,
    const String& name,
    ExceptionState& exception_state) const {
  if (!storage_access_types_->all() &&
      !storage_access_types_->broadcastChannel()) {
    exception_state.ThrowSecurityError(kBroadcastChannelNotRequested);
    return nullptr;
  }
  HeapMojoAssociatedRemote<mojom::blink::BroadcastChannelProvider>&
      broadcast_channel_provider =
          GlobalStorageAccessHandle::From(*GetSupplementable())
              .GetBroadcastChannelProvider();
  if (!broadcast_channel_provider) {
    return nullptr;
  }
  GetSupplementable()->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_BroadcastChannel_Use);
  return MakeGarbageCollected<blink::BroadcastChannel>(
      PassKey(), execution_context, name, broadcast_channel_provider.get());
}

blink::SharedWorker* StorageAccessHandle::SharedWorker(
    ExecutionContext* context,
    const String& url,
    const V8UnionSharedWorkerOptionsOrString* name_or_options,
    ExceptionState& exception_state) const {
  if (!storage_access_types_->all() && !storage_access_types_->sharedWorker()) {
    exception_state.ThrowSecurityError(kSharedWorkerNotRequested);
    return nullptr;
  }
  HeapMojoRemote<mojom::blink::SharedWorkerConnector>& shared_worker_connector =
      GlobalStorageAccessHandle::From(*GetSupplementable())
          .GetSharedWorkerConnector();
  if (!shared_worker_connector) {
    return nullptr;
  }
  PublicURLManager* public_url_manager =
      GlobalStorageAccessHandle::From(*GetSupplementable())
          .GetPublicURLManager();
  if (!public_url_manager) {
    return nullptr;
  }
  GetSupplementable()->CountUse(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_SharedWorker_Use);
  return SharedWorker::Create(PassKey(), context, url, name_or_options,
                              exception_state, public_url_manager,
                              &shared_worker_connector);
}

namespace bindings {

ExecutionContext* ExecutionContextFromV8Wrappable(
    const StorageAccessHandle* storage_access_handle) {
  return storage_access_handle->GetSupplementable();
}

}  // namespace bindings

}  // namespace blink
```