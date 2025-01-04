Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Understanding the Request:** The core request is to analyze the functionality of `v8_context_snapshot_impl.cc` within the Chromium Blink rendering engine. The request also specifically asks to relate its functions to JavaScript, HTML, and CSS, provide examples, explain logic, and address potential user errors and debugging steps.

2. **Initial Skim and Keyword Recognition:** I first quickly scanned the code for keywords and recognizable patterns. Words like "snapshot," "context," "V8," "JavaScript," "DOM," "Window," "Document," "HTML," and function names like `Init`, `CreateContext`, `InstallContextIndependentProps`, `TakeSnapshot` immediately stood out. These provide strong clues about the file's purpose. The presence of `#ifdef` directives relating to `USE_V8_CONTEXT_SNAPSHOT` is also important, indicating conditional compilation.

3. **Identifying Core Functionality - The "Snapshot" Concept:** The repeated mention of "snapshot" and the functions `TakeSnapshot` and `CreateContext` strongly suggest the file's primary role is managing snapshots of the V8 JavaScript execution environment. This leads to the hypothesis that it's about saving and restoring the state of the JavaScript environment.

4. **Connecting to JavaScript, HTML, and CSS:**  Given Blink's role, the JavaScript environment will inevitably interact with the DOM (HTML) and potentially CSS. The inclusion of headers like `v8_html_document.h`, `v8_window.h`, `html_document.h`, etc., confirms this connection. The code mentions creating `Window` and `HTMLDocument` objects within the snapshot, directly linking it to the web page structure. While CSS isn't explicitly mentioned in this *specific* file, it's understood that the state being captured could include JavaScript objects that manipulate CSS styles.

5. **Analyzing Key Functions:** I then focused on the important functions identified in the skim:

    * **`Init()`:**  This is a standard initialization function, likely called at startup. It registers the core snapshot-related functions (`CreateContext`, `InstallContextIndependentProps`, etc.).

    * **`CreateContext()`:** This function's name is very telling. It's responsible for creating a new V8 context, but conditionally, based on whether a snapshot is being used. The logic involves checking for the `USE_V8_CONTEXT_SNAPSHOT` flag and then using `v8::Context::FromSnapshot` to restore from a saved state. The parameters like `document` and `extension_config` hint at how the context is integrated into the browser environment.

    * **`InstallContextIndependentProps()`:** The name suggests this function sets up properties on V8 objects that don't depend on the specific context instance. This is likely about setting up the basic structure and methods of built-in JavaScript objects (like `window` and `document`).

    * **`InstallInterfaceTemplates()`:**  This function likely registers the V8 templates for the various Blink/DOM interfaces (like `Window`, `Document`, `Node`). Templates define the structure and behavior of JavaScript objects representing these interfaces.

    * **`TakeSnapshot()`:** This is the core function for saving the snapshot. It involves creating a `v8::SnapshotCreator`, configuring the environment (disabling experimental features), creating contexts for different "worlds" (main and isolated), and then serializing the V8 heap into a blob.

    * **`GetReferenceTable()`:** This function seems to be about providing a lookup table of function pointers. This is likely an optimization technique to avoid dynamic lookups during snapshot creation/restoration.

6. **Inferring Logic and Examples:** Based on the function analysis, I could infer the overall process:

    * **Taking a Snapshot:** The browser, under specific conditions (like during testing or a specific build process), can trigger `TakeSnapshot`. This saves the state of the JavaScript environment at that moment. The input is the current V8 isolate. The output is the serialized snapshot data.

    * **Restoring from a Snapshot:** When a new page or context is created, the browser can check if a snapshot is available. If so, `CreateContext` is used with the snapshot data to quickly restore the initial state. The input is the snapshot data and information about the DOM (like the `document`). The output is a new V8 context with the pre-initialized state.

7. **Identifying Potential Errors:**  The conditional checks for `USE_V8_CONTEXT_SNAPSHOT` and the checks within `CreateContext` (like the `CHECK(!html_document || ...)` and the `if (world.IsMainWorld()) { if (!html_document) ... }`)  highlight potential error scenarios. For example, trying to create a main-world context from a snapshot without a valid `HTMLDocument` could be an error. Incorrect build configurations where the snapshot is enabled but no snapshot data exists could also cause issues.

8. **Tracing User Actions (Debugging):** I thought about how a developer might end up in this code. Setting breakpoints in these functions during page load or during JavaScript execution that creates new contexts would be logical debugging steps. The conditions under which snapshots are taken and restored become crucial for understanding the flow.

9. **Structuring the Answer:** Finally, I organized the information logically, starting with the overall functionality, then diving into specifics for JavaScript, HTML, and CSS, providing examples, explaining logic, discussing errors, and outlining debugging strategies. I made sure to connect the code elements (like function names and header files) to the explanations. The use of bullet points and clear headings makes the information easier to digest. I also included the assumptions made during the analysis.
This C++ source file, `v8_context_snapshot_impl.cc`, within the Chromium Blink rendering engine, is responsible for **managing V8 context snapshots**. Essentially, it handles the process of **saving and restoring the state of the JavaScript environment** within a web page. This is a performance optimization technique that can significantly speed up the creation of new JavaScript contexts.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Taking V8 Context Snapshots (`TakeSnapshot`)**:
   - This function is responsible for capturing the current state of the V8 JavaScript engine's context. This includes the initial set of built-in JavaScript objects, their prototypes, and other essential runtime information.
   - It serializes this state into a binary "snapshot" that can be stored.
   - **Assumption:** This function is called in a controlled environment, likely during the browser's build process or under specific testing conditions.
   - **Input:** The current V8 isolate (an isolated instance of the V8 engine).
   - **Output:** A `v8::StartupData` object containing the serialized snapshot data.

2. **Creating V8 Contexts from Snapshots (`CreateContext`)**:
   - This function attempts to create a new V8 JavaScript context by loading from a previously created snapshot.
   - If a valid snapshot is available and the necessary conditions are met, it avoids the overhead of initializing the context from scratch.
   - **Input:**
     - The V8 isolate.
     - The `DOMWrapperWorld` (representing the main world or an isolated world within the page).
     - Optional extension configurations.
     - A global proxy object (if needed).
     - The `Document` object associated with the context.
   - **Output:** A `v8::Local<v8::Context>` representing the newly created context, or an empty handle if a snapshot cannot be used.

3. **Installing Context-Independent Properties (`InstallContextIndependentProps`)**:
   - After creating a context from a snapshot, certain properties that are independent of the specific context instance need to be installed. This function handles that.
   - It iterates through a table of `WrapperTypeInfo` (which describes the structure of Blink's JavaScript-exposed classes like `Window`, `Document`, etc.) and calls corresponding installation functions.
   - **Input:** A `ScriptState` object representing the current JavaScript execution environment.
   - **Output:**  Modifies the provided `ScriptState`'s context by adding context-independent properties.

4. **Ensuring Interface Templates (`InstallInterfaceTemplates`)**:
   - This function ensures that the V8 templates for various Blink interfaces (like `Window`, `Document`, `Node`) are properly registered within the V8 isolate. These templates define the structure and behavior of JavaScript objects that represent DOM elements and other browser concepts.
   - It loads these templates from the snapshot data.
   - **Input:** The V8 isolate.
   - **Output:** Registers the interface templates with the V8 isolate.

5. **Providing a Reference Table (`GetReferenceTable`)**:
   - This function returns a table of function pointers that are used during snapshot creation and deserialization. This helps in resolving addresses of functions needed to reconstruct the V8 context.
   - **Input:** None.
   - **Output:** A pointer to a static array of `intptr_t` representing the reference table.

**Relationship with JavaScript, HTML, and CSS:**

This file is **directly related to JavaScript** and **indirectly related to HTML and CSS**.

* **JavaScript:** The entire purpose of this file is to optimize the initialization of the JavaScript execution environment (the V8 context). The snapshot captures the initial state of JavaScript objects, prototypes, and the overall runtime. The code interacts heavily with V8 APIs.
    * **Example:** The `CreateContext` function uses `v8::Context::FromSnapshot` to directly load the JavaScript environment from a saved state. The `InstallContextIndependentProps` function sets up properties on JavaScript objects like `window`.

* **HTML:** The snapshot includes the initial state of objects that represent the HTML structure, such as the `HTMLDocument` object. When a new page is loaded (or a new frame is created), using a context snapshot can quickly provide the initial `document` object and its associated properties, making the page render faster.
    * **Example:** The code includes headers for `v8_html_document.h` and `html_document.h`, indicating it deals with the JavaScript representation of HTML documents within the snapshot. The `TakeSnapshotForWorld` function sets up the cached accessor for `window.document`.

* **CSS:** While this specific file doesn't directly manipulate CSS, the state captured in the snapshot *can* indirectly influence CSS. For example, the initial JavaScript environment might include objects or APIs that are used to interact with the CSSOM (CSS Object Model). Faster JavaScript context initialization can lead to faster CSS processing and rendering.
    * **Example:**  Consider JavaScript code that runs early on page load and manipulates CSS styles. If the JavaScript context initializes faster due to the snapshot, this CSS manipulation can happen sooner, leading to a faster visual rendering of the page.

**Logical Inference with Assumptions, Inputs, and Outputs:**

**Scenario: Taking a Snapshot**

* **Assumption:** The browser is in a special "snapshotting" mode during build or testing.
* **Input:** A V8 isolate representing the JavaScript environment in a known good state.
* **Output:** A serialized binary blob (the snapshot) representing the state of that V8 isolate.

**Scenario: Creating a Context from a Snapshot**

* **Assumption:** A valid snapshot exists for the current browser version and configuration.
* **Input:** The snapshot data, information about the desired DOM world (main or isolated), and the associated `Document` object.
* **Output:** A new V8 JavaScript context that is pre-initialized based on the snapshot, potentially saving significant initialization time.

**User or Programming Common Usage Errors:**

1. **Incorrect Snapshot Usage in Development:**  If a developer tries to manually load a snapshot that is incompatible with the current Blink version or V8 version, it can lead to crashes or unexpected behavior.
    * **Example:** Trying to use a snapshot generated from an older Chromium version with a newer version.

2. **Snapshot Corruption:** If the snapshot file on disk becomes corrupted, attempting to create a context from it will likely fail.

3. **Mismatched Snapshot Configuration:** If the browser is configured to use context snapshots, but the necessary snapshot files are missing or incorrectly located, the `CreateContext` function will fail to load from the snapshot.

4. **Accidental Modification of Snapshot Logic:** Developers unfamiliar with the snapshot mechanism might inadvertently modify this code, leading to broken snapshot creation or restoration.

**User Operations Leading to This Code (Debugging Clues):**

As a developer debugging issues related to JavaScript context initialization or performance, you might end up examining this code in the following scenarios:

1. **Page Load Performance Issues:** If page load times are slow, especially the initial JavaScript execution, developers might investigate if context snapshotting is working correctly. Setting breakpoints in `CreateContext` can reveal if a snapshot is being used and if it's failing.

2. **JavaScript Errors During Startup:** If JavaScript errors occur very early in the page load process, even before any user-defined scripts run, it might indicate a problem with the initial context setup. Debugging `CreateContext` and `InstallContextIndependentProps` could be helpful.

3. **Browser Build/Integration Issues:** Developers working on the Chromium browser itself or integrating V8 might need to debug the snapshot creation process (`TakeSnapshot`) if snapshots are not being generated correctly.

4. **Testing New JavaScript Features:** When adding new JavaScript features or modifying existing ones, developers might need to regenerate the context snapshot to ensure the new features are included in the initial context state. They might debug `TakeSnapshot` in this case.

**Step-by-Step User Operations (as a Debugging Clue):**

Let's imagine a user reports a slow initial page load for a specific website. Here's how a developer might reach this code as part of their debugging process:

1. **User Reports Slow Page Load:** The user notices a delay before the website becomes interactive.

2. **Developer Starts Profiling:** The developer uses browser developer tools (like the Performance tab in Chrome) to profile the page load.

3. **Identifying JavaScript Initialization as a Bottleneck:** The profiler reveals that a significant amount of time is spent during the initial JavaScript execution and context setup.

4. **Investigating Context Creation:** The developer suspects there might be an issue with how the JavaScript context is being created. They start looking at the Blink rendering engine source code related to V8 context creation.

5. **Finding `v8_context_snapshot_impl.cc`:**  Keywords like "context," "V8," and "snapshot" lead them to this file.

6. **Setting Breakpoints:** The developer sets breakpoints in `CreateContext` to see if a snapshot is being used.

7. **Observing `CreateContext` Behavior:**
   - **Scenario A (Snapshot is Used):** The breakpoint in `CreateContext` is hit, and the code flow goes through the `v8::Context::FromSnapshot` path. The developer might then investigate if the snapshot loading is taking an unusually long time or if there are errors during deserialization.
   - **Scenario B (Snapshot is NOT Used):** The breakpoint is hit, but the conditions for using a snapshot are not met (e.g., `IsUsingContextSnapshot()` returns `false`). This indicates a potential configuration issue or that snapshots are not enabled for this specific scenario.

8. **Further Investigation:** Based on the behavior of `CreateContext`, the developer might then investigate:
   - If snapshots are enabled in the build configuration.
   - If the snapshot files are present and valid.
   - The logic within `TakeSnapshot` to ensure snapshots are being generated correctly in the first place.
   - The functions `InstallContextIndependentProps` and `InstallInterfaceTemplates` to see if there are issues with setting up the initial context state after loading from a snapshot.

In summary, `v8_context_snapshot_impl.cc` is a crucial component for optimizing JavaScript context creation in Blink, directly impacting page load performance. Developers would investigate this code when troubleshooting performance bottlenecks or errors related to the initial JavaScript environment setup.

Prompt: 
```
这是目录为blink/renderer/bindings/modules/v8/v8_context_snapshot_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/modules/v8/v8_context_snapshot_impl.h"

#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_context_snapshot.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_event_target.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_document.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_initializer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_node.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_window_properties.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_document.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_window.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/platform/bindings/dom_data_store.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/v8_object_constructor.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_context_data.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/bindings/v8_private_property.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "tools/v8_context_snapshot/buildflags.h"

#if defined(V8_USE_EXTERNAL_STARTUP_DATA)
#include "gin/public/v8_snapshot_file_type.h"
#endif

namespace blink {
namespace {

bool IsUsingContextSnapshot() {
#if BUILDFLAG(USE_V8_CONTEXT_SNAPSHOT)
  if (Platform::Current()->IsTakingV8ContextSnapshot() ||
      gin::GetLoadedSnapshotFileType() ==
          gin::V8SnapshotFileType::kWithAdditionalContext) {
    return true;
  }
#endif  // BUILDFLAG(USE_V8_CONTEXT_SNAPSHOT)
  return false;
}

}  // namespace

void V8ContextSnapshotImpl::Init() {
  V8ContextSnapshot::SetCreateContextFromSnapshotFunc(CreateContext);
  V8ContextSnapshot::SetInstallContextIndependentPropsFunc(
      InstallContextIndependentProps);
  V8ContextSnapshot::SetEnsureInterfaceTemplatesFunc(InstallInterfaceTemplates);
  V8ContextSnapshot::SetTakeSnapshotFunc(TakeSnapshot);
  V8ContextSnapshot::SetGetReferenceTableFunc(GetReferenceTable);
}

namespace {

// Layout of the snapshot
//
// Context:
//   [ main world context, isolated world context ]
// Data:
//   [ main world: [ Window template, HTMLDocument template, ... ],
//     isolated world: [ Window template, HTMLDocument template, ... ],
//   ]
//
// The main world's snapshot contains the window object (as the global object)
// and the main document of type HTMLDocument (although the main document is
// not necessarily an HTMLDocument).  The isolated world's snapshot contains
// the window object only.

constexpr const size_t kNumOfWorlds = 2;

inline DOMWrapperWorld* IndexToWorld(v8::Isolate* isolate, size_t index) {
  return index == 0 ? &DOMWrapperWorld::MainWorld(isolate)
                    : DOMWrapperWorld::EnsureIsolatedWorld(
                          isolate, DOMWrapperWorld::WorldId::kMainWorldId + 1);
}

inline int WorldToIndex(const DOMWrapperWorld& world) {
  if (world.IsMainWorld()) {
    return 0;
  } else if (world.IsIsolatedWorld()) {
    return 1;
  } else {
    LOG(FATAL) << "Unknown DOMWrapperWorld";
  }
}

using InstallPropsPerContext =
    void (*)(v8::Local<v8::Context> context,
             const DOMWrapperWorld& world,
             v8::Local<v8::Object> instance_object,
             v8::Local<v8::Object> prototype_object,
             v8::Local<v8::Object> interface_object,
             v8::Local<v8::Template> interface_template);
using InstallPropsPerIsolate =
    void (*)(v8::Isolate* isolate,
             const DOMWrapperWorld& world,
             v8::Local<v8::Template> instance_template,
             v8::Local<v8::Template> prototype_template,
             v8::Local<v8::Template> interface_template);

// Construction of |type_info_table| requires non-trivial initialization due
// to cross-component address resolution.  We ignore this issue because the
// issue happens only on component builds and the official release builds
// (statically-linked builds) are never affected by this issue.
#if defined(COMPONENT_BUILD) && defined(WIN32) && defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wglobal-constructors"
#endif

const struct {
  const WrapperTypeInfo* wrapper_type_info;
  // Installs context-independent properties to per-isolate templates.
  InstallPropsPerIsolate install_props_per_isolate;
  // Installs context-independent properties to objects in the context.
  InstallPropsPerContext install_props_per_context;
  bool needs_per_context_install[kNumOfWorlds];
} type_info_table[] = {
    {V8Window::GetWrapperTypeInfo(),
     bindings::v8_context_snapshot::InstallPropsOfV8Window,
     bindings::v8_context_snapshot::InstallPropsOfV8Window,
     {true, true}},
    {V8WindowProperties::GetWrapperTypeInfo(),
     bindings::v8_context_snapshot::InstallPropsOfV8WindowProperties,
     bindings::v8_context_snapshot::InstallPropsOfV8WindowProperties,
     {true, true}},
    {V8HTMLDocument::GetWrapperTypeInfo(),
     bindings::v8_context_snapshot::InstallPropsOfV8HTMLDocument,
     bindings::v8_context_snapshot::InstallPropsOfV8HTMLDocument,
     {true, false}},
    {V8Document::GetWrapperTypeInfo(),
     bindings::v8_context_snapshot::InstallPropsOfV8Document,
     bindings::v8_context_snapshot::InstallPropsOfV8Document,
     {true, false}},
    {V8Node::GetWrapperTypeInfo(),
     bindings::v8_context_snapshot::InstallPropsOfV8Node,
     bindings::v8_context_snapshot::InstallPropsOfV8Node,
     {true, false}},
    {V8EventTarget::GetWrapperTypeInfo(),
     bindings::v8_context_snapshot::InstallPropsOfV8EventTarget,
     bindings::v8_context_snapshot::InstallPropsOfV8EventTarget,
     {true, true}},
};

#if defined(COMPONENT_BUILD) && defined(WIN32) && defined(__clang__)
#pragma clang diagnostic pop
#endif

enum class InternalFieldSerializedValue : uint8_t {
  kSwHTMLDocument = 1,
};

struct DeserializerData {
  STACK_ALLOCATED();

 public:
  v8::Isolate* isolate;
  const DOMWrapperWorld& world;
  HTMLDocument* html_document;
};

v8::Local<v8::Function> CreateInterfaceObject(
    v8::Isolate* isolate,
    v8::Local<v8::Context> context,
    const DOMWrapperWorld& world,
    const WrapperTypeInfo* wrapper_type_info) {
  v8::Local<v8::Function> parent_interface_object;
  if (wrapper_type_info->parent_class) {
    parent_interface_object = CreateInterfaceObject(
        isolate, context, world, wrapper_type_info->parent_class);
  }
  return V8ObjectConstructor::CreateInterfaceObject(
      wrapper_type_info, context, world, isolate, parent_interface_object,
      V8ObjectConstructor::CreationMode::kDoNotInstallConditionalFeatures);
}

v8::Local<v8::Object> CreatePlatformObject(
    v8::Isolate* isolate,
    v8::Local<v8::Context> context,
    const DOMWrapperWorld& world,
    const WrapperTypeInfo* wrapper_type_info) {
  v8::Local<v8::Function> interface_object =
      CreateInterfaceObject(isolate, context, world, wrapper_type_info);
  v8::Context::Scope context_scope(context);
  return V8ObjectConstructor::NewInstance(isolate, interface_object)
      .ToLocalChecked();
}

v8::StartupData SerializeInternalFieldCallback(v8::Local<v8::Object> object,
                                               int index,
                                               void* unused_data) {
  NOTREACHED();
}

void DeserializeInternalFieldCallback(v8::Local<v8::Object> object,
                                      int index,
                                      v8::StartupData payload,
                                      void* data) {
  NOTREACHED();
}

v8::StartupData SerializeAPIWrapperCallback(v8::Local<v8::Object> holder,
                                            void* cpp_heap_pointer,
                                            void* unused_data) {
  auto* wrappable = static_cast<ScriptWrappable*>(cpp_heap_pointer);
  if (!wrappable) {
    return {nullptr, 0};
  }
  const WrapperTypeInfo* wrapper_type_info = wrappable->GetWrapperTypeInfo();
  CHECK_EQ(wrappable, ToAnyScriptWrappable(holder->GetIsolate(), holder));
  constexpr size_t kSize = 1;
  static_assert(sizeof (InternalFieldSerializedValue) == kSize);
  auto* serialized_value = new InternalFieldSerializedValue();
  if (wrapper_type_info == V8HTMLDocument::GetWrapperTypeInfo()) {
    *serialized_value = InternalFieldSerializedValue::kSwHTMLDocument;
  } else {
    LOG(FATAL) << "Unknown WrapperTypeInfo";
  }
  return {reinterpret_cast<char*>(serialized_value), kSize};
}

void DeserializeAPIWrapperCallback(v8::Local<v8::Object> holder,
                                   v8::StartupData payload,
                                   void* data) {
  CHECK_EQ(payload.raw_size, 1);  // No endian support
  CHECK_EQ(*reinterpret_cast<const InternalFieldSerializedValue*>(payload.data),
           InternalFieldSerializedValue::kSwHTMLDocument);

  DeserializerData* deserializer_data =
      reinterpret_cast<DeserializerData*>(data);
  CHECK(deserializer_data->html_document);
  CHECK(deserializer_data->world.IsMainWorld());
  V8DOMWrapper::SetNativeInfo(deserializer_data->isolate, holder,
                              deserializer_data->html_document);
  const bool result =
      DOMDataStore::SetWrapperInInlineStorage</*entered_context=*/false>(
          deserializer_data->isolate, deserializer_data->html_document,
          V8HTMLDocument::GetWrapperTypeInfo(), holder);
  CHECK(result);
}

// We only care for WrapperTypeInfo and do not supply an actual instance of
// the document. Since we need a script wrappable to get type info now, this
// class is a minimal implementation of ScriptWrappable that returns correct
// type info for HTMLDocument.
class DummyHTMLDocumentForSnapshot : public ScriptWrappable {
 public:
  DummyHTMLDocumentForSnapshot() = default;

 private:
  const WrapperTypeInfo* GetWrapperTypeInfo() const override {
    return V8HTMLDocument::GetWrapperTypeInfo();
  }
};

void TakeSnapshotForWorld(v8::SnapshotCreator* snapshot_creator,
                          const DOMWrapperWorld& world) {
  v8::Isolate* isolate = snapshot_creator->GetIsolate();
  V8PerIsolateData* per_isolate_data = V8PerIsolateData::From(isolate);

  // Set up the context and global object.
  v8::Local<v8::FunctionTemplate> window_interface_template =
      V8Window::GetWrapperTypeInfo()
          ->GetV8ClassTemplate(isolate, world)
          .As<v8::FunctionTemplate>();
  v8::Local<v8::ObjectTemplate> window_instance_template =
      window_interface_template->InstanceTemplate();
  v8::Local<v8::Context> context;
  {
    V8PerIsolateData::UseCounterDisabledScope use_counter_disabled_scope(
        per_isolate_data);
    context = v8::Context::New(isolate, nullptr, window_instance_template);
    CHECK(!context.IsEmpty());
  }

  // Set up the cached accessor of 'window.document'.
  if (world.IsMainWorld()) {
    v8::Context::Scope context_scope(context);

    const WrapperTypeInfo* document_wrapper_type_info =
        V8HTMLDocument::GetWrapperTypeInfo();
    v8::Local<v8::Object> document_wrapper = CreatePlatformObject(
        isolate, context, world, document_wrapper_type_info);

    V8DOMWrapper::SetNativeInfo(
        isolate, document_wrapper,
        MakeGarbageCollected<DummyHTMLDocumentForSnapshot>());

    V8PrivateProperty::GetWindowDocumentCachedAccessor(isolate).Set(
        context->Global(), document_wrapper);
  }

  snapshot_creator->AddContext(
      context, SerializeInternalFieldCallback,
      v8::SerializeContextDataCallback(),
      v8::SerializeAPIWrapperCallback(SerializeAPIWrapperCallback));
  for (const auto& type_info : type_info_table) {
    snapshot_creator->AddData(
        type_info.wrapper_type_info->GetV8ClassTemplate(isolate, world));
  }
}

}  // namespace

v8::Local<v8::Context> V8ContextSnapshotImpl::CreateContext(
    v8::Isolate* isolate,
    const DOMWrapperWorld& world,
    v8::ExtensionConfiguration* extension_config,
    v8::Local<v8::Object> global_proxy,
    Document* document) {
  DCHECK(document);
  if (!IsUsingContextSnapshot())
    return v8::Local<v8::Context>();

  V8PerIsolateData* per_isolate_data = V8PerIsolateData::From(isolate);
  if (per_isolate_data->GetV8ContextSnapshotMode() !=
      V8PerIsolateData::V8ContextSnapshotMode::kUseSnapshot) {
    return v8::Local<v8::Context>();
  }

  HTMLDocument* html_document = DynamicTo<HTMLDocument>(document);
  CHECK(!html_document || html_document->GetWrapperTypeInfo() ==
                              V8HTMLDocument::GetWrapperTypeInfo());
  if (world.IsMainWorld()) {
    if (!html_document)
      return v8::Local<v8::Context>();
  } else {
    // Prevent an accidental misuse in a non-main world.
    html_document = nullptr;
  }

  DeserializerData deserializer_data = {isolate, world, html_document};
  v8::DeserializeInternalFieldsCallback internal_field_desrializer(
      DeserializeInternalFieldCallback, &deserializer_data);
  v8::DeserializeAPIWrapperCallback api_wrappers_deserializer(
      DeserializeAPIWrapperCallback, &deserializer_data);
  return v8::Context::FromSnapshot(
             isolate, WorldToIndex(world), internal_field_desrializer,
             extension_config, global_proxy,
             document->GetExecutionContext()->GetMicrotaskQueue(),
             v8::DeserializeContextDataCallback(), api_wrappers_deserializer)
      .ToLocalChecked();
}

void V8ContextSnapshotImpl::InstallContextIndependentProps(
    ScriptState* script_state) {
  if (!IsUsingContextSnapshot())
    return;

  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> context = script_state->GetContext();
  const DOMWrapperWorld& world = script_state->World();
  const int world_index = WorldToIndex(world);
  V8PerContextData* per_context_data = script_state->PerContextData();
  v8::Local<v8::String> prototype_string = V8AtomicString(isolate, "prototype");

  for (const auto& type_info : type_info_table) {
    if (!type_info.needs_per_context_install[world_index])
      continue;

    const auto* wrapper_type_info = type_info.wrapper_type_info;
    v8::Local<v8::Template> interface_template =
        wrapper_type_info->GetV8ClassTemplate(isolate, world);
    v8::Local<v8::Function> interface_object =
        per_context_data->ConstructorForType(wrapper_type_info);
    v8::Local<v8::Object> prototype_object =
        interface_object->Get(context, prototype_string)
            .ToLocalChecked()
            .As<v8::Object>();
    v8::Local<v8::Object> instance_object;
    type_info.install_props_per_context(context, world, instance_object,
                                        prototype_object, interface_object,
                                        interface_template);
  }
}

void V8ContextSnapshotImpl::InstallInterfaceTemplates(v8::Isolate* isolate) {
  if (!IsUsingContextSnapshot())
    return;

  V8PerIsolateData* per_isolate_data = V8PerIsolateData::From(isolate);
  if (per_isolate_data->GetV8ContextSnapshotMode() !=
      V8PerIsolateData::V8ContextSnapshotMode::kUseSnapshot) {
    return;
  }

  v8::HandleScope handle_scope(isolate);

  for (size_t world_index = 0; world_index < kNumOfWorlds; ++world_index) {
    DOMWrapperWorld* world = IndexToWorld(isolate, world_index);
    for (size_t i = 0; i < std::size(type_info_table); ++i) {
      const auto& type_info = type_info_table[i];
      v8::Local<v8::FunctionTemplate> interface_template =
          isolate
              ->GetDataFromSnapshotOnce<v8::FunctionTemplate>(
                  world_index * std::size(type_info_table) + i)
              .ToLocalChecked();
      per_isolate_data->AddV8Template(*world, type_info.wrapper_type_info,
                                      interface_template);
      type_info.install_props_per_isolate(
          isolate, *world, interface_template->InstanceTemplate(),
          interface_template->PrototypeTemplate(), interface_template);
    }
  }
}

v8::StartupData V8ContextSnapshotImpl::TakeSnapshot(v8::Isolate* isolate) {
  CHECK(isolate);
  CHECK(isolate->IsCurrent());
  V8PerIsolateData* per_isolate_data = V8PerIsolateData::From(isolate);
  CHECK_EQ(per_isolate_data->GetV8ContextSnapshotMode(),
           V8PerIsolateData::V8ContextSnapshotMode::kTakeSnapshot);
  DCHECK(IsUsingContextSnapshot());

  // Take a snapshot with minimum set-up.  It's easier to add properties than
  // removing ones, so make it no need to remove any property.
  RuntimeEnabledFeatures::SetStableFeaturesEnabled(false);
  RuntimeEnabledFeatures::SetExperimentalFeaturesEnabled(false);
  RuntimeEnabledFeatures::SetTestFeaturesEnabled(false);

  v8::SnapshotCreator* snapshot_creator =
      per_isolate_data->GetSnapshotCreator();

  {
    v8::HandleScope handle_scope(isolate);
    snapshot_creator->SetDefaultContext(v8::Context::New(isolate));
    for (size_t i = 0; i < kNumOfWorlds; ++i) {
      DOMWrapperWorld* world = IndexToWorld(isolate, i);
      TakeSnapshotForWorld(snapshot_creator, *world);
    }
  }

  // Remove v8::Eternal in V8PerIsolateData before creating the blob.
  per_isolate_data->ClearPersistentsForV8ContextSnapshot();
  // V8Initializer::MessageHandlerInMainThread will be installed regardless of
  // the V8 context snapshot.
  isolate->RemoveMessageListeners(V8Initializer::MessageHandlerInMainThread);

  return snapshot_creator->CreateBlob(
      v8::SnapshotCreator::FunctionCodeHandling::kClear);
}

const intptr_t* V8ContextSnapshotImpl::GetReferenceTable() {
  DCHECK(IsMainThread());

  if (!IsUsingContextSnapshot())
    return nullptr;

  DEFINE_STATIC_LOCAL(const intptr_t*, reference_table, (nullptr));
  if (reference_table)
    return reference_table;

  intptr_t last_table[] = {
      reinterpret_cast<intptr_t>(V8ObjectConstructor::IsValidConstructorMode),
      0,  // nullptr termination
  };
  base::span<const intptr_t> tables[] = {
      bindings::v8_context_snapshot::GetRefTableOfV8Document(),
      bindings::v8_context_snapshot::GetRefTableOfV8EventTarget(),
      bindings::v8_context_snapshot::GetRefTableOfV8HTMLDocument(),
      bindings::v8_context_snapshot::GetRefTableOfV8Node(),
      bindings::v8_context_snapshot::GetRefTableOfV8Window(),
      bindings::v8_context_snapshot::GetRefTableOfV8WindowProperties(),
      last_table,
  };
  DCHECK_EQ(std::size(tables), std::size(type_info_table) + 1);

  size_t size_bytes = 0;
  for (const auto& table : tables)
    size_bytes += table.size_bytes();
  intptr_t* unified_table =
      static_cast<intptr_t*>(::WTF::Partitions::FastMalloc(
          size_bytes, "V8ContextSnapshotImpl::GetReferenceTable"));
  size_t offset_count = 0;
  for (const auto& table : tables) {
    std::memcpy(unified_table + offset_count, table.data(), table.size_bytes());
    offset_count += table.size();
  }
  reference_table = unified_table;

  return reference_table;
}

}  // namespace blink

"""

```