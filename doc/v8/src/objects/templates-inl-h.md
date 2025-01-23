Response:
Let's break down the thought process for analyzing this V8 header file.

1. **Identify the Core Purpose:** The file name `templates-inl.h` and the inclusion of `templates.h` strongly suggest this file deals with templates within V8's object system. The `.inl` extension signifies inline implementations, implying optimizations for performance.

2. **Scan for Key Data Structures:** Look for defined classes or structs. The code clearly defines `TemplateInfo`, `FunctionTemplateInfo`, `ObjectTemplateInfo`, `FunctionTemplateRareData`, and `DictionaryTemplateInfo`. These are likely the central data structures manipulated by this code.

3. **Examine Constructor Implementations:** The `TQ_OBJECT_CONSTRUCTORS_IMPL` macros for the listed classes indicate how instances of these template information objects are created. The "TQ" prefix hints at Torque's involvement (as also suggested by the included `templates-tq-inl.inc`).

4. **Analyze Member Functions and Macros:**  Go through the defined functions and macros for each class.
    * **`NEVER_READ_ONLY_SPACE_IMPL`:** This suggests that `DictionaryTemplateInfo` and `ObjectTemplateInfo` are never placed in read-only memory. This is a low-level memory management detail.
    * **`BOOL_ACCESSORS`:** This macro generates getter and setter methods for boolean flags within `FunctionTemplateInfo`. The bit shift parameters (`IsObjectTemplateCallHandlerBit::kShift`, etc.) indicate these are bitfield flags, likely for efficient storage of multiple boolean properties. The "relaxed_flag" parameter appearing repeatedly suggests a shared storage location for these flags.
    * **`BIT_FIELD_ACCESSORS`:** Similar to `BOOL_ACCESSORS`, but for non-boolean bitfields, storing integer values within a limited number of bits.
    * **`RELAXED_UINT32_ACCESSORS`:**  Provides accessors for a `uint32_t` field named `flag`. The "relaxed" prefix likely implies a less strict memory ordering or atomicity guarantee, hinting at performance considerations.
    * **Explicit `get_relaxed_flag` and `set_relaxed_flag`:** These functions provide an interface to access the combined `relaxed_flag` bitfield, likely used internally for managing these boolean flags.
    * **`callback` related functions:** These functions manage a callback address, possibly for handling function calls related to the template. The `maybe_redirected_callback` and the simulator-specific logic suggest a mechanism for redirecting or wrapping the actual callback.
    * **`EnsureFunctionTemplateRareData`:**  This function lazily allocates and retrieves `FunctionTemplateRareData`, suggesting it contains less frequently accessed information.
    * **`RARE_ACCESSORS`:** Another macro for generating accessors, this time for fields within the `FunctionTemplateRareData`. The names of these fields (`prototype_template`, `parent_template`, etc.) reveal relationships between different templates.
    * **`GetInstanceType` and `SetInstanceType`:** These functions manage an instance type associated with the template, crucial for object creation and type checking. The comment about translating between embedder and internal API types is important.
    * **`SetAllowedReceiverInstanceTypeRange`:** This function sets constraints on the types of objects that can be used as the `this` value when calling functions created from the template.
    * **`should_cache`, `is_cached`:** These functions relate to caching template instantiations for performance.
    * **`instantiated`:** Checks if a `SharedFunctionInfo` has been created from the template.
    * **`BreakAtEntry`:**  Related to debugging and setting breakpoints.
    * **`GetParent` (both for `FunctionTemplateInfo` and `ObjectTemplateInfo`):** These functions navigate the inheritance hierarchy of templates.
    * **`embedder_field_count`, `set_embedder_field_count`, `immutable_proto`, `set_immutable_proto`, `code_like`, `set_code_like`:** These functions manage properties specific to `ObjectTemplateInfo`.
    * **`IsTemplateFor`:** Checks if a given JavaScript object or its map was created using this template.
    * **`TryGetIsolate`, `GetIsolateChecked`:** Functions to retrieve the V8 isolate associated with the template.
    * **`ProbeInstantiationsCache`, `CacheTemplateInstantiation`, `UncacheTemplateInstantiation`:** These functions implement the caching mechanism for template instantiations.

5. **Identify Connections to JavaScript:** The names of the template classes (`FunctionTemplateInfo`, `ObjectTemplateInfo`) and the concepts they represent (prototypes, instances, callbacks, property handlers) directly correspond to JavaScript concepts used in creating custom object types and interacting with the V8 engine's internals via the V8 API.

6. **Determine Torque Involvement:** The inclusion of `torque-generated/src/objects/templates-tq-inl.inc` and the `TQ_OBJECT_CONSTRUCTORS_IMPL` macro confirm that this code is generated or influenced by Torque, V8's type-safe TypeScript-like language for writing low-level V8 code. The `.tq` file extension mentioned in the prompt reinforces this.

7. **Infer Functionality Based on Structure and Names:** Connect the observed structures and functions to their likely roles in the V8 engine. For instance, the `callback` functions are probably used when a function created from a `FunctionTemplate` is called. The caching mechanisms are clearly for optimizing the creation of objects from templates.

8. **Formulate Examples:**  Based on the identified functionalities and the connection to JavaScript, construct illustrative JavaScript examples demonstrating how these templates are used in practice. Focus on the V8 API functions like `FunctionTemplate`, `ObjectTemplate`, `SetCallHandler`, `SetAccessor`, etc.

9. **Consider Potential Errors:** Think about common mistakes developers might make when working with the V8 API related to templates. Incorrectly setting accessors, not understanding the prototype chain, and issues with callback functions are good candidates.

10. **Address Code Logic and Assumptions (if applicable):** For more complex logic (like the caching), try to trace the flow with hypothetical inputs. In this case, the caching logic is relatively straightforward: check the cache, add to the cache, remove from the cache. The assumptions are related to the size limits of the caches.

11. **Structure the Answer:** Organize the findings into logical sections (file description, Torque, JavaScript relationship, code logic, common errors) for clarity and readability.

By following this methodical approach, you can effectively analyze even complex source code files and understand their purpose and functionality within a larger system like the V8 JavaScript engine.
This header file, `v8/src/objects/templates-inl.h`, provides inline implementations for methods of template-related classes in the V8 JavaScript engine. These classes are crucial for the V8 API, which allows embedding applications (like web browsers or Node.js) to create and manipulate JavaScript objects and functions from their native code.

Here's a breakdown of its functionalities:

**1. Inline Implementations for Template Classes:**

* The file provides inline implementations (hence the `.inl` suffix) for methods declared in the corresponding header file `v8/src/objects/templates.h`. This improves performance by reducing function call overhead for frequently used methods.
* It defines inline methods for classes like `TemplateInfo`, `FunctionTemplateInfo`, `ObjectTemplateInfo`, `FunctionTemplateRareData`, and `DictionaryTemplateInfo`. These classes represent templates used to construct JavaScript objects and functions.

**2. Torque-Generated Code Inclusion:**

* The line `#include "torque-generated/src/objects/templates-tq-inl.inc"` indicates that some parts of the implementation, specifically related to these template classes, are generated by Torque.
* **Yes, if `v8/src/objects/templates-inl.h` ended with `.tq`, it would be a V8 Torque source code file.** Torque is V8's internal language for writing performance-critical parts of the engine in a type-safe manner. However, `.inl.h` suggests this file *includes* Torque-generated code, rather than being a pure Torque file itself.

**3. Management of Template Properties and Flags:**

* **Accessors for Boolean Flags:** Macros like `BOOL_ACCESSORS` generate inline getter and setter methods for various boolean flags within the `FunctionTemplateInfo` class. These flags control aspects like:
    * `is_object_template_call_handler`: Whether the function template is used as a call handler for an object template.
    * `has_side_effects`: Whether functions created from the template have side effects.
    * `undetectable`: Whether objects created from the template are undetectable by certain JavaScript mechanisms.
    * `needs_access_check`: Whether access to properties of objects created from the template requires access checks.
    * And other similar properties related to the behavior of functions and objects created from the template.
* **Accessors for Bit Fields:** The `BIT_FIELD_ACCESSORS` macro does the same for bit fields, allowing storage of integer values within specific bit ranges. This is used for properties like `allowed_receiver_instance_type_range_start` and `allowed_receiver_instance_type_range_end`, which specify the allowed receiver types for functions created from the template.
* **Relaxed Accessors:** The `RELAXED_UINT32_ACCESSORS` and the explicit `relaxed_flag` accessors likely deal with flags that might be accessed concurrently, and "relaxed" might refer to memory ordering guarantees.

**4. Callback Management:**

* The code provides methods for managing a callback function associated with a `FunctionTemplateInfo`. This callback is invoked when a function created from the template is called.
* The `callback`, `init_callback`, `set_callback`, `init_callback_redirection`, and `remove_callback_redirection` methods handle setting and managing this callback address, potentially with simulator-specific logic for redirection.

**5. Rare Data Handling:**

* The `EnsureFunctionTemplateRareData` function and the `RARE_ACCESSORS` macro suggest a mechanism for storing less frequently accessed data associated with a `FunctionTemplateInfo` in a separate object (`FunctionTemplateRareData`). This optimizes memory usage by only allocating this data when needed.
* The rare data includes things like `prototype_template`, `parent_template`, property handlers (`named_property_handler`, `indexed_property_handler`), and more.

**6. Instance Type Management:**

* The `GetInstanceType` and `SetInstanceType` methods manage the instance type associated with a `FunctionTemplateInfo`. This is important for defining the type of JavaScript objects created from the template.
* The `SetAllowedReceiverInstanceTypeRange` method allows specifying a range of allowed instance types for the receiver (`this`) of functions created from the template.

**7. Template Caching:**

* The code includes logic for caching template instantiations to improve performance. The `should_cache`, `is_cached`, `ProbeInstantiationsCache`, `CacheTemplateInstantiation`, and `UncacheTemplateInstantiation` methods manage this caching mechanism.
* It uses both a fast, fixed-size cache and a slower, dynamically sized dictionary for caching.

**8. Relationship with JavaScript and Examples:**

Yes, this file is directly related to how the V8 engine allows embedding applications to interact with JavaScript. The `FunctionTemplate` and `ObjectTemplate` objects in the V8 API, used in C++ to define JavaScript functions and objects, are backed by the data structures managed by this code.

**JavaScript Example:**

```javascript
// (This is conceptual, as you don't directly interact with these internal structures in JS)

// Imagine the following C++ code using the V8 API:
/* C++ Code:
v8::Local<v8::FunctionTemplate> myFuncTemplate = v8::FunctionTemplate::New(isolate, MyCallback);
v8::Local<v8::ObjectTemplate> myObjectTemplate = v8::ObjectTemplate::New(isolate);
myObjectTemplate->SetAccessor(v8::String::NewFromUtf8(isolate, "myProperty").ToLocalChecked(), MyGetter);
*/

// Internally, V8 would be creating and manipulating objects like FunctionTemplateInfo and ObjectTemplateInfo.
// For example, setting the callback would involve setting the 'callback' address in the FunctionTemplateInfo.
// Setting the accessor would involve creating an InterceptorInfo and associating it with the ObjectTemplateInfo.

// When you create a JavaScript function or object from these templates:
/* JavaScript Code:
function MyConstructor() {
  this.myProperty = 10;
}
const myObject = new MyConstructor();
console.log(myObject.myProperty); // Accessing the property would trigger the getter.
*/

// V8 would use the information stored in the TemplateInfo structures to:
// 1. Call the appropriate JavaScript constructor or create the object based on the template.
// 2. Invoke the 'MyCallback' function when a function created from 'myFuncTemplate' is called.
// 3. Execute the 'MyGetter' when 'myObject.myProperty' is accessed.
```

**9. Code Logic Inference (Example with Caching):**

**Assumption:**  A `FunctionTemplateInfo` with a specific `serial_number` represents a template that has been used to create JavaScript functions or objects before.

**Input:**
* `isolate`: The current V8 isolate.
* `native_context`: The native context in which the template is being used.
* `serial_number`: The serial number of the `FunctionTemplateInfo`.
* `caching_mode`:  The current caching mode.

**Scenario:**  Calling `TemplateInfo::ProbeInstantiationsCache` to check if an instantiation (like a `SharedFunctionInfo`) of the template is already cached.

**Logic:**
1. **Check for "Do Not Cache":** If `serial_number` is `kDoNotCache`, the template should not be cached, so return nothing.
2. **Check for "Uncached":** If `serial_number` is `kUncached`, it means the template hasn't been cached yet, so return nothing.
3. **Check Fast Cache:** If `serial_number` is within the bounds of the fast cache (`kFastTemplateInstantiationsCacheSize`), look up the instantiation in the `fast_template_instantiations_cache` of the `native_context`. If found (not `TheHole`), return it.
4. **Check Slow Cache (if applicable):** If the fast cache check fails and `caching_mode` allows, or the `serial_number` is within the bounds of the slow cache (`kSlowTemplateInstantiationsCacheSize`), look up the instantiation in the `slow_template_instantiations_cache`. If found, return it.
5. **Cache Miss:** If none of the above conditions are met, return nothing, indicating a cache miss.

**Output:**
* A `MaybeHandle<ReturnType>` containing the cached instantiation if found, otherwise an empty `MaybeHandle`.

**10. User-Common Programming Errors (Related to V8 API usage which is backed by these structures):**

* **Incorrectly Setting Accessors/Interceptors:**
    ```c++
    // C++ Code (Example of error)
    v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
    // Forgetting to set a setter for an accessor:
    templ->SetAccessor(String::NewFromUtf8(isolate, "myProp").ToLocalChecked(), MyGetter);

    // JavaScript Code:
    const obj = templ->NewInstance(context).ToLocalChecked();
    obj->Set(context, String::NewFromUtf8(isolate, "myProp").ToLocalChecked(), v8::Number::New(isolate, 42)); // Error!

    // Explanation: If you only define a getter for an accessor, attempts to set the property in JavaScript will either fail silently or throw an error depending on the specific configuration.
    ```

* **Misunderstanding Prototype Chains:**
    ```c++
    // C++ Code
    v8::Local<v8::FunctionTemplate> parentTemplate = v8::FunctionTemplate::New(isolate);
    v8::Local<v8::ObjectTemplate> parentPrototype = parentTemplate->PrototypeTemplate();
    parentPrototype->Set(String::NewFromUtf8(isolate, "parentMethod").ToLocalChecked(), FunctionTemplate::New(isolate, ParentMethod));

    v8::Local<v8::FunctionTemplate> childTemplate = v8::FunctionTemplate::New(isolate);
    childTemplate->SetParent(parentTemplate); // Establishing inheritance

    // JavaScript Code
    function Child() {}
    const child = new Child();
    child.parentMethod(); // Works because of the prototype chain.

    // Error Example: Not setting properties on the prototype if you intend for them to be shared.
    v8::Local<v8::FunctionTemplate> flawedTemplate = v8::FunctionTemplate::New(isolate);
    flawedTemplate->InstanceTemplate()->Set(String::NewFromUtf8(isolate, "instanceProp").ToLocalChecked(), v8::Number::New(isolate, 10)); // Wrong place!

    // JavaScript Code
    function Flawed() { }
    const f1 = new Flawed();
    const f2 = new Flawed();
    f1.instanceProp = 20; // This creates a *local* property on f1, not shared.
    console.log(f2.instanceProp); // Still 10.

    // Explanation: Instance properties should usually be set within the constructor or on the prototype if they are meant to be shared. Setting them directly on the instance template leads to unexpected behavior.
    ```

* **Incorrectly Handling Callbacks:**
    ```c++
    // C++ Code
    v8::Local<v8::FunctionTemplate> funcTemplate = v8::FunctionTemplate::New(isolate, MyCallback);

    // Callback signature mismatch (MyCallback should accept const v8::FunctionCallbackInfo<v8::Value>& args)
    void MyCallback(const v8::FunctionCallbackInfo<>& args) {
        // ... potential issues accessing arguments ...
    }

    // JavaScript Code
    const func = funcTemplate->GetFunction(context).ToLocalChecked();
    func->Call(context, context->Global(), {}); // Calling the function

    // Explanation:  Incorrectly defining the callback function signature can lead to crashes or unexpected behavior when the JavaScript function is called. The arguments passed from JavaScript need to be correctly accessed using the `v8::FunctionCallbackInfo`.
    ```

In summary, `v8/src/objects/templates-inl.h` is a core part of V8's internal implementation, providing the foundation for how JavaScript objects and functions are created and managed when embedding applications use the V8 API. It leverages inline implementations and Torque-generated code for performance and type safety. Understanding its functionalities is crucial for anyone working on V8 internals or developing complex embedding applications.

### 提示词
```
这是目录为v8/src/objects/templates-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/templates-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_TEMPLATES_INL_H_
#define V8_OBJECTS_TEMPLATES_INL_H_

#include "src/heap/heap-write-barrier-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/templates.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

#include "torque-generated/src/objects/templates-tq-inl.inc"

TQ_OBJECT_CONSTRUCTORS_IMPL(TemplateInfo)
TQ_OBJECT_CONSTRUCTORS_IMPL(FunctionTemplateInfo)
TQ_OBJECT_CONSTRUCTORS_IMPL(ObjectTemplateInfo)
TQ_OBJECT_CONSTRUCTORS_IMPL(FunctionTemplateRareData)
TQ_OBJECT_CONSTRUCTORS_IMPL(DictionaryTemplateInfo)

NEVER_READ_ONLY_SPACE_IMPL(DictionaryTemplateInfo)
NEVER_READ_ONLY_SPACE_IMPL(ObjectTemplateInfo)

BOOL_ACCESSORS(FunctionTemplateInfo, relaxed_flag,
               is_object_template_call_handler,
               IsObjectTemplateCallHandlerBit::kShift)
BOOL_ACCESSORS(FunctionTemplateInfo, relaxed_flag, has_side_effects,
               HasSideEffectsBit::kShift)
BOOL_ACCESSORS(FunctionTemplateInfo, relaxed_flag, undetectable,
               UndetectableBit::kShift)
BOOL_ACCESSORS(FunctionTemplateInfo, relaxed_flag, needs_access_check,
               NeedsAccessCheckBit::kShift)
BOOL_ACCESSORS(FunctionTemplateInfo, relaxed_flag, read_only_prototype,
               ReadOnlyPrototypeBit::kShift)
BOOL_ACCESSORS(FunctionTemplateInfo, relaxed_flag, remove_prototype,
               RemovePrototypeBit::kShift)
BOOL_ACCESSORS(FunctionTemplateInfo, relaxed_flag, accept_any_receiver,
               AcceptAnyReceiverBit::kShift)
BOOL_ACCESSORS(FunctionTemplateInfo, relaxed_flag, published,
               PublishedBit::kShift)

BIT_FIELD_ACCESSORS(
    FunctionTemplateInfo, relaxed_flag,
    allowed_receiver_instance_type_range_start,
    FunctionTemplateInfo::AllowedReceiverInstanceTypeRangeStartBits)
BIT_FIELD_ACCESSORS(
    FunctionTemplateInfo, relaxed_flag,
    allowed_receiver_instance_type_range_end,
    FunctionTemplateInfo::AllowedReceiverInstanceTypeRangeEndBits)

RELAXED_UINT32_ACCESSORS(FunctionTemplateInfo, flag,
                         FunctionTemplateInfo::kFlagOffset)

int32_t FunctionTemplateInfo::relaxed_flag() const {
  return flag(kRelaxedLoad);
}
void FunctionTemplateInfo::set_relaxed_flag(int32_t flags) {
  return set_flag(flags, kRelaxedStore);
}

Address FunctionTemplateInfo::callback(i::IsolateForSandbox isolate) const {
  Address result = maybe_redirected_callback(isolate);
  if (!USE_SIMULATOR_BOOL) return result;
  if (result == kNullAddress) return kNullAddress;
  return ExternalReference::UnwrapRedirection(result);
}

void FunctionTemplateInfo::init_callback(i::IsolateForSandbox isolate,
                                         Address initial_value) {
  init_maybe_redirected_callback(isolate, initial_value);
  if (USE_SIMULATOR_BOOL) {
    init_callback_redirection(isolate);
  }
}

void FunctionTemplateInfo::set_callback(i::IsolateForSandbox isolate,
                                        Address value) {
  set_maybe_redirected_callback(isolate, value);
  if (USE_SIMULATOR_BOOL) {
    init_callback_redirection(isolate);
  }
}

void FunctionTemplateInfo::init_callback_redirection(
    i::IsolateForSandbox isolate) {
  CHECK(USE_SIMULATOR_BOOL);
  Address value = maybe_redirected_callback(isolate);
  if (value == kNullAddress) return;
  value =
      ExternalReference::Redirect(value, ExternalReference::DIRECT_API_CALL);
  set_maybe_redirected_callback(isolate, value);
}

void FunctionTemplateInfo::remove_callback_redirection(
    i::IsolateForSandbox isolate) {
  CHECK(USE_SIMULATOR_BOOL);
  Address value = callback(isolate);
  set_maybe_redirected_callback(isolate, value);
}

EXTERNAL_POINTER_ACCESSORS_MAYBE_READ_ONLY_HOST(
    FunctionTemplateInfo, maybe_redirected_callback, Address,
    kMaybeRedirectedCallbackOffset, kFunctionTemplateInfoCallbackTag)

template <class IsolateT>
bool FunctionTemplateInfo::has_callback(IsolateT* isolate) const {
  return !IsTheHole(callback_data(kAcquireLoad), isolate);
}

// static
Tagged<FunctionTemplateRareData>
FunctionTemplateInfo::EnsureFunctionTemplateRareData(
    Isolate* isolate,
    DirectHandle<FunctionTemplateInfo> function_template_info) {
  Tagged<HeapObject> extra =
      function_template_info->rare_data(isolate, kAcquireLoad);
  if (IsUndefined(extra, isolate)) {
    return AllocateFunctionTemplateRareData(isolate, function_template_info);
  } else {
    return Cast<FunctionTemplateRareData>(extra);
  }
}

#define RARE_ACCESSORS(Name, CamelName, Default, ...)                          \
  DEF_GETTER(FunctionTemplateInfo, Get##CamelName, Tagged<__VA_ARGS__>) {      \
    Tagged<HeapObject> extra = rare_data(cage_base, kAcquireLoad);             \
    Tagged<Undefined> undefined =                                              \
        GetReadOnlyRoots(cage_base).undefined_value();                         \
    return extra == undefined ? Default                                        \
                              : Cast<FunctionTemplateRareData>(extra)->Name(); \
  }                                                                            \
  inline void FunctionTemplateInfo::Set##CamelName(                            \
      Isolate* isolate,                                                        \
      DirectHandle<FunctionTemplateInfo> function_template_info,               \
      DirectHandle<__VA_ARGS__> Name) {                                        \
    Tagged<FunctionTemplateRareData> rare_data =                               \
        EnsureFunctionTemplateRareData(isolate, function_template_info);       \
    rare_data->set_##Name(*Name);                                              \
  }

RARE_ACCESSORS(prototype_template, PrototypeTemplate, undefined,
               UnionOf<Undefined, ObjectTemplateInfo>)
RARE_ACCESSORS(prototype_provider_template, PrototypeProviderTemplate,
               undefined, UnionOf<Undefined, FunctionTemplateInfo>)
RARE_ACCESSORS(parent_template, ParentTemplate, undefined,
               UnionOf<Undefined, FunctionTemplateInfo>)
RARE_ACCESSORS(named_property_handler, NamedPropertyHandler, undefined,
               UnionOf<Undefined, InterceptorInfo>)
RARE_ACCESSORS(indexed_property_handler, IndexedPropertyHandler, undefined,
               UnionOf<Undefined, InterceptorInfo>)
RARE_ACCESSORS(instance_template, InstanceTemplate, undefined,
               UnionOf<Undefined, ObjectTemplateInfo>)
RARE_ACCESSORS(instance_call_handler, InstanceCallHandler, undefined,
               UnionOf<Undefined, FunctionTemplateInfo>)
RARE_ACCESSORS(access_check_info, AccessCheckInfo, undefined,
               UnionOf<Undefined, AccessCheckInfo>)
RARE_ACCESSORS(c_function_overloads, CFunctionOverloads,
               GetReadOnlyRoots(cage_base).empty_fixed_array(), FixedArray)
#undef RARE_ACCESSORS

InstanceType FunctionTemplateInfo::GetInstanceType() const {
  int type = instance_type();
  DCHECK(base::IsInRange(type, Internals::kFirstJSApiObjectType,
                         Internals::kLastJSApiObjectType));
  return static_cast<InstanceType>(type);
}

void FunctionTemplateInfo::SetInstanceType(int api_instance_type) {
  // Translate |api_instance_type| value from range
  // [Internals::kFirstEmbedderJSApiObjectType,
  //  Internals::kLastEmbedderJSApiObjectType] to range
  // [Internals::kFirstJSApiObjectType, Internals::kLastJSApiObjectType].
  DCHECK_LE(Internals::kFirstEmbedderJSApiObjectType, api_instance_type);
  DCHECK_LE(api_instance_type, Internals::kLastEmbedderJSApiObjectType);
  // kNoJSApiObjectType must correspond to JS_API_OBJECT_TYPE.
  static_assert(kNoJSApiObjectType == 0);
  static_assert(JS_API_OBJECT_TYPE == Internals::kFirstJSApiObjectType);
  set_instance_type(static_cast<InstanceType>(
      api_instance_type + Internals::kFirstJSApiObjectType));
}

void FunctionTemplateInfo::SetAllowedReceiverInstanceTypeRange(
    int api_instance_type_start, int api_instance_type_end) {
  // Translate |api_instance_type_start| and |api_instance_type_end| values
  // from range [Internals::kFirstEmbedderJSApiObjectType,
  //             Internals::kLastEmbedderJSApiObjectType] to range
  // [Internals::kFirstJSApiObjectType, Internals::kLastJSApiObjectType].
  DCHECK_LE(Internals::kFirstEmbedderJSApiObjectType, api_instance_type_start);
  DCHECK_LE(api_instance_type_start, api_instance_type_end);
  DCHECK_LE(api_instance_type_end, Internals::kLastEmbedderJSApiObjectType);
  // kNoJSApiObjectType must correspond to JS_API_OBJECT_TYPE.
  static_assert(kNoJSApiObjectType == 0);
  static_assert(JS_API_OBJECT_TYPE == Internals::kFirstJSApiObjectType);
  set_allowed_receiver_instance_type_range_start(static_cast<InstanceType>(
      api_instance_type_start + Internals::kFirstJSApiObjectType));
  set_allowed_receiver_instance_type_range_end(static_cast<InstanceType>(
      api_instance_type_end + Internals::kFirstJSApiObjectType));
}

// Ensure that instance type fields in FunctionTemplateInfo are big enough
// to fit the whole JSApiObject type range.
static_assert(
    FunctionTemplateInfo::AllowedReceiverInstanceTypeRangeStartBits::is_valid(
        LAST_JS_API_OBJECT_TYPE));
static_assert(
    FunctionTemplateInfo::AllowedReceiverInstanceTypeRangeEndBits::is_valid(
        LAST_JS_API_OBJECT_TYPE));

bool TemplateInfo::should_cache() const {
  return serial_number() != kDoNotCache;
}
bool TemplateInfo::is_cached() const { return serial_number() > kUncached; }

bool FunctionTemplateInfo::instantiated() {
  return IsSharedFunctionInfo(shared_function_info());
}

inline bool FunctionTemplateInfo::BreakAtEntry(Isolate* isolate) {
  Tagged<Object> maybe_shared = shared_function_info();
  if (IsSharedFunctionInfo(maybe_shared)) {
    Tagged<SharedFunctionInfo> shared = Cast<SharedFunctionInfo>(maybe_shared);
    return shared->BreakAtEntry(isolate);
  }
  return false;
}

Tagged<FunctionTemplateInfo> FunctionTemplateInfo::GetParent(Isolate* isolate) {
  Tagged<Object> parent = GetParentTemplate();
  return IsUndefined(parent, isolate) ? Tagged<FunctionTemplateInfo>{}
                                      : Cast<FunctionTemplateInfo>(parent);
}

Tagged<ObjectTemplateInfo> ObjectTemplateInfo::GetParent(Isolate* isolate) {
  Tagged<Object> maybe_ctor = constructor();
  if (IsUndefined(maybe_ctor, isolate)) return ObjectTemplateInfo();
  Tagged<FunctionTemplateInfo> constructor =
      Cast<FunctionTemplateInfo>(maybe_ctor);
  while (true) {
    constructor = constructor->GetParent(isolate);
    if (constructor.is_null()) return ObjectTemplateInfo();
    Tagged<Object> maybe_obj = constructor->GetInstanceTemplate();
    if (!IsUndefined(maybe_obj, isolate)) {
      return Cast<ObjectTemplateInfo>(maybe_obj);
    }
  }
  return Tagged<ObjectTemplateInfo>();
}

int ObjectTemplateInfo::embedder_field_count() const {
  return EmbedderFieldCountBits::decode(data());
}

void ObjectTemplateInfo::set_embedder_field_count(int count) {
  DCHECK_LE(count, JSObject::kMaxEmbedderFields);
  return set_data(EmbedderFieldCountBits::update(data(), count));
}

bool ObjectTemplateInfo::immutable_proto() const {
  return IsImmutablePrototypeBit::decode(data());
}

void ObjectTemplateInfo::set_immutable_proto(bool immutable) {
  return set_data(IsImmutablePrototypeBit::update(data(), immutable));
}

bool ObjectTemplateInfo::code_like() const {
  return IsCodeKindBit::decode(data());
}

void ObjectTemplateInfo::set_code_like(bool is_code_like) {
  return set_data(IsCodeKindBit::update(data(), is_code_like));
}

bool FunctionTemplateInfo::IsTemplateFor(Tagged<JSObject> object) const {
  return IsTemplateFor(object->map());
}

bool TemplateInfo::TryGetIsolate(Isolate** isolate) const {
  if (GetIsolateFromHeapObject(*this, isolate)) return true;
  Isolate* isolate_value = Isolate::TryGetCurrent();
  if (isolate_value != nullptr) {
    *isolate = isolate_value;
    return true;
  }
  return false;
}

Isolate* TemplateInfo::GetIsolateChecked() const {
  Isolate* isolate;
  CHECK(TryGetIsolate(&isolate));
  return isolate;
}

// static
template <typename ReturnType>
MaybeHandle<ReturnType> TemplateInfo::ProbeInstantiationsCache(
    Isolate* isolate, DirectHandle<NativeContext> native_context,
    int serial_number, CachingMode caching_mode) {
  DCHECK_NE(serial_number, TemplateInfo::kDoNotCache);
  if (serial_number == TemplateInfo::kUncached) {
    return {};
  }

  if (serial_number < TemplateInfo::kFastTemplateInstantiationsCacheSize) {
    Tagged<FixedArray> fast_cache =
        native_context->fast_template_instantiations_cache();
    Handle<Object> object{fast_cache->get(serial_number), isolate};
    if (IsTheHole(*object, isolate)) {
      return {};
    }
    return Cast<ReturnType>(object);
  }
  if (caching_mode == CachingMode::kUnlimited ||
      (serial_number < TemplateInfo::kSlowTemplateInstantiationsCacheSize)) {
    Tagged<SimpleNumberDictionary> slow_cache =
        native_context->slow_template_instantiations_cache();
    InternalIndex entry = slow_cache->FindEntry(isolate, serial_number);
    if (entry.is_found()) {
      return handle(Cast<ReturnType>(slow_cache->ValueAt(entry)), isolate);
    }
  }
  return {};
}

// static
template <typename InstantiationType, typename TemplateInfoType>
void TemplateInfo::CacheTemplateInstantiation(
    Isolate* isolate, DirectHandle<NativeContext> native_context,
    DirectHandle<TemplateInfoType> data, CachingMode caching_mode,
    Handle<InstantiationType> object) {
  DCHECK_NE(TemplateInfo::kDoNotCache, data->serial_number());

  int serial_number = data->serial_number();
  if (serial_number == TemplateInfo::kUncached) {
    serial_number = isolate->heap()->GetNextTemplateSerialNumber();
  }

  if (serial_number < TemplateInfo::kFastTemplateInstantiationsCacheSize) {
    Handle<FixedArray> fast_cache =
        handle(native_context->fast_template_instantiations_cache(), isolate);
    DirectHandle<FixedArray> new_cache =
        FixedArray::SetAndGrow(isolate, fast_cache, serial_number, object);
    if (*new_cache != *fast_cache) {
      native_context->set_fast_template_instantiations_cache(*new_cache);
    }
    data->set_serial_number(serial_number);
  } else if (caching_mode == CachingMode::kUnlimited ||
             (serial_number <
              TemplateInfo::kSlowTemplateInstantiationsCacheSize)) {
    Handle<SimpleNumberDictionary> cache =
        handle(native_context->slow_template_instantiations_cache(), isolate);
    auto new_cache =
        SimpleNumberDictionary::Set(isolate, cache, serial_number, object);
    if (*new_cache != *cache) {
      native_context->set_slow_template_instantiations_cache(*new_cache);
    }
    data->set_serial_number(serial_number);
  } else {
    // we've overflowed the cache limit, no more caching
    data->set_serial_number(TemplateInfo::kDoNotCache);
  }
}

// static
template <typename TemplateInfoType>
void TemplateInfo::UncacheTemplateInstantiation(
    Isolate* isolate, DirectHandle<NativeContext> native_context,
    DirectHandle<TemplateInfoType> data, CachingMode caching_mode) {
  int serial_number = data->serial_number();
  if (serial_number < 0) return;

  if (serial_number < TemplateInfo::kFastTemplateInstantiationsCacheSize) {
    Tagged<FixedArray> fast_cache =
        native_context->fast_template_instantiations_cache();
    DCHECK(!IsUndefined(fast_cache->get(serial_number), isolate));
    fast_cache->set(serial_number, ReadOnlyRoots{isolate}.the_hole_value(),
                    SKIP_WRITE_BARRIER);
    data->set_serial_number(TemplateInfo::kUncached);
  } else if (caching_mode == CachingMode::kUnlimited ||
             (serial_number <
              TemplateInfo::kSlowTemplateInstantiationsCacheSize)) {
    Handle<SimpleNumberDictionary> cache =
        handle(native_context->slow_template_instantiations_cache(), isolate);
    InternalIndex entry = cache->FindEntry(isolate, serial_number);
    DCHECK(entry.is_found());
    cache = SimpleNumberDictionary::DeleteEntry(isolate, cache, entry);
    native_context->set_slow_template_instantiations_cache(*cache);
    data->set_serial_number(TemplateInfo::kUncached);
  }
}

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_TEMPLATES_INL_H_
```