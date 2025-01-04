Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and, if related to JavaScript, illustrative JavaScript examples. This means we need to identify the core purpose of the code and how it manifests in the JavaScript runtime.

2. **Initial Skim for Keywords and Structure:**  Quickly read through the code, looking for familiar terms related to JavaScript or compilation. Keywords like `literal`, `object`, `array`, `regexp`, `boilerplate`, `allocation`, `map`, `properties`, `elements`, `JSObject`, `JSRegExp`, and function names like `CreateObjectLiteral`, `CreateArrayLiteral`, `CreateRegExpLiteral` jump out. The file path `v8/src/runtime/runtime-literals.cc` strongly suggests this code deals with the creation of literal values during runtime.

3. **Identify Core Data Structures:**  Pay attention to the classes and structs defined: `JSObjectWalkVisitor`, `DeprecationUpdateContext`, `AllocationSiteCreationContext`, `AllocationSiteUsageContext`, `ObjectLiteralHelper`, `ArrayLiteralHelper`. These indicate different aspects of managing the lifecycle and creation of object and array literals. The `AllocationSite` appears important for optimization.

4. **Focus on Key Functions:** The `RUNTIME_FUNCTION` macros are the entry points for the JavaScript runtime. The functions `Runtime_CreateObjectLiteral`, `Runtime_CreateArrayLiteral`, and `Runtime_CreateRegExpLiteral` are directly invoked when JavaScript code uses object literals, array literals, or regular expression literals.

5. **Trace the Creation Process:**  For each literal type (object, array, regex), follow the logic within its corresponding `RUNTIME_FUNCTION`.

    * **Object/Array Literals:** Notice the use of `ObjectBoilerplateDescription` and `ArrayBoilerplateDescription`. The concept of a "boilerplate" emerges as a pre-constructed template. The code checks for existing boilerplates and creates them if necessary. The `DeepWalk` and `DeepCopy` functions suggest a recursive processing of nested literals. Allocation sites are managed for optimization.

    * **RegExp Literals:** The handling is slightly different. It checks if a boilerplate exists. If not, it creates a `JSRegExp` instance directly. The concept of a "literal site" and its initialization steps become apparent.

6. **Connect to JavaScript Concepts:** Now, link the C++ mechanics to the corresponding JavaScript syntax.

    * **Object Literals:**  The code directly handles the creation of `{ key: value }` structures. The handling of prototypes (`__proto__: null`) and the distinction between fast and slow properties are relevant.

    * **Array Literals:**  The code is responsible for creating `[item1, item2]` arrays, including handling nested arrays and objects within them. The concept of "elements kind" (e.g., packed, holey) becomes relevant at this level.

    * **RegExp Literals:**  The code deals with the creation of `/pattern/flags` regular expressions. The caching or "boilerplate" mechanism for regexps hints at performance optimization.

7. **Formulate the Summary:**  Based on the traced logic, summarize the file's purpose: creating and managing object, array, and regular expression literals. Emphasize the optimization aspects like "boilerplates" and "allocation sites."

8. **Construct JavaScript Examples:** Create simple JavaScript code snippets that directly trigger the C++ functionality being analyzed. Focus on the basic syntax of object, array, and regular expression literals. Demonstrate nesting for objects and arrays. Point out how the C++ code handles these constructs behind the scenes.

9. **Review and Refine:** Read through the summary and examples. Ensure they are clear, accurate, and directly relate the C++ code to JavaScript behavior. Check for any technical jargon that might need clarification. For instance, initially, I might have just said "allocation sites are used," but refining it to explain *why* (optimization, performance) adds more value. Similarly, explaining the concept of a "boilerplate" is crucial for understanding the C++ code's logic. Also, ensure the JavaScript examples are simple and directly illustrate the point. Avoid complex JavaScript constructs that might obscure the connection.

This iterative process of skimming, identifying key components, tracing execution, connecting to JavaScript concepts, summarizing, and illustrating with examples allows for a comprehensive understanding of the C++ code's role in the V8 JavaScript engine.
这个C++源代码文件 `v8/src/runtime/runtime-literals.cc` 的主要功能是**在 V8 JavaScript 引擎的运行时环境 (runtime) 中创建和管理 JavaScript 的字面量 (literals)**，包括对象字面量、数组字面量和正则表达式字面量。

更具体地说，它的功能可以归纳为以下几点：

1. **创建字面量对象:**  文件中包含了 `Runtime_CreateObjectLiteral` 和 `Runtime_CreateArrayLiteral` 这两个运行时函数 (runtime functions)。当 JavaScript 代码执行到对象字面量 (例如 `{}`, `{a: 1}`) 或数组字面量 (例如 `[]`, `[1, 2]`) 时，V8 引擎会调用这些 runtime 函数来实际创建对应的 JavaScript 对象。

2. **利用 Boilerplate 进行优化:**  为了提高性能，V8 引入了 "boilerplate" 的概念。对于经常被创建的相同结构的字面量，V8 会创建一个 "boilerplate" 对象作为模板。后续创建相同的字面量时，可以直接复制 boilerplate，而不是从头开始构建，从而节省时间和内存。这个文件中的代码负责创建、存储和利用这些 boilerplate。

3. **管理 Allocation Sites:**  为了进一步优化对象分配和属性访问，V8 使用 "allocation sites"。这些站点跟踪具有相似结构的对象的创建过程。`runtime-literals.cc` 中的代码负责在创建字面量时关联或创建 allocation sites。

4. **处理嵌套字面量:**  当对象或数组字面量包含嵌套的对象或数组字面量时，这个文件中的代码会递归地创建这些嵌套的字面量。

5. **创建正则表达式字面量:** `Runtime_CreateRegExpLiteral` 负责创建正则表达式字面量 (例如 `/abc/g`) 对应的 `JSRegExp` 对象。与对象和数组类似，它也涉及到 boilerplate 的管理，但过程略有不同。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`runtime-literals.cc` 文件中的代码直接支持了 JavaScript 中创建字面量的核心功能。  每当你使用字面量语法时，V8 引擎内部就会调用这个文件中的 C++ 代码来完成实际的创建工作。

**JavaScript 示例:**

**1. 对象字面量:**

```javascript
const obj1 = { a: 1, b: 'hello' };
const obj2 = { a: 1, b: 'hello' }; // 结构与 obj1 相同，可能会使用相同的 boilerplate
const obj3 = { c: 2, d: true };      // 结构不同，可能会创建新的 boilerplate

const nestedObj = {
  x: 10,
  y: {
    z: 20
  }
};
```

当 JavaScript 引擎执行以上代码时，`Runtime_CreateObjectLiteral` (或其相关的内部函数) 会被调用。对于 `obj1` 和 `obj2`，如果引擎检测到它们具有相同的结构，可能会先创建一个 boilerplate，然后 `obj2` 的创建会通过复制这个 boilerplate 来完成。`nestedObj` 的创建会涉及到递归调用来创建内部的对象字面量 `{ z: 20 }`。

**2. 数组字面量:**

```javascript
const arr1 = [1, 2, 'three'];
const arr2 = [1, 2, 'three']; // 结构和元素类型与 arr1 相同，可能使用相同 boilerplate
const arr3 = [4, 5, 6];        // 元素不同，但结构可能相同

const nestedArr = [
  1,
  [2, 3],
  { a: 4 }
];
```

当创建 `arr1` 和 `arr2` 时，`Runtime_CreateArrayLiteral` 会被调用。类似于对象字面量，引擎可能会利用 boilerplate 进行优化。`nestedArr` 的创建会涉及到创建内部的数组字面量 `[2, 3]` 和对象字面量 `{ a: 4 }`。

**3. 正则表达式字面量:**

```javascript
const regex1 = /abc/g;
const regex2 = /abc/g; // 模式和标志与 regex1 相同，可能会复用一些内部结构
const regex3 = /def/i;

const dynamicRegex = new RegExp('pattern', 'flags'); // 虽然不是字面量，但最终会创建 JSRegExp 对象
```

当 JavaScript 引擎遇到 `/abc/g` 这样的正则表达式字面量时，`Runtime_CreateRegExpLiteral` 会被调用。V8 会尝试复用具有相同模式和标志的正则表达式的内部结构。对于 `dynamicRegex`，虽然使用了 `RegExp` 构造函数，但最终也会创建 `JSRegExp` 对象，不过 `runtime-literals.cc` 主要处理字面量的情况。

**总结:**

`v8/src/runtime/runtime-literals.cc` 是 V8 引擎中负责将 JavaScript 字面量语法转换为实际运行时的 JavaScript 对象的核心组件。它通过 boilerplate 和 allocation sites 等机制实现了性能优化，确保了字面量创建的高效性。理解这个文件的功能有助于深入了解 V8 引擎如何高效地处理 JavaScript 代码中的基本数据结构。

Prompt: 
```
这是目录为v8/src/runtime/runtime-literals.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/ast/ast.h"
#include "src/common/globals.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/objects/allocation-site-scopes-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/runtime/runtime.h"

namespace v8 {
namespace internal {

namespace {

bool IsUninitializedLiteralSite(Tagged<Object> literal_site) {
  return literal_site == Smi::zero();
}

bool HasBoilerplate(DirectHandle<Object> literal_site) {
  return !IsSmi(*literal_site);
}

void PreInitializeLiteralSite(DirectHandle<FeedbackVector> vector,
                              FeedbackSlot slot) {
  vector->SynchronizedSet(slot, Smi::FromInt(1));
}

template <class ContextObject>
class JSObjectWalkVisitor {
 public:
  explicit JSObjectWalkVisitor(ContextObject* site_context)
      : site_context_(site_context) {}

  V8_WARN_UNUSED_RESULT MaybeHandle<JSObject> StructureWalk(
      Handle<JSObject> object);

 protected:
  V8_WARN_UNUSED_RESULT inline MaybeHandle<JSObject> VisitElementOrProperty(
      DirectHandle<JSObject> object, Handle<JSObject> value) {
    // Dont create allocation sites for nested object literals
    if (!IsJSArray(*value)) {
      return StructureWalk(value);
    }

    Handle<AllocationSite> current_site = site_context()->EnterNewScope();
    MaybeHandle<JSObject> copy_of_value = StructureWalk(value);
    site_context()->ExitScope(current_site, value);
    return copy_of_value;
  }

  inline ContextObject* site_context() { return site_context_; }
  inline Isolate* isolate() { return site_context()->isolate(); }

 private:
  ContextObject* site_context_;
};

template <class ContextObject>
MaybeHandle<JSObject> JSObjectWalkVisitor<ContextObject>::StructureWalk(
    Handle<JSObject> object) {
  Isolate* isolate = this->isolate();
  bool copying = ContextObject::kCopying;

  {
    StackLimitCheck check(isolate);

    if (check.HasOverflowed()) {
      isolate->StackOverflow();
      return MaybeHandle<JSObject>();
    }
  }

  if (object->map(isolate)->is_deprecated()) {
    base::SharedMutexGuard<base::kExclusive> mutex_guard(
        isolate->boilerplate_migration_access());
    JSObject::MigrateInstance(isolate, object);
  }

  Handle<JSObject> copy;
  if (copying) {
    // JSFunction objects are not allowed to be in normal boilerplates at all.
    DCHECK(!IsJSFunction(*object, isolate));
    Handle<AllocationSite> site_to_pass;
    if (site_context()->ShouldCreateMemento(object)) {
      site_to_pass = site_context()->current();
    }
    copy = isolate->factory()->CopyJSObjectWithAllocationSite(object,
                                                              site_to_pass);
  } else {
    copy = object;
  }

  DCHECK(copying || copy.is_identical_to(object));

  HandleScope scope(isolate);

  // Deep copy own properties. Arrays only have 1 property "length".
  if (!IsJSArray(*copy, isolate)) {
    if (copy->HasFastProperties(isolate)) {
      DirectHandle<DescriptorArray> descriptors(
          copy->map(isolate)->instance_descriptors(isolate), isolate);
      for (InternalIndex i : copy->map(isolate)->IterateOwnDescriptors()) {
        PropertyDetails details = descriptors->GetDetails(i);
        DCHECK_EQ(PropertyLocation::kField, details.location());
        DCHECK_EQ(PropertyKind::kData, details.kind());
        FieldIndex index = FieldIndex::ForPropertyIndex(
            copy->map(isolate), details.field_index(),
            details.representation());
        Tagged<Object> raw = copy->RawFastPropertyAt(isolate, index);
        if (IsJSObject(raw, isolate)) {
          Handle<JSObject> value(Cast<JSObject>(raw), isolate);
          ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                     VisitElementOrProperty(copy, value));
          if (copying) copy->FastPropertyAtPut(index, *value);
        } else if (copying && details.representation().IsDouble()) {
          uint64_t double_value = Cast<HeapNumber>(raw)->value_as_bits();
          auto value = isolate->factory()->NewHeapNumberFromBits(double_value);
          copy->FastPropertyAtPut(index, *value);
        }
      }
    } else {
      if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        DirectHandle<SwissNameDictionary> dict(
            copy->property_dictionary_swiss(isolate), isolate);
        for (InternalIndex i : dict->IterateEntries()) {
          Tagged<Object> raw = dict->ValueAt(i);
          if (!IsJSObject(raw, isolate)) continue;
          DCHECK(IsName(dict->KeyAt(i)));
          Handle<JSObject> value(Cast<JSObject>(raw), isolate);
          ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                     VisitElementOrProperty(copy, value));
          if (copying) dict->ValueAtPut(i, *value);
        }
      } else {
        DirectHandle<NameDictionary> dict(copy->property_dictionary(isolate),
                                          isolate);
        for (InternalIndex i : dict->IterateEntries()) {
          Tagged<Object> raw = dict->ValueAt(isolate, i);
          if (!IsJSObject(raw, isolate)) continue;
          DCHECK(IsName(dict->KeyAt(isolate, i)));
          Handle<JSObject> value(Cast<JSObject>(raw), isolate);
          ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                     VisitElementOrProperty(copy, value));
          if (copying) dict->ValueAtPut(i, *value);
        }
      }
    }

    // Assume non-arrays don't end up having elements.
    if (copy->elements(isolate)->length() == 0) return copy;
  }

  // Deep copy own elements.
  switch (copy->GetElementsKind(isolate)) {
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS: {
      DirectHandle<FixedArray> elements(
          Cast<FixedArray>(copy->elements(isolate)), isolate);
      if (elements->map() == ReadOnlyRoots(isolate).fixed_cow_array_map()) {
#ifdef DEBUG
        for (int i = 0; i < elements->length(); i++) {
          DCHECK(!IsJSObject(elements->get(i)));
        }
#endif
      } else {
        for (int i = 0; i < elements->length(); i++) {
          Tagged<Object> raw = elements->get(i);
          if (!IsJSObject(raw, isolate)) continue;
          Handle<JSObject> value(Cast<JSObject>(raw), isolate);
          ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                     VisitElementOrProperty(copy, value));
          if (copying) elements->set(i, *value);
        }
      }
      break;
    }
    case DICTIONARY_ELEMENTS: {
      DirectHandle<NumberDictionary> element_dictionary(
          copy->element_dictionary(isolate), isolate);
      for (InternalIndex i : element_dictionary->IterateEntries()) {
        Tagged<Object> raw = element_dictionary->ValueAt(isolate, i);
        if (!IsJSObject(raw, isolate)) continue;
        Handle<JSObject> value(Cast<JSObject>(raw), isolate);
        ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                   VisitElementOrProperty(copy, value));
        if (copying) element_dictionary->ValueAtPut(i, *value);
      }
      break;
    }
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
      UNIMPLEMENTED();
      break;
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
    case WASM_ARRAY_ELEMENTS:
      UNREACHABLE();

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:

      TYPED_ARRAYS(TYPED_ARRAY_CASE)
      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      // Typed elements cannot be created using an object literal.
      UNREACHABLE();

    case PACKED_SMI_ELEMENTS:
    case HOLEY_SMI_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS:
    case HOLEY_DOUBLE_ELEMENTS:
    case NO_ELEMENTS:
      // No contained objects, nothing to do.
      break;
  }

  return copy;
}

class DeprecationUpdateContext {
 public:
  explicit DeprecationUpdateContext(Isolate* isolate) { isolate_ = isolate; }
  Isolate* isolate() { return isolate_; }
  bool ShouldCreateMemento(DirectHandle<JSObject> object) { return false; }
  inline void ExitScope(DirectHandle<AllocationSite> scope_site,
                        DirectHandle<JSObject> object) {}
  Handle<AllocationSite> EnterNewScope() { return Handle<AllocationSite>(); }
  Handle<AllocationSite> current() {
    UNREACHABLE();
  }

  static const bool kCopying = false;

 private:
  Isolate* isolate_;
};

// AllocationSiteCreationContext aids in the creation of AllocationSites to
// accompany object literals.
class AllocationSiteCreationContext : public AllocationSiteContext {
 public:
  explicit AllocationSiteCreationContext(Isolate* isolate)
      : AllocationSiteContext(isolate) {}

  Handle<AllocationSite> EnterNewScope() {
    Handle<AllocationSite> scope_site;
    if (top().is_null()) {
      // We are creating the top level AllocationSite as opposed to a nested
      // AllocationSite.
      InitializeTraversal(isolate()->factory()->NewAllocationSite(true));
      scope_site = Handle<AllocationSite>(*top(), isolate());
      if (v8_flags.trace_creation_allocation_sites) {
        PrintF("*** Creating top level %s AllocationSite %p\n", "Fat",
               reinterpret_cast<void*>(scope_site->ptr()));
      }
    } else {
      DCHECK(!current().is_null());
      scope_site = isolate()->factory()->NewAllocationSite(false);
      if (v8_flags.trace_creation_allocation_sites) {
        PrintF(
            "*** Creating nested %s AllocationSite (top, current, new) (%p, "
            "%p, "
            "%p)\n",
            "Slim", reinterpret_cast<void*>(top()->ptr()),
            reinterpret_cast<void*>(current()->ptr()),
            reinterpret_cast<void*>(scope_site->ptr()));
      }
      current()->set_nested_site(*scope_site);
      update_current_site(*scope_site);
    }
    DCHECK(!scope_site.is_null());
    return scope_site;
  }
  void ExitScope(Handle<AllocationSite> scope_site, Handle<JSObject> object) {
    if (object.is_null()) return;
    scope_site->set_boilerplate(*object, kReleaseStore);
    if (v8_flags.trace_creation_allocation_sites) {
      bool top_level =
          !scope_site.is_null() && top().is_identical_to(scope_site);
      if (top_level) {
        PrintF("*** Setting AllocationSite %p transition_info %p\n",
               reinterpret_cast<void*>(scope_site->ptr()),
               reinterpret_cast<void*>(object->ptr()));
      } else {
        PrintF("*** Setting AllocationSite (%p, %p) transition_info %p\n",
               reinterpret_cast<void*>(top()->ptr()),
               reinterpret_cast<void*>(scope_site->ptr()),
               reinterpret_cast<void*>(object->ptr()));
      }
    }
  }
  static const bool kCopying = false;
};

MaybeHandle<JSObject> DeepWalk(Handle<JSObject> object,
                               DeprecationUpdateContext* site_context) {
  JSObjectWalkVisitor<DeprecationUpdateContext> v(site_context);
  MaybeHandle<JSObject> result = v.StructureWalk(object);
  Handle<JSObject> for_assert;
  DCHECK(!result.ToHandle(&for_assert) || for_assert.is_identical_to(object));
  return result;
}

MaybeHandle<JSObject> DeepWalk(Handle<JSObject> object,
                               AllocationSiteCreationContext* site_context) {
  JSObjectWalkVisitor<AllocationSiteCreationContext> v(site_context);
  MaybeHandle<JSObject> result = v.StructureWalk(object);
  Handle<JSObject> for_assert;
  DCHECK(!result.ToHandle(&for_assert) || for_assert.is_identical_to(object));
  return result;
}

MaybeHandle<JSObject> DeepCopy(Handle<JSObject> object,
                               AllocationSiteUsageContext* site_context) {
  JSObjectWalkVisitor<AllocationSiteUsageContext> v(site_context);
  MaybeHandle<JSObject> copy = v.StructureWalk(object);
  Handle<JSObject> for_assert;
  DCHECK(!copy.ToHandle(&for_assert) || !for_assert.is_identical_to(object));
  return copy;
}

Handle<JSObject> CreateObjectLiteral(
    Isolate* isolate,
    DirectHandle<ObjectBoilerplateDescription> object_boilerplate_description,
    int flags, AllocationType allocation);

Handle<JSObject> CreateArrayLiteral(
    Isolate* isolate,
    DirectHandle<ArrayBoilerplateDescription> array_boilerplate_description,
    AllocationType allocation);

struct ObjectLiteralHelper {
  static inline Handle<JSObject> Create(Isolate* isolate,
                                        Handle<HeapObject> description,
                                        int flags, AllocationType allocation) {
    auto object_boilerplate_description =
        Cast<ObjectBoilerplateDescription>(description);
    return CreateObjectLiteral(isolate, object_boilerplate_description, flags,
                               allocation);
  }
};

struct ArrayLiteralHelper {
  static inline Handle<JSObject> Create(Isolate* isolate,
                                        Handle<HeapObject> description,
                                        int flags_not_used,
                                        AllocationType allocation) {
    auto array_boilerplate_description =
        Cast<ArrayBoilerplateDescription>(description);
    return CreateArrayLiteral(isolate, array_boilerplate_description,
                              allocation);
  }
};

Handle<JSObject> CreateObjectLiteral(
    Isolate* isolate,
    DirectHandle<ObjectBoilerplateDescription> object_boilerplate_description,
    int flags, AllocationType allocation) {
  DirectHandle<NativeContext> native_context = isolate->native_context();
  bool use_fast_elements = (flags & ObjectLiteral::kFastElements) != 0;
  bool has_null_prototype = (flags & ObjectLiteral::kHasNullPrototype) != 0;

  // In case we have function literals, we want the object to be in
  // slow properties mode for now. We don't go in the map cache because
  // maps with constant functions can't be shared if the functions are
  // not the same (which is the common case).
  int number_of_properties =
      object_boilerplate_description->backing_store_size();

  // Ignoring number_of_properties for force dictionary map with
  // __proto__:null.
  DirectHandle<Map> map =
      has_null_prototype
          ? direct_handle(native_context->slow_object_with_null_prototype_map(),
                          isolate)
          : isolate->factory()->ObjectLiteralMapFromCache(native_context,
                                                          number_of_properties);

  Handle<JSObject> boilerplate =
      isolate->factory()->NewFastOrSlowJSObjectFromMap(
          map, number_of_properties, allocation);

  // Normalize the elements of the boilerplate to save space if needed.
  if (!use_fast_elements) JSObject::NormalizeElements(boilerplate);

  // Add the constant properties to the boilerplate.
  int length = object_boilerplate_description->boilerplate_properties_count();
  // TODO(verwaest): Support tracking representations in the boilerplate.
  for (int index = 0; index < length; index++) {
    Handle<Object> key(object_boilerplate_description->name(index), isolate);
    Handle<Object> value(object_boilerplate_description->value(index), isolate);

    if (IsHeapObject(*value)) {
      if (IsArrayBoilerplateDescription(Cast<HeapObject>(*value), isolate)) {
        auto array_boilerplate = Cast<ArrayBoilerplateDescription>(value);
        value = CreateArrayLiteral(isolate, array_boilerplate, allocation);

      } else if (IsObjectBoilerplateDescription(Cast<HeapObject>(*value),
                                                isolate)) {
        auto object_boilerplate = Cast<ObjectBoilerplateDescription>(value);
        value = CreateObjectLiteral(isolate, object_boilerplate,
                                    object_boilerplate->flags(), allocation);
      }
    }

    uint32_t element_index = 0;
    if (Object::ToArrayIndex(*key, &element_index)) {
      // Array index (uint32).
      if (IsUninitialized(*value, isolate)) {
        value = handle(Smi::zero(), isolate);
      }
      JSObject::SetOwnElementIgnoreAttributes(boilerplate, element_index, value,
                                              NONE)
          .Check();
    } else {
      Handle<String> name = Cast<String>(key);
      DCHECK(!name->AsArrayIndex(&element_index));
      JSObject::SetOwnPropertyIgnoreAttributes(boilerplate, name, value, NONE)
          .Check();
    }
  }

  if (map->is_dictionary_map() && !has_null_prototype) {
    // TODO(cbruni): avoid making the boilerplate fast again, the clone stub
    // supports dict-mode objects directly.
    JSObject::MigrateSlowToFast(
        boilerplate, boilerplate->map()->UnusedPropertyFields(), "FastLiteral");
  }
  return boilerplate;
}

Handle<JSObject> CreateArrayLiteral(
    Isolate* isolate,
    DirectHandle<ArrayBoilerplateDescription> array_boilerplate_description,
    AllocationType allocation) {
  ElementsKind constant_elements_kind =
      array_boilerplate_description->elements_kind();

  Handle<FixedArrayBase> constant_elements_values(
      array_boilerplate_description->constant_elements(isolate), isolate);

  // Create the JSArray.
  Handle<FixedArrayBase> copied_elements_values;
  if (IsDoubleElementsKind(constant_elements_kind)) {
    copied_elements_values = isolate->factory()->CopyFixedDoubleArray(
        Cast<FixedDoubleArray>(constant_elements_values));
  } else {
    DCHECK(IsSmiOrObjectElementsKind(constant_elements_kind));
    const bool is_cow = (constant_elements_values->map() ==
                         ReadOnlyRoots(isolate).fixed_cow_array_map());
    if (is_cow) {
      copied_elements_values = constant_elements_values;
      if (DEBUG_BOOL) {
        auto fixed_array_values = Cast<FixedArray>(copied_elements_values);
        for (int i = 0; i < fixed_array_values->length(); i++) {
          DCHECK(!IsFixedArray(fixed_array_values->get(i)));
        }
      }
    } else {
      Handle<FixedArray> fixed_array_values =
          Cast<FixedArray>(constant_elements_values);
      Handle<FixedArray> fixed_array_values_copy =
          isolate->factory()->CopyFixedArray(fixed_array_values);
      copied_elements_values = fixed_array_values_copy;
      for (int i = 0; i < fixed_array_values->length(); i++) {
        Tagged<Object> value = fixed_array_values_copy->get(i);
        Tagged<HeapObject> value_heap_object;
        if (value.GetHeapObject(isolate, &value_heap_object)) {
          if (IsArrayBoilerplateDescription(value_heap_object, isolate)) {
            HandleScope sub_scope(isolate);
            DirectHandle<ArrayBoilerplateDescription> boilerplate(
                Cast<ArrayBoilerplateDescription>(value_heap_object), isolate);
            DirectHandle<JSObject> result =
                CreateArrayLiteral(isolate, boilerplate, allocation);
            fixed_array_values_copy->set(i, *result);

          } else if (IsObjectBoilerplateDescription(value_heap_object,
                                                    isolate)) {
            HandleScope sub_scope(isolate);
            DirectHandle<ObjectBoilerplateDescription> boilerplate(
                Cast<ObjectBoilerplateDescription>(value_heap_object), isolate);
            DirectHandle<JSObject> result = CreateObjectLiteral(
                isolate, boilerplate, boilerplate->flags(), allocation);
            fixed_array_values_copy->set(i, *result);
          }
        }
      }
    }
  }
  return isolate->factory()->NewJSArrayWithElements(
      copied_elements_values, constant_elements_kind,
      copied_elements_values->length(), allocation);
}

template <typename LiteralHelper>
MaybeHandle<JSObject> CreateLiteralWithoutAllocationSite(
    Isolate* isolate, Handle<HeapObject> description, int flags) {
  Handle<JSObject> literal = LiteralHelper::Create(isolate, description, flags,
                                                   AllocationType::kYoung);
  DeprecationUpdateContext update_context(isolate);
  RETURN_ON_EXCEPTION(isolate, DeepWalk(literal, &update_context));
  return literal;
}

template <typename LiteralHelper>
MaybeHandle<JSObject> CreateLiteral(Isolate* isolate,
                                    Handle<HeapObject> maybe_vector,
                                    int literals_index,
                                    Handle<HeapObject> description, int flags) {
  if (!IsFeedbackVector(*maybe_vector)) {
    DCHECK(IsUndefined(*maybe_vector));
    return CreateLiteralWithoutAllocationSite<LiteralHelper>(
        isolate, description, flags);
  }
  auto vector = Cast<FeedbackVector>(maybe_vector);
  FeedbackSlot literals_slot(FeedbackVector::ToSlot(literals_index));
  CHECK(literals_slot.ToInt() < vector->length());
  Handle<Object> literal_site(Cast<Object>(vector->Get(literals_slot)),
                              isolate);
  Handle<AllocationSite> site;
  Handle<JSObject> boilerplate;

  if (HasBoilerplate(literal_site)) {
    site = Cast<AllocationSite>(literal_site);
    boilerplate = Handle<JSObject>(site->boilerplate(), isolate);
  } else {
    // Eagerly create AllocationSites for literals that contain an Array.
    bool needs_initial_allocation_site =
        (flags & AggregateLiteral::kNeedsInitialAllocationSite) != 0;
    if (!needs_initial_allocation_site &&
        IsUninitializedLiteralSite(*literal_site)) {
      PreInitializeLiteralSite(vector, literals_slot);
      return CreateLiteralWithoutAllocationSite<LiteralHelper>(
          isolate, description, flags);
    } else {
      boilerplate = LiteralHelper::Create(isolate, description, flags,
                                          AllocationType::kOld);
    }
    // Install AllocationSite objects.
    AllocationSiteCreationContext creation_context(isolate);
    site = creation_context.EnterNewScope();
    RETURN_ON_EXCEPTION(isolate, DeepWalk(boilerplate, &creation_context));
    creation_context.ExitScope(site, boilerplate);

    vector->SynchronizedSet(literals_slot, *site);
  }

  static_assert(static_cast<int>(ObjectLiteral::kDisableMementos) ==
                static_cast<int>(ArrayLiteral::kDisableMementos));
  bool enable_mementos = (flags & ObjectLiteral::kDisableMementos) == 0;

  // Copy the existing boilerplate.
  AllocationSiteUsageContext usage_context(isolate, site, enable_mementos);
  usage_context.EnterNewScope();
  MaybeHandle<JSObject> copy = DeepCopy(boilerplate, &usage_context);
  usage_context.ExitScope(site, boilerplate);
  return copy;
}

}  // namespace

RUNTIME_FUNCTION(Runtime_CreateObjectLiteral) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(0);
  int literals_index = args.tagged_index_value_at(1);
  Handle<ObjectBoilerplateDescription> description =
      args.at<ObjectBoilerplateDescription>(2);
  int flags = args.smi_value_at(3);
  RETURN_RESULT_OR_FAILURE(
      isolate, CreateLiteral<ObjectLiteralHelper>(
                   isolate, maybe_vector, literals_index, description, flags));
}

RUNTIME_FUNCTION(Runtime_CreateArrayLiteral) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(0);
  int literals_index = args.tagged_index_value_at(1);
  Handle<ArrayBoilerplateDescription> elements =
      args.at<ArrayBoilerplateDescription>(2);
  int flags = args.smi_value_at(3);
  RETURN_RESULT_OR_FAILURE(
      isolate, CreateLiteral<ArrayLiteralHelper>(
                   isolate, maybe_vector, literals_index, elements, flags));
}

RUNTIME_FUNCTION(Runtime_CreateRegExpLiteral) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(0);
  int index = args.tagged_index_value_at(1);
  Handle<String> pattern = args.at<String>(2);
  int flags = args.smi_value_at(3);

  if (IsUndefined(*maybe_vector)) {
    // We don't have a vector; don't create a boilerplate, simply construct a
    // plain JSRegExp instance and return it.
    RETURN_RESULT_OR_FAILURE(
        isolate, JSRegExp::New(isolate, pattern, JSRegExp::Flags(flags)));
  }

  auto vector = Cast<FeedbackVector>(maybe_vector);
  FeedbackSlot literal_slot(FeedbackVector::ToSlot(index));
  DirectHandle<Object> literal_site(Cast<Object>(vector->Get(literal_slot)),
                                    isolate);

  // This function must not be called when a boilerplate already exists (if it
  // exists, callers should instead copy the boilerplate into a new JSRegExp
  // instance).
  CHECK(!HasBoilerplate(literal_site));

  Handle<JSRegExp> regexp_instance;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, regexp_instance,
      JSRegExp::New(isolate, pattern, JSRegExp::Flags(flags)));

  // JSRegExp literal sites are initialized in a two-step process:
  // Uninitialized-Preinitialized, and Preinitialized-Initialized.
  if (IsUninitializedLiteralSite(*literal_site)) {
    PreInitializeLiteralSite(vector, literal_slot);
    return *regexp_instance;
  }

  DirectHandle<RegExpData> data(regexp_instance->data(isolate), isolate);
  DirectHandle<String> source(Cast<String>(regexp_instance->source()), isolate);
  DirectHandle<RegExpBoilerplateDescription> boilerplate =
      isolate->factory()->NewRegExpBoilerplateDescription(
          data, source,
          Smi::FromInt(static_cast<int>(regexp_instance->flags())));

  vector->SynchronizedSet(literal_slot, *boilerplate);
  DCHECK(
      HasBoilerplate(handle(Cast<Object>(vector->Get(literal_slot)), isolate)));

  return *regexp_instance;
}

}  // namespace internal
}  // namespace v8

"""

```