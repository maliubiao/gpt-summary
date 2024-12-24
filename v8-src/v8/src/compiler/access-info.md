Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understanding the Goal:** The request asks for the *functionality* of the `access-info.cc` file within the V8 JavaScript engine. It also asks for a connection to JavaScript, illustrated with examples.

2. **Initial Scan and Keywords:**  I'd start by quickly scanning the code for recognizable keywords and data structures. Things that jump out include:

    * `Copyright 2015 the V8 project authors`:  Confirms it's a V8 file.
    * `#include`:  Lists dependencies. These can be clues about the file's purpose. `compiler`, `heap-refs`, `objects`, `ic` suggest interaction with the compiler, heap memory management, and inline caching.
    * `namespace v8 { namespace internal { namespace compiler`: Confirms its location within the V8 compiler.
    * `AccessInfo`, `ElementAccessInfo`, `PropertyAccessInfo`:  These are central data structures and likely define the core concepts. The names suggest information about how properties and elements are accessed.
    * `AccessMode`:  Indicates different ways of accessing (load, store, has, define).
    * `MapRef`, `JSObjectRef`, `FieldIndex`, `Representation`, `Type`:  These are related to object layout and type information.
    * `CompilationDependencies`:  Suggests that the information generated here influences compilation decisions.
    * `InlinePropertyAccess`, `InlineElementAccess`:  Indicates optimization related to inlining.

3. **Focusing on Core Classes:** The `PropertyAccessInfo` and `ElementAccessInfo` classes appear to be the central entities. I'd examine their member variables and static factory methods (`Invalid`, `NotFound`, `DataField`, etc.). This reveals the kinds of information they encapsulate:

    * **`PropertyAccessInfo`:**  Seems to hold details about how a *property* of an object is accessed. This includes the type of access (data field, accessor, etc.), the location of the property (field index, dictionary index), its representation in memory, its type, and dependencies.
    * **`ElementAccessInfo`:**  Similar to `PropertyAccessInfo` but for *elements* of an array-like object. It focuses on `elements_kind` (e.g., `FAST_SMI_ELEMENTS`).

4. **Identifying Key Functions and Methods:** I'd look for important methods that *create* or *manipulate* these `AccessInfo` objects. `AccessInfoFactory` is a key class here, with methods like `ComputePropertyAccessInfo`, `ComputeElementAccessInfos`, `FinalizePropertyAccessInfos`. These methods are responsible for gathering the necessary information and creating the `AccessInfo` objects.

5. **Inferring Functionality from Context:** By combining the knowledge of the data structures and key methods, I'd start to infer the file's overall purpose. The names and the compiler namespace strongly suggest that this code is involved in *optimizing* property and element access during JavaScript compilation. It gathers information about the types, locations, and access patterns of properties and elements.

6. **Connecting to JavaScript:** The next step is to link this C++ code to JavaScript concepts. I'd consider how these internal details manifest in JavaScript behavior:

    * **Property Access:**  `obj.property`, `obj['property']`. The C++ code aims to optimize how these accesses are performed.
    * **Element Access:** `arr[index]`. Similar optimization goals.
    * **Prototypes:** The code mentions prototype chain traversal. This is a fundamental JavaScript concept.
    * **Data vs. Accessors:** The code distinguishes between data fields and accessors (getters/setters).
    * **Object Types and Maps:** The presence of `MapRef` and different object types (e.g., string, array) is directly related to how V8 represents JavaScript objects internally. Changes in object structure (e.g., adding properties) lead to map changes.
    * **Inline Caching:** The `ic` namespace and the focus on access patterns strongly suggest this code is related to inline caching, a key optimization technique.

7. **Crafting JavaScript Examples:**  To illustrate the connection, I'd create simple JavaScript snippets that demonstrate the concepts being handled in the C++ code. The examples should highlight:

    * **Different access patterns:**  Simple property access, prototype chain access.
    * **Data properties vs. accessors.**
    * **How object structure affects optimization.**  For example, adding a property can change the object's internal representation.
    * **The impact of object types:**  Arrays vs. regular objects, primitives.

8. **Structuring the Summary:**  Finally, I'd organize the findings into a clear and concise summary. This involves:

    * **Stating the main function:**  Gathering information for optimizing property and element access.
    * **Explaining the core concepts:** `AccessInfo`, different access modes, etc.
    * **Highlighting the connection to JavaScript:**  Explaining *why* this information is important for JavaScript performance.
    * **Providing illustrative JavaScript examples.**

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This is just about property lookups."  **Correction:** Realizing it also covers element access and is deeply integrated with the compilation process, not just runtime lookups.
* **Overly technical explanation:**  Initially focusing on low-level C++ details. **Refinement:** Shifting the focus to the *purpose* of the code and its connection to observable JavaScript behavior.
* **Vague examples:** Starting with very general JavaScript examples. **Refinement:**  Creating more specific examples that directly relate to the concepts discussed in the C++ code (e.g., showing the difference between direct property access and prototype lookups).
* **Missing key concepts:**  Forgetting to explicitly mention inline caching or the role of `Map` objects. **Refinement:**  Adding these crucial details.

By following this iterative process of scanning, identifying key components, inferring functionality, connecting to JavaScript, and refining the explanation, I can arrive at a comprehensive and understandable summary like the example provided in the prompt.
## 功能归纳：v8/src/compiler/access-info.cc

该文件 `access-info.cc` 的主要功能是**在 V8 编译器的优化阶段，收集和表示关于 JavaScript 对象属性和元素访问的信息，以便进行更有效的代码生成。**  它创建和管理 `PropertyAccessInfo` 和 `ElementAccessInfo` 对象，这些对象包含了执行特定属性或元素访问所需的信息。

**更具体地说，它的功能包括：**

1. **表示属性访问信息 (`PropertyAccessInfo`)：**
   - 存储了关于如何访问特定对象属性的各种信息，例如：
     - 访问类型 (`AccessMode`: Load, Store, Has, Define 等)
     - 属性所在的对象 (`holder`)
     - 属性值的来源 (例如，数据字段、常量、访问器、模块导出)
     - 如果是数据字段，则包含字段的索引 (`FieldIndex`)、内存表示 (`Representation`)、类型 (`Type`) 以及拥有该字段的 Map (`field_owner_map`)
     - 如果是访问器，则包含 getter/setter 函数的引用
     - 可能涉及到的 Map 转换 (`transition_map`)
     - 用于查找属性的起始对象 Map 集合 (`lookup_start_object_maps_`)
     - 编译依赖项 (`CompilationDependency`)

2. **表示元素访问信息 (`ElementAccessInfo`)：**
   - 存储了关于如何访问数组或类似数组对象元素的信息，例如：
     - 元素的类型 (`ElementsKind`: PACKED_SMI_ELEMENTS, HOLEY_DOUBLE_ELEMENTS 等)
     - 用于查找元素的起始对象 Map 集合 (`lookup_start_object_maps_`)
     - 可能发生的 Map 转换 (`transition_sources_`)

3. **工厂类 (`AccessInfoFactory`)：**
   - 提供了一系列方法来计算和创建 `PropertyAccessInfo` 和 `ElementAccessInfo` 对象。
   - 这些方法会分析对象的 Map、属性描述符、内联缓存 (Inline Caches, ICs) 的反馈等信息。
   - 例如，`ComputePropertyAccessInfo` 用于分析属性访问，`ComputeElementAccessInfos` 用于分析元素访问。
   - 包含了合并多个 `AccessInfo` 对象的功能，以便处理多态的情况。

4. **辅助函数：**
   - 提供了一些辅助函数，例如 `CanInlinePropertyAccess` 用于判断是否可以内联属性访问。

**与 JavaScript 功能的关系：**

`access-info.cc` 的功能直接关系到 JavaScript 的属性和元素访问性能。编译器利用这里收集到的信息，可以生成更优化的机器代码，避免一些运行时开销。

**JavaScript 举例说明：**

**1. 数据字段访问优化:**

```javascript
function getData(obj) {
  return obj.x;
}

const myObj = { x: 10 };
getData(myObj); // 第一次调用，可能触发内联缓存

// 编译器会根据 myObj 的 Map 和属性 'x' 的信息，生成优化的代码。
// access-info.cc 会记录 'x' 是一个数据字段，其 Representation 是 Smi (Small Integer)。

const anotherObj = { x: 20 };
getData(anotherObj); // 第二次调用，如果 anotherObj 的 Map 和 'x' 的 Representation 一致，
                     // 则可以直接使用之前生成的优化代码。
```

在这个例子中，`access-info.cc` 会记录 `myObj` 的 Map 和属性 `x` 的相关信息。如果后续调用 `getData` 时传入的对象具有相同的结构（相同的 Map），编译器就可以直接访问 `x` 字段，而不需要进行昂贵的运行时属性查找。

**2. 访问器 (Getter) 优化:**

```javascript
const myObj = {
  get y() {
    return this._y;
  },
  _y: 5
};

function getAccessor(obj) {
  return obj.y;
}

getAccessor(myObj);

// access-info.cc 会记录 'y' 是一个访问器属性，并可能包含对 getter 函数的引用。
// 编译器可以尝试内联 getter 函数的调用。
```

`access-info.cc` 会识别出 `y` 是一个访问器属性，并存储其 getter 函数的信息。编译器在优化 `getAccessor` 函数时，可能会选择内联 `myObj.y` 的 getter 函数调用，直接执行 `return this._y;` 的逻辑。

**3. 原型链访问优化:**

```javascript
function getProtoProp(obj) {
  return obj.z;
}

const proto = { z: 100 };
const myObj = Object.create(proto);
getProtoProp(myObj);

// access-info.cc 会记录需要在原型链上查找 'z' 属性。
// 如果原型链是稳定的，编译器可以优化原型链的查找过程。
```

当访问 `myObj.z` 时，`access-info.cc` 会记录需要在 `myObj` 的原型链上查找 `z` 属性。如果 V8 编译器能够确定原型链是稳定的（不会在运行时被修改），它可以生成更高效的代码来查找原型上的属性。

**4. 元素访问优化:**

```javascript
function getElement(arr, index) {
  return arr[index];
}

const myArray = [1, 2, 3];
getElement(myArray, 1);

// access-info.cc 会记录 myArray 的元素类型 (ElementsKind)，例如 PACKED_SMI_ELEMENTS。
// 编译器可以根据元素类型生成优化的数组元素访问代码。
```

对于数组元素的访问，`access-info.cc` 会记录数组的元素类型。如果数组存储的是小整数 (Smi)，编译器就可以生成更高效的机器指令来访问这些元素。

**总结：**

`access-info.cc` 在 V8 编译器的代码生成过程中扮演着至关重要的角色。它通过收集和表示 JavaScript 对象属性和元素访问的详细信息，使得编译器能够进行更深层次的优化，从而显著提升 JavaScript 代码的执行效率。它将 JavaScript 灵活的动态特性转换为编译器可以理解和优化的静态信息，是 V8 引擎实现高性能的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/access-info.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""

// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/access-info.h"

#include <optional>
#include <ostream>

#include "src/builtins/accessors.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/heap-refs.h"
#include "src/compiler/js-heap-broker-inl.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/type-cache.h"
#include "src/ic/call-optimization.h"
#include "src/objects/cell-inl.h"
#include "src/objects/elements-kind.h"
#include "src/objects/field-index-inl.h"
#include "src/objects/field-type.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-details.h"
#include "src/objects/struct-inl.h"
#include "src/objects/templates.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {

bool CanInlinePropertyAccess(MapRef map, AccessMode access_mode) {
  // We can inline property access to prototypes of all primitives, except
  // the special Oddball ones that have no wrapper counterparts (i.e. Null,
  // Undefined and TheHole).
  // We can only inline accesses to dictionary mode holders if the access is a
  // load and the holder is a prototype. The latter ensures a 1:1
  // relationship between the map and the object (and therefore the property
  // dictionary).
  static_assert(ODDBALL_TYPE == LAST_PRIMITIVE_HEAP_OBJECT_TYPE);
  if (IsBooleanMap(*map.object())) return true;
  if (map.instance_type() < LAST_PRIMITIVE_HEAP_OBJECT_TYPE) return true;
  if (IsJSObjectMap(*map.object())) {
    if (map.is_dictionary_map()) {
      if (!V8_DICT_PROPERTY_CONST_TRACKING_BOOL) return false;
      return access_mode == AccessMode::kLoad &&
             map.object()->is_prototype_map();
    }
    return !map.object()->has_named_interceptor() &&
           // TODO(verwaest): Allowlist contexts to which we have access.
           !map.is_access_check_needed();
  }
  return false;
}

#ifdef DEBUG
bool HasFieldRepresentationDependenciesOnMap(
    ZoneVector<CompilationDependency const*>& dependencies,
    Handle<Map> const& field_owner_map) {
  for (auto dep : dependencies) {
    if (CompilationDependencies::IsFieldRepresentationDependencyOnMap(
            dep, field_owner_map)) {
      return true;
    }
  }
  return false;
}
#endif

}  // namespace

std::ostream& operator<<(std::ostream& os, AccessMode access_mode) {
  switch (access_mode) {
    case AccessMode::kLoad:
      return os << "Load";
    case AccessMode::kStore:
      return os << "Store";
    case AccessMode::kStoreInLiteral:
      return os << "StoreInLiteral";
    case AccessMode::kHas:
      return os << "Has";
    case AccessMode::kDefine:
      return os << "Define";
  }
  UNREACHABLE();
}

ElementAccessInfo::ElementAccessInfo(
    ZoneVector<MapRef>&& lookup_start_object_maps, ElementsKind elements_kind,
    Zone* zone)
    : elements_kind_(elements_kind),
      lookup_start_object_maps_(lookup_start_object_maps),
      transition_sources_(zone) {
  CHECK(!lookup_start_object_maps.empty());
}

// static
PropertyAccessInfo PropertyAccessInfo::Invalid(Zone* zone) {
  return PropertyAccessInfo(zone);
}

// static
PropertyAccessInfo PropertyAccessInfo::NotFound(Zone* zone, MapRef receiver_map,
                                                OptionalJSObjectRef holder) {
  return PropertyAccessInfo(zone, kNotFound, holder, {{receiver_map}, zone});
}

// static
PropertyAccessInfo PropertyAccessInfo::DataField(
    JSHeapBroker* broker, Zone* zone, MapRef receiver_map,
    ZoneVector<CompilationDependency const*>&& dependencies,
    FieldIndex field_index, Representation field_representation,
    Type field_type, MapRef field_owner_map, OptionalMapRef field_map,
    OptionalJSObjectRef holder, OptionalMapRef transition_map) {
  DCHECK(!field_representation.IsNone());
  DCHECK_IMPLIES(
      field_representation.IsDouble(),
      HasFieldRepresentationDependenciesOnMap(
          dependencies, transition_map.has_value() ? transition_map->object()
                        : holder.has_value() ? holder->map(broker).object()
                                             : receiver_map.object()));
  return PropertyAccessInfo(kDataField, holder, transition_map, field_index,
                            field_representation, field_type, field_owner_map,
                            field_map, {{receiver_map}, zone},
                            std::move(dependencies));
}

// static
PropertyAccessInfo PropertyAccessInfo::FastDataConstant(
    Zone* zone, MapRef receiver_map,
    ZoneVector<CompilationDependency const*>&& dependencies,
    FieldIndex field_index, Representation field_representation,
    Type field_type, MapRef field_owner_map, OptionalMapRef field_map,
    OptionalJSObjectRef holder, OptionalMapRef transition_map) {
  DCHECK(!field_representation.IsNone());
  return PropertyAccessInfo(kFastDataConstant, holder, transition_map,
                            field_index, field_representation, field_type,
                            field_owner_map, field_map, {{receiver_map}, zone},
                            std::move(dependencies));
}

// static
PropertyAccessInfo PropertyAccessInfo::FastAccessorConstant(
    Zone* zone, MapRef receiver_map, OptionalJSObjectRef holder,
    OptionalObjectRef constant, OptionalJSObjectRef api_holder) {
  return PropertyAccessInfo(zone, kFastAccessorConstant, holder, constant,
                            api_holder, {} /* name */, {{receiver_map}, zone});
}

// static
PropertyAccessInfo PropertyAccessInfo::ModuleExport(Zone* zone,
                                                    MapRef receiver_map,
                                                    CellRef cell) {
  return PropertyAccessInfo(zone, kModuleExport, {} /* holder */,
                            cell /* constant */, {} /* api_holder */,
                            {} /* name */, {{receiver_map}, zone});
}

// static
PropertyAccessInfo PropertyAccessInfo::StringLength(Zone* zone,
                                                    MapRef receiver_map) {
  return PropertyAccessInfo(zone, kStringLength, {}, {{receiver_map}, zone});
}

// static
PropertyAccessInfo PropertyAccessInfo::StringWrapperLength(
    Zone* zone, MapRef receiver_map) {
  return PropertyAccessInfo(zone, kStringWrapperLength, {},
                            {{receiver_map}, zone});
}

// static
PropertyAccessInfo PropertyAccessInfo::DictionaryProtoDataConstant(
    Zone* zone, MapRef receiver_map, JSObjectRef holder,
    InternalIndex dictionary_index, NameRef name) {
  return PropertyAccessInfo(zone, kDictionaryProtoDataConstant, holder,
                            {{receiver_map}, zone}, dictionary_index, name);
}

// static
PropertyAccessInfo PropertyAccessInfo::DictionaryProtoAccessorConstant(
    Zone* zone, MapRef receiver_map, OptionalJSObjectRef holder,
    ObjectRef constant, OptionalJSObjectRef api_holder, NameRef property_name) {
  return PropertyAccessInfo(zone, kDictionaryProtoAccessorConstant, holder,
                            constant, api_holder, property_name,
                            {{receiver_map}, zone});
}

PropertyAccessInfo::PropertyAccessInfo(Zone* zone)
    : kind_(kInvalid),
      lookup_start_object_maps_(zone),
      unrecorded_dependencies_(zone),
      field_representation_(Representation::None()),
      field_type_(Type::None()),
      dictionary_index_(InternalIndex::NotFound()) {}

PropertyAccessInfo::PropertyAccessInfo(
    Zone* zone, Kind kind, OptionalJSObjectRef holder,
    ZoneVector<MapRef>&& lookup_start_object_maps)
    : kind_(kind),
      lookup_start_object_maps_(lookup_start_object_maps),
      holder_(holder),
      unrecorded_dependencies_(zone),
      field_representation_(Representation::None()),
      field_type_(Type::None()),
      dictionary_index_(InternalIndex::NotFound()) {}

PropertyAccessInfo::PropertyAccessInfo(
    Zone* zone, Kind kind, OptionalJSObjectRef holder,
    OptionalObjectRef constant, OptionalJSObjectRef api_holder,
    OptionalNameRef name, ZoneVector<MapRef>&& lookup_start_object_maps)
    : kind_(kind),
      lookup_start_object_maps_(lookup_start_object_maps),
      constant_(constant),
      holder_(holder),
      api_holder_(api_holder),
      unrecorded_dependencies_(zone),
      field_representation_(Representation::None()),
      field_type_(Type::Any()),
      dictionary_index_(InternalIndex::NotFound()),
      name_(name) {
  DCHECK_IMPLIES(kind == kDictionaryProtoAccessorConstant, name.has_value());
}

PropertyAccessInfo::PropertyAccessInfo(
    Kind kind, OptionalJSObjectRef holder, OptionalMapRef transition_map,
    FieldIndex field_index, Representation field_representation,
    Type field_type, MapRef field_owner_map, OptionalMapRef field_map,
    ZoneVector<MapRef>&& lookup_start_object_maps,
    ZoneVector<CompilationDependency const*>&& unrecorded_dependencies)
    : kind_(kind),
      lookup_start_object_maps_(lookup_start_object_maps),
      holder_(holder),
      unrecorded_dependencies_(std::move(unrecorded_dependencies)),
      transition_map_(transition_map),
      field_index_(field_index),
      field_representation_(field_representation),
      field_type_(field_type),
      field_owner_map_(field_owner_map),
      field_map_(field_map),
      dictionary_index_(InternalIndex::NotFound()) {
  DCHECK_IMPLIES(transition_map.has_value(),
                 field_owner_map.equals(transition_map.value()));
}

PropertyAccessInfo::PropertyAccessInfo(
    Zone* zone, Kind kind, OptionalJSObjectRef holder,
    ZoneVector<MapRef>&& lookup_start_object_maps,
    InternalIndex dictionary_index, NameRef name)
    : kind_(kind),
      lookup_start_object_maps_(lookup_start_object_maps),
      holder_(holder),
      unrecorded_dependencies_(zone),
      field_representation_(Representation::None()),
      field_type_(Type::Any()),
      dictionary_index_(dictionary_index),
      name_{name} {}

namespace {

template <class RefT>
bool OptionalRefEquals(OptionalRef<RefT> lhs, OptionalRef<RefT> rhs) {
  if (!lhs.has_value()) return !rhs.has_value();
  if (!rhs.has_value()) return false;
  return lhs->equals(rhs.value());
}

template <class T>
void AppendVector(ZoneVector<T>* dst, const ZoneVector<T>& src) {
  dst->insert(dst->end(), src.begin(), src.end());
}

}  // namespace

bool PropertyAccessInfo::Merge(PropertyAccessInfo const* that,
                               AccessMode access_mode, Zone* zone) {
  if (kind_ != that->kind_) return false;
  if (!OptionalRefEquals(holder_, that->holder_)) return false;

  switch (kind_) {
    case kInvalid:
      DCHECK_EQ(that->kind_, kInvalid);
      return true;

    case kDataField:
    case kFastDataConstant: {
      // Check if we actually access the same field (we use the
      // GetFieldAccessStubKey method here just like the ICs do
      // since that way we only compare the relevant bits of the
      // field indices).
      if (field_index_.GetFieldAccessStubKey() !=
          that->field_index_.GetFieldAccessStubKey()) {
        return false;
      }

      switch (access_mode) {
        case AccessMode::kHas:
        case AccessMode::kLoad: {
          if (!field_representation_.Equals(that->field_representation_)) {
            if (field_representation_.IsDouble() ||
                that->field_representation_.IsDouble()) {
              return false;
            }
            field_representation_ = Representation::Tagged();
          }
          if (!OptionalRefEquals(field_map_, that->field_map_)) {
            field_map_ = {};
          }
          break;
        }
        case AccessMode::kStore:
        case AccessMode::kStoreInLiteral:
        case AccessMode::kDefine: {
          // For stores, the field map and field representation information
          // must match exactly, otherwise we cannot merge the stores. We
          // also need to make sure that in case of transitioning stores,
          // the transition targets match.
          if (!OptionalRefEquals(field_map_, that->field_map_) ||
              !field_representation_.Equals(that->field_representation_) ||
              !OptionalRefEquals(transition_map_, that->transition_map_)) {
            return false;
          }
          break;
        }
      }

      field_type_ = Type::Union(field_type_, that->field_type_, zone);
      AppendVector(&lookup_start_object_maps_, that->lookup_start_object_maps_);
      AppendVector(&unrecorded_dependencies_, that->unrecorded_dependencies_);
      return true;
    }

    case kDictionaryProtoAccessorConstant:
    case kFastAccessorConstant: {
      // Check if we actually access the same constant.
      if (!OptionalRefEquals(constant_, that->constant_)) return false;

      DCHECK(unrecorded_dependencies_.empty());
      DCHECK(that->unrecorded_dependencies_.empty());
      AppendVector(&lookup_start_object_maps_, that->lookup_start_object_maps_);
      return true;
    }

    case kDictionaryProtoDataConstant: {
      DCHECK_EQ(AccessMode::kLoad, access_mode);
      if (dictionary_index_ != that->dictionary_index_) return false;
      AppendVector(&lookup_start_object_maps_, that->lookup_start_object_maps_);
      return true;
    }

    case kNotFound:
    case kStringLength:
    case kStringWrapperLength: {
      DCHECK(unrecorded_dependencies_.empty());
      DCHECK(that->unrecorded_dependencies_.empty());
      AppendVector(&lookup_start_object_maps_, that->lookup_start_object_maps_);
      return true;
    }
    case kModuleExport:
      return false;
  }
}

ConstFieldInfo PropertyAccessInfo::GetConstFieldInfo() const {
  return IsFastDataConstant() ? ConstFieldInfo(*field_owner_map_)
                              : ConstFieldInfo::None();
}

AccessInfoFactory::AccessInfoFactory(JSHeapBroker* broker, Zone* zone)
    : broker_(broker), type_cache_(TypeCache::Get()), zone_(zone) {}

std::optional<ElementAccessInfo> AccessInfoFactory::ComputeElementAccessInfo(
    MapRef map, AccessMode access_mode) const {
  if (!map.CanInlineElementAccess()) return {};
  return ElementAccessInfo({{map}, zone()}, map.elements_kind(), zone());
}

bool AccessInfoFactory::ComputeElementAccessInfos(
    ElementAccessFeedback const& feedback,
    ZoneVector<ElementAccessInfo>* access_infos) const {
  AccessMode access_mode = feedback.keyed_mode().access_mode();
  if (access_mode == AccessMode::kLoad || access_mode == AccessMode::kHas) {
    // For polymorphic loads of similar elements kinds (i.e. all tagged or all
    // double), always use the "worst case" code without a transition.  This is
    // much faster than transitioning the elements to the worst case, trading a
    // TransitionElementsKind for a CheckMaps, avoiding mutation of the array.
    std::optional<ElementAccessInfo> access_info =
        ConsolidateElementLoad(feedback);
    if (access_info.has_value()) {
      access_infos->push_back(*access_info);
      return true;
    }
  }

  for (auto const& group : feedback.transition_groups()) {
    DCHECK(!group.empty());
    OptionalMapRef target = group.front();
    std::optional<ElementAccessInfo> access_info =
        ComputeElementAccessInfo(target.value(), access_mode);
    if (!access_info.has_value()) return false;

    for (size_t i = 1; i < group.size(); ++i) {
      OptionalMapRef map_ref = group[i];
      if (!map_ref.has_value()) continue;
      access_info->AddTransitionSource(map_ref.value());
    }
    access_infos->push_back(*access_info);
  }
  return true;
}

PropertyAccessInfo AccessInfoFactory::ComputeDataFieldAccessInfo(
    MapRef receiver_map, MapRef map, NameRef name, OptionalJSObjectRef holder,
    InternalIndex descriptor, AccessMode access_mode) const {
  DCHECK(descriptor.is_found());
  // TODO(jgruber,v8:7790): Use DescriptorArrayRef instead.
  DirectHandle<DescriptorArray> descriptors =
      map.instance_descriptors(broker()).object();
  PropertyDetails const details = descriptors->GetDetails(descriptor);
  int index = descriptors->GetFieldIndex(descriptor);
  Representation details_representation = details.representation();
  if (details_representation.IsNone()) {
    // The ICs collect feedback in PREMONOMORPHIC state already,
    // but at this point the {receiver_map} might still contain
    // fields for which the representation has not yet been
    // determined by the runtime. So we need to catch this case
    // here and fall back to use the regular IC logic instead.
    return Invalid();
  }
  FieldIndex field_index = FieldIndex::ForPropertyIndex(*map.object(), index,
                                                        details_representation);
  // Private brands are used when loading private methods, which are stored in a
  // BlockContext, an internal object.
  Type field_type = name.object()->IsPrivateBrand() ? Type::OtherInternal()
                                                    : Type::NonInternal();
  OptionalMapRef field_map;

  ZoneVector<CompilationDependency const*> unrecorded_dependencies(zone());

  Handle<FieldType> descriptors_field_type =
      broker()->CanonicalPersistentHandle(
          descriptors->GetFieldType(descriptor));
  OptionalObjectRef descriptors_field_type_ref =
      TryMakeRef<Object>(broker(), descriptors_field_type);
  if (!descriptors_field_type_ref.has_value()) return Invalid();

  // Note: FindFieldOwner may be called multiple times throughout one
  // compilation. This is safe since its result is fixed for a given map and
  // descriptor.
  MapRef field_owner_map = map.FindFieldOwner(broker(), descriptor);

  if (details_representation.IsSmi()) {
    field_type = Type::SignedSmall();
    unrecorded_dependencies.push_back(
        dependencies()->FieldRepresentationDependencyOffTheRecord(
            map, field_owner_map, descriptor, details_representation));
  } else if (details_representation.IsDouble()) {
    field_type = type_cache_->kFloat64;
    unrecorded_dependencies.push_back(
        dependencies()->FieldRepresentationDependencyOffTheRecord(
            map, field_owner_map, descriptor, details_representation));
  } else if (details_representation.IsHeapObject()) {
    if (IsNone(*descriptors_field_type)) {
      // Cleared field-types are pre-monomorphic states. The field type was
      // garbge collected and we need to record an updated type.
      static_assert(FieldType::kFieldTypesCanBeClearedOnGC);
      switch (access_mode) {
        case AccessMode::kStore:
        case AccessMode::kStoreInLiteral:
        case AccessMode::kDefine:
          return Invalid();
        case AccessMode::kLoad:
        case AccessMode::kHas:
          break;
      }
    }
    unrecorded_dependencies.push_back(
        dependencies()->FieldRepresentationDependencyOffTheRecord(
            map, field_owner_map, descriptor, details_representation));
    if (IsClass(*descriptors_field_type)) {
      // Remember the field map, and try to infer a useful type.
      OptionalMapRef maybe_field_map =
          TryMakeRef(broker(), FieldType::AsClass(*descriptors_field_type));
      if (!maybe_field_map.has_value()) return Invalid();
      field_type = Type::For(maybe_field_map.value(), broker());
      field_map = maybe_field_map;
    }
  } else {
    CHECK(details_representation.IsTagged());
  }
  // TODO(turbofan): We may want to do this only depending on the use
  // of the access info.
  unrecorded_dependencies.push_back(
      dependencies()->FieldTypeDependencyOffTheRecord(
          map, field_owner_map, descriptor,
          descriptors_field_type_ref.value()));

  PropertyConstness constness =
      dependencies()->DependOnFieldConstness(map, field_owner_map, descriptor);

  switch (constness) {
    case PropertyConstness::kMutable:
      return PropertyAccessInfo::DataField(
          broker(), zone(), receiver_map, std::move(unrecorded_dependencies),
          field_index, details_representation, field_type, field_owner_map,
          field_map, holder, {});

    case PropertyConstness::kConst:
      return PropertyAccessInfo::FastDataConstant(
          zone(), receiver_map, std::move(unrecorded_dependencies), field_index,
          details_representation, field_type, field_owner_map, field_map,
          holder, {});
  }
  UNREACHABLE();
}

namespace {

using AccessorsObjectGetter = std::function<Handle<Object>()>;

PropertyAccessInfo AccessorAccessInfoHelper(
    Isolate* isolate, Zone* zone, JSHeapBroker* broker,
    const AccessInfoFactory* ai_factory, MapRef receiver_map, NameRef name,
    MapRef holder_map, OptionalJSObjectRef holder, AccessMode access_mode,
    AccessorsObjectGetter get_accessors) {
  if (holder_map.instance_type() == JS_MODULE_NAMESPACE_TYPE) {
    DCHECK(holder_map.object()->is_prototype_map());
    DirectHandle<PrototypeInfo> proto_info = broker->CanonicalPersistentHandle(
        Cast<PrototypeInfo>(holder_map.object()->prototype_info()));
    DirectHandle<JSModuleNamespace> module_namespace =
        broker->CanonicalPersistentHandle(
            Cast<JSModuleNamespace>(proto_info->module_namespace()));
    Handle<Cell> cell = broker->CanonicalPersistentHandle(
        Cast<Cell>(module_namespace->module()->exports()->Lookup(
            isolate, name.object(),
            Smi::ToInt(Object::GetHash(*name.object())))));
    if (IsAnyStore(access_mode)) {
      // ES#sec-module-namespace-exotic-objects-set-p-v-receiver
      // ES#sec-module-namespace-exotic-objects-defineownproperty-p-desc
      //
      // Storing to a module namespace object is always an error or a no-op in
      // JS.
      return PropertyAccessInfo::Invalid(zone);
    }
    if (IsTheHole(cell->value(kRelaxedLoad), isolate)) {
      // This module has not been fully initialized yet.
      return PropertyAccessInfo::Invalid(zone);
    }
    OptionalCellRef cell_ref = TryMakeRef(broker, cell);
    if (!cell_ref.has_value()) {
      return PropertyAccessInfo::Invalid(zone);
    }
    return PropertyAccessInfo::ModuleExport(zone, receiver_map,
                                            cell_ref.value());
  }
  if (access_mode == AccessMode::kHas) {
    // kHas is not supported for dictionary mode objects.
    DCHECK(!holder_map.is_dictionary_map());

    // HasProperty checks don't call getter/setters, existence is sufficient.
    return PropertyAccessInfo::FastAccessorConstant(zone, receiver_map, holder,
                                                    {}, {});
  }
  Handle<Object> maybe_accessors = get_accessors();
  if (!IsAccessorPair(*maybe_accessors)) {
    return PropertyAccessInfo::Invalid(zone);
  }
  DirectHandle<AccessorPair> accessors = Cast<AccessorPair>(maybe_accessors);
  Handle<Object> accessor = broker->CanonicalPersistentHandle(
      access_mode == AccessMode::kLoad ? accessors->getter(kAcquireLoad)
                                       : accessors->setter(kAcquireLoad));

  OptionalObjectRef accessor_ref = TryMakeRef(broker, accessor);
  if (!accessor_ref.has_value()) return PropertyAccessInfo::Invalid(zone);

  OptionalJSObjectRef api_holder_ref;
  if (!IsJSFunction(*accessor)) {
    CallOptimization optimization(broker->local_isolate_or_isolate(), accessor);
    if (!optimization.is_simple_api_call() ||
        optimization.IsCrossContextLazyAccessorPair(
            *broker->target_native_context().object(), *holder_map.object())) {
      return PropertyAccessInfo::Invalid(zone);
    }
    if (DEBUG_BOOL && holder.has_value()) {
      std::optional<Tagged<NativeContext>> holder_creation_context =
          holder->object()->GetCreationContext();
      CHECK(holder_creation_context.has_value());
      CHECK_EQ(*broker->target_native_context().object(),
               holder_creation_context.value());
    }

    CallOptimization::HolderLookup holder_lookup;
    Handle<JSObject> api_holder = broker->CanonicalPersistentHandle(
        optimization.LookupHolderOfExpectedType(
            broker->local_isolate_or_isolate(), receiver_map.object(),
            &holder_lookup));
    if (holder_lookup == CallOptimization::kHolderNotFound) {
      return PropertyAccessInfo::Invalid(zone);
    }
    DCHECK_IMPLIES(holder_lookup == CallOptimization::kHolderIsReceiver,
                   api_holder.is_null());
    DCHECK_IMPLIES(holder_lookup == CallOptimization::kHolderFound,
                   !api_holder.is_null());

    if (!api_holder.is_null()) {
      api_holder_ref = TryMakeRef(broker, api_holder);
      if (!api_holder_ref.has_value()) return PropertyAccessInfo::Invalid(zone);
    }
  }
  if (access_mode == AccessMode::kLoad) {
    std::optional<Tagged<Name>> cached_property_name =
        FunctionTemplateInfo::TryGetCachedPropertyName(isolate, *accessor);
    if (cached_property_name.has_value()) {
      OptionalNameRef cached_property_name_ref =
          TryMakeRef(broker, cached_property_name.value());
      if (cached_property_name_ref.has_value()) {
        PropertyAccessInfo access_info = ai_factory->ComputePropertyAccessInfo(
            holder_map, cached_property_name_ref.value(), access_mode);
        if (!access_info.IsInvalid()) return access_info;
      }
    }
  }

  if (holder_map.is_dictionary_map()) {
    CHECK(!api_holder_ref.has_value());
    return PropertyAccessInfo::DictionaryProtoAccessorConstant(
        zone, receiver_map, holder, accessor_ref.value(), api_holder_ref, name);
  } else {
    return PropertyAccessInfo::FastAccessorConstant(
        zone, receiver_map, holder, accessor_ref.value(), api_holder_ref);
  }
}

}  // namespace

PropertyAccessInfo AccessInfoFactory::ComputeAccessorDescriptorAccessInfo(
    MapRef receiver_map, NameRef name, MapRef holder_map,
    OptionalJSObjectRef holder, InternalIndex descriptor,
    AccessMode access_mode) const {
  DCHECK(descriptor.is_found());
  Handle<DescriptorArray> descriptors = broker()->CanonicalPersistentHandle(
      holder_map.object()->instance_descriptors(kRelaxedLoad));
  SLOW_DCHECK(descriptor ==
              descriptors->Search(*name.object(), *holder_map.object(), true));

  auto get_accessors = [&]() {
    return broker()->CanonicalPersistentHandle(
        descriptors->GetStrongValue(descriptor));
  };
  return AccessorAccessInfoHelper(isolate(), zone(), broker(), this,
                                  receiver_map, name, holder_map, holder,
                                  access_mode, get_accessors);
}

PropertyAccessInfo AccessInfoFactory::ComputeDictionaryProtoAccessInfo(
    MapRef receiver_map, NameRef name, JSObjectRef holder,
    InternalIndex dictionary_index, AccessMode access_mode,
    PropertyDetails details) const {
  CHECK(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);
  DCHECK(holder.map(broker()).object()->is_prototype_map());
  DCHECK_EQ(access_mode, AccessMode::kLoad);

  // We can only inline accesses to constant properties.
  if (details.constness() != PropertyConstness::kConst) {
    return Invalid();
  }

  if (details.kind() == PropertyKind::kData) {
    return PropertyAccessInfo::DictionaryProtoDataConstant(
        zone(), receiver_map, holder, dictionary_index, name);
  }

  auto get_accessors = [&]() {
    return JSObject::DictionaryPropertyAt(isolate(), holder.object(),
                                          dictionary_index);
  };
  return AccessorAccessInfoHelper(isolate(), zone(), broker(), this,
                                  receiver_map, name, holder.map(broker()),
                                  holder, access_mode, get_accessors);
}

bool AccessInfoFactory::TryLoadPropertyDetails(
    MapRef map, OptionalJSObjectRef maybe_holder, NameRef name,
    InternalIndex* index_out, PropertyDetails* details_out) const {
  if (map.is_dictionary_map()) {
    DCHECK(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);
    DCHECK(map.object()->is_prototype_map());

    DisallowGarbageCollection no_gc;

    if (!maybe_holder.has_value()) {
      // TODO(v8:11457) In this situation, we have a dictionary mode prototype
      // as a receiver. Consider other means of obtaining the holder in this
      // situation.

      // Without the holder, we can't get the property details.
      return false;
    }

    DirectHandle<JSObject> holder = maybe_holder->object();
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Tagged<SwissNameDictionary> dict = holder->property_dictionary_swiss();
      *index_out = dict->FindEntry(isolate(), name.object());
      if (index_out->is_found()) {
        *details_out = dict->DetailsAt(*index_out);
      }
    } else {
      Tagged<NameDictionary> dict = holder->property_dictionary();
      *index_out = dict->FindEntry(isolate(), name.object());
      if (index_out->is_found()) {
        *details_out = dict->DetailsAt(*index_out);
      }
    }
  } else {
    Tagged<DescriptorArray> descriptors =
        *map.instance_descriptors(broker()).object();
    *index_out = descriptors->Search(*name.object(), *map.object(), true);
    if (index_out->is_found()) {
      *details_out = descriptors->GetDetails(*index_out);
    }
  }

  return true;
}

PropertyAccessInfo AccessInfoFactory::ComputePropertyAccessInfo(
    MapRef map, NameRef name, AccessMode access_mode) const {
  CHECK(name.IsUniqueName());

  // Dictionary property const tracking is unsupported with concurrent inlining.
  CHECK(!V8_DICT_PROPERTY_CONST_TRACKING_BOOL);

  JSHeapBroker::MapUpdaterGuardIfNeeded mumd_scope(broker());

  if (access_mode == AccessMode::kHas && !IsJSReceiverMap(*map.object())) {
    return Invalid();
  }

  // Check if it is safe to inline property access for the {map}.
  if (!CanInlinePropertyAccess(map, access_mode)) {
    return Invalid();
  }

  // We support fast inline cases for certain JSObject getters.
  if (access_mode == AccessMode::kLoad || access_mode == AccessMode::kHas) {
    PropertyAccessInfo access_info = LookupSpecialFieldAccessor(map, name);
    if (!access_info.IsInvalid()) return access_info;
  }

  // Only relevant if V8_DICT_PROPERTY_CONST_TRACKING enabled.
  bool dictionary_prototype_on_chain = false;
  bool fast_mode_prototype_on_chain = false;

  // Remember the receiver map. We use {map} as loop variable.
  MapRef receiver_map = map;
  OptionalJSObjectRef holder;

  // Perform the implicit ToObject for primitives here.
  // Implemented according to ES6 section 7.3.2 GetV (V, P).
  // Note: Keep sync'd with
  // CompilationDependencies::DependOnStablePrototypeChains.
  if (receiver_map.IsPrimitiveMap()) {
    OptionalJSFunctionRef constructor =
        broker()->target_native_context().GetConstructorFunction(broker(),
                                                                 receiver_map);
    if (!constructor.has_value()) return Invalid();
    map = constructor->initial_map(broker());
    DCHECK(!map.IsPrimitiveMap());
  }

  while (true) {
    PropertyDetails details = PropertyDetails::Empty();
    InternalIndex index = InternalIndex::NotFound();
    if (!TryLoadPropertyDetails(map, holder, name, &index, &details)) {
      return Invalid();
    }

    if (index.is_found()) {
      if (IsAnyStore(access_mode)) {
        DCHECK(!map.is_dictionary_map());

        // Don't bother optimizing stores to read-only properties.
        if (details.IsReadOnly()) return Invalid();

        if (details.kind() == PropertyKind::kData && holder.has_value()) {
          // This is a store to a property not found on the receiver but on a
          // prototype. According to ES6 section 9.1.9 [[Set]], we need to
          // create a new data property on the receiver. We can still optimize
          // if such a transition already exists.
          return LookupTransition(receiver_map, name, holder, NONE);
        }
      }

      if (IsDefiningStore(access_mode)) {
        if (details.attributes() != PropertyAttributes::NONE) {
          // We should store the property with WEC attributes, but that's not
          // the attributes of the property that we found. We just bail out and
          // let the runtime figure out what to do (which probably requires
          // changing the object's map).
          return Invalid();
        }
      }

      if (map.is_dictionary_map()) {
        DCHECK(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);

        if (fast_mode_prototype_on_chain) {
          // TODO(v8:11248) While the work on dictionary mode prototypes is in
          // progress, we may still see fast mode objects on the chain prior to
          // reaching a dictionary mode prototype holding the property . Due to
          // this only being an intermediate state, we don't stupport these kind
          // of heterogenous prototype chains.
          return Invalid();
        }

        // TryLoadPropertyDetails only succeeds if we know the holder.
        return ComputeDictionaryProtoAccessInfo(
            receiver_map, name, holder.value(), index, access_mode, details);
      }

      if (dictionary_prototype_on_chain) {
        // If V8_DICT_PROPERTY_CONST_TRACKING_BOOL was disabled, then a
        // dictionary prototype would have caused a bailout earlier.
        DCHECK(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);

        // TODO(v8:11248) We have a fast mode holder, but there was a dictionary
        // mode prototype earlier on the chain. Note that seeing a fast mode
        // prototype even though V8_DICT_PROPERTY_CONST_TRACKING is enabled
        // should only be possible while the implementation of dictionary mode
        // prototypes is work in progress. Eventually, enabling
        // V8_DICT_PROPERTY_CONST_TRACKING will guarantee that all prototypes
        // are always in dictionary mode, making this case unreachable. However,
        // due to the complications of checking dictionary mode prototypes for
        // modification, we don't attempt to support dictionary mode prototypes
        // occuring before a fast mode holder on the chain.
        return Invalid();
      }
      if (details.location() == PropertyLocation::kField) {
        if (details.kind() == PropertyKind::kData) {
          return ComputeDataFieldAccessInfo(receiver_map, map, name, holder,
                                            index, access_mode);
        } else {
          DCHECK_EQ(PropertyKind::kAccessor, details.kind());
          // TODO(turbofan): Add support for general accessors?
          return Invalid();
        }
      } else {
        DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        return ComputeAccessorDescriptorAccessInfo(receiver_map, name, map,
                                                   holder, index, access_mode);
      }

      UNREACHABLE();
    }

    // The property wasn't found on {map}. Look on the prototype if appropriate.
    DCHECK(!index.is_found());

    // Don't search on the prototype chain for special indices in case of
    // integer indexed exotic objects (see ES6 section 9.4.5).
    if (IsJSTypedArrayMap(*map.object()) && name.IsString()) {
      StringRef name_str = name.AsString();
      SharedStringAccessGuardIfNeeded access_guard(
          *name_str.object(), broker()->local_isolate_or_isolate());
      if (IsSpecialIndex(*name_str.object(), access_guard)) return Invalid();
    }

    // Don't search on the prototype when storing in literals, or performing a
    // Define operation
    if (access_mode == AccessMode::kStoreInLiteral ||
        access_mode == AccessMode::kDefine) {
      PropertyAttributes attrs = NONE;
      if (name.object()->IsPrivate()) {
        // When PrivateNames are added to an object, they are by definition
        // non-enumerable.
        attrs = DONT_ENUM;
      }
      return LookupTransition(receiver_map, name, holder, attrs);
    }

    // Don't lookup private symbols on the prototype chain.
    if (name.object()->IsPrivate()) {
      return Invalid();
    }

    if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL && holder.has_value()) {
      // At this point, we are past the first loop iteration.
      DCHECK(holder->object()->map()->is_prototype_map());
      DCHECK(!holder->map(broker()).equals(receiver_map));

      fast_mode_prototype_on_chain =
          fast_mode_prototype_on_chain || !map.is_dictionary_map();
      dictionary_prototype_on_chain =
          dictionary_prototype_on_chain || map.is_dictionary_map();
    }

    // Walk up the prototype chain.
    // Load the map's prototype's map to guarantee that every time we use it,
    // we use the same Map.
    HeapObjectRef prototype = map.prototype(broker());

    MapRef map_prototype_map = prototype.map(broker());
    if (!IsJSObjectMap(*map_prototype_map.object())) {
      // Don't allow proxies on the prototype chain.
      if (!prototype.IsNull()) {
        DCHECK(IsJSProxy(*prototype.object()) ||
               IsWasmObject(*prototype.object()));
        return Invalid();
      }

      DCHECK(prototype.IsNull());

      if (dictionary_prototype_on_chain) {
        // TODO(v8:11248) See earlier comment about
        // dictionary_prototype_on_chain. We don't support absent properties
        // with dictionary mode prototypes on the chain, either. This is again
        // just due to how we currently deal with dependencies for dictionary
        // properties during finalization.
        return Invalid();
      }

      // Store to property not found on the receiver or any prototype, we need
      // to transition to a new data property.
      // Implemented according to ES6 section 9.1.9 [[Set]] (P, V, Receiver)
      if (access_mode == AccessMode::kStore) {
        return LookupTransition(receiver_map, name, holder, NONE);
      }

      // The property was not found (access returns undefined or throws
      // depending on the language mode of the load operation.
      // Implemented according to ES6 section 9.1.8 [[Get]] (P, Receiver)
      return PropertyAccessInfo::NotFound(zone(), receiver_map, holder);
    }

    CHECK(prototype.IsJSObject());
    holder = prototype.AsJSObject();
    map = map_prototype_map;

    if (!CanInlinePropertyAccess(map, access_mode)) {
      return Invalid();
    }

    // Successful lookup on prototype chain needs to guarantee that all the
    // prototypes up to the holder have stable maps, except for dictionary-mode
    // prototypes. We currently do this by taking a
    // DependOnStablePrototypeChains dependency in the caller.
    //
    // TODO(jgruber): This is brittle and easy to miss. Consider a refactor
    // that moves the responsibility of taking the dependency into
    // AccessInfoFactory.
  }
  UNREACHABLE();
}

PropertyAccessInfo AccessInfoFactory::FinalizePropertyAccessInfosAsOne(
    ZoneVector<PropertyAccessInfo> access_infos, AccessMode access_mode) const {
  ZoneVector<PropertyAccessInfo> merged_access_infos(zone());
  MergePropertyAccessInfos(access_infos, access_mode, &merged_access_infos);
  if (merged_access_infos.size() == 1) {
    PropertyAccessInfo& result = merged_access_infos.front();
    if (!result.IsInvalid()) {
      result.RecordDependencies(dependencies());
      return result;
    }
  }
  return Invalid();
}

void PropertyAccessInfo::RecordDependencies(
    CompilationDependencies* dependencies) {
  for (CompilationDependency const* d : unrecorded_dependencies_) {
    dependencies->RecordDependency(d);
  }
  unrecorded_dependencies_.clear();
}

bool AccessInfoFactory::FinalizePropertyAccessInfos(
    ZoneVector<PropertyAccessInfo> access_infos, AccessMode access_mode,
    ZoneVector<PropertyAccessInfo>* result) const {
  if (access_infos.empty()) return false;
  MergePropertyAccessInfos(access_infos, access_mode, result);
  for (PropertyAccessInfo const& info : *result) {
    if (info.IsInvalid()) return false;
  }
  for (PropertyAccessInfo& info : *result) {
    info.RecordDependencies(dependencies());
  }
  return true;
}

void AccessInfoFactory::MergePropertyAccessInfos(
    ZoneVector<PropertyAccessInfo> infos, AccessMode access_mode,
    ZoneVector<PropertyAccessInfo>* result) const {
  DCHECK(result->empty());
  for (auto it = infos.begin(), end = infos.end(); it != end; ++it) {
    bool merged = false;
    for (auto ot = it + 1; ot != end; ++ot) {
      if (ot->Merge(&(*it), access_mode, zone())) {
        merged = true;
        break;
      }
    }
    if (!merged) result->push_back(*it);
  }
  CHECK(!result->empty());
}

CompilationDependencies* AccessInfoFactory::dependencies() const {
  return broker()->dependencies();
}
Isolate* AccessInfoFactory::isolate() const { return broker()->isolate(); }

namespace {

Maybe<ElementsKind> GeneralizeElementsKind(ElementsKind this_kind,
                                           ElementsKind that_kind) {
  if (IsHoleyElementsKind(this_kind)) {
    that_kind = GetHoleyElementsKind(that_kind);
  } else if (IsHoleyElementsKind(that_kind)) {
    this_kind = GetHoleyElementsKind(this_kind);
  }
  if (this_kind == that_kind) return Just(this_kind);
  if (IsDoubleElementsKind(that_kind) == IsDoubleElementsKind(this_kind)) {
    if (IsMoreGeneralElementsKindTransition(that_kind, this_kind)) {
      return Just(this_kind);
    }
    if (IsMoreGeneralElementsKindTransition(this_kind, that_kind)) {
      return Just(that_kind);
    }
  }
  return Nothing<ElementsKind>();
}

}  // namespace

std::optional<ElementAccessInfo> AccessInfoFactory::ConsolidateElementLoad(
    ElementAccessFeedback const& feedback) const {
  if (feedback.transition_groups().empty()) return {};

  DCHECK(!feedback.transition_groups().front().empty());
  MapRef first_map = feedback.transition_groups().front().front();
  InstanceType instance_type = first_map.instance_type();
  ElementsKind elements_kind = first_map.elements_kind();

  ZoneVector<MapRef> maps(zone());
  for (auto const& group : feedback.transition_groups()) {
    for (MapRef map : group) {
      if (map.instance_type() != instance_type ||
          !map.CanInlineElementAccess()) {
        return {};
      }
      if (!GeneralizeElementsKind(elements_kind, map.elements_kind())
               .To(&elements_kind)) {
        return {};
      }
      maps.push_back(map);
    }
  }

  return ElementAccessInfo(std::move(maps), elements_kind, zone());
}

PropertyAccessInfo AccessInfoFactory::LookupSpecialFieldAccessor(
    MapRef map, NameRef name) const {
  // Check for String::length field accessor.
  if (IsStringMap(*map.object())) {
    if (Name::Equals(isolate(), name.object(),
                     isolate()->factory()->length_string())) {
      return PropertyAccessInfo::StringLength(zone(), map);
    }
    return Invalid();
  }
  if (IsJSPrimitiveWrapperMap(*map.object()) &&
      (map.elements_kind() == FAST_STRING_WRAPPER_ELEMENTS ||
       map.elements_kind() == SLOW_STRING_WRAPPER_ELEMENTS)) {
    if (Name::Equals(isolate(), name.object(),
                     isolate()->factory()->length_string())) {
      return PropertyAccessInfo::StringWrapperLength(zone(), map);
    }
  }
  // Check for special JSObject field accessors.
  FieldIndex field_index;
  if (Accessors::IsJSObjectFieldAccessor(isolate(), map.object(), name.object(),
                                         &field_index)) {
    Type field_type = Type::NonInternal();
    Representation field_representation = Representation::Tagged();
    if (IsJSArrayMap(*map.object())) {
      DCHECK(Name::Equals(isolate(), isolate()->factory()->length_string(),
                          name.object()));
      // The JSArray::length property is a smi in the range
      // [0, FixedDoubleArray::kMaxLength] in case of fast double
      // elements, a smi in the range [0, FixedArray::kMaxLength]
      // in case of other fast elements, and [0, kMaxUInt32] in
      // case of other arrays.
      if (IsDoubleElementsKind(map.elements_kind())) {
        field_type = type_cache_->kFixedDoubleArrayLengthType;
        field_representation = Representation::Smi();
      } else if (IsFastElementsKind(map.elements_kind())) {
        field_type = type_cache_->kFixedArrayLengthType;
        field_representation = Representation::Smi();
      } else {
        field_type = type_cache_->kJSArrayLengthType;
      }
    }
    // Special fields are always mutable.
    return PropertyAccessInfo::DataField(broker(), zone(), map, {{}, zone()},
                                         field_index, field_representation,
                                         field_type, map, {}, {}, {});
  }
  return Invalid();
}

PropertyAccessInfo AccessInfoFactory::LookupTransition(
    MapRef map, NameRef name, OptionalJSObjectRef holder,
    PropertyAttributes attrs) const {
  // Check if the {map} has a data transition with the given {name}.
  Tagged<Map> transition =
      TransitionsAccessor(isolate(), *map.object(), true)
          .SearchTransition(*name.object(), PropertyKind::kData, attrs);
  if (transition.is_null()) return Invalid();
  OptionalMapRef maybe_transition_map = TryMakeRef(broker(), transition);
  if (!maybe_transition_map.has_value()) return Invalid();
  MapRef transition_map = maybe_transition_map.value();

  InternalIndex const number = transition_map.object()->LastAdded();
  DirectHandle<DescriptorArray> descriptors =
      transition_map.instance_descriptors(broker()).object();
  PropertyDetails const details = descriptors->GetDetails(number);

  // Don't bother optimizing stores to read-only properties.
  if (details.IsReadOnly()) return Invalid();

  // TODO(bmeurer): Handle transition to data constant?
  if (details.location() != PropertyLocation::kField) return Invalid();

  int const index = details.field_index();
  Representation details_representation = details.representation();
  if (details_representation.IsNone()) return Invalid();

  FieldIndex field_index = FieldIndex::ForPropertyIndex(
      *transition_map.object(), index, details_representation);
  Type field_type = Type::NonInternal();
  OptionalMapRef field_map;

  DCHECK_EQ(transition_map, transition_map.FindFieldOwner(broker(), number));

  ZoneVector<CompilationDependency const*> unrecorded_dependencies(zone());
  if (details_representation.IsSmi()) {
    field_type = Type::SignedSmall();
    unrecorded_dependencies.push_back(
        dependencies()->FieldRepresentationDependencyOffTheRecord(
            transition_map, transition_map, number, details_representation));
  } else if (details_representation.IsDouble()) {
    field_type = type_cache_->kFloat64;
    unrecorded_dependencies.push_back(
        dependencies()->FieldRepresentationDependencyOffTheRecord(
            transition_map, transition_map, number, details_representation));
  } else if (details_representation.IsHeapObject()) {
    // Extract the field type from the property details (make sure its
    // representation is TaggedPointer to reflect the heap object case).
    // TODO(jgruber,v8:7790): Use DescriptorArrayRef instead.
    Handle<FieldType> descriptors_field_type =
        broker()->CanonicalPersistentHandle(descriptors->GetFieldType(number));
    OptionalObjectRef descriptors_field_type_ref =
        TryMakeRef<Object>(broker(), descriptors_field_type);
    if (!descriptors_field_type_ref.has_value()) return Invalid();

    if (IsNone(*descriptors_field_type)) {
      // Cleared field-types are pre-monomorphic states. The field type was
      // garbge collected and we need to record an updated type.
      static_assert(FieldType::kFieldTypesCanBeClearedOnGC);
      return Invalid();
    }
    unrecorded_dependencies.push_back(
        dependencies()->FieldRepresentationDependencyOffTheRecord(
            transition_map, transition_map, number, details_representation));
    if (IsClass(*descriptors_field_type)) {
      unrecorded_dependencies.push_back(
          dependencies()->FieldTypeDependencyOffTheRecord(
              transition_map, transition_map, number,
              *descriptors_field_type_ref));
      // Remember the field map, and try to infer a useful type.
      OptionalMapRef maybe_field_map =
          TryMakeRef(broker(), FieldType::AsClass(*descriptors_field_type));
      if (!maybe_field_map.has_value()) return Invalid();
      field_type = Type::For(maybe_field_map.value(), broker());
      field_map = maybe_field_map;
    }
  }

  unrecorded_dependencies.push_back(
      dependencies()->TransitionDependencyOffTheRecord(transition_map));
  // Transitioning stores *may* store to const fields. The resulting
  // DataConstant access infos can be distinguished from later, i.e. redundant,
  // stores to the same constant field by the presence of a transition map.
  switch (dependencies()->DependOnFieldConstness(transition_map, transition_map,
                                                 number)) {
    case PropertyConstness::kMutable:
      return PropertyAccessInfo::DataField(
          broker(), zone(), map, std::move(unrecorded_dependencies),
          field_index, details_representation, field_type, transition_map,
          field_map, holder, transition_map);
    case PropertyConstness::kConst:
      return PropertyAccessInfo::FastDataConstant(
          zone(), map, std::move(unrecorded_dependencies), field_index,
          details_representation, field_type, transition_map, field_map, holder,
          transition_map);
  }
  UNREACHABLE();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```