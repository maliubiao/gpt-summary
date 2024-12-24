Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

**1. Initial Skim and Keyword Spotting:**

First, I'd quickly read through the code, not necessarily understanding every detail, but looking for recurring keywords and patterns. Things that would jump out:

* `CompilationDependencies`: This is clearly the central class.
* `#define DEPENDENCY_LIST`: This suggests an enumeration of different types of dependencies.
* `IsValid`, `PrepareInstall`, `Install`: These look like lifecycle methods for dependencies.
* `JSHeapBroker`, `Zone`:  These point to V8's memory management.
* `MapRef`, `JSFunctionRef`, `ObjectRef`: These indicate references to V8's object model.
* `DependentCode`: This suggests a connection to the generated machine code.
* `Protector`: This keyword appears frequently and likely relates to guarding against optimizations.
* Mentions of various object properties (`prototype`, `elements_kind`, `field_representation`, etc.).

**2. Understanding the Core Concept:**

The name "Compilation Dependencies" is highly informative. The code is clearly about tracking conditions that, if changed, would invalidate previously compiled code. This invalidation is necessary because the compiler makes assumptions based on the current state of the JavaScript objects.

**3. Analyzing the Dependency Types:**

The `DEPENDENCY_LIST` macro is crucial. I would systematically go through each entry and try to infer its purpose:

* **ConsistentJSFunctionView:**  Likely ensures the internal state of a function hasn't changed in a way that would break assumptions.
* **ConstantInDictionaryPrototypeChain:** Focuses on the immutability of properties in the prototype chain, especially when using dictionary (slow) objects.
* **ElementsKind:** Tracks the type of elements in an array (e.g., packed integers, holes, doubles).
* **FieldConstness/Representation/Type:**  Relates to how object properties are stored in memory (e.g., as integers, doubles, objects).
* **GlobalProperty/ScriptContextSlotProperty:**  Tracks the values of global variables and variables in script contexts.
* **InitialMap/StableMap/Transition:** These relate to the structure and evolution of JavaScript objects (maps are like class definitions in V8).
* **Protector:**  As mentioned before, these seem like guard flags against specific optimizations.

**4. Tracing the Lifecycle (`IsValid`, `PrepareInstall`, `Install`):**

* **`IsValid`:** This method for each dependency type checks if the condition it tracks still holds true. If not, the compiled code is no longer valid.
* **`PrepareInstall`:**  This step seems to do some pre-processing before actually linking the dependency. It might involve creating objects or setting up internal state.
* **`Install`:** This method connects the dependency to the compiled code, likely by adding entries to tables that the runtime system can check for invalidation.

**5. Connecting to JavaScript Functionality:**

At this point, I'd start thinking about *why* these dependencies are important from a JavaScript perspective. How do changes in these internal states manifest in JavaScript behavior?

* **Changing an object's prototype:**  This directly relates to prototype chain lookups.
* **Modifying an object's properties (type, value, constness):** This affects how the engine can access those properties efficiently.
* **Changing the elements kind of an array:**  This can drastically change how array operations are optimized.
* **Modifying global variables:**  This can alter the behavior of code that relies on those globals.

**6. Formulating the Summary:**

Based on the above analysis, I would start constructing the summary, highlighting the core function: tracking assumptions made during compilation to ensure compiled code remains valid. I'd mention the different categories of dependencies and their purpose.

**7. Creating the JavaScript Example:**

The key here is to choose examples that directly demonstrate how changes in the tracked conditions can affect JavaScript behavior and thus necessitate recompilation (or deoptimization in V8's case). I'd try to pick relatively simple and common scenarios:

* **Prototype Chain Dependency:** Demonstrate changing the prototype of an object after a function has been optimized based on the initial prototype chain.
* **Elements Kind Dependency:** Show how adding a non-integer value to an array of integers can trigger a change in the elements kind.
* **Stable Map Dependency:**  Illustrate how adding a new property to an object can cause a map transition, invalidating code that assumed the original map.
* **Global Property Dependency:** Show how changing a global variable can affect a function's behavior.

**Self-Correction/Refinement During the Process:**

* **Initial confusion about specific dependency types:** I might need to reread the code around a particular dependency to fully grasp its meaning. Looking at the `Install` method often gives clues about what's being registered and why.
* **Overly technical explanation:**  I'd try to simplify the explanation, avoiding overly V8-specific jargon where possible, while still being accurate. The goal is to explain the *functionality* and its impact on JavaScript.
* **Lack of clear JavaScript examples:**  If the initial examples aren't clear, I'd rethink them and try different scenarios that more directly illustrate the dependency. Thinking about common optimization scenarios in V8 helps here.

By following these steps, combining code analysis with an understanding of JavaScript semantics and V8's internals, I can arrive at a comprehensive and informative summary and illustrative JavaScript examples.
## 功能归纳

`v8/src/compiler/compilation-dependencies.cc` 文件是 V8 引擎中负责 **跟踪代码编译时所依赖的各种假设条件** 的核心组件。它的主要功能是：

1. **定义和管理各种编译依赖项 (Compilation Dependencies):**  该文件定义了一系列表示不同类型依赖关系的类，例如 `InitialMapDependency`、`PrototypePropertyDependency`、`StableMapDependency` 等。每种依赖项都代表了编译器在生成优化代码时所依赖的一个特定条件。

2. **记录编译依赖:** 当编译器在编译 JavaScript 代码时，如果它基于某些对象的当前状态或属性做出假设来进行优化，那么它会通过 `CompilationDependencies` 类记录这些依赖项。

3. **验证依赖项:** 在代码执行或重新优化时，`CompilationDependencies` 负责检查之前记录的依赖项是否仍然有效。如果某个依赖项失效（例如，依赖的对象的状态发生了改变），则说明之前编译的代码可能不再安全或最优，需要进行去优化 (deoptimization) 或重新编译。

4. **安装依赖项:** 当编译完成并准备执行代码时，`CompilationDependencies` 会将这些依赖项“安装”到相关的 V8 内部数据结构中，以便在运行时可以高效地检查这些依赖项的有效性。

5. **提供依赖项管理接口:** 该文件提供了一组 API，供编译器在编译过程中记录各种类型的依赖项。

**简单来说，这个文件的作用就是确保 V8 编译器所做的优化是建立在稳定的基础之上的。如果编译时的假设条件在运行时被破坏，V8 能够检测到并采取相应的措施，保证代码的正确性。**

## 与 JavaScript 功能的关系及 JavaScript 示例

`compilation-dependencies.cc` 直接关系到 V8 引擎执行 JavaScript 代码的性能和正确性。编译器利用其记录的依赖项进行各种优化，例如内联缓存 (inline caches)、类型反馈 (type feedback) 等。

以下是一些与 JavaScript 功能相关的依赖项以及相应的 JavaScript 示例：

**1. `InitialMapDependency` (初始 Map 依赖):**

* **功能:** 跟踪一个函数的初始 Map (类似于对象结构) 是否发生变化。如果一个函数的初始 Map 发生改变，那么基于该初始 Map 编译的代码可能失效。
* **JavaScript 示例:**

```javascript
function Point(x, y) {
  this.x = x;
  this.y = y;
}

// V8 可能会基于 Point 的初始 Map 优化使用它的代码
function distance(p1, p2) {
  return Math.sqrt((p1.x - p2.x)**2 + (p1.y - p2.y)**2);
}

let point1 = new Point(1, 2);
let point2 = new Point(4, 6);
distance(point1, point2); // 第一次调用可能会触发 distance 函数的编译

// 修改 Point 构造函数的原型，可能会导致其初始 Map 改变
Point.prototype.z = 0;
let point3 = new Point(7, 8);
distance(point1, point3); // 再次调用 distance，V8 可能会发现 InitialMapDependency 失效，需要重新编译或去优化
```

**2. `PrototypePropertyDependency` (原型属性依赖):**

* **功能:** 跟踪一个函数的 `prototype` 属性指向的对象是否发生变化。优化后的代码可能假设原型链的结构不变。
* **JavaScript 示例:**

```javascript
function Animal() {}
Animal.prototype.speak = function() { return "generic sound"; };

function Dog() {}
Dog.prototype = new Animal(); // 建立原型链
Dog.prototype.speak = function() { return "woof"; };

function makeSpeak(animal) {
  return animal.speak(); // V8 可能会根据当前的 Dog.prototype 优化此函数
}

let myDog = new Dog();
makeSpeak(myDog); // 第一次调用可能会触发 makeSpeak 函数的编译

// 修改 Dog 的原型指向另一个对象，打破了之前的假设
Dog.prototype = { speak: function() { return "bark"; } };
let anotherDog = new Dog();
makeSpeak(anotherDog); // 再次调用 makeSpeak，V8 可能会发现 PrototypePropertyDependency 失效
```

**3. `StableMapDependency` (稳定 Map 依赖):**

* **功能:** 跟踪一个对象的 Map 是否保持稳定，即对象的结构 (属性的数量和类型) 没有发生改变。许多优化依赖于对象的结构不发生变化。
* **JavaScript 示例:**

```javascript
function createPoint(x, y) {
  return { x: x, y: y };
}

let point = createPoint(10, 20);

function getX(p) {
  return p.x; // V8 可能会假设 point 只有一个 x 和 y 属性，并进行优化
}

getX(point); // 第一次调用可能会触发 getX 函数的编译

// 给 point 对象添加新的属性，导致其 Map 不再稳定
point.z = 30;
getX(point); // 再次调用 getX，V8 可能会发现 StableMapDependency 失效
```

**4. `ElementsKindDependency` (元素类型依赖):**

* **功能:** 跟踪数组的元素类型 (例如，是否只包含整数、浮点数或包含空洞等)。针对特定元素类型的数组可以进行更高效的优化。
* **JavaScript 示例:**

```javascript
function sumArray(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    sum += arr[i]; // V8 可能会假设 arr 都是数字类型进行优化
  }
  return sum;
}

let numbers = [1, 2, 3, 4, 5];
sumArray(numbers); // 第一次调用可能会触发 sumArray 函数的编译

// 将非数字类型的值添加到数组中，改变了数组的元素类型
numbers.push("6");
sumArray(numbers); // 再次调用 sumArray，V8 可能会发现 ElementsKindDependency 失效
```

**总结:**

`compilation-dependencies.cc` 文件在 V8 引擎的优化编译过程中扮演着至关重要的角色。它通过跟踪各种假设条件，确保了编译后的代码能够在运行时正确且高效地执行。当这些假设条件被破坏时，V8 能够及时检测到并采取相应的措施，从而保证 JavaScript 代码的健壮性和性能。这些依赖项的存在是 V8 能够进行激进优化的基础。

Prompt: 
```
这是目录为v8/src/compiler/compilation-dependencies.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/compilation-dependencies.h"

#include <optional>

#include "src/base/hashmap.h"
#include "src/common/assert-scope.h"
#include "src/execution/protectors.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/internal-index.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-function-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-cell.h"

namespace v8 {
namespace internal {
namespace compiler {

#define DEPENDENCY_LIST(V)              \
  V(ConsistentJSFunctionView)           \
  V(ConstantInDictionaryPrototypeChain) \
  V(ElementsKind)                       \
  V(EmptyContextExtension)              \
  V(FieldConstness)                     \
  V(FieldRepresentation)                \
  V(FieldType)                          \
  V(GlobalProperty)                     \
  V(InitialMap)                         \
  V(InitialMapInstanceSizePrediction)   \
  V(NoSlackTrackingChange)              \
  V(OwnConstantDataProperty)            \
  V(OwnConstantDoubleProperty)          \
  V(OwnConstantDictionaryProperty)      \
  V(OwnConstantElement)                 \
  V(PretenureMode)                      \
  V(Protector)                          \
  V(PrototypeProperty)                  \
  V(ScriptContextSlotProperty)          \
  V(StableMap)                          \
  V(Transition)                         \
  V(ObjectSlotValue)

CompilationDependencies::CompilationDependencies(JSHeapBroker* broker,
                                                 Zone* zone)
    : zone_(zone), broker_(broker), dependencies_(zone) {
  broker->set_dependencies(this);
}

namespace {

enum CompilationDependencyKind {
#define V(Name) k##Name,
  DEPENDENCY_LIST(V)
#undef V
};

#define V(Name) class Name##Dependency;
DEPENDENCY_LIST(V)
#undef V

const char* CompilationDependencyKindToString(CompilationDependencyKind kind) {
#define V(Name) #Name "Dependency",
  static const char* const names[] = {DEPENDENCY_LIST(V)};
#undef V
  return names[kind];
}

class PendingDependencies;

}  // namespace

class CompilationDependency : public ZoneObject {
 public:
  explicit CompilationDependency(CompilationDependencyKind kind) : kind(kind) {}

  virtual bool IsValid(JSHeapBroker* broker) const = 0;
  virtual void PrepareInstall(JSHeapBroker* broker) const {}
  virtual void Install(JSHeapBroker* broker,
                       PendingDependencies* deps) const = 0;

#define V(Name)                                     \
  bool Is##Name() const { return kind == k##Name; } \
  V8_ALLOW_UNUSED const Name##Dependency* As##Name() const;
  DEPENDENCY_LIST(V)
#undef V

  const char* ToString() const {
    return CompilationDependencyKindToString(kind);
  }

  const CompilationDependencyKind kind;

 private:
  virtual size_t Hash() const = 0;
  virtual bool Equals(const CompilationDependency* that) const = 0;
  friend struct CompilationDependencies::CompilationDependencyHash;
  friend struct CompilationDependencies::CompilationDependencyEqual;
};

size_t CompilationDependencies::CompilationDependencyHash::operator()(
    const CompilationDependency* dep) const {
  return base::hash_combine(dep->kind, dep->Hash());
}

bool CompilationDependencies::CompilationDependencyEqual::operator()(
    const CompilationDependency* lhs, const CompilationDependency* rhs) const {
  return lhs->kind == rhs->kind && lhs->Equals(rhs);
}

namespace {

// Dependencies can only be fully deduplicated immediately prior to
// installation (because PrepareInstall may create the object on which the dep
// will be installed). We gather and dedupe deps in this class, and install
// them from here.
class PendingDependencies final {
 public:
  explicit PendingDependencies(Zone* zone)
      : deps_(8, {}, ZoneAllocationPolicy(zone)) {}

  void Register(Handle<HeapObject> object,
                DependentCode::DependencyGroup group) {
    // InstructionStream, which are per-local Isolate, cannot depend on objects
    // in the shared or RO heaps. Shared and RO heap dependencies are designed
    // to never invalidate assumptions. E.g., maps for shared structs do not
    // have transitions or change the shape of their fields. See
    // DependentCode::DeoptimizeDependencyGroups for corresponding DCHECK.
    if (HeapLayout::InWritableSharedSpace(*object) ||
        HeapLayout::InReadOnlySpace(*object))
      return;
    deps_.LookupOrInsert(object, HandleValueHash(object))->value |= group;
  }

  void InstallAll(Isolate* isolate, Handle<Code> code) {
    if (V8_UNLIKELY(v8_flags.predictable)) {
      InstallAllPredictable(isolate, code);
      return;
    }

    // With deduplication done we no longer rely on the object address for
    // hashing.
    AllowGarbageCollection yes_gc;
    for (auto* entry = deps_.Start(); entry != nullptr;
         entry = deps_.Next(entry)) {
      DependentCode::InstallDependency(isolate, code, entry->key, entry->value);
    }
    deps_.Invalidate();
  }

  void InstallAllPredictable(Isolate* isolate, Handle<Code> code) {
    CHECK(v8_flags.predictable);
    // First, guarantee predictable iteration order.
    using DepsMap = decltype(deps_);
    std::vector<const DepsMap::Entry*> entries;
    entries.reserve(deps_.occupancy());
    for (auto* entry = deps_.Start(); entry != nullptr;
         entry = deps_.Next(entry)) {
      entries.push_back(entry);
    }

    std::sort(entries.begin(), entries.end(),
              [](const DepsMap::Entry* lhs, const DepsMap::Entry* rhs) {
                return lhs->key->ptr() < rhs->key->ptr();
              });

    // With deduplication done we no longer rely on the object address for
    // hashing.
    AllowGarbageCollection yes_gc;
    for (const auto* entry : entries) {
      DependentCode::InstallDependency(isolate, code, entry->key, entry->value);
    }
    deps_.Invalidate();
  }

 private:
  uint32_t HandleValueHash(DirectHandle<HeapObject> handle) {
    return static_cast<uint32_t>(base::hash_value(handle->ptr()));
  }
  struct HandleValueEqual {
    bool operator()(uint32_t hash1, uint32_t hash2, Handle<HeapObject> lhs,
                    Handle<HeapObject> rhs) const {
      return hash1 == hash2 && lhs.is_identical_to(rhs);
    }
  };

  base::TemplateHashMapImpl<Handle<HeapObject>, DependentCode::DependencyGroups,
                            HandleValueEqual, ZoneAllocationPolicy>
      deps_;
};

class InitialMapDependency final : public CompilationDependency {
 public:
  InitialMapDependency(JSHeapBroker* broker, JSFunctionRef function,
                       MapRef initial_map)
      : CompilationDependency(kInitialMap),
        function_(function),
        initial_map_(initial_map) {}

  bool IsValid(JSHeapBroker* broker) const override {
    DirectHandle<JSFunction> function = function_.object();
    return function->has_initial_map() &&
           function->initial_map() == *initial_map_.object();
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    deps->Register(initial_map_.object(),
                   DependentCode::kInitialMapChangedGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(function_), h(initial_map_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const InitialMapDependency* const zat = that->AsInitialMap();
    return function_.equals(zat->function_) &&
           initial_map_.equals(zat->initial_map_);
  }

  const JSFunctionRef function_;
  const MapRef initial_map_;
};

class PrototypePropertyDependency final : public CompilationDependency {
 public:
  PrototypePropertyDependency(JSHeapBroker* broker, JSFunctionRef function,
                              ObjectRef prototype)
      : CompilationDependency(kPrototypeProperty),
        function_(function),
        prototype_(prototype) {
    DCHECK(function_.has_instance_prototype(broker));
    DCHECK(!function_.PrototypeRequiresRuntimeLookup(broker));
    DCHECK(function_.instance_prototype(broker).equals(prototype_));
  }

  bool IsValid(JSHeapBroker* broker) const override {
    DirectHandle<JSFunction> function = function_.object();
    return function->has_prototype_slot() &&
           function->has_instance_prototype() &&
           !function->PrototypeRequiresRuntimeLookup() &&
           function->instance_prototype() == *prototype_.object();
  }

  void PrepareInstall(JSHeapBroker* broker) const override {
    SLOW_DCHECK(IsValid(broker));
    Handle<JSFunction> function = function_.object();
    if (!function->has_initial_map()) JSFunction::EnsureHasInitialMap(function);
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    DirectHandle<JSFunction> function = function_.object();
    CHECK(function->has_initial_map());
    Handle<Map> initial_map(function->initial_map(), broker->isolate());
    deps->Register(initial_map, DependentCode::kInitialMapChangedGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(function_), h(prototype_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const PrototypePropertyDependency* const zat = that->AsPrototypeProperty();
    return function_.equals(zat->function_) &&
           prototype_.equals(zat->prototype_);
  }

  const JSFunctionRef function_;
  const ObjectRef prototype_;
};

class StableMapDependency final : public CompilationDependency {
 public:
  explicit StableMapDependency(MapRef map)
      : CompilationDependency(kStableMap), map_(map) {}

  bool IsValid(JSHeapBroker* broker) const override {
    // TODO(v8:11670): Consider turn this back into a CHECK inside the
    // constructor and DependOnStableMap, if possible in light of concurrent
    // heap state modifications.
    return !map_.object()->is_dictionary_map() && map_.object()->is_stable();
  }
  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    deps->Register(map_.object(), DependentCode::kPrototypeCheckGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(map_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const StableMapDependency* const zat = that->AsStableMap();
    return map_.equals(zat->map_);
  }

  const MapRef map_;
};

class ConstantInDictionaryPrototypeChainDependency final
    : public CompilationDependency {
 public:
  explicit ConstantInDictionaryPrototypeChainDependency(
      const MapRef receiver_map, const NameRef property_name,
      const ObjectRef constant, PropertyKind kind)
      : CompilationDependency(kConstantInDictionaryPrototypeChain),
        receiver_map_(receiver_map),
        property_name_{property_name},
        constant_{constant},
        kind_{kind} {
    DCHECK(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);
  }

  // Checks that |constant_| is still the value of accessing |property_name_|
  // starting at |receiver_map_|.
  bool IsValid(JSHeapBroker* broker) const override {
    return !GetHolderIfValid(broker).is_null();
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    Isolate* isolate = broker->isolate();
    DirectHandle<JSObject> holder = GetHolderIfValid(broker).ToHandleChecked();
    Handle<Map> map = receiver_map_.object();

    while (map->prototype() != *holder) {
      map = handle(map->prototype()->map(), isolate);
      DCHECK(IsJSObjectMap(*map));  // Due to IsValid holding.
      deps->Register(map, DependentCode::kPrototypeCheckGroup);
    }

    DCHECK(IsJSObjectMap(map->prototype()->map()));  // Due to IsValid holding.
    deps->Register(handle(map->prototype()->map(), isolate),
                   DependentCode::kPrototypeCheckGroup);
  }

 private:
  // If the dependency is still valid, returns holder of the constant. Otherwise
  // returns null.
  // TODO(neis) Currently, invoking IsValid and then Install duplicates the call
  // to GetHolderIfValid. Instead, consider letting IsValid change the state
  // (and store the holder), or merge IsValid and Install.
  MaybeHandle<JSObject> GetHolderIfValid(JSHeapBroker* broker) const {
    DisallowGarbageCollection no_gc;
    Isolate* isolate = broker->isolate();

    Tagged<HeapObject> prototype = receiver_map_.object()->prototype();

    enum class ValidationResult { kFoundCorrect, kFoundIncorrect, kNotFound };
    auto try_load = [&](auto dictionary) -> ValidationResult {
      InternalIndex entry =
          dictionary->FindEntry(isolate, property_name_.object());
      if (entry.is_not_found()) {
        return ValidationResult::kNotFound;
      }

      PropertyDetails details = dictionary->DetailsAt(entry);
      if (details.constness() != PropertyConstness::kConst) {
        return ValidationResult::kFoundIncorrect;
      }

      Tagged<Object> dictionary_value = dictionary->ValueAt(entry);
      Tagged<Object> value;
      // We must be able to detect the case that the property |property_name_|
      // of |holder_| was originally a plain function |constant_| (when creating
      // this dependency) and has since become an accessor whose getter is
      // |constant_|. Therefore, we cannot just look at the property kind of
      // |details|, because that reflects the current situation, not the one
      // when creating this dependency.
      if (details.kind() != kind_) {
        return ValidationResult::kFoundIncorrect;
      }
      if (kind_ == PropertyKind::kAccessor) {
        if (!IsAccessorPair(dictionary_value)) {
          return ValidationResult::kFoundIncorrect;
        }
        // Only supporting loading at the moment, so we only ever want the
        // getter.
        value = Cast<AccessorPair>(dictionary_value)
                    ->get(AccessorComponent::ACCESSOR_GETTER);
      } else {
        value = dictionary_value;
      }
      return value == *constant_.object() ? ValidationResult::kFoundCorrect
                                          : ValidationResult::kFoundIncorrect;
    };

    while (IsJSObject(prototype)) {
      // We only care about JSObjects because that's the only type of holder
      // (and types of prototypes on the chain to the holder) that
      // AccessInfoFactory::ComputePropertyAccessInfo allows.
      Tagged<JSObject> object = Cast<JSObject>(prototype);

      // We only support dictionary mode prototypes on the chain for this kind
      // of dependency.
      CHECK(!object->HasFastProperties());

      ValidationResult result =
          V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL
              ? try_load(object->property_dictionary_swiss())
              : try_load(object->property_dictionary());

      if (result == ValidationResult::kFoundCorrect) {
        return handle(object, isolate);
      } else if (result == ValidationResult::kFoundIncorrect) {
        return MaybeHandle<JSObject>();
      }

      // In case of kNotFound, continue walking up the chain.
      prototype = object->map()->prototype();
    }

    return MaybeHandle<JSObject>();
  }

  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(receiver_map_), h(property_name_), h(constant_),
                              static_cast<int>(kind_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const ConstantInDictionaryPrototypeChainDependency* const zat =
        that->AsConstantInDictionaryPrototypeChain();
    return receiver_map_.equals(zat->receiver_map_) &&
           property_name_.equals(zat->property_name_) &&
           constant_.equals(zat->constant_) && kind_ == zat->kind_;
  }

  const MapRef receiver_map_;
  const NameRef property_name_;
  const ObjectRef constant_;
  const PropertyKind kind_;
};

class OwnConstantDataPropertyDependency final : public CompilationDependency {
 public:
  OwnConstantDataPropertyDependency(JSHeapBroker* broker, JSObjectRef holder,
                                    MapRef map, FieldIndex index,
                                    ObjectRef value)
      : CompilationDependency(kOwnConstantDataProperty),
        broker_(broker),
        holder_(holder),
        map_(map),
        index_(index),
        value_(value) {}

  bool IsValid(JSHeapBroker* broker) const override {
    if (holder_.object()->map() != *map_.object()) {
      TRACE_BROKER_MISSING(broker_,
                           "Map change detected in " << holder_.object());
      return false;
    }
    DisallowGarbageCollection no_heap_allocation;
    Tagged<Object> current_value = holder_.object()->RawFastPropertyAt(index_);
    Tagged<Object> used_value = *value_.object();
    if (current_value != used_value) {
      TRACE_BROKER_MISSING(broker_, "Constant property value changed in "
                                        << holder_.object() << " at FieldIndex "
                                        << index_.property_index());
      return false;
    }
    return true;
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(holder_), h(map_), index_.bit_field(),
                              h(value_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const OwnConstantDataPropertyDependency* const zat =
        that->AsOwnConstantDataProperty();
    return holder_.equals(zat->holder_) && map_.equals(zat->map_) &&
           index_ == zat->index_ && value_.equals(zat->value_);
  }

  JSHeapBroker* const broker_;
  JSObjectRef const holder_;
  MapRef const map_;
  FieldIndex const index_;
  ObjectRef const value_;
};

class OwnConstantDoublePropertyDependency final : public CompilationDependency {
 public:
  OwnConstantDoublePropertyDependency(JSHeapBroker* broker, JSObjectRef holder,
                                      MapRef map, FieldIndex index,
                                      Float64 value)
      : CompilationDependency(kOwnConstantDoubleProperty),
        broker_(broker),
        holder_(holder),
        map_(map),
        index_(index),
        value_(value) {}

  bool IsValid(JSHeapBroker* broker) const override {
    if (holder_.object()->map() != *map_.object()) {
      TRACE_BROKER_MISSING(broker_,
                           "Map change detected in " << holder_.object());
      return false;
    }
    DisallowGarbageCollection no_heap_allocation;
    Tagged<Object> current_value = holder_.object()->RawFastPropertyAt(index_);
    Float64 used_value = value_;

    // Compare doubles by bit pattern.
    if (!IsHeapNumber(current_value) ||
        Cast<HeapNumber>(current_value)->value_as_bits() !=
            used_value.get_bits()) {
      TRACE_BROKER_MISSING(broker_, "Constant Double property value changed in "
                                        << holder_.object() << " at FieldIndex "
                                        << index_.property_index());
      return false;
    }

    return true;
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(holder_), h(map_), index_.bit_field(),
                              value_.get_bits());
  }

  bool Equals(const CompilationDependency* that) const override {
    const OwnConstantDoublePropertyDependency* const zat =
        that->AsOwnConstantDoubleProperty();
    return holder_.equals(zat->holder_) && map_.equals(zat->map_) &&
           index_ == zat->index_ && value_.get_bits() == zat->value_.get_bits();
  }

  JSHeapBroker* const broker_;
  JSObjectRef const holder_;
  MapRef const map_;
  FieldIndex const index_;
  Float64 const value_;
};

class OwnConstantDictionaryPropertyDependency final
    : public CompilationDependency {
 public:
  OwnConstantDictionaryPropertyDependency(JSHeapBroker* broker,
                                          JSObjectRef holder,
                                          InternalIndex index, ObjectRef value)
      : CompilationDependency(kOwnConstantDictionaryProperty),
        holder_(holder),
        map_(holder.map(broker)),
        index_(index),
        value_(value) {
    // We depend on map() being cached.
    static_assert(ref_traits<JSObject>::ref_serialization_kind !=
                  RefSerializationKind::kNeverSerialized);
  }

  bool IsValid(JSHeapBroker* broker) const override {
    if (holder_.object()->map() != *map_.object()) {
      TRACE_BROKER_MISSING(broker,
                           "Map change detected in " << holder_.object());
      return false;
    }

    std::optional<Tagged<Object>> maybe_value = JSObject::DictionaryPropertyAt(
        holder_.object(), index_, broker->isolate()->heap());

    if (!maybe_value) {
      TRACE_BROKER_MISSING(
          broker, holder_.object()
                      << "has a value that might not safe to read at index "
                      << index_.as_int());
      return false;
    }

    if (*maybe_value != *value_.object()) {
      TRACE_BROKER_MISSING(broker, "Constant property value changed in "
                                       << holder_.object()
                                       << " at InternalIndex "
                                       << index_.as_int());
      return false;
    }
    return true;
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(holder_), h(map_), index_.raw_value(),
                              h(value_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const OwnConstantDictionaryPropertyDependency* const zat =
        that->AsOwnConstantDictionaryProperty();
    return holder_.equals(zat->holder_) && map_.equals(zat->map_) &&
           index_ == zat->index_ && value_.equals(zat->value_);
  }

  JSObjectRef const holder_;
  MapRef const map_;
  InternalIndex const index_;
  ObjectRef const value_;
};

class ConsistentJSFunctionViewDependency final : public CompilationDependency {
 public:
  explicit ConsistentJSFunctionViewDependency(JSFunctionRef function)
      : CompilationDependency(kConsistentJSFunctionView), function_(function) {}

  bool IsValid(JSHeapBroker* broker) const override {
    return function_.IsConsistentWithHeapState(broker);
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(function_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const ConsistentJSFunctionViewDependency* const zat =
        that->AsConsistentJSFunctionView();
    return function_.equals(zat->function_);
  }

  const JSFunctionRef function_;
};

class TransitionDependency final : public CompilationDependency {
 public:
  explicit TransitionDependency(MapRef map)
      : CompilationDependency(kTransition), map_(map) {
    DCHECK(map_.CanBeDeprecated());
  }

  bool IsValid(JSHeapBroker* broker) const override {
    return !map_.object()->is_deprecated();
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    deps->Register(map_.object(), DependentCode::kTransitionGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(map_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const TransitionDependency* const zat = that->AsTransition();
    return map_.equals(zat->map_);
  }

  const MapRef map_;
};

class PretenureModeDependency final : public CompilationDependency {
 public:
  PretenureModeDependency(AllocationSiteRef site, AllocationType allocation)
      : CompilationDependency(kPretenureMode),
        site_(site),
        allocation_(allocation) {}

  bool IsValid(JSHeapBroker* broker) const override {
    return allocation_ == site_.object()->GetAllocationType();
  }
  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    deps->Register(site_.object(),
                   DependentCode::kAllocationSiteTenuringChangedGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(site_), allocation_);
  }

  bool Equals(const CompilationDependency* that) const override {
    const PretenureModeDependency* const zat = that->AsPretenureMode();
    return site_.equals(zat->site_) && allocation_ == zat->allocation_;
  }

  const AllocationSiteRef site_;
  const AllocationType allocation_;
};

class FieldRepresentationDependency final : public CompilationDependency {
 public:
  FieldRepresentationDependency(MapRef map, MapRef owner,
                                InternalIndex descriptor,
                                Representation representation)
      : CompilationDependency(kFieldRepresentation),
        map_(map),
        owner_(owner),
        descriptor_(descriptor),
        representation_(representation) {}

  bool IsValid(JSHeapBroker* broker) const override {
    DisallowGarbageCollection no_heap_allocation;
    if (map_.object()->is_deprecated()) return false;
    return representation_.Equals(map_.object()
                                      ->instance_descriptors(broker->isolate())
                                      ->GetDetails(descriptor_)
                                      .representation());
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    Isolate* isolate = broker->isolate();
    Handle<Map> owner = owner_.object();
    CHECK(!owner->is_deprecated());
    CHECK(representation_.Equals(owner->instance_descriptors(isolate)
                                     ->GetDetails(descriptor_)
                                     .representation()));
    deps->Register(owner, DependentCode::kFieldRepresentationGroup);
  }

  bool DependsOn(const Handle<Map>& receiver_map) const {
    return map_.object().equals(receiver_map);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(map_), descriptor_.as_int(),
                              representation_.kind());
  }

  bool Equals(const CompilationDependency* that) const override {
    const FieldRepresentationDependency* const zat =
        that->AsFieldRepresentation();
    return map_.equals(zat->map_) && descriptor_ == zat->descriptor_ &&
           representation_.Equals(zat->representation_);
  }

  const MapRef map_;
  const MapRef owner_;
  const InternalIndex descriptor_;
  const Representation representation_;
};

class FieldTypeDependency final : public CompilationDependency {
 public:
  FieldTypeDependency(MapRef map, MapRef owner, InternalIndex descriptor,
                      ObjectRef type)
      : CompilationDependency(kFieldType),
        map_(map),
        owner_(owner),
        descriptor_(descriptor),
        type_(type) {}

  bool IsValid(JSHeapBroker* broker) const override {
    DisallowGarbageCollection no_heap_allocation;
    if (map_.object()->is_deprecated()) return false;
    return *type_.object() == map_.object()
                                  ->instance_descriptors(broker->isolate())
                                  ->GetFieldType(descriptor_);
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    Isolate* isolate = broker->isolate();
    Handle<Map> owner = owner_.object();
    CHECK(!owner->is_deprecated());
    CHECK_EQ(*type_.object(),
             owner->instance_descriptors(isolate)->GetFieldType(descriptor_));
    deps->Register(owner, DependentCode::kFieldTypeGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(map_), descriptor_.as_int(), h(type_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const FieldTypeDependency* const zat = that->AsFieldType();
    return map_.equals(zat->map_) && descriptor_ == zat->descriptor_ &&
           type_.equals(zat->type_);
  }

  const MapRef map_;
  const MapRef owner_;
  const InternalIndex descriptor_;
  const ObjectRef type_;
};

class FieldConstnessDependency final : public CompilationDependency {
 public:
  FieldConstnessDependency(MapRef map, MapRef owner, InternalIndex descriptor)
      : CompilationDependency(kFieldConstness),
        map_(map),
        owner_(owner),
        descriptor_(descriptor) {}

  bool IsValid(JSHeapBroker* broker) const override {
    DisallowGarbageCollection no_heap_allocation;
    if (map_.object()->is_deprecated()) return false;
    return PropertyConstness::kConst ==
           map_.object()
               ->instance_descriptors(broker->isolate())
               ->GetDetails(descriptor_)
               .constness();
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    Isolate* isolate = broker->isolate();
    Handle<Map> owner = owner_.object();
    CHECK(!owner->is_deprecated());
    CHECK_EQ(PropertyConstness::kConst, owner->instance_descriptors(isolate)
                                            ->GetDetails(descriptor_)
                                            .constness());
    deps->Register(owner, DependentCode::kFieldConstGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(map_), descriptor_.as_int());
  }

  bool Equals(const CompilationDependency* that) const override {
    const FieldConstnessDependency* const zat = that->AsFieldConstness();
    return map_.equals(zat->map_) && descriptor_ == zat->descriptor_;
  }

  const MapRef map_;
  const MapRef owner_;
  const InternalIndex descriptor_;
};

class GlobalPropertyDependency final : public CompilationDependency {
 public:
  GlobalPropertyDependency(PropertyCellRef cell, PropertyCellType type,
                           bool read_only)
      : CompilationDependency(kGlobalProperty),
        cell_(cell),
        type_(type),
        read_only_(read_only) {
    DCHECK_EQ(type_, cell_.property_details().cell_type());
    DCHECK_EQ(read_only_, cell_.property_details().IsReadOnly());
  }

  bool IsValid(JSHeapBroker* broker) const override {
    DirectHandle<PropertyCell> cell = cell_.object();
    // The dependency is never valid if the cell is 'invalidated'. This is
    // marked by setting the value to the hole.
    if (cell->value() ==
        *(broker->isolate()->factory()->property_cell_hole_value())) {
      return false;
    }
    return type_ == cell->property_details().cell_type() &&
           read_only_ == cell->property_details().IsReadOnly();
  }
  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    deps->Register(cell_.object(), DependentCode::kPropertyCellChangedGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(cell_), static_cast<int>(type_), read_only_);
  }

  bool Equals(const CompilationDependency* that) const override {
    const GlobalPropertyDependency* const zat = that->AsGlobalProperty();
    return cell_.equals(zat->cell_) && type_ == zat->type_ &&
           read_only_ == zat->read_only_;
  }

  const PropertyCellRef cell_;
  const PropertyCellType type_;
  const bool read_only_;
};

class ScriptContextSlotPropertyDependency final : public CompilationDependency {
 public:
  ScriptContextSlotPropertyDependency(
      ContextRef script_context, size_t index,
      ContextSidePropertyCell::Property property)
      : CompilationDependency(kScriptContextSlotProperty),
        script_context_(script_context),
        index_(index),
        property_(property) {
    DCHECK(v8_flags.script_context_mutable_heap_number ||
           v8_flags.const_tracking_let);
  }

  bool IsValid(JSHeapBroker* broker) const override {
    return script_context_.object()->GetScriptContextSideProperty(index_) ==
           property_;
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    Isolate* isolate = broker->isolate();
    deps->Register(
        handle(Context::GetOrCreateContextSidePropertyCell(
                   script_context_.object(), index_, property_, isolate),
               isolate),
        DependentCode::kScriptContextSlotPropertyChangedGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(script_context_), index_);
  }

  bool Equals(const CompilationDependency* that) const override {
    const ScriptContextSlotPropertyDependency* const zat =
        that->AsScriptContextSlotProperty();
    return script_context_.equals(zat->script_context_) &&
           index_ == zat->index_ && property_ == zat->property_;
  }

  const ContextRef script_context_;
  size_t index_;
  ContextSidePropertyCell::Property property_;
};

class EmptyContextExtensionDependency final : public CompilationDependency {
 public:
  explicit EmptyContextExtensionDependency(ScopeInfoRef scope_info)
      : CompilationDependency(kEmptyContextExtension), scope_info_(scope_info) {
    DCHECK(v8_flags.empty_context_extension_dep);
    DCHECK(scope_info.SloppyEvalCanExtendVars());
    DCHECK(!HeapLayout::InReadOnlySpace(*scope_info.object()));
  }

  bool IsValid(JSHeapBroker* broker) const override {
    return !scope_info_.SomeContextHasExtension();
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    deps->Register(scope_info_.object(),
                   DependentCode::kEmptyContextExtensionGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(scope_info_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const EmptyContextExtensionDependency* const zat =
        that->AsEmptyContextExtension();
    return scope_info_.equals(zat->scope_info_);
  }

  const ScopeInfoRef scope_info_;
};

class ProtectorDependency final : public CompilationDependency {
 public:
  explicit ProtectorDependency(PropertyCellRef cell)
      : CompilationDependency(kProtector), cell_(cell) {}

  bool IsValid(JSHeapBroker* broker) const override {
    DirectHandle<PropertyCell> cell = cell_.object();
    return cell->value() == Smi::FromInt(Protectors::kProtectorValid);
  }
  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    deps->Register(cell_.object(), DependentCode::kPropertyCellChangedGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(cell_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const ProtectorDependency* const zat = that->AsProtector();
    return cell_.equals(zat->cell_);
  }

  const PropertyCellRef cell_;
};

// Check that an object slot will not change during compilation.
class ObjectSlotValueDependency final : public CompilationDependency {
 public:
  explicit ObjectSlotValueDependency(HeapObjectRef object, int offset,
                                     ObjectRef value)
      : CompilationDependency(kObjectSlotValue),
        object_(object.object()),
        offset_(offset),
        value_(value.object()) {}

  bool IsValid(JSHeapBroker* broker) const override {
    PtrComprCageBase cage_base = GetPtrComprCageBase(*object_);
    Tagged<Object> current_value =
        offset_ == HeapObject::kMapOffset
            ? object_->map()
            : TaggedField<Object>::Relaxed_Load(cage_base, *object_, offset_);
    return *value_ == current_value;
  }
  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
  }

 private:
  size_t Hash() const override {
    return base::hash_combine(object_.address(), offset_, value_.address());
  }

  bool Equals(const CompilationDependency* that) const override {
    const ObjectSlotValueDependency* const zat = that->AsObjectSlotValue();
    return object_->address() == zat->object_->address() &&
           offset_ == zat->offset_ && value_.address() == zat->value_.address();
  }

  Handle<HeapObject> object_;
  int offset_;
  Handle<Object> value_;
};

class ElementsKindDependency final : public CompilationDependency {
 public:
  ElementsKindDependency(AllocationSiteRef site, ElementsKind kind)
      : CompilationDependency(kElementsKind), site_(site), kind_(kind) {
    DCHECK(AllocationSite::ShouldTrack(kind_));
  }

  bool IsValid(JSHeapBroker* broker) const override {
    DirectHandle<AllocationSite> site = site_.object();
    ElementsKind kind =
        site->PointsToLiteral()
            ? site->boilerplate(kAcquireLoad)->map()->elements_kind()
            : site->GetElementsKind();
    return kind_ == kind;
  }
  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    deps->Register(site_.object(),
                   DependentCode::kAllocationSiteTransitionChangedGroup);
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(site_), static_cast<int>(kind_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const ElementsKindDependency* const zat = that->AsElementsKind();
    return site_.equals(zat->site_) && kind_ == zat->kind_;
  }

  const AllocationSiteRef site_;
  const ElementsKind kind_;
};

// Only valid if the holder can use direct reads, since validation uses
// GetOwnConstantElementFromHeap.
class OwnConstantElementDependency final : public CompilationDependency {
 public:
  OwnConstantElementDependency(JSObjectRef holder, uint32_t index,
                               ObjectRef element)
      : CompilationDependency(kOwnConstantElement),
        holder_(holder),
        index_(index),
        element_(element) {}

  bool IsValid(JSHeapBroker* broker) const override {
    DisallowGarbageCollection no_gc;
    Tagged<JSObject> holder = *holder_.object();
    std::optional<Tagged<Object>> maybe_element =
        holder_.GetOwnConstantElementFromHeap(
            broker, holder->elements(), holder->GetElementsKind(), index_);
    if (!maybe_element.has_value()) return false;

    return maybe_element.value() == *element_.object();
  }
  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(holder_), index_, h(element_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const OwnConstantElementDependency* const zat =
        that->AsOwnConstantElement();
    return holder_.equals(zat->holder_) && index_ == zat->index_ &&
           element_.equals(zat->element_);
  }

  const JSObjectRef holder_;
  const uint32_t index_;
  const ObjectRef element_;
};

class NoSlackTrackingChangeDependency final : public CompilationDependency {
 public:
  explicit NoSlackTrackingChangeDependency(MapRef map)
      : CompilationDependency(kNoSlackTrackingChange), map_(map) {}

  bool IsValid(JSHeapBroker* broker) const override {
    if (map_.construction_counter() != 0 &&
        map_.object()->construction_counter() == 0) {
      // Slack tracking finished during compilation.
      return false;
    }
    return map_.UnusedPropertyFields() ==
               map_.object()->UnusedPropertyFields() &&
           map_.GetInObjectProperties() ==
               map_.object()->GetInObjectProperties();
  }

  void PrepareInstall(JSHeapBroker*) const override {}
  void Install(JSHeapBroker*, PendingDependencies*) const override {}

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(map_));
  }

  bool Equals(const CompilationDependency* that) const override {
    const NoSlackTrackingChangeDependency* const zat =
        that->AsNoSlackTrackingChange();
    return map_.equals(zat->map_);
  }

  const MapRef map_;
};

class InitialMapInstanceSizePredictionDependency final
    : public CompilationDependency {
 public:
  InitialMapInstanceSizePredictionDependency(JSFunctionRef function,
                                             int instance_size)
      : CompilationDependency(kInitialMapInstanceSizePrediction),
        function_(function),
        instance_size_(instance_size) {}

  bool IsValid(JSHeapBroker* broker) const override {
    // The dependency is valid if the prediction is the same as the current
    // slack tracking result.
    if (!function_.object()->has_initial_map()) return false;
    int instance_size =
        function_.object()->ComputeInstanceSizeWithMinSlack(broker->isolate());
    return instance_size == instance_size_;
  }

  void PrepareInstall(JSHeapBroker* broker) const override {
    SLOW_DCHECK(IsValid(broker));
    function_.object()->CompleteInobjectSlackTrackingIfActive();
  }

  void Install(JSHeapBroker* broker, PendingDependencies* deps) const override {
    SLOW_DCHECK(IsValid(broker));
    DCHECK(!function_.object()
                ->initial_map()
                ->IsInobjectSlackTrackingInProgress());
  }

 private:
  size_t Hash() const override {
    ObjectRef::Hash h;
    return base::hash_combine(h(function_), instance_size_);
  }

  bool Equals(const CompilationDependency* that) const override {
    const InitialMapInstanceSizePredictionDependency* const zat =
        that->AsInitialMapInstanceSizePrediction();
    return function_.equals(zat->function_) &&
           instance_size_ == zat->instance_size_;
  }

  const JSFunctionRef function_;
  const int instance_size_;
};

}  // namespace

void CompilationDependencies::RecordDependency(
    CompilationDependency const* dependency) {
  if (dependency != nullptr) dependencies_.insert(dependency);
}

MapRef CompilationDependencies::DependOnInitialMap(JSFunctionRef function) {
  MapRef map = function.initial_map(broker_);
  RecordDependency(zone_->New<InitialMapDependency>(broker_, function, map));
  return map;
}

HeapObjectRef CompilationDependencies::DependOnPrototypeProperty(
    JSFunctionRef function) {
  HeapObjectRef prototype = function.instance_prototype(broker_);
  RecordDependency(
      zone_->New<PrototypePropertyDependency>(broker_, function, prototype));
  return prototype;
}

void CompilationDependencies::DependOnStableMap(MapRef map) {
  if (map.CanTransition()) {
    RecordDependency(zone_->New<StableMapDependency>(map));
  }
}

void CompilationDependencies::DependOnConstantInDictionaryPrototypeChain(
    MapRef receiver_map, NameRef property_name, ObjectRef constant,
    PropertyKind kind) {
  RecordDependency(zone_->New<ConstantInDictionaryPrototypeChainDependency>(
      receiver_map, property_name, constant, kind));
}

AllocationType CompilationDependencies::DependOnPretenureMode(
    AllocationSiteRef site) {
  if (!v8_flags.allocation_site_pretenuring) return AllocationType::kYoung;
  AllocationType allocation = site.GetAllocationType();
  RecordDependency(zone_->New<PretenureModeDependency>(site, allocation));
  return allocation;
}

PropertyConstness CompilationDependencies::DependOnFieldConstness(
    MapRef map, MapRef owner, InternalIndex descriptor) {
  PropertyConstness constness =
      map.GetPropertyDetails(broker_, descriptor).constness();
  if (constness == PropertyConstness::kMutable) return constness;

  // If the map can have fast elements transitions, then the field can be only
  // considered constant if the map does not transition.
  if (Map::CanHaveFastTransitionableElementsKind(map.instance_type())) {
    // If the map can already transition away, let us report the field as
    // mutable.
    if (!map.is_stable()) {
      return PropertyConstness::kMutable;
    }
    DependOnStableMap(map);
  }

  DCHECK_EQ(constness, PropertyConstness::kConst);
  RecordDependency(
      zone_->New<FieldConstnessDependency>(map, owner, descriptor));
  return PropertyConstness::kConst;
}

void CompilationDependencies::DependOnGlobalProperty(PropertyCellRef cell) {
  PropertyCellType type = cell.property_details().cell_type();
  bool read_only = cell.property_details().IsReadOnly();
  RecordDependency(zone_->New<GlobalPropertyDependency>(cell, type, read_only));
}

bool CompilationDependencies::DependOnScriptContextSlotProperty(
    ContextRef script_context, size_t index,
    ContextSidePropertyCell::Property property, JSHeapBroker* broker) {
  if ((v8_flags.const_tracking_let ||
       v8_flags.script_context_mutable_heap_number) &&
      script_context.object()->IsScriptContext() &&
      script_context.object()->GetScriptContextSideProperty(index) ==
          property) {
    RecordDependency(zone_->New<ScriptContextSlotPropertyDependency>(
        script_context, index, property));
    return true;
  }
  return false;
}

bool CompilationDependencies::DependOnEmptyContextExtension(
    ScopeInfoRef scope_info) {
  if (!v8_flags.empty_context_extension_dep) return false;
  DCHECK(scope_info.SloppyEvalCanExtendVars());
  if (HeapLayout::InReadOnlySpace(*scope_info.object()) ||
      scope_info.object()->SomeContextHasExtension()) {
    // There are respective contexts with non-empty context extension, so
    // dynamic checks are required.
    return false;
  }
  RecordDependency(zone_->New<EmptyContextExtensionDependency>(scope_info));
  return true;
}

bool CompilationDependencies::DependOnProtector(PropertyCellRef cell) {
  cell.CacheAsProtector(broker_);
  if (cell.value(broker_).AsSmi() != Protectors::kProtectorValid) return false;
  RecordDependency(zone_->New<ProtectorDependency>(cell));
  return true;
}

bool CompilationDependencies::DependOnMegaDOMProtector() {
  return DependOnProtector(
      MakeRef(broker_, broker_->isolate()->factory()->mega_dom_protector()));
}

bool CompilationDependencies::DependOnNoProfilingProtector() {
  // A shortcut in case profiling was already enabled but the interrupt
  // request to invalidate NoProfilingProtector wasn't processed yet.
#ifdef V8_RUNTIME_CALL_STATS
  if (TracingFlags::is_runtime_stats_enabled()) return false;
#endif
  if (broker_->isolate()->is_profiling()) return false;
  return DependOnProtector(MakeRef(
      broker_, broker_->isolate()->factory()->no_profiling_protector()));
}

bool CompilationDependencies::DependOnNoUndetectableObjectsProtector() {
  return DependOnProtector(MakeRef(
      broker_,
      broker_->isolate()->factory()->no_undetectable_objects_protector()));
}

bool CompilationDependencies::DependOnArrayBufferDetachingProtector() {
  return DependOnProtector(MakeRef(
      broker_,
      broker_->isolate()->factory()->array_buffer_detaching_protector()));
}

bool CompilationDependencies::DependOnArrayIteratorProtector() {
  return DependOnProtector(MakeRef(
      broker_, broker_->isolate()->factory()->array_iterator_protector()));
}

bool CompilationDependencies::DependOnArraySpeciesProtector() {
  return DependOnProtector(MakeRef(
      broker_, broker_->isolate()->factory()->array_species_protector()));
}

bool CompilationDependencies::DependOnNoElementsProtector() {
  return DependOnProtector(
      MakeRef(broker_, broker_->isolate()->factory()->no_elements_protector()));
}

bool CompilationDependencies::DependOnPromiseHookProtector() {
  return DependOnProtector(MakeRef(
      broker_, broker_->isolate()->factory()->promise_hook_protector()));
}

bool CompilationDependencies::DependOnPromiseSpeciesProtector() {
  return DependOnProtector(MakeRef(
      broker_, broker_->isolate()->factory()->promise_species_protector()));
}

bool CompilationDependencies::DependOnPromiseThenProtector() {
  return DependOnProtector(MakeRef(
      broker_, broker_->isolate()->factory()->promise_then_protector()));
}

bool CompilationDependencies::DependOnStringWrapperToPrimitiveProtector() {
  return DependOnProtector(MakeRef(
      broker_,
      broker_->isolate()->factory()->string_wrapper_to_primitive_protector()));
}

void CompilationDependencies::DependOnElementsKind(AllocationSiteRef site) {
  ElementsKind kind =
      site.PointsToLiteral()
          ? site.boilerplate(broker_).value().map(broker_).elements_kind()
          : site.GetElementsKind();
  if (AllocationSite::ShouldTrack(kind)) {
    RecordDependency(zone_->New<ElementsKindDependency>(site, kind));
  }
}

void CompilationDependencies::DependOnObjectSlotValue(HeapObjectRef object,
                                                      int offset,
                                                      ObjectRef value) {
  RecordDependency(
      zone_->New<ObjectSlotValueDependency>(object, offset, value));
}

void CompilationDependencies::DependOnOwnConstantElement(JSObjectRef holder,
                                                         uint32_t index,
                                                         ObjectRef element) {
  RecordDependency(
      zone_->New<OwnConstantElementDependency>(holder, index, element));
}

void CompilationDependencies::DependOnOwnConstantDataProperty(
    JSObjectRef holder, MapRef map, FieldIndex index, ObjectRef value) {
  RecordDependency(zone_->New<OwnConstantDataPropertyDependency>(
      broker_, holder, map, index, value));
}

void CompilationDependencies::DependOnOwnConstantDoubleProperty(
    JSObjectRef holder, MapRef map, FieldIndex index, Float64 value) {
  RecordDependency(zone_->New<OwnConstantDoublePropertyDependency>(
      broker_, holder, map, index, value));
}

void CompilationDependencies::DependOnOwnConstantDictionaryProperty(
    JSObjectRef holder, InternalIndex index, ObjectRef value) {
  RecordDependency(zone_->New<OwnConstantDictionaryPropertyDependency>(
      broker_, holder, index, value));
}

V8_INLINE void TraceInvalidCompilationDependency(
    compiler::JSHeapBroker* broker, const CompilationDependency* d) {
  DCHECK(v8_flags.trace_compilation_dependencies);
  DCHECK(!d->IsValid(broker));
  PrintF("Compilation aborted due to invalid dependency: %s\n", d->ToString());
}

bool CompilationDependencies::Commit(Handle<Code> code) {
  if (!PrepareInstall()) return false;

  {
    PendingDependencies pending_deps(zone_);
    DisallowCodeDependencyChange no_dependency_change;
    for (const CompilationDependency* dep : dependencies_) {
      // Check each dependency's validity again right before installing it,
      // because the first iteration above might have invalidated some
      // dependencies. For example, PrototypePropertyDependency::PrepareInstall
      // can call EnsureHasInitialMap, which can invalidate a
      // StableMapDependency on the prototype object's map.
      if (!dep->IsValid(broker_)) {
        if (v8_flags.trace_compilation_dependencies) {
          TraceInvalidCompilationDependency(broker_, dep);
        }
        dependencies_.clear();
        return false;
      }
      dep->Install(broker_, &pending_deps);
    }
    pending_deps.InstallAll(broker_->isolate(), code);
  }

  // It is even possible that a GC during the above installations invalidated
  // one of the dependencies. However, this should only affect
  //
  // 1. pretenure mode dependencies, or
  // 2. function consistency dependencies,
  //
  // which we assert below. It is safe to return successfully in these cases,
  // because
  //
  // 1. once the code gets executed it will do a stack check that triggers its
  //    deoptimization.
  // 2. since the function state was deemed consistent above, that means the
  //    compilation saw a self-consistent state of the jsfunction.
  if (v8_flags.stress_gc_during_compilation) {
    broker_->isolate()->heap()->PreciseCollectAllGarbage(
        GCFlag::kForced, GarbageCollectionReason::kTesting, kNoGCCallbackFlags);
  }
#ifdef DEBUG
  for (auto dep : dependencies_) {
    CHECK_IMPLIES(!dep->IsValid(broker_),
                  dep->IsPretenureMode() || dep->IsConsistentJSFunctionView());
  }
#endif

  dependencies_.clear();
  return true;
}

bool CompilationDependencies::PrepareInstall() {
  if (V8_UNLIKELY(v8_flags.predictable)) {
    return PrepareInstallPredictable();
  }

  for (auto dep : dependencies_) {
    if (!dep->IsValid(broker_)) {
      if (v8_flags.trace_compilation_dependencies) {
        TraceInvalidCompilationDependency(broker_, dep);
      }
      dependencies_.clear();
      return false;
    }
    dep->PrepareInstall(broker_);
  }
  return true;
}

bool CompilationDependencies::PrepareInstallPredictable() {
  CHECK(v8_flags.predictable);

  std::vector<const CompilationDependency*> deps(dependencies_.begin(),
                                                 dependencies_.end());
  std::sort(deps.begin(), deps.end());

  for (auto dep : deps) {
    if (!dep->IsValid(broker_)) {
      if (v8_flags.trace_compilation_dependencies) {
        TraceInvalidCompilationDependency(broker_, dep);
      }
      dependencies_.clear();
      return false;
    }
    dep->PrepareInstall(broker_);
  }
  return true;
}

#define V(Name)                                                     \
  const Name##Dependency* CompilationDependency::As##Name() const { \
    DCHECK(Is##Name());                                             \
    return static_cast<const Name##Dependency*>(this);              \
  }
DEPENDENCY_LIST(V)
#undef V

void CompilationDependencies::DependOnStablePrototypeChains(
    ZoneVector<MapRef> const& receiver_maps, WhereToStart start,
    OptionalJSObjectRef last_prototype) {
  for (MapRef receiver_map : receiver_maps) {
    DependOnStablePrototypeChain(receiver_map, start, last_prototype);
  }
}

void CompilationDependencies::DependOnStablePrototypeChain(
    MapRef receiver_map, WhereToStart start,
    OptionalJSObjectRef last_prototype) {
  if (receiver_map.IsPrimitiveMap()) {
    // Perform the implicit ToObject for primitives here.
    // Implemented according to ES6 section 7.3.2 GetV (V, P).
    // Note: Keep sync'd with AccessInfoFactory::ComputePropertyAccessInfo.
    OptionalJSFunctionRef constructor =
        broker_->target_native_context().GetConstructorFunction(broker_,
                                                                receiver_map);
    receiver_map = constructor.value().initial_map(broker_);
  }
  if (start == kStartAtReceiver) DependOnStableMap(receiver_map);

  MapRef map = receiver_map;
  while (true) {
    HeapObjectRef proto = map.prototype(broker_);
    if (!proto.IsJSObject()) {
      CHECK_EQ(proto.map(broker_).oddball_type(broker_), OddballType::kNull);
      break;
    }
    map = proto.map(broker_);
    DependOnStableMap(map);
    if (last_prototype.has_value() && proto.equals(*last_prototype)) break;
  }
}

void CompilationDependencies::DependOnElementsKinds(AllocationSiteRef site) {
  AllocationSiteRef current = site;
  while (true) {
    DependOnElementsKind(current);
    if (!current.nested_site(broker_).IsAllocationSite()) break;
    current = current.nested_site(broker_).AsAllocationSite();
  }
  CHECK_EQ(current.nested_site(broker_).AsSmi(), 0);
}

void CompilationDependencies::DependOnConsistentJSFunctionView(
    JSFunctionRef function) {
  RecordDependency(zone_->New<ConsistentJSFunctionViewDependency>(function));
}

void CompilationDependencies::DependOnNoSlackTrackingChange(MapRef map) {
  if (map.construction_counter() == 0) return;
  RecordDependency(zone_->New<NoSlackTrackingChangeDependency>(map));
}

SlackTrackingPrediction::SlackTrackingPrediction(MapRef initial_map,
                                                 int instance_size)
    : instance_size_(instance_size),
      inobject_property_count_(
          (instance_size >> kTaggedSizeLog2) -
          initial_map.GetInObjectPropertiesStartInWords()) {}

SlackTrackingPrediction
CompilationDependencies::DependOnInitialMapInstanceSizePrediction(
    JSFunctionRef function) {
  MapRef initial_map = DependOnInitialMap(function);
  int instance_size = function.InitialMapInstanceSizeWithMinSlack(broker_);
  // Currently, we always install the prediction dependency. If this turns out
  // to be too expensive, we can only install the dependency if slack
  // tracking is active.
  RecordDependency(zone_->New<InitialMapInstanceSizePredictionDependency>(
      function, instance_size));
  CHECK_LE(instance_size, function.initial_map(broker_).instance_size());
  return SlackTrackingPrediction(initial_map, instance_size);
}

CompilationDependency const*
CompilationDependencies::TransitionDependencyOffTheRecord(
    MapRef target_map) const {
  if (target_map.CanBeDeprecated()) {
    return zone_->New<TransitionDependency>(target_map);
  } else {
    DCHECK(!target_map.is_deprecated());
    return nullptr;
  }
}

CompilationDependency const*
CompilationDependencies::FieldRepresentationDependencyOffTheRecord(
    MapRef map, MapRef owner, InternalIndex descriptor,
    Representation representation) const {
  return zone_->New<FieldRepresentationDependency>(map, owner, descriptor,
                                                   representation);
}

CompilationDependency const*
CompilationDependencies::FieldTypeDependencyOffTheRecord(
    MapRef map, MapRef owner, InternalIndex descriptor, ObjectRef type) const {
  return zone_->New<FieldTypeDependency>(map, owner, descriptor, type);
}

#ifdef DEBUG
// static
bool CompilationDependencies::IsFieldRepresentationDependencyOnMap(
    const CompilationDependency* dep, const Handle<Map>& receiver_map) {
  return dep->IsFieldRepresentation() &&
         dep->AsFieldRepresentation()->DependsOn(receiver_map);
}
#endif  // DEBUG

#undef DEPENDENCY_LIST

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```