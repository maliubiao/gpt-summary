Response: Let's break down the thought process to analyze the C++ code and relate it to JavaScript.

**1. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code for familiar keywords and patterns. Things that jump out are:

* `// Copyright`, `#include`:  Standard C++ header. Not directly relevant to the core function.
* `namespace v8::internal`:  Indicates this is internal V8 implementation code, not public API.
* `literal-objects`:  The filename itself is a strong hint. This likely deals with how JavaScript literal objects (like `{}`) are handled internally.
* `ClassBoilerplate`, `ObjectDescriptor`, `ArrayBoilerplateDescription`, `RegExpBoilerplateDescription`: These class names suggest the code is responsible for creating templates or blueprints for different kinds of literal objects. "Boilerplate" often refers to pre-configured structures.
* `DescriptorArray`, `NameDictionary`, `SwissNameDictionary`, `NumberDictionary`: These look like internal data structures used by V8 to store object properties efficiently. The different dictionary types likely represent optimizations for various scenarios (e.g., sparse vs. dense objects, string vs. numeric keys).
* `PropertyDetails`, `PropertyAttributes`:  These likely define the characteristics of object properties (e.g., enumerable, writable, configurable).
* `AccessorPair`:  This clearly relates to getters and setters in JavaScript.
* `Smi`:  Short for "Small Integer," a V8 optimization.
* `kData`, `kGetter`, `kSetter`, `kAutoAccessor`: These enums within `ClassBoilerplate` directly map to different kinds of JavaScript properties.
* `ComputeEnumerationIndex`:  Suggests the code is concerned with the order in which properties are iterated over.
* Template Metaprogramming (`template <typename IsolateT>`) :  Indicates the code is designed to be used with different types of isolates (which represent independent JavaScript execution environments).

**2. Focusing on `ClassBoilerplate` and `ObjectDescriptor`:**

Given the filename and the prominent use of `ClassBoilerplate`, it's a good guess that this is a central class. The `ObjectDescriptor` nested class seems like a helper for building the `ClassBoilerplate`.

**3. Analyzing `ObjectDescriptor`'s Functionality:**

* **Purpose:** The comments and methods suggest `ObjectDescriptor` is responsible for collecting information about an object's properties (name, type, attributes, computed properties) and then creating the necessary internal data structures (`DescriptorArray`, dictionaries, etc.).
* **`CreateTemplates()`:** This method is key. It allocates the initial data structures based on the counts of properties and computed properties. The choice between `DescriptorArray` and dictionaries is important for performance.
* **`AddConstant()`, `AddNamedProperty()`, `AddIndexedProperty()`, `AddComputed()`:** These methods handle adding different types of properties to the templates being built. The logic within these methods shows how V8 represents properties internally (e.g., using `Descriptor` for `DescriptorArray`, adding entries to dictionaries).
* **`Finalize()`:** This seems to perform final setup after all properties have been added.

**4. Understanding `ClassBoilerplate::New()`:**

* **Purpose:** This static method is responsible for creating a new `ClassBoilerplate` instance, which serves as a blueprint for creating instances of a JavaScript class.
* **Workflow:** It uses two `ObjectDescriptor` instances: one for static members of the class and one for instance members (prototype).
* **Property Iteration:** The loop iterating through `expr->public_members()` processes each property of the JavaScript class definition.
* **Mapping to JavaScript:**  The `switch` statement based on `property->kind()` is crucial for understanding the connection to JavaScript. It maps JavaScript class member types (methods, getters, setters, fields) to V8's internal representation.
* **Computed Properties:** The handling of `is_computed_name()` shows how V8 deals with properties whose names are determined at runtime (e.g., `{[key]: value}`).
* **Finalization:**  It calls `Finalize()` on both `ObjectDescriptor` instances and then populates the `ClassBoilerplate` object with the created templates.

**5. Connecting to JavaScript Examples:**

Now, the key is to illustrate how this C++ code relates to actual JavaScript code.

* **Basic Object Literal:** A simple object literal like `const obj = { a: 1, b: 'hello' };` directly triggers the mechanisms described in this file. V8 needs to create a structure to store the properties 'a' and 'b' and their values. This would likely involve the `ObjectDescriptor` and potentially a `DescriptorArray` if the object is small enough.
* **Class Definition:**  A class definition like `class MyClass { constructor() { this.x = 1; } get y() { return 2; } set z(val) { this._z = val; } static staticMethod() {} }`  is the primary focus of the `ClassBoilerplate`. The `ClassBoilerplate::New()` method is directly involved in processing this definition, creating templates for both the class itself (static members) and its prototype (instance members).
* **Computed Property Names:** The example with `const obj = { [key]: value };` demonstrates the handling of computed properties. The `AddComputed()` method in `ObjectDescriptor` is used in this case.
* **Getters and Setters:** The `get` and `set` keywords in JavaScript classes directly correspond to the `kGetter` and `kSetter` value kinds in the C++ code and the creation of `AccessorPair` objects.

**6. Refinement and Explanation:**

Finally, the process involves organizing the findings into a coherent explanation, focusing on the core functionality and providing clear JavaScript examples. The key is to bridge the gap between the low-level C++ implementation and the high-level JavaScript concepts. Explaining the different dictionary types and their potential performance implications adds further depth. Highlighting the purpose of enumeration order and how computed properties affect it is also important.
这个 C++ 源代码文件 `v8/src/objects/literal-objects.cc` 的主要功能是**定义和实现了用于创建和管理 JavaScript 字面量对象（包括普通对象、数组和正则表达式）的模板结构，特别是针对类的定义。**  它为 V8 引擎在编译和执行 JavaScript 代码时，高效地创建这些字面量对象提供了基础。

具体来说，这个文件做了以下几件事情：

**1. 定义了 `ClassBoilerplate` 类:**

* `ClassBoilerplate` 是一个核心结构，它充当了 JavaScript 类定义的“蓝图”或“模板”。
* 它存储了创建类实例所需的各种信息，例如静态属性、实例属性、计算属性以及它们对应的模板（`DescriptorArray` 或各种 `Dictionary` 类型）。
* `ClassBoilerplate::New()` 方法负责根据 `ClassLiteral` 语法树节点（AST）来创建 `ClassBoilerplate` 对象。

**2. 定义了 `ObjectDescriptor` 辅助类:**

* `ObjectDescriptor` 是一个模板类，用于辅助构建属性模板（`DescriptorArray` 或 `Dictionary`）。
* 它跟踪属性的数量、计算属性的数量，并根据需要创建合适的模板结构。
* 它提供了添加常量属性、命名属性、索引属性和计算属性的方法，并将这些属性信息添加到相应的模板中。

**3. 处理不同类型的属性:**

* 代码区分了数据属性（`kData`）、getter 属性（`kGetter`）、setter 属性（`kSetter`）和自动访问器属性（`kAutoAccessor`），并为每种类型生成相应的内部表示。
* 它处理了属性的属性（例如，是否可枚举、可写、可配置）。
* 它还处理了计算属性，这些属性的名称是在运行时计算出来的。

**4. 管理属性存储:**

* 代码根据属性的数量和类型，选择使用 `DescriptorArray` (适用于少量属性) 或各种 `Dictionary` 类型 (`NameDictionary`, `SwissNameDictionary`, `NumberDictionary`) 来存储属性信息，以优化内存使用和访问速度。
* `DescriptorArray` 适用于静态已知的少量属性，而 `Dictionary` 适用于动态添加或数量较多的属性。

**5. 处理数组和正则表达式字面量:**

* 虽然 `ClassBoilerplate` 是这个文件的重点，但文件中也包含了 `ArrayBoilerplateDescription` 和 `RegExpBoilerplateDescription` 结构，它们分别用于描述数组和正则表达式字面量的模板信息。

**6. 维护属性枚举顺序:**

* 代码考虑了属性的枚举顺序，并尽力在内部表示中维护这个顺序。

**与 JavaScript 的关系及示例:**

这个文件直接关系到 JavaScript 中定义类和创建对象的过程。当 V8 引擎遇到 JavaScript 中的类定义或对象字面量时，会利用这里定义的结构和方法来创建内部表示。

**JavaScript 类示例:**

```javascript
class MyClass {
  constructor(x) {
    this.x = x;
    this.y = 10;
  }

  getMethod() {
    return this.x + this.y;
  }

  set setMethod(value) {
    this.y = value;
  }

  static staticProperty = 'static value';

  get computedProp() {
    return this.x * 2;
  }
}
```

当 V8 编译这段代码时，`ClassBoilerplate::New()` 方法会被调用，根据 `MyClass` 的定义创建一个 `ClassBoilerplate` 对象。这个 `ClassBoilerplate` 对象会包含：

* **静态属性模板:**  存储 `staticProperty` 的信息，可能使用 `DescriptorArray` 或 `NameDictionary`。
* **实例属性模板:** 存储 `constructor`、`getMethod`、`setMethod`、`computedProp` 以及隐式的 `x` 和 `y` 属性的信息，同样可能使用 `DescriptorArray` 或 `NameDictionary`。
* **计算属性信息:** 记录 `computedProp` 的 getter 方法。

**JavaScript 对象字面量示例:**

```javascript
const myObject = {
  a: 1,
  b: 'hello',
  get c() { return this.a + 1; }
};
```

虽然这个文件主要关注类，但创建对象字面量的过程也与类似的机制有关。V8 会创建一个类似的对象描述结构，用于存储 `a`、`b` 和 `c` (getter) 的信息。

**JavaScript 数组字面量示例:**

```javascript
const myArray = [1, 2, 'three'];
```

`ArrayBoilerplateDescription` 会被用来描述这个数组的元素类型和初始值（如果提供了）。

**JavaScript 正则表达式字面量示例:**

```javascript
const myRegex = /ab+c/i;
```

`RegExpBoilerplateDescription` 会存储正则表达式的模式和标志。

**总结:**

`v8/src/objects/literal-objects.cc` 是 V8 引擎中负责高效创建和管理 JavaScript 字面量对象的核心组件。它通过定义 `ClassBoilerplate` 和相关的辅助结构，为类、对象、数组和正则表达式的创建提供了模板和机制，从而提高了 JavaScript 代码的执行效率。  它将 JavaScript 的高级语法结构映射到 V8 内部的低级表示，是 V8 引擎实现的关键部分。

### 提示词
```
这是目录为v8/src/objects/literal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/literal-objects.h"

#include "src/ast/ast.h"
#include "src/base/logging.h"
#include "src/builtins/accessors.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/heap/local-factory-inl.h"
#include "src/objects/dictionary.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-regexp.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/objects/struct-inl.h"
#include "src/sandbox/isolate.h"

namespace v8 {
namespace internal {

namespace {

// The enumeration order index in the property details is unused if they are
// stored in a SwissNameDictionary or NumberDictionary (because they handle
// propery ordering differently). We then use this dummy value instead.
constexpr int kDummyEnumerationIndex = 0;

inline int EncodeComputedEntry(ClassBoilerplate::ValueKind value_kind,
                               unsigned key_index) {
  using Flags = ClassBoilerplate::ComputedEntryFlags;
  int flags = Flags::ValueKindBits::encode(value_kind) |
              Flags::KeyIndexBits::encode(key_index);
  return flags;
}

void SetAccessorPlaceholderIndices(Tagged<AccessorPair> pair,
                                   ClassBoilerplate::ValueKind value_kind,
                                   Tagged<Smi> index) {
  switch (value_kind) {
    case ClassBoilerplate::kGetter:
      pair->set_getter(index);
      break;
    case ClassBoilerplate::kSetter:
      pair->set_setter(index);
      break;
    case ClassBoilerplate::kAutoAccessor:
      // Auto-accessor set the pair of consecutive indices in a single call.
      pair->set_getter(index);
      pair->set_setter(Smi::FromInt(Smi::ToInt(index) + 1));
      break;
    default:
      UNREACHABLE();
  }
}

void SetAccessorPlaceholderIndices(Tagged<AccessorPair> pair,
                                   ClassBoilerplate::ValueKind value_kind,
                                   Tagged<Smi> index, ReleaseStoreTag tag) {
  switch (value_kind) {
    case ClassBoilerplate::kGetter:
      pair->set_getter(index, tag);
      break;
    case ClassBoilerplate::kSetter:
      pair->set_setter(index, tag);
      break;
    case ClassBoilerplate::kAutoAccessor:
      // Auto-accessor set the pair of consecutive indices in a single call.
      pair->set_getter(index, tag);
      pair->set_setter(Smi::FromInt(Smi::ToInt(index) + 1), tag);
      break;
    default:
      UNREACHABLE();
  }
}

template <typename IsolateT>
void AddToDescriptorArrayTemplate(
    IsolateT* isolate, DirectHandle<DescriptorArray> descriptor_array_template,
    Handle<Name> name, ClassBoilerplate::ValueKind value_kind,
    Handle<Object> value) {
  InternalIndex entry = descriptor_array_template->Search(
      *name, descriptor_array_template->number_of_descriptors());
  // TODO(ishell): deduplicate properties at AST level, this will allow us to
  // avoid creation of closures that will be overwritten anyway.
  if (entry.is_not_found()) {
    // Entry not found, add new one.
    Descriptor d;
    if (value_kind == ClassBoilerplate::kData) {
      d = Descriptor::DataConstant(name, value, DONT_ENUM);
    } else {
      DCHECK(value_kind == ClassBoilerplate::kGetter ||
             value_kind == ClassBoilerplate::kSetter ||
             value_kind == ClassBoilerplate::kAutoAccessor);
      Handle<AccessorPair> pair = isolate->factory()->NewAccessorPair();
      SetAccessorPlaceholderIndices(*pair, value_kind, Cast<Smi>(*value));
      d = Descriptor::AccessorConstant(name, pair, DONT_ENUM);
    }
    descriptor_array_template->Append(&d);

  } else {
    // Entry found, update it.
    int sorted_index = descriptor_array_template->GetDetails(entry).pointer();
    if (value_kind == ClassBoilerplate::kData) {
      Descriptor d = Descriptor::DataConstant(name, value, DONT_ENUM);
      d.SetSortedKeyIndex(sorted_index);
      descriptor_array_template->Set(entry, &d);
    } else {
      DCHECK(value_kind == ClassBoilerplate::kGetter ||
             value_kind == ClassBoilerplate::kSetter ||
             value_kind == ClassBoilerplate::kAutoAccessor);
      Tagged<Object> raw_accessor =
          descriptor_array_template->GetStrongValue(entry);
      Tagged<AccessorPair> pair;
      if (IsAccessorPair(raw_accessor)) {
        pair = Cast<AccessorPair>(raw_accessor);
      } else {
        Handle<AccessorPair> new_pair = isolate->factory()->NewAccessorPair();
        Descriptor d = Descriptor::AccessorConstant(name, new_pair, DONT_ENUM);
        d.SetSortedKeyIndex(sorted_index);
        descriptor_array_template->Set(entry, &d);
        pair = *new_pair;
      }
      SetAccessorPlaceholderIndices(*pair, value_kind, Cast<Smi>(*value),
                                    kReleaseStore);
    }
  }
}

template <typename IsolateT>
Handle<NameDictionary> DictionaryAddNoUpdateNextEnumerationIndex(
    IsolateT* isolate, Handle<NameDictionary> dictionary, Handle<Name> name,
    Handle<Object> value, PropertyDetails details,
    InternalIndex* entry_out = nullptr) {
  return NameDictionary::AddNoUpdateNextEnumerationIndex(
      isolate, dictionary, name, value, details, entry_out);
}

template <typename IsolateT>
Handle<SwissNameDictionary> DictionaryAddNoUpdateNextEnumerationIndex(
    IsolateT* isolate, Handle<SwissNameDictionary> dictionary,
    Handle<Name> name, Handle<Object> value, PropertyDetails details,
    InternalIndex* entry_out = nullptr) {
  // SwissNameDictionary does not maintain the enumeration order in property
  // details, so it's a normal Add().
  return SwissNameDictionary::Add(isolate, dictionary, name, value, details);
}

template <typename IsolateT>
Handle<NumberDictionary> DictionaryAddNoUpdateNextEnumerationIndex(
    IsolateT* isolate, Handle<NumberDictionary> dictionary, uint32_t element,
    Handle<Object> value, PropertyDetails details,
    InternalIndex* entry_out = nullptr) {
  // NumberDictionary does not maintain the enumeration order, so it's
  // a normal Add().
  return NumberDictionary::Add(isolate, dictionary, element, value, details,
                               entry_out);
}

// TODO(42203211): The first parameter should be just DirectHandle<Dictionary>
// but now it does not compile with implicit Handle to DirectHandle conversions.
template <template <typename> typename HandleType, typename Dictionary,
          typename = std::enable_if_t<std::is_convertible_v<
              HandleType<Dictionary>, DirectHandle<Dictionary>>>>
void DictionaryUpdateMaxNumberKey(HandleType<Dictionary> dictionary,
                                  DirectHandle<Name> name) {
  static_assert((std::is_same<Dictionary, SwissNameDictionary>::value ||
                 std::is_same<Dictionary, NameDictionary>::value));
  // No-op for (ordered) name dictionaries.
}

void DictionaryUpdateMaxNumberKey(DirectHandle<NumberDictionary> dictionary,
                                  uint32_t element) {
  dictionary->UpdateMaxNumberKey(element, Handle<JSObject>());
  dictionary->set_requires_slow_elements();
}

constexpr int ComputeEnumerationIndex(int value_index) {
  // We "shift" value indices to ensure that the enumeration index for the value
  // will not overlap with minimum properties set for both class and prototype
  // objects.
  return value_index +
         std::max({ClassBoilerplate::kMinimumClassPropertiesCount,
                   ClassBoilerplate::kMinimumPrototypePropertiesCount});
}

constexpr int kAccessorNotDefined = -1;

inline int GetExistingValueIndex(Tagged<Object> value) {
  return IsSmi(value) ? Smi::ToInt(value) : kAccessorNotDefined;
}

template <typename IsolateT, typename Dictionary, typename Key>
void AddToDictionaryTemplate(IsolateT* isolate, Handle<Dictionary> dictionary,
                             Key key, int key_index,
                             ClassBoilerplate::ValueKind value_kind,
                             Tagged<Smi> value) {
  InternalIndex entry = dictionary->FindEntry(isolate, key);

  const bool is_elements_dictionary =
      std::is_same<Dictionary, NumberDictionary>::value;
  static_assert(is_elements_dictionary !=
                (std::is_same<Dictionary, NameDictionary>::value ||
                 std::is_same<Dictionary, SwissNameDictionary>::value));

  if (entry.is_not_found()) {
    // Entry not found, add new one.
    int enum_order =
        Dictionary::kIsOrderedDictionaryType || is_elements_dictionary
            ? kDummyEnumerationIndex
            : ComputeEnumerationIndex(key_index);
    Handle<Object> value_handle;
    PropertyDetails details(
        value_kind != ClassBoilerplate::kData ? PropertyKind::kAccessor
                                              : PropertyKind::kData,
        DONT_ENUM, PropertyDetails::kConstIfDictConstnessTracking, enum_order);
    if (value_kind == ClassBoilerplate::kData) {
      value_handle = handle(value, isolate);
    } else {
      DCHECK(value_kind == ClassBoilerplate::kGetter ||
             value_kind == ClassBoilerplate::kSetter ||
             value_kind == ClassBoilerplate::kAutoAccessor);
      Handle<AccessorPair> pair(isolate->factory()->NewAccessorPair());
      SetAccessorPlaceholderIndices(*pair, value_kind, Cast<Smi>(value));
      value_handle = pair;
    }

    // Add value to the dictionary without updating next enumeration index.
    Handle<Dictionary> dict = DictionaryAddNoUpdateNextEnumerationIndex(
        isolate, dictionary, key, value_handle, details, &entry);
    // It is crucial to avoid dictionary reallocations because it may remove
    // potential gaps in enumeration indices values that are necessary for
    // inserting computed properties into right places in the enumeration order.
    CHECK_EQ(*dict, *dictionary);

    DictionaryUpdateMaxNumberKey(dictionary, key);

  } else {
    // Entry found, update it.
    int enum_order_existing =
        Dictionary::kIsOrderedDictionaryType
            ? kDummyEnumerationIndex
            : dictionary->DetailsAt(entry).dictionary_index();
    int enum_order_computed =
        Dictionary::kIsOrderedDictionaryType || is_elements_dictionary
            ? kDummyEnumerationIndex
            : ComputeEnumerationIndex(key_index);

    Tagged<Object> existing_value = dictionary->ValueAt(entry);
    if (value_kind == ClassBoilerplate::kData) {
      // Computed value is a normal method.
      if (IsAccessorPair(existing_value)) {
        Tagged<AccessorPair> current_pair = Cast<AccessorPair>(existing_value);

        int existing_getter_index =
            GetExistingValueIndex(current_pair->getter());
        int existing_setter_index =
            GetExistingValueIndex(current_pair->setter());
        // At least one of the accessors must already be defined.
        static_assert(kAccessorNotDefined < 0);
        DCHECK(existing_getter_index >= 0 || existing_setter_index >= 0);
        if (existing_getter_index < key_index &&
            existing_setter_index < key_index) {
          // Either both getter and setter were defined before the computed
          // method or just one of them was defined before while the other one
          // was not defined yet, so overwrite property to kData.
          PropertyDetails details(
              PropertyKind::kData, DONT_ENUM,
              PropertyDetails::kConstIfDictConstnessTracking,
              enum_order_existing);
          dictionary->DetailsAtPut(entry, details);
          dictionary->ValueAtPut(entry, value);

        } else if (existing_getter_index != kAccessorNotDefined &&
                   existing_getter_index < key_index) {
          DCHECK_LT(key_index, existing_setter_index);
          // Getter was defined and it was done before the computed method
          // and then it was overwritten by the current computed method which
          // in turn was later overwritten by the setter method. So we clear
          // the getter.
          current_pair->set_getter(*isolate->factory()->null_value());

        } else if (existing_setter_index != kAccessorNotDefined &&
                   existing_setter_index < key_index) {
          DCHECK_LT(key_index, existing_getter_index);
          // Setter was defined and it was done before the computed method
          // and then it was overwritten by the current computed method which
          // in turn was later overwritten by the getter method. So we clear
          // the setter.
          current_pair->set_setter(*isolate->factory()->null_value());

        } else {
          // One of the following cases holds:
          // The computed method was defined before ...
          // 1.) the getter and setter, both of which are defined,
          // 2.) the getter, and the setter isn't defined,
          // 3.) the setter, and the getter isn't defined.
          // Therefore, the computed value is overwritten, receiving the
          // computed property's enum index.
          DCHECK(key_index < existing_getter_index ||
                 existing_getter_index == kAccessorNotDefined);
          DCHECK(key_index < existing_setter_index ||
                 existing_setter_index == kAccessorNotDefined);
          DCHECK(existing_getter_index != kAccessorNotDefined ||
                 existing_setter_index != kAccessorNotDefined);
          if (!is_elements_dictionary) {
            // The enum index is unused by elements dictionaries,
            // which is why we don't need to update the property details if
            // |is_elements_dictionary| holds.
            PropertyDetails details = dictionary->DetailsAt(entry);
            details = details.set_index(enum_order_computed);
            dictionary->DetailsAtPut(entry, details);
          }
        }
      } else {  // if (existing_value.IsAccessorPair()) ends here
        DCHECK(value_kind == ClassBoilerplate::kData);

        DCHECK_IMPLIES(!IsSmi(existing_value), IsAccessorInfo(existing_value));
        DCHECK_IMPLIES(!IsSmi(existing_value),
                       Cast<AccessorInfo>(existing_value)->name() ==
                               *isolate->factory()->length_string() ||
                           Cast<AccessorInfo>(existing_value)->name() ==
                               *isolate->factory()->name_string());
        if (!IsSmi(existing_value) || Smi::ToInt(existing_value) < key_index) {
          // Overwrite existing value because it was defined before the computed
          // one (AccessorInfo "length" and "name" properties are always defined
          // before).
          PropertyDetails details(
              PropertyKind::kData, DONT_ENUM,
              PropertyDetails::kConstIfDictConstnessTracking,
              enum_order_existing);
          dictionary->DetailsAtPut(entry, details);
          dictionary->ValueAtPut(entry, value);
        } else {
          // The computed value appears before the existing one. Set the
          // existing entry's enum index to that of the computed one.
          if (!is_elements_dictionary) {
            // The enum index is unused by elements dictionaries,
            // which is why we don't need to update the property details if
            // |is_elements_dictionary| holds.
            PropertyDetails details(
                PropertyKind::kData, DONT_ENUM,
                PropertyDetails::kConstIfDictConstnessTracking,
                enum_order_computed);

            dictionary->DetailsAtPut(entry, details);
          }
        }
      }
    } else {  // if (value_kind == ClassBoilerplate::kData) ends here
      if (IsAccessorPair(existing_value)) {
        // Update respective component of existing AccessorPair.
        Tagged<AccessorPair> current_pair = Cast<AccessorPair>(existing_value);

        bool updated = false;
        switch (value_kind) {
          case ClassBoilerplate::kAutoAccessor: {
            int existing_get_component_index =
                GetExistingValueIndex(current_pair->get(ACCESSOR_GETTER));
            int existing_set_component_index =
                GetExistingValueIndex(current_pair->get(ACCESSOR_SETTER));
            if (existing_get_component_index < key_index &&
                existing_set_component_index < key_index) {
              SetAccessorPlaceholderIndices(current_pair, value_kind, value,
                                            kReleaseStore);
              updated = true;
            } else {
              if (existing_get_component_index < key_index) {
                SetAccessorPlaceholderIndices(current_pair,
                                              ClassBoilerplate::kGetter, value,
                                              kReleaseStore);
                updated = true;
              } else if (existing_set_component_index < key_index) {
                SetAccessorPlaceholderIndices(
                    current_pair, ClassBoilerplate::kSetter,
                    Smi::FromInt(Smi::ToInt(value) + 1), kReleaseStore);
                updated = true;
              }
            }
            break;
          }
          case ClassBoilerplate::kGetter:
          case ClassBoilerplate::kSetter: {
            AccessorComponent component =
                value_kind == ClassBoilerplate::kGetter ? ACCESSOR_GETTER
                                                        : ACCESSOR_SETTER;
            int existing_component_index =
                GetExistingValueIndex(current_pair->get(component));
            if (existing_component_index < key_index) {
              SetAccessorPlaceholderIndices(current_pair, value_kind, value,
                                            kReleaseStore);
              updated = true;
            }
            break;
          }
          default:
            UNREACHABLE();
        }
        if (!updated) {
          // The existing accessor property overwrites the computed one, update
          // its enumeration order accordingly.

          if (!is_elements_dictionary) {
            // The enum index is unused by elements dictionaries,
            // which is why we don't need to update the property details if
            // |is_elements_dictionary| holds.

            PropertyDetails details(
                PropertyKind::kAccessor, DONT_ENUM,
                PropertyDetails::kConstIfDictConstnessTracking,
                enum_order_computed);
            dictionary->DetailsAtPut(entry, details);
          }
        }

      } else {
        DCHECK(!IsAccessorPair(existing_value));
        DCHECK(value_kind != ClassBoilerplate::kData);

        if (!IsSmi(existing_value) || Smi::ToInt(existing_value) < key_index) {
          // Overwrite the existing data property because it was defined before
          // the computed accessor property.
          DirectHandle<AccessorPair> pair(
              isolate->factory()->NewAccessorPair());
          SetAccessorPlaceholderIndices(*pair, value_kind, value);
          PropertyDetails details(
              PropertyKind::kAccessor, DONT_ENUM,
              PropertyDetails::kConstIfDictConstnessTracking,
              enum_order_existing);
          dictionary->DetailsAtPut(entry, details);
          dictionary->ValueAtPut(entry, *pair);
        } else {
          // The computed accessor property appears before the existing data
          // property. Set the existing entry's enum index to that of the
          // computed one.

          if (!is_elements_dictionary) {
            // The enum index is unused by elements dictionaries,
            // which is why we don't need to update the property details if
            // |is_elements_dictionary| holds.
            PropertyDetails details(
                PropertyKind::kData, DONT_ENUM,
                PropertyDetails::kConstIfDictConstnessTracking,
                enum_order_computed);

            dictionary->DetailsAtPut(entry, details);
          }
        }
      }
    }
  }
}

}  // namespace

// Helper class that eases building of a properties, elements and computed
// properties templates.
template <typename IsolateT>
class ObjectDescriptor {
 public:
  void IncComputedCount() { ++computed_count_; }
  void IncPropertiesCount() { ++property_count_; }
  void IncElementsCount() { ++element_count_; }

  explicit ObjectDescriptor(int property_slack)
      : property_slack_(property_slack) {}

  bool HasDictionaryProperties() const {
    return computed_count_ > 0 ||
           (property_count_ + property_slack_) > kMaxNumberOfDescriptors;
  }

  Handle<Object> properties_template() const {
    return HasDictionaryProperties() ? properties_dictionary_template_
                                     : Cast<Object>(descriptor_array_template_);
  }

  Handle<NumberDictionary> elements_template() const {
    return elements_dictionary_template_;
  }

  Handle<FixedArray> computed_properties() const {
    return computed_properties_;
  }

  void CreateTemplates(IsolateT* isolate) {
    auto* factory = isolate->factory();
    descriptor_array_template_ = factory->empty_descriptor_array();
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      properties_dictionary_template_ =
          factory->empty_swiss_property_dictionary();
    } else {
      properties_dictionary_template_ = factory->empty_property_dictionary();
    }
    if (property_count_ || computed_count_ || property_slack_) {
      if (HasDictionaryProperties()) {
        int need_space_for =
            property_count_ + computed_count_ + property_slack_;
        if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
          properties_dictionary_template_ =
              isolate->factory()->NewSwissNameDictionary(need_space_for,
                                                         AllocationType::kOld);

        } else {
          properties_dictionary_template_ = NameDictionary::New(
              isolate, need_space_for, AllocationType::kOld);
        }
      } else {
        descriptor_array_template_ = DescriptorArray::Allocate(
            isolate, 0, property_count_ + property_slack_,
            AllocationType::kOld);
      }
    }
    elements_dictionary_template_ =
        element_count_ || computed_count_
            ? NumberDictionary::New(isolate, element_count_ + computed_count_,
                                    AllocationType::kOld)
            : factory->empty_slow_element_dictionary();

    computed_properties_ =
        computed_count_
            ? factory->NewFixedArray(computed_count_, AllocationType::kOld)
            : factory->empty_fixed_array();

    temp_handle_ = handle(Smi::zero(), isolate);
  }

  void AddConstant(IsolateT* isolate, Handle<Name> name, Handle<Object> value,
                   PropertyAttributes attribs) {
    bool is_accessor = IsAccessorInfo(*value);
    DCHECK(!IsAccessorPair(*value));
    if (HasDictionaryProperties()) {
      PropertyKind kind =
          is_accessor ? i::PropertyKind::kAccessor : i::PropertyKind::kData;
      int enum_order = V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL
                           ? kDummyEnumerationIndex
                           : next_enumeration_index_++;
      PropertyDetails details(kind, attribs, PropertyCellType::kNoCell,
                              enum_order);
      if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        properties_dictionary_template_ =
            DictionaryAddNoUpdateNextEnumerationIndex(
                isolate, properties_ordered_dictionary_template(), name, value,
                details);
      } else {
        properties_dictionary_template_ =
            DictionaryAddNoUpdateNextEnumerationIndex(
                isolate, properties_dictionary_template(), name, value,
                details);
      }
    } else {
      Descriptor d = is_accessor
                         ? Descriptor::AccessorConstant(name, value, attribs)
                         : Descriptor::DataConstant(name, value, attribs);
      descriptor_array_template_->Append(&d);
    }
  }

  void AddNamedProperty(IsolateT* isolate, Handle<Name> name,
                        ClassBoilerplate::ValueKind value_kind,
                        int value_index) {
    Tagged<Smi> value = Smi::FromInt(value_index);
    if (HasDictionaryProperties()) {
      UpdateNextEnumerationIndex(value_index);
      if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        AddToDictionaryTemplate(isolate,
                                properties_ordered_dictionary_template(), name,
                                value_index, value_kind, value);
      } else {
        AddToDictionaryTemplate(isolate, properties_dictionary_template(), name,
                                value_index, value_kind, value);
      }
    } else {
      temp_handle_.PatchValue(value);
      AddToDescriptorArrayTemplate(isolate, descriptor_array_template_, name,
                                   value_kind, temp_handle_);
    }
  }

  void AddIndexedProperty(IsolateT* isolate, uint32_t element,
                          ClassBoilerplate::ValueKind value_kind,
                          int value_index) {
    Tagged<Smi> value = Smi::FromInt(value_index);
    AddToDictionaryTemplate(isolate, elements_dictionary_template_, element,
                            value_index, value_kind, value);
  }

  void AddComputed(ClassBoilerplate::ValueKind value_kind, int key_index) {
    int value_index = key_index + 1;
    UpdateNextEnumerationIndex(value_index);

    int flags = EncodeComputedEntry(value_kind, key_index);
    computed_properties_->set(current_computed_index_++, Smi::FromInt(flags));
  }

  void UpdateNextEnumerationIndex(int value_index) {
    int current_index = ComputeEnumerationIndex(value_index);
    DCHECK_LE(next_enumeration_index_, current_index);
    next_enumeration_index_ = current_index + 1;
  }

  void Finalize(IsolateT* isolate) {
    if (HasDictionaryProperties()) {
      DCHECK_EQ(current_computed_index_, computed_properties_->length());
      if (!V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        properties_dictionary_template()->set_next_enumeration_index(
            next_enumeration_index_);
      }
    } else {
      DCHECK(descriptor_array_template_->IsSortedNoDuplicates());
    }
  }

 private:
  Handle<NameDictionary> properties_dictionary_template() const {
    return Cast<NameDictionary>(properties_dictionary_template_);
  }

  Handle<SwissNameDictionary> properties_ordered_dictionary_template() const {
    return Cast<SwissNameDictionary>(properties_dictionary_template_);
  }

  const int property_slack_;
  int property_count_ = 0;
  int next_enumeration_index_ = PropertyDetails::kInitialIndex;
  int element_count_ = 0;
  int computed_count_ = 0;
  int current_computed_index_ = 0;

  Handle<DescriptorArray> descriptor_array_template_;

  // Is either a NameDictionary or SwissNameDictionary.
  Handle<HeapObject> properties_dictionary_template_;

  Handle<NumberDictionary> elements_dictionary_template_;
  Handle<FixedArray> computed_properties_;
  // This temporary handle is used for storing to descriptor array.
  Handle<Object> temp_handle_;
};

template <typename IsolateT, typename PropertyDict>
void ClassBoilerplate::AddToPropertiesTemplate(
    IsolateT* isolate, Handle<PropertyDict> dictionary, Handle<Name> name,
    int key_index, ClassBoilerplate::ValueKind value_kind, Tagged<Smi> value) {
  AddToDictionaryTemplate(isolate, dictionary, name, key_index, value_kind,
                          value);
}
template void ClassBoilerplate::AddToPropertiesTemplate(
    Isolate* isolate, Handle<NameDictionary> dictionary, Handle<Name> name,
    int key_index, ClassBoilerplate::ValueKind value_kind, Tagged<Smi> value);
template void ClassBoilerplate::AddToPropertiesTemplate(
    LocalIsolate* isolate, Handle<NameDictionary> dictionary, Handle<Name> name,
    int key_index, ClassBoilerplate::ValueKind value_kind, Tagged<Smi> value);
template void ClassBoilerplate::AddToPropertiesTemplate(
    Isolate* isolate, Handle<SwissNameDictionary> dictionary, Handle<Name> name,
    int key_index, ClassBoilerplate::ValueKind value_kind, Tagged<Smi> value);

template <typename IsolateT>
void ClassBoilerplate::AddToElementsTemplate(
    IsolateT* isolate, Handle<NumberDictionary> dictionary, uint32_t key,
    int key_index, ClassBoilerplate::ValueKind value_kind, Tagged<Smi> value) {
  AddToDictionaryTemplate(isolate, dictionary, key, key_index, value_kind,
                          value);
}
template void ClassBoilerplate::AddToElementsTemplate(
    Isolate* isolate, Handle<NumberDictionary> dictionary, uint32_t key,
    int key_index, ClassBoilerplate::ValueKind value_kind, Tagged<Smi> value);
template void ClassBoilerplate::AddToElementsTemplate(
    LocalIsolate* isolate, Handle<NumberDictionary> dictionary, uint32_t key,
    int key_index, ClassBoilerplate::ValueKind value_kind, Tagged<Smi> value);

// static
template <typename IsolateT>
Handle<ClassBoilerplate> ClassBoilerplate::New(IsolateT* isolate,
                                               ClassLiteral* expr,
                                               AllocationType allocation) {
  // Create a non-caching handle scope to ensure that the temporary handle used
  // by ObjectDescriptor for passing Smis around does not corrupt handle cache
  // in CanonicalHandleScope.
  typename IsolateT::HandleScopeType scope(isolate);
  auto* factory = isolate->factory();
  ObjectDescriptor<IsolateT> static_desc(kMinimumClassPropertiesCount);
  ObjectDescriptor<IsolateT> instance_desc(kMinimumPrototypePropertiesCount);

  for (int i = 0; i < expr->public_members()->length(); i++) {
    ClassLiteral::Property* property = expr->public_members()->at(i);
    ObjectDescriptor<IsolateT>& desc =
        property->is_static() ? static_desc : instance_desc;
    if (property->is_computed_name()) {
      if (property->kind() != ClassLiteral::Property::FIELD) {
        desc.IncComputedCount();
      }
    } else {
      if (property->key()->AsLiteral()->IsPropertyName()) {
        desc.IncPropertiesCount();
      } else {
        desc.IncElementsCount();
      }
    }
  }

  //
  // Initialize class object template.
  //
  static_desc.CreateTemplates(isolate);
  static_assert(JSFunction::kLengthDescriptorIndex == 0);
  {
    // Add length_accessor.
    PropertyAttributes attribs =
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);
    static_desc.AddConstant(isolate, factory->length_string(),
                            factory->function_length_accessor(), attribs);
  }
  {
    // Add name_accessor.
    // All classes, even anonymous ones, have a name accessor.
    PropertyAttributes attribs =
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);
    static_desc.AddConstant(isolate, factory->name_string(),
                            factory->function_name_accessor(), attribs);
  }
  {
    // Add prototype_accessor.
    PropertyAttributes attribs =
        static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);
    static_desc.AddConstant(isolate, factory->prototype_string(),
                            factory->function_prototype_accessor(), attribs);
  }
  {
    Handle<ClassPositions> class_positions = factory->NewClassPositions(
        expr->start_position(), expr->end_position());
    static_desc.AddConstant(isolate, factory->class_positions_symbol(),
                            class_positions, DONT_ENUM);
  }

  //
  // Initialize prototype object template.
  //
  instance_desc.CreateTemplates(isolate);
  {
    Handle<Object> value(
        Smi::FromInt(ClassBoilerplate::kConstructorArgumentIndex), isolate);
    instance_desc.AddConstant(isolate, factory->constructor_string(), value,
                              DONT_ENUM);
  }

  //
  // Fill in class boilerplate.
  //
  int dynamic_argument_index = ClassBoilerplate::kFirstDynamicArgumentIndex;

  for (int i = 0; i < expr->public_members()->length(); i++) {
    ClassLiteral::Property* property = expr->public_members()->at(i);
    ClassBoilerplate::ValueKind value_kind;
    int value_index = dynamic_argument_index;
    switch (property->kind()) {
      case ClassLiteral::Property::METHOD:
        value_kind = ClassBoilerplate::kData;
        break;
      case ClassLiteral::Property::GETTER:
        value_kind = ClassBoilerplate::kGetter;
        break;
      case ClassLiteral::Property::SETTER:
        value_kind = ClassBoilerplate::kSetter;
        break;
      case ClassLiteral::Property::FIELD:
        DCHECK_IMPLIES(property->is_computed_name(), !property->is_private());
        if (property->is_computed_name()) {
          ++dynamic_argument_index;
        }
        continue;
      case ClassLiteral::Property::AUTO_ACCESSOR:
        value_kind = ClassBoilerplate::kAutoAccessor;
        // Auto-accessors have two arguments (getter and setter).
        ++dynamic_argument_index;
    }

    ObjectDescriptor<IsolateT>& desc =
        property->is_static() ? static_desc : instance_desc;
    if (property->is_computed_name()) {
      int computed_name_index = value_index;
      dynamic_argument_index += 2;  // Computed name and value indices.
      desc.AddComputed(value_kind, computed_name_index);
      continue;
    }
    dynamic_argument_index++;

    Literal* key_literal = property->key()->AsLiteral();
    uint32_t index;
    if (key_literal->AsArrayIndex(&index)) {
      desc.AddIndexedProperty(isolate, index, value_kind, value_index);

    } else {
      Handle<String> name = key_literal->AsRawPropertyName()->string();
      DCHECK(IsInternalizedString(*name));
      desc.AddNamedProperty(isolate, name, value_kind, value_index);
    }
  }

  static_desc.Finalize(isolate);
  instance_desc.Finalize(isolate);

  auto result = Cast<ClassBoilerplate>(
      factory->NewStruct(CLASS_BOILERPLATE_TYPE, allocation));

  result->set_arguments_count(dynamic_argument_index);

  result->set_static_properties_template(*static_desc.properties_template());
  result->set_static_elements_template(*static_desc.elements_template());
  result->set_static_computed_properties(*static_desc.computed_properties());

  result->set_instance_properties_template(
      *instance_desc.properties_template());
  result->set_instance_elements_template(*instance_desc.elements_template());
  result->set_instance_computed_properties(
      *instance_desc.computed_properties());

  return scope.CloseAndEscape(result);
}

template Handle<ClassBoilerplate> ClassBoilerplate::New(
    Isolate* isolate, ClassLiteral* expr, AllocationType allocation);
template Handle<ClassBoilerplate> ClassBoilerplate::New(
    LocalIsolate* isolate, ClassLiteral* expr, AllocationType allocation);

void ArrayBoilerplateDescription::BriefPrintDetails(std::ostream& os) {
  os << " " << ElementsKindToString(elements_kind()) << ", "
     << Brief(constant_elements());
}

void RegExpBoilerplateDescription::BriefPrintDetails(std::ostream& os) {
  // Note: keep boilerplate layout synced with JSRegExp layout.
  static_assert(JSRegExp::kDataOffset == JSObject::kHeaderSize);
  static_assert(JSRegExp::kSourceOffset == JSRegExp::kDataOffset + kTaggedSize);
  static_assert(JSRegExp::kFlagsOffset ==
                JSRegExp::kSourceOffset + kTaggedSize);
  static_assert(JSRegExp::kHeaderSize == JSRegExp::kFlagsOffset + kTaggedSize);
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  os << " " << Brief(data(isolate)) << ", " << Brief(source()) << ", "
     << flags();
}

}  // namespace internal
}  // namespace v8
```