Response:
The user wants a summary of the provided C++ code snippet for `v8/src/objects/literal-objects.cc`. The summary should cover:

1. **Functionality:** What does this code do?
2. **Torque Source:** Is it a Torque file (indicated by a `.tq` extension)?
3. **JavaScript Relation:** If it's related to JavaScript features, provide JavaScript examples.
4. **Code Logic & Reasoning:**  If there are logical steps, explain them with hypothetical inputs and outputs.
5. **Common Programming Errors:** Point out any common mistakes related to this code.
6. **Overall Summary:** A concise recap of the file's purpose.

Let's break down the code and address each point:

*   **Includes:** The code includes various V8 headers related to AST (Abstract Syntax Tree), heap management, objects, and dictionaries. This suggests it deals with the internal representation and manipulation of JavaScript objects, particularly literals and classes.
*   **Namespaces:** The code resides within the `v8::internal` namespace, indicating it's part of V8's internal implementation.
*   **Helper Functions:**  Several helper functions exist:
    *   `EncodeComputedEntry`:  Deals with encoding information for computed properties.
    *   `SetAccessorPlaceholderIndices`: Manages the indices for getter and setter accessors.
    *   `AddToDescriptorArrayTemplate`:  Adds properties to a `DescriptorArray`, which is an optimized way to store object properties.
    *   `DictionaryAddNoUpdateNextEnumerationIndex`: Adds entries to various dictionary types (`NameDictionary`, `SwissNameDictionary`, `NumberDictionary`) without modifying the enumeration order.
    *   `DictionaryUpdateMaxNumberKey`: Updates the maximum numerical key in a `NumberDictionary`.
    *   `ComputeEnumerationIndex`: Calculates the order in which properties will be enumerated.
    *   `GetExistingValueIndex`: Retrieves the index of an existing accessor.
    *   `AddToDictionaryTemplate`: A generalized function to add properties to different dictionary types, handling different scenarios like overwriting existing properties and managing enumeration order.
*   **`ObjectDescriptor` Class:** This class seems to be a builder for creating templates for object properties, elements, and computed properties. It manages the creation of `DescriptorArray` or dictionaries based on the number of properties.
*   **`ClassBoilerplate` Class:** This class has methods for adding properties and elements to class templates. The `New` method seems to be the core logic for creating a `ClassBoilerplate` from a `ClassLiteral` (likely representing a class definition in the AST). It iterates through class members and populates the object and prototype templates.

**Answers to the User's Requests:**

1. **Functionality:** The code in `v8/src/objects/literal-objects.cc` is responsible for creating and managing templates for JavaScript literal objects and classes. This involves setting up the initial structure and properties of these objects, including handling regular properties, computed properties, getters, setters, and methods. It uses different data structures like `DescriptorArray` and various dictionary types for efficient storage and access of properties.

2. **Torque Source:** The code ends with `.cc`, indicating it's a C++ source file, not a Torque (`.tq`) file.

3. **JavaScript Relation:** This code is directly related to the creation and initialization of JavaScript objects and classes. For example, when you define a class or an object literal in JavaScript, this kind of code is involved in setting up its internal representation in V8.

4. **Code Logic & Reasoning:** The `AddToDictionaryTemplate` function demonstrates complex logic. Let's consider a simplified scenario:

    *   **Hypothetical Input:**  We are adding a method `myMethod` to a class's prototype using a `NameDictionary`. The `key_index` indicates the order this method was defined.
    *   **Scenario 1: Method Doesn't Exist:** If `myMethod` is not already in the dictionary, a new entry is created with the method's code and an enumeration index based on `key_index`.
    *   **Scenario 2: Method Exists as Data Property:** If `myMethod` exists as a simple data property defined *before* the current method (lower `key_index`), the existing data property is overwritten with the new method, and its enumeration order might be updated.
    *   **Scenario 3: Method Exists as Accessor:** If `myMethod` exists as a getter or setter, the logic becomes more complex, checking the `key_index` of the existing accessor to decide whether to overwrite it or update its enumeration order.

5. **Common Programming Errors:** While this is internal V8 code, a related user error would be misunderstanding property enumeration order, especially when dealing with computed properties or when a property is defined multiple times with different attributes (e.g., first as data, then as a getter). This code attempts to handle such scenarios consistently.

6. **Overall Summary (Part 1):** The file `v8/src/objects/literal-objects.cc` is a crucial part of V8's object system. It provides the mechanisms for creating the initial structure and properties of JavaScript literal objects and classes. It uses optimized data structures and complex logic to handle various scenarios during object initialization, including regular properties, computed properties, and accessors, while also managing the order in which properties will be enumerated. The `ObjectDescriptor` and `ClassBoilerplate` classes are key components in this process.

这是 `v8/src/objects/literal-objects.cc` 的第一部分源代码，其主要功能是 **负责创建和管理 JavaScript 对象字面量和类定义在 V8 内部的模板**。更具体地说，它定义了用于描述对象和类初始状态的数据结构和算法，包括属性、方法、访问器（getter/setter）以及它们的属性（例如，是否可枚举）。

以下是根据您的问题对代码功能的详细归纳：

**1. 主要功能:**

*   **创建对象和类的蓝图 (Boilerplate):**  该文件定义了用于创建 JavaScript 对象字面量和类的模板。这些模板描述了对象在创建时的初始属性和方法。
*   **管理属性存储:**  它处理将属性添加到这些模板的过程，包括普通属性、计算属性以及访问器属性。
*   **优化属性存储:**  它根据属性的数量和类型，选择使用不同的内部数据结构来存储属性，例如 `DescriptorArray` (对于少量属性) 和各种字典类型 (`NameDictionary`, `SwissNameDictionary`, `NumberDictionary`) (对于大量或特定类型的属性)。
*   **处理计算属性:**  它包含处理计算属性名的逻辑，并确保它们在枚举顺序中正确放置。
*   **管理访问器:**  它处理 getter 和 setter 方法，并将其与相应的属性关联起来。
*   **处理静态和实例成员:** 对于类，它区分静态成员和实例成员，并将它们添加到相应的模板中。
*   **维护属性枚举顺序:** 代码努力维护属性的定义顺序，这对于 JavaScript 的 `for...in` 循环等操作至关重要。
*   **与 AST (抽象语法树) 交互:**  它接收来自解析器生成的抽象语法树的信息 (`ClassLiteral`)，并据此构建对象模板。

**2. 是否为 Torque 源代码:**

`v8/src/objects/literal-objects.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。

**3. 与 JavaScript 功能的关系及示例:**

该文件直接关联到 JavaScript 中对象字面量和类的定义。

**对象字面量示例:**

```javascript
const obj = {
  x: 10,
  y: 20,
  get sum() { return this.x + this.y; },
  set doubleX(val) { this.x = val * 2; },
  [Symbol('private')]: 'secret' // 计算属性
};
```

当 V8 引擎执行这段代码时，`literal-objects.cc` 中的代码会参与以下过程：

*   为 `obj` 创建一个初始模板。
*   将属性 `x` 和 `y` 作为数据属性添加到模板中。
*   将 `sum` 作为 getter 访问器添加到模板中。
*   将 `doubleX` 作为 setter 访问器添加到模板中。
*   将使用 Symbol 的计算属性添加到模板中。

**类定义示例:**

```javascript
class MyClass {
  constructor(value) {
    this.instanceProperty = value;
  }

  static staticMethod() {
    console.log('Static method called');
  }

  getMethod() {
    return this.instanceProperty;
  }

  get accessorProperty() {
    return this.instanceProperty * 2;
  }

  set accessorProperty(val) {
    this.instanceProperty = val / 2;
  }
}
```

当 V8 引擎遇到 `MyClass` 的定义时，`literal-objects.cc` 中的代码会参与以下过程：

*   创建一个类的模板，其中包含静态方法 `staticMethod`。
*   创建一个原型对象的模板，其中包含实例方法 `getMethod` 和访问器 `accessorProperty`。
*   处理 `constructor` 方法。
*   记录类的位置信息 (使用 `ClassPositions`)。

**4. 代码逻辑推理 (假设输入与输出):**

**假设输入:** 一个表示以下 JavaScript 类定义的 `ClassLiteral` 对象：

```javascript
class Example {
  constructor() {
    this.a = 1;
  }
  getMethod() { return this.a; }
  get b() { return this.a * 2; }
}
```

**代码逻辑推理:**

*   `ClassBoilerplate::New` 函数会被调用，接收 `ClassLiteral` 对象。
*   `ObjectDescriptor` 会被用来创建类本身和原型对象的模板。
*   对于构造函数中的 `this.a = 1;`，会创建一个用于实例属性的模板。
*   对于 `getMethod() {}`，会创建一个指向该方法的指针，并添加到原型对象的模板中。
*   对于 `get b() {}`，会创建一个 getter 访问器，并添加到原型对象的模板中。

**可能的输出 (简化描述):**

*   一个 `ClassBoilerplate` 对象，其中包含：
    *   一个描述类本身的模板，可能包含指向构造函数的指针等信息。
    *   一个描述原型对象的模板，包含指向 `getMethod` 函数和 `b` 的 getter 函数的指针。

**5. 涉及用户常见的编程错误:**

虽然此代码是 V8 内部实现，但它处理的逻辑与用户常见的编程错误相关，例如：

*   **重复定义属性:** 如果 JavaScript 代码中重复定义了同一个属性（例如，先定义为数据属性，后定义为 getter），`literal-objects.cc` 中的代码需要处理这种情况，并根据定义顺序或属性类型进行相应的处理。V8 通常会遵循后定义覆盖前定义的原则，但访问器会有特殊处理。
*   **对枚举顺序的误解:**  用户可能会依赖于属性的枚举顺序，但由于 JavaScript 规范并没有严格保证所有情况下的枚举顺序，或者某些操作（如删除属性）会影响枚举顺序，可能会导致意外的行为。`literal-objects.cc` 尽力维护定义顺序，但在某些情况下可能无法完全保证。
*   **在构造函数中使用 `super` 之前访问 `this`:** 虽然这个文件不直接处理 `super`，但它处理类的初始化，而错误的 `super` 使用会导致 `this` 未初始化，这与对象模板的创建过程相关。

**示例 (重复定义属性):**

```javascript
const obj = {
  prop: 10,
  prop: function() { console.log('method'); }
};
// 最终 `obj.prop` 将会是那个函数。
```

**6. 功能归纳 (第 1 部分):**

`v8/src/objects/literal-objects.cc` 的第一部分主要负责为 JavaScript 对象字面量和类创建内部模板。它定义了用于存储属性（包括数据属性、计算属性和访问器）的数据结构和算法，并努力维护属性的枚举顺序。该代码与 V8 的抽象语法树紧密结合，接收类和对象定义的描述，并将其转化为 V8 内部使用的对象模板。这些模板是 V8 引擎高效创建和管理 JavaScript 对象的基础。

Prompt: 
```
这是目录为v8/src/objects/literal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/literal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
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
        val
"""


```