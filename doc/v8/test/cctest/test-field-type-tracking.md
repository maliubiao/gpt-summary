Response: The user wants me to summarize the functionality of the C++ code in `v8/test/cctest/test-field-type-tracking.cc`.
This file seems to be part of the V8 JavaScript engine's testing framework.
Based on the file name, it likely focuses on testing how V8 tracks the types of fields (properties) within JavaScript objects.

Key elements I've observed in the code:

- **Helper functions:**  Functions like `CreateAccessorPair` and `CheckMigrationTarget` suggest the code tests scenarios involving object properties (accessors and regular data properties) and how V8 optimizes object layouts.
- **`Expectations` class:** This class appears to be crucial for setting up expected states of object maps (internal V8 structures describing object layout and property characteristics) after various operations. It tracks property kinds (data, accessor), attributes (e.g., read-only), representations (how the value is stored in memory), and field types.
- **Test cases:** The code includes numerous `TEST` macros, which are part of the V8 testing framework. These tests cover various scenarios related to property reconfiguration (changing property types or attributes) and field generalization (widening the allowed types for a field).
- **JavaScript interaction:** The use of `CompileRun` in `TEST(ReconfigureAccessorToNonExistingDataFieldHeavy)` indicates a connection to JavaScript. The test sets up a JavaScript object and then interacts with its properties.

Therefore, the core functionality seems to be: **testing how V8 tracks and updates field types of JavaScript objects in response to various operations, including adding, modifying, and reconfiguring properties.**

Now, let's think about how to illustrate this with a JavaScript example. The tests revolve around how V8 optimizes objects based on the types of their properties.

Consider a simple JavaScript object:

```javascript
let obj = {};
obj.x = 1; // V8 might initially assume 'x' is a Smi (small integer)
obj.x = 1.5; // Now 'x' needs to be a double
obj.x = "hello"; // Finally, 'x' needs to be able to hold any value (tagged)
```

The C++ code is likely testing the internal mechanisms of V8 that handle these transitions. Specifically, how V8 changes the internal "map" of the object to accommodate the changing types. The `Expectations` class helps verify that these internal map transitions happen as expected.

Another example related to accessors:

```javascript
let obj = {
  get y() { return this._y; },
  set y(value) { this._y = value; }
};
```

The C++ code tests how V8 represents these accessor properties internally, potentially optimizing them differently from regular data properties.

Based on this, the summary should highlight the testing aspect, the focus on field type tracking, and the connection to JavaScript object optimization.
The C++ code snippet you provided is a part of the V8 JavaScript engine's testing framework. Specifically, the file `test-field-type-tracking.cc` focuses on **testing the mechanisms within V8 that track the types of fields (properties) of JavaScript objects.**

Here's a breakdown of its functionality:

* **Testing Field Type Tracking:** The primary goal is to ensure that V8 correctly identifies and updates the possible types that a property of an object can hold. This is crucial for optimization, as V8 can generate more efficient machine code if it knows the type of a field.
* **Simulating Property Transitions:** The tests simulate various scenarios involving adding, modifying, and reconfiguring properties of JavaScript objects. This includes:
    * Adding new properties with specific initial types.
    * Changing the type of an existing property (e.g., from integer to floating-point, or to a generic object).
    * Reconfiguring property attributes (e.g., making a property read-only).
    * Converting data properties to accessor properties (getters/setters) and vice versa.
* **Verifying Map Transitions:** V8 uses internal data structures called "Maps" to describe the layout and property characteristics of objects. These tests verify that when the type or attributes of a property change, V8 correctly transitions the object to a new Map that reflects these changes.
* **Checking for Expected Optimizations/Deoptimizations:** By tracking field types, V8 can apply optimizations. The tests likely verify that these optimizations are applied correctly and that deoptimizations (falling back to less optimized code) occur when necessary due to type changes.
* **Using Expectations:** The `Expectations` class is a key component. It allows the tests to define the expected state of an object's Map after a sequence of operations. This includes the expected property kinds, attributes, representations (how the value is stored in memory), and field types.
* **Handling Accessors and Constants:** The code also includes tests specifically for accessor properties (defined with `get` and `set`) and constant properties, ensuring that their type tracking is handled correctly.

**Relationship to JavaScript with Examples:**

The C++ code directly tests the underlying implementation that powers how JavaScript objects behave. Here's how the concepts relate with JavaScript examples:

**1. Field Type Changes:**

```javascript
let obj = {};
obj.count = 5; // V8 might infer 'count' is an integer (Smi)
obj.count = 3.14; // Now V8 needs to update the type of 'count' to a floating-point number (Double)
obj.count = "hello"; // Finally, 'count' needs to be able to hold any type (Tagged)
```

The C++ tests ensure that V8 correctly updates the internal representation of the `obj` and its `count` property as its type changes.

**2. Property Reconfiguration:**

```javascript
let obj = { x: 10 };
Object.defineProperty(obj, 'x', { value: 20, writable: false }); // Making 'x' read-only
```

The C++ tests verify how V8 handles the transition to a new Map when property attributes like `writable` are changed.

**3. Accessor Properties:**

```javascript
let obj = {
  _name: "initial",
  get name() { return this._name; },
  set name(newName) { this._name = newName; }
};
```

The C++ code includes tests for how V8 tracks the types and behavior of these accessor properties, which involve getter and setter functions. The `CreateAccessorPair` function in the C++ code is directly related to creating these getter/setter pairs internally.

**4. Constant Properties:**

```javascript
const PI = 3.14159;
let obj = { constant: PI };
```

The tests with `AddDataConstant` in the C++ code are about how V8 handles properties whose values are known at the time of creation and are expected to remain constant.

In essence, the C++ code in `test-field-type-tracking.cc` is a low-level examination of V8's internal mechanisms for optimizing JavaScript object property access and management. It uses carefully constructed scenarios to verify that V8 behaves correctly and efficiently when dealing with different property types and configurations.

Prompt: 
```
这是目录为v8/test/cctest/test-field-type-tracking.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <initializer_list>
#include <utility>

#include "src/base/logging.h"
#include "src/execution/execution.h"
#include "src/heap/factory-inl.h"
#include "src/objects/field-type.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/internal-index.h"
#include "src/objects/map-updater.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-details.h"
#include "src/objects/property.h"
#include "src/objects/struct-inl.h"
#include "src/objects/transitions.h"
#include "src/utils/ostreams.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {
namespace compiler {
namespace test_field_type_tracking {

// TODO(ishell): fix this once TransitionToPrototype stops generalizing
// all field representations (similar to crbug/448711 where elements kind
// and observed transitions caused generalization of all fields).
const bool IS_PROTO_TRANS_ISSUE_FIXED =
    v8_flags.move_prototype_transitions_first;

// TODO(ishell): fix this once TransitionToAccessorProperty is able to always
// keep map in fast mode.
const bool IS_ACCESSOR_FIELD_SUPPORTED = false;

// Number of properties used in the tests.
const int kPropCount = 7;

enum ChangeAlertMechanism { kDeprecation, kFieldOwnerDependency, kNoAlert };

//
// Helper functions.
//

static Handle<AccessorPair> CreateAccessorPair(bool with_getter,
                                               bool with_setter) {
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Handle<AccessorPair> pair = factory->NewAccessorPair();
  DirectHandle<String> empty_string = factory->empty_string();
  if (with_getter) {
    DirectHandle<JSFunction> func =
        factory->NewFunctionForTesting(empty_string);
    pair->set_getter(*func);
  }
  if (with_setter) {
    DirectHandle<JSFunction> func =
        factory->NewFunctionForTesting(empty_string);
    pair->set_setter(*func);
  }
  return pair;
}

// Check cached migration target map after Map::Update() and Map::TryUpdate()
static void CheckMigrationTarget(Isolate* isolate, Tagged<Map> old_map,
                                 Tagged<Map> new_map) {
  Tagged<Map> target =
      TransitionsAccessor(isolate, old_map).GetMigrationTarget();
  if (target.is_null()) return;
  CHECK_EQ(new_map, target);
  CHECK_EQ(MapUpdater::TryUpdateNoLock(isolate, old_map,
                                       ConcurrencyMode::kSynchronous),
           target);
}

class Expectations {
  static const int MAX_PROPERTIES = 10;
  Isolate* isolate_;
  ElementsKind elements_kind_;
  PropertyKind kinds_[MAX_PROPERTIES];
  PropertyLocation locations_[MAX_PROPERTIES];
  PropertyConstness constnesses_[MAX_PROPERTIES];
  PropertyAttributes attributes_[MAX_PROPERTIES];
  Representation representations_[MAX_PROPERTIES];
  // FieldType for kField, value for DATA_CONSTANT and getter for
  // ACCESSOR_CONSTANT.
  Handle<Object> values_[MAX_PROPERTIES];
  // Setter for ACCESSOR_CONSTANT.
  Handle<Object> setter_values_[MAX_PROPERTIES];
  int number_of_properties_;

 public:
  explicit Expectations(Isolate* isolate, ElementsKind elements_kind)
      : isolate_(isolate),
        elements_kind_(elements_kind),
        number_of_properties_(0) {}

  explicit Expectations(Isolate* isolate)
      : Expectations(
            isolate,
            isolate->object_function()->initial_map()->elements_kind()) {}

  void Init(int index, PropertyKind kind, PropertyAttributes attributes,
            PropertyConstness constness, PropertyLocation location,
            Representation representation, Handle<Object> value) {
    CHECK(index < MAX_PROPERTIES);
    kinds_[index] = kind;
    locations_[index] = location;
    if (kind == PropertyKind::kData && location == PropertyLocation::kField &&
        IsTransitionableFastElementsKind(elements_kind_)) {
      // Maps with transitionable elements kinds must have the most general
      // field type.
      value = FieldType::Any(isolate_);
      representation = Representation::Tagged();
    }
    constnesses_[index] = constness;
    attributes_[index] = attributes;
    representations_[index] = representation;
    values_[index] = value;
  }

  void Print() const {
    StdoutStream os;
    os << "Expectations: #" << number_of_properties_ << "\n";
    for (int i = 0; i < number_of_properties_; i++) {
      os << " " << i << ": ";
      os << "Descriptor @ ";

      if (kinds_[i] == PropertyKind::kData) {
        FieldType::PrintTo(Cast<FieldType>(*values_[i]), os);
      } else {
        // kAccessor
        os << "(get: " << Brief(*values_[i])
           << ", set: " << Brief(*setter_values_[i]) << ") ";
      }

      os << " (";
      if (constnesses_[i] == PropertyConstness::kConst) os << "const ";
      os << (kinds_[i] == PropertyKind::kData ? "data " : "accessor ");
      if (locations_[i] == PropertyLocation::kField) {
        os << "field"
           << ": " << representations_[i].Mnemonic();
      } else {
        os << "descriptor";
      }
      os << ", attrs: " << attributes_[i] << ")\n";
    }
    os << "\n";
  }

  void SetElementsKind(ElementsKind elements_kind) {
    elements_kind_ = elements_kind;
  }

  Handle<FieldType> GetFieldType(int index) {
    CHECK(index < MAX_PROPERTIES);
    CHECK_EQ(PropertyLocation::kField, locations_[index]);
    return Cast<FieldType>(values_[index]);
  }

  void SetDataField(int index, PropertyAttributes attrs,
                    PropertyConstness constness, Representation representation,
                    Handle<FieldType> field_type) {
    Init(index, PropertyKind::kData, attrs, constness, PropertyLocation::kField,
         representation, field_type);
  }

  void SetDataField(int index, PropertyConstness constness,
                    Representation representation,
                    Handle<FieldType> field_type) {
    SetDataField(index, attributes_[index], constness, representation,
                 field_type);
  }

  void SetAccessorField(int index, PropertyAttributes attrs) {
    Init(index, PropertyKind::kAccessor, attrs, PropertyConstness::kConst,
         PropertyLocation::kDescriptor, Representation::Tagged(),
         FieldType::Any(isolate_));
  }

  void SetAccessorField(int index) {
    SetAccessorField(index, attributes_[index]);
  }

  void SetDataConstant(int index, PropertyAttributes attrs,
                       DirectHandle<JSFunction> value) {
    Handle<FieldType> field_type(FieldType::Class(value->map()), isolate_);
    Init(index, PropertyKind::kData, attrs, PropertyConstness::kConst,
         PropertyLocation::kField, Representation::HeapObject(), field_type);
  }

  void SetDataConstant(int index, DirectHandle<JSFunction> value) {
    SetDataConstant(index, attributes_[index], value);
  }

  void SetAccessorConstant(int index, PropertyAttributes attrs,
                           Handle<Object> getter, Handle<Object> setter) {
    Init(index, PropertyKind::kAccessor, attrs, PropertyConstness::kConst,
         PropertyLocation::kDescriptor, Representation::Tagged(), getter);
    setter_values_[index] = setter;
  }

  void SetAccessorConstantComponent(int index, PropertyAttributes attrs,
                                    AccessorComponent component,
                                    Handle<Object> accessor) {
    CHECK_EQ(PropertyKind::kAccessor, kinds_[index]);
    CHECK_EQ(PropertyLocation::kDescriptor, locations_[index]);
    CHECK(index < number_of_properties_);
    if (component == ACCESSOR_GETTER) {
      values_[index] = accessor;
    } else {
      setter_values_[index] = accessor;
    }
  }

  void SetAccessorConstant(int index, PropertyAttributes attrs,
                           DirectHandle<AccessorPair> pair) {
    Handle<Object> getter = handle(pair->getter(), isolate_);
    Handle<Object> setter = handle(pair->setter(), isolate_);
    SetAccessorConstant(index, attrs, getter, setter);
  }

  void SetAccessorConstant(int index, Handle<Object> getter,
                           Handle<Object> setter) {
    SetAccessorConstant(index, attributes_[index], getter, setter);
  }

  void SetAccessorConstant(int index, DirectHandle<AccessorPair> pair) {
    Handle<Object> getter = handle(pair->getter(), isolate_);
    Handle<Object> setter = handle(pair->setter(), isolate_);
    SetAccessorConstant(index, getter, setter);
  }

  void GeneralizeField(int index) {
    CHECK(index < number_of_properties_);
    representations_[index] = Representation::Tagged();
    if (locations_[index] == PropertyLocation::kField) {
      values_[index] = FieldType::Any(isolate_);
    }
  }

  bool Check(Tagged<DescriptorArray> descriptors,
             InternalIndex descriptor) const {
    PropertyDetails details = descriptors->GetDetails(descriptor);

    if (details.kind() != kinds_[descriptor.as_int()]) return false;
    if (details.location() != locations_[descriptor.as_int()]) return false;
    if (details.constness() != constnesses_[descriptor.as_int()]) return false;

    PropertyAttributes expected_attributes = attributes_[descriptor.as_int()];
    if (details.attributes() != expected_attributes) return false;

    Representation expected_representation =
        representations_[descriptor.as_int()];

    if (!details.representation().Equals(expected_representation)) return false;

    Tagged<Object> expected_value = *values_[descriptor.as_int()];
    if (details.location() == PropertyLocation::kField) {
      if (details.kind() == PropertyKind::kData) {
        Tagged<FieldType> type = descriptors->GetFieldType(descriptor);
        return Cast<FieldType>(expected_value) == type;
      } else {
        // kAccessor
        UNREACHABLE();
      }
    } else {
      CHECK_EQ(PropertyKind::kAccessor, details.kind());
      Tagged<Object> value = descriptors->GetStrongValue(descriptor);
      if (value == expected_value) return true;
      if (!IsAccessorPair(value)) return false;
      Tagged<AccessorPair> pair = Cast<AccessorPair>(value);
      return pair->Equals(expected_value, *setter_values_[descriptor.as_int()]);
    }
    UNREACHABLE();
  }

  bool Check(Tagged<Map> map, int expected_nof) const {
    CHECK_EQ(elements_kind_, map->elements_kind());
    CHECK(number_of_properties_ <= MAX_PROPERTIES);
    CHECK_EQ(expected_nof, map->NumberOfOwnDescriptors());
    CHECK(!map->is_dictionary_map());

    Tagged<DescriptorArray> descriptors = map->instance_descriptors();
    CHECK(expected_nof <= number_of_properties_);
    for (InternalIndex i : InternalIndex::Range(expected_nof)) {
      if (!Check(descriptors, i)) {
        Print();
#ifdef OBJECT_PRINT
        i::Print(descriptors);
#endif
        return false;
      }
    }
    return true;
  }

  bool Check(Tagged<Map> map) const {
    return Check(map, number_of_properties_);
  }

  bool CheckNormalized(Tagged<Map> map) const {
    CHECK(map->is_dictionary_map());
    CHECK_EQ(elements_kind_, map->elements_kind());
    // TODO(leszeks): Iterate over the key/value pairs of the map and compare
    // them against the expected fields.
    return true;
  }

  //
  // Helper methods for initializing expectations and adding properties to
  // given |map|.
  //

  Handle<Map> AsElementsKind(Handle<Map> map, ElementsKind elements_kind) {
    elements_kind_ = elements_kind;
    map = Map::AsElementsKind(isolate_, map, elements_kind);
    CHECK_EQ(elements_kind_, map->elements_kind());
    return map;
  }

  void ChangeAttributesForAllProperties(PropertyAttributes attributes) {
    for (int i = 0; i < number_of_properties_; i++) {
      attributes_[i] = attributes;
    }
  }

  Handle<Map> AddDataField(Handle<Map> map, PropertyAttributes attributes,
                           PropertyConstness constness,
                           Representation representation,
                           Handle<FieldType> field_type) {
    CHECK_EQ(number_of_properties_, map->NumberOfOwnDescriptors());
    int property_index = number_of_properties_++;
    SetDataField(property_index, attributes, constness, representation,
                 field_type);

    Handle<String> name = CcTest::MakeName("prop", property_index);
    return Map::CopyWithField(isolate_, map, name, field_type, attributes,
                              constness, representation, INSERT_TRANSITION)
        .ToHandleChecked();
  }

  Handle<Map> AddDataConstant(Handle<Map> map, PropertyAttributes attributes,
                              DirectHandle<JSFunction> value) {
    CHECK_EQ(number_of_properties_, map->NumberOfOwnDescriptors());
    int property_index = number_of_properties_++;
    SetDataConstant(property_index, attributes, value);

    Handle<String> name = CcTest::MakeName("prop", property_index);
    return Map::CopyWithConstant(isolate_, map, name, value, attributes,
                                 INSERT_TRANSITION)
        .ToHandleChecked();
  }

  Handle<Map> TransitionToDataField(Handle<Map> map,
                                    PropertyAttributes attributes,
                                    PropertyConstness constness,
                                    Representation representation,
                                    Handle<FieldType> heap_type,
                                    DirectHandle<Object> value) {
    CHECK_EQ(number_of_properties_, map->NumberOfOwnDescriptors());
    int property_index = number_of_properties_++;
    SetDataField(property_index, attributes, constness, representation,
                 heap_type);

    Handle<String> name = CcTest::MakeName("prop", property_index);
    return Map::TransitionToDataProperty(isolate_, map, name, value, attributes,
                                         constness, StoreOrigin::kNamed);
  }

  Handle<Map> TransitionToDataConstant(Handle<Map> map,
                                       PropertyAttributes attributes,
                                       DirectHandle<JSFunction> value) {
    CHECK_EQ(number_of_properties_, map->NumberOfOwnDescriptors());
    int property_index = number_of_properties_++;
    SetDataConstant(property_index, attributes, value);

    Handle<String> name = CcTest::MakeName("prop", property_index);
    return Map::TransitionToDataProperty(isolate_, map, name, value, attributes,
                                         PropertyConstness::kConst,
                                         StoreOrigin::kNamed);
  }

  Handle<Map> FollowDataTransition(DirectHandle<Map> map,
                                   PropertyAttributes attributes,
                                   PropertyConstness constness,
                                   Representation representation,
                                   Handle<FieldType> heap_type) {
    CHECK_EQ(number_of_properties_, map->NumberOfOwnDescriptors());
    int property_index = number_of_properties_++;
    SetDataField(property_index, attributes, constness, representation,
                 heap_type);

    DirectHandle<String> name = CcTest::MakeName("prop", property_index);
    MaybeHandle<Map> target = TransitionsAccessor::SearchTransition(
        isolate_, map, *name, PropertyKind::kData, attributes);
    CHECK(!target.is_null());
    return target.ToHandleChecked();
  }

  Handle<Map> AddAccessorConstant(Handle<Map> map,
                                  PropertyAttributes attributes,
                                  Handle<AccessorPair> pair) {
    CHECK_EQ(number_of_properties_, map->NumberOfOwnDescriptors());
    int property_index = number_of_properties_++;
    SetAccessorConstant(property_index, attributes, pair);

    Handle<String> name = CcTest::MakeName("prop", property_index);

    Descriptor d = Descriptor::AccessorConstant(name, pair, attributes);
    return Map::CopyInsertDescriptor(isolate_, map, &d, INSERT_TRANSITION);
  }

  Handle<Map> AddAccessorConstant(Handle<Map> map,
                                  PropertyAttributes attributes,
                                  Handle<Object> getter,
                                  Handle<Object> setter) {
    CHECK_EQ(number_of_properties_, map->NumberOfOwnDescriptors());
    int property_index = number_of_properties_++;
    SetAccessorConstant(property_index, attributes, getter, setter);

    Handle<String> name = CcTest::MakeName("prop", property_index);

    CHECK(!IsNull(*getter, isolate_) || !IsNull(*setter, isolate_));
    Factory* factory = isolate_->factory();

    if (!IsNull(*getter, isolate_)) {
      Handle<AccessorPair> pair = factory->NewAccessorPair();
      pair->SetComponents(*getter, *factory->null_value());
      Descriptor d = Descriptor::AccessorConstant(name, pair, attributes);
      map = Map::CopyInsertDescriptor(isolate_, map, &d, INSERT_TRANSITION);
    }
    if (!IsNull(*setter, isolate_)) {
      Handle<AccessorPair> pair = factory->NewAccessorPair();
      pair->SetComponents(*getter, *setter);
      Descriptor d = Descriptor::AccessorConstant(name, pair, attributes);
      map = Map::CopyInsertDescriptor(isolate_, map, &d, INSERT_TRANSITION);
    }
    return map;
  }

  Handle<Map> TransitionToAccessorConstant(Handle<Map> map,
                                           PropertyAttributes attributes,
                                           DirectHandle<AccessorPair> pair) {
    CHECK_EQ(number_of_properties_, map->NumberOfOwnDescriptors());
    int property_index = number_of_properties_++;
    SetAccessorConstant(property_index, attributes, pair);

    Handle<String> name = CcTest::MakeName("prop", property_index);

    Isolate* isolate = CcTest::i_isolate();
    DirectHandle<Object> getter(pair->getter(), isolate);
    DirectHandle<Object> setter(pair->setter(), isolate);

    InternalIndex descriptor =
        map->instance_descriptors(isolate)->SearchWithCache(isolate, *name,
                                                            *map);
    map = Map::TransitionToAccessorProperty(isolate, map, name, descriptor,
                                            getter, setter, attributes);
    CHECK(!map->is_deprecated());
    CHECK(!map->is_dictionary_map());
    return map;
  }
};


////////////////////////////////////////////////////////////////////////////////
// A set of tests for property reconfiguration that makes new transition tree
// branch.
//

namespace {

Handle<Map> ReconfigureProperty(Isolate* isolate, Handle<Map> map,
                                InternalIndex modify_index,
                                PropertyKind new_kind,
                                PropertyAttributes new_attributes,
                                Representation new_representation,
                                Handle<FieldType> new_field_type) {
  DCHECK_EQ(PropertyKind::kData, new_kind);  // Only kData case is supported.
  MapUpdater mu(isolate, map);
  return mu.ReconfigureToDataField(modify_index, new_attributes,
                                   PropertyConstness::kConst,
                                   new_representation, new_field_type);
}

}  // namespace

TEST(ReconfigureAccessorToNonExistingDataField) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> none_type = FieldType::None(isolate);
  Handle<AccessorPair> pair = CreateAccessorPair(true, true);

  Expectations expectations(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  map = expectations.AddAccessorConstant(map, NONE, pair);

  CHECK(!map->is_deprecated());
  CHECK(map->is_stable());
  CHECK(expectations.Check(*map));

  InternalIndex first(0);
  Handle<Map> new_map =
      ReconfigureProperty(isolate, map, first, PropertyKind::kData, NONE,
                          Representation::None(), none_type);
  // |map| did not change except marked unstable.
  CHECK(!map->is_deprecated());
  CHECK(!map->is_stable());
  CHECK(expectations.Check(*map));

  // Property kind reconfiguration always makes the field mutable.
  expectations.SetDataField(0, NONE, PropertyConstness::kMutable,
                            Representation::None(), none_type);

  CHECK(!new_map->is_deprecated());
  CHECK(new_map->is_stable());
  CHECK(expectations.Check(*new_map));

  DirectHandle<Map> new_map2 =
      ReconfigureProperty(isolate, map, first, PropertyKind::kData, NONE,
                          Representation::None(), none_type);
  CHECK_EQ(*new_map, *new_map2);

  DirectHandle<Object> value(Smi::zero(), isolate);
  DirectHandle<Map> prepared_map = Map::PrepareForDataProperty(
      isolate, new_map, first, PropertyConstness::kConst, value);
  // None to Smi generalization is trivial, map does not change.
  CHECK_EQ(*new_map, *prepared_map);

  expectations.SetDataField(0, NONE, PropertyConstness::kMutable,
                            Representation::Smi(), any_type);
  CHECK(prepared_map->is_stable());
  CHECK(expectations.Check(*prepared_map));

  // Now create an object with |map|, migrate it to |prepared_map| and ensure
  // that the data property is uninitialized.
  Factory* factory = isolate->factory();
  DirectHandle<JSObject> obj = factory->NewJSObjectFromMap(map);
  JSObject::MigrateToMap(isolate, obj, prepared_map);
  FieldIndex index = FieldIndex::ForDescriptor(*prepared_map, first);
  CHECK(IsUninitialized(obj->RawFastPropertyAt(index), isolate));
#ifdef VERIFY_HEAP
  Object::ObjectVerify(*obj, isolate);
#endif
}


// This test checks that the LookupIterator machinery involved in
// JSObject::SetOwnPropertyIgnoreAttributes() does not try to migrate object
// to a map with a property with None representation.
TEST(ReconfigureAccessorToNonExistingDataFieldHeavy) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  CompileRun(
      "function getter() { return 1; };"
      "function setter() {};"
      "var o = {};"
      "Object.defineProperty(o, 'foo', "
      "                      { get: getter, set: setter, "
      "                        configurable: true, enumerable: true});");

  Handle<String> foo_str = factory->InternalizeUtf8String("foo");
  Handle<String> obj_name = factory->InternalizeUtf8String("o");

  Handle<Object> obj_value =
      Object::GetProperty(isolate, isolate->global_object(), obj_name)
          .ToHandleChecked();
  CHECK(IsJSObject(*obj_value));
  Handle<JSObject> obj = Cast<JSObject>(obj_value);

  CHECK_EQ(1, obj->map()->NumberOfOwnDescriptors());
  InternalIndex first(0);
  CHECK(IsAccessorPair(
      obj->map()->instance_descriptors(isolate)->GetStrongValue(first)));

  Handle<Object> value(Smi::FromInt(42), isolate);
  JSObject::SetOwnPropertyIgnoreAttributes(obj, foo_str, value, NONE).Check();

  // Check that the property contains |value|.
  CHECK_EQ(1, obj->map()->NumberOfOwnDescriptors());
  FieldIndex index = FieldIndex::ForDescriptor(obj->map(), first);
  Tagged<Object> the_value = obj->RawFastPropertyAt(index);
  CHECK(IsSmi(the_value));
  CHECK_EQ(42, Smi::ToInt(the_value));
}


////////////////////////////////////////////////////////////////////////////////
// A set of tests for field generalization case.
//

namespace {

// <Constness, Representation, FieldType> data.
struct CRFTData {
  PropertyConstness constness;
  Representation representation;
  Handle<FieldType> type;
};

Handle<Code> CreateDummyOptimizedCode(Isolate* isolate) {
  uint8_t buffer[1];
  CodeDesc desc;
  desc.buffer = buffer;
  desc.buffer_size = arraysize(buffer);
  desc.instr_size = arraysize(buffer);
  return Factory::CodeBuilder(isolate, desc, CodeKind::TURBOFAN_JS)
      .set_is_turbofanned()
      .set_empty_source_position_table()
      .set_deoptimization_data(DeoptimizationData::Empty(isolate))
      .Build();
}

static void CheckCodeObjectForDeopt(const CRFTData& from,
                                    const CRFTData& expected,
                                    DirectHandle<Code> code_field_type,
                                    DirectHandle<Code> code_field_repr,
                                    Handle<Code> code_field_const,
                                    bool expected_deopt) {
  if (!FieldType::Equals(*from.type, *expected.type)) {
    CHECK_EQ(expected_deopt, code_field_type->marked_for_deoptimization());
  } else {
    CHECK(!code_field_type->marked_for_deoptimization());
  }

  if (!from.representation.Equals(expected.representation)) {
    CHECK_EQ(expected_deopt, code_field_repr->marked_for_deoptimization());
  } else {
    CHECK(!code_field_repr->marked_for_deoptimization());
  }

  if (!code_field_const.is_null()) {
    if (from.constness != expected.constness) {
      CHECK_EQ(expected_deopt, code_field_const->marked_for_deoptimization());
    } else {
      CHECK(!code_field_const->marked_for_deoptimization());
    }
  }
}

// This test ensures that field generalization at |property_index| is done
// correctly independently of the fact that the |map| is detached from
// transition tree or not.
//
//  {} - p0 - p1 - p2: |detach_point_map|
//                  |
//                  X - detached at |detach_property_at_index|
//                  |
//                  + - p3 - p4: |map|
//
// Detaching does not happen if |detach_property_at_index| is -1.
//
void TestGeneralizeField(int detach_property_at_index, int property_index,
                         const CRFTData& from, const CRFTData& to,
                         const CRFTData& expected,
                         ChangeAlertMechanism expected_alert) {
  Isolate* isolate = CcTest::i_isolate();
  Handle<FieldType> any_type = FieldType::Any(isolate);

  CHECK(detach_property_at_index >= -1 &&
        detach_property_at_index < kPropCount);
  CHECK_LT(property_index, kPropCount);
  CHECK_NE(detach_property_at_index, property_index);

  const bool is_detached_map = detach_property_at_index >= 0;

  Expectations expectations(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  Handle<Map> detach_point_map;
  for (int i = 0; i < kPropCount; i++) {
    if (i == property_index) {
      map = expectations.AddDataField(map, NONE, from.constness,
                                      from.representation, from.type);
    } else {
      map = expectations.AddDataField(map, NONE, PropertyConstness::kConst,
                                      Representation::Smi(), any_type);
      if (i == detach_property_at_index) {
        detach_point_map = map;
      }
    }
  }
  CHECK(!map->is_deprecated());
  CHECK(map->is_stable());
  CHECK(expectations.Check(*map));

  if (is_detached_map) {
    detach_point_map = ReconfigureProperty(
        isolate, detach_point_map, InternalIndex(detach_property_at_index),
        PropertyKind::kData, NONE, Representation::Double(), any_type);
    expectations.SetDataField(detach_property_at_index,
                              PropertyConstness::kConst,
                              Representation::Double(), any_type);
    CHECK(map->is_deprecated());
    CHECK(expectations.Check(*detach_point_map,
                             detach_point_map->NumberOfOwnDescriptors()));
  }

  // Create dummy optimized code object to test correct dependencies
  // on the field owner.
  Handle<Code> code_field_type = CreateDummyOptimizedCode(isolate);
  Handle<Code> code_field_repr = CreateDummyOptimizedCode(isolate);
  Handle<Code> code_field_const = CreateDummyOptimizedCode(isolate);
  Handle<Map> field_owner(
      map->FindFieldOwner(isolate, InternalIndex(property_index)), isolate);
  DependentCode::InstallDependency(isolate, code_field_type, field_owner,
                                   DependentCode::kFieldTypeGroup);
  DependentCode::InstallDependency(isolate, code_field_repr, field_owner,
                                   DependentCode::kFieldRepresentationGroup);
  DependentCode::InstallDependency(isolate, code_field_const, field_owner,
                                   DependentCode::kFieldConstGroup);
  CHECK(!code_field_type->marked_for_deoptimization());
  CHECK(!code_field_repr->marked_for_deoptimization());
  CHECK(!code_field_const->marked_for_deoptimization());

  // Create new maps by generalizing representation of propX field.
  DirectHandle<Map> new_map = ReconfigureProperty(
      isolate, map, InternalIndex(property_index), PropertyKind::kData, NONE,
      to.representation, to.type);

  expectations.SetDataField(property_index, expected.constness,
                            expected.representation, expected.type);

  CHECK(!new_map->is_deprecated());
  CHECK(expectations.Check(*new_map));

  bool should_deopt = false;
  if (is_detached_map) {
    CHECK(!map->is_stable());
    CHECK(map->is_deprecated());
    CHECK_NE(*map, *new_map);
    should_deopt = (expected_alert == kFieldOwnerDependency) &&
                   !field_owner->is_deprecated();
  } else if (expected_alert == kDeprecation) {
    CHECK(!map->is_stable());
    CHECK(map->is_deprecated());
    CHECK(field_owner->is_deprecated());
    should_deopt = false;
  } else {
    CHECK(!field_owner->is_deprecated());
    CHECK(map->is_stable());  // Map did not change, must be left stable.
    CHECK_EQ(*map, *new_map);
    should_deopt = (expected_alert == kFieldOwnerDependency);
  }

  CheckCodeObjectForDeopt(from, expected, code_field_type, code_field_repr,
                          code_field_const, should_deopt);

  {
    // Check that all previous maps are not stable.
    Tagged<Map> tmp = *new_map;
    while (true) {
      Tagged<Object> back = tmp->GetBackPointer();
      if (IsUndefined(back, isolate)) break;
      tmp = Cast<Map>(back);
      CHECK(!tmp->is_stable());
    }
  }

  // Update all deprecated maps and check that they are now the same.
  DirectHandle<Map> updated_map = Map::Update(isolate, map);
  CHECK_EQ(*new_map, *updated_map);
  CheckMigrationTarget(isolate, *map, *updated_map);
}

void TestGeneralizeField(const CRFTData& from, const CRFTData& to,
                         const CRFTData& expected,
                         ChangeAlertMechanism expected_alert) {
  // Check the cases when the map being reconfigured is a part of the
  // transition tree.
  static_assert(kPropCount > 4);
  int indices[] = {0, 2, kPropCount - 1};
  for (int i = 0; i < static_cast<int>(arraysize(indices)); i++) {
    TestGeneralizeField(-1, indices[i], from, to, expected, expected_alert);
  }

  if (!from.representation.IsNone()) {
    // Check the cases when the map being reconfigured is NOT a part of the
    // transition tree. "None -> anything" representation changes make sense
    // only for "attached" maps.
    int indices2[] = {0, kPropCount - 1};
    for (int i = 0; i < static_cast<int>(arraysize(indices2)); i++) {
      TestGeneralizeField(indices2[i], 2, from, to, expected, expected_alert);
    }

    // Check that reconfiguration to the very same field works correctly.
    CRFTData data = from;
    TestGeneralizeField(-1, 2, data, data, data, kNoAlert);
  }
}

}  // namespace

TEST(GeneralizeSmiFieldToDouble) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);
}

TEST(GeneralizeSmiFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

TEST(GeneralizeDoubleFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

TEST(GeneralizeHeapObjectFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

TEST(GeneralizeHeapObjectFieldToHeapObject) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  Handle<FieldType> current_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  Handle<FieldType> new_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  Handle<FieldType> expected_type = any_type;

  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::HeapObject(), current_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(),
       expected_type},
      kFieldOwnerDependency);
  current_type = expected_type;

  new_type = FieldType::Class(Map::Create(isolate, 0), isolate);

  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      kNoAlert);
}

TEST(GeneralizeNoneFieldToSmi) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> none_type = FieldType::None(isolate);
  Handle<FieldType> any_type = FieldType::Any(isolate);

  // None -> Smi representation change is trivial.
  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::None(), none_type},
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      kFieldOwnerDependency);
}

TEST(GeneralizeNoneFieldToDouble) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> none_type = FieldType::None(isolate);
  Handle<FieldType> any_type = FieldType::Any(isolate);

  // None -> Double representation change is NOT trivial.
  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::None(), none_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);
}

TEST(GeneralizeNoneFieldToHeapObject) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> none_type = FieldType::None(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  // None -> HeapObject representation change is trivial.
  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::None(), none_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      kFieldOwnerDependency);
}

TEST(GeneralizeNoneFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> none_type = FieldType::None(isolate);
  Handle<FieldType> any_type = FieldType::Any(isolate);

  // None -> HeapObject representation change is trivial.
  TestGeneralizeField(
      {PropertyConstness::kMutable, Representation::None(), none_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}


////////////////////////////////////////////////////////////////////////////////
// A set of tests for field generalization case with kAccessor properties.
//

TEST(GeneralizeFieldWithAccessorProperties) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<AccessorPair> pair = CreateAccessorPair(true, true);

  const int kAccessorProp = kPropCount / 2;
  Expectations expectations(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  for (int i = 0; i < kPropCount; i++) {
    if (i == kAccessorProp) {
      map = expectations.AddAccessorConstant(map, NONE, pair);
    } else {
      map = expectations.AddDataField(map, NONE, PropertyConstness::kMutable,
                                      Representation::Smi(), any_type);
    }
  }
  CHECK(!map->is_deprecated());
  CHECK(map->is_stable());
  CHECK(expectations.Check(*map));

  // Create new maps by generalizing representation of propX field.
  Handle<Map> maps[kPropCount];
  for (int i = 0; i < kPropCount; i++) {
    if (i == kAccessorProp) {
      // Skip accessor property reconfiguration.
      maps[i] = maps[i - 1];
      continue;
    }
    Handle<Map> new_map =
        ReconfigureProperty(isolate, map, InternalIndex(i), PropertyKind::kData,
                            NONE, Representation::Double(), any_type);
    maps[i] = new_map;

    expectations.SetDataField(i, PropertyConstness::kMutable,
                              Representation::Double(), any_type);

    CHECK(!map->is_stable());
    CHECK(map->is_deprecated());
    CHECK_NE(*map, *new_map);
    CHECK(i == 0 || maps[i - 1]->is_deprecated());

    CHECK(!new_map->is_deprecated());
    CHECK(expectations.Check(*new_map));
  }

  DirectHandle<Map> active_map = maps[kPropCount - 1];
  CHECK(!active_map->is_deprecated());

  // Update all deprecated maps and check that they are now the same.
  DirectHandle<Map> updated_map = Map::Update(isolate, map);
  CHECK_EQ(*active_map, *updated_map);
  CheckMigrationTarget(isolate, *map, *updated_map);
  for (int i = 0; i < kPropCount; i++) {
    updated_map = Map::Update(isolate, maps[i]);
    CHECK_EQ(*active_map, *updated_map);
    CheckMigrationTarget(isolate, *maps[i], *updated_map);
  }
}

////////////////////////////////////////////////////////////////////////////////
// A set of tests for attribute reconfiguration case.
//

namespace {

// This test ensures that field generalization is correctly propagated from one
// branch of transition tree (|map2|) to another (|map|).
//
//             + - p2B - p3 - p4: |map2|
//             |
//  {} - p0 - p1 - p2A - p3 - p4: |map|
//
// where "p2A" and "p2B" differ only in the attributes.
//
void TestReconfigureDataFieldAttribute_GeneralizeField(
    const CRFTData& from, const CRFTData& to, const CRFTData& expected,
    ChangeAlertMechanism expected_alert) {
  Isolate* isolate = CcTest::i_isolate();

  Expectations expectations(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  for (int i = 0; i < kPropCount; i++) {
    map = expectations.AddDataField(map, NONE, from.constness,
                                    from.representation, from.type);
  }
  CHECK(!map->is_deprecated());
  CHECK(map->is_stable());
  CHECK(expectations.Check(*map));

  // Create another branch in transition tree (property at index |kSplitProp|
  // has different attributes), initialize expectations.
  const int kSplitProp = kPropCount / 2;
  Expectations expectations2(isolate);

  Handle<Map> map2 = initial_map;
  for (int i = 0; i < kSplitProp; i++) {
    map2 = expectations2.FollowDataTransition(map2, NONE, from.constness,
                                              from.representation, from.type);
  }
  map2 = expectations2.AddDataField(map2, READ_ONLY, to.constness,
                                    to.representation, to.type);

  for (int i = kSplitProp + 1; i < kPropCount; i++) {
    map2 = expectations2.AddDataField(map2, NONE, to.constness,
                                      to.representation, to.type);
  }
  CHECK(!map2->is_deprecated());
  CHECK(map2->is_stable());
  CHECK(expectations2.Check(*map2));

  // Create dummy optimized code object to test correct dependencies
  // on the field owner.
  Handle<Code> code_field_type = CreateDummyOptimizedCode(isolate);
  Handle<Code> code_field_repr = CreateDummyOptimizedCode(isolate);
  Handle<Code> code_field_const = CreateDummyOptimizedCode(isolate);
  Handle<Code> code_src_field_const = CreateDummyOptimizedCode(isolate);
  {
    Handle<Map> field_owner(
        map->FindFieldOwner(isolate, InternalIndex(kSplitProp)), isolate);
    DependentCode::InstallDependency(isolate, code_field_type, field_owner,
                                     DependentCode::kFieldTypeGroup);
    DependentCode::InstallDependency(isolate, code_field_repr, field_owner,
                                     DependentCode::kFieldRepresentationGroup);
    DependentCode::InstallDependency(isolate, code_field_const, field_owner,
                                     DependentCode::kFieldConstGroup);
  }
  {
    Handle<Map> field_owner(
        map2->FindFieldOwner(isolate, InternalIndex(kSplitProp)), isolate);
    DependentCode::InstallDependency(isolate, code_src_field_const, field_owner,
                                     DependentCode::kFieldConstGroup);
  }
  CHECK(!code_field_type->marked_for_deoptimization());
  CHECK(!code_field_repr->marked_for_deoptimization());
  CHECK(!code_field_const->marked_for_deoptimization());
  CHECK(!code_src_field_const->marked_for_deoptimization());

  // Reconfigure attributes of property |kSplitProp| of |map2| to NONE, which
  // should generalize representations in |map1|.
  DirectHandle<Map> new_map = MapUpdater::ReconfigureExistingProperty(
      isolate, map2, InternalIndex(kSplitProp), PropertyKind::kData, NONE,
      PropertyConstness::kConst);

  // |map2| should be mosly left unchanged but marked unstable and if the
  // source property was constant it should also be transitioned to kMutable.
  CHECK(!map2->is_stable());
  CHECK(!map2->is_deprecated());
  CHECK_NE(*map2, *new_map);
  CHECK(!code_src_field_const->marked_for_deoptimization());
  CHECK(expectations2.Check(*map2));

  for (int i = kSplitProp; i < kPropCount; i++) {
    expectations.SetDataField(i, expected.constness, expected.representation,
                              expected.type);
  }

  if (expected_alert == kDeprecation) {
    // |map| should be deprecated and |new_map| should match new expectations.
    CHECK(map->is_deprecated());
    CHECK(!code_field_type->marked_for_deoptimization());
    CHECK(!code_field_repr->marked_for_deoptimization());
    CHECK(!code_field_const->marked_for_deoptimization());
    CHECK_NE(*map, *new_map);

    CHECK(!new_map->is_deprecated());
    CHECK(expectations.Check(*new_map));

    // Update deprecated |map|, it should become |new_map|.
    DirectHandle<Map> updated_map = Map::Update(isolate, map);
    CHECK_EQ(*new_map, *updated_map);
    CheckMigrationTarget(isolate, *map, *updated_map);
  } else {
    CHECK(expected_alert == kFieldOwnerDependency ||
          expected_alert == kNoAlert);
    // In case of in-place generalization |map| should be returned as a result
    // of the property reconfiguration, respective field types should be
    // generalized and respective code dependencies should be invalidated.
    // |map| should be NOT deprecated and it should match new expectations.
    CHECK(!map->is_deprecated());
    CHECK_EQ(*map, *new_map);
    bool expect_deopt = expected_alert == kFieldOwnerDependency;
    CheckCodeObjectForDeopt(from, expected, code_field_type, code_field_repr,
                            code_field_const, expect_deopt);

    CHECK(!new_map->is_deprecated());
    CHECK(expectations.Check(*new_map));

    DirectHandle<Map> updated_map = Map::Update(isolate, map);
    CHECK_EQ(*new_map, *updated_map);
  }
}

}  // namespace

TEST(ReconfigureDataFieldAttribute_GeneralizeSmiFieldToDouble) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      kDeprecation);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);
}

TEST(ReconfigureDataFieldAttribute_GeneralizeSmiFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

TEST(ReconfigureDataFieldAttribute_GeneralizeDoubleFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

TEST(ReconfigureDataFieldAttribute_GeneralizeHeapObjFieldToHeapObj) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  Handle<FieldType> current_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  Handle<FieldType> new_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  Handle<FieldType> expected_type = any_type;

  // Check generalizations that trigger deopts.
  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::HeapObject(), current_type},
      {PropertyConstness::kConst, Representation::HeapObject(), new_type},
      {PropertyConstness::kConst, Representation::HeapObject(), expected_type},
      kFieldOwnerDependency);

  // PropertyConstness::kConst to PropertyConstness::kMutable migration does
  // not create a new map, therefore trivial generalization.
  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::HeapObject(), current_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(),
       expected_type},
      kFieldOwnerDependency);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::HeapObject(), current_type},
      {PropertyConstness::kConst, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(),
       expected_type},
      kFieldOwnerDependency);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::HeapObject(), current_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(),
       expected_type},
      kFieldOwnerDependency);
  current_type = expected_type;

  // Check generalizations that do not trigger deopts.
  new_type = FieldType::Class(Map::Create(isolate, 0), isolate);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), new_type},
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      kNoAlert);

  // PropertyConstness::kConst to PropertyConstness::kMutable migration does
  // not create a new map, therefore trivial generalization.
  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      kFieldOwnerDependency);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      kNoAlert);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      kNoAlert);
}

TEST(ReconfigureDataFieldAttribute_GeneralizeHeapObjectFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  TestReconfigureDataFieldAttribute_GeneralizeField(
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

// Checks that given |map| is deprecated and that it updates to given |new_map|
// which in turn should match expectations.
struct CheckDeprecated {
  void Check(Isolate* isolate, Handle<Map> map, DirectHandle<Map> new_map,
             const Expectations& expectations) {
    CHECK(map->is_deprecated());
    CHECK_NE(*map, *new_map);

    CHECK(!new_map->is_deprecated());
    CHECK(expectations.Check(*new_map));

    // Update deprecated |map|, it should become |new_map|.
    DirectHandle<Map> updated_map = Map::Update(isolate, map);
    CHECK_EQ(*new_map, *updated_map);
    CheckMigrationTarget(isolate, *map, *updated_map);
  }
};

// Checks that given |map| is NOT deprecated, equals to given |new_map| and
// matches expectations.
struct CheckSameMap {
  void Check(Isolate* isolate, Handle<Map> map, DirectHandle<Map> new_map,
             const Expectations& expectations) {
    // |map| was not reconfigured, therefore it should stay stable.
    CHECK(map->is_stable());
    CHECK(!map->is_deprecated());
    CHECK_EQ(*map, *new_map);

    CHECK(!new_map->is_deprecated());
    CHECK(expectations.Check(*new_map));

    // Update deprecated |map|, it should become |new_map|.
    DirectHandle<Map> updated_map = Map::Update(isolate, map);
    CHECK_EQ(*new_map, *updated_map);
  }
};

// Checks that given |map| is NOT deprecated and matches expectations.
// |new_map| is unrelated to |map|.
struct CheckUnrelated {
  void Check(Isolate* isolate, DirectHandle<Map> map, DirectHandle<Map> new_map,
             const Expectations& expectations) {
    CHECK(!map->is_deprecated());
    CHECK_NE(*map, *new_map);
    CHECK(expectations.Check(*map));

    CHECK(new_map->is_stable());
    CHECK(!new_map->is_deprecated());
  }
};

// Checks that given |map| is NOT deprecated, and |new_map| is a result of going
// dictionary mode.
struct CheckNormalize {
  void Check(Isolate* isolate, DirectHandle<Map> map, DirectHandle<Map> new_map,
             const Expectations& expectations) {
    CHECK(!map->is_deprecated());
    CHECK_NE(*map, *new_map);

    CHECK(IsUndefined(new_map->GetBackPointer(), isolate));
    CHECK(!new_map->is_deprecated());
    CHECK(expectations.CheckNormalized(*new_map));
  }
};

// This test ensures that field generalization is correctly propagated from one
// branch of transition tree (|map2|) to another (|map1|).
//
//             + - p2B - p3 - p4: |map2|
//             |
//  {} - p0 - p1: |map|
//             |
//             + - p2A - p3 - p4: |map1|
//                        |
//                        + - the property customized by the TestConfig provided
//
// where "p2A" and "p2B" differ only in the attributes.
//
template <typename TestConfig, typename Checker>
static void TestReconfigureProperty_CustomPropertyAfterTargetMap(
    TestConfig* config, Checker* checker) {
  Isolate* isolate = CcTest::i_isolate();
  Handle<FieldType> any_type = FieldType::Any(isolate);

  const int kCustomPropIndex = kPropCount - 2;
  Expectations expectations(isolate);

  const int kSplitProp = 2;
  CHECK_LT(kSplitProp, kCustomPropIndex);

  const PropertyConstness constness = PropertyConstness::kMutable;
  const Representation representation = Representation::Smi();

  // Create common part of transition tree.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  for (int i = 0; i < kSplitProp; i++) {
    map = expectations.AddDataField(map, NONE, constness, representation,
                                    any_type);
  }
  CHECK(!map->is_deprecated());
  CHECK(map->is_stable());
  CHECK(expectations.Check(*map));

  // Create branch to |map1|.
  Handle<Map> map1 = map;
  Expectations expectations1 = expectations;
  for (int i = kSplitProp; i < kCustomPropIndex; i++) {
    map1 = expectations1.AddDataField(map1, NONE, constness, representation,
                                      any_type);
  }
  map1 = config->AddPropertyAtBranch(1, &expectations1, map1);
  for (int i = kCustomPropIndex + 1; i < kPropCount; i++) {
    map1 = expectations1.AddDataField(map1, NONE, constness, representation,
                                      any_type);
  }
  CHECK(!map1->is_deprecated());
  CHECK(map1->is_stable());
  CHECK(expectations1.Check(*map1));

  // Create another branch in transition tree (property at index |kSplitProp|
  // has different attributes), initialize expectations.
  Handle<Map> map2 = map;
  Expectations expectations2 = expectations;
  map2 = expectations2.AddDataField(map2, READ_ONLY, constness, representation,
                                    any_type);
  for (int i = kSplitProp + 1; i < kCustomPropIndex; i++) {
    map2 = expectations2.AddDataField(map2, NONE, constness, representation,
                                      any_type);
  }
  map2 = config->AddPropertyAtBranch(2, &expectations2, map2);
  for (int i = kCustomPropIndex + 1; i < kPropCount; i++) {
    map2 = expectations2.AddDataField(map2, NONE, constness, representation,
                                      any_type);
  }
  CHECK(!map2->is_deprecated());
  CHECK(map2->is_stable());
  CHECK(expectations2.Check(*map2));

  // Reconfigure attributes of property |kSplitProp| of |map2| to NONE, which
  // should generalize representations in |map1|.
  Handle<Map> new_map = MapUpdater::ReconfigureExistingProperty(
      isolate, map2, InternalIndex(kSplitProp), PropertyKind::kData, NONE,
      PropertyConstness::kConst);

  // |map2| should be left unchanged but marked unstable.
  CHECK(!map2->is_stable());
  CHECK(!map2->is_deprecated());
  CHECK_NE(*map2, *new_map);
  CHECK(expectations2.Check(*map2));

  config->UpdateExpectations(kCustomPropIndex, &expectations1);
  checker->Check(isolate, map1, new_map, expectations1);
}

TEST(ReconfigureDataFieldAttribute_SameDataConstantAfterTargetMap) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  struct TestConfig {
    Handle<JSFunction> js_func_;
    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      js_func_ = factory->NewFunctionForTesting(factory->empty_string());
    }

    Handle<Map> AddPropertyAtBranch(int branch_id, Expectations* expectations,
                                    Handle<Map> map) {
      CHECK(branch_id == 1 || branch_id == 2);
      // Add the same data constant property at both transition tree branches.
      return expectations->AddDataConstant(map, NONE, js_func_);
    }

    void UpdateExpectations(int property_index, Expectations* expectations) {
      // Expectations stay the same.
    }
  };

  TestConfig config;
  // Two branches are "compatible" so the |map1| should NOT be deprecated.
  CheckSameMap checker;
  TestReconfigureProperty_CustomPropertyAfterTargetMap(&config, &checker);
}

TEST(ReconfigureDataFieldAttribute_DataConstantToDataFieldAfterTargetMap) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  struct TestConfig {
    Handle<JSFunction> js_func1_;
    Handle<JSFunction> js_func2_;
    Handle<FieldType> function_type_;
    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      Handle<String> name = factory->empty_string();
      Handle<Map> sloppy_map =
          Map::CopyInitialMap(isolate, isolate->sloppy_function_map());
      Handle<SharedFunctionInfo> info =
          factory->NewSharedFunctionInfoForBuiltin(name, Builtin::kIllegal, 0,
                                                   kDontAdapt);
      function_type_ = FieldType::Class(sloppy_map, isolate);
      CHECK(sloppy_map->is_stable());

      js_func1_ =
          Factory::JSFunctionBuilder{isolate, info, isolate->native_context()}
              .set_map(sloppy_map)
              .Build();

      js_func2_ =
          Factory::JSFunctionBuilder{isolate, info, isolate->native_context()}
              .set_map(sloppy_map)
              .Build();
    }

    Handle<Map> AddPropertyAtBranch(int branch_id, Expectations* expectations,
                                    Handle<Map> map) {
      CHECK(branch_id == 1 || branch_id == 2);
      DirectHandle<JSFunction> js_func = branch_id == 1 ? js_func1_ : js_func2_;
      return expectations->AddDataConstant(map, NONE, js_func);
    }

    void UpdateExpectations(int property_index, Expectations* expectations) {
      expectations->SetDataField(property_index, PropertyConstness::kConst,
                                 Representation::HeapObject(), function_type_);
    }
  };

  TestConfig config;
  CheckSameMap checker;
  TestReconfigureProperty_CustomPropertyAfterTargetMap(&config, &checker);
}

TEST(ReconfigureDataFieldAttribute_DataConstantToAccConstantAfterTargetMap) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  struct TestConfig {
    Handle<JSFunction> js_func_;
    Handle<AccessorPair> pair_;
    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      js_func_ = factory->NewFunctionForTesting(factory->empty_string());
      pair_ = CreateAccessorPair(true, true);
    }

    Handle<Map> AddPropertyAtBranch(int branch_id, Expectations* expectations,
                                    Handle<Map> map) {
      CHECK(branch_id == 1 || branch_id == 2);
      if (branch_id == 1) {
        return expectations->AddDataConstant(map, NONE, js_func_);
      } else {
        return expectations->AddAccessorConstant(map, NONE, pair_);
      }
    }

    void UpdateExpectations(int property_index, Expectations* expectations) {}
  };

  TestConfig config;
  // These are completely separate branches in transition tree.
  CheckUnrelated checker;
  TestReconfigureProperty_CustomPropertyAfterTargetMap(&config, &checker);
}


TEST(ReconfigureDataFieldAttribute_SameAccessorConstantAfterTargetMap) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  struct TestConfig {
    Handle<AccessorPair> pair_;
    TestConfig() { pair_ = CreateAccessorPair(true, true); }

    Handle<Map> AddPropertyAtBranch(int branch_id, Expectations* expectations,
                                    Handle<Map> map) {
      CHECK(branch_id == 1 || branch_id == 2);
      // Add the same accessor constant property at both transition tree
      // branches.
      return expectations->AddAccessorConstant(map, NONE, pair_);
    }

    void UpdateExpectations(int property_index, Expectations* expectations) {
      // Two branches are "compatible" so the |map1| should NOT be deprecated.
    }
  };

  TestConfig config;
  CheckSameMap checker;
  TestReconfigureProperty_CustomPropertyAfterTargetMap(&config, &checker);
}


TEST(ReconfigureDataFieldAttribute_AccConstantToAccFieldAfterTargetMap) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  struct TestConfig {
    Handle<AccessorPair> pair1_;
    Handle<AccessorPair> pair2_;
    TestConfig() {
      pair1_ = CreateAccessorPair(true, true);
      pair2_ = CreateAccessorPair(true, true);
    }

    Handle<Map> AddPropertyAtBranch(int branch_id, Expectations* expectations,
                                    Handle<Map> map) {
      CHECK(branch_id == 1 || branch_id == 2);
      Handle<AccessorPair> pair = branch_id == 1 ? pair1_ : pair2_;
      return expectations->AddAccessorConstant(map, NONE, pair);
    }

    void UpdateExpectations(int property_index, Expectations* expectations) {
      if (IS_ACCESSOR_FIELD_SUPPORTED) {
        expectations->SetAccessorField(property_index);
      } else {
        // Currently we have a normalize case and ACCESSOR property becomes
        // ACCESSOR_CONSTANT.
        expectations->SetAccessorConstant(property_index, pair2_);
      }
 
"""


```