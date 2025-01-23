Response: Let's break down the thought process for analyzing this C++ file and generating the summary and JavaScript examples.

1. **Initial Scan and Keywords:**  The first thing to do is quickly scan the file, looking for recognizable keywords and patterns. I see:
    * `RUNTIME_FUNCTION`: This strongly suggests these are functions exposed to the V8 runtime, meaning they're used by the JavaScript engine internally.
    * `Throw...Error`:  Lots of functions starting with `Throw`, which immediately tells me this file is heavily involved in error handling within the engine, particularly related to classes and `super`.
    * `ClassBoilerplate`: This term appears frequently, hinting at class creation and initialization.
    * `DescriptorArray`, `PropertyDictionary`, `NumberDictionary`, `Map`: These are V8's internal data structures for representing objects and their properties.
    * `SuperMode`, `LoadFromSuper`, `StoreToSuper`:  Explicit references to `super` keyword functionality.

2. **Categorizing the Functions:**  Based on the keywords and function names, I can start grouping the functions:
    * **Error Throwing:**  `Runtime_ThrowUnsupportedSuperError`, `Runtime_ThrowConstructorNonCallableError`, `Runtime_ThrowStaticPrototypeError`, `Runtime_ThrowSuperAlreadyCalledError`, `Runtime_ThrowSuperNotCalled`, `Runtime_ThrowNotSuperConstructor`. These are clearly responsible for throwing specific JavaScript errors.
    * **Class Creation/Initialization:** `Runtime_DefineClass`, `CreateClassPrototype`, `InitClassPrototype`, `InitClassConstructor`,  `AddDescriptorsByTemplate`. These are the core functions for setting up class structures.
    * **`super` Keyword Handling:** `Runtime_LoadFromSuper`, `Runtime_LoadKeyedFromSuper`, `Runtime_StoreToSuper`, `Runtime_StoreKeyedToSuper`, `GetSuperHolder`. This section deals with the specific semantics of accessing and modifying properties via `super`.

3. **Understanding the Core Logic (Key Functions):**  I'd then focus on the most complex and central functions:

    * **`Runtime_DefineClass`:** This appears to be the main entry point for defining a JavaScript class. It takes the `ClassBoilerplate` (which likely contains pre-computed information about the class structure) and handles setting up the prototype chain, constructor, and properties. The logic involving `super_class` and different prototype handling is important.
    * **`AddDescriptorsByTemplate`:** This function is used to populate object properties based on templates (either `DescriptorArray` for fast properties or dictionaries for more dynamic scenarios). It handles different property kinds (data, accessors) and potentially sets method names. The logic for computed properties is also within this function.
    * **`Runtime_LoadFromSuper` and `Runtime_StoreToSuper`:** These functions implement the core logic of accessing and modifying properties using the `super` keyword. They involve traversing the prototype chain (`GetSuperHolder`) and performing the appropriate get or set operation.

4. **Connecting to JavaScript:**  Now, for each category of functions, I'd think about the corresponding JavaScript features:

    * **Error Throwing:** These directly map to specific JavaScript errors that developers might encounter when working with classes. I would think of scenarios that trigger these errors (e.g., calling `super()` multiple times, trying to access `super.prototype`, calling a non-callable constructor, extending a non-constructor).
    * **Class Creation/Initialization:** This entire section relates to the `class` syntax in JavaScript. The process of creating a class, its constructor, methods, and prototype is handled by these functions. I would consider examples of class definitions with inheritance, methods, static members, and computed property names.
    * **`super` Keyword Handling:**  This directly translates to the use of `super` within class methods, both to call the parent constructor and to access properties on the parent class's prototype.

5. **Crafting JavaScript Examples:**  For each relevant function or group of functions, I'd create concise JavaScript examples demonstrating the behavior. The goal is to make the connection between the C++ code and the observable JavaScript behavior clear. I'd aim for simple, illustrative examples rather than overly complex ones. It's important to show both successful and error-causing scenarios.

6. **Summarizing the Functionality:** Finally, I would synthesize the information gathered into a high-level summary. This involves:
    * Stating the main purpose of the file.
    * Highlighting the key areas of functionality (error handling, class definition, `super`).
    * Emphasizing the connection to JavaScript's class syntax and inheritance features.

7. **Refinement and Review:**  After drafting the summary and examples, I would review them for clarity, accuracy, and completeness. Are the examples easy to understand? Does the summary accurately reflect the file's content? Could anything be explained more clearly?  For example, initially, I might just say "handles class creation."  But refining that to "handles the internal mechanics of defining and initializing JavaScript classes, including constructors, prototypes, methods, and inheritance" is more informative.

This iterative process of scanning, categorizing, understanding core logic, connecting to JavaScript, creating examples, and summarizing allows for a comprehensive and accurate analysis of the C++ code in relation to JavaScript functionality.
This C++ source file, `runtime-classes.cc` located in `v8/src/runtime`, is a crucial part of the V8 JavaScript engine responsible for implementing the **runtime semantics of JavaScript classes and the `super` keyword**. It defines various runtime functions that are called by the V8 interpreter and compiler when dealing with class-related operations.

Here's a breakdown of its main functionalities:

**1. Throwing Specific Class-Related Errors:**

* The file contains runtime functions dedicated to throwing specific types of errors that can occur during class definition and usage. These errors provide informative messages to the JavaScript developer. Examples include:
    * `Runtime_ThrowUnsupportedSuperError`: Thrown when `super` is used in an invalid context (e.g., outside a method).
    * `Runtime_ThrowConstructorNonCallableError`: Thrown when something that isn't a constructor is attempted to be called as one.
    * `Runtime_ThrowStaticPrototypeError`: Thrown when trying to access the `prototype` property of a static class member.
    * `Runtime_ThrowSuperAlreadyCalledError`: Thrown when `super()` is called multiple times in a constructor.
    * `Runtime_ThrowSuperNotCalled`: Thrown when a derived class constructor doesn't call `super()`.
    * `Runtime_ThrowNotSuperConstructor`: Thrown when the value after `extends` is not a valid constructor.

**2. Implementing Class Definition and Initialization:**

* The file contains the core logic for defining JavaScript classes. This involves:
    * `Runtime_DefineClass`: This is likely the main entry point for the `class` syntax. It takes the class boilerplate (which contains pre-computed information about the class structure), the constructor function, and the superclass (if any).
    * `CreateClassPrototype`:  Creates the prototype object for a class.
    * `InitClassPrototype`: Initializes the prototype object with methods and properties.
    * `InitClassConstructor`: Initializes the constructor function with static methods and properties, and sets up the prototype.
    * Internal helper functions like `AddDescriptorsByTemplate` and `SubstituteValues`: These functions handle the process of adding properties (methods, accessors, data properties) to the class prototype and constructor based on templates generated during compilation. They deal with different kinds of property storage (DescriptorArrays for fast properties, Dictionaries for more dynamic cases).

**3. Implementing the `super` Keyword:**

* The file provides runtime functions to handle the behavior of the `super` keyword in both accessing properties and calling the superclass constructor:
    * `Runtime_LoadFromSuper`: Implements the logic for reading a property from the superclass prototype chain using `super.propertyName`.
    * `Runtime_LoadKeyedFromSuper`: Implements the logic for reading a property from the superclass prototype chain using `super[expression]`.
    * `Runtime_StoreToSuper`: Implements the logic for writing a property to the superclass prototype chain using `super.propertyName = value`.
    * `Runtime_StoreKeyedToSuper`: Implements the logic for writing a property to the superclass prototype chain using `super[expression] = value`.
    * `GetSuperHolder`:  A helper function to find the object in the prototype chain where the `super` lookup should begin.

**Relationship to JavaScript Functionality (with Examples):**

This file directly underpins the core features of JavaScript classes introduced in ECMAScript 2015 (ES6). Here are some examples demonstrating the connection:

**JavaScript Example 1:  `Runtime_ThrowConstructorNonCallableError`**

```javascript
function notAConstructor() {
  return {};
}

class MyClass extends notAConstructor { // Error will be thrown here
  constructor() {
    super();
  }
}
```

When the JavaScript engine encounters `extends notAConstructor`, it will attempt to ensure `notAConstructor` is a callable constructor. If it's not, V8 will call the `Runtime_ThrowConstructorNonCallableError` function internally to throw a `TypeError`.

**JavaScript Example 2: `Runtime_DefineClass`, `InitClassPrototype`, `InitClassConstructor`**

```javascript
class Animal {
  constructor(name) {
    this.name = name;
  }

  speak() {
    console.log("Generic animal sound");
  }
}

class Dog extends Animal {
  constructor(name, breed) {
    super(name); // Triggers super constructor call
    this.breed = breed;
  }

  speak() {
    super.speak(); // Accessing superclass method
    console.log("Woof!");
  }
}

let myDog = new Dog("Buddy", "Golden Retriever");
myDog.speak();
```

* When the `class Animal` and `class Dog` declarations are encountered, the V8 compiler will generate bytecode that ultimately calls `Runtime_DefineClass`.
* `InitClassPrototype` will be responsible for adding the `speak` method to `Animal.prototype`.
* `InitClassConstructor` will handle setting up the constructor functions for both `Animal` and `Dog`.
* The `super(name)` call in the `Dog` constructor will involve internal mechanisms related to calling the superclass constructor.
* The `super.speak()` call in the `Dog`'s `speak` method will utilize `Runtime_LoadFromSuper` to find and execute the `speak` method of the `Animal` class.

**JavaScript Example 3: `Runtime_ThrowSuperNotCalled`**

```javascript
class Base {
  constructor() {
    this.baseProperty = "base";
  }
}

class Derived extends Base {
  constructor() {
    // Oops! Forgot to call super()
    this.derivedProperty = "derived";
  }
}

new Derived(); // This will throw a ReferenceError because super() wasn't called.
```

The V8 engine checks within the `Derived` constructor if `super()` has been called before accessing `this`. If not, `Runtime_ThrowSuperNotCalled` is invoked to throw the appropriate error.

**In summary, `runtime-classes.cc` is a fundamental file in V8 that implements the intricate details of JavaScript's class syntax and the `super` keyword. It manages the creation, initialization, and behavior of classes, and ensures that the correct errors are thrown when class-related rules are violated.**

### 提示词
```
这是目录为v8/src/runtime/runtime-classes.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <limits>

#include "src/builtins/accessors.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/logging/log.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/lookup-inl.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"

namespace v8 {
namespace internal {


RUNTIME_FUNCTION(Runtime_ThrowUnsupportedSuperError) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewReferenceError(MessageTemplate::kUnsupportedSuper));
}


RUNTIME_FUNCTION(Runtime_ThrowConstructorNonCallableError) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> constructor = args.at<JSFunction>(0);
  Handle<String> name(constructor->shared()->Name(), isolate);

  DirectHandle<Context> context(constructor->native_context(), isolate);
  DCHECK(IsNativeContext(*context));
  Handle<JSFunction> realm_type_error_function(
      Cast<JSFunction>(context->get(Context::TYPE_ERROR_FUNCTION_INDEX)),
      isolate);
  if (name->length() == 0) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewError(realm_type_error_function,
                          MessageTemplate::kAnonymousConstructorNonCallable));
  }
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewError(realm_type_error_function,
                        MessageTemplate::kConstructorNonCallable, name));
}


RUNTIME_FUNCTION(Runtime_ThrowStaticPrototypeError) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kStaticPrototype));
}

RUNTIME_FUNCTION(Runtime_ThrowSuperAlreadyCalledError) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewReferenceError(MessageTemplate::kSuperAlreadyCalled));
}

RUNTIME_FUNCTION(Runtime_ThrowSuperNotCalled) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewReferenceError(MessageTemplate::kSuperNotCalled));
}

namespace {

Tagged<Object> ThrowNotSuperConstructor(Isolate* isolate,
                                        Handle<Object> constructor,
                                        DirectHandle<JSFunction> function) {
  DirectHandle<String> super_name;
  if (IsJSFunction(*constructor)) {
    super_name =
        direct_handle(Cast<JSFunction>(constructor)->shared()->Name(), isolate);
  } else if (IsOddball(*constructor)) {
    DCHECK(IsNull(*constructor, isolate));
    super_name = isolate->factory()->null_string();
  } else {
    super_name = Object::NoSideEffectsToString(isolate, constructor);
  }
  // null constructor
  if (super_name->length() == 0) {
    super_name = isolate->factory()->null_string();
  }
  Handle<String> function_name(function->shared()->Name(), isolate);
  // anonymous class
  if (function_name->length() == 0) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kNotSuperConstructorAnonymousClass,
                     super_name));
  }
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kNotSuperConstructor, super_name,
                            function_name));
}

}  // namespace

RUNTIME_FUNCTION(Runtime_ThrowNotSuperConstructor) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<Object> constructor = args.at(0);
  DirectHandle<JSFunction> function = args.at<JSFunction>(1);
  return ThrowNotSuperConstructor(isolate, constructor, function);
}

namespace {

template <typename Dictionary>
Handle<Name> KeyToName(Isolate* isolate, Handle<Object> key) {
  static_assert((std::is_same<Dictionary, SwissNameDictionary>::value ||
                 std::is_same<Dictionary, NameDictionary>::value));
  DCHECK(IsName(*key));
  return Cast<Name>(key);
}

template <>
Handle<Name> KeyToName<NumberDictionary>(Isolate* isolate, Handle<Object> key) {
  DCHECK(IsNumber(*key));
  return isolate->factory()->NumberToString(key);
}

// Gets |index|'th argument which may be a class constructor object, a class
// prototype object or a class method. In the latter case the following
// post-processing may be required:
// 1) set method's name to a concatenation of |name_prefix| and |key| if the
//    method's shared function info indicates that method does not have a
//    shared name.
template <typename Dictionary>
MaybeHandle<Object> GetMethodAndSetName(Isolate* isolate,
                                        RuntimeArguments& args,
                                        Tagged<Smi> index,
                                        DirectHandle<String> name_prefix,
                                        Handle<Object> key) {
  int int_index = index.value();

  // Class constructor and prototype values do not require post processing.
  if (int_index < ClassBoilerplate::kFirstDynamicArgumentIndex) {
    return args.at<Object>(int_index);
  }

  Handle<JSFunction> method = args.at<JSFunction>(int_index);

  if (!method->shared()->HasSharedName()) {
    // TODO(ishell): method does not have a shared name at this point only if
    // the key is a computed property name. However, the bytecode generator
    // explicitly generates ToName bytecodes to ensure that the computed
    // property name is properly converted to Name. So, we can actually be smart
    // here and avoid converting Smi keys back to Name.
    Handle<Name> name = KeyToName<Dictionary>(isolate, key);
    if (!JSFunction::SetName(method, name, name_prefix)) {
      return MaybeHandle<Object>();
    }
  }
  return method;
}

// Gets |index|'th argument which may be a class constructor object, a class
// prototype object or a class method.
// This is a simplified version of GetMethodAndSetName()
// function above that is used when it's guaranteed that the method has
// shared name.
Tagged<Object> GetMethodWithSharedName(Isolate* isolate, RuntimeArguments& args,
                                       Tagged<Object> index) {
  DisallowGarbageCollection no_gc;
  int int_index = Smi::ToInt(index);

  // Class constructor and prototype values do not require post processing.
  if (int_index < ClassBoilerplate::kFirstDynamicArgumentIndex) {
    return args[int_index];
  }

  DirectHandle<JSFunction> method = args.at<JSFunction>(int_index);
  DCHECK(method->shared()->HasSharedName());
  return *method;
}

template <typename Dictionary>
Handle<Dictionary> ShallowCopyDictionaryTemplate(
    Isolate* isolate, Handle<Dictionary> dictionary_template) {
  Handle<Dictionary> dictionary =
      Dictionary::ShallowCopy(isolate, dictionary_template);
  // Clone all AccessorPairs in the dictionary.
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> value = dictionary->ValueAt(i);
    if (IsAccessorPair(value)) {
      DirectHandle<AccessorPair> pair(Cast<AccessorPair>(value), isolate);
      pair = AccessorPair::Copy(isolate, pair);
      dictionary->ValueAtPut(i, *pair);
    }
  }
  return dictionary;
}

template <typename Dictionary>
bool SubstituteValues(Isolate* isolate, Handle<Dictionary> dictionary,
                      RuntimeArguments& args) {
  // Replace all indices with proper methods.
  ReadOnlyRoots roots(isolate);
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> maybe_key = dictionary->KeyAt(i);
    if (!Dictionary::IsKey(roots, maybe_key)) continue;
    Handle<Object> key(maybe_key, isolate);
    Handle<Object> value(dictionary->ValueAt(i), isolate);
    if (IsAccessorPair(*value)) {
      auto pair = Cast<AccessorPair>(value);
      Tagged<Object> tmp = pair->getter();
      if (IsSmi(tmp)) {
        Handle<Object> result;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, result,
            GetMethodAndSetName<Dictionary>(isolate, args, Cast<Smi>(tmp),
                                            isolate->factory()->get_string(),
                                            key),
            false);
        pair->set_getter(*result);
      }
      tmp = pair->setter();
      if (IsSmi(tmp)) {
        Handle<Object> result;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, result,
            GetMethodAndSetName<Dictionary>(isolate, args, Cast<Smi>(tmp),
                                            isolate->factory()->set_string(),
                                            key),
            false);
        pair->set_setter(*result);
      }
    } else if (IsSmi(*value)) {
      Handle<Object> result;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, result,
          GetMethodAndSetName<Dictionary>(isolate, args, Cast<Smi>(*value),
                                          isolate->factory()->empty_string(),
                                          key),
          false);
      dictionary->ValueAtPut(i, *result);
    }
  }
  return true;
}

template <typename Dictionary>
void UpdateProtectors(Isolate* isolate, Handle<JSObject> receiver,
                      DirectHandle<Dictionary> properties_dictionary) {
  ReadOnlyRoots roots(isolate);
  for (InternalIndex i : properties_dictionary->IterateEntries()) {
    Tagged<Object> maybe_key = properties_dictionary->KeyAt(i);
    if (!Dictionary::IsKey(roots, maybe_key)) continue;
    DirectHandle<Name> name(Cast<Name>(maybe_key), isolate);
    LookupIterator::UpdateProtector(isolate, receiver, name);
  }
}

void UpdateProtectors(Isolate* isolate, Handle<JSObject> receiver,
                      DirectHandle<DescriptorArray> properties_template) {
  int nof_descriptors = properties_template->number_of_descriptors();
  for (InternalIndex i : InternalIndex::Range(nof_descriptors)) {
    DirectHandle<Name> name(properties_template->GetKey(i), isolate);
    LookupIterator::UpdateProtector(isolate, receiver, name);
  }
}

bool AddDescriptorsByTemplate(
    Isolate* isolate, DirectHandle<Map> map,
    DirectHandle<DescriptorArray> descriptors_template,
    Handle<NumberDictionary> elements_dictionary_template,
    Handle<JSObject> receiver, RuntimeArguments& args) {
  int nof_descriptors = descriptors_template->number_of_descriptors();

  DirectHandle<DescriptorArray> descriptors =
      DescriptorArray::Allocate(isolate, nof_descriptors, 0);

  Handle<NumberDictionary> elements_dictionary =
      *elements_dictionary_template ==
              ReadOnlyRoots(isolate).empty_slow_element_dictionary()
          ? elements_dictionary_template
          : ShallowCopyDictionaryTemplate(isolate,
                                          elements_dictionary_template);

  // Count the number of properties that must be in the instance and
  // create the property array to hold the constants.
  int count = 0;
  for (InternalIndex i : InternalIndex::Range(nof_descriptors)) {
    PropertyDetails details = descriptors_template->GetDetails(i);
    if (details.location() == PropertyLocation::kDescriptor &&
        details.kind() == PropertyKind::kData) {
      count++;
    }
  }
  DirectHandle<PropertyArray> property_array =
      isolate->factory()->NewPropertyArray(count);

  // Read values from |descriptors_template| and store possibly post-processed
  // values into "instantiated" |descriptors| array.
  int field_index = 0;
  for (InternalIndex i : InternalIndex::Range(nof_descriptors)) {
    Tagged<Object> value = descriptors_template->GetStrongValue(i);
    if (IsAccessorPair(value)) {
      DirectHandle<AccessorPair> pair = AccessorPair::Copy(
          isolate, handle(Cast<AccessorPair>(value), isolate));
      value = *pair;
    }
    DisallowGarbageCollection no_gc;
    Tagged<Name> name = descriptors_template->GetKey(i);
    // TODO(v8:5799): consider adding a ClassBoilerplate flag
    // "has_interesting_properties".
    if (name->IsInteresting(isolate)) {
      map->set_may_have_interesting_properties(true);
    }
    DCHECK(IsUniqueName(name));
    PropertyDetails details = descriptors_template->GetDetails(i);
    if (details.location() == PropertyLocation::kDescriptor) {
      if (details.kind() == PropertyKind::kData) {
        if (IsSmi(value)) {
          value = GetMethodWithSharedName(isolate, args, value);
        }
        details = details.CopyWithRepresentation(
            Object::OptimalRepresentation(value, isolate));
      } else {
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        if (IsAccessorPair(value)) {
          Tagged<AccessorPair> pair = Cast<AccessorPair>(value);
          Tagged<Object> tmp = pair->getter();
          if (IsSmi(tmp)) {
            pair->set_getter(GetMethodWithSharedName(isolate, args, tmp));
          }
          tmp = pair->setter();
          if (IsSmi(tmp)) {
            pair->set_setter(GetMethodWithSharedName(isolate, args, tmp));
          }
        }
      }
    } else {
      UNREACHABLE();
    }
    DCHECK(Object::FitsRepresentation(value, details.representation()));
    if (details.location() == PropertyLocation::kDescriptor &&
        details.kind() == PropertyKind::kData) {
      details =
          PropertyDetails(details.kind(), details.attributes(),
                          PropertyLocation::kField, PropertyConstness::kConst,
                          details.representation(), field_index)
              .set_pointer(details.pointer());

      property_array->set(field_index, value);
      field_index++;
      descriptors->Set(i, name, FieldType::Any(), details);
    } else {
      descriptors->Set(i, name, value, details);
    }
  }

  UpdateProtectors(isolate, receiver, descriptors_template);

  map->InitializeDescriptors(isolate, *descriptors);
  if (elements_dictionary->NumberOfElements() > 0) {
    if (!SubstituteValues<NumberDictionary>(isolate, elements_dictionary,
                                            args)) {
      return false;
    }
    map->set_elements_kind(DICTIONARY_ELEMENTS);
  }

  // Atomically commit the changes.
  receiver->set_map(isolate, *map, kReleaseStore);
  if (elements_dictionary->NumberOfElements() > 0) {
    receiver->set_elements(*elements_dictionary);
  }
  if (property_array->length() > 0) {
    receiver->SetProperties(*property_array);
  }
  return true;
}

// TODO(v8:7569): This is a workaround for the Handle vs MaybeHandle difference
// in the return types of the different Add functions:
// OrderedNameDictionary::Add returns MaybeHandle, NameDictionary::Add returns
// Handle.
template <typename T>
Handle<T> ToHandle(Handle<T> h) {
  return h;
}
template <typename T>
Handle<T> ToHandle(MaybeHandle<T> h) {
  return h.ToHandleChecked();
}

template <typename Dictionary>
bool AddDescriptorsByTemplate(
    Isolate* isolate, DirectHandle<Map> map,
    Handle<Dictionary> properties_dictionary_template,
    Handle<NumberDictionary> elements_dictionary_template,
    DirectHandle<FixedArray> computed_properties, Handle<JSObject> receiver,
    RuntimeArguments& args) {
  int computed_properties_length = computed_properties->length();

  // Shallow-copy properties template.
  Handle<Dictionary> properties_dictionary =
      ShallowCopyDictionaryTemplate(isolate, properties_dictionary_template);
  Handle<NumberDictionary> elements_dictionary =
      ShallowCopyDictionaryTemplate(isolate, elements_dictionary_template);

  using ValueKind = ClassBoilerplate::ValueKind;
  using ComputedEntryFlags = ClassBoilerplate::ComputedEntryFlags;

  // Merge computed properties with properties and elements dictionary
  // templates.
  int i = 0;
  while (i < computed_properties_length) {
    int flags = Smi::ToInt(computed_properties->get(i++));

    ValueKind value_kind = ComputedEntryFlags::ValueKindBits::decode(flags);
    int key_index = ComputedEntryFlags::KeyIndexBits::decode(flags);
    Tagged<Smi> value = Smi::FromInt(key_index + 1);  // Value follows name.

    Handle<Object> key = args.at(key_index);
    DCHECK(IsName(*key));
    uint32_t element;
    Handle<Name> name = Cast<Name>(key);
    if (name->AsArrayIndex(&element)) {
      ClassBoilerplate::AddToElementsTemplate(
          isolate, elements_dictionary, element, key_index, value_kind, value);

    } else {
      name = isolate->factory()->InternalizeName(name);
      ClassBoilerplate::AddToPropertiesTemplate(
          isolate, properties_dictionary, name, key_index, value_kind, value);
      if (name->IsInteresting(isolate)) {
        // TODO(pthier): Add flags to swiss dictionaries.
        if constexpr (!V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
          properties_dictionary->set_may_have_interesting_properties(true);
        }
      }
    }
  }

  // Replace all indices with proper methods.
  if (!SubstituteValues<Dictionary>(isolate, properties_dictionary, args)) {
    return false;
  }

  UpdateProtectors(isolate, receiver,
                   DirectHandle<Dictionary>(properties_dictionary));

  if (elements_dictionary->NumberOfElements() > 0) {
    if (!SubstituteValues<NumberDictionary>(isolate, elements_dictionary,
                                            args)) {
      return false;
    }
    map->set_elements_kind(DICTIONARY_ELEMENTS);
  }

  // Atomically commit the changes.
  receiver->set_map(isolate, *map, kReleaseStore);
  receiver->set_raw_properties_or_hash(*properties_dictionary, kRelaxedStore);
  if (elements_dictionary->NumberOfElements() > 0) {
    receiver->set_elements(*elements_dictionary);
  }
  return true;
}

Handle<JSObject> CreateClassPrototype(Isolate* isolate) {
  // For constant tracking we want to avoid the hassle of handling
  // in-object properties, so create a map with no in-object
  // properties.

  // TODO(ishell) Support caching of zero in-object properties map
  // by ObjectLiteralMapFromCache().
  DirectHandle<Map> map = Map::Create(isolate, 0);
  return isolate->factory()->NewJSObjectFromMap(map);
}

bool InitClassPrototype(Isolate* isolate,
                        DirectHandle<ClassBoilerplate> class_boilerplate,
                        Handle<JSObject> prototype,
                        Handle<JSPrototype> prototype_parent,
                        DirectHandle<JSFunction> constructor,
                        RuntimeArguments& args) {
  Handle<Map> map(prototype->map(), isolate);
  map = Map::CopyDropDescriptors(isolate, map);
  map->set_is_prototype_map(true);
  Map::SetPrototype(isolate, map, prototype_parent);
  isolate->UpdateProtectorsOnSetPrototype(prototype, prototype_parent);
  constructor->set_prototype_or_initial_map(*prototype, kReleaseStore);
  map->SetConstructor(*constructor);
  DirectHandle<FixedArray> computed_properties(
      class_boilerplate->instance_computed_properties(), isolate);
  Handle<NumberDictionary> elements_dictionary_template(
      Cast<NumberDictionary>(class_boilerplate->instance_elements_template()),
      isolate);

  Handle<Object> properties_template(
      class_boilerplate->instance_properties_template(), isolate);

  if (IsDescriptorArray(*properties_template)) {
    auto descriptors_template = Cast<DescriptorArray>(properties_template);

    // The size of the prototype object is known at this point.
    // So we can create it now and then add the rest instance methods to the
    // map.
    return AddDescriptorsByTemplate(isolate, map, descriptors_template,
                                    elements_dictionary_template, prototype,
                                    args);
  } else {
    map->set_is_dictionary_map(true);
    map->set_is_migration_target(false);
    map->set_may_have_interesting_properties(true);
    map->set_construction_counter(Map::kNoSlackTracking);

    auto properties_dictionary_template =
        Cast<PropertyDictionary>(properties_template);
    return AddDescriptorsByTemplate(
        isolate, map, properties_dictionary_template,
        elements_dictionary_template, computed_properties, prototype, args);
  }
}

bool InitClassConstructor(Isolate* isolate,
                          DirectHandle<ClassBoilerplate> class_boilerplate,
                          Handle<JSPrototype> constructor_parent,
                          Handle<JSFunction> constructor,
                          RuntimeArguments& args) {
  Handle<Map> map(constructor->map(), isolate);
  map = Map::CopyDropDescriptors(isolate, map);
  DCHECK(map->is_prototype_map());

  if (!constructor_parent.is_null()) {
    // Set map's prototype without enabling prototype setup mode for superclass
    // because it does not make sense.
    Map::SetPrototype(isolate, map, constructor_parent, false);
    // Ensure that setup mode will never be enabled for superclass.
    JSObject::MakePrototypesFast(constructor_parent, kStartAtReceiver, isolate);
  }

  Handle<NumberDictionary> elements_dictionary_template(
      Cast<NumberDictionary>(class_boilerplate->static_elements_template()),
      isolate);
  DirectHandle<FixedArray> computed_properties(
      class_boilerplate->static_computed_properties(), isolate);

  Handle<Object> properties_template(
      class_boilerplate->static_properties_template(), isolate);

  if (IsDescriptorArray(*properties_template)) {
    auto descriptors_template = Cast<DescriptorArray>(properties_template);

    return AddDescriptorsByTemplate(isolate, map, descriptors_template,
                                    elements_dictionary_template, constructor,
                                    args);
  } else {
    map->set_is_dictionary_map(true);
    map->InitializeDescriptors(isolate,
                               ReadOnlyRoots(isolate).empty_descriptor_array());
    map->set_is_migration_target(false);
    map->set_may_have_interesting_properties(true);
    map->set_construction_counter(Map::kNoSlackTracking);

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      auto properties_dictionary_template =
          Cast<SwissNameDictionary>(properties_template);

      return AddDescriptorsByTemplate(
          isolate, map, properties_dictionary_template,
          elements_dictionary_template, computed_properties, constructor, args);
    } else {
      auto properties_dictionary_template =
          Cast<NameDictionary>(properties_template);
      return AddDescriptorsByTemplate(
          isolate, map, properties_dictionary_template,
          elements_dictionary_template, computed_properties, constructor, args);
    }
  }
}

MaybeHandle<Object> DefineClass(
    Isolate* isolate, DirectHandle<ClassBoilerplate> class_boilerplate,
    Handle<Object> super_class, Handle<JSFunction> constructor,
    RuntimeArguments& args) {
  Handle<JSPrototype> prototype_parent;
  Handle<JSPrototype> constructor_parent;

  if (IsTheHole(*super_class, isolate)) {
    prototype_parent = isolate->initial_object_prototype();
  } else {
    if (IsNull(*super_class, isolate)) {
      prototype_parent = isolate->factory()->null_value();
    } else if (IsConstructor(*super_class)) {
      DCHECK(!IsJSFunction(*super_class) ||
             !IsResumableFunction(
                 Cast<JSFunction>(super_class)->shared()->kind()));
      Handle<Object> maybe_prototype_parent;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, maybe_prototype_parent,
          Runtime::GetObjectProperty(isolate, Cast<JSAny>(super_class),
                                     isolate->factory()->prototype_string()));
      if (!TryCast(maybe_prototype_parent, &prototype_parent)) {
        THROW_NEW_ERROR(
            isolate, NewTypeError(MessageTemplate::kPrototypeParentNotAnObject,
                                  maybe_prototype_parent));
      }
      // Create new handle to avoid |constructor_parent| corruption because of
      // |super_class| handle value overwriting via storing to
      // args[ClassBoilerplate::kPrototypeArgumentIndex] below.
      constructor_parent = handle(Cast<JSPrototype>(*super_class), isolate);
    } else {
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kExtendsValueNotConstructor,
                                   super_class));
    }
  }

  Handle<JSObject> prototype = CreateClassPrototype(isolate);
  DCHECK_EQ(*constructor, args[ClassBoilerplate::kConstructorArgumentIndex]);
  // Temporarily change ClassBoilerplate::kPrototypeArgumentIndex for the
  // subsequent calls, but use a scope to make sure to change it back before
  // returning, to not corrupt the caller's argument frame (in particular, for
  // the interpreter, to not clobber the register frame).
  RuntimeArguments::ChangeValueScope set_prototype_value_scope(
      isolate, &args, ClassBoilerplate::kPrototypeArgumentIndex, *prototype);

  if (!InitClassConstructor(isolate, class_boilerplate, constructor_parent,
                            constructor, args) ||
      !InitClassPrototype(isolate, class_boilerplate, prototype,
                          prototype_parent, constructor, args)) {
    DCHECK(isolate->has_exception());
    return MaybeHandle<Object>();
  }
  if (v8_flags.log_maps) {
    Handle<Map> empty_map;
    LOG(isolate,
        MapEvent("InitialMap", empty_map, handle(constructor->map(), isolate),
                 "init class constructor",
                 SharedFunctionInfo::DebugName(
                     isolate, handle(constructor->shared(), isolate))));
    LOG(isolate,
        MapEvent("InitialMap", empty_map, handle(prototype->map(), isolate),
                 "init class prototype"));
  }

  return prototype;
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DefineClass) {
  HandleScope scope(isolate);
  DCHECK_LE(ClassBoilerplate::kFirstDynamicArgumentIndex, args.length());
  DirectHandle<ClassBoilerplate> class_boilerplate =
      args.at<ClassBoilerplate>(0);
  Handle<JSFunction> constructor = args.at<JSFunction>(1);
  Handle<Object> super_class = args.at(2);
  DCHECK_EQ(class_boilerplate->arguments_count(), args.length());

  RETURN_RESULT_OR_FAILURE(
      isolate,
      DefineClass(isolate, class_boilerplate, super_class, constructor, args));
}

namespace {

enum class SuperMode { kLoad, kStore };

MaybeHandle<JSReceiver> GetSuperHolder(Isolate* isolate,
                                       Handle<JSObject> home_object,
                                       SuperMode mode, PropertyKey* key) {
  if (IsAccessCheckNeeded(*home_object) &&
      !isolate->MayAccess(isolate->native_context(), home_object)) {
    RETURN_ON_EXCEPTION(isolate, isolate->ReportFailedAccessCheck(home_object));
    UNREACHABLE();
  }

  PrototypeIterator iter(isolate, home_object);
  Handle<Object> proto = PrototypeIterator::GetCurrent(iter);
  if (!IsJSReceiver(*proto)) {
    MessageTemplate message =
        mode == SuperMode::kLoad
            ? MessageTemplate::kNonObjectPropertyLoadWithProperty
            : MessageTemplate::kNonObjectPropertyStoreWithProperty;
    Handle<Name> name = key->GetName(isolate);
    THROW_NEW_ERROR(isolate, NewTypeError(message, proto, name));
  }
  return Cast<JSReceiver>(proto);
}

MaybeHandle<Object> LoadFromSuper(Isolate* isolate, Handle<JSAny> receiver,
                                  Handle<JSObject> home_object,
                                  PropertyKey* key) {
  Handle<JSReceiver> holder;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, holder,
      GetSuperHolder(isolate, home_object, SuperMode::kLoad, key));
  LookupIterator it(isolate, receiver, *key, holder);
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, result, Object::GetProperty(&it));
  return result;
}

}  // anonymous namespace

RUNTIME_FUNCTION(Runtime_LoadFromSuper) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<JSObject> home_object = args.at<JSObject>(1);
  Handle<Name> name = args.at<Name>(2);

  PropertyKey key(isolate, name);

  RETURN_RESULT_OR_FAILURE(isolate,
                           LoadFromSuper(isolate, receiver, home_object, &key));
}


RUNTIME_FUNCTION(Runtime_LoadKeyedFromSuper) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<JSObject> home_object = args.at<JSObject>(1);
  // TODO(ishell): To improve performance, consider performing the to-string
  // conversion of {key} before calling into the runtime.
  Handle<Object> key = args.at(2);

  bool success;
  PropertyKey lookup_key(isolate, key, &success);
  if (!success) return ReadOnlyRoots(isolate).exception();

  RETURN_RESULT_OR_FAILURE(
      isolate, LoadFromSuper(isolate, receiver, home_object, &lookup_key));
}

namespace {

MaybeHandle<Object> StoreToSuper(Isolate* isolate, Handle<JSObject> home_object,
                                 Handle<JSAny> receiver, PropertyKey* key,
                                 Handle<Object> value,
                                 StoreOrigin store_origin) {
  Handle<JSReceiver> holder;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, holder,
      GetSuperHolder(isolate, home_object, SuperMode::kStore, key));
  LookupIterator it(isolate, receiver, *key, holder);
  MAYBE_RETURN(Object::SetSuperProperty(&it, value, store_origin),
               MaybeHandle<Object>());
  return value;
}

}  // anonymous namespace

RUNTIME_FUNCTION(Runtime_StoreToSuper) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<JSObject> home_object = args.at<JSObject>(1);
  Handle<Name> name = args.at<Name>(2);
  Handle<Object> value = args.at(3);

  PropertyKey key(isolate, name);

  RETURN_RESULT_OR_FAILURE(
      isolate, StoreToSuper(isolate, home_object, receiver, &key, value,
                            StoreOrigin::kNamed));
}

RUNTIME_FUNCTION(Runtime_StoreKeyedToSuper) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<JSObject> home_object = args.at<JSObject>(1);
  // TODO(ishell): To improve performance, consider performing the to-string
  // conversion of {key} before calling into the runtime.
  Handle<Object> key = args.at(2);
  Handle<Object> value = args.at(3);

  bool success;
  PropertyKey lookup_key(isolate, key, &success);
  if (!success) return ReadOnlyRoots(isolate).exception();

  RETURN_RESULT_OR_FAILURE(
      isolate, StoreToSuper(isolate, home_object, receiver, &lookup_key, value,
                            StoreOrigin::kMaybeKeyed));
}

}  // namespace internal
}  // namespace v8
```