Response:
Let's break down the thought process for analyzing the provided C++ code and generating the requested information.

1. **Understand the Goal:** The request asks for a functional description of the `runtime-classes.cc` file within the V8 JavaScript engine. It also has specific instructions regarding Torque, JavaScript examples, logic inference, and common programming errors.

2. **Initial Scan and Keyword Identification:**  A quick scan of the code reveals several important keywords and patterns:
    * `RUNTIME_FUNCTION`: This strongly indicates that the file defines runtime functions callable from JavaScript.
    * `Throw...Error`:  Multiple functions with names like `ThrowUnsupportedSuperError`, `ThrowConstructorNonCallableError`, etc. This suggests error handling related to classes and inheritance.
    * `HandleScope`, `Isolate`:  These are standard V8 C++ constructs for memory management and access to the V8 engine's state.
    * `ClassBoilerplate`: This likely relates to the internal representation of JavaScript classes.
    * `Map`, `DescriptorArray`, `PropertyDictionary`, `NumberDictionary`:  These are V8's internal data structures for managing object properties and metadata.
    * `Super`:  Functions like `Runtime_LoadFromSuper` and `Runtime_StoreToSuper` clearly deal with the `super` keyword in JavaScript.
    * `DefineClass`: This function is central to the process of creating JavaScript classes.

3. **Categorize Runtime Functions:** Based on the function names and their actions, group them by functionality:
    * **Error Handling:**  Functions that throw specific errors related to class features (e.g., `super`, constructor calls, static prototypes).
    * **Class Creation (`DefineClass`):** The core function for defining a JavaScript class. It involves handling inheritance, prototypes, and property setup.
    * **`super` Keyword:** Functions for loading and storing properties via `super`.

4. **Detailed Analysis of Key Functions:**  Focus on the most significant functions:
    * **`Runtime_DefineClass`:**  Recognize its role in class creation. Notice how it interacts with `ClassBoilerplate`, handles superclasses, creates prototypes, and initializes properties using template data structures (`DescriptorArray`, `PropertyDictionary`, `NumberDictionary`). Pay attention to the different code paths depending on the type of `properties_template`.
    * **Error Throwing Functions:**  Understand the specific errors they throw and the conditions that trigger them. For instance, `Runtime_ThrowConstructorNonCallableError` is called when a non-callable object is used as a constructor.
    * **`Runtime_LoadFromSuper` and `Runtime_StoreToSuper`:**  Decipher their purpose in accessing properties of the superclass using the `super` keyword. Note the access checks and error handling for non-object prototypes.

5. **Identify Relationships with JavaScript:** Connect the C++ runtime functions to their corresponding JavaScript features:
    * Error throwing functions are directly related to JavaScript error messages and scenarios.
    * `Runtime_DefineClass` implements the `class` syntax in JavaScript.
    * `Runtime_LoadFromSuper` and `Runtime_StoreToSuper` are the underlying mechanisms for `super.property` access.

6. **Construct JavaScript Examples:** For each group of functions, create simple JavaScript examples that would trigger the execution of those runtime functions. This helps illustrate the connection between the C++ code and the user-facing JavaScript behavior.

7. **Infer Logic and Provide Input/Output Examples:** For functions like `Runtime_DefineClass`, consider the inputs (e.g., `ClassBoilerplate`, constructor function, superclass) and the output (the created prototype object). While providing precise input/output for a complex function like `DefineClass` is challenging without deep V8 internals knowledge, focus on the *types* of inputs and the *general* nature of the output.

8. **Identify Common Programming Errors:**  Think about the JavaScript errors surfaced by the runtime functions. This leads to examples of incorrect class usage, such as calling `super()` multiple times, forgetting to call `super()`, or extending non-constructor objects.

9. **Address Torque:**  The request specifically asks about `.tq` files. Based on common knowledge of V8 development, recognize that `.tq` files are Torque files, a type system and language used for writing V8 builtins. Since the filename ends in `.cc`, it's *not* a Torque file.

10. **Structure the Response:** Organize the information logically using the headings provided in the request (Functionality, Torque, JavaScript Examples, Logic Inference, Common Errors). Use clear and concise language.

11. **Review and Refine:**  Read through the generated response to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have only listed the error types. On review, I'd realize adding the *reasons* for those errors (e.g., "calling a non-callable object as a constructor") makes the explanation more helpful.

Self-Correction Example during the Process:

* **Initial thought:** "This file just throws errors."
* **Correction:**  While error handling is a significant part, the `Runtime_DefineClass` function is clearly about the *creation* of classes, which is a more fundamental function. Re-prioritize and give more weight to `DefineClass` in the explanation.

By following these steps, systematically analyzing the code, and connecting it to JavaScript concepts, we can generate a comprehensive and informative response like the example provided in the prompt.
好的，让我们来分析一下 `v8/src/runtime/runtime-classes.cc` 这个 V8 源代码文件的功能。

**功能概览:**

`v8/src/runtime/runtime-classes.cc` 文件定义了一系列 V8 的 **运行时 (Runtime)** 函数，这些函数主要负责处理与 JavaScript **类 (Classes)** 相关的操作。这些运行时函数通常由 V8 的字节码解释器 (Ignition) 或即时编译器 (TurboFan) 在执行 JavaScript 代码时调用。

具体来说，这个文件包含了以下主要功能：

1. **抛出与类相关的错误:** 定义了多种用于抛出特定类相关错误的运行时函数，例如：
    * `Runtime_ThrowUnsupportedSuperError`: 当在不支持 `super` 调用的地方使用时抛出错误。
    * `Runtime_ThrowConstructorNonCallableError`: 当尝试将非函数对象作为构造函数调用时抛出错误。
    * `Runtime_ThrowStaticPrototypeError`: 当尝试访问静态属性的 `prototype` 时抛出错误。
    * `Runtime_ThrowSuperAlreadyCalledError`: 当构造函数中 `super()` 被多次调用时抛出错误。
    * `Runtime_ThrowSuperNotCalled`: 当派生类的构造函数中没有调用 `super()` 时抛出错误。
    * `Runtime_ThrowNotSuperConstructor`: 当 `extends` 关键字后面的表达式不是构造函数或 `null` 时抛出错误。

2. **定义类 (DefineClass):** 核心函数 `Runtime_DefineClass` 负责实际创建 JavaScript 类。它会处理类的继承关系、原型链的构建、静态属性和方法的初始化等。这个函数会使用 `ClassBoilerplate` 对象中预先计算好的模板信息来高效地创建类。

3. **处理 `super` 关键字:** 实现了与 `super` 关键字相关的运行时函数：
    * `Runtime_LoadFromSuper`: 用于从父类中加载属性 (例如 `super.method()` 或 `super.property`)。
    * `Runtime_LoadKeyedFromSuper`: 用于从父类中加载键控属性 (例如 `super[name]`)。
    * `Runtime_StoreToSuper`: 用于向父类存储属性 (例如 `super.property = value`)。
    * `Runtime_StoreKeyedToSuper`: 用于向父类存储键控属性 (例如 `super[name] = value`)。

**关于 Torque:**

文件 `v8/src/runtime/runtime-classes.cc` **不是**以 `.tq` 结尾的，因此它不是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的类型化的中间语言，用于更安全、更高效地编写内置函数。

**与 JavaScript 功能的关系及示例:**

这个文件中的运行时函数直接对应于 JavaScript 中类的语法和语义。以下是一些 JavaScript 例子，说明了这些运行时函数在幕后是如何工作的：

1. **抛出错误:**

   ```javascript
   class Parent {}
   class Child extends Parent {
     constructor() {
       super(); // 正确调用
       super(); // 错误：Runtime_ThrowSuperAlreadyCalledError
     }
   }

   class InvalidConstructor extends null { // 使用 null 作为父类
     constructor() {} // 错误：Runtime_ThrowSuperNotCalled
   }

   function notAConstructor() {}
   class MyClass extends notAConstructor {} // 错误：Runtime_ThrowNotSuperConstructor

   class StaticClass {
     static method() {}
   }
   console.log(StaticClass.method.prototype); // 错误：Runtime_ThrowStaticPrototypeError
   ```

2. **定义类 (`Runtime_DefineClass`):**

   ```javascript
   class MyClass {
     constructor(x) {
       this.x = x;
     }
     method() {
       console.log(this.x);
     }
   }

   const instance = new MyClass(10);
   instance.method(); // 输出 10
   ```
   当 JavaScript 引擎执行 `class MyClass ...` 这段代码时，会调用 `Runtime_DefineClass` 运行时函数来创建 `MyClass` 构造函数和其原型对象。

3. **处理 `super` 关键字 (`Runtime_LoadFromSuper`, `Runtime_StoreToSuper` 等):**

   ```javascript
   class Parent {
     constructor(value) {
       this.value = value;
     }
     getValue() {
       return this.value;
     }
   }

   class Child extends Parent {
     constructor(value, extra) {
       super(value * 2); // 调用父类的构造函数
       this.extra = extra;
     }
     getValue() {
       return super.getValue() + this.extra; // 调用父类的方法
     }
     setValue(newValue) {
       super.value = newValue; // 设置父类的属性
     }
   }

   const child = new Child(5, 3);
   console.log(child.getValue()); // 输出 13 (10 + 3)
   child.setValue(20);
   console.log(child.getValue()); // 输出 23 (20 + 3)
   ```
   在 `Child` 类中对 `super()` 和 `super.getValue()` 的调用，以及对 `super.value` 的赋值，都会在运行时触发相应的 `Runtime_LoadFromSuper` 或 `Runtime_StoreToSuper` 函数。

**代码逻辑推理与假设输入/输出:**

以 `Runtime_DefineClass` 为例，进行一些简化的逻辑推理：

**假设输入:**

* `class_boilerplate`: 一个包含类元数据的 `ClassBoilerplate` 对象，例如类的名称、静态和实例成员的描述符等。
* `super_class`: 父类的构造函数对象 (如果存在继承)。
* `constructor`: 当前要定义的类的构造函数对象。
* `args`: 一个包含类定义中动态参数的 `RuntimeArguments` 对象，例如方法、getter/setter 函数等。

**简化的内部逻辑流程:**

1. **确定原型链:** 根据 `super_class` 确定新类的原型对象的父对象。
2. **创建原型对象:** 使用预定义的模板创建类的原型对象。
3. **初始化构造函数:** 设置构造函数的原型属性，并添加静态属性和方法。
4. **初始化原型对象:** 将实例方法、getter 和 setter 添加到原型对象。

**简化的输出:**

* `prototype`:  新创建的类的原型对象。

**请注意:** `Runtime_DefineClass` 的内部逻辑非常复杂，涉及到 V8 内部对象模型的诸多细节，上述只是一个高度简化的描述。

**用户常见的编程错误:**

这个文件中的错误处理函数揭示了一些用户在编写 JavaScript 类时常见的错误：

1. **忘记在派生类的构造函数中调用 `super()`:**
   ```javascript
   class Parent {}
   class Child extends Parent {
     constructor() {
       // 忘记调用 super();
       this.someProperty = 10; // 报错：Must call super constructor in derived class before accessing 'this' or returning from derived constructor
     }
   }
   ```

2. **多次调用 `super()`:**
   ```javascript
   class Parent {}
   class Child extends Parent {
     constructor() {
       super();
       super(); // 错误：Super constructor may only be called once
     }
   }
   ```

3. **在不支持 `super` 的地方使用 `super`:**
   ```javascript
   const obj = {
     method() {
       super(); // 错误：'super' keyword unexpected here
     }
   };
   ```

4. **尝试将非构造函数作为父类继承:**
   ```javascript
   const notAConstructor = {};
   class MyClass extends notAConstructor {} // 错误：Class extends value #<Object> is not a constructor or null
   ```

5. **访问静态属性的 `prototype`:**
   ```javascript
   class MyClass {
     static staticMethod() {}
   }
   console.log(MyClass.staticMethod.prototype); // 输出 undefined (但尝试访问可能会触发内部错误)
   ```

总而言之，`v8/src/runtime/runtime-classes.cc` 是 V8 引擎中至关重要的一个文件，它实现了 JavaScript 类语法的核心运行时支持，包括类的创建、继承、`super` 关键字的处理以及相关错误的抛出。理解这个文件的内容有助于更深入地了解 JavaScript 类的底层实现机制。

### 提示词
```
这是目录为v8/src/runtime/runtime-classes.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-classes.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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