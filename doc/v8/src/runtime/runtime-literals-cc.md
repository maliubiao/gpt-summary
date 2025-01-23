Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Understand the Request:** The core request is to understand the functionality of `runtime-literals.cc`. The prompt provides useful hints: check for `.tq`, its relationship with JavaScript, look for logic, and identify common programming errors.

2. **Initial Scan - File Name and Location:** The file is in `v8/src/runtime`. "runtime" strongly suggests this code is executed *during* the execution of JavaScript code, not during compilation. The "literals" part hints that it deals with the creation of literal values in JavaScript (objects, arrays, regular expressions).

3. **Check for `.tq`:** The prompt explicitly asks about `.tq`. A quick scan of the provided code reveals no `.tq` extension or any Torque-specific syntax. This immediately tells us it's standard C++ runtime code.

4. **Identify Core Functionality - Function Names and Keywords:**  Look for function names, especially those starting with `Runtime_`. These are V8's internal runtime functions callable from JavaScript (or the compiler). The names are very descriptive:
    * `Runtime_CreateObjectLiteral`
    * `Runtime_CreateArrayLiteral`
    * `Runtime_CreateRegExpLiteral`

   These names strongly suggest the file's primary function: handling the creation of object, array, and regular expression literals.

5. **Analyze Key Data Structures:** Look for data structures and classes used in the code:
    * `ObjectBoilerplateDescription`, `ArrayBoilerplateDescription`, `RegExpBoilerplateDescription`: These clearly hold pre-computed information about the structure and initial values of literals. The term "boilerplate" is significant, implying optimization through pre-computation.
    * `AllocationSite`: This class plays a central role. The code mentions "mementos" and "transitions," which suggests it's related to object allocation tracking and optimization, likely for inline caching or hidden class transitions.
    * `FeedbackVector`, `FeedbackSlot`: These are used in conjunction with `AllocationSite`. Feedback vectors store information about the execution of JavaScript code, used for optimizations. The slots within the vector likely hold the `AllocationSite` information.

6. **Trace the Logic of `CreateObjectLiteral` and `CreateArrayLiteral`:**  These functions are central. Focus on the steps involved:
    * **Check for Existing Boilerplate:** The code checks if an `AllocationSite` already exists for the literal. This is a key optimization – if a literal has been created before with the same structure, the existing "boilerplate" can be reused or copied.
    * **Boilerplate Creation (if needed):** If no boilerplate exists, it's created based on the `...BoilerplateDescription`. This involves creating the initial object/array with its properties and values.
    * **Allocation Sites:**  `AllocationSiteCreationContext` is used when a new boilerplate is created. This links the boilerplate to the location in the code where the literal is created.
    * **Deep Copying:** The `DeepCopy` function is crucial. It ensures that when a boilerplate is reused, a *copy* is made so modifications to one literal don't affect others. The copying process also handles nested objects and arrays, potentially creating new `AllocationSite`s for them.
    * **`DeepWalk`:** This function seems to traverse the object graph, possibly for deprecation updates or initial `AllocationSite` setup.

7. **Trace the Logic of `CreateRegExpLiteral`:** This function is a bit simpler initially. It checks for an existing boilerplate and if not, creates a `JSRegExp` instance directly. It also handles the two-step initialization of `RegExp` literal sites.

8. **Relate to JavaScript:**  Think about how these runtime functions connect to JavaScript code. When the JavaScript engine encounters an object literal (`{}`), an array literal (`[]`), or a regular expression literal (`/.../`), it calls these runtime functions. Provide simple JavaScript examples.

9. **Identify Potential Programming Errors:** Consider how the optimizations and mechanisms in this code could be affected by common user errors. Focus on things like:
    * Modifying objects after they are created as literals (which could trigger deoptimizations).
    * Creating very large or deeply nested literals (which could cause performance issues or stack overflows).
    * Issues related to `__proto__` and `null` prototypes.

10. **Structure the Answer:** Organize the findings logically:
    * **Purpose:** Start with a high-level summary.
    * **Torque:** Address the `.tq` question.
    * **JavaScript Relationship:** Explain how it connects to JavaScript and provide examples.
    * **Code Logic:** Describe the key functions and their behavior, focusing on `CreateObjectLiteral`, `CreateArrayLiteral`, and `CreateRegExpLiteral`. Include details about boilerplates, allocation sites, and deep copying. Provide hypothetical input/output scenarios.
    * **Common Errors:**  Give practical examples of how user code can interact (or cause problems) with these mechanisms.

11. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Check if all parts of the original prompt have been addressed. Make sure the JavaScript examples are clear and relevant.

This systematic approach, starting with the big picture and gradually diving into details, is crucial for understanding complex code like this. Paying attention to naming conventions, data structures, and the overall flow of execution is key.
`v8/src/runtime/runtime-literals.cc` 是 V8 引擎的源代码文件，负责实现 **创建 JavaScript 字面量** 的运行时功能。

**功能列表:**

1. **创建对象字面量 (`Runtime_CreateObjectLiteral`)**:  当 JavaScript 代码执行到对象字面量 (e.g., `{a: 1, b: 2}`) 时，这个运行时函数会被调用来创建相应的 `JSObject`。
2. **创建数组字面量 (`Runtime_CreateArrayLiteral`)**:  当 JavaScript 代码执行到数组字面量 (e.g., `[1, 2, 3]`) 时，这个运行时函数会被调用来创建相应的 `JSArray`。
3. **创建正则表达式字面量 (`Runtime_CreateRegExpLiteral`)**: 当 JavaScript 代码执行到正则表达式字面量 (e.g., `/abc/g`) 时，这个运行时函数会被调用来创建相应的 `JSRegExp` 对象。
4. **处理字面量的 "样板" (Boilerplate)**: 为了优化性能，V8 会为具有相同结构（相同的属性名和顺序）的字面量创建 "样板"。这些样板可以被复用，避免每次都从头创建对象。`runtime-literals.cc` 负责管理和创建这些样板。
5. **处理分配站点 (Allocation Sites)**:  分配站点是 V8 用来跟踪对象分配信息的机制，用于优化对象的创建和访问。`runtime-literals.cc` 中的代码涉及到分配站点的创建、关联和使用，特别是与字面量相关的分配站点。
6. **深度遍历和拷贝对象 (`DeepWalk`, `DeepCopy`)**:  在创建字面量时，如果字面量中包含嵌套的对象或数组，V8 需要深度遍历这些结构，并根据需要进行拷贝，以确保每个字面量实例是独立的。
7. **处理原型为 `null` 的对象字面量**:  对于像 `Object.create(null)` 或 `{ __proto__: null }` 这样的对象字面量，V8 需要特殊处理，因为它们没有继承自 `Object.prototype`。
8. **支持常量属性**:  对于在字面量中定义的常量属性，V8 会将其存储在样板中，以便快速访问。

**是否为 Torque 源代码:**

根据您提供的代码片段，`v8/src/runtime/runtime-literals.cc` **不是**以 `.tq` 结尾，因此它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。 Torque 文件通常用于定义 V8 的内置函数和操作。

**与 JavaScript 功能的关系和示例:**

`v8/src/runtime/runtime-literals.cc` 直接关联到 JavaScript 中创建字面量的语法。

**对象字面量:**

```javascript
const obj1 = { a: 1, b: 'hello' };
const obj2 = { a: 1, b: 'hello' }; // 结构与 obj1 相同，可能复用样板

const obj3 = { b: 'hello', a: 1 }; // 结构不同于 obj1，不会复用样板

const obj4 = { c: { d: 2 } }; // 包含嵌套对象

const obj5 = Object.create(null); // 原型为 null
const obj6 = { __proto__: null }; // 原型为 null
```

当执行这些 JavaScript 代码时，`Runtime_CreateObjectLiteral` 函数会被调用。V8 会检查是否已存在与该对象结构匹配的样板。如果存在，则可能直接从样板创建对象，提高效率。如果不存在，则会创建一个新的样板。

**数组字面量:**

```javascript
const arr1 = [1, 2, 'world'];
const arr2 = [1, 2, 'world']; // 内容相同，可能复用样板

const arr3 = [3, 4, 'test']; // 内容不同，不会复用样板

const arr4 = [ { a: 1 }, [2, 3] ]; // 包含嵌套对象和数组
```

当执行这些 JavaScript 代码时，`Runtime_CreateArrayLiteral` 函数会被调用。与对象字面量类似，V8 会尝试复用现有的数组样板。

**正则表达式字面量:**

```javascript
const regex1 = /abc/g;
const regex2 = /abc/g; // 相同的模式和标志

const regex3 = /def/i; // 不同的模式和标志
```

当执行这些 JavaScript 代码时，`Runtime_CreateRegExpLiteral` 函数会被调用。V8 会为具有相同模式和标志的正则表达式创建样板。

**代码逻辑推理 (假设输入与输出):**

假设 JavaScript 代码执行以下语句：

```javascript
function createLiteral() {
  return { x: 10, y: 'test' };
}

const objA = createLiteral();
const objB = createLiteral();
```

**假设输入到 `Runtime_CreateObjectLiteral`:**

* **第一次调用 (创建 `objA`):**
    * `maybe_vector`:  可能是一个用于存储反馈信息的向量，初始可能为空或未定义。
    * `literals_index`:  指示此字面量在反馈向量中的索引。
    * `description`:  包含对象字面量结构信息，例如属性名 `x` 和 `y`，以及它们的类型。
    * `flags`:  标志位，可能指示是否需要快速属性等。
* **第二次调用 (创建 `objB`):**
    * `maybe_vector`:  可能与第一次调用相同。
    * `literals_index`:  与第一次调用不同。
    * `description`:  与第一次调用相同，因为对象结构一样。
    * `flags`:  与第一次调用相同。

**可能的输出:**

* **第一次调用:**  创建一个新的 `JSObject`，并可能创建一个新的对象样板，并将该样板与 `maybe_vector` 中的 `literals_index` 关联起来。返回新创建的 `JSObject` 的句柄。
* **第二次调用:**  V8 检测到存在与当前字面量结构相同的样板（在第一次调用时创建的）。它会复用这个样板，创建一个新的 `JSObject` 实例，其结构和属性值与样板一致。返回新创建的 `JSObject` 的句柄。

**涉及用户常见的编程错误:**

1. **在循环中创建大量结构相同的字面量:**

   ```javascript
   const objects = [];
   for (let i = 0; i < 10000; i++) {
     objects.push({ a: i, b: 'constant' });
   }
   ```

   **说明:** V8 会尝试为这些结构相同的对象创建和复用样板，这通常是高效的。然而，如果对象数量非常巨大，可能会占用较多内存来存储这些样板。

2. **创建具有不同属性顺序的字面量:**

   ```javascript
   const obj1 = { a: 1, b: 2 };
   const obj2 = { b: 2, a: 1 };
   ```

   **说明:** 即使属性名相同，但顺序不同，V8 也会认为它们的结构不同，不会复用样板。这可能导致创建更多的样板，占用更多内存。

3. **意外地修改了字面量对象的结构 (添加或删除属性):**

   ```javascript
   const obj = { x: 1 };
   // ... 某些操作后 ...
   obj.y = 2; // 动态添加属性
   ```

   **说明:**  最初使用字面量创建的对象可能使用了样板。但如果在运行时动态地修改了对象的结构，V8 可能需要取消优化，并更改对象的内部表示，这可能会影响性能。

4. **创建包含可变对象的字面量:**

   ```javascript
   const shared = { value: 0 };
   const obj1 = { ref: shared };
   const obj2 = { ref: shared };

   obj1.ref.value = 1; // 修改了共享对象
   console.log(obj2.ref.value); // 输出 1
   ```

   **说明:**  虽然 `obj1` 和 `obj2` 是通过结构相同的字面量创建的，但它们引用的 `shared` 对象是同一个。修改其中一个对象的属性会影响另一个对象。这并非编程错误，但需要理解对象引用的行为。

5. **过度依赖原型为 `null` 的对象字面量，并进行大量属性访问:**

   ```javascript
   const map = Object.create(null);
   map.key1 = 'value1';
   map.key2 = 'value2';
   // ... 大量属性访问 ...
   ```

   **说明:**  虽然原型为 `null` 的对象在某些场景下很有用 (例如，创建纯粹的键值对存储)，但由于它们没有继承自 `Object.prototype`，某些优化可能无法应用，属性访问可能稍慢。

理解 `v8/src/runtime/runtime-literals.cc` 的功能有助于开发者更好地理解 JavaScript 字面量的创建过程以及 V8 如何优化这些操作，从而编写更高效的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/runtime/runtime-literals.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-literals.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```