Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

**1. Initial Read-Through and Keyword Identification:**

The first step is to quickly read through the code, identifying key terms and concepts. Words that stand out include:

* `handler` (LoadHandler, StoreHandler)
* `ICHandler` (Inline Cache Handler - a central concept in V8's optimization)
* `prototype` (and related terms like `lookup_start_object_map`, `holder`)
* `validity_cell`
* `transition` (related to object shape changes)
* `Smi` (Small Integer - a V8 internal optimization)
* `Map` (V8's representation of object structure/shape)
* `data1`, `data2`, `data3` (slots to store information)
* `access check`
* `keyed access` (accessing properties using bracket notation/indices)
* `global object`, `proxy`, `interceptor`, `accessor`
* `Wasm` (WebAssembly - a separate concern but present here)

**2. Understanding the Core Purpose:**

The file name `handler-configuration.cc` and the repeated use of `LoadHandler` and `StoreHandler` strongly suggest that this code is responsible for *creating and configuring* handlers for property access (both reading and writing) within V8's Inline Cache (IC). The comments mentioning "prototype checks" and "validity cells" reinforce this idea. IC handlers are small pieces of code or data that V8 uses to optimize subsequent accesses to the same property.

**3. Deconstructing Key Functions and Templates:**

* **`SetBitFieldValue`:** This is a utility function for manipulating bits within a `Smi`. This hints that some handler information is encoded efficiently within small integers.

* **`InitPrototypeChecksImpl` and `InitPrototypeChecks`:** These are crucial. They seem to manage how V8 verifies that the prototype chain hasn't changed since the handler was created. The `lookup_start_object_map` and `holder` parameters are key here. The `fill_handler` template parameter suggests two modes: one where a full `ICHandler` object is created, and one where just the size and some bits in a `Smi` are determined.

* **`GetHandlerDataSize`:** This function, called with `fill_handler = false`, calculates how much data (how many slots) a handler needs. This is important for memory allocation.

* **`LoadHandler::LoadFromPrototype` and `LoadHandler::LoadFullChain`:** These are concrete examples of how load handlers are created for prototype chain lookups. They take information about the starting object and the target holder.

* **`LoadHandler::GetKeyedAccessLoadMode`:**  Deals with how array-like or string-like access (e.g., `obj[0]`) is handled.

* **`StoreHandler::GetKeyedAccessStoreMode`:** Similar to the load version but for storing values.

* **`StoreHandler::StoreElementTransition`:** Handles storing to indexed properties and the potential need for an "elements transition" (changing the internal representation of an array).

* **`StoreHandler::StoreOwnTransition` and `StoreHandler::StoreTransition`:** These functions manage changes to the object's own properties, including transitions to dictionary mode (when an object gets too many properties).

* **`StoreHandler::StoreThroughPrototype`:**  Handles storing properties that are found on the prototype chain.

* **`StoreHandler::StoreGlobal` and `StoreHandler::StoreProxy`:** Specific cases for storing to global objects and proxy objects.

* **`LoadHandler::CanHandleHolderNotLookupStart`:** A check to see if a handler is general enough to handle cases where the initial lookup object isn't the actual object the property belongs to.

* **`PrintSmiLoadHandler` and `PrintSmiStoreHandler`:** Debugging and diagnostic functions to print the contents of SMI-based handlers.

**4. Connecting to JavaScript:**

At this stage, start thinking about how these C++ concepts map to JavaScript behavior:

* **Property Access:**  The core function of the handlers is to optimize `object.property` (loads) and `object.property = value` (stores).
* **Prototype Inheritance:** The "prototype checks" directly relate to how JavaScript's prototype chain works. V8 needs to ensure the chain hasn't been modified between accesses.
* **Object Shape/Maps:** The "transitions" are about how V8 internally handles changes in the structure of objects when properties are added or deleted. This is represented by the `Map` object.
* **Arrays and Indexed Access:** The "keyed access" functions are clearly tied to how JavaScript accesses array elements (e.g., `array[index]`).
* **Global Objects:**  The `StoreGlobal` function points to how assignments to global variables are handled.
* **Proxies:** The `StoreProxy` function relates to the JavaScript `Proxy` object.
* **Getters and Setters:**  The mentions of "accessor" and "ApiGetter/Setter" are about JavaScript getter and setter functions.

**5. Crafting the JavaScript Examples:**

Now, use the understanding gained to create concrete JavaScript examples. Focus on demonstrating the concepts identified in the C++ code:

* **Basic Property Access:** Show how simple `.` notation works.
* **Prototype Inheritance:** Demonstrate accessing properties on prototypes.
* **Adding Properties (Transitions):** Show how adding a new property changes an object.
* **Array Access:**  Illustrate the `[]` notation for arrays.
* **Global Variables:**  Demonstrate assigning to a global.
* **Proxies:**  Provide a simple example of using a `Proxy`.
* **Getters and Setters:** Create objects with `get` and `set` definitions.

**6. Refining and Explaining:**

Finally, review the generated JavaScript examples and provide clear explanations of how they relate to the C++ code's functionality. Emphasize the connection between the C++ mechanisms (like handlers, validity cells, and transitions) and the observable JavaScript behavior.

**Self-Correction/Refinement during the process:**

* **Initial Oversimplification:**  At first, you might think of handlers as just simple function pointers. However, noticing the `Smi` usage and the bit manipulation reveals that they are often more compact data structures.
* **Ignoring Details:**  It's easy to get bogged down in the specifics of every bitfield. Focus on the *purpose* of these fields rather than the exact bit layout. For example, understand that `AllowOutOfBoundsBits` is for array access, without needing to memorize its precise bit position.
* **Missing Connections:**  If a C++ function seems isolated, try to think broadly about the JavaScript features it might relate to. For instance, if you see code dealing with "interceptors," think about features like `Object.defineProperty` and how it can intercept property access.

By following this structured approach, combining code reading with conceptual understanding and JavaScript knowledge, you can effectively analyze complex C++ code like this and explain its relevance to higher-level languages.
这个 C++ 文件 `handler-configuration.cc` 的主要功能是**定义和实现了 V8 引擎中用于优化对象属性访问的“处理器”（Handlers）的配置和创建逻辑**。 这些处理器是 V8 的内联缓存（Inline Caches，简称 IC）机制的核心组成部分。

更具体地说，这个文件负责：

1. **定义不同类型的处理器**： 例如 `LoadHandler` 用于属性读取操作，`StoreHandler` 用于属性写入操作。 这些处理器可以是简单的 Smi（Small Integer）编码，也可以是更复杂的对象，包含更多信息。
2. **配置处理器的信息**：  处理器中存储了用于快速执行属性访问的关键信息，例如：
    * **属性的类型和位置**： 例如，属性是否直接存在于对象自身（in-object），还是存储在外部的属性数组中，或者位于原型链上。
    * **原型链的验证信息**： 用于确保在缓存的处理器生效期间，对象的原型链没有发生改变。这通过 `validity_cell` 来实现。
    * **访问检查信息**：  指示是否需要进行访问检查（例如，对于代理对象）。
    * **数据槽（data slots）**： 用于存储额外的上下文信息，例如持有属性的对象、原型对象、转换映射（transition map）等。
3. **创建不同场景下的处理器**： 文件中包含了用于创建各种类型处理器的静态方法，例如：
    * `LoadHandler::LoadFromPrototype`:  当属性位于对象的原型链上时创建读取处理器。
    * `StoreHandler::StoreElementTransition`: 当对数组元素进行写入操作，可能需要进行元素类型转换时创建写入处理器。
    * `StoreHandler::StoreOwnTransition` 和 `StoreHandler::StoreTransition`:  当向对象自身添加或修改属性时创建写入处理器。
    * `StoreHandler::StoreThroughPrototype`: 当属性位于对象的原型链上时创建写入处理器。
4. **管理处理器的元数据**： 例如，`GetKeyedAccessLoadMode` 和 `GetKeyedAccessStoreMode` 用于获取键控访问（例如数组访问）的处理模式。
5. **提供调试和打印功能**：  `PrintHandler` 方法用于打印处理器的信息，方便调试。

**与 JavaScript 的关系以及 JavaScript 示例**

这个文件中的代码直接支持了 JavaScript 中属性的读取和写入操作的性能优化。 当 JavaScript 代码访问一个对象的属性时，V8 引擎会尝试使用内联缓存来加速这个过程。  处理器就是内联缓存中存储的关键信息。

**JavaScript 示例：属性读取**

```javascript
function Person(name) {
  this.name = name;
}

Person.prototype.sayHello = function() {
  console.log("Hello, my name is " + this.name);
};

const person = new Person("Alice");

// 第一次访问 person.name
console.log(person.name); // V8 会创建一个针对 `name` 属性的 LoadHandler

// 后续访问 person.name
console.log(person.name); // V8 会尝试使用之前创建的 LoadHandler 加速访问

// 访问原型链上的方法
person.sayHello(); // V8 会创建一个针对 `sayHello` 属性的 LoadHandler，涉及到原型链查找
```

在这个例子中，当第一次访问 `person.name` 时，V8 会检查内联缓存，如果没有找到合适的处理器，则会执行属性查找，并根据查找结果创建一个 `LoadHandler`。 这个 `LoadHandler` 会记录诸如 `name` 属性位于 `person` 对象的哪个位置等信息。  后续再次访问 `person.name` 时，V8 可以直接使用这个 `LoadHandler`，跳过复杂的属性查找过程，从而提高性能。

同样，访问原型链上的方法 `person.sayHello()` 时，V8 也会创建一个 `LoadHandler`，这个处理器会记录 `sayHello` 方法位于 `Person.prototype` 上。

**JavaScript 示例：属性写入**

```javascript
const obj = {};

// 第一次给 obj 添加属性 a
obj.a = 1; // V8 会创建一个针对属性 `a` 的 StoreHandler，并可能涉及到对象结构的转换 (transition)

// 修改属性 a 的值
obj.a = 2; // V8 可能会使用之前创建的 StoreHandler

// 给 obj 添加新的属性 b
obj.b = 3; // V8 可能会创建一个新的 StoreHandler，并可能再次涉及到对象结构的转换
```

在这个例子中，当给 `obj` 添加属性 `a` 时，V8 会创建一个 `StoreHandler`。 如果后续修改 `a` 的值，V8 可能会重复使用这个处理器。 当添加新的属性 `b` 时，如果对象的内部结构需要改变以容纳新的属性（例如，从“快属性”切换到“慢属性”存储），V8 可能会创建一个新的 `StoreHandler`，并且这个过程可能会涉及到对象 `Map` 的转换（transition）。

**总结**

`handler-configuration.cc` 文件是 V8 引擎中至关重要的组成部分，它定义了用于优化 JavaScript 属性访问的关键数据结构和创建逻辑。  这些处理器通过缓存属性的位置、类型和原型链信息，显著提升了 JavaScript 代码的执行效率。 开发者虽然不能直接操作这些处理器，但理解它们的工作原理有助于理解 V8 的优化机制，从而编写出更高效的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/ic/handler-configuration.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/ic/handler-configuration.h"

#include "src/codegen/code-factory.h"
#include "src/ic/handler-configuration-inl.h"
#include "src/objects/data-handler-inl.h"
#include "src/objects/maybe-object.h"
#include "src/objects/transitions.h"

namespace v8 {
namespace internal {

namespace {

template <typename BitField>
Tagged<Smi> SetBitFieldValue(Isolate* isolate, Tagged<Smi> smi_handler,
                             typename BitField::FieldType value) {
  int config = smi_handler.value();
  config = BitField::update(config, true);
  return Smi::FromInt(config);
}

// TODO(ishell): Remove templatezation once we move common bits from
// Load/StoreHandler to the base class.
template <typename ICHandler, bool fill_handler = true>
int InitPrototypeChecksImpl(Isolate* isolate, Handle<ICHandler> handler,
                            Tagged<Smi>* smi_handler,
                            DirectHandle<Map> lookup_start_object_map,
                            MaybeObjectHandle data1,
                            MaybeObjectHandle maybe_data2) {
  int data_size = 1;
  // Holder-is-receiver case itself does not add entries unless there is an
  // optional data2 value provided.

  DCHECK_IMPLIES(IsJSGlobalObjectMap(*lookup_start_object_map),
                 lookup_start_object_map->is_prototype_map());

  if (IsPrimitiveMap(*lookup_start_object_map) ||
      lookup_start_object_map->is_access_check_needed()) {
    DCHECK(!IsJSGlobalObjectMap(*lookup_start_object_map));
    // The validity cell check for primitive and global proxy receivers does
    // not guarantee that certain native context ever had access to other
    // native context. However, a handler created for one native context could
    // be used in other native context through the megamorphic stub cache.
    // So we record the original native context to which this handler
    // corresponds.
    if (fill_handler) {
      DirectHandle<Context> native_context = isolate->native_context();
      handler->set_data2(MakeWeak(*native_context));
    } else {
      // Enable access checks on the lookup start object.
      *smi_handler = SetBitFieldValue<
          typename ICHandler::DoAccessCheckOnLookupStartObjectBits>(
          isolate, *smi_handler, true);
    }
    data_size++;
  } else if (lookup_start_object_map->is_dictionary_map() &&
             !IsJSGlobalObjectMap(*lookup_start_object_map)) {
    if (!fill_handler) {
      // Enable lookup on lookup start object.
      *smi_handler =
          SetBitFieldValue<typename ICHandler::LookupOnLookupStartObjectBits>(
              isolate, *smi_handler, true);
    }
  }
  if (fill_handler) {
    handler->set_data1(*data1);
  }
  if (!maybe_data2.is_null()) {
    if (fill_handler) {
      // This value will go either to data2 or data3 slot depending on whether
      // data2 slot is already occupied by native context.
      if (data_size == 1) {
        handler->set_data2(*maybe_data2);
      } else {
        DCHECK_EQ(2, data_size);
        handler->set_data3(*maybe_data2);
      }
    }
    data_size++;
  }
  return data_size;
}

// Returns 0 if the validity cell check is enough to ensure that the
// prototype chain from |lookup_start_object_map| till |holder| did not change.
// If the |holder| is an empty handle then the full prototype chain is
// checked.
template <typename ICHandler>
int GetHandlerDataSize(Isolate* isolate, Tagged<Smi>* smi_handler,
                       Handle<Map> lookup_start_object_map,
                       MaybeObjectHandle data1,
                       MaybeObjectHandle maybe_data2 = MaybeObjectHandle()) {
  DCHECK_NOT_NULL(smi_handler);
  return InitPrototypeChecksImpl<ICHandler, false>(
      isolate, Handle<ICHandler>(), smi_handler, lookup_start_object_map, data1,
      maybe_data2);
}

template <typename ICHandler>
void InitPrototypeChecks(Isolate* isolate, Handle<ICHandler> handler,
                         Handle<Map> lookup_start_object_map,
                         MaybeObjectHandle data1,
                         MaybeObjectHandle maybe_data2 = MaybeObjectHandle()) {
  InitPrototypeChecksImpl<ICHandler, true>(
      isolate, handler, nullptr, lookup_start_object_map, data1, maybe_data2);
}

}  // namespace

// static
Handle<Object> LoadHandler::LoadFromPrototype(
    Isolate* isolate, Handle<Map> lookup_start_object_map,
    Handle<JSReceiver> holder, Tagged<Smi> smi_handler,
    MaybeObjectHandle maybe_data1, MaybeObjectHandle maybe_data2) {
  MaybeObjectHandle data1;
  if (maybe_data1.is_null()) {
    data1 = MaybeObjectHandle::Weak(holder);
  } else {
    data1 = maybe_data1;
  }

  int data_size = GetHandlerDataSize<LoadHandler>(
      isolate, &smi_handler, lookup_start_object_map, data1, maybe_data2);

  DirectHandle<UnionOf<Smi, Cell>> validity_cell =
      Map::GetOrCreatePrototypeChainValidityCell(lookup_start_object_map,
                                                 isolate);

  Handle<LoadHandler> handler = isolate->factory()->NewLoadHandler(data_size);

  handler->set_smi_handler(smi_handler);
  handler->set_validity_cell(*validity_cell);
  InitPrototypeChecks(isolate, handler, lookup_start_object_map, data1,
                      maybe_data2);
  return handler;
}

// static
Handle<Object> LoadHandler::LoadFullChain(Isolate* isolate,
                                          Handle<Map> lookup_start_object_map,
                                          const MaybeObjectHandle& holder,
                                          Handle<Smi> smi_handler_handle) {
  Tagged<Smi> smi_handler = *smi_handler_handle;
  MaybeObjectHandle data1 = holder;
  int data_size = GetHandlerDataSize<LoadHandler>(
      isolate, &smi_handler, lookup_start_object_map, data1);

  DirectHandle<UnionOf<Smi, Cell>> validity_cell =
      Map::GetOrCreatePrototypeChainValidityCell(lookup_start_object_map,
                                                 isolate);
  if (IsSmi(*validity_cell)) {
    DCHECK_EQ(1, data_size);
    // Lookup on lookup start object isn't supported in case of a simple smi
    // handler.
    if (!LookupOnLookupStartObjectBits::decode(smi_handler.value())) {
      return smi_handler_handle;
    }
  }

  Handle<LoadHandler> handler = isolate->factory()->NewLoadHandler(data_size);

  handler->set_smi_handler(smi_handler);
  handler->set_validity_cell(*validity_cell);
  InitPrototypeChecks(isolate, handler, lookup_start_object_map, data1);
  return handler;
}

// static
KeyedAccessLoadMode LoadHandler::GetKeyedAccessLoadMode(
    Tagged<MaybeObject> handler) {
  DisallowGarbageCollection no_gc;
  if (IsSmi(handler)) {
    int const raw_handler = handler.ToSmi().value();
    Kind const kind = KindBits::decode(raw_handler);
    if (kind == Kind::kElement || kind == Kind::kIndexedString) {
      bool handle_oob = AllowOutOfBoundsBits::decode(raw_handler);
      bool handle_holes = AllowHandlingHole::decode(raw_handler);
      return CreateKeyedAccessLoadMode(handle_oob, handle_holes);
    }
  }
  return KeyedAccessLoadMode::kInBounds;
}

// static
KeyedAccessStoreMode StoreHandler::GetKeyedAccessStoreMode(
    Tagged<MaybeObject> handler) {
  DisallowGarbageCollection no_gc;
  if (IsSmi(handler)) {
    int const raw_handler = handler.ToSmi().value();
    Kind const kind = KindBits::decode(raw_handler);
    // All the handlers except the Slow Handler that use tshe
    // KeyedAccessStoreMode, compute it using KeyedAccessStoreModeForBuiltin
    // method. Hence if any other Handler get to this path, just return
    // KeyedAccessStoreMode::kInBounds.
    if (kind != Kind::kSlow) {
      return KeyedAccessStoreMode::kInBounds;
    }
    KeyedAccessStoreMode store_mode =
        KeyedAccessStoreModeBits::decode(raw_handler);
    return store_mode;
  }
  return KeyedAccessStoreMode::kInBounds;
}

// static
Handle<Object> StoreHandler::StoreElementTransition(
    Isolate* isolate, DirectHandle<Map> receiver_map,
    DirectHandle<Map> transition, KeyedAccessStoreMode store_mode,
    MaybeHandle<UnionOf<Smi, Cell>> prev_validity_cell) {
  DirectHandle<Code> code =
      ElementsTransitionAndStoreBuiltin(isolate, store_mode);
  Handle<UnionOf<Smi, Cell>> validity_cell;
  if (!prev_validity_cell.ToHandle(&validity_cell)) {
    validity_cell =
        Map::GetOrCreatePrototypeChainValidityCell(receiver_map, isolate);
  }
  Handle<StoreHandler> handler = isolate->factory()->NewStoreHandler(1);
  handler->set_smi_handler(*code);
  handler->set_validity_cell(*validity_cell);
  handler->set_data1(MakeWeak(*transition));
  return handler;
}

// static
MaybeObjectHandle StoreHandler::StoreOwnTransition(Isolate* isolate,
                                                   Handle<Map> transition_map) {
  bool is_dictionary_map = transition_map->is_dictionary_map();
#ifdef DEBUG
  if (!is_dictionary_map) {
    InternalIndex descriptor = transition_map->LastAdded();
    DirectHandle<DescriptorArray> descriptors(
        transition_map->instance_descriptors(isolate), isolate);
    PropertyDetails details = descriptors->GetDetails(descriptor);
    if (descriptors->GetKey(descriptor)->IsPrivate()) {
      DCHECK_EQ(DONT_ENUM, details.attributes());
    } else {
      DCHECK_EQ(NONE, details.attributes());
    }
    Representation representation = details.representation();
    DCHECK(!representation.IsNone());
  }
#endif
  // Declarative handlers don't support access checks.
  DCHECK(!transition_map->is_access_check_needed());

  // StoreOwnTransition does not involve any prototype checks.
  if (is_dictionary_map) {
    DCHECK(!IsJSGlobalObjectMap(*transition_map));
    int config = KindBits::encode(Kind::kNormal);
    return MaybeObjectHandle(Tagged<Object>(Smi::FromInt(config)), isolate);

  } else {
    return MaybeObjectHandle::Weak(transition_map);
  }
}

// static
MaybeObjectHandle StoreHandler::StoreTransition(Isolate* isolate,
                                                Handle<Map> transition_map) {
  bool is_dictionary_map = transition_map->is_dictionary_map();
#ifdef DEBUG
  if (!is_dictionary_map) {
    InternalIndex descriptor = transition_map->LastAdded();
    DirectHandle<DescriptorArray> descriptors(
        transition_map->instance_descriptors(isolate), isolate);
    // Private fields must be added via StoreOwnTransition handler.
    DCHECK(!descriptors->GetKey(descriptor)->IsPrivateName());
    PropertyDetails details = descriptors->GetDetails(descriptor);
    if (descriptors->GetKey(descriptor)->IsPrivate()) {
      DCHECK_EQ(DONT_ENUM, details.attributes());
    } else {
      DCHECK_EQ(NONE, details.attributes());
    }
    Representation representation = details.representation();
    DCHECK(!representation.IsNone());
  }
#endif
  // Declarative handlers don't support access checks.
  DCHECK(!transition_map->is_access_check_needed());

  // Get validity cell value if it is necessary for the handler.
  Handle<UnionOf<Smi, Cell>> validity_cell;
  if (is_dictionary_map || !transition_map->IsPrototypeValidityCellValid()) {
    validity_cell =
        Map::GetOrCreatePrototypeChainValidityCell(transition_map, isolate);
  }

  if (is_dictionary_map) {
    DCHECK(!IsJSGlobalObjectMap(*transition_map));
    Handle<StoreHandler> handler = isolate->factory()->NewStoreHandler(0);
    // Store normal with enabled lookup on receiver.
    int config = KindBits::encode(Kind::kNormal) |
                 LookupOnLookupStartObjectBits::encode(true);
    handler->set_smi_handler(Smi::FromInt(config));
    handler->set_validity_cell(*validity_cell);
    return MaybeObjectHandle(handler);

  } else {
    // Ensure the transition map contains a valid prototype validity cell.
    if (!validity_cell.is_null()) {
      transition_map->set_prototype_validity_cell(*validity_cell,
                                                  kRelaxedStore);
    }
    return MaybeObjectHandle::Weak(transition_map);
  }
}

// static
Handle<Object> StoreHandler::StoreThroughPrototype(
    Isolate* isolate, Handle<Map> receiver_map, Handle<JSReceiver> holder,
    Tagged<Smi> smi_handler, MaybeObjectHandle maybe_data1,
    MaybeObjectHandle maybe_data2) {
  MaybeObjectHandle data1;
  if (maybe_data1.is_null()) {
    data1 = MaybeObjectHandle::Weak(holder);
  } else {
    data1 = maybe_data1;
  }

  int data_size = GetHandlerDataSize<StoreHandler>(
      isolate, &smi_handler, receiver_map, data1, maybe_data2);

  DirectHandle<UnionOf<Smi, Cell>> validity_cell =
      Map::GetOrCreatePrototypeChainValidityCell(receiver_map, isolate);

  Handle<StoreHandler> handler = isolate->factory()->NewStoreHandler(data_size);

  handler->set_smi_handler(smi_handler);
  handler->set_validity_cell(*validity_cell);
  InitPrototypeChecks(isolate, handler, receiver_map, data1, maybe_data2);
  return handler;
}

// static
MaybeObjectHandle StoreHandler::StoreGlobal(Handle<PropertyCell> cell) {
  return MaybeObjectHandle::Weak(cell);
}

// static
Handle<Object> StoreHandler::StoreProxy(Isolate* isolate,
                                        Handle<Map> receiver_map,
                                        Handle<JSProxy> proxy,
                                        Handle<JSReceiver> receiver) {
  Handle<Smi> smi_handler = StoreProxy(isolate);
  if (receiver.is_identical_to(proxy)) return smi_handler;
  return StoreThroughPrototype(isolate, receiver_map, proxy, *smi_handler,
                               MaybeObjectHandle::Weak(proxy));
}

bool LoadHandler::CanHandleHolderNotLookupStart(Tagged<Object> handler) {
  if (IsSmi(handler)) {
    auto kind = LoadHandler::KindBits::decode(handler.ToSmi().value());
    return kind == LoadHandler::Kind::kSlow ||
           kind == LoadHandler::Kind::kNonExistent;
  }
  return IsLoadHandler(handler);
}

#if defined(OBJECT_PRINT)
namespace {
void PrintSmiLoadHandler(int raw_handler, std::ostream& os) {
  LoadHandler::Kind kind = LoadHandler::KindBits::decode(raw_handler);
  os << "kind = ";
  switch (kind) {
    case LoadHandler::Kind::kElement:
      os << "kElement, ";
      if (LoadHandler::IsWasmArrayBits::decode(raw_handler)) {
        os << "WasmArray, "
           << LoadHandler::WasmArrayTypeBits::decode(raw_handler);

      } else {
        os << "allow out of bounds = "
           << LoadHandler::AllowOutOfBoundsBits::decode(raw_handler)
           << ", is JSArray = "
           << LoadHandler::IsJsArrayBits::decode(raw_handler)
           << ", alow reading holes = "
           << LoadHandler::AllowHandlingHole::decode(raw_handler)
           << ", elements kind = "
           << ElementsKindToString(
                  LoadHandler::ElementsKindBits::decode(raw_handler));
      }
      break;
    case LoadHandler::Kind::kIndexedString:
      os << "kIndexedString, allow out of bounds = "
         << LoadHandler::AllowOutOfBoundsBits::decode(raw_handler);
      break;
    case LoadHandler::Kind::kNormal:
      os << "kNormal";
      break;
    case LoadHandler::Kind::kGlobal:
      os << "kGlobal";
      break;
    case LoadHandler::Kind::kField: {
      if (LoadHandler::IsWasmStructBits::decode(raw_handler)) {
        os << "kField, WasmStruct, type = "
           << LoadHandler::WasmFieldTypeBits::decode(raw_handler)
           << ", field offset = "
           << LoadHandler::WasmFieldOffsetBits::decode(raw_handler);
      } else {
        os << "kField, is in object = "
           << LoadHandler::IsInobjectBits::decode(raw_handler)
           << ", is double = " << LoadHandler::IsDoubleBits::decode(raw_handler)
           << ", field index = "
           << LoadHandler::FieldIndexBits::decode(raw_handler);
      }
      break;
    }
    case LoadHandler::Kind::kConstantFromPrototype:
      os << "kConstantFromPrototype";
      break;
    case LoadHandler::Kind::kAccessorFromPrototype:
      os << "kAccessorFromPrototype";
      break;
    case LoadHandler::Kind::kNativeDataProperty:
      os << "kNativeDataProperty, descriptor = "
         << LoadHandler::DescriptorBits::decode(raw_handler);
      break;
    case LoadHandler::Kind::kApiGetter:
      os << "kApiGetter";
      break;
    case LoadHandler::Kind::kApiGetterHolderIsPrototype:
      os << "kApiGetterHolderIsPrototype";
      break;
    case LoadHandler::Kind::kInterceptor:
      os << "kInterceptor";
      break;
    case LoadHandler::Kind::kSlow:
      os << "kSlow";
      break;
    case LoadHandler::Kind::kProxy:
      os << "kProxy";
      break;
    case LoadHandler::Kind::kNonExistent:
      os << "kNonExistent";
      break;
    case LoadHandler::Kind::kModuleExport:
      os << "kModuleExport, exports index = "
         << LoadHandler::ExportsIndexBits::decode(raw_handler);
      break;
    default:
      os << "<invalid value " << static_cast<int>(kind) << ">";
      break;
  }
}

void PrintSmiStoreHandler(int raw_handler, std::ostream& os) {
  StoreHandler::Kind kind = StoreHandler::KindBits::decode(raw_handler);
  os << "kind = ";
  switch (kind) {
    case StoreHandler::Kind::kField:
    case StoreHandler::Kind::kConstField: {
      os << "k";
      if (kind == StoreHandler::Kind::kConstField) {
        os << "Const";
      }
      Representation representation = Representation::FromKind(
          StoreHandler::RepresentationBits::decode(raw_handler));
      os << "Field, descriptor = "
         << StoreHandler::DescriptorBits::decode(raw_handler)
         << ", is in object = "
         << StoreHandler::IsInobjectBits::decode(raw_handler)
         << ", representation = " << representation.Mnemonic()
         << ", field index = "
         << StoreHandler::FieldIndexBits::decode(raw_handler);
      break;
    }
    case StoreHandler::Kind::kAccessorFromPrototype:
      os << "kAccessorFromPrototype";
      break;
    case StoreHandler::Kind::kNativeDataProperty:
      os << "kNativeDataProperty, descriptor = "
         << StoreHandler::DescriptorBits::decode(raw_handler);
      break;
    case StoreHandler::Kind::kApiSetter:
      os << "kApiSetter";
      break;
    case StoreHandler::Kind::kApiSetterHolderIsPrototype:
      os << "kApiSetterHolderIsPrototype";
      break;
    case StoreHandler::Kind::kGlobalProxy:
      os << "kGlobalProxy";
      break;
    case StoreHandler::Kind::kNormal:
      os << "kNormal";
      break;
    case StoreHandler::Kind::kInterceptor:
      os << "kInterceptor";
      break;
    case StoreHandler::Kind::kSlow: {
      KeyedAccessStoreMode keyed_access_store_mode =
          StoreHandler::KeyedAccessStoreModeBits::decode(raw_handler);
      os << "kSlow, keyed access store mode = " << keyed_access_store_mode;
      break;
    }
    case StoreHandler::Kind::kProxy:
      os << "kProxy";
      break;
    case StoreHandler::Kind::kSharedStructField:
      os << "kSharedStructField";
      break;
    case StoreHandler::Kind::kKindsNumber:
      UNREACHABLE();
  }
}

}  // namespace

// static
void LoadHandler::PrintHandler(Tagged<Object> handler, std::ostream& os) {
  DisallowGarbageCollection no_gc;
  if (IsSmi(handler)) {
    int raw_handler = handler.ToSmi().value();
    os << "LoadHandler(Smi)(";
    PrintSmiLoadHandler(raw_handler, os);
    os << ")";
  } else if (IsCode(handler)) {
    os << "LoadHandler(Code)("
       << Builtins::name(Cast<Code>(handler)->builtin_id()) << ")";
  } else if (IsSymbol(handler)) {
    os << "LoadHandler(Symbol)(" << Brief(Cast<Symbol>(handler)) << ")";
  } else if (IsLoadHandler(handler)) {
    Tagged<LoadHandler> load_handler = Cast<LoadHandler>(handler);
    int raw_handler = Cast<Smi>(load_handler->smi_handler()).value();
    os << "LoadHandler(do access check on lookup start object = "
       << DoAccessCheckOnLookupStartObjectBits::decode(raw_handler)
       << ", lookup on lookup start object = "
       << LookupOnLookupStartObjectBits::decode(raw_handler) << ", ";
    PrintSmiLoadHandler(raw_handler, os);
    if (load_handler->data_field_count() >= 1) {
      os << ", data1 = ";
      ShortPrint(load_handler->data1(), os);
    }
    if (load_handler->data_field_count() >= 2) {
      os << ", data2 = ";
      ShortPrint(load_handler->data2(), os);
    }
    if (load_handler->data_field_count() >= 3) {
      os << ", data3 = ";
      ShortPrint(load_handler->data3(), os);
    }
    os << ", validity cell = ";
    ShortPrint(load_handler->validity_cell(), os);
    os << ")";
  } else {
    os << "LoadHandler(<unexpected>)(" << Brief(handler) << ")";
  }
}

void StoreHandler::PrintHandler(Tagged<Object> handler, std::ostream& os) {
  DisallowGarbageCollection no_gc;
  if (IsSmi(handler)) {
    int raw_handler = handler.ToSmi().value();
    os << "StoreHandler(Smi)(";
    PrintSmiStoreHandler(raw_handler, os);
    os << ")" << std::endl;
  } else if (IsStoreHandler(handler)) {
    os << "StoreHandler(";
    Tagged<StoreHandler> store_handler = Cast<StoreHandler>(handler);
    if (IsCode(store_handler->smi_handler())) {
      Tagged<Code> code = Cast<Code>(store_handler->smi_handler());
      os << "builtin = ";
      ShortPrint(code, os);
    } else {
      int raw_handler = Cast<Smi>(store_handler->smi_handler()).value();
      os << "do access check on lookup start object = "
         << DoAccessCheckOnLookupStartObjectBits::decode(raw_handler)
         << ", lookup on lookup start object = "
         << LookupOnLookupStartObjectBits::decode(raw_handler) << ", ";
      PrintSmiStoreHandler(raw_handler, os);
    }
    if (store_handler->data_field_count() >= 1) {
      os << ", data1 = ";
      ShortPrint(store_handler->data1(), os);
    }
    if (store_handler->data_field_count() >= 2) {
      os << ", data2 = ";
      ShortPrint(store_handler->data2(), os);
    }
    if (store_handler->data_field_count() >= 3) {
      os << ", data3 = ";
      ShortPrint(store_handler->data3(), os);
    }
    os << ", validity cell = ";
    ShortPrint(store_handler->validity_cell(), os);
    os << ")" << std::endl;
  } else if (IsMap(handler)) {
    os << "StoreHandler(field transition to " << Brief(handler) << ")"
       << std::endl;
  } else if (IsCode(handler)) {
    Tagged<Code> code = Cast<Code>(handler);
    os << "StoreHandler(builtin = ";
    ShortPrint(code, os);
    os << ")" << std::endl;
  } else {
    os << "StoreHandler(<unexpected>)(" << Brief(handler) << ")" << std::endl;
  }
}

std::ostream& operator<<(std::ostream& os, WasmValueType type) {
  return os << WasmValueType2String(type);
}

#endif  // defined(OBJECT_PRINT)

}  // namespace internal
}  // namespace v8
```