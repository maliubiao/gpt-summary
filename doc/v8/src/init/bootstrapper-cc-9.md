Response:
The user wants a summary of the provided C++ code snippet from `v8/src/init/bootstrapper.cc`. The request includes several specific points:

1. **Functionality:** What does this code do?
2. **Torque Source:** Does it look like Torque code (ends with `.tq`)?
3. **JavaScript Relation:** If related to JavaScript, provide a JavaScript example.
4. **Code Logic Inference:** Provide input/output examples for code logic.
5. **Common Programming Errors:**  Illustrate common mistakes related to this code.
6. **Overall Functionality (Summary):** A concise summary of its purpose within V8.
7. **Part of a Series:**  Acknowledge that this is part 10 of 11.

Let's break down the code and address each point.

**Code Analysis:**

The code primarily focuses on creating and initializing specific JavaScript objects and their maps (internal data structures that define object properties and layout). Here's a breakdown of the key sections:

* **`data_property_descriptor_map`:**  It creates a map for `JSDataPropertyDescriptor` objects, defining properties like `writable`, `enumerable`, and `configurable`.
* **`js_array_template_literal_object_map`:** It creates a map and sets up a `TemplateLiteral` object. This involves creating a `raw` property and private symbol fields (`function_literal_id` and `slot_id`). It also freezes the template object.
* **`regexp_result_map` and `regexp_result_with_indices_map`:** It sets up maps for `JSRegExpResult` objects (results of regular expression matches). It predefines properties like `index`, `input`, and `groups`. It also handles the case with the `/d` flag, adding an `indices` property.
* **`regexp_result_indices_map`:** It creates a map for `JSRegExpResultIndices` objects, specifically focusing on the `groups` property.
* **Adding `@@iterator` to arguments objects:** It adds the `@@iterator` symbol as an accessor to different types of arguments objects (`sloppy_arguments_map`, `fast_aliased_arguments_map`, etc.).
* **`atomics_waitasync_promises`:** Initializes an empty `OrderedHashSet` for promises related to `Atomics.waitAsync`.

**Addressing the Request Points:**

1. **Functionality:** The code initializes internal V8 object maps and specific objects crucial for JavaScript functionality like data property descriptors, template literals, and regular expression results.

2. **Torque Source:** The code is C++, not Torque. The prompt itself suggests this by saying "if v8/src/init/bootstrapper.cc以.tq结尾".

3. **JavaScript Relation:**  This code directly impacts how these JavaScript features work.

4. **Code Logic Inference:**  The logic is primarily about setting up internal object structures. It's not really about taking external input and producing different outputs in a user-facing way. However, we can think of it like this:

   * **Input (Internal):**  The internal state of the V8 engine during initialization.
   * **Output (Internal):** The created and configured object maps and objects (e.g., the `data_property_descriptor_map`, the `js_array_template_literal_object_map`).

5. **Common Programming Errors:**  Since this is internal V8 code, common *user* programming errors aren't directly related. However, misunderstandings about these underlying mechanisms can lead to issues:

   * **Incorrectly assuming properties are always enumerable/writable/configurable:**  The code explicitly sets these attributes. Users might expect default behavior without realizing the underlying setup.
   * **Being surprised by the structure of RegExp results:**  The predefined properties (`index`, `input`, `groups`) are established here. Users might not be aware of these specific properties.
   * **Not understanding the `raw` property of template literals:** This code sets up that specific structure, which is a key part of how template literals function.

6. **Overall Functionality (Summary):** This code snippet is responsible for the foundational initialization of several core JavaScript language features within the V8 engine, including property descriptors, template literals, and regular expression results. It creates the internal object layouts and properties necessary for these features to function correctly.

7. **Part of a Series:**  Acknowledged.

Let's construct the answer incorporating these points.
```cpp
ppendDescriptor(isolate(), &d);
    }
    {  // writable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->writable_string(),
                                JSDataPropertyDescriptor::kWritableIndex, NONE,
                                Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // enumerable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->enumerable_string(),
                                JSDataPropertyDescriptor::kEnumerableIndex,
                                NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // configurable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->configurable_string(),
                                JSDataPropertyDescriptor::kConfigurableIndex,
                                NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }

    Map::SetPrototype(isolate(), map, isolate()->initial_object_prototype());
    map->SetConstructor(native_context()->object_function());

    native_context()->set_data_property_descriptor_map(*map);
  }

  {
    // -- TemplateLiteral JSArray Map
    DirectHandle<JSFunction> array_function(native_context()->array_function(),
                                            isolate());
    Handle<Map> template_map(array_function->initial_map(), isolate_);
    template_map = Map::CopyAsElementsKind(isolate_, template_map,
                                           PACKED_ELEMENTS, OMIT_TRANSITION);
    DCHECK_GE(TemplateLiteralObject::kHeaderSize,
              template_map->instance_size());
    template_map->set_instance_size(TemplateLiteralObject::kHeaderSize);
    // Temporarily instantiate a full template_literal_object to get the final
    // map.
    auto template_object =
        Cast<JSArray>(factory()->NewJSObjectFromMap(template_map));
    {
      DisallowGarbageCollection no_gc;
      Tagged<JSArray> raw = *template_object;
      raw->set_elements(ReadOnlyRoots(isolate()).empty_fixed_array());
      raw->set_length(Smi::FromInt(0));
    }

    // Install a "raw" data property for {raw_object} on {template_object}.
    // See ES#sec-gettemplateobject.
    PropertyDescriptor raw_desc;
    // Use arbrirary object {template_object} as ".raw" value.
    raw_desc.set_value(template_object);
    raw_desc.set_configurable(false);
    raw_desc.set_enumerable(false);
    raw_desc.set_writable(false);
    JSArray::DefineOwnProperty(isolate(), template_object,
                               factory()->raw_string(), &raw_desc,
                               Just(kThrowOnError))
        .ToChecked();
    // Install private symbol fields for function_literal_id and slot_id.
    raw_desc.set_value(handle(Smi::zero(), isolate()));
    JSArray::DefineOwnProperty(
        isolate(), template_object,
        factory()->template_literal_function_literal_id_symbol(), &raw_desc,
        Just(kThrowOnError))
        .ToChecked();
    JSArray::DefineOwnProperty(isolate(), template_object,
                               factory()->template_literal_slot_id_symbol(),
                               &raw_desc, Just(kThrowOnError))
        .ToChecked();

    // Freeze the {template_object} as well.
    JSObject::SetIntegrityLevel(isolate(), template_object, FROZEN,
                                kThrowOnError)
        .ToChecked();
    {
      DisallowGarbageCollection no_gc;
      Tagged<DescriptorArray> desc =
          template_object->map()->instance_descriptors();
      {
        // Verify TemplateLiteralObject::kRawOffset
        InternalIndex descriptor_index = desc->Search(
            *factory()->raw_string(), desc->number_of_descriptors());
        FieldIndex index =
            FieldIndex::ForDescriptor(template_object->map(), descriptor_index);
        CHECK(index.is_inobject());
        CHECK_EQ(index.offset(), TemplateLiteralObject::kRawOffset);
      }

      {
        // Verify TemplateLiteralObject::kFunctionLiteralIdOffset
        InternalIndex descriptor_index = desc->Search(
            *factory()->template_literal_function_literal_id_symbol(),
            desc->number_of_descriptors());
        FieldIndex index =
            FieldIndex::ForDescriptor(template_object->map(), descriptor_index);
        CHECK(index.is_inobject());
        CHECK_EQ(index.offset(),
                 TemplateLiteralObject::kFunctionLiteralIdOffset);
      }

      {
        // Verify TemplateLiteralObject::kSlotIdOffset
        InternalIndex descriptor_index =
            desc->Search(*factory()->template_literal_slot_id_symbol(),
                         desc->number_of_descriptors());
        FieldIndex index =
            FieldIndex::ForDescriptor(template_object->map(), descriptor_index);
        CHECK(index.is_inobject());
        CHECK_EQ(index.offset(), TemplateLiteralObject::kSlotIdOffset);
      }
    }

    native_context()->set_js_array_template_literal_object_map(
        template_object->map());
  }

  // Create a constructor for RegExp results (a variant of Array that
  // predefines the properties index, input, and groups).
  {
    // JSRegExpResult initial map.
    // Add additional slack to the initial map in case regexp_match_indices
    // are enabled to account for the additional descriptor.
    Handle<Map> initial_map = CreateInitialMapForArraySubclass(
        JSRegExpResult::kSize, JSRegExpResult::kInObjectPropertyCount);

    // index descriptor.
    {
      Descriptor d = Descriptor::DataField(isolate(), factory()->index_string(),
                                           JSRegExpResult::kIndexIndex, NONE,
                                           Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
    }

    // input descriptor.
    {
      Descriptor d = Descriptor::DataField(isolate(), factory()->input_string(),
                                           JSRegExpResult::kInputIndex, NONE,
                                           Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
    }

    // groups descriptor.
    {
      Descriptor d = Descriptor::DataField(
          isolate(), factory()->groups_string(), JSRegExpResult::kGroupsIndex,
          NONE, Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
    }

    // Private internal only fields. All of the remaining fields have special
    // symbols to prevent their use in Javascript.
    {
      PropertyAttributes attribs = DONT_ENUM;

      // names descriptor.
      {
        Descriptor d = Descriptor::DataField(
            isolate(), factory()->regexp_result_names_symbol(),
            JSRegExpResult::kNamesIndex, attribs, Representation::Tagged());
        initial_map->AppendDescriptor(isolate(), &d);
      }

      // regexp_input_index descriptor.
      {
        Descriptor d = Descriptor::DataField(
            isolate(), factory()->regexp_result_regexp_input_symbol(),
            JSRegExpResult::kRegExpInputIndex, attribs,
            Representation::Tagged());
        initial_map->AppendDescriptor(isolate(), &d);
      }

      // regexp_last_index descriptor.
      {
        Descriptor d = Descriptor::DataField(
            isolate(), factory()->regexp_result_regexp_last_index_symbol(),
            JSRegExpResult::kRegExpLastIndex, attribs,
            Representation::Tagged());
        initial_map->AppendDescriptor(isolate(), &d);
      }
    }

    // Set up the map for RegExp results objects for regexps with the /d flag.
    DirectHandle<Map> initial_with_indices_map =
        Map::Copy(isolate(), initial_map, "JSRegExpResult with indices");
    initial_with_indices_map->set_instance_size(
        JSRegExpResultWithIndices::kSize);
    DCHECK_EQ(initial_with_indices_map->GetInObjectProperties(),
              JSRegExpResultWithIndices::kInObjectPropertyCount);

    // indices descriptor
    {
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->indices_string(),
                                JSRegExpResultWithIndices::kIndicesIndex, NONE,
                                Representation::Tagged());
      Map::EnsureDescriptorSlack(isolate(), initial_with_indices_map, 1);
      initial_with_indices_map->AppendDescriptor(isolate(), &d);
    }

    native_context()->set_regexp_result_map(*initial_map);
    native_context()->set_regexp_result_with_indices_map(
        *initial_with_indices_map);
  }

  // Create a constructor for JSRegExpResultIndices (a variant of Array that
  // predefines the groups property).
  {
    // JSRegExpResultIndices initial map.
    DirectHandle<Map> initial_map = CreateInitialMapForArraySubclass(
        JSRegExpResultIndices::kSize,
        JSRegExpResultIndices::kInObjectPropertyCount);

    // groups descriptor.
    {
      Descriptor d = Descriptor::DataField(
          isolate(), factory()->groups_string(),
          JSRegExpResultIndices::kGroupsIndex, NONE, Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
      DCHECK_EQ(initial_map->LastAdded().as_int(),
                JSRegExpResultIndices::kGroupsDescriptorIndex);
    }

    native_context()->set_regexp_result_indices_map(*initial_map);
  }

  // Add @@iterator method to the arguments object maps.
  {
    PropertyAttributes attribs = DONT_ENUM;
    Handle<AccessorInfo> arguments_iterator =
        factory()->arguments_iterator_accessor();
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->sloppy_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->fast_aliased_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->slow_aliased_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->strict_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
  }
  {
    DirectHandle<OrderedHashSet> promises =
        OrderedHashSet::Allocate(isolate(), 0).ToHandleChecked();
    native_context()->set_atomics_waitasync_promises(*promises);
  }

  return true;
}
```

### 功能列举

这段 C++ 代码的主要功能是**初始化 V8 引擎中一些核心的 JavaScript 对象和它们的内部结构（Maps）**。具体来说，它做了以下几件事：

1. **创建 `JSDataPropertyDescriptor` 对象的 Map：**  设置了描述数据属性的 Map，包含 `writable`、`enumerable` 和 `configurable` 属性。这定义了 JavaScript 中属性的行为方式。
2. **创建 `TemplateLiteral` 对象的 Map：**  配置了模板字面量的内部结构，包括设置 `raw` 属性以及用于内部优化的私有符号字段。
3. **创建 `RegExp` 结果对象的 Map：** 为 `RegExp.exec()` 或 `String.prototype.match()` 等方法返回的结果对象 (`JSRegExpResult`) 创建了 Map，预定义了 `index`、`input` 和 `groups` 属性。它还处理了带有 `/d` 标志的正则表达式，为其结果对象 (`JSRegExpResultWithIndices`) 添加了 `indices` 属性。
4. **创建 `RegExp` 结果索引对象的 Map：**  为 `RegExp` 结果中用于捕获组索引的对象 (`JSRegExpResultIndices`) 创建了 Map，预定义了 `groups` 属性。
5. **为 arguments 对象添加 `@@iterator` 方法：**  为不同类型的 `arguments` 对象（sloppy, fast aliased, slow aliased, strict）添加了 `@@iterator` 符号属性，使其可以被迭代。
6. **初始化 `atomics_waitasync_promises`：**  创建了一个空的 `OrderedHashSet` 来存储与 `Atomics.waitAsync` 相关的 Promise 对象。

### 关于源代码类型

`v8/src/init/bootstrapper.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。

### 与 JavaScript 的关系及举例

这段代码直接关系到 JavaScript 的核心功能。它在 V8 引擎的初始化阶段建立了 JavaScript 对象的内部结构，使得这些对象能够按照语言规范运行。

**JavaScript 例子：**

1. **数据属性描述符：**

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'name', {
     value: 'example',
     writable: false,
     enumerable: true,
     configurable: false
   });

   console.log(obj.name); // 输出: example
   obj.name = 'new value'; // 静默失败，因为 writable: false
   console.log(obj.name); // 输出: example
   for (let key in obj) {
     console.log(key); // 输出: name，因为 enumerable: true
   }
   delete obj.name; // 失败，因为 configurable: false
   console.log(obj.name); // 输出: example
   ```

   这段代码创建的 Map 决定了 `Object.defineProperty` 中 `writable`、`enumerable` 和 `configurable` 这些属性的含义和作用。

2. **模板字面量：**

   ```javascript
   const name = 'World';
   const greeting = `Hello, ${name}!`;
   console.log(greeting); // 输出: Hello, World!

   const templateObject = `string text`;
   console.log(templateObject.raw[0]); // 输出: string text
   ```

   这段代码负责创建模板字面量背后的对象，包括其 `raw` 属性，这在处理转义字符时非常重要。

3. **正则表达式结果：**

   ```javascript
   const regex = /hello (world)/;
   const str = 'hello world test';
   const result = regex.exec(str);

   console.log(result.index); // 输出: 0
   console.log(result.input); // 输出: hello world test
   console.log(result.groups[0]); // 输出: world
   ```

   这段代码创建的 Map 确保了正则表达式的执行结果对象具有 `index`、`input` 和 `groups` 这些属性。

4. **arguments 对象迭代：**

   ```javascript
   function foo() {
     for (const arg of arguments) {
       console.log(arg);
     }
   }
   foo(1, 2, 3); // 输出: 1, 2, 3
   ```

   这段代码添加的 `@@iterator` 方法使得 `arguments` 对象可以被 `for...of` 循环迭代。

### 代码逻辑推理

这段代码的逻辑主要是关于对象和 Map 的创建和配置。它没有复杂的算法或数据处理流程。

**假设输入：**  V8 引擎启动，需要初始化 JavaScript 运行环境。

**输出：**  创建并配置了 `JSDataPropertyDescriptor` Map，`TemplateLiteral` 对象 Map，各种 `RegExp` 结果对象的 Map，并为 `arguments` 对象添加了迭代器方法。这些数据结构存储在 `native_context` 中，供 V8 引擎后续使用。

### 涉及用户常见的编程错误

虽然这段代码是 V8 内部的初始化代码，但理解它有助于避免一些与 JavaScript 对象属性相关的常见编程错误：

1. **误以为所有属性都是可写的、可枚举的或可配置的：**  用户可能没有使用 `Object.defineProperty` 显式设置属性描述符，就默认认为属性可以被修改、枚举或删除。

   ```javascript
   const obj = { name: 'test' };
   // 默认情况下，属性是 writable: true, enumerable: true, configurable: true

   // 假设用户忘记了某个库或代码将 name 属性设置为不可写
   Object.defineProperty(obj, 'name', { writable: false });
   obj.name = 'new value'; // 静默失败，但用户可能没有意识到
   console.log(obj.name); // 输出: test
   ```

2. **不理解模板字面量的 `raw` 属性：**  用户可能不了解模板字面量 `raw` 属性的存在及其用途，在处理需要原始字符串的场景时可能出错。

   ```javascript
   const str = `line1\nline2`;
   console.log(str);      // 输出: line1
                         //      line2
   console.log(str.raw);  // 输出: undefined (需要作为标签模板使用)

   function tag(strings, ...values) {
     console.log(strings.raw[0]);
   }
   tag`line1\nline2`; // 输出: line1\nline2
   ```

3. **错误地假设正则表达式结果总是返回所有属性：** 用户可能依赖于某些非标准的属性，或者不理解 `groups` 属性只有在正则表达式包含命名捕获组时才存在。

   ```javascript
   const regex = /hello (?<noun>world)/;
   const str = 'hello world';
   const result = regex.exec(str);

   console.log(result.groups.noun); // 输出: world

   const regex2 = /hello (world)/;
   const result2 = regex2.exec(str);
   // console.log(result2.groups.noun); // 报错: Cannot read properties of undefined (reading 'noun')
   ```

### 功能归纳

作为第 10 部分（共 11 部分），这段代码在 V8 引擎的启动过程中扮演着关键的角色，**负责构建和初始化一些核心的 JavaScript 语言特性所需的内部数据结构（Maps）和对象**。这些初始化工作为后续 JavaScript 代码的执行奠定了基础，确保了诸如属性描述符、模板字面量、正则表达式结果和 `arguments` 对象等功能能够按照预期运行。它是 V8 引擎自举过程中的一个重要步骤，用于建立基本的 JavaScript 对象模型。

Prompt: 
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共11部分，请归纳一下它的功能

"""
ppendDescriptor(isolate(), &d);
    }
    {  // writable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->writable_string(),
                                JSDataPropertyDescriptor::kWritableIndex, NONE,
                                Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // enumerable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->enumerable_string(),
                                JSDataPropertyDescriptor::kEnumerableIndex,
                                NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // configurable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->configurable_string(),
                                JSDataPropertyDescriptor::kConfigurableIndex,
                                NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }

    Map::SetPrototype(isolate(), map, isolate()->initial_object_prototype());
    map->SetConstructor(native_context()->object_function());

    native_context()->set_data_property_descriptor_map(*map);
  }

  {
    // -- TemplateLiteral JSArray Map
    DirectHandle<JSFunction> array_function(native_context()->array_function(),
                                            isolate());
    Handle<Map> template_map(array_function->initial_map(), isolate_);
    template_map = Map::CopyAsElementsKind(isolate_, template_map,
                                           PACKED_ELEMENTS, OMIT_TRANSITION);
    DCHECK_GE(TemplateLiteralObject::kHeaderSize,
              template_map->instance_size());
    template_map->set_instance_size(TemplateLiteralObject::kHeaderSize);
    // Temporarily instantiate a full template_literal_object to get the final
    // map.
    auto template_object =
        Cast<JSArray>(factory()->NewJSObjectFromMap(template_map));
    {
      DisallowGarbageCollection no_gc;
      Tagged<JSArray> raw = *template_object;
      raw->set_elements(ReadOnlyRoots(isolate()).empty_fixed_array());
      raw->set_length(Smi::FromInt(0));
    }

    // Install a "raw" data property for {raw_object} on {template_object}.
    // See ES#sec-gettemplateobject.
    PropertyDescriptor raw_desc;
    // Use arbrirary object {template_object} as ".raw" value.
    raw_desc.set_value(template_object);
    raw_desc.set_configurable(false);
    raw_desc.set_enumerable(false);
    raw_desc.set_writable(false);
    JSArray::DefineOwnProperty(isolate(), template_object,
                               factory()->raw_string(), &raw_desc,
                               Just(kThrowOnError))
        .ToChecked();
    // Install private symbol fields for function_literal_id and slot_id.
    raw_desc.set_value(handle(Smi::zero(), isolate()));
    JSArray::DefineOwnProperty(
        isolate(), template_object,
        factory()->template_literal_function_literal_id_symbol(), &raw_desc,
        Just(kThrowOnError))
        .ToChecked();
    JSArray::DefineOwnProperty(isolate(), template_object,
                               factory()->template_literal_slot_id_symbol(),
                               &raw_desc, Just(kThrowOnError))
        .ToChecked();

    // Freeze the {template_object} as well.
    JSObject::SetIntegrityLevel(isolate(), template_object, FROZEN,
                                kThrowOnError)
        .ToChecked();
    {
      DisallowGarbageCollection no_gc;
      Tagged<DescriptorArray> desc =
          template_object->map()->instance_descriptors();
      {
        // Verify TemplateLiteralObject::kRawOffset
        InternalIndex descriptor_index = desc->Search(
            *factory()->raw_string(), desc->number_of_descriptors());
        FieldIndex index =
            FieldIndex::ForDescriptor(template_object->map(), descriptor_index);
        CHECK(index.is_inobject());
        CHECK_EQ(index.offset(), TemplateLiteralObject::kRawOffset);
      }

      {
        // Verify TemplateLiteralObject::kFunctionLiteralIdOffset
        InternalIndex descriptor_index = desc->Search(
            *factory()->template_literal_function_literal_id_symbol(),
            desc->number_of_descriptors());
        FieldIndex index =
            FieldIndex::ForDescriptor(template_object->map(), descriptor_index);
        CHECK(index.is_inobject());
        CHECK_EQ(index.offset(),
                 TemplateLiteralObject::kFunctionLiteralIdOffset);
      }

      {
        // Verify TemplateLiteralObject::kSlotIdOffset
        InternalIndex descriptor_index =
            desc->Search(*factory()->template_literal_slot_id_symbol(),
                         desc->number_of_descriptors());
        FieldIndex index =
            FieldIndex::ForDescriptor(template_object->map(), descriptor_index);
        CHECK(index.is_inobject());
        CHECK_EQ(index.offset(), TemplateLiteralObject::kSlotIdOffset);
      }
    }

    native_context()->set_js_array_template_literal_object_map(
        template_object->map());
  }

  // Create a constructor for RegExp results (a variant of Array that
  // predefines the properties index, input, and groups).
  {
    // JSRegExpResult initial map.
    // Add additional slack to the initial map in case regexp_match_indices
    // are enabled to account for the additional descriptor.
    Handle<Map> initial_map = CreateInitialMapForArraySubclass(
        JSRegExpResult::kSize, JSRegExpResult::kInObjectPropertyCount);

    // index descriptor.
    {
      Descriptor d = Descriptor::DataField(isolate(), factory()->index_string(),
                                           JSRegExpResult::kIndexIndex, NONE,
                                           Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
    }

    // input descriptor.
    {
      Descriptor d = Descriptor::DataField(isolate(), factory()->input_string(),
                                           JSRegExpResult::kInputIndex, NONE,
                                           Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
    }

    // groups descriptor.
    {
      Descriptor d = Descriptor::DataField(
          isolate(), factory()->groups_string(), JSRegExpResult::kGroupsIndex,
          NONE, Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
    }

    // Private internal only fields. All of the remaining fields have special
    // symbols to prevent their use in Javascript.
    {
      PropertyAttributes attribs = DONT_ENUM;

      // names descriptor.
      {
        Descriptor d = Descriptor::DataField(
            isolate(), factory()->regexp_result_names_symbol(),
            JSRegExpResult::kNamesIndex, attribs, Representation::Tagged());
        initial_map->AppendDescriptor(isolate(), &d);
      }

      // regexp_input_index descriptor.
      {
        Descriptor d = Descriptor::DataField(
            isolate(), factory()->regexp_result_regexp_input_symbol(),
            JSRegExpResult::kRegExpInputIndex, attribs,
            Representation::Tagged());
        initial_map->AppendDescriptor(isolate(), &d);
      }

      // regexp_last_index descriptor.
      {
        Descriptor d = Descriptor::DataField(
            isolate(), factory()->regexp_result_regexp_last_index_symbol(),
            JSRegExpResult::kRegExpLastIndex, attribs,
            Representation::Tagged());
        initial_map->AppendDescriptor(isolate(), &d);
      }
    }

    // Set up the map for RegExp results objects for regexps with the /d flag.
    DirectHandle<Map> initial_with_indices_map =
        Map::Copy(isolate(), initial_map, "JSRegExpResult with indices");
    initial_with_indices_map->set_instance_size(
        JSRegExpResultWithIndices::kSize);
    DCHECK_EQ(initial_with_indices_map->GetInObjectProperties(),
              JSRegExpResultWithIndices::kInObjectPropertyCount);

    // indices descriptor
    {
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->indices_string(),
                                JSRegExpResultWithIndices::kIndicesIndex, NONE,
                                Representation::Tagged());
      Map::EnsureDescriptorSlack(isolate(), initial_with_indices_map, 1);
      initial_with_indices_map->AppendDescriptor(isolate(), &d);
    }

    native_context()->set_regexp_result_map(*initial_map);
    native_context()->set_regexp_result_with_indices_map(
        *initial_with_indices_map);
  }

  // Create a constructor for JSRegExpResultIndices (a variant of Array that
  // predefines the groups property).
  {
    // JSRegExpResultIndices initial map.
    DirectHandle<Map> initial_map = CreateInitialMapForArraySubclass(
        JSRegExpResultIndices::kSize,
        JSRegExpResultIndices::kInObjectPropertyCount);

    // groups descriptor.
    {
      Descriptor d = Descriptor::DataField(
          isolate(), factory()->groups_string(),
          JSRegExpResultIndices::kGroupsIndex, NONE, Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
      DCHECK_EQ(initial_map->LastAdded().as_int(),
                JSRegExpResultIndices::kGroupsDescriptorIndex);
    }

    native_context()->set_regexp_result_indices_map(*initial_map);
  }

  // Add @@iterator method to the arguments object maps.
  {
    PropertyAttributes attribs = DONT_ENUM;
    Handle<AccessorInfo> arguments_iterator =
        factory()->arguments_iterator_accessor();
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->sloppy_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->fast_aliased_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->slow_aliased_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->strict_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
  }
  {
    DirectHandle<OrderedHashSet> promises =
        OrderedHashSet::Allocate(isolate(), 0).ToHandleChecked();
    native_context()->set_atomics_waitasync_promises(*promises);
  }

  return true;
}

bool Genesis::InstallExtrasBindings() {
  HandleScope scope(isolate());

  Handle<JSObject> extras_binding = factory()->NewJSObjectWithNullProto();

  // binding.isTraceCategoryEnabled(category)
  SimpleInstallFunction(isolate(), extras_binding, "isTraceCategoryEnabled",
                        Builtin::kIsTraceCategoryEnabled, 1, kAdapt);

  // binding.trace(phase, category, name, id, data)
  SimpleInstallFunction(isolate(), extras_binding, "trace", Builtin::kTrace, 5,
                        kAdapt);

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  // binding.getContinuationPreservedEmbedderData()
  SimpleInstallFunction(
      isolate(), extras_binding, "getContinuationPreservedEmbedderData",
      Builtin::kGetContinuationPreservedEmbedderData, 0, kAdapt);

  // binding.setContinuationPreservedEmbedderData(value)
  SimpleInstallFunction(
      isolate(), extras_binding, "setContinuationPreservedEmbedderData",
      Builtin::kSetContinuationPreservedEmbedderData, 1, kAdapt);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

  InitializeConsole(extras_binding);

  native_context()->set_extras_binding_object(*extras_binding);

  return true;
}

void Genesis::InitializeMapCaches() {
  {
    DirectHandle<NormalizedMapCache> cache = NormalizedMapCache::New(isolate());
    native_context()->set_normalized_map_cache(*cache);
  }

  {
    DirectHandle<WeakFixedArray> cache = factory()->NewWeakFixedArray(
        JSObject::kMapCacheSize, AllocationType::kOld);

    DisallowGarbageCollection no_gc;
    for (int i = 0; i < JSObject::kMapCacheSize; i++) {
      cache->set(i, ClearedValue(isolate()));
    }
    native_context()->set_map_cache(*cache);
    Tagged<Map> initial = native_context()->object_function()->initial_map();
    cache->set(0, MakeWeak(initial));
    cache->set(initial->GetInObjectProperties(), MakeWeak(initial));
  }
}

bool Bootstrapper::InstallExtensions(DirectHandle<NativeContext> native_context,
                                     v8::ExtensionConfiguration* extensions) {
  // Don't install extensions into the snapshot.
  if (isolate_->serializer_enabled()) return true;
  BootstrapperActive active(this);
  v8::Context::Scope context_scope(Utils::ToLocal(native_context));
  return Genesis::InstallExtensions(isolate_, native_context, extensions) &&
         Genesis::InstallSpecialObjects(isolate_, native_context);
}

bool Genesis::InstallSpecialObjects(
    Isolate* isolate, DirectHandle<NativeContext> native_context) {
  HandleScope scope(isolate);

  // Error.stackTraceLimit.
  {
    Handle<JSObject> Error = isolate->error_function();
    Handle<String> name = isolate->factory()->stackTraceLimit_string();
    DirectHandle<Smi> stack_trace_limit(
        Smi::FromInt(v8_flags.stack_trace_limit), isolate);
    JSObject::AddProperty(isolate, Error, name, stack_trace_limit, NONE);
  }

#if V8_ENABLE_WEBASSEMBLY
  WasmJs::Install(isolate);
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_ENABLE_MEMORY_CORRUPTION_API
  if (v8_flags.expose_memory_corruption_api) {
    SandboxTesting::InstallMemoryCorruptionApi(isolate);
  }
#endif  // V8_ENABLE_MEMORY_CORRUPTION_API

  return true;
}

static uint32_t Hash(RegisteredExtension* extension) {
  return v8::internal::ComputePointerHash(extension);
}

Genesis::ExtensionStates::ExtensionStates() : map_(8) {}

Genesis::ExtensionTraversalState Genesis::ExtensionStates::get_state(
    RegisteredExtension* extension) {
  base::HashMap::Entry* entry = map_.Lookup(extension, Hash(extension));
  if (entry == nullptr) {
    return UNVISITED;
  }
  return static_cast<ExtensionTraversalState>(
      reinterpret_cast<intptr_t>(entry->value));
}

void Genesis::ExtensionStates::set_state(RegisteredExtension* extension,
                                         ExtensionTraversalState state) {
  map_.LookupOrInsert(extension, Hash(extension))->value =
      reinterpret_cast<void*>(static_cast<intptr_t>(state));
}

bool Genesis::InstallExtensions(Isolate* isolate,
                                DirectHandle<Context> native_context,
                                v8::ExtensionConfiguration* extensions) {
  ExtensionStates extension_states;  // All extensions have state UNVISITED.
  return InstallAutoExtensions(isolate, &extension_states) &&
         (!v8_flags.expose_gc ||
          InstallExtension(isolate, "v8/gc", &extension_states)) &&
         (!v8_flags.expose_externalize_string ||
          InstallExtension(isolate, "v8/externalize", &extension_states)) &&
         (!(v8_flags.expose_statistics ||
            TracingFlags::is_gc_stats_enabled()) ||
          InstallExtension(isolate, "v8/statistics", &extension_states)) &&
         (!v8_flags.expose_trigger_failure ||
          InstallExtension(isolate, "v8/trigger-failure", &extension_states)) &&
         (!v8_flags.expose_ignition_statistics ||
          InstallExtension(isolate, "v8/ignition-statistics",
                           &extension_states)) &&
         (!isValidCpuTraceMarkFunctionName() ||
          InstallExtension(isolate, "v8/cpumark", &extension_states)) &&
#ifdef V8_FUZZILLI
         InstallExtension(isolate, "v8/fuzzilli", &extension_states) &&
#endif
#ifdef ENABLE_VTUNE_TRACEMARK
         (!v8_flags.enable_vtune_domain_support ||
          InstallExtension(isolate, "v8/vtunedomain", &extension_states)) &&
#endif  // ENABLE_VTUNE_TRACEMARK
         InstallRequestedExtensions(isolate, extensions, &extension_states);
}

bool Genesis::InstallAutoExtensions(Isolate* isolate,
                                    ExtensionStates* extension_states) {
  for (v8::RegisteredExtension* it = v8::RegisteredExtension::first_extension();
       it != nullptr; it = it->next()) {
    if (it->extension()->auto_enable() &&
        !InstallExtension(isolate, it, extension_states)) {
      return false;
    }
  }
  return true;
}

bool Genesis::InstallRequestedExtensions(Isolate* isolate,
                                         v8::ExtensionConfiguration* extensions,
                                         ExtensionStates* extension_states) {
  for (const char** it = extensions->begin(); it != extensions->end(); ++it) {
    if (!InstallExtension(isolate, *it, extension_states)) return false;
  }
  return true;
}

// Installs a named extension.  This methods is unoptimized and does
// not scale well if we want to support a large number of extensions.
bool Genesis::InstallExtension(Isolate* isolate, const char* name,
                               ExtensionStates* extension_states) {
  for (v8::RegisteredExtension* it = v8::RegisteredExtension::first_extension();
       it != nullptr; it = it->next()) {
    if (strcmp(name, it->extension()->name()) == 0) {
      return InstallExtension(isolate, it, extension_states);
    }
  }
  return Utils::ApiCheck(false, "v8::Context::New()",
                         "Cannot find required extension");
}

bool Genesis::InstallExtension(Isolate* isolate,
                               v8::RegisteredExtension* current,
                               ExtensionStates* extension_states) {
  HandleScope scope(isolate);

  if (extension_states->get_state(current) == INSTALLED) return true;
  // The current node has already been visited so there must be a
  // cycle in the dependency graph; fail.
  if (!Utils::ApiCheck(extension_states->get_state(current) != VISITED,
                       "v8::Context::New()", "Circular extension dependency")) {
    return false;
  }
  DCHECK(extension_states->get_state(current) == UNVISITED);
  extension_states->set_state(current, VISITED);
  v8::Extension* extension = current->extension();
  // Install the extension's dependencies
  for (int i = 0; i < extension->dependency_count(); i++) {
    if (!InstallExtension(isolate, extension->dependencies()[i],
                          extension_states)) {
      return false;
    }
  }
  if (!CompileExtension(isolate, extension)) {
    // We print out the name of the extension that fail to install.
    // When an error is thrown during bootstrapping we automatically print
    // the line number at which this happened to the console in the isolate
    // error throwing functionality.
    base::OS::PrintError("Error installing extension '%s'.\n",
                         current->extension()->name());
    return false;
  }

  DCHECK(!isolate->has_exception());
  extension_states->set_state(current, INSTALLED);
  return true;
}

bool Genesis::ConfigureGlobalObject(
    v8::Local<v8::ObjectTemplate> global_proxy_template) {
  Handle<JSObject> global_proxy(native_context()->global_proxy(), isolate());
  Handle<JSObject> global_object(native_context()->global_object(), isolate());

  if (!global_proxy_template.IsEmpty()) {
    // Configure the global proxy object.
    Handle<ObjectTemplateInfo> global_proxy_data =
        v8::Utils::OpenHandle(*global_proxy_template);
    if (!ConfigureApiObject(global_proxy, global_proxy_data)) {
      base::OS::PrintError("V8 Error: Failed to configure global_proxy_data\n");
      return false;
    }

    // Configure the global object.
    DirectHandle<FunctionTemplateInfo> proxy_constructor(
        Cast<FunctionTemplateInfo>(global_proxy_data->constructor()),
        isolate());
    if (!IsUndefined(proxy_constructor->GetPrototypeTemplate(), isolate())) {
      Handle<ObjectTemplateInfo> global_object_data(
          Cast<ObjectTemplateInfo>(proxy_constructor->GetPrototypeTemplate()),
          isolate());
      if (!ConfigureApiObject(global_object, global_object_data)) {
        base::OS::PrintError(
            "V8 Error: Failed to configure global_object_data\n");
        return false;
      }
    }
  }

  JSObject::ForceSetPrototype(isolate(), global_proxy, global_object);

  native_context()->set_array_buffer_map(
      native_context()->array_buffer_fun()->initial_map());

  return true;
}

bool Genesis::ConfigureApiObject(Handle<JSObject> object,
                                 Handle<ObjectTemplateInfo> object_template) {
  DCHECK(!object_template.is_null());
  DCHECK(Cast<FunctionTemplateInfo>(object_template->constructor())
             ->IsTemplateFor(object->map()));

  MaybeHandle<JSObject> maybe_obj =
      ApiNatives::InstantiateObject(object->GetIsolate(), object_template);
  Handle<JSObject> instantiated_template;
  if (!maybe_obj.ToHandle(&instantiated_template)) {
    DCHECK(isolate()->has_exception());

    DirectHandle<String> message =
        ErrorUtils::ToString(isolate_, handle(isolate_->exception(), isolate_))
            .ToHandleChecked();
    base::OS::PrintError(
        "V8 Error: Exception in Genesis::ConfigureApiObject: %s\n",
        message->ToCString().get());

    isolate()->clear_exception();
    return false;
  }
  TransferObject(instantiated_template, object);
  return true;
}

static bool PropertyAlreadyExists(Isolate* isolate, Handle<JSObject> to,
                                  Handle<Name> key) {
  LookupIterator it(isolate, to, key, LookupIterator::OWN_SKIP_INTERCEPTOR);
  CHECK_NE(LookupIterator::ACCESS_CHECK, it.state());
  return it.IsFound();
}

void Genesis::TransferNamedProperties(DirectHandle<JSObject> from,
                                      Handle<JSObject> to) {
  // If JSObject::AddProperty asserts due to already existing property,
  // it is likely due to both global objects sharing property name(s).
  // Merging those two global objects is impossible.
  // The global template must not create properties that already exist
  // in the snapshotted global object.
  if (from->HasFastProperties()) {
    DirectHandle<DescriptorArray> descs(
        from->map()->instance_descriptors(isolate()), isolate());
    for (InternalIndex i : from->map()->IterateOwnDescriptors()) {
      PropertyDetails details = descs->GetDetails(i);
      if (details.location() == PropertyLocation::kField) {
        if (details.kind() == PropertyKind::kData) {
          HandleScope inner(isolate());
          Handle<Name> key = Handle<Name>(descs->GetKey(i), isolate());
          // If the property is already there we skip it.
          if (PropertyAlreadyExists(isolate(), to, key)) continue;
          FieldIndex index = FieldIndex::ForDetails(from->map(), details);
          DirectHandle<Object> value = JSObject::FastPropertyAt(
              isolate(), from, details.representation(), index);
          JSObject::AddProperty(isolate(), to, key, value,
                                details.attributes());
        } else {
          DCHECK_EQ(PropertyKind::kAccessor, details.kind());
          UNREACHABLE();
        }

      } else {
        DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        Handle<Name> key(descs->GetKey(i), isolate());
        // If the property is already there we skip it.
        if (PropertyAlreadyExists(isolate(), to, key)) continue;
        HandleScope inner(isolate());
        DCHECK(!to->HasFastProperties());
        // Add to dictionary.
        Handle<Object> value(descs->GetStrongValue(i), isolate());
        PropertyDetails d(PropertyKind::kAccessor, details.attributes(),
                          PropertyCellType::kMutable);
        JSObject::SetNormalizedProperty(to, key, value, d);
      }
    }
  } else if (IsJSGlobalObject(*from)) {
    // Copy all keys and values in enumeration order.
    Handle<GlobalDictionary> properties(
        Cast<JSGlobalObject>(*from)->global_dictionary(kAcquireLoad),
        isolate());
    DirectHandle<FixedArray> indices =
        GlobalDictionary::IterationIndices(isolate(), properties);
    for (int i = 0; i < indices->length(); i++) {
      InternalIndex index(Smi::ToInt(indices->get(i)));
      DirectHandle<PropertyCell> cell(properties->CellAt(index), isolate());
      Handle<Name> key(cell->name(), isolate());
      // If the property is already there we skip it.
      if (PropertyAlreadyExists(isolate(), to, key)) continue;
      // Set the property.
      Handle<Object> value(cell->value(), isolate());
      if (IsTheHole(*value, isolate())) continue;
      PropertyDetails details = cell->property_details();
      if (details.kind() == PropertyKind::kData) {
        JSObject::AddProperty(isolate(), to, key, value, details.attributes());
      } else {
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        DCHECK(!to->HasFastProperties());
        PropertyDetails d(PropertyKind::kAccessor, details.attributes(),
                          PropertyCellType::kMutable);
        JSObject::SetNormalizedProperty(to, key, value, d);
      }
    }

  } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // Copy all keys and values in enumeration order.
    DirectHandle<SwissNameDictionary> properties(
        from->property_dictionary_swiss(), isolate());
    ReadOnlyRoots roots(isolate());
    for (InternalIndex entry : properties->IterateEntriesOrdered()) {
      Tagged<Object> raw_key;
      if (!properties->ToKey(roots, entry, &raw_key)) continue;

      DCHECK(IsName(raw_key));
      Handle<Name> key(Cast<Name>(raw_key), isolate());
      // If the property is already there we skip it.
      if (PropertyAlreadyExists(isolate(), to, key)) continue;
      // Set the property.
      DirectHandle<Object> value(properties->ValueAt(entry), isolate());
      DCHECK(!IsCell(*value));
      DCHECK(!IsTheHole(*value, isolate()));
      PropertyDetails details = properties->DetailsAt(entry);
      DCHECK_EQ(PropertyKind::kData, details.kind());
      JSObject::AddProperty(isolate(), to, key, value, details.attributes());
    }
  } else {
    // Copy all keys and values in enumeration order.
    Handle<NameDictionary> properties =
        Handle<NameDictionary>(from->property_dictionary(), isolate());
    DirectHandle<FixedArray> key_indices =
        NameDictionary::IterationIndices(isolate(), properties);
    ReadOnlyRoots roots(isolate());
    for (int i = 0; i < key_indices->length(); i++) {
      InternalIndex key_index(Smi::ToInt(key_indices->get(i)));
      Tagged<Object> raw_key = properties->KeyAt(key_index);
      DCHECK(properties->IsKey(roots, raw_key));
      DCHECK(IsName(raw_key));
      Handle<Name> key(Cast<Name>(raw_key), isolate());
      // If the property is already there we skip it.
      if (PropertyAlreadyExists(isolate(), to, key)) continue;
      // Set the property.
      DirectHandle<Object> value(properties->ValueAt(key_index), isolate());
      DCHECK(!IsCell(*value));
      DCHECK(!IsTheHole(*value, isolate()));
      PropertyDetails details = properties->DetailsAt(key_index);
      DCHECK_EQ(PropertyKind::kData, details.kind());
      JSObject::AddProperty(isolate(), to, key, value, details.attributes());
    }
  }
}

void Genesis::TransferIndexedProperties(DirectHandle<JSObject> from,
                                        DirectHandle<JSObject> to) {
  // Cloning the elements array is sufficient.
  Handle<FixedArray> from_elements =
      Handle<FixedArray>(Cast<FixedArray>(from->elements()), isolate());
  DirectHandle<FixedArray> to_elements =
      factory()->CopyFixedArray(from_elements);
  to->set_elements(*to_elements);
}

void Genesis::TransferObject(DirectHandle<JSObject> from, Handle<JSObject> to) {
  HandleScope outer(isolate());

  DCHECK(!IsJSArray(*from));
  DCHECK(!IsJSArray(*to));

  TransferNamedProperties(from, to);
  TransferIndexedProperties(from, to);

  // Transfer the prototype (new map is needed).
  Handle<JSPrototype> proto(from->map()->prototype(), isolate());
  JSObject::ForceSetPrototype(isolate(), to, proto);
}

Handle<Map> Genesis::CreateInitialMapForArraySubclass(int size,
                                                      int inobject_properties) {
  // Find global.Array.prototype to inherit from.
  DirectHandle<JSFunction> array_constructor(native_context()->array_function(),
                                             isolate());
  Handle<JSObject> array_prototype(native_context()->initial_array_prototype(),
                                   isolate());

  // Add initial map.
  Handle<Map> initial_map = factory()->NewContextfulMapForCurrentContext(
      JS_ARRAY_TYPE, size, TERMINAL_FAST_ELEMENTS_KIND, inobject_properties);
  initial_map->SetConstructor(*array_constructor);

  // Set prototype on map.
  initial_map->set_has_non_instance_prototype(false);
  Map::SetPrototype(isolate(), initial_map, array_prototype);

  // Update map with length accessor from Array.
  static constexpr int kTheLengthAccessor = 1;
  Map::EnsureDescriptorSlack(isolate(), initial_map,
                             inobject_properties + kTheLengthAccessor);

  // length descriptor.
  {
    Tagged<JSFunction> array_function = native_context()->array_function();
    DirectHandle<DescriptorArray> array_descriptors(
        array_function->initial_map()->instance_descriptors(isolate()),
        isolate());
    Handle<String> length = factory()->length_string();
    InternalIndex old = array_descriptors->SearchWithCache(
        isolate(), *length, array_function->initial_map());
    DCHECK(old.is_found());
    Descriptor d = Descriptor::AccessorConstant(
        length, handle(array_descriptors->GetStrongValue(old), isolate()),
        array_descriptors->GetDetails(old).attributes());
    initial_map->AppendDescriptor(isolate(), &d);
  }
  return initial_map;
}

Genesis::Genesis(Isolate* isolate,
                 MaybeHandle<JSGlobalProxy> maybe_global_proxy,
                 v8::Local<v8::ObjectTemplate> global_proxy_template,
                 size_t context_snapshot_index,
                 DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
                 v8::MicrotaskQueue* microtask_queue)
    : isolate_(isolate), active_(isolate->bootstrapper()) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kGenesis);
  result_ = {};
  global_proxy_ = {};

  // Before creating the roots we must save the context and restore it
  // on all function exits.
  SaveContext saved_context(isolate);

  // The deserializer needs to hook up references to the global proxy.
  // Create an uninitialized global proxy now if we don't have one
  // and initialize it later in CreateNewGlobals.
  Handle<JSGlobalProxy> global_proxy;
  if (!maybe_global_proxy.ToHandle(&global_proxy)) {
    int instance_size = 0;
    if (context_snapshot_index > 0) {
      // The global proxy function to reinitialize this global proxy is in the
      // context that is yet to be deserialized. We need to prepare a global
      // proxy of the correct size.
      Tagged<Object> size =
          isolate->heap()->serialized_global_proxy_sizes()->get(
              static_cast<int>(context_snapshot_index) -
              SnapshotCreatorImpl::kFirstAddtlContextIndex);
      instance_size = Smi::ToInt(size);
    } else {
      instance_size = JSGlobalProxy::SizeWithEmbedderFields(
          global_proxy_template.IsEmpty()
              ? 0
              : global_proxy_template->InternalFieldCount());
    }
    global_proxy =
        isolate->factory()->NewUninitializedJSGlobalProxy(instance_size);
  }

  // We can only de-serialize a context if the isolate was initialized from
  // a snapshot. Otherwise we have to build the context from scratch.
  // Also create a context from scratch to expose natives, if required by flag.
  DCHECK(native_context_.is_null());
  if (isolate->initialized_from_snapshot()) {
    DirectHandle<Context> context;
    if (Snapshot::NewContextFromSnapshot(isolate, global_proxy,
                                         context_snapshot_index,
                                         embedder_fields_deserializer)
      
"""


```