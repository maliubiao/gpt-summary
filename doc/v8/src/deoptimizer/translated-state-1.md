Response: The user wants a summary of the C++ code provided, focusing on its functionality and relation to JavaScript. Since this is part 2 of 2, I should assume it builds upon concepts introduced in the first part.

Based on the code, here's a breakdown of the functionality:

1. **Stack Frame Reconstruction:** The code seems heavily involved in reconstructing the state of the JavaScript execution stack during deoptimization. It reads information about stack slots (tagged values, integers, booleans, floats, doubles, SIMD values), literals, and optimized-out values.

2. **Object Materialization:**  There's a significant portion dedicated to "materializing" JavaScript objects that were previously optimized away. This involves allocating memory for them and initializing their fields based on the saved state.

3. **Handling Different Object Types:** The code has specific logic for materializing various JavaScript object types like `FixedArray`, `HeapNumber`, `JSObject`, `Context` objects, and more.

4. **String Concatenation Handling:**  It includes a special mechanism to resolve and materialize string concatenations.

5. **Feedback Vector Updates:** The code deals with updating the feedback vector, which is a performance optimization mechanism in V8.

6. **Deferred Materialization:** The concepts of `kUninitialized`, `kAllocated`, and `kFinished` states for `TranslatedValue` suggest a strategy of materializing objects on demand.

7. **Interaction with the Heap:** The code directly interacts with the V8 heap to allocate and initialize objects.

8. **Deoptimization-Specific Data:** It uses `DeoptimizationData` and `FrameTranslation` to guide the reconstruction process.

**Relating to JavaScript:**

The code directly deals with the internal representation of JavaScript values and objects within the V8 engine. When JavaScript code is optimized by TurboFan (V8's optimizing compiler), the representation of variables and objects might be different from their standard JavaScript form. When deoptimization happens (returning to a less optimized version of the code), V8 needs to reconstruct the original JavaScript state. This code is a core part of that process.

**Illustrative JavaScript Example:**

Consider a simple JavaScript function that gets optimized and then deoptimized:

```javascript
function add(a, b) {
  return a + b;
}

// ... some calls to add with numbers to trigger optimization ...

// Now, call add with non-numbers, potentially causing deoptimization
add("hello", "world");
```

When the `add` function is initially optimized for numbers, the V8 engine might store `a` and `b` as raw machine integers. When the call with strings occurs, the engine needs to "deoptimize" – revert to a state where `a` and `b` are represented as JavaScript strings.

The C++ code in `translated-state.cc` is responsible for:

* **Reading the stack:**  Identifying where `a` and `b` were stored on the stack in the optimized frame.
* **Recognizing their types:** Determining that they should now be JavaScript strings.
* **Creating string objects:** Allocating memory on the heap for the strings "hello" and "world".
* **Updating the stack:** Placing pointers to these newly created string objects back onto the stack in the deoptimized frame.

The code snippets dealing with `TAGGED_STACK_SLOT`, `STRING_STACK_SLOT`, and object materialization are directly involved in this kind of process. The `LITERAL` case might handle cases where the strings are constants.
这个C++源代码文件 `v8/src/deoptimizer/translated-state.cc` 的主要功能是 **在 JavaScript 代码反优化 (deoptimization) 过程中，重建程序执行的状态**。它负责从优化后的栈帧 (optimized JS frame) 中提取信息，并将这些信息转换成更通用的、易于理解和操作的表示形式，以便 V8 引擎能够顺利地切换回未优化的代码执行。

具体来说，这个文件的代码实现了以下核心功能：

1. **读取反优化信息 (Deoptimization Info):**  它解析由优化编译器生成的反优化数据，这些数据描述了优化后的栈帧布局以及如何将其映射回未优化的状态。

2. **遍历栈帧 (Stack Frame Traversal):**  它迭代优化后的栈帧，根据反优化信息识别不同类型的值，例如：
    * **栈槽 (Stack Slots):** 读取存储在栈上的各种 JavaScript 值，包括 tagged 指针、整数、布尔值、浮点数、双精度浮点数和 SIMD 值。
    * **字面量 (Literals):**  从字面量数组中获取常量值。
    * **优化掉的值 (Optimized Out):**  处理那些在优化过程中被移除的值。

3. **创建翻译后的值 (Translated Values):**  它将读取到的原始数据转换为 `TranslatedValue` 对象，这些对象是对 JavaScript 值的抽象表示，包含了值的类型和实际数据。

4. **构建翻译后的帧 (Translated Frames):**  它将 `TranslatedValue` 对象组织成 `TranslatedFrame` 对象，表示反优化后的栈帧。每个 `TranslatedFrame` 包含了该帧中所有需要重建的值。

5. **对象实例化 (Object Materialization):**  对于在优化过程中可能被抽象表示的对象，该代码负责在反优化时重新在堆上分配内存并初始化这些对象。它能处理多种 JavaScript 对象类型，包括数组、数字、普通对象、上下文 (Context) 等。

6. **处理字符串连接 (String Concatenation):**  专门处理在优化过程中可能被延迟执行的字符串连接操作，在反优化时将其结果实例化。

7. **更新反馈信息 (Feedback Update):**  涉及到更新反馈向量 (Feedback Vector)，这是 V8 引擎用于性能优化的机制之一，在反优化时可能需要禁用某些投机优化。

**与 JavaScript 的关系及示例：**

这个文件的功能是 V8 引擎内部运作的关键部分，直接关系到 JavaScript 代码的执行和性能。当 JavaScript 代码被 V8 的优化编译器 (TurboFan) 优化后，其内部的表示形式可能会与未优化时有所不同。当由于某些原因 (例如类型发生了变化) 需要回退到未优化代码时，就需要这个文件中的代码来 "翻译" 优化后的状态，使其能够被未优化的代码继续执行。

**JavaScript 示例：**

假设有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

// 假设多次调用 add 函数并且参数都是数字，
// V8 的优化编译器可能会将 add 函数优化，
// 并假设 a 和 b 总是数字。

add(1, 2);
add(3, 4);

// 现在，如果调用 add 函数时传入了字符串，
// V8 可能会触发反优化。
add("hello", "world");
```

在 `add("hello", "world")` 触发反优化时，`translated-state.cc` 的代码会执行以下类似的操作：

1. **识别栈槽：** 它会读取当前优化后栈帧中存储 `a` 和 `b` 的栈槽。在优化后的代码中，`a` 和 `b` 可能被表示为直接的机器整数。

2. **类型转换：**  根据反优化信息，它知道现在 `a` 和 `b` 实际上是字符串。

3. **对象实例化：** 它会在堆上创建 JavaScript 字符串对象 "hello" 和 "world"。

4. **更新栈帧：** 它会将指向这两个新字符串对象的指针放置到反优化后的栈帧中，以便未优化的 `add` 函数能够正确地访问和处理它们。

文件中 `TranslationOpcode::TAGGED_STACK_SLOT`、`TranslationOpcode::STRING_STACK_SLOT` 以及处理 `LITERAL` 的部分都与这个过程密切相关。例如，当遇到 `STRING_STACK_SLOT` 时，代码会知道需要从栈上读取一个表示字符串的指针，并可能需要进行解压缩等操作。当遇到 `LITERAL` 并且字面量是字符串时，代码会直接获取预先存在的字符串对象。

总而言之，`translated-state.cc` 是 V8 引擎中一个至关重要的组件，它确保了 JavaScript 代码在优化和反优化之间能够平滑过渡，保证了代码的正确执行。

Prompt: 
```
这是目录为v8/src/deoptimizer/translated-state.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      uint32_t value = GetUInt32Slot(fp, slot_offset);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%u ; (uint32) [fp %c %3d] ", value,
               slot_offset < 0 ? '-' : '+', std::abs(slot_offset));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewUint32(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::BOOL_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      uint32_t value = GetUInt32Slot(fp, slot_offset);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%u ; (bool) [fp %c %3d] ", value,
               slot_offset < 0 ? '-' : '+', std::abs(slot_offset));
      }
      TranslatedValue translated_value = TranslatedValue::NewBool(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::FLOAT_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      Float32 value = GetFloatSlot(fp, slot_offset);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%e ; (float) [fp %c %3d] ", value.get_scalar(),
               slot_offset < 0 ? '-' : '+', std::abs(slot_offset));
      }
      TranslatedValue translated_value = TranslatedValue::NewFloat(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::DOUBLE_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      Float64 value = GetDoubleSlot(fp, slot_offset);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%e ; (double) [fp %c %d] ", value.get_scalar(),
               slot_offset < 0 ? '-' : '+', std::abs(slot_offset));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewDouble(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::SIMD128_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      Simd128 value = getSimd128Slot(fp, slot_offset);
      if (trace_file != nullptr) {
        int8x16 val = value.to_i8x16();
        PrintF(trace_file,
               "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x ; (Simd128) [fp %c %d]",
               val.val[0], val.val[1], val.val[2], val.val[3], val.val[4],
               val.val[5], val.val[6], val.val[7], val.val[8], val.val[9],
               val.val[10], val.val[11], val.val[12], val.val[13], val.val[14],
               val.val[15], slot_offset < 0 ? '-' : '+', std::abs(slot_offset));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewSimd128(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::HOLEY_DOUBLE_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      Float64 value = GetDoubleSlot(fp, slot_offset);
      if (trace_file != nullptr) {
        if (value.is_hole_nan()) {
          PrintF(trace_file, "the hole");
        } else {
          PrintF(trace_file, "%e", value.get_scalar());
        }
        PrintF(trace_file, " ; (holey double) [fp %c %d] ",
               slot_offset < 0 ? '-' : '+', std::abs(slot_offset));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewHoleyDouble(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::LITERAL: {
      int literal_index = iterator->NextOperand();
      TranslatedValue translated_value = literal_array.Get(this, literal_index);
      if (trace_file != nullptr) {
        if (translated_value.kind() == TranslatedValue::Kind::kTagged) {
          PrintF(trace_file, V8PRIxPTR_FMT " ; (literal %2d) ",
                 translated_value.raw_literal().ptr(), literal_index);
          ShortPrint(translated_value.raw_literal(), trace_file);
        } else {
          switch (translated_value.kind()) {
            case TranslatedValue::Kind::kDouble:
              if (translated_value.double_value().is_nan()) {
                PrintF(trace_file, "(wasm double literal %f 0x%" PRIx64 ")",
                       translated_value.double_value().get_scalar(),
                       translated_value.double_value().get_bits());
              } else {
                PrintF(trace_file, "(wasm double literal %f)",
                       translated_value.double_value().get_scalar());
              }
              break;
            case TranslatedValue::Kind::kFloat:
              if (translated_value.float_value().is_nan()) {
                PrintF(trace_file, "(wasm float literal %f 0x%x)",
                       translated_value.float_value().get_scalar(),
                       translated_value.float_value().get_bits());
              } else {
                PrintF(trace_file, "(wasm float literal %f)",
                       translated_value.float_value().get_scalar());
              }
              break;
            case TranslatedValue::Kind::kInt64:
              PrintF(trace_file, "(wasm int64 literal %" PRId64 ")",
                     translated_value.int64_value());
              break;
            case TranslatedValue::Kind::kInt32:
              PrintF(trace_file, "(wasm int32 literal %d)",
                     translated_value.int32_value());
              break;
            default:
              PrintF(trace_file, " (wasm literal) ");
              break;
          }
        }
      }
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::OPTIMIZED_OUT: {
      if (trace_file != nullptr) {
        PrintF(trace_file, "(optimized out)");
      }

      TranslatedValue translated_value = TranslatedValue::NewTagged(
          this, ReadOnlyRoots(isolate_).optimized_out());
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }
  }

  FATAL("We should never get here - unexpected deopt info.");
}

Address TranslatedState::DecompressIfNeeded(intptr_t value) {
  if (COMPRESS_POINTERS_BOOL &&
#ifdef V8_TARGET_ARCH_LOONG64
      // The 32-bit compressed values are supposed to be sign-extended on
      // loongarch64.
      is_int32(value)) {
#else
      static_cast<uintptr_t>(value) <= std::numeric_limits<uint32_t>::max()) {
#endif
    return V8HeapCompressionScheme::DecompressTagged(
        isolate(), static_cast<uint32_t>(value));
  } else {
    return value;
  }
}

TranslatedState::TranslatedState(const JavaScriptFrame* frame)
    : purpose_(kFrameInspection) {
  int deopt_index = SafepointEntry::kNoDeoptIndex;
  Tagged<Code> code = frame->LookupCode();
  Tagged<DeoptimizationData> data =
      static_cast<const OptimizedJSFrame*>(frame)->GetDeoptimizationData(
          code, &deopt_index);
  DCHECK(!data.is_null() && deopt_index != SafepointEntry::kNoDeoptIndex);
  DeoptimizationFrameTranslation::Iterator it(
      data->FrameTranslation(), data->TranslationIndex(deopt_index).value());
  int actual_argc = frame->GetActualArgumentCount();
  DeoptimizationLiteralProvider literals(data->LiteralArray());
  Init(frame->isolate(), frame->fp(), frame->fp(), &it,
       data->ProtectedLiteralArray(), literals, nullptr /* registers */,
       nullptr /* trace file */, code->parameter_count_without_receiver(),
       actual_argc);
}

void TranslatedState::Init(
    Isolate* isolate, Address input_frame_pointer, Address stack_frame_pointer,
    DeoptTranslationIterator* iterator,
    Tagged<ProtectedDeoptimizationLiteralArray> protected_literal_array,
    const DeoptimizationLiteralProvider& literal_array,
    RegisterValues* registers, FILE* trace_file, int formal_parameter_count,
    int actual_argument_count) {
  DCHECK(frames_.empty());

  stack_frame_pointer_ = stack_frame_pointer;
  formal_parameter_count_ = formal_parameter_count;
  actual_argument_count_ = actual_argument_count;
  isolate_ = isolate;

  // Read out the 'header' translation.
  TranslationOpcode opcode = iterator->NextOpcode();
  CHECK(TranslationOpcodeIsBegin(opcode));
  iterator->NextOperand();  // Skip the lookback distance.
  int count = iterator->NextOperand();
  frames_.reserve(count);
  iterator->NextOperand();  // Drop JS frames count.

  if (opcode == TranslationOpcode::BEGIN_WITH_FEEDBACK) {
    ReadUpdateFeedback(iterator, literal_array.get_on_heap_literals(),
                       trace_file);
  }

  std::stack<int> nested_counts;

  // Read the frames
  for (int frame_index = 0; frame_index < count; frame_index++) {
    // Read the frame descriptor.
    frames_.push_back(CreateNextTranslatedFrame(
        iterator, protected_literal_array, literal_array, input_frame_pointer,
        trace_file));
    TranslatedFrame& frame = frames_.back();

    // Read the values.
    int values_to_process = frame.GetValueCount();
    while (values_to_process > 0 || !nested_counts.empty()) {
      if (trace_file != nullptr) {
        if (nested_counts.empty()) {
          // For top level values, print the value number.
          PrintF(trace_file,
                 "    %3i: ", frame.GetValueCount() - values_to_process);
        } else {
          // Take care of indenting for nested values.
          PrintF(trace_file, "         ");
          for (size_t j = 0; j < nested_counts.size(); j++) {
            PrintF(trace_file, "  ");
          }
        }
      }

      int nested_count =
          CreateNextTranslatedValue(frame_index, iterator, literal_array,
                                    input_frame_pointer, registers, trace_file);

      if (trace_file != nullptr) {
        PrintF(trace_file, "\n");
      }

      // Update the value count and resolve the nesting.
      values_to_process--;
      if (nested_count > 0) {
        nested_counts.push(values_to_process);
        values_to_process = nested_count;
      } else {
        while (values_to_process == 0 && !nested_counts.empty()) {
          values_to_process = nested_counts.top();
          nested_counts.pop();
        }
      }
    }
  }

  CHECK(!iterator->HasNextOpcode() ||
        TranslationOpcodeIsBegin(iterator->NextOpcode()));
}

void TranslatedState::Prepare(Address stack_frame_pointer) {
  for (auto& frame : frames_) {
    frame.Handlify(isolate());
  }

  if (!feedback_vector_.is_null()) {
    feedback_vector_handle_ = handle(feedback_vector_, isolate());
    feedback_vector_ = FeedbackVector();
  }
  stack_frame_pointer_ = stack_frame_pointer;

  UpdateFromPreviouslyMaterializedObjects();
}

TranslatedValue* TranslatedState::GetValueByObjectIndex(int object_index) {
  CHECK_LT(static_cast<size_t>(object_index), object_positions_.size());
  TranslatedState::ObjectPosition pos = object_positions_[object_index];
  return &(frames_[pos.frame_index_].values_[pos.value_index_]);
}

Handle<HeapObject> TranslatedState::ResolveStringConcat(TranslatedValue* slot) {
  CHECK_EQ(TranslatedValue::kUninitialized, slot->materialization_state());

  int index = slot->string_concat_index();
  TranslatedState::ObjectPosition pos = string_concat_positions_[index];
  int value_index = pos.value_index_;

  TranslatedFrame* frame = &(frames_[pos.frame_index_]);
  DCHECK_EQ(slot, &(frame->values_[value_index]));

  // TODO(dmercadier): try to avoid the recursive GetValue call.
  value_index++;
  TranslatedValue* left_slot = &(frame->values_[value_index]);
  Handle<Object> left = left_slot->GetValue();

  // Skipping the left input that we've just processed. Note that we can't just
  // do `value_index++`, because the left input could itself be a dematerialized
  // string concatenation, in which case it will occupy multiple slots.
  SkipSlots(1, frame, &value_index);

  TranslatedValue* right_slot = &(frame->values_[value_index]);
  Handle<Object> right = right_slot->GetValue();

  Handle<String> result =
      isolate()
          ->factory()
          ->NewConsString(Cast<String>(left), Cast<String>(right))
          .ToHandleChecked();

  slot->set_initialized_storage(result);
  return result;
}

Handle<HeapObject> TranslatedState::InitializeObjectAt(TranslatedValue* slot) {
  DisallowGarbageCollection no_gc;

  slot = ResolveCapturedObject(slot);
  if (slot->materialization_state() != TranslatedValue::kFinished) {
    std::stack<int> worklist;
    worklist.push(slot->object_index());
    slot->mark_finished();

    while (!worklist.empty()) {
      int index = worklist.top();
      worklist.pop();
      InitializeCapturedObjectAt(index, &worklist, no_gc);
    }
  }
  return slot->storage();
}

void TranslatedState::InitializeCapturedObjectAt(
    int object_index, std::stack<int>* worklist,
    const DisallowGarbageCollection& no_gc) {
  CHECK_LT(static_cast<size_t>(object_index), object_positions_.size());
  TranslatedState::ObjectPosition pos = object_positions_[object_index];
  int value_index = pos.value_index_;

  TranslatedFrame* frame = &(frames_[pos.frame_index_]);
  TranslatedValue* slot = &(frame->values_[value_index]);
  value_index++;

  CHECK_EQ(TranslatedValue::kFinished, slot->materialization_state());
  CHECK_EQ(TranslatedValue::kCapturedObject, slot->kind());

  // Ensure all fields are initialized.
  int children_init_index = value_index;
  for (int i = 0; i < slot->GetChildrenCount(); i++) {
    // If the field is an object that has not been initialized yet, queue it
    // for initialization (and mark it as such).
    TranslatedValue* child_slot = frame->ValueAt(children_init_index);
    if (child_slot->kind() == TranslatedValue::kCapturedObject ||
        child_slot->kind() == TranslatedValue::kDuplicatedObject) {
      child_slot = ResolveCapturedObject(child_slot);
      if (child_slot->materialization_state() != TranslatedValue::kFinished) {
        DCHECK_EQ(TranslatedValue::kAllocated,
                  child_slot->materialization_state());
        worklist->push(child_slot->object_index());
        child_slot->mark_finished();
      }
    }
    SkipSlots(1, frame, &children_init_index);
  }

  // Read the map.
  // The map should never be materialized, so let us check we already have
  // an existing object here.
  CHECK_EQ(frame->values_[value_index].kind(), TranslatedValue::kTagged);
  auto map = Cast<Map>(frame->values_[value_index].GetValue());
  CHECK(IsMap(*map));
  value_index++;

  // Handle the special cases.
  switch (map->instance_type()) {
    case HEAP_NUMBER_TYPE:
    case FIXED_DOUBLE_ARRAY_TYPE:
      return;

    case FIXED_ARRAY_TYPE:
    case AWAIT_CONTEXT_TYPE:
    case BLOCK_CONTEXT_TYPE:
    case CATCH_CONTEXT_TYPE:
    case DEBUG_EVALUATE_CONTEXT_TYPE:
    case EVAL_CONTEXT_TYPE:
    case FUNCTION_CONTEXT_TYPE:
    case MODULE_CONTEXT_TYPE:
    case NATIVE_CONTEXT_TYPE:
    case SCRIPT_CONTEXT_TYPE:
    case WITH_CONTEXT_TYPE:
    case OBJECT_BOILERPLATE_DESCRIPTION_TYPE:
    case HASH_TABLE_TYPE:
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
    case NAME_DICTIONARY_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case PROPERTY_ARRAY_TYPE:
    case SCRIPT_CONTEXT_TABLE_TYPE:
    case SLOPPY_ARGUMENTS_ELEMENTS_TYPE:
      InitializeObjectWithTaggedFieldsAt(frame, &value_index, slot, map, no_gc);
      break;

    default:
      CHECK(IsJSObjectMap(*map));
      InitializeJSObjectAt(frame, &value_index, slot, map, no_gc);
      break;
  }
  CHECK_EQ(value_index, children_init_index);
}

void TranslatedState::EnsureObjectAllocatedAt(TranslatedValue* slot) {
  slot = ResolveCapturedObject(slot);

  if (slot->materialization_state() == TranslatedValue::kUninitialized) {
    std::stack<int> worklist;
    worklist.push(slot->object_index());
    slot->mark_allocated();

    while (!worklist.empty()) {
      int index = worklist.top();
      worklist.pop();
      EnsureCapturedObjectAllocatedAt(index, &worklist);
    }
  }
}

int TranslatedValue::GetSmiValue() const {
  Tagged<Object> value = GetRawValue();
  CHECK(IsSmi(value));
  return Cast<Smi>(value).value();
}

void TranslatedState::MaterializeFixedDoubleArray(TranslatedFrame* frame,
                                                  int* value_index,
                                                  TranslatedValue* slot,
                                                  DirectHandle<Map> map) {
  int length = frame->values_[*value_index].GetSmiValue();
  (*value_index)++;
  Handle<FixedDoubleArray> array =
      Cast<FixedDoubleArray>(isolate()->factory()->NewFixedDoubleArray(length));
  CHECK_GT(length, 0);
  for (int i = 0; i < length; i++) {
    CHECK_NE(TranslatedValue::kCapturedObject,
             frame->values_[*value_index].kind());
    Handle<Object> value = frame->values_[*value_index].GetValue();
    if (IsNumber(*value)) {
      array->set(i, Object::NumberValue(*value));
    } else {
      CHECK(value.is_identical_to(isolate()->factory()->the_hole_value()));
      array->set_the_hole(isolate(), i);
    }
    (*value_index)++;
  }
  slot->set_storage(array);
}

void TranslatedState::MaterializeHeapNumber(TranslatedFrame* frame,
                                            int* value_index,
                                            TranslatedValue* slot) {
  CHECK_NE(TranslatedValue::kCapturedObject,
           frame->values_[*value_index].kind());
  DirectHandle<Object> value = frame->values_[*value_index].GetValue();
  CHECK(IsNumber(*value));
  Handle<HeapNumber> box =
      isolate()->factory()->NewHeapNumber(Object::NumberValue(*value));
  (*value_index)++;
  slot->set_storage(box);
}

namespace {

enum StorageKind : uint8_t { kStoreTagged, kStoreHeapObject };

}  // namespace

void TranslatedState::SkipSlots(int slots_to_skip, TranslatedFrame* frame,
                                int* value_index) {
  while (slots_to_skip > 0) {
    TranslatedValue* slot = &(frame->values_[*value_index]);
    (*value_index)++;
    slots_to_skip--;

    if (slot->kind() == TranslatedValue::kCapturedObject ||
        slot->kind() == TranslatedValue::kCapturedStringConcat) {
      slots_to_skip += slot->GetChildrenCount();
    }
  }
}

void TranslatedState::EnsureCapturedObjectAllocatedAt(
    int object_index, std::stack<int>* worklist) {
  CHECK_LT(static_cast<size_t>(object_index), object_positions_.size());
  TranslatedState::ObjectPosition pos = object_positions_[object_index];
  int value_index = pos.value_index_;

  TranslatedFrame* frame = &(frames_[pos.frame_index_]);
  TranslatedValue* slot = &(frame->values_[value_index]);
  value_index++;

  CHECK_EQ(TranslatedValue::kAllocated, slot->materialization_state());
  CHECK_EQ(TranslatedValue::kCapturedObject, slot->kind());

  // Read the map.
  // The map should never be materialized, so let us check we already have
  // an existing object here.
  CHECK_EQ(frame->values_[value_index].kind(), TranslatedValue::kTagged);
  auto map = Cast<Map>(frame->values_[value_index].GetValue());
  CHECK(IsMap(*map));
  value_index++;

  // Handle the special cases.
  switch (map->instance_type()) {
    case FIXED_DOUBLE_ARRAY_TYPE:
      // Materialize (i.e. allocate&initialize) the array and return since
      // there is no need to process the children.
      return MaterializeFixedDoubleArray(frame, &value_index, slot, map);

    case HEAP_NUMBER_TYPE:
      // Materialize (i.e. allocate&initialize) the heap number and return.
      // There is no need to process the children.
      return MaterializeHeapNumber(frame, &value_index, slot);

    case FIXED_ARRAY_TYPE:
    case SCRIPT_CONTEXT_TABLE_TYPE:
    case AWAIT_CONTEXT_TYPE:
    case BLOCK_CONTEXT_TYPE:
    case CATCH_CONTEXT_TYPE:
    case DEBUG_EVALUATE_CONTEXT_TYPE:
    case EVAL_CONTEXT_TYPE:
    case FUNCTION_CONTEXT_TYPE:
    case MODULE_CONTEXT_TYPE:
    case NATIVE_CONTEXT_TYPE:
    case SCRIPT_CONTEXT_TYPE:
    case WITH_CONTEXT_TYPE:
    case HASH_TABLE_TYPE:
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
    case NAME_DICTIONARY_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE: {
      // Check we have the right size.
      int array_length = frame->values_[value_index].GetSmiValue();
      int instance_size = FixedArray::SizeFor(array_length);
      CHECK_EQ(instance_size, slot->GetChildrenCount() * kTaggedSize);

      // Canonicalize empty fixed array.
      if (*map == ReadOnlyRoots(isolate()).empty_fixed_array()->map() &&
          array_length == 0) {
        slot->set_storage(isolate()->factory()->empty_fixed_array());
      } else {
        slot->set_storage(AllocateStorageFor(slot));
      }

      // Make sure all the remaining children (after the map) are allocated.
      return EnsureChildrenAllocated(slot->GetChildrenCount() - 1, frame,
                                     &value_index, worklist);
    }

    case SLOPPY_ARGUMENTS_ELEMENTS_TYPE: {
      // Verify that the arguments size is correct.
      int args_length = frame->values_[value_index].GetSmiValue();
      int args_size = SloppyArgumentsElements::SizeFor(args_length);
      CHECK_EQ(args_size, slot->GetChildrenCount() * kTaggedSize);

      slot->set_storage(AllocateStorageFor(slot));

      // Make sure all the remaining children (after the map) are allocated.
      return EnsureChildrenAllocated(slot->GetChildrenCount() - 1, frame,
                                     &value_index, worklist);
    }

    case PROPERTY_ARRAY_TYPE: {
      // Check we have the right size.
      int length_or_hash = frame->values_[value_index].GetSmiValue();
      int array_length = PropertyArray::LengthField::decode(length_or_hash);
      int instance_size = PropertyArray::SizeFor(array_length);
      CHECK_EQ(instance_size, slot->GetChildrenCount() * kTaggedSize);

      slot->set_storage(AllocateStorageFor(slot));

      // Make sure all the remaining children (after the map) are allocated.
      return EnsureChildrenAllocated(slot->GetChildrenCount() - 1, frame,
                                     &value_index, worklist);
    }

    default:
      EnsureJSObjectAllocated(slot, map);
      int remaining_children_count = slot->GetChildrenCount() - 1;

      TranslatedValue* properties_slot = frame->ValueAt(value_index);
      value_index++, remaining_children_count--;
      if (properties_slot->kind() == TranslatedValue::kCapturedObject) {
        // We are materializing the property array, so make sure we put the
        // mutable heap numbers at the right places.
        EnsurePropertiesAllocatedAndMarked(properties_slot, map);
        EnsureChildrenAllocated(properties_slot->GetChildrenCount(), frame,
                                &value_index, worklist);
      } else {
        CHECK_EQ(properties_slot->kind(), TranslatedValue::kTagged);
      }

      TranslatedValue* elements_slot = frame->ValueAt(value_index);
      value_index++, remaining_children_count--;
      if (elements_slot->kind() == TranslatedValue::kCapturedObject ||
          !IsJSArrayMap(*map)) {
        // Handle this case with the other remaining children below.
        value_index--, remaining_children_count++;
      } else {
        CHECK_EQ(elements_slot->kind(), TranslatedValue::kTagged);
        elements_slot->GetValue();
        if (purpose_ == kFrameInspection) {
          // We are materializing a JSArray for the purpose of frame inspection.
          // If we were to construct it with the above elements value then an
          // actual deopt later on might create another JSArray instance with
          // the same elements store. That would violate the key assumption
          // behind left-trimming.
          elements_slot->ReplaceElementsArrayWithCopy();
        }
      }

      // Make sure all the remaining children (after the map, properties store,
      // and possibly elements store) are allocated.
      return EnsureChildrenAllocated(remaining_children_count, frame,
                                     &value_index, worklist);
  }
  UNREACHABLE();
}

void TranslatedValue::ReplaceElementsArrayWithCopy() {
  DCHECK_EQ(kind(), TranslatedValue::kTagged);
  DCHECK_EQ(materialization_state(), TranslatedValue::kFinished);
  auto elements = Cast<FixedArrayBase>(GetValue());
  DCHECK(IsFixedArray(*elements) || IsFixedDoubleArray(*elements));
  if (IsFixedDoubleArray(*elements)) {
    DCHECK(!elements->IsCowArray());
    set_storage(isolate()->factory()->CopyFixedDoubleArray(
        Cast<FixedDoubleArray>(elements)));
  } else if (!elements->IsCowArray()) {
    set_storage(
        isolate()->factory()->CopyFixedArray(Cast<FixedArray>(elements)));
  }
}

void TranslatedState::EnsureChildrenAllocated(int count, TranslatedFrame* frame,
                                              int* value_index,
                                              std::stack<int>* worklist) {
  // Ensure all children are allocated.
  for (int i = 0; i < count; i++) {
    // If the field is an object that has not been allocated yet, queue it
    // for initialization (and mark it as such).
    TranslatedValue* child_slot = frame->ValueAt(*value_index);
    if (child_slot->kind() == TranslatedValue::kCapturedObject ||
        child_slot->kind() == TranslatedValue::kDuplicatedObject) {
      child_slot = ResolveCapturedObject(child_slot);
      if (child_slot->materialization_state() ==
          TranslatedValue::kUninitialized) {
        worklist->push(child_slot->object_index());
        child_slot->mark_allocated();
      }
    } else {
      // Make sure the simple values (heap numbers, etc.) are properly
      // initialized.
      child_slot->GetValue();
    }
    SkipSlots(1, frame, value_index);
  }
}

void TranslatedState::EnsurePropertiesAllocatedAndMarked(
    TranslatedValue* properties_slot, DirectHandle<Map> map) {
  CHECK_EQ(TranslatedValue::kUninitialized,
           properties_slot->materialization_state());

  Handle<ByteArray> object_storage = AllocateStorageFor(properties_slot);
  properties_slot->mark_allocated();
  properties_slot->set_storage(object_storage);

  DisallowGarbageCollection no_gc;
  Tagged<Map> raw_map = *map;
  Tagged<ByteArray> raw_object_storage = *object_storage;

  // Set markers for out-of-object properties.
  Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate());
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    FieldIndex index = FieldIndex::ForDescriptor(raw_map, i);
    Representation representation = descriptors->GetDetails(i).representation();
    if (!index.is_inobject() &&
        (representation.IsDouble() || representation.IsHeapObject())) {
      int outobject_index = index.outobject_array_index();
      int array_index = outobject_index * kTaggedSize;
      raw_object_storage->set(array_index, kStoreHeapObject);
    }
  }
}

Handle<ByteArray> TranslatedState::AllocateStorageFor(TranslatedValue* slot) {
  int allocate_size =
      ByteArray::LengthFor(slot->GetChildrenCount() * kTaggedSize);
  // It is important to allocate all the objects tenured so that the marker
  // does not visit them.
  Handle<ByteArray> object_storage =
      isolate()->factory()->NewByteArray(allocate_size, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  Tagged<ByteArray> raw_object_storage = *object_storage;
  for (int i = 0; i < object_storage->length(); i++) {
    raw_object_storage->set(i, kStoreTagged);
  }
  return object_storage;
}

void TranslatedState::EnsureJSObjectAllocated(TranslatedValue* slot,
                                              DirectHandle<Map> map) {
  CHECK(IsJSObjectMap(*map));
  CHECK_EQ(map->instance_size(), slot->GetChildrenCount() * kTaggedSize);

  Handle<ByteArray> object_storage = AllocateStorageFor(slot);

  // Now we handle the interesting (JSObject) case.
  DisallowGarbageCollection no_gc;
  Tagged<Map> raw_map = *map;
  Tagged<ByteArray> raw_object_storage = *object_storage;
  Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate());

  // Set markers for in-object properties.
  for (InternalIndex i : raw_map->IterateOwnDescriptors()) {
    FieldIndex index = FieldIndex::ForDescriptor(raw_map, i);
    Representation representation = descriptors->GetDetails(i).representation();
    if (index.is_inobject() &&
        (representation.IsDouble() || representation.IsHeapObject())) {
      CHECK_GE(index.index(), OFFSET_OF_DATA_START(FixedArray) / kTaggedSize);
      int array_index =
          index.index() * kTaggedSize - OFFSET_OF_DATA_START(FixedArray);
      raw_object_storage->set(array_index, kStoreHeapObject);
    }
  }
  slot->set_storage(object_storage);
}

TranslatedValue* TranslatedState::GetResolvedSlot(TranslatedFrame* frame,
                                                  int value_index) {
  TranslatedValue* slot = frame->ValueAt(value_index);
  if (slot->kind() == TranslatedValue::kDuplicatedObject) {
    slot = ResolveCapturedObject(slot);
  }
  CHECK_NE(slot->materialization_state(), TranslatedValue::kUninitialized);
  return slot;
}

TranslatedValue* TranslatedState::GetResolvedSlotAndAdvance(
    TranslatedFrame* frame, int* value_index) {
  TranslatedValue* slot = GetResolvedSlot(frame, *value_index);
  SkipSlots(1, frame, value_index);
  return slot;
}

Handle<Object> TranslatedState::GetValueAndAdvance(TranslatedFrame* frame,
                                                   int* value_index) {
  TranslatedValue* slot = GetResolvedSlot(frame, *value_index);
  SkipSlots(1, frame, value_index);
  return slot->GetValue();
}

void TranslatedState::InitializeJSObjectAt(
    TranslatedFrame* frame, int* value_index, TranslatedValue* slot,
    DirectHandle<Map> map, const DisallowGarbageCollection& no_gc) {
  auto object_storage = Cast<HeapObject>(slot->storage_);
  DCHECK_EQ(TranslatedValue::kCapturedObject, slot->kind());
  int children_count = slot->GetChildrenCount();

  // The object should have at least a map and some payload.
  CHECK_GE(children_count, 2);

#if DEBUG
  // No need to invalidate slots in object because no slot was recorded yet.
  // Verify this here.
  Address object_start = object_storage->address();
  Address object_end = object_start + children_count * kTaggedSize;
  isolate()->heap()->VerifySlotRangeHasNoRecordedSlots(object_start,
                                                       object_end);
#endif  // DEBUG

  // Notify the concurrent marker about the layout change.
  isolate()->heap()->NotifyObjectLayoutChange(
      *object_storage, no_gc, InvalidateRecordedSlots::kNo,
      InvalidateExternalPointerSlots::kNo);

  // Finish any sweeping so that it becomes safe to overwrite the ByteArray
  // headers. See chromium:1228036.
  isolate()->heap()->EnsureSweepingCompletedForObject(*object_storage);

  // Fill the property array field.
  {
    DirectHandle<Object> properties = GetValueAndAdvance(frame, value_index);
    WRITE_FIELD(*object_storage, JSObject::kPropertiesOrHashOffset,
                *properties);
    WRITE_BARRIER(*object_storage, JSObject::kPropertiesOrHashOffset,
                  *properties);
  }

  // For all the other fields we first look at the fixed array and check the
  // marker to see if we store an unboxed double.
  DCHECK_EQ(kTaggedSize, JSObject::kPropertiesOrHashOffset);
  for (int i = 2; i < children_count; i++) {
    slot = GetResolvedSlotAndAdvance(frame, value_index);
    // Read out the marker and ensure the field is consistent with
    // what the markers in the storage say (note that all heap numbers
    // should be fully initialized by now).
    int offset = i * kTaggedSize;
    uint8_t marker = object_storage->ReadField<uint8_t>(offset);
#ifdef V8_ENABLE_SANDBOX
#ifdef V8_ENABLE_LEAPTIERING
    if (InstanceTypeChecker::IsJSFunction(map->instance_type()) &&
        offset == JSFunction::kDispatchHandleOffset) {
      // The JSDispatchHandle will be materialized as a number, but we need
      // the raw value here. TODO(saelo): can we implement "proper" support
      // for JSDispatchHandles in the deoptimizer?
      DirectHandle<Object> field_value = slot->GetValue();
      CHECK(IsNumber(*field_value));
      JSDispatchHandle handle = Object::NumberValue(Cast<Number>(*field_value));
      object_storage->WriteField<JSDispatchHandle>(
          JSFunction::kDispatchHandleOffset, handle);
#else
    if (InstanceTypeChecker::IsJSFunction(map->instance_type()) &&
        offset == JSFunction::kCodeOffset) {
      // We're materializing a JSFunction's reference to a Code object. This is
      // an indirect pointer, so need special handling. TODO(saelo) generalize
      // this, for example by introducing a new kStoreIndirectPointer marker
      // value.
      DirectHandle<HeapObject> field_value = slot->storage();
      CHECK(IsCode(*field_value));
      Tagged<Code> value = Cast<Code>(*field_value);
      object_storage->RawIndirectPointerField(offset, kCodeIndirectPointerTag)
          .Relaxed_Store(value);
      INDIRECT_POINTER_WRITE_BARRIER(*object_storage, offset,
                                     kCodeIndirectPointerTag, value);
#endif  // V8_ENABLE_LEAPTIERING
    } else if (InstanceTypeChecker::IsJSRegExp(map->instance_type()) &&
               offset == JSRegExp::kDataOffset) {
      DirectHandle<HeapObject> field_value = slot->storage();
      // If the value comes from the DeoptimizationLiteralArray, it is a
      // RegExpDataWrapper as we can't store TrustedSpace values in a FixedArray
      // directly.
      Tagged<RegExpData> value;
      if (Is<RegExpDataWrapper>(*field_value)) {
        value = Cast<RegExpDataWrapper>(*field_value)->data(isolate());
      } else {
        CHECK(IsRegExpData(*field_value));
        value = Cast<RegExpData>(*field_value);
      }
      object_storage
          ->RawIndirectPointerField(offset, kRegExpDataIndirectPointerTag)
          .Relaxed_Store(value);
      INDIRECT_POINTER_WRITE_BARRIER(*object_storage, offset,
                                     kRegExpDataIndirectPointerTag, value);
    } else if (marker == kStoreHeapObject) {
#else
    if (marker == kStoreHeapObject) {
#endif  // V8_ENABLE_SANDBOX
      DirectHandle<HeapObject> field_value = slot->storage();
      WRITE_FIELD(*object_storage, offset, *field_value);
      WRITE_BARRIER(*object_storage, offset, *field_value);
    } else {
      CHECK_EQ(kStoreTagged, marker);
      DirectHandle<Object> field_value = slot->GetValue();
      DCHECK_IMPLIES(IsHeapNumber(*field_value),
                     !IsSmiDouble(Object::NumberValue(*field_value)));
      WRITE_FIELD(*object_storage, offset, *field_value);
      WRITE_BARRIER(*object_storage, offset, *field_value);
    }
  }
  object_storage->set_map(isolate(), *map, kReleaseStore);
}

void TranslatedState::InitializeObjectWithTaggedFieldsAt(
    TranslatedFrame* frame, int* value_index, TranslatedValue* slot,
    DirectHandle<Map> map, const DisallowGarbageCollection& no_gc) {
  auto object_storage = Cast<HeapObject>(slot->storage_);
  int children_count = slot->GetChildrenCount();

  // Skip the writes if we already have the canonical empty fixed array.
  if (*object_storage == ReadOnlyRoots(isolate()).empty_fixed_array()) {
    CHECK_EQ(2, children_count);
    DirectHandle<Object> length_value = GetValueAndAdvance(frame, value_index);
    CHECK_EQ(*length_value, Smi::FromInt(0));
    return;
  }

#if DEBUG
  // No need to invalidate slots in object because no slot was recorded yet.
  // Verify this here.
  Address object_start = object_storage->address();
  Address object_end = object_start + children_count * kTaggedSize;
  isolate()->heap()->VerifySlotRangeHasNoRecordedSlots(object_start,
                                                       object_end);
#endif  // DEBUG

  // Notify the concurrent marker about the layout change.
  isolate()->heap()->NotifyObjectLayoutChange(
      *object_storage, no_gc, InvalidateRecordedSlots::kNo,
      InvalidateExternalPointerSlots::kNo);

  // Finish any sweeping so that it becomes safe to overwrite the ByteArray
  // headers. See chromium:1228036.
  isolate()->heap()->EnsureSweepingCompletedForObject(*object_storage);

  // Write the fields to the object.
  for (int i = 1; i < children_count; i++) {
    slot = GetResolvedSlotAndAdvance(frame, value_index);
    int offset = i * kTaggedSize;
    uint8_t marker = object_storage->ReadField<uint8_t>(offset);
    DirectHandle<Object> field_value;
    if (i > 1 && marker == kStoreHeapObject) {
      field_value = slot->storage();
    } else {
      CHECK(marker == kStoreTagged || i == 1);
      field_value = slot->GetValue();
      DCHECK_IMPLIES(IsHeapNumber(*field_value),
                     !IsSmiDouble(Object::NumberValue(*field_value)));
    }
    WRITE_FIELD(*object_storage, offset, *field_value);
    WRITE_BARRIER(*object_storage, offset, *field_value);
  }

  object_storage->set_map(isolate(), *map, kReleaseStore);
}

TranslatedValue* TranslatedState::ResolveCapturedObject(TranslatedValue* slot) {
  while (slot->kind() == TranslatedValue::kDuplicatedObject) {
    slot = GetValueByObjectIndex(slot->object_index());
  }
  CHECK_EQ(TranslatedValue::kCapturedObject, slot->kind());
  return slot;
}

TranslatedFrame* TranslatedState::GetFrameFromJSFrameIndex(int jsframe_index) {
  for (size_t i = 0; i < frames_.size(); i++) {
    if (frames_[i].kind() == TranslatedFrame::kUnoptimizedFunction ||
        frames_[i].kind() == TranslatedFrame::kJavaScriptBuiltinContinuation ||
        frames_[i].kind() ==
            TranslatedFrame::kJavaScriptBuiltinContinuationWithCatch) {
      if (jsframe_index > 0) {
        jsframe_index--;
      } else {
        return &(frames_[i]);
      }
    }
  }
  return nullptr;
}

TranslatedFrame* TranslatedState::GetArgumentsInfoFromJSFrameIndex(
    int jsframe_index, int* args_count) {
  for (size_t i = 0; i < frames_.size(); i++) {
    if (frames_[i].kind() == TranslatedFrame::kUnoptimizedFunction ||
        frames_[i].kind() == TranslatedFrame::kJavaScriptBuiltinContinuation ||
        frames_[i].kind() ==
            TranslatedFrame::kJavaScriptBuiltinContinuationWithCatch) {
      if (jsframe_index > 0) {
        jsframe_index--;
      } else {
        // We have the JS function frame, now check if it has arguments
        // adaptor.
        if (i > 0 &&
            frames_[i - 1].kind() == TranslatedFrame::kInlinedExtraArguments) {
          *args_count = frames_[i - 1].height();
          return &(frames_[i - 1]);
        }

        // JavaScriptBuiltinContinuation frames that are not preceeded by
        // a arguments adapter frame are currently only used by C++ API calls
        // from TurboFan. Calls to C++ API functions from TurboFan need
        // a special marker frame state, otherwise the API call wouldn't
        // be shown in a stack trace.
        if (frames_[i].kind() ==
            TranslatedFrame::kJavaScriptBuiltinContinuation) {
          DCHECK(frames_[i].shared_info()->IsDontAdaptArguments());
          DCHECK(frames_[i].shared_info()->IsApiFunction());

          // The argument count for this special case is always the second
          // to last value in the TranslatedFrame. It should also always be
          // {1}, as the GenericLazyDeoptContinuation builtin has one explicit
          // argument (the result).
          static constexpr int kTheContext = 1;
          const uint32_t height = frames_[i].height() + kTheContext;
          *args_count = frames_[i].ValueAt(height - 1)->GetSmiValue();
          DCHECK_EQ(*args_count, JSParameterCount(1));
          return &(frames_[i]);
        }

        DCHECK_EQ(frames_[i].kind(), TranslatedFrame::kUnoptimizedFunction);
        *args_count = frames_[i].bytecode_array()->parameter_count();
        return &(frames_[i]);
      }
    }
  }
  return nullptr;
}

void TranslatedState::StoreMaterializedValuesAndDeopt(JavaScriptFrame* frame) {
  MaterializedObjectStore* materialized_store =
      isolate_->materialized_object_store();
  Handle<FixedArray> previously_materialized_objects =
      materialized_store->Get(stack_frame_pointer_);

  Handle<Object> marker = isolate_->factory()->arguments_marker();

  int length = static_cast<int>(object_positions_.size());
  bool new_store = false;
  if (previously_materialized_objects.is_null()) {
    previously_materialized_objects =
        isolate_->factory()->NewFixedArray(length, AllocationType::kOld);
    for (int i = 0; i < length; i++) {
      previously_materialized_objects->set(i, *marker);
    }
    new_store = true;
  }

  CHECK_EQ(length, previously_materialized_objects->length());

  bool value_changed = false;
  for (int i = 0; i < length; i++) {
    TranslatedState::ObjectPosition pos = object_positions_[i];
    TranslatedValue* value_info =
        &(frames_[pos.frame_index_].values_[pos.value_index_]);

    CHECK(value_info->IsMaterializedObject());

    // Skip duplicate objects (i.e., those that point to some other object id).
    if (value_info->object_index() != i) continue;

    DirectHandle<Object> previous_value(previously_materialized_objects->get(i),
                                        isolate_);
    Handle<Object> value(value_info->GetRawValue(), isolate_);

    if (value.is_identical_to(marker)) {
      DCHECK_EQ(*previous_value, *marker);
    } else {
      if (*previous_value == *marker) {
        if (IsSmi(*value)) {
          value =
              isolate()->factory()->NewHeapNumber(Object::NumberValue(*value));
        }
        previously_materialized_objects->set(i, *value);
        value_changed = true;
      } else {
        CHECK(*previous_value == *value ||
              (IsHeapNumber(*previous_value) && IsSmi(*value) &&
               Object::NumberValue(*previous_value) ==
                   Object::NumberValue(*value)));
      }
    }
  }

  if (new_store && value_changed) {
    materialized_store->Set(stack_frame_pointer_,
                            previously_materialized_objects);
    CHECK_EQ(frames_[0].kind(), TranslatedFrame::kUnoptimizedFunction);
    CHECK_EQ(frame->function(), frames_[0].front().GetRawValue());
    Deoptimizer::DeoptimizeFunction(frame->function(), frame->LookupCode());
  }
}

void TranslatedState::UpdateFromPreviouslyMaterializedObjects() {
  MaterializedObjectStore* materialized_store =
      isolate_->materialized_object_store();
  Handle<FixedArray> previously_materialized_objects =
      materialized_store->Get(stack_frame_pointer_);

  // If we have no previously materialized objects, there is nothing to do.
  if (previously_materialized_objects.is_null()) return;

  DirectHandle<Object> marker = isolate_->factory()->arguments_marker();

  int length = static_cast<int>(object_positions_.size());
  CHECK_EQ(length, previously_materialized_objects->length());

  for (int i = 0; i < length; i++) {
    // For a previously materialized objects, inject their value into the
    // translated values.
    if (previously_materialized_objects->get(i) != *marker) {
      TranslatedState::ObjectPosition pos = object_positions_[i];
      TranslatedValue* value_info =
          &(frames_[pos.frame_index_].values_[pos.value_index_]);
      CHECK(value_info->IsMaterializedObject());

      if (value_info->kind() == TranslatedValue::kCapturedObject) {
        Handle<Object> object(previously_materialized_objects->get(i),
                              isolate_);
        CHECK(IsHeapObject(*object));
        value_info->set_initialized_storage(Cast<HeapObject>(object));
      }
    }
  }
}

void TranslatedState::VerifyMaterializedObjects() {
#if VERIFY_HEAP
  if (!v8_flags.verify_heap) return;
  int length = static_cast<int>(object_positions_.size());
  for (int i = 0; i < length; i++) {
    TranslatedValue* slot = GetValueByObjectIndex(i);
    if (slot->kind() == TranslatedValue::kCapturedObject) {
      CHECK_EQ(slot, GetValueByObjectIndex(slot->object_index()));
      if (slot->materialization_state() == TranslatedValue::kFinished) {
        Object::ObjectVerify(*slot->storage(), isolate());
      } else {
        CHECK_EQ(slot->materialization_state(),
                 TranslatedValue::kUninitialized);
      }
    }
  }
#endif
}

bool TranslatedState::DoUpdateFeedback() {
  if (!feedback_vector_handle_.is_null()) {
    CHECK(!feedback_slot_.IsInvalid());
    isolate()->CountUsage(v8::Isolate::kDeoptimizerDisableSpeculation);
    FeedbackNexus nexus(isolate(), feedback_vector_handle_, feedback_slot_);
    nexus.SetSpeculationMode(SpeculationMode::kDisallowSpeculation);
    return true;
  }
  return false;
}

void TranslatedState::ReadUpdateFeedback(
    DeoptTranslationIterator* iterator,
    Tagged<DeoptimizationLiteralArray> literal_array, FILE* trace_file) {
  CHECK_EQ(TranslationOpcode::UPDATE_FEEDBACK, iterator->NextOpcode());
  feedback_vector_ =
      Cast<FeedbackVector>(literal_array->get(iterator->NextOperand()));
  feedback_slot_ = FeedbackSlot(iterator->NextOperand());
  if (trace_file != nullptr) {
    PrintF(trace_file, "  reading FeedbackVector (slot %d)\n",
           feedback_slot_.ToInt());
  }
}

}  // namespace internal
}  // namespace v8

// Undefine the heap manipulation macros.
#include "src/objects/object-macros-undef.h"

"""


```