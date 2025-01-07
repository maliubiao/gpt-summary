Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/wasm-compiler.cc`. I need to go through the code and identify the main purpose of each function and group them thematically.

Here's a breakdown of my thought process to generate the answer:

1. **Identify the File's Purpose:** The filename `wasm-compiler.cc` within the `v8/src/compiler` directory strongly suggests this code is involved in the compilation of WebAssembly (Wasm) code within the V8 JavaScript engine.

2. **Examine Class Structure:** The code defines a class `WasmGraphBuilder`. This class seems central to the code's functionality. The name suggests it's responsible for building a graph representation of Wasm code. The `gasm_` member variable of type `GraphAssembler` reinforces this idea.

3. **Analyze Function Categories:**  I will go through each function in the provided snippet and try to categorize its functionality. Common prefixes or suffixes in the function names can be helpful here.

    * **String Manipulation:**  A significant portion of the code deals with string operations: `StringEncodeWtf8`, `StringToUtf8Array`, `StringEncodeWtf16`, `StringAsWtf16`, `StringEncodeWtf16Array`, `StringConcat`, `StringEqual`, `StringIsUSVSequence`, `StringAsWtf8`, `StringViewWtf8Advance`, `StringViewWtf8Encode`, `StringViewWtf8Slice`, `StringViewWtf16GetCodeUnit`, `StringCodePointAt`, `StringViewWtf16Encode`, `StringViewWtf16Slice`, `StringAsIter`, `StringViewIterNext`, `StringViewIterAdvance`, `StringViewIterRewind`, `StringViewIterSlice`, `StringCompare`, `StringFromCharCode`, `StringFromCodePoint`, `StringHash`. These functions appear to be wrappers around built-in V8 string functionalities, adapted for Wasm's string representation.

    * **String Helper Functions:** Functions like `AssertNotNull` seem to be utility functions for ensuring non-null values, often used before invoking other string operations.

    * **Thread Management:**  `BuildModifyThreadInWasmFlagHelper` and `BuildModifyThreadInWasmFlag` likely deal with managing a flag indicating whether the current thread is executing Wasm code. This is crucial for the correct operation of the trap handler and potentially other V8 subsystems.

    * **Assertions and Error Handling:** The `Assert` function allows for adding debug-time checks and triggering aborts if conditions are not met.

    * **Well-Known Built-ins:** Functions prefixed with `WellKnown_`  (`WellKnown_StringIndexOf`, `WellKnown_StringToLocaleLowerCaseStringref`, `WellKnown_StringToLowerCaseStringref`, `WellKnown_ParseFloat`, `WellKnown_DoubleToString`, `WellKnown_IntToString`)  suggest calls to standard JavaScript built-in functions, adapted for use within the Wasm compilation pipeline.

    * **i31 Operations:**  `RefI31`, `I31GetS`, and `I31GetU` deal with the WebAssembly `i31ref` type, representing a signed 31-bit integer.

    * **Type Setting:** `SetType` is used to explicitly set the type of a node in the graph being built.

    * **Debugging and Decoration:** `AddBytecodePositionDecorator` and `RemoveBytecodePositionDecorator` are for adding debugging information to the generated graph, linking nodes back to the original Wasm bytecode.

    * **Wrapper Specific:** The `WasmWrapperGraphBuilder` class appears to be a specialized version of `WasmGraphBuilder` used for generating wrapper code, likely for calling Wasm functions from JavaScript or vice-versa. It has specific handling for built-in calls and integer conversions.

4. **Check for Torque:** The prompt explicitly asks about Torque. I need to check if the filename ends with `.tq`. In this case, it ends with `.cc`, so it's a standard C++ file, not a Torque file.

5. **JavaScript Relationship:**  The prompt also asks about the relationship with JavaScript. Many of the functions directly interact with V8's built-in string and number handling mechanisms, which are core parts of JavaScript. The `WellKnown_` functions explicitly call JavaScript built-ins. I can create JavaScript examples to illustrate how these functionalities are related.

6. **Code Logic and Examples:**  For functions that involve logic, such as the string manipulation or i31 operations, I can devise simple input and output examples to demonstrate their behavior.

7. **Common Programming Errors:**  For potential user errors, I should focus on areas where developers interacting with Wasm might make mistakes, such as null checks or incorrect handling of string encodings.

8. **Summarize Functionality:**  Finally, I need to synthesize all the identified functionalities into a concise summary. The summary should emphasize the role of `wasm-compiler.cc` in the Wasm compilation process within V8.

9. **Address "Part 9 of 12":** The prompt mentions this is part 9 of 12. This suggests the surrounding parts likely cover other aspects of the Wasm compilation process. I should briefly acknowledge this context in the summary.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
```cpp
Node* WasmGraphBuilder::StringEncodeWtf8(const wasm::WasmMemory* memory,
                                          unibrow::Utf8Variant variant,
                                          Node* string,
                                          CheckForNull null_check, Node* offset,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf8,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            offset, gasm_->SmiConstant(memory->index),
                            gasm_->SmiConstant(static_cast<int32_t>(variant)));
}

Node* WasmGraphBuilder::StringEncodeWtf8Array(Node* string,
                                               CheckForNull null_check,
                                               Node* array,
                                               CheckForNull array_null_check,
                                               Node* start,
                                               unibrow::Utf8Variant variant,
                                               wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  if (array_null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf8Array,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            array, start,
                            gasm_->SmiConstant(static_cast<int32_t>(variant)));
}

Node* WasmGraphBuilder::StringToUtf8Array(Node* string, CheckForNull null_check,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringToUtf8Array,
                            Operator::kNoDeopt | Operator::kNoThrow, string);
}

Node* WasmGraphBuilder::StringEncodeWtf16(const wasm::WasmMemory* memory,
                                          Node* string, CheckForNull null_check,
                                          Node* offset,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf16,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            offset, gasm_->Int32Constant(memory->index));
}

Node* WasmGraphBuilder::StringAsWtf16(Node* string, CheckForNull null_check,
                                      wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->StringAsWtf16(string);
}

Node* WasmGraphBuilder::StringEncodeWtf16Array(
    Node* string, CheckForNull string_null_check, Node* array,
    CheckForNull array_null_check, Node* start,
    wasm::WasmCodePosition position) {
  if (string_null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  if (array_null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf16Array,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            array, start);
}

Node* WasmGraphBuilder::StringConcat(Node* head, CheckForNull head_null_check,
                                     Node* tail, CheckForNull tail_null_check,
                                     wasm::WasmCodePosition position) {
  if (head_null_check == kWithNullCheck) {
    head = AssertNotNull(head, wasm::kWasmStringRef, position);
  }
  if (tail_null_check == kWithNullCheck) {
    tail = AssertNotNull(tail, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(
      Builtin::kStringAdd_CheckNone, Operator::kNoDeopt | Operator::kNoThrow,
      head, tail,
      LOAD_INSTANCE_FIELD(NativeContext, MachineType::TaggedPointer()));
}

Node* WasmGraphBuilder::StringEqual(Node* a, wasm::ValueType a_type, Node* b,
                                    wasm::ValueType b_type,
                                    wasm::WasmCodePosition position) {
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);
  // Covers "identical string pointer" and "both are null" cases.
  gasm_->GotoIf(gasm_->TaggedEqual(a, b), &done, Int32Constant(1));
  if (a_type.is_nullable()) {
    gasm_->GotoIf(gasm_->IsNull(a, a_type), &done, Int32Constant(0));
  }
  if (b_type.is_nullable()) {
    gasm_->GotoIf(gasm_->IsNull(b, b_type), &done, Int32Constant(0));
  }
  // TODO(jkummerow): Call Builtin::kStringEqual directly.
  gasm_->Goto(&done, gasm_->CallBuiltin(Builtin::kWasmStringEqual,
                                        Operator::kEliminatable, a, b));
  gasm_->Bind(&done);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::StringIsUSVSequence(Node* str, CheckForNull null_check,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    str = AssertNotNull(str, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringIsUSVSequence,
                            Operator::kEliminatable, str);
}

Node* WasmGraphBuilder::StringAsWtf8(Node* str, CheckForNull null_check,
                                     wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    str = AssertNotNull(str, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringAsWtf8, Operator::kEliminatable,
                            str);
}

Node* WasmGraphBuilder::StringViewWtf8Advance(Node* view,
                                              CheckForNull null_check,
                                              Node* pos, Node* bytes,
                                              wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf8Advance,
                            Operator::kEliminatable, view, pos, bytes);
}

void WasmGraphBuilder::StringViewWtf8Encode(
    const wasm::WasmMemory* memory, unibrow::Utf8Variant variant, Node* view,
    CheckForNull null_check, Node* addr, Node* pos, Node* bytes,
    Node** next_pos, Node** bytes_written, wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&addr}, position);
  Node* pair =
      gasm_->CallBuiltin(Builtin::kWasmStringViewWtf8Encode,
                         Operator::kNoDeopt | Operator::kNoThrow, addr, pos,
                         bytes, view, gasm_->SmiConstant(memory->index),
                         gasm_->SmiConstant(static_cast<int32_t>(variant)));
  *next_pos = gasm_->Projection(0, pair);
  *bytes_written = gasm_->Projection(1, pair);
}

Node* WasmGraphBuilder::StringViewWtf8Slice(Node* view, CheckForNull null_check,
                                            Node* pos, Node* bytes,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf8Slice,
                            Operator::kEliminatable, view, pos, bytes);
}

Node* WasmGraphBuilder::StringViewWtf16GetCodeUnit(
    Node* string, CheckForNull null_check, Node* offset,
    wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  Node* prepare = gasm_->StringPrepareForGetCodeunit(string);
  Node* base = gasm_->Projection(0, prepare);
  Node* base_offset = gasm_->Projection(1, prepare);
  Node* charwidth_shift = gasm_->Projection(2, prepare);

  // Bounds check.
  Node* length = gasm_->LoadStringLength(string);
  TrapIfFalse(wasm::kTrapStringOffsetOutOfBounds,
              gasm_->Uint32LessThan(offset, length), position);

  auto onebyte = gasm_->MakeLabel();
  auto bailout = gasm_->MakeDeferredLabel();
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);
  gasm_->GotoIf(
      gasm_->Word32Equal(charwidth_shift,
                         gasm_->Int32Constant(kCharWidthBailoutSentinel)),
      &bailout);
  gasm_->GotoIf(gasm_->Word32Equal(charwidth_shift, gasm_->Int32Constant(0)),
                &onebyte);

  // Two-byte.
  Node* object_offset =
      gasm_->IntAdd(gasm_->IntMul(gasm_->BuildChangeInt32ToIntPtr(offset),
                                  gasm_->IntPtrConstant(2)),
                    base_offset);
  Node* result = gasm_->LoadImmutableFromObject(MachineType::Uint16(), base,
                                                object_offset);
  gasm_->Goto(&done, result);

  // One-byte.
  gasm_->Bind(&onebyte);
  object_offset =
      gasm_->IntAdd(gasm_->BuildChangeInt32ToIntPtr(offset), base_offset);
  result =
      gasm_->LoadImmutableFromObject(MachineType::Uint8(), base, object_offset);
  gasm_->Goto(&done, result);

  gasm_->Bind(&bailout);
  gasm_->Goto(&done, gasm_->CallBuiltinThroughJumptable(
                         Builtin::kWasmStringViewWtf16GetCodeUnit,
                         Operator::kEliminatable, string, offset));

  gasm_->Bind(&done);
  // Make sure the original string is kept alive as long as we're operating
  // on pointers extracted from it (otherwise e.g. external strings' resources
  // might get freed prematurely).
  gasm_->Retain(string);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::StringCodePointAt(Node* string, CheckForNull null_check,
                                          Node* offset,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  Node* prepare = gasm_->StringPrepareForGetCodeunit(string);
  Node* base = gasm_->Projection(0, prepare);
  Node* base_offset = gasm_->Projection(1, prepare);
  Node* charwidth_shift = gasm_->Projection(2, prepare);

  // Bounds check.
  Node* length = gasm_->LoadStringLength(string);
  TrapIfFalse(wasm::kTrapStringOffsetOutOfBounds,
              gasm_->Uint32LessThan(offset, length), position);

  auto onebyte = gasm_->MakeLabel();
  auto bailout = gasm_->MakeDeferredLabel();
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);
  gasm_->GotoIf(
      gasm_->Word32Equal(charwidth_shift,
                         gasm_->Int32Constant(kCharWidthBailoutSentinel)),
      &bailout);
  gasm_->GotoIf(gasm_->Word32Equal(charwidth_shift, gasm_->Int32Constant(0)),
                &onebyte);

  // Two-byte.
  Node* object_offset =
      gasm_->IntAdd(gasm_->IntMul(gasm_->BuildChangeInt32ToIntPtr(offset),
                                  gasm_->IntPtrConstant(2)),
                    base_offset);
  Node* lead = gasm_->LoadImmutableFromObject(MachineType::Uint16(), base,
                                              object_offset);
  Node* is_lead_surrogate =
      gasm_->Word32Equal(gasm_->Word32And(lead, gasm_->Int32Constant(0xFC00)),
                         gasm_->Int32Constant(0xD800));
  gasm_->GotoIfNot(is_lead_surrogate, &done, lead);
  Node* trail_offset = gasm_->Int32Add(offset, gasm_->Int32Constant(1));
  gasm_->GotoIfNot(gasm_->Uint32LessThan(trail_offset, length), &done, lead);
  Node* trail = gasm_->LoadImmutableFromObject(
      MachineType::Uint16(), base,
      gasm_->IntAdd(object_offset, gasm_->IntPtrConstant(2)));
  Node* is_trail_surrogate =
      gasm_->WordEqual(gasm_->Word32And(trail, gasm_->Int32Constant(0xFC00)),
                       gasm_->Int32Constant(0xDC00));
  gasm_->GotoIfNot(is_trail_surrogate, &done, lead);
  Node* surrogate_bias =
      gasm_->Int32Constant(0x10000 - (0xD800 << 10) - 0xDC00);
  Node* result =
      gasm_->Int32Add(gasm_->Word32Shl(lead, gasm_->Int32Constant(10)),
                      gasm_->Int32Add(trail, surrogate_bias));
  gasm_->Goto(&done, result);

  // One-byte.
  gasm_->Bind(&onebyte);
  object_offset =
      gasm_->IntAdd(gasm_->BuildChangeInt32ToIntPtr(offset), base_offset);
  result =
      gasm_->LoadImmutableFromObject(MachineType::Uint8(), base, object_offset);
  gasm_->Goto(&done, result);

  gasm_->Bind(&bailout);
  gasm_->Goto(&done, gasm_->CallBuiltinThroughJumptable(
                         Builtin::kWasmStringCodePointAt,
                         Operator::kEliminatable, string, offset));

  gasm_->Bind(&done);
  // Make sure the original string is kept alive as long as we're operating
  // on pointers extracted from it (otherwise e.g. external strings' resources
  // might get freed prematurely).
  gasm_->Retain(string);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::StringViewWtf16Encode(const wasm::WasmMemory* memory,
                                              Node* string,
                                              CheckForNull null_check,
                                              Node* offset, Node* start,
                                              Node* codeunits,
                                              wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf16Encode,
                            Operator::kNoDeopt | Operator::kNoThrow, offset,
                            start, codeunits, string,
                            gasm_->SmiConstant(memory->index));
}

Node* WasmGraphBuilder::StringViewWtf16Slice(Node* string,
                                             CheckForNull null_check,
                                             Node* start, Node* end,
                                             wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf16Slice,
                            Operator::kEliminatable, string, start, end);
}

Node* WasmGraphBuilder::StringAsIter(Node* str, CheckForNull null_check,
                                     wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    str = AssertNotNull(str, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringAsIter, Operator::kEliminatable,
                            str);
}

Node* WasmGraphBuilder::StringViewIterNext(Node* view, CheckForNull null_check,
                                           wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterNext,
                            Operator::kEliminatable, view);
}

Node* WasmGraphBuilder::StringViewIterAdvance(Node* view,
                                              CheckForNull null_check,
                                              Node* codepoints,
                                              wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterAdvance,
                            Operator::kEliminatable, view, codepoints);
}

Node* WasmGraphBuilder::StringViewIterRewind(Node* view,
                                             CheckForNull null_check,
                                             Node* codepoints,
                                             wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterRewind,
                            Operator::kEliminatable, view, codepoints);
}

Node* WasmGraphBuilder::StringViewIterSlice(Node* view, CheckForNull null_check,
                                            Node* codepoints,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterSlice,
                            Operator::kEliminatable, view, codepoints);
}

Node* WasmGraphBuilder::StringCompare(Node* lhs, CheckForNull null_check_lhs,
                                      Node* rhs, CheckForNull null_check_rhs,
                                      wasm::WasmCodePosition position) {
  if (null_check_lhs == kWithNullCheck) {
    lhs = AssertNotNull(lhs, wasm::kWasmStringRef, position);
  }
  if (null_check_rhs == kWithNullCheck) {
    rhs = AssertNotNull(rhs, wasm::kWasmStringRef, position);
  }
  return gasm_->BuildChangeSmiToInt32(gasm_->CallBuiltin(
      Builtin::kStringCompare, Operator::kEliminatable, lhs, rhs));
}

Node* WasmGraphBuilder::StringFromCharCode(Node* char_code) {
  Node* capped = gasm_->Word32And(char_code, gasm_->Uint32Constant(0xFFFF));
  return gasm_->CallBuiltin(Builtin::kWasmStringFromCodePoint,
                            Operator::kEliminatable, capped);
}

Node* WasmGraphBuilder::StringFromCodePoint(Node* code_point) {
  // TODO(jkummerow): Refactor the code in
  // EffectControlLinearizer::LowerStringFromSingleCodePoint to make it
  // accessible for Wasm.
  // This call traps when the {code_point} is invalid.
  return gasm_->CallBuiltin(Builtin::kWasmStringFromCodePoint,
                            Operator::kNoDeopt | Operator::kNoWrite,
                            code_point);
}

Node* WasmGraphBuilder::StringHash(Node* string, CheckForNull null_check,
                                   wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }

  auto runtime_label = gasm_->MakeLabel();
  auto end_label = gasm_->MakeLabel(MachineRepresentation::kWord32);

  Node* raw_hash = gasm_->LoadFromObject(
      MachineType::Int32(), string,
      wasm::ObjectAccess::ToTagged(offsetof(Name, raw_hash_field_)));
  Node* hash_not_computed_mask =
      gasm_->Int32Constant(static_cast<int32_t>(Name::kHashNotComputedMask));
  static_assert(Name::HashFieldTypeBits::kShift == 0);
  Node* hash_not_computed = gasm_->Word32And(raw_hash, hash_not_computed_mask);
  gasm_->GotoIf(hash_not_computed, &runtime_label);

  // Fast path if hash is already computed: Decode raw hash value.
  static_assert(Name::HashBits::kLastUsedBit == kBitsPerInt - 1);
  Node* hash = gasm_->Word32Shr(
      raw_hash,
      gasm_->Int32Constant(static_cast<int32_t>(Name::HashBits::kShift)));
  gasm_->Goto(&end_label, hash);

  gasm_->Bind(&runtime_label);
  Node* hash_runtime = gasm_->CallBuiltin(Builtin::kWasmStringHash,
                                          Operator::kEliminatable, string);
  gasm_->Goto(&end_label, hash_runtime);

  gasm_->Bind(&end_label);
  return end_label.PhiAt(0);
}

void WasmGraphBuilder::BuildModifyThreadInWasmFlagHelper(
    Node* thread_in_wasm_flag_address, bool new_value) {
  if (v8_flags.debug_code) {
    Node* flag_value =
        gasm_->Load(MachineType::Int32(), thread_in_wasm_flag_address, 0);
    Node* check =
        gasm_->Word32Equal(flag_value, Int32Constant(new_value ? 0 : 1));
    Assert(check, new_value ? AbortReason::kUnexpectedThreadInWasmSet
                            : AbortReason::kUnexpectedThreadInWasmUnset);
  }

  gasm_->Store({MachineRepresentation::kWord32, kNoWriteBarrier},
               thread_in_wasm_flag_address, 0,
               Int32Constant(new_value ? 1 : 0));
}

void WasmGraphBuilder::BuildModifyThreadInWasmFlag(bool new_value) {
  if (!trap_handler::IsTrapHandlerEnabled()) return;
  Node* isolate_root = BuildLoadIsolateRoot();

  Node* thread_in_wasm_flag_address =
      gasm_->Load(MachineType::Pointer(), isolate_root,
                  Isolate::thread_in_wasm_flag_address_offset());

  BuildModifyThreadInWasmFlagHelper(thread_in_wasm_flag_address, new_value);
}

void WasmGraphBuilder::Assert(Node* condition, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  Diamond check(graph(), mcgraph()->common(), condition, BranchHint::kTrue);
  check.Chain(control());
  SetControl(check.if_false);
  Node* message_id = gasm_->NumberConstant(static_cast<int32_t>(abort_reason));
  Node* old_effect = effect();
  Node* call = BuildCallToRuntimeWithContext(
      Runtime::kAbort, NoContextConstant(), &message_id, 1);
  check.merge->ReplaceInput(1, call);
  SetEffectControl(check.EffectPhi(old_effect, effect()), check.merge);
}

Node* WasmGraphBuilder::WellKnown_StringIndexOf(
    Node* string, Node* search, Node* start, CheckForNull string_null_check,
    CheckForNull search_null_check) {
  if (string_null_check == kWithNullCheck) {
    // If string is null, throw.
    auto if_not_null = gasm_->MakeLabel();
    auto if_null = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(IsNull(string, wasm::kWasmStringRef), &if_null);
    gasm_->Goto(&if_not_null);
    gasm_->Bind(&if_null);
    gasm_->CallBuiltin(Builtin::kThrowIndexOfCalledOnNull, Operator::kNoWrite);
    gasm_->Unreachable();
    gasm_->Bind(&if_not_null);
  }
  if (search_null_check == kWithNullCheck) {
    // If search is null, replace it with "null".
    auto search_not_null =
        gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
    gasm_->GotoIfNot(IsNull(search, wasm::kWasmStringRef), &search_not_null,
                     search);
    Node* null_string = LOAD_ROOT(null_string, null_string);
    gasm_->Goto(&search_not_null, null_string);
    gasm_->Bind(&search_not_null);
    search = search_not_null.PhiAt(0);
  }
  {
    // Clamp the start index.
    auto clamped_start = gasm_->MakeLabel(MachineRepresentation::kWord32);
    gasm_->GotoIf(gasm_->Int32LessThan(start, Int32Constant(0)), &clamped_start,
                  Int32Constant(0));
    Node* length = gasm_->LoadStringLength(string);
    gasm_->GotoIf(gasm_->Int32LessThan(start, length), &clamped_start, start);
    gasm_->Goto(&clamped_start, length);
    gasm_->Bind(&clamped_start);
    start = clamped_start.PhiAt(0);
  }

  BuildModifyThreadInWasmFlag(false);
  // This can't overflow because we've clamped {start} above.
  Node* start_smi = gasm_->BuildChangeInt32ToSmi(start);
  Node* result =
      gasm_->CallBuiltin(Builtin::kStringIndexOf, Operator::kEliminatable,
                         string, search, start_smi);
  BuildModifyThreadInWasmFlag(true);
  return gasm_->BuildChangeSmiToInt32(result);
}

Node* WasmGraphBuilder::WellKnown_StringToLocaleLowerCaseStringref(
    int func_index, Node* string, Node* locale,
    CheckForNull string_null_check) {
#if V8_INTL_SUPPORT
  if (string_null_check == kWithNullCheck) {
    // We can let the builtin throw the exception, but it only checks for
    // JS null, so we must externalize any Wasm null here.
    // Externalizing the {locale} is not required, because
    // {Object::ConvertToString} has been taught how to deal with WasmNull.
    string = gasm_->WasmExternConvertAny(string);
  }
  int param_count = 2;  // String, locale.
  CallDescriptor* call_descriptor = Linkage::GetJSCallDescriptor(
      zone_, false, param_count, CallDescriptor::kCanUseRoots,
      Operator::kNoDeopt | Operator::kNoWrite);
  Node* callees_array =
      LOAD_INSTANCE_FIELD(WellKnownImports, MachineType::TaggedPointer());
  Node* callee = gasm_->LoadFixedArrayElementPtr(callees_array, func_index);
  Node* context = gasm_->LoadContextFromJSFunction(callee);
  BuildModifyThreadInWasmFlag(
Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共12部分，请归纳一下它的功能

"""
osition);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf8Array,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            array, start,
                            gasm_->SmiConstant(static_cast<int32_t>(variant)));
}

Node* WasmGraphBuilder::StringToUtf8Array(Node* string, CheckForNull null_check,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringToUtf8Array,
                            Operator::kNoDeopt | Operator::kNoThrow, string);
}

Node* WasmGraphBuilder::StringEncodeWtf16(const wasm::WasmMemory* memory,
                                          Node* string, CheckForNull null_check,
                                          Node* offset,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf16,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            offset, gasm_->Int32Constant(memory->index));
}

Node* WasmGraphBuilder::StringAsWtf16(Node* string, CheckForNull null_check,
                                      wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->StringAsWtf16(string);
}

Node* WasmGraphBuilder::StringEncodeWtf16Array(
    Node* string, CheckForNull string_null_check, Node* array,
    CheckForNull array_null_check, Node* start,
    wasm::WasmCodePosition position) {
  if (string_null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  if (array_null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf16Array,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            array, start);
}

Node* WasmGraphBuilder::StringConcat(Node* head, CheckForNull head_null_check,
                                     Node* tail, CheckForNull tail_null_check,
                                     wasm::WasmCodePosition position) {
  if (head_null_check == kWithNullCheck) {
    head = AssertNotNull(head, wasm::kWasmStringRef, position);
  }
  if (tail_null_check == kWithNullCheck) {
    tail = AssertNotNull(tail, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(
      Builtin::kStringAdd_CheckNone, Operator::kNoDeopt | Operator::kNoThrow,
      head, tail,
      LOAD_INSTANCE_FIELD(NativeContext, MachineType::TaggedPointer()));
}

Node* WasmGraphBuilder::StringEqual(Node* a, wasm::ValueType a_type, Node* b,
                                    wasm::ValueType b_type,
                                    wasm::WasmCodePosition position) {
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);
  // Covers "identical string pointer" and "both are null" cases.
  gasm_->GotoIf(gasm_->TaggedEqual(a, b), &done, Int32Constant(1));
  if (a_type.is_nullable()) {
    gasm_->GotoIf(gasm_->IsNull(a, a_type), &done, Int32Constant(0));
  }
  if (b_type.is_nullable()) {
    gasm_->GotoIf(gasm_->IsNull(b, b_type), &done, Int32Constant(0));
  }
  // TODO(jkummerow): Call Builtin::kStringEqual directly.
  gasm_->Goto(&done, gasm_->CallBuiltin(Builtin::kWasmStringEqual,
                                        Operator::kEliminatable, a, b));
  gasm_->Bind(&done);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::StringIsUSVSequence(Node* str, CheckForNull null_check,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    str = AssertNotNull(str, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringIsUSVSequence,
                            Operator::kEliminatable, str);
}

Node* WasmGraphBuilder::StringAsWtf8(Node* str, CheckForNull null_check,
                                     wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    str = AssertNotNull(str, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringAsWtf8, Operator::kEliminatable,
                            str);
}

Node* WasmGraphBuilder::StringViewWtf8Advance(Node* view,
                                              CheckForNull null_check,
                                              Node* pos, Node* bytes,
                                              wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf8Advance,
                            Operator::kEliminatable, view, pos, bytes);
}

void WasmGraphBuilder::StringViewWtf8Encode(
    const wasm::WasmMemory* memory, unibrow::Utf8Variant variant, Node* view,
    CheckForNull null_check, Node* addr, Node* pos, Node* bytes,
    Node** next_pos, Node** bytes_written, wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&addr}, position);
  Node* pair =
      gasm_->CallBuiltin(Builtin::kWasmStringViewWtf8Encode,
                         Operator::kNoDeopt | Operator::kNoThrow, addr, pos,
                         bytes, view, gasm_->SmiConstant(memory->index),
                         gasm_->SmiConstant(static_cast<int32_t>(variant)));
  *next_pos = gasm_->Projection(0, pair);
  *bytes_written = gasm_->Projection(1, pair);
}

Node* WasmGraphBuilder::StringViewWtf8Slice(Node* view, CheckForNull null_check,
                                            Node* pos, Node* bytes,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf8Slice,
                            Operator::kEliminatable, view, pos, bytes);
}

Node* WasmGraphBuilder::StringViewWtf16GetCodeUnit(
    Node* string, CheckForNull null_check, Node* offset,
    wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  Node* prepare = gasm_->StringPrepareForGetCodeunit(string);
  Node* base = gasm_->Projection(0, prepare);
  Node* base_offset = gasm_->Projection(1, prepare);
  Node* charwidth_shift = gasm_->Projection(2, prepare);

  // Bounds check.
  Node* length = gasm_->LoadStringLength(string);
  TrapIfFalse(wasm::kTrapStringOffsetOutOfBounds,
              gasm_->Uint32LessThan(offset, length), position);

  auto onebyte = gasm_->MakeLabel();
  auto bailout = gasm_->MakeDeferredLabel();
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);
  gasm_->GotoIf(
      gasm_->Word32Equal(charwidth_shift,
                         gasm_->Int32Constant(kCharWidthBailoutSentinel)),
      &bailout);
  gasm_->GotoIf(gasm_->Word32Equal(charwidth_shift, gasm_->Int32Constant(0)),
                &onebyte);

  // Two-byte.
  Node* object_offset =
      gasm_->IntAdd(gasm_->IntMul(gasm_->BuildChangeInt32ToIntPtr(offset),
                                  gasm_->IntPtrConstant(2)),
                    base_offset);
  Node* result = gasm_->LoadImmutableFromObject(MachineType::Uint16(), base,
                                                object_offset);
  gasm_->Goto(&done, result);

  // One-byte.
  gasm_->Bind(&onebyte);
  object_offset =
      gasm_->IntAdd(gasm_->BuildChangeInt32ToIntPtr(offset), base_offset);
  result =
      gasm_->LoadImmutableFromObject(MachineType::Uint8(), base, object_offset);
  gasm_->Goto(&done, result);

  gasm_->Bind(&bailout);
  gasm_->Goto(&done, gasm_->CallBuiltinThroughJumptable(
                         Builtin::kWasmStringViewWtf16GetCodeUnit,
                         Operator::kEliminatable, string, offset));

  gasm_->Bind(&done);
  // Make sure the original string is kept alive as long as we're operating
  // on pointers extracted from it (otherwise e.g. external strings' resources
  // might get freed prematurely).
  gasm_->Retain(string);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::StringCodePointAt(Node* string, CheckForNull null_check,
                                          Node* offset,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  Node* prepare = gasm_->StringPrepareForGetCodeunit(string);
  Node* base = gasm_->Projection(0, prepare);
  Node* base_offset = gasm_->Projection(1, prepare);
  Node* charwidth_shift = gasm_->Projection(2, prepare);

  // Bounds check.
  Node* length = gasm_->LoadStringLength(string);
  TrapIfFalse(wasm::kTrapStringOffsetOutOfBounds,
              gasm_->Uint32LessThan(offset, length), position);

  auto onebyte = gasm_->MakeLabel();
  auto bailout = gasm_->MakeDeferredLabel();
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);
  gasm_->GotoIf(
      gasm_->Word32Equal(charwidth_shift,
                         gasm_->Int32Constant(kCharWidthBailoutSentinel)),
      &bailout);
  gasm_->GotoIf(gasm_->Word32Equal(charwidth_shift, gasm_->Int32Constant(0)),
                &onebyte);

  // Two-byte.
  Node* object_offset =
      gasm_->IntAdd(gasm_->IntMul(gasm_->BuildChangeInt32ToIntPtr(offset),
                                  gasm_->IntPtrConstant(2)),
                    base_offset);
  Node* lead = gasm_->LoadImmutableFromObject(MachineType::Uint16(), base,
                                              object_offset);
  Node* is_lead_surrogate =
      gasm_->Word32Equal(gasm_->Word32And(lead, gasm_->Int32Constant(0xFC00)),
                         gasm_->Int32Constant(0xD800));
  gasm_->GotoIfNot(is_lead_surrogate, &done, lead);
  Node* trail_offset = gasm_->Int32Add(offset, gasm_->Int32Constant(1));
  gasm_->GotoIfNot(gasm_->Uint32LessThan(trail_offset, length), &done, lead);
  Node* trail = gasm_->LoadImmutableFromObject(
      MachineType::Uint16(), base,
      gasm_->IntAdd(object_offset, gasm_->IntPtrConstant(2)));
  Node* is_trail_surrogate =
      gasm_->WordEqual(gasm_->Word32And(trail, gasm_->Int32Constant(0xFC00)),
                       gasm_->Int32Constant(0xDC00));
  gasm_->GotoIfNot(is_trail_surrogate, &done, lead);
  Node* surrogate_bias =
      gasm_->Int32Constant(0x10000 - (0xD800 << 10) - 0xDC00);
  Node* result =
      gasm_->Int32Add(gasm_->Word32Shl(lead, gasm_->Int32Constant(10)),
                      gasm_->Int32Add(trail, surrogate_bias));
  gasm_->Goto(&done, result);

  // One-byte.
  gasm_->Bind(&onebyte);
  object_offset =
      gasm_->IntAdd(gasm_->BuildChangeInt32ToIntPtr(offset), base_offset);
  result =
      gasm_->LoadImmutableFromObject(MachineType::Uint8(), base, object_offset);
  gasm_->Goto(&done, result);

  gasm_->Bind(&bailout);
  gasm_->Goto(&done, gasm_->CallBuiltinThroughJumptable(
                         Builtin::kWasmStringCodePointAt,
                         Operator::kEliminatable, string, offset));

  gasm_->Bind(&done);
  // Make sure the original string is kept alive as long as we're operating
  // on pointers extracted from it (otherwise e.g. external strings' resources
  // might get freed prematurely).
  gasm_->Retain(string);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::StringViewWtf16Encode(const wasm::WasmMemory* memory,
                                              Node* string,
                                              CheckForNull null_check,
                                              Node* offset, Node* start,
                                              Node* codeunits,
                                              wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf16Encode,
                            Operator::kNoDeopt | Operator::kNoThrow, offset,
                            start, codeunits, string,
                            gasm_->SmiConstant(memory->index));
}

Node* WasmGraphBuilder::StringViewWtf16Slice(Node* string,
                                             CheckForNull null_check,
                                             Node* start, Node* end,
                                             wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf16Slice,
                            Operator::kEliminatable, string, start, end);
}

Node* WasmGraphBuilder::StringAsIter(Node* str, CheckForNull null_check,
                                     wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    str = AssertNotNull(str, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringAsIter, Operator::kEliminatable,
                            str);
}

Node* WasmGraphBuilder::StringViewIterNext(Node* view, CheckForNull null_check,
                                           wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterNext,
                            Operator::kEliminatable, view);
}

Node* WasmGraphBuilder::StringViewIterAdvance(Node* view,
                                              CheckForNull null_check,
                                              Node* codepoints,
                                              wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterAdvance,
                            Operator::kEliminatable, view, codepoints);
}

Node* WasmGraphBuilder::StringViewIterRewind(Node* view,
                                             CheckForNull null_check,
                                             Node* codepoints,
                                             wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterRewind,
                            Operator::kEliminatable, view, codepoints);
}

Node* WasmGraphBuilder::StringViewIterSlice(Node* view, CheckForNull null_check,
                                            Node* codepoints,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterSlice,
                            Operator::kEliminatable, view, codepoints);
}

Node* WasmGraphBuilder::StringCompare(Node* lhs, CheckForNull null_check_lhs,
                                      Node* rhs, CheckForNull null_check_rhs,
                                      wasm::WasmCodePosition position) {
  if (null_check_lhs == kWithNullCheck) {
    lhs = AssertNotNull(lhs, wasm::kWasmStringRef, position);
  }
  if (null_check_rhs == kWithNullCheck) {
    rhs = AssertNotNull(rhs, wasm::kWasmStringRef, position);
  }
  return gasm_->BuildChangeSmiToInt32(gasm_->CallBuiltin(
      Builtin::kStringCompare, Operator::kEliminatable, lhs, rhs));
}

Node* WasmGraphBuilder::StringFromCharCode(Node* char_code) {
  Node* capped = gasm_->Word32And(char_code, gasm_->Uint32Constant(0xFFFF));
  return gasm_->CallBuiltin(Builtin::kWasmStringFromCodePoint,
                            Operator::kEliminatable, capped);
}

Node* WasmGraphBuilder::StringFromCodePoint(Node* code_point) {
  // TODO(jkummerow): Refactor the code in
  // EffectControlLinearizer::LowerStringFromSingleCodePoint to make it
  // accessible for Wasm.
  // This call traps when the {code_point} is invalid.
  return gasm_->CallBuiltin(Builtin::kWasmStringFromCodePoint,
                            Operator::kNoDeopt | Operator::kNoWrite,
                            code_point);
}

Node* WasmGraphBuilder::StringHash(Node* string, CheckForNull null_check,
                                   wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }

  auto runtime_label = gasm_->MakeLabel();
  auto end_label = gasm_->MakeLabel(MachineRepresentation::kWord32);

  Node* raw_hash = gasm_->LoadFromObject(
      MachineType::Int32(), string,
      wasm::ObjectAccess::ToTagged(offsetof(Name, raw_hash_field_)));
  Node* hash_not_computed_mask =
      gasm_->Int32Constant(static_cast<int32_t>(Name::kHashNotComputedMask));
  static_assert(Name::HashFieldTypeBits::kShift == 0);
  Node* hash_not_computed = gasm_->Word32And(raw_hash, hash_not_computed_mask);
  gasm_->GotoIf(hash_not_computed, &runtime_label);

  // Fast path if hash is already computed: Decode raw hash value.
  static_assert(Name::HashBits::kLastUsedBit == kBitsPerInt - 1);
  Node* hash = gasm_->Word32Shr(
      raw_hash,
      gasm_->Int32Constant(static_cast<int32_t>(Name::HashBits::kShift)));
  gasm_->Goto(&end_label, hash);

  gasm_->Bind(&runtime_label);
  Node* hash_runtime = gasm_->CallBuiltin(Builtin::kWasmStringHash,
                                          Operator::kEliminatable, string);
  gasm_->Goto(&end_label, hash_runtime);

  gasm_->Bind(&end_label);
  return end_label.PhiAt(0);
}

void WasmGraphBuilder::BuildModifyThreadInWasmFlagHelper(
    Node* thread_in_wasm_flag_address, bool new_value) {
  if (v8_flags.debug_code) {
    Node* flag_value =
        gasm_->Load(MachineType::Int32(), thread_in_wasm_flag_address, 0);
    Node* check =
        gasm_->Word32Equal(flag_value, Int32Constant(new_value ? 0 : 1));
    Assert(check, new_value ? AbortReason::kUnexpectedThreadInWasmSet
                            : AbortReason::kUnexpectedThreadInWasmUnset);
  }

  gasm_->Store({MachineRepresentation::kWord32, kNoWriteBarrier},
               thread_in_wasm_flag_address, 0,
               Int32Constant(new_value ? 1 : 0));
}

void WasmGraphBuilder::BuildModifyThreadInWasmFlag(bool new_value) {
  if (!trap_handler::IsTrapHandlerEnabled()) return;
  Node* isolate_root = BuildLoadIsolateRoot();

  Node* thread_in_wasm_flag_address =
      gasm_->Load(MachineType::Pointer(), isolate_root,
                  Isolate::thread_in_wasm_flag_address_offset());

  BuildModifyThreadInWasmFlagHelper(thread_in_wasm_flag_address, new_value);
}

void WasmGraphBuilder::Assert(Node* condition, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  Diamond check(graph(), mcgraph()->common(), condition, BranchHint::kTrue);
  check.Chain(control());
  SetControl(check.if_false);
  Node* message_id = gasm_->NumberConstant(static_cast<int32_t>(abort_reason));
  Node* old_effect = effect();
  Node* call = BuildCallToRuntimeWithContext(
      Runtime::kAbort, NoContextConstant(), &message_id, 1);
  check.merge->ReplaceInput(1, call);
  SetEffectControl(check.EffectPhi(old_effect, effect()), check.merge);
}

Node* WasmGraphBuilder::WellKnown_StringIndexOf(
    Node* string, Node* search, Node* start, CheckForNull string_null_check,
    CheckForNull search_null_check) {
  if (string_null_check == kWithNullCheck) {
    // If string is null, throw.
    auto if_not_null = gasm_->MakeLabel();
    auto if_null = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(IsNull(string, wasm::kWasmStringRef), &if_null);
    gasm_->Goto(&if_not_null);
    gasm_->Bind(&if_null);
    gasm_->CallBuiltin(Builtin::kThrowIndexOfCalledOnNull, Operator::kNoWrite);
    gasm_->Unreachable();
    gasm_->Bind(&if_not_null);
  }
  if (search_null_check == kWithNullCheck) {
    // If search is null, replace it with "null".
    auto search_not_null =
        gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
    gasm_->GotoIfNot(IsNull(search, wasm::kWasmStringRef), &search_not_null,
                     search);
    Node* null_string = LOAD_ROOT(null_string, null_string);
    gasm_->Goto(&search_not_null, null_string);
    gasm_->Bind(&search_not_null);
    search = search_not_null.PhiAt(0);
  }
  {
    // Clamp the start index.
    auto clamped_start = gasm_->MakeLabel(MachineRepresentation::kWord32);
    gasm_->GotoIf(gasm_->Int32LessThan(start, Int32Constant(0)), &clamped_start,
                  Int32Constant(0));
    Node* length = gasm_->LoadStringLength(string);
    gasm_->GotoIf(gasm_->Int32LessThan(start, length), &clamped_start, start);
    gasm_->Goto(&clamped_start, length);
    gasm_->Bind(&clamped_start);
    start = clamped_start.PhiAt(0);
  }

  BuildModifyThreadInWasmFlag(false);
  // This can't overflow because we've clamped {start} above.
  Node* start_smi = gasm_->BuildChangeInt32ToSmi(start);
  Node* result =
      gasm_->CallBuiltin(Builtin::kStringIndexOf, Operator::kEliminatable,
                         string, search, start_smi);
  BuildModifyThreadInWasmFlag(true);
  return gasm_->BuildChangeSmiToInt32(result);
}

Node* WasmGraphBuilder::WellKnown_StringToLocaleLowerCaseStringref(
    int func_index, Node* string, Node* locale,
    CheckForNull string_null_check) {
#if V8_INTL_SUPPORT
  if (string_null_check == kWithNullCheck) {
    // We can let the builtin throw the exception, but it only checks for
    // JS null, so we must externalize any Wasm null here.
    // Externalizing the {locale} is not required, because
    // {Object::ConvertToString} has been taught how to deal with WasmNull.
    string = gasm_->WasmExternConvertAny(string);
  }
  int param_count = 2;  // String, locale.
  CallDescriptor* call_descriptor = Linkage::GetJSCallDescriptor(
      zone_, false, param_count, CallDescriptor::kCanUseRoots,
      Operator::kNoDeopt | Operator::kNoWrite);
  Node* callees_array =
      LOAD_INSTANCE_FIELD(WellKnownImports, MachineType::TaggedPointer());
  Node* callee = gasm_->LoadFixedArrayElementPtr(callees_array, func_index);
  Node* context = gasm_->LoadContextFromJSFunction(callee);
  BuildModifyThreadInWasmFlag(false);
  Node* result = gasm_->Call(call_descriptor, callee, string, locale,
                             UndefinedValue(),                   // new.target
                             gasm_->Int32Constant(param_count),  // argc
                             context);                           // context
  BuildModifyThreadInWasmFlag(true);
  return result;
#else
  UNREACHABLE();
#endif
}

Node* WasmGraphBuilder::WellKnown_StringToLowerCaseStringref(
    Node* string, CheckForNull null_check) {
#if V8_INTL_SUPPORT
  BuildModifyThreadInWasmFlag(false);
  if (null_check == kWithNullCheck) {
    auto if_not_null = gasm_->MakeLabel();
    auto if_null = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(IsNull(string, wasm::kWasmStringRef), &if_null);
    gasm_->Goto(&if_not_null);
    gasm_->Bind(&if_null);
    gasm_->CallBuiltin(Builtin::kThrowToLowerCaseCalledOnNull,
                       Operator::kNoWrite);
    gasm_->Unreachable();
    gasm_->Bind(&if_not_null);
  }
  Node* result =
      gasm_->CallBuiltin(Builtin::kStringToLowerCaseIntl,
                         Operator::kEliminatable, string, NoContextConstant());
  BuildModifyThreadInWasmFlag(true);
  return result;
#else
  UNREACHABLE();
#endif
}

Node* WasmGraphBuilder::WellKnown_ParseFloat(Node* string,
                                             CheckForNull null_check) {
  if (null_check == kWithNullCheck) {
    auto done = gasm_->MakeLabel(MachineRepresentation::kFloat64);
    auto if_null = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(IsNull(string, wasm::kWasmStringRef), &if_null);
    BuildModifyThreadInWasmFlag(false);
    Node* result = gasm_->CallBuiltin(Builtin::kWasmStringToDouble,
                                      Operator::kEliminatable, string);
    BuildModifyThreadInWasmFlag(true);
    gasm_->Goto(&done, result);
    gasm_->Bind(&if_null);
    gasm_->Goto(&done,
                Float64Constant(std::numeric_limits<double>::quiet_NaN()));
    gasm_->Bind(&done);
    return done.PhiAt(0);
  } else {
    BuildModifyThreadInWasmFlag(false);
    Node* result = gasm_->CallBuiltin(Builtin::kWasmStringToDouble,
                                      Operator::kEliminatable, string);
    BuildModifyThreadInWasmFlag(true);
    return result;
  }
}

Node* WasmGraphBuilder::WellKnown_DoubleToString(Node* n) {
  BuildModifyThreadInWasmFlag(false);
  Node* result = gasm_->CallBuiltin(Builtin::kWasmFloat64ToString,
                                    Operator::kEliminatable, n);
  BuildModifyThreadInWasmFlag(true);
  return result;
}

Node* WasmGraphBuilder::WellKnown_IntToString(Node* n, Node* radix) {
  BuildModifyThreadInWasmFlag(false);
  Node* result = gasm_->CallBuiltin(Builtin::kWasmIntToString,
                                    Operator::kNoDeopt, n, radix);
  BuildModifyThreadInWasmFlag(true);
  return result;
}

Node* WasmGraphBuilder::RefI31(Node* input) {
  if constexpr (SmiValuesAre31Bits()) {
    return gasm_->Word32Shl(input, gasm_->BuildSmiShiftBitsConstant32());
  } else {
    DCHECK(SmiValuesAre32Bits());
    // Set the topmost bit to sign-extend the second bit. This way,
    // interpretation in JS (if this value escapes there) will be the same as
    // i31.get_s.
    input = gasm_->BuildChangeInt32ToIntPtr(input);
    return gasm_->WordSar(
        gasm_->WordShl(input,
                       gasm_->IntPtrConstant(kSmiShiftSize + kSmiTagSize + 1)),
        gasm_->IntPtrConstant(1));
  }
}

Node* WasmGraphBuilder::I31GetS(Node* input, CheckForNull null_check,
                                wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    input = AssertNotNull(input, wasm::kWasmI31Ref, position);
  }
  if constexpr (SmiValuesAre31Bits()) {
    input = gasm_->BuildTruncateIntPtrToInt32(input);
    return gasm_->Word32SarShiftOutZeros(input,
                                         gasm_->BuildSmiShiftBitsConstant32());
  } else {
    DCHECK(SmiValuesAre32Bits());
    // Topmost bit is already sign-extended.
    return gasm_->BuildTruncateIntPtrToInt32(gasm_->WordSar(
        input, gasm_->IntPtrConstant(kSmiShiftSize + kSmiTagSize)));
  }
}

Node* WasmGraphBuilder::I31GetU(Node* input, CheckForNull null_check,
                                wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    input = AssertNotNull(input, wasm::kWasmI31Ref, position);
  }
  if constexpr (SmiValuesAre31Bits()) {
    input = gasm_->BuildTruncateIntPtrToInt32(input);
    return gasm_->Word32Shr(input, gasm_->BuildSmiShiftBitsConstant32());
  } else {
    DCHECK(SmiValuesAre32Bits());
    // We need to remove the topmost bit of the 32-bit Smi.
    return gasm_->BuildTruncateIntPtrToInt32(
        gasm_->WordShr(gasm_->WordShl(input, gasm_->IntPtrConstant(1)),
                       gasm_->IntPtrConstant(kSmiShiftSize + kSmiTagSize + 1)));
  }
}

Node* WasmGraphBuilder::SetType(Node* node, wasm::ValueType type) {
  DCHECK_NOT_NULL(env_);
  if (!compiler::NodeProperties::IsTyped(node)) {
    compiler::NodeProperties::SetType(
        node, compiler::Type::Wasm(type, env_->module, graph_zone()));
  } else {
    // We might try to set the type twice since some nodes are cached in the
    // graph assembler, but we should never change the type.
    // The exception is imported strings support, which may special-case
    // values that are officially externref-typed as being known to be strings.
#if DEBUG
    static constexpr wasm::ValueType kRefExtern =
        wasm::ValueType::Ref(wasm::HeapType::kExtern);
    DCHECK((compiler::NodeProperties::GetType(node).AsWasm().type == type) ||
           (enabled_features_.has_imported_strings() &&
            compiler::NodeProperties::GetType(node).AsWasm().type ==
                wasm::kWasmRefExternString &&
            (type == wasm::kWasmExternRef || type == kRefExtern)));
#endif
  }
  return node;
}

class WasmDecorator final : public GraphDecorator {
 public:
  explicit WasmDecorator(NodeOriginTable* origins, wasm::Decoder* decoder)
      : origins_(origins), decoder_(decoder) {}

  void Decorate(Node* node) final {
    origins_->SetNodeOrigin(
        node, NodeOrigin("wasm graph creation", "n/a",
                         NodeOrigin::kWasmBytecode, decoder_->position()));
  }

 private:
  compiler::NodeOriginTable* origins_;
  wasm::Decoder* decoder_;
};

void WasmGraphBuilder::AddBytecodePositionDecorator(
    NodeOriginTable* node_origins, wasm::Decoder* decoder) {
  DCHECK_NULL(decorator_);
  decorator_ = graph()->zone()->New<WasmDecorator>(node_origins, decoder);
  graph()->AddDecorator(decorator_);
}

void WasmGraphBuilder::RemoveBytecodePositionDecorator() {
  DCHECK_NOT_NULL(decorator_);
  graph()->RemoveDecorator(decorator_);
  decorator_ = nullptr;
}

namespace {

// A non-null {isolate} signifies that the generated code is treated as being in
// a JS frame for functions like BuildLoadIsolateRoot().
class WasmWrapperGraphBuilder : public WasmGraphBuilder {
 public:
  WasmWrapperGraphBuilder(Zone* zone, MachineGraph* mcgraph,
                          const wasm::CanonicalSig* sig,
                          ParameterMode parameter_mode, Isolate* isolate,
                          compiler::SourcePositionTable* spt)
      : WasmGraphBuilder(nullptr, zone, mcgraph, nullptr, spt, parameter_mode,
                         isolate, wasm::WasmEnabledFeatures::All(), sig) {}

  CallDescriptor* GetBigIntToI64CallDescriptor(bool needs_frame_state) {
    return wasm::GetWasmEngine()->call_descriptors()->GetBigIntToI64Descriptor(
        needs_frame_state);
  }

  Node* GetTargetForBuiltinCall(Builtin builtin) {
    // Per-process shared wrappers don't have access to a jump table, so they
    // can't use kCallWasmRuntimeStub mode.
    return gasm_->GetBuiltinPointerTarget(builtin);
  }

  Node* IsNull(Node* object, wasm::CanonicalValueType type) {
    // We immediately lower null in wrappers, as they do not go through a
    // lowering phase.
    Node* null = type.use_wasm_null() ? LOAD_ROOT(WasmNull, wasm_null)
                                      : LOAD_ROOT(NullValue, null_value);
    return gasm_->TaggedEqual(object, null);
  }

  Node* BuildChangeInt32ToNumber(Node* value) {
    // We expect most integers at runtime to be Smis, so it is important for
    // wrapper performance that Smi conversion be inlined.
    if (SmiValuesAre32Bits()) {
      return gasm_->BuildChangeInt32ToSmi(value);
    }
    DCHECK(SmiValuesAre31Bits());

    auto builtin = gasm_->MakeDeferredLabel();
    auto done = gasm_->MakeLabel(MachineRepresentation::kTagged);

    // Double value to test if value can be a Smi, and if so, to convert it.
    Node* add = gasm_->Int32AddWithOverflow(value, value);
    Node* ovf = gasm_->Projection(1, add);
    gasm_->GotoIf(ovf, &builtin);

    // If it didn't overflow, the result is {2 * value} as pointer-sized value.
    Node* smi_tagged =
        gasm_->BuildChangeInt32ToIntPtr(gasm_->Projection(0, add));
    gasm_->Goto(&done, smi_tagged);

    // Otherwise, call builtin, to convert to a HeapNumber.
    gasm_->Bind(&builtin);
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmInt32ToHeapNumber);
    if (!int32_to_heapnumber_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmInt32ToHeapNumberDescriptor(), 0,
          CallDescriptor::kNoFlags, Operator::kNoProperties,
          StubCallMode::kCallBuiltinPointer);
      int32_to_heapnumber_operator_.set(common->Call(call_descriptor));
    }
    Node* call =
        gasm_->Call(int32_to_heapnumber_operator_.get(), target, value);
    gasm_->Goto(&done, call);
    gasm_->Bind(&done);
    return done.PhiAt(0);
  }

  Node* BuildChangeTaggedToInt32(Node* value, Node* context,
                                 Node* frame_state) {
    // We expect most integers at runtime to be Smis, so it is important for
    // wrapper performance that Smi conversion be inlined.
    auto builtin = gasm_->MakeDeferredLabel();
    auto don
"""


```