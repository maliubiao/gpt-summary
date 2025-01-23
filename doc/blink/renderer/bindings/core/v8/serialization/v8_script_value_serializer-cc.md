Response:
The user wants to understand the functionality of the `v8_script_value_serializer.cc` file in the Chromium Blink engine. They are interested in:

1. **General Functionality**: What does this file do?
2. **Relationship to Web Technologies**: How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logical Reasoning**: If the code performs logic, illustrate with hypothetical inputs and outputs.
4. **Common User Errors**:  Identify situations where users or programmers might misuse this functionality.
5. **Debugging Context**: Explain how a user's actions might lead to this code being executed, serving as debugging clues.
6. **Summarization**: Provide a concise summary of the file's purpose.

Based on the file name and the included headers, the core function seems to be about *serializing* JavaScript values within the Blink renderer, specifically for use with the V8 JavaScript engine. Serialization involves converting in-memory data structures into a format that can be stored or transmitted.

**Plan:**

1. **Identify Core Functionality**: Focus on the `Serialize` method and the types of data being handled.
2. **Relate to Web Technologies**: Explain how serialization is crucial for features like `postMessage`, `IndexedDB`, and `Cache API`, which involve transferring or storing JavaScript values.
3. **Illustrate with Examples**:  Show how serializing objects created in JavaScript (e.g., `Blob`, `ArrayBuffer`) relates to HTML (e.g., `<canvas>`, `<input type="file">`) and how it's used in web APIs. CSS is less directly related but could be involved through Canvas API or custom properties.
4. **Logical Reasoning**:  Consider how the `ExtractTransferable` function works, taking an input JavaScript object and determining if it can be transferred by reference instead of by value. Provide a simple example of an ArrayBuffer being marked for transfer.
5. **User Errors**: Think about common mistakes developers make with transferable objects, like trying to use a transferred ArrayBuffer in the sending context.
6. **Debugging Scenario**: Outline a simple user action, like using `postMessage` with a transferable object, and trace how it might lead to this serializer.
7. **Summarize**:  Provide a concise description of the file's role in the Blink rendering engine.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer.h"

#include "base/auto_reset.h"
#include "base/feature_list.h"
#include "base/numerics/byte_conversions.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/web_blob_info.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_quad.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file_list.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_data.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_message_port.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_handle.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_offscreen_canvas.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_transform_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_writable_stream.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/fileapi/file_list.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix_read_only.h"
#include "third_party/blink/renderer/core/geometry/dom_point.h"
#include "third_party/blink/renderer/core/geometry/dom_point_read_only.h"
#include "third_party/blink/renderer/core/geometry/dom_quad.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_read_only.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_config.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/mojo/mojo_handle.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/transform_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_base.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"

namespace blink {

// The "Blink-side" serialization version, which defines how Blink will behave
// during the serialization process, is in
// SerializedScriptValue::wireFormatVersion. The serialization format has two
// "envelopes": an outer one controlled by Blink and an inner one by V8.
//
// They are formatted as follows:
// [version tag] [Blink version] [version tag] [v8 version] ...
//
// Before version 16, there was only a single envelope and the version number
// for both parts was always equal.
//
// See also V8ScriptValueDeserializer.cpp.
//
// This version number must be incremented whenever any incompatible changes are
// made to how Blink writes data. Purely V8-side changes do not require an
// adjustment to this value.

// static
bool V8ScriptValueSerializer::ExtractTransferable(
    v8::Isolate* isolate,
    v8::Local<v8::Value> object,
    wtf_size_t object_index,
    Transferables& transferables,
    ExceptionState& exception_state) {
  // Validation of Objects implementing an interface, per WebIDL spec 4.1.15.
  if (MessagePort* port = V8MessagePort::ToWrappable(isolate, object)) {
    // Check for duplicate MessagePorts.
    if (transferables.message_ports.Contains(port)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Message port at index " + String::Number(object_index) +
              " is a duplicate of an earlier port.");
      return false;
    }
    transferables.message_ports.push_back(port);
    return true;
  }
  if (MojoHandle* handle = V8MojoHandle::ToWrappable(isolate, object)) {
    // Check for duplicate MojoHandles.
    if (transferables.mojo_handles.Contains(handle)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Mojo handle at index " + String::Number(object_index) +
              " is a duplicate of an earlier handle.");
      return false;
    }
    transferables.mojo_handles.push_back(handle);
    return true;
  }
  if (object->IsArrayBuffer()) {
    DOMArrayBuffer* array_buffer =
        NativeValueTraits<IDLAllowResizable<DOMArrayBuffer>>::NativeValue(
            isolate, object, exception_state);
    if (exception_state.HadException())
      return false;
    if (transferables.array_buffers.Contains(array_buffer)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "ArrayBuffer at index " + String::Number(object_index) +
              " is a duplicate of an earlier ArrayBuffer.");
      return false;
    }
    transferables.array_buffers.push_back(array_buffer);
    return true;
  }
  if (object->IsSharedArrayBuffer()) {
    DOMSharedArrayBuffer* shared_array_buffer =
        NativeValueTraits<IDLAllowResizable<DOMSharedArrayBuffer>>::NativeValue(
            isolate, object, exception_state);
    if (exception_state.HadException())
      return false;
    if (transferables.array_buffers.Contains(shared_array_buffer)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "SharedArrayBuffer at index " + String::Number(object_index) +
              " is a duplicate of an earlier SharedArrayBuffer.");
      return false;
    }
    transferables.array_buffers.push_back(shared_array_buffer);
    return true;
  }
  if (ImageBitmap* image_bitmap = V8ImageBitmap::ToWrappable(isolate, object)) {
    if (transferables.image_bitmaps.Contains(image_bitmap)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "ImageBitmap at index " + String::Number(object_index) +
              " is a duplicate of an earlier ImageBitmap.");
      return false;
    }
    transferables.image_bitmaps.push_back(image_bitmap);
    return true;
  }
  if (OffscreenCanvas* offscreen_canvas =
          V8OffscreenCanvas::ToWrappable(isolate, object)) {
    if (transferables.offscreen_canvases.Contains(offscreen_canvas)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "OffscreenCanvas at index " + String::Number(object_index) +
              " is a duplicate of an earlier OffscreenCanvas.");
      return false;
    }
    transferables.offscreen_canvases.push_back(offscreen_canvas);
    return true;
  }
  if (ReadableStream* stream = V8ReadableStream::ToWrappable(isolate, object)) {
    if (transferables.readable_streams.Contains(stream)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "ReadableStream at index " + String::Number(object_index) +
              " is a duplicate of an earlier ReadableStream.");
      return false;
    }
    transferables.readable_streams.push_back(stream);
    return true;
  }
  if (WritableStream* stream = V8WritableStream::ToWrappable(isolate, object)) {
    if (transferables.writable_streams.Contains(stream)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "WritableStream at index " + String::Number(object_index) +
              " is a duplicate of an earlier WritableStream.");
      return false;
    }
    transferables.writable_streams.push_back(stream);
    return true;
  }
  if (TransformStream* stream =
          V8TransformStream::ToWrappable(isolate, object)) {
    if (transferables.transform_streams.Contains(stream)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "TransformStream at index " + String::Number(object_index) +
              " is a duplicate of an earlier TransformStream.");
      return false;
    }
    transferables.transform_streams.push_back(stream);
    return true;
  }
  return false;
}

V8ScriptValueSerializer::V8ScriptValueSerializer(ScriptState* script_state,
                                                 const Options& options)
    : script_state_(script_state),
      serialized_script_value_(SerializedScriptValue::Create()),
      serializer_(script_state_->GetIsolate(), this),
      transferables_(options.transferables),
      blob_info_array_(options.blob_info),
      wasm_policy_(options.wasm_policy),
      for_storage_(options.for_storage == SerializedScriptValue::kForStorage) {}

scoped_refptr<SerializedScriptValue> V8ScriptValueSerializer::Serialize(
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
#if DCHECK_IS_ON()
  DCHECK(!serialize_invoked_);
  serialize_invoked_ = true;
#endif
  DCHECK(serialized_script_value_);

  // Prepare to transfer the provided transferables.
  PrepareTransfer(exception_state);
  if (exception_state.HadException())
    return nullptr;

  // Write out the file header.
  static_assert(
      SerializedScriptValue::kWireFormatVersion < 0x80,
      "the following calculation depends on the encoded length of the version");
  static_assert(SerializedScriptValue::kWireFormatVersion == 21,
                "Only version 21 is supported.");
  static constexpr size_t kTrailerOffsetPosition =
      1 /* version tag */ + 1 /* version */ + 1 /* trailer offset tag */;
  static constexpr uint8_t kZeroOffset[sizeof(uint64_t) + sizeof(uint32_t)] =
      {};
  WriteTag(kVersionTag);
  WriteUint32(SerializedScriptValue::kWireFormatVersion);
  WriteTag(kTrailerOffsetTag);
  WriteRawBytes(kZeroOffset, sizeof(kZeroOffset));
  serializer_.WriteHeader();

  // Serialize the value and handle errors.
  v8::Isolate* isolate = script_state_->GetIsolate();
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state_),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  bool wrote_value;
  if (!serializer_.WriteValue(script_state_->GetContext(), value)
           .To(&wrote_value)) {
    DCHECK(rethrow_scope.HasCaught());
    return nullptr;
  }
  DCHECK(wrote_value);

  // Finalize the transfer (e.g. detaching array buffers).
  FinalizeTransfer(exception_state);
  if (exception_state.HadException())
    return nullptr;

  if (shared_array_buffers_.size()) {
    auto* execution_context = ExecutionContext::From(script_state_);
    if (!execution_context->CheckSharedArrayBufferTransferAllowedAndReport()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "SharedArrayBuffer transfer requires self.crossOriginIsolated.");
      return nullptr;
    }
  }

  serialized_script_value_->CloneSharedArrayBuffers(shared_array_buffers_);

  // Append the trailer, if applicable.
  Vector<uint8_t> trailer;
  trailer = trailer_writer_.MakeTrailerData();
  if (!trailer.empty()) {
    WriteRawBytes(trailer.data(), trailer.size());
  }

  // Finalize the results.
  auto [buffer_ptr, buffer_size] = serializer_.Release();
  auto buffer =
      // SAFETY: The size from Release() is promised to be the size of the
      // allocation for the returned pointer. The pointer is allocated by the
      // serializer_ delegate which is `this` and `ReallocateBufferMemory`
      // allocates memory such that it can be deleted by the DataBufferPtr's
      // Deleter.
      UNSAFE_BUFFERS(SerializedScriptValue::DataBufferPtr::FromOwningPointer(
          buffer_ptr, buffer_size));
  if (!trailer.empty()) {
    buffer.as_span()
        .subspan<kTrailerOffsetPosition, sizeof(uint64_t)>()
        .copy_from(base::U64ToBigEndian(buffer.size() - trailer.size()));
    buffer.as_span()
        .subspan<kTrailerOffsetPosition + sizeof(uint64_t), sizeof(uint32_t)>()
        .copy_from(base::U32ToBigEndian(trailer.size()));
  }
  serialized_script_value_->SetData(std::move(buffer));
  return std::move(serialized_script_value_);
}

void V8ScriptValueSerializer::PrepareTransfer(ExceptionState& exception_state) {
  if (!transferables_)
    return;

  // Transfer array buffers.
  for (uint32_t i = 0; i < transferables_->array_buffers.size(); i++) {
    DOMArrayBufferBase* array_buffer = transferables_->array_buffers[i].Get();
    if (!array_buffer->IsShared()) {
      v8::Local<v8::Value> wrapper = ToV8Traits<DOMArrayBuffer>::ToV8(
          script_state_, static_cast<DOMArrayBuffer*>(array_buffer));
      serializer_.TransferArrayBuffer(
          i, v8::Local<v8::ArrayBuffer>::Cast(wrapper));
    } else {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "SharedArrayBuffer can not be in transfer list.");
      return;
    }
  }
}

void V8ScriptValueSerializer::FinalizeTransfer(
    ExceptionState& exception_state) {
  // TODO(jbroman): Strictly speaking, this is not correct; transfer should
  // occur in the order of the transfer list.
  // https://html.spec.whatwg.org/C/#structuredclonewithtransfer

  v8::Isolate* isolate = script_state_->GetIsolate();

  ArrayBufferArray array_buffers;
  // The scope object to promptly free the backing store to avoid memory
  // regressions.
  // TODO(bikineev): Revisit after young generation is there.
  struct PromptlyFreeArrayBuffers {
    // The void* is to avoid blink-gc-plugin error.
    void* buffer;
    ~PromptlyFreeArrayBuffers() {
      static_cast<ArrayBufferArray*>(buffer)->clear();
    }
  } promptly_free_array_buffers{&array_buffers};
  if (transferables_)
    array_buffers.AppendVector(transferables_->array_buffers);

  if (!array_buffers.empty()) {
    serialized_script_value_->TransferArrayBuffers(isolate, array_buffers,
                                                   exception_state);
    if (exception_state.HadException())
      return;
  }

  if (transferables_) {
    serialized_script_value_->TransferImageBitmaps(
        isolate, transferables_->image_bitmaps, exception_state);
    if (exception_state.HadException())
      return;

    serialized_script_value_->TransferOffscreenCanvas(
        isolate, transferables_->offscreen_canvases, exception_state);
    if (exception_state.HadException())
      return;

    // Order matters here, because the order in which streams are added to the
    // |stream_ports_| array must match the indexes which are calculated in
    // WriteDOMObject().
    serialized_script_value_->TransferReadableStreams(
        script_state_, transferables_->readable_streams, exception_state);
    if (exception_state.HadException())
      return;
    serialized_script_value_->TransferWritableStreams(
        script_state_, transferables_->writable_streams, exception_state);
    if (exception_state.HadException())
      return;
    serialized_script_value_->TransferTransformStreams(
        script_state_, transferables_->transform_streams, exception_state);
    if (exception_state.HadException())
      return;

    for (auto& transfer_list : transferables_->transfer_lists.Values()) {
      transfer_list->FinalizeTransfer(exception_state);
      if (exception_state.HadException())
        return;
    }
  }
}

void V8ScriptValueSerializer::WriteUnguessableToken(
    const base::UnguessableToken& token) {
  WriteUint64(token.GetHighForSerialization());
  WriteUint64(token.GetLowForSerialization());
}

void V8ScriptValueSerializer::WriteUTF8String(const StringView& string) {
  StringUTF8Adaptor utf8(string);
  WriteUint32(utf8.size());
  WriteRawBytes(utf8.data(), utf8.size());
}

bool V8ScriptValueSerializer::WriteDOMObject(ScriptWrappable* wrappable,
                                             ExceptionState& exception_state) {
  ScriptWrappable::TypeDispatcher dispatcher(wrappable);
  if (auto* blob = dispatcher.ToMostDerived<Blob>()) {
    if (blob_info_array_) {
      size_t index = blob_info_array_->size();
      DCHECK_LE(index, std::numeric_limits<uint32_t>::max());
      blob_info_array_->emplace_back(blob->GetBlobDataHandle(), blob->type(),
                                     blob->size());
      WriteAndRequireInterfaceTag(kBlobIndexTag);
      WriteUint32(static_cast<uint32_t>(index));
    } else {
      serialized_script_value_->BlobDataHandles().Set(
          blob->Uuid(), blob->GetBlobDataHandle());
      WriteAndRequireInterfaceTag(kBlobTag);
      WriteUTF8String(blob->Uuid());
      WriteUTF8String(blob->type());
      WriteUint64(blob->size());
    }
    return true;
  }
  if (auto* file = dispatcher.ToMostDerived<File>()) {
    WriteAndRequireInterfaceTag(blob_info_array_ ? kFileIndexTag : kFileTag);
    return WriteFile(file, exception_state);
  }
  if (auto* file_list = dispatcher.ToMostDerived<FileList>()) {
    // This does not presently deduplicate a File object and its entry in a
    // FileList, which is non-standard behavior.
    unsigned length = file_list->length();
    WriteAndRequireInterfaceTag(blob_info_array_ ? kFileListIndexTag
                                                 : kFileListTag);
    WriteUint32(length);
    for (unsigned i = 0; i < length; i++) {
      if (!WriteFile(file_list->item(i), exception_state))
        return false;
    }
    return true;
  }
  if (auto* image_bitmap = dispatcher.ToMostDerived<ImageBitmap>()) {
    if (image_bitmap->IsNeutered()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "An ImageBitmap is detached and could not be cloned.");
      return false;
    }

    auto* execution_context = ExecutionContext::From(script_state_);
    // If this ImageBitmap was transferred, it can be serialized by index.
    size_t index = kNotFound;
    if (transferables_)
      index = transferables_->image_bitmaps.Find(image_bitmap);
    if (index != kNotFound) {
      if (image_bitmap->OriginClean()) {
        execution_context->CountUse(
            mojom::WebFeature::kOriginCleanImageBitmapTransfer);
      } else {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kDataCloneError,
            "Non-origin-clean ImageBitmap cannot be transferred.");
        return false;
      }

      DCHECK_LE(index, std::numeric_limits<uint32_t>::max());
      WriteAndRequireInterfaceTag(kImageBitmapTransferTag);
      WriteUint32(static_cast<uint32_t>(index));
      return true;
    }

    // Otherwise, it must be fully serialized.
    if (image_bitmap->OriginClean()) {
      execution_context->CountUse(
          mojom::WebFeature::kOriginCleanImageBitmapSerialization);
    } else {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Non-origin-clean ImageBitmap cannot be cloned.");
      return false;
    }
    WriteAndRequireInterfaceTag(kImageBitmapTag);
    SkImageInfo info = image_bitmap->GetBitmapSkImageInfo();
    SerializedImageBitmapSettings bitmap_settings(
        info, image_bitmap->ImageOrientation());
    WriteUint32Enum(ImageSerializationTag::kParametricColorSpaceTag);
    DCHECK_EQ(bitmap_settings.GetSerializedSkColorSpace().size(),
              kSerializedParametricColorSpaceLength);
    for (const auto& value : bitmap_settings.GetSerializedSkColorSpace())
      WriteDouble(value);
    WriteUint32Enum(ImageSerializationTag::kCanvasPixelFormatTag);
    WriteUint32Enum(bitmap_settings.GetSerializedPixelFormat());
    WriteUint32Enum(ImageSerializationTag::kCanvasOpacityModeTag);
    WriteUint32Enum(bitmap_settings.GetSerializedOpacityMode());
    WriteUint32Enum(ImageSerializationTag::kOriginCleanTag);
    WriteUint32(image_bitmap->OriginClean());
    WriteUint32Enum(ImageSerializationTag::kIsPremultipliedTag);
    WriteUint32(bitmap_settings.IsPremultiplied());
    WriteUint32Enum(ImageSerializationTag::kImageOrientationTag);
    WriteUint32Enum(bitmap_settings.GetSerializedImageOrientation());
    WriteUint32Enum(ImageSerializationTag::kEndTag);
    // Obtain size disregarding image orientation since the image orientation
    // will be applied at deserialization time.
    Image::SizeConfig size_config;
    size_config.apply_orientation = false;
    gfx::Size bitmap_size =
        image_bitmap->BitmapImage()->SizeWithConfig(size_config);
    WriteUint32(bitmap_size.width());
    WriteUint32(bitmap_size.height());
    Vector<uint8_t> pixels =
        image_bitmap->CopyBitmapData(info, /*apply_orientation=*/false);
    // Check if we succeeded to copy the bitmap data.
    if (!bitmap_size.IsEmpty() && pixels.size() == 0) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "An ImageBitmap could not be read successfully.");
      return false;
    }
    WriteUint32(pixels.size());
    WriteRawBytes(pixels.data(), pixels.size());
    return true;
  }
  if (auto* image_data = dispatcher.ToMostDerived<ImageData>()) {
    WriteAndRequireInterfaceTag(kImageDataTag);
    SerializedImageDataSettings settings(
        image_data->GetPredefinedColorSpace(),
        image_data->GetImageDataStorageFormat());
    WriteUint32Enum(ImageSerializationTag::kPredefinedColorSpaceTag);
    WriteUint32Enum(settings.GetSerializedPredefinedColorSpace());
    WriteUint32Enum(ImageSerializationTag::kImageDataStorageFormatTag);
    WriteUint32Enum(settings.GetSerializedImageDataStorageFormat());
    WriteUint32Enum(ImageSerializationTag::kEndTag);
    WriteUint32(image_data->width());
    WriteUint32(image_data->height());
    if (image_data->IsBufferBaseDetached()) {
      WriteUint64(0u);
    } else {
      SkPixmap image_data_pixmap = image_data->GetSkPixmap();
      size_t pixel_buffer_length = image_data_pixmap.computeByteSize();
      WriteUint64(base::strict_cast<uint64_t>(pixel_buffer_length));
      WriteRawBytes(image_data_pixmap.addr(), pixel_buffer_length);
    }
    return true;
  }
  if (auto* point = dispatcher.ToMostDerived<DOMPoint>()) {
    WriteAndRequireInterfaceTag(kDOMPointTag);
    WriteDouble(point->x());
    WriteDouble(point->y());
    WriteDouble(point->z());
    WriteDouble(point->w());
    return true;
  }
  if (auto* point = dispatcher.ToMostDerived<DOMPointReadOnly>()) {
    WriteAndRequireInterfaceTag(kDOMPointReadOnlyTag);
    WriteDouble(point->x());
    WriteDouble(point->y());
    WriteDouble(point->z());
    WriteDouble(point->w());
    return true;
  }
  if (auto* rect = dispatcher.ToMostDerived<DOMRect>()) {
    WriteAndRequireInterfaceTag(kDOMRectTag);
    WriteDouble(rect->x());
    WriteDouble(rect->y());
    WriteDouble(rect->width());
    WriteDouble(rect->height());
    return true;
  }
  if (auto* rect = dispatcher.ToMostDerived<DOMRectReadOnly>()) {
    WriteAndRequireInterfaceTag(kDOMRectReadOnlyTag);
    WriteDouble(rect->x());
    WriteDouble(rect->y());
    WriteDouble(rect->width());
    WriteDouble(rect->height());
    return true;
  }
  if (auto* quad = dispatcher.ToMostDerived<DOMQuad>()) {
    WriteAndRequireInterfaceTag(kDOMQuadTag);
    for (const DOMPoint* point :
         {quad->p1(), quad->p2(), quad->p3(), quad->p4()}) {
      WriteDouble(point->x());
      WriteDouble(point->y());
      WriteDouble(point->z());
      WriteDouble(point->w());
    }
    return true;
  }
  if (auto* matrix = dispatcher.ToMostDerived<DOMMatrix>()) {
    if (matrix->is2D()) {
      WriteAndRequireInterfaceTag(kDOMMatrix2DTag);
      WriteDouble(matrix->a());
      WriteDouble(matrix->b());
      WriteDouble(matrix->c());
      WriteDouble(matrix->d());
      WriteDouble(matrix->e());
      WriteDouble(matrix->f());
    } else {
      WriteAndRequireInterfaceTag(kDOMMatrixTag);
      WriteDouble(matrix->m11());
      WriteDouble(matrix->m12());
      WriteDouble(matrix->m13());
      WriteDouble(matrix->m14());
      WriteDouble(matrix->m21());
      WriteDouble(matrix->m22());
      WriteDouble(matrix->m23());
      WriteDouble(matrix->m24());
      WriteDouble(matrix->m31());
      WriteDouble(matrix->m32());
      WriteDouble(matrix->m33());
      WriteDouble(matrix->m34());
      WriteDouble(matrix->m41());
      WriteDouble(matrix->m42());
      WriteDouble(matrix->m43());
      WriteDouble(matrix->m44());
    }
    return true;
  }
  if (auto* matrix = dispatcher.ToMostDerived<DOMMatrixReadOnly>()) {
    if (matrix->is2D()) {
      WriteAndRequireInterfaceTag(kDOMMatrix2DReadOnlyTag);
      WriteDouble(matrix->a());
      WriteDouble(matrix->b());
      WriteDouble(matrix->c());
      WriteDouble(matrix->d());
      WriteDouble(matrix->e());
      WriteDouble(matrix->f());
    } else {
      WriteAndRequireInterfaceTag(kDOMMatrixReadOnlyTag);
      WriteDouble(matrix->m11());
      WriteDouble(matrix->m12());
      WriteDouble(
### 提示词
```
这是目录为blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer.h"

#include "base/auto_reset.h"
#include "base/feature_list.h"
#include "base/numerics/byte_conversions.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/web_blob_info.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_quad.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file_list.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_data.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_message_port.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_handle.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_offscreen_canvas.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_transform_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_writable_stream.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/fileapi/file_list.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix_read_only.h"
#include "third_party/blink/renderer/core/geometry/dom_point.h"
#include "third_party/blink/renderer/core/geometry/dom_point_read_only.h"
#include "third_party/blink/renderer/core/geometry/dom_quad.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_read_only.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_config.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/mojo/mojo_handle.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/transform_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_base.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"

namespace blink {

// The "Blink-side" serialization version, which defines how Blink will behave
// during the serialization process, is in
// SerializedScriptValue::wireFormatVersion. The serialization format has two
// "envelopes": an outer one controlled by Blink and an inner one by V8.
//
// They are formatted as follows:
// [version tag] [Blink version] [version tag] [v8 version] ...
//
// Before version 16, there was only a single envelope and the version number
// for both parts was always equal.
//
// See also V8ScriptValueDeserializer.cpp.
//
// This version number must be incremented whenever any incompatible changes are
// made to how Blink writes data. Purely V8-side changes do not require an
// adjustment to this value.

// static
bool V8ScriptValueSerializer::ExtractTransferable(
    v8::Isolate* isolate,
    v8::Local<v8::Value> object,
    wtf_size_t object_index,
    Transferables& transferables,
    ExceptionState& exception_state) {
  // Validation of Objects implementing an interface, per WebIDL spec 4.1.15.
  if (MessagePort* port = V8MessagePort::ToWrappable(isolate, object)) {
    // Check for duplicate MessagePorts.
    if (transferables.message_ports.Contains(port)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Message port at index " + String::Number(object_index) +
              " is a duplicate of an earlier port.");
      return false;
    }
    transferables.message_ports.push_back(port);
    return true;
  }
  if (MojoHandle* handle = V8MojoHandle::ToWrappable(isolate, object)) {
    // Check for duplicate MojoHandles.
    if (transferables.mojo_handles.Contains(handle)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Mojo handle at index " + String::Number(object_index) +
              " is a duplicate of an earlier handle.");
      return false;
    }
    transferables.mojo_handles.push_back(handle);
    return true;
  }
  if (object->IsArrayBuffer()) {
    DOMArrayBuffer* array_buffer =
        NativeValueTraits<IDLAllowResizable<DOMArrayBuffer>>::NativeValue(
            isolate, object, exception_state);
    if (exception_state.HadException())
      return false;
    if (transferables.array_buffers.Contains(array_buffer)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "ArrayBuffer at index " + String::Number(object_index) +
              " is a duplicate of an earlier ArrayBuffer.");
      return false;
    }
    transferables.array_buffers.push_back(array_buffer);
    return true;
  }
  if (object->IsSharedArrayBuffer()) {
    DOMSharedArrayBuffer* shared_array_buffer =
        NativeValueTraits<IDLAllowResizable<DOMSharedArrayBuffer>>::NativeValue(
            isolate, object, exception_state);
    if (exception_state.HadException())
      return false;
    if (transferables.array_buffers.Contains(shared_array_buffer)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "SharedArrayBuffer at index " + String::Number(object_index) +
              " is a duplicate of an earlier SharedArrayBuffer.");
      return false;
    }
    transferables.array_buffers.push_back(shared_array_buffer);
    return true;
  }
  if (ImageBitmap* image_bitmap = V8ImageBitmap::ToWrappable(isolate, object)) {
    if (transferables.image_bitmaps.Contains(image_bitmap)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "ImageBitmap at index " + String::Number(object_index) +
              " is a duplicate of an earlier ImageBitmap.");
      return false;
    }
    transferables.image_bitmaps.push_back(image_bitmap);
    return true;
  }
  if (OffscreenCanvas* offscreen_canvas =
          V8OffscreenCanvas::ToWrappable(isolate, object)) {
    if (transferables.offscreen_canvases.Contains(offscreen_canvas)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "OffscreenCanvas at index " + String::Number(object_index) +
              " is a duplicate of an earlier OffscreenCanvas.");
      return false;
    }
    transferables.offscreen_canvases.push_back(offscreen_canvas);
    return true;
  }
  if (ReadableStream* stream = V8ReadableStream::ToWrappable(isolate, object)) {
    if (transferables.readable_streams.Contains(stream)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "ReadableStream at index " + String::Number(object_index) +
              " is a duplicate of an earlier ReadableStream.");
      return false;
    }
    transferables.readable_streams.push_back(stream);
    return true;
  }
  if (WritableStream* stream = V8WritableStream::ToWrappable(isolate, object)) {
    if (transferables.writable_streams.Contains(stream)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "WritableStream at index " + String::Number(object_index) +
              " is a duplicate of an earlier WritableStream.");
      return false;
    }
    transferables.writable_streams.push_back(stream);
    return true;
  }
  if (TransformStream* stream =
          V8TransformStream::ToWrappable(isolate, object)) {
    if (transferables.transform_streams.Contains(stream)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "TransformStream at index " + String::Number(object_index) +
              " is a duplicate of an earlier TransformStream.");
      return false;
    }
    transferables.transform_streams.push_back(stream);
    return true;
  }
  return false;
}

V8ScriptValueSerializer::V8ScriptValueSerializer(ScriptState* script_state,
                                                 const Options& options)
    : script_state_(script_state),
      serialized_script_value_(SerializedScriptValue::Create()),
      serializer_(script_state_->GetIsolate(), this),
      transferables_(options.transferables),
      blob_info_array_(options.blob_info),
      wasm_policy_(options.wasm_policy),
      for_storage_(options.for_storage == SerializedScriptValue::kForStorage) {}

scoped_refptr<SerializedScriptValue> V8ScriptValueSerializer::Serialize(
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
#if DCHECK_IS_ON()
  DCHECK(!serialize_invoked_);
  serialize_invoked_ = true;
#endif
  DCHECK(serialized_script_value_);

  // Prepare to transfer the provided transferables.
  PrepareTransfer(exception_state);
  if (exception_state.HadException())
    return nullptr;

  // Write out the file header.
  static_assert(
      SerializedScriptValue::kWireFormatVersion < 0x80,
      "the following calculation depends on the encoded length of the version");
  static_assert(SerializedScriptValue::kWireFormatVersion == 21,
                "Only version 21 is supported.");
  static constexpr size_t kTrailerOffsetPosition =
      1 /* version tag */ + 1 /* version */ + 1 /* trailer offset tag */;
  static constexpr uint8_t kZeroOffset[sizeof(uint64_t) + sizeof(uint32_t)] =
      {};
  WriteTag(kVersionTag);
  WriteUint32(SerializedScriptValue::kWireFormatVersion);
  WriteTag(kTrailerOffsetTag);
  WriteRawBytes(kZeroOffset, sizeof(kZeroOffset));
  serializer_.WriteHeader();

  // Serialize the value and handle errors.
  v8::Isolate* isolate = script_state_->GetIsolate();
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state_),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  bool wrote_value;
  if (!serializer_.WriteValue(script_state_->GetContext(), value)
           .To(&wrote_value)) {
    DCHECK(rethrow_scope.HasCaught());
    return nullptr;
  }
  DCHECK(wrote_value);

  // Finalize the transfer (e.g. detaching array buffers).
  FinalizeTransfer(exception_state);
  if (exception_state.HadException())
    return nullptr;

  if (shared_array_buffers_.size()) {
    auto* execution_context = ExecutionContext::From(script_state_);
    if (!execution_context->CheckSharedArrayBufferTransferAllowedAndReport()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "SharedArrayBuffer transfer requires self.crossOriginIsolated.");
      return nullptr;
    }
  }

  serialized_script_value_->CloneSharedArrayBuffers(shared_array_buffers_);

  // Append the trailer, if applicable.
  Vector<uint8_t> trailer;
  trailer = trailer_writer_.MakeTrailerData();
  if (!trailer.empty()) {
    WriteRawBytes(trailer.data(), trailer.size());
  }

  // Finalize the results.
  auto [buffer_ptr, buffer_size] = serializer_.Release();
  auto buffer =
      // SAFETY: The size from Release() is promised to be the size of the
      // allocation for the returned pointer. The pointer is allocated by the
      // serializer_ delegate which is `this` and `ReallocateBufferMemory`
      // allocates memory such that it can be deleted by the DataBufferPtr's
      // Deleter.
      UNSAFE_BUFFERS(SerializedScriptValue::DataBufferPtr::FromOwningPointer(
          buffer_ptr, buffer_size));
  if (!trailer.empty()) {
    buffer.as_span()
        .subspan<kTrailerOffsetPosition, sizeof(uint64_t)>()
        .copy_from(base::U64ToBigEndian(buffer.size() - trailer.size()));
    buffer.as_span()
        .subspan<kTrailerOffsetPosition + sizeof(uint64_t), sizeof(uint32_t)>()
        .copy_from(base::U32ToBigEndian(trailer.size()));
  }
  serialized_script_value_->SetData(std::move(buffer));
  return std::move(serialized_script_value_);
}

void V8ScriptValueSerializer::PrepareTransfer(ExceptionState& exception_state) {
  if (!transferables_)
    return;

  // Transfer array buffers.
  for (uint32_t i = 0; i < transferables_->array_buffers.size(); i++) {
    DOMArrayBufferBase* array_buffer = transferables_->array_buffers[i].Get();
    if (!array_buffer->IsShared()) {
      v8::Local<v8::Value> wrapper = ToV8Traits<DOMArrayBuffer>::ToV8(
          script_state_, static_cast<DOMArrayBuffer*>(array_buffer));
      serializer_.TransferArrayBuffer(
          i, v8::Local<v8::ArrayBuffer>::Cast(wrapper));
    } else {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "SharedArrayBuffer can not be in transfer list.");
      return;
    }
  }
}

void V8ScriptValueSerializer::FinalizeTransfer(
    ExceptionState& exception_state) {
  // TODO(jbroman): Strictly speaking, this is not correct; transfer should
  // occur in the order of the transfer list.
  // https://html.spec.whatwg.org/C/#structuredclonewithtransfer

  v8::Isolate* isolate = script_state_->GetIsolate();

  ArrayBufferArray array_buffers;
  // The scope object to promptly free the backing store to avoid memory
  // regressions.
  // TODO(bikineev): Revisit after young generation is there.
  struct PromptlyFreeArrayBuffers {
    // The void* is to avoid blink-gc-plugin error.
    void* buffer;
    ~PromptlyFreeArrayBuffers() {
      static_cast<ArrayBufferArray*>(buffer)->clear();
    }
  } promptly_free_array_buffers{&array_buffers};
  if (transferables_)
    array_buffers.AppendVector(transferables_->array_buffers);

  if (!array_buffers.empty()) {
    serialized_script_value_->TransferArrayBuffers(isolate, array_buffers,
                                                   exception_state);
    if (exception_state.HadException())
      return;
  }

  if (transferables_) {
    serialized_script_value_->TransferImageBitmaps(
        isolate, transferables_->image_bitmaps, exception_state);
    if (exception_state.HadException())
      return;

    serialized_script_value_->TransferOffscreenCanvas(
        isolate, transferables_->offscreen_canvases, exception_state);
    if (exception_state.HadException())
      return;

    // Order matters here, because the order in which streams are added to the
    // |stream_ports_| array must match the indexes which are calculated in
    // WriteDOMObject().
    serialized_script_value_->TransferReadableStreams(
        script_state_, transferables_->readable_streams, exception_state);
    if (exception_state.HadException())
      return;
    serialized_script_value_->TransferWritableStreams(
        script_state_, transferables_->writable_streams, exception_state);
    if (exception_state.HadException())
      return;
    serialized_script_value_->TransferTransformStreams(
        script_state_, transferables_->transform_streams, exception_state);
    if (exception_state.HadException())
      return;

    for (auto& transfer_list : transferables_->transfer_lists.Values()) {
      transfer_list->FinalizeTransfer(exception_state);
      if (exception_state.HadException())
        return;
    }
  }
}

void V8ScriptValueSerializer::WriteUnguessableToken(
    const base::UnguessableToken& token) {
  WriteUint64(token.GetHighForSerialization());
  WriteUint64(token.GetLowForSerialization());
}

void V8ScriptValueSerializer::WriteUTF8String(const StringView& string) {
  StringUTF8Adaptor utf8(string);
  WriteUint32(utf8.size());
  WriteRawBytes(utf8.data(), utf8.size());
}

bool V8ScriptValueSerializer::WriteDOMObject(ScriptWrappable* wrappable,
                                             ExceptionState& exception_state) {
  ScriptWrappable::TypeDispatcher dispatcher(wrappable);
  if (auto* blob = dispatcher.ToMostDerived<Blob>()) {
    if (blob_info_array_) {
      size_t index = blob_info_array_->size();
      DCHECK_LE(index, std::numeric_limits<uint32_t>::max());
      blob_info_array_->emplace_back(blob->GetBlobDataHandle(), blob->type(),
                                     blob->size());
      WriteAndRequireInterfaceTag(kBlobIndexTag);
      WriteUint32(static_cast<uint32_t>(index));
    } else {
      serialized_script_value_->BlobDataHandles().Set(
          blob->Uuid(), blob->GetBlobDataHandle());
      WriteAndRequireInterfaceTag(kBlobTag);
      WriteUTF8String(blob->Uuid());
      WriteUTF8String(blob->type());
      WriteUint64(blob->size());
    }
    return true;
  }
  if (auto* file = dispatcher.ToMostDerived<File>()) {
    WriteAndRequireInterfaceTag(blob_info_array_ ? kFileIndexTag : kFileTag);
    return WriteFile(file, exception_state);
  }
  if (auto* file_list = dispatcher.ToMostDerived<FileList>()) {
    // This does not presently deduplicate a File object and its entry in a
    // FileList, which is non-standard behavior.
    unsigned length = file_list->length();
    WriteAndRequireInterfaceTag(blob_info_array_ ? kFileListIndexTag
                                                 : kFileListTag);
    WriteUint32(length);
    for (unsigned i = 0; i < length; i++) {
      if (!WriteFile(file_list->item(i), exception_state))
        return false;
    }
    return true;
  }
  if (auto* image_bitmap = dispatcher.ToMostDerived<ImageBitmap>()) {
    if (image_bitmap->IsNeutered()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "An ImageBitmap is detached and could not be cloned.");
      return false;
    }

    auto* execution_context = ExecutionContext::From(script_state_);
    // If this ImageBitmap was transferred, it can be serialized by index.
    size_t index = kNotFound;
    if (transferables_)
      index = transferables_->image_bitmaps.Find(image_bitmap);
    if (index != kNotFound) {
      if (image_bitmap->OriginClean()) {
        execution_context->CountUse(
            mojom::WebFeature::kOriginCleanImageBitmapTransfer);
      } else {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kDataCloneError,
            "Non-origin-clean ImageBitmap cannot be transferred.");
        return false;
      }

      DCHECK_LE(index, std::numeric_limits<uint32_t>::max());
      WriteAndRequireInterfaceTag(kImageBitmapTransferTag);
      WriteUint32(static_cast<uint32_t>(index));
      return true;
    }

    // Otherwise, it must be fully serialized.
    if (image_bitmap->OriginClean()) {
      execution_context->CountUse(
          mojom::WebFeature::kOriginCleanImageBitmapSerialization);
    } else {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Non-origin-clean ImageBitmap cannot be cloned.");
      return false;
    }
    WriteAndRequireInterfaceTag(kImageBitmapTag);
    SkImageInfo info = image_bitmap->GetBitmapSkImageInfo();
    SerializedImageBitmapSettings bitmap_settings(
        info, image_bitmap->ImageOrientation());
    WriteUint32Enum(ImageSerializationTag::kParametricColorSpaceTag);
    DCHECK_EQ(bitmap_settings.GetSerializedSkColorSpace().size(),
              kSerializedParametricColorSpaceLength);
    for (const auto& value : bitmap_settings.GetSerializedSkColorSpace())
      WriteDouble(value);
    WriteUint32Enum(ImageSerializationTag::kCanvasPixelFormatTag);
    WriteUint32Enum(bitmap_settings.GetSerializedPixelFormat());
    WriteUint32Enum(ImageSerializationTag::kCanvasOpacityModeTag);
    WriteUint32Enum(bitmap_settings.GetSerializedOpacityMode());
    WriteUint32Enum(ImageSerializationTag::kOriginCleanTag);
    WriteUint32(image_bitmap->OriginClean());
    WriteUint32Enum(ImageSerializationTag::kIsPremultipliedTag);
    WriteUint32(bitmap_settings.IsPremultiplied());
    WriteUint32Enum(ImageSerializationTag::kImageOrientationTag);
    WriteUint32Enum(bitmap_settings.GetSerializedImageOrientation());
    WriteUint32Enum(ImageSerializationTag::kEndTag);
    // Obtain size disregarding image orientation since the image orientation
    // will be applied at deserialization time.
    Image::SizeConfig size_config;
    size_config.apply_orientation = false;
    gfx::Size bitmap_size =
        image_bitmap->BitmapImage()->SizeWithConfig(size_config);
    WriteUint32(bitmap_size.width());
    WriteUint32(bitmap_size.height());
    Vector<uint8_t> pixels =
        image_bitmap->CopyBitmapData(info, /*apply_orientation=*/false);
    // Check if we succeeded to copy the bitmap data.
    if (!bitmap_size.IsEmpty() && pixels.size() == 0) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "An ImageBitmap could not be read successfully.");
      return false;
    }
    WriteUint32(pixels.size());
    WriteRawBytes(pixels.data(), pixels.size());
    return true;
  }
  if (auto* image_data = dispatcher.ToMostDerived<ImageData>()) {
    WriteAndRequireInterfaceTag(kImageDataTag);
    SerializedImageDataSettings settings(
        image_data->GetPredefinedColorSpace(),
        image_data->GetImageDataStorageFormat());
    WriteUint32Enum(ImageSerializationTag::kPredefinedColorSpaceTag);
    WriteUint32Enum(settings.GetSerializedPredefinedColorSpace());
    WriteUint32Enum(ImageSerializationTag::kImageDataStorageFormatTag);
    WriteUint32Enum(settings.GetSerializedImageDataStorageFormat());
    WriteUint32Enum(ImageSerializationTag::kEndTag);
    WriteUint32(image_data->width());
    WriteUint32(image_data->height());
    if (image_data->IsBufferBaseDetached()) {
      WriteUint64(0u);
    } else {
      SkPixmap image_data_pixmap = image_data->GetSkPixmap();
      size_t pixel_buffer_length = image_data_pixmap.computeByteSize();
      WriteUint64(base::strict_cast<uint64_t>(pixel_buffer_length));
      WriteRawBytes(image_data_pixmap.addr(), pixel_buffer_length);
    }
    return true;
  }
  if (auto* point = dispatcher.ToMostDerived<DOMPoint>()) {
    WriteAndRequireInterfaceTag(kDOMPointTag);
    WriteDouble(point->x());
    WriteDouble(point->y());
    WriteDouble(point->z());
    WriteDouble(point->w());
    return true;
  }
  if (auto* point = dispatcher.ToMostDerived<DOMPointReadOnly>()) {
    WriteAndRequireInterfaceTag(kDOMPointReadOnlyTag);
    WriteDouble(point->x());
    WriteDouble(point->y());
    WriteDouble(point->z());
    WriteDouble(point->w());
    return true;
  }
  if (auto* rect = dispatcher.ToMostDerived<DOMRect>()) {
    WriteAndRequireInterfaceTag(kDOMRectTag);
    WriteDouble(rect->x());
    WriteDouble(rect->y());
    WriteDouble(rect->width());
    WriteDouble(rect->height());
    return true;
  }
  if (auto* rect = dispatcher.ToMostDerived<DOMRectReadOnly>()) {
    WriteAndRequireInterfaceTag(kDOMRectReadOnlyTag);
    WriteDouble(rect->x());
    WriteDouble(rect->y());
    WriteDouble(rect->width());
    WriteDouble(rect->height());
    return true;
  }
  if (auto* quad = dispatcher.ToMostDerived<DOMQuad>()) {
    WriteAndRequireInterfaceTag(kDOMQuadTag);
    for (const DOMPoint* point :
         {quad->p1(), quad->p2(), quad->p3(), quad->p4()}) {
      WriteDouble(point->x());
      WriteDouble(point->y());
      WriteDouble(point->z());
      WriteDouble(point->w());
    }
    return true;
  }
  if (auto* matrix = dispatcher.ToMostDerived<DOMMatrix>()) {
    if (matrix->is2D()) {
      WriteAndRequireInterfaceTag(kDOMMatrix2DTag);
      WriteDouble(matrix->a());
      WriteDouble(matrix->b());
      WriteDouble(matrix->c());
      WriteDouble(matrix->d());
      WriteDouble(matrix->e());
      WriteDouble(matrix->f());
    } else {
      WriteAndRequireInterfaceTag(kDOMMatrixTag);
      WriteDouble(matrix->m11());
      WriteDouble(matrix->m12());
      WriteDouble(matrix->m13());
      WriteDouble(matrix->m14());
      WriteDouble(matrix->m21());
      WriteDouble(matrix->m22());
      WriteDouble(matrix->m23());
      WriteDouble(matrix->m24());
      WriteDouble(matrix->m31());
      WriteDouble(matrix->m32());
      WriteDouble(matrix->m33());
      WriteDouble(matrix->m34());
      WriteDouble(matrix->m41());
      WriteDouble(matrix->m42());
      WriteDouble(matrix->m43());
      WriteDouble(matrix->m44());
    }
    return true;
  }
  if (auto* matrix = dispatcher.ToMostDerived<DOMMatrixReadOnly>()) {
    if (matrix->is2D()) {
      WriteAndRequireInterfaceTag(kDOMMatrix2DReadOnlyTag);
      WriteDouble(matrix->a());
      WriteDouble(matrix->b());
      WriteDouble(matrix->c());
      WriteDouble(matrix->d());
      WriteDouble(matrix->e());
      WriteDouble(matrix->f());
    } else {
      WriteAndRequireInterfaceTag(kDOMMatrixReadOnlyTag);
      WriteDouble(matrix->m11());
      WriteDouble(matrix->m12());
      WriteDouble(matrix->m13());
      WriteDouble(matrix->m14());
      WriteDouble(matrix->m21());
      WriteDouble(matrix->m22());
      WriteDouble(matrix->m23());
      WriteDouble(matrix->m24());
      WriteDouble(matrix->m31());
      WriteDouble(matrix->m32());
      WriteDouble(matrix->m33());
      WriteDouble(matrix->m34());
      WriteDouble(matrix->m41());
      WriteDouble(matrix->m42());
      WriteDouble(matrix->m43());
      WriteDouble(matrix->m44());
    }
    return true;
  }
  if (auto* message_port = dispatcher.ToMostDerived<MessagePort>()) {
    size_t index = kNotFound;
    if (transferables_)
      index = transferables_->message_ports.Find(message_port);
    if (index == kNotFound) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A MessagePort could not be cloned because it was not transferred.");
      return false;
    }
    DCHECK_LE(index, std::numeric_limits<uint32_t>::max());
    WriteAndRequireInterfaceTag(kMessagePortTag);
    WriteUint32(static_cast<uint32_t>(index));
    return true;
  }
  if (auto* mojo_handle = dispatcher.ToMostDerived<MojoHandle>()) {
    if (!RuntimeEnabledFeatures::MojoJSEnabled())
      return false;
    size_t index = kNotFound;
    if (transferables_)
      index = transferables_->mojo_handles.Find(mojo_handle);
    if (index == kNotFound) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A MojoHandle could not be cloned because it was not transferred.");
      return false;
    }
    DCHECK_LE(index, std::numeric_limits<uint32_t>::max());
    serialized_script_value_->MojoHandles().push_back(
        mojo_handle->TakeHandle());
    index = serialized_script_value_->MojoHandles().size() - 1;
    WriteAndRequireInterfaceTag(kMojoHandleTag);
    WriteUint32(static_cast<uint32_t>(index));
    return true;
  }
  if (auto* canvas = dispatcher.ToMostDerived<OffscreenCanvas>()) {
    size_t index = kNotFound;
    if (transferables_)
      index = transferables_->offscreen_canvases.Find(canvas);
    if (index == kNotFound) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "An OffscreenCanvas could not be cloned "
          "because it was not transferred.");
      return false;
    }
    if (canvas->IsNeutered()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "An OffscreenCanvas could not be "
                                        "transferred because it was detached.");
      return false;
    }
    if (canvas->RenderingContext()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "An OffscreenCanvas could not be transferred "
          "because it had a rendering context.");
      return false;
    }
    WriteAndRequireInterfaceTag(kOffscreenCanvasTransferTag);
    WriteUint32(canvas->width());
    WriteUint32(canvas->height());
    WriteUint64(canvas->PlaceholderCanvasId());
    WriteUint32(canvas->ClientId());
    WriteUint32(canvas->SinkId());
    WriteUint32(canvas->FilterQuality() == cc::PaintFlags::FilterQuality::kNone
                    ? 0
                    : 1);
    return true;
  }
  if (auto* stream = dispatcher.ToMostDerived<ReadableStream>()) {
    size_t index = kNotFound;
    if (transferables_)
      index = transferables_->readable_streams.Find(stream);
    if (index == kNotFound) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "A ReadableStream could not be cloned "
                                        "because it was not transferred.");
      return false;
    }
    if (stream->IsLocked()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A ReadableStream could not be cloned because it was locked");
      return false;
    }
    WriteAndRequireInterfaceTag(kReadableStreamTransferTag);
    WriteUint32(static_cast<uint32_t>(index));
    return true;
  }
  if (auto* stream = dispatcher.ToMostDerived<WritableStream>()) {
    size_t index = kNotFound;
    if (transferables_)
      index = transferables_->writable_streams.Find(stream);
    if (index == kNotFound) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "A WritableStream could not be cloned "
                                        "because it was not transferred.");
      return false;
    }
    if (stream->locked()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A WritableStream could not be cloned because it was locked");
      return false;
    }
    WriteAndRequireInterfaceTag(kWritableStreamTransferTag);
    DCHECK(transferables_);
    // The index calculation depends on the order that TransferReadableStreams
    // and TransferWritableStreams are called in
    // V8ScriptValueSerializer::FinalizeTransfer.
    WriteUint32(
        static_cast<uint32_t>(index + transferables_->readable_streams.size()));
    return true;
  }
  if (auto* stream = dispatcher.ToMostDerived<TransformStream>()) {
    size_t index = kNotFound;
    if (transferables_)
      index = transferables_->transform_streams.Find(stream);
    if (index == kNotFound) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "A TransformStream could not be cloned "
                                        "because it was not transferred.");
      return false;
    }
    // https://streams.spec.whatwg.org/#ts-transfer
    // 3. If ! IsReadableStreamLocked(readable) is true, throw a
    //    "DataCloneError" DOMException.
    // 4. If ! IsWritableStreamLocked(writable) is true, throw a
    //    "DataCloneError" DOMException.
    if (stream->Readable()->locked() || stream->Writable()->locked()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A TransformStream could not be cloned because it was locked");
      return false;
    }
    WriteAndRequireInterfaceTag(kTransformStreamTransferTag);
    DCHECK(transferables_);
    // TransformStream
```