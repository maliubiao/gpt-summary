Response:
The user wants a summary of the functionality of the `IDBObjectStore` class in the provided C++ code. I need to analyze the methods defined in the class and infer their purpose based on their names and the operations they perform. Specifically, I should look for relationships with Javascript, HTML, and CSS, provide examples of logical reasoning, common user errors, and how a user interaction might lead to this code being executed. Since this is part 1 of 2, I need to focus on summarizing the functionality and avoid going into too much detail on specific aspects.

Here's a breakdown of the functionality I can identify:

*   **Core IndexedDB Operations:** The class seems to implement the basic operations for an IndexedDB object store, such as `get`, `getKey`, `getAll`, `getAllKeys`, `add`, `put`, `delete`, and `clear`.
*   **Index Management:** It includes methods for getting index names (`indexNames`) and creating new indexes (`createIndex`).
*   **Metadata Management:**  Methods like `setName` suggest functionality for modifying the object store's metadata.
*   **Cursor Handling:** The mention of `IDBCursorWithValue` and the `IndexPopulator` class suggest involvement in iterating over data in the object store.
*   **Key Generation:** The presence of `getKeyGeneratorCurrentNumber` indicates support for auto-incrementing keys.
*   **Transaction Integration:** The class heavily relies on `IDBTransaction`, indicating its operations are transactional.

For the first part, the key is to provide a concise summary of these functionalities without diving deep into each one.
```cpp
 * Copyright (C) 2010 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/indexeddb/idb_object_store.h"

#include <limits>
#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/mojom/indexeddb/indexeddb.mojom-blink.h"
#include "third_party/blink/public/platform/web_blob_info.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value_factory.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_binding_for_modules.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_idb_get_all_records_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_idbcursor_idbindex_idbobjectstore.h"
#include "third_party/blink/renderer/core/dom/dom_string_list.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_any.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_cursor_with_value.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_database.h"
#party/blink/renderer/modules/indexeddb/idb_key.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_path.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_value_wrapping.h"
#include "third_party/blink/renderer/modules/indexeddb/indexed_db_blink_mojom_traits.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "v8/include/v8.h"

namespace blink {

IDBObjectStore::IDBObjectStore(scoped_refptr<IDBObjectStoreMetadata> metadata,
                               IDBTransaction* transaction)
    : metadata_(std::move(metadata)), transaction_(transaction) {
  DCHECK(transaction_);
  DCHECK(metadata_.get());
}

void IDBObjectStore::Trace(Visitor* visitor) const {
  visitor->Trace(transaction_);
  visitor->Trace(index_map_);
  ScriptWrappable::Trace(visitor);
}

void IDBObjectStore::setName(const String& name,
                             ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBObjectStore::setName");
  if (!transaction_->IsVersionChange()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kNotVersionChangeTransactionErrorMessage);
    return;
  }
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return;
  }

  if (this->name() == name)
    return;
  if (db().ContainsObjectStore(name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kConstraintError,
        IDBDatabase::kObjectStoreNameTakenErrorMessage);
    return;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return;
  }

  db().RenameObjectStore(Id(), name);
}

ScriptValue IDBObjectStore::keyPath(ScriptState* script_state) const {
  return ScriptValue(script_state->GetIsolate(),
                     Metadata().key_path.ToV8(script_state));
}

DOMStringList* IDBObjectStore::indexNames() const {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::indexNames", "store_name",
               metadata_->name.Utf8());
  auto* index_names = MakeGarbageCollected<DOMStringList>();
  for (const auto& it : Metadata().indexes)
    index_names->Append(it.value->name);
  index_names->Sort();
  return index_names;
}

IDBRequest* IDBObjectStore::get(ScriptState* script_state,
                                const ScriptValue& key,
                                ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getRequestSetup", "store_name",
               metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreGet);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  IDBKeyRange* key_range = IDBKeyRange::FromScriptValue(
      ExecutionContext::From(script_state), key, exception_state);
  if (exception_state.HadException())
    return nullptr;
  if (!key_range) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataError,
        IDBDatabase::kNoKeyOrKeyRangeErrorMessage);
    return nullptr;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().Get(transaction_->Id(), Id(), IDBIndexMetadata::kInvalidId, key_range,
           /*key_only=*/false,
           WTF::BindOnce(&IDBRequest::OnGet, WrapWeakPersistent(request)));
  return request;
}

IDBRequest* IDBObjectStore::getKey(ScriptState* script_state,
                                   const ScriptValue& key,
                                   ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getKeyRequestSetup", "store_name",
               metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreGetKey);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  IDBKeyRange* key_range = IDBKeyRange::FromScriptValue(
      ExecutionContext::From(script_state), key, exception_state);
  if (exception_state.HadException())
    return nullptr;
  if (!key_range) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataError,
        IDBDatabase::kNoKeyOrKeyRangeErrorMessage);
    return nullptr;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().Get(transaction_->Id(), Id(), IDBIndexMetadata::kInvalidId, key_range,
           /*key_only=*/true,
           WTF::BindOnce(&IDBRequest::OnGet, WrapPersistent(request)));
  return request;
}

IDBRequest* IDBObjectStore::getAll(ScriptState* script_state,
                                   const ScriptValue& key_range,
                                   ExceptionState& exception_state) {
  return getAll(script_state, key_range, std::numeric_limits<uint32_t>::max(),
                exception_state);
}

IDBRequest* IDBObjectStore::getAll(ScriptState* script_state,
                                   const ScriptValue& key_range,
                                   uint32_t max_count,
                                   ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getAllRequestSetup", "store_name",
               metadata_->name.Utf8());

  return CreateGetAllRequest(
      IDBRequest::TypeForMetrics::kObjectStoreGetAll, script_state, key_range,
      mojom::blink::IDBGetAllResultType::Values, max_count,
      mojom::blink::IDBCursorDirection::Next, exception_state);
}

IDBRequest* IDBObjectStore::getAllKeys(ScriptState* script_state,
                                       const ScriptValue& key_range,
                                       ExceptionState& exception_state) {
  return getAllKeys(script_state, key_range,
                    std::numeric_limits<uint32_t>::max(), exception_state);
}

IDBRequest* IDBObjectStore::getAllKeys(ScriptState* script_state,
                                       const ScriptValue& key_range,
                                       uint32_t max_count,
                                       ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getAllKeysRequestSetup",
               "store_name", metadata_->name.Utf8());

  return CreateGetAllRequest(
      IDBRequest::TypeForMetrics::kObjectStoreGetAllKeys, script_state,
      key_range, mojom::blink::IDBGetAllResultType::Keys, max_count,
      mojom::blink::IDBCursorDirection::Next, exception_state);
}

IDBRequest* IDBObjectStore::getAllRecords(
    ScriptState* script_state,
    const IDBGetAllRecordsOptions* options,
    ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getAllRecordsRequestSetup",
               "store_name", metadata_->name.Utf8());

  uint32_t max_count =
      options->getCountOr(std::numeric_limits<uint32_t>::max());

  mojom::blink::IDBCursorDirection direction =
      IDBCursor::V8EnumToDirection(options->direction().AsEnum());

  return CreateGetAllRequest(
      IDBRequest::TypeForMetrics::kObjectStoreGetAllRecords, script_state,
      options->query(), mojom::blink::IDBGetAllResultType::Records, max_count,
      direction, exception_state);
}

static Vector<std::unique_ptr<IDBKey>> GenerateIndexKeysForValue(
    v8::Isolate* isolate,
    const IDBObjectStoreMetadata& store_metadata,
    const IDBIndexMetadata& index_metadata,
    const ScriptValue& object_value) {
  NonThrowableExceptionState exception_state;

  // Look up the key using the index's key path.
  std::unique_ptr<IDBKey> index_key = CreateIDBKeyFromValueAndKeyPaths(
      isolate, object_value.V8Value(), store_metadata.key_path,
      index_metadata.key_path, exception_state);

  // No match. (In the special case for a store with a key generator and in-line
  // keys and where the store and index key paths match, the back-end will
  // synthesize an index key.)
  if (!index_key)
    return Vector<std::unique_ptr<IDBKey>>();

  // Special case for multi-entry indexes, per spec: if an index's multiEntry
  // flag is true the computed index key is an array, then an index entry is
  // created for each subkey, with duplicate and invalid subkeys removed.
  // https://w3c.github.io/IndexedDB/#store-a-record-into-an-object-store
  // https://w3c.github.io/IndexedDB/#convert-a-value-to-a-multientry-key
  if (index_metadata.multi_entry &&
      index_key->GetType() == mojom::IDBKeyType::Array) {
    return IDBKey::ToMultiEntryArray(std::move(index_key));
  }

  // Otherwise, invalid index keys are simply ignored.
  if (!index_key->IsValid())
    return Vector<std::unique_ptr<IDBKey>>();

  // And a single key is added for the record in the index.
  Vector<std::unique_ptr<IDBKey>> index_keys;
  index_keys.ReserveInitialCapacity(1);
  index_keys.emplace_back(std::move(index_key));
  return index_keys;
}

IDBRequest* IDBObjectStore::add(ScriptState* script_state,
                                const ScriptValue& value,
                                ExceptionState& exception_state) {
  v8::Isolate* isolate = script_state->GetIsolate();
  return add(script_state, value, ScriptValue(isolate, v8::Undefined(isolate)),
             exception_state);
}

IDBRequest* IDBObjectStore::add(ScriptState* script_state,
                                const ScriptValue& value,
                                const ScriptValue& key,
                                ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::addRequestSetup", "store_name",
               metadata_->name.Utf8());
  return DoPut(script_state, mojom::IDBPutMode::AddOnly, value, key,
               exception_state);
}

IDBRequest* IDBObjectStore::put(ScriptState* script_state,
                                const ScriptValue& value,
                                ExceptionState& exception_state) {
  v8::Isolate* isolate = script_state->GetIsolate();
  return put(script_state, value, ScriptValue(isolate, v8::Undefined(isolate)),
             exception_state);
}

IDBRequest* IDBObjectStore::put(ScriptState* script_state,
                                const ScriptValue& value,
                                const ScriptValue& key,
                                ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::putRequestSetup", "store_name",
               metadata_->name.Utf8());
  return DoPut(script_state, mojom::IDBPutMode::AddOrUpdate, value, key,
               exception_state);
}

IDBRequest* IDBObjectStore::DoPut(ScriptState* script_state,
                                  mojom::IDBPutMode put_mode,
                                  const ScriptValue& value,
                                  const ScriptValue& key_value,
                                  ExceptionState& exception_state) {
  std::unique_ptr<IDBKey> key =
      key_value.IsUndefined()
          ? nullptr
          : CreateIDBKeyFromValue(script_state->GetIsolate(),
                                  key_value.V8Value(), exception_state);
  if (exception_state.HadException())
    return nullptr;
  return DoPut(script_state, put_mode,
               MakeGarbageCollected<IDBRequest::Source>(this),
               value, key.get(), exception_state);
}

IDBRequest* IDBObjectStore::DoPut(ScriptState* script_state,
                                  mojom::IDBPutMode put_mode,
                                  const IDBRequest::Source* source,
                                  const ScriptValue& value,
                                  const IDBKey* key,
                                  ExceptionState& exception_state) {
  IDBRequest::TypeForMetrics tracing_type;
  switch (put_mode) {
    case mojom::IDBPutMode::AddOrUpdate:
      tracing_type = IDBRequest::TypeForMetrics::kObjectStorePut;
      break;
    case mojom::IDBPutMode::AddOnly:
      tracing_type = IDBRequest::TypeForMetrics::kObjectStoreAdd;
      break;
    case mojom::IDBPutMode::CursorUpdate:
      tracing_type = IDBRequest::TypeForMetrics::kObjectStoreUpdate;
      break;
  }
  IDBRequest::AsyncTraceState metrics(tracing_type);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  if (transaction_->IsReadOnly()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kReadOnlyError,
        IDBDatabase::kTransactionReadOnlyErrorMessage);
    return nullptr;
  }

  v8::Isolate* isolate = script_state->GetIsolate();
  DCHECK(isolate->InContext());
  transaction_->SetActiveDuringSerialization(false);
  // TODO(crbug.com/719053): This wasm behavior differs from other browsers.
  SerializedScriptValue::SerializeOptions::WasmSerializationPolicy wasm_policy =
      ExecutionContext::From(script_state)->IsSecureContext()
          ? SerializedScriptValue::SerializeOptions::kSerialize
          : SerializedScriptValue::SerializeOptions::kBlockedInNonSecureContext;
  IDBValueWrapper value_wrapper(isolate, value.V8Value(), wasm_policy,
                                exception_state);
  transaction_->SetActiveDuringSerialization(true);
  if (exception_state.HadException())
    return nullptr;

  // Keys that need to be extracted must be taken from a clone so that
  // side effects (i.e. getters) are not triggered. Construct the
  // clone lazily since the operation may be expensive.
  ScriptValue clone;

  const IDBKeyPath& key_path = IdbKeyPath();
  const bool uses_in_line_keys = !key_path.IsNull();
  const bool has_key_generator = autoIncrement();

  if (put_mode != mojom::IDBPutMode::CursorUpdate && uses_in_line_keys && key) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      "The object store uses in-line keys and "
                                      "the key parameter was provided.");
    return nullptr;
  }

  // If the primary key is extracted from the value using a key path, this holds
  // onto the extracted key for the duration of the method.
  std::unique_ptr<IDBKey> key_path_key;

  // This test logically belongs in IDBCursor, but must operate on the cloned
  // value.
  if (put_mode == mojom::IDBPutMode::CursorUpdate && uses_in_line_keys) {
    DCHECK(key);
    DCHECK(clone.IsEmpty());
    value_wrapper.Clone(script_state, &clone);

    DCHECK(!key_path_key);
    key_path_key = CreateIDBKeyFromValueAndKeyPath(
        script_state->GetIsolate(), clone.V8Value(), key_path, exception_state);
    if (exception_state.HadException())
      return nullptr;
    if (!key_path_key || !key_path_key->IsEqual(key)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataError,
          "The effective object store of this cursor uses in-line keys and "
          "evaluating the key path of the value parameter results in a "
          "different value than the cursor's effective key.");
      return nullptr;
    }
  }

  if (!uses_in_line_keys && !has_key_generator && !key) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      "The object store uses out-of-line keys "
                                      "and has no key generator and the key "
                                      "parameter was not provided.");
    return nullptr;
  }

  if (uses_in_line_keys) {
    if (clone.IsEmpty()) {
      // For an IDBCursor.update(), the value should have been cloned above.
      DCHECK(put_mode != mojom::IDBPutMode::CursorUpdate);
      value_wrapper.Clone(script_state, &clone);

      DCHECK(!key_path_key);
      key_path_key = CreateIDBKeyFromValueAndKeyPath(script_state->GetIsolate(),
                                                     clone.V8Value(), key_path,
                                                     exception_state);
      if (exception_state.HadException())
        return nullptr;
      if (key_path_key && !key_path_key->IsValid()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kDataError,
            "Evaluating the object store's key path yielded a value that is "
            "not a valid key.");
        return nullptr;
      }
    } else {
      // The clone was created in the large if block above. The block should
      // have thrown if key_path_key is not valid.
      DCHECK(put_mode == mojom::IDBPutMode::CursorUpdate);
      DCHECK(key_path_key && key_path_key->IsValid());
    }

    // The clone should have either been created in the if block right above,
    // or in the large if block further above above. Both if blocks throw if
    // key_path_key is populated with an invalid key. However, the latter block,
    // which handles IDBObjectStore.put() and IDBObjectStore.add(), may end up
    // with a null key_path_key. This is acceptable for object stores with key
    // generators (autoIncrement is true).
    DCHECK(!key_path_key || key_path_key->IsValid());

    if (!key_path_key) {
      if (!has_key_generator) {
        exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                          "Evaluating the object store's key "
                                          "path did not yield a value.");
        return nullptr;
      }

      // Auto-incremented keys must be generated by the backing store, to
      // ensure uniqueness when the same IndexedDB database is concurrently
      // accessed by multiple render processes. This check ensures that we'll be
      // able to inject the generated key into the supplied value when we read
      // them from the backing store.
      if (!CanInjectIDBKeyIntoScriptValue(script_state->GetIsolate(), clone,
                                          key_path)) {
        exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                          "A generated key could not be "
                                          "inserted into the value.");
        return nullptr;
      }
    }

    if (key_path_key)
      key = key_path_key.get();
  }

  if (key && !key->IsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      IDBDatabase::kNotValidKeyErrorMessage);
    return nullptr;
  }

  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  Vector<IDBIndexKeys> index_keys;
  index_keys.ReserveInitialCapacity(Metadata().indexes.size());
  for (const auto& it : Metadata().indexes) {
    if (clone.IsEmpty())
      value_wrapper.Clone(script_state, &clone);
    index_keys.emplace_back(IDBIndexKeys{
        .id = it.key,
        .keys = GenerateIndexKeysForValue(script_state->GetIsolate(),
                                          Metadata(), *it.value, clone)});
  }
  // Records 1KB to 1GB.
  UMA_HISTOGRAM_COUNTS_1M(
      "WebCore.IndexedDB.PutValueSize2",
      base::saturated_cast<base::HistogramBase::Sample>(
          value_wrapper.DataLengthBeforeWrapInBytes() / 1024));

  IDBRequest* request = IDBRequest::Create(
      script_state, source, transaction_.Get(), std::move(metrics));

  value_wrapper.DoneCloning();

  auto idb_value = std::make_unique<IDBValue>(
      value_wrapper.TakeWireBytes(), value_wrapper.TakeBlobInfo(),
      value_wrapper.TakeFileSystemAccessTransferTokens());

  transaction_->Put(
      Id(), std::move(idb_value), IDBKey::Clone(key), put_mode,
      std::move(index_keys),
      WTF::BindOnce(&IDBRequest::OnPut, WrapWeakPersistent(request)));

  return request;
}

IDBRequest* IDBObjectStore::Delete(ScriptState* script_state,
                                   const ScriptValue& key,
                                   ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::deleteRequestSetup", "store_name",
               metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreDelete);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  if (transaction_->IsReadOnly()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kReadOnlyError,
        IDBDatabase::kTransactionReadOnlyErrorMessage);
    return nullptr;
  }

  IDBKeyRange* key_range = IDBKeyRange::FromScriptValue(
      ExecutionContext::From(script_state), key, exception_state);
  if (exception_state.HadException())
    return nullptr;
  if (!key_range) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataError,
        IDBDatabase::kNoKeyOrKeyRangeErrorMessage);
    return nullptr;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  return deleteFunction(script_state, key_range, std::move(metrics));
}

IDBRequest* IDBObjectStore::deleteFunction(
    ScriptState* script_state,
    IDBKeyRange* key_range,
    IDBRequest::AsyncTraceState metrics) {
  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().DeleteRange(
      transaction_->Id(), Id(), key_range,
      WTF::BindOnce(&IDBRequest::OnDelete, WrapPersistent(request)));
  return request;
}

IDBRequest* IDBObjectStore::getKeyGeneratorCurrentNumber(
    ScriptState* script_state,
    IDBRequest::AsyncTraceState metrics) {
  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));

  db().GetKeyGeneratorCurrentNumber(
      transaction_->Id(), Id(),
      WTF::BindOnce(&IDBRequest::OnGotKeyGeneratorCurrentNumber,
                    WrapWeakPersistent(request)));
  return request;
}

IDBRequest* IDBObjectStore::clear(ScriptState* script_state,
                                  ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBObjectStore::clearRequestSetup");
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreClear);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  if (transaction_->IsReadOnly()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kReadOnlyError,
        IDBDatabase::kTransactionReadOnlyErrorMessage);
    return nullptr;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().Clear(transaction_->Id(), Id(),
             WTF::BindOnce(&IDBRequest::OnClear, WrapPersistent(request)));
  return request;
}

namespace {
// This class creates the index keys for a given index by extracting
// them from the SerializedScriptValue, for all the existing values in
// the object store. It only needs to be kept alive by virtue of being
// a listener on an IDBRequest object, in the same way that JavaScript
// cursor success handlers are kept alive.
class IndexPopulator final : public NativeEventListener {
 public:
  IndexPopulator(ScriptState* script_state,
                 IDBDatabase* database,
                 int64_t transaction_id,
                 int64_t object_store_id,
                 scoped_refptr<const IDBObjectStoreMetadata> store_metadata,
                 scoped_refptr<const IDBIndexMetadata> index_metadata)
      : script_state_(script_state),
        database_(database),
        transaction_id_(transaction_id),
        object_store_id_(object_store_id),
        store_metadata_(store_metadata),
        index_metadata_(std::move(index_metadata)) {
    DCHECK(index_metadata_.get());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    visitor->Trace(database_);
    NativeEventListener::Trace(visitor);
  }

 private:
  const IDBObjectStoreMetadata& ObjectStoreMetadata() const {
    return *store_metadata_;
  }
  const IDBIndexMetadata& IndexMetadata() const { return *index_metadata_; }

  void Invoke(ExecutionContext* execution_context, Event* event) override {
    if (!script_state_->ContextIsValid())
      
Prompt: 
```
这是目录为blink/renderer/modules/indexeddb/idb_object_store.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/indexeddb/idb_object_store.h"

#include <limits>
#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/mojom/indexeddb/indexeddb.mojom-blink.h"
#include "third_party/blink/public/platform/web_blob_info.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value_factory.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_binding_for_modules.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_idb_get_all_records_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_idbcursor_idbindex_idbobjectstore.h"
#include "third_party/blink/renderer/core/dom/dom_string_list.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_any.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_cursor_with_value.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_database.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_path.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_value_wrapping.h"
#include "third_party/blink/renderer/modules/indexeddb/indexed_db_blink_mojom_traits.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "v8/include/v8.h"

namespace blink {

IDBObjectStore::IDBObjectStore(scoped_refptr<IDBObjectStoreMetadata> metadata,
                               IDBTransaction* transaction)
    : metadata_(std::move(metadata)), transaction_(transaction) {
  DCHECK(transaction_);
  DCHECK(metadata_.get());
}

void IDBObjectStore::Trace(Visitor* visitor) const {
  visitor->Trace(transaction_);
  visitor->Trace(index_map_);
  ScriptWrappable::Trace(visitor);
}

void IDBObjectStore::setName(const String& name,
                             ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBObjectStore::setName");
  if (!transaction_->IsVersionChange()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kNotVersionChangeTransactionErrorMessage);
    return;
  }
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return;
  }

  if (this->name() == name)
    return;
  if (db().ContainsObjectStore(name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kConstraintError,
        IDBDatabase::kObjectStoreNameTakenErrorMessage);
    return;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return;
  }

  db().RenameObjectStore(Id(), name);
}

ScriptValue IDBObjectStore::keyPath(ScriptState* script_state) const {
  return ScriptValue(script_state->GetIsolate(),
                     Metadata().key_path.ToV8(script_state));
}

DOMStringList* IDBObjectStore::indexNames() const {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::indexNames", "store_name",
               metadata_->name.Utf8());
  auto* index_names = MakeGarbageCollected<DOMStringList>();
  for (const auto& it : Metadata().indexes)
    index_names->Append(it.value->name);
  index_names->Sort();
  return index_names;
}

IDBRequest* IDBObjectStore::get(ScriptState* script_state,
                                const ScriptValue& key,
                                ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getRequestSetup", "store_name",
               metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreGet);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  IDBKeyRange* key_range = IDBKeyRange::FromScriptValue(
      ExecutionContext::From(script_state), key, exception_state);
  if (exception_state.HadException())
    return nullptr;
  if (!key_range) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataError,
        IDBDatabase::kNoKeyOrKeyRangeErrorMessage);
    return nullptr;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().Get(transaction_->Id(), Id(), IDBIndexMetadata::kInvalidId, key_range,
           /*key_only=*/false,
           WTF::BindOnce(&IDBRequest::OnGet, WrapWeakPersistent(request)));
  return request;
}

IDBRequest* IDBObjectStore::getKey(ScriptState* script_state,
                                   const ScriptValue& key,
                                   ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getKeyRequestSetup", "store_name",
               metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreGetKey);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  IDBKeyRange* key_range = IDBKeyRange::FromScriptValue(
      ExecutionContext::From(script_state), key, exception_state);
  if (exception_state.HadException())
    return nullptr;
  if (!key_range) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataError,
        IDBDatabase::kNoKeyOrKeyRangeErrorMessage);
    return nullptr;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().Get(transaction_->Id(), Id(), IDBIndexMetadata::kInvalidId, key_range,
           /*key_only=*/true,
           WTF::BindOnce(&IDBRequest::OnGet, WrapPersistent(request)));
  return request;
}

IDBRequest* IDBObjectStore::getAll(ScriptState* script_state,
                                   const ScriptValue& key_range,
                                   ExceptionState& exception_state) {
  return getAll(script_state, key_range, std::numeric_limits<uint32_t>::max(),
                exception_state);
}

IDBRequest* IDBObjectStore::getAll(ScriptState* script_state,
                                   const ScriptValue& key_range,
                                   uint32_t max_count,
                                   ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getAllRequestSetup", "store_name",
               metadata_->name.Utf8());

  return CreateGetAllRequest(
      IDBRequest::TypeForMetrics::kObjectStoreGetAll, script_state, key_range,
      mojom::blink::IDBGetAllResultType::Values, max_count,
      mojom::blink::IDBCursorDirection::Next, exception_state);
}

IDBRequest* IDBObjectStore::getAllKeys(ScriptState* script_state,
                                       const ScriptValue& key_range,
                                       ExceptionState& exception_state) {
  return getAllKeys(script_state, key_range,
                    std::numeric_limits<uint32_t>::max(), exception_state);
}

IDBRequest* IDBObjectStore::getAllKeys(ScriptState* script_state,
                                       const ScriptValue& key_range,
                                       uint32_t max_count,
                                       ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getAllKeysRequestSetup",
               "store_name", metadata_->name.Utf8());

  return CreateGetAllRequest(
      IDBRequest::TypeForMetrics::kObjectStoreGetAllKeys, script_state,
      key_range, mojom::blink::IDBGetAllResultType::Keys, max_count,
      mojom::blink::IDBCursorDirection::Next, exception_state);
}

IDBRequest* IDBObjectStore::getAllRecords(
    ScriptState* script_state,
    const IDBGetAllRecordsOptions* options,
    ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::getAllRecordsRequestSetup",
               "store_name", metadata_->name.Utf8());

  uint32_t max_count =
      options->getCountOr(std::numeric_limits<uint32_t>::max());

  mojom::blink::IDBCursorDirection direction =
      IDBCursor::V8EnumToDirection(options->direction().AsEnum());

  return CreateGetAllRequest(
      IDBRequest::TypeForMetrics::kObjectStoreGetAllRecords, script_state,
      options->query(), mojom::blink::IDBGetAllResultType::Records, max_count,
      direction, exception_state);
}

static Vector<std::unique_ptr<IDBKey>> GenerateIndexKeysForValue(
    v8::Isolate* isolate,
    const IDBObjectStoreMetadata& store_metadata,
    const IDBIndexMetadata& index_metadata,
    const ScriptValue& object_value) {
  NonThrowableExceptionState exception_state;

  // Look up the key using the index's key path.
  std::unique_ptr<IDBKey> index_key = CreateIDBKeyFromValueAndKeyPaths(
      isolate, object_value.V8Value(), store_metadata.key_path,
      index_metadata.key_path, exception_state);

  // No match. (In the special case for a store with a key generator and in-line
  // keys and where the store and index key paths match, the back-end will
  // synthesize an index key.)
  if (!index_key)
    return Vector<std::unique_ptr<IDBKey>>();

  // Special case for multi-entry indexes, per spec: if an index's multiEntry
  // flag is true the computed index key is an array, then an index entry is
  // created for each subkey, with duplicate and invalid subkeys removed.
  // https://w3c.github.io/IndexedDB/#store-a-record-into-an-object-store
  // https://w3c.github.io/IndexedDB/#convert-a-value-to-a-multientry-key
  if (index_metadata.multi_entry &&
      index_key->GetType() == mojom::IDBKeyType::Array) {
    return IDBKey::ToMultiEntryArray(std::move(index_key));
  }

  // Otherwise, invalid index keys are simply ignored.
  if (!index_key->IsValid())
    return Vector<std::unique_ptr<IDBKey>>();

  // And a single key is added for the record in the index.
  Vector<std::unique_ptr<IDBKey>> index_keys;
  index_keys.ReserveInitialCapacity(1);
  index_keys.emplace_back(std::move(index_key));
  return index_keys;
}

IDBRequest* IDBObjectStore::add(ScriptState* script_state,
                                const ScriptValue& value,
                                ExceptionState& exception_state) {
  v8::Isolate* isolate = script_state->GetIsolate();
  return add(script_state, value, ScriptValue(isolate, v8::Undefined(isolate)),
             exception_state);
}

IDBRequest* IDBObjectStore::add(ScriptState* script_state,
                                const ScriptValue& value,
                                const ScriptValue& key,
                                ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::addRequestSetup", "store_name",
               metadata_->name.Utf8());
  return DoPut(script_state, mojom::IDBPutMode::AddOnly, value, key,
               exception_state);
}

IDBRequest* IDBObjectStore::put(ScriptState* script_state,
                                const ScriptValue& value,
                                ExceptionState& exception_state) {
  v8::Isolate* isolate = script_state->GetIsolate();
  return put(script_state, value, ScriptValue(isolate, v8::Undefined(isolate)),
             exception_state);
}

IDBRequest* IDBObjectStore::put(ScriptState* script_state,
                                const ScriptValue& value,
                                const ScriptValue& key,
                                ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::putRequestSetup", "store_name",
               metadata_->name.Utf8());
  return DoPut(script_state, mojom::IDBPutMode::AddOrUpdate, value, key,
               exception_state);
}

IDBRequest* IDBObjectStore::DoPut(ScriptState* script_state,
                                  mojom::IDBPutMode put_mode,
                                  const ScriptValue& value,
                                  const ScriptValue& key_value,
                                  ExceptionState& exception_state) {
  std::unique_ptr<IDBKey> key =
      key_value.IsUndefined()
          ? nullptr
          : CreateIDBKeyFromValue(script_state->GetIsolate(),
                                  key_value.V8Value(), exception_state);
  if (exception_state.HadException())
    return nullptr;
  return DoPut(script_state, put_mode,
               MakeGarbageCollected<IDBRequest::Source>(this),
               value, key.get(), exception_state);
}

IDBRequest* IDBObjectStore::DoPut(ScriptState* script_state,
                                  mojom::IDBPutMode put_mode,
                                  const IDBRequest::Source* source,
                                  const ScriptValue& value,
                                  const IDBKey* key,
                                  ExceptionState& exception_state) {
  IDBRequest::TypeForMetrics tracing_type;
  switch (put_mode) {
    case mojom::IDBPutMode::AddOrUpdate:
      tracing_type = IDBRequest::TypeForMetrics::kObjectStorePut;
      break;
    case mojom::IDBPutMode::AddOnly:
      tracing_type = IDBRequest::TypeForMetrics::kObjectStoreAdd;
      break;
    case mojom::IDBPutMode::CursorUpdate:
      tracing_type = IDBRequest::TypeForMetrics::kObjectStoreUpdate;
      break;
  }
  IDBRequest::AsyncTraceState metrics(tracing_type);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  if (transaction_->IsReadOnly()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kReadOnlyError,
        IDBDatabase::kTransactionReadOnlyErrorMessage);
    return nullptr;
  }

  v8::Isolate* isolate = script_state->GetIsolate();
  DCHECK(isolate->InContext());
  transaction_->SetActiveDuringSerialization(false);
  // TODO(crbug.com/719053): This wasm behavior differs from other browsers.
  SerializedScriptValue::SerializeOptions::WasmSerializationPolicy wasm_policy =
      ExecutionContext::From(script_state)->IsSecureContext()
          ? SerializedScriptValue::SerializeOptions::kSerialize
          : SerializedScriptValue::SerializeOptions::kBlockedInNonSecureContext;
  IDBValueWrapper value_wrapper(isolate, value.V8Value(), wasm_policy,
                                exception_state);
  transaction_->SetActiveDuringSerialization(true);
  if (exception_state.HadException())
    return nullptr;

  // Keys that need to be extracted must be taken from a clone so that
  // side effects (i.e. getters) are not triggered. Construct the
  // clone lazily since the operation may be expensive.
  ScriptValue clone;

  const IDBKeyPath& key_path = IdbKeyPath();
  const bool uses_in_line_keys = !key_path.IsNull();
  const bool has_key_generator = autoIncrement();

  if (put_mode != mojom::IDBPutMode::CursorUpdate && uses_in_line_keys && key) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      "The object store uses in-line keys and "
                                      "the key parameter was provided.");
    return nullptr;
  }

  // If the primary key is extracted from the value using a key path, this holds
  // onto the extracted key for the duration of the method.
  std::unique_ptr<IDBKey> key_path_key;

  // This test logically belongs in IDBCursor, but must operate on the cloned
  // value.
  if (put_mode == mojom::IDBPutMode::CursorUpdate && uses_in_line_keys) {
    DCHECK(key);
    DCHECK(clone.IsEmpty());
    value_wrapper.Clone(script_state, &clone);

    DCHECK(!key_path_key);
    key_path_key = CreateIDBKeyFromValueAndKeyPath(
        script_state->GetIsolate(), clone.V8Value(), key_path, exception_state);
    if (exception_state.HadException())
      return nullptr;
    if (!key_path_key || !key_path_key->IsEqual(key)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataError,
          "The effective object store of this cursor uses in-line keys and "
          "evaluating the key path of the value parameter results in a "
          "different value than the cursor's effective key.");
      return nullptr;
    }
  }

  if (!uses_in_line_keys && !has_key_generator && !key) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      "The object store uses out-of-line keys "
                                      "and has no key generator and the key "
                                      "parameter was not provided.");
    return nullptr;
  }

  if (uses_in_line_keys) {
    if (clone.IsEmpty()) {
      // For an IDBCursor.update(), the value should have been cloned above.
      DCHECK(put_mode != mojom::IDBPutMode::CursorUpdate);
      value_wrapper.Clone(script_state, &clone);

      DCHECK(!key_path_key);
      key_path_key = CreateIDBKeyFromValueAndKeyPath(script_state->GetIsolate(),
                                                     clone.V8Value(), key_path,
                                                     exception_state);
      if (exception_state.HadException())
        return nullptr;
      if (key_path_key && !key_path_key->IsValid()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kDataError,
            "Evaluating the object store's key path yielded a value that is "
            "not a valid key.");
        return nullptr;
      }
    } else {
      // The clone was created in the large if block above. The block should
      // have thrown if key_path_key is not valid.
      DCHECK(put_mode == mojom::IDBPutMode::CursorUpdate);
      DCHECK(key_path_key && key_path_key->IsValid());
    }

    // The clone should have either been created in the if block right above,
    // or in the large if block further above above. Both if blocks throw if
    // key_path_key is populated with an invalid key. However, the latter block,
    // which handles IDBObjectStore.put() and IDBObjectStore.add(), may end up
    // with a null key_path_key. This is acceptable for object stores with key
    // generators (autoIncrement is true).
    DCHECK(!key_path_key || key_path_key->IsValid());

    if (!key_path_key) {
      if (!has_key_generator) {
        exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                          "Evaluating the object store's key "
                                          "path did not yield a value.");
        return nullptr;
      }

      // Auto-incremented keys must be generated by the backing store, to
      // ensure uniqueness when the same IndexedDB database is concurrently
      // accessed by multiple render processes. This check ensures that we'll be
      // able to inject the generated key into the supplied value when we read
      // them from the backing store.
      if (!CanInjectIDBKeyIntoScriptValue(script_state->GetIsolate(), clone,
                                          key_path)) {
        exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                          "A generated key could not be "
                                          "inserted into the value.");
        return nullptr;
      }
    }

    if (key_path_key)
      key = key_path_key.get();
  }

  if (key && !key->IsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      IDBDatabase::kNotValidKeyErrorMessage);
    return nullptr;
  }

  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  Vector<IDBIndexKeys> index_keys;
  index_keys.ReserveInitialCapacity(Metadata().indexes.size());
  for (const auto& it : Metadata().indexes) {
    if (clone.IsEmpty())
      value_wrapper.Clone(script_state, &clone);
    index_keys.emplace_back(IDBIndexKeys{
        .id = it.key,
        .keys = GenerateIndexKeysForValue(script_state->GetIsolate(),
                                          Metadata(), *it.value, clone)});
  }
  // Records 1KB to 1GB.
  UMA_HISTOGRAM_COUNTS_1M(
      "WebCore.IndexedDB.PutValueSize2",
      base::saturated_cast<base::HistogramBase::Sample>(
          value_wrapper.DataLengthBeforeWrapInBytes() / 1024));

  IDBRequest* request = IDBRequest::Create(
      script_state, source, transaction_.Get(), std::move(metrics));

  value_wrapper.DoneCloning();

  auto idb_value = std::make_unique<IDBValue>(
      value_wrapper.TakeWireBytes(), value_wrapper.TakeBlobInfo(),
      value_wrapper.TakeFileSystemAccessTransferTokens());

  transaction_->Put(
      Id(), std::move(idb_value), IDBKey::Clone(key), put_mode,
      std::move(index_keys),
      WTF::BindOnce(&IDBRequest::OnPut, WrapWeakPersistent(request)));

  return request;
}

IDBRequest* IDBObjectStore::Delete(ScriptState* script_state,
                                   const ScriptValue& key,
                                   ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::deleteRequestSetup", "store_name",
               metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreDelete);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  if (transaction_->IsReadOnly()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kReadOnlyError,
        IDBDatabase::kTransactionReadOnlyErrorMessage);
    return nullptr;
  }

  IDBKeyRange* key_range = IDBKeyRange::FromScriptValue(
      ExecutionContext::From(script_state), key, exception_state);
  if (exception_state.HadException())
    return nullptr;
  if (!key_range) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataError,
        IDBDatabase::kNoKeyOrKeyRangeErrorMessage);
    return nullptr;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  return deleteFunction(script_state, key_range, std::move(metrics));
}

IDBRequest* IDBObjectStore::deleteFunction(
    ScriptState* script_state,
    IDBKeyRange* key_range,
    IDBRequest::AsyncTraceState metrics) {
  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().DeleteRange(
      transaction_->Id(), Id(), key_range,
      WTF::BindOnce(&IDBRequest::OnDelete, WrapPersistent(request)));
  return request;
}

IDBRequest* IDBObjectStore::getKeyGeneratorCurrentNumber(
    ScriptState* script_state,
    IDBRequest::AsyncTraceState metrics) {
  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));

  db().GetKeyGeneratorCurrentNumber(
      transaction_->Id(), Id(),
      WTF::BindOnce(&IDBRequest::OnGotKeyGeneratorCurrentNumber,
                    WrapWeakPersistent(request)));
  return request;
}

IDBRequest* IDBObjectStore::clear(ScriptState* script_state,
                                  ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBObjectStore::clearRequestSetup");
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreClear);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  if (transaction_->IsReadOnly()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kReadOnlyError,
        IDBDatabase::kTransactionReadOnlyErrorMessage);
    return nullptr;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().Clear(transaction_->Id(), Id(),
             WTF::BindOnce(&IDBRequest::OnClear, WrapPersistent(request)));
  return request;
}

namespace {
// This class creates the index keys for a given index by extracting
// them from the SerializedScriptValue, for all the existing values in
// the object store. It only needs to be kept alive by virtue of being
// a listener on an IDBRequest object, in the same way that JavaScript
// cursor success handlers are kept alive.
class IndexPopulator final : public NativeEventListener {
 public:
  IndexPopulator(ScriptState* script_state,
                 IDBDatabase* database,
                 int64_t transaction_id,
                 int64_t object_store_id,
                 scoped_refptr<const IDBObjectStoreMetadata> store_metadata,
                 scoped_refptr<const IDBIndexMetadata> index_metadata)
      : script_state_(script_state),
        database_(database),
        transaction_id_(transaction_id),
        object_store_id_(object_store_id),
        store_metadata_(store_metadata),
        index_metadata_(std::move(index_metadata)) {
    DCHECK(index_metadata_.get());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    visitor->Trace(database_);
    NativeEventListener::Trace(visitor);
  }

 private:
  const IDBObjectStoreMetadata& ObjectStoreMetadata() const {
    return *store_metadata_;
  }
  const IDBIndexMetadata& IndexMetadata() const { return *index_metadata_; }

  void Invoke(ExecutionContext* execution_context, Event* event) override {
    if (!script_state_->ContextIsValid())
      return;
    TRACE_EVENT0("IndexedDB", "IDBObjectStore::IndexPopulator::Invoke");

    DCHECK_EQ(ExecutionContext::From(script_state_), execution_context);
    DCHECK_EQ(event->type(), event_type_names::kSuccess);
    EventTarget* target = event->target();
    IDBRequest* request = static_cast<IDBRequest*>(target);

    if (!database_) {  // If database is stopped?
      return;
    }

    ScriptState::Scope scope(script_state_);

    IDBAny* cursor_any = request->ResultAsAny();
    IDBCursorWithValue* cursor = nullptr;
    if (cursor_any->GetType() == IDBAny::kIDBCursorWithValueType)
      cursor = cursor_any->IdbCursorWithValue();

    if (cursor && !cursor->IsDeleted()) {
      cursor->Continue(nullptr, nullptr, IDBRequest::AsyncTraceState(),
                       ASSERT_NO_EXCEPTION);

      const IDBKey* primary_key = cursor->IdbPrimaryKey();
      ScriptValue value = cursor->value(script_state_);

      Vector<IDBIndexKeys> index_keys;
      index_keys.ReserveInitialCapacity(1);
      index_keys.emplace_back(IDBIndexKeys{
          .id = IndexMetadata().id,
          .keys = GenerateIndexKeysForValue(script_state_->GetIsolate(),
                                            ObjectStoreMetadata(),
                                            IndexMetadata(), value)});

      database_->SetIndexKeys(transaction_id_, object_store_id_,
                              IDBKey::Clone(primary_key),
                              std::move(index_keys));
    } else {
      // Now that we are done indexing, tell the backend to go
      // back to processing tasks of type NormalTask.
      Vector<int64_t> index_ids;
      index_ids.push_back(IndexMetadata().id);
      database_->SetIndexesReady(transaction_id_, object_store_id_, index_ids);
      database_.Clear();
    }
  }

  Member<ScriptState> script_state_;
  Member<IDBDatabase> database_;
  const int64_t transaction_id_;
  const int64_t object_store_id_;
  scoped_refptr<const IDBObjectStoreMetadata> store_metadata_;
  scoped_refptr<const IDBIndexMetadata> index_metadata_;
};
}  // namespace

IDBIndex* IDBObjectStore::createIndex(ScriptState* script_state,
                                      const String& name,
                                      const IDBKeyPath& key_path,
                                      const IDBIndexParameters* options,
                                      ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::createIndexRequestSetup",
               "store_name", metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreCreateIndex);
  if (!transaction_->IsVersionChange()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kNotVersionChangeTransactionErrorMessage);
    return nullptr;
  }
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }
  if (ContainsIndex(name)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kConstraintError,
                                     
"""


```