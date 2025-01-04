Response:
My thinking process to answer the request about `blink/renderer/modules/ml/ml_context.cc` goes like this:

1. **Understand the Goal:** The core request is to understand the functionality of this specific Chromium Blink file and how it relates to web technologies, along with practical usage and debugging insights. The request also explicitly asks for a summary of its functions for this first part of the response.

2. **Initial Code Scan - Identify Key Includes and Namespaces:** I start by quickly scanning the `#include` directives and the `namespace blink {` and internal namespaces. This immediately tells me:
    * It's part of the `blink` rendering engine.
    * It's within the `modules/ml` directory, suggesting it's related to machine learning features.
    * It includes headers from `third_party/blink` (Blink-specific), `third_party/chromium` (general Chromium), and `services/webnn` (Web Neural Network API).
    * It uses V8 bindings (`renderer/bindings/core/v8`, `renderer/bindings/modules/v8`), indicating interaction with JavaScript.
    * It deals with promises (`ScriptPromise`).

3. **Focus on the Class Definition (`MLContext`):**  The filename suggests the central component is the `MLContext` class. I look at its members, constructor, destructor, and methods.

4. **Analyze the Constructor:** The constructor takes `ExecutionContext`, `V8MLDeviceType`, `V8MLPowerPreference`, and `CreateContextSuccessPtr`. This tells me:
    * It's tied to a specific browsing context (`ExecutionContext`).
    * It handles device type and power preference for ML execution, likely influencing which hardware (CPU, GPU) is used.
    * It receives information about the created WebNN context (`create_context_success`).
    * It establishes a connection to the WebNN service using Mojo (`context_remote_`).

5. **Examine Key Methods and their Functionality:**  I go through the methods, trying to understand their purpose based on their names and parameters:
    * `GetDeviceType`, `GetPowerPreference`:  Simple accessors for the constructor parameters.
    * `Trace`: Used for Blink's garbage collection and debugging infrastructure.
    * `lost`: Returns a promise that resolves when the MLContext is lost. This suggests error handling and lifecycle management.
    * `destroy`:  Explicitly releases resources and disconnects from the WebNN service.
    * `CreateWebNNGraphBuilder`:  Central to building and compiling ML models. It interacts with the WebNN service to create a `WebNNGraphBuilder`.
    * `OnLost`: Handles the loss of the WebNN context, resolving the `lost` promise and rejecting pending operations.
    * `opSupportLimits`:  Provides information about the supported operations and data types on the underlying WebNN implementation. This is crucial for feature detection and error prevention.

6. **Identify Relationships with Web Technologies:**  Based on the included headers and the methods, I start drawing connections:
    * **JavaScript:** The use of V8 bindings and `ScriptPromise` directly links this code to JavaScript. Methods like `createWebNNGraphBuilder` are likely exposed to JavaScript.
    * **HTML:**  The `ExecutionContext` ties the `MLContext` to a browsing context, which is ultimately initiated by loading HTML. The ML features would be used within the context of a web page.
    * **CSS:** While less direct, CSS could influence the user experience and potentially trigger ML-related functionalities (e.g., through interactions or animations).

7. **Consider Logic and Potential Usage:** I think about how a developer would use these APIs:
    * Create an `MLContext` with desired device and power settings.
    * Use `createWebNNGraphBuilder` to construct an ML model.
    * Handle the `lost` promise to gracefully deal with context invalidation.
    * Inspect `opSupportLimits` to understand device capabilities.

8. **Brainstorm Common Errors:** I consider what could go wrong from a developer's perspective:
    * Trying to use the context after it's been destroyed.
    * Building graphs with unsupported operations or data types.
    * Not handling the `lost` promise, leading to unhandled errors.

9. **Trace User Actions (Debugging Clues):** I imagine the steps a user might take to trigger this code:
    * Open a web page that uses the Web Neural Network API.
    * The JavaScript code on the page would call methods in the `navigator.ml` API (or a similar entry point).
    * This would eventually lead to the creation of an `MLContext` in the Blink renderer process.
    * Interactions on the page or background processes could trigger model building or execution.
    * Errors or disconnects could lead to the `OnLost` handler being invoked.

10. **Synthesize a Summary:** Finally, I condense my understanding into a concise summary of the file's functionality, focusing on the core purpose of `MLContext` and its role in managing the WebNN API within the Blink rendering engine. I highlight its responsibilities for context creation, lifecycle management, error handling, and providing support information.

By following these steps, I can systematically analyze the provided code snippet and construct a comprehensive answer that addresses all aspects of the request, including functionality, relationships to web technologies, potential errors, and debugging information.
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ml/ml_context.h"

#include "base/feature_list.h"
#include "base/numerics/checked_math.h"
#include "base/types/cxx23_to_underlying.h"
#include "base/types/expected_macros.h"
#include "base/types/pass_key.h"
#include "services/webnn/public/cpp/context_properties.h"
#include "services/webnn/public/cpp/graph_validation_utils.h"
#include "services/webnn/public/cpp/operand_descriptor.h"
#include "services/webnn/public/cpp/supported_data_types.h"
#include "services/webnn/public/cpp/webnn_errors.h"
#include "services/webnn/public/mojom/features.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_context_provider.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_graph_builder.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_tensor.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_batch_normalization_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_binary_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_concat_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_context_lost_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_context_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_conv_2d_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_device_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gather_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gemm_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gru_cell_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gru_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_logical_not_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_cell_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_normalization_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_op_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_operand_data_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_power_preference.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_prelu_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_quantize_dequantize_linear_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_scatter_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_single_input_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_tensor_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_where_support_limits.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer_view_helpers.h"
#include "third_party/blink/renderer/modules/ml/ml_trace.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_error.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_utils.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_tensor.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

namespace {

MLSupportLimits* SupportedDataTypesToSupportLimits(
    const webnn::SupportedDataTypes& supported_data_types) {
  MLSupportLimits* support_limits = MLSupportLimits::Create();
  Vector<String> data_types;
  for (auto data_type : supported_data_types) {
    data_types.push_back(webnn::DataTypeToString(data_type));
  }

  support_limits->setDataTypes(data_types);
  return support_limits;
}

blink::V8MLInputOperandLayout::Enum InputOperandLayoutToBlink(
    webnn::InputOperandLayout layout) {
  switch (layout) {
    case webnn::InputOperandLayout::kNchw:
      return blink::V8MLInputOperandLayout::Enum::kNchw;
    case webnn::InputOperandLayout::kNhwc:
      return blink::V8MLInputOperandLayout::Enum::kNhwc;
  }
}

}  // namespace

MLContext::MLContext(
    ExecutionContext* execution_context,
    const V8MLDeviceType device_type,
    const V8MLPowerPreference power_preference,
    webnn::mojom::blink::CreateContextSuccessPtr create_context_success)
    : device_type_(device_type),
      power_preference_(power_preference),
      lost_property_(MakeGarbageCollected<LostProperty>(execution_context)),
      context_remote_(execution_context),
      properties_(std::move(create_context_success->context_properties)),
      webnn_handle_(std::move(create_context_success->context_handle)) {
  context_remote_.Bind(
      std::move(create_context_success->context_remote),
      execution_context->GetTaskRunner(TaskType::kMachineLearning));
  context_remote_.set_disconnect_with_reason_handler(
      WTF::BindOnce(&MLContext::OnLost, WrapWeakPersistent(this)));
}

MLContext::~MLContext() = default;

V8MLDeviceType MLContext::GetDeviceType() const {
  return device_type_;
}

V8MLPowerPreference MLContext::GetPowerPreference() const {
  return power_preference_;
}

void MLContext::Trace(Visitor* visitor) const {
  visitor->Trace(lost_property_);
  visitor->Trace(context_remote_);
  visitor->Trace(pending_resolvers_);
  visitor->Trace(graphs_);
  visitor->Trace(graph_builders_);
  visitor->Trace(tensors_);
  ScriptWrappable::Trace(visitor);
}

ScriptPromise<MLContextLostInfo> MLContext::lost(ScriptState* script_state) {
  return lost_property_->Promise(script_state->World());
}

void MLContext::destroy(ScriptState* script_state,
                        ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "destroy() called on an invalid context.");
    return;
  }

  if (context_remote_.is_bound()) {
    OnLost(0, "destroy() called on MLContext.");

    for (const auto& graph : graphs_) {
      graph->destroy();
    }

    for (const auto& graph_builder : graph_builders_) {
      graph_builder->OnConnectionError();
    }

    for (const auto& tensor : tensors_) {
      tensor->destroy();
    }
  }
}

MLGraphBuilder* MLContext::CreateWebNNGraphBuilder(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!context_remote_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Context is lost.");
    return nullptr;
  }

  mojo::PendingAssociatedRemote<webnn::mojom::blink::WebNNGraphBuilder>
      pending_remote;
  context_remote_->CreateGraphBuilder(
      pending_remote.InitWithNewEndpointAndPassReceiver());

  auto* graph_builder = MakeGarbageCollected<MLGraphBuilder>(
      ExecutionContext::From(script_state), this, std::move(pending_remote));
  graph_builders_.insert(graph_builder);

  return graph_builder;
}

void MLContext::OnLost(uint32_t custom_reason, const std::string& description) {
  context_remote_.reset();

  auto* context_lost_info = MLContextLostInfo::Create();
  if (description.empty()) {
    context_lost_info->setMessage(
        "WebNN context is lost due to connection error.");
  } else {
    context_lost_info->setMessage(String::FromUTF8(description));
  }

  CHECK_EQ(lost_property_->GetState(), LostProperty::kPending);
  lost_property_->Resolve(context_lost_info);

  for (const auto& resolver : pending_resolvers_) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "Context is lost.");
  }
  pending_resolvers_.clear();
}

const MLOpSupportLimits* MLContext::opSupportLimits(ScriptState* script_state) {
  const webnn::DataTypeLimits& data_type_limits = properties_.data_type_limits;

  MLOpSupportLimits* op_support_limits = MLOpSupportLimits::Create();
  op_support_limits->setPreferredInputLayout(
      InputOperandLayoutToBlink(properties_.input_operand_layout));
  op_support_limits->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.input));
  op_support_limits->setConstant(
      SupportedDataTypesToSupportLimits(data_type_limits.constant));
  op_support_limits->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.output()));

  MLSingleInputSupportLimits* argmin = MLSingleInputSupportLimits::Create();
  argmin->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.arg_min_max_input));
  argmin->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.arg_min_max_output));
  op_support_limits->setArgMin(argmin);
  MLSingleInputSupportLimits* argmax = MLSingleInputSupportLimits::Create();
  argmax->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.arg_min_max_input));
  argmax->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.arg_min_max_output));
  op_support_limits->setArgMax(argmax);

  MLBatchNormalizationSupportLimits* batch_normalization =
      MLBatchNormalizationSupportLimits::Create();
  batch_normalization->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setMean(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setVariance(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setScale(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setBias(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  op_support_limits->setBatchNormalization(batch_normalization);

  MLSingleInputSupportLimits* cast = MLSingleInputSupportLimits::Create();
  cast->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.cast_input));
  cast->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.cast_input));
  op_support_limits->setCast(cast);

  MLSingleInputSupportLimits* clamp = MLSingleInputSupportLimits::Create();
  clamp->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.clamp_input));
  clamp->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.clamp_input));
  op_support_limits->setClamp(clamp);

  MLConcatSupportLimits* concat = MLConcatSupportLimits::Create();
  concat->setInputs(
      SupportedDataTypesToSupportLimits(data_type_limits.concat_inputs));
  concat->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.concat_inputs));
  op_support_limits->setConcat(concat);

  MLConv2dSupportLimits* conv2d = MLConv2dSupportLimits::Create();
  conv2d->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.conv2d_input));
  conv2d->setFilter(
      SupportedDataTypesToSupportLimits(data_type_limits.conv2d_input));
  conv2d->setBias(
      SupportedDataTypesToSupportLimits(data_type_limits.conv2d_input));
  conv2d->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.conv2d_input));
  op_support_limits->setConv2d(conv2d);

  MLConv2dSupportLimits* conv_transpose2d = MLConv2dSupportLimits::Create();
  conv_transpose2d->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.conv_transpose2d_input));
  conv_transpose2d->setFilter(SupportedDataTypesToSupportLimits(
      data_type_limits.conv_transpose2d_input));
  conv_transpose2d->setBias(SupportedDataTypesToSupportLimits(
      data_type_limits.conv_transpose2d_input));
  conv_transpose2d->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.conv_transpose2d_input));
  op_support_limits->setConvTranspose2d(conv_transpose2d);

  MLSingleInputSupportLimits* cumulative_sum =
      MLSingleInputSupportLimits::Create();
  cumulative_sum->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.cumulative_sum_input));
  cumulative_sum->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.cumulative_sum_input));
  op_support_limits->setCumulativeSum(cumulative_sum);

  MLQuantizeDequantizeLinearSupportLimits* dequantize_linear =
      MLQuantizeDequantizeLinearSupportLimits::Create();
  dequantize_linear->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.dequantize_linear_input));
  dequantize_linear->setScale(SupportedDataTypesToSupportLimits(
      data_type_limits.dequantize_linear_scale));
  dequantize_linear->setZeroPoint(SupportedDataTypesToSupportLimits(
      data_type_limits.dequantize_linear_input));
  dequantize_linear->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.dequantize_linear_scale));
  op_support_limits->setDequantizeLinear(dequantize_linear);

  // Element-wise binary ops.
  MLBinarySupportLimits* add = MLBinarySupportLimits::Create();
  add->setA(SupportedDataTypesToSupportLimits(data_type_limits.add_input));
  add->setB(SupportedDataTypesToSupportLimits(data_type_limits.add_input));
  add->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.add_input));
  op_support_limits->setAdd(add);
  MLBinarySupportLimits* sub = MLBinarySupportLimits::Create();
  sub->setA(SupportedDataTypesToSupportLimits(data_type_limits.sub_input));
  sub->setB(SupportedDataTypesToSupportLimits(data_type_limits.sub_input));
  sub->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.sub_input));
  op_support_limits->setSub(sub);
  MLBinarySupportLimits* mul = MLBinarySupportLimits::Create();
  mul->setA(SupportedDataTypesToSupportLimits(data_type_limits.mul_input));
  mul->setB(SupportedDataTypesToSupportLimits(data_type_limits.mul_input));
  mul->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.mul_input));
  op_support_limits->setMul(mul);
  MLBinarySupportLimits* div = MLBinarySupportLimits::Create();
  div->setA(SupportedDataTypesToSupportLimits(data_type_limits.div_input));
  div->setB(SupportedDataTypesToSupportLimits(data_type_limits.div_input));
  div->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.div_input));
  op_support_limits->setDiv(div);
  MLBinarySupportLimits* max = MLBinarySupportLimits::Create();
  max->setA(SupportedDataTypesToSupportLimits(data_type_limits.max_input));
  max->setB(SupportedDataTypesToSupportLimits(data_type_limits.max_input));
  max->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.max_input));
  op_support_limits->setMax(max);
  MLBinarySupportLimits* min = MLBinarySupportLimits::Create();
  min->setA(SupportedDataTypesToSupportLimits(data_type_limits.min_input));
  min->setB(SupportedDataTypesToSupportLimits(data_type_limits.min_input));
  min->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.min_input));
  op_support_limits->setMin(min);
  MLBinarySupportLimits* pow = MLBinarySupportLimits::Create();
  pow->setA(SupportedDataTypesToSupportLimits(data_type_limits.pow_input));
  pow->setB(SupportedDataTypesToSupportLimits(data_type_limits.pow_input));
  pow->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.pow_input));
  op_support_limits->setPow(pow);

  // Element-wise logical ops.
  MLBinarySupportLimits* equal = MLBinarySupportLimits::Create();
  equal->setA(SupportedDataTypesToSupportLimits(data_type_limits.equal_input));
  equal->setB(SupportedDataTypesToSupportLimits(data_type_limits.equal_input));
  equal->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setEqual(equal);
  MLBinarySupportLimits* greater = MLBinarySupportLimits::Create();
  greater->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.greater_input));
  greater->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.greater_input));
  greater->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setGreater(greater);
  MLBinarySupportLimits* greater_or_equal = MLBinarySupportLimits::Create();
  greater_or_equal->setA(SupportedDataTypesToSupportLimits(
      data_type_limits.greater_or_equal_input));
  greater_or_equal->setB(SupportedDataTypesToSupportLimits(
      data_type_limits.greater_or_equal_input));
  greater_or_equal->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setGreaterOrEqual(greater_or_equal);
  MLBinarySupportLimits* lesser = MLBinarySupportLimits::Create();
  lesser->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.lesser_input));
  lesser->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.lesser_input));
  lesser->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLesser(lesser);
  MLBinarySupportLimits* lesser_or_equal = MLBinarySupportLimits::Create();
  lesser_or_equal->setA(SupportedDataTypesToSupportLimits(
      data_type_limits.lesser_or_equal_input));
  lesser_or_equal->setB(SupportedDataTypesToSupportLimits(
      data_type_limits.lesser_or_equal_input));
  lesser_or_equal->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLesserOrEqual(lesser_or_equal);
  MLBinarySupportLimits* logical_and = MLBinarySupportLimits::Create();
  logical_and->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_and_input));
  logical_and->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_and_input));
  logical_and->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLogicalAnd(logical_and);
  MLBinarySupportLimits* logical_or = MLBinarySupportLimits::Create();
  logical_or->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_or_input));
  logical_or->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_or_input));
  logical_or->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLogicalOr(logical_or);
  MLBinarySupportLimits* logical_xor = MLBinarySupportLimits::Create();
  logical_xor->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_xor_input));
  logical_xor->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_xor_input));
  logical_xor->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLogicalXor(logical_xor);
  MLLogicalNotSupportLimits* logical_not = MLLogicalNotSupportLimits::Create();
  logical_not->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_not_input));
  logical_not->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLogicalNot(logical_not);

  // Element-wise unary ops.
  MLSingleInputSupportLimits* abs = MLSingleInputSupportLimits::Create();
  abs->setInput(SupportedDataTypesToSupportLimits(data_type_limits.abs_input));
  abs->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.abs_input));
  op_support_limits->setAbs(abs);
  MLSingleInputSupportLimits* ceil = MLSingleInputSupportLimits::Create();
  ceil->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.ceil_input));
  ceil->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.ceil_input));
  op_support_limits->setCeil(ceil);
  MLSingleInputSupportLimits* cos = MLSingleInputSupportLimits::Create();
  cos->setInput(SupportedDataTypesToSupportLimits(data_type_limits.cos_input));
  cos->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.cos_input));
  op_support_limits->setCos(cos);
  MLSingleInputSupportLimits* erf = MLSingleInputSupportLimits::Create();
  erf->setInput(SupportedDataTypesToSupportLimits(data_type_limits.erf_input));
  erf->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.erf_input));
  op_support_limits->setErf(erf);
  MLSingleInputSupportLimits* exp = MLSingleInputSupportLimits::Create();
  exp->setInput(SupportedDataTypesToSupportLimits(data_type_limits.exp_input));
  exp->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.exp_input));
  op_support_limits->setExp(exp);
  MLSingleInputSupportLimits* floor = MLSingleInputSupportLimits::Create();
  floor->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.floor_input));
  floor->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.floor_input));
  op_support_limits->setFloor(floor);
  MLSingleInputSupportLimits* identity = MLSingleInputSupportLimits::Create();
  identity->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.identity_input));
  identity->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.identity_input));
  op_support_limits->setIdentity(identity);
  MLSingleInputSupportLimits* log = MLSingleInputSupportLimits::Create();
  log->setInput(SupportedDataTypesToSupportLimits(data_type_limits.log_input));
  log->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.log_input));
  op_support_limits->setLog(log);
  MLSingleInputSupportLimits* neg = MLSingleInputSupportLimits::Create();
  neg->setInput(SupportedDataTypesToSupportLimits(data_type_limits.neg_input));
  neg->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.neg_input));
  op_support_limits->setNeg(neg);
  MLSingleInputSupportLimits* reciprocal = MLSingleInputSupportLimits::Create();
  reciprocal->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reciprocal_input));
  reciprocal->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reciprocal_input));
  op_support_limits->setReciprocal(reciprocal);
  MLSingleInputSupportLimits* sign = MLSingleInputSupportLimits::Create();
  sign->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.sign_input));
  sign->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.sign_input));
  op_support_limits->setSign(sign);
  MLSingleInputSupportLimits* sin = MLSingleInputSupportLimits::Create();
  sin->setInput(SupportedDataTypesToSupportLimits(data_type_limits.sin_input));
  sin->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.sin_input));
  op_support_limits->setSin(sin);
  MLSingleInputSupportLimits* sqrt = MLSingleInputSupportLimits::Create();
  sqrt->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.sqrt_input));
  sqrt->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.sqrt_input));
  op_support_limits->setSqrt(sqrt);
  MLSingleInputSupportLimits* tan = MLSingleInputSupportLimits::Create();
  tan->setInput(SupportedDataTypesToSupportLimits(data_type_limits.tan_input));
  tan->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.tan_input));
  op_support_limits->setTan(tan);

  MLSingleInputSupportLimits* elu = MLSingleInputSupportLimits::Create();
  elu->setInput(SupportedDataTypesToSupportLimits(data_type_limits.elu_input));
  
Prompt: 
```
这是目录为blink/renderer/modules/ml/ml_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ml/ml_context.h"

#include "base/feature_list.h"
#include "base/numerics/checked_math.h"
#include "base/types/cxx23_to_underlying.h"
#include "base/types/expected_macros.h"
#include "base/types/pass_key.h"
#include "services/webnn/public/cpp/context_properties.h"
#include "services/webnn/public/cpp/graph_validation_utils.h"
#include "services/webnn/public/cpp/operand_descriptor.h"
#include "services/webnn/public/cpp/supported_data_types.h"
#include "services/webnn/public/cpp/webnn_errors.h"
#include "services/webnn/public/mojom/features.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_context_provider.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_graph_builder.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_tensor.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_batch_normalization_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_binary_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_concat_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_context_lost_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_context_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_conv_2d_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_device_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gather_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gemm_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gru_cell_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gru_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_logical_not_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_cell_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_normalization_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_op_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_operand_data_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_power_preference.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_prelu_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_quantize_dequantize_linear_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_scatter_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_single_input_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_support_limits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_tensor_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_where_support_limits.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer_view_helpers.h"
#include "third_party/blink/renderer/modules/ml/ml_trace.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_error.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_utils.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_tensor.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

namespace {

MLSupportLimits* SupportedDataTypesToSupportLimits(
    const webnn::SupportedDataTypes& supported_data_types) {
  MLSupportLimits* support_limits = MLSupportLimits::Create();
  Vector<String> data_types;
  for (auto data_type : supported_data_types) {
    data_types.push_back(webnn::DataTypeToString(data_type));
  }

  support_limits->setDataTypes(data_types);
  return support_limits;
}

blink::V8MLInputOperandLayout::Enum InputOperandLayoutToBlink(
    webnn::InputOperandLayout layout) {
  switch (layout) {
    case webnn::InputOperandLayout::kNchw:
      return blink::V8MLInputOperandLayout::Enum::kNchw;
    case webnn::InputOperandLayout::kNhwc:
      return blink::V8MLInputOperandLayout::Enum::kNhwc;
  }
}

}  // namespace

MLContext::MLContext(
    ExecutionContext* execution_context,
    const V8MLDeviceType device_type,
    const V8MLPowerPreference power_preference,
    webnn::mojom::blink::CreateContextSuccessPtr create_context_success)
    : device_type_(device_type),
      power_preference_(power_preference),
      lost_property_(MakeGarbageCollected<LostProperty>(execution_context)),
      context_remote_(execution_context),
      properties_(std::move(create_context_success->context_properties)),
      webnn_handle_(std::move(create_context_success->context_handle)) {
  context_remote_.Bind(
      std::move(create_context_success->context_remote),
      execution_context->GetTaskRunner(TaskType::kMachineLearning));
  context_remote_.set_disconnect_with_reason_handler(
      WTF::BindOnce(&MLContext::OnLost, WrapWeakPersistent(this)));
}

MLContext::~MLContext() = default;

V8MLDeviceType MLContext::GetDeviceType() const {
  return device_type_;
}

V8MLPowerPreference MLContext::GetPowerPreference() const {
  return power_preference_;
}

void MLContext::Trace(Visitor* visitor) const {
  visitor->Trace(lost_property_);
  visitor->Trace(context_remote_);
  visitor->Trace(pending_resolvers_);
  visitor->Trace(graphs_);
  visitor->Trace(graph_builders_);
  visitor->Trace(tensors_);
  ScriptWrappable::Trace(visitor);
}

ScriptPromise<MLContextLostInfo> MLContext::lost(ScriptState* script_state) {
  return lost_property_->Promise(script_state->World());
}

void MLContext::destroy(ScriptState* script_state,
                        ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "destroy() called on an invalid context.");
    return;
  }

  if (context_remote_.is_bound()) {
    OnLost(0, "destroy() called on MLContext.");

    for (const auto& graph : graphs_) {
      graph->destroy();
    }

    for (const auto& graph_builder : graph_builders_) {
      graph_builder->OnConnectionError();
    }

    for (const auto& tensor : tensors_) {
      tensor->destroy();
    }
  }
}

MLGraphBuilder* MLContext::CreateWebNNGraphBuilder(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!context_remote_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Context is lost.");
    return nullptr;
  }

  mojo::PendingAssociatedRemote<webnn::mojom::blink::WebNNGraphBuilder>
      pending_remote;
  context_remote_->CreateGraphBuilder(
      pending_remote.InitWithNewEndpointAndPassReceiver());

  auto* graph_builder = MakeGarbageCollected<MLGraphBuilder>(
      ExecutionContext::From(script_state), this, std::move(pending_remote));
  graph_builders_.insert(graph_builder);

  return graph_builder;
}

void MLContext::OnLost(uint32_t custom_reason, const std::string& description) {
  context_remote_.reset();

  auto* context_lost_info = MLContextLostInfo::Create();
  if (description.empty()) {
    context_lost_info->setMessage(
        "WebNN context is lost due to connection error.");
  } else {
    context_lost_info->setMessage(String::FromUTF8(description));
  }

  CHECK_EQ(lost_property_->GetState(), LostProperty::kPending);
  lost_property_->Resolve(context_lost_info);

  for (const auto& resolver : pending_resolvers_) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "Context is lost.");
  }
  pending_resolvers_.clear();
}

const MLOpSupportLimits* MLContext::opSupportLimits(ScriptState* script_state) {
  const webnn::DataTypeLimits& data_type_limits = properties_.data_type_limits;

  MLOpSupportLimits* op_support_limits = MLOpSupportLimits::Create();
  op_support_limits->setPreferredInputLayout(
      InputOperandLayoutToBlink(properties_.input_operand_layout));
  op_support_limits->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.input));
  op_support_limits->setConstant(
      SupportedDataTypesToSupportLimits(data_type_limits.constant));
  op_support_limits->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.output()));

  MLSingleInputSupportLimits* argmin = MLSingleInputSupportLimits::Create();
  argmin->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.arg_min_max_input));
  argmin->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.arg_min_max_output));
  op_support_limits->setArgMin(argmin);
  MLSingleInputSupportLimits* argmax = MLSingleInputSupportLimits::Create();
  argmax->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.arg_min_max_input));
  argmax->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.arg_min_max_output));
  op_support_limits->setArgMax(argmax);

  MLBatchNormalizationSupportLimits* batch_normalization =
      MLBatchNormalizationSupportLimits::Create();
  batch_normalization->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setMean(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setVariance(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setScale(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setBias(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  batch_normalization->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.batch_normalization_input));
  op_support_limits->setBatchNormalization(batch_normalization);

  MLSingleInputSupportLimits* cast = MLSingleInputSupportLimits::Create();
  cast->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.cast_input));
  cast->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.cast_input));
  op_support_limits->setCast(cast);

  MLSingleInputSupportLimits* clamp = MLSingleInputSupportLimits::Create();
  clamp->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.clamp_input));
  clamp->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.clamp_input));
  op_support_limits->setClamp(clamp);

  MLConcatSupportLimits* concat = MLConcatSupportLimits::Create();
  concat->setInputs(
      SupportedDataTypesToSupportLimits(data_type_limits.concat_inputs));
  concat->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.concat_inputs));
  op_support_limits->setConcat(concat);

  MLConv2dSupportLimits* conv2d = MLConv2dSupportLimits::Create();
  conv2d->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.conv2d_input));
  conv2d->setFilter(
      SupportedDataTypesToSupportLimits(data_type_limits.conv2d_input));
  conv2d->setBias(
      SupportedDataTypesToSupportLimits(data_type_limits.conv2d_input));
  conv2d->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.conv2d_input));
  op_support_limits->setConv2d(conv2d);

  MLConv2dSupportLimits* conv_transpose2d = MLConv2dSupportLimits::Create();
  conv_transpose2d->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.conv_transpose2d_input));
  conv_transpose2d->setFilter(SupportedDataTypesToSupportLimits(
      data_type_limits.conv_transpose2d_input));
  conv_transpose2d->setBias(SupportedDataTypesToSupportLimits(
      data_type_limits.conv_transpose2d_input));
  conv_transpose2d->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.conv_transpose2d_input));
  op_support_limits->setConvTranspose2d(conv_transpose2d);

  MLSingleInputSupportLimits* cumulative_sum =
      MLSingleInputSupportLimits::Create();
  cumulative_sum->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.cumulative_sum_input));
  cumulative_sum->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.cumulative_sum_input));
  op_support_limits->setCumulativeSum(cumulative_sum);

  MLQuantizeDequantizeLinearSupportLimits* dequantize_linear =
      MLQuantizeDequantizeLinearSupportLimits::Create();
  dequantize_linear->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.dequantize_linear_input));
  dequantize_linear->setScale(SupportedDataTypesToSupportLimits(
      data_type_limits.dequantize_linear_scale));
  dequantize_linear->setZeroPoint(SupportedDataTypesToSupportLimits(
      data_type_limits.dequantize_linear_input));
  dequantize_linear->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.dequantize_linear_scale));
  op_support_limits->setDequantizeLinear(dequantize_linear);

  // Element-wise binary ops.
  MLBinarySupportLimits* add = MLBinarySupportLimits::Create();
  add->setA(SupportedDataTypesToSupportLimits(data_type_limits.add_input));
  add->setB(SupportedDataTypesToSupportLimits(data_type_limits.add_input));
  add->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.add_input));
  op_support_limits->setAdd(add);
  MLBinarySupportLimits* sub = MLBinarySupportLimits::Create();
  sub->setA(SupportedDataTypesToSupportLimits(data_type_limits.sub_input));
  sub->setB(SupportedDataTypesToSupportLimits(data_type_limits.sub_input));
  sub->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.sub_input));
  op_support_limits->setSub(sub);
  MLBinarySupportLimits* mul = MLBinarySupportLimits::Create();
  mul->setA(SupportedDataTypesToSupportLimits(data_type_limits.mul_input));
  mul->setB(SupportedDataTypesToSupportLimits(data_type_limits.mul_input));
  mul->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.mul_input));
  op_support_limits->setMul(mul);
  MLBinarySupportLimits* div = MLBinarySupportLimits::Create();
  div->setA(SupportedDataTypesToSupportLimits(data_type_limits.div_input));
  div->setB(SupportedDataTypesToSupportLimits(data_type_limits.div_input));
  div->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.div_input));
  op_support_limits->setDiv(div);
  MLBinarySupportLimits* max = MLBinarySupportLimits::Create();
  max->setA(SupportedDataTypesToSupportLimits(data_type_limits.max_input));
  max->setB(SupportedDataTypesToSupportLimits(data_type_limits.max_input));
  max->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.max_input));
  op_support_limits->setMax(max);
  MLBinarySupportLimits* min = MLBinarySupportLimits::Create();
  min->setA(SupportedDataTypesToSupportLimits(data_type_limits.min_input));
  min->setB(SupportedDataTypesToSupportLimits(data_type_limits.min_input));
  min->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.min_input));
  op_support_limits->setMin(min);
  MLBinarySupportLimits* pow = MLBinarySupportLimits::Create();
  pow->setA(SupportedDataTypesToSupportLimits(data_type_limits.pow_input));
  pow->setB(SupportedDataTypesToSupportLimits(data_type_limits.pow_input));
  pow->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.pow_input));
  op_support_limits->setPow(pow);

  // Element-wise logical ops.
  MLBinarySupportLimits* equal = MLBinarySupportLimits::Create();
  equal->setA(SupportedDataTypesToSupportLimits(data_type_limits.equal_input));
  equal->setB(SupportedDataTypesToSupportLimits(data_type_limits.equal_input));
  equal->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setEqual(equal);
  MLBinarySupportLimits* greater = MLBinarySupportLimits::Create();
  greater->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.greater_input));
  greater->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.greater_input));
  greater->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setGreater(greater);
  MLBinarySupportLimits* greater_or_equal = MLBinarySupportLimits::Create();
  greater_or_equal->setA(SupportedDataTypesToSupportLimits(
      data_type_limits.greater_or_equal_input));
  greater_or_equal->setB(SupportedDataTypesToSupportLimits(
      data_type_limits.greater_or_equal_input));
  greater_or_equal->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setGreaterOrEqual(greater_or_equal);
  MLBinarySupportLimits* lesser = MLBinarySupportLimits::Create();
  lesser->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.lesser_input));
  lesser->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.lesser_input));
  lesser->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLesser(lesser);
  MLBinarySupportLimits* lesser_or_equal = MLBinarySupportLimits::Create();
  lesser_or_equal->setA(SupportedDataTypesToSupportLimits(
      data_type_limits.lesser_or_equal_input));
  lesser_or_equal->setB(SupportedDataTypesToSupportLimits(
      data_type_limits.lesser_or_equal_input));
  lesser_or_equal->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLesserOrEqual(lesser_or_equal);
  MLBinarySupportLimits* logical_and = MLBinarySupportLimits::Create();
  logical_and->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_and_input));
  logical_and->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_and_input));
  logical_and->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLogicalAnd(logical_and);
  MLBinarySupportLimits* logical_or = MLBinarySupportLimits::Create();
  logical_or->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_or_input));
  logical_or->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_or_input));
  logical_or->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLogicalOr(logical_or);
  MLBinarySupportLimits* logical_xor = MLBinarySupportLimits::Create();
  logical_xor->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_xor_input));
  logical_xor->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_xor_input));
  logical_xor->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLogicalXor(logical_xor);
  MLLogicalNotSupportLimits* logical_not = MLLogicalNotSupportLimits::Create();
  logical_not->setA(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_not_input));
  logical_not->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.logical_output));
  op_support_limits->setLogicalNot(logical_not);

  // Element-wise unary ops.
  MLSingleInputSupportLimits* abs = MLSingleInputSupportLimits::Create();
  abs->setInput(SupportedDataTypesToSupportLimits(data_type_limits.abs_input));
  abs->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.abs_input));
  op_support_limits->setAbs(abs);
  MLSingleInputSupportLimits* ceil = MLSingleInputSupportLimits::Create();
  ceil->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.ceil_input));
  ceil->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.ceil_input));
  op_support_limits->setCeil(ceil);
  MLSingleInputSupportLimits* cos = MLSingleInputSupportLimits::Create();
  cos->setInput(SupportedDataTypesToSupportLimits(data_type_limits.cos_input));
  cos->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.cos_input));
  op_support_limits->setCos(cos);
  MLSingleInputSupportLimits* erf = MLSingleInputSupportLimits::Create();
  erf->setInput(SupportedDataTypesToSupportLimits(data_type_limits.erf_input));
  erf->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.erf_input));
  op_support_limits->setErf(erf);
  MLSingleInputSupportLimits* exp = MLSingleInputSupportLimits::Create();
  exp->setInput(SupportedDataTypesToSupportLimits(data_type_limits.exp_input));
  exp->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.exp_input));
  op_support_limits->setExp(exp);
  MLSingleInputSupportLimits* floor = MLSingleInputSupportLimits::Create();
  floor->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.floor_input));
  floor->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.floor_input));
  op_support_limits->setFloor(floor);
  MLSingleInputSupportLimits* identity = MLSingleInputSupportLimits::Create();
  identity->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.identity_input));
  identity->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.identity_input));
  op_support_limits->setIdentity(identity);
  MLSingleInputSupportLimits* log = MLSingleInputSupportLimits::Create();
  log->setInput(SupportedDataTypesToSupportLimits(data_type_limits.log_input));
  log->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.log_input));
  op_support_limits->setLog(log);
  MLSingleInputSupportLimits* neg = MLSingleInputSupportLimits::Create();
  neg->setInput(SupportedDataTypesToSupportLimits(data_type_limits.neg_input));
  neg->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.neg_input));
  op_support_limits->setNeg(neg);
  MLSingleInputSupportLimits* reciprocal = MLSingleInputSupportLimits::Create();
  reciprocal->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reciprocal_input));
  reciprocal->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reciprocal_input));
  op_support_limits->setReciprocal(reciprocal);
  MLSingleInputSupportLimits* sign = MLSingleInputSupportLimits::Create();
  sign->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.sign_input));
  sign->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.sign_input));
  op_support_limits->setSign(sign);
  MLSingleInputSupportLimits* sin = MLSingleInputSupportLimits::Create();
  sin->setInput(SupportedDataTypesToSupportLimits(data_type_limits.sin_input));
  sin->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.sin_input));
  op_support_limits->setSin(sin);
  MLSingleInputSupportLimits* sqrt = MLSingleInputSupportLimits::Create();
  sqrt->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.sqrt_input));
  sqrt->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.sqrt_input));
  op_support_limits->setSqrt(sqrt);
  MLSingleInputSupportLimits* tan = MLSingleInputSupportLimits::Create();
  tan->setInput(SupportedDataTypesToSupportLimits(data_type_limits.tan_input));
  tan->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.tan_input));
  op_support_limits->setTan(tan);

  MLSingleInputSupportLimits* elu = MLSingleInputSupportLimits::Create();
  elu->setInput(SupportedDataTypesToSupportLimits(data_type_limits.elu_input));
  elu->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.elu_input));
  op_support_limits->setElu(elu);

  MLSingleInputSupportLimits* expand = MLSingleInputSupportLimits::Create();
  expand->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.expand_input));
  expand->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.expand_input));
  op_support_limits->setExpand(expand);

  MLGatherSupportLimits* gather = MLGatherSupportLimits::Create();
  gather->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.gather_input));
  gather->setIndices(
      SupportedDataTypesToSupportLimits(data_type_limits.gather_indices));
  gather->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.gather_input));
  op_support_limits->setGather(gather);

  MLGatherSupportLimits* gather_elements = MLGatherSupportLimits::Create();
  gather_elements->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.gather_elements_input));
  gather_elements->setIndices(SupportedDataTypesToSupportLimits(
      data_type_limits.gather_elements_indices));
  gather_elements->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.gather_elements_input));
  op_support_limits->setGatherElements(gather_elements);

  MLGatherSupportLimits* gather_nd = MLGatherSupportLimits::Create();
  gather_nd->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.gather_nd_input));
  gather_nd->setIndices(
      SupportedDataTypesToSupportLimits(data_type_limits.gather_nd_indices));
  gather_nd->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.gather_nd_input));
  op_support_limits->setGatherND(gather_nd);

  MLSingleInputSupportLimits* gelu = MLSingleInputSupportLimits::Create();
  gelu->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.gelu_input));
  gelu->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.gelu_input));
  op_support_limits->setGelu(gelu);

  MLGemmSupportLimits* gemm = MLGemmSupportLimits::Create();
  gemm->setA(SupportedDataTypesToSupportLimits(data_type_limits.gemm_input));
  gemm->setB(SupportedDataTypesToSupportLimits(data_type_limits.gemm_input));
  gemm->setC(SupportedDataTypesToSupportLimits(data_type_limits.gemm_input));
  gemm->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.gemm_input));
  op_support_limits->setGemm(gemm);

  MLGruSupportLimits* gru = MLGruSupportLimits::Create();
  gru->setInput(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_input));
  gru->setWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_input));
  gru->setRecurrentWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_input));
  gru->setBias(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_input));
  gru->setRecurrentBias(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_input));
  gru->setInitialHiddenState(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_input));
  gru->setOutputs(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_input));
  op_support_limits->setGru(gru);

  MLGruCellSupportLimits* gru_cell = MLGruCellSupportLimits::Create();
  gru_cell->setInput(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_cell_input));
  gru_cell->setWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_cell_input));
  gru_cell->setRecurrentWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_cell_input));
  gru_cell->setHiddenState(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_cell_input));
  gru_cell->setBias(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_cell_input));
  gru_cell->setRecurrentBias(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_cell_input));
  gru_cell->setOutput(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.gru_cell_input));
  op_support_limits->setGruCell(gru_cell);

  MLSingleInputSupportLimits* hard_sigmoid =
      MLSingleInputSupportLimits::Create();
  hard_sigmoid->setInput(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.hard_sigmoid_input));
  hard_sigmoid->setOutput(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.hard_sigmoid_input));
  op_support_limits->setHardSigmoid(hard_sigmoid);

  MLSingleInputSupportLimits* hard_swish = MLSingleInputSupportLimits::Create();
  hard_swish->setInput(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.hard_swish_input));
  hard_swish->setOutput(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.hard_swish_input));
  op_support_limits->setHardSwish(hard_swish);

  MLNormalizationSupportLimits* instance_normalization =
      MLNormalizationSupportLimits::Create();
  instance_normalization->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.instance_normalization_input));
  instance_normalization->setScale(SupportedDataTypesToSupportLimits(
      data_type_limits.instance_normalization_input));
  instance_normalization->setBias(SupportedDataTypesToSupportLimits(
      data_type_limits.instance_normalization_input));
  instance_normalization->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.instance_normalization_input));
  op_support_limits->setInstanceNormalization(instance_normalization);

  MLNormalizationSupportLimits* layer_normalization =
      MLNormalizationSupportLimits::Create();
  layer_normalization->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.layer_normalization_input));
  layer_normalization->setScale(SupportedDataTypesToSupportLimits(
      data_type_limits.layer_normalization_input));
  layer_normalization->setBias(SupportedDataTypesToSupportLimits(
      data_type_limits.layer_normalization_input));
  layer_normalization->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.layer_normalization_input));
  op_support_limits->setLayerNormalization(layer_normalization);

  MLSingleInputSupportLimits* leaky_relu = MLSingleInputSupportLimits::Create();
  leaky_relu->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.leaky_relu_input));
  leaky_relu->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.leaky_relu_input));
  op_support_limits->setLeakyRelu(leaky_relu);

  MLSingleInputSupportLimits* linear = MLSingleInputSupportLimits::Create();
  linear->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.linear_input));
  linear->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.linear_input));
  op_support_limits->setLinear(linear);

  MLLstmSupportLimits* lstm = MLLstmSupportLimits::Create();
  lstm->setInput(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_input));
  lstm->setWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_input));
  lstm->setRecurrentWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_input));
  lstm->setBias(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_input));
  lstm->setRecurrentBias(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_input));
  lstm->setPeepholeWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_input));
  lstm->setInitialHiddenState(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_input));
  lstm->setInitialCellState(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_input));
  lstm->setOutputs(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_input));
  op_support_limits->setLstm(lstm);

  MLLstmCellSupportLimits* lstm_cell = MLLstmCellSupportLimits::Create();
  lstm_cell->setInput(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_cell_input));
  lstm_cell->setWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_cell_input));
  lstm_cell->setRecurrentWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_cell_input));
  lstm_cell->setHiddenState(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_cell_input));
  lstm_cell->setCellState(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_cell_input));
  lstm_cell->setBias(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_cell_input));
  lstm_cell->setRecurrentBias(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_cell_input));
  lstm_cell->setPeepholeWeight(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_cell_input));
  lstm_cell->setOutputs(SupportedDataTypesToSupportLimits(
      properties_.data_type_limits.lstm_cell_input));
  op_support_limits->setLstmCell(lstm_cell);

  MLBinarySupportLimits* matmul = MLBinarySupportLimits::Create();
  matmul->setA(
      SupportedDataT
"""


```