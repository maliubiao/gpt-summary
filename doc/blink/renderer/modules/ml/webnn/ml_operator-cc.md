Response:
Let's break down the thought process for analyzing this `ml_operator.cc` file.

1. **Identify the Core Purpose:** The filename `ml_operator.cc` and the namespace `blink::ml::webnn` strongly suggest this file defines the representation of WebNN (Web Neural Network API) operators within the Blink rendering engine. It's likely responsible for mapping high-level WebNN concepts to lower-level representations.

2. **Scan for Key Structures and Functions:**  A quick scan reveals:
    * The `MLOperator` class: This is clearly the central class. It likely represents a single WebNN operation.
    * Enumerations/Switch Statements based on `webnn::mojom::blink::Operation::Tag`:  This indicates the file handles different types of WebNN operations. The `OperatorKindToString` function is a prime example.
    * Derived classes like `MLArgMinMaxOperator`, `MLConcatOperator`, etc.: These suggest specialized classes for specific operator types, inheriting from the base `MLOperator`.
    * Inclusion of V8 binding headers (`v8_ml_*_options.h`): This points to the interaction with JavaScript and the WebNN API exposed to developers.

3. **Analyze `MLOperator::OperatorKindToString`:** This function is crucial for understanding the scope of the file. It maps `webnn::mojom::blink::Operation::Tag` enum values (and sometimes a `sub_kind`) to human-readable string representations (e.g., "add", "conv2d", "relu"). This directly relates to how WebNN operators are identified and potentially serialized or logged.

4. **Examine the `MLOperator` Class:**
    * Constructor and Destructor:  Basic lifecycle management.
    * `builder_`:  A pointer to `MLGraphBuilder`, suggesting operators are constructed within the context of a larger graph.
    * `kind_`, `sub_kind_`: Store the type of operation.
    * `options_`:  A pointer to `MLOperatorOptions`, indicating configuration specific to each operator.
    * `inputs_`, `outputs_`:  Vectors of `MLOperand`, representing the data flow into and out of the operator. This is fundamental to how neural networks are structured.
    * `Connect` method:  This is how operators are linked together in a graph, defining the data dependencies.

5. **Investigate Derived Operator Classes:**  Classes like `MLArgMinMaxOperator`, `MLConcatOperator`, etc., each have:
    * A constructor taking specific parameters relevant to that operation (e.g., `axis` for `MLConcatOperator`).
    * Storage for these specific parameters as member variables.
    * They inherit from `MLOperator`, inheriting the core structure and functionality.

6. **Identify Connections to JavaScript, HTML, and CSS:**
    * **JavaScript:** The inclusion of `v8_ml_*_options.h` headers strongly implies a direct link. These headers define the V8 bindings for the JavaScript WebNN API. The C++ code in `ml_operator.cc` *implements* the functionality exposed through these bindings. JavaScript code will call methods that eventually lead to the creation and execution of these `MLOperator` objects.
    * **HTML:** While not directly manipulating HTML elements, WebNN functionality (and thus this code) could be triggered by user interactions within an HTML page (e.g., clicking a button that starts a machine learning inference). The `<canvas>` element is often used for visualizing or providing input to ML models.
    * **CSS:**  Less direct. CSS could *indirectly* influence WebNN by affecting the rendering of input or output data. For instance, CSS might style the video feed used as input for an object detection model.

7. **Consider Logical Inference and User Errors:**
    * **Logical Inference:** The code itself doesn't perform inference. It *defines* the building blocks (operators) that will be used by a separate inference engine. The logic here is about *representing* the operations correctly.
    * **User Errors:** Focus on common mistakes when using the WebNN API in JavaScript that would lead to issues handled by this code. Mismatched input shapes, incorrect data types, and using unsupported options are prime examples.

8. **Trace User Operations to This Code:** Think about the sequence of events when a web developer uses the WebNN API:
    * JavaScript code is written using the `navigator.ml.createGraphBuilder()` and methods on the `MLGraphBuilder` interface (like `add`, `conv2d`, etc.).
    * These JavaScript calls translate into calls within the Blink rendering engine.
    * The `MLGraphBuilder` (likely the class pointed to by `builder_`) uses the information from the JavaScript calls to create instances of the `MLOperator` subclasses defined in this file.

9. **Structure the Answer:**  Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logical Inference, User Errors, and Debugging Clues. Use examples to illustrate the points.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file directly *executes* the ML operations. **Correction:** The presence of `MLGraphBuilder` and the focus on *defining* operators suggests it's more about the *structure* of the computation graph. Execution likely happens elsewhere.
* **Overemphasis on specific HTML/CSS elements:**  While `<canvas>` is common, the connection is more about the *triggering* of WebNN rather than direct manipulation of specific elements *within this file*.
* **Focusing too much on low-level implementation details:** The request asks for the *functionality* from a higher-level perspective. Avoid diving too deep into the intricacies of the `mojom` definitions unless necessary to explain the core purpose.

By following this kind of structured analysis, combining code scanning with an understanding of the surrounding WebNN ecosystem, one can effectively determine the functionality and context of a file like `ml_operator.cc`.
This C++ source code file, `ml_operator.cc`, located within the Chromium Blink engine, is a crucial component for implementing the **Web Neural Network API (WebNN)**. It defines the core representation of various **neural network operators** that can be used to build and execute machine learning models in web browsers.

Here's a breakdown of its functionality:

**1. Definition of MLOperator Class Hierarchy:**

* **`MLOperator`:** This is the base class for all WebNN operators. It encapsulates common properties and behaviors shared by all operators, such as:
    * **`builder_`:** A pointer to the `MLGraphBuilder` which was used to create this operator. This links the operator back to the overall computational graph.
    * **`kind_`:**  An enumeration (`webnn::mojom::blink::Operation::Tag`) indicating the specific type of operation (e.g., `kConv2d`, `kAdd`, `kRelu`).
    * **`sub_kind_`:**  An optional sub-kind for operators that have variations (e.g., `ArgMin` vs. `ArgMax` within `kArgMinMax`).
    * **`options_`:** A pointer to an `MLOperatorOptions` object (or a derived class) containing configuration parameters specific to this operator.
    * **`inputs_`:** A vector of `MLOperand` representing the input tensors to this operator.
    * **`outputs_`:** A vector of `MLOperand` representing the output tensors produced by this operator.
    * **`Connect()`:**  A method to establish the connections between operators by setting their input and output operands.

* **Derived Classes (e.g., `MLArgMinMaxOperator`, `MLConcatOperator`, etc.):**  The file then defines numerous classes that inherit from `MLOperator`. Each derived class represents a specific WebNN operator, holding any parameters unique to that operator. Examples include:
    * **`MLArgMinMaxOperator`:**  For finding the indices of the minimum or maximum values along a specified axis.
    * **`MLConcatOperator`:** For concatenating tensors along a given axis.
    * **`MLCumulativeSumOperator`:** For calculating the cumulative sum of elements along an axis.
    * **`MLLstmOperator` and `MLLstmCellOperator`:** For implementing Long Short-Term Memory (LSTM) recurrent neural network layers.
    * **`MLGruOperator` and `MLGruCellOperator`:** For implementing Gated Recurrent Unit (GRU) recurrent neural network layers.
    * **`MLPadOperator`:** For adding padding to tensors.
    * **`MLReverseOperator`:** For reversing the elements of a tensor along specified axes.
    * **`MLSliceOperator`:** For extracting a sub-tensor from a tensor.
    * **`MLSoftmaxOperator`:** For applying the softmax function.
    * **`MLSplitOperator`:** For splitting a tensor into multiple sub-tensors.
    * **`MLTileOperator`:** For repeating the elements of a tensor.

**2. Mapping WebNN Operator Kinds to Strings:**

* **`OperatorKindToString()`:** This static function is crucial for debugging and potentially for serialization or logging. It takes the raw operator kind (`webnn::mojom::blink::Operation::Tag`) and sub-kind and returns a human-readable string representation of the operator (e.g., "add", "conv2d", "softmax"). This makes it easier to understand what type of operation is being performed.

**3. Management of Operator Dependencies:**

* The `Connect()` method in `MLOperator` is vital for building the computational graph. When an operator is connected to its inputs, it registers itself as a dependent operator on those input operands. This helps in managing the flow of data and ensuring that operations are executed in the correct order.

**Relationship to JavaScript, HTML, and CSS:**

This C++ file is the *implementation* behind the WebNN API that is exposed to JavaScript. Here's how it relates:

* **JavaScript:**
    * **Direct Mapping:**  The names of the operators in `OperatorKindToString()` directly correspond to the methods available on the `MLGraphBuilder` interface in the JavaScript WebNN API (e.g., `builder.add()`, `builder.conv2d()`, `builder.softmax()`).
    * **Options Objects:** The `ML*Options` classes (e.g., `MLConv2dOptions`, `MLPool2dOptions`) correspond to the option dictionaries that are passed to the JavaScript operator creation methods. The V8 binding headers included (`v8_ml_*_options.h`) handle the conversion between JavaScript objects and these C++ option classes.
    * **Operand Representation:** The `MLOperand` class (defined in `ml_operand.h`) represents the tensors that flow between operators. JavaScript interacts with `MLOperand` objects when defining the inputs and outputs of operations.

    **Example:**  A JavaScript snippet like this:

    ```javascript
    const builder = await navigator.ml.createGraphBuilder();
    const input = builder.input('input', { type: 'float32', dimensions: [1, 28, 28, 1] });
    const weights = builder.constant(new Float32Array( /* ... weight data ... */ ), [3, 3, 1, 32]);
    const conv2dOptions = { padding: 'same', strides: [1, 1] };
    const conv2dOutput = builder.conv2d(input, weights, conv2dOptions);
    // ... more operations ...
    ```

    When `builder.conv2d()` is called, the JavaScript engine will eventually invoke C++ code that uses the information provided (input operand, weights operand, and `conv2dOptions`) to create an instance of the `MLOperator` (specifically, one representing the `conv2d` operation). The `conv2dOptions` will be used to populate the corresponding fields in the `MLOperator`'s options.

* **HTML:**
    * **Triggering WebNN:** User interactions within an HTML page (e.g., clicking a button, loading an image) can trigger JavaScript code that utilizes the WebNN API.
    * **Input/Output:** HTML elements like `<canvas>` or `<video>` can be used as sources of input data for WebNN models or to display the results of WebNN computations.

* **CSS:**
    * **Indirect Influence:** CSS might indirectly influence WebNN by affecting the presentation of input data (e.g., styling an image before it's processed by a model) or the visualization of output results. However, CSS does not directly interact with the core logic defined in `ml_operator.cc`.

**Logical Inference and Examples:**

This file primarily focuses on *defining* the operators and their properties, not on performing the actual logical inference. The inference logic is handled by other parts of the WebNN implementation, which utilize the information stored in these `MLOperator` objects.

**Hypothetical Input and Output (within the context of this file):**

Imagine a scenario where the JavaScript code wants to create an "add" operation:

* **Hypothetical Input (to the C++ code):**
    * `kind`: `webnn::mojom::blink::Operation::Tag::kElementWiseBinary`
    * `sub_kind`: `webnn::mojom::blink::ElementWiseBinary::Kind::kAdd`
    * `input1`: An `MLOperand` representing the first input tensor.
    * `input2`: An `MLOperand` representing the second input tensor.
    * `options`:  An `MLOperatorOptions` object (likely empty or with default values for the "add" operation).

* **Hypothetical Output (from the C++ code):**
    * A new instance of `MLOperator` (specifically, representing an "add" operation) will be created, storing the `kind`, `sub_kind`, and references to the input `MLOperand` objects. This `MLOperator` object is then added to the `MLGraphBuilder`.

**User and Programming Common Usage Errors:**

Common errors that could lead to issues within this code or during the creation of these operators include:

* **Mismatched Input Shapes/Types:** If the JavaScript code provides input `MLOperand` objects with incompatible shapes or data types for a given operator (e.g., trying to add two tensors with different dimensions), the validation logic within the WebNN implementation (likely in other files) will detect this and prevent the creation of an invalid operator.
* **Invalid Operator Options:** Providing incorrect or unsupported values for operator options (e.g., specifying an invalid padding type for a convolution) will also lead to errors during operator creation. The V8 bindings and the `MLOperator` constructors perform validation.
* **Using Operators Incorrectly:** Trying to use an operator in a way that violates its constraints (e.g., providing a non-integer axis to an `ArgMinMax` operator) will result in errors.

**Example of a User Error:**

```javascript
// Incorrect: Trying to perform argMax on a non-existent axis
const builder = await navigator.ml.createGraphBuilder();
const inputTensor = builder.input('input', { type: 'float32', dimensions: [2, 3] });
const options = { axis: 2 }; // Error: Axis 2 does not exist for a tensor of rank 2
const argMaxOutput = builder.argMax(inputTensor, options);
```

In this case, the JavaScript call to `builder.argMax()` will eventually reach the `MLArgMinMaxOperator` constructor in `ml_operator.cc`. Validation logic, either in the constructor or earlier in the processing pipeline, will detect that the provided `axis` is out of bounds, leading to an error.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User writes JavaScript code using the WebNN API:** The developer uses methods on the `navigator.ml` object (specifically `createGraphBuilder()`) and then methods on the `MLGraphBuilder` instance (like `add()`, `conv2d()`, etc.) to define the structure of their neural network.
2. **JavaScript engine invokes Blink's WebNN implementation:** When these JavaScript WebNN API methods are called, the JavaScript engine (V8 in Chromium) will interact with the underlying C++ implementation within the Blink rendering engine.
3. **`MLGraphBuilder` methods are called:** The `MLGraphBuilder` class (likely in `ml_graph_builder.cc`) acts as a central point for creating and managing the operators in the graph. When a method like `builder.conv2d()` is called, the `MLGraphBuilder` will create an instance of the appropriate `MLOperator` subclass (in this case, likely related to convolution).
4. **`MLOperator` constructor is executed:** The constructor of the relevant `MLOperator` subclass (e.g., `MLConv2dOperator`) in `ml_operator.cc` will be invoked. This is where the specific details of the operation (input operands, options) are stored.
5. **`Connect()` method is potentially called:** After the operator is created, the `MLGraphBuilder` will likely call the `Connect()` method of the `MLOperator` to establish the links between this operator and its input operands.

**Debugging Scenario:**

If a developer encounters an error related to a specific WebNN operator (e.g., "Invalid padding value for conv2d"), a debugger could be used to step through the following sequence:

* Set a breakpoint in the JavaScript code where the problematic WebNN API call is made (e.g., `builder.conv2d()`).
* Step into the Chromium source code. You would likely first enter the V8 bindings for the WebNN API.
* Continue stepping until you reach the `MLGraphBuilder`'s implementation of the `conv2d()` method.
* Step further to enter the constructor of the `MLConv2dOperator` in `ml_operator.cc`.
* Examine the values of the input operands and the options object passed to the constructor to identify the source of the error.
* You might also step into the `OperatorKindToString()` function to verify the string representation of the operator being created.

In summary, `ml_operator.cc` is a foundational file for the WebNN API in Chromium, responsible for defining the C++ representation of the various neural network operations that can be composed to build and execute machine learning models within the browser. It bridges the gap between the JavaScript API and the underlying computation.

### 提示词
```
这是目录为blink/renderer/modules/ml/webnn/ml_operator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ml/webnn/ml_operator.h"

#include "services/webnn/public/mojom/webnn_graph.mojom-blink.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_arg_min_max_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_cumulative_sum_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gru_cell_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gru_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_cell_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_pad_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_reverse_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_slice_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_split_options.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_builder.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_operand.h"

namespace blink {

// static
String MLOperator::OperatorKindToString(
    webnn::mojom::blink::Operation::Tag kind,
    OperationSubKind sub_kind) {
  switch (kind) {
    case webnn::mojom::blink::Operation::Tag::kArgMinMax: {
      switch (absl::get<webnn::mojom::blink::ArgMinMax::Kind>(sub_kind)) {
        case webnn::mojom::blink::ArgMinMax::Kind::kMin:
          return "argMin";
        case webnn::mojom::blink::ArgMinMax::Kind::kMax:
          return "argMax";
      }
    }
    case webnn::mojom::blink::Operation::Tag::kBatchNormalization:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "batchNormalization";
    case webnn::mojom::blink::Operation::Tag::kElementWiseBinary: {
      switch (
          absl::get<webnn::mojom::blink::ElementWiseBinary::Kind>(sub_kind)) {
        case webnn::mojom::blink::ElementWiseBinary::Kind::kAdd:
          return "add";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kSub:
          return "sub";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kMul:
          return "mul";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kDiv:
          return "div";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kMin:
          return "min";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kMax:
          return "max";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kPow:
          return "pow";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kEqual:
          return "equal";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kGreater:
          return "greater";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kGreaterOrEqual:
          return "greaterOrEqual";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kLesser:
          return "lesser";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kLesserOrEqual:
          return "lesserOrEqual";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kLogicalAnd:
          return "logicalAnd";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kLogicalOr:
          return "logicalOr";
        case webnn::mojom::blink::ElementWiseBinary::Kind::kLogicalXor:
          return "logicalXor";
      }
    }
    case webnn::mojom::blink::Operation::Tag::kClamp:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "clamp";
    case webnn::mojom::blink::Operation::Tag::kConcat:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "concat";
    case webnn::mojom::blink::Operation::Tag::kConv2d: {
      switch (absl::get<webnn::mojom::blink::Conv2d::Kind>(sub_kind)) {
        case webnn::mojom::blink::Conv2d::Kind::kDirect:
          return "conv2d";
        case webnn::mojom::blink::Conv2d::Kind::kTransposed:
          return "convTranspose2d";
      }
    }
    case webnn::mojom::blink::Operation::Tag::kCumulativeSum:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "cumulativeSum";
    case webnn::mojom::blink::Operation::Tag::kDequantizeLinear:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "dequantizeLinear";
    case webnn::mojom::blink::Operation::Tag::kElementWiseUnary: {
      switch (
          absl::get<webnn::mojom::blink::ElementWiseUnary::Kind>(sub_kind)) {
        case webnn::mojom::blink::ElementWiseUnary::Kind::kAbs:
          return "abs";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kCast:
          return "cast";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kCeil:
          return "ceil";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kCos:
          return "cos";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kExp:
          return "exp";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kFloor:
          return "floor";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kLog:
          return "log";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kNeg:
          return "neg";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kSign:
          return "sign";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kSin:
          return "sin";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kTan:
          return "tan";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kErf:
          return "erf";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kIdentity:
          return "identity";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kLogicalNot:
          return "logicalNot";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kReciprocal:
          return "reciprocal";
        case webnn::mojom::blink::ElementWiseUnary::Kind::kSqrt:
          return "sqrt";
      }
    }
    case webnn::mojom::blink::Operation::Tag::kInstanceNormalization:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "instanceNormalization";
    case webnn::mojom::blink::Operation::Tag::kLayerNormalization:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "layerNormalization";
    case webnn::mojom::blink::Operation::Tag::kLeakyRelu:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "leakyRelu";
    case webnn::mojom::blink::Operation::Tag::kLinear:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "linear";
    case webnn::mojom::blink::Operation::Tag::kLstm:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "lstm";
    case webnn::mojom::blink::Operation::Tag::kLstmCell:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "lstmCell";
    case webnn::mojom::blink::Operation::Tag::kElu:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "elu";
    case webnn::mojom::blink::Operation::Tag::kExpand:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "expand";
    case webnn::mojom::blink::Operation::Tag::kGather:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "gather";
    case webnn::mojom::blink::Operation::Tag::kGatherElements:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "gatherElements";
    case webnn::mojom::blink::Operation::Tag::kGatherNd:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "gatherND";
    case webnn::mojom::blink::Operation::Tag::kGelu:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "gelu";
    case webnn::mojom::blink::Operation::Tag::kGemm:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "gemm";
    case webnn::mojom::blink::Operation::Tag::kGru:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "gru";
    case webnn::mojom::blink::Operation::Tag::kGruCell:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "gruCell";
    case webnn::mojom::blink::Operation::Tag::kHardSigmoid:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "hardSigmoid";
    case webnn::mojom::blink::Operation::Tag::kHardSwish:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "hardSwish";
    case webnn::mojom::blink::Operation::Tag::kPool2d: {
      switch (absl::get<webnn::mojom::blink::Pool2d::Kind>(sub_kind)) {
        case webnn::mojom::blink::Pool2d::Kind::kAveragePool2d:
          return "averagePool2d";
        case webnn::mojom::blink::Pool2d::Kind::kL2Pool2d:
          return "l2Pool2d";
        case webnn::mojom::blink::Pool2d::Kind::kMaxPool2d:
          return "maxPool2d";
      }
    }
    case webnn::mojom::blink::Operation::Tag::kMatmul:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "matmul";
    case webnn::mojom::blink::Operation::Tag::kPad:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "pad";
    case webnn::mojom::blink::Operation::Tag::kPrelu:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "prelu";
    case webnn::mojom::blink::Operation::Tag::kQuantizeLinear:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "quantizeLinear";
    case webnn::mojom::blink::Operation::Tag::kReduce: {
      switch (absl::get<webnn::mojom::blink::Reduce::Kind>(sub_kind)) {
        case webnn::mojom::blink::Reduce::Kind::kL1:
          return "reduceL1";
        case webnn::mojom::blink::Reduce::Kind::kL2:
          return "reduceL2";
        case webnn::mojom::blink::Reduce::Kind::kLogSum:
          return "reduceLogSum";
        case webnn::mojom::blink::Reduce::Kind::kLogSumExp:
          return "reduceLogSumExp";
        case webnn::mojom::blink::Reduce::Kind::kMax:
          return "reduceMax";
        case webnn::mojom::blink::Reduce::Kind::kMean:
          return "reduceMean";
        case webnn::mojom::blink::Reduce::Kind::kMin:
          return "reduceMin";
        case webnn::mojom::blink::Reduce::Kind::kProduct:
          return "reduceProduct";
        case webnn::mojom::blink::Reduce::Kind::kSum:
          return "reduceSum";
        case webnn::mojom::blink::Reduce::Kind::kSumSquare:
          return "reduceSumSquare";
      }
    }
    case webnn::mojom::blink::Operation::Tag::kRelu:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "relu";
    case webnn::mojom::blink::Operation::Tag::kReshape:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "reshape";
    case webnn::mojom::blink::Operation::Tag::kResample2d:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "resample2d";
    case webnn::mojom::blink::Operation::Tag::kReverse:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "reverse";
    case webnn::mojom::blink::Operation::Tag::kScatterElements:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "scatterElements";
    case webnn::mojom::blink::Operation::Tag::kScatterNd:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "scatterND";
    case webnn::mojom::blink::Operation::Tag::kSigmoid:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "sigmoid";
    case webnn::mojom::blink::Operation::Tag::kSoftsign:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "softsign";
    case webnn::mojom::blink::Operation::Tag::kSlice:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "slice";
    case webnn::mojom::blink::Operation::Tag::kSoftmax:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "softmax";
    case webnn::mojom::blink::Operation::Tag::kSoftplus:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "softplus";
    case webnn::mojom::blink::Operation::Tag::kSplit:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "split";
    case webnn::mojom::blink::Operation::Tag::kTanh:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "tanh";
    case webnn::mojom::blink::Operation::Tag::kTile:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "tile";
    case webnn::mojom::blink::Operation::Tag::kTranspose:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "transpose";
    case webnn::mojom::blink::Operation::Tag::kTriangular:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "triangular";
    case webnn::mojom::blink::Operation::Tag::kWhere:
      CHECK(absl::holds_alternative<absl::monostate>(sub_kind));
      return "where";
  }
}

MLOperator::MLOperator(MLGraphBuilder* builder,
                       webnn::mojom::blink::Operation::Tag kind,
                       const MLOperatorOptions* options,
                       OperationSubKind sub_kind)
    : builder_(builder), kind_(kind), options_(options), sub_kind_(sub_kind) {}

MLOperator::~MLOperator() = default;

void MLOperator::Trace(Visitor* visitor) const {
  visitor->Trace(builder_);
  visitor->Trace(options_);
  visitor->Trace(inputs_);
  visitor->Trace(outputs_);
}

webnn::mojom::blink::Operation::Tag MLOperator::Kind() const {
  return kind_;
}

MLOperator::OperationSubKind MLOperator::SubKind() const {
  return sub_kind_;
}

const MLOperatorOptions* MLOperator::Options() const {
  return options_.Get();
}

const HeapVector<Member<const MLOperand>>& MLOperator::Inputs() const {
  return inputs_;
}

const HeapVector<Member<const MLOperand>>& MLOperator::Outputs() const {
  return outputs_;
}

void MLOperator::Connect(HeapVector<Member<MLOperand>> inputs,
                         HeapVector<Member<const MLOperand>> outputs) {
  DCHECK(!inputs.empty());
  DCHECK(!outputs.empty());
  for (auto& input : inputs) {
    input->AddDependentOperator(this);
  }

  inputs_.assign(inputs);
  outputs_ = std::move(outputs);
}

MLArgMinMaxOperator::MLArgMinMaxOperator(MLGraphBuilder* builder,
                                         OperationSubKind sub_kind,
                                         const uint32_t axis,
                                         const MLArgMinMaxOptions* options)
    : MLOperator(builder,
                 webnn::mojom::blink::Operation::Tag::kArgMinMax,
                 options,
                 sub_kind),
      axis_(axis) {}

MLArgMinMaxOperator::~MLArgMinMaxOperator() = default;

MLConcatOperator::MLConcatOperator(MLGraphBuilder* builder,
                                   const uint32_t axis,
                                   const MLOperatorOptions* options)
    : MLOperator(builder,
                 webnn::mojom::blink::Operation::Tag::kConcat,
                 options),
      axis_(axis) {}

MLConcatOperator::~MLConcatOperator() = default;

uint32_t MLConcatOperator::Axis() const {
  return axis_;
}

MLCumulativeSumOperator::MLCumulativeSumOperator(
    MLGraphBuilder* builder,
    const uint32_t axis,
    const MLCumulativeSumOptions* options)
    : MLOperator(builder,
                 webnn::mojom::blink::Operation::Tag::kCumulativeSum,
                 options),
      axis_(axis) {}

MLCumulativeSumOperator::~MLCumulativeSumOperator() = default;

MLLstmOperator::MLLstmOperator(MLGraphBuilder* builder,
                               uint32_t steps,
                               uint32_t hidden_size,
                               const MLLstmOptions* options)
    : MLOperator(builder, webnn::mojom::blink::Operation::Tag::kLstm, options),
      steps_(steps),
      hidden_size_(hidden_size) {}

MLLstmOperator::~MLLstmOperator() = default;

uint32_t MLLstmOperator::steps() const {
  return steps_;
}

uint32_t MLLstmOperator::hidden_size() const {
  return hidden_size_;
}

MLLstmCellOperator::MLLstmCellOperator(MLGraphBuilder* builder,
                                       uint32_t hidden_size,
                                       const MLLstmCellOptions* options)
    : MLOperator(builder,
                 webnn::mojom::blink::Operation::Tag::kLstmCell,
                 options),
      hidden_size_(hidden_size) {}

MLLstmCellOperator::~MLLstmCellOperator() = default;

uint32_t MLLstmCellOperator::hidden_size() const {
  return hidden_size_;
}

MLGruOperator::MLGruOperator(MLGraphBuilder* builder,
                             uint32_t steps,
                             uint32_t hidden_size,
                             const MLOperatorOptions* options)
    : MLOperator(builder, webnn::mojom::blink::Operation::Tag::kGru, options),
      steps_(steps),
      hidden_size_(hidden_size) {}

MLGruOperator::~MLGruOperator() = default;

MLGruCellOperator::MLGruCellOperator(MLGraphBuilder* builder,
                                     uint32_t hidden_size,
                                     const MLGruCellOptions* options)
    : MLOperator(builder,
                 webnn::mojom::blink::Operation::Tag::kGruCell,
                 options),
      hidden_size_(hidden_size) {}

MLGruCellOperator::~MLGruCellOperator() = default;

MLPadOperator::MLPadOperator(MLGraphBuilder* builder,
                             const Vector<uint32_t>& beginning_padding,
                             const Vector<uint32_t>& ending_padding,
                             const MLPadOptions* options)
    : MLOperator(builder, webnn::mojom::blink::Operation::Tag::kPad, options),
      beginning_padding_(beginning_padding),
      ending_padding_(ending_padding) {}

MLPadOperator::~MLPadOperator() = default;

const Vector<uint32_t>& MLPadOperator::BeginningPadding() const {
  return beginning_padding_;
}

const Vector<uint32_t>& MLPadOperator::EndingPadding() const {
  return ending_padding_;
}

MLReverseOperator::MLReverseOperator(MLGraphBuilder* builder,
                                     Vector<uint32_t> axes,
                                     const MLReverseOptions* options)
    : MLOperator(builder,
                 webnn::mojom::blink::Operation::Tag::kReverse,
                 options),
      axes_(std::move(axes)) {}

MLReverseOperator::~MLReverseOperator() = default;

const Vector<uint32_t>& MLReverseOperator::Axes() const {
  return axes_;
}

MLSliceOperator::MLSliceOperator(MLGraphBuilder* builder,
                                 const Vector<uint32_t>& starts,
                                 const Vector<uint32_t>& sizes,
                                 const Vector<uint32_t>& strides,
                                 const MLSliceOptions* options)
    : MLOperator(builder, webnn::mojom::blink::Operation::Tag::kSlice, options),
      starts_(starts),
      sizes_(sizes),
      strides_(strides) {}

MLSliceOperator::~MLSliceOperator() = default;

const Vector<uint32_t>& MLSliceOperator::Starts() const {
  return starts_;
}

const Vector<uint32_t>& MLSliceOperator::Sizes() const {
  return sizes_;
}

const Vector<uint32_t>& MLSliceOperator::Strides() const {
  return strides_;
}

MLSoftmaxOperator::MLSoftmaxOperator(MLGraphBuilder* builder,
                                     const uint32_t axis,
                                     const MLOperatorOptions* options)
    : MLOperator(builder,
                 webnn::mojom::blink::Operation::Tag::kSoftmax,
                 options),
      axis_(axis) {}

MLSoftmaxOperator::~MLSoftmaxOperator() = default;

MLSplitOperator::MLSplitOperator(MLGraphBuilder* builder,
                                 const uint32_t splits,
                                 const MLSplitOptions* options)
    : MLOperator(builder, webnn::mojom::blink::Operation::Tag::kSplit, options),
      is_even_split_(true),
      split_number_(splits) {}

MLSplitOperator::MLSplitOperator(MLGraphBuilder* builder,
                                 const Vector<uint32_t>& splits,
                                 const MLSplitOptions* options)
    : MLOperator(builder, webnn::mojom::blink::Operation::Tag::kSplit, options),
      is_even_split_(false),
      split_sizes_(splits) {}

MLSplitOperator::~MLSplitOperator() = default;

bool MLSplitOperator::IsEvenSplit() const {
  return is_even_split_;
}

uint32_t MLSplitOperator::SplitNumber() const {
  CHECK(is_even_split_);
  return split_number_;
}

const Vector<uint32_t>& MLSplitOperator::SplitSizes() const {
  CHECK(!is_even_split_);
  return split_sizes_;
}

MLTileOperator::MLTileOperator(MLGraphBuilder* builder,
                               const Vector<uint32_t>& repetitions,
                               const MLOperatorOptions* options)
    : MLOperator(builder, webnn::mojom::blink::Operation::Tag::kTile, options),
      repetitions_(repetitions) {}

MLTileOperator::~MLTileOperator() = default;

const Vector<uint32_t>& MLTileOperator::Repetitions() const {
  return repetitions_;
}

}  // namespace blink
```