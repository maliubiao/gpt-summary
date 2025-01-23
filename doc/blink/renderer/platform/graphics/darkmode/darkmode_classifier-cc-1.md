Response:
The user wants a summary of the provided C++ code snippet, which is the second part of a file related to dark mode classification in the Chromium Blink engine.

Here's a breakdown of how to approach this:

1. **Identify the main components:**  Scan the code for distinct sections or functionalities. Keywords like `ARY_OP`, `SIMPLE_UNARY_OP`, `BROADCAST_BINARY_OP`, `REDUCE_OP`, `Dequantize`, and `Inference` stand out.

2. **Understand the purpose of each component:**
    * `ARY_OP` and `SIMPLE_UNARY_OP`: These seem to define unary mathematical operations (taking one input).
    * `BROADCAST_BINARY_OP`: This likely defines binary mathematical operations (taking two inputs), with some form of broadcasting (applying operations between arrays of different shapes).
    * `REDUCE_OP`: This appears to define operations that reduce the dimensionality of an array, like finding the sum or mean along certain axes.
    * `Dequantize`: These functions seem to convert quantized (likely integer) data back to floating-point values.
    * `CONSTANTS`: This section defines constant arrays, presumably weights and biases for a neural network.
    * `Inference`: This function appears to be the core of the model, performing calculations using the defined operations and constants.

3. **Connect to the broader context (Dark Mode Classification):**  The presence of "dnn" (deep neural network), weights, biases, and an `Inference` function strongly suggest this code implements a neural network for classifying something related to dark mode. The input is likely features related to a web page's appearance, and the output is a probability or score indicating whether dark mode should be applied.

4. **Consider the relationship to web technologies (JavaScript, HTML, CSS):**  The code itself is C++, so it doesn't directly execute in web pages. However, it's part of the Blink rendering engine, which *interprets* HTML, CSS, and executes JavaScript. The dark mode classification logic likely uses information derived from parsed HTML and CSS (e.g., colors, background images) as input. The result of the classification might influence how the page is rendered, potentially by applying different CSS styles or filters.

5. **Address specific instructions:**
    * **Functionality Listing:** List the identified components and their purposes.
    * **Relationship with JS/HTML/CSS:** Explain the indirect relationship through the rendering engine, providing examples.
    * **Logical Reasoning (Hypothetical Inputs/Outputs):**  For the `Inference` function, make educated guesses about the input and output shapes and what they represent based on the constant names (e.g., `dnn_hiddenlayer_0_weights`).
    * **Common Usage Errors:** Think about typical programming errors related to array manipulation, shape mismatches, and the use of pre-trained models.

6. **Structure the response:** Organize the information logically, starting with a general summary and then detailing each aspect. Use clear headings and bullet points.

7. **Refine and Review:** Check for accuracy, clarity, and completeness. Ensure all parts of the prompt are addressed. For example, ensure the conclusion summarizes the overall function based on both parts of the file.根据您提供的代码片段，这是 `darkmode_classifier.cc` 文件的第二部分，主要包含以下功能：

**1. 数学运算的宏定义和模板函数:**

* **`SIMPLE_UNARY_OP` 和 `ARY_OP`:**  定义了对单个输入执行数学运算的函数，例如 `Sqrt` (平方根), `Square` (平方), `Tan` (正切) 等。这些宏简化了定义这些操作的过程。
* **`OpNoBroadcast`:**  对两个形状相同的数组执行逐元素二元操作。
* **`OpInnerBroadcast`:** 对两个形状不同的数组执行广播二元操作，其中一个数组的内维度为 1，可以被广播到另一个数组的对应维度。
* **`BROADCAST_BINARY_OP`:**  定义了对两个输入执行广播二元数学运算的函数，例如 `Add` (加法), `Maximum` (最大值), `Minimum` (最小值), `Mul` (乘法), `Sub` (减法), `SquaredDifference` (平方差)。这个宏内部调用了 `OpNoBroadcast` 或 `OpInnerBroadcast`。
* **`REDUCE_OP`:**  定义了对数组进行降维操作的函数，例如 `MaxInnerReduce` (求最大值), `SumInnerReduce` (求和), `MeanInnerReduce` (求平均值)。它包含了针对一般情况的 `InnerReduce` 和针对四维张量的优化版本 `GenericReduceRank4`。

**2. 反量化 (Dequantize) 操作:**

* **`DequantizeMinCombined`:**  将量化后的整数数据反量化为浮点数，使用提供的最小值和最大值范围。
* **`DequantizeMinFirst`:** 另一种反量化的实现方式。

**3. 预训练模型的常量数据:**

* 定义了几个常量数组，例如 `dnn_hiddenlayer_0_weights_part_0` (第一个隐藏层的权重), `dnn_hiddenlayer_0_biases_part_0` (第一个隐藏层的偏置), `dnn_logits_weights_part_0` (logits 层的权重), `dnn_logits_biases_part_0` (logits 层的偏置)。这些常量数据很可能是预训练的深度神经网络模型的参数。

**4. 推理 (Inference) 函数:**

* **`Inference` 函数:** 这是整个代码的核心，它使用前面定义的数学运算和常量数据，对输入数据 `input0` 进行推理，输出结果到 `logits_MatMul_merged_with_dnn_logits_BiasAdd0`。
* 在 `Inference` 函数内部，调用了 `FullyConnected` (全连接层) 和 `Relu` (ReLU激活函数) 等函数，这些函数很可能在文件的第一部分定义。
* 推理过程模拟了一个简单的神经网络结构，包括一个隐藏层和一个 logits 层。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件本身不直接与 JavaScript, HTML, CSS 交互，因为它属于 Blink 渲染引擎的底层实现。但是，它的功能是为了支持浏览器更好地判断网页内容是否适合应用暗黑模式，这与网页的呈现方式密切相关。

* **HTML:**  Blink 引擎会解析 HTML 结构，提取出相关的特征信息，例如元素的颜色、背景、文本内容等。这些信息可能被转化为 `Inference` 函数的输入 `input0`。例如，`input0` 的四个值可能代表了网页的某些颜色特征的统计信息。
* **CSS:** CSS 决定了网页的样式。`darkmode_classifier.cc` 的分析结果会影响浏览器如何应用 CSS 样式。如果分类器判断网页内容适合暗黑模式，浏览器可能会应用一套不同的 CSS 样式表，或者修改现有样式来适应暗黑主题。
* **JavaScript:** JavaScript 可以动态地修改网页的 HTML 结构和 CSS 样式。虽然这个 C++ 文件不直接与 JavaScript 交互，但 JavaScript 可以通过浏览器提供的 API (例如，查询元素的样式) 来获取一些可能被暗黑模式分类器使用的信息。此外，JavaScript 可能会监听暗黑模式的切换事件，并根据需要调整页面元素。

**举例说明:**

假设 `input0` 是一个包含四个浮点数的数组，分别代表了网页背景亮度、文本亮度、主色调饱和度和对比度。

* **假设输入:** `input0 = {0.9, 0.1, 0.5, 0.8}` (浅色背景，深色文字，中等饱和度，高对比度)
* **推理过程:** `Inference` 函数会使用预训练的权重和偏置，对 `input0` 进行矩阵乘法、加法和 ReLU 激活等运算。
* **假设输出:** `logits_MatMul_merged_with_dnn_logits_BiasAdd0 = {0.1}`。这个输出值可能经过 sigmoid 函数或其他归一化处理后，表示网页不适合应用暗黑模式的概率较低 (因为值接近 0)。

**用户或编程常见的使用错误:**

由于这段代码是 Blink 引擎的内部实现，普通用户不会直接接触。编程错误主要会发生在 Blink 引擎的开发者身上：

* **形状不匹配:** 在进行矩阵运算时，如果输入数据的形状与预期的权重或偏置形状不匹配，会导致程序崩溃或产生错误的计算结果。例如，如果传递给 `FullyConnected` 函数的 `input0` 的形状不是 `{1, 4}`，就会出错。
* **使用了错误的权重或偏置:** 如果预训练模型的权重或偏置数据损坏或使用了错误的版本，会导致分类结果不准确。
* **反量化参数错误:**  在 `DequantizeMinCombined` 或 `DequantizeMinFirst` 中，如果 `min_range` 或 `max_range` 的值不正确，会导致反量化后的数据偏差。
* **在不需要广播时使用了广播操作:**  错误地使用了 `OpInnerBroadcast` 而不是 `OpNoBroadcast`，可能导致计算结果错误。
* **Reduce 操作的维度指定错误:** 在使用 `REDUCE_OP` 定义的函数时，如果指定了错误的降维维度，会导致计算结果不正确。

**归纳一下它的功能 (结合第1部分):**

综合来看，`blink/renderer/platform/graphics/darkmode/darkmode_classifier.cc` 文件的功能是：

* **实现了一个用于判断网页内容是否适合应用暗黑模式的深度学习模型。** 这包括模型的结构定义（可能在第一部分），以及模型的权重、偏置等参数（在本部分）。
* **提供了一系列底层的数学运算函数**，用于支持模型的推理过程，包括基本的算术运算、矩阵运算、激活函数以及降维操作。
* **包含了反量化操作**，用于将模型中可能存在的量化数据转换为浮点数进行计算。
* **`Inference` 函数是模型推理的核心入口点**，接收输入特征，并使用预训练的参数进行计算，输出一个表示网页适合暗黑模式程度的概率或得分。

总而言之，这个文件是 Blink 引擎中用于实现暗黑模式智能判断的核心组件，它通过一个轻量级的神经网络模型来分析网页的特征，从而决定是否应该应用暗黑模式，提升用户的浏览体验。

### 提示词
```
这是目录为blink/renderer/platform/graphics/darkmode/darkmode_classifier.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ARY_OP(Sinh, std::sinh(value), values.sinh())
SIMPLE_UNARY_OP(Sqrt, std::sqrt(value), values.sqrt())
SIMPLE_UNARY_OP(Square, value* value, values.square())
SIMPLE_UNARY_OP(Tan, std::tan(value), values.tan())
SIMPLE_UNARY_OP(Tanh, std::tanh(value), values.tanh())

// -----------------------------------------------------------------------------
// Broadcasting binary ops
// -----------------------------------------------------------------------------

template <typename T, typename OP>
void OpNoBroadcast(const int32_t left_rank,
                   const int32_t* __restrict left_shape,
                   const T* __restrict left_values,
                   const int32_t right_rank,
                   const int32_t* __restrict right_shape,
                   const T* __restrict right_values,
                   T* __restrict output_values,
                   OP op) {
  BENCHMARK_TIMER(op.name, "NoBroadcast");
  const int32_t size = ShapeSize(left_rank, left_shape);
#if USE_EIGEN
  auto lhs = ConstRowVectorMap<T>(left_values, size).array();
  auto rhs = ConstRowVectorMap<T>(right_values, size).array();
  auto output = RowVectorMap<T>(output_values, size).array();
  op.apply(lhs, rhs, output);
#else
  for (int32_t i = 0; i < size; ++i) {
    output_values[i] = op(left_values[i], right_values[i]);
  }
#endif
}

template <typename T, typename OP>
void OpInnerBroadcast(int32_t left_rank,
                      const int32_t* __restrict left_shape,
                      const T* __restrict left_values,
                      int32_t right_rank,
                      const int32_t* __restrict right_shape,
                      const T* __restrict right_values,
                      T* __restrict output_values,
                      OP op) {
  BENCHMARK_TIMER(op.name, "InnerBroadcast");
  const int32_t output_size = ShapeSize(left_rank, left_shape);
  const int32_t inner_size = ShapeSize(right_rank, right_shape);
  const int32_t outer_size = output_size / inner_size;
#if USE_EIGEN
  if (inner_size == 1) {
    // Apply the same value to all elements.
    auto left = ConstMatrixMap<T>(left_values, inner_size, outer_size);
    auto output = MatrixMap<T>(output_values, inner_size, outer_size);
    op.apply(left.array(), right_values[0], output.array());
  } else {
    auto left = ConstMatrixMap<T>(left_values, inner_size, outer_size);
    auto right = ConstRowVectorMap<T>(right_values, inner_size);
    auto output = MatrixMap<T>(output_values, inner_size, outer_size);
    for (int32_t col = 0; col < outer_size; col++) {
      op.apply(left.col(col).array(), right.array(), output.col(col).array());
    }
  }
#else
  for (int32_t idx_out = 0; idx_out < outer_size; ++idx_out) {
    for (int32_t idx_in = 0; idx_in < inner_size; ++idx_in) {
      const int32_t offset = idx_out * inner_size + idx_in;
      output_values[offset] = op(left_values[offset], right_values[idx_in]);
    }
  }
#endif
}

#define BROADCAST_BINARY_OP(OP_NAME, EXPR, EXPR_EIGEN)                         \
  template <typename T>                                                        \
  struct Op##OP_NAME {                                                         \
    const char* name = #OP_NAME;                                               \
    T operator()(const T lhs, const T rhs) { return EXPR; }                    \
    template <typename X, typename Y, typename Z>                              \
    void apply(const X& lhs, const Y& rhs, Z out) {                            \
      out = EXPR_EIGEN;                                                        \
    }                                                                          \
  };                                                                           \
  template <typename T>                                                        \
  void OP_NAME##NoBroadcast(                                                   \
      const int32_t left_rank, const int32_t* __restrict left_shape,           \
      const T* __restrict left_values, const int32_t right_rank,               \
      const int32_t* __restrict right_shape, const T* __restrict right_values, \
      T* __restrict output_values) {                                           \
    OpNoBroadcast(left_rank, left_shape, left_values, right_rank, right_shape, \
                  right_values, output_values, Op##OP_NAME<T>());              \
  }                                                                            \
  template <typename T>                                                        \
  void OP_NAME##InnerBroadcast(                                                \
      const int32_t left_rank, const int32_t* __restrict left_shape,           \
      const T* __restrict left_values, const int32_t right_rank,               \
      const int32_t* __restrict right_shape, const T* __restrict right_values, \
      T* __restrict output_values) {                                           \
    OpInnerBroadcast(left_rank, left_shape, left_values, right_rank,           \
                     right_shape, right_values, output_values,                 \
                     Op##OP_NAME<T>());                                        \
  }

// Second macro param is value expression, third entry is Eigen vector
// expression.
BROADCAST_BINARY_OP(Add, lhs + rhs, lhs + rhs)
BROADCAST_BINARY_OP(Maximum, std::max(lhs, rhs), lhs.max(rhs))
BROADCAST_BINARY_OP(Minimum, std::min(lhs, rhs), lhs.min(rhs))
BROADCAST_BINARY_OP(Mul, lhs* rhs, lhs* rhs)
BROADCAST_BINARY_OP(Sub, lhs - rhs, lhs - rhs)
BROADCAST_BINARY_OP(SquaredDifference,
                    (lhs - rhs) * (lhs - rhs),
                    (lhs - rhs).square())

// -----------------------------------------------------------------------------
// Reduce ops
// -----------------------------------------------------------------------------

// We use macros instead of template functions with templated functors here
// because it's a lot less verbose and easier for the compiler to optimize.
#define REDUCE_OP(OP_NAME, DEFAULT_VALUE, UPDATE_EXPR, RESULT_EXPR)           \
  template <typename T, typename Tidx>                                        \
  void OP_NAME##InnerReduce(                                                  \
      int32_t input_rank, const int32_t* __restrict input_shape,              \
      const T* __restrict input_values, int32_t index_tensor_rank,            \
      const int32_t* __restrict index_shape,                                  \
      const Tidx* __restrict index_values, T* __restrict output_values) {     \
    BENCHMARK_TIMER(#OP_NAME, "InnerReduce");                                 \
    const int32_t inner_size =                                                \
        GetReduceInnerSize(input_rank, input_shape, index_tensor_rank,        \
                           index_shape, index_values);                        \
    const int32_t input_size = ShapeSize(input_rank, input_shape);            \
    const int32_t outer_size = input_size / inner_size;                       \
    for (int32_t idx_out = 0; idx_out < outer_size; ++idx_out) {              \
      T value = DEFAULT_VALUE;                                                \
      for (int32_t idx_in = 0; idx_in < inner_size; ++idx_in) {               \
        const T prev = value;                                                 \
        const T next = input_values[idx_out * inner_size + idx_in];           \
        value = UPDATE_EXPR;                                                  \
      }                                                                       \
      const T count = inner_size;                                             \
      (void)sizeof(count);                                                    \
      output_values[idx_out] = RESULT_EXPR;                                   \
    }                                                                         \
  }                                                                           \
  template <typename T, typename Tidx>                                        \
  void OP_NAME##GenericReduceRank4(                                           \
      int32_t input_rank, const int32_t* __restrict input_shape,              \
      const T* __restrict input_values, int32_t index_tensor_rank,            \
      const int32_t* __restrict index_shape,                                  \
      const Tidx* __restrict index_values, T* __restrict output_values) {     \
    assert(input_rank == 4);                                                  \
    assert(index_tensor_rank <= 1);                                           \
    BENCHMARK_TIMER(#OP_NAME, "GenericReduceRank4");                          \
    int out_shape[4] = {input_shape[0], input_shape[1], input_shape[2],       \
                        input_shape[3]};                                      \
    bool reduce_mask[4] = {false, false, false, false};                       \
    const int num_indices = index_tensor_rank > 0 ? index_shape[0] : 1;       \
    for (int i = 0; i < num_indices; ++i) {                                   \
      reduce_mask[index_values[i]] = true;                                    \
      out_shape[index_values[i]] = 1;                                         \
    }                                                                         \
    const int out_strides[4] = {                                              \
        reduce_mask[0] ? 0 : out_shape[1] * out_shape[2] * out_shape[3],      \
        reduce_mask[1] ? 0 : out_shape[2] * out_shape[3],                     \
        reduce_mask[2] ? 0 : out_shape[3],                                    \
        reduce_mask[3] ? 0 : 1,                                               \
    };                                                                        \
    const int output_size = ShapeSize(input_rank, out_shape);                 \
    std::fill_n(output_values, output_size, DEFAULT_VALUE);                   \
    for (int dim0 = 0; dim0 < input_shape[0]; ++dim0) {                       \
      for (int dim1 = 0; dim1 < input_shape[1]; ++dim1) {                     \
        for (int dim2 = 0; dim2 < input_shape[2]; ++dim2) {                   \
          for (int dim3 = 0; dim3 < input_shape[3]; ++dim3, ++input_values) { \
            T* out_ptr = output_values + out_strides[0] * dim0 +              \
                         out_strides[1] * dim1 + out_strides[2] * dim2 +      \
                         out_strides[3] * dim3;                               \
            const T prev = *out_ptr;                                          \
            const T next = *input_values;                                     \
            *out_ptr = UPDATE_EXPR;                                           \
          }                                                                   \
        }                                                                     \
      }                                                                       \
    }                                                                         \
    const T count = (reduce_mask[0] ? input_shape[0] : 1) *                   \
                    (reduce_mask[1] ? input_shape[1] : 1) *                   \
                    (reduce_mask[2] ? input_shape[2] : 1) *                   \
                    (reduce_mask[3] ? input_shape[3] : 1);                    \
    (void)sizeof(count);                                                      \
    for (int i = 0; i < output_size; ++i) {                                   \
      const T value = output_values[i];                                       \
      output_values[i] = RESULT_EXPR;                                         \
    }                                                                         \
  }

REDUCE_OP(Max, std::numeric_limits<T>::lowest(), std::max(prev, next), value)
REDUCE_OP(Sum, 0, prev + next, value)
REDUCE_OP(Mean, 0, prev + next, value / count)

#undef REDUCE_OP

// -----------------------------------------------------------------------------
// Dequantize ops
// -----------------------------------------------------------------------------

template <typename T>
void DequantizeMinCombined(const int32_t rank,
                           const int32_t* __restrict input_shape,
                           const T* __restrict input_values,
                           const float* __restrict min_range,
                           const float* __restrict max_range,
                           float* __restrict output_values) {
  BENCHMARK_TIMER("DequantizeMinCombined");
  const int size = ShapeSize(rank, input_shape);
  const float offset =
      std::is_signed<T>::value
          ? (static_cast<float>(std::numeric_limits<T>::max()) -
             std::numeric_limits<T>::min() + 1) /
                2.0f
          : 0.0f;
  const float range_scale = (max_range[0] - min_range[0]) /
                            (static_cast<float>(std::numeric_limits<T>::max()) -
                             std::numeric_limits<T>::min());
  for (int i = 0; i < size; i++) {
    output_values[i] =
        ((static_cast<int32_t>(input_values[i]) + offset) * range_scale) +
        min_range[0];
  }
}

template <typename T>
void DequantizeMinFirst(const int32_t rank,
                        const int32_t* __restrict input_shape,
                        const T* __restrict input_values,
                        const float* __restrict min_range,
                        const float* __restrict max_range,
                        float* __restrict output_values) {
  BENCHMARK_TIMER("DequantizeMinFirst");
  const int size = ShapeSize(rank, input_shape);
  const float range_scale = (max_range[0] - min_range[0]) /
                            (static_cast<float>(std::numeric_limits<T>::max()) -
                             std::numeric_limits<T>::min());
  const float range_min_rounded =
      (max_range[0] == min_range[0]
           ? min_range[0]
           : round(min_range[0] / range_scale) * range_scale);
  for (int i = 0; i < size; i++) {
    output_values[i] = ((static_cast<int32_t>(input_values[i]) -
                         std::numeric_limits<T>::min()) *
                        range_scale) +
                       range_min_rounded;
  }
}

// -----------------------------------------------------------------------------
// CONSTANTS
// Note that for now, endianness of the target machine needs to match that of
// the one training was performed on.
// -----------------------------------------------------------------------------
const int32_t dnn_hiddenlayer_0_weights_part_0_shape[2] = {4, 10};
const union {
  uint8_t bytes[160];
  float values[40];
} dnn_hiddenlayer_0_weights_part_0 = {{
    0xbc, 0x22, 0x0a, 0xbf, 0xb4, 0x46, 0x8c, 0x3f, 0xba, 0x31, 0x34, 0xbe,
    0x4c, 0x65, 0xdb, 0xbe, 0xf0, 0x54, 0x5e, 0xbe, 0xc1, 0x5d, 0xb3, 0x3f,
    0xf4, 0xe6, 0x15, 0xbf, 0x05, 0xc6, 0x34, 0xbf, 0xc0, 0x37, 0x7e, 0xbd,
    0x6c, 0x35, 0x0b, 0xbf, 0xca, 0x53, 0x26, 0xbf, 0x58, 0xb4, 0x87, 0x3f,
    0x37, 0xee, 0x39, 0xbf, 0xda, 0xfa, 0xf9, 0xbe, 0x97, 0xc1, 0x06, 0xbf,
    0xf9, 0x4e, 0x81, 0x3f, 0xb2, 0x44, 0x85, 0xbf, 0x7f, 0x98, 0x7c, 0x3d,
    0x15, 0x26, 0xbc, 0xbe, 0x5c, 0x48, 0x05, 0x3f, 0xc8, 0xaa, 0xa1, 0xbd,
    0x35, 0xb3, 0x43, 0xbe, 0xeb, 0x46, 0x91, 0x3f, 0x80, 0x71, 0xe3, 0x3c,
    0xd1, 0x98, 0x79, 0x3f, 0x3c, 0xd0, 0x0d, 0xbf, 0x1e, 0x02, 0xd3, 0x3e,
    0x5d, 0x4b, 0xa2, 0xbf, 0x68, 0xac, 0xaa, 0xbd, 0xf8, 0xe1, 0x75, 0x3e,
    0x4a, 0x9c, 0x27, 0xbe, 0xf8, 0xae, 0xb2, 0xbe, 0x7f, 0x9d, 0x91, 0x3f,
    0x1e, 0x8b, 0xa8, 0xbe, 0x35, 0x7e, 0xb2, 0x3f, 0xbe, 0x8c, 0xd3, 0xbe,
    0xf9, 0xcd, 0xb5, 0x3f, 0xa1, 0x50, 0xaa, 0x3f, 0xe4, 0x6d, 0xdd, 0xbe,
    0x0d, 0xce, 0xd3, 0xbe,
}};
const int32_t dnn_hiddenlayer_0_biases_part_0_shape[1] = {10};
const union {
  uint8_t bytes[40];
  float values[10];
} dnn_hiddenlayer_0_biases_part_0 = {{
    0x00, 0x00, 0x00, 0x00, 0xbf, 0x6a, 0x53, 0x3e, 0xd3, 0xc1,
    0xd0, 0x3e, 0x00, 0x00, 0x00, 0x00, 0xb6, 0xd8, 0xc0, 0x3e,
    0xca, 0xe7, 0x35, 0x3e, 0x23, 0xa5, 0x44, 0x3f, 0x61, 0xfd,
    0xd2, 0x3e, 0x00, 0x00, 0x00, 0x00, 0xb6, 0xe0, 0x43, 0x3c,
}};
const int32_t dnn_logits_biases_part_0_shape[1] = {1};
const union {
  uint8_t bytes[4];
  float values[1];
} dnn_logits_biases_part_0 = {{
    0x75,
    0xca,
    0xd7,
    0xbe,
}};
const int32_t dnn_logits_weights_part_0_shape[2] = {10, 1};
const union {
  uint8_t bytes[40];
  float values[10];
} dnn_logits_weights_part_0 = {{
    0x13, 0x12, 0x39, 0x3f, 0xf3, 0xa5, 0xc2, 0xbf, 0x81, 0x7f,
    0xbe, 0x3f, 0xf8, 0x17, 0x26, 0x3e, 0xa4, 0x19, 0xa6, 0x3f,
    0xf0, 0xc9, 0xb7, 0xbf, 0x6a, 0x99, 0xd2, 0x3f, 0x8a, 0x7d,
    0xe9, 0x3f, 0x83, 0x9a, 0x3a, 0xbf, 0xf1, 0x6c, 0x08, 0x3e,
}};

}  // anonymous namespace

// -----------------------------------------------------------------------------
// INFERENCE
// -----------------------------------------------------------------------------

int32_t input0Shape[2] = {1, 4};
int32_t logits_MatMul_merged_with_dnn_logits_BiasAdd0Shape[2] = {1, 1};

void Inference(
    const float* __restrict input0 /* shape: 1,4 */,
    float* __restrict logits_MatMul_merged_with_dnn_logits_BiasAdd0 /* shape:
                                                                       1,1 */
    ,
    FixedAllocations* __restrict fixed) {
  const int32_t input0_shape[] = {1, 4};
  int32_t logits_MatMul_merged_with_dnn_logits_BiasAdd0_shape[2];

  // dnn/hiddenlayer_0/MatMul_merged_with_dnn/hiddenlayer_0/BiasAdd
  FullyConnected<float>(input0_shape, input0,
                        dnn_hiddenlayer_0_weights_part_0_shape,
                        dnn_hiddenlayer_0_weights_part_0.values,
                        dnn_hiddenlayer_0_biases_part_0_shape,
                        dnn_hiddenlayer_0_biases_part_0.values, fixed->alloc0);
  fixed->alloc0_shape[0] = 1;
  fixed->alloc0_shape[1] = 10;

  // dnn/hiddenlayer_0/hiddenlayer_0/Relu
  Relu<float>(2,  // rank
              fixed->alloc0_shape, fixed->alloc0, fixed->alloc1);
  fixed->alloc1_shape[0] = 1;
  fixed->alloc1_shape[1] = 10;

  // dnn/logits/MatMul_merged_with_dnn/logits/BiasAdd
  FullyConnected<float>(
      fixed->alloc1_shape, fixed->alloc1, dnn_logits_weights_part_0_shape,
      dnn_logits_weights_part_0.values, dnn_logits_biases_part_0_shape,
      dnn_logits_biases_part_0.values,
      logits_MatMul_merged_with_dnn_logits_BiasAdd0);
  logits_MatMul_merged_with_dnn_logits_BiasAdd0_shape[0] = 1;
  logits_MatMul_merged_with_dnn_logits_BiasAdd0_shape[1] = 1;
}

}  // namespace darkmode_tfnative_model
```