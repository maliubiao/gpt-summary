Response:
Let's break down the thought process for analyzing this Frida code.

1. **Understand the Goal:** The core request is to analyze the `portal_service.cc` file from Frida, explaining its functionality, connections to reverse engineering, low-level concepts, and potential user errors, all while keeping the target audience (someone interested in dynamic instrumentation) in mind.

2. **High-Level Overview:**  The filename `portal_service.cc` strongly suggests this component handles communication or a "portal" between different parts of the Frida system. Given it's in `frida-node`, it likely acts as a bridge between the native Frida core and Node.js.

3. **Initial Code Scan - Identify Key Classes and Methods:**  Quickly look through the code for class names, method names, and any obvious patterns. This gives a structural understanding.

    * **Classes:** `PortalService`, `StartOperation`, `StopOperation`, `EnumerateTagsOperation`. The `Operation` suffix hints at asynchronous tasks.
    * **Methods:**  `Init`, `New`, `Start`, `Stop`, `Post`, `Narrowcast`, `Broadcast`, `EnumerateTags`, `Tag`, `Untag`, `GetDevice`, `TransformSignal`, `ValueToConnectionId`.
    * **Includes:**  Headers like `application.h`, `device.h`, `endpoint_parameters.h`, `operation.h`, `signals.h` provide context about the related components. `<cstring>` is for string manipulation.
    * **Namespaces:** `frida` clearly identifies the code's belonging.
    * **V8 Bindings:** The presence of `v8::...` and `Nan::...` indicates this code interacts with the V8 JavaScript engine, confirming the Node.js bridge aspect.

4. **Deconstruct Functionality - Method by Method:**  Go through each significant method and deduce its purpose.

    * **`PortalService` Constructor/Destructor:**  Standard object lifecycle management. The `g_object_ref` and `frida_unref` suggest interaction with GLib's object system, common in Frida.
    * **`Init`:**  This is the entry point for exposing the `PortalService` class to JavaScript. It creates the JavaScript class template and sets up methods and properties. The `ReadOnly` access to "device" is a clue.
    * **`New`:** Handles the creation of `PortalService` instances from JavaScript. It parses arguments (`cluster_params`, `control_params`), which are likely related to how the portal connects or operates. Error handling for argument mismatches is present.
    * **`GetDevice`:**  A simple getter that retrieves the associated `Device` object.
    * **`Start`, `Stop`:**  These methods initiate and terminate the portal service. The use of `Operation` classes and asynchronous calls (`frida_portal_service_start/stop`) is important.
    * **`Post`, `Narrowcast`, `Broadcast`:** These are clearly message sending mechanisms. `Post` to a specific connection, `Narrowcast` to tagged connections, and `Broadcast` to all. The handling of message payloads (JSON conversion, optional binary data) is evident.
    * **`EnumerateTags`, `Tag`, `Untag`:** These deal with managing tags associated with connections.
    * **`ValueToConnectionId`:**  A utility function to ensure a valid connection ID is passed.
    * **`TransformSignal`:**  This function handles incoming signals from the native Frida side and transforms them into JavaScript-compatible objects. The special handling of "node-joined", "node-left", "authenticated", and "message" signals is noteworthy.

5. **Connect to Reverse Engineering:**  Think about how each function could be used in a reverse engineering context.

    * **`Start`, `Stop`:** Essential for activating and deactivating the communication channel to the target process.
    * **`Post`, `Narrowcast`, `Broadcast`:**  Crucial for sending commands and data to the injected Frida agent in the target process. This is the *core* of interacting with the target.
    * **`EnumerateTags`, `Tag`, `Untag`:** Useful for managing and filtering communication within a complex Frida setup, perhaps when multiple scripts or agents are involved.
    * **`GetDevice`:** Allows access to information about the target device.

6. **Identify Low-Level Concepts:** Look for clues pointing to underlying system interactions.

    * **GLib:** The `g_object_ref`, `frida_unref`, `GBytes`, `GError`, `GAsyncResult`, and the use of `cancellable_` all indicate interaction with GLib, a fundamental library in many Linux systems and used extensively by Frida. This relates to memory management, asynchronous operations, and error handling.
    * **Asynchronous Operations:** The `Operation` classes and the `OnReady` callbacks highlight the asynchronous nature of communication with the Frida core. This is important for non-blocking operations.
    * **Node.js Bindings (V8/Nan):**  The use of `v8::...` and `Nan::...` signifies the bridging between C++ and JavaScript. Understanding how these bindings work is key to understanding Frida's architecture.
    * **Memory Management:**  Explicit `g_object_ref`, `g_object_unref`, `g_bytes_new`, `g_bytes_unref`, and `g_strfreev` point to manual memory management, which is common in C/C++.
    * **Endpoint Parameters:** The `FridaEndpointParameters` suggest configurable connection details, possibly related to network communication or inter-process communication.

7. **Infer Logical Reasoning (Hypothetical Inputs and Outputs):** For some methods, it's possible to imagine simple scenarios:

    * **`Post`:**  Input: `connectionId = 123`, `message = { "command": "readMemory", "address": 0x1000 }`, `data = <buffer of data>`. Output:  The message and data are sent to the connection with ID 123.
    * **`Narrowcast`:** Input: `tag = "ui"`, `message = { "event": "buttonClicked" }`, `data = null`. Output: The message is sent to all connections tagged with "ui".
    * **`EnumerateTags`:** Input: `connectionId = 456`. Output: A JavaScript array of strings representing the tags associated with connection 456.

8. **Spot User Errors:**  Examine the code for error handling and common mistakes a developer might make.

    * **Incorrect Number of Arguments:**  The checks `if (info.Length() < ...)` explicitly handle this.
    * **Type Mismatches:**  The `EndpointParameters::TryParse` and the buffer checks (`node::Buffer::HasInstance`) prevent incorrect data types. The `ValueToConnectionId` function enforces the connection ID type.
    * **Using `new` keyword:** The check in `New` enforces correct instantiation.

9. **Trace User Operations (Debugging Clues):** Consider how a user's actions in a Frida script would lead to this code being executed.

    * The user would first need to get a `Device` object.
    * Then, they would likely create a `PortalService` instance, providing connection parameters.
    * Calling methods like `start()`, `post()`, `broadcast()`, etc., in their JavaScript code would invoke the corresponding NAN_METHOD functions in this C++ code.

10. **Structure the Explanation:** Organize the findings into logical categories (Functionality, Reverse Engineering, Low-Level Details, etc.) for clarity. Use clear and concise language, avoiding overly technical jargon where possible. Provide concrete examples to illustrate the concepts.

By following these steps, a comprehensive analysis of the `portal_service.cc` file can be achieved, addressing all aspects of the prompt. The process involves a combination of code reading, logical deduction, and knowledge of the underlying technologies (Frida, Node.js, GLib).
好的，我们来详细分析一下 `frida/subprojects/frida-node/src/portal_service.cc` 这个文件。

**文件功能概述**

`portal_service.cc` 文件实现了 Frida 中 `PortalService` 类的功能，这个类主要负责在 Frida 运行时环境中的不同组件之间建立和管理通信通道。  可以将其理解为一个消息传递中心，允许 Frida 脚本（通常运行在 Node.js 环境中）与目标进程内的 Frida Agent 进行通信。

**具体功能点:**

1. **创建和管理 Portal:**
   - `PortalService::PortalService()`: 构造函数，初始化 `PortalService` 对象，持有 Frida C API 中对应的 `FridaPortalService` 句柄。
   - `PortalService::~PortalService()`: 析构函数，释放持有的 Frida C API 资源。
   - `PortalService::Init()`:  将 `PortalService` 类及其方法暴露给 Node.js 环境，使其可以在 JavaScript 中被调用。

2. **连接管理:**
   - `PortalService::New()`:  在 JavaScript 中创建 `PortalService` 实例时被调用。它接收集群（cluster）和控制（control）端点的参数，这些参数定义了通信的方式和地址。
   - `PortalService::GetDevice()`:  获取与此 `PortalService` 关联的 `Device` 对象，代表了 Frida 所连接的目标设备。
   - `PortalService::Start()`: 启动 Portal 服务，开始监听和处理连接请求。
   - `PortalService::Stop()`: 停止 Portal 服务，断开连接并停止监听。

3. **消息传递:**
   - `PortalService::Post()`: 向特定的连接 ID 发送消息。这通常用于向连接到 Portal 的特定客户端发送消息。
   - `PortalService::Narrowcast()`: 向具有特定标签 (tag) 的连接发送消息。这允许向一组具有共同属性的客户端发送消息。
   - `PortalService::Broadcast()`: 向所有连接到 Portal 的客户端广播消息。

4. **标签管理:**
   - `PortalService::EnumerateTags()`:  列举特定连接 ID 上的所有标签。
   - `PortalService::Tag()`:  为特定的连接 ID 添加标签。
   - `PortalService::Untag()`:  移除特定连接 ID 上的标签。

5. **信号处理:**
   - `PortalService::TransformSignal()`:  处理来自 Frida C API 的信号，并将其转换为可以在 Node.js 环境中使用的格式。例如，处理 `node-joined` (新节点加入) 或 `node-left` (节点离开) 等事件。

**与逆向方法的关系及举例说明**

`PortalService` 是 Frida 进行动态 Instrumentation 的核心组件之一，它直接支持了逆向分析人员与目标进程进行交互的能力。

**举例说明:**

假设你想在 Android 应用程序运行时，监控某个特定函数的调用情况，并将调用信息发送回你的分析脚本。

1. **连接目标进程:** Frida 脚本会首先连接到目标 Android 应用程序进程。
2. **注入 Agent:** Frida 会将一个 Agent (通常是用 JavaScript 编写) 注入到目标进程中。
3. **建立通信通道:**  `PortalService` 就充当了这个通信通道的角色。Agent 可以通过 `PortalService` 发送消息给运行 Frida 脚本的 Node.js 环境。
4. **发送 Hook 信息:**  在 Agent 中，你可以使用 Frida 提供的 API Hook 目标函数。当函数被调用时，Agent 可以构造包含函数参数、返回值等信息的消息，并使用 `send()` 函数发送出去。
5. **Node.js 接收消息:**  在 `portal_service.cc` 中，当 Agent 发送消息时，会通过底层的 Frida C API 传递到这里，最终通过 `TransformSignal` 等机制转换成 Node.js 可以处理的事件。
6. **分析脚本处理:** 你的 Node.js 脚本可以监听 `PortalService` 发出的消息事件，并解析这些信息进行分析，例如打印函数调用堆栈、参数值等。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明**

`PortalService` 的实现虽然在表面上是高层次的通信管理，但其底层运作涉及多个底层的知识点：

1. **Frida C API:**  该文件大量使用了 Frida 的 C API (`frida_portal_service_new`, `frida_portal_service_start` 等)。这些 C API 实际上是对操作系统底层 API 的封装，用于进程间通信、内存操作等。
2. **进程间通信 (IPC):** `PortalService` 的核心功能是进程间通信。在不同的操作系统上，Frida 可能会使用不同的 IPC 机制，例如 Linux 上的 Unix 域套接字、Windows 上的命名管道等。虽然 `portal_service.cc` 自身没有直接实现这些底层细节，但它依赖的 Frida C API 抽象了这些复杂性。
3. **GLib 库:**  代码中使用了 `g_object_ref`, `g_object_unref`, `GBytes`, `GError` 等 GLib 库的类型和函数。GLib 是一个跨平台的通用实用程序库，提供了内存管理、数据结构、异步操作等功能，被 Frida 广泛使用。
4. **V8 JavaScript 引擎:**  该文件通过 Node.js 的 Addon 机制与 V8 引擎交互。理解 V8 的对象模型、Native Addon 的编写方式对于理解 `PortalService` 如何将 C++ 对象和方法暴露给 JavaScript 至关重要。
5. **Linux/Android 框架:**
   - **Endpoint Parameters:**  `cluster_params` 和 `control_params` 可能涉及到网络地址、端口号等信息，这与 Linux/Android 的网络编程概念相关。
   - **Device 对象:**  `frida_portal_service_get_device()` 返回的 `Device` 对象封装了对目标设备的抽象，可能涉及到对 Android ADB 协议或者其他设备管理接口的调用。
   - **信号机制:**  `TransformSignal` 处理的信号 (`node-joined`, `node-left` 等) 可能与 Frida Agent 在目标进程中的生命周期事件有关，这涉及到目标操作系统的进程管理和事件通知机制。

**举例说明:**

当 `PortalService::Start()` 被调用时，底层的 `frida_portal_service_start()` 函数可能会创建一个监听套接字，等待来自 Frida Agent 的连接。这个操作直接涉及到 Linux 或 Android 的套接字 API。

**逻辑推理及假设输入与输出**

我们来看几个方法的逻辑推理：

**1. `PortalService::New(const Nan::FunctionCallbackInfo<v8::Value>& info)`**

* **假设输入:**
    * `info[0]` (cluster_params_value):  一个 V8 对象，例如 `{ address: '127.0.0.1', port: 27042 }`，代表集群通信的参数。
    * `info[1]` (control_params_value): 一个 V8 对象，例如 `{ address: '127.0.0.1', port: 27043 }`，代表控制通信的参数。

* **逻辑:**
    1. 检查是否使用 `new` 关键字调用。
    2. 检查参数数量是否足够。
    3. 使用 `EndpointParameters::TryParse` 尝试解析 `cluster_params_value` 和 `control_params_value` 成 `FridaEndpointParameters` 对象。
    4. 如果解析成功，调用 `frida_portal_service_new` 创建底层的 `FridaPortalService` 句柄。
    5. 创建 `PortalService` 的 C++ 对象，并将其与 V8 对象关联。
    6. 创建 `Signals` 对象，用于处理来自底层 C API 的信号。

* **假设输出:**  一个新的 `PortalService` 的 JavaScript 对象被创建，并且它的内部持有一个指向底层 `FridaPortalService` 句柄的指针。

**2. `PortalService::Post(const Nan::FunctionCallbackInfo<v8::Value>& info)`**

* **假设输入:**
    * `info[0]`: 一个 V8 数字，例如 `1`，代表连接 ID。
    * `info[1]`: 一个 V8 字符串或对象，例如 `'{"type": "command", "payload": "resume"}'`，代表要发送的消息。
    * `info[2]`: 一个 V8 Buffer 对象，包含可选的二进制数据。

* **逻辑:**
    1. 检查参数数量。
    2. 使用 `ValueToConnectionId` 将 `info[0]` 转换为 `guint` 类型的连接 ID。
    3. 使用 `wrapper->runtime_->ValueToJson(info[1])` 将 JavaScript 的消息对象转换为 JSON 字符串。
    4. 如果 `info[2]` 是 Buffer，则创建 `GBytes` 对象来持有二进制数据。
    5. 调用 `frida_portal_service_post` 发送消息。

* **假设输出:**  一条消息（包含 JSON 字符串和可选的二进制数据）被发送到指定的连接 ID。

**用户或编程常见的使用错误及举例说明**

1. **未正确创建 `PortalService` 实例:**  如果用户在 JavaScript 中没有使用 `new PortalService()` 来创建实例，`PortalService::New` 方法会抛出错误 "Use the `new` keyword to create a new instance"。

   ```javascript
   // 错误用法
   const portalService = PortalService({});

   // 正确用法
   const portalService = new PortalService({});
   ```

2. **缺少必要的参数:**  在调用 `PortalService` 的方法时，如果缺少必要的参数，例如在调用 `post` 时没有提供连接 ID 或消息内容，对应的方法会抛出 `TypeError`。

   ```javascript
   const portalService = new PortalService({});
   // ...

   // 错误用法，缺少连接 ID 和消息
   portalService.post();

   // 错误用法，缺少消息
   portalService.post(1);

   // 正确用法
   portalService.post(1, { type: 'ping' });
   ```

3. **参数类型不匹配:**  如果传递给方法的参数类型与期望的类型不符，例如将一个字符串作为连接 ID 传递，`ValueToConnectionId` 会抛出 "Expected a connection ID" 的 `TypeError`。

   ```javascript
   const portalService = new PortalService({});
   // ...

   // 错误用法，连接 ID 应该是数字
   portalService.post("invalid_id", { type: 'ping' });
   ```

4. **在 Portal 未启动时发送消息:**  如果在调用 `start()` 之前就尝试使用 `post`, `narrowcast` 或 `broadcast` 发送消息，可能会导致错误或消息无法发送。虽然代码本身没有显式的检查，但底层的 Frida C API 可能会返回错误。

**用户操作是如何一步步的到达这里，作为调试线索**

以下是一个典型的用户操作流程，最终会触发 `portal_service.cc` 中的代码执行：

1. **编写 Frida 脚本 (JavaScript):** 用户编写一个 JavaScript 脚本，使用 Frida 的 Node.js 绑定来连接到目标进程并与之交互。

   ```javascript
   const frida = require('frida');

   async function main() {
     const session = await frida.attach('com.example.targetapp');
     const portalService = new frida.PortalService(); // 这里会调用 portal_service.cc 的 New 方法

     portalService.start(); // 调用 portal_service.cc 的 Start 方法

     portalService.post(1, { command: 'enumerate_modules' }); // 调用 portal_service.cc 的 Post 方法

     portalService.on('message', (message) => {
       console.log('Received message:', message);
     });

     // ...
   }

   main();
   ```

2. **运行 Frida 脚本:** 用户使用 Frida 命令行工具或以编程方式运行这个 JavaScript 脚本。

   ```bash
   frida -f com.example.targetapp script.js
   ```

3. **Frida Node.js 绑定初始化:**  当 `require('frida')` 被调用时，Frida 的 Node.js 绑定会被加载，这包括了编译好的 `portal_service.node` (由 `portal_service.cc` 编译而来)。

4. **创建 `PortalService` 实例:**  当脚本中 `new frida.PortalService()` 被调用时，Node.js 会调用 `portal_service.cc` 中的 `PortalService::New` 方法。

5. **启动 Portal 服务:**  调用 `portalService.start()` 会执行 `portal_service.cc` 中的 `PortalService::Start` 方法，启动底层的通信机制。

6. **发送消息:**  `portalService.post(1, ...)` 会执行 `portal_service.cc` 中的 `PortalService::Post` 方法，将消息发送到指定的连接。这个连接通常是 Frida Agent 在目标进程中的表示。

7. **接收消息 (通过信号):**  当 Frida Agent 发送消息返回时，底层的 Frida C API 会发出信号。`portal_service.cc` 中的 `TransformSignal` 方法会被调用，将底层的信号数据转换为 JavaScript 可以理解的对象，并通过 Node.js 的事件机制触发 `portalService.on('message', ...)` 中的回调函数。

**作为调试线索:**

当你在调试 Frida 脚本时，如果遇到与消息传递相关的问题，例如消息没有发送出去、收不到消息、或者参数错误等，就可以将 `portal_service.cc` 作为关键的调试线索。

* **检查 `PortalService::New` 的参数:**  确认在创建 `PortalService` 实例时传递的集群和控制参数是否正确。
* **断点在 `PortalService::Post`, `Narrowcast`, `Broadcast`:**  查看消息是否被正确地构造和发送。
* **检查 `PortalService::TransformSignal`:**  确认从底层 C API 接收到的信号是否被正确地转换成 JavaScript 对象。
* **查看 Frida C API 的调用:**  通过阅读代码，可以了解 `portal_service.cc` 中调用的 Frida C API 函数，并在必要时查阅 Frida 的 C API 文档，了解这些函数的行为和可能的错误情况。

总而言之，`portal_service.cc` 是 Frida Node.js 绑定中负责核心通信功能的关键模块，理解其功能和实现细节对于深入理解 Frida 的运作机制和进行高级的动态 Instrumentation 非常重要。

Prompt: 
```
这是目录为frida/subprojects/frida-node/src/portal_service.cc的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "portal_service.h"

#include "application.h"
#include "device.h"
#include "endpoint_parameters.h"
#include "operation.h"
#include "signals.h"

#include <cstring>

using std::strcmp;
using v8::DEFAULT;
using v8::Function;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::Value;

namespace frida {

PortalService::PortalService(FridaPortalService* handle,
    Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

PortalService::~PortalService() {
  frida_unref(handle_);
}

void PortalService::Init(Local<Object> exports, Runtime* runtime) {
  auto name = Nan::New("PortalService").ToLocalChecked();
  auto tpl = CreateTemplate(name, PortalService::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("device").ToLocalChecked(), GetDevice,
      0, data, DEFAULT, ReadOnly);

  Nan::SetPrototypeMethod(tpl, "start", Start);
  Nan::SetPrototypeMethod(tpl, "stop", Stop);
  Nan::SetPrototypeMethod(tpl, "post", Post);
  Nan::SetPrototypeMethod(tpl, "narrowcast", Narrowcast);
  Nan::SetPrototypeMethod(tpl, "broadcast", Broadcast);
  Nan::SetPrototypeMethod(tpl, "enumerateTags", EnumerateTags);
  Nan::SetPrototypeMethod(tpl, "tag", Tag);
  Nan::SetPrototypeMethod(tpl, "untag", Untag);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
}

NAN_METHOD(PortalService::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto cluster_params_value = info[0];
  auto control_params_value = info[1];

  FridaEndpointParameters* cluster_params = NULL;
  FridaEndpointParameters* control_params = NULL;
  bool valid = true;

  if (!cluster_params_value->IsNull()) {
    cluster_params =
        EndpointParameters::TryParse(cluster_params_value, runtime);
    if (cluster_params != NULL) {
      g_object_ref(cluster_params);
    } else {
      Nan::ThrowTypeError("Bad argument, 'clusterParams' type mismatch");
      valid = false;
    }
  } else {
    cluster_params =
        frida_endpoint_parameters_new(NULL, 0, NULL, NULL, NULL, NULL);
  }

  if (valid && !control_params_value->IsNull()) {
    control_params =
        EndpointParameters::TryParse(control_params_value, runtime);
    if (control_params != NULL) {
      g_object_ref(control_params);
    } else {
      Nan::ThrowTypeError("Bad argument, 'controlParams' type mismatch");
      valid = false;
    }
  }

  if (valid) {
    auto handle = frida_portal_service_new(cluster_params, control_params);
    auto wrapper = new PortalService(handle, runtime);
    g_object_unref(handle);
    auto obj = info.This();
    wrapper->Wrap(obj);
    Nan::Set(obj, Nan::New("signals").ToLocalChecked(),
        Signals::New(handle, runtime, TransformSignal, runtime));

    info.GetReturnValue().Set(obj);
  }

  g_clear_object(&control_params);
  g_clear_object(&cluster_params);
}

NAN_PROPERTY_GETTER(PortalService::GetDevice) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());
  auto handle = wrapper->GetHandle<FridaPortalService>();

  info.GetReturnValue().Set(
      Device::New(frida_portal_service_get_device(handle), wrapper->runtime_));
}

namespace {

class StartOperation : public Operation<FridaPortalService> {
 protected:
  void Begin() {
    frida_portal_service_start(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_portal_service_start_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    runtime_->GetUVContext()->IncreaseUsage();
    return Nan::Undefined();
  }
};

}

NAN_METHOD(PortalService::Start) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto operation = new StartOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class StopOperation : public Operation<FridaPortalService> {
 protected:
  void Begin() {
    frida_portal_service_stop(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_portal_service_stop_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    runtime_->GetUVContext()->DecreaseUsage();
    return Nan::Undefined();
  }
};

}

NAN_METHOD(PortalService::Stop) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto operation = new StopOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

NAN_METHOD(PortalService::Post) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  guint connection_id;
  if (!ValueToConnectionId(info[0], &connection_id))
    return;

  Nan::Utf8String message(wrapper->runtime_->ValueToJson(info[1]));

  GBytes* data = NULL;
  auto buffer = info[2];
  if (!buffer->IsNull()) {
    if (!node::Buffer::HasInstance(buffer)) {
      Nan::ThrowTypeError("Expected a buffer");
      return;
    }
    data = g_bytes_new(node::Buffer::Data(buffer),
        node::Buffer::Length(buffer));
  }

  frida_portal_service_post(wrapper->GetHandle<FridaPortalService>(),
      connection_id, *message, data);

  g_bytes_unref(data);
}

NAN_METHOD(PortalService::Narrowcast) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  Nan::Utf8String tag(info[0]);

  Nan::Utf8String message(wrapper->runtime_->ValueToJson(info[1]));

  GBytes* data = NULL;
  auto buffer = info[2];
  if (!buffer->IsNull()) {
    if (!node::Buffer::HasInstance(buffer)) {
      Nan::ThrowTypeError("Expected a buffer");
      return;
    }
    data = g_bytes_new(node::Buffer::Data(buffer),
        node::Buffer::Length(buffer));
  }

  frida_portal_service_narrowcast(wrapper->GetHandle<FridaPortalService>(),
      *tag, *message, data);

  g_bytes_unref(data);
}

NAN_METHOD(PortalService::Broadcast) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  Nan::Utf8String message(wrapper->runtime_->ValueToJson(info[0]));

  GBytes* data = NULL;
  auto buffer = info[1];
  if (!buffer->IsNull()) {
    if (!node::Buffer::HasInstance(buffer)) {
      Nan::ThrowTypeError("Expected a buffer");
      return;
    }
    data = g_bytes_new(node::Buffer::Data(buffer),
        node::Buffer::Length(buffer));
  }

  frida_portal_service_broadcast(wrapper->GetHandle<FridaPortalService>(),
      *message, data);

  g_bytes_unref(data);
}

namespace {

class EnumerateTagsOperation : public Operation<FridaPortalService> {
 public:
  EnumerateTagsOperation(guint connection_id)
    : connection_id_(connection_id),
      tags_(NULL),
      n_(0) {
  }

  ~EnumerateTagsOperation() {
    g_strfreev(tags_);
  }

 protected:
  void Begin() {
    tags_ = frida_portal_service_enumerate_tags(handle_, connection_id_, &n_);
    OnReady(G_OBJECT(handle_), NULL, this);
  }

  void End(GAsyncResult* result, GError** error) {
  }

  Local<Value> Result(Isolate* isolate) {
    return Runtime::ValueFromStrv(tags_, n_);
  }

 private:
  guint connection_id_;
  gchar** tags_;
  gint n_;
};

}

NAN_METHOD(PortalService::EnumerateTags) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  if (info.Length() < 1) {
    Nan::ThrowTypeError("Bad argument, expected a connection ID");
    return;
  }

  guint connection_id;
  if (!ValueToConnectionId(info[0], &connection_id))
    return;

  auto operation = new EnumerateTagsOperation(connection_id);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

NAN_METHOD(PortalService::Tag) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  guint connection_id;
  if (!ValueToConnectionId(info[0], &connection_id))
    return;

  Nan::Utf8String tag(info[1]);

  frida_portal_service_tag(wrapper->GetHandle<FridaPortalService>(),
      connection_id, *tag);
}

NAN_METHOD(PortalService::Untag) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  guint connection_id;
  if (!ValueToConnectionId(info[0], &connection_id))
    return;

  Nan::Utf8String tag(info[1]);

  frida_portal_service_untag(wrapper->GetHandle<FridaPortalService>(),
      connection_id, *tag);
}

bool PortalService::ValueToConnectionId(Local<Value> value,
    guint* connection_id) {
  if (!value->IsNumber()) {
    Nan::ThrowTypeError("Expected a connection ID");
    return false;
  }

  auto id = Nan::To<uint32_t>(value).FromMaybe(0);
  if (id == 0) {
    Nan::ThrowTypeError("Expected a connection ID");
    return false;
  }

  *connection_id = id;
  return true;
}

Local<Value> PortalService::TransformSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);

  if (index == 1 && (strcmp(name, "node-joined") == 0 ||
        strcmp(name, "node-left") == 0))
    return Application::New(g_value_get_object(value), runtime);

  if (index == 1 && (strcmp(name, "authenticated") == 0 ||
        strcmp(name, "message") == 0)) {
    auto json = Nan::New(g_value_get_string(value)).ToLocalChecked();
    return runtime->ValueFromJson(json);
  }

  return Local<Value>();
}

}

"""

```