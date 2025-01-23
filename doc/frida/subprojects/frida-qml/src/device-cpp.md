Response:
Let's break down the thought process for analyzing the `device.cpp` file.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of this specific Frida source code file (`device.cpp`). Beyond that, it asks for connections to reverse engineering, low-level concepts, logic, potential errors, and how a user might end up interacting with this code.

**2. Initial Scan and Keyword Spotting:**

First, I'd quickly scan the code for prominent keywords and patterns:

* **Frida-related terms:** `FridaDevice`, `FridaSpawnOptions`, `FridaSession`, `FridaScript`, `frida_device_`, `frida_session_`, `frida_script_`. This immediately tells me it's dealing with the core Frida API.
* **QObject and Qt-related terms:** `QObject`, `QDebug`, `QJsonDocument`, `QPointer`, `QMetaObject::invokeMethod`, `Qt::QueuedConnection`. This indicates the file is part of a Qt-based application (likely the Frida QML frontend).
* **GObject and GLib terms:** `GObject`, `GAsyncResult`, `GError`, `GBytes`, `g_object_`, `g_signal_`, `g_timeout_source_`. This signifies interaction with the underlying GLib library that Frida uses.
* **Core C++ features:**  `#include`, `class`, `public`, `private`, `signals`, `slots`, `new`, `delete`, `std::string`, `std::make_shared`. Basic C++ syntax.
* **Asynchronous operations:** Callback functions like `onSpawnReadyWrapper`, `onResumeReadyWrapper`, `onAttachReadyWrapper`, `onCreateFromSourceReadyWrapper`, `onLoadReadyWrapper`. This points to Frida's asynchronous nature.

**3. Deconstructing the Class Structure:**

The file defines the `Device` class as the primary entity. I'd then look at the other classes involved:

* **`Device`:**  Seems to represent a target device (like a phone or computer). It manages processes and scripts on that device.
* **`Script` and `ScriptInstance`:**  `Script` likely holds the code to be injected, while `ScriptInstance` represents a running instance of that script on a specific process.
* **`SpawnOptions`:**  Configuration options for spawning new processes.
* **`SessionEntry`:** Represents a Frida session attached to a specific process on the device. It manages the scripts within that process.
* **`ScriptEntry`:**  Manages a single script running within a session.

Understanding the relationships between these classes is crucial. The `Device` owns `SessionEntry` objects, and each `SessionEntry` owns `ScriptEntry` objects.

**4. Analyzing Key Functionalities:**

Now, I'd go through the important methods of the `Device` class and its related classes, focusing on what they *do*:

* **`Device` constructor:** Initializes the `Device` object with data from the underlying `FridaDevice` handle.
* **`inject` (both versions):** The core function for injecting scripts. One version spawns a new process, the other attaches to an existing one.
* **`createScriptInstance`:** Creates the `ScriptInstance` and sets up communication channels (signals and slots) between the `Script`, `ScriptInstance`, and `Device`.
* **`performSpawn`, `onSpawnReady`:** Handles the process spawning logic, including error handling.
* **`performInject`:**  Attaches to a process and creates a `SessionEntry`.
* **`performLoad`:**  Sends the script code to the target process for compilation.
* **`performStop`:**  Unloads and cleans up a script.
* **`performPost`:**  Sends messages from the QML frontend to the injected script.
* **`performEnableDebugger`, `performDisableDebugger`:**  Controls the debugger for the injected script.
* **`scheduleGarbageCollect`, `onGarbageCollectTimeout`:**  Manages the cleanup of inactive sessions.
* **`SessionEntry`:** Handles attaching to a process, managing `ScriptEntry` objects, and handling detach events.
* **`ScriptEntry`:** Manages the lifecycle of a script within a session (loading, starting, stopping, sending messages, handling errors).

**5. Connecting to the Prompts:**

Once I had a good grasp of the functionality, I'd explicitly address each part of the prompt:

* **Functionality:** Summarize the purpose of each key method and class, focusing on the overall goal of dynamic instrumentation.
* **Reverse Engineering:** Think about *how* these functionalities are used in reverse engineering. Injecting scripts to inspect memory, hook functions, modify behavior, etc.
* **Binary/Kernel/Framework:**  Identify points where low-level concepts are involved. Spawning processes, attaching to processes, interacting with the operating system's debugging features, the different script runtimes.
* **Logic and Assumptions:** Look for decision points and the flow of execution. For example, the different paths in `inject` based on whether a PID or program name is given. Consider edge cases and error handling.
* **User Errors:**  Imagine common mistakes a developer using Frida might make. Incorrect PIDs, invalid script code, not handling errors properly.
* **User Steps to Reach Here:**  Trace back the user actions that would lead to this code being executed. Starting Frida, selecting a device, choosing a process, injecting a script.

**6. Structuring the Answer:**

Finally, I would organize the information clearly, using headings and bullet points to make it easy to read and understand. I'd start with a high-level summary and then delve into the details for each aspect of the prompt. I would also provide specific code snippets as examples where appropriate.

**Self-Correction/Refinement During the Process:**

* **Initial Overwhelm:**  The file is quite long. It's important not to try to understand every single line at the beginning. Focus on the main classes and their core methods first.
* **Callback Hell:**  The asynchronous nature with many callbacks can be confusing. Draw diagrams or mentally trace the execution flow for key operations like `inject`.
* **Qt/GLib Integration:**  Recognize that this code bridges the Qt world with the underlying Frida/GLib layer. Understand how signals/slots in Qt map to GLib signals.
* **Specificity:**  Avoid vague statements. When describing a function's purpose, be specific about what data it manipulates and what Frida API calls it makes.
* **Review and Clarify:** After drafting the answer, review it to ensure it's accurate, comprehensive, and easy for someone unfamiliar with the code to understand. Are there any ambiguous terms or concepts that need further explanation?

By following this structured approach, I can effectively analyze the `device.cpp` file and provide a detailed and informative answer that addresses all aspects of the prompt.
这是 `frida/subprojects/frida-qml/src/device.cpp` 文件的功能列表和相关说明：

**主要功能:**

这个文件定义了 `Device` 类，它在 Frida QML 界面中代表一个受 Frida 监控的目标设备。它的主要职责是管理与目标设备的交互，包括：

1. **设备信息管理:**
   - 获取并存储设备的基本信息，如 ID、名称和类型。
   - 加载和管理设备的图标。

2. **进程管理:**
   - **Spawn (启动) 新进程并注入 Frida 运行时:** 允许用户指定一个可执行文件，在目标设备上启动它，并在启动后自动将 Frida 运行时注入到该进程中。
   - **Attach (附加) 到现有进程并注入 Frida 运行时:** 允许用户指定一个正在运行的进程的 PID，并将 Frida 运行时注入到该进程中。

3. **脚本管理:**
   - **创建 ScriptInstance:** 为即将注入的脚本创建一个 `ScriptInstance` 对象，用于管理脚本的生命周期和状态。
   - **加载脚本代码:** 将用户的 JavaScript 代码加载到目标进程的 Frida 运行时中。
   - **停止脚本:** 从目标进程中卸载并停止运行的脚本。
   - **处理脚本消息:**  接收从目标进程中运行的 Frida 脚本发送的消息。
   - **向脚本发送消息:** 允许 QML 界面向目标进程中运行的 Frida 脚本发送消息。
   - **管理脚本状态:** 跟踪脚本的生命周期状态（加载中、已加载、编译中、启动中、已启动、错误等）。
   - **启用/禁用调试器:** 允许用户在目标进程的脚本中启用或禁用 JavaScript 调试器。

4. **会话管理:**
   - **创建和管理 Frida 会话 (Session):**  当注入到进程时，会创建一个 Frida 会话，用于与目标进程中的 Frida 运行时进行通信。
   - **处理会话分离 (Detach):**  监控 Frida 会话是否意外断开，并通知相关的脚本。
   - **垃圾回收会话:**  定期清理不再有活动脚本的会话。

5. **异步操作管理:**
   - 使用 GLib 的异步 API (例如 `frida_device_spawn`, `frida_device_attach`, `frida_script_load`) 执行与 Frida Core 的交互，并使用回调函数处理结果。
   - 使用 Qt 的信号和槽机制，在不同的线程之间传递操作结果和状态更新。

**与逆向方法的关系及举例说明:**

`device.cpp` 是 Frida 动态插桩工具的核心组成部分，直接支持了多种常见的逆向工程方法：

- **动态分析:** 通过注入 JavaScript 代码，逆向工程师可以在程序运行时动态地观察和修改程序的行为。
    - **举例:** 逆向工程师可以使用 `inject` 方法将一个脚本注入到目标应用程序中，该脚本可以 hook (拦截) 关键函数的调用，打印函数的参数和返回值，或者修改函数的行为。
- **代码注入:**  `inject` 方法是代码注入的核心实现，允许在不修改目标程序二进制文件的情况下，将自定义代码注入到目标进程中执行。
    - **举例:** 逆向工程师可以使用 `inject` 方法将一个脚本注入到恶意软件进程中，分析其网络通信行为或解密其加密的数据。
- **动态调试:**  通过 `performEnableDebugger` 和 `performDisableDebugger` 方法，可以启用 JavaScript 调试器，允许逆向工程师像调试普通 JavaScript 代码一样调试目标进程中的 Frida 脚本。
    - **举例:** 逆向工程师可以使用调试器单步执行注入的脚本，查看变量的值，设置断点，以便更深入地理解程序的执行流程。
- **内存操作:**  注入的 Frida 脚本可以使用 Frida 提供的 API 来读取和修改目标进程的内存。
    - **举例:** 逆向工程师可以编写脚本来查找特定的内存地址，读取其中的数据，或者修改某些变量的值来改变程序的行为。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明:**

`device.cpp` 虽然本身是用 C++ 和 Qt 编写的，但它与 Frida Core 库交互，而 Frida Core 库则深入到操作系统底层：

- **进程和线程:**  `inject` 方法需要理解操作系统中进程的概念，以及如何附加到或创建新的进程。这涉及到操作系统提供的进程管理 API (例如 Linux 的 `fork`, `execve`, `ptrace` 或 Android 的 `zygote`)。
    - **举例:**  `frida_device_spawn` 的实现最终会调用操作系统底层的进程创建函数。`frida_device_attach` 则会利用操作系统提供的进程间通信和调试机制 (例如 `ptrace` 在 Linux 上) 来附加到目标进程。
- **动态链接和加载:** Frida 需要将自身的运行时库注入到目标进程中，这涉及到对操作系统动态链接器 (例如 `ld-linux.so` 或 `linker64` 在 Android 上) 的理解。
    - **举例:**  Frida 的注入机制通常会利用目标进程的动态链接器来加载 Frida 的 agent 库。
- **内存管理:**  Frida 脚本可以操作目标进程的内存，这需要理解操作系统的内存管理机制，包括虚拟地址空间、内存映射等。
    - **举例:**  Frida 脚本可以使用 `Memory.read*` 和 `Memory.write*` 等 API 来读取和修改目标进程的内存，这些 API 的底层实现会调用操作系统提供的内存访问函数。
- **系统调用:**  Frida 脚本可以通过拦截系统调用的方式来监控程序的行为。
    - **举例:**  Frida 可以 hook (拦截) `open`, `read`, `write`, `connect` 等系统调用，从而监控目标程序的 IO 操作和网络通信。
- **Android 框架 (特别是 ART 虚拟机):** 在 Android 环境下，Frida 经常需要与 Android 运行时 (ART) 虚拟机交互，例如 hook Java 方法。
    - **举例:**  Frida 可以利用 ART 提供的 API (例如 JNI) 来获取 Java 方法的信息，并实现对 Java 方法的 hook。

**逻辑推理及假设输入与输出:**

以下是一些逻辑推理的例子以及假设的输入和输出：

- **假设输入:** 用户调用 `inject(script, "com.example.app", options)`，其中 `script` 是一个包含 JavaScript 代码的 `Script` 对象，`"com.example.app"` 是要启动的 Android 应用的包名，`options` 包含启动参数。
- **逻辑推理:**
    1. `Device::inject` 方法被调用。
    2. 创建一个 `ScriptInstance` 对象。
    3. `m_mainContext->schedule` 将一个 lambda 函数添加到主线程的事件循环中。
    4. 主线程执行 lambda 函数，调用 `performSpawn`。
    5. `performSpawn` 调用 Frida Core 的 `frida_device_spawn` 函数，尝试启动指定的应用程序。
    6. 如果启动成功，`onSpawnReadyWrapper` 回调函数会被调用。
    7. `onSpawnReady` 从 `GAsyncResult` 中获取新进程的 PID。
    8. 调用 `QMetaObject::invokeMethod` 触发 `ScriptInstance` 的 `onSpawnComplete` 信号，并将 PID 作为参数传递。
    9. 接着调用 `performInject` 将脚本注入到新启动的进程中。
- **假设输出:**  如果一切顺利，目标应用被成功启动，并且 `ScriptInstance` 的 `onSpawnComplete` 信号会被触发，QML 界面会收到新进程的 PID。如果启动失败，`onError` 信号会被触发，并包含错误信息。

- **假设输入:** 用户调用 `inject(script, 12345)`，其中 `script` 是一个 `Script` 对象，`12345` 是目标进程的 PID。
- **逻辑推理:**
    1. `Device::inject` 方法被调用。
    2. 创建一个 `ScriptInstance` 对象。
    3. `m_mainContext->schedule` 将一个 lambda 函数添加到主线程的事件循环中。
    4. 主线程执行 lambda 函数，调用 `performInject`。
    5. `performInject` 检查是否已经存在与该 PID 的会话，如果不存在，则创建一个新的 `SessionEntry` 并尝试附加到该进程。
    6. 创建一个新的 `ScriptEntry` 并将其添加到会话中。
    7. 调用 `tryPerformLoad` 尝试加载脚本代码。
- **假设输出:** 如果附加成功，并且脚本加载成功，`ScriptInstance` 的状态最终会变为 "Started"，并且可以开始接收和发送消息。如果附加失败，`ScriptInstance` 会收到错误通知。

**用户或编程常见的使用错误及举例说明:**

- **尝试注入到不存在的进程:** 用户提供了错误的 PID，导致 `frida_device_attach` 失败。
    - **举例:**  用户在 QML 界面中输入了一个错误的 PID，点击 "注入" 按钮，导致 `onAttachReady` 中 `error` 不为空，触发 `script->notifySessionError(error)`，最终 `ScriptInstance` 会收到一个错误状态。
- **提供的脚本代码有语法错误:**  注入的 JavaScript 代码包含语法错误，导致 Frida 运行时解析或执行失败。
    - **举例:**  用户编写的 JavaScript 代码缺少分号或者使用了未定义的变量，当 `performLoad` 调用 `frida_session_create_script` 时，Frida Core 会返回一个错误，`onCreateComplete` 会处理这个错误并更新 `ScriptInstance` 的状态为 "Error"。
- **在没有附加到进程的情况下尝试操作脚本:**  例如，在成功注入之前尝试发送消息。
    - **举例:**  用户在脚本状态还是 "Loading" 或 "Establishing" 时尝试调用发送消息的功能，`ScriptEntry::post` 方法会根据当前状态将消息放入队列或丢弃，避免在脚本未准备好时发送消息导致错误。
- **忘记处理异步操作的结果:**  Frida 的很多操作都是异步的，如果用户没有正确地处理回调函数或信号，可能会导致程序行为不符合预期。
    - **举例:**  用户在调用 `inject` 后没有监听 `ScriptInstance` 的 `onStatus` 或 `onError` 信号，可能无法及时知道脚本是否注入成功或遇到了错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Frida QML 界面:**  用户双击 Frida QML 应用程序的图标或在终端中运行启动命令。
2. **界面加载并连接到 Frida 服务:**  QML 界面初始化并连接到本地运行的 Frida 服务。
3. **用户选择目标设备:**  在设备列表中，用户选择要进行插桩的目标设备（例如，连接的 Android 设备或本地计算机）。
4. **用户选择目标进程:**
   - **方式一 (Attach):** 用户在进程列表中选择一个正在运行的进程，并点击 "Attach" 或类似的按钮。这会触发 QML 界面调用 `Device::inject` 方法，并传入所选进程的 PID。
   - **方式二 (Spawn):** 用户输入要启动的可执行文件路径或应用程序包名，并可能设置启动参数，然后点击 "Spawn" 或类似的按钮。这会触发 QML 界面调用 `Device::inject` 方法，并传入可执行文件路径/包名和启动选项。
5. **用户编写或选择要注入的 JavaScript 脚本:**  用户在代码编辑器中输入 JavaScript 代码，或者从文件中加载已有的脚本。
6. **用户执行注入操作:**  用户点击界面上的 "注入"、"运行" 或类似的按钮。
7. **QML 界面调用 `Device` 类的相应方法:**  根据用户的操作，QML 界面会调用 `Device` 类的 `inject` 方法，并将 `Script` 对象和目标进程信息作为参数传递。
8. **`Device::inject` 方法创建 `ScriptInstance` 并安排异步操作:**  `inject` 方法会创建 `ScriptInstance` 对象，并使用 `m_mainContext->schedule` 将需要在主线程执行的操作（例如调用 Frida Core 的 API）添加到事件循环中。
9. **主线程执行异步操作:**  主线程按照事件循环的顺序执行添加的任务，调用 Frida Core 的 C API (例如 `frida_device_spawn`, `frida_device_attach`, `frida_session_create_script`)。
10. **Frida Core 与目标设备进行交互:**  Frida Core 库负责与目标设备进行实际的通信和操作，例如启动进程、附加到进程、注入代码等。
11. **Frida Core 通过回调函数通知结果:**  Frida Core 的异步操作完成后，会调用预先设置的回调函数 (例如 `onSpawnReadyWrapper`, `onAttachReadyWrapper`, `onCreateFromSourceReadyWrapper`)，并将操作结果 (成功或失败，以及相关的数据) 传递回来。
12. **`Device` 类处理回调结果并更新状态:**  `Device` 类中的回调函数会处理 Frida Core 返回的结果，并更新相关的对象状态 (例如 `ScriptInstance` 的状态)。
13. **通过信号和槽机制通知 QML 界面:**  `Device` 类使用 Qt 的信号和槽机制，将状态更新和操作结果通知给 QML 界面，以便界面能够更新显示并响应用户的操作。

因此，当开发者在 QML 界面上执行注入操作时，会逐步触发 `device.cpp` 中的代码执行，并通过与 Frida Core 的交互，最终完成在目标设备上注入和运行脚本的目标。调试时，可以在 `device.cpp` 中的关键函数 (例如 `inject`, `performSpawn`, `performInject`, `performLoad`) 设置断点，观察变量的值和执行流程，从而追踪问题的根源。

### 提示词
```
这是目录为frida/subprojects/frida-qml/src/device.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include <frida-core.h>

#include "device.h"

#include "maincontext.h"
#include "script.h"
#include "spawnoptions.h"
#include "variant.h"

#include <memory>
#include <QDebug>
#include <QJsonDocument>
#include <QPointer>

#define QUICKJS_BYTECODE_MAGIC 0x02

static void deleteByteArray(gpointer data);

Device::Device(FridaDevice *handle, QObject *parent) :
    QObject(parent),
    m_handle(handle),
    m_id(frida_device_get_id(handle)),
    m_name(frida_device_get_name(handle)),
    m_type(static_cast<Device::Type>(frida_device_get_dtype(handle))),
    m_gcTimer(nullptr),
    m_mainContext(new MainContext(frida_get_main_context()))
{
    auto serializedIcon = Frida::parseVariant(frida_device_get_icon(handle)).toMap();
    if (!serializedIcon.isEmpty())
        m_icon = IconProvider::instance()->add(serializedIcon);

    g_object_ref(m_handle);
    g_object_set_data(G_OBJECT(m_handle), "qdevice", this);
}

void Device::dispose()
{
    if (m_gcTimer != nullptr) {
        g_source_destroy(m_gcTimer);
        m_gcTimer = nullptr;
    }

    auto it = m_sessions.constBegin();
    while (it != m_sessions.constEnd()) {
        delete it.value();
        ++it;
    }

    g_object_set_data(G_OBJECT(m_handle), "qdevice", nullptr);
    g_object_unref(m_handle);
}

Device::~Device()
{
    IconProvider::instance()->remove(m_icon);

    m_mainContext->perform([this] () { dispose(); });
}

ScriptInstance *Device::inject(Script *script, QString program, SpawnOptions *options)
{
    ScriptInstance *instance = createScriptInstance(script, -1);
    if (instance == nullptr)
        return nullptr;

    FridaSpawnOptions *optionsHandle;
    if (options != nullptr) {
        optionsHandle = options->handle();
        g_object_ref(optionsHandle);
    } else {
        optionsHandle = nullptr;
    }

    m_mainContext->schedule([=] () { performSpawn(program, optionsHandle, instance); });

    return instance;
}

ScriptInstance *Device::inject(Script *script, int pid)
{
    ScriptInstance *instance = createScriptInstance(script, pid);
    if (instance == nullptr)
        return nullptr;

    m_mainContext->schedule([=] () { performInject(pid, instance); });

    return instance;
}

ScriptInstance *Device::createScriptInstance(Script *script, int pid)
{
    ScriptInstance *instance = (script != nullptr) ? script->bind(this, pid) : nullptr;
    if (instance == nullptr)
        return nullptr;

    QPointer<Device> device(this);
    auto onStatusChanged = std::make_shared<QMetaObject::Connection>();
    auto onResumeRequest = std::make_shared<QMetaObject::Connection>();
    auto onStopRequest = std::make_shared<QMetaObject::Connection>();
    auto onSend = std::make_shared<QMetaObject::Connection>();
    auto onEnableDebugger = std::make_shared<QMetaObject::Connection>();
    auto onDisableDebugger = std::make_shared<QMetaObject::Connection>();
    *onStatusChanged = connect(script, &Script::statusChanged, [=] () {
        tryPerformLoad(instance);
    });
    *onResumeRequest = connect(instance, &ScriptInstance::resumeProcessRequest, [=] () {
        m_mainContext->schedule([=] () { performResume(instance); });
    });
    *onStopRequest = connect(instance, &ScriptInstance::stopRequest, [=] () {
        QObject::disconnect(*onStatusChanged);
        QObject::disconnect(*onResumeRequest);
        QObject::disconnect(*onStopRequest);
        QObject::disconnect(*onSend);
        QObject::disconnect(*onEnableDebugger);
        QObject::disconnect(*onDisableDebugger);

        script->unbind(instance);

        if (!device.isNull()) {
            device->m_mainContext->schedule([=] () { device->performStop(instance); });
        }
    });
    *onSend = connect(instance, &ScriptInstance::send, [=] (QJsonValue value) {
        m_mainContext->schedule([=] () { performPost(instance, value); });
    });
    *onEnableDebugger = connect(instance, &ScriptInstance::enableDebuggerRequest, [=] (quint16 port) {
        m_mainContext->schedule([=] () { performEnableDebugger(instance, port); });
    });
    *onDisableDebugger = connect(instance, &ScriptInstance::disableDebuggerRequest, [=] () {
        m_mainContext->schedule([=] () { performDisableDebugger(instance); });
    });

    return instance;
}

void Device::performSpawn(QString program, FridaSpawnOptions *options, ScriptInstance *wrapper)
{
    std::string programStr = program.toStdString();
    frida_device_spawn(handle(), programStr.c_str(), options, nullptr, onSpawnReadyWrapper, wrapper);
    g_object_unref(options);
}

void Device::onSpawnReadyWrapper(GObject *obj, GAsyncResult *res, gpointer data)
{
    Device *device = static_cast<Device *>(g_object_get_data(obj, "qdevice"));
    if (device != nullptr) {
        device->onSpawnReady(res, static_cast<ScriptInstance *>(data));
    }
}

void Device::onSpawnReady(GAsyncResult *res, ScriptInstance *wrapper)
{
    GError *error = nullptr;
    guint pid = frida_device_spawn_finish(handle(), res, &error);

    if (error == nullptr) {
        QMetaObject::invokeMethod(wrapper, "onSpawnComplete", Qt::QueuedConnection,
            Q_ARG(int, pid));

        performInject(pid, wrapper);
    } else {
        QMetaObject::invokeMethod(wrapper, "onError", Qt::QueuedConnection,
            Q_ARG(QString, QString::fromUtf8(error->message)));
        QMetaObject::invokeMethod(wrapper, "onStatus", Qt::QueuedConnection,
            Q_ARG(ScriptInstance::Status, ScriptInstance::Status::Error));

        g_clear_error(&error);
    }
}

void Device::performResume(ScriptInstance *wrapper)
{
    frida_device_resume(handle(), wrapper->pid(), nullptr, onResumeReadyWrapper, wrapper);
}

void Device::onResumeReadyWrapper(GObject *obj, GAsyncResult *res, gpointer data)
{
    Device *device = static_cast<Device *>(g_object_get_data(obj, "qdevice"));
    if (device != nullptr) {
        device->onResumeReady(res, static_cast<ScriptInstance *>(data));
    }
}

void Device::onResumeReady(GAsyncResult *res, ScriptInstance *wrapper)
{
    GError *error = nullptr;
    frida_device_resume_finish(handle(), res, &error);

    if (error == nullptr) {
        QMetaObject::invokeMethod(wrapper, "onResumeComplete", Qt::QueuedConnection);
    } else {
        QMetaObject::invokeMethod(wrapper, "onError", Qt::QueuedConnection,
            Q_ARG(QString, QString::fromUtf8(error->message)));
        QMetaObject::invokeMethod(wrapper, "onStatus", Qt::QueuedConnection,
            Q_ARG(ScriptInstance::Status, ScriptInstance::Status::Error));

        g_clear_error(&error);
    }
}

void Device::performInject(int pid, ScriptInstance *wrapper)
{
    auto session = m_sessions[pid];
    if (session == nullptr) {
        session = new SessionEntry(this, pid);
        m_sessions[pid] = session;
        connect(session, &SessionEntry::detached, [=] () {
            for (ScriptEntry *script : session->scripts())
                m_scripts.remove(script->wrapper());
            m_sessions.remove(pid);
            m_mainContext->schedule([=] () {
                delete session;
            });
        });
    }

    auto script = session->add(wrapper);
    m_scripts[wrapper] = script;
    connect(script, &ScriptEntry::stopped, [=] () {
        m_mainContext->schedule([=] () { delete script; });
    });

    QMetaObject::invokeMethod(this, "tryPerformLoad", Qt::QueuedConnection,
        Q_ARG(ScriptInstance *, wrapper));
}

void Device::tryPerformLoad(ScriptInstance *wrapper)
{
    Script *script = reinterpret_cast<Script *>(wrapper->parent());
    if (script->status() != Script::Status::Loaded)
        return;

    auto name = script->name();
    auto runtime = script->runtime();
    auto code = script->code();
    m_mainContext->schedule([=] () { performLoad(wrapper, name, runtime, code); });
}

void Device::performLoad(ScriptInstance *wrapper, QString name, Script::Runtime runtime, QByteArray code)
{
    auto script = m_scripts[wrapper];
    if (script == nullptr)
        return;
    script->load(name, runtime, code);
}

void Device::performStop(ScriptInstance *wrapper)
{
    auto script = m_scripts[wrapper];
    if (script == nullptr)
        return;
    m_scripts.remove(wrapper);

    script->session()->remove(script);

    scheduleGarbageCollect();
}

void Device::performPost(ScriptInstance *wrapper, QJsonValue value)
{
    auto script = m_scripts[wrapper];
    if (script == nullptr)
        return;
    script->post(value);
}

void Device::performEnableDebugger(ScriptInstance *wrapper, quint16 port)
{
    auto script = m_scripts[wrapper];
    if (script == nullptr)
        return;
    script->enableDebugger(port);
}

void Device::performDisableDebugger(ScriptInstance *wrapper)
{
    auto script = m_scripts[wrapper];
    if (script == nullptr)
        return;
    script->disableDebugger();
}

void Device::scheduleGarbageCollect()
{
    if (m_gcTimer != nullptr) {
        g_source_destroy(m_gcTimer);
        m_gcTimer = nullptr;
    }

    auto timer = g_timeout_source_new_seconds(5);
    g_source_set_callback(timer, onGarbageCollectTimeoutWrapper, this, nullptr);
    g_source_attach(timer, m_mainContext->handle());
    g_source_unref(timer);
    m_gcTimer = timer;
}

gboolean Device::onGarbageCollectTimeoutWrapper(gpointer data)
{
    static_cast<Device *>(data)->onGarbageCollectTimeout();

    return FALSE;
}

void Device::onGarbageCollectTimeout()
{
    m_gcTimer = nullptr;

    auto newSessions = QHash<int, SessionEntry *>();
    auto it = m_sessions.constBegin();
    while (it != m_sessions.constEnd()) {
        auto pid = it.key();
        auto session = it.value();
        if (session->scripts().isEmpty()) {
            delete session;
        } else {
            newSessions[pid] = session;
        }
        ++it;
    }
    m_sessions = newSessions;
}

SessionEntry::SessionEntry(Device *device, int pid, QObject *parent) :
    QObject(parent),
    m_device(device),
    m_pid(pid),
    m_handle(nullptr)
{
    frida_device_attach(device->handle(), pid, nullptr, nullptr, onAttachReadyWrapper, this);
}

SessionEntry::~SessionEntry()
{
    if (m_handle != nullptr) {
        frida_session_detach(m_handle, nullptr, nullptr, nullptr);

        g_signal_handlers_disconnect_by_func(m_handle, GSIZE_TO_POINTER(onDetachedWrapper), this);

        g_object_set_data(G_OBJECT(m_handle), "qsession", nullptr);
        g_object_unref(m_handle);
    }
}

ScriptEntry *SessionEntry::add(ScriptInstance *wrapper)
{
    auto script = new ScriptEntry(this, wrapper, this);
    m_scripts.append(script);
    script->updateSessionHandle(m_handle);
    return script;
}

void SessionEntry::remove(ScriptEntry *script)
{
    script->stop();
    m_scripts.removeOne(script);
}

void SessionEntry::onAttachReadyWrapper(GObject *obj, GAsyncResult *res, gpointer data)
{
    if (g_object_get_data(obj, "qdevice") != nullptr) {
        static_cast<SessionEntry *>(data)->onAttachReady(res);
    }
}

void SessionEntry::onAttachReady(GAsyncResult *res)
{
    GError *error = nullptr;
    m_handle = frida_device_attach_finish(m_device->handle(), res, &error);
    if (error == nullptr) {
        g_object_set_data(G_OBJECT(m_handle), "qsession", this);

        g_signal_connect_swapped(m_handle, "detached", G_CALLBACK(onDetachedWrapper), this);

        for (ScriptEntry *script : std::as_const(m_scripts)) {
            script->updateSessionHandle(m_handle);
        }
    } else {
        for (ScriptEntry *script : std::as_const(m_scripts)) {
            script->notifySessionError(error);
        }
        g_clear_error(&error);
    }
}

void SessionEntry::onDetachedWrapper(SessionEntry *self, int reason, FridaCrash * crash)
{
    Q_UNUSED(crash);

    self->onDetached(static_cast<DetachReason>(reason));
}

void SessionEntry::onDetached(DetachReason reason)
{
    const char *message;
    switch (reason) {
    case DetachReason::ApplicationRequested:
        message = "Detached by application";
        break;
    case DetachReason::ProcessReplaced:
        message = "Process replaced";
        break;
    case DetachReason::ProcessTerminated:
        message = "Process terminated";
        break;
    case DetachReason::ConnectionTerminated:
        message = "Connection terminated";
        break;
    case DetachReason::DeviceLost:
        message = "Device lost";
        break;
    default:
        g_assert_not_reached();
    }

    for (ScriptEntry *script : std::as_const(m_scripts))
        script->notifySessionError(message);

    Q_EMIT detached(reason);
}

ScriptEntry::ScriptEntry(SessionEntry *session, ScriptInstance *wrapper, QObject *parent) :
    QObject(parent),
    m_status(ScriptInstance::Status::Loading),
    m_session(session),
    m_wrapper(wrapper),
    m_runtime(Script::Runtime::Default),
    m_handle(nullptr),
    m_sessionHandle(nullptr)
{
}

ScriptEntry::~ScriptEntry()
{
    if (m_handle != nullptr) {
        frida_script_unload(m_handle, nullptr, nullptr, nullptr);

        g_signal_handlers_disconnect_by_func(m_handle, GSIZE_TO_POINTER(onMessage), this);

        g_object_set_data(G_OBJECT(m_handle), "qscript", nullptr);
        g_object_unref(m_handle);
    }
}

void ScriptEntry::updateSessionHandle(FridaSession *sessionHandle)
{
    m_sessionHandle = sessionHandle;
    start();
}

void ScriptEntry::notifySessionError(GError *error)
{
    updateError(error);
    updateStatus(ScriptInstance::Status::Error);
}

void ScriptEntry::notifySessionError(QString message)
{
    updateError(message);
    updateStatus(ScriptInstance::Status::Error);
}

void ScriptEntry::post(QJsonValue value)
{
    if (m_status == ScriptInstance::Status::Started) {
        performPost(value);
    } else if (m_status < ScriptInstance::Status::Started) {
        m_pending.enqueue(value);
    } else {
        // Drop silently
    }
}

void ScriptEntry::enableDebugger(quint16 port)
{
  if (m_handle == nullptr)
    return;

  frida_script_enable_debugger(m_handle, port, nullptr, nullptr, nullptr);
}

void ScriptEntry::disableDebugger()
{
  if (m_handle == nullptr)
    return;

  frida_script_disable_debugger(m_handle, nullptr, nullptr, nullptr);
}

void ScriptEntry::updateStatus(ScriptInstance::Status status)
{
    if (status == m_status)
        return;

    m_status = status;

    QMetaObject::invokeMethod(m_wrapper, "onStatus", Qt::QueuedConnection,
        Q_ARG(ScriptInstance::Status, status));

    if (status == ScriptInstance::Status::Started) {
        while (!m_pending.isEmpty())
            performPost(m_pending.dequeue());
    } else if (status > ScriptInstance::Status::Started) {
        m_pending.clear();
    }
}

void ScriptEntry::updateError(GError *error)
{
    updateError(QString::fromUtf8(error->message));
}

void ScriptEntry::updateError(QString message)
{
    QMetaObject::invokeMethod(m_wrapper, "onError", Qt::QueuedConnection,
        Q_ARG(QString, message));
}

void ScriptEntry::load(QString name, Script::Runtime runtime, QByteArray code)
{
    if (m_status != ScriptInstance::Status::Loading)
        return;

    m_name = name;
    m_runtime = runtime;
    m_code = code;
    updateStatus(ScriptInstance::Status::Loaded);

    start();
}

void ScriptEntry::start()
{
    if (m_status == ScriptInstance::Status::Loading)
        return;

    if (m_sessionHandle != nullptr) {
        updateStatus(ScriptInstance::Status::Compiling);

        QByteArray code = m_code;

        auto options = frida_script_options_new();

        if (!m_name.isEmpty()) {
            std::string name = m_name.toStdString();
            frida_script_options_set_name(options, name.c_str());
        }

        frida_script_options_set_runtime(options, static_cast<FridaScriptRuntime>(m_runtime));

        if (m_code.startsWith(QUICKJS_BYTECODE_MAGIC)) {
            QByteArray *code = new QByteArray(m_code);
            GBytes *bytes = g_bytes_new_with_free_func(code->data(), code->size(), deleteByteArray, code);
            frida_session_create_script_from_bytes(m_sessionHandle, bytes, options, nullptr,
                onCreateFromBytesReadyWrapper, this);
        } else {
            std::string source = QString::fromUtf8(m_code).toStdString();
            frida_session_create_script(m_sessionHandle, source.c_str(), options, nullptr,
                onCreateFromSourceReadyWrapper, this);
        }

        g_object_unref(options);
    } else {
        updateStatus(ScriptInstance::Status::Establishing);
    }
}

static void deleteByteArray(gpointer data)
{
    QByteArray *array = static_cast<QByteArray *>(data);
    delete array;
}

void ScriptEntry::stop()
{
    bool canStopNow = m_status != ScriptInstance::Status::Compiling && m_status != ScriptInstance::Status::Starting;

    m_status = ScriptInstance::Status::Destroyed;

    if (canStopNow)
        Q_EMIT stopped();
}

void ScriptEntry::onCreateFromSourceReadyWrapper(GObject *obj, GAsyncResult *res, gpointer data)
{
    if (g_object_get_data(obj, "qsession") != nullptr) {
        static_cast<ScriptEntry *>(data)->onCreateFromSourceReady(res);
    }
}

void ScriptEntry::onCreateFromSourceReady(GAsyncResult *res)
{
    GError *error = nullptr;
    FridaScript *handle = frida_session_create_script_finish(m_sessionHandle, res, &error);
    onCreateComplete(&handle, &error);
}

void ScriptEntry::onCreateFromBytesReadyWrapper(GObject *obj, GAsyncResult *res, gpointer data)
{
    if (g_object_get_data(obj, "qsession") != nullptr) {
        static_cast<ScriptEntry *>(data)->onCreateFromBytesReady(res);
    }
}

void ScriptEntry::onCreateFromBytesReady(GAsyncResult *res)
{
    GError *error = nullptr;
    FridaScript *handle = frida_session_create_script_from_bytes_finish(m_sessionHandle, res, &error);
    onCreateComplete(&handle, &error);
}

void ScriptEntry::onCreateComplete(FridaScript **handle, GError **error)
{
    if (m_status == ScriptInstance::Status::Destroyed) {
        g_clear_object(handle);
        g_clear_error(error);

        Q_EMIT stopped();
        return;
    }

    if (*error == nullptr) {
        m_handle = static_cast<FridaScript *>(g_steal_pointer(handle));
        g_object_set_data(G_OBJECT(m_handle), "qscript", this);

        g_signal_connect_swapped(m_handle, "message", G_CALLBACK(onMessage), this);

        updateStatus(ScriptInstance::Status::Starting);
        frida_script_load(m_handle, nullptr, onLoadReadyWrapper, this);
    } else {
        updateError(*error);
        updateStatus(ScriptInstance::Status::Error);
        g_clear_error(error);
    }
}

void ScriptEntry::onLoadReadyWrapper(GObject *obj, GAsyncResult *res, gpointer data)
{
    if (g_object_get_data(obj, "qscript") != nullptr) {
        static_cast<ScriptEntry *>(data)->onLoadReady(res);
    }
}

void ScriptEntry::onLoadReady(GAsyncResult *res)
{
    GError *error = nullptr;
    frida_script_load_finish(m_handle, res, &error);

    if (m_status == ScriptInstance::Status::Destroyed) {
        g_clear_error(&error);

        Q_EMIT stopped();
        return;
    }

    if (error == nullptr) {
        updateStatus(ScriptInstance::Status::Started);
    } else {
        updateError(error);
        updateStatus(ScriptInstance::Status::Error);
        g_clear_error(&error);
    }
}

void ScriptEntry::performPost(QJsonValue value)
{
    QJsonDocument document = value.isObject()
        ? QJsonDocument(value.toObject())
        : QJsonDocument(value.toArray());
    auto json = document.toJson(QJsonDocument::Compact);
    frida_script_post(m_handle, json.data(), nullptr);
}

void ScriptEntry::onMessage(ScriptEntry *self, const gchar *message, GBytes *data)
{
    auto messageJson = QByteArray::fromRawData(message, static_cast<int>(strlen(message)));
    auto messageDocument = QJsonDocument::fromJson(messageJson);
    auto messageObject = messageDocument.object();

    if (messageObject["type"] == "log") {
        std::string logMessage = messageObject["payload"].toString().toStdString();
        qDebug("%s", logMessage.c_str());
    } else {
        QVariant dataValue;
        if (data != nullptr) {
            gsize dataSize;
            auto dataBuffer = static_cast<const char *>(g_bytes_get_data(data, &dataSize));
            dataValue = QByteArray(dataBuffer, dataSize);
        }

        QMetaObject::invokeMethod(self->m_wrapper, "onMessage", Qt::QueuedConnection,
            Q_ARG(QJsonObject, messageDocument.object()),
            Q_ARG(QVariant, dataValue));
    }
}
```