Response:
Let's break down the thought process to analyze the `core.js` file and address the prompt's requirements.

**1. Understanding the Goal:**

The core goal is to understand the functionality of this JavaScript file within the context of Frida, a dynamic instrumentation toolkit. This involves identifying its core components, how they interact, and their relevance to reverse engineering and system-level interactions.

**2. Initial Scan and High-Level Overview:**

A quick read reveals several key aspects:

* **Module Structure:** It imports other modules like `Console`, `hexdump`, `MessageDispatcher`, and `Worker`. This suggests a modular design, with this file acting as a central point.
* **Global Object (`engine`):**  It manipulates the global object, adding properties and functions. This is a strong indicator that this file sets up the core Frida environment within the JavaScript runtime.
* **RPC Mechanism (`rpc`, `recv`, `send`):**  The presence of `rpc`, `recv`, and `send` strongly suggests a communication channel between the injected JavaScript and the Frida host process.
* **Platform Bridges (`ObjC`, `Swift`, `Java`):** The conditional loading of `ObjC`, `Swift`, and `Java` indicates the ability to interact with platform-specific APIs on iOS, macOS, and Android.
* **Memory Manipulation (`Memory`):**  Functions related to memory allocation, reading, writing, and patching are present.
* **Module and Process Inspection (`Module`, `Process`):** Functionality to enumerate and inspect modules and processes is available.
* **Interception (`Interceptor`, `Stalker`):** The inclusion of `Interceptor` and `Stalker` points to Frida's core capabilities of hooking and tracing code execution.
* **Data Type Handling (`int64`, `uint64`, `ptr`):**  Support for specific data types like 64-bit integers and pointers is implemented.
* **Asynchronous Operations (Promises):**  The use of Promises for operations like socket communication and file I/O suggests an asynchronous model for non-blocking operations.

**3. Detailed Analysis of Key Features and their Implications:**

Now, let's delve deeper into each area, considering the prompt's specific points:

* **Functionality:** Systematically go through each property added to the `engine` object and the imported modules. Describe what each function or module is responsible for. For example:
    * `rpc`:  Provides an interface for exporting JavaScript functions to the Frida host.
    * `recv`/`send`:  Manages message passing between the script and the host.
    * `setTimeout`/`setInterval`: Provides familiar JavaScript timer functions.
    * `ObjC`/`Swift`/`Java`: Enables interaction with native APIs.
    * `Memory`: Offers low-level memory manipulation capabilities.
    * `Module`/`Process`: Allows introspection of the target process.
    * `Interceptor`: The core hooking mechanism.
    * `Stalker`: A dynamic tracing engine.
    * `Socket`: Functionality for network communication.
    * `SqliteDatabase`: Interaction with SQLite databases.

* **Relationship to Reverse Engineering:** For each functional area, consider how it can be used in reverse engineering:
    * `rpc`: Expose functions to control the script from the host.
    * `recv`/`send`: Observe communication patterns, send custom commands.
    * `ObjC`/`Swift`/`Java`:  Hook methods, inspect object states, modify behavior.
    * `Memory`: Analyze memory layouts, modify data, bypass checks.
    * `Module`/`Process`: Understand program structure, locate functions, analyze dependencies.
    * `Interceptor`: Hook functions to intercept calls, log arguments, modify return values.
    * `Stalker`: Trace execution flow, identify key code paths.
    * `hexdump`: Examine raw memory contents.

* **Binary Bottom, Linux, Android Kernel/Framework:** Identify features that directly interact with the underlying system:
    * `NativePointer`: Represents memory addresses, a fundamental concept in binary.
    * `Memory.read*`/`Memory.write*`: Direct memory access.
    * `Memory.patchCode`: Modifying executable code in memory.
    * `Kernel.scan`/`Memory.scan`: Searching for byte patterns in memory.
    * `Module` enumeration:  Relies on OS-level information about loaded libraries.
    * `Process` enumeration:  Interacting with the OS process management.
    * `Interceptor`: Operates at the binary level, modifying function prologues or using platform-specific hooking mechanisms.
    * `Stalker`: Monitors CPU instruction execution.
    * `ObjC`/`Java` interaction: Bridges the gap between JavaScript and platform-specific runtime environments.

* **Logical Reasoning (Assumptions and Outputs):**  Look for functions where the output depends on the input. For instance:
    * `Module.getBaseAddress(moduleName)`: Input is a module name, output is the base address (if found).
    * `Memory.scan(address, size, pattern)`: Input is an address, size, and a pattern, output is matches found.
    * `Thread.backtrace(cpuContext)`: Input is CPU context, output is a stack trace.

* **User/Programming Errors:**  Think about common mistakes a user might make:
    * Incorrect module names in `Module.getBaseAddress`.
    * Invalid memory addresses passed to `Memory` functions.
    * Incorrect data types for function arguments.
    * Forgetting to `JSON.stringify` data sent with `send`.
    * Issues with asynchronous operations (not handling Promises correctly).
    * Incorrect usage of `Interceptor.attach` callbacks.

* **User Operation to Reach Here (Debugging Clue):** Consider the steps a user would take to execute this code:
    1. Write a Frida script (likely in JavaScript).
    2. Use the Frida CLI or API to attach to a target process.
    3. The Frida agent injects the JavaScript runtime and executes this `core.js` file to set up the environment.
    4. The user's script then interacts with the objects and functions defined in `core.js`.

**4. Structuring the Response:**

Organize the information logically, using headings and bullet points for clarity. Follow the structure requested by the prompt (functionality, reverse engineering, system knowledge, logic, errors, debugging).

**5. Refinement and Review:**

After drafting the response, review it for accuracy, completeness, and clarity. Ensure that the examples are relevant and easy to understand. Check if all parts of the prompt have been addressed. For example, double-check that you've provided examples for *each* category mentioned in the prompt. Make sure the explanation of user operations is clear and concise.

By following this structured approach, combining a high-level understanding with detailed analysis, and constantly relating back to the prompt's requirements, you can effectively analyze the `core.js` file and provide a comprehensive answer.
这是一个名为 `core.js` 的 JavaScript 文件，它是 Frida 动态Instrumentation工具中 `frida-gum` 模块的一部分，特别是 `gumjs` 绑定的一部分。它的主要作用是**构建 Frida JavaScript 运行时的核心环境**，使得用户编写的 Frida 脚本能够与目标进程进行交互。

以下是其主要功能点的详细说明，并结合逆向、底层知识、逻辑推理和常见错误进行举例：

**1. 初始化核心对象和函数:**

* **`Console`:**  引入并实例化了 `Console` 模块，为 JavaScript 脚本提供了 `console.log`, `console.warn`, `console.error` 等常用的控制台输出功能。
    * **与逆向的关系:** 在逆向分析中，可以使用 `console.log` 输出关键变量的值、函数调用时的参数和返回值，帮助理解程序执行流程和数据状态。例如，在 hook 一个函数时，可以输出其参数：
      ```javascript
      Interceptor.attach(Module.getExportByName(null, "my_function"), {
        onEnter: function(args) {
          console.log("my_function called with arg1:", args[0]);
        },
        onLeave: function(retval) {
          console.log("my_function returned:", retval);
        }
      });
      ```
* **`hexdump`:**  引入了 `hexdump` 模块，用于以十六进制格式打印内存数据，方便查看二进制数据内容。
    * **与逆向的关系:**  在分析数据结构、协议或内存布局时，`hexdump` 可以直观地展示内存中的原始字节。例如，查看一个 buffer 的内容：
      ```javascript
      let buffer = Memory.alloc(32);
      Memory.writeUtf8String(buffer, "Hello Frida!");
      console.log(hexdump(buffer.readByteArray(12)));
      ```
* **`MessageDispatcher`:** 创建并初始化了 `MessageDispatcher`，用于处理 Frida Agent 和 Frida Client 之间的消息通信。这包括注册消息处理回调 (`recv`) 和发送消息 (`send`)。
    * **与逆向的关系:** Frida 脚本可以通过 `send` 将分析结果、Hook 信息等发送回控制台或客户端程序，客户端可以通过 `recv` 向脚本发送指令。例如，脚本检测到特定事件后发送通知：
      ```javascript
      send({ event: "critical_function_called" });
      ```
* **`Worker`:** 引入了 `Worker` 模块，允许在单独的线程中执行 JavaScript 代码，避免阻塞主线程。
    * **与逆向的关系:**  对于耗时的操作，例如内存扫描，可以使用 `Worker` 在后台执行，提高脚本的响应速度。

**2. 定义全局对象 `engine` 的属性和方法:**

* **`rpc`:**  定义了 `rpc` 对象，用于暴露 JavaScript 函数给 Frida 客户端调用。用户可以通过 `rpc.exports` 定义可以远程调用的函数。
    * **与逆向的关系:**  允许从客户端动态地调用 Agent 中的函数，实现更灵活的交互和控制。例如，在脚本中定义一个读取内存的函数：
      ```javascript
      rpc.exports = {
        readMemory: function(address, size) {
          return Memory.readByteArray(ptr(address), size);
        }
      };
      ```
      然后在客户端可以通过 `frida -p <pid> -l script.js -o readMemory(0x..., 16)` 调用。
* **`recv`:**  定义了 `recv` 函数，用于注册接收来自 Frida 客户端消息的回调函数。
    * **与逆向的关系:**  允许脚本接收来自客户端的指令和数据，实现双向通信。
* **`send`:**  定义了 `send` 函数，用于向 Frida 客户端发送消息。
* **`setTimeout`, `setInterval`, `setImmediate`, `clearImmediate`:** 提供了标准的 JavaScript 定时器功能。
    * **与逆向的关系:**  可以用于延迟执行某些操作，或者周期性地检查某些状态。
* **`int64`, `uint64`:**  提供了创建 64 位有符号和无符号整数的功能。
    * **涉及到二进制底层:**  在处理 64 位地址或数据时非常重要。
* **`ptr`:**  提供将字符串转换为 `NativePointer` 对象的功能，用于表示内存地址。
    * **涉及到二进制底层:**  `NativePointer` 是 Frida 中表示内存地址的核心对象。
* **`NULL`:**  定义了一个表示空指针的 `NativePointer` 对象。
    * **涉及到二进制底层:**  空指针在 C/C++ 等底层语言中具有特殊意义。
* **`console`:**  将之前引入的 `Console` 实例赋值给 `engine.console`。
* **`hexdump`:**  将之前引入的 `hexdump` 函数赋值给 `engine.hexdump`。
* **`Worker`:**  将之前引入的 `Worker` 构造函数赋值给 `engine.Worker`。
* **`ObjC`, `Swift`, `Java`:**  提供了访问 Objective-C (iOS/macOS), Swift (iOS/macOS), 和 Java (Android) 运行时环境的接口。这些属性是动态加载的，只有在目标进程包含相应的运行时环境时才可用。
    * **涉及到 Android 内核及框架:** `Java` 接口允许 Hook Android Framework 层的 Java 代码，例如 Activity 的生命周期函数，SystemService 的方法等。
    * **涉及到 Linux:**  在 macOS 上，Objective-C 运行时是基础库的一部分。
    * **与逆向的关系:**  这是 Frida 强大的平台桥接功能，允许用户在 JavaScript 中直接操作原生代码对象和方法。例如，Hook 一个 Android Java 方法：
      ```javascript
      Java.perform(function() {
        let String = Java.use('java.lang.String');
        String.valueOf.overload('java.lang.Object').implementation = function(obj) {
          console.log("valueOf called with:", obj);
          return this.valueOf.overload('java.lang.Object').call(this, obj);
        };
      });
      ```

**3. 扩展 `NativePointer` 原型:**

* 为 `NativePointer.prototype` 添加了 `Memory` 模块中以 `read` 和 `write` 开头的方法，例如 `readByteArray`, `writeU8` 等。这使得可以直接在 `NativePointer` 对象上调用这些方法来读写内存。
    * **涉及到二进制底层:**  直接操作内存是动态 Instrumentation 的核心能力。

**4. 为 `Int64`, `UInt64`, `NativePointer` 添加 `equals` 方法:**

* 方便比较这些特殊类型的对象是否相等。

**5. 扩展 `Script` 对象:**

* 提供了 `Script.nextTick` 方法，用于在下一个事件循环中执行回调，类似于 Node.js 的 `process.nextTick`。

**6. 扩展 `Kernel`, `Memory`, `Module`, `Process`, `Thread`, `Interceptor`, `Stalker`, `Instruction`, `ApiResolver`, `IOStream`, `InputStream`, `OutputStream`, `SocketListener`, `SocketConnection`, `Socket`, `SourceMap`, `SqliteDatabase`, `Cloak` 等 Frida 核心对象的 API:**

* 这些扩展提供了更便捷和高级的接口来操作内核、内存、模块、进程、线程，进行代码插桩、内存扫描、API 解析、网络通信等。
    * **涉及到二进制底层, linux, android内核及框架:**
        * `Kernel` 对象提供了与操作系统内核交互的能力，例如枚举模块、内存区域。
        * `Memory` 对象提供了内存分配、读写、扫描、代码 Patch 等底层操作。代码 Patch 直接修改二进制指令。
        * `Module` 对象允许枚举和查找模块（共享库或可执行文件）的导出、导入、符号、内存区域等信息。
        * `Process` 对象允许枚举进程中的线程、模块、内存区域等信息。
        * `Thread` 对象允许获取线程的调用栈。
        * `Interceptor` 对象用于 Hook 函数，修改函数的行为，这涉及到修改目标进程的指令或数据。
        * `Stalker` 对象是一个动态代码跟踪引擎，可以跟踪代码的执行路径。
        * `Instruction` 对象用于解析 CPU 指令。
    * **与逆向的关系:** 这些 API 是 Frida 进行动态逆向分析的基础。例如：
        * 使用 `Module.enumerateExports` 查找目标函数的地址。
        * 使用 `Interceptor.attach` Hook 目标函数，观察其参数和返回值。
        * 使用 `Memory.read*` 读取关键内存区域的数据。
        * 使用 `Process.enumerateThreads` 查看进程中的线程。
        * 使用 `Thread.backtrace` 获取函数调用栈。
        * 使用 `Stalker.follow` 跟踪代码执行流程。

**7. 定义辅助函数 `makeEnumerateApi`, `makeEnumerateRanges`:**

* 用于简化为 Frida 对象添加同步和异步枚举方法的过程。

**逻辑推理示例:**

* **假设输入:** 调用 `Module.getBaseAddress("libc.so")`。
* **输出:** 如果目标进程加载了 `libc.so`，则返回其在内存中的基址 (一个 `NativePointer` 对象)。如果未加载，则抛出一个 `Error`，提示找不到模块。

**用户或编程常见的使用错误举例:**

* **错误使用 `rpc.exports`:**
  ```javascript
  // 错误：直接赋值非函数
  rpc.exports.myVar = 123;
  // 正确：应该赋值一个函数
  rpc.exports = {
    getMyVar: function() {
      return 123;
    }
  };
  ```
* **忘记 `JSON.stringify` 发送复杂对象:**
  ```javascript
  let data = { message: "Hello" };
  // 错误：直接发送对象可能导致客户端解析错误
  send(data);
  // 正确：将对象转换为 JSON 字符串
  send(JSON.stringify(data));
  ```
* **在异步操作中访问已被释放的内存:**
  ```javascript
  Interceptor.attach(Module.getExportByName(null, "alloc_buffer"), {
    onLeave: function(retval) {
      let buffer = retval;
      setTimeout(function() {
        // 错误：buffer 指向的内存可能已被释放
        console.log(buffer.readUtf8String());
      }, 1000);
    }
  });
  ```
* **Hook 地址不正确导致程序崩溃:**  在 `Interceptor.attach` 中使用的目标地址不正确，可能指向了非代码区域，导致程序执行流程错乱。

**用户操作如何一步步到达这里 (调试线索):**

1. **编写 Frida 脚本:** 用户首先需要编写一个 JavaScript 文件，例如 `my_script.js`，其中使用了 Frida 提供的 API，例如 `Interceptor.attach`, `Memory.readByteArray` 等。
2. **使用 Frida CLI 或 API 运行脚本:** 用户会使用 Frida 的命令行工具（如 `frida -p <pid> -l my_script.js`）或编程接口（如 Python 的 `frida` 模块）将脚本注入到目标进程中。
3. **Frida Agent 加载 `core.js`:** 当 Frida Agent 被注入到目标进程后，它会首先加载和初始化其核心组件。`core.js` 是其中非常关键的一部分，它会被执行以建立 JavaScript 运行时环境，并提供各种全局对象和函数。
4. **执行用户脚本:**  `core.js` 初始化完成后，Frida Agent 会执行用户编写的 `my_script.js`。在这个过程中，用户脚本中调用的 `Interceptor.attach` 等函数实际上是 `core.js` 中定义或扩展的 API。
5. **如果在用户脚本中使用了 `console.log` 或发送/接收消息，并且出现问题，那么调试的起点就可能涉及到 `core.js` 中 `Console` 和 `MessageDispatcher` 的实现。** 例如，如果 `send` 函数没有按预期发送消息，或者 `recv` 回调没有被触发，可能需要检查 `core.js` 中消息传递的逻辑。
6. **如果涉及到内存操作、模块枚举等底层功能出现问题，那么需要检查 `core.js` 中对 `Memory`, `Module`, `Process` 等对象的扩展和原生函数的调用。**

总而言之，`core.js` 是 Frida JavaScript 运行时的基石，它定义了核心的 API 和环境，使得用户编写的 JavaScript 脚本能够与目标进程进行交互，实现动态 Instrumentation 的各种功能，包括代码 Hook、内存读写、函数调用跟踪等，这些功能在软件逆向工程中扮演着至关重要的角色。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/runtime/core.js的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```javascript
const Console = require('./console');
const hexdump = require('./hexdump');
const MessageDispatcher = require('./message-dispatcher');
const Worker = require('./worker');

const engine = global;
let messageDispatcher;

function initialize() {
  messageDispatcher = new MessageDispatcher();

  const proxyClass = engine.Proxy;
  if ('create' in proxyClass) {
    const createProxy = proxyClass.create;
    engine.Proxy = function (target, handler) {
      return createProxy.call(proxyClass, handler, Object.getPrototypeOf(target));
    };
  }
}

Object.defineProperties(engine, {
  rpc: {
    enumerable: true,
    value: {
      exports: {}
    }
  },
  recv: {
    enumerable: true,
    value: function () {
      let type, callback;
      if (arguments.length === 1) {
        type = '*';
        callback = arguments[0];
      } else {
        type = arguments[0];
        callback = arguments[1];
      }
      return messageDispatcher.registerCallback(type, callback);
    }
  },
  send: {
    enumerable: true,
    value: function (payload, data) {
      const message = {
        type: 'send',
        payload: payload
      };
      engine._send(JSON.stringify(message), data || null);
    }
  },
  setTimeout: {
    enumerable: true,
    value: function (func, delay = 0, ...args) {
      return _setTimeout(function () {
        func.apply(null, args);
      }, delay);
    }
  },
  setInterval: {
    enumerable: true,
    value: function (func, delay, ...args) {
      return _setInterval(function () {
        func.apply(null, args);
      }, delay);
    }
  },
  setImmediate: {
    enumerable: true,
    value: function (func, ...args) {
      return setTimeout(func, 0, ...args);
    }
  },
  clearImmediate: {
    enumerable: true,
    value: function (id) {
      clearTimeout(id);
    }
  },
  int64: {
    enumerable: true,
    value: function (value) {
      return new Int64(value);
    }
  },
  uint64: {
    enumerable: true,
    value: function (value) {
      return new UInt64(value);
    }
  },
  ptr: {
    enumerable: true,
    value: function (str) {
      return new NativePointer(str);
    }
  },
  NULL: {
    enumerable: true,
    value: new NativePointer('0')
  },
  console: {
    enumerable: true,
    value: new Console()
  },
  hexdump: {
    enumerable: true,
    value: hexdump
  },
  Worker: {
    enumerable: true,
    value: Worker
  },
  ObjC: {
    enumerable: true,
    configurable: true,
    get: function () {
      let m;
      if (Frida._loadObjC())
        m = Frida._objc;
      else
        m = makeStubBridge();
      Object.defineProperty(engine, 'ObjC', { value: m });
      return m;
    }
  },
  Swift: {
    enumerable: true,
    configurable: true,
    get: function () {
      let m;
      if (Frida._loadSwift())
        m = Frida._swift;
      else
        m = makeStubBridge();
      Object.defineProperty(engine, 'Swift', { value: m });
      return m;
    }
  },
  Java: {
    enumerable: true,
    configurable: true,
    get: function () {
      let m;
      if (Frida._loadJava())
        m = Frida._java;
      else
        m = makeStubBridge();
      Object.defineProperty(engine, 'Java', { value: m });
      return m;
    }
  },
});

function makeStubBridge() {
  return Object.freeze({ available: false });
}

const pointerPrototype = NativePointer.prototype;

Object.getOwnPropertyNames(Memory)
  .forEach(methodName => {
    if (methodName.indexOf('read') === 0) {
      pointerPrototype[methodName] = makePointerReadMethod(Memory[methodName]);
    } else if (methodName.indexOf('write') === 0) {
      pointerPrototype[methodName] = makePointerWriteMethod(Memory[methodName]);
    }
  });

function makePointerReadMethod(read) {
  return function (...args) {
    return read.call(Memory, this, ...args);
  };
}

function makePointerWriteMethod(write) {
  return function (...args) {
    write.call(Memory, this, ...args);
    return this;
  };
}

[
  Int64,
  UInt64,
  NativePointer
].forEach(klass => {
  klass.prototype.equals = numberWrapperEquals;
});

function numberWrapperEquals(rhs) {
  return this.compare(rhs) === 0;
}

const _nextTick = Script._nextTick;
Script.nextTick = function (callback, ...args) {
  _nextTick(callback.bind(engine, ...args));
};

makeEnumerateApi(Kernel, 'enumerateModules', 0);
makeEnumerateRanges(Kernel);
makeEnumerateApi(Kernel, 'enumerateModuleRanges', 2);

Object.defineProperties(Kernel, {
  scan: {
    enumerable: true,
    value: function (address, size, pattern, callbacks) {
      let onSuccess, onFailure;
      const request = new Promise((resolve, reject) => {
        onSuccess = resolve;
        onFailure = reject;
      });

      Kernel._scan(address, size, pattern, {
        onMatch: callbacks.onMatch,
        onError(reason) {
          onFailure(new Error(reason));
          callbacks.onError?.();
        },
        onComplete() {
          onSuccess();
          callbacks.onComplete?.();
        }
      });

      return request;
    }
  }
});

Object.defineProperties(Memory, {
  alloc: {
    enumerable: true,
    value: function (size, { near, maxDistance } = {}) {
      if (near !== undefined && maxDistance === undefined)
        throw new Error('missing maxDistance option');

      return Memory._alloc(size, near ?? NULL, maxDistance ?? 0);
    }
  },
  dup: {
    enumerable: true,
    value: function (mem, size) {
      const result = Memory.alloc(size);
      Memory.copy(result, mem, size);
      return result;
    }
  },
  patchCode: {
    enumerable: true,
    value: function (address, size, apply) {
      Memory._checkCodePointer(address);
      Memory._patchCode(address, size, apply);
    }
  },
  scan: {
    enumerable: true,
    value: function (address, size, pattern, callbacks) {
      let onSuccess, onFailure;
      const request = new Promise((resolve, reject) => {
        onSuccess = resolve;
        onFailure = reject;
      });

      Memory._scan(address, size, pattern, {
        onMatch: callbacks.onMatch,
        onError(reason) {
          onFailure(new Error(reason));
          callbacks.onError?.(reason);
        },
        onComplete() {
          onSuccess();
          callbacks.onComplete?.();
        }
      });

      return request;
    }
  }
});

makeEnumerateApi(Module, 'enumerateImports', 1);
makeEnumerateApi(Module, 'enumerateExports', 1);
makeEnumerateApi(Module, 'enumerateSymbols', 1);
makeEnumerateApi(Module, 'enumerateRanges', 2);
makeEnumerateApi(Module, 'enumerateSections', 1);
makeEnumerateApi(Module, 'enumerateDependencies', 1);

Object.defineProperties(Module, {
  load: {
    enumerable: true,
    value: function (moduleName) {
      Module._load(moduleName);
      return Process.getModuleByName(moduleName);
    }
  },
  getBaseAddress: {
    enumerable: true,
    value: function (moduleName) {
      const base = Module.findBaseAddress(moduleName);
      if (base === null)
        throw new Error("unable to find module '" + moduleName + "'");
      return base;
    }
  },
  getExportByName: {
    enumerable: true,
    value: function (moduleName, symbolName) {
      const address = Module.findExportByName(moduleName, symbolName);
      if (address === null) {
        const prefix = (moduleName !== null) ? (moduleName + ': ') : '';
        throw new Error(prefix + "unable to find export '" + symbolName + "'");
      }
      return address;
    }
  },
});

Object.defineProperties(Module.prototype, {
  enumerateImports: {
    enumerable: true,
    value: function () {
      return Module.enumerateImports(this.path);
    }
  },
  enumerateExports: {
    enumerable: true,
    value: function () {
      return Module.enumerateExports(this.path);
    }
  },
  enumerateSymbols: {
    enumerable: true,
    value: function () {
      return Module.enumerateSymbols(this.path);
    }
  },
  enumerateRanges: {
    enumerable: true,
    value: function (protection) {
      return Module.enumerateRanges(this.path, protection);
    }
  },
  enumerateSections: {
    enumerable: true,
    value: function () {
      return Module.enumerateSections(this.path);
    }
  },
  enumerateDependencies: {
    enumerable: true,
    value: function () {
      return Module.enumerateDependencies(this.path);
    }
  },
  findExportByName: {
    enumerable: true,
    value: function (exportName) {
      return Module.findExportByName(this.path, exportName);
    }
  },
  getExportByName: {
    enumerable: true,
    value: function (exportName) {
      return Module.getExportByName(this.path, exportName);
    }
  },
});

Object.defineProperties(ModuleMap.prototype, {
  get: {
    enumerable: true,
    value: function (address) {
      const details = this.find(address);
      if (details === null)
        throw new Error('unable to find module containing ' + address);
      return details;
    }
  },
  getName: {
    enumerable: true,
    value: function (address) {
      const name = this.findName(address);
      if (name === null)
        throw new Error('unable to find module containing ' + address);
      return name;
    }
  },
  getPath: {
    enumerable: true,
    value: function (address) {
      const path = this.findPath(address);
      if (path === null)
        throw new Error('unable to find module containing ' + address);
      return path;
    }
  },
});

makeEnumerateApi(Process, 'enumerateThreads', 0);
makeEnumerateApi(Process, 'enumerateModules', 0);
makeEnumerateRanges(Process);
makeEnumerateApi(Process, 'enumerateMallocRanges', 0);

Object.defineProperties(Process, {
  runOnThread: {
    enumerable: true,
    value: function (threadId, callback) {
      return new Promise((resolve, reject) => {
        Process._runOnThread(threadId, () => {
          try {
            resolve(callback());
          } catch (e) {
            reject(e);
          }
        });
      });
    },
  },
  findModuleByAddress: {
    enumerable: true,
    value: function (address) {
      let module = null;
      Process._enumerateModules({
        onMatch(m) {
          const base = m.base;
          if (base.compare(address) <= 0 && base.add(m.size).compare(address) > 0) {
            module = m;
            return 'stop';
          }
        },
        onComplete() {
        }
      });
      return module;
    }
  },
  getModuleByAddress: {
    enumerable: true,
    value: function (address) {
      const module = Process.findModuleByAddress(address);
      if (module === null)
        throw new Error('unable to find module containing ' + address);
      return module;
    }
  },
  getModuleByName: {
    enumerable: true,
    value: function (name) {
      const module = Process.findModuleByName(name);
      if (module === null)
        throw new Error("unable to find module '" + name + "'");
      return module;
    }
  },
  getRangeByAddress: {
    enumerable: true,
    value: function (address) {
      const range = Process.findRangeByAddress(address);
      if (range === null)
        throw new Error('unable to find range containing ' + address);
      return range;
    }
  },
});

if (Process.findRangeByAddress === undefined) {
  Object.defineProperty(Process, 'findRangeByAddress', {
    enumerable: true,
    value: function (address) {
      let range = null;
      Process._enumerateRanges('---', {
        onMatch(r) {
          const base = r.base;
          if (base.compare(address) <= 0 && base.add(r.size).compare(address) > 0) {
            range = r;
            return 'stop';
          }
        },
        onComplete() {
        }
      });
      return range;
    }
  });
}

Object.defineProperties(Thread, {
  backtrace: {
    enumerable: true,
    value: function (cpuContext = null, backtracerOrOptions = {}) {
      const options = (typeof backtracerOrOptions === 'object')
          ? backtracerOrOptions
          : { backtracer: backtracerOrOptions };

      const {
        backtracer = Backtracer.ACCURATE,
        limit = 0,
      } = options;

      return Thread._backtrace(cpuContext, backtracer, limit);
    }
  },
});

if (globalThis.Interceptor !== undefined) {
  Object.defineProperties(Interceptor, {
    attach: {
      enumerable: true,
      value: function (target, callbacks, data) {
        Memory._checkCodePointer(target);
        return Interceptor._attach(target, callbacks, data);
      }
    },
    replace: {
      enumerable: true,
      value: function (target, replacement, data) {
        Memory._checkCodePointer(target);
        Interceptor._replace(target, replacement, data);
      }
    },
    replaceFast: {
      enumerable: true,
      value: function (target, replacement) {
        Memory._checkCodePointer(target);
        return Interceptor._replaceFast(target, replacement);
      }
    },
  });
}

if (globalThis.Stalker !== undefined) {
  const stalkerEventType = {
    call: 1,
    ret: 2,
    exec: 4,
    block: 8,
    compile: 16,
  };

  Object.defineProperties(Stalker, {
    exclude: {
      enumerable: true,
      value: function (range) {
        Stalker._exclude(range.base, range.size);
      }
    },
    follow: {
      enumerable: true,
      value: function (first, second) {
        let threadId = first;
        let options = second;

        if (typeof first === 'object') {
          threadId = undefined;
          options = first;
        }

        if (threadId === undefined)
          threadId = Process.getCurrentThreadId();
        if (options === undefined)
          options = {};

        if (typeof threadId !== 'number' || (options === null || typeof options !== 'object'))
          throw new Error('invalid argument');

        const {
          transform = null,
          events = {},
          onReceive = null,
          onCallSummary = null,
          onEvent = NULL,
          data = NULL,
        } = options;

        if (events === null || typeof events !== 'object')
          throw new Error('events must be an object');

        if (!data.isNull() && (onReceive !== null || onCallSummary !== null))
          throw new Error('onEvent precludes passing onReceive/onCallSummary');

        const eventMask = Object.keys(events).reduce((result, name) => {
          const value = stalkerEventType[name];
          if (value === undefined)
            throw new Error(`unknown event type: ${name}`);

          const enabled = events[name];
          if (typeof enabled !== 'boolean')
            throw new Error('desired events must be specified as boolean values');

          return enabled ? (result | value) : result;
        }, 0);

        Stalker._follow(threadId, transform, eventMask, onReceive, onCallSummary, onEvent, data);
      }
    },
    parse: {
      enumerable: true,
      value: function (events, options = {}) {
        const {
          annotate = true,
          stringify = false
        } = options;

        return Stalker._parse(events, annotate, stringify);
      }
    }
  });
}

Object.defineProperty(Instruction, 'parse', {
  enumerable: true,
  value: function (target) {
    Memory._checkCodePointer(target);
    return Instruction._parse(target);
  }
});

makeEnumerateApi(ApiResolver.prototype, 'enumerateMatches', 1);

const _closeIOStream = IOStream.prototype._close;
IOStream.prototype.close = function () {
  const stream = this;
  return new Promise(function (resolve, reject) {
    _closeIOStream.call(stream, function (error, success) {
      if (error === null)
        resolve(success);
      else
        reject(error);
    });
  });
};

const _closeInput = InputStream.prototype._close;
InputStream.prototype.close = function () {
  const stream = this;
  return new Promise(function (resolve, reject) {
    _closeInput.call(stream, function (error, success) {
      if (error === null)
        resolve(success);
      else
        reject(error);
    });
  });
};

const _read = InputStream.prototype._read;
InputStream.prototype.read = function (size) {
  const stream = this;
  return new Promise(function (resolve, reject) {
    _read.call(stream, size, function (error, data) {
      if (error === null)
        resolve(data);
      else
        reject(error);
    });
  });
};

const _readAll = InputStream.prototype._readAll;
InputStream.prototype.readAll = function (size) {
  const stream = this;
  return new Promise(function (resolve, reject) {
    _readAll.call(stream, size, function (error, data) {
      if (error === null) {
        resolve(data);
      } else {
        error.partialData = data;
        reject(error);
      }
    });
  });
};

const _closeOutput = OutputStream.prototype._close;
OutputStream.prototype.close = function () {
  const stream = this;
  return new Promise(function (resolve, reject) {
    _closeOutput.call(stream, function (error, success) {
      if (error === null)
        resolve(success);
      else
        reject(error);
    });
  });
};

const _write = OutputStream.prototype._write;
OutputStream.prototype.write = function (data) {
  const stream = this;
  return new Promise(function (resolve, reject) {
    _write.call(stream, data, function (error, size) {
      if (error === null)
        resolve(size);
      else
        reject(error);
    });
  });
};

const _writeAll = OutputStream.prototype._writeAll;
OutputStream.prototype.writeAll = function (data) {
  const stream = this;
  return new Promise(function (resolve, reject) {
    _writeAll.call(stream, data, function (error, size) {
      if (error === null) {
        resolve(size);
      } else {
        error.partialSize = size;
        reject(error);
      }
    });
  });
};

const _writeMemoryRegion = OutputStream.prototype._writeMemoryRegion;
OutputStream.prototype.writeMemoryRegion = function (address, length) {
  const stream = this;
  return new Promise(function (resolve, reject) {
    _writeMemoryRegion.call(stream, address, length, function (error, size) {
      if (error === null) {
        resolve(size);
      } else {
        error.partialSize = size;
        reject(error);
      }
    });
  });
};

const _closeListener = SocketListener.prototype._close;
SocketListener.prototype.close = function () {
  const listener = this;
  return new Promise(function (resolve) {
    _closeListener.call(listener, resolve);
  });
};

const _accept = SocketListener.prototype._accept;
SocketListener.prototype.accept = function () {
  const listener = this;
  return new Promise(function (resolve, reject) {
    _accept.call(listener, function (error, connection) {
      if (error === null)
        resolve(connection);
      else
        reject(error);
    });
  });
};

const _setNoDelay = SocketConnection.prototype._setNoDelay;
SocketConnection.prototype.setNoDelay = function (noDelay = true) {
  const connection = this;
  return new Promise(function (resolve, reject) {
    _setNoDelay.call(connection, noDelay, function (error, success) {
      if (error === null)
        resolve(success);
      else
        reject(error);
    });
  });
};

Object.defineProperties(Socket, {
  listen: {
    enumerable: true,
    value: function (options = {}) {
      return new Promise(function (resolve, reject) {
        const {
          family = null,

          host = null,
          port = 0,

          type = null,
          path = null,

          backlog = 10,
        } = options;

        Socket._listen(family, host, port, type, path, backlog, function (error, listener) {
          if (error === null)
            resolve(listener);
          else
            reject(error);
        });
      });
    },
  },
  connect: {
    enumerable: true,
    value: function (options) {
      return new Promise(function (resolve, reject) {
        const {
          family = null,

          host = 'localhost',
          port = 0,

          type = null,
          path = null,

          tls = false,
        } = options;

        Socket._connect(family, host, port, type, path, tls, function (error, connection) {
          if (error === null)
            resolve(connection);
          else
            reject(error);
        });
      });
    },
  },
});

SourceMap.prototype.resolve = function (generatedPosition) {
  const generatedColumn = generatedPosition.column;
  const position = (generatedColumn !== undefined)
      ? this._resolve(generatedPosition.line, generatedColumn)
      : this._resolve(generatedPosition.line);
  if (position === null)
    return null;

  const [source, line, column, name] = position;

  return {source, line, column, name};
};

if (engine.SqliteDatabase !== undefined) {
  const sqliteOpenFlags = {
    readonly: 1,
    readwrite: 2,
    create: 4,
  };

  Object.defineProperties(SqliteDatabase, {
    open: {
      enumerable: true,
      value: function (file, options = {}) {
        if (typeof file !== 'string' || (options === null || typeof options !== 'object'))
          throw new Error('invalid argument');

        const {
          flags = ['readwrite', 'create'],
        } = options;

        if (!(flags instanceof Array) || flags.length === 0)
          throw new Error('flags must be a non-empty array');

        const flagsValue = flags.reduce((result, name) => {
          const value = sqliteOpenFlags[name];
          if (value === undefined)
            throw new Error(`unknown flag: ${name}`);

          return result | value;
        }, 0);

        if (flagsValue === 3 || flagsValue === 5 || flagsValue === 7)
          throw new Error(`invalid flags combination: ${flags.join(' | ')}`);

        return SqliteDatabase._open(file, flagsValue);
      }
    }
  });
}

Object.defineProperties(Cloak, {
  hasCurrentThread: {
    enumerable: true,
    value() {
      return Cloak.hasThread(Process.getCurrentThreadId());
    }
  },
  addRange: {
    enumerable: true,
    value(range) {
      Cloak._addRange(range.base, range.size);
    }
  },
  removeRange: {
    enumerable: true,
    value(range) {
      Cloak._removeRange(range.base, range.size);
    }
  },
  clipRange: {
    enumerable: true,
    value(range) {
      return Cloak._clipRange(range.base, range.size);
    }
  },
});

function makeEnumerateApi(mod, name, arity) {
  const impl = mod['_' + name];

  Object.defineProperty(mod, name, {
    enumerable: true,
    value: function (...args) {
      const callbacks = args[arity];
      if (callbacks === undefined)
        return enumerateSync(impl, this, args);

      impl.apply(this, args);
    }
  });

  Object.defineProperty(mod, name + 'Sync', {
    enumerable: true,
    value: function (...args) {
      return enumerateSync(impl, this, args);
    }
  });
}

function enumerateSync(impl, self, args) {
  const items = [];
  impl.call(self, ...args, {
    onMatch(item) {
      items.push(item);
    },
    onComplete() {
    }
  });
  return items;
}

function makeEnumerateRanges(mod) {
  const impl = mod['_enumerateRanges'];

  Object.defineProperties(mod, {
    enumerateRanges: {
      enumerable: true,
      value: function (specifier, callbacks) {
        if (callbacks === undefined)
          return enumerateSync(enumerateRanges.bind(this, impl, this), this, [specifier]);

        enumerateRanges(impl, this, specifier, callbacks);
      }
    },
    enumerateRangesSync: {
      enumerable: true,
      value: function (specifier) {
        return enumerateSync(enumerateRanges.bind(this, impl, this), this, [specifier]);
      }
    },
  });
}

function enumerateRanges(impl, self, specifier, callbacks) {
  let protection;
  let coalesce = false;
  if (typeof specifier === 'string') {
    protection = specifier;
  } else {
    protection = specifier.protection;
    coalesce = specifier.coalesce;
  }

  if (coalesce) {
    const {onMatch, onComplete} = callbacks;
    let current = null;
    impl.call(self, protection, {
      onMatch(r) {
        if (current !== null) {
          if (r.base.equals(current.base.add(current.size)) && r.protection === current.protection) {
            const coalescedRange = {
              base: current.base,
              size: current.size + r.size,
              protection: current.protection
            };
            if (current.hasOwnProperty('file'))
              coalescedRange.file = current.file;
            Object.freeze(coalescedRange);
            current = coalescedRange;
          } else {
            onMatch(current);
            current = r;
          }
        } else {
          current = r;
        }
      },
      onComplete() {
        if (current !== null)
          onMatch(current);
        onComplete();
      }
    });
  } else {
    impl.call(self, protection, callbacks);
  }
}

initialize();
```