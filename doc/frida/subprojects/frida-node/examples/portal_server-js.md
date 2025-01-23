Response:
Let's break down the thought process for analyzing the provided JavaScript code and answering the prompt's questions.

**1. Initial Understanding and Goal Identification:**

* **Read the introduction:** The prompt identifies the file as `portal_server.js` within a Frida project, suggesting it's a server component for dynamic instrumentation.
* **Skim the code:** Quickly go through the code to identify key components: `require` statements (crypto, frida, readline), class definitions (`Application`, `Peer`, `Channel`), event listeners (`connect`), and asynchronous operations (`async`, `await`).
* **Identify the core functionality:** The code seems to manage connections from nodes (Frida agents) and controllers (likely clients interacting with the server). It involves authentication, message passing, and channel management.

**2. Functionality Breakdown (Instruction 1):**

* **Start with the `Application` class:** This is the central orchestrator.
* **Constructor Analysis:**
    * `EndpointParameters`:  Notice the configuration for cluster and control interfaces. Identify the address types (Unix socket, TCP). Note the different authentication schemes (token, callback).
    * `PortalService`: This is the main Frida component handling connections.
    * `Maps and Sets`:  Identify the data structures used to store peers, nicknames, and channels.
    * `Event Listeners (`connect`): Map these to specific actions (node/controller connect/disconnect, authentication, subscriptions, messages).
* **`run()` Method:**
    *  `_service.start()`: Starts the Frida portal service.
    *  `_device.enableSpawnGating()`: An important Frida concept for controlling process creation.
    *  `readline`:  Handles command-line input. Identify the basic commands (`stop`, empty input).
* **Helper Methods (methods starting with `_`):** Analyze each one individually. For example:
    * `_authenticate`:  Focus on the authentication logic (token parsing, SHA1 hashing, timingSafeEqual).
    * `_onNode...`, `_onController...`, `_onAuthenticated`, `_onSubscribe`, `_onMessage`:  Understand the actions triggered by these events (logging, managing peer data, handling messages).
    * `_acquireNick`, `_releaseNick`:  Nickname management.
    * `_getChannel`:  Channel creation/retrieval.
* **`Peer` Class:**  Simple data holder for connection information and nickname.
* **`Channel` Class:**  Manages members, message history, and uses `narrowcast` for sending messages within the channel.

**3. Relationship to Reverse Engineering (Instruction 2):**

* **Key Concept:** Frida is a dynamic instrumentation tool. This server acts as a central point for managing Frida agents.
* **Connection to Instrumentation:** The server facilitates communication with agents running *inside* target processes. Consider how the server enables actions like:
    * **Connecting to a running process:**  The `enumerateProcesses()` command hints at this.
    * **Injecting code:** Although not directly in this server code, the existence of Frida implies the ability to inject JavaScript.
    * **Intercepting function calls:**  A core Frida capability that this server could facilitate by coordinating with connected agents.
    * **Modifying program behavior:**  The message handling (`_onMessage`) suggests control over agent actions.

**4. Binary, Linux, Android Knowledge (Instruction 3):**

* **Low-Level Concepts:**
    * **Unix Sockets:** The `unix:/Users/oleavr/src/cluster` address points to inter-process communication.
    * **TCP/IP:** The `::1:27042` address uses standard networking.
    * **Certificates:**  SSL/TLS for secure communication.
    * **Authentication:**  Tokens and callbacks are security mechanisms.
* **Frida Specifics:**
    * **Spawn Gating:**  A Frida feature to intercept process creation.
    * **Tags:** Used by Frida for filtering and targeting specific agents or contexts.
    * **`narrowcast` and `broadcast`:** Frida's methods for sending messages to specific or all connected clients.
* **Android (Implicit):** While not explicitly Android code, Frida is heavily used for Android reverse engineering. The concepts of process injection and instrumentation apply. The server might manage Frida agents running on Android devices.

**5. Logical Reasoning (Instruction 4):**

* **Focus on Key Logic:**  Authentication, nickname assignment, and message routing.
* **Authentication:**
    * **Input:** A JSON string like `{"nick": "user1", "secret": "password"}`.
    * **Process:** The server hashes the provided secret and compares it to a hardcoded hash of "knock-knock".
    * **Output (Success):** An object like `{ nick: "user1" }`.
    * **Output (Failure):** An error like "Invalid token" or "Get outta here".
* **Nickname Acquisition:**
    * **Input:** A requested nickname (e.g., "Alice").
    * **Process:** The server checks if the nickname is already taken. If so, it appends numbers until a unique one is found.
    * **Output:** A unique nickname (e.g., "Alice", "Alice2", "Alice3").
* **Message Routing:**
    * **Input (Join):**  `{ type: 'join', channel: 'general' }`.
    * **Process:** The server adds the peer to the specified channel.
    * **Output (Internal):** The peer's `memberships` and the channel's `members` are updated. A "join" message is sent to the channel.
    * **Input (Say):** `{ type: 'say', channel: 'general', text: 'Hello everyone!' }`.
    * **Process:** The server retrieves the channel and sends the message to all members.
    * **Output (Internal):** The message is added to the channel's history.

**6. User/Programming Errors (Instruction 5):**

* **Authentication:**  Providing an incorrect secret.
* **Token Format:**  Sending a malformed JSON token.
* **Missing Nick or Secret:**  The token not containing the required fields.
* **Case Sensitivity (Possible):** Depending on how the client implements the token creation, case sensitivity of the secret could be an issue.
* **Command Errors:** Typing an unrecognized command at the prompt.
* **Network Issues:**  The client failing to connect to the specified address and port.
* **Permissions:** Issues with file permissions for the Unix socket or certificate files.

**7. User Steps to Reach the Code (Instruction 6):**

* **Setting up Frida:** Install Frida and its Python bindings.
* **Navigating to the Examples:**  Locate the Frida repository and navigate to the `frida/subprojects/frida-node/examples/` directory.
* **Running the Server:** Execute `node portal_server.js` in the terminal.
* **Interacting with the Server (Basic):** Type commands like `stop` or press Enter to see the process list.
* **Developing a Client (More Advanced):**  Create a separate client application that connects to the server (using the specified address and port) and authenticates. This client would send messages like `join`, `part`, `say`, etc.
* **Debugging:** If the client isn't working as expected, you might step through the `portal_server.js` code using a Node.js debugger to understand the server's behavior.

**Self-Correction/Refinement During the Process:**

* **Initial Focus:**  Might initially focus too much on the individual event handlers. Realize the need to step back and understand the overall flow and the purpose of the `Application` class.
* **Frida Concepts:**  Realize the importance of explaining key Frida concepts like "spawn gating" and "tags."
* **Assumptions:** Be mindful of making assumptions. For example, don't assume the specific client implementation details. Focus on what the server code *does*.
* **Clarity:**  Ensure the explanations are clear and concise, avoiding overly technical jargon where possible. Use examples to illustrate concepts.

By following this structured thought process, breaking down the code into manageable parts, and considering the prompt's specific requirements, one can arrive at a comprehensive and accurate analysis of the `portal_server.js` file.
好的，让我们来详细分析一下 `frida/subprojects/frida-node/examples/portal_server.js` 这个文件。

**文件功能概览**

这个 `portal_server.js` 文件实现了一个基于 Frida 的 Portal 服务器。其核心功能是作为一个中介，连接和管理两种类型的客户端：

1. **Nodes:**  这些是运行在目标设备或进程上的 Frida Agent。它们通过 Cluster 接口连接到服务器。
2. **Controllers:** 这些是用户界面或控制端，例如 Web 客户端，它们通过 Control 接口连接到服务器。

Portal 服务器的主要职责包括：

* **连接管理:** 接受来自 Nodes 和 Controllers 的连接。
* **身份验证:** 对连接的 Controller 进行身份验证。
* **消息路由:** 在连接的 Nodes 和 Controllers 之间传递消息。
* **通道管理:**  允许用户创建和加入聊天通道。
* **昵称管理:**  为连接的用户分配和管理昵称。
* **进程枚举:**  允许用户列出目标设备上的进程。
* **Spawn Gating:**  允许在进程启动时进行拦截和操作。

**与逆向方法的关系及举例**

这个 Portal 服务器是 Frida 动态 Instrumentation 工具生态系统的一部分，与逆向工程密切相关。其主要作用是提供一个集中控制和协调多个 Frida Agent 的平台。

**举例说明:**

假设你正在逆向一个 Android 应用程序。

1. **部署 Frida Agent:** 你需要在你的 Android 设备上运行一个 Frida Agent。
2. **连接到 Portal 服务器:** 这个 Frida Agent (作为 Node) 会连接到 Portal 服务器，通过配置的 Cluster 接口（例如 Unix Socket）。
3. **连接控制端:** 你使用一个 Web 客户端（作为 Controller）连接到 Portal 服务器，通过 Control 接口 (例如 TCP)。
4. **远程控制:** 通过 Web 客户端，你可以发送命令给 Portal 服务器。
5. **Instrumentation:** Portal 服务器会将这些命令路由到连接的 Frida Agent。例如，你可以发送命令来 hook 某个函数，修改其参数或返回值。
6. **结果反馈:** Frida Agent 执行 Instrumentation 后，会将结果返回给 Portal 服务器，服务器再将结果转发给你的 Web 客户端。

**二进制底层、Linux、Android 内核及框架的知识**

虽然这个 JavaScript 代码本身不是直接操作二进制或内核的，但它作为 Frida 生态系统的一部分，与这些底层概念紧密相关。

* **二进制底层:** Frida 的核心功能是能够注入 JavaScript 代码到目标进程中，并与目标进程的内存空间进行交互。这涉及到对目标进程的二进制代码的理解，例如函数地址、数据结构等。Portal 服务器管理连接的 Frida Agent，这些 Agent 负责执行底层的二进制操作。
* **Linux:**  代码中使用了 Unix Socket (`unix:/Users/oleavr/src/cluster`) 作为 Node 连接的地址。Unix Socket 是一种 Linux 特有的进程间通信机制。
* **Android 内核及框架:**  Frida 经常被用于 Android 应用程序的逆向工程。连接到 Portal 服务器的 Frida Agent 可能运行在 Android 设备上，能够访问和操作 Android 框架的各种组件，例如 ActivityManager、PackageManager 等。`enableSpawnGating()` 功能允许在 Android 系统启动新的进程时进行拦截，这涉及到对 Android 系统进程启动流程的理解。

**逻辑推理及假设输入与输出**

让我们分析一下 `_authenticate` 函数的逻辑推理：

**假设输入:**

* `rawToken`: 一个 JSON 字符串，例如 `{"nick": "testuser", "secret": "mysecret"}`。

**逻辑推理:**

1. **解析 Token:** 尝试将 `rawToken` 解析为 JSON 对象。如果解析失败，抛出 "Invalid token" 错误。
2. **验证字段:** 检查解析后的 JSON 对象是否包含 `nick` 和 `secret` 字段，并且这两个字段都是字符串类型。如果不是，抛出 "Invalid token" 错误。
3. **哈希 Secret:** 使用 SHA1 算法对接收到的 `secret` 进行哈希计算。
4. **哈希期望值:** 使用 SHA1 算法对硬编码的字符串 "knock-knock" 进行哈希计算。
5. **安全比较:** 使用 `crypto.timingSafeEqual` 函数比较两个哈希值。`timingSafeEqual` 可以防止时序攻击。如果哈希值不匹配，抛出 "Get outta here" 错误。
6. **返回用户信息:** 如果身份验证成功，返回一个包含 `nick` 的对象，例如 `{ nick: "testuser" }`。

**假设输出:**

* **成功:**  对于输入 `{"nick": "testuser", "secret": "knock-knock"}`, 输出将是 `{ nick: "testuser" }`。
* **失败 (密码错误):** 对于输入 `{"nick": "testuser", "secret": "wrongpassword"}`, 将抛出错误 "Get outta here"。
* **失败 (无效 Token):** 对于输入 `"invalid json"`, 将抛出错误 "Invalid token"。
* **失败 (缺少字段):** 对于输入 `{"nick": "testuser"}`, 将抛出错误 "Invalid token"。

**用户或编程常见的使用错误及举例**

* **Controller 身份验证失败:** 用户在连接 Controller 时，提供的 Token 中的 `secret` 值不是 "knock-knock"。
    * **错误信息:** 服务器会抛出 "Get outta here" 错误，Controller 连接会被拒绝。
    * **用户操作:** 用户需要确保在 Controller 端配置正确的 Token ( `{"nick": "your_nickname", "secret": "knock-knock"}`).
* **提供的 Token 格式不正确:**  用户提供的 Token 不是有效的 JSON 字符串，或者缺少必要的 `nick` 或 `secret` 字段。
    * **错误信息:** 服务器会抛出 "Invalid token" 错误，Controller 连接会被拒绝。
    * **用户操作:** 用户需要检查 Controller 端发送的 Token 格式是否正确，是否包含了 `nick` 和 `secret` 字段，并且是有效的 JSON。
* **尝试使用已被占用的昵称:**  当多个 Controller 连接时，如果后连接的用户尝试使用已被其他用户使用的昵称，服务器会自动分配一个新的昵称。
    * **现象:**  用户可能发现自己的昵称后面被添加了数字，例如 "testuser" 变成了 "testuser2"。
    * **用户操作:**  这通常不是一个错误，而是服务器的昵称管理机制。用户可以通过查看服务器的日志或 Controller 收到的消息来了解自己的最终昵称。
* **忘记启动 Frida Agent (Node):**  在尝试使用 Controller 连接之前，没有在目标设备上启动并连接 Frida Agent。
    * **现象:**  Controller 可以成功连接到 Portal 服务器，但是无法对目标设备进行任何操作，因为没有连接的 Agent。
    * **用户操作:**  需要在目标设备上启动 Frida Agent，并确保其配置指向正确的 Portal 服务器地址 (在 `clusterParams` 中配置)。
* **Portal 服务器地址配置错误:** Controller 或 Agent 配置的 Portal 服务器地址与实际运行的服务器地址不一致。
    * **现象:** Controller 或 Agent 无法连接到 Portal 服务器。
    * **用户操作:** 检查 Controller 和 Agent 的配置，确保 Portal 服务器的地址（IP 地址、端口、Unix Socket 路径）是正确的。

**用户操作是如何一步步的到达这里，作为调试线索**

假设一个用户想要使用这个 Portal 服务器进行 Android 应用程序的逆向：

1. **安装 Frida 和 frida-node:** 用户需要在他们的开发机器上安装 Frida 和 frida-node。
2. **下载或创建 `portal_server.js` 文件:** 用户可能从 Frida 的示例代码中获取了这个文件，或者自己创建了这个文件。
3. **配置 Portal 服务器:** 用户可能会根据自己的环境修改 `portal_server.js` 文件中的配置，例如 `clusterParams` 中的 Unix Socket 路径，或者 `controlParams` 中的端口。
4. **启动 Portal 服务器:** 用户在终端中导航到包含 `portal_server.js` 的目录，并执行 `node portal_server.js` 命令来启动服务器。这时，代码开始执行，创建 `Application` 实例，并启动 `PortalService`。
5. **启动 Frida Agent (Node):** 用户需要在他们的 Android 设备上部署并运行 Frida Agent。这个 Agent 需要配置连接到 Portal 服务器的 `clusterParams` 中指定的地址。Agent 启动后，会尝试连接到 Portal 服务器，触发 `_onNodeConnected` 和 `_onNodeJoined` 等事件。
6. **启动 Controller (例如 Web 客户端):** 用户运行一个实现了 Frida Portal 协议的客户端，例如一个基于浏览器的 Web 客户端。
7. **配置 Controller 连接参数:** 用户在 Web 客户端中配置 Portal 服务器的地址 (在 `controlParams` 中配置) 和身份验证 Token (例如 `{"nick": "myclient", "secret": "knock-knock"}`).
8. **Controller 连接:** Web 客户端尝试连接到 Portal 服务器，触发 `_onControllerConnected` 事件。
9. **Controller 身份验证:** Web 客户端发送身份验证 Token，Portal 服务器执行 `_authenticate` 函数进行验证，成功后触发 `_onAuthenticated` 事件。
10. **订阅消息:** Controller 可能会订阅服务器的消息，触发 `_onSubscribe` 事件。
11. **发送命令和接收消息:** 用户通过 Web 客户端发送各种命令（例如，列出进程、hook 函数），这些命令会通过 Portal 服务器路由到连接的 Frida Agent，并接收来自 Agent 或服务器的消息，例如 Instrumentation 的结果或聊天消息，触发 `_onMessage` 事件。
12. **命令行交互 (服务器端):** 用户可能在运行 `portal_server.js` 的终端中输入命令，例如直接输入回车查看当前连接的进程列表，或者输入 `stop` 命令来停止服务器。

**调试线索:**

* **服务器启动日志:** 查看 `node portal_server.js` 启动后在终端输出的日志信息，可以了解服务器是否成功启动，监听的端口和地址是什么。
* **Node 连接日志 (`_onNodeConnected`, `_onNodeJoined`):**  如果 Android 设备上的 Frida Agent 成功连接，服务器的日志会显示相应的连接和加入信息。
* **Controller 连接和认证日志 (`_onControllerConnected`, `_onAuthenticated`):** 检查日志可以确认 Controller 是否成功连接并完成身份验证。
* **错误日志:** 如果出现连接或身份验证错误，服务器的日志可能会输出错误信息，例如 "Get outta here" 或 "Invalid token"。
* **消息传递日志 (`_onMessage`):**  查看 `_onMessage` 函数的日志可以了解 Controller 发送了哪些消息，以及服务器如何处理这些消息。
* **网络连接:** 使用 `netstat` 或类似的工具检查服务器监听的端口，以及 Node 和 Controller 是否建立了网络连接。
* **代码断点:**  在 `portal_server.js` 中设置断点，使用 Node.js 的调试工具（例如 `node inspect portal_server.js` 或 Chrome DevTools）可以逐步执行代码，查看变量的值，理解代码的执行流程。

希望以上详细的分析能够帮助你理解 `portal_server.js` 文件的功能、与逆向工程的关系以及涉及的底层知识。

### 提示词
```
这是目录为frida/subprojects/frida-node/examples/portal_server.js的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```javascript
const crypto = require('crypto');
const frida = require('..');
const readline = require('readline');

const ENABLE_CONTROL_INTERFACE = true;

class Application {
  constructor() {
    const clusterParams = new frida.EndpointParameters({
      address: 'unix:/Users/oleavr/src/cluster',
      certificate: '/Users/oleavr/src/identity2.pem',
      authentication: {
        scheme: 'token',
        token: 'wow-such-secret'
      },
    });

    let controlParams = null;
    if (ENABLE_CONTROL_INTERFACE) {
      controlParams = new frida.EndpointParameters({
        address: '::1',
        port: 27042,
        authentication: {
          scheme: 'callback',
          callback: this._authenticate
        },
        assetRoot: '/Users/oleavr/src/frida/frida-python/examples/web_client/dist'
      });
    }

    const service = new frida.PortalService({ clusterParams, controlParams });
    this._service = service;
    this._device = service.device;
    this._peers = new Map();
    this._nicks = new Set();
    this._channels = new Map();

    service.nodeConnected.connect(this._onNodeConnected);
    service.nodeJoined.connect(this._onNodeJoined);
    service.nodeLeft.connect(this._onNodeLeft);
    service.nodeDisconnected.connect(this._onNodeDisconnected);

    service.controllerConnected.connect(this._onControllerConnected);
    service.controllerDisconnected.connect(this._onControllerDisconnected);

    service.authenticated.connect(this._onAuthenticated);
    service.subscribe.connect(this._onSubscribe);
    service.message.connect(this._onMessage);
  }

  async run() {
    await this._service.start();
    console.log('Started!');

    await this._device.enableSpawnGating();
    console.log('Enabled spawn gating');

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true
    });
    rl.on('close', () => {
      this._service.stop();
    });
    rl.on('line', async command => {
      try {
        if (command.length === 0) {
          console.log('Processes:', await this._device.enumerateProcesses());
          return;
        }

        if (command === 'stop') {
          await this._service.stop();
        }
      } catch (e) {
        console.error(e);
      } finally {
        this._showPrompt();
      }
    });
    this._showPrompt();
  }

  _showPrompt() {
    process.stdout.write('Enter command: ');
  }

  _authenticate = async rawToken => {
    let nick, secret;
    try {
      const token = JSON.parse(rawToken);
      ({ nick, secret } = token);
    } catch (e) {
      throw new Error('Invalid token');
    }
    if (typeof nick !== 'string' || typeof secret !== 'string')
      throw new Error('Invalid token');

    const provided = crypto.createHash('sha1').update(secret).digest();
    const expected = crypto.createHash('sha1').update('knock-knock').digest();
    if (!crypto.timingSafeEqual(provided, expected))
      throw new Error('Get outta here');

    return { nick };
  };

  _onNodeConnected = (connectionId, remoteAddress) => {
    console.log('onNodeConnected()', connectionId, remoteAddress);
  };

  _onNodeJoined = async (connectionId, application) => {
    console.log('onNodeJoined()', connectionId, application);
    console.log('\ttags:', await this._service.enumerateTags(connectionId));
  };

  _onNodeLeft = (connectionId, application) => {
    console.log('onNodeLeft()', connectionId, application);
  };

  _onNodeDisconnected = (connectionId, remoteAddress) => {
    console.log('onNodeDisconnected()', connectionId, remoteAddress);
  };

  _onControllerConnected = (connectionId, remoteAddress) => {
    console.log('onControllerConnected()', connectionId, remoteAddress);

    this._peers.set(connectionId, new Peer(connectionId, remoteAddress));
  };

  _onControllerDisconnected = (connectionId, remoteAddress) => {
    console.log('onControllerDisconnected()', connectionId, remoteAddress);

    const peer = this._peers.get(connectionId);
    this._peers.delete(connectionId);

    for (const channel of peer.memberships)
      channel.removeMember(peer);

    if (peer.nick !== null)
      this._releaseNick(peer.nick);
  };

  _onAuthenticated = (connectionId, sessionInfo) => {
    console.log('onAuthenticated()', connectionId, sessionInfo);

    const peer = this._peers.get(connectionId);
    if (peer === undefined)
      return;

    peer.nick = this._acquireNick(sessionInfo.nick);
  };

  _onSubscribe = connectionId => {
    console.log('onSubscribe()', connectionId);

    this._service.post(connectionId, {
      type: 'welcome',
      channels: Array.from(this._channels.keys())
    });
  };

  _onMessage = (connectionId, message, data) => {
    const peer = this._peers.get(connectionId);

    switch (message.type) {
      case 'join': {
        this._getChannel(message.channel).addMember(peer);

        break;
      }
      case 'part': {
        const channel = this._channels.get(message.channel);
        if (channel === undefined)
          return;

        channel.removeMember(peer);

        break;
      }
      case 'say': {
        const channel = this._channels.get(message.channel);
        if (channel === undefined)
          return;

        channel.post(message.text, peer);

        break;
      }
      case 'announce': {
        this._service.broadcast({
          type: 'announce',
          sender: peer.nick,
          text: message.text
        });

        break;
      }
      default: {
        console.error('Unhandled message:', message);

        break;
      }
    }
  };

  _acquireNick(requested) {
    let candidate = requested;
    let serial = 2;
    while (this._nicks.has(candidate)) {
      candidate = requested + serial;
      serial++;
    }

    const nick = candidate;
    this._nicks.add(nick);

    return nick;
  }

  _releaseNick(nick) {
    this._nicks.delete(nick);
  }

  _getChannel(name) {
    let channel = this._channels.get(name);
    if (channel === undefined) {
      channel = new Channel(name, this._service);
      this._channels.set(name, channel);
    }
    return channel;
  }
}

class Peer {
  constructor(connectionId, remoteAddress) {
    this.nick = null;
    this.connectionId = connectionId;
    this.remoteAddress = remoteAddress;
    this.memberships = new Set();
  }

  toJSON() {
    return {
      nick: this.nick,
      address: this.remoteAddress.address
    };
  }
}

class Channel {
  constructor(name, service) {
    this.name = name;
    this.members = new Set();
    this.history = [];

    this._service = service;
  }

  addMember(peer) {
    if (peer.memberships.has(this))
      return;

    peer.memberships.add(this);
    this.members.add(peer);

    this._service.narrowcast(this.name, {
      type: 'join',
      channel: this.name,
      user: peer
    });
    this._service.tag(peer.connectionId, this.name);

    this._service.post(peer.connectionId, {
      type: 'membership',
      channel: this.name,
      members: Array.from(this.members),
      history: this.history
    });
  }

  removeMember(peer) {
    if (!peer.memberships.has(this))
      return;

    peer.memberships.delete(this);
    this.members.delete(peer);

    this._service.untag(peer.connectionId, this.name);
    this._service.narrowcast(this.name, {
      type: 'part',
      channel: this.name,
      user: peer
    });
  }

  post(text, peer) {
    if (!peer.memberships.has(this))
      return;

    const item = {
      type: 'chat',
      sender: peer.nick,
      text: text
    };

    this._service.narrowcast(this.name, item);

    const { history } = this;
    history.push(item);
    if (history.length === 20)
      history.shift();
  }
}

const app = new Application();
app.run()
  .catch(e => {
    console.error(e);
  });
```