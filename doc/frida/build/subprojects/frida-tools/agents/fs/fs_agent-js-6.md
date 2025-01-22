Response:
Let's break down the thought process for analyzing the provided JavaScript code snippet and generating the comprehensive response.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a Frida agent file (`fs_agent.js`), focusing on its functionality, potential interactions with the OS (kernel, etc.), and how to replicate its debugging features using LLDB. The request also specifies a "part 7 of 12" constraint, which means the provided code is likely a segment of a larger file and the analysis should focus on *this* part.

**2. Code Inspection - First Pass (High-Level):**

My first scan of the code immediately identifies several key patterns and features:

* **Imports:**  It imports modules like `events`, `buffer`, `process`, and potentially custom modules from relative paths. This suggests it's operating within a Node.js-like environment.
* **`NodeEventTarget` Class:**  This class implements event handling with methods like `addEventListener`, `removeEventListener`, `emit`, `on`, `off`, etc. This strongly hints at an event-driven architecture.
* **`EventEmitterMixin`:** This looks like a mixin function that adds EventEmitter capabilities to a class.
* **`defineEventHandler`:**  This function appears to dynamically define event handler properties (e.g., `on<EventName>`).
* **Error Handling:** There are instances of throwing errors, indicating a focus on robustness.
* **`nextTick`:** The use of `process.nextTick` suggests asynchronous operations and event loop management.

**3. Code Inspection - Deeper Dive (Functionality):**

I then go through the code more systematically, analyzing the purpose of each function and class:

* **`NodeEventTarget`:**  Clearly provides the basic structure for something that emits and listens to events. The checks `if(!j(this))` imply a type check related to event targets.
* **`isEventTarget` and `j`:** These are helper functions to check if an object is a valid `NodeEventTarget`.
* **`_` and `B`:** These functions seem related to handling promises, specifically catching rejections and throwing them asynchronously using `nextTick`.
* **`defineEventHandler`:**  This is interesting. It dynamically creates `on<Event>` properties that are linked to the underlying event listener mechanism. The logic for adding and removing listeners within the setter is important.
* **`EventEmitterMixin`:** This makes it easy to extend other classes with EventEmitter functionality.

**4. Identifying Potential OS/Kernel Interactions:**

Based *only* on this code snippet, direct interaction with the Linux kernel or binary level is *unlikely*. The core functionality revolves around event handling and asynchronous operations within a JavaScript environment. There are no direct system calls or low-level memory manipulations visible.

* **Hypothetical Scenarios (based on file path):**  The file path `frida/build/subprojects/frida-tools/agents/fs/fs_agent.js` strongly suggests that this agent is related to *filesystem* operations within Frida. While *this specific snippet* doesn't show direct filesystem interaction, the larger context implies it's likely handling events *related* to filesystem activity. This is crucial for the "user operation" and "debugging clues" parts of the response.

**5. LLDB Replication (Focusing on Debugging Functionality):**

Since this snippet primarily deals with event handling, replicating its *direct* functionality in LLDB would be less relevant. Instead, I focus on how an LLDB user could *observe* the events being emitted and handled.

* **Breakpoints on `emit`:**  Setting a breakpoint on the `emit` method of a `NodeEventTarget` instance would allow observation of which events are being triggered and with what data.
* **Inspecting Listener Maps:**  LLDB scripting could be used to inspect the internal `kEvents` map of a `NodeEventTarget` instance to see which listeners are registered for which events.
* **Tracing Execution:**  Basic LLDB stepping and `next` commands would help follow the flow of execution when an event is emitted and handled.

**6. User Errors and Usage:**

I think about common mistakes developers make when working with event emitters:

* **Forgetting to add listeners:** An event might be emitted, but nothing happens if no one is listening.
* **Incorrect event names:** Typos in event names will prevent listeners from being triggered.
* **Incorrect listener function signatures:** If the listener expects certain arguments and the emitter provides different ones, the listener might not work as expected.
* **Memory leaks (unremoved listeners):** Forgetting to remove listeners (using `off` or `removeListener`) can lead to memory leaks, especially for long-lived objects.

**7. User Operation and Debugging Clues:**

This is where I connect the code snippet to its likely context (filesystem monitoring). I construct a scenario where a user is using Frida to monitor filesystem events:

* **User attaches Frida to a process.**
* **The Frida script loads the `fs_agent.js`.**
* **The agent likely intercepts filesystem calls (this is the *implicit* part not shown in the snippet).**
* **When a filesystem event occurs (e.g., file creation, deletion), the agent's intercepted code calls `emit` on a `NodeEventTarget` instance.**

The debugging clues would then involve:

* **Seeing the `emit` call in the LLDB trace.**
* **Inspecting the event name and data passed to `emit`.**
* **Checking which listeners are registered for that event.**
* **Stepping through the listener function to understand its behavior.**

**8. Logical Reasoning and Assumptions:**

Throughout the analysis, I make certain assumptions based on common JavaScript patterns and the file's location:

* **Node.js environment:**  The use of `process`, `Buffer`, and `require`-like imports strongly suggests a Node.js-like environment.
* **Frida's instrumentation capabilities:** I assume Frida is being used to intercept and hook into system or library calls, even though this specific code snippet doesn't show that.
* **Event-driven architecture:** The prevalence of event-related code points to an event-driven design.

**9. Structuring the Response:**

Finally, I organize the information into the requested categories:

* **Functionality Summary:**  A concise overview of what the code does.
* **OS/Kernel/Binary Interaction:**  Addressing this point directly, explaining that direct interaction isn't visible in *this snippet* but inferring likely higher-level interactions.
* **LLDB Replication:**  Providing practical LLDB commands and scripting examples for observing event handling.
* **Assumptions and Outputs:**  Illustrating the event flow with a simple example.
* **User Errors:** Listing common mistakes.
* **User Operation and Debugging:**  Constructing a scenario and outlining debugging steps.
* **Part 7 Summary:**  A brief recap of the functionality covered in *this specific snippet*.

**Self-Correction/Refinement:**

During the process, I might realize certain things:

* **Initial focus too narrow:** I might initially focus too much on the low-level details of `NodeEventTarget` and miss the broader context of its role in a Frida agent.
* **Need to infer context:** The file path is a critical clue for understanding the agent's purpose.
* **LLDB replication needs to be practical:** Simply saying "set a breakpoint" isn't very helpful. Providing concrete examples of commands or scripting is better.

By following this systematic thought process, combining code analysis with contextual understanding and practical debugging considerations, I can generate a comprehensive and accurate response to the request.好的，让我们来分析一下 `fs_agent.js` 代码片段的功能，并结合你提出的要求进行详细说明。

**功能归纳 (针对提供的代码片段):**

这段代码片段主要实现了 **自定义的事件发射器 (Event Emitter)** 功能，命名为 `NodeEventTarget`，并提供了一个用于将此事件发射器功能混入其他类的 `EventEmitterMixin`。 此外，它还提供了一个 `defineEventHandler` 函数，用于更方便地为一个对象动态地定义事件处理属性（例如，`on<eventName>`）。

**具体功能点：**

1. **`NodeEventTarget` 类:**
   - 实现了基本的事件监听和发射机制。
   - 提供了 `addEventListener`、`removeEventListener`、`on`、`off`、`addListener`、`once`、`emit` 和 `removeAllListeners` 等方法，用于注册、移除和触发事件。
   - 使用内部的 `kEvents` Map 来存储事件及其对应的监听器。
   - 实现了对 `once` 事件的支持，即监听器在触发一次后自动移除。
   - 提供了 `listenerCount` 方法来获取特定事件的监听器数量。
   - 提供了 `eventNames` 方法来获取所有已注册的事件名称。
   - 进行了类型检查，确保只有 `NodeEventTarget` 的实例才能调用这些方法。

2. **`isEventTarget(e)` 函数:**
   - 检查给定的对象 `e` 是否是 `NodeEventTarget` 的实例。

3. **`j(e)` 函数:**
   -  功能与 `isEventTarget` 类似，也用于检查对象是否为 `NodeEventTarget` 的实例，可能是为了代码内部的简洁性。

4. **`_(e)` 函数:**
   - 接收一个 Promise 对象 `e`。
   - 如果 Promise 成功 resolve，则不做任何操作（传递 `void 0` 给 `then`）。
   - 如果 Promise 失败 reject，则调用 `B(e)` 函数处理 rejected 的错误。

5. **`B(e)` 函数:**
   - 接收一个错误对象 `e`。
   - 使用 `n.nextTick` 将抛出错误的操作延迟到下一个事件循环。
   - 实际上是将错误异步地抛出，防止阻塞当前执行流程。

6. **`defineEventHandler(e, t)` 函数:**
   - 接收一个对象 `e` 和一个事件名称 `t`。
   - 在对象 `e` 上动态定义一个属性 `on${t}` (例如，如果 `t` 是 "data"，则定义属性 `onData`)。
   - 该属性的 `get` 访问器返回当前注册的该事件的处理器函数。
   - 该属性的 `set` 访问器允许设置新的事件处理器函数。
   - 在设置新的处理器时，会处理旧的处理器（如果存在），并更新内部的事件监听器管理。
   - 这提供了一种更符合直观的 `on<EventName> = function() {}` 语法来设置事件监听器。

7. **`EventEmitterMixin` 函数:**
   - 这是一个高阶函数，接收一个类 `e` 作为参数。
   - 它创建了一个新的类 `n`，该类继承自传入的类 `e`。
   - 在 `n` 的构造函数中，调用了 `t.call(this)`，这里的 `t` 实际上是指向 `NodeEventTarget` 构造函数的引用。
   - 它将 `NodeEventTarget.prototype` 上的所有属性（除了 `constructor`）复制到新类 `n` 的原型上。
   - 最终返回新创建的类 `n`，从而实现了将 `NodeEventTarget` 的事件发射功能混入到其他类的目的。

**是否涉及到二进制底层，Linux 内核？**

这段代码片段本身 **没有直接涉及到二进制底层或 Linux 内核**。 它完全是在 JavaScript 运行时环境中运行的，专注于实现事件处理逻辑。

**举例说明 (如果涉及到二进制底层，Linux 内核):**

由于此代码片段未直接涉及，我们假设整个 `fs_agent.js` 的 **其他部分** 可能会与底层交互。 例如：

- **二进制底层:** 如果 `fs_agent.js` 的某些部分需要解析或生成特定的二进制数据结构来与底层系统交互（例如，读取文件元数据），那么会涉及到 `Buffer` 对象的处理和二进制数据的操作。
- **Linux 内核:**  更常见的场景是，`fs_agent.js` 通过 Frida 框架提供的 API 来 **hook (拦截)** 系统调用，例如 `open`、`read`、`write` 等与文件系统相关的系统调用。Frida 允许在这些系统调用发生时执行 JavaScript 代码。在这种情况下，虽然这段代码本身不直接操作内核，但它是 **基于 Frida 框架对内核系统调用的拦截之上** 工作的。

**用 LLDB 指令或者 LLDB Python 脚本复刻调试功能的示例 (如果源代码是调试功能的实现):**

这段代码片段本身 **是事件处理功能的实现，而不是直接的调试功能的实现**。 然而，我们可以使用 LLDB 来观察和调试使用了这个事件处理机制的代码。

假设在 `fs_agent.js` 的其他部分，当文件被创建时会触发一个名为 `fileCreated` 的事件，并传递文件名作为参数。我们可以用 LLDB 来观察这个过程：

**LLDB 指令示例:**

1. **在 `NodeEventTarget.prototype.emit` 方法处设置断点:**
   ```lldb
   br set -s "frida-tools" -n "NodeEventTarget.prototype.emit"
   ```
   这将会在任何 `NodeEventTarget` 实例调用 `emit` 方法时暂停执行。

2. **继续执行，直到断点命中:**
   ```lldb
   continue
   ```

3. **当断点命中时，查看 `this` 指针 (即 `NodeEventTarget` 实例) 和传递的参数 (事件名称和数据):**
   ```lldb
   po self  // 或者 po $arg1，取决于 LLDB 版本和配置
   po $arg2 // 事件名称
   po $arg3 // 传递的数据 (例如文件名)
   ```
   通过查看 `$arg2` 的值，我们可以知道触发了哪个事件（例如，"fileCreated"）。通过查看 `$arg3` 的值，我们可以获取传递的数据（例如，被创建的文件名）。

4. **查看监听器:** 可以通过 LLDB Python 脚本来更详细地查看 `kEvents` Map 中的监听器。

**LLDB Python 脚本示例:**

```python
def print_listeners(emitter):
    """Prints the listeners for each event in a NodeEventTarget."""
    kEvents = emitter.kEvents
    print(f"Listeners for emitter: {emitter}")
    for event_name, listeners in kEvents.items():
        print(f"  Event: {event_name}")
        for i, listener in enumerate(listeners):
            print(f"    [{i}] {listener}")

# 在 LLDB 中调用该脚本：
#(lldb) script
#>>> import lldb
#>>> def print_listeners(emitter):
#>>>     # ... (脚本内容)
#>>>
#>>> target = lldb.debugger.GetSelectedTarget()
#>>> process = target.GetProcess()
#>>> # 假设 'myEmitter' 是你想要检查的 NodeEventTarget 实例的 JavaScript 变量名
#>>> res = process.EvaluateExpression("myEmitter")
#>>> if res.IsValid() and res.GetValue() != "undefined":
#>>>     emitter_obj = res.GetObjectDescription()
#>>>     # 需要更复杂的方法来获取 JavaScript 对象的内部属性，这里只是一个概念
#>>>     # 可能需要使用 Frida 的 API 或更底层的调试技术
#>>>     print_listeners(emitter_obj)
#>>> else:
#>>>     print("Could not find the emitter object.")
#>>>
```

**假设输入与输出 (如果做了逻辑推理):**

**假设输入:**

```javascript
const emitter = new NodeEventTarget();

emitter.on('data', (data) => {
  console.log('Received data:', data);
});

emitter.emit('data', 'Hello from emitter!');
emitter.emit('data', 123);
```

**预期输出:**

```
Received data: Hello from emitter!
Received data: 123
```

**假设输入 (使用 `defineEventHandler`):**

```javascript
const myObject = {};
defineEventHandler(myObject, 'customEvent');

myObject.onCustomEvent = (data) => {
  console.log('Custom event received:', data);
};

const emitter = new NodeEventTarget();
emitter.on('customEvent', myObject.onCustomEvent);

emitter.emit('customEvent', { value: 'test' });
```

**预期输出:**

```
Custom event received: { value: 'test' }
```

**用户或编程常见的使用错误:**

1. **忘记添加事件监听器:**

   ```javascript
   const emitter = new NodeEventTarget();
   // 没有添加 'data' 事件的监听器
   emitter.emit('data', 'This will not be handled.');
   ```
   **结果:**  'data' 事件被触发，但没有任何代码会执行来处理它。

2. **事件名称拼写错误:**

   ```javascript
   const emitter = new NodeEventTarget();
   emitter.on('dat', (data) => { // 'data' 拼写错误
     console.log('Received data:', data);
   });
   emitter.emit('data', 'Oops!');
   ```
   **结果:**  `emit('data', ...)` 触发的事件名称与监听器注册的事件名称不匹配，监听器不会被调用。

3. **错误的监听器函数签名:**

   ```javascript
   const emitter = new NodeEventTarget();
   emitter.on('message', () => { // 监听器期望没有参数
     console.log('Received a message');
   });
   emitter.emit('message', 'Important information'); // 实际传递了参数
   ```
   **结果:**  监听器函数会执行，但它可能没有正确处理传递的参数，或者参数被忽略。

4. **忘记移除不再需要的监听器 (导致内存泄漏):**

   ```javascript
   const emitter = new NodeEventTarget();
   let counter = 0;
   const listener = (data) => {
     counter++;
     console.log('Counter:', counter);
   };
   emitter.on('tick', listener);

   // ... 一段时间后 ...

   // 假设我们不再需要监听 'tick' 事件了，但是忘记移除监听器
   // emitter.off('tick', listener);

   // 即使不再需要，监听器仍然会响应 'tick' 事件，可能导致资源浪费
   setInterval(() => emitter.emit('tick'), 1000);
   ```
   **结果:**  即使在逻辑上不再需要，监听器仍然存在并继续执行，可能导致内存占用不断增加。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户希望使用 Frida 对某个应用程序的文件系统操作进行动态分析。**
2. **Frida 脚本加载了 `fs_agent.js` 作为分析工具的一部分。**
3. **`fs_agent.js` (或其他相关模块) 可能会 hook (拦截) 应用程序的文件系统相关的 API 调用（例如，`open`、`read`、`write` 等）。**
4. **当应用程序执行文件系统操作时，被 hook 的函数会调用 `NodeEventTarget` 实例的 `emit` 方法，触发相应的事件。**
5. **在 `fs_agent.js` 中注册了这些事件的监听器，用于收集和报告文件系统操作的信息。**

**调试线索:**

- 如果用户发现某些文件系统操作没有被捕获到，可能需要检查 `fs_agent.js` 中是否正确地 hook 了相关的 API 调用，以及是否定义了正确的事件并正确地触发了它们。
- 如果用户观察到某些事件没有被处理，或者处理的方式不正确，可能需要检查是否正确地注册了事件监听器，以及监听器函数的逻辑是否正确。
- 使用 LLDB 可以在 `emit` 方法处设置断点，查看触发的事件名称和数据，以及检查是否存在对应的监听器。

**第 7 部分功能归纳:**

作为第 7 部分，这段代码片段的核心功能是提供了一个 **可复用的、基于类的事件发射器 (`NodeEventTarget`)**，以及一个方便地将事件发射器功能混入其他类的方法 (`EventEmitterMixin`)。它还提供了一种动态定义事件处理属性的机制 (`defineEventHandler`)。  这为构建更复杂的、基于事件驱动的 Frida 代理奠定了基础。后续的部分可能会使用这些基础组件来实现更具体的文件系统监控和分析功能。

Prompt: 
```
这是目录为frida/build/subprojects/frida-tools/agents/fs/fs_agent.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第7部分，共12部分，请归纳一下它的功能

"""
hrow new a("NodeEventTarget");return this.removeEventListener(e,t,n),this}on(e,t){if(!j(this))throw new a("NodeEventTarget");return this.addEventListener(e,t,{[g]:!0}),this}addListener(e,t){if(!j(this))throw new a("NodeEventTarget");return this.addEventListener(e,t,{[g]:!0}),this}emit(e,t){if(!j(this))throw new a("NodeEventTarget");const n=this.listenerCount(e)>0;return this[E](t,e),n}once(e,t){if(!j(this))throw new a("NodeEventTarget");return this.addEventListener(e,t,{once:!0,[g]:!0}),this}removeAllListeners(e){if(!j(this))throw new a("NodeEventTarget");return void 0!==e?this[kEvents].delete(String(e)):this[kEvents].clear(),this}}function z(e){if("function"==typeof e||"function"==typeof e?.handleEvent)return!0;if(null==e)return!1;throw new r("listener","EventListener",e)}Object.defineProperties(NodeEventTarget.prototype,{setMaxListeners:P,getMaxListeners:P,eventNames:P,listenerCount:P,off:P,removeListener:P,on:P,addListener:P,once:P,emit:P,removeAllListeners:P});export function isEventTarget(e){return e?.constructor?.[h]}function j(e){return e?.constructor?.[l]}function _(e){const t=e.then;"function"==typeof t&&t.call(e,void 0,(function(e){B(e)}))}function B(e){n.nextTick((()=>{throw e}))}export function defineEventHandler(e,t){Object.defineProperty(e,`on${t}`,{get(){return this[p]?.get(t)?.handler},set(e){this[p]||(this[p]=new Map);let n=this[p]?.get(t);if(n){if("function"==typeof n.handler){this[kEvents].get(t).size--;const e=this[kEvents].get(t).size;this[kRemoveListener](e,t,n.handler,!1)}if(n.handler=e,"function"==typeof n.handler){this[kEvents].get(t).size++;const n=this[kEvents].get(t).size;this[kNewListener](n,t,e,!1,!1,!1)}}else n=function(e){function t(...e){if("function"==typeof t.handler)return Reflect.apply(t.handler,this,e)}return t.handler=e,t}(e),this.addEventListener(t,n);this[p].set(t,n)},configurable:!0,enumerable:!0})}export const EventEmitterMixin=e=>{class n extends e{constructor(...e){super(...e),t.call(this)}}const i=Object.getOwnPropertyDescriptors(t.prototype);return delete i.constructor,Object.defineProperties(n.prototype,i),n};
✄
{"version":3,"file":"from.js","names":["errorCodes","Buffer","process","ERR_INVALID_ARG_TYPE","ERR_STREAM_NULL_VALUES","from","Readable","iterable","opts","iterator","isAsync","objectMode","read","this","push","Symbol","asyncIterator","readable","highWaterMark","reading","_read","async","value","done","next","res","then","err","destroy","_destroy","error","cb","hadError","hasThrow","throw","return","close","nextTick","e"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"gBAAkBA,MAAkB,gCAE3BC,MAAc,gBAChBC,MAAa,UAEpB,MAAMC,qBACJA,EAAoBC,uBACpBA,GACEJ,iBAEW,SAASK,EAAKC,EAAUC,EAAUC,GAC/C,IAAIC,EAYAC,EAXJ,GAAwB,iBAAbH,GAAyBA,aAAoBN,EACtD,OAAO,IAAIK,EAAS,CAClBK,YAAY,KACTH,EACHI,OACEC,KAAKC,KAAKP,GACVM,KAAKC,KAAK,KACZ,IAKJ,GAAIP,GAAYA,EAASQ,OAAOC,eAC9BN,GAAU,EACVD,EAAWF,EAASQ,OAAOC,qBACtB,KAAIT,IAAYA,EAASQ,OAAON,UAIrC,MAAM,IAAIN,EAAqB,WAAY,CAAC,YAAaI,GAHzDG,GAAU,EACVD,EAAWF,EAASQ,OAAON,WAG7B,CAEA,MAAMQ,EAAW,IAAIX,EAAS,CAC5BK,YAAY,EACZO,cAAe,KAEZV,IAKL,IAAIW,GAAU,EA6Dd,OA3DAF,EAASG,MAAQ,WACVD,IACHA,GAAU,EA4BdE,iBACE,OAAS,CACP,IACE,MAAMC,MAAEA,EAAKC,KAAEA,GAASb,QAChBD,EAASe,OACff,EAASe,OAEX,GAAID,EACFN,EAASH,KAAK,UACT,CACL,MAAMW,EAAOH,GACW,mBAAfA,EAAMI,WACPJ,EACNA,EACF,GAAY,OAARG,EAEF,MADAN,GAAU,EACJ,IAAIf,EACL,GAAIa,EAASH,KAAKW,GACvB,SAEAN,GAAU,CAEd,CAGF,CAFE,MAAOQ,GACPV,EAASW,QAAQD,EACnB,CACA,KACF,CACF,CAvDIH,GAEJ,EAEAP,EAASY,SAAW,SAASC,EAAOC,IAOpCV,eAAqBS,GACnB,MAAME,EAAW,MAACF,EACZG,EAAqC,mBAAnBxB,EAASyB,MACjC,GAAIF,GAAYC,EAAU,CACxB,MAAMX,MAAEA,EAAKC,KAAEA,SAAed,EAASyB,MAAMJ,GAE7C,SADMR,EACFC,EACF,MAEJ,CACA,GAA+B,mBAApBd,EAAS0B,OAAuB,CACzC,MAAMb,MAAEA,SAAgBb,EAAS0B,eAC3Bb,CACR,CACF,EApBEc,CAAMN,GAAOJ,MACX,IAAMxB,EAAQmC,SAASN,EAAID,KAC1BQ,GAAMpC,EAAQmC,SAASN,EAAIO,GAAKR,IAErC,EA+COb,CACT"}
✄
import{codes as t}from"../errors.js";import{Buffer as e}from"buffer";import n from"process";const{ERR_INVALID_ARG_TYPE:o,ERR_STREAM_NULL_VALUES:r}=t;export default function i(t,i,a){let c,f;if("string"==typeof i||i instanceof e)return new t({objectMode:!0,...a,read(){this.push(i),this.push(null)}});if(i&&i[Symbol.asyncIterator])f=!0,c=i[Symbol.asyncIterator]();else{if(!i||!i[Symbol.iterator])throw new o("iterable",["Iterable"],i);f=!1,c=i[Symbol.iterator]()}const s=new t({objectMode:!0,highWaterMark:1,...a});let u=!1;return s._read=function(){u||(u=!0,async function(){for(;;){try{const{value:t,done:e}=f?await c.next():c.next();if(e)s.push(null);else{const e=t&&"function"==typeof t.then?await t:t;if(null===e)throw u=!1,new r;if(s.push(e))continue;u=!1}}catch(t){s.destroy(t)}break}}())},s._destroy=function(t,e){(async function(t){const e=null!=t,n="function"==typeof c.throw;if(e&&n){const{value:e,done:n}=await c.throw(t);if(await e,n)return}if("function"==typeof c.return){const{value:t}=await c.return();await t}})(t).then((()=>n.nextTick(e,t)),(o=>n.nextTick(e,o||t)))},s}
✄
{"version":3,"file":"legacy.js","names":["EE","Stream","opts","call","this","Object","setPrototypeOf","prototype","pipe","dest","options","source","ondata","chunk","writable","write","pause","ondrain","readable","resume","on","_isStdio","end","onend","onclose","didOnEnd","destroy","onerror","er","cleanup","listenerCount","emit","removeListener","prependListener","emitter","event","fn","_events","Array","isArray","unshift"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"OAAOA,MAAQ,gBAER,SAASC,OAAOC,GACrBF,EAAGG,KAAKC,KAAMF,EAChB,CACAG,OAAOC,eAAeL,OAAOM,UAAWP,EAAGO,WAC3CF,OAAOC,eAAeL,OAAQD,GAE9BC,OAAOM,UAAUC,KAAO,SAASC,EAAMC,GACrC,MAAMC,EAASP,KAEf,SAASQ,EAAOC,GACVJ,EAAKK,WAAkC,IAAtBL,EAAKM,MAAMF,IAAoBF,EAAOK,OACzDL,EAAOK,OAEX,CAIA,SAASC,IACHN,EAAOO,UAAYP,EAAOQ,QAC5BR,EAAOQ,QAEX,CANAR,EAAOS,GAAG,OAAQR,GAQlBH,EAAKW,GAAG,QAASH,GAIZR,EAAKY,UAAcX,IAA2B,IAAhBA,EAAQY,MACzCX,EAAOS,GAAG,MAAOG,GACjBZ,EAAOS,GAAG,QAASI,IAGrB,IAAIC,GAAW,EACf,SAASF,IACHE,IACJA,GAAW,EAEXhB,EAAKa,MACP,CAGA,SAASE,IACHC,IACJA,GAAW,EAEiB,mBAAjBhB,EAAKiB,SAAwBjB,EAAKiB,UAC/C,CAGA,SAASC,EAAQC,GACfC,IACwC,IAApC7B,EAAG8B,cAAc1B,KAAM,UACzBA,KAAK2B,KAAK,QAASH,EAEvB,CAMA,SAASC,IACPlB,EAAOqB,eAAe,OAAQpB,GAC9BH,EAAKuB,eAAe,QAASf,GAE7BN,EAAOqB,eAAe,MAAOT,GAC7BZ,EAAOqB,eAAe,QAASR,GAE/Bb,EAAOqB,eAAe,QAASL,GAC/BlB,EAAKuB,eAAe,QAASL,GAE7BhB,EAAOqB,eAAe,MAAOH,GAC7BlB,EAAOqB,eAAe,QAASH,GAE/BpB,EAAKuB,eAAe,QAASH,EAC/B,CASA,OA3BAI,gBAAgBtB,EAAQ,QAASgB,GACjCM,gBAAgBxB,EAAM,QAASkB,GAmB/BhB,EAAOS,GAAG,MAAOS,GACjBlB,EAAOS,GAAG,QAASS,GAEnBpB,EAAKW,GAAG,QAASS,GACjBpB,EAAKsB,KAAK,OAAQpB,GAGXF,CACT,SAEO,SAASwB,gBAAgBC,EAASC,EAAOC,GAG9C,GAAuC,mBAA5BF,EAAQD,gBACjB,OAAOC,EAAQD,gBAAgBE,EAAOC,GAMnCF,EAAQG,SAAYH,EAAQG,QAAQF,GAEhCG,MAAMC,QAAQL,EAAQG,QAAQF,IACrCD,EAAQG,QAAQF,GAAOK,QAAQJ,GAE/BF,EAAQG,QAAQF,GAAS,CAACC,EAAIF,EAAQG,QAAQF,IAJ9CD,EAAQd,GAAGe,EAAOC,EAKtB"}
✄
import e from"events";export function Stream(r){e.call(this,r)}Object.setPrototypeOf(Stream.prototype,e.prototype),Object.setPrototypeOf(Stream,e),Stream.prototype.pipe=function(r,t){const n=this;function o(e){r.writable&&!1===r.write(e)&&n.pause&&n.pause()}function i(){n.readable&&n.resume&&n.resume()}n.on("data",o),r.on("drain",i),r._isStdio||t&&!1===t.end||(n.on("end",p),n.on("close",c));let s=!1;function p(){s||(s=!0,r.end())}function c(){s||(s=!0,"function"==typeof r.destroy&&r.destroy())}function d(r){m(),0===e.listenerCount(this,"error")&&this.emit("error",r)}function m(){n.removeListener("data",o),r.removeListener("drain",i),n.removeListener("end",p),n.removeListener("close",c),n.removeListener("error",d),r.removeListener("error",d),n.removeListener("end",m),n.removeListener("close",m),r.removeListener("close",m)}return prependListener(n,"error",d),prependListener(r,"error",d),n.on("end",m),n.on("close",m),r.on("close",m),r.emit("pipe",n),r};export function prependListener(e,r,t){if("function"==typeof e.prependListener)return e.prependListener(r,t);e._events&&e._events[r]?Array.isArray(e._events[r])?e._events[r].unshift(t):e._events[r]=[t,e._events[r]]:e.on(r,t)}
✄
{"version":3,"file":"once.js","names":["once","callback","called","args","Reflect","apply","this"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"eAqBe,SAASA,EAAKC,GAC3B,IAAIC,GAAS,EACb,OAAO,YAAYC,GACbD,IACJA,GAAS,EACTE,QAAQC,MAAMJ,EAAUK,KAAMH,GAChC,CACF"}
✄
export default function t(t){let e=!1;return function(...n){e||(e=!0,Reflect.apply(t,this,n))}}
✄
{"version":3,"file":"passthrough.js","names":["Transform","Object","setPrototypeOf","PassThrough","prototype","options","this","call","_transform","chunk","encoding","cb"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"OAyBOA,MAAe,iBACtBC,OAAOC,eAAeC,EAAYC,UAAWJ,EAAUI,WACvDH,OAAOC,eAAeC,EAAaH,kBAEpB,SAASG,EAAYE,GAClC,KAAMC,gBAAgBH,GACpB,OAAO,IAAIA,EAAYE,GAEzBL,EAAUO,KAAKD,KAAMD,EACvB,CAEAF,EAAYC,UAAUI,WAAa,SAASC,EAAOC,EAAUC,GAC3DA,EAAG,KAAMF,EACX"}
✄
import t from"./transform.js";Object.setPrototypeOf(o.prototype,t.prototype),Object.setPrototypeOf(o,t);export default function o(e){if(!(this instanceof o))return new o(e);t.call(this,e)}o.prototype._transform=function(t,o,e){e(null,t)};
✄
{"version":3,"file":"pipeline.js","names":["AbortController","destroyImpl","Duplex","eos","aggregateTwoErrors","errorCodes","AbortError","once","PassThrough","Readable","isIterable","isReadableNodeStream","isNodeStream","process","ERR_INVALID_ARG_TYPE","ERR_INVALID_RETURN_VALUE","ERR_MISSING_ARGS","ERR_STREAM_DESTROYED","destroyer","stream","reading","writing","callback","finished","on","readable","writable","err","rState","_readableState","code","ended","errored","errorEmitted","makeAsyncIterable","val","async","prototype","Symbol","asyncIterator","call","fromReadable","pump","iterable","finish","error","onresolve","resume","wait","Promise","resolve","reject","cleanup","writableNeedDrain","chunk","write","end","off","pipeline","streams","pop","popCallback","Array","isArray","length","pipelineImpl","opts","ac","signal","outerSignal","abort","finishImpl","value","addEventListener","destroys","ret","finishCount","final","shift","removeEventListener","i","push","from","pt","objectMode","then","destroy","pipe","stdout","stderr","aborted","nextTick"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"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"}
✄
import{AbortController as e}from"./abort_controller.js";import*as t from"./destroy.js";import r from"./duplex.js";import o from"./end-of-stream.js";import{aggregateTwoErrors as n,codes as i,AbortError as s}from"../errors.js";import a from"./once.js";import l from"./passthrough.js";import f from"./readable.js";import{isIterable as c,isReadableNodeStream as p,isNodeStream as d}from"./utils.js";import m from"process";const{ERR_INVALID_ARG_TYPE:u,ERR_INVALID_RETURN_VALUE:R,ERR_MISSING_ARGS:E,ERR_STREAM_DESTROYED:w}=i;function b(e,r,n,i){i=a(i);let s=!1;return e.on("close",(()=>{s=!0})),o(e,{readable:r,writable:n},(t=>{s=!t;const o=e._readableState;t&&"ERR_STREAM_PREMATURE_CLOSE"===t.code&&r&&o&&o.ended&&!o.errored&&!o.errorEmitted?e.once("end",i).once("error",i):i(t)})),r=>{s||(s=!0,t.destroyer(e,r),i(r||new w("pipe")))}}function y(e){if(c(e))return e;if(p(e))return async function*(e){yield*f.prototype[Symbol.asyncIterator].call(e)}(e);throw new u("val",["Readable","Iterable","AsyncIterable"],e)}async function _(e,t,r){let i,s=null;const a=e=>{if(e&&(i=e),s){const e=s;s=null,e()}},l=()=>new Promise(((e,t)=>{i?t(i):s=()=>{i?t(i):e()}}));t.on("drain",a);const f=o(t,{readable:!1},a);try{t.writableNeedDrain&&await l();for await(const r of e)t.write(r)||await l();t.end(),await l(),r()}catch(e){r(i!==e?n(i,e):e)}finally{f(),t.off("drain",a)}}export default pipeline;export function pipeline(...e){const t=a(function(e){return e.pop()}(e));return Array.isArray(e[0])&&1===e.length&&(e=e[0]),pipelineImpl(e,t)}export function pipelineImpl(t,o,n){if(t.length<2)throw new E("streams");const i=new e,a=i.signal,f=n?.signal;function u(){j(new s)}let w,h;f?.addEventListener("abort",u);const A=[];let I,S=0;function g(e){j(e,0==--S)}function j(e,t){if(!e||w&&"ERR_STREAM_PREMATURE_CLOSE"!==w.code||(w=e),w||t){for(;A.length;)A.shift()(w);f?.removeEventListener("abort",u),i.abort(),t&&o(w,h)}}for(let e=0;e<t.length;e++){const o=t[e],n=e<t.length-1,i=e>0;if(d(o)&&(S++,A.push(b(o,n,i,g))),0===e)if("function"==typeof o){if(I=o({signal:a}),!c(I))throw new R("Iterable, AsyncIterable or Stream","source",I)}else I=c(o)||p(o)?o:r.from(o);else if("function"==typeof o)if(I=y(I),I=o(I,{signal:a}),n){if(!c(I,!0))throw new R("AsyncIterable",`transform[${e-1}]`,I)}else{const e=new l({objectMode:!0}),t=I?.then;if("function"==typeof t)t.call(I,(t=>{h=t,e.end(t)}),(t=>{e.destroy(t)}));else{if(!c(I,!0))throw new R("AsyncIterable or Promise","destination",I);S++,_(I,e,g)}I=e,S++,A.push(b(I,!1,!0,g))}else d(o)?(p(I)?(I.pipe(o),o!==m.stdout&&o!==m.stderr||I.on("end",(()=>o.end()))):(I=y(I),S++,_(I,o,g)),I=o):I=r.from(o)}return(a?.aborted||f?.aborted)&&m.nextTick(u),I}
✄
{"version":3,"file":"promises.js","names":["eos","pl","isIterable","isNodeStream","pipeline","streams","Promise","resolve","reject","signal","lastArg","length","pop","err","value","finished","stream","opts"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"OAAOA,MAAS,4CACSC,MAAU,qCAEjCC,kBACAC,MACK,oBAEA,SAASC,YAAYC,GAC1B,OAAO,IAAIC,SAAQ,CAACC,EAASC,KAC3B,IAAIC,EACJ,MAAMC,EAAUL,EAAQA,EAAQM,OAAS,GACzC,GAAID,GAA8B,iBAAZA,IACjBP,EAAaO,KAAaR,EAAWQ,GAAU,CAElDD,EADgBJ,EAAQO,MACPH,MACnB,CAEAR,EAAGI,GAAS,CAACQ,EAAKC,KACZD,EACFL,EAAOK,GAEPN,EAAQO,EACV,GACC,CAAEL,UAAS,GAElB,QAEO,SAASM,SAASC,EAAQC,GAC/B,OAAO,IAAIX,SAAQ,CAACC,EAASC,KAC3BR,EAAIgB,EAAQC,GAAOJ,IACbA,EACFL,EAAOK,GAEPN,GACF,GACA,GAEN"}
✄
import e from"./end-of-stream.js";import{pipelineImpl as i}from"./pipeline.js";import{isIterable as n,isNodeStream as o}from"./utils.js";export function pipeline(...e){return new Promise(((t,p)=>{let r;const s=e[e.length-1];if(s&&"object"==typeof s&&!o(s)&&!n(s)){r=e.pop().signal}i(e,((e,i)=>{e?p(e):t(i)}),{signal:r})}))}export function finished(i,n){return new Promise(((o,t)=>{e(i,n,(e=>{e?t(e):o()}))}))}
✄
{"version":3,"file":"readable.js","names":["addAbortSignal","BufferList","destroyImpl","eos","aggregateTwoErrors","errorCodes","from","Stream","prependListener","getHighWaterMark","getDefaultHighWaterMark","Buffer","EE","process","StringDecoder","Readable","ERR_INVALID_ARG_TYPE","ERR_METHOD_NOT_IMPLEMENTED","ERR_OUT_OF_RANGE","ERR_STREAM_PUSH_AFTER_EOF","ERR_STREAM_UNSHIFT_AFTER_END_EVENT","kPaused","Symbol","Object","setPrototypeOf","prototype","nop","errorOrDestroy","ReadableState","options","stream","isDuplex","Duplex","this","objectMode","readableObjectMode","highWaterMark","buffer","length","pipes","flowing","ended","endEmitted","reading","constructed","sync","needReadable","emittedReadable","readableListening","resumeScheduled","errorEmitted","emitClose","autoDestroy","destroyed","errored","closed","closeEmitted","defaultEncoding","awaitDrainWriters","multiAwaitDrain","readingMore","dataEmitted","decoder","encoding","_readableState","read","_read","destroy","_destroy","construct","_construct","signal","call","maybeReadMore","readableAddChunk","chunk","addToFront","state","err","toString","_isUint8Array","_uint8ArrayToBuffer","end","push","emitReadable","emitReadable_","onEofChunk","addChunk","write","listenerCount","clear","emit","unshift","_undestroy","undestroy","cb","captureRejectionSymbol","isPaused","setEncoding","enc","content","data","howMuchToRead","n","Number","isNaN","first","nextTick","flow","maybeReadMore_","len","updateReadableListening","self","resume","nReadingNextTick","resume_","streamToAsyncIterator","wrap","iter","async","error","callback","next","resolve","on","writable","Promise","destroyOnReturn","undefined","destroyer","createAsyncIterator","fromList","ret","shift","join","concat","consume","endReadable","endReadableNT","allowHalfOpen","endWritableNT","wState","_writableState","finished","writableEnded","NaN","isInteger","parseInt","nOrig","computeNewHighWaterMark","doRead","result","then","pipe","dest","pipeOpts","src","Set","endFn","stdout","stderr","onend","unpipe","onunpipe","readable","unpipeInfo","hasUnpiped","removeListener","onclose","onfinish","ondrain","onerror","ondata","cleanedUp","needDrain","cleanup","once","pause","includes","add","delete","size","pipeOnDrain","er","s","writableNeedDrain","dests","i","index","indexOf","splice","ev","fn","res","addListener","off","removeAllListeners","apply","arguments","paused","streamKeys","keys","j","bind","asyncIterator","iterator","defineProperties","get","r","set","val","readableDidRead","enumerable","readableAborted","readableHighWaterMark","readableBuffer","readableFlowing","readableLength","readableEncoding","value","readableEnded","pipesCount","_fromList","iterable","opts"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"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
"""


```