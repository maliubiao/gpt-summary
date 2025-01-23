Response:
### 功能归纳

`frida/subprojects/frida-core/src/droidy/jdwp.vala` 文件是 Frida 工具中用于与 Java Debug Wire Protocol (JDWP) 交互的核心模块。JDWP 是 Java 虚拟机（JVM）调试协议，允许调试器与 JVM 进行通信，获取运行时信息、设置断点、单步执行等操作。该文件的主要功能包括：

1. **JDWP 客户端实现**：
   - 实现了 JDWP 协议的客户端，能够与 JVM 进行通信。
   - 支持异步操作，允许在调试过程中进行非阻塞的通信。

2. **状态管理**：
   - 管理客户端的状态（`CREATED`, `READY`, `CLOSED`），确保在正确的状态下执行操作。
   - 通过 `change_state` 方法更新状态，并通知状态变化。

3. **协议命令执行**：
   - 提供了多种 JDWP 命令的执行方法，如 `suspend`、`resume`、`create_string`、`read_string` 等。
   - 支持通过 `CommandBuilder` 构建 JDWP 命令，并通过 `execute` 方法发送命令并处理响应。

4. **事件处理**：
   - 支持处理 JDWP 事件，如断点事件、单步事件、异常事件等。
   - 通过 `handle_event` 方法分发事件，并通过 `events_received` 信号通知上层应用。

5. **调试功能**：
   - 提供了调试相关的功能，如获取类信息、方法信息、调用静态方法和实例方法等。
   - 支持通过 `invoke_static_method` 和 `invoke_instance_method` 调用 Java 方法，并处理返回值和异常。

6. **ID 管理**：
   - 管理 JDWP 中的各种 ID，如 `ObjectID`、`ThreadID`、`ReferenceTypeID` 等。
   - 通过 `IDSizes` 类获取 ID 的大小信息，确保协议的正确解析。

7. **错误处理**：
   - 提供了详细的错误处理机制，能够捕获并处理 JDWP 协议中的错误。
   - 通过 `throw_local_error` 方法抛出本地错误，确保调试过程的稳定性。

### 二进制底层与 Linux 内核相关

虽然该文件主要处理 JDWP 协议，不直接涉及 Linux 内核或二进制底层操作，但它通过 `IOStream` 与 JVM 进行通信，底层可能涉及网络套接字或进程间通信（IPC）。例如：

- **网络通信**：JDWP 通常通过 TCP/IP 进行通信，底层可能使用 Linux 的 `socket` 系统调用。
- **进程间通信**：如果 JVM 与调试器在同一台机器上运行，可能会使用 Unix 域套接字或管道进行通信。

### LLDB 调试示例

假设你想使用 LLDB 调试该代码中的 `Client` 类，特别是 `execute` 方法，你可以使用以下 LLDB 命令或 Python 脚本来设置断点并检查变量：

#### LLDB 命令示例

```bash
# 启动 LLDB 并附加到目标进程
lldb -- <target_process>

# 设置断点
(lldb) b frida::JDWP::Client::execute

# 运行程序
(lldb) run

# 当断点命中时，检查变量
(lldb) p command
(lldb) p pending_replies
(lldb) p state
```

#### LLDB Python 脚本示例

```python
import lldb

def execute_breakpoint_handler(frame, bp_loc, dict):
    # 获取当前帧的变量
    command = frame.FindVariable("command")
    pending_replies = frame.FindVariable("pending_replies")
    state = frame.FindVariable("_state")

    # 打印变量值
    print(f"Command: {command}")
    print(f"Pending Replies: {pending_replies}")
    print(f"State: {state}")

    # 继续执行
    return False

# 创建调试器实例
debugger = lldb.SBDebugger.Create()

# 附加到目标进程
target = debugger.CreateTarget("<target_process>")
process = target.AttachToProcessWithID(lldb.SBListener(), <pid>)

# 设置断点
breakpoint = target.BreakpointCreateByName("frida::JDWP::Client::execute")
breakpoint.SetScriptCallbackFunction("execute_breakpoint_handler")

# 继续执行
process.Continue()
```

### 假设输入与输出

假设你调用 `invoke_static_method` 方法来调用一个静态方法：

#### 输入
```vala
var result = yield client.invoke_static_method(class_id, thread_id, method_id, arguments);
```

#### 输出
- 如果方法调用成功，`result` 将包含返回值。
- 如果方法调用失败，将抛出异常，异常信息包含 Java 异常的 `toString()` 结果。

### 常见使用错误

1. **未正确处理异步操作**：
   - 错误示例：在异步操作未完成时，尝试访问结果。
   - 解决方法：确保使用 `yield` 等待异步操作完成。

2. **未处理异常**：
   - 错误示例：调用 `invoke_static_method` 时未捕获可能的异常。
   - 解决方法：使用 `try-catch` 块捕获并处理异常。

3. **状态错误**：
   - 错误示例：在 `CLOSED` 状态下尝试执行命令。
   - 解决方法：在执行命令前检查 `state`，确保客户端处于 `READY` 状态。

### 用户操作步骤

1. **启动调试器**：用户启动 Frida 调试器，并附加到目标 JVM 进程。
2. **初始化客户端**：用户调用 `Client.open` 方法初始化 JDWP 客户端。
3. **设置断点**：用户调用 `set_event_request` 方法设置断点。
4. **执行命令**：用户调用 `invoke_static_method` 或 `invoke_instance_method` 执行 Java 方法。
5. **处理事件**：用户通过 `events_received` 信号处理调试事件，如断点命中、异常抛出等。
6. **关闭客户端**：用户调用 `close` 方法关闭客户端，结束调试会话。

通过这些步骤，用户可以逐步调试 Java 应用程序，获取运行时信息并控制程序执行。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/droidy/jdwp.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
[CCode (gir_namespace = "FridaJDWP", gir_version = "1.0")]
namespace Frida.JDWP {
	public class Client : GLib.Object, AsyncInitable {
		public signal void closed ();
		public signal void events_received (Events events);

		public IOStream stream {
			get;
			construct;
		}

		public State state {
			get {
				return _state;
			}
		}

		private InputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		private State _state = CREATED;
		private uint32 next_id = 1;
		private IDSizes id_sizes = new IDSizes.unknown ();
		private ReferenceTypeID java_lang_object;
		private MethodID java_lang_object_to_string;
		private Gee.ArrayQueue<Bytes> pending_writes = new Gee.ArrayQueue<Bytes> ();
		private Gee.Map<uint32, PendingReply> pending_replies = new Gee.HashMap<uint32, PendingReply> ();

		public enum State {
			CREATED,
			READY,
			CLOSED
		}

		private const uint32 MAX_PACKET_SIZE = 10 * 1024 * 1024;

		public static async Client open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var session = new Client (stream);

			try {
				yield session.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return session;
		}

		private Client (IOStream stream) {
			GLib.Object (stream: stream);
		}

		construct {
			input = stream.get_input_stream ();
			output = stream.get_output_stream ();
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			yield handshake (cancellable);
			process_incoming_packets.begin ();

			id_sizes = yield get_id_sizes (cancellable);

			change_state (READY);

			var object_class = yield get_class_by_signature ("Ljava/lang/Object;", cancellable);
			java_lang_object = object_class.ref_type.id;

			var object_methods = yield get_methods (object_class.ref_type.id, cancellable);
			foreach (var method in object_methods) {
				if (method.name == "toString") {
					java_lang_object_to_string = method.id;
					break;
				}
			}

			return true;
		}

		private void change_state (State new_state) {
			bool state_differs = new_state != _state;
			if (state_differs)
				_state = new_state;

			if (state_differs)
				notify_property ("state");
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (state == CLOSED)
				return;

			io_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (close.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield stream.close_async (Priority.DEFAULT, cancellable);
			} catch (IOError e) {
			}
		}

		public async void suspend (Cancellable? cancellable = null) throws Error, IOError {
			yield execute (make_command (VM, VMCommand.SUSPEND), cancellable);
		}

		public async void resume (Cancellable? cancellable = null) throws Error, IOError {
			yield execute (make_command (VM, VMCommand.RESUME), cancellable);
		}

		public async String create_string (string str, Cancellable? cancellable = null) throws Error, IOError {
			var command = make_command (VM, VMCommand.CREATE_STRING);
			command.append_utf8_string (str);

			var reply = yield execute (command, cancellable);

			return new String (reply.read_object_id ());
		}

		public async string read_string (ObjectID id, Cancellable? cancellable = null) throws Error, IOError {
			var command = make_command (STRING_REFERENCE, StringReferenceCommand.VALUE);
			command.append_object_id (id);

			var reply = yield execute (command, cancellable);

			return reply.read_utf8_string ();
		}

		public async ClassInfo get_class_by_signature (string signature, Cancellable? cancellable = null) throws Error, IOError {
			var candidates = yield get_classes_by_signature (signature, cancellable);
			if (candidates.is_empty)
				throw new Error.INVALID_ARGUMENT ("Class %s not found", signature);
			if (candidates.size > 1)
				throw new Error.INVALID_ARGUMENT ("Class %s is ambiguous", signature);
			return candidates.get (0);
		}

		public async Gee.List<ClassInfo> get_classes_by_signature (string signature, Cancellable? cancellable = null)
				throws Error, IOError {
			var command = make_command (VM, VMCommand.CLASSES_BY_SIGNATURE);
			command.append_utf8_string (signature);

			var reply = yield execute (command, cancellable);

			var result = new Gee.ArrayList<ClassInfo> ();
			int32 n = reply.read_int32 ();
			for (int32 i = 0; i != n; i++)
				result.add (ClassInfo.deserialize (reply));
			return result;
		}

		public async Gee.List<MethodInfo> get_methods (ReferenceTypeID type, Cancellable? cancellable = null)
				throws Error, IOError {
			var command = make_command (REFERENCE_TYPE, ReferenceTypeCommand.METHODS);
			command.append_reference_type_id (type);

			var reply = yield execute (command, cancellable);

			var result = new Gee.ArrayList<MethodInfo> ();
			int32 n = reply.read_int32 ();
			for (int32 i = 0; i != n; i++)
				result.add (MethodInfo.deserialize (reply));
			return result;
		}

		public async Value invoke_static_method (TaggedReferenceTypeID ref_type, ThreadID thread, MethodID method,
				Value[] arguments = {}, InvokeOptions options = 0, Cancellable? cancellable = null) throws Error, IOError {
			var command = (ref_type.tag == CLASS)
				? make_command (CLASS_TYPE, ClassTypeCommand.INVOKE_METHOD)
				: make_command (INTERFACE_TYPE, InterfaceTypeCommand.INVOKE_METHOD);
			command
				.append_reference_type_id (ref_type.id)
				.append_thread_id (thread)
				.append_method_id (method)
				.append_int32 (arguments.length);
			foreach (var arg in arguments)
				command.append_value (arg);
			command.append_int32 (options);

			var reply = yield execute (command, cancellable);

			return yield handle_invoke_reply (reply, thread, cancellable);
		}

		public async Value invoke_instance_method (ObjectID object, ThreadID thread, ReferenceTypeID clazz, MethodID method,
				Value[] arguments = {}, InvokeOptions options = 0, Cancellable? cancellable = null) throws Error, IOError {
			var command = make_command (OBJECT_REFERENCE, ObjectReferenceCommand.INVOKE_METHOD);
			command
				.append_object_id (object)
				.append_thread_id (thread)
				.append_reference_type_id (clazz)
				.append_method_id (method)
				.append_int32 (arguments.length);
			foreach (var arg in arguments)
				command.append_value (arg);
			command.append_int32 (options);

			var reply = yield execute (command, cancellable);

			return yield handle_invoke_reply (reply, thread, cancellable);
		}

		private async Value handle_invoke_reply (PacketReader reply, ThreadID thread, Cancellable? cancellable) throws Error, IOError {
			var retval = reply.read_value ();

			var exception = reply.read_tagged_object_id ();
			if (!exception.id.is_null) {
				String description = (String) yield invoke_instance_method (exception.id, thread,
					java_lang_object, java_lang_object_to_string, {}, 0, cancellable);
				string description_str = yield read_string (description.val, cancellable);
				throw new Error.PROTOCOL ("%s", description_str);
			}

			return retval;
		}

		public async EventRequestID set_event_request (EventKind kind, SuspendPolicy suspend_policy, EventModifier[] modifiers = {},
				Cancellable? cancellable = null) throws Error, IOError {
			var command = make_command (EVENT_REQUEST, EventRequestCommand.SET);
			command
				.append_uint8 (kind)
				.append_uint8 (suspend_policy)
				.append_int32 (modifiers.length);
			foreach (var modifier in modifiers)
				modifier.serialize (command);

			var reply = yield execute (command, cancellable);

			return EventRequestID (reply.read_int32 ());
		}

		public async void clear_event_request (EventKind kind, EventRequestID request_id, Cancellable? cancellable = null)
				throws Error, IOError {
			var command = make_command (EVENT_REQUEST, EventRequestCommand.CLEAR);
			command
				.append_uint8 (kind)
				.append_int32 (request_id.handle);

			yield execute (command, cancellable);
		}

		public async void clear_all_breakpoints (Cancellable? cancellable = null) throws Error, IOError {
			var command = make_command (EVENT_REQUEST, EventRequestCommand.CLEAR_ALL_BREAKPOINTS);

			yield execute (command, cancellable);
		}

		private async void handshake (Cancellable? cancellable) throws Error, IOError {
			try {
				size_t n;

				string magic = "JDWP-Handshake";

				unowned uint8[] raw_handshake = magic.data;
				yield output.write_all_async (raw_handshake, Priority.DEFAULT, cancellable, out n);

				var raw_reply = new uint8[magic.length];
				yield input.read_all_async (raw_reply, Priority.DEFAULT, cancellable, out n);

				if (Memory.cmp (raw_reply, raw_handshake, raw_reply.length) != 0)
					throw new Error.PROTOCOL ("Unexpected handshake reply");
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s".printf (e.message));
			}
		}

		private async IDSizes get_id_sizes (Cancellable? cancellable) throws Error, IOError {
			var command = make_command (VM, VMCommand.ID_SIZES);

			var reply = yield execute (command, cancellable);

			return IDSizes.deserialize (reply);
		}

		private CommandBuilder make_command (CommandSet command_set, uint8 command) {
			return new CommandBuilder (next_id++, command_set, command, id_sizes);
		}

		private async PacketReader execute (CommandBuilder command, Cancellable? cancellable) throws Error, IOError {
			if (state == CLOSED)
				throw new Error.INVALID_OPERATION ("Unable to perform command; connection is closed");

			var pending = new PendingReply (execute.callback);
			pending_replies[command.id] = pending;

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				pending.complete_with_error (new IOError.CANCELLED ("Operation was cancelled"));
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			write_bytes (command.build ());

			yield;

			cancel_source.destroy ();

			cancellable.set_error_if_cancelled ();

			var reply = pending.reply;
			if (reply == null)
				throw_local_error (pending.error);

			return reply;
		}

		private async void process_incoming_packets () {
			while (true) {
				try {
					var packet = yield read_packet ();

					dispatch_packet (packet);
				} catch (GLib.Error error) {
					change_state (CLOSED);

					foreach (var pending in pending_replies.values)
						pending.complete_with_error (error);
					pending_replies.clear ();

					closed ();

					return;
				}
			}
		}

		private async void process_pending_writes () {
			while (!pending_writes.is_empty) {
				Bytes current = pending_writes.peek_head ();

				try {
					size_t n;
					yield output.write_all_async (current.get_data (), Priority.DEFAULT, io_cancellable, out n);
				} catch (GLib.Error e) {
					return;
				}

				pending_writes.poll_head ();
			}
		}

		private void dispatch_packet (PacketReader packet) throws Error {
			packet.skip (sizeof (uint32));
			var id = packet.read_uint32 ();
			var flags = (PacketFlags) packet.read_uint8 ();

			if ((flags & PacketFlags.REPLY) != 0)
				handle_reply (packet, id);
			else
				handle_command (packet, id);
		}

		private void handle_reply (PacketReader packet, uint32 id) throws Error {
			PendingReply? pending;
			if (!pending_replies.unset (id, out pending))
				return;

			var error_code = packet.read_uint16 ();
			if (error_code == 0)
				pending.complete_with_reply (packet);
			else
				pending.complete_with_error (new Error.NOT_SUPPORTED ("Command failed: %u", error_code));
		}

		private void handle_command (PacketReader packet, uint32 id) throws Error {
			var command_set = (CommandSet) packet.read_uint8 ();
			var command = packet.read_uint8 ();
			switch (command_set) {
				case EVENT:
					handle_event ((EventCommand) command, packet);
					break;
				default:
					break;
			}
		}

		private void handle_event (EventCommand command, PacketReader packet) throws Error {
			switch (command) {
				case COMPOSITE:
					handle_event_composite (packet);
					break;
				default:
					break;
			}
		}

		private void handle_event_composite (PacketReader packet) throws Error {
			var suspend_policy = (SuspendPolicy) packet.read_uint8 ();

			var items = new Gee.ArrayList<Event> ();
			int32 n = packet.read_int32 ();
			for (int32 i = 0; i != n; i++) {
				Event? event = null;
				var kind = (EventKind) packet.read_uint8 ();
				switch (kind) {
					case SINGLE_STEP:
						event = SingleStepEvent.deserialize (packet);
						break;
					case BREAKPOINT:
						event = BreakpointEvent.deserialize (packet);
						break;
					case FRAME_POP:
						event = FramePopEvent.deserialize (packet);
						break;
					case EXCEPTION:
						event = ExceptionEvent.deserialize (packet);
						break;
					case USER_DEFINED:
						event = UserDefinedEvent.deserialize (packet);
						break;
					case THREAD_START:
						event = ThreadStartEvent.deserialize (packet);
						break;
					case THREAD_DEATH:
						event = ThreadDeathEvent.deserialize (packet);
						break;
					case CLASS_PREPARE:
						event = ClassPrepareEvent.deserialize (packet);
						break;
					case CLASS_UNLOAD:
						event = ClassUnloadEvent.deserialize (packet);
						break;
					case CLASS_LOAD:
						event = ClassLoadEvent.deserialize (packet);
						break;
					case FIELD_ACCESS:
						event = FieldAccessEvent.deserialize (packet);
						break;
					case FIELD_MODIFICATION:
						event = FieldModificationEvent.deserialize (packet);
						break;
					case EXCEPTION_CATCH:
						event = ExceptionCatchEvent.deserialize (packet);
						break;
					case METHOD_ENTRY:
						event = MethodEntryEvent.deserialize (packet);
						break;
					case METHOD_EXIT:
						event = MethodExitEvent.deserialize (packet);
						break;
					case METHOD_EXIT_WITH_RETURN_VALUE:
						event = MethodExitWithReturnValueEvent.deserialize (packet);
						break;
					case MONITOR_CONTENDED_ENTER:
						event = MonitorContendedEnterEvent.deserialize (packet);
						break;
					case MONITOR_CONTENDED_ENTERED:
						event = MonitorContendedEnteredEvent.deserialize (packet);
						break;
					case MONITOR_WAIT:
						event = MonitorWaitEvent.deserialize (packet);
						break;
					case MONITOR_WAITED:
						event = MonitorWaitedEvent.deserialize (packet);
						break;
					case VM_START:
						event = VMStartEvent.deserialize (packet);
						break;
					case VM_DEATH:
						event = VMDeathEvent.deserialize (packet);
						break;
					case VM_DISCONNECTED:
						event = VMDisconnectedEvent.deserialize (packet);
						break;
				}
				if (event != null)
					items.add (event);
			}

			events_received (new Events (suspend_policy, items));
		}

		private async PacketReader read_packet () throws Error, IOError {
			try {
				size_t n;

				int header_size = 11;
				var raw_reply = new uint8[header_size];
				yield input.read_all_async (raw_reply, Priority.DEFAULT, io_cancellable, out n);
				if (n == 0)
					throw new Error.TRANSPORT ("Connection closed unexpectedly");

				uint32 reply_size = uint32.from_big_endian (*((uint32 *) raw_reply));
				if (reply_size != raw_reply.length) {
					if (reply_size < raw_reply.length)
						throw new Error.PROTOCOL ("Invalid packet length (too small)");
					if (reply_size > MAX_PACKET_SIZE)
						throw new Error.PROTOCOL ("Invalid packet length (too large)");

					raw_reply.resize ((int) reply_size);
					yield input.read_all_async (raw_reply[header_size:], Priority.DEFAULT, io_cancellable, out n);
					if (n == 0)
						throw new Error.TRANSPORT ("Connection closed unexpectedly");
				}

				return new PacketReader ((owned) raw_reply, id_sizes);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s".printf (e.message));
			}
		}

		private void write_bytes (Bytes bytes) {
			pending_writes.offer_tail (bytes);
			if (pending_writes.size == 1)
				process_pending_writes.begin ();
		}

		private static void throw_local_error (GLib.Error e) throws Error, IOError {
			if (e is Error)
				throw (Error) e;

			if (e is IOError)
				throw (IOError) e;

			assert_not_reached ();
		}

		private class PendingReply {
			private SourceFunc? handler;

			public PacketReader? reply {
				get;
				private set;
			}

			public GLib.Error? error {
				get;
				private set;
			}

			public PendingReply (owned SourceFunc handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_reply (PacketReader? reply) {
				if (handler == null)
					return;
				this.reply = reply;
				handler ();
				handler = null;
			}

			public void complete_with_error (GLib.Error error) {
				if (handler == null)
					return;
				this.error = error;
				handler ();
				handler = null;
			}
		}
	}

	public enum TypeTag {
		CLASS     = 1,
		INTERFACE = 2,
		ARRAY     = 3;

		public string to_short_string () {
			return Marshal.enum_to_nick<TypeTag> (this).up ();
		}
	}

	public enum ValueTag {
		BYTE         = 66,
		CHAR         = 67,
		DOUBLE       = 68,
		FLOAT        = 70,
		INT          = 73,
		LONG         = 74,
		OBJECT       = 76,
		SHORT        = 83,
		VOID         = 86,
		BOOLEAN      = 90,
		ARRAY        = 91,
		CLASS_OBJECT = 99,
		THREAD_GROUP = 103,
		CLASS_LOADER = 108,
		STRING       = 115,
		THREAD       = 116,
	}

	public abstract class Value : GLib.Object {
		public ValueTag tag {
			get;
			construct;
		}

		public abstract string to_string ();
	}

	public class Byte : Value {
		public uint8 val {
			get;
			construct;
		}

		public Byte (uint8 val) {
			GLib.Object (tag: ValueTag.BYTE, val: val);
		}

		public override string to_string () {
			return val.to_string ();
		}
	}

	public class Char : Value {
		public string val {
			get;
			construct;
		}

		public Char (string val) {
			GLib.Object (tag: ValueTag.CHAR, val: val);
		}

		public override string to_string () {
			return val;
		}
	}

	public class Double : Value {
		public double val {
			get;
			construct;
		}

		public Double (double val) {
			GLib.Object (tag: ValueTag.DOUBLE, val: val);
		}

		public override string to_string () {
			return val.to_string ();
		}
	}

	public class Float : Value {
		public float val {
			get;
			construct;
		}

		public Float (float val) {
			GLib.Object (tag: ValueTag.FLOAT, val: val);
		}

		public override string to_string () {
			return val.to_string ();
		}
	}

	public class Int : Value {
		public int32 val {
			get;
			construct;
		}

		public Int (int32 val) {
			GLib.Object (tag: ValueTag.INT, val: val);
		}

		public override string to_string () {
			return val.to_string ();
		}
	}

	public class Long : Value {
		public int64 val {
			get;
			construct;
		}

		public Long (int64 val) {
			GLib.Object (tag: ValueTag.LONG, val: val);
		}

		public override string to_string () {
			return val.to_string ();
		}
	}

	public class Object : Value {
		public ObjectID val {
			get;
			construct;
		}

		public Object (ObjectID val) {
			GLib.Object (tag: ValueTag.OBJECT, val: val);
		}

		public override string to_string () {
			return val.to_string ();
		}
	}

	public class Short : Value {
		public int16 val {
			get;
			construct;
		}

		public Short (int16 val) {
			GLib.Object (tag: ValueTag.SHORT, val: val);
		}

		public override string to_string () {
			return val.to_string ();
		}
	}

	public class Void : Value {
		public Void () {
			GLib.Object (tag: ValueTag.VOID);
		}

		public override string to_string () {
			return "void";
		}
	}

	public class Boolean : Value {
		public bool val {
			get;
			construct;
		}

		public Boolean (bool val) {
			GLib.Object (tag: ValueTag.BOOLEAN, val: val);
		}

		public override string to_string () {
			return val.to_string ();
		}
	}

	public class Array : Object {
		public Array (ObjectID val) {
			GLib.Object (tag: ValueTag.ARRAY, val: val);
		}
	}

	public class ClassObject : Object {
		public ClassObject (ObjectID val) {
			GLib.Object (tag: ValueTag.CLASS_OBJECT, val: val);
		}
	}

	public class ThreadGroup : Object {
		public ThreadGroup (ObjectID val) {
			GLib.Object (tag: ValueTag.THREAD_GROUP, val: val);
		}
	}

	public class ClassLoader : Object {
		public ClassLoader (ObjectID val) {
			GLib.Object (tag: ValueTag.CLASS_LOADER, val: val);
		}
	}

	public class String : Object {
		public String (ObjectID val) {
			GLib.Object (tag: ValueTag.STRING, val: val);
		}
	}

	public class Thread : Object {
		public Thread (ObjectID val) {
			GLib.Object (tag: ValueTag.THREAD, val: val);
		}
	}

	public class ClassInfo : GLib.Object {
		public TaggedReferenceTypeID ref_type {
			get;
			construct;
		}

		public ClassStatus status {
			get;
			construct;
		}

		public ClassInfo (TaggedReferenceTypeID ref_type, ClassStatus status) {
			GLib.Object (
				ref_type: ref_type,
				status: status
			);
		}

		public string to_string () {
			return "ClassInfo(ref_type: %s, status: %s)".printf (ref_type.to_string (), status.to_short_string ());
		}

		internal static ClassInfo deserialize (PacketReader packet) throws Error {
			var ref_type = packet.read_tagged_reference_type_id ();
			var status = (ClassStatus) packet.read_int32 ();
			return new ClassInfo (ref_type, status);
		}
	}

	[Flags]
	public enum ClassStatus {
		VERIFIED    = (1 << 0),
		PREPARED    = (1 << 1),
		INITIALIZED = (1 << 2),
		ERROR       = (1 << 3);

		public string to_short_string () {
			return this.to_string ().replace ("FRIDA_JDWP_CLASS_STATUS_", "");
		}
	}

	public class MethodInfo : GLib.Object {
		public MethodID id {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public string signature {
			get;
			construct;
		}

		public int32 mod_bits {
			get;
			construct;
		}

		public MethodInfo (MethodID id, string name, string signature, int32 mod_bits) {
			GLib.Object (
				id: id,
				name: name,
				signature: signature,
				mod_bits: mod_bits
			);
		}

		public string to_string () {
			return "MethodInfo(id: %s, name: \"%s\", signature: \"%s\", mod_bits: 0x%08x)".printf (
				id.to_string (),
				name,
				signature,
				mod_bits
			);
		}

		internal static MethodInfo deserialize (PacketReader packet) throws Error {
			var id = packet.read_method_id ();
			var name = packet.read_utf8_string ();
			var signature = packet.read_utf8_string ();
			var mod_bits = packet.read_int32 ();
			return new MethodInfo (id, name, signature, mod_bits);
		}
	}

	[Flags]
	public enum InvokeOptions {
		INVOKE_SINGLE_THREADED = 0x01,
		INVOKE_NONVIRTUAL      = 0x02,
	}

	public struct ObjectID {
		public int64 handle {
			get;
			private set;
		}

		public bool is_null {
			get {
				return handle == 0;
			}
		}

		public ObjectID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return (handle != 0) ? handle.to_string () : "null";
		}
	}

	public struct TaggedObjectID {
		public TypeTag tag {
			get;
			private set;
		}

		public ObjectID id {
			get;
			private set;
		}

		public TaggedObjectID (TypeTag tag, ObjectID id) {
			this.tag = tag;
			this.id = id;
		}

		public string to_string () {
			return "TaggedObjectID(tag: %s, id: %s)".printf (tag.to_short_string (), id.to_string ());
		}
	}

	public struct ThreadID {
		public int64 handle {
			get;
			private set;
		}

		public ThreadID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return handle.to_string ();
		}
	}

	public struct ReferenceTypeID {
		public int64 handle {
			get;
			private set;
		}

		public ReferenceTypeID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return (handle != 0) ? handle.to_string () : "null";
		}
	}

	public struct TaggedReferenceTypeID {
		public TypeTag tag {
			get;
			private set;
		}

		public ReferenceTypeID id {
			get;
			private set;
		}

		public TaggedReferenceTypeID (TypeTag tag, ReferenceTypeID id) {
			this.tag = tag;
			this.id = id;
		}

		public string to_string () {
			return "TaggedReferenceTypeID(tag: %s, id: %s)".printf (tag.to_short_string (), id.to_string ());
		}
	}

	public struct MethodID {
		public int64 handle {
			get;
			private set;
		}

		public MethodID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return handle.to_string ();
		}
	}

	public struct FieldID {
		public int64 handle {
			get;
			private set;
		}

		public FieldID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return handle.to_string ();
		}
	}

	public class Location : GLib.Object {
		public TaggedReferenceTypeID declaring {
			get;
			construct;
		}

		public MethodID method {
			get;
			construct;
		}

		public uint64 index {
			get;
			construct;
		}

		public Location (TaggedReferenceTypeID declaring, MethodID method, uint64 index = 0) {
			GLib.Object (
				declaring: declaring,
				method: method,
				index: index
			);
		}

		public string to_string () {
			return "Location(declaring: %s, method: %s, index: %s)".printf (
				declaring.to_string (),
				method.to_string (),
				index.to_string ()
			);
		}

		internal void serialize (PacketBuilder builder) {
			builder
				.append_tagged_reference_type_id (declaring)
				.append_method_id (method)
				.append_uint64 (index);
		}

		internal static Location deserialize (PacketReader packet) throws Error {
			var declaring = packet.read_tagged_reference_type_id ();
			var method = packet.read_method_id ();
			var index = packet.read_uint64 ();
			return new Location (declaring, method, index);
		}
	}

	public enum EventKind {
		SINGLE_STEP                   = 1,
		BREAKPOINT                    = 2,
		FRAME_POP                     = 3,
		EXCEPTION                     = 4,
		USER_DEFINED                  = 5,
		THREAD_START                  = 6,
		THREAD_DEATH                  = 7,
		CLASS_PREPARE                 = 8,
		CLASS_UNLOAD                  = 9,
		CLASS_LOAD                    = 10,
		FIELD_ACCESS                  = 20,
		FIELD_MODIFICATION            = 21,
		EXCEPTION_CATCH               = 30,
		METHOD_ENTRY                  = 40,
		METHOD_EXIT                   = 41,
		METHOD_EXIT_WITH_RETURN_VALUE = 42,
		MONITOR_CONTENDED_ENTER       = 43,
		MONITOR_CONTENDED_ENTERED     = 44,
		MONITOR_WAIT                  = 45,
		MONITOR_WAITED                = 46,
		VM_START                      = 90,
		VM_DEATH                      = 99,
		VM_DISCONNECTED               = 100,
	}

	public enum SuspendPolicy {
		NONE         = 0,
		EVENT_THREAD = 1,
		ALL          = 2,
	}

	public class Events : GLib.Object {
		public SuspendPolicy suspend_policy {
			get;
			construct;
		}

		public Gee.List<Event> items {
			get;
			construct;
		}

		public Events (SuspendPolicy suspend_policy, Gee.List<Event> items) {
			GLib.Object (
				suspend_policy: suspend_policy,
				items: items
			);
		}

		public string to_string () {
			var result = new StringBuilder ("Events(\n");

			foreach (var event in items) {
				result
					.append_c ('\t')
					.append (event.to_string ())
					.append_c ('\n');
			}

			result.append_c (')');

			return result.str;
		}
	}

	public abstract class Event : GLib.Object {
		public EventKind kind {
			get;
			construct;
		}

		public EventRequestID request {
			get;
			construct;
		}

		public abstract string to_string ();
	}

	public class SingleStepEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}

		public SingleStepEvent (EventRequestID request, ThreadID thread, Location location) {
			GLib.Object (
				kind: EventKind.SINGLE_STEP,
				request: request,
				thread: thread,
				location: location
			);
		}

		public override string to_string () {
			return "SingleStepEvent(request: %s, thread: %s, location: %s)".printf (
				request.to_string (),
				thread.to_string (),
				location.to_string ()
			);
		}

		internal static SingleStepEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var location = Location.deserialize (packet);
			return new SingleStepEvent (request, thread, location);
		}
	}

	public class BreakpointEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}

		public BreakpointEvent (EventRequestID request, ThreadID thread, Location location) {
			GLib.Object (
				kind: EventKind.BREAKPOINT,
				request: request,
				thread: thread,
				location: location
			);
		}

		public override string to_string () {
			return "BreakpointEvent(request: %s, thread: %s, location: %s)".printf (
				request.to_string (),
				thread.to_string (),
				location.to_string ()
			);
		}

		internal static BreakpointEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var location = Location.deserialize (packet);
			return new BreakpointEvent (request, thread, location);
		}
	}

	public class FramePopEvent : Event {
		public override string to_string () {
			return "FramePopEvent()";
		}

		internal static FramePopEvent deserialize (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("FRAME_POP event not supported");
		}
	}

	public class ExceptionEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}

		public TaggedObjectID exception {
			get;
			construct;
		}

		public Location? catch_location {
			get;
			construct;
		}

		public ExceptionEvent (EventRequestID request, ThreadID thread, Location location, TaggedObjectID exception,
				Location? catch_location) {
			GLib.Object (
				kind: EventKind.EXCEPTION,
				request: request,
				thread: thread,
				location: location,
				exception: exception,
				catch_location: catch_location
			);
		}

		public override string to_string () {
			return "ExceptionEvent(request: %s, thread: %s, location: %s, exception: %s, catch_location: %s)".printf (
				request.to_string (),
				thread.to_string (),
				location.to_string (),
				exception.to_string (),
				(catch_location != null) ? catch_location.to_string () : "null"
			);
		}

		internal static ExceptionEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var location = Location.deserialize (packet);
			var exception = packet.read_tagged_object_id ();
			var catch_location = Location.deserialize (packet);
			return new ExceptionEvent (request, thread, location, exception, catch_location);
		}
	}

	public class UserDefinedEvent : Event {
		public override string to_string () {
			return "UserDefinedEvent()";
		}

		internal static UserDefinedEvent deserialize (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("USER_DEFINED event not supported");
		}
	}

	public class ThreadStartEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public ThreadStartEvent (EventRequestID request, ThreadID thread) {
			GLib.Object (
				kind: EventKind.THREAD_START,
				request: request,
				thread: thread
			);
		}

		public override string to_string () {
			return "ThreadStartEvent(request: %s, thread: %s)".printf (
				request.to_string (),
				thread.to_string ()
			);
		}

		internal static ThreadStartEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			return new ThreadStartEvent (request, thread);
		}
	}

	public class ThreadDeathEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public ThreadDeathEvent (EventRequestID request, ThreadID thread) {
			GLib.Object (
				kind: EventKind.THREAD_DEATH,
				request: request,
				thread: thread
			);
		}

		public override string to_string () {
			return "ThreadDeathEvent(request: %s, thread: %s)".printf (
				request.to_string (),
				thread.to_string ()
			);
		}

		internal static ThreadDeathEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			return new ThreadDeathEvent (request, thread);
		}
	}

	public class ClassPrepareEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public TaggedReferenceTypeID ref_type {
			get;
			construct;
		}

		public string signature {
			get;
			construct;
		}

		public ClassStatus status {
			get;
			construct;
		}

		public ClassPrepareEvent (EventRequestID request, ThreadID thread, TaggedReferenceTypeID ref_type, string signature,
				ClassStatus status) {
			GLib.Object (
				kind: EventKind.CLASS_PREPARE,
				request: request,
				thread: thread,
				ref_type: ref_type,
				signature: signature,
				status: status
```