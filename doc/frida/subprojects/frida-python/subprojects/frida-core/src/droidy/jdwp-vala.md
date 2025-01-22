Response:
### 功能归纳

`jdwp.vala` 文件是 Frida 工具中用于实现 **JDWP（Java Debug Wire Protocol）** 客户端功能的核心部分。JDWP 是 Java 调试协议，用于调试 Java 虚拟机（JVM）中的应用程序。该文件的主要功能包括：

1. **JDWP 客户端实现**：
   - 该文件实现了一个 JDWP 客户端，能够与 JVM 进行通信，执行调试操作。
   - 支持与 JVM 的握手、数据包传输、命令执行等基本功能。

2. **调试功能**：
   - **挂起和恢复线程**：可以通过 `suspend` 和 `resume` 方法挂起和恢复 JVM 中的线程。
   - **创建和读取字符串**：支持在 JVM 中创建字符串对象，并读取字符串内容。
   - **获取类和方法信息**：可以通过类签名获取类信息，获取类的方法列表。
   - **调用静态方法和实例方法**：支持在 JVM 中调用静态方法和实例方法，并处理返回值。
   - **事件处理**：支持设置和清除事件请求，处理调试事件（如断点、异常、线程启动等）。

3. **事件处理**：
   - 支持多种调试事件的处理，如单步执行、断点、异常捕获、线程启动和终止等。
   - 通过 `events_received` 信号通知上层应用接收到的事件。

4. **底层通信**：
   - 通过 `IOStream` 进行底层的数据传输，支持异步操作。
   - 处理 JDWP 协议的数据包，包括数据包的读取、写入和解析。

5. **状态管理**：
   - 管理客户端的状态（`CREATED`、`READY`、`CLOSED`），并在状态变化时通知上层应用。

### 涉及二进制底层和 Linux 内核的部分

虽然该文件主要处理的是 JDWP 协议和 Java 虚拟机的调试功能，但它依赖于底层的 I/O 操作和异步处理机制。这些操作可能会涉及到 Linux 内核的 I/O 调度和网络通信。

- **I/O 操作**：通过 `InputStream` 和 `OutputStream` 进行数据的读取和写入，这些操作最终会通过 Linux 内核的系统调用（如 `read` 和 `write`）来完成。
- **异步处理**：使用了 GLib 的异步机制（如 `async` 和 `yield`），这些机制在底层可能会使用到 Linux 内核的事件循环（如 `epoll`）来实现非阻塞 I/O。

### 使用 LLDB 复刻调试功能的示例

假设你想使用 LLDB 来复刻该文件中的调试功能，可以通过以下步骤实现：

1. **挂起和恢复线程**：
   - 使用 LLDB 的 `process interrupt` 命令挂起目标进程的所有线程。
   - 使用 `thread continue` 命令恢复线程的执行。

   ```lldb
   (lldb) process interrupt
   (lldb) thread continue
   ```

2. **设置断点**：
   - 使用 LLDB 的 `breakpoint set` 命令在特定方法或行号上设置断点。

   ```lldb
   (lldb) breakpoint set --name java.lang.Object.toString
   ```

3. **调用方法**：
   - 使用 LLDB 的 `expression` 命令调用 Java 方法。

   ```lldb
   (lldb) expression -- (void)[obj toString]
   ```

4. **处理事件**：
   - 使用 LLDB 的 `process handle` 命令来处理调试事件，如断点命中、异常捕获等。

   ```lldb
   (lldb) process handle SIGTRAP --stop true --notify true
   ```

### 假设输入与输出

假设你调用 `invoke_static_method` 方法来调用一个静态方法：

- **输入**：
  - `ref_type`: 类的引用类型 ID。
  - `thread`: 线程 ID。
  - `method`: 方法 ID。
  - `arguments`: 方法参数列表。

- **输出**：
  - 返回方法的返回值，如果方法抛出异常，则抛出 `Error.PROTOCOL` 异常。

### 常见使用错误

1. **未正确处理异步操作**：
   - 如果未正确处理异步操作（如未等待 `yield` 完成），可能会导致程序逻辑错误或崩溃。

   ```vala
   // 错误示例：未等待异步操作完成
   invoke_static_method (ref_type, thread, method);
   ```

   ```vala
   // 正确示例：等待异步操作完成
   yield invoke_static_method (ref_type, thread, method);
   ```

2. **未处理异常**：
   - 如果未正确处理异常（如未捕获 `Error` 或 `IOError`），可能会导致程序崩溃。

   ```vala
   // 错误示例：未捕获异常
   var result = yield invoke_static_method (ref_type, thread, method);
   ```

   ```vala
   // 正确示例：捕获异常
   try {
       var result = yield invoke_static_method (ref_type, thread, method);
   } catch (Error e) {
       print ("Error: %s\n", e.message);
   }
   ```

### 用户操作如何一步步到达这里

1. **启动调试会话**：
   - 用户通过 Frida 工具启动一个调试会话，连接到目标 JVM。

2. **发送调试命令**：
   - 用户通过 Frida 的 API 发送调试命令（如挂起线程、设置断点、调用方法等）。

3. **处理调试事件**：
   - Frida 的 JDWP 客户端接收到调试事件（如断点命中、异常捕获等），并通过 `events_received` 信号通知上层应用。

4. **处理返回结果**：
   - Frida 的 JDWP 客户端处理调试命令的返回结果，并将结果返回给用户。

### 总结

`jdwp.vala` 文件实现了 Frida 工具中与 JVM 调试相关的核心功能，包括调试命令的执行、事件处理、底层通信等。通过 LLDB 可以复刻部分调试功能，但在实际使用中需要注意异步操作和异常处理的正确性。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/droidy/jdwp.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
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
		
"""


```