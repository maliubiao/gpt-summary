Response:
### 功能归纳

该源代码文件 `jdwp.vala` 是 Frida 动态插桩工具的一部分，主要用于实现 Java Debug Wire Protocol (JDWP) 的客户端功能。JDWP 是 Java 虚拟机（JVM）调试接口的核心协议，允许调试器与 JVM 进行通信。该文件的主要功能包括：

1. **事件处理**：
   - 处理各种调试事件，如类加载、类卸载、方法进入/退出、字段访问/修改、异常捕获、监视器事件等。
   - 每个事件类都有对应的 `deserialize` 方法，用于从 JDWP 协议的数据包中解析出事件信息。

2. **事件修饰器**：
   - 提供多种事件修饰器（Event Modifier），用于过滤或修改事件的触发条件。例如，`CountModifier` 用于限制事件的触发次数，`ThreadOnlyModifier` 用于仅在特定线程中触发事件等。

3. **数据包构建与解析**：
   - `PacketBuilder` 类用于构建 JDWP 协议的数据包，支持各种数据类型的序列化。
   - `PacketReader` 类用于解析 JDWP 协议的数据包，支持各种数据类型的反序列化。

4. **ID 管理**：
   - `IDSizes` 类用于管理 JDWP 协议中各种 ID 的大小（如对象 ID、方法 ID、字段 ID 等），确保在序列化和反序列化时正确处理这些 ID。

5. **调试功能**：
   - 支持调试器的基本功能，如设置断点、清除断点、挂起/恢复线程、调用方法等。

### 二进制底层与 Linux 内核

该文件主要涉及 Java 虚拟机的调试协议，不直接涉及 Linux 内核或二进制底层操作。不过，JDWP 协议本身是通过网络或本地套接字进行通信的，因此可能会涉及到底层的网络通信和字节流处理。

### LLDB 调试示例

假设你想使用 LLDB 来调试一个 Java 程序，并且想要复刻该文件中实现的调试功能（如设置断点、捕获方法进入/退出事件等），可以使用以下 LLDB Python 脚本示例：

```python
import lldb

def set_breakpoint(debugger, module, function):
    target = debugger.GetSelectedTarget()
    breakpoint = target.BreakpointCreateByName(function, module)
    if breakpoint.IsValid():
        print(f"Breakpoint set at {function} in {module}")
    else:
        print(f"Failed to set breakpoint at {function} in {module}")

def handle_event(debugger, event):
    process = debugger.GetSelectedTarget().GetProcess()
    if process.GetState() == lldb.eStateStopped:
        thread = process.GetSelectedThread()
        frame = thread.GetSelectedFrame()
        function = frame.GetFunctionName()
        print(f"Stopped at function: {function}")

def main():
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(True)
    target = debugger.CreateTarget("java")
    if not target:
        print("Failed to create target")
        return

    # Set breakpoint on a specific Java method
    set_breakpoint(debugger, "com.example.MyClass", "myMethod")

    # Launch the process
    process = target.LaunchSimple(None, None, os.getcwd())
    if not process:
        print("Failed to launch process")
        return

    # Event loop to handle breakpoints and other events
    while process.GetState() == lldb.eStateRunning:
        event = lldb.SBEvent()
        if debugger.GetListener().WaitForEvent(1, event):
            handle_event(debugger, event)

if __name__ == "__main__":
    main()
```

### 假设输入与输出

假设输入是一个 Java 程序，其中包含一个类 `com.example.MyClass` 和一个方法 `myMethod`。当运行上述 LLDB 脚本时，输出可能如下：

```
Breakpoint set at myMethod in com.example.MyClass
Stopped at function: com.example.MyClass.myMethod
```

### 用户常见错误

1. **断点设置失败**：
   - 用户可能错误地指定了方法名或类名，导致断点设置失败。例如，拼写错误或类名不完整。
   - **示例**：`set_breakpoint(debugger, "com.example.MyClass", "myMethod")` 中的 `myMethod` 拼写错误为 `myMethd`。

2. **事件处理错误**：
   - 用户可能在事件处理函数中没有正确处理线程状态，导致调试器无法正确捕获事件。
   - **示例**：在 `handle_event` 函数中没有检查线程状态，导致调试器在非预期状态下停止。

### 用户操作路径

1. **启动调试器**：
   - 用户启动 LLDB 并加载目标 Java 程序。

2. **设置断点**：
   - 用户调用 `set_breakpoint` 函数，在特定方法上设置断点。

3. **运行程序**：
   - 用户启动 Java 程序，调试器开始监控程序执行。

4. **捕获事件**：
   - 当程序执行到断点时，调试器捕获事件并调用 `handle_event` 函数，输出当前停止的函数名。

5. **继续执行**：
   - 用户可以选择继续执行程序，调试器将继续监控并捕获后续事件。

通过以上步骤，用户可以复刻该文件中实现的调试功能，并使用 LLDB 进行 Java 程序的调试。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/droidy/jdwp.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""
	);
		}

		public override string to_string () {
			return "ClassPrepareEvent(request: %s, thread: %s, ref_type: %s, signature: \"%s\", status: %s)".printf (
				request.to_string (),
				thread.to_string (),
				ref_type.to_string (),
				signature,
				status.to_short_string ()
			);
		}

		internal static ClassPrepareEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var ref_type = packet.read_tagged_reference_type_id ();
			var signature = packet.read_utf8_string ();
			var status = (ClassStatus) packet.read_int32 ();
			return new ClassPrepareEvent (request, thread, ref_type, signature, status);
		}
	}

	public class ClassUnloadEvent : Event {
		public string signature {
			get;
			construct;
		}

		public ClassUnloadEvent (EventRequestID request, string signature) {
			GLib.Object (
				kind: EventKind.CLASS_UNLOAD,
				request: request,
				signature: signature
			);
		}

		public override string to_string () {
			return "ClassUnloadEvent(request: %s, signature: \"%s\")".printf (request.to_string (), signature);
		}

		internal static ClassUnloadEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var signature = packet.read_utf8_string ();
			return new ClassUnloadEvent (request, signature);
		}
	}

	public class ClassLoadEvent : Event {
		public override string to_string () {
			return "ClassLoadEvent()";
		}

		internal static ClassLoadEvent deserialize (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("CLASS_LOAD event not supported");
		}
	}

	public abstract class FieldEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}

		public TaggedReferenceTypeID ref_type {
			get;
			construct;
		}

		public FieldID field {
			get;
			construct;
		}

		public TaggedObjectID object {
			get;
			construct;
		}
	}

	public class FieldAccessEvent : FieldEvent {
		public FieldAccessEvent (EventRequestID request, ThreadID thread, Location location, TaggedReferenceTypeID ref_type,
				FieldID field, TaggedObjectID object) {
			GLib.Object (
				kind: EventKind.FIELD_ACCESS,
				request: request,
				thread: thread,
				location: location,
				ref_type: ref_type,
				field: field,
				object: object
			);
		}

		public override string to_string () {
			return "FieldAccessEvent(request: %s, thread: %s, location: %s, ref_type: %s, field: %s, object: %s)".printf (
				request.to_string (),
				thread.to_string (),
				location.to_string (),
				ref_type.to_string (),
				field.to_string (),
				object.to_string ()
			);
		}

		internal static FieldAccessEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var location = Location.deserialize (packet);
			var ref_type = packet.read_tagged_reference_type_id ();
			var field = packet.read_field_id ();
			var object = packet.read_tagged_object_id ();
			return new FieldAccessEvent (request, thread, location, ref_type, field, object);
		}
	}

	public class FieldModificationEvent : FieldEvent {
		public Value value_to_be {
			get;
			construct;
		}

		public FieldModificationEvent (EventRequestID request, ThreadID thread, Location location, TaggedReferenceTypeID ref_type,
				FieldID field, TaggedObjectID object, Value value_to_be) {
			GLib.Object (
				kind: EventKind.FIELD_MODIFICATION,
				request: request,
				thread: thread,
				location: location,
				ref_type: ref_type,
				field: field,
				object: object,
				value_to_be: value_to_be
			);
		}

		public override string to_string () {
			return ("FieldModificationEvent(request: %s, thread: %s, location: %s, ref_type: %s, field: %s, object: %s, " +
					"value_to_be: %s)").printf (
				request.to_string (),
				thread.to_string (),
				location.to_string (),
				ref_type.to_string (),
				field.to_string (),
				object.to_string (),
				value_to_be.to_string ()
			);
		}

		internal static FieldModificationEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var location = Location.deserialize (packet);
			var ref_type = packet.read_tagged_reference_type_id ();
			var field = packet.read_field_id ();
			var object = packet.read_tagged_object_id ();
			var value_to_be = packet.read_value ();
			return new FieldModificationEvent (request, thread, location, ref_type, field, object, value_to_be);
		}
	}

	public class ExceptionCatchEvent : Event {
		public override string to_string () {
			return "ExceptionCatchEvent()";
		}

		internal static ExceptionCatchEvent deserialize (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("EXCEPTION_CATCH event not supported");
		}
	}

	public abstract class MethodEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}
	}

	public class MethodEntryEvent : MethodEvent {
		public MethodEntryEvent (EventRequestID request, ThreadID thread, Location location) {
			GLib.Object (
				kind: EventKind.METHOD_ENTRY,
				request: request,
				thread: thread,
				location: location
			);
		}

		public override string to_string () {
			return "MethodEntryEvent(request: %s, thread: %s, location: %s)".printf (
				request.to_string (),
				thread.to_string (),
				location.to_string ()
			);
		}

		internal static MethodEntryEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var location = Location.deserialize (packet);
			return new MethodEntryEvent (request, thread, location);
		}
	}

	public class MethodExitEvent : MethodEvent {
		public MethodExitEvent (EventRequestID request, ThreadID thread, Location location) {
			GLib.Object (
				kind: EventKind.METHOD_EXIT,
				request: request,
				thread: thread,
				location: location
			);
		}

		public override string to_string () {
			return "MethodExitEvent(request: %s, thread: %s, location: %s)".printf (
				request.to_string (),
				thread.to_string (),
				location.to_string ()
			);
		}

		internal static MethodExitEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var location = Location.deserialize (packet);
			return new MethodExitEvent (request, thread, location);
		}
	}

	public class MethodExitWithReturnValueEvent : MethodEvent {
		public Value retval {
			get;
			construct;
		}

		public MethodExitWithReturnValueEvent (EventRequestID request, ThreadID thread, Location location, Value retval) {
			GLib.Object (
				kind: EventKind.METHOD_EXIT_WITH_RETURN_VALUE,
				request: request,
				thread: thread,
				location: location,
				retval: retval
			);
		}

		public override string to_string () {
			return "MethodExitWithReturnValueEvent(request: %s, thread: %s, location: %s, retval: %s)".printf (
				request.to_string (),
				thread.to_string (),
				location.to_string (),
				retval.to_string ()
			);
		}

		internal static MethodExitWithReturnValueEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var location = Location.deserialize (packet);
			var retval = packet.read_value ();
			return new MethodExitWithReturnValueEvent (request, thread, location, retval);
		}
	}

	public abstract class MonitorEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public TaggedObjectID object {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}
	}

	public class MonitorContendedEnterEvent : MonitorEvent {
		public MonitorContendedEnterEvent (EventRequestID request, ThreadID thread, TaggedObjectID object, Location location) {
			GLib.Object (
				kind: EventKind.MONITOR_CONTENDED_ENTER,
				request: request,
				thread: thread,
				object: object,
				location: location
			);
		}

		public override string to_string () {
			return "MonitorContendedEnterEvent(request: %s, thread: %s, object: %s, location: %s)".printf (
				request.to_string (),
				thread.to_string (),
				object.to_string (),
				location.to_string ()
			);
		}

		internal static MonitorContendedEnterEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var object = packet.read_tagged_object_id ();
			var location = Location.deserialize (packet);
			return new MonitorContendedEnterEvent (request, thread, object, location);
		}
	}

	public class MonitorContendedEnteredEvent : MonitorEvent {
		public MonitorContendedEnteredEvent (EventRequestID request, ThreadID thread, TaggedObjectID object, Location location) {
			GLib.Object (
				kind: EventKind.MONITOR_CONTENDED_ENTERED,
				request: request,
				thread: thread,
				object: object,
				location: location
			);
		}

		public override string to_string () {
			return "MonitorContendedEnteredEvent(request: %s, thread: %s, object: %s, location: %s)".printf (
				request.to_string (),
				thread.to_string (),
				object.to_string (),
				location.to_string ()
			);
		}

		internal static MonitorContendedEnteredEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var object = packet.read_tagged_object_id ();
			var location = Location.deserialize (packet);
			return new MonitorContendedEnteredEvent (request, thread, object, location);
		}
	}

	public class MonitorWaitEvent : MonitorEvent {
		public int64 timeout {
			get;
			construct;
		}

		public MonitorWaitEvent (EventRequestID request, ThreadID thread, TaggedObjectID object, Location location, int64 timeout) {
			GLib.Object (
				kind: EventKind.MONITOR_CONTENDED_ENTER,
				request: request,
				thread: thread,
				object: object,
				location: location,
				timeout: timeout
			);
		}

		public override string to_string () {
			return ("MonitorWaitEvent(request: %s, thread: %s, object: %s, location: %s, timeout=%s)").printf (
				request.to_string (),
				thread.to_string (),
				object.to_string (),
				location.to_string (),
				timeout.to_string ()
			);
		}

		internal static MonitorWaitEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var object = packet.read_tagged_object_id ();
			var location = Location.deserialize (packet);
			var timeout = packet.read_int64 ();
			return new MonitorWaitEvent (request, thread, object, location, timeout);
		}
	}

	public class MonitorWaitedEvent : MonitorEvent {
		public bool timed_out {
			get;
			construct;
		}

		public MonitorWaitedEvent (EventRequestID request, ThreadID thread, TaggedObjectID object, Location location,
				bool timed_out) {
			GLib.Object (
				kind: EventKind.MONITOR_CONTENDED_ENTER,
				request: request,
				thread: thread,
				object: object,
				location: location,
				timed_out: timed_out
			);
		}

		public override string to_string () {
			return ("MonitorWaitedEvent(request: %s, thread: %s, object: %s, location: %s, timed_out=%s)").printf (
				request.to_string (),
				thread.to_string (),
				object.to_string (),
				location.to_string (),
				timed_out.to_string ()
			);
		}

		internal static MonitorWaitedEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			var object = packet.read_tagged_object_id ();
			var location = Location.deserialize (packet);
			var timed_out = packet.read_boolean ();
			return new MonitorWaitedEvent (request, thread, object, location, timed_out);
		}
	}

	public class VMStartEvent : Event {
		public ThreadID thread {
			get;
			construct;
		}

		public VMStartEvent (EventRequestID request, ThreadID thread) {
			GLib.Object (
				kind: EventKind.VM_START,
				request: request,
				thread: thread
			);
		}

		public override string to_string () {
			return "VMStartEvent(request: %s, thread: %s)".printf (request.to_string (), thread.to_string ());
		}

		internal static VMStartEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			var thread = packet.read_thread_id ();
			return new VMStartEvent (request, thread);
		}
	}

	public class VMDeathEvent : Event {
		public VMDeathEvent (EventRequestID request) {
			GLib.Object (kind: EventKind.VM_DEATH, request: request);
		}

		public override string to_string () {
			return "VMDeathEvent(request: %s)".printf (request.to_string ());
		}

		internal static VMDeathEvent deserialize (PacketReader packet) throws Error {
			var request = EventRequestID (packet.read_int32 ());
			return new VMDeathEvent (request);
		}
	}

	public class VMDisconnectedEvent : Event {
		public override string to_string () {
			return "VMDisconnectedEvent()";
		}

		internal static VMDisconnectedEvent deserialize (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("VM_DISCONNECTED event not supported");
		}
	}

	public abstract class EventModifier : GLib.Object {
		internal abstract void serialize (PacketBuilder builder);
	}

	public class CountModifier : EventModifier {
		public int32 count {
			get;
			construct;
		}

		public CountModifier (int32 count) {
			GLib.Object (count: count);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.COUNT)
				.append_int32 (count);
		}
	}

	public class ThreadOnlyModifier : EventModifier {
		public ThreadID thread {
			get;
			construct;
		}

		public ThreadOnlyModifier (ThreadID thread) {
			GLib.Object (thread: thread);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.THREAD_ONLY)
				.append_thread_id (thread);
		}
	}

	public class ClassOnlyModifier : EventModifier {
		public ReferenceTypeID clazz {
			get;
			construct;
		}

		public ClassOnlyModifier (ReferenceTypeID clazz) {
			GLib.Object (clazz: clazz);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.CLASS_ONLY)
				.append_reference_type_id (clazz);
		}
	}

	public class ClassMatchModifier : EventModifier {
		public string class_pattern {
			get;
			construct;
		}

		public ClassMatchModifier (string class_pattern) {
			GLib.Object (class_pattern: class_pattern);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.CLASS_MATCH)
				.append_utf8_string (class_pattern);
		}
	}

	public class ClassExcludeModifier : EventModifier {
		public string class_pattern {
			get;
			construct;
		}

		public ClassExcludeModifier (string class_pattern) {
			GLib.Object (class_pattern: class_pattern);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.CLASS_EXCLUDE)
				.append_utf8_string (class_pattern);
		}
	}

	public class LocationOnlyModifier : EventModifier {
		public Location location {
			get;
			construct;
		}

		public LocationOnlyModifier (TaggedReferenceTypeID declaring, MethodID method, uint64 index = 0) {
			GLib.Object (location: new Location (declaring, method, index));
		}

		internal override void serialize (PacketBuilder builder) {
			builder.append_uint8 (EventModifierKind.LOCATION_ONLY);
			location.serialize (builder);
		}
	}

	public class ExceptionOnlyModifier : EventModifier {
		public ReferenceTypeID exception_or_null {
			get;
			construct;
		}

		public bool caught {
			get;
			construct;
		}

		public bool uncaught {
			get;
			construct;
		}

		public ExceptionOnlyModifier (ReferenceTypeID exception_or_null, bool caught, bool uncaught) {
			GLib.Object (
				exception_or_null: exception_or_null,
				caught: caught,
				uncaught: uncaught
			);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.EXCEPTION_ONLY)
				.append_reference_type_id (exception_or_null)
				.append_boolean (caught)
				.append_boolean (uncaught);
		}
	}

	public class FieldOnlyModifier : EventModifier {
		public ReferenceTypeID declaring {
			get;
			construct;
		}

		public FieldID field {
			get;
			construct;
		}

		public FieldOnlyModifier (ReferenceTypeID declaring, FieldID field) {
			GLib.Object (
				declaring: declaring,
				field: field
			);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.FIELD_ONLY)
				.append_reference_type_id (declaring)
				.append_field_id (field);
		}
	}

	public class StepModifier : EventModifier {
		public ThreadID thread {
			get;
			construct;
		}

		public StepSize step_size {
			get;
			construct;
		}

		public StepDepth step_depth {
			get;
			construct;
		}

		public StepModifier (ThreadID thread, StepSize step_size, StepDepth step_depth) {
			GLib.Object (
				thread: thread,
				step_size: step_size,
				step_depth: step_depth
			);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.STEP)
				.append_thread_id (thread)
				.append_int32 (step_size)
				.append_int32 (step_depth);
		}
	}

	public enum StepSize {
		MIN  = 0,
		LINE = 1,
	}

	public enum StepDepth {
		INTO = 0,
		OVER = 1,
		OUT  = 2,
	}

	public class InstanceOnlyModifier : EventModifier {
		public ObjectID instance {
			get;
			construct;
		}

		public InstanceOnlyModifier (ObjectID instance) {
			GLib.Object (instance: instance);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.INSTANCE_ONLY)
				.append_object_id (instance);
		}
	}

	public class SourceNameMatchModifier : EventModifier {
		public string source_name_pattern {
			get;
			construct;
		}

		public SourceNameMatchModifier (string source_name_pattern) {
			GLib.Object (source_name_pattern: source_name_pattern);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.SOURCE_NAME_MATCH)
				.append_utf8_string (source_name_pattern);
		}
	}

	private enum EventModifierKind {
		COUNT             = 1,
		THREAD_ONLY       = 3,
		CLASS_ONLY        = 4,
		CLASS_MATCH       = 5,
		CLASS_EXCLUDE     = 6,
		LOCATION_ONLY     = 7,
		EXCEPTION_ONLY    = 8,
		FIELD_ONLY        = 9,
		STEP              = 10,
		INSTANCE_ONLY     = 11,
		SOURCE_NAME_MATCH = 12,
	}

	public struct EventRequestID {
		public int32 handle {
			get;
			private set;
		}

		public EventRequestID (int32 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return handle.to_string ();
		}
	}

	private enum CommandSet {
		VM               = 1,
		REFERENCE_TYPE   = 2,
		CLASS_TYPE       = 3,
		INTERFACE_TYPE   = 5,
		OBJECT_REFERENCE = 9,
		STRING_REFERENCE = 10,
		EVENT_REQUEST    = 15,
		EVENT            = 64,
	}

	private enum VMCommand {
		CLASSES_BY_SIGNATURE = 2,
		ID_SIZES             = 7,
		SUSPEND              = 8,
		RESUME               = 9,
		CREATE_STRING        = 11,
	}

	private enum ReferenceTypeCommand {
		METHODS = 5,
	}

	private enum ClassTypeCommand {
		INVOKE_METHOD = 3,
	}

	private enum InterfaceTypeCommand {
		INVOKE_METHOD = 1,
	}

	private enum ObjectReferenceCommand {
		INVOKE_METHOD = 6,
	}

	private enum StringReferenceCommand {
		VALUE = 1,
	}

	private enum EventRequestCommand {
		SET                   = 1,
		CLEAR                 = 2,
		CLEAR_ALL_BREAKPOINTS = 3,
	}

	private enum EventCommand {
		COMPOSITE = 100,
	}

	[Flags]
	private enum PacketFlags {
		REPLY = (1 << 7),
	}

	private class CommandBuilder : PacketBuilder {
		public CommandBuilder (uint32 id, CommandSet command_set, uint8 command, IDSizes id_sizes) {
			base (id, 0, id_sizes);

			append_uint8 (command_set);
			append_uint8 (command);
		}
	}

	private class PacketBuilder {
		public uint32 id {
			get;
			private set;
		}

		public size_t offset {
			get {
				return cursor;
			}
		}

		private ByteArray buffer = new ByteArray.sized (64);
		private size_t cursor = 0;

		private IDSizes id_sizes;

		public PacketBuilder (uint32 id, uint8 flags, IDSizes id_sizes) {
			this.id = id;
			this.id_sizes = id_sizes;

			uint32 length_placeholder = 0;
			append_uint32 (length_placeholder);
			append_uint32 (id);
			append_uint8 (flags);
		}

		public unowned PacketBuilder append_uint8 (uint8 val) {
			*(get_pointer (cursor, sizeof (uint8))) = val;
			cursor += (uint) sizeof (uint8);
			return this;
		}

		public unowned PacketBuilder append_int16 (int16 val) {
			*(get_pointer (cursor, sizeof (int16))) = val.to_big_endian ();
			cursor += (uint) sizeof (int16);
			return this;
		}

		public unowned PacketBuilder append_uint16 (uint16 val) {
			*(get_pointer (cursor, sizeof (uint16))) = val.to_big_endian ();
			cursor += (uint) sizeof (uint16);
			return this;
		}

		public unowned PacketBuilder append_int32 (int32 val) {
			*((int32 *) get_pointer (cursor, sizeof (int32))) = val.to_big_endian ();
			cursor += (uint) sizeof (int32);
			return this;
		}

		public unowned PacketBuilder append_uint32 (uint32 val) {
			*((uint32 *) get_pointer (cursor, sizeof (uint32))) = val.to_big_endian ();
			cursor += (uint) sizeof (uint32);
			return this;
		}

		public unowned PacketBuilder append_int64 (int64 val) {
			*((int64 *) get_pointer (cursor, sizeof (int64))) = val.to_big_endian ();
			cursor += (uint) sizeof (int64);
			return this;
		}

		public unowned PacketBuilder append_uint64 (uint64 val) {
			*((uint64 *) get_pointer (cursor, sizeof (uint64))) = val.to_big_endian ();
			cursor += (uint) sizeof (uint64);
			return this;
		}

		public unowned PacketBuilder append_double (double val) {
			var bits = (uint64 *) &val;
			return append_uint64 (*bits);
		}

		public unowned PacketBuilder append_float (float val) {
			var bits = (uint32 *) &val;
			return append_uint32 (*bits);
		}

		public unowned PacketBuilder append_boolean (bool val) {
			return append_uint8 ((uint8) val);
		}

		public unowned PacketBuilder append_utf8_string (string str) {
			append_uint32 (str.length);

			uint size = str.length;
			Memory.copy (get_pointer (cursor, size), str, size);
			cursor += size;

			return this;
		}

		public unowned PacketBuilder append_value (Value v) {
			append_uint8 (v.tag);

			switch (v.tag) {
				case BYTE:
					append_uint8 (((Byte) v).val);
					break;
				case CHAR: {
					string16 s;
					try {
						s = ((Char) v).val.to_utf16 ();
					} catch (ConvertError e) {
						assert_not_reached ();
					}
					var c = (uint16 *) s;
					append_uint16 (*c);
					break;
				}
				case DOUBLE:
					append_double (((Double) v).val);
					break;
				case FLOAT:
					append_float (((Float) v).val);
					break;
				case INT:
					append_int32 (((Int) v).val);
					break;
				case LONG:
					append_int64 (((Long) v).val);
					break;
				case OBJECT:
				case ARRAY:
				case CLASS_OBJECT:
				case THREAD_GROUP:
				case CLASS_LOADER:
				case STRING:
				case THREAD:
					append_object_id (((Object) v).val);
					break;
				case SHORT:
					append_int16 (((Short) v).val);
					break;
				case VOID:
					break;
				case BOOLEAN:
					append_boolean (((Boolean) v).val);
					break;
			}

			return this;
		}

		public unowned PacketBuilder append_object_id (ObjectID object) {
			return append_handle (object.handle, id_sizes.get_object_id_size_or_die ());
		}

		public unowned PacketBuilder append_thread_id (ThreadID thread) {
			return append_handle (thread.handle, id_sizes.get_object_id_size_or_die ());
		}

		public unowned PacketBuilder append_reference_type_id (ReferenceTypeID type) {
			return append_handle (type.handle, id_sizes.get_reference_type_id_size_or_die ());
		}

		public unowned PacketBuilder append_tagged_reference_type_id (TaggedReferenceTypeID ref_type) {
			return this
				.append_uint8 (ref_type.tag)
				.append_reference_type_id (ref_type.id);
		}

		public unowned PacketBuilder append_method_id (MethodID method) {
			return append_handle (method.handle, id_sizes.get_method_id_size_or_die ());
		}

		public unowned PacketBuilder append_field_id (FieldID field) {
			return append_handle (field.handle, id_sizes.get_field_id_size_or_die ());
		}

		private unowned PacketBuilder append_handle (int64 val, size_t size) {
			switch (size) {
				case 4:
					return append_int32 ((int32) val);
				case 8:
					return append_int64 (val);
				default:
					assert_not_reached ();
			}
		}

		private uint8 * get_pointer (size_t offset, size_t n) {
			size_t minimum_size = offset + n;
			if (buffer.len < minimum_size)
				buffer.set_size ((uint) minimum_size);

			return (uint8 *) buffer.data + offset;
		}

		public Bytes build () {
			*((uint32 *) get_pointer (0, sizeof (uint32))) = buffer.len.to_big_endian ();
			return ByteArray.free_to_bytes ((owned) buffer);
		}
	}

	private class PacketReader {
		public size_t available_bytes {
			get {
				return end - cursor;
			}
		}

		private uint8[] data;
		private uint8 * cursor;
		private uint8 * end;

		private IDSizes id_sizes;

		public PacketReader (owned uint8[] data, IDSizes id_sizes) {
			this.data = (owned) data;
			this.cursor = (uint8 *) this.data;
			this.end = cursor + this.data.length;

			this.id_sizes = id_sizes;
		}

		public void skip (size_t n) throws Error {
			check_available (n);
			cursor += n;
		}

		public uint8 read_uint8 () throws Error {
			const size_t n = sizeof (uint8);
			check_available (n);

			uint8 val = *cursor;
			cursor += n;

			return val;
		}

		public int16 read_int16 () throws Error {
			const size_t n = sizeof (int16);
			check_available (n);

			int16 val = int16.from_big_endian (*((int16 *) cursor));
			cursor += n;

			return val;
		}

		public uint16 read_uint16 () throws Error {
			const size_t n = sizeof (uint16);
			check_available (n);

			uint16 val = uint16.from_big_endian (*((uint16 *) cursor));
			cursor += n;

			return val;
		}

		public int32 read_int32 () throws Error {
			const size_t n = sizeof (int32);
			check_available (n);

			int32 val = int32.from_big_endian (*((int32 *) cursor));
			cursor += n;

			return val;
		}

		public uint32 read_uint32 () throws Error {
			const size_t n = sizeof (uint32);
			check_available (n);

			uint32 val = uint32.from_big_endian (*((uint32 *) cursor));
			cursor += n;

			return val;
		}

		public int64 read_int64 () throws Error {
			const size_t n = sizeof (int64);
			check_available (n);

			int64 val = int64.from_big_endian (*((int64 *) cursor));
			cursor += n;

			return val;
		}

		public uint64 read_uint64 () throws Error {
			const size_t n = sizeof (uint64);
			check_available (n);

			uint64 val = uint64.from_big_endian (*((uint64 *) cursor));
			cursor += n;

			return val;
		}

		public double read_double () throws Error {
			var bits = read_uint64 ();
			var val = (double *) &bits;
			return *val;
		}

		public float read_float () throws Error {
			var bits = read_uint32 ();
			var val = (float *) &bits;
			return *val;
		}

		public bool read_boolean () throws Error {
			return (bool) read_uint8 ();
		}

		public string read_utf8_string () throws Error {
			size_t size = read_uint32 ();
			check_available (size);

			unowned string data = (string) cursor;
			string str = data.substring (0, (long) size);
			cursor += size;

			return str;
		}

		public Value read_value () throws Error {
			var tag = (ValueTag) read_uint8 ();

			switch (tag) {
				case BYTE:
					return new Byte (read_uint8 ());
				case CHAR: {
					uint16 c = read_uint16 ();
					var s = (string16 *) &c;
					try {
						return new Char (s->to_utf8 (1));
					} catch (ConvertError e) {
						throw new Error.PROTOCOL ("%s", e.message);
					}
				}
				case DOUBLE:
					return new Double (read_double ());
				case FLOAT:
					return new Float (read_float ());
				case INT:
					return new Int (read_int32 ());
				case LONG:
					return new Long (read_int64 ());
				case OBJECT:
					return new Object (read_object_id ());
				case SHORT:
					return new Short (read_int16 ());
				case VOID:
					return new Void ();
				case BOOLEAN:
					return new Boolean (read_boolean ());
				case ARRAY:
					return new Array (read_object_id ());
				case CLASS_OBJECT:
					return new ClassObject (read_object_id ());
				case THREAD_GROUP:
					return new ThreadGroup (read_object_id ());
				case CLASS_LOADER:
					return new ClassLoader (read_object_id ());
				case STRING:
					return new String (read_object_id ());
				case THREAD:
					return new Thread (read_object_id ());
			}

			throw new Error.PROTOCOL ("Unexpected value tag");
		}

		public ObjectID read_object_id () throws Error {
			return ObjectID (read_handle (id_sizes.get_object_id_size ()));
		}

		public TaggedObjectID read_tagged_object_id () throws Error {
			var tag = (TypeTag) read_uint8 ();
			var id = read_object_id ();
			return TaggedObjectID (tag, id);
		}

		public ThreadID read_thread_id () throws Error {
			return ThreadID (read_handle (id_sizes.get_object_id_size ()));
		}

		public ReferenceTypeID read_reference_type_id () throws Error {
			return ReferenceTypeID (read_handle (id_sizes.get_reference_type_id_size ()));
		}

		public TaggedReferenceTypeID read_tagged_reference_type_id () throws Error {
			var tag = (TypeTag) read_uint8 ();
			var id = read_reference_type_id ();
			return TaggedReferenceTypeID (tag, id);
		}

		public MethodID read_method_id () throws Error {
			return MethodID (read_handle (id_sizes.get_method_id_size ()));
		}

		public FieldID read_field_id () throws Error {
			return FieldID (read_handle (id_sizes.get_field_id_size ()));
		}

		private int64 read_handle (size_t size) throws Error {
			switch (size) {
				case 4:
					return read_int32 ();
				case 8:
					return read_int64 ();
				default:
					assert_not_reached ();
			}
		}

		private void check_available (size_t n) throws Error {
			if (cursor + n > end)
				throw new Error.PROTOCOL ("Invalid JDWP packet");
		}
	}

	private class IDSizes {
		private bool valid;
		private int field_id_size = -1;
		private int method_id_size = -1;
		private int object_id_size = -1;
		private int reference_type_id_size = -1;
		private int frame_id_size = -1;

		public IDSizes (int field_id_size, int method_id_size, int object_id_size, int reference_type_id_size, int frame_id_size) {
			this.field_id_size = field_id_size;
			this.method_id_size = method_id_size;
			this.object_id_size = object_id_size;
			this.reference_type_id_size = reference_type_id_size;
			this.frame_id_size = frame_id_size;

			valid = true;
		}

		public IDSizes.unknown () {
			valid = false;
		}

		public size_t get_field_id_size () throws Error {
			check ();
			return field_id_size;
		}

		public size_t get_field_id_size_or_die () {
			assert (valid);
			return field_id_size;
		}

		public size_t get_method_id_size () throws Error {
			check ();
			return method_id_size;
		}

		public size_t get_method_id_size_or_die () {
			assert (valid);
			return method_id_size;
		}

		public size_t get_object_id_size () throws Error {
			check ();
			return object_id_size;
		}

		public size_t get_object_id_size_or_die () {
			assert (valid);
			return object_id_size;
		}

		public size_t get_reference_type_id_size () throws Error {
			check ();
			return reference_type_id_size;
		}

		public size_t get_reference_type_id_size_or_die () {
			assert (valid);
			return reference_type_id_size;
		}

		private void check () throws Error {
			if (!valid)
				throw new Error.PROTOCOL ("ID sizes not known");
		}

		internal static IDSizes deserialize (PacketReader packet) throws Error {
			var field_id_size = packet.read_int32 ();
			var method_id_size = packet.read_int32 ();
			var object_id_size = packet.read_int32 ();
			var reference_type_id_size = packet.read_int32 ();
			var frame_id_size = packet.read_int32 ();
			return new IDSizes (field_id_size, method_id_size, object_id_size, reference_type_id_size, frame_id_size);
		}
	}
}

"""


```