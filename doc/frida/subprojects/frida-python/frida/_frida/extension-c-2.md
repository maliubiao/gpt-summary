Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of the Frida dynamic instrumentation tool.

Here's a breakdown of how to address each point in the request:

1. **List the functionalities:**  Analyze the code to identify the core actions and data structures it manipulates. Focus on the exposed functions and the objects they operate on.

2. **Relationship to reverse engineering:** Connect the identified functionalities to common reverse engineering tasks. Consider how these functions can be used to inspect and modify program behavior.

3. **Involvement of low-level concepts:** Look for interactions with operating system primitives, kernel concepts, and architectural details. Keywords like "process", "spawn", "memory", "threads" are good indicators.

4. **Logical reasoning with input/output:** For functions that perform transformations or decisions, devise hypothetical inputs and predict the outputs based on the code's logic.

5. **Common usage errors:** Identify potential mistakes a user could make when calling these functions from the Python API. Think about type mismatches, incorrect parameters, or misunderstanding the function's purpose.

6. **User operation leading to the code:** Trace back how a user's actions in the Frida Python API would eventually call the C functions in this file.

7. **Overall functionality summary:** Condense the findings into a concise summary of the file's purpose within the Frida ecosystem.

**Detailed analysis of the code snippet:**

* **Object Handling:** The code heavily uses the GObject system for managing objects like `DeviceManager`, `Device`, `Application`, `Process`, `Spawn`, and `Child`. Functions like `PyGObject_new_take_handle`, `PyGObject_steal_handle`, `g_object_ref`, and `g_object_unref` are central to this.

* **Device Management:** The `PyDeviceManager_*` functions clearly relate to managing devices that Frida can interact with. This includes:
    * Creating and closing a device manager (`PyDeviceManager_init`, `PyDeviceManager_dealloc`, `PyDeviceManager_close`).
    * Getting a specific device (`PyDeviceManager_get_device_matching`).
    * Enumerating all available devices (`PyDeviceManager_enumerate_devices`).
    * Adding and removing remote devices (`PyDeviceManager_add_remote_device`, `PyDeviceManager_remove_remote_device`).

* **Device Interaction:** The `PyDevice_*` functions deal with interacting with a specific device:
    * Getting device information (ID, name, type - these are initialized in `PyDevice_init_from_handle`).
    * Checking if a device is lost (`PyDevice_is_lost`).
    * Querying system parameters (`PyDevice_query_system_parameters`).
    * Working with applications (`PyDevice_get_frontmost_application`, `PyDevice_enumerate_applications`).
    * Working with processes (`PyDevice_enumerate_processes`).
    * Managing spawn gating (`PyDevice_enable_spawn_gating`, `PyDevice_disable_spawn_gating`, `PyDevice_enumerate_pending_spawn`).
    * Managing child processes (`PyDevice_enumerate_pending_children`).
    * Spawning new processes (`PyDevice_spawn`).
    * Sending input to a process (`PyDevice_input`).
    * Resuming and killing processes (`PyDevice_resume`, `PyDevice_kill`).
    * Attaching to a process (`PyDevice_attach`).
    * Injecting libraries (`PyDevice_inject_library_file`, `PyDevice_inject_library_blob`).
    * Opening channels and services (`PyDevice_open_channel`, `PyDevice_open_service`).
    * Unpairing a device (`PyDevice_unpair`).

* **Data Marshaling:**  The code includes functions to convert between Python objects and the underlying GObject/GLib types (e.g., `PyGObject_marshal_variant`, `PyGObject_unmarshal_string`). This is crucial for the Python API to interact with the C backend.

* **Error Handling:**  The code uses `GError` for error reporting and includes functions like `PyFrida_raise` to propagate these errors back to the Python layer.

* **Threading:** The `Py_BEGIN_ALLOW_THREADS` and `Py_END_ALLOW_THREADS` macros indicate that Frida performs potentially blocking operations in separate threads to avoid freezing the Python interpreter.

**Planning the response structure:**

Organize the answer into the requested sections: functionalities, relationship to reverse engineering, low-level concepts, logical reasoning, user errors, user operations, and summary. Provide specific examples and details for each point.
```c
    {
        Py_IncRef (Py_None);
        result = Py_None;
        break;
      }
    }
  }

  if (result == NULL)
    result = PyGObject_new_take_handle (g_object_ref (address), PYFRIDA_TYPE (GObject));

  return result;
}

static gboolean
PyGObject_unmarshal_certificate (const gchar * str, GTlsCertificate ** certificate)
{
  GError * error = NULL;

  if (strchr (str, '\n') != NULL)
    *certificate = g_tls_certificate_new_from_pem (str, -1, &error);
  else
    *certificate = g_tls_certificate_new_from_file (str, &error);
  if (error != NULL)
    goto propagate_error;

  return TRUE;

propagate_error:
  {
    PyFrida_raise (g_error_new_literal (FRIDA_ERROR, FRIDA_ERROR_INVALID_ARGUMENT, error->message));
    g_error_free (error);

    return FALSE;
  }
}

static int
PyDeviceManager_init (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  g_atomic_int_inc (&toplevel_objects_alive);

  PyGObject_take_handle (&self->parent, frida_device_manager_new (), PYFRIDA_TYPE (DeviceManager));

  return 0;
}

static void
PyDeviceManager_dealloc (PyDeviceManager * self)
{
  FridaDeviceManager * handle;

  g_atomic_int_dec_and_test (&toplevel_objects_alive);

  handle = PyGObject_steal_handle (&self->parent);
  if (handle != NULL)
  {
    Py_BEGIN_ALLOW_THREADS
    frida_device_manager_close_sync (handle, NULL, NULL);
    frida_unref (handle);
    Py_END_ALLOW_THREADS
  }

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyDeviceManager_close (PyDeviceManager * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_manager_close_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDeviceManager_get_device_matching (PyDeviceManager * self, PyObject * args)
{
  PyObject * predicate;
  gint timeout;
  GError * error = NULL;
  FridaDevice * result;

  if (!PyArg_ParseTuple (args, "Oi", &predicate, &timeout))
    return NULL;

  if (!PyCallable_Check (predicate))
    goto not_callable;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_manager_get_device_sync (PY_GOBJECT_HANDLE (self), (FridaDeviceManagerPredicate) PyDeviceManager_is_matching_device,
      predicate, timeout, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PyDevice_new_take_handle (result);

not_callable:
  {
    PyErr_SetString (PyExc_TypeError, "object must be callable");
    return NULL;
  }
}

static gboolean
PyDeviceManager_is_matching_device (FridaDevice * device, PyObject * predicate)
{
  gboolean is_matching = FALSE;
  PyGILState_STATE gstate;
  PyObject * device_object, * result;

  gstate = PyGILState_Ensure ();

  device_object = PyDevice_new_take_handle (g_object_ref (device));

  result = PyObject_CallFunction (predicate, "O", device_object);
  if (result != NULL)
  {
    is_matching = result == Py_True;

    Py_DecRef (result);
  }
  else
  {
    PyErr_Print ();
  }

  Py_DecRef (device_object);

  PyGILState_Release (gstate);

  return is_matching;
}

static PyObject *
PyDeviceManager_enumerate_devices (PyDeviceManager * self)
{
  GError * error = NULL;
  FridaDeviceList * result;
  gint result_length, i;
  PyObject * devices;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_manager_enumerate_devices_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_device_list_size (result);
  devices = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (devices, i, PyDevice_new_take_handle (frida_device_list_get (result, i)));
  }
  frida_unref (result);

  return devices;
}

static PyObject *
PyDeviceManager_add_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "address", "certificate", "origin", "token", "keepalive_interval", NULL };
  char * address;
  char * certificate = NULL;
  char * origin = NULL;
  char * token = NULL;
  int keepalive_interval = -1;
  FridaRemoteDeviceOptions * options;
  GError * error = NULL;
  FridaDevice * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esesesi", keywords,
        "utf-8", &address,
        "utf-8", &certificate,
        "utf-8", &origin,
        "utf-8", &token,
        &keepalive_interval))
    return NULL;

  options = PyDeviceManager_parse_remote_device_options (certificate, origin, token, keepalive_interval);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_device_manager_add_remote_device_sync (PY_GOBJECT_HANDLE (self), address, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PyDevice_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);

  PyMem_Free (token);
  PyMem_Free (origin);
  PyMem_Free (certificate);
  PyMem_Free (address);

  return result;
}

static PyObject *
PyDeviceManager_remove_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "address", NULL };
  char * address;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es", keywords, "utf-8", &address))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_manager_remove_remote_device_sync (PY_GOBJECT_HANDLE (self), address, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  PyMem_Free (address);

  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static FridaRemoteDeviceOptions *
PyDeviceManager_parse_remote_device_options (const gchar * certificate_value, const gchar * origin, const gchar * token,
    gint keepalive_interval)
{
  FridaRemoteDeviceOptions * options;

  options = frida_remote_device_options_new ();

  if (certificate_value != NULL)
  {
    GTlsCertificate * certificate;

    if (!PyGObject_unmarshal_certificate (certificate_value, &certificate))
      goto propagate_error;

    frida_remote_device_options_set_certificate (options, certificate);

    g_object_unref (certificate);
  }

  if (origin != NULL)
    frida_remote_device_options_set_origin (options, origin);

  if (token != NULL)
    frida_remote_device_options_set_token (options, token);

  if (keepalive_interval != -1)
    frida_remote_device_options_set_keepalive_interval (options, keepalive_interval);

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_new_take_handle (FridaDevice * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Device));
}

static int
PyDevice_init (PyDevice * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->id = NULL;
  self->name = NULL;
  self->icon = NULL;
  self->type = NULL;
  self->bus = NULL;

  return 0;
}

static void
PyDevice_init_from_handle (PyDevice * self, FridaDevice * handle)
{
  GVariant * icon;

  self->id = PyUnicode_FromString (frida_device_get_id (handle));
  self->name = PyUnicode_FromString (frida_device_get_name (handle));
  icon = frida_device_get_icon (handle);
  if (icon != NULL)
  {
    self->icon = PyGObject_marshal_variant (icon);
  }
  else
  {
    self->icon = Py_None;
    Py_IncRef (Py_None);
  }
  self->type = PyGObject_marshal_enum (frida_device_get_dtype (handle), FRIDA_TYPE_DEVICE_TYPE);
  self->bus = PyBus_new_take_handle (g_object_ref (frida_device_get_bus (handle)));
}

static void
PyDevice_dealloc (PyDevice * self)
{
  Py_DecRef (self->bus);
  Py_DecRef (self->type);
  Py_DecRef (self->icon);
  Py_DecRef (self->name);
  Py_DecRef (self->id);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyDevice_repr (PyDevice * self)
{
  PyObject * id_bytes, * name_bytes, * type_bytes, * result;

  id_bytes = PyUnicode_AsUTF8String (self->id);
  name_bytes = PyUnicode_AsUTF8String (self->name);
  type_bytes = PyUnicode_AsUTF8String (self->type);

  result = PyUnicode_FromFormat ("Device(id=\"%s\", name=\"%s\", type='%s')",
      PyBytes_AsString (id_bytes),
      PyBytes_AsString (name_bytes),
      PyBytes_AsString (type_bytes));

  Py_DecRef (type_bytes);
  Py_DecRef (name_bytes);
  Py_DecRef (id_bytes);

  return result;
}

static PyObject *
PyDevice_is_lost (PyDevice * self)
{
  gboolean is_lost;

  Py_BEGIN_ALLOW_THREADS
  is_lost = frida_device_is_lost (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  return PyBool_FromLong (is_lost);
}

static PyObject *
PyDevice_query_system_parameters (PyDevice * self)
{
  GError * error = NULL;
  GHashTable * result;
  PyObject * parameters;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_query_system_parameters_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  parameters = PyGObject_marshal_parameters_dict (result);
  g_hash_table_unref (result);

  return parameters;
}

static PyObject *
PyDevice_get_frontmost_application (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "scope", NULL };
  const char * scope_value = NULL;
  FridaFrontmostQueryOptions * options;
  GError * error = NULL;
  FridaApplication * result;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|s", keywords, &scope_value))
    return NULL;

  options = frida_frontmost_query_options_new ();

  if (scope_value != NULL)
  {
    FridaScope scope;

    if (!PyGObject_unmarshal_enum (scope_value, FRIDA_TYPE_SCOPE, &scope))
      goto invalid_argument;

    frida_frontmost_query_options_set_scope (options, scope);
  }

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_get_frontmost_application_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  if (result != NULL)
    return PyApplication_new_take_handle (result);
  else
    PyFrida_RETURN_NONE;

invalid_argument:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_enumerate_applications (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "identifiers", "scope", NULL };
  PyObject * identifiers = NULL;
  const char * scope = NULL;
  FridaApplicationQueryOptions * options;
  GError * error = NULL;
  FridaApplicationList * result;
  gint result_length, i;
  PyObject * applications;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|Os", keywords, &identifiers, &scope))
    return NULL;

  options = PyDevice_parse_application_query_options (identifiers, scope);
  if (options == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_applications_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_application_list_size (result);
  applications = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (applications, i, PyApplication_new_take_handle (frida_application_list_get (result, i)));
  }
  g_object_unref (result);

  return applications;
}

static FridaApplicationQueryOptions *
PyDevice_parse_application_query_options (PyObject * identifiers_value, const gchar * scope_value)
{
  FridaApplicationQueryOptions * options;

  options = frida_application_query_options_new ();

  if (identifiers_value != NULL)
  {
    gint n, i;

    n = PySequence_Size (identifiers_value);
    if (n == -1)
      goto propagate_error;

    for (i = 0; i != n; i++)
    {
      PyObject * element;
      gchar * identifier = NULL;

      element = PySequence_GetItem (identifiers_value, i);
      if (element == NULL)
        goto propagate_error;
      PyGObject_unmarshal_string (element, &identifier);
      Py_DecRef (element);
      if (identifier == NULL)
        goto propagate_error;

      frida_application_query_options_select_identifier (options, identifier);

      g_free (identifier);
    }
  }

  if (scope_value != NULL)
  {
    FridaScope scope;

    if (!PyGObject_unmarshal_enum (scope_value, FRIDA_TYPE_SCOPE, &scope))
      goto propagate_error;

    frida_application_query_options_set_scope (options, scope);
  }

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_enumerate_processes (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "pids", "scope", NULL };
  PyObject * pids = NULL;
  const char * scope = NULL;
  FridaProcessQueryOptions * options;
  GError * error = NULL;
  FridaProcessList * result;
  gint result_length, i;
  PyObject * processes;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|Os", keywords, &pids, &scope))
    return NULL;

  options = PyDevice_parse_process_query_options (pids, scope);
  if (options == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_processes_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_process_list_size (result);
  processes = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (processes, i, PyProcess_new_take_handle (frida_process_list_get (result, i)));
  }
  g_object_unref (result);

  return processes;
}

static FridaProcessQueryOptions *
PyDevice_parse_process_query_options (PyObject * pids_value, const gchar * scope_value)
{
  FridaProcessQueryOptions * options;

  options = frida_process_query_options_new ();

  if (pids_value != NULL)
  {
    gint n, i;

    n = PySequence_Size (pids_value);
    if (n == -1)
      goto propagate_error;

    for (i = 0; i != n; i++)
    {
      PyObject * element;
      long long pid;

      element = PySequence_GetItem (pids_value, i);
      if (element == NULL)
        goto propagate_error;
      pid = PyLong_AsLongLong (element);
      Py_DecRef (element);
      if (pid == -1)
        goto propagate_error;

      frida_process_query_options_select_pid (options, pid);
    }
  }

  if (scope_value != NULL)
  {
    FridaScope scope;

    if (!PyGObject_unmarshal_enum (scope_value, FRIDA_TYPE_SCOPE, &scope))
      goto propagate_error;

    frida_process_query_options_set_scope (options, scope);
  }

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_enable_spawn_gating (PyDevice * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_enable_spawn_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDevice_disable_spawn_gating (PyDevice * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_disable_spawn_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDevice_enumerate_pending_spawn (PyDevice * self)
{
  GError * error = NULL;
  FridaSpawnList * result;
  gint result_length, i;
  PyObject * spawn;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_pending_spawn_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_spawn_list_size (result);
  spawn = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (spawn, i, PySpawn_new_take_handle (frida_spawn_list_get (result, i)));
  }
  g_object_unref (result);

  return spawn;
}

static PyObject *
PyDevice_enumerate_pending_children (PyDevice * self)
{
  GError * error = NULL;
  FridaChildList * result;
  gint result_length, i;
  PyObject * children;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_pending_children_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_child_list_size (result);
  children = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (children, i, PyChild_new_take_handle (frida_child_list_get (result, i)));
  }
  g_object_unref (result);

  return children;
}

static PyObject *
PyDevice_spawn (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "program", "argv", "envp", "env", "cwd", "stdio", "aux", NULL };
  const char * program;
  PyObject * argv_value = Py_None;
  PyObject * envp_value = Py_None;
  PyObject * env_value = Py_None;
  const char * cwd = NULL;
  const char * stdio_value = NULL;
  PyObject * aux_value = Py_None;
  FridaSpawnOptions * options;
  GError * error = NULL;
  guint pid;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "s|OOOzzO", keywords,
      &program,
      &argv_value,
      &envp_value,
      &env_value,
      &cwd,
      &stdio_value,
      &aux_value))
    return NULL;

  options = frida_spawn_options_new ();

  if (argv_value != Py_None)
  {
    gchar ** argv;
    gint argv_length;

    if (!PyGObject_unmarshal_strv (argv_value, &argv, &argv_length))
      goto invalid_argument;

    frida_spawn_options_set_argv (options, argv, argv_length);

    g_strfreev (argv);
  }

  if (envp_value != Py_None)
  {
    gchar ** envp;
    gint envp_length;

    if (!PyGObject_unmarshal_envp (envp_value, &envp, &envp_length))
      goto invalid_argument;

    frida_spawn_options_set_envp (options, envp, envp_length);

    g_strfreev (envp);
  }

  if (env_value != Py_None)
  {
    gchar ** env;
    gint env_length;

    if (!PyGObject_unmarshal_envp (env_value, &env, &env_length))
      goto invalid_argument;

    frida_spawn_options_set_env (options, env, env_length);

    g_strfreev (env);
  }

  if (cwd != NULL)
    frida_spawn_options_set_cwd (options, cwd);

  if (stdio_value != NULL)
  {
    FridaStdio stdio;

    if (!PyGObject_unmarshal_enum (stdio_value, FRIDA_TYPE_STDIO, &stdio))
      goto invalid_argument;

    frida_spawn_options_set_stdio (options, stdio);
  }

  if (aux_value != Py_None)
  {
    GHashTable * aux;
    Py_ssize_t pos;
    PyObject * key, * value;

    aux = frida_spawn_options_get_aux (options);

    if (!PyDict_Check (aux_value))
      goto invalid_aux_dict;

    pos = 0;
    while (PyDict_Next (aux_value, &pos, &key, &value))
    {
      gchar * raw_key;
      GVariant * raw_value;

      if (!PyGObject_unmarshal_string (key, &raw_key))
        goto invalid_dict_key;

      if (!PyGObject_unmarshal_variant (value, &raw_value))
      {
        g_free (raw_key);
        goto invalid_dict_value;
      }

      g_hash_table_insert (aux, raw_key, g_variant_ref_sink (raw_value));
    }
  }

  Py_BEGIN_ALLOW_THREADS
  pid = frida_device_spawn_sync (PY_GOBJECT_HANDLE (self), program, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromUnsignedLong (pid);

invalid_argument:
invalid_dict_key:
invalid_dict_value:
  {
    g_object_unref (options);

    return NULL;
  }
invalid_aux_dict:
  {
    g_object_unref (options);

    PyErr_SetString (PyExc_TypeError, "unsupported parameter");

    return NULL;
  }
}

static PyObject *
PyDevice_input (PyDevice * self, PyObject * args)
{
  long pid;
  gconstpointer data_buffer;
  Py_ssize_t data_size;
  GBytes * data;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "ly#", &pid, &data_buffer, &data_size))
    return NULL;

  data = g_bytes_new (data_buffer, data_size);

  Py_BEGIN_ALLOW_THREADS
  frida_device_input_sync (PY_GOBJECT_HANDLE (self), (guint) pid, data, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);

  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDevice_resume (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_resume_sync (PY_GOBJECT_HANDLE (self), (guint) pid, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDevice_kill (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_kill_sync (PY_GOBJECT_HANDLE (self), (guint) pid,
Prompt: 
```
这是目录为frida/subprojects/frida-python/frida/_frida/extension.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
    {
        Py_IncRef (Py_None);
        result = Py_None;
        break;
      }
    }
  }

  if (result == NULL)
    result = PyGObject_new_take_handle (g_object_ref (address), PYFRIDA_TYPE (GObject));

  return result;
}

static gboolean
PyGObject_unmarshal_certificate (const gchar * str, GTlsCertificate ** certificate)
{
  GError * error = NULL;

  if (strchr (str, '\n') != NULL)
    *certificate = g_tls_certificate_new_from_pem (str, -1, &error);
  else
    *certificate = g_tls_certificate_new_from_file (str, &error);
  if (error != NULL)
    goto propagate_error;

  return TRUE;

propagate_error:
  {
    PyFrida_raise (g_error_new_literal (FRIDA_ERROR, FRIDA_ERROR_INVALID_ARGUMENT, error->message));
    g_error_free (error);

    return FALSE;
  }
}


static int
PyDeviceManager_init (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  g_atomic_int_inc (&toplevel_objects_alive);

  PyGObject_take_handle (&self->parent, frida_device_manager_new (), PYFRIDA_TYPE (DeviceManager));

  return 0;
}

static void
PyDeviceManager_dealloc (PyDeviceManager * self)
{
  FridaDeviceManager * handle;

  g_atomic_int_dec_and_test (&toplevel_objects_alive);

  handle = PyGObject_steal_handle (&self->parent);
  if (handle != NULL)
  {
    Py_BEGIN_ALLOW_THREADS
    frida_device_manager_close_sync (handle, NULL, NULL);
    frida_unref (handle);
    Py_END_ALLOW_THREADS
  }

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyDeviceManager_close (PyDeviceManager * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_manager_close_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDeviceManager_get_device_matching (PyDeviceManager * self, PyObject * args)
{
  PyObject * predicate;
  gint timeout;
  GError * error = NULL;
  FridaDevice * result;

  if (!PyArg_ParseTuple (args, "Oi", &predicate, &timeout))
    return NULL;

  if (!PyCallable_Check (predicate))
    goto not_callable;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_manager_get_device_sync (PY_GOBJECT_HANDLE (self), (FridaDeviceManagerPredicate) PyDeviceManager_is_matching_device,
      predicate, timeout, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PyDevice_new_take_handle (result);

not_callable:
  {
    PyErr_SetString (PyExc_TypeError, "object must be callable");
    return NULL;
  }
}

static gboolean
PyDeviceManager_is_matching_device (FridaDevice * device, PyObject * predicate)
{
  gboolean is_matching = FALSE;
  PyGILState_STATE gstate;
  PyObject * device_object, * result;

  gstate = PyGILState_Ensure ();

  device_object = PyDevice_new_take_handle (g_object_ref (device));

  result = PyObject_CallFunction (predicate, "O", device_object);
  if (result != NULL)
  {
    is_matching = result == Py_True;

    Py_DecRef (result);
  }
  else
  {
    PyErr_Print ();
  }

  Py_DecRef (device_object);

  PyGILState_Release (gstate);

  return is_matching;
}

static PyObject *
PyDeviceManager_enumerate_devices (PyDeviceManager * self)
{
  GError * error = NULL;
  FridaDeviceList * result;
  gint result_length, i;
  PyObject * devices;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_manager_enumerate_devices_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_device_list_size (result);
  devices = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (devices, i, PyDevice_new_take_handle (frida_device_list_get (result, i)));
  }
  frida_unref (result);

  return devices;
}

static PyObject *
PyDeviceManager_add_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "address", "certificate", "origin", "token", "keepalive_interval", NULL };
  char * address;
  char * certificate = NULL;
  char * origin = NULL;
  char * token = NULL;
  int keepalive_interval = -1;
  FridaRemoteDeviceOptions * options;
  GError * error = NULL;
  FridaDevice * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esesesi", keywords,
        "utf-8", &address,
        "utf-8", &certificate,
        "utf-8", &origin,
        "utf-8", &token,
        &keepalive_interval))
    return NULL;

  options = PyDeviceManager_parse_remote_device_options (certificate, origin, token, keepalive_interval);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_device_manager_add_remote_device_sync (PY_GOBJECT_HANDLE (self), address, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PyDevice_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);

  PyMem_Free (token);
  PyMem_Free (origin);
  PyMem_Free (certificate);
  PyMem_Free (address);

  return result;
}

static PyObject *
PyDeviceManager_remove_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "address", NULL };
  char * address;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es", keywords, "utf-8", &address))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_manager_remove_remote_device_sync (PY_GOBJECT_HANDLE (self), address, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  PyMem_Free (address);

  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static FridaRemoteDeviceOptions *
PyDeviceManager_parse_remote_device_options (const gchar * certificate_value, const gchar * origin, const gchar * token,
    gint keepalive_interval)
{
  FridaRemoteDeviceOptions * options;

  options = frida_remote_device_options_new ();

  if (certificate_value != NULL)
  {
    GTlsCertificate * certificate;

    if (!PyGObject_unmarshal_certificate (certificate_value, &certificate))
      goto propagate_error;

    frida_remote_device_options_set_certificate (options, certificate);

    g_object_unref (certificate);
  }

  if (origin != NULL)
    frida_remote_device_options_set_origin (options, origin);

  if (token != NULL)
    frida_remote_device_options_set_token (options, token);

  if (keepalive_interval != -1)
    frida_remote_device_options_set_keepalive_interval (options, keepalive_interval);

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}


static PyObject *
PyDevice_new_take_handle (FridaDevice * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Device));
}

static int
PyDevice_init (PyDevice * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->id = NULL;
  self->name = NULL;
  self->icon = NULL;
  self->type = NULL;
  self->bus = NULL;

  return 0;
}

static void
PyDevice_init_from_handle (PyDevice * self, FridaDevice * handle)
{
  GVariant * icon;

  self->id = PyUnicode_FromString (frida_device_get_id (handle));
  self->name = PyUnicode_FromString (frida_device_get_name (handle));
  icon = frida_device_get_icon (handle);
  if (icon != NULL)
  {
    self->icon = PyGObject_marshal_variant (icon);
  }
  else
  {
    self->icon = Py_None;
    Py_IncRef (Py_None);
  }
  self->type = PyGObject_marshal_enum (frida_device_get_dtype (handle), FRIDA_TYPE_DEVICE_TYPE);
  self->bus = PyBus_new_take_handle (g_object_ref (frida_device_get_bus (handle)));
}

static void
PyDevice_dealloc (PyDevice * self)
{
  Py_DecRef (self->bus);
  Py_DecRef (self->type);
  Py_DecRef (self->icon);
  Py_DecRef (self->name);
  Py_DecRef (self->id);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyDevice_repr (PyDevice * self)
{
  PyObject * id_bytes, * name_bytes, * type_bytes, * result;

  id_bytes = PyUnicode_AsUTF8String (self->id);
  name_bytes = PyUnicode_AsUTF8String (self->name);
  type_bytes = PyUnicode_AsUTF8String (self->type);

  result = PyUnicode_FromFormat ("Device(id=\"%s\", name=\"%s\", type='%s')",
      PyBytes_AsString (id_bytes),
      PyBytes_AsString (name_bytes),
      PyBytes_AsString (type_bytes));

  Py_DecRef (type_bytes);
  Py_DecRef (name_bytes);
  Py_DecRef (id_bytes);

  return result;
}

static PyObject *
PyDevice_is_lost (PyDevice * self)
{
  gboolean is_lost;

  Py_BEGIN_ALLOW_THREADS
  is_lost = frida_device_is_lost (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  return PyBool_FromLong (is_lost);
}

static PyObject *
PyDevice_query_system_parameters (PyDevice * self)
{
  GError * error = NULL;
  GHashTable * result;
  PyObject * parameters;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_query_system_parameters_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  parameters = PyGObject_marshal_parameters_dict (result);
  g_hash_table_unref (result);

  return parameters;
}

static PyObject *
PyDevice_get_frontmost_application (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "scope", NULL };
  const char * scope_value = NULL;
  FridaFrontmostQueryOptions * options;
  GError * error = NULL;
  FridaApplication * result;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|s", keywords, &scope_value))
    return NULL;

  options = frida_frontmost_query_options_new ();

  if (scope_value != NULL)
  {
    FridaScope scope;

    if (!PyGObject_unmarshal_enum (scope_value, FRIDA_TYPE_SCOPE, &scope))
      goto invalid_argument;

    frida_frontmost_query_options_set_scope (options, scope);
  }

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_get_frontmost_application_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  if (result != NULL)
    return PyApplication_new_take_handle (result);
  else
    PyFrida_RETURN_NONE;

invalid_argument:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_enumerate_applications (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "identifiers", "scope", NULL };
  PyObject * identifiers = NULL;
  const char * scope = NULL;
  FridaApplicationQueryOptions * options;
  GError * error = NULL;
  FridaApplicationList * result;
  gint result_length, i;
  PyObject * applications;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|Os", keywords, &identifiers, &scope))
    return NULL;

  options = PyDevice_parse_application_query_options (identifiers, scope);
  if (options == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_applications_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_application_list_size (result);
  applications = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (applications, i, PyApplication_new_take_handle (frida_application_list_get (result, i)));
  }
  g_object_unref (result);

  return applications;
}

static FridaApplicationQueryOptions *
PyDevice_parse_application_query_options (PyObject * identifiers_value, const gchar * scope_value)
{
  FridaApplicationQueryOptions * options;

  options = frida_application_query_options_new ();

  if (identifiers_value != NULL)
  {
    gint n, i;

    n = PySequence_Size (identifiers_value);
    if (n == -1)
      goto propagate_error;

    for (i = 0; i != n; i++)
    {
      PyObject * element;
      gchar * identifier = NULL;

      element = PySequence_GetItem (identifiers_value, i);
      if (element == NULL)
        goto propagate_error;
      PyGObject_unmarshal_string (element, &identifier);
      Py_DecRef (element);
      if (identifier == NULL)
        goto propagate_error;

      frida_application_query_options_select_identifier (options, identifier);

      g_free (identifier);
    }
  }

  if (scope_value != NULL)
  {
    FridaScope scope;

    if (!PyGObject_unmarshal_enum (scope_value, FRIDA_TYPE_SCOPE, &scope))
      goto propagate_error;

    frida_application_query_options_set_scope (options, scope);
  }

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_enumerate_processes (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "pids", "scope", NULL };
  PyObject * pids = NULL;
  const char * scope = NULL;
  FridaProcessQueryOptions * options;
  GError * error = NULL;
  FridaProcessList * result;
  gint result_length, i;
  PyObject * processes;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|Os", keywords, &pids, &scope))
    return NULL;

  options = PyDevice_parse_process_query_options (pids, scope);
  if (options == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_processes_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_process_list_size (result);
  processes = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (processes, i, PyProcess_new_take_handle (frida_process_list_get (result, i)));
  }
  g_object_unref (result);

  return processes;
}

static FridaProcessQueryOptions *
PyDevice_parse_process_query_options (PyObject * pids_value, const gchar * scope_value)
{
  FridaProcessQueryOptions * options;

  options = frida_process_query_options_new ();

  if (pids_value != NULL)
  {
    gint n, i;

    n = PySequence_Size (pids_value);
    if (n == -1)
      goto propagate_error;

    for (i = 0; i != n; i++)
    {
      PyObject * element;
      long long pid;

      element = PySequence_GetItem (pids_value, i);
      if (element == NULL)
        goto propagate_error;
      pid = PyLong_AsLongLong (element);
      Py_DecRef (element);
      if (pid == -1)
        goto propagate_error;

      frida_process_query_options_select_pid (options, pid);
    }
  }

  if (scope_value != NULL)
  {
    FridaScope scope;

    if (!PyGObject_unmarshal_enum (scope_value, FRIDA_TYPE_SCOPE, &scope))
      goto propagate_error;

    frida_process_query_options_set_scope (options, scope);
  }

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_enable_spawn_gating (PyDevice * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_enable_spawn_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDevice_disable_spawn_gating (PyDevice * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_disable_spawn_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDevice_enumerate_pending_spawn (PyDevice * self)
{
  GError * error = NULL;
  FridaSpawnList * result;
  gint result_length, i;
  PyObject * spawn;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_pending_spawn_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_spawn_list_size (result);
  spawn = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (spawn, i, PySpawn_new_take_handle (frida_spawn_list_get (result, i)));
  }
  g_object_unref (result);

  return spawn;
}

static PyObject *
PyDevice_enumerate_pending_children (PyDevice * self)
{
  GError * error = NULL;
  FridaChildList * result;
  gint result_length, i;
  PyObject * children;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_pending_children_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_child_list_size (result);
  children = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (children, i, PyChild_new_take_handle (frida_child_list_get (result, i)));
  }
  g_object_unref (result);

  return children;
}

static PyObject *
PyDevice_spawn (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "program", "argv", "envp", "env", "cwd", "stdio", "aux", NULL };
  const char * program;
  PyObject * argv_value = Py_None;
  PyObject * envp_value = Py_None;
  PyObject * env_value = Py_None;
  const char * cwd = NULL;
  const char * stdio_value = NULL;
  PyObject * aux_value = Py_None;
  FridaSpawnOptions * options;
  GError * error = NULL;
  guint pid;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "s|OOOzzO", keywords,
      &program,
      &argv_value,
      &envp_value,
      &env_value,
      &cwd,
      &stdio_value,
      &aux_value))
    return NULL;

  options = frida_spawn_options_new ();

  if (argv_value != Py_None)
  {
    gchar ** argv;
    gint argv_length;

    if (!PyGObject_unmarshal_strv (argv_value, &argv, &argv_length))
      goto invalid_argument;

    frida_spawn_options_set_argv (options, argv, argv_length);

    g_strfreev (argv);
  }

  if (envp_value != Py_None)
  {
    gchar ** envp;
    gint envp_length;

    if (!PyGObject_unmarshal_envp (envp_value, &envp, &envp_length))
      goto invalid_argument;

    frida_spawn_options_set_envp (options, envp, envp_length);

    g_strfreev (envp);
  }

  if (env_value != Py_None)
  {
    gchar ** env;
    gint env_length;

    if (!PyGObject_unmarshal_envp (env_value, &env, &env_length))
      goto invalid_argument;

    frida_spawn_options_set_env (options, env, env_length);

    g_strfreev (env);
  }

  if (cwd != NULL)
    frida_spawn_options_set_cwd (options, cwd);

  if (stdio_value != NULL)
  {
    FridaStdio stdio;

    if (!PyGObject_unmarshal_enum (stdio_value, FRIDA_TYPE_STDIO, &stdio))
      goto invalid_argument;

    frida_spawn_options_set_stdio (options, stdio);
  }

  if (aux_value != Py_None)
  {
    GHashTable * aux;
    Py_ssize_t pos;
    PyObject * key, * value;

    aux = frida_spawn_options_get_aux (options);

    if (!PyDict_Check (aux_value))
      goto invalid_aux_dict;

    pos = 0;
    while (PyDict_Next (aux_value, &pos, &key, &value))
    {
      gchar * raw_key;
      GVariant * raw_value;

      if (!PyGObject_unmarshal_string (key, &raw_key))
        goto invalid_dict_key;

      if (!PyGObject_unmarshal_variant (value, &raw_value))
      {
        g_free (raw_key);
        goto invalid_dict_value;
      }

      g_hash_table_insert (aux, raw_key, g_variant_ref_sink (raw_value));
    }
  }

  Py_BEGIN_ALLOW_THREADS
  pid = frida_device_spawn_sync (PY_GOBJECT_HANDLE (self), program, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromUnsignedLong (pid);

invalid_argument:
invalid_dict_key:
invalid_dict_value:
  {
    g_object_unref (options);

    return NULL;
  }
invalid_aux_dict:
  {
    g_object_unref (options);

    PyErr_SetString (PyExc_TypeError, "unsupported parameter");

    return NULL;
  }
}

static PyObject *
PyDevice_input (PyDevice * self, PyObject * args)
{
  long pid;
  gconstpointer data_buffer;
  Py_ssize_t data_size;
  GBytes * data;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "ly#", &pid, &data_buffer, &data_size))
    return NULL;

  data = g_bytes_new (data_buffer, data_size);

  Py_BEGIN_ALLOW_THREADS
  frida_device_input_sync (PY_GOBJECT_HANDLE (self), (guint) pid, data, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);

  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDevice_resume (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_resume_sync (PY_GOBJECT_HANDLE (self), (guint) pid, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDevice_kill (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_kill_sync (PY_GOBJECT_HANDLE (self), (guint) pid, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyDevice_attach (PyDevice * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "pid", "realm", "persist_timeout", NULL };
  long pid;
  char * realm_value = NULL;
  unsigned int persist_timeout = 0;
  FridaSessionOptions * options = NULL;
  GError * error = NULL;
  FridaSession * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "l|esI", keywords,
        &pid,
        "utf-8", &realm_value,
        &persist_timeout))
    return NULL;

  options = PyDevice_parse_session_options (realm_value, persist_timeout);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_device_attach_sync (PY_GOBJECT_HANDLE (self), (guint) pid, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PySession_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);

  PyMem_Free (realm_value);

  return result;
}

static FridaSessionOptions *
PyDevice_parse_session_options (const gchar * realm_value,
                                guint persist_timeout)
{
  FridaSessionOptions * options;

  options = frida_session_options_new ();

  if (realm_value != NULL)
  {
    FridaRealm realm;

    if (!PyGObject_unmarshal_enum (realm_value, FRIDA_TYPE_REALM, &realm))
      goto propagate_error;

    frida_session_options_set_realm (options, realm);
  }

  frida_session_options_set_persist_timeout (options, persist_timeout);

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_inject_library_file (PyDevice * self, PyObject * args)
{
  long pid;
  const char * path, * entrypoint, * data;
  GError * error = NULL;
  guint id;

  if (!PyArg_ParseTuple (args, "lsss", &pid, &path, &entrypoint, &data))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  id = frida_device_inject_library_file_sync (PY_GOBJECT_HANDLE (self), (guint) pid, path, entrypoint, data, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromUnsignedLong (id);
}

static PyObject *
PyDevice_inject_library_blob (PyDevice * self, PyObject * args)
{
  long pid;
  GBytes * blob;
  gconstpointer blob_buffer;
  Py_ssize_t blob_size;
  const char * entrypoint, * data;
  GError * error = NULL;
  guint id;

  if (!PyArg_ParseTuple (args, "ly#ss", &pid, &blob_buffer, &blob_size, &entrypoint, &data))
    return NULL;

  blob = g_bytes_new (blob_buffer, blob_size);

  Py_BEGIN_ALLOW_THREADS
  id = frida_device_inject_library_blob_sync (PY_GOBJECT_HANDLE (self), (guint) pid, blob, entrypoint, data, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_bytes_unref (blob);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromUnsignedLong (id);
}

static PyObject *
PyDevice_open_channel (PyDevice * self, PyObject * args)
{
  const char * address;
  GError * error = NULL;
  GIOStream * stream;

  if (!PyArg_ParseTuple (args, "s", &address))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  stream = frida_device_open_channel_sync (PY_GOBJECT_HANDLE (self), address, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PyIOStream_new_take_handle (stream);
}

static PyObject *
PyDevice_open_service (PyDevice * self, PyObject * args)
{
  const char * address;
  GError * error = NULL;
  FridaService * service;

  if (!PyArg_ParseTuple (args, "s", &address))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  service = frida_device_open_service_sync (PY_GOBJECT_HANDLE (self), address, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PyService_new_take_handle (service);
}

static PyObject *
PyDevice_unpair (PyDevice * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_unpair_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}


static PyObject *
PyApplication_new_take_handle (FridaApplication * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Application));
}

static int
PyApplication_init (PyApplication * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->identifier = NULL;
  self->name = NULL;
  self->pid = 0;
  self->parameters = NULL;

  return 0;
}

static void
PyApplication_init_from_handle (PyApplication * self, FridaApplication * handle)
{
  self->identifier = PyUnicode_FromString (frida_application_get_identifier (handle));
  self->name = PyUnicode_FromString (frida_application_get_name (handle));
  self->pid = frida_application_get_pid (handle);
  self->parameters = PyApplication_marshal_parameters_dict (frida_application_get_parameters (handle));
}

static void
PyApplication_dealloc (PyApplication * self)
{
  Py_DecRef (self->parameters);
  Py_DecRef (self->name);
  Py_DecRef (self->identifier);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyApplication_repr (PyApplication * self)
{
  PyObject * result;
  FridaApplication * handle;
  GString * repr;
  gchar * str;

  handle = PY_GOBJECT_HANDLE (self);

  repr = g_string_new ("Application(");

  g_string_append_printf (repr, "identifier=\"%s\", name=\"%s\"",
      frida_application_get_identifier (handle),
      frida_application_get_name (handle));

  if (self->pid != 0)
    g_string_append_printf (repr, ", pid=%u", self->pid);

  str = PyFrida_repr (self->parameters);
  g_string_append_printf (repr, ", parameters=%s", str);
  g_free (str);

  g_string_append (repr, ")");

  result = PyUnicode_FromString (repr->str);

  g_string_free (repr, TRUE);

  return result;
}

static PyObject *
PyApplication_marshal_parameters_dict (GHashTable * dict)
{
  PyObject * result;
  GHashTableIter iter;
  const gchar * key;
  GVariant * raw_value;

  result = PyDict_New ();

  g_hash_table_iter_init (&iter, dict);

  while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &raw_value))
  {
    PyObject * value;

    if (strcmp (key, "started") == 0 && g_variant_is_of_type (raw_value, G_VARIANT_TYPE_STRING))
      value = PyGObject_marshal_datetime (g_variant_get_string (raw_value, NULL));
    else
      value = PyGObject_marshal_variant (raw_value);

    PyDict_SetItemString (result, key, value);

    Py_DecRef (value);
  }

  return result;
}


static PyObject *
PyProcess_new_take_handle (FridaProcess * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Process));
}

static int
PyProcess_init (PyProcess * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->name = NULL;
  self->parameters = NULL;

  return 0;
}

static void
PyProcess_init_from_handle (PyProcess * self, FridaProcess * handle)
{
  self->pid = frida_process_get_pid (handle);
  self->name = PyUnicode_FromString (frida_process_get_name (handle));
  self->parameters = PyProcess_marshal_parameters_dict (frida_process_get_parameters (handle));
}

static void
PyProcess_dealloc (PyProcess * self)
{
  Py_DecRef (self->parameters);
  Py_DecRef (self->name);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyProcess_repr (PyProcess * self)
{
  PyObject * result;
  FridaProcess * handle;
  GString * repr;
  gchar * str;

  handle = PY_GOBJECT_HANDLE (self);

  repr = g_string_new ("Process(");

  g_string_append_printf (repr, "pid=%u, name=\"%s\"",
      self->pid,
      frida_process_get_name (handle));

  str = PyFrida_repr (self->parameters);
  g_string_append_printf (repr, ", parameters=%s", str);
  g_free (str);

  g_string_append (repr, ")");

  result = PyUnicode_FromString (repr->str);

  g_string_free (repr, TRUE);

  return result;
}

static PyObject *
PyProcess_marshal_parameters_dict (GHashTable * dict)
{
  PyObject * result;
  GHashTableIter iter;
  const gchar * key;
  GVariant * raw_value;

  result = PyDict_New ();

  g_hash_table_iter_init (&iter, dict);

  while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &raw_value))
  {
    PyObject * value;

    if (strcmp (key, "started") == 0 && g_variant_is_of_type (raw_value, G_VARIANT_TYPE_STRING))
      value = PyGObject_marshal_datetime (g_variant_get_string (raw_value, NULL));
    else
      value = PyGObject_marshal_variant (raw_value);

    PyDict_SetItemString (result, key, value);

    Py_DecRef (value);
  }

  return result;
}


static PyObject *
PySpawn_new_take_handle (FridaSpawn * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Spawn));
}

static int
PySpawn_init (PySpawn * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->identifier = NULL;

  return 0;
}

static void
PySpawn_init_from_handle (PySpawn * self, FridaSpawn * handle)
{
  self->pid = frida_spawn_get_pid (handle);
  self->identifier = PyGObject_marshal_string (frida_spawn_get_identifier (handle));
}

static void
PySpawn_dealloc (PySpawn * self)
{
  Py_DecRef (self->identifier);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PySpawn_repr (PySpawn * self)
{
  PyObject * result;

  if (self->identifier != Py_None)
  {
    PyObject * identifier_bytes;

    identifier_bytes = PyUnicode_AsUTF8String (self->identifier);

    result = PyUnicode_FromFormat ("Spawn(pid=%u, identifier=\"%s\")",
        self->pid,
        PyBytes_AsString (identifier_bytes));

    Py_DecRef (identifier_bytes);
  }
  else
  {
    result = PyUnicode_FromFormat ("Spawn(pid=%u)",
        self->pid);
  }

  return result;
}


static PyObject *
PyChild_new_take_handle (FridaChild * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Child));
}

static int
PyChild_init (PyChild * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->parent_pid = 0;
  self->origin = NULL;
  self->identifier = NULL;
  self->path = NULL;
  self->argv = NULL;
  self->envp = NULL;

  return 0;
}

static void
PyChild_init_from_handle (PyChild * self, FridaChild * handle)
{
  gchar * const * argv, * const * envp;
  gint argv_length, envp_length;

  self->pid = frida_child_get_pid (handle);
  self->parent_pid = frida_child_get_parent_pid (handle);

  self->origin = PyGObject_marshal_enum (frida_child_get_origin (handle), FRIDA_TYPE_CHILD_ORIGIN);

  self->identifier = PyGObject_marshal_string (frida_child_get_identifier (handle));

  self->path = PyGObject_marshal_string (frida_child_get_path (handle));

  argv = frida_child_get_argv (handle, &argv_length);
  self->argv = PyGObject_marshal_strv (argv, argv_length);

  envp = frida_child_get_envp (handle, &envp_length);
  self->envp = PyGObject_marshal_envp (envp, envp_length);
}

static void
PyChild_dealloc (PyChild * self)
{
  Py_DecRef (self->envp);
  Py_DecRef (self->argv);
  Py_DecRef (self->path);
  Py_DecRef (self->identifier);
  Py_DecRef (self->origin);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyChild_repr (PyChild * self)
{
  PyObject * result;
  FridaChild * handle;
  GString * repr;
  FridaChildOrigin origin;
  GEnumClass * origin_class;
  GEnumValue * origin_value;

  handle = PY_GOBJECT_HANDLE (self);

  repr = g_string_new ("Child(");

  g_string_append_printf (
"""


```