#!/usr/bin/env python3
"""Add deferred CSOLoader teardown after the final custom dlopen handle closes."""
from pathlib import Path
import sys

MARKER = "/* VREZYGISK_DEFERRED_UNLOAD_CALLBACK */"


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one source anchor, found {count}")
    return source.replace(old, new, 1)


def patch(linker_path: Path) -> None:
    root = linker_path.parent.parent
    linker_header_path = root / "include" / "linker.h"
    csoloader_header_path = root / "include" / "csoloader.h"
    csoloader_path = linker_path.with_name("csoloader.c")

    header = linker_header_path.read_text()
    if "void *owner_context;" not in header:
        header = replace_once(
            header,
            "  enum linker_image_state main_lifecycle_state;",
            "  enum linker_image_state main_lifecycle_state;\n  void *owner_context;",
            "linker owner context",
        )
        header = replace_once(
            header,
            "void linker_fork_child(void);",
            "void linker_fork_child(void);\n"
            "void linker_set_deferred_unload_callback(void (*callback)(void *));",
            "linker deferred unload callback API",
        )
        linker_header_path.write_text(header)

    source = linker_path.read_text()
    if MARKER not in source:
        source = replace_once(
            source,
            '#include "linker.h"',
            '#include "linker.h"\nstatic bool _linker_has_open_handles(const struct linker *linker);\nstatic void (*g_deferred_unload_callback)(void *);',
            "deferred callback declarations before custom hooks",
        )
        source = replace_once(
            source,
            "/* INFO: Internal functions END */",
            """void linker_set_deferred_unload_callback(void (*callback)(void *)) {
  if (!_linker_registry_lock()) return;
  g_deferred_unload_callback = callback;
  _linker_registry_unlock();
}

/* VREZYGISK_DEFERRED_UNLOAD_CALLBACK */

/* INFO: Internal functions END */""",
            "deferred unload callback registration",
        )

        source = replace_once(
            source,
            """static int custom_dlclose(void *handle) {
  int (*original_dlclose)(void *) =
      (int (*)(void *))_linker_get_original_libdl_symbol("dlclose");
  if (!_linker_registry_lock())
    return original_dlclose ? original_dlclose(handle) : -1;

  struct linker *linker = _linker_find_owner_by_handle(handle);
  struct csoloader_elf *img = _linker_image_from_handle(linker, handle);
  if (img) {
    bool released = _linker_adjust_handle_ref(linker, img, false);
    _linker_registry_unlock();
    return released ? 0 : -1;
  }
  _linker_registry_unlock();
  return original_dlclose ? original_dlclose(handle) : -1;
}""",
            """static int custom_dlclose(void *handle) {
  int (*original_dlclose)(void *) =
      (int (*)(void *))_linker_get_original_libdl_symbol("dlclose");
  if (!_linker_registry_lock())
    return original_dlclose ? original_dlclose(handle) : -1;

  struct linker *linker = _linker_find_owner_by_handle(handle);
  struct csoloader_elf *img = _linker_image_from_handle(linker, handle);
  if (img) {
    bool released = _linker_adjust_handle_ref(linker, img, false);
    void *notify_owners[MAX_ACTIVE_LINKERS];
    size_t notify_count = 0;
    void (*callback)(void *) = g_deferred_unload_callback;
    if (released && callback) {
      for (int i = 0; i < g_active_linker_count; ++i) {
        struct linker *candidate = g_active_linkers[i];
        if (candidate && candidate->is_closing &&
            !_linker_has_open_handles(candidate) &&
            candidate->owner_context && notify_count < MAX_ACTIVE_LINKERS)
          notify_owners[notify_count++] = candidate->owner_context;
      }
    }
    _linker_registry_unlock();
    for (size_t i = 0; i < notify_count; ++i)
      callback(notify_owners[i]);
    return released ? 0 : -1;
  }
  _linker_registry_unlock();
  return original_dlclose ? original_dlclose(handle) : -1;
}""",
            "notify deferred unload after final handle release",
        )

        old_destroy = """bool linker_destroy(struct linker *linker) {
  if (!linker || !linker->img || !_linker_registry_lock()) return false;
  linker->is_closing = true;
  _linker_registry_unlock();

  if (linker->is_linked) {
    _linker_call_destructors(linker->img, &linker->main_lifecycle_state);
    for (int i = 0; i < linker->dep_count; ++i)
      _linker_run_dependency_destructors(&linker->dependencies[i]);
  }

  if (!_linker_registry_lock()) return false;
  if (_linker_has_open_handles(linker)) {
    LOGE("Refusing to unmap %s while custom dlopen handles remain open",
         linker->img->elf);
    _linker_registry_unlock();
    return false;
  }

  if (linker->is_linked) {
    unregister_eh_frame_for_library(linker->img);
    unregister_custom_library_for_backtrace(linker->img);
  }
  void *main_base = linker->img->base;
  size_t main_map_size = linker->main_map_size;
  _linker_release_dependencies(linker, true, false);
  _linker_unregister(linker);
  _linker_unregister_tls_segment((struct loaded_dep *)linker);
  csoloader_elf_destroy(linker->img);
  linker->img = NULL;
  if (main_base && main_map_size > 0) munmap(main_base, main_map_size);

  free(linker->dependencies);
  linker->dependencies = NULL;
  linker->dep_capacity = 0;
  linker->dep_count = 0;
  linker->main_handle_refs = 0;
  linker->is_linked = false;
  linker->main_map_size = 0;
  _linker_registry_unlock();
  return true;
}"""
        new_destroy = """bool linker_destroy(struct linker *linker) {
  if (!linker || !linker->img || !_linker_registry_lock()) return false;
  linker->is_closing = true;
  if (_linker_has_open_handles(linker)) {
    LOGD("Deferring unload of %s until custom handles are closed",
         linker->img->elf);
    _linker_registry_unlock();
    return false;
  }
  _linker_registry_unlock();

  /* Do not run finalizers while a custom handle can still execute image code. */
  if (linker->is_linked) {
    _linker_call_destructors(linker->img, &linker->main_lifecycle_state);
    for (int i = 0; i < linker->dep_count; ++i)
      _linker_run_dependency_destructors(&linker->dependencies[i]);
  }

  if (!_linker_registry_lock()) return false;
  if (_linker_has_open_handles(linker)) {
    _linker_registry_unlock();
    return false;
  }
  if (linker->is_linked) {
    unregister_eh_frame_for_library(linker->img);
    unregister_custom_library_for_backtrace(linker->img);
  }
  void *main_base = linker->img->base;
  size_t main_map_size = linker->main_map_size;
  _linker_release_dependencies(linker, true, false);
  _linker_unregister(linker);
  _linker_unregister_tls_segment((struct loaded_dep *)linker);
  csoloader_elf_destroy(linker->img);
  linker->img = NULL;
  if (main_base && main_map_size > 0) munmap(main_base, main_map_size);

  free(linker->dependencies);
  linker->dependencies = NULL;
  linker->dep_capacity = 0;
  linker->dep_count = 0;
  linker->main_handle_refs = 0;
  linker->is_linked = false;
  linker->main_map_size = 0;
  linker->owner_context = NULL;
  _linker_registry_unlock();
  return true;
}"""
        source = replace_once(source, old_destroy, new_destroy,
                              "defer finalizers until handles are closed")
        linker_path.write_text(source)

    csoloader_header = csoloader_header_path.read_text()
    if "csoloader_set_deferred_unload_callback" not in csoloader_header:
        csoloader_header = replace_once(
            csoloader_header,
            "void csoloader_deinit(void);",
            "void csoloader_deinit(void);\n"
            "void csoloader_set_deferred_unload_callback(void (*callback)(void *));",
            "public CSOLoader deferred callback declaration",
        )
        csoloader_header_path.write_text(csoloader_header)

    csoloader = csoloader_path.read_text()
    if "csoloader_set_deferred_unload_callback" not in csoloader:
        csoloader = replace_once(
            csoloader,
            "bool csoloader_load(struct csoloader *lib, const char *lib_path) {",
            "void csoloader_set_deferred_unload_callback(void (*callback)(void *)) {\n"
            "  linker_set_deferred_unload_callback(callback);\n"
            "}\n\n"
            "bool csoloader_load(struct csoloader *lib, const char *lib_path) {",
            "CSOLoader deferred callback wrapper",
        )
        csoloader = replace_once(
            csoloader,
            "  lib->linker.main_map_size = dep_info.map_size;",
            "  lib->linker.main_map_size = dep_info.map_size;\n"
            "  lib->linker.owner_context = lib;",
            "bind deferred callback to owning csoloader",
        )
        csoloader_path.write_text(csoloader)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <CSOLoader/src/linker.c>", file=sys.stderr)
        return 2
    patch(Path(sys.argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
