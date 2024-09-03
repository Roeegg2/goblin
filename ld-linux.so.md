# Analysis of ld-linux.so

dl_main:
  - call `dl_main_state_init()`
  - call `__tls_pre_init_tp()`
  - processes environment variables (calls `process_envvars`)
  - if ld-linux.so is ran as program itself:
    - then process flags
    - change stack flags (since the stack flags are set to ld-linux's, but not the programs)
    - call `_dl_map_object()` - maps the program requested by the user to memory
    - adjust the auxillary vector values to program requested's values
    -
  - otherwise (invoked by the kernel as a result of ld-linux being in INTERIP segment):
    - call `_dl_map_object()` - map the program to shared memory
  - call `rtld_setup_main_map()` - complete initilization of the `struct link_map` of the main program
  -
  - if ld-linux invoked by the kernel:
    - call `elf_get_dynamic_info()` - get .dyn segment data
  - if "verify" specified #NOTE shouldn't this if be inside the previous if?
    - check the executable called has ld-linux as interpreter
  - call `setup_vdso()` - setup data structures for the VDSO
  - call `setup_vdso_pointers()` - setup function pointers
  - call `call_init_paths()` - wrapper of `_dl_init_paths()`, just initiliazes the search paths of the shared object
  - setup PHDR info for ld-linux itself
  - get GNU_RELRO segment info
  - call `_dl_assign_tls_modid` - add ld-linux to TLS list if it also has a TLS block
  - call `init_tls` -
  - call `security_init()` - sets up stack canaries, - etc
  - call `LIBC_PROBE (init_start, 2, LM_ID_BASE, r);`
  - if LD_PRELOAD defined:
    - call `handle_preload_list()` with LD_PRELOAD
  - if --preload defined:
    - call `handle_preload_list()` with --preload
  - if there is /etc/ld.so.preload:
    - call `_dl_sysdep_read_whole_file()` to get file contents /etc/ld.so.preload
    - for each lib entry in the file, call `do_preload()` - which
    - set up array of preload libraries
  - if need to load vDSO:
    - call `_dl_audit_objopen()` to call the `objopen()` audit function,
  - call `_dl_map_object_deps()` to load all LD_PRELOAD and then DT_NEEDED shared objects
  - ? line 1977
  - ? line 1981
  - make sure all libraries are in the correct version (normal/tracing)
  - if any of the shared objects use TLS, call `tcbp = init_tls()`
  - if not done earlier, call `security_init()`
  - ...


# Analysis of specific functions
  init_tls:




## list of functions to learn about:
  - `setup_vdso`
  - `setup_vdso_pointers`
  - `audit_list_add_dynamic_tag`
  - `map_doit`

  - `__tls_pre_init_tp` - simple sets up the data structures so they can be used
  - `_dl_assign_tls_modid` -
  - `init_tls`
    - `_dl_tls_static_surplus_init`
    - `_dl_tls_setup`
    - `_dl_determine_tlsoffset`
    - `_dl_tls_initial_modid_limit_setup`
    - `call_tls_init_tp`



## important structs and types:
  - `struct dl_main_state` - struct to hold some information extracted from the environment variables
  - `struct link_map` - struct to describe a loaded shared object.
  - `struct map_args` - arguments to `map_doit()`


## Some important terminology:
  - `audit` - a mechanism that lets one intercept and monitor dynamic linking events (such as )
