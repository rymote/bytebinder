foreach(EXAMPLE
        01_read_write_local
        02_attach_remote
        03_progressive_value_search
        04_find_xrefs_and_hook
        05_dump_memory_snapshot
        06_vtable_discovery
        07_pointer_chain
        08_scan_session
        09_pointer_scan
        10_find_what_writes)
    add_executable(usage_${EXAMPLE} ${EXAMPLE}.cpp)
    target_link_libraries(usage_${EXAMPLE} PRIVATE
        $<IF:$<TARGET_EXISTS:bytebinder-static>,bytebinder-static,bytebinder-shared>)
endforeach()
