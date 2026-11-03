#if defined(_WIN32)
    #include <windows.h>
    #include <crtdbg.h>
    #include <stdlib.h>
#endif

namespace {
    // Stop Windows debug runtimes from popping modal dialogs (CRT assertion,
    // abort(), unhandled exception): those hang CI forever.
    struct windows_dialog_suppressor {
        windows_dialog_suppressor() {
#if defined(_WIN32)
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
                         | SEM_NOOPENFILEERRORBOX);
    #if defined(_DEBUG)
            _CrtSetReportMode(_CRT_WARN,   _CRTDBG_MODE_FILE);
            _CrtSetReportFile(_CRT_WARN,   _CRTDBG_FILE_STDERR);
            _CrtSetReportMode(_CRT_ERROR,  _CRTDBG_MODE_FILE);
            _CrtSetReportFile(_CRT_ERROR,  _CRTDBG_FILE_STDERR);
            _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
            _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
            _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    #endif
#endif
        }
    };
    const windows_dialog_suppressor windows_dialog_suppressor_instance;
}
