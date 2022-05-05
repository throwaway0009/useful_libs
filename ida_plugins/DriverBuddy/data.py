from .wdf import *
from .wdm import *

# List of C/C++ functions that are commonly vulnerable or that can facilitate buffer overflow conditions
c_functions = [
    ######################################################
    # String Copy Functions
    "strcpy",
    "strcpyA",
    "strcpyW",
    # While 'safer', the current "n" functions include non-null termination of overflowed buffers;
    # no error returns on overflow
    "StrCpyN",
    "StrCpyNA",
    "strcpynA",
    "StrCpyNW",
    "StrNCpy",
    "strncpy",
    "StrNCpyA",
    "StrNCpyW",
    ######################################################
    # String Concatenation Functions
    "lstrcat",
    "lstrcatA",
    "lstrcatW",
    "strcat",
    "StrCat",
    "strcatA",
    "StrCatA",
    "StrCatBuff",
    "StrCatBuffA",
    "StrCatBuffW",
    "strcatW",
    "StrCatW",
    # While 'safer', the current "n" functions include non-null termination of overflowed buffers;
    # no error returns on overflow
    "lstrcatnA",
    "lstrcatn",
    "lstrcatnW",
    "lstrncat",
    "strncat",
    ######################################################
    # String Tokenizing Functions
    "strtok",  # not always thread-safe
    "wcstok",
    "_mbstok",
    "_tcstok",
    ######################################################
    # Makepath/Splitpath Functions (Use the safer alternative: _makepath_s, _splitpath_s)
    "makepath",
    "_splitpath",
    "_tmakepath",
    "_tsplitpath",
    "_wmakepath",
    "_wsplitpath",
    ######################################################
    # Numeric Conversion Functions;
    # Do not perform a safe conversion on account of a failure to distinguish between 'signed' and 'unsigned'
    "_itoa",
    "_i64toa",
    "_i64tow",
    "_itow",
    "_ui64toa",
    "_ui64tot",
    "_ui64tow",
    "_ultoa",
    "_ultot",
    "_ultow",
    ######################################################
    # Scanf Functions; Directs user defined input to a buffer and so can facilitate buffer overflows
    "scanf",
    "_sntscanf",
    "_stscanf",
    "_tscanf",
    "fscanf",
    "snscanf",
    "snwscanf",
    "sscanf",
    "swscanf",
    "wscanf",
    ######################################################
    # Gets Functions; Reads characters from STDIN and writes to buffer until EOL it can facilitate buffer overflows
    "_getts",
    "_gettws",
    "gets",
    ######################################################
    # String Length functions; Can become victims of integer overflow or 'wraparound' errors
    "strlen",
    "_mbslen",
    "_mbstrlen",
    "lstrlen",
    "StrLen",
    "wcslen",
    ######################################################
    # Memory Copy Functions; Can facilitate buffer overflow conditions and other memory mis-management situations
    "CopyMemory",
    "memcpy",
    "RtlCopyMemory",
    "wmemcpy",
    ######################################################
    # Stack Dynamic Memory Allocation Functions;
    # Can facilitate buffer overflow conditions and other memory mis-management situations
    "_alloca",
    "alloca",
    ######################################################
    # Unrestricted Memory Manipulation;
    # Can facilitate buffer overflow conditions and other memory mis-management situations
    "memmove",
    "realloc",
    # Can expose residual memory contents or render existing buffers impossible to securely erase.
    # Do not use realloc on memory intended to be secure as the old structure will not be zeroed out
    ######################################################
    # *printf Family; Can facilitate format string bugs
    "_snprintf",
    "_sntprintf",
    "_swprintf",
    "nsprintf",
    "sprintf",
    "std_strlprintf",
    # Function is generally safe but will result in buffer overflows if destination is not checked for zero length
    "vsprintf",
    ######################################################
    # File Handling;
    # Verify that user cannot modify filename for malicious purposes
    # and that file is not 'opened' more than once simultaneously
    "_wfopen",
    "_open",
    "_wopen",
    "fopen",
    ######################################################
    # Considered Harmful
    "rewind",
    # The 'rewind' function is considered unsafe and obsolete.
    # Rewind() makes it impossible to determine if the file position indicator was set back to the beginning of the file,
    # potentially resulting in improper control flow. fseek() is considered a safer alternative
    "_strlwr",  # Function is deprecated. Use the safer version, _strlwr_s
    "_strupr",  # Function is deprecated. Use the safer version, _strupr_s
    "assert",
    # The 'assert' macro usually only exists for code in the debug build.
    # In general, no check will take place in production code.
    # Verify that this check does not perform any critical function and is not being used in place of error handling
    "catgets",
    # This function may use the NLSPATH environment variable.
    # Environment variables may be within the control of the end user and should be handled with caution.
    "getenv",  # Environment variables may be within the control of the end user and should be handled with caution.
    "gethostbyname",
    # Environment variables may be within the control of the end user and should be handled with caution.
    "setbuf",
    # Allows data to be read from a file/stream. Use with caution and do not allow user defined streams where possible.
    # Conduct a manual check to ensure data is handled in a safe manner
    "umask",  # Manually check this function to ensure that safe privilege levels are being applied
    ######################################################
]

# List of Windows API functions that are interesting
# Will partial match to start of function name, ie, Zw will match ZwClose
winapi_functions = [
    # IsBad* Functions: can mask errors during pointer assignment;
    # resulting in memory leaks, crashes and unstable behaviour
    "IsBad",
    # IsBadCodePtr
    # IsBadHugeReadPtr
    # IsBadHugeWritePtr
    # IsBadReadPtr
    # IsBadStringPtr
    # IsBadWritePtr
    ######################################################
    "EnterCriticalSection",
    # This function can throw exceptions when limited memory is available,
    # resulting in unstable behaviour and potential DoS conditions.
    # Use the safer InitialCriticalSectionAndSpinCount function
    "LoadLibrary",
    "IofCallDriver",
    "IoRegisterDeviceInterface",
    "Ob",
    "ProbeFor",
    "PsCreateSystemThread",
    "SeAccessCheck",
    "SeQueryAuthenticationIdToken",
    "Zw",
]

# List of driver specific functions, modify for driver you're working on
driver_functions = []

# Data structures needed to store addresses of functions we are interested in
functions_map = {}
imports_map = {}
c_map = {}
winapi_map = {}
driver_map = {}


def cb(address, name, ord):
    """
    Callback function needed by idaapi.enum_import_names().
    Called for every function in imports section of binary.
    :param address: Address of enumerated function
    :param name: Name of enumerated function
    :param ord: Ordinal of enumerated function. Not used for imports.
    :return boolean: 1 okay, -1 on error, otherwise callback return value
    """
    imports_map[name] = address
    functions_map[name] = address
    return True


def populate_function_map():
    """
    Loads functions known to IDA from the subs and imports sections into a map.
    :return boolean: True if functions are loaded successfully, otherwise False
    """
    result = False
    # Populate function_map with sub functions
    for address in Functions():
        func_name = get_func_name(address)
        functions_map[func_name] = address
        result = True
    # Populate function_map with import functions
    import_list = get_import_module_qty()
    for index in range(0, import_list):
        name = get_import_module_name(index)
        enum_import_names(index, cb)
        result = True
    return result


def populate_c_map():
    """
    Enumerate through the list of all functions and load vulnerable C/C++ functions found into a map.
    :return boolean: True if vulnerable functions are found, False otherwise
    """
    result = False
    for name, address in functions_map.items():
        if name in c_functions:
            c_map[name] = address
            result = True
    return result


def populate_winapi_map():
    """
    Enumerate through the list of all functions and load vulnerable Win API functions found into a map.
    :return boolean: True if vulnerable functions are found, False otherwise
    """
    result = False
    for name, address in functions_map.items():
        for winapi in winapi_functions:
            if name.lower().startswith(winapi.lower()):
                winapi_map[name] = address
                result = True
    return result


def populate_driver_map():
    """
    Enumerate through the list of all functions and load vulnerable driver specific functions found into a map.
    :return boolean: True if vulnerable functions found, False otherwise
    """
    result = False
    for name, address in functions_map.items():
        if name in driver_functions:
            driver_map[name] = address
            result = True
    return result


def populate_data_structures():
    """
    Enumerate through the list of functions and load vulnerable functions found into a map.
    :return boolean: False if unable to enumerate functions, True otherwise
    """
    print("[>] Populating IDA functions...")
    result = populate_function_map()
    if result is True:
        print("[>] Searching for interesting C/C++ functions...")
        result = populate_c_map()
        if result is True:
            print("[+] Interesting C/C++ functions detected:")
            get_xrefs(c_map)
        else:
            print("[-] No interesting C/C++ functions found")
        print("[>] Searching for interesting Windows API functions...")
        result = populate_winapi_map()
        if result is True:
            print("[+] Interesting Windows API functions detected:")
            get_xrefs(winapi_map)
        else:
            print("[-] No interesting Windows API functions found")
        print("[>] Searching for interesting driver functions...")
        result = populate_driver_map()
        if result is True:
            print("[+] Interesting driver functions detected:")
            get_xrefs(driver_map)
        else:
            print("[-] No interesting specific driver functions found")
        return True
    else:
        print("[!] ERR: Couldn't populate function_map")
        return False


def get_xrefs(func_map):
    """
    Gets cross references to vulnerable functions stored in map.
    :param func_map: function map you want xrefs for
    :return:
    """
    for name, address in func_map.items():
        code_refs = CodeRefsTo(int(address), 0)
        for ref in code_refs:
            # xref = "0x%08x" % ref
            print("[+] Found 0x{addr:08x} xref to {}".format(name, addr=ref))


def get_driver_id(driver_entry_addr):
    """
    Attempts to determine the type of the loaded driver by using functions found inside the imports section.
    :param driver_entry_addr: `DriverEntry` address
    :return string: return the detected driver type
    """
    print("[>] Trying to determine driver type...")
    driver_type = ""
    # Iterate through imports and try to determine driver type
    for name, address in imports_map.items():
        if name == "FltRegisterFilter":
            driver_type = "Mini-Filter"
            break
        elif name == "WdfVersionBind":
            driver_type = "WDF"
            populate_wdf()
            break
        elif name == "StreamClassRegisterMinidriver":
            driver_type = "Stream Minidriver"
            break
        elif name == "KsCreateFilterFactory":
            driver_type = "AVStream"
            break
        elif name == "PcRegisterSubdevice":
            driver_type = "PortCls"
            break
        else:
            continue
    if driver_type == "":
        print("[!] Unable to determine driver type; assuming WDM")
        # Only WDM drivers make it here so run all the WDM stuff
        driver_type = "WDM"
        real_driver_entry = check_for_fake_driver_entry(driver_entry_addr)
        real_ddc_addr = locate_ddc(real_driver_entry)
        if real_ddc_addr is not None:
            for ddc in real_ddc_addr.values():
                define_ddc(ddc)
    return driver_type


def is_driver():
    """
    Determine if the loaded file is actually a Windows driver, check if `DriverEntry` is in the exports section.
    :return: address of `DriverEntry` if found in exports, False otherwise
    """
    print("[>] Checking for `DriverEntry`")
    for segment_address in Segments():
        for func_addr in Functions(get_segm_start(segment_address), get_segm_end(segment_address)):
            func_name = get_func_name(func_addr)
            if func_name == "DriverEntry":
                return func_addr
    return False
