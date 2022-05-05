from idaapi import *
from idautils import *
from idc import *

"""
WDM driver specific function calls.
"""


def check_for_fake_driver_entry(driver_entry_address):
    """
    Checks if DriverEntry in WDM driver is fake and try to recover the real one
    :param driver_entry_address: Autodetected address of `DriverEntry` function
    :return: real_driver_entry address
    """
    address = get_func(driver_entry_address)
    end_address = address.end_ea
    while print_insn_mnem(end_address) != "jmp" and print_insn_mnem(end_address) != "call":
        end_address -= 0x1
    # e.g print_operand(end_address, 0) = sub_11008
    real_driver_entry_address = get_name_ea_simple(print_operand(end_address, 0))
    if hex(real_driver_entry_address) != "0xffffffffffffffff":
        print("[+] Found real `DriverEntry` address at 0x{addr:08x}".format(addr=real_driver_entry_address))
        set_name(real_driver_entry_address, "Real_Driver_Entry")
        return real_driver_entry_address
    else:
        print("[!] Cannot find real `DriverEntry`; using IDA's one at 0x{addr:08x}".format(addr=driver_entry_address))
        return driver_entry_address


def locate_ddc(driver_entry_address):
    """
    Tries to automatically discover the `DispatchDeviceControl` in WDM drivers.
    Also looks for `DispatchInternalDeviceControl`. Has some experimental DDC searching
    :param driver_entry_address: Address of `DriverEntry` function found using check_for_fake_driver_entry.
    :return: dictionary containing `DispatchDeviceControl` and `DispatchInternalDeviceControl` addresses, None otherwise
    """
    driver_entry_func = list(FuncItems(driver_entry_address))
    # Offset to search for `DispatchDeviceControl` loaded into `DriverObject` struct
    ddc_offset = "+0E0h]"
    didc_offset = "+0E8h]"
    dispatch = {}
    # Enumerate the `DriverEntry` function and check if `DriverObject` struct loads address of `DispatchDeviceControl`
    prev_instruction = driver_entry_func[0]
    for i in driver_entry_func[1:]:
        if ddc_offset in print_operand(i, 0)[4:] and print_insn_mnem(prev_instruction) == "lea":
            real_ddc = get_name_ea_simple(print_operand(prev_instruction, 1))
            print("[+] Found `DispatchDeviceControl` at 0x{addr:08x}".format(addr=real_ddc))
            set_name(real_ddc, "DispatchDeviceControl")
            dispatch["ddc"] = real_ddc
        if didc_offset in print_operand(i, 0)[4:] and print_insn_mnem(prev_instruction) == "lea":
            real_didc = get_name_ea_simple(print_operand(prev_instruction, 1))
            print("[+] Found `DispatchInternalDeviceControl` at 0x{addr:08x}".format(addr=real_didc))
            set_name(real_didc, "DispatchInternalDeviceControl")
            dispatch["didc"] = real_didc
        prev_instruction = i

    # if we already have `DispatchDeviceControl` return it
    if "ddc" in dispatch:
        return dispatch
    # otherwise, try some experimental `DispatchDeviceControl` searching:
    # check for case where function is loading known `IO_STACK_LOCATION` & `IRP` addresses,
    # indicating it could be the `DispatchDeviceControl`.
    # probably going to give you false-positives
    print("[!] Unable to locate `DispatchDeviceControl`; using some experimental searching")
    ddc_list = []
    for f in Functions():
        # For each function, get list of all instructions
        instructions = list(FuncItems(f))
        iocode = "0xDEADB33F"  # no idea from where it come from
        iostack_location = "[rdx+0B8h]"
        for i in instructions:
            if iostack_location in print_operand(i, 1):
                iostack_register = print_operand(i, 0)
                iocode = "[" + iostack_register + "+18h]"
            if iocode in GetDisasm(i):
                ddc_list.append(f)
    real_ddc = {}
    # Go through potential list of `DispatchDeviceControl` and see if they get called from `DriverEntry`,
    # if so, then it might be real deal
    for ddc in ddc_list:
        for count, refs in enumerate(XrefsTo(ddc, 0)):
            reffunc = get_func(refs.frm)
            if reffunc is not None and reffunc.start_ea == driver_entry_address:
                real_ddc[count] = ddc
                print("[+] Possible `DispatchDeviceControl` at 0x{addr:08x}".format(addr=ddc))
                set_name(ddc, "Possible_DispatchDeviceControl_{}".format(count))
    if real_ddc != {}:
        return real_ddc
    else:
        return None


def define_ddc(ddc_address):
    """
    Defines known structs in the `DispatchDeviceControl`
    :param ddc_address: Address of possible `DispatchDeviceControl`, found using locate_ddc.
    :return: None
    """
    # Special hidden IDA function to load "standard structures"
    irp_id = import_type(-1, "IRP")
    io_stack_location_id = import_type(-1, "IO_STACK_LOCATION")
    device_object_id = import_type(-1, "DEVICE_OBJECT")
    # Register canaries
    io_stack_reg = "io_stack_reg"
    irp_reg = "irp_reg"
    device_object_reg = "device_object_reg"
    rdx_flag = 0
    rcx_flag = 0
    io_stack_flag = 0
    irp_reg_flag = 0
    # Get list of all instructions of DispatchDeviceControl function
    instructions = list(FuncItems(ddc_address))
    # Scan instructions until we discover RCX, or RDX register being used
    for i in instructions:
        disasm = GetDisasm(i)
        src = print_operand(i, 1)
        if "rdx" in disasm and rdx_flag != 1 or irp_reg in disasm and irp_reg_flag != 1:
            # Check for `IO_STACK_LOCATION`
            if "+0B8h" in disasm:
                if "rdx+0B8h" in src or irp_reg + "+0B8h" in src:
                    op_stroff(i, 1, irp_id, 0)
                    # If it is a MOV, we want to save where `IO_STACK_LOCATION` is
                    if print_insn_mnem(i) == "mov":
                        io_stack_reg = print_operand(i, 0)
                        io_stack_flag = 0
                        print("[+] Stored `IO_STACK_LOCATION` in {}".format(io_stack_reg))
                else:
                    op_stroff(i, 0, irp_id, 0)
                print("[+] Made struct `IO_STACK_LOCATION`")
            # Check for `SystemBuffer`
            elif "+18h" in disasm:
                if "rdx+18h" in src or irp_reg + "+18h" in src:
                    op_stroff(i, 1, irp_id, 0)
                else:
                    op_stroff(i, 0, irp_id, 0)
                print("[+] Made struct `IRP + SystemBuffer`")
            # Check for `IoStatus.Information`
            elif "+38h" in disasm:
                if "rdx+38h" in src or irp_reg + "+38h" in src:
                    op_stroff(i, 1, irp_id, 0)
                else:
                    op_stroff(i, 0, irp_id, 0)
                print("[+] Made struct `IRP + IoStatus.Information`")
            # Need to keep track of where `IRP` is being moved
            elif print_insn_mnem(i) == "mov" and (src == "rdx" or src == irp_reg):
                irp_reg = print_operand(i, 0)
                irp_reg_flag = 0
                print("[+] Stored `IRP` in {}".format(irp_reg))
            # rdx got clobbered
            elif print_insn_mnem(i) == "mov" and print_operand(i, 0) == "rdx":
                print("[+] RDX got clobbered: {}".format(GetDisasm(i)))
                rdx_flag = 1
            # irp_reg got clobbered
            elif print_insn_mnem(i) == "mov" and print_operand(i, 0) == irp_reg:
                print("[+] IRP got clobbered: {}".format(GetDisasm(i)))
                irp_reg_flag = 1
            else:
                "[!] ERR: something weird happened {}".format(GetDisasm(i))
        elif "rcx" in disasm and rcx_flag != 1:
            # Check for DEVICE_OBJECT.Extension
            if "rcx+40h" in disasm:
                if "rcx+40h" in src:
                    op_stroff(i, 1, device_object_id, 0)
                else:
                    op_stroff(i, 0, device_object_id, 0)
                print("[+] Made struct `DEVICE_OBJECT.Extension`")
            # Need to keep track of where `DEVICE_OBJECT` is being moved
            elif print_insn_mnem(i) == "mov" and src == "rcx":
                device_object_reg = print_operand(i, 0)
                print("[+] Stored `DEVICE_OBJECT` in {}".format(device_object_reg))
            # rcx got clobbered
            elif print_insn_mnem(i) == "mov" and print_operand(i, 0) == "rcx":
                print("[+] RCX got clobbered: {}".format(GetDisasm(i)))
                rcx_flag = 1
        elif io_stack_reg in disasm and io_stack_flag != 1:
            print("[+] io_stack_reg = {}; {}".format(io_stack_reg, GetDisasm(i)))
            # Check for `DeviceIoControlCode` which is `IO_STACK_LOCATION+18h`
            if io_stack_reg + "+18h" in disasm:
                if io_stack_reg + "+18h" in src:
                    op_stroff(i, 1, io_stack_location_id, 0)
                else:
                    op_stroff(i, 0, io_stack_location_id, 0)
                print("[+] Made struct `IO_STACK_LOCATION + DeviceIoControlCode`")
            # Check for InputBufferLength which is `IO_STACK_LOCATION+10h`
            elif io_stack_reg in "+10h" in disasm:
                if io_stack_reg + "+10h" in src:
                    op_stroff(i, 1, io_stack_location_id, 0)
                else:
                    op_stroff(i, 1, io_stack_location_id, 0)
                print("[+] Made struct `IO_STACK_LOCATION + InputBufferLength`")
            # Check for OutputBufferLength which is `IO_STACK_LOCATION+8`
            elif io_stack_reg + "+8" in disasm:
                if io_stack_reg + "+8" in src:
                    op_stroff(i, 1, io_stack_location_id, 0)
                else:
                    op_stroff(i, 0, io_stack_location_id, 0)
                print("[+] Made struct `IO_STACK_LOCATION + OutputBufferLength`")
            # io_stack_reg is being clobbered
            elif print_insn_mnem(i) == "mov" and print_operand(i, 0) == io_stack_reg:
                io_stack_flag = 1
        else:
            continue
            # print("[+] nothing interesting in 0x{addr:08x}\nInstruction: {}".format(GetDisasm(i), addr=i))
