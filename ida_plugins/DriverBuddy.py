from DriverBuddy import data
from DriverBuddy import ioctl
from idaapi import *
from idautils import *
from idc import *

"""
DriverBuddy.py: Entry point for IDA python plugin used in Windows driver vulnerability research.

Written by Braden Hollembaek, Adam Pond of NCC Group; Paolo Stagno of VoidSec
"""


class DriverBuddyPlugin(plugin_t):
    flags = PLUGIN_UNL
    comment = ("Plugin to aid in Windows driver vulnerability research. " +
               "Automatically tries to find IOCTL handlers, decode IOCTLS, " +
               "flag dangerous C/C++ functions, find Windows imports for privesc, " +
               "and identify the type of Windows driver.")
    help = ""
    wanted_name = "Driver Buddy"
    wanted_hotkey = "Ctrl-Alt-D"

    def init(self):
        self.hotkeys = []
        self.hotkeys.append(add_hotkey("Ctrl+Alt+I", self.decode))
        return PLUGIN_KEEP

    def run(self, args):
        print("[+] Welcome to Driver Buddy!")
        auto_wait()  # Wait for IDA autoanalysis to complete
        driver_entry_addr = data.is_driver()
        if driver_entry_addr is False:
            print("[!] ERR: cannot find `DriverEntry` stub")
            print("[-] Exiting...")
        else:
            print("[+] `DriverEntry` found at: 0x{addr:08x}".format(addr=driver_entry_addr))
            if data.populate_data_structures() is True:
                driver_type = data.get_driver_id(driver_entry_addr)
                print(("[+] Driver type detected: {}".format(driver_type)))
                if ioctl.find_ioctls() is False:
                    print("[!] Unable to automatically find any IOCTLs")
            else:
                print("[!] ERR: unable to enumerate functions")
                print("[-] Exiting...")
        print("[+] Driver Buddy analysis completed!")
        return

    def decode(self, _=0):
        # TODO make a menu for this
        if idc.get_operand_type(idc.get_screen_ea(), 1) != 5:  # Immediate
            return
        value = idc.get_operand_value(idc.get_screen_ea(), 1) & 0xffffffff
        ioctl.get_ioctl_code(value)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DriverBuddyPlugin()
