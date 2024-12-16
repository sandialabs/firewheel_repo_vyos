#!/usr/bin/env python

import sys
import pickle
from subprocess import PIPE, Popen


# pylint: disable=useless-object-inheritance
class InterfaceRemap(object):
    """
    This VM Resource helps to remap the MAC addresses on VyOS to a particular
    interface/IP address. This is required because at experiment creation time
    the interface names (e.g. ``eth0``) are assumed to have some specific MAC
    address (called a hardware id by VyOS) (e.g. ``00:00:00:00:00:06``).
    However, when the VM starts the particular MAC address is not *guaranteed*
    to be assigned to a given interface name. Therefore, this script will identify
    which interfaces have which particular MAC address, and update the script with
    the correct MAC address as needed.
    """

    def __init__(self, ascii_file, binary_file=None):
        """
        Initialize the configuration file as a class variable.

        Arguments:
            ascii_file (str): The path to the configuration file, which should contain
                a dictionary in pickle format. The dictionary should look like::
                    {
                        "configuration_location": <path to VyOS configuration>
                    }
            binary_file (str): This is not used, but kept for backwards compatibility.
        """
        self.ascii_file = ascii_file
        self.binary_file = binary_file

    def _build_existing_map(self):
        """
        Identify the existing mapping of interface names to MAC addresses.
        """
        self.existing_interfaces = {}
        # The python installed on VyOS doesn't have the check_output call.
        process = Popen(["ip", "li"], stdout=PIPE)
        (interfaces, err) = process.communicate()

        iface = None
        for line in interfaces.strip().split("\n"):
            if "link/ether" not in line:
                iface = line.split()[1].strip(":")
            else:
                mac = line.split()[1]
                self.existing_interfaces[mac] = iface

    def _build_config_map(self, config_script_file):
        """
        Identify where in the existing configuration file, the ``hw-id`` is used.

        Arguments:
            config_script_file (str): The path to the VyOS configuration.
        """
        self.config_interfaces = {}
        with open(config_script_file, "r") as f:
            for line in f:
                split_line = line.strip().split()
                if "hw-id" in split_line:
                    self.config_interfaces[split_line[5]] = split_line[3]

    def _build_rename_map(self):
        """
        Rebuild the configuration mapping based on the existing interface mapping.
        """
        # Keyed on config name, value is existing name.
        self.rename_map = {}

        for k in self.config_interfaces:
            if k in self.existing_interfaces:
                self.rename_map[self.config_interfaces[k]] = self.existing_interfaces[k]
            else:
                print("Warning: Unmapped interface in config: %s." % k)

    def _rename_script_interfaces(self, script_file):
        """
        Update the configuration script with the new mapping.

        Arguments:
            script_file (str): The configuration script path.
        """
        with open(script_file, "r") as f:
            config_script = f.read()
        line_arr = config_script.strip().split("\n")
        new_arr = []
        index = 0

        for line in line_arr:
            split_line = line.strip().split()
            for iface in self.rename_map:
                try:
                    loc = split_line.index(iface)
                    split_line[loc] = self.rename_map[iface]
                    # WARNING: We have the potential for loops of renaming with
                    # this. Assuming 1 interface name per line, ever.
                    break
                except ValueError:
                    # string wasn't found, move on.
                    pass
            new_arr.append(" ".join(split_line))
            index += 1
        print("\n".join(new_arr))
        with open(script_file, "w") as f:
            f.write("\n".join(new_arr))

    def run(self):
        """
        Execute the entire VMR and print some of the output during execution.
        """
        with open(self.ascii_file, "r") as f:
            self.config = pickle.load(f)

        self._build_existing_map()
        print(self.existing_interfaces)
        self._build_config_map(self.config["configuration_location"])
        print(self.config_interfaces)
        self._build_rename_map()
        print(self.rename_map)
        self._rename_script_interfaces(self.config["configuration_location"])


if __name__ == "__main__":
    ascii_file = sys.argv[1]
    iface_rename = InterfaceRemap(ascii_file)
    iface_rename.run()
