from vyos import (
    VyOSRouter,
    VyOSConfigItem,
    VyOSConfiguration,
    IncorrectDefinitionOrderError,
)

from firewheel.control.experiment_graph import require_class


class VyOSConfigurationHelium(VyOSConfiguration):
    """
    Create configuration files for Helium-based VyOS routers (1.1.X).
    """

    config = {
        "system_login_level": "admin",
    }

    def create_system_login(self):
        """
        Creates the 'login' block which is nested inside the 'system' block

        Raises:
            IncorrectDefinitionOrderError: Must set system hostname before
                setting the system login.
        """
        super().create_system_login()

        # find the 'user' block
        user = self.root.recursive_find("user")
        if not user:
            # 'user' block has not been created and needs to be before moving
            # forward.
            raise IncorrectDefinitionOrderError(
                "Must set user before updating the system login."
            )

        # create the 'level' block
        level = VyOSConfigItem("level", self.config["system_login_level"])
        user.add_children(level)

    def create_bgp_neighbors(self, neighbor_info):
        """
        Loop the BGP peer information and create config item objects
        for each.

        Arguments:
            neighbor_info (dict): BGP peer information. Structure defined in comments
                in set_router_bgp()

        Returns:
            list: The list of all neighbors that were created.
        """
        neighbors = super().create_bgp_neighbors(neighbor_info)

        # Loop through all the neighbors
        for neighbor in neighbors:
            # Create the next-hop parameter
            next_hop = VyOSConfigItem("nexthop-self")
            neighbor.add_children(next_hop)

        # return all the neighbors just created
        return neighbors

    def create_ssh_service(self):
        """
        Create 'ssh' block which is nested in the 'service' block

        Raises:
            IncorrectDefinitionOrderError: Must set ssh service through the
                :py:meth:`vyos.VyOSConfiguration.set_service` method.
        """
        super().create_ssh_service()
        ssh = self.root.recursive_find("ssh")
        if not ssh:
            # 'ssh' block has not been created and needs to be before moving
            # forward.
            raise IncorrectDefinitionOrderError("Must create ssh.")

        allowroot = VyOSConfigItem("allow-root")
        ssh.add_children(allowroot)


@require_class(VyOSRouter)
class Helium118:
    """
    This object provides the VyOS Helium 1.1.8 image to a VM.
    """

    def __init__(self, name=None):
        """
        Initializes the Heium118 object and configures the VM parameters.

        Arguments:
            name (str): The name for the router VM.

        Raises:
            RuntimeError: If the vertex doesn't have a name.
        """
        self.name = getattr(self, "name", name)

        if not self.name:
            raise RuntimeError("Name must be specified for Helium 1.1.8 router!")

        self.vm = getattr(self, "vm", {})

        if "architecture" not in self.vm:
            self.vm["architecture"] = "x86_64"
        if "vcpu" not in self.vm:
            self.vm["vcpu"] = {
                "model": "qemu64",
                "sockets": 1,
                "cores": 1,
                "threads": 1,
            }
        if "mem" not in self.vm:
            self.vm["mem"] = 256
        if "drives" not in self.vm:
            self.vm["drives"] = [
                {"db_path": "vyos-1.1.8.qc2.xz", "file": "vyos-1.1.8.qc2"}
            ]
        if "vga" not in self.vm:
            self.vm["vga"] = "std"

        self.set_image("vyos-1.1.8")
        self.vyos_config_class = VyOSConfigurationHelium()
