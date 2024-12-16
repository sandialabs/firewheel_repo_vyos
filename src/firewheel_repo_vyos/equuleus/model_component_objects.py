from vyos import (
    VyOSRouter,
    VyOSConfigItem,
    VyOSConfiguration,
    IncorrectDefinitionOrderError,
)

from firewheel.control.experiment_graph import require_class


class VyOSConfigurationEquuleus(VyOSConfiguration):
    """
    Create configuration files for Equuleus-based VyOS routers (1.3.X).
    """

    config = {}

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
            address = VyOSConfigItem("address-family", "ipv4-unicast")
            neighbor.add_children(address)

            # Create the next-hop parameter
            next_hop = VyOSConfigItem("nexthop-self")
            address.add_children(next_hop)

        # return all the neighbors just created
        return neighbors

    def create_protocols_bgp_redistribute_ospf(self, bgp_config):
        """
        Create the 'redistribution' block that is nested inside of the
        'protocols' block. Specifies which BGP links redistribute
        OSPF information.

        Arguments:
            bgp_config (dict): Specifies which BGP links will be redistributing
                OSPF information. Structure defined in comments of set_router_ospf()

        Returns:
            VyOSConfigItem: The "redistribute" configuration item.

        Raises:
            IncorrectDefinitionOrderError: Must specify BGP information before
                specifying redistribution of OSPF on BGP links.
        """
        if "redistribution" not in bgp_config:
            # no redistribution happening, nothing to do
            return

        protocols = self.root.find("protocols")
        if not protocols:
            raise IncorrectDefinitionOrderError(
                "Must specify BGP information "
                + "before specifying redistribution "
                + "of OSPF on BGP links"
            )

        bgp = protocols.find("bgp")
        if not bgp:
            raise IncorrectDefinitionOrderError(
                "Must specify BGP information "
                + "before specifying redistribution "
                + "of OSPF on BGP links"
            )

        address = VyOSConfigItem("address-family", "ipv4-unicast")
        bgp.add_children(address)

        redistribute = VyOSConfigItem("redistribute")
        address.add_children(redistribute)

        return redistribute


@require_class(VyOSRouter)
class Equuleus:
    """
    This object provides the VyOS Equuleus 1.3.x image to a VM.
    """

    def __init__(self, name=None):
        """
        Initializes the Equuleus object and configures the VM parameters.

        Arguments:
            name (str): The name for the router VM.

        Raises:
            RuntimeError: If the vertex doesn't have a name.
        """
        self.name = getattr(self, "name", name)

        if not name and not self.name:
            raise RuntimeError("Name must be specified for Equuleus 1.3.x router!")
        if name:
            self.name = name

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
                {"db_path": "vyos-equuleus.qc2.xz", "file": "vyos-equuleus.qc2"}
            ]
        if "vga" not in self.vm:
            self.vm["vga"] = "std"

        self.set_image("vyos-equuleus")
        self.vyos_config_class = VyOSConfigurationEquuleus()
