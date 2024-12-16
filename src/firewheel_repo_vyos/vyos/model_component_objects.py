import pickle

from netaddr import IPAddress, IPNetwork
from base_objects import Switch
from generic_vm_objects import GenericRouter

from firewheel.control.experiment_graph import require_class

config = {
    "vyos_system_username": "vyos",
    "vyos_system_password": "vyos",
    "interfaces_duplex": "auto",
    "interfaces_smp_affinity": "auto",
    "snmp_community": "public",
    "default_lease_time": "infinite",
    "ssh_port": "22",
    "ssh_version": "2",
    "netflow_version": "5",  # 9 or 5
    "netflow_sampling_rate": "1024",  # if needed (due to too much traffic)
    # then uncomment the sampling-rate block in
    # vyosconfig.py or ciscoconfig.py
    "netflow_expiry_interval": "10",
    "netflow_flow_generic": "10",
    "netflow_icmp": "10",
    "netflow_max_active_life": "10",
    "netflow_tcp_fin": "10",
    "netflow_tcp_generic": "10",
    "netflow_tcp_rst": "10",
    "netflow_udp": "10",
    "control_ip_network_base": "172",
    "default_out_firewall_name": "fw_default_out",
}


@require_class(GenericRouter)
class VyOSRouter:
    """
    This object provides some generic functionality that is common to all
    versions of VyOS virtual router operating system
    If the router isn't already a GenericRouter this will fail on ``__init__``
    arguments missing.
    """

    def __init__(self, name=None):
        """
        Initialize the VM as a VyOS router.

        This schedules dropping the VyOS config (as a callback function)
        and configuring the system.

        Args:
            name (str, optional): The name of the VM. Defaults to None.

        Raises:
            NameError: If the Vertex does not have a name.
        """
        self.name = getattr(self, "name", name)

        if not self.name:
            raise NameError("Must specify name for VyOS router!")

        self.vyos_config_class = getattr(self, "vyos_config_class", None)

        self._firewall_policies = None
        self.assign_firewall_policies({})

        configuration_location = "/opt/vyatta/etc/config/firewheel-config.sh"

        # Drop the configuration file on the router.
        # This is done by supplying a callback to the ScheduleEntry.
        # This will be called when the schedule is being generated to be uploaded
        self.drop_content(
            -100, configuration_location, self._configure_vyos, executable=True
        )

        remap_config = {"configuration_location": configuration_location}
        self.add_vm_resource(
            -97,
            "interface_remap.py",
            pickle.dumps(remap_config, protocol=0).decode(),
            None,
        )

        # Run the configuration script to actually configure the router
        self.run_executable(-95, f"/bin/vbash {configuration_location}")

    def add_default_profiles(self):
        """
        Adds default ssh keys, .bashrc, .vimrc, etc. to both the ``root`` and ``vyos`` user.
        """
        # root
        self.drop_file(-249, "/root/combined_profiles.tgz", "combined_profiles.tgz")
        self.run_executable(
            -248, "chown", "-R root:root /root/combined_profiles.tgz", vm_resource=False
        )
        self.run_executable(
            -247, "tar", "--no-same-owner -C /root/ -xf /root/combined_profiles.tgz"
        )
        self.run_executable(-246, "rm", "-f /root/combined_profiles.tgz")

        # vyos
        self.drop_file(
            -249, "/home/vyos/combined_profiles.tgz", "combined_profiles.tgz"
        )
        self.run_executable(
            -248,
            "chown",
            "-R vyos:vyos /home/vyos/combined_profiles.tgz",
            vm_resource=False,
        )
        self.run_executable(
            -247,
            "su",
            'vyos -c "tar -C /home/vyos -xf /home/vyos/combined_profiles.tgz"',
        )
        self.run_executable(-246, "rm", "-f /home/vyos/combined_profiles.tgz")

    def assign_firewall_policies(self, policies):
        """
        Assign firewall policies/rules to the router.

        Args:
            policies (dict): A mapping between policy categories and a
                list containing rule sets and/or groups that apply to the policy
                category. Keys be a subset of ``{"in", "out", "local"}`` and values must
                be a list of :py:class:`VyOSConfigItem` objects.
        """
        VyOSRouter._validate_firewall_policies(policies)
        self._firewall_policies = policies
        # Set default policy values (if not otherwise specified)
        def_out_fw = VyOSConfigItem("name", config["default_out_firewall_name"])
        def_out_fw.add_children(VyOSConfigItem("default-action", "accept"))
        self._firewall_policies.setdefault("out", [def_out_fw])

    @staticmethod
    def _validate_firewall_policies(policies):
        permissible_keys = ["in", "out", "local"]
        if not all(_ in permissible_keys for _ in policies.keys()):
            raise ValueError(
                "The only valid policy categories are 'in', 'out', and 'local'."
            )
        if not all(isinstance(_, list) for _ in policies.values()):
            raise TypeError("The values for each policy must be a `list`.")
        for values in policies.values():
            if not all(isinstance(_, VyOSConfigItem) for _ in values):
                raise TypeError(
                    "Groups and Rule sets must be provided as instances of "
                    "`VyOSConfigItem` objects."
                )

    def _configure_vyos(self):
        """
        Configure VyOS by setting interfaces, OSPF, BGP, DHCP, etc.

        Returns:
            str: The configuration script as a string.

        Raises:
            RuntimeError: If the ``self.vyos_config_class`` is not an instance of
                :py:class:`vyos.VyOSConfiguration`.
        """
        # The specific instance of a :py:class:`vyos.VyOSConfiguration`
        # to use. Defaults to :py:class:`vyos.VyOSConfiguration`.
        if self.vyos_config_class is None:
            self.vyos_config_class = VyOSConfiguration()

        if not isinstance(self.vyos_config_class, VyOSConfiguration):
            raise RuntimeError(
                f"The `vyos_config_class` attribute {self.vyos_config_class} of this "
                "`VyOSRouter` object must be an instance of `VyOSConfiguration`"
            )
        self.vc = self.vyos_config_class
        self.vc.set_router_interfaces(
            self.interfaces.interfaces, self._firewall_policies
        )
        try:
            self.vc.set_router_ospf(self.routing)
            self.vc.set_router_bgp(self.routing)
            self.vc.set_router_static(self.routing)
        except AttributeError:
            self.log.debug("VyOS was not configured for routing")

        self.vc.set_firewall(rule_sets=self._firewall_policies.values())
        self.vc.set_service()
        self.vc.set_system(self.name)
        try:
            self._resolve_nat()
            self.vc.set_nat(self.nat)
        except AttributeError:
            self.log.debug("VyOS was not configured for NAT")

        self._configure_dhcp()

        # If the router is configured for netflow then
        # enable forwarding to a collector
        try:
            if self.netflow:
                self.vc.create_flow_accounting(self.netflow)
        except AttributeError:
            self.log.debug("VyOS was not configured for netflow.")

        configuration = self.vc.build_configuration_script()

        return configuration

    def _resolve_nat(self):
        """
        Resolve a NAT block so all specifications use the detailed syntax and
        interfaces refer to names, not nat-labels.
        This is needed for the configuration generation to function properly.
        """
        self._resolve_nat_simplified_syntax()
        self._resolve_nat_interfaces()

    def _resolve_nat_interfaces(self):
        """
        Resolve a NAT block so all interface references use name, not nat-label.
        Assumes all rules are already use detailed syntax.

        Raises:
            ValueError: If there is an invalid NAT rule.
        """
        try:
            if not self.nat:
                return
        except AttributeError:
            return

        for rule in self.nat:
            if "interface" in rule:
                for iface in self.interfaces.interfaces:
                    if "nat-label" in iface and iface["nat-label"] == rule["interface"]:
                        rule["interface"] = iface["name"]
                        continue
            else:
                # All rules should be resolved to full syntax by now--that means
                # even with the simplified syntax they should have a 'type'
                # field.
                if "type" not in rule:
                    raise ValueError(
                        'NAT rule on %s is missing required "type" value. '
                        'Please specify either "source" or "destination". Rule: %s'
                        % (self.name, rule)
                    )

                if rule["type"] == "source":
                    for iface in self.interfaces.interfaces:
                        if (
                            "address" in rule["translation"]
                            and rule["translation"]["address"] != "masquerade"
                        ):
                            # Setting the NAT access address to the local
                            # interface address doesn't do much good.
                            # We instead check that the address given for NAT is
                            # in the same subnet as an interface's address.
                            iface_subnet = IPNetwork(
                                f"{iface['address']}/{iface['netmask']}"
                            )
                            nat_addr = IPAddress(rule["translation"]["address"])
                            if nat_addr in iface_subnet:
                                rule["interface"] = iface["name"]
                                continue
                        elif (
                            "subnet" in rule["translation"]
                            and rule["translation"]["subnet"]
                        ):
                            nat_subnet = IPNetwork(rule["translation"]["subnet"])
                            iface_addr = IPAddress(iface["address"])
                            if iface_addr in nat_subnet:
                                rule["interface"] = iface["name"]
                                continue
                elif rule["type"] == "destination":
                    for iface in self.interfaces:
                        if "address" in rule["access"] and rule["access"]["address"]:
                            iface_subnet = IPNetwork(
                                f"{iface['address']}/{iface['netmask']}"
                            )
                            nat_addr = IPAddress(rule["access"]["address"])
                            if nat_addr in iface_subnet:
                                rule["interface"] = iface["name"]
                                continue
                        elif "subnet" in rule["access"] and rule["access"]["subnet"]:
                            nat_subnet = IPNetwork(rule["access"]["subnet"])
                            iface_addr = IPAddress(iface["address"])
                            if iface_addr in nat_subnet:
                                rule["interface"] = iface["name"]
                                continue

    def _resolve_nat_simplified_syntax(self):
        """
        Resolve a NAT block so all rules use the detailed syntax.

        Raises:
            ValueError: If there is an invalid NAT rule.
        """
        try:
            if not self.nat:
                return
        except AttributeError:
            return

        new_rules = []

        for rule in self.nat:
            # Translate masquerade rules to detailed syntax.
            if "masquerade" in rule:
                rule["type"] = "source"
                rule["translation"] = {"address": "masquerade"}
                subnet_list = rule["subnet_list"]
                rule["access"] = {}
                rule["access"]["subnet"] = f"{subnet_list[0]}"
                rule["interface"] = rule["masquerade"]

                if len(subnet_list) > 1:
                    # Build additional rules.
                    for cur_subnet in subnet_list[1:]:
                        new_rule = {
                            "type": "source",
                            "translation": {"address": "masquerade"},
                            "access": {"subnet": f"{cur_subnet}"},
                            "interface": rule["masquerade"],
                        }
                        new_rules.append(new_rule)

            # Translate port forward rules to detailed syntax.
            if "port forward" in rule:
                for port in rule["port forward"]:
                    firstarr = port.split("/")
                    orig_port = firstarr[0]
                    try:
                        protocol = firstarr[1]
                    except IndexError as exp:
                        raise ValueError(
                            'Must specify incoming port as "port/protocol". Had "%s".'
                            % port
                        ) from exp

                    valarr = rule["port forward"][port].split(":")
                    dest_addr = valarr[0]
                    try:
                        dest_port = valarr[1]
                    except IndexError as exp:
                        raise ValueError(
                            'Must specify the NAT destination as "address:port". Had "%s"'
                            % rule["port forward"][port]
                        ) from exp

                    # Find the interface that has the dest_addr.
                    # If there is more than 1 other non-control addr,
                    # generate more rules
                    # Each rule: interface is other interface
                    # my_addr is iface address
                    control_net_names = self._find_control_network()
                    dest_ip = IPAddress(dest_addr)
                    src_ifaces = []
                    for iface in self.interfaces:
                        iface_subnet = IPNetwork(
                            f"{iface['address']}/{iface['netmask']}"
                        )

                        if dest_ip in iface_subnet:
                            my_addr = iface["address"]
                        elif iface["name"] not in control_net_names:
                            src_ifaces.append(
                                {"name": iface["name"], "address": iface["address"]}
                            )

                    if len(src_ifaces) == 0:
                        # We couldn't determine a source interface for the rule.
                        # This is a fatal error--the rule must specify an interface.
                        # NAT processing could continue, but we have an invalid rule here.
                        raise ValueError(
                            "Invalid NAT rule on %s--cannot determine source interface. Rule: %s"
                            % (self.name, rule)
                        )

                    iface = src_ifaces[0]["name"]

                    rule["type"] = "destination"
                    rule["translation"] = {"address": dest_addr, "port": dest_port}
                    rule["access"] = {"address": my_addr, "port": orig_port}
                    rule["interface"] = iface
                    rule["protocol"] = protocol

                    if len(src_ifaces) > 1:
                        # Build additional rules.
                        for cur_iface in src_ifaces[1:]:
                            new_rule = {
                                "type": "destination",
                                "translation": {
                                    "address": dest_addr,
                                    "port": dest_port,
                                },
                                "access": {"address": my_addr, "port": orig_port},
                                "interface": cur_iface["name"],
                                "protocol": protocol,
                            }
                            new_rules.append(new_rule)

        if len(new_rules) > 0:
            for rule in new_rules:
                self.nat.append(rule)

    def _configure_dhcp(self):
        """
        Determine if and where we need to run a DHCP server and find the
        necessary info to do so in the graph.
        Build the configuration entries for this.
        """
        dhcp_config = {}
        for iface in self.interfaces.interfaces:
            if "dhcp" in iface and iface["dhcp"] is True:
                net = str(iface["network"])
                net_name = iface["switch"].name
                dhcp_config[net_name] = {"authoritative": True}
                dhcp_config[net_name][net] = {}

                switch = iface["switch"]
                if switch.get("dns1"):
                    dhcp_config[net_name][net]["dns1"] = switch["dns1"]
                if switch.get("dns2"):
                    dhcp_config[net_name][net]["dns2"] = switch["dns2"]
                if switch.get("default_gw"):
                    dhcp_config[net_name][net]["gateway"] = switch["default_gw"]

                # Ignore domain for now

                # This is in seconds. Cisco will need to convert to days
                dhcp_config[net_name][net]["lease"] = 262144

                ipnet = iface["network"]
                start = str(IPAddress(ipnet.first + 1))
                stop = str(IPAddress(ipnet.last - 1))
                dhcp_config[net_name][net]["range"] = (start, stop)

                dhcp_config[net_name][net]["static-mapping"] = (
                    self._configure_dhcp_mappings(switch, self.name)
                )
                self.log.debug(
                    "DHCP static-mapping for %s: %s",
                    switch.name,
                    dhcp_config[net_name][net]["static-mapping"],
                )

        self.vc.set_dhcp_service(dhcp_config)

    def _configure_dhcp_mappings(self, switch, host_to_ignore):
        """
        Build a list of static mappings for IP addresses based on hosts
        connected to the network.

        Args:
            switch (base_objects.Switch): Switch for the network for which we are building the list.
            host_to_ignore (str): A name of a host for which we should ignore mapping.

        Returns:
            dict: A dictionary in the correct format for the 'static-mapping' field of a
            DHCP configuration.

        Raises:
            RuntimeError: The given switch was not decorated as a :py:class:`base_objects.Switch`.
        """
        hosts = {}
        if not switch.is_decorated_by(Switch):
            raise RuntimeError("The given switch was not decorated as a `Switch`.")

        neighbors = switch.get_neighbors()

        for neighbor in neighbors:
            if neighbor.name == host_to_ignore:
                continue
            # A switch could have non-host neighbors (e.g. SwitchBridge),
            # depending when exactly we run.
            try:
                for iface in neighbor.interfaces.interfaces:
                    if iface["switch"] == switch:
                        hosts[neighbor.name] = {
                            "ip": iface["address"],
                            "netmask": iface["netmask"],
                            "mac": iface["mac"],
                        }
            except AttributeError:
                self.log.warning(
                    'Tried to access interfaces on "%s", but they don\'t exist.',
                    neighbor.name,
                )
        return hosts


class VyOSConfiguration:
    """
    Create configuration files for VyOS routers.
    Each OS may need minor differences in the command syntax, so this class
    and the methods within should be inherited extend functionality as needed.
    """

    config = ""
    root = None

    def __init__(self):
        """
        Constructor. Creates a root node that can be stored in the graph
        """
        self.root = VyOSConfigItem("root")

    def get_configuration_root(self):
        """
        Returns the root config item so that all the VyOSConfigItems can be
        stored in the graph.

        Returns:
            vyos.VyOSConfigItem: The root configuration item.
        """
        return self.root

    def build_configuration_script(self):
        """
        Generate the configuration script. This is called after all router
        attributes have been set. This traverses the tree to build the config
        and then returns the resulting configuration script

        Returns:
            str: The newly created configuration script.
        """
        # Add the required setup at the top of the config script
        config = ""
        config += (
            "#!/bin/vbash\n"
            "\n"
            "su vyos\n"
            "source /opt/vyatta/etc/functions/script-template\n"
            "\n"
        )

        # The following loop was put in place due to the commit sporadically
        # failing due to being unable to acquire a write lock causing the
        # Vyos router to end in an non-configured state breaking experiments.
        #
        # The key fix needed was checking based on the `vyatta_cli_shell_api`
        # as other attempts such as looking at the error code from `commit`
        # were unsuccessful. The idea was sourced from the `vyatta-cfg` source
        # code at https://github.com/vyos/vyatta-cfg/blob/equuleus/functions/interpreter/vyatta-cfg-run#L106
        #
        # The re-try is not very clean in the logs as you will see many warnings
        # that the configuration has already been set from the previous loop
        # execution, however it does end up working and that's the desired end result.
        config += (
            "COMMIT_FAILURE=1\n"
            "\n"
            "until (( ! $COMMIT_FAILURE )); do\n"
            "configure\n"
            "\n"
        )

        for child in self.root.children:
            child_commands = child.generate_commands("", [])

            for cmd in child_commands:
                config += f"set {cmd}\n"
        config += "\n"

        config += (
            "commit\n"
            "\n"
            "if ! vyatta_cli_shell_api sessionChanged; then\n"
            'echo "Commit succeeded, continuing"\n'
            "COMMIT_FAILURE=0\n"
            "else\n"
            'echo "Commit failed, restarting router to re-try"\n'
            "sudo /etc/init.d/vyatta-router restart\n"
            'echo "Sleeping for 120 seconds to allow router to restart"\n'
            "sleep 120\n"
            'echo "Done sleeping"\n'
            "fi\n"
            "\n"
            "done\n"
            "\n"
            "save\n"
            "exit\n"
            "exit\n"
        )

        config += "sudo chown -R root:vyattacfg /opt/vyatta/config/active\n"
        config += "sudo chown -R root:vyattacfg /opt/vyatta/etc/quagga/\n"

        return config

    def set_system(self, hostname):
        """
        Creates (if necessary) and sets the 'system' block in the
        configuration file.

        This is the main function for creating the 'system' block.
        A sample 'system' block looks like: ::

            system {
                host-name subnet-0-amsterdam-Rtr-0
                login {
                    user vyos {
                        authentication {
                            plaintext-password vyos
                        }
                        level admin
                    }
                }
            }

        Arguments:
            hostname (str): The name of the router
        """
        # Check to see if there is already a system block created
        system = self.root.find("system")
        if not system:
            # no system block exists, create one
            system = VyOSConfigItem("system")
            self.root.add_children(system)

        # hostname can not have dots or underscores, replace them
        # with hyphens
        hostname = hostname.replace(".", "-").replace("_", "-")
        name = VyOSConfigItem("host-name", hostname)
        system.add_children(name)

        # create the 'login' block
        self.create_system_login()

    def create_flow_accounting(self, router):
        """
        Configures flow accounting for the router

        Arguments:
            router(dict): The router to add flow accounting to
        """
        system = self.root.find("system")
        if not system:
            # no system block exists, create one
            system = VyOSConfigItem("system")
            self.root.add_children(system)

        flow_accounting = VyOSConfigItem("flow-accounting")
        system.add_children(flow_accounting)

        interfaces = router["interfaces"]
        # create a 'flow-accounting' block for each interface
        for iface in interfaces:
            # Don't configure netflow on control plane
            if iface["address"].startswith(config["control_ip_network_base"]) or iface[
                "address"
            ].startswith(
                "0.0.0.0"  # noqa: S104
            ):
                continue

            # Specify which interface for flow-accounting
            interface = VyOSConfigItem("interface", iface["name"])
            flow_accounting.add_children(interface)

        # Create block for netflow
        netflow = self.create_netflow(
            router["netflow_collector_ip"],
            router["netflow_collector_port"],
            router["netflow_engine_id"],
        )
        flow_accounting.add_children(netflow)

    def create_netflow(self, collector_ip, collector_port, engine_id):
        """
        Configures netflow for the router

        Arguments:
            collector_ip (str): The IP address of the collector
            collector_port (str): The port the collector runs on
            engine_id (str): The netflow engine ID

        Returns:
            vyos.VyOSConfigItem: The netflow configuration block.
        """
        netflow = VyOSConfigItem("netflow")

        # Add all fields inside the netflow block.
        # All are configurable in the config
        version = VyOSConfigItem("version", config["netflow_version"])
        netflow.add_children(version)

        eid = VyOSConfigItem("engine-id", engine_id)
        netflow.add_children(eid)

        server = VyOSConfigItem("server", collector_ip)
        port = VyOSConfigItem("port", collector_port)
        server.add_children(port)
        netflow.add_children(server)

        timeout = VyOSConfigItem("timeout")
        netflow.add_children(timeout)

        expiry_interval = VyOSConfigItem(
            "expiry-interval", config["netflow_expiry_interval"]
        )
        timeout.add_children(expiry_interval)

        flow_generic = VyOSConfigItem("flow-generic", config["netflow_flow_generic"])
        timeout.add_children(flow_generic)

        icmp = VyOSConfigItem("icmp", config["netflow_icmp"])
        timeout.add_children(icmp)

        max_active_life = VyOSConfigItem(
            "max-active-life", config["netflow_max_active_life"]
        )
        timeout.add_children(max_active_life)

        tcp_fin = VyOSConfigItem("tcp-fin", config["netflow_tcp_fin"])
        timeout.add_children(tcp_fin)

        tcp_rst = VyOSConfigItem("tcp-rst", config["netflow_tcp_rst"])
        timeout.add_children(tcp_rst)

        tcp_generic = VyOSConfigItem("tcp-generic", config["netflow_tcp_generic"])
        timeout.add_children(tcp_generic)

        udp = VyOSConfigItem("udp", config["netflow_udp"])
        timeout.add_children(udp)

        return netflow

    def create_system_login(self):
        """
        Creates the 'login' block which is nested inside the 'system' block

        Raises:
            IncorrectDefinitionOrderError: Must set system hostname before
                setting the system login.
        """
        # find the 'system' block
        system = self.root.find("system")
        if not system:
            # 'system' block has not been created and needs to be before moving
            # forward.
            raise IncorrectDefinitionOrderError(
                "Must set system hostname before setting the system login"
            )
        # create the 'login' block
        login = VyOSConfigItem("login")
        system.add_children(login)

        # create the 'user' block
        user = VyOSConfigItem("user", config["vyos_system_username"])
        login.add_children(user)

        # create the 'authentication' block
        authentication = VyOSConfigItem("authentication")
        user.add_children(authentication)

        # set the user's password
        password = VyOSConfigItem("plaintext-password", config["vyos_system_password"])
        authentication.add_children(password)

    def set_service(self):
        """
        Creates (if necessary) the 'service' block of the vyos configuration
        file. This is the main function for creating this block.

        A sample 'service' block looks like: ::

             service {
                ssh {
                    allow-root
                    port 22
                    protocol-version v2
                }
                snmp {
                    community public
                }
             }
        """
        # create the service block
        service = self.root.find("service")
        if not service:
            # No service block was found, create one
            service = VyOSConfigItem("service")
            self.root.add_children(service)

        # Create 'ssh' block
        self.create_ssh_service()

        # Create 'snmp' block
        self.create_snmp_service()

    def create_snmp_service(self):
        """
        Creates the 'snmp' block nested in the 'service' block

        Raises:
            IncorrectDefinitionOrderError: Must set snmp service through the
                :py:meth:`vyos.VyOSConfiguration.set_service` method.
        """
        service = self.root.find("service")
        if not service:
            # 'service' block was not found, force declaration of the 'snmp'
            # service block through the set_service function
            raise IncorrectDefinitionOrderError(
                "Must set snmp service through the set_service function"
            )

        snmp = service.find("snmp")
        if not snmp:
            snmp = VyOSConfigItem("snmp")
            service.add_children(snmp)

        # create 'community' parameter for snmp
        community = VyOSConfigItem("community", config["snmp_community"])
        snmp.add_children(community)

    def create_ssh_service(self):
        """
        Create 'ssh' block which is nested in the 'service' block

        Raises:
            IncorrectDefinitionOrderError: Must set ssh service through the
                :py:meth:`vyos.VyOSConfiguration.set_service` method.
        """
        service = self.root.find("service")
        if not service:
            # 'service' block was not found, force declaration of the 'ssh'
            # service block through the set_service function
            raise IncorrectDefinitionOrderError(
                "Must set ssh service through the set_service function"
            )

        ssh = service.find("ssh")
        if not ssh:
            ssh = VyOSConfigItem("ssh")
            service.add_children(ssh)

        # create port parameter
        port = VyOSConfigItem("port", config["ssh_port"])
        ssh.add_children(port)

    def set_dhcp_service(self, network_info):
        """
        Creates the 'dhcp-server' block which is nested in the 'service' block.

        Arguments:
            network_info(dict): Dictionary describing DHCP parameters (IP, CIDR as string): ::

                {
                    <network name>: {
                        'authoritative': <bool>
                        <cidr>: {
                            'gateway': <ip>,
                            'dns1': <ip>,
                            'dns2': <ip>,
                            'domain': <string>,
                            'lease': <int>,
                            'range': (<ip>, <ip>),
                            'static-mapping': {
                                <hostname>: {
                                    'ip': <ip>,
                                    'mac': <mac>
                                },
                                ...
                            }
                        },
                        ...
                    },
                    ...
                }
        """
        # If we have nothing to configure, don't do anything.
        if len(network_info.keys()) == 0:
            return

        service = self.root.find("service")
        if not service:
            # No service block was found, create one
            service = VyOSConfigItem("service")
            self.root.add_children(service)

        dhcp = service.find("dhcp-server")
        if not dhcp:
            dhcp = VyOSConfigItem("dhcp-server")
            service.add_children(dhcp)

        # Make sure DHCP is enabled.
        disabled = VyOSConfigItem("disabled", "false")
        dhcp.add_children(disabled)

        for net_name in network_info:
            network = VyOSConfigItem("shared-network-name", net_name)
            dhcp.add_children(network)

            if "authoritative" not in network_info[net_name]:
                # Assume not authoritative.
                if network_info[net_name]["authoritative"] is True:
                    auth_str = "enable"
                else:
                    auth_str = "disable"
                authoritative = VyOSConfigItem("authoritative", auth_str)
                network.add_children(authoritative)

            for subnet_cidr in network_info[net_name]:
                if subnet_cidr == "authoritative":
                    continue
                subnet = VyOSConfigItem("subnet", subnet_cidr)
                network.add_children(subnet)

                if "gateway" in network_info[net_name][subnet_cidr]:
                    gateway = VyOSConfigItem(
                        "default-router", network_info[net_name][subnet_cidr]["gateway"]
                    )
                    subnet.add_children(gateway)

                if "dns1" in network_info[net_name][subnet_cidr]:
                    dns1 = VyOSConfigItem(
                        "dns-server", network_info[net_name][subnet_cidr]["dns1"]
                    )
                    subnet.add_children(dns1)

                if "dns2" in network_info[net_name][subnet_cidr]:
                    dns2 = VyOSConfigItem(
                        "dns-server", network_info[net_name][subnet_cidr]["dns2"]
                    )
                    subnet.add_children(dns2)

                if "domain" in network_info[net_name][subnet_cidr]:
                    domain_name = VyOSConfigItem(
                        "domain-name", network_info[net_name][subnet_cidr]["domain"]
                    )
                    subnet.add_children(domain_name)

                if "lease" in network_info[net_name][subnet_cidr]:
                    lease = VyOSConfigItem(
                        "lease", network_info[net_name][subnet_cidr]["lease"]
                    )
                    subnet.add_children(lease)

                if "range" in network_info[net_name][subnet_cidr]:
                    range_start = VyOSConfigItem(
                        "start", network_info[net_name][subnet_cidr]["range"][0]
                    )
                    range_end = VyOSConfigItem(
                        "stop", network_info[net_name][subnet_cidr]["range"][1]
                    )
                    range_start.add_children(range_end)
                    subnet.add_children(range_start)

                if "static-mapping" in network_info[net_name][subnet_cidr]:
                    for host in network_info[net_name][subnet_cidr]["static-mapping"]:
                        static = VyOSConfigItem("static-mapping", host)
                        subnet.add_children(static)

                        ip = VyOSConfigItem(
                            "ip-address",
                            network_info[net_name][subnet_cidr]["static-mapping"][host][
                                "ip"
                            ],
                        )
                        static.add_children(ip)

                        mac = VyOSConfigItem(
                            "mac-address",
                            network_info[net_name][subnet_cidr]["static-mapping"][host][
                                "mac"
                            ],
                        )
                        static.add_children(mac)

    def set_router_interfaces(self, ifaces, firewall_policies):
        """
        Creates (if necessary) the router's interfaces. Accomplishes this
        by creating the 'interfaces' block followed by the 'ethernet' block,
        which has several block nested in itself.

        A sample 'interfaces' block looks like::

            interfaces {
                ethernet eth0 {
                    address 172.16.0.2/14
                    duplex auto
                    smp_affinity auto
                }
                ethernet eth1 {
                    address 62.58.99.2/24
                    duplex auto
                    smp_affinity auto
                    ip {
                        ospf {
                            dead-interval 40
                            hello-interval 10
                            retransmit-interval 5
                            transmit-delay 1
                        }
                    }
                }
            }

        Arguments:
            ifaces (dict): Double dictionary containing the interface information
                for the router.
                Structure is defined as: ::

                    interface number (int):
                        'name'      (i.e. eth0)
                        'address'   (i.e. 192.168.1.2)
                        'netmask'   (i.e. 255.255.255.0)

            firewall_policies (dict): A mapping between the firewall
                policy category and associated rule set (each set is a
                :py:class:`VyOSConfigItem` object).

        # noqa: DAR101 firewall_policies
        # - required because newlines are required by RST but break
        #   :spelling:ignore:`darglint`
        #   (see https://github.com/terrencepreilly/darglint/issues/120)
        """
        # Get interfaces block, most likely isn't created yet
        interfaces = self.root.find("interfaces")
        if not interfaces:
            # does not exist yet, create it
            interfaces = VyOSConfigItem("interfaces")
            self.root.add_children(interfaces)

        # loop through all interfaces specified in the ifaces structure
        # and define each interface in the router configuration
        for iface in ifaces:
            # Create an ethernet block
            ethernet = VyOSConfigItem("ethernet", iface["name"])
            interfaces.add_children(ethernet)

            # Get the network address in CIDR notation
            address = None
            if iface["address"] != "0.0.0.0":  # noqa: S104
                network_address = IPNetwork(f"{iface['address']}/{iface['netmask']}")
                # create the address parameter
                address = VyOSConfigItem("address", str(network_address))

            # create the hardware id (MAC address) for this interface
            hwid = VyOSConfigItem("hw-id", iface["mac"])

            # create the firewall name block
            firewall = VyOSConfigItem("firewall")
            for category, rule_sets in firewall_policies.items():
                policy_fw = VyOSConfigItem(category)
                for rule_set in rule_sets:
                    rule_set_name = rule_set.value
                    policy_fw.add_children(VyOSConfigItem("name", rule_set_name))
                firewall.add_children(policy_fw)

            # Add all the children
            if address:
                ethernet.add_children(address)

            ethernet.add_children(hwid, firewall)

    def add_quality_of_service(self, iface):
        """Adds quality of service blocks for all interfaces with QoS.

        QoS traffic shapers are named according to the router interface.
        Currently, the bandwidth can be restricted to a maximum value, but
        the traffic shapers offer more advanced options, such as different
        types of queue scheduling.

        Args:
            iface (dict): The interface to add QoS configs

        Returns:
            VyOSConfigItem: The VyOSConfigItem to add to the ``iface``

        """

        if not (iface.get("bandwidth")):
            return None

        qos_policy = self.root.find("qos-policy")
        if not qos_policy:
            # does not exist yet, create it
            qos_policy = VyOSConfigItem("qos-policy")
            self.root.add_children(qos_policy)

        bandwidth = iface["bandwidth"]
        policy_name = "qos" + iface["name"].strip()
        iface_config = VyOSConfigItem("qos-policy", "{out " + policy_name + "}")

        qos_config = VyOSConfigItem("traffic-shaper", policy_name)
        qos_policy.add_children(qos_config)

        bandwidth_config = VyOSConfigItem("bandwidth", bandwidth)
        ceiling_config = VyOSConfigItem("ceiling", bandwidth)
        default_config = VyOSConfigItem("default", "{bandwidth 100%}")

        qos_config.add_children(bandwidth_config, ceiling_config, default_config)

        return iface_config

    def set_router_ospf(self, routing):
        """
        Defines OSPF information in the correct blocks in the vyos
        configuration. This is the main function for specifying all
        OSPF information for the router. The OSPF information comes
        in through the OSPF structure.

        The OSPF structure is defined as: ::

            interface number (integer):
                'name'                  (i.e. eth0)
                'status'                (i.e. Enabled)
                'area'                  (i.e. 0)
                'hello-interval'        (i.e. 10)
                'transmit-delay'        (i.e. 1)
                'retransmit-interval'   (i.e. 5)
                'dead-interval'         (i.e. 40)

        The redistribute structure specifies which links will be
        redistributing BGP information over the OSPF link.

        The redistribute structure is defined as:

            - status -- Enabled or Disabled, specifies if redistribution is active
            - metric -- the weight specified for the link
            - metric-type -- specifies how cost is calculated for the link
            - route-map -- route-map to be used when advertising the network

        Arguments:
            routing(dict): The routing information for this router.
        """
        if (
            "ospf" not in routing
            or not routing["ospf"]
            or "interfaces" not in routing["ospf"]
            or not routing["ospf"]["interfaces"]
        ):
            return
        ospf = routing["ospf"]

        # add OSPF definitions to the 'interfaces' block
        self.create_interfaces_ospf(ospf)
        # add OSPF definitions to the 'protocols' block
        self.create_protocols_ospf(routing)

    def set_router_static(self, routing):
        """
        Defines static routing information

        Arguments:
            routing(dict): The routing information for this router
        """

        # If no static routing is configured, then just return
        if "static" not in routing or not routing["static"]:
            return

        protocols = self.root.find("protocols")
        if not protocols:
            protocols = VyOSConfigItem("protocols")
            self.root.add_children(protocols)

        static = protocols.find("static")
        if not static:
            static = VyOSConfigItem("static")
            protocols.add_children(static)

        for route in routing["static"]:
            r = VyOSConfigItem("route", route)
            nh = VyOSConfigItem("next-hop", routing["static"][route])
            r.add_children(nh)
            static.add_children(r)

    def set_router_bgp(self, routing):
        """
        Defines the BGP information for the router. This requires the
        neighbor_info structure which is defined as:

            interface number (integer):

                'address' (i.e. 192.168.1.4)
                'as'      (peer's AS number, i.e. 1044)

        The redistribute structure specifies information about which
        links will be redistributing OSPF information.
        The structure is defined as:

            status -- Enabled or Disabled, specifies if redistribution is active
            metric -- the weight specified for the link
            route-map -- route-map to be used when advertising the network

        Arguments:
            routing (dict): The routing information for this router.

        Raises:
            Exception: Must specify an AS when defining a BGP block.
        """
        # If BGP is not configured or there are no neighbors for this router
        # then just return
        if (
            "bgp" not in routing
            or not routing["bgp"]
            or "neighbors" not in routing["bgp"]
            or not routing["bgp"]["neighbors"]
        ):
            return

        protocols = self.root.find("protocols")
        if not protocols:
            protocols = VyOSConfigItem("protocols")
            self.root.add_children(protocols)

        bgp = protocols.find("bgp")
        if not bgp:
            if (
                "bgp" not in routing
                or not routing["bgp"]
                or "parameters" not in routing["bgp"]
                or "router-as" not in routing["bgp"]["parameters"]
                or not routing["bgp"]["parameters"]["router-as"]
            ):
                raise Exception("Cannot create BGP block without an AS specified")
            bgp = VyOSConfigItem("bgp", routing["bgp"]["parameters"]["router-as"])
            protocols.add_children(bgp)

        # BGP block exists, so fill it with neighbor information
        neighbors = self.create_bgp_neighbors(routing["bgp"]["neighbors"])
        # Add all the neighbors to the tree
        for neighbor in neighbors:
            bgp.add_children(neighbor)

        # Just redistribute connected instead of specific networks
        """
        if bgp_networks:
            for network in bgp_networks.keys():
                network_cidr = str(IPNetwork('%s/%s' % \
                        (bgp_networks[network]['address'],
                        bgp_networks[network]['netmask'])).cidr)
                network = VyOSConfigItem('network', network_cidr)
                bgp.add_children(network)
        """
        # Make networks block in graph struct, anything in there should
        # be explicitly advertised
        if "networks" in routing["bgp"]:
            for net in routing["bgp"]["networks"]:
                # This should almost always be an IPNetwork Type
                if not isinstance(net, IPNetwork):
                    if not isinstance(net, str):
                        net_cidr = str(IPNetwork(f"{net['address']}/{net['netmask']}"))
                    else:
                        net_cidr = net
                else:
                    net_cidr = str(net)
                network = VyOSConfigItem("network", net_cidr)
                bgp.add_children(network)

        redistribute = self.create_protocols_bgp_redistribute_ospf(routing["bgp"])
        self.bgp_redistribute_ospf(redistribute, routing["bgp"])

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
        neighbors = []
        # Loop through all the neighbors
        for n_info in neighbor_info:
            # Create the neighbor
            neighbor = VyOSConfigItem("neighbor", n_info["address"])

            # Create the remote-as parameter
            remote_as = VyOSConfigItem("remote-as", n_info["remote-as"])
            neighbor.add_children(remote_as)

            neighbors.append(neighbor)
        # return all the neighbors just created
        return neighbors

    def create_interfaces_ospf(self, ospf):
        """
        Add OSPF information to the 'interfaces' block. This requires
        the creation of an 'ip' block as well as an 'ospf' block
        nested inside the 'ip' block.

        See example in comments in set_router_interfaces()

        Arguments:
            ospf(dict): OSPF information. Structure defined in comments of
                set_router_ospf()

        Raises:
            IncorrectDefinitionOrderError: Must set router interfaces before
                setting its OSPF information.
        """
        # vyos configs have as ospf block inside the interfaces block
        interfaces = self.root.find("interfaces")
        if not interfaces:
            raise IncorrectDefinitionOrderError(
                "Must set router interfaces before setting its OSPF information"
            )

        # Loops through the ospf information adding an 'ip' block and
        # an 'ospf' block to each 'ethernet' block that defines an
        # interface that has OSPF enabled
        for iface in ospf["interfaces"]:
            # Get the ethernet block that pertains to what we're looking for
            ethernet = interfaces.find("ethernet", iface)
            if not ethernet:
                continue

            # ospf information is in an ip block
            ip = ethernet.find("ip")
            if not ip:
                ip = VyOSConfigItem("ip")
                ethernet.add_children(ip)

            ospf_block = VyOSConfigItem("ospf")
            ip.add_children(ospf_block)

            if "dead-interval" in ospf["interfaces"][iface]:
                dead_interval = VyOSConfigItem(
                    "dead-interval",
                    int(float(ospf["interfaces"][iface]["dead-interval"])),
                )
                ospf_block.add_children(dead_interval)

            if "hello-interval" in ospf["interfaces"][iface]:
                hello_interval = VyOSConfigItem(
                    "hello-interval",
                    int(float(ospf["interfaces"][iface]["hello-interval"])),
                )
                ospf_block.add_children(hello_interval)

            if "retransmit-interval" in ospf["interfaces"][iface]:
                retransmit_interval = VyOSConfigItem(
                    "retransmit-interval",
                    int(float(ospf["interfaces"][iface]["retransmit-interval"])),
                )
                ospf_block.add_children(retransmit_interval)

            if "transmit-delay" in ospf["interfaces"][iface]:
                transmit_delay = VyOSConfigItem(
                    "transmit-delay",
                    int(float(ospf["interfaces"][iface]["transmit-delay"])),
                )
                ospf_block.add_children(transmit_delay)

    def create_protocols_ospf(self, routing):
        """
        Add OSPF information to the 'protocols' block.

        Arguments:
            routing(dict): The routing info for this router.
        """
        ospf = routing["ospf"]
        # OSPF is defined in the protocols block
        protocols = self.root.find("protocols")
        if not protocols:
            protocols = VyOSConfigItem("protocols")
            self.root.add_children(protocols)

        # Create the 'ospf' block, nested in the 'protocols' block
        ospf_block = VyOSConfigItem("ospf")
        protocols.add_children(ospf_block)

        # Create and add areas to the OSPF block
        areas = self.create_protocols_ospf_areas(ospf)
        for area in areas:
            ospf_block.add_children(area)

        if "parameters" not in routing:
            print(routing)

        # Create Parameters block
        parameters = VyOSConfigItem("parameters")
        ospf_block.add_children(parameters)
        rid = VyOSConfigItem("router-id", routing["parameters"]["router-id"])
        parameters.add_children(rid)

        # Create redistribute block
        self.create_protocols_ospf_redistribute(ospf)

    def create_protocols_ospf_redistribute(self, ospf):
        """
        Create the 'redistribution' block that is nested inside of the
        'protocols' block. Specifies which OSPF links redistribute.

        Arguments:
            ospf (dict): Specifies which OSPF links will be redistributing
                BGP information. Structure defined in comments of set_router_ospf()

        Raises:
            IncorrectDefinitionOrderError: Must specify OSPF information before
                specifying redistribution of BGP on OSPF links.
        """
        if "redistribution" not in ospf:
            # not redistribting anything, nothing to do
            return

        protocols = self.root.find("protocols")
        if not protocols:
            raise IncorrectDefinitionOrderError(
                "Must specify OSPF information "
                + "before specifying redistribution "
                + "of BGP on OSPF links"
            )

        ospf_block = protocols.find("ospf")
        if not ospf_block:
            raise IncorrectDefinitionOrderError(
                "Must specify OSPF information "
                + "before specifying redistribution "
                + "of BGP on OSPF links"
            )

        # create redistribute block
        redistribute = ospf_block.find("redistribute")
        if not redistribute:
            redistribute = VyOSConfigItem("redistribute")
            ospf_block.add_children(redistribute)

        # Redistribute connected if necessary
        if "connected" in ospf["redistribution"]:
            redistribute_connected = VyOSConfigItem("connected")
            redistribute.add_children(redistribute_connected)

        # create 'bgp' block to be nested in 'redistribute' block
        if "bgp" in ospf["redistribution"]:
            bgp = VyOSConfigItem("bgp")
            redistribute.add_children(bgp)

            if "parameters" not in ospf["redistribution"]["bgp"]:
                return

            if "metric" in ospf["redistribution"]["bgp"]["parameters"]:
                if ospf["redistribution"]["bgp"]["parameters"]["metric"] > 16:
                    metric_val = 16
                else:
                    metric_val = ospf["redistribution"]["bgp"]["parameters"]["metric"]
                metric = VyOSConfigItem("metric", metric_val)
                bgp.add_children(metric)

            if "metric-type" in ospf["redistribution"]["bgp"]["parameters"]:
                type_val = 1
                metric_type = VyOSConfigItem("metric-type", type_val)
                bgp.add_children(metric_type)

            if "route-map" in ospf["redistribution"]["bgp"]["parameters"]:
                route_map = VyOSConfigItem(
                    "route-map",
                    ospf["redistribution"]["bgp"]["parameters"]["route-map"],
                )
                bgp.add_children(route_map)

    def bgp_redistribute_ospf(self, redistribute, bgp_config=None):
        """
        Create the 'redistribution' block that is nested inside of the
        'protocols' block. Specifies which BGP links redistribute
        OSPF information.

        Arguments:
            redistribute (VyOSConfigItem): The redistribute item or None if it does not exist.
            bgp_config (dict): Specifies which BGP links will be redistributing
                OSPF information. Structure defined in comments of set_router_ospf()
        """
        if redistribute is None:
            # no redistribution happening, nothing to do
            return

        redistribution = bgp_config["redistribution"]

        if "ospf" not in redistribution:
            return

        ospf = VyOSConfigItem("ospf")
        redistribute.add_children(ospf)

        if "parameters" in redistribution["ospf"]:
            parameters = redistribution["ospf"]["parameters"]

            if parameters.get("metric"):
                if parameters["metric"] > 16:
                    metric_val = 16
                else:
                    metric_val = parameters["metric"]
                metric = VyOSConfigItem("metric", metric_val)
                ospf.add_children(metric)

            if parameters.get("route-map"):
                route_map = VyOSConfigItem("route-map", parameters["route-map"])
                ospf.add_children(route_map)

    def create_protocols_bgp_redistribute_ospf(self, bgp_config):
        """
        Create the 'redistribution' block that is nested inside of the
        'protocols' block. Specifies which BGP links redistribute
        OSPF information.

        Arguments:
            bgp_config (dict): Specifies which BGP links will be redistributing
                OSPF information. Structure defined in comments of set_router_ospf()

        Returns:
            VyOSConfigItem: The "redistribute" configuration item that may need to be
                added elsewhere.

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
        redistribute = bgp.find("redistribute")
        if not redistribute:
            redistribute = VyOSConfigItem("redistribute")
            bgp.add_children(redistribute)

        return redistribute

    def create_protocols_ospf_areas(self, ospf):
        """
        Create the 'area' block that is nested inside the 'ospf' block which
        is nested inside the 'protocols' block. Specifies which area corresponds
        to which networks.

        Arguments:
            ospf (dict): OSPF information for each interface. Structure defined in
                comments of set_router_ospf()

        Returns:
            list: A list of dictionaries containing a mapping of OSPF areas to networks.
        """
        areas = []
        # group all networks based on area id
        area_networks = self.create_protocols_ospf_area_networks(ospf)

        # go through each area id, create an 'area' block
        for area in area_networks:
            # Create the area block
            area_block = VyOSConfigItem("area", area)
            # create a network block for each network in the area
            for network in area_networks[area]:
                net = VyOSConfigItem("network", network)
                area_block.add_children(net)
            areas.append(area_block)
        return areas

    def create_protocols_ospf_area_networks(self, ospf):
        """
        Groups OSPF information by area id with each network
        that is specified for that id.

        Arguments:
            ospf (dict): OSPF information for each interface. Structure defined in
                comments of set_router_ospf()

        Returns:
            dict: The OSPF area dictionary.

        Raises:
            IncorrectDefinitionOrderError: If the router interfaces were not set
                before adding OSPF information.
        """
        area_networks = {}
        # get active interfaces
        interfaces = self.root.find("interfaces")
        if not interfaces:
            raise IncorrectDefinitionOrderError(
                "Must set router interfaces " + "before setting its OSPF information"
            )

        # Loop through ospf enabled interfaces
        for iface in ospf["interfaces"]:
            ethernet = interfaces.find("ethernet", iface)
            # only specify networks for active interfaces
            if ethernet:
                # the interface has already been set with an address in
                # <IP Address>/<netmask> format, so don't need to specify
                # the prefix length to get the cidr address
                address = IPNetwork(ethernet.find("address").value)
                if ospf["interfaces"][iface]["area"] not in area_networks:
                    area_networks[ospf["interfaces"][iface]["area"]] = []
                area_networks[ospf["interfaces"][iface]["area"]].append(address.cidr)

        return area_networks

    def set_firewall(self, rule_sets):
        """
        Set the firewall parameters for this router

        Args:
            rule_sets (list): A list containing firewall configurations
                (groups, rule sets, etc.) being applied to the router
                (each item in a configuration is a :py:class:`VyOSConfigItem` object).
        """
        firewall = VyOSConfigItem("firewall")
        for config in rule_sets:
            for config_item in config:
                firewall.add_children(config_item)

        # Enable sending redirects (default)
        firewall.add_children(VyOSConfigItem("send-redirects", "disable"))

        self.root.add_children(firewall)

    def set_nat(self, nat):
        """
        Set up the NAT rules for this router.

        Arguments:
            nat (list): A list of NAT rules (in dictionary format).

        Raises:
            Exception: If there is an invalid NAT rule.
        """
        nat_root = VyOSConfigItem("nat")
        self.root.add_children(nat_root)

        source_rule_counter = 0
        destination_rule_counter = 0
        rule_increment = 5

        source = None
        destination = None
        for rule in nat:
            if rule.get("type"):
                # Find the root node for the rule: source or destination NAT.
                if rule["type"] == "source":
                    if source is None:
                        source = VyOSConfigItem("source")
                        nat_root.add_children(source)

                    source_rule_counter += rule_increment
                    cur_rule = VyOSConfigItem("rule", str(source_rule_counter))
                    source.add_children(cur_rule)

                    # Set up the access block.
                    source_filter = VyOSConfigItem("source")
                    cur_rule.add_children(source_filter)

                    if "address" in rule["access"] and rule["access"]["address"]:
                        src_addr = VyOSConfigItem("address", rule["access"]["address"])
                        source_filter.add_children(src_addr)
                    elif "subnet" in rule["access"] and rule["access"]["subnet"]:
                        src_addr = VyOSConfigItem("address", rule["access"]["subnet"])
                        source_filter.add_children(src_addr)

                    if "port" in rule["access"] and rule["access"]["port"]:
                        src_port = VyOSConfigItem("port", rule["access"]["port"])
                        source_filter.add_children(src_port)

                        protocol = VyOSConfigItem("protocol", rule["protocol"])
                        cur_rule.add_children(protocol)

                    # Set up the translation block.
                    translation = VyOSConfigItem("translation")
                    cur_rule.add_children(translation)

                    if (
                        "address" in rule["translation"]
                        and rule["translation"]["address"]
                    ):
                        trans_addr = VyOSConfigItem(
                            "address", rule["translation"]["address"]
                        )
                        translation.add_children(trans_addr)
                    elif (
                        "subnet" in rule["translation"]
                        and rule["translation"]["subnet"]
                    ):
                        trans_addr = VyOSConfigItem(
                            "address", rule["translation"]["subnet"]
                        )
                        translation.add_children(trans_addr)

                    # Set up the out-bound interface.
                    if rule.get("interface"):
                        out_iface = VyOSConfigItem(
                            "outbound-interface", rule["interface"]
                        )
                        cur_rule.add_children(out_iface)
                elif rule["type"] == "destination":
                    if destination is None:
                        destination = VyOSConfigItem("destination")
                        nat_root.add_children(destination)

                    destination_rule_counter += rule_increment
                    cur_rule = VyOSConfigItem("rule", str(destination_rule_counter))
                    destination.add_children(cur_rule)

                    use_port = False
                    # Set up the access block.
                    dest = VyOSConfigItem("destination")
                    cur_rule.add_children(dest)

                    if "address" in rule["access"] and rule["access"]["address"]:
                        dest_addr = VyOSConfigItem("address", rule["access"]["address"])
                        dest.add_children(dest_addr)
                    elif "subnet" in rule["access"] and rule["access"]["subnet"]:
                        dest_addr = VyOSConfigItem("address", rule["access"]["subnet"])
                        dest.add_children(dest_addr)

                    if "port" in rule["access"] and rule["access"]["port"]:
                        dest_port = VyOSConfigItem("port", rule["access"]["port"])
                        dest.add_children(dest_port)
                        use_port = True

                    # Set up the translation block.
                    translation = VyOSConfigItem("translation")
                    cur_rule.add_children(translation)

                    if (
                        "address" in rule["translation"]
                        and rule["translation"]["address"]
                    ):
                        trans_addr = VyOSConfigItem(
                            "address", rule["translation"]["address"]
                        )
                        translation.add_children(trans_addr)
                    elif (
                        "subnet" in rule["translation"]
                        and rule["translation"]["subnet"]
                    ):
                        trans_addr = VyOSConfigItem(
                            "subnet", rule["translation"]["subnet"]
                        )
                        translation.add_children(trans_addr)

                    if "port" in rule["translation"] and rule["translation"]["port"]:
                        trans_port = VyOSConfigItem("port", rule["translation"]["port"])
                        translation.add_children(trans_port)
                        use_port = True

                    # Se up the in-bound interface.
                    if rule.get("interface"):
                        in_iface = VyOSConfigItem(
                            "inbound-interface", rule["interface"]
                        )
                        cur_rule.add_children(in_iface)

                    if use_port is True:
                        protocol = VyOSConfigItem("protocol", rule["protocol"])
                        cur_rule.add_children(protocol)
                else:
                    raise Exception("Invalid NAT rule type.")
            else:
                raise Exception("Need to specify type.")


class VyOSConfigItem:
    """
    Single configuration item that represents either a block or a parameter
    in the vyos configuration file.
    """

    def __init__(self, name, value=None):
        """
        Constructor.

        Arguments:
            name (str): The name of the block or parameter
            value (str, optional): Value for this block or parameter
        """
        self.name = name
        # Value is optional since some blocks only contain a name
        self.value = value if value else ""
        # Initialize variables to reference relatives in the tree
        self.parent = None
        self.children = []

    def find(self, child_name, value=None):
        """
        Search the children of this node to find the specified
        configuration item.

        Arguments:
            child_name (str): The name field for the desired config item
            value (str, optional): If specified then matches both the name
                and the item's value.

        Returns:
            vyos.VyOSConfigItem: The child being searched for, or None if one is
            not found.
        """
        for c in self.children:
            if value:
                if c.name == child_name and c.value == value:
                    return c
            elif c.name == child_name:
                return c
        return None

    def recursive_find(self, child_name, value=None):
        """
        Recursively search the children of this node to find the specified
        configuration item.

        Arguments:
            child_name (str): The name field for the desired config item
            value (str, optional): If specified then matches both the name
                and the item's value.

        Returns:
            vyos.VyOSConfigItem: The child being searched for, or None if one is
            not found.
        """
        test_list = []
        for c in self.children:
            if c.name == child_name:
                if value:
                    if c.value == value:
                        return c
                else:
                    return c
            else:
                test_list.append(c)

        for c in test_list:
            res = c.recursive_find(child_name, value)
            if res is not None:
                return res

        return None

    def get_child_values(self, child_name):
        """
        Search the children and get the values of all
        children that have the given name.
        Useful for getting all the interface names that
        have been declared since they are the values to
        'ethernet' blocks.

        Arguments:
            child_name (str): The name field for the desired config item

        Returns:
            list: A list of values.
        """
        values = []
        for c in self.children:
            if c.name == child_name:
                values.append(c.value)
        return values

    def add_children(self, *args):
        """
        Add a child to this config item

        Arguments:
            *args (list): A list of :py:class:`vyos.VyOSConfigItem` objects.
        """
        for arg in args:
            self.children.append(arg)
            arg.parent = self

    def generate_commands(self, base_command, commands):
        """
        Generate the configuration commands for this item and
        all of its children. Then return commands back up
        to the parent to eventually be returned to the initial caller

        Arguments:
            base_command (str): The base command for a given item.
            commands (list): The list of commands.

        Returns:
            list: The list of commands being generated.
        """
        command = f"{self.name}"
        if self.value:
            command += f" {self.value}"

        # The new command needs the base (its parents)
        if base_command:
            command = f"{base_command} {command}"
        # The new base needs to include this new command moving forward
        base_command = command

        if len(self.children) > 0:
            for child in self.children:
                child.generate_commands(base_command, commands)
        else:
            commands.append(command)

        return commands


class IncorrectDefinitionOrderError(Exception):
    """
    Exception to specify that a value has been defined out of order.
    The message will specify what value was needed before the exception
    was thrown
    """
