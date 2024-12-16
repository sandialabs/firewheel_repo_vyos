.. _vyos.equuleus_mc:

#############
vyos.equuleus
#############

This Model Component provides the VyOS Equuleus 1.3.x image to a VM.

.. warning::

    Prior to using this Model Component, the compressed image ``vyos-equuleus.qc2.xz`` will need to be created and added to this directory. You can find the instructions to create an image below.

**Model Component Dependencies:**
    * :ref:`vyos_mc`

******************
Creating the Image
******************

To create a new FIREWHEEL-compatible VyOS image please follow the following steps:

* Either download a pre-created VyOS ISO file from https://vyos.net/get/ or build one following the `official documentation <https://docs.vyos.io/en/equuleus/contributing/build-vyos.html>`_.
* Create a backing disk with at least 5 GiB.

  .. code-block:: bash

    $ qemu-img create -f qcow2 vyos-1.3.0-rc6-amd64.qcow2 5G

* Launch the VM with the ISO inserted as a CD.

  .. seealso::

    The :ref:`building_iso` tutorial has other tips for building images from ISO files.

* Login with the default credentials: ``vyos``/``vyos``
* Run the ``install image`` command with, default options and the username/password ``vyos``/``vyos``.
* Power off the VM and relaunch without the ISO attached.
* Once the system was booted, log into the system using ``vyos``/``vyos``, then run the following commands:

  .. code-block:: bash

    $ configure
    # set service ssh
    # commit
    # save
    # exit

* The default VyOS image comes pre-installed with the `QEMU Guest Agent <https://wiki.qemu.org/Features/GuestAgent>`__ and an upstart script which will help run it.
  This version will work, but it's important to understand the trade-offs of using this or the patched version that FIREWHEEL provides.
  We recommend reading :ref:`qga-driver`.

  .. note::

    If you choose to replace the existing version, you should load the patched/statically linked version ``/usr/sbin/qemu-guest-agent-patched-static`` on the VM.
    To do this, on the VyOS VM you will need to run ``sudo dhclient`` to ensure that it has an IP address.
    Then the file can be loaded via SCP (assuming the VM was bridged following the :ref:`building_iso` tutorial).
    Once the file is uploaded, modify the upstart script ``/etc/init.d/qemu-guest-agent`` to point to ``qemu-guest-agent-patched-static`` rather than ``qemu-ga``.

* Then we will create a needed path for the QEMU Guest Agent and ensure that it starts on boot.
  On the VM run the following commands:

  .. code-block:: bash

    $ sudo mkdir -p /usr/local/var/run
    $ sudo update-rc.d qemu-guest-agent defaults

*****************
Available Objects
*****************

.. automodule:: vyos.equuleus
    :members:
    :undoc-members:
    :special-members:
    :private-members:
    :show-inheritance:
    :exclude-members: __dict__,__weakref__,__module__

