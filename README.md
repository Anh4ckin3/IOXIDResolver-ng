
# IOXIDResolver-ng


## Authors

- [@Anh4ckin3](https://www.github.com/Anh4ckin3)


## Ressource 

 - This tool is based on a work made by [Airbus security](https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/).

 


## Introduction 

The IOXIDResolver.py-ng script is designed to explore the network interfaces of a target machine via the Microsoft Remote Procedure Call (MSRPC) protocol. The script interacts with the `IObjectExporter` service, exposed by MSRPC, to call the `ServerAlive2` method. This method returns the available network interfaces of the target machine.


## Demo


