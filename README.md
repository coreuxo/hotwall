# hotwall

A userspace firewall.

## Building

```bash
make
```

## Testing
```bash 
make test 
make check # Runs full test suite with memory checkes
```

## Installation 
```bash 
sudo make install
```

## Usage 
### Basic Operation 
```bash 
sudo ./bin/firewall eth0
```
### CLI Management
```bash 
sudo ./bin/firewall -C eth0
```
### With Configuration 
```bash 
sudo ./bin/firewall -c /etc/firewall.conf eth0
```

## Configuration 
- NIY (soon)

## Features

- **Stateful Packet Filtering**: Connection tracking and stateful inspection
- **NAT Support**: SNAT, DNAT, and masquerading
- **IDS/IPS**: Signature-based intrusion detection and prevention
- **QoS**: Traffic shaping and quality of service
- **Multi-threaded**: High-performance packet processing
- **CLI Management**: Interactive management interface
- **Configuration Files**: Rule and policy management

