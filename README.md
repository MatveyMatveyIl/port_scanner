# Port scanner

**primitive port scanner for udp and tcp**

## Install

```pip install -r requirements.txt```

## Usage

### help
``sudo python3 -m portscan -h``

### example
`` sudo python3 -m portscan -v -g --timeout 1 -j 100 77.88.55.66 tcp/1-100,443 udp/1-100,1000``

## Features
- Timeout
- The number of threads can be set(Multithreading)
- verbose mode and application protocol definition
- The following protocols are defined
  - `HTTP` `DNS` `ECHO` `HTTPS` 
- TCP scan with TCP SYN packets using scapy

### Author
## Ilichev Matvey 
