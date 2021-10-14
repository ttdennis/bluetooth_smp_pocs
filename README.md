# Bluetooth SMP PoCs

This repository contains proof-of-concepts for attacks against the BLE SMP protocols when a static
passkey is used. More information can be found in the corresponding [Insinuator blogpost]().

## SMP Bruteforce
The bruteforce script requires [Internalblue](https://github.com/seemoo-lab/internalblue) and
pycryptodome to be installed. You will either need `CAP_NET_RAW` or root privileges to use the
required HCI socket. Additionally, the Bluetooth device needs to be down. You can simply run
`systemctl stop bluetooth` to do that.

To run the script you need to Bluetooth address of the device you want to brute-force. Run the
script as follows:

```bash
python smp_bruteforce.py AA:BB:CC:DD:EE:FF
```

Successfully running the script looks as follows:

![smp_bruteforce script excecution GIF](assets/smp_bruteforce.gif)
