# Bluetooth SMP PoCs

This repository contains proof-of-concepts for attacks against the BLE SMP protocols when a static
passkey is used. More information can be found in the corresponding [Insinuator blogpost](https://web.archive.org/web/20250816205228/https://insinuator.net/2021/10/change-your-ble-passkey-like-you-change-your-underwear/).

## SMP Bruteforce

The script uses Google's [Bumble](https://google.github.io/bumble/) Bluetooth library and therefore works with any Bluetooth transport that [Bumble supports](https://google.github.io/bumble/transports/index.html).

To run the script you need to Bluetooth address of the device you want to brute-force. Run the
script as follows:

```bash
python smp_bruteforce.py --target AA:BB:CC:DD:EE:FF
```

It will assume `usb:0` as default transport. This will usually work if you have exactly one USB Bluetooth dongle in your system.
If you're using some other transport, you can specify it with the `-c` option.

Successfully running the script looks as follows:

![smp_bruteforce script excecution GIF](assets/smp_bruteforce.gif)
