# Summary

_beacon2mqtt_ is a tiny program for sensing (i.e., passively scanning) BLE advertising beacons
and transmitting them in JSON over MQTT.  
It is orignally designed as a _sensor gateway_
to collect data from battery-powered BLE sensor devices into a (local) storage.

- it runs as a daemon process.
- it can filter beacons in several different ways (by whitelist, discarding duplicates, etc).
- it is written in C/C++, and tested on Raspberry pi 4B.

# Examples

To try `beacon2mqtt` and check out how it works, you need a Linux machine (server),
equipped with a Bluetooth chip, such as Raspberry pi zero w, 3, and 4,
and another machine (client) that is capable of transmitting BLE beacons,
which could be another Raspberry pi.
Let us here assume you have two Raspberry pi's.

On the server machine,
install [mosquitto](https://mosquitto.org/) and invoke `beacon2mqtt`.

```
$ sudo apt-get install -y mosquitto mosquitto-clients
$ sudo beacon2mqtt  
$ mosquitto_sub -t beacon  
```

On the client machine,
install [hcitool](https://kernel.googlesource.com/pub/scm/bluetooth/bluez/) and transmit beacons as follows:

```
$ sudo apt-get install -y bluez
$ sudo hciconfig hci0 up  
$ sudo hciconfig hci0 leadv 3  
$ sudo hcitool -i hci0 cmd 0x08 0x0008 1E 02 01 1A 1A FF 4C 00 02 15 E2 0A 39 F4 73 F5 4B C4 A1 2F 17 D1 AD 07 A9 61 00 00 00 00 C8 00  
$ sleep 10; sudo hciconfig hci0 down
```

Then, on the server-side terminal, you will see the following JSON-formatted message:

```
{"bdaddr":"AA:BB:CC:DD:EE:FF","beacon_type":"ibeacon","ad_structures":[{"ad_type":255,"major":0,"minor":0,"rssi":200,"uuid":"e20a39f4-73f5-4bc4-a12f-17d1ad07a961"}]}   
```

# Installation on Debian/Ubuntu

## Prerequisites

### Packages
 
- libbluetooth-dev
- libmosquitto-dev
- nlohmann-json3-dev
- uuid-dev
- (optional) bluez
- (optional) mosquitto mosquitto-clients


## Build
- run `make && make install` in the top directory  
  `beacon2mqtt` will be built and installed into `/usr/local/bin`.  
  To change the installation directory,
  run `make PREFIX=<prefix> install` instead (default: `PREFIX=/usr/local`).

## Run

In a nutshell, you just need to invoke the tool with root persmission.
It goes into the background as a daemon, and immediately returns.

```
$ sudo beacon2mqtt
```

Although it supports various options (refer to what `beacon2mqtt -h` shows),
`-i <bluetooth_device>` and `-b <mqtt_broker>` are probably among the most essential.  
The following example specifies `hci` as the device and `localhost` as the broker.

```
$ sudo beacon2mqtt -i hci0 -b localhost
```

As a remark,
notice that, since `beacon2mqtt` scans beacons through the bluetooth device on your machine,
it needs root permission for that.
