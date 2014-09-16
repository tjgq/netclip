# netclip

Netclip is a protocol for synchronizing the text clipboard of two or more peers in the same local network. It provides confidentiality and supports multiple concurrent users.

A reference client is available at <http://github.com/tjgq/netclipper>.

### Description

#### Transport

The protocol exchanges packets on UDP port 2547 over the 224.0.0.1 link-local multicast address.

#### Message structure

```
+-------+------+----+------+-----+---------+-----+
| Magic | HMAC | IV | Time | Len | Payload | Pad |
+-------+------+----+------+-----+---------+-----+
```

* Magic (4 bytes) is the ASCII encoding of the string 'CLIP'.

* HMAC (32 bytes) is the SHA-256 Keyed-Hash Message Authentication Code (FIPS 198) for the remainder of the message (IV, Time, Len, Payload, Pad).

* IV (16 bytes) is an initialization vector for the encryption algorithm.

The remainder of the message (Time, Len, Payload, Pad) is encrypted in AES-256 CBC mode (FIPS 197) with initialization vector IV.

* Time (8 bytes) is a 64-bit Unix time in network byte order.

* Len (2 bytes) is the payload length in bytes, in network byte order.

* Payload (variable length) is a UTF-8 encoded text string.

* Pad (variable length) are zero or more null bytes such that the length of (Time, Len, Payload, Pad) is a multiple of 16 bytes.

#### Notes

All protocol peers belonging to the same user must use a shared key used for encryption/decryption and message authentication. This provides confidentiality and allows the rejection of messages intended for other users running the protocol in the same local network.

The protocol provides limited protection against replay attacks. A message whose Time does not belong to a 1-minute window centered on the current 64-bit Unix time is rejected. As a consequence, clock synchronization is required among protocol peers.

Message delivery is not guaranteed. The protocol makes no provisions for the acknowledgement or retransmission of messages.

Message size cannot exceed 65507 bytes, the maximum data length for a UDP packet. The system's TCP/IP stack may impose a lower limit.
