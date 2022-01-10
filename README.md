# mcuboot-img-parser
MCUboot binary firmware image parser

## Usage

```sh
mcuboot-img-parser /path/to/mcuboot_image.bin
```

## Example

```
$ ./target/release/mcuboot-img-parser build/zephyr/zephyr.signed.bin
mcuboot-tlv-parser v0.0.1
-------------------------
[*] Opening image file build/zephyr/zephyr.signed.bin, total file size:  17202
[*] Offset: 00000000, 0x00000000: ImageHeader { magic: 2532554813, load_addr: 0, hdr_size: 512, prot_tlv_size: 0, img_size: 16480, flags: 0, ver_major: 0, ver_minor: 0, ver_rev: 0, ver_build: 0, pad1: 0 }
[*] Offset: 00000512, 0x00000200: ImageHeader padding 480 bytes: [0, 0, 0, 0, 0, 0, 0, 0] ...
[*] Offset: 00000512, 0x00000200: BinaryImage 16480 bytes: [68, 7, 0, 20, 75, d7, 0, 0] ...
[*] Offset: 00016992, 0x00004260: ImageTLVInfo { magic: 26887, tlv_tot: 210 }
[*] Offset: 00016996, 0x00004264: TLV_SHA256, 32 bytes: [c, 4d, 34, 42, 55, 96, 5, 0] ...
[*] Offset: 00017032, 0x00004288: TLV_PUBKEY, 91 bytes: [30, 59, 30, 13, 6, 7, 2a, 86] ...
[*] Offset: 00017127, 0x000042e7: TLV_ECDSA256, 71 bytes: [30, 45, 2, 21, 0, 98, b6, 89] ...
```
