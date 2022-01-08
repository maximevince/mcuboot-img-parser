# mcuboot-img-parser
MCUboot binary firmware image parser

## Usage

```sh
mcuboot-img-parser /path/to/mcuboot_image.bin
```

## Example

```
mcuboot-tlv-parser v0.0.1
[*] Opening image file /home/vinz/Downloads/helloworld.signed.encrypted.bin
[*] Total file size:  17318
[*] ImageHeader { magic: 2532554813, load_addr: 0, hdr_size: 512, prot_tlv_size: 0, img_size: 16480, flags: 4, ver_major: 1, ver_minor: 2, ver_rev: 0, ver_build: 0, pad1: 0 }
[*] ImageTLVInfo { magic: 26887, tlv_tot: 326 }
[*] Image total size: 17318

[*] TLV_SHA256 @ 16996, 32b
[2F, 49, 11, EE, C3, B1, 6C, 45, 36, 75, 2D, 93, 70, BB, BD, 29, A8, A7, F4, 36, 70, F9, 09, FF, BF, 30, 25, BC, 08, 11, 9B, 7A]

[*] TLV_PUBKEY @ 17032, 91b
[30, 59, 30, 13, 06, 07, 2A, 86, 48, CE, 3D, 02, 01, 06, 08, 2A, 86, 48, CE, 3D, 03, 01, 07, 03, 42, 00, 04, 2A, CB, 40, 3C, E8, FE, ED, 5B, A4, 49, 95, A1, A9, 1D, AE, E8, DB, BE, 19, 37, CD, 14, FB, 2F, 24, 57, 37, E5, 95, 39, 88, D9, 94, B9, D6, 5A, EB, D7, CD, D5, 30, 8A, D6, FE, 48, B2, 4A, 6A, 81, 0E, E5, F0, 7D, 8B, 68, 34, CC, 3A, 6A, FC, 53, 8E, FA, C1]

[*] TLV_ECDSA256 @ 17127, 70b
[30, 44, 02, 20, 2A, B5, C5, 45, D0, 78, 11, 5C, 90, 98, B9, B2, F6, 18, 82, CA, 42, 21, B9, C1, 59, A4, DB, 1A, 79, 84, 75, E3, 71, 94, 24, C0, 02, 20, 4A, 74, 7C, 7D, 14, EB, B4, F9, 0C, 06, F1, 2D, 26, 79, 4D, AB, DD, AB, D8, E7, 95, FF, 75, 61, F1, 20, 34, 1B, F9, 37, AC, CD]

[*] TLV_ENC_EC256 @ 17201, 113b
[04, E5, 36, B4, 87, 11, 72, 3C, 97, 65, A6, 6D, 36, EC, F2, 45, 14, ED, CF, 43, 26, 02, 02, BA, DF, 94, 9C, 02, 8D, 4E, 22, 94, 6C, AF, AD, 42, 37, 44, D4, 19, 90, AE, 23, 77, DF, 95, AA, 50, EF, A1, C2, 2C, 6E, A2, 83, 90, 9F, 55, CF, E0, 5D, 42, 30, C2, DF, 67, DD, E8, FA, 58, F5, C3, 51, 11, 3C, A9, 9C, 95, 73, 7F, 89, 4C, D7, 39, 46, 49, EC, EF, 1A, A2, F1, 9C, BC, 6D, B4, 37, B3, 54, 56, B2, 27, CE, 41, C7, A1, E1, 94, 63, 2B, 9A, 3A, 7B, 08]

```
