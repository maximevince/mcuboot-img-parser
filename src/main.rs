extern crate nom;
extern crate hex;

use std::env;
use std::fs;
use std::mem::size_of;

use nom::{IResult, bytes::complete::tag, bytes::complete::take};
use nom::number::complete::{le_u32, le_u16, le_u8};

extern crate num;
#[macro_use]
extern crate num_derive;

#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code, non_camel_case_types)]
#[derive(FromPrimitive)]
pub enum TlvKinds {
    TLV_KEYHASH      = 0x01,  /* hash of the public key */
    TLV_PUBKEY       = 0x02,  /* public key */
    TLV_SHA256       = 0x10,  /* SHA256 of image hdr and body */
    TLV_RSA2048_PSS  = 0x20,  /* RSA2048 of hash output */
    TLV_ECDSA224     = 0x21,  /* ECDSA of hash output */
    TLV_ECDSA256     = 0x22,  /* ECDSA of hash output */
    TLV_RSA3072_PSS  = 0x23,  /* RSA3072 of hash output */
    TLV_ED25519      = 0x24,  /* ed25519 of hash output */
    TLV_ENC_RSA2048  = 0x30,  /* Key encrypted with RSA-OAEP-2048 */
    TLV_ENC_KW       = 0x31,  /* Key encrypted with AES-KW 128 or 256*/
    TLV_ENC_EC256    = 0x32,  /* Key encrypted with ECIES-EC256 */
    TLV_ENC_X25519   = 0x33,  /* Key encrypted with ECIES-X25519 */
    TLV_DEPENDENCY   = 0x40,  /* Image depends on other image */
    TLV_SEC_CNT      = 0x50,  /* security counter */
    TLV_BOOT_RECORD  = 0x60,  /* measured boot record */
    TLV_UNKNOWN      = 0xFF,
}


#[allow(dead_code, non_camel_case_types)]
pub enum TlvFlags {
    PIC = 0x01,
    NON_BOOTABLE = 0x02,
    ENCRYPTED_AES128 = 0x04,
    RAM_LOAD = 0x20,
    ENCRYPTED_AES256 = 0x08,
}

/** Image header.  All fields are in little endian byte order. */
#[derive(Debug,PartialEq)]
pub struct ImageHeader {
    pub magic:          u32,
    pub load_addr:      u32,
    pub hdr_size:       u16,
    pub prot_tlv_size:  u16,
    pub img_size:       u32,
    pub flags:          u32,
    pub ver_major:      u8,
    pub ver_minor:      u8,
    pub ver_rev:        u16,
    pub ver_build:      u32,
    pub pad1:           u32,
}

/** ImageHeader flags */
#[allow(dead_code)]
static IMAGE_F_PIC:                 u32 = 0x00000001; /* Not supported. */
#[allow(dead_code)]
static IMAGE_F_ENCRYPTED_AES128:    u32 = 0x00000004; /* Encrypted using AES128. */
#[allow(dead_code)]
static IMAGE_F_ENCRYPTED_AES256:    u32 = 0x00000008; /* Encrypted using AES256. */
#[allow(dead_code)]
static IMAGE_F_NON_BOOTABLE:        u32 = 0x00000010; /* Split image app. */


/** Image TLV header.  All fields in little endian. */
#[derive(Debug,PartialEq)]
pub struct ImageTLVInfo {
    pub magic:   u16,
    pub tlv_tot: u16,  /* size of TLV area (including tlv_info header) */
}


/** Image trailer TLV format. All fields in little endian. */
#[derive(Debug,PartialEq)]
pub struct ImageTLV {
    pub it_type: u16,   /* IMAGE_TLV_[...]. */
    pub it_len:  u16,   /* Data length (not including TLV header). */
}


static IMG_HDR:             &[u8] = &[ 0x3d, 0xb8, 0xf3, 0x96 ];
static TLV_INFO_MAGIC:      &[u8] = &[ 0x07, 0x69 ];
#[allow(dead_code)]
static TLV_PROT_INFO_MAGIC: &[u8] = &[ 0x08, 0x69 ]; /* not implemented yet */


fn parse_u32(i: &[u8]) -> IResult<&[u8], u32> {
    let (i, bytes) = take(4u8)(i)?;
    Ok((i, le_u32(bytes)?.1))
}

fn parse_u16(i: &[u8]) -> IResult<&[u8], u16> {
    let (i, bytes) = take(2u8)(i)?;
    Ok((i, le_u16(bytes)?.1))
}

fn parse_u8(i: &[u8]) -> IResult<&[u8], u8> {
    let (i, bytes) = take(1u8)(i)?;
    Ok((i, le_u8(bytes)?.1))
}


fn parse_img_hdr(i: &[u8]) -> IResult<&[u8], ImageHeader> {
  let (i, _)            = tag(IMG_HDR)(i)?;
  let (i, load_addr)    = parse_u32(i)?;
  let (i, hdr_size)     = parse_u16(i)?;
  let (i, prot_tlv_size)= parse_u16(i)?;
  let (i, img_size)     = parse_u32(i)?;
  let (i, flags)        = parse_u32(i)?;
  let (i, ver_major)    = parse_u8(i)?;
  let (i, ver_minor)    = parse_u8(i)?;
  let (i, ver_rev)      = parse_u16(i)?;
  let (i, ver_build)    = parse_u32(i)?;
  let (i, pad1)         = parse_u32(i)?;

  Ok((i, ImageHeader { magic: le_u32(IMG_HDR)?.1, load_addr, hdr_size, prot_tlv_size, img_size, flags, ver_major, ver_minor, ver_rev, ver_build, pad1 }))
}

fn parse_tlv_info(i: &[u8]) -> IResult<&[u8], ImageTLVInfo> {
  let (i, _)        = tag(TLV_INFO_MAGIC)(i)?;
  let (i, tlv_tot)  = parse_u16(i)?;

  Ok((i, ImageTLVInfo { magic: le_u16(TLV_INFO_MAGIC)?.1, tlv_tot }))
}

fn parse_tlv(i: &[u8]) -> IResult<&[u8], ImageTLV> {
  let (i, it_type) = parse_u16(i)?;
  let (i, it_len)  = parse_u16(i)?;
  //let (i, payload)  = take(it_len)?;

  //Ok((i, ImageTLV { it_type, it_len }, payload))
  Ok((i, ImageTLV { it_type, it_len }))
}

fn parse_tlv_payload(i: &[u8], len: u16) -> IResult<&[u8], &[u8]> {
  let (i, payload) = take(len)(i)?;
  Ok((i, payload))
}

fn main() {
    println!("mcuboot-tlv-parser v0.0.1");

    // Get first argument: filename
    if env::args().count() < 2 {
        println!("Usage: {} <mcuboot_image.bin>", env::args().next().unwrap_or("".to_string()));
        return;
    }
    let filename = env::args().nth(1).unwrap();

    // Open image file
    println!("[*] Opening image file {}", filename);
    let buf = fs::read(filename).unwrap();
    println!("[*] Total file size:  {}", buf.len());

    // Parser image header
    let (_, img_hdr) = parse_img_hdr(&buf).unwrap();
    println!("[*] {:?}", img_hdr);

    // Parse TLV header
    let tlv_off = img_hdr.hdr_size as u32 + img_hdr.img_size;
    let (_, tlv_info) = parse_tlv_info(&buf[tlv_off as usize .. buf.len()]).unwrap();
    println!("[*] {:?}", tlv_info);

    // Check computed image size with actual file size
    let img_total_size = tlv_off + img_hdr.prot_tlv_size as u32 + tlv_info.tlv_tot as u32;
    println!("[*] Image total size: {}", img_total_size);
    assert!(buf.len() == img_total_size as usize);

    // Check for protected TLVs
    if img_hdr.prot_tlv_size != 0 {
        println!("Protected TLVs are not supported yet");
        return;
    }

    // Iterate over TLVs
    let mut tlv_it_idx = tlv_off as usize + size_of::<ImageTLVInfo>();

    while tlv_it_idx < img_total_size as usize {
        let (i, tlv) = parse_tlv(&buf[tlv_it_idx .. buf.len()]).unwrap();
        let (_, payload) = parse_tlv_payload(i, tlv.it_len).unwrap();
        let tlv_type: TlvKinds = match num::FromPrimitive::from_u16(tlv.it_type) {
            Some(inner) => inner,
            None => TlvKinds::TLV_UNKNOWN,
        };
        println!("");
        println!("[*] {:?} @ {}, {}b", tlv_type, tlv_it_idx, tlv.it_len);
        println!("{:02X?}", payload);
        tlv_it_idx += tlv.it_len as usize + size_of::<ImageTLV>();
    }
}

