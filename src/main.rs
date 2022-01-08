extern crate nom;
extern crate hex;

use std::env;
use std::fs;

use nom::{IResult, bytes::complete::tag, bytes::complete::take};
use nom::number::complete::{le_u32, le_u16, le_u8};


#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // TODO: For now
pub enum TlvKinds {
    KEYHASH = 0x01,
    SHA256 = 0x10,
    RSA2048 = 0x20,
    ECDSA224 = 0x21,
    ECDSA256 = 0x22,
    RSA3072 = 0x23,
    ED25519 = 0x24,
    ENCRSA2048 = 0x30,
    ENCKW = 0x31,
    ENCEC256 = 0x32,
    ENCX25519 = 0x33,
    DEPENDENCY = 0x40,
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
    pub magic:     u32,
    pub load_addr:  u32,
    pub hdr_size:   u16,
    pub p_tlv_size: u16,
    pub img_size:   u32,
    pub flags:      u32,
    pub ver_major:  u8,
    pub ver_minor:  u8,
    pub ver_rev:    u16,
    pub ver_build:  u32,
    pub pad1:       u32,
}

/** Image TLV header.  All fields in little endian. */
#[derive(Debug,PartialEq)]
pub struct ITHeader {
    pub magic:   u16,
    pub tlv_tot: u16,  /* size of TLV area (including tlv_info header) */
}


/** Image trailer TLV format. All fields in little endian. */
pub struct TLVTrailer {
    pub it_type: u16,   /* IMAGE_TLV_[...]. */
    pub it_len:  u16,   /* Data length (not including TLV header). */
}

//#define BOOT_TLV_OFF(hdr) ((hdr)->ih_hdr_size + (hdr)->ih_img_size)

static IMG_HDR:             &[u8] = &[ 0x3d, 0xb8, 0xf3, 0x96 ];
static TLV_INFO_MAGIC:      &[u8] = &[ 0x07, 0x69 ];
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
  let (i, p_tlv_size)   = parse_u16(i)?;
  let (i, img_size)     = parse_u32(i)?;
  let (i, flags)        = parse_u32(i)?;
  let (i, ver_major)    = parse_u8(i)?;
  let (i, ver_minor)    = parse_u8(i)?;
  let (i, ver_rev)      = parse_u16(i)?;
  let (i, ver_build)    = parse_u32(i)?;
  let (i, pad1)         = parse_u32(i)?;

  Ok((i, ImageHeader { magic: le_u32(IMG_HDR)?.1, load_addr, hdr_size, p_tlv_size, img_size, flags, ver_major, ver_minor, ver_rev, ver_build, pad1 }))
}

fn parse_tlv_info(i: &[u8]) -> IResult<&[u8], ITHeader> {
  let (i, _)        = tag(TLV_INFO_MAGIC)(i)?;
  let (i, tlv_tot)  = parse_u16(i)?;

  Ok((i, ITHeader { magic: le_u16(TLV_INFO_MAGIC)?.1, tlv_tot }))
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
    println!("Opening image file {}", filename);
    let buf = fs::read(filename).unwrap();

    // Parser image header
    let (r, img_hdr) = parse_img_hdr(&buf).unwrap();
    println!("{:?}", img_hdr);

    // Parse TLV header
    let tlv_off = img_hdr.hdr_size as u32 + img_hdr.img_size;
    let (r, tlv_info) = parse_tlv_info(&buf[tlv_off as usize .. buf.len()]).unwrap();
    println!("{:?}", tlv_info);

    // Check computed image size with actual file size
    let img_total_size = tlv_off + img_hdr.p_tlv_size as u32 + tlv_info.tlv_tot as u32;
    println!("Total file size:  {}", buf.len());
    println!("Image total size: {}", img_total_size);
    assert!(buf.len() == img_total_size as usize);

}
