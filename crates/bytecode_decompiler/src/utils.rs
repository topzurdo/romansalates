pub fn read_u8(bytes: &[u8], offset: &mut usize) -> Option<u8> {
    let value = *bytes.get(*offset)?;
    *offset += 1;
    Some(value)
}

pub fn read_u32_le(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    let slice = bytes.get(*offset..(*offset + 4))?;
    *offset += 4;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

pub fn read_f32(bytes: &[u8], offset: &mut usize) -> Option<f32> {
    Some(f32::from_bits(read_u32_le(bytes, offset)?))
}

pub fn read_f64(bytes: &[u8], offset: &mut usize) -> Option<f64> {
    let lo = read_u32_le(bytes, offset)?;
    let hi = read_u32_le(bytes, offset)?;
    Some(f64::from_bits((hi as u64) << 32 | lo as u64))
}

pub fn read_bytes<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Option<&'a [u8]> {
    let slice = bytes.get(*offset..(*offset + len))?;
    *offset += len;
    Some(slice)
}

pub fn read_varint(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    let mut result = 0u32;
    let mut shift = 0;
    loop {
        let b = read_u8(bytes, offset)?;
        result |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    Some(result)
}
