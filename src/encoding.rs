//! Bech32 decoding used to inspect reference key/address fixtures independently.
use anyhow::{ensure, Context, Result};

/// Decode original Bech32 with strict checksum and zero-padding validation.
/// Cardano deliberately permits strings longer than Bitcoin's 90-character limit.
pub fn bech32(text: &str) -> Result<(String, Vec<u8>)> {
    ensure!(
        !text.is_empty() && text.bytes().all(|b| (33..=126).contains(&b)),
        "invalid Bech32 characters"
    );
    ensure!(
        text == text.to_lowercase() || text == text.to_uppercase(),
        "mixed Bech32 case"
    );
    let text = text.to_lowercase();
    let separator = text.rfind('1').context("missing Bech32 separator")?;
    ensure!(
        separator > 0 && text.len() >= separator + 7,
        "invalid Bech32 length"
    );
    let hrp = &text[..separator];
    let alphabet = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let data = text[separator + 1..]
        .bytes()
        .map(|b| {
            alphabet
                .iter()
                .position(|x| *x == b)
                .map(|x| x as u8)
                .context("invalid Bech32 digit")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut check = 1u32;
    for value in hrp
        .bytes()
        .map(|x| x >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|x| x & 31))
        .chain(data.iter().copied())
    {
        let top = check >> 25;
        check = ((check & 0x1ff_ffff) << 5) ^ u32::from(value);
        for (i, generator) in [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            .iter()
            .enumerate()
        {
            if (top >> i) & 1 != 0 {
                check ^= generator;
            }
        }
    }
    ensure!(check == 1, "invalid Bech32 checksum");
    let mut output = Vec::new();
    let (mut accumulator, mut bits) = (0u32, 0u32);
    for digit in &data[..data.len() - 6] {
        accumulator = ((accumulator << 5) | u32::from(*digit)) & 0xfff;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    ensure!(
        bits < 5 && ((accumulator << (8 - bits)) & 0xff) == 0,
        "invalid Bech32 padding"
    );
    Ok((hrp.into(), output))
}

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    let mut check = 1u32;
    for value in values {
        let top = check >> 25;
        check = ((check & 0x1ff_ffff) << 5) ^ u32::from(value);
        for (i, generator) in [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            .iter()
            .enumerate()
        {
            if (top >> i) & 1 != 0 {
                check ^= generator;
            }
        }
    }
    check
}

/// Encode explicit 5-bit data, including deliberately malformed padding fixtures.
pub fn bech32_from_words(hrp: &str, words: &[u8]) -> Result<String> {
    ensure!(
        !hrp.is_empty()
            && hrp.bytes().all(|b| (33..=126).contains(&b))
            && hrp == hrp.to_lowercase(),
        "invalid Bech32 HRP"
    );
    ensure!(words.iter().all(|w| *w < 32), "invalid Bech32 data word");
    let expanded = hrp
        .bytes()
        .map(|b| b >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|b| b & 31));
    let check = polymod(expanded.chain(words.iter().copied()).chain([0; 6])) ^ 1;
    let alphabet = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut output = format!("{hrp}1");
    for word in words
        .iter()
        .copied()
        .chain((0..6).map(|i| ((check >> (5 * (5 - i))) & 31) as u8))
    {
        output.push(alphabet[word as usize] as char);
    }
    Ok(output)
}

pub fn bech32_encode(hrp: &str, bytes: &[u8]) -> Result<String> {
    let mut words = Vec::new();
    let (mut accumulator, mut bits) = (0u32, 0u32);
    for byte in bytes {
        accumulator = ((accumulator << 8) | u32::from(*byte)) & 0xffff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            words.push(((accumulator >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        words.push(((accumulator << (5 - bits)) & 31) as u8);
    }
    bech32_from_words(hrp, &words)
}

pub fn base58_encode(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.len() <= 4096, "base58 input exceeds bound");
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeroes = bytes.iter().take_while(|b| **b == 0).count();
    let mut digits = Vec::<u8>::new();
    for byte in bytes.iter().skip(zeroes) {
        let mut carry = u32::from(*byte);
        for digit in &mut digits {
            carry += u32::from(*digit) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    Ok(std::iter::repeat_n('1', zeroes)
        .chain(digits.iter().rev().map(|d| alphabet[*d as usize] as char))
        .collect())
}

pub fn base58_decode(text: &str) -> Result<Vec<u8>> {
    ensure!(text.len() <= 4096, "base58 text exceeds bound");
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeroes = text.bytes().take_while(|b| *b == b'1').count();
    let mut bytes = Vec::<u8>::new();
    for character in text.bytes().skip(zeroes) {
        let mut carry = alphabet
            .iter()
            .position(|b| *b == character)
            .context("invalid base58 character")? as u32;
        for byte in &mut bytes {
            carry += u32::from(*byte) * 58;
            *byte = (carry % 256) as u8;
            carry /= 256;
        }
        while carry > 0 {
            bytes.push((carry % 256) as u8);
            carry /= 256;
        }
    }
    Ok(std::iter::repeat_n(0, zeroes)
        .chain(bytes.into_iter().rev())
        .collect())
}
