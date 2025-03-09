#!/usr/bin/env python3

import binascii
import sys

class FileRepairer:
    def __init__(self, magic_bytes: bytes, valid_sections: list, section_parser: callable, section_offset: int = 0):
        self.magic_bytes = magic_bytes
        self.valid_sections = valid_sections
        self.section_parser = section_parser
        self.section_offset = section_offset

    def validate_magicbytes(self, data: bytes) -> int:
        """Validate file header (magic bytes)."""
        return len(self.magic_bytes) if data.startswith(self.magic_bytes) else 0

    def repair_magicbytes(self, data: bytes) -> bytes:
        """Fix missing header."""
        if not self.validate_magicbytes(data):
            return self.magic_bytes + data[len(self.magic_bytes):]
        return data

    def parse_sections(self, data: bytes, offset: int) -> int:
        """Parse sections with auto-truncation if necessary."""
        try:
            return self.section_parser(data, offset)
        except (IndexError, ValueError):
            return len(data) 

    def parse_and_repair(self, content: bytes) -> bytes:
        """Repair logic for fixing the file."""
        if not self.validate_magicbytes(content):
            content = self.repair_magicbytes(content)

        offset = self.section_offset
        while offset < len(content):
            new_offset = self.parse_sections(content, offset)
            if new_offset <= offset:
                content = content[:offset]
                break
            offset = new_offset

        return content


# Define parsers and structures for each file format

def parse_png_sections(data: bytes, offset: int) -> int:
    """Parse PNG-like sections. """
    chunk_length = int.from_bytes(data[offset:offset+4], "big")
    chunk_type = data[offset+4:offset+8]
    
    if chunk_type == b"IEND":
        return len(data)  

    if chunk_type not in [b"IHDR", b"IDAT", b"IEND"]:
        raise ValueError("Invalid chunk type")
    
    chunk_end = offset + 12 + chunk_length
    crc = int.from_bytes(data[chunk_end-4:chunk_end], "big")
    computed_crc = binascii.crc32(chunk_type + data[offset+8:chunk_end-4]) & 0xFFFFFFFF
    
    if computed_crc != crc:
        raise ValueError("CRC mismatch")
    
    return chunk_end

# JPEG File Parsing (checking for SOI and EOI)
def parse_jpeg_sections(data: bytes, offset: int) -> int:
    """Parse JPEG sections."""
    # JPEG starts with SOI (Start Of Image: 0xFF, 0xD8) and ends with EOI (End Of Image: 0xFF, 0xD9)
    if offset == 0:
        # Check for SOI marker at the beginning
        if data[offset:offset+2] != b"\xFF\xD8":
            raise ValueError("Invalid JPEG SOI marker")
    
    # JPEG segments are between 0xFF and 0xD9 markers
    while offset < len(data):
        marker = data[offset:offset+2]
        if marker == b"\xFF\xD9":  # EOI marker
            return len(data)  # Reached the end of image, stop parsing
        offset += 2
        length = int.from_bytes(data[offset:offset+2], "big") - 2  # Length of the segment
        offset += 2 + length  # Move to the next marker
    
    return len(data)  # If no EOI found, truncate

# GIF File Parsing (GIF header and blocks)
def parse_gif_sections(data: bytes, offset: int) -> int:
    """Parse GIF sections."""
    # Check for GIF header (either GIF87a or GIF89a)
    if offset == 0:
        if not (data.startswith(b"GIF87a", 0) or data.startswith(b"GIF89a", 0)):
            raise ValueError("Invalid GIF header")
    
    # Look for Graphics Control Extension or Image Descriptor
    while offset < len(data):
        block_start = data[offset]
        if block_start == 0x21:  # Extension block, possibly Graphic Control Extension
            offset += 1
            extension_type = data[offset]
            if extension_type == 0xF9:  # Graphic Control Extension
                block_length = data[offset+1]
                offset += 2 + block_length  # Skip the block
            else:
                raise ValueError("Unknown GIF extension")
        elif block_start == 0x2C:  # Image Descriptor
            offset += 9  # Skip Image Descriptor header
        elif block_start == 0x3B:  # GIF Trailer (EOF)
            return len(data)
        else:
            raise ValueError("Unknown GIF block")
    
    return len(data)

# BMP File Parsing (checking for BMP header)
def parse_bmp_sections(data: bytes, offset: int) -> int:
    """Parse BMP header."""
    # BMP files start with 'BM' (0x42, 0x4D) at offset 0
    if offset == 0:
        if data[offset:offset+2] != b"BM":
            raise ValueError("Invalid BMP header")
    
    # BMP file sections (we'll just check for the main header and image data)
    header_size = int.from_bytes(data[offset+14:offset+18], "little")  # The header size (normally 40 bytes)
    offset += header_size  # Skip header size
    
    return len(data)  # Reached the end


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 file_fixer.py <input> <output>")
        return

    file_format = sys.argv[1].split('.')[-1].lower()  

    if file_format == 'png':
        magic_bytes = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"
        valid_sections = [b"IHDR", b"PLTE", b"IDAT", b"IEND"]
        repairer = FileRepairer(magic_bytes, valid_sections, parse_png_sections)
    
    elif file_format == 'jpeg' or file_format == 'jpg':
        magic_bytes = b"\xFF\xD8\xFF"
        valid_sections = [b"\xFF\xD8", b"\xFF\xD9"]  # SOI and EOI markers
        repairer = FileRepairer(magic_bytes, valid_sections, parse_jpeg_sections)
    
    elif file_format == 'gif':
        magic_bytes = b"GIF87a"
        valid_sections = [b"GIF87a", b"GIF89a"]
        repairer = FileRepairer(magic_bytes, valid_sections, parse_gif_sections)
    
    elif file_format == 'bmp':
        magic_bytes = b"BM"
        valid_sections = [b"BM"]
        repairer = FileRepairer(magic_bytes, valid_sections, parse_bmp_sections)
    
    else:
        print("Unsupported file format.")
        return

    with open(sys.argv[1], "rb") as f:
        content = f.read()

    fixed = repairer.parse_and_repair(content)

    with open(sys.argv[2], "wb") as f:
        f.write(fixed)

    print(f"Fixed {file_format} written to {sys.argv[2]}")

if __name__ == "__main__":
    main()

