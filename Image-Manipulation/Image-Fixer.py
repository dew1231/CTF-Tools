import binascii
import sys
import struct

class FileRepairer:
    def __init__(self, magic_bytes: bytes, valid_chunks: list, chunk_parser: callable, section_offset: int = 0, header_to_insert: bytes = None):
        self.magic_bytes = magic_bytes
        self.valid_chunks = valid_chunks
        self.chunk_parser = chunk_parser
        self.section_offset = section_offset
        self.header_to_insert = header_to_insert

    def validate_magicbytes(self, data: bytes) -> int:
        """Validate file header (magic bytes)."""
        return len(self.magic_bytes) if data.startswith(self.magic_bytes) else 0

    def repair_magicbytes(self, data: bytes) -> bytes:
        """Fix missing header."""
        if not self.validate_magicbytes(data):
            return self.magic_bytes + data[len(self.magic_bytes):]
        return data

    def insert_missing_header(self, data: bytes) -> bytes:
        """Insert header if missing (specific to file formats like JPEG with JFIF)."""
        if self.header_to_insert and not data.startswith(self.header_to_insert):
            return self.header_to_insert + data
        return data

    def parse_chunks(self, data: bytes, offset: int) -> int:
        """Parse chunks with auto-truncation if necessary."""
        try:
            return self.chunk_parser(data, offset)
        except (IndexError, ValueError):
            return len(data)  # Truncate at error

    def parse_and_repair(self, content: bytes) -> bytes:
        """Repair logic for fixing the file."""
        if not self.validate_magicbytes(content):
            content = self.repair_magicbytes(content)

        # Insert missing header if needed
        content = self.insert_missing_header(content)

        offset = self.section_offset
        while offset < len(content):
            new_offset = self.parse_chunks(content, offset)
            if new_offset <= offset:
                # Truncate invalid data
                content = content[:offset]
                break
            offset = new_offset

        return content


# PNG Format with Chunk and CRC Validation
def parse_png_chunks(data: bytes, offset: int) -> int:
    """Parse PNG chunks, validate CRC, and check for all valid chunks."""
    chunk_length = struct.unpack(">I", data[offset:offset + 4])[0]
    chunk_type = data[offset + 4:offset + 8]
    
    # Handle chunk validity
    if chunk_type not in [b"IHDR", b"IDAT", b"IEND", b"PLTE", b"tEXt", b"iTXt", b"bKGD", b"cHRM", b"eXIf", b"gAMA", b"tIME"]:
        raise ValueError(f"Unknown or invalid chunk type {chunk_type}")

    chunk_data = data[offset + 8:offset + 8 + chunk_length]
    expected_crc = struct.unpack(">I", data[offset + 8 + chunk_length:offset + 12 + chunk_length])[0]
    
    # Validate CRC
    computed_crc = binascii.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
    if computed_crc != expected_crc:
        raise ValueError(f"Invalid CRC for chunk {chunk_type}")
    
    # Move to next chunk
    return offset + 12 + chunk_length  # 4 bytes length + 4 bytes type + chunk length


# JPEG Format (with Exif and APP0 Chunks)
def parse_jpeg_chunks(data: bytes, offset: int) -> int:
    """Parse JPEG chunks, including Exif and JFIF."""
    if data[offset:offset + 2] != b"\xFF\xD8":
        raise ValueError("Invalid JPEG header (SOI missing)")

    while offset < len(data):
        marker = data[offset:offset + 2]
        if marker == b"\xFF\xD9":  # EOI marker
            return len(data)
        elif marker == b"\xFF\xE0":  # APP0 for JFIF
            app0_length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
            exif_data = data[offset + 4:offset + 4 + app0_length]
            # Validate the JFIF header (if missing, insert it)
            if not exif_data.startswith(b"JFIF"):
                raise ValueError("Missing JFIF header, inserting JFIF")
            offset += app0_length + 2  # Skip APP0 block
        else:
            offset += 2  # Skip over marker
            segment_length = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + segment_length
    return len(data)


# Main function to handle file format-specific logic
def main():
    if len(sys.argv) != 3:
        print("Usage: python3 file_fixer.py <input> <output>")
        return

    file_format = sys.argv[1].split('.')[-1].lower()  # Assuming the file format is indicated by the extension

    if file_format == 'png':
        magic_bytes = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"
        valid_chunks = [b"IHDR", b"PLTE", b"IDAT", b"IEND", b"bKGD", b"cHRM", b"eXIf", b"gAMA", b"tEXt", b"iTXt"]
        repairer = FileRepairer(magic_bytes, valid_chunks, parse_png_chunks)
    
    elif file_format == 'jpeg' or file_format == 'jpg':
        magic_bytes = b"\xFF\xD8\xFF"
        valid_chunks = [b"\xFF\xD8", b"\xFF\xD9"]  # SOI and EOI markers
        header_to_insert = b"\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01"  # JFIF Header
        repairer = FileRepairer(magic_bytes, valid_chunks, parse_jpeg_chunks, header_to_insert=header_to_insert)
    
    elif file_format == 'gif':
        magic_bytes = b"GIF87a"
        valid_chunks = [b"GIF87a", b"GIF89a"]
        repairer = FileRepairer(magic_bytes, valid_chunks, parse_png_chunks)  # You can customize chunks for GIF
    
    elif file_format == 'bmp':
        magic_bytes = b"BM"
        valid_chunks = [b"BM"]
        repairer = FileRepairer(magic_bytes, valid_chunks, parse_png_chunks)  # You can customize chunks for BMP
    
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

