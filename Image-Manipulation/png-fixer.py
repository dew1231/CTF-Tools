import binascii
import sys

# Constants
FILE_HEADER = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"
PNG_CHUNKS_TYPE = [b"IHDR", b"PLTE", b"IDAT", b"IEND", b"bKGD", b"cHRM", b"dSIG", 
                   b"eXIf", b"gAMA", b"hIST", b"iCCP", b"iTXt", b"pHYs", b"sBIT", 
                   b"sPLT", b"sRGB", b"sTER", b"tEXt", b"tIME", b"tRNS", b"zTXt"]
SPLITTER = "-----------------------"

def validate_crc(chunk_type: bytes, data: bytes, crc: int) -> bool:
    """Validate chunk CRC."""
    computed_crc = binascii.crc32(chunk_type + data) & 0xFFFFFFFF
    return computed_crc == crc

def validate_magicbytes(data: bytes) -> int:
    """Validate PNG header."""
    return len(FILE_HEADER) if data.startswith(FILE_HEADER) else 0

def repair_magicbytes(data: bytes) -> bytes:
    """Fix PNG header and align IHDR chunk."""
    # Remove extra bytes between header and IHDR if needed
    ihdr_pos = data.find(b"IHDR", 8, 16)  # IHDR should be at offset 8
    if ihdr_pos != -1 and ihdr_pos > 8:
        # Strip bytes between header and IHDR
        return FILE_HEADER + data[ihdr_pos-4:]  # Keep length bytes
    return FILE_HEADER + data[len(FILE_HEADER):]

def parse_chunks(data: bytes, offset: int) -> int:
    """Parse chunks with auto-truncation after IEND."""
    try:
        chunk_length = int.from_bytes(data[offset:offset+4], "big")
        chunk_type = data[offset+4:offset+8]
        
        # Stop parsing after IEND
        if chunk_type == b"IEND":
            return len(data)  # Force exit
        
        if chunk_type not in PNG_CHUNKS_TYPE:
            raise ValueError("Invalid chunk type")
        
        chunk_end = offset + 12 + chunk_length
        crc = int.from_bytes(data[chunk_end-4:chunk_end], "big")
        
        if not validate_crc(chunk_type, data[offset+8:chunk_end-4], crc):
            raise ValueError("CRC mismatch")
            
        return chunk_end
    except (IndexError, ValueError):
        return len(data)  # Truncate at error

def parse_and_repair(content: bytes) -> bytes:
    """Main repair logic."""
    # Fix header and align IHDR
    if not validate_magicbytes(content):
        content = repair_magicbytes(content)
    
    offset = 8  # Start after PNG header
    while offset < len(content):
        new_offset = parse_chunks(content, offset)
        if new_offset <= offset:
            # Truncate invalid data
            content = content[:offset]
            break
        offset = new_offset
    
    return content

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 png_fixer.py <input> <output>")
        return
    
    with open(sys.argv[1], "rb") as f:
        content = f.read()
    
    fixed = parse_and_repair(content)
    
    with open(sys.argv[2], "wb") as f:
        f.write(fixed)
    
    print(f"Fixed PNG written to {sys.argv[2]}")

if __name__ == "__main__":
    main()
