import binascii
from collections import namedtuple
import struct


class Update2File():
    SIGNATURE = 0xF8CC425B

    HEADER_FORMAT = struct.Struct('I 4x 1024s I')
    HEADER_SIZE = HEADER_FORMAT.size

    BLOCK_FORMAT = struct.Struct('4I 256s')
    BLOCK_SIZE = BLOCK_FORMAT.size
    Block = namedtuple('Block', [
        'crc32',
        'key_index',
        'address',
        'xor_offset',
        'data',
    ])

    FOOTER_FORMAT = struct.Struct('4I 2048s')
    FOOTER_SIZE = FOOTER_FORMAT.size

    def __init__(self, source):
        self.raw = bytes(source)

        (
            self.signature,
            self.key,
            self.block_count
        ) = self.HEADER_FORMAT.unpack(self.raw[:self.HEADER_SIZE])

        #if self.signature != self.SIGNATURE:
        #    raise ValueError(
        #        "incorrect file signature: expected %08x, got %08x"
        #        % (self.SIGNATURE, self.signature)
        #    )

    def read_block(self, block_idx):
        if block_idx < 0 or block_idx > self.block_count - 1:
            raise IndexError("invalid block index")

        block_off = self.HEADER_SIZE + self.BLOCK_SIZE * block_idx
        block = self.Block._make(self.BLOCK_FORMAT.unpack(
            self.raw[block_off:block_off + self.BLOCK_SIZE]
        ))

        address = block.address
        for key_index in range(block.key_index, block.key_index + 44 * 6):
            address ^= self.key[key_index % 1024]
        block = block._replace(address = address)

        repack = self.BLOCK_FORMAT.pack(*block)
        actual = binascii.crc32(repack[4:], ~0)
        expected = block.crc32 ^ 0xffffffff
        if actual != expected:
            raise RuntimeError(
                "block CRC mismatch: expected %08x, got %08x"
                % (expected, actual)
            )

        return block

    def read_footer(self):
        offset = self.HEADER_SIZE + self.BLOCK_SIZE * self.block_count
        footer = self.Block._make(self.FOOTER_FORMAT.unpack(
            self.raw[offset:offset + self.FOOTER_SIZE]
        ))

        address = footer.address
        for key_index in range(footer.key_index, footer.key_index + 514 * 4):
            address ^= self.key[key_index % 1024]
        footer = footer._replace(address = address)

        repack = self.FOOTER_FORMAT.pack(*footer)
        actual = binascii.crc32(repack[4:], ~0)
        expected = footer.crc32 ^ 0xffffffff
        if actual != expected:
            raise RuntimeError(
                "footer CRC mismatch: expected %08x, got %08x"
                % (expected, actual)
            )

        return footer

    @property
    def blocks(self):
        for idx in range(0, self.block_count):
            yield self.read_block(idx)

        yield self.read_footer()
