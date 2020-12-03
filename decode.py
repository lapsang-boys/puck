from typing import Any
import sys

import pwnlib.util.packing as packing
from pwnlib.util.fiddling import hexdump

class Io():
    def __init__(self, buf: Any):
        self.buf = buf
        self.cur_pos = 0

    def readn(self, n: int):
        " read n bytes lol "
        # Todo(_): Missing length check!
        contents = self.buf[self.cur_pos:self.cur_pos+n]
        self.cur_pos += n
        return contents

    def skip(self, n: int):
        self.cur_pos += n

    def rstr(self):
        " read str lol "
        n = self.buf[self.cur_pos:].index(b"\0")
        if n == -1:
            raise ValueError("rstr: not null-terminated, lol")

        contents = self.readn(n)
        self.skip(1) # Null-byte
        return contents.decode("utf-8")

    def r16le(self):
        raw = self.buf[self.cur_pos:self.cur_pos+2]
        self.cur_pos += 2
        return packing.u16(raw, endian="little")

    def r32le(self):
        raw = self.buf[self.cur_pos:self.cur_pos+4]
        self.cur_pos += 4
        return packing.u32(raw, endian="little")

    def r16be(self):
        pass

    def readuntil(self, needle):
        n = self.buf[self.cur_pos:].index(needle)
        return self.readn(n)

    def parse_png(self):
        path_without_ext = self.rstr()
        dbg(path_without_ext, "path_without_ext")
        self.parse("png")

    def parse(self, extension: str):
        dir_id = 1
        while True:
            print(self.cur_pos)
            vpk_filename = self.rstr()
            if len(vpk_filename) == 0:
                break
            dbg(vpk_filename, "vpk_filename")

            file_unk1 = self.readn(4) # Plausibly CRC32
            dbg(file_unk1, "file_unk1")

            file_reserved1 = self.readn(2)
            dbg(file_reserved1, "file_reserved1")

            pak_id = self.r16le()
            if pak_id > 208:
                raise ValueError(f"pak_id too large -- boo: {pak_id}")
            print("pak_id")
            print(pak_id)

            vpk_offset = self.r32le() # Plausibly offsets
            print("vpk_offset")
            print(vpk_offset)
            vpk_size = self.r32le() # Plausibly size
            print("vpk_size")
            print(vpk_size)

            with open(f"pak{dir_id:02d}_{pak_id:03d}.vpk", "rb") as vpk_archive:
                with open(f"{vpk_filename}.{extension}", "wb") as extracted_file:
                    vpk_archive.seek(vpk_offset)
                    blob = vpk_archive.read(vpk_size)
                    extracted_file.write(blob)

            vpk_block_end = self.readn(2)
            dbg(vpk_block_end, "vpk_block_end")
            if vpk_block_end != b"\xff\xff":
                raise ValueError("Not parseable -- boo nej")

    def parse_bik(self):
        path_without_ext = self.rstr()
        dbg(path_without_ext, "path_without_ext")
        self.parse("bik")

def dbg(v: Any, s: str = None):
    if s:
        print(s)
    print(hexdump(v, total=False))

def main():
    vpk_filename = sys.argv[1]
    contents = None
    fp = open(vpk_filename, "rb")
    io = Io(fp.read())
    fp.close()

    magic = io.readn(4)
    version = io.readn(4)
    size = io.readn(4) # Filesize - 76 / 0x4c, but why tidningspapper garn
    # Header_size (0x1c) + unk1 (0x30) == 0x4c / 76
    dbg(magic, "magic")
    dbg(version, "version")
    dbg(size, "size")
    reserved1 = io.readn(4)
    reserved2 = io.readn(4)
    dbg(reserved1, "reserved1")
    dbg(reserved2, "reserved2")
    header_unk1 = io.readn(4)
    header_unk2 = io.readn(4)
    dbg(header_unk1, "header_unk1")
    dbg(header_unk2, "header_unk2")

    while True:
        blob = io.readuntil(b"\xff\xff\x00\x00")
        io.skip(4)
        fileformat = io.rstr()
        if fileformat == "png":
            io.parse_png()
        # print(io.cur_pos)
        if len(fileformat) == 0:
            raise ValueError("Plausibly file end -- boo")
        # dbg(fileformat, "fileformat")

        # if fileformat == "bik":
        #     io.parse_bik()
        # elif fileformat == "media":
        #     io.parse_media()
        # elif fileformat == "media/heroes":
        #     io.parse_media()
        # elif fileformat == "bin":
        #     io.parse_media()
        # else:
        #     blob = io.readn(64)
        #     dbg(blob, "blob")
        #     print(io.cur_pos)
        #     raise ValueError(f"Unk fileformat: {fileformat}")

if __name__ == "__main__":
    main()
