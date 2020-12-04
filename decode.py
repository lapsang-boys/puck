from pstats import SortKey
from typing import Any, List
import cProfile, pstats
import io as otherio
import os
import os.path
import pathlib
import struct
import sys
import zlib

import pwnlib.util.packing as packing
from pwnlib.util.fiddling import hexdump

OUTPUT_FOLDER = "out"

def dbg(v: Any, s: str = None):
    pass
    # if s:
    #     print(s)
    # print(hexdump(v, total=False))

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
        pos = self.buf.index(b"\0", self.cur_pos)
        if pos == -1:
            raise ValueError("rstr: not null-terminated, lol")

        n = pos-self.cur_pos
        contents = self.readn(n)
        self.skip(1) # Null-byte
        if b"fbx" in contents:
            print("\t", contents)
            print("\t", "!!!! asdf")
        return contents.decode("utf-8")

    def r16le(self):
        raw = self.buf[self.cur_pos:self.cur_pos+2]
        self.cur_pos += 2
        return struct.unpack("<h", raw)[0]

    def r32le(self):
        raw = self.buf[self.cur_pos:self.cur_pos+4]
        self.cur_pos += 4
        return struct.unpack("<i", raw)[0]

    def r32leu(self):
        raw = self.buf[self.cur_pos:self.cur_pos+4]
        self.cur_pos += 4
        return struct.unpack("<I", raw)[0]

    def r32be(self):
        raw = self.buf[self.cur_pos:self.cur_pos+4]
        self.cur_pos += 4
        return struct.unpack(">i", raw)[0]

    def r16be(self):
        pass

    def readuntil(self, needle):
        n = self.buf[self.cur_pos:].index(needle)
        return self.readn(n)

    def parse_with_path(self, extension: str = None, dump_files: bool = False) -> List[str]:
        dirs = []
        size = 0
        while True:
            dir = self.rstr()
            if not dir:
                return size, dirs
            dirs.append(dir)
            folder_size = self.parse(dir, extension, dump_files)
            size += folder_size

    def dump(self, dir: str, vpk_filename: str, extension: str, dir_id: int, pak_id: int, vpk_offset: int, vpk_size: int, crc32: int):
        output_path = f"{OUTPUT_FOLDER}/{dir}/{vpk_filename}.{extension}"
        if os.path.exists(output_path):
            print(f"exists: {output_path}")
            return
        else:
            output_dir = os.path.dirname(output_path)
            pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)

        archive_path = f"pak{dir_id:02d}_{pak_id:03d}.vpk"
        if not os.path.exists(archive_path):
            print(f"Not exists: {archive_path}")
            return

        with open(archive_path, "rb") as vpk_archive:
            with open(output_path, "wb") as extracted_file:
                vpk_archive.seek(vpk_offset)
                blob = vpk_archive.read(vpk_size)
                assert zlib.crc32(blob) == crc32
                extracted_file.write(blob)

    def parse(self, dir: str, extension: str = None, dump_files: bool = False):
        dir_id = 1
        size = 0
        while True:
            vpk_filename = self.rstr()
            if len(vpk_filename) == 0:
                break

            crc32 = self.r32leu()

            file_reserved1 = self.readn(2)

            pak_id = self.r16le()
            if pak_id > 208:
                raise ValueError(f"pak_id too large -- boo: {pak_id}")
            # print("pak_id")
            # print(pak_id)

            vpk_offset = self.r32le() # Plausibly offsets
            # print("vpk_offset")
            # print(vpk_offset)
            vpk_size = self.r32le() # Plausibly size
            size += vpk_size
            # print("vpk_size")
            # print(vpk_size)

            if dump_files:
                self.dump(dir, vpk_filename, extension, dir_id, pak_id, vpk_offset, vpk_size, crc32)

            vpk_block_end = self.readn(2)
            if vpk_block_end != b"\xff\xff":
                raise ValueError("Not parseable -- boo nej")

        return size

    def parse_bik(self):
        path_without_ext = self.rstr()
        self.parse("bik")

def parse_fileformat(io):
    fileformat = io.rstr()
    if len(fileformat) == 0:
        raise ValueError("Plausibly file end -- boo")

    dump = False
    if fileformat == "vmesh_c":
        dump = True
    size, dirs = io.parse_with_path(fileformat, dump)
    print(fileformat, size)
    # if fileformat == "mp4":
    #     print(fileformat, size)
    #     for d in dirs:
    #         print("\t", d)

    #     print()

def main():
    vpk_filename = sys.argv[1]
    contents = None
    fp = open(vpk_filename, "rb")
    io = Io(fp.read())
    fp.close()

    magic = io.readn(4)
    version = io.r32le()
    size = io.readn(4) # Filesize - 76 / 0x4c, but why tidningspapper garn
    # Header_size (0x1c) + unk1 (0x30) == 0x4c / 76
    reserved1 = io.readn(4)
    reserved2 = io.readn(4)
    header_unk1 = io.readn(4)
    header_unk2 = io.readn(4)

    while True:
        # pr = cProfile.Profile()
        # pr.enable()
        parse_fileformat(io)
        # pr.disable()

        # s = otherio.StringIO()
        # sortby = SortKey.CUMULATIVE
        # ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        # ps.print_stats()
        # print(s.getvalue())

if __name__ == "__main__":
    main()
