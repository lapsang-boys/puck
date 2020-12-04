package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

func main() {
	var (
		dumpFiles bool
		outputDir string
		verbose   bool
	)
	flag.BoolVar(&dumpFiles, "dump", false, "dump files")
	flag.StringVar(&outputDir, "o", "_dump_", "output directory")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.Parse()
	for _, path := range flag.Args() {
		pakDirFile, err := parse(path)
		if err != nil {
			log.Fatalf("%+v", err)
		}
		if verbose {
			debugOutput(pakDirFile)
		}
		if dumpFiles {
			if err := dump(pakDirFile, outputDir); err != nil {
				log.Fatalf("%+v", err)
			}
		}
	}
}

// --- [ debug ] ---------------------------------------------------------------

func debugOutput(pakDirFile PakDirFile) {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for _, chunk := range pakDirFile.chunks {
		fmt.Fprintf(w, "=== [ ext: %s ] ===============================================================\n", chunk.ext)
		fmt.Fprintln(w)
		for _, dir := range chunk.dirs {
			fmt.Fprintln(w, "dirName:", dir.dirName)
			fmt.Fprintln(w)
			for _, file := range dir.files {
				fmt.Fprintln(w, "   fileName:", file.fileName)
				//fmt.Fprintln(w, "   pakID:", file.pakID)
				//fmt.Fprintln(w, "   fileOffset:", file.fileOffset)
				//fmt.Fprintln(w, "   fileSize:", file.fileSize)
			}
			fmt.Fprintln(w)
		}
	}
}

// --- [ dump ] ----------------------------------------------------------------

func dump(pakDirFile PakDirFile, outputDir string) error {
	for _, chunk := range pakDirFile.chunks {
		fmt.Println("ext:", chunk.ext)
		for _, dir := range chunk.dirs {
			fmt.Println("dirName:", dir.dirName)
			dstDir := filepath.Join(outputDir, chunk.ext, filepath.Clean(dir.dirName))
			if !strings.HasPrefix(dstDir, outputDir) {
				return errors.Errorf("invalid destination directory %q; not prefixed by output directory %q", dstDir, outputDir)
			}
			if err := os.MkdirAll(dstDir, 0755); err != nil {
				return errors.WithStack(err)
			}
			for _, file := range dir.files {
				fmt.Println("fileName:", file.fileName)
				fmt.Println("pakID:", file.pakID)
				fmt.Println("fileOffset:", file.fileOffset)
				fmt.Println("fileSize:", file.fileSize)
				fileName := fmt.Sprintf("%s.%s", file.fileName, chunk.ext)
				dstPath := filepath.Join(dstDir, filepath.Clean(fileName))
				if !strings.HasPrefix(dstPath, outputDir) {
					return errors.Errorf("invalid destination path %q; not prefixed by output directory %q", dstPath, outputDir)
				}
				buf, err := getFileContent(pakDirFile.dirID, file)
				if err != nil {
					return errors.WithStack(err)
				}
				if err := ioutil.WriteFile(dstPath, buf, 0644); err != nil {
					return errors.WithStack(err)
				}
			}
		}
	}
	return nil
}

func getFileContent(dirID int, file File) ([]byte, error) {
	pakPath := fmt.Sprintf("pak%02d_%03d.vpk", dirID, file.pakID)
	f, err := os.Open(pakPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer f.Close()
	if _, err := f.Seek(int64(file.fileOffset), io.SeekStart); err != nil {
		return nil, errors.WithStack(err)
	}
	buf := make([]byte, file.fileSize)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, errors.WithStack(err)
	}
	return buf, nil
}

// --- [ parse ] ---------------------------------------------------------------

func parse(path string) (PakDirFile, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return PakDirFile{}, errors.WithStack(err)
	}
	p := &parser{
		buf: buf,
		pos: 0,
	}
	// pak01_dir.vpk
	name := filepath.Base(path)
	var dirID int
	if _, err := fmt.Sscanf(name, "pak%02d_dir.vpk", &dirID); err != nil {
		return PakDirFile{}, errors.Errorf("unable to locate directory ID in file name; expected pakNN_dir.vpk, got %q", name)
	}
	if !strings.HasPrefix(name, "pak") {
		return PakDirFile{}, errors.Errorf("")
	}
	pakDirFile := p.parsePakDirFile(dirID)
	return pakDirFile, nil
}

type PakDirFile struct {
	dirID     int
	magic     []byte
	version   int
	size      int
	reserved1 []byte
	reserved2 []byte
	hdrUkn1   []byte
	hdrUkn2   []byte
	chunks    []Chunk
}

func (p *parser) parsePakDirFile(dirID int) PakDirFile {
	pakDirFile := PakDirFile{}
	pakDirFile.dirID = dirID
	pakDirFile.magic = p.readn(4)
	pakDirFile.version = p.readInt32LE()
	pakDirFile.size = p.readInt32LE()
	pakDirFile.reserved1 = p.skip(4)
	pakDirFile.reserved2 = p.skip(4)
	pakDirFile.hdrUkn1 = p.skip(4)
	pakDirFile.hdrUkn2 = p.skip(4)
	//pretty.Println("pakDirFile:", pakDirFile)
	for {
		chunk, ok := p.parseChunk()
		if !ok {
			break
		}
		//pretty.Println("chunk:", chunk)
		pakDirFile.chunks = append(pakDirFile.chunks, chunk)
	}
	return pakDirFile
}

type Chunk struct {
	ext  string
	dirs []Dir
}

func (p *parser) parseChunk() (Chunk, bool) {
	chunk := Chunk{}
	ext := p.readString()
	if len(ext) == 0 {
		return Chunk{}, false
	}
	chunk.ext = ext
	//fmt.Println("ext:", ext)
	chunk.dirs = p.parseDirs()
	return chunk, true
}

func (p *parser) parseDirs() []Dir {
	var dirs []Dir
	for {
		dirName := p.readString()
		if len(dirName) == 0 {
			break
		}
		//fmt.Println("dirName:", dirName)
		dir := p.parseDir(dirName)
		dirs = append(dirs, dir)
	}
	return dirs
}

type Dir struct {
	dirName string
	files   []File
}

func (p *parser) parseDir(dirName string) Dir {
	dir := Dir{
		dirName: dirName,
	}
	dir.files = p.parseFiles()
	return dir
}

func (p *parser) parseFiles() []File {
	var files []File
	for {
		fileName := p.readString()
		if len(fileName) == 0 {
			break
		}
		file := p.parseFile(fileName)
		files = append(files, file)
	}
	return files
}

type File struct {
	fileName      string
	fileUkn1      []byte
	fileReserved1 []byte
	pakID         int
	fileOffset    int
	fileSize      int
	blockEnd      []byte
}

func (p *parser) parseFile(fileName string) File {
	file := File{
		fileName: fileName,
	}
	file.fileUkn1 = p.readn(4)
	file.fileReserved1 = p.readn(2)
	file.pakID = p.readInt16LE()
	const maxPakID = 208
	if file.pakID > maxPakID {
		panic(fmt.Errorf("pakID too large; expected <= %d, got %d", maxPakID, file.pakID))
	}
	file.fileOffset = p.readInt32LE()
	file.fileSize = p.readInt32LE()
	file.blockEnd = p.readn(2)
	return file
}

// ### [ Helper functions ] ####################################################

type parser struct {
	buf []byte
	pos int
}

func (p *parser) readn(n int) []byte {
	buf := p.buf[p.pos : p.pos+n]
	p.pos += n
	//fmt.Println(hex.Dump(buf))
	return buf
}

func (p *parser) readInt16LE() int {
	const n = 2
	buf := p.buf[p.pos : p.pos+n]
	p.pos += n
	x := binary.LittleEndian.Uint16(buf)
	return int(x)
}

func (p *parser) readInt32LE() int {
	const n = 4
	buf := p.buf[p.pos : p.pos+n]
	p.pos += n
	x := binary.LittleEndian.Uint32(buf)
	return int(x)
}

func (p *parser) skip(n int) []byte {
	return p.readn(n)
}

func (p *parser) readString() string {
	n := bytes.IndexByte(p.buf[p.pos:], '\x00')
	if n == -1 {
		return ""
	}
	s := string(p.buf[p.pos : p.pos+n])
	p.pos += n
	p.skip(1)
	return s
}
