package casblob

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

type CompressionType uint8

const (
	Identity  CompressionType = 0
	Zstandard CompressionType = 1
)

var zstdLevelOpt = zstd.WithEncoderLevel(zstd.SpeedFastest)
var encoder, _ = zstd.NewWriter(nil, zstdLevelOpt)

const chunkSize = 1024 * 1024 * 1 // 1M

// Compressed blobs contain a header followed by chunks of compressed data
// (or a single chunk of uncompressed data).

type header struct {
	// The following data is stored in little-endian format on disk.
	uncompressedSize int64           // 8 bytes
	compression      CompressionType // uint8, 1 byte
	// Stored as an int32 number of chunks, followed by their int64 offsets.
	// 4 bytes + (n * 8 bytes)
	chunkOffsets []int64
}

const chunkTableOffset = 8 + 1 + 4

// Returns the size of the header itself.
func (h *header) size() int64 {
	return chunkTableOffset + (int64(len(h.chunkOffsets)) * 8)
}

// Provides an io.ReadCloser that returns uncompressed data from a zstd
// compressed blob.
type zstdBlobReader struct {
	*header

	file    *os.File
	decoder *zstd.Decoder
}

// Read the header and leave f at the start of the data.
func readHeader(f *os.File) (*header, error) {
	var err error
	var h header

	fileInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	foundFileSize := fileInfo.Size()

	err = binary.Read(f, binary.LittleEndian, &h.uncompressedSize)
	if err != nil {
		return nil, err
	}

	err = binary.Read(f, binary.LittleEndian, &h.compression)
	if err != nil {
		return nil, err
	}

	var numChunks int32
	err = binary.Read(f, binary.LittleEndian, &numChunks)
	if err != nil {
		return nil, err
	}

	if numChunks < 1 {
		return nil, fmt.Errorf("internal error: need at least one chunk, found %d", numChunks)
	}

	h.chunkOffsets = make([]int64, numChunks, numChunks)
	for i := 0; int32(i) < numChunks; i++ {
		err = binary.Read(f, binary.LittleEndian, &h.chunkOffsets[i])
		if err != nil {
			return nil, err
		}

		if h.chunkOffsets[i] > foundFileSize {
			return nil,
				fmt.Errorf("offset table value %d larger than file size %d",
					h.chunkOffsets[i], foundFileSize)
		}
	}

	return &h, nil
}

func GetLogicalSize(filename string) (int64, error) {
	f, err := os.Open(filename)
	if err != nil {
		return -1, err
	}
	defer f.Close()

	hdr, err := readHeader(f)
	if err != nil {
		return -1, err
	}

	return hdr.uncompressedSize, nil
}

// Closes f if there is an error. Otherwise the caller must Close the returned
// io.ReadCloser.
func GetUncompressedReadCloser(f *os.File, expectedSize int64) (io.ReadCloser, error) {
	h, err := readHeader(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	if expectedSize != -1 && h.uncompressedSize != expectedSize {
		return nil, fmt.Errorf("expected a blob of size %d, found %d",
			expectedSize, h.uncompressedSize)
	}

	if h.compression == Identity {
		// Simple case. Assumes that we only have one chunk if the data is
		// uncompressed (which makes sense).
		return f, nil
	}

	if h.compression != Zstandard {
		return nil,
			fmt.Errorf("internal error: unsupported compression type %d",
				h.compression)
	}

	z, err := zstd.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	return &zstdBlobReader{
		header:  h,
		decoder: z,
		file:    f,
	}, nil
}

func (h *header) write(f *os.File) error {
	var err error

	err = binary.Write(f, binary.LittleEndian, h.uncompressedSize)
	if err != nil {
		return err
	}

	err = binary.Write(f, binary.LittleEndian, h.compression)
	if err != nil {
		return err
	}

	err = binary.Write(f, binary.LittleEndian, int32(len(h.chunkOffsets)))
	if err != nil {
		return err
	}

	return h.writeChunkTable(f)
}

func (h *header) writeChunkTable(f *os.File) error {
	var err error

	for _, o := range h.chunkOffsets {
		err = binary.Write(f, binary.LittleEndian, o)
		if err != nil {
			return err
		}
	}

	return nil
}

var errNilReader = errors.New("CompressedBlob has no reader")

func (b *zstdBlobReader) Read(p []byte) (int, error) {
	if b.decoder == nil {
		return 0, errNilReader
	}

	return b.decoder.Read(p)
}

var errAlreadyClosed = errors.New("File already closed")

func (b *zstdBlobReader) Close() error {
	if b.decoder != nil {
		b.decoder.Close()
		b.decoder = nil
	}

	if b.file == nil {
		return nil
	}

	f := b.file
	b.file = nil

	return f.Close()
}

var errNotImplemented = errors.New("not implemented yet")

// Read from r and write to f, using CompressionType t.
// Return the size on disk or an error if something went wrong.
func WriteAndClose(r io.Reader, f *os.File, t CompressionType, hash string, size int64) (int64, error) {
	var err error
	defer f.Close()

	if size <= 0 {
		return -1, fmt.Errorf("invalid file size: %d", size)
	}

	numChunks := int64(1)
	remainder := int64(0)
	if t == Zstandard {
		numChunks = size / chunkSize
		remainder = size % chunkSize
		if remainder > 0 {
			numChunks++
		}
	}

	h := header{
		uncompressedSize: size,
		compression:      t,
		chunkOffsets:     make([]int64, numChunks, numChunks),
	}

	h.chunkOffsets[0] = chunkTableOffset

	err = h.write(f)
	if err != nil {
		return -1, err
	}

	fileOffset := h.size()

	var n int64

	if t == Identity {
		hasher := sha256.New()

		n, err = io.Copy(io.MultiWriter(f, hasher), r)
		if err != nil {
			return -1, err
		}
		if n != size {
			return -1, fmt.Errorf("expected to copy %d bytes, actually copied %d bytes",
				size, n)
		}

		actualHash := hex.EncodeToString(hasher.Sum(nil))
		if actualHash != hash {
			return -1,
				fmt.Errorf("checksums don't match. Expected %s, found %s",
					hash, actualHash)
		}

		return n + fileOffset, f.Close()
	}

	// Compress the data in chunks...

	nextChunk := 0 // Index in h.chunkOffsets.
	remainingRawData := size

	uncompressedChunk := make([]byte, chunkSize, chunkSize)

	hasher := sha256.New()

	for nextChunk < len(h.chunkOffsets) {
		h.chunkOffsets[nextChunk] = fileOffset
		nextChunk++

		chunkEnd := int64(chunkSize)
		if remainingRawData <= chunkSize {
			chunkEnd = remainingRawData
		}
		remainingRawData -= chunkEnd

		_, err = io.ReadFull(r, uncompressedChunk[0:chunkEnd])
		if err != nil {
			return -1, err
		}

		compressedChunk := encoder.EncodeAll(uncompressedChunk[0:chunkEnd], nil)

		hasher.Write(uncompressedChunk[0:chunkEnd])

		written, err := f.Write(compressedChunk)
		if err != nil {
			return -1, err
		}

		fileOffset += int64(written)
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if actualHash != hash {
		return -1, fmt.Errorf("checksums don't match. Expected %s, found %s",
			hash, actualHash)
	}

	// We know all the chunk offsets now, go back and fill those in.
	_, err = f.Seek(chunkTableOffset, io.SeekStart)
	if err != nil {
		return -1, err
	}

	err = h.writeChunkTable(f)
	if err != nil {
		return -1, err
	}

	err = f.Sync()
	if err != nil {
		return -1, err
	}

	return fileOffset, f.Close()
}
