package io.tomahawkd.cic.pcap;

import io.kaitai.struct.KaitaiStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

// Pcap files could be bigger than 2GB (Integer.MAX_VALUE)
// so here we need to create a cached pool for file
public class BigFileKaitaiStream extends KaitaiStream {

    private FileChannel fc;
    private MappedByteBuffer cachedByteBuffer;


    private final long fileSize;
    private final Position pos;

    private final long bufferBlockCount;
    private final int cacheSize;

    public BigFileKaitaiStream(Path file) throws IOException {
        // default byte buffer size is 256M
        this(file, 1 << 28);
    }

    public BigFileKaitaiStream(Path file, int cacheSize) throws IOException {
        this.fc = FileChannel.open(file, StandardOpenOption.READ);
        this.fileSize = fc.size();
        this.cacheSize = cacheSize;
        this.pos = new Position(cacheSize);
        if (fileSize < cacheSize) {
            this.bufferBlockCount = 1;
            this.cachedByteBuffer = fc.map(FileChannel.MapMode.READ_ONLY, 0, fileSize);
        } else {
            this.bufferBlockCount = (long) Math.ceil((double) fileSize / (double) cacheSize);
            this.cachedByteBuffer = fc.map(FileChannel.MapMode.READ_ONLY, 0, cacheSize);
        }
    }

    /**
     * Load next block to the cache byte buffer.
     * The position has been advanced to new block in this method.
     */
    private void loadNextBlock() {
        try {
            this.pos.nextBlock();
            this.cachedByteBuffer = fc.map(
                    FileChannel.MapMode.READ_ONLY, this.pos.blockPos(), this.cacheSize);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Load the specific block according to pos
     * The position has been advanced to new block in this method.
     *
     * @param pos File position
     */
    private void loadBlock(long pos) {
        long oldBlock = this.pos.block();
        this.pos.seek(pos);
        if (oldBlock == this.pos.block()) return;

        if (bufferBlockCount <= this.pos.block())
            throw new RuntimeException(
                    "Requesting block " + this.pos.block() +
                            " is greater than file has (" + bufferBlockCount + ')');

        try {
            this.cachedByteBuffer = fc.map(
                    FileChannel.MapMode.READ_ONLY, this.pos.blockPos(), this.cacheSize);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void close() throws IOException {
        if (fc != null) {
            fc.close();
            fc = null;
        }
        cachedByteBuffer = null;
    }

    @Override
    public boolean isEof() {
        return this.pos.overallPos() >= this.fileSize;
    }

    @Override
    public void seek(int newPos) {
        cachedByteBuffer.position(newPos);
        this.pos.seek(newPos);
    }

    @Override
    public void seek(long newPos) {
        loadBlock(newPos);
        seek(this.pos.pos());
    }

    @Override
    public int pos() {
        return this.pos.pos();
    }

    @Override
    public long size() {
        return this.fileSize;
    }

    @Override
    public byte readS1() {
        return readBytes(1)[0];
    }

    @Override
    public short readS2be() {
        return ByteBuffer
                .wrap(readBytes(2))
                .order(ByteOrder.BIG_ENDIAN)
                .getShort();
    }

    @Override
    public int readS4be() {
        return ByteBuffer
                .wrap(readBytes(4))
                .order(ByteOrder.BIG_ENDIAN)
                .getInt();
    }

    @Override
    public long readS8be() {
        return ByteBuffer
                .wrap(readBytes(8))
                .order(ByteOrder.BIG_ENDIAN)
                .getLong();
    }

    @Override
    public short readS2le() {
        return ByteBuffer
                .wrap(readBytes(2))
                .order(ByteOrder.LITTLE_ENDIAN)
                .getShort();
    }

    @Override
    public int readS4le() {
        return ByteBuffer
                .wrap(readBytes(4))
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt();
    }

    @Override
    public long readS8le() {
        return ByteBuffer
                .wrap(readBytes(8))
                .order(ByteOrder.LITTLE_ENDIAN)
                .getLong();
    }

    @Override
    public int readU1() {
        return readS1() & 0xff;
    }

    @Override
    public int readU2be() {
        return readS2be() & 0xffff;
    }

    @Override
    public long readU4be() {
        return readS4be() & 0xffff_ffffL;
    }

    @Override
    public int readU2le() {
        return readS2le() & 0xffff;
    }

    @Override
    public long readU4le() {
        return readS4le() & 0xffff_ffffL;
    }

    @Override
    public float readF4be() {
        return ByteBuffer
                .wrap(readBytes(4))
                .order(ByteOrder.BIG_ENDIAN)
                .getFloat();
    }

    @Override
    public double readF8be() {
        return ByteBuffer
                .wrap(readBytes(8))
                .order(ByteOrder.BIG_ENDIAN)
                .getDouble();
    }

    @Override
    public float readF4le() {
        return ByteBuffer
                .wrap(readBytes(4))
                .order(ByteOrder.LITTLE_ENDIAN)
                .getFloat();
    }

    @Override
    public double readF8le() {
        return ByteBuffer
                .wrap(readBytes(8))
                .order(ByteOrder.LITTLE_ENDIAN)
                .getDouble();
    }

    @Override
    public byte[] readBytes(long n) {
        int length = toByteArrayLength(n);
        byte[] buf = new byte[length];
        readBytes(buf, 0, length);
        return buf;
    }

    private void readBytes(byte[] dst, int offset, int length) {
        checkBounds(offset, length, dst.length);
        int left = cachedByteBuffer.limit() - cachedByteBuffer.position();

        if (left > length) {
            cachedByteBuffer.get(dst, offset, length);
            this.pos.advance(length);
        } else if (left == length) {
            cachedByteBuffer.get(dst, offset, length);
            loadNextBlock();
        } else {
            cachedByteBuffer.get(dst, offset, left);
            loadNextBlock();
            readBytes(dst, offset + left, length - left);
        }
    }

    private void checkBounds(int off, int len, int size) {
        if ((off | len | (off + len) | (size - (off + len))) < 0)
            throw new IndexOutOfBoundsException();
    }

    @Override
    public byte[] readBytesFull() {
        long remaining = fileSize - this.pos.overallPos();
        if (fileSize - this.pos.overallPos() > Integer.MAX_VALUE)
            throw new RuntimeException("Requested byte array size is too large");
        return readBytes(remaining);
    }

    @Override
    public byte[] readBytesTerm(int term, boolean includeTerm, boolean consumeTerm, boolean eosError) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int count = 0;
        while (true) {
            if (!isEof()) {
                if (eosError) {
                    throw new RuntimeException("End of stream reached, but no terminator " + term + " found");
                } else {
                    return buf.toByteArray();
                }
            }

            int c = readU1();
            if (c == term) {
                if (includeTerm)
                    buf.write(c);
                if (!consumeTerm)
                    this.seek(this.pos.overallPos() - 1);
                return buf.toByteArray();
            }
            if (count + 1 == Integer.MAX_VALUE) {
                throw new RuntimeException("Reached byte array max capacity.");
            }
            count++;
            buf.write(c);
        }
    }

    static class Position {

        private long currentBlock;
        private int currentPos;
        private final int cacheSize;

        public Position(int cacheSize) {
            this.currentBlock = 0;
            this.currentPos = 0;
            this.cacheSize = cacheSize;
        }

        public long block() {
            return currentBlock;
        }

        public long blockPos() {
            return currentBlock * cacheSize;
        }

        public int pos() {
            return currentPos;
        }

        public void nextBlock() {
            this.currentBlock++;
            this.currentPos = 0;
        }

        public void advance(int length) {
            int newPos = currentPos + length;
            if (newPos >= cacheSize) {
                currentBlock++;
                currentPos = newPos - cacheSize;
            } else currentPos = newPos;
        }

        public void seek(long newPos) {
            currentBlock = newPos / cacheSize;
            currentPos = (int) (newPos % cacheSize);
        }

        public void seek(int newPos) {
            currentPos = newPos % cacheSize;
        }

        public long overallPos() {
            return blockPos() + currentPos;
        }
    }
}
