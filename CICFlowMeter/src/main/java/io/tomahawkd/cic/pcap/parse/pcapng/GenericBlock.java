package io.tomahawkd.cic.pcap.parse.pcapng;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStream;
import io.kaitai.struct.KaitaiStruct;

// Block structure:
//                         1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 0 |                          Block Type                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 4 |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 8 /                          Block Body                           /
//   /              variable length, padded to 32 bits               /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
public abstract class GenericBlock extends KaitaiStruct {

    private final Pcapng parent;

    private final BlockType type;

    private final long length;

    // the type is read before the block is created
    public GenericBlock(KaitaiStream _io, Pcapng parent, BlockType type) {
        super(_io);
        this.parent = parent;
        this.type = type;
        this.length = this._io.readU4le();
        readBody(new ByteBufferKaitaiStream(this._io.readBytes(length - 8 - 4)));
        long length = this._io.readU4le();
        if (length != this.length) {
            throw new KaitaiStream.ValidationNotEqualError(length, this.length, _io(), "/types/header/seq/0");
        }
    }

    public GenericBlock(EndianDeclaredKaitaiStream _io, Pcapng parent, BlockType type) {
        super(_io);
        this.parent = parent;
        this.type = type;
        this.length = this._io.readU4le();
        readBody(new EndianDeclaredKaitaiStream(
                new ByteBufferKaitaiStream(this._io.readBytes(length - 8 - 4)), _io.getOrder()));
        long length = this._io.readU4le();
        if (length != this.length) {
            throw new KaitaiStream.ValidationNotEqualError(length, this.length, _io(), "/types/header/seq/0");
        }
    }

    public abstract void readBody(KaitaiStream stream);

    public Pcapng parent() {
        return parent;
    }

    public BlockType getType() {
        return type;
    }

    public long getLength() {
        return length;
    }
}
