package io.tomahawkd.cic.pcap.parse.pcapng;

import io.kaitai.struct.KaitaiStream;

import java.io.IOException;
import java.nio.ByteOrder;

public class EndianDeclaredKaitaiStream extends KaitaiStream {

    private final KaitaiStream stream;
    private ByteOrder order;

    public EndianDeclaredKaitaiStream(KaitaiStream stream, ByteOrder order) {
        this.stream = stream;
        this.order = order;
    }

    @Override
    public void close() throws IOException {
        stream.close();
    }

    public void setOrder(ByteOrder order) {
        this.order = order;
    }

    public ByteOrder getOrder() {
        return order;
    }

    @Override
    public boolean isEof() {
        return stream.isEof();
    }

    @Override
    public void seek(int newPos) {
        stream.seek(newPos);
    }

    @Override
    public void seek(long newPos) {
        stream.seek(newPos);
    }

    @Override
    public int pos() {
        return stream.pos();
    }

    @Override
    public long size() {
        return stream.size();
    }

    @Override
    public byte readS1() {
        return stream.readS1();
    }

    public short readS2() {
        if (order == ByteOrder.BIG_ENDIAN) return stream.readS2be();
        else return stream.readS2le();
    }

    public int readS4() {
        if (order == ByteOrder.BIG_ENDIAN) return stream.readS4be();
        else return stream.readS4le();
    }

    public long readS8() {
        if (order == ByteOrder.BIG_ENDIAN) return stream.readS8be();
        else return stream.readS8le();
    }

    @Override
    public int readU1() {
        return stream.readU1();
    }

    public int readU2() {
        if (order == ByteOrder.BIG_ENDIAN) return stream.readU2be();
        else return stream.readU2le();
    }

    public long readU4() {
        if (order == ByteOrder.BIG_ENDIAN) return stream.readU4be();
        else return stream.readU4le();
    }

    public float readF4() {
        if (order == ByteOrder.BIG_ENDIAN) return stream.readF4be();
        else return stream.readF4le();
    }

    public double readF8() {
        if (order == ByteOrder.BIG_ENDIAN) return stream.readF8be();
        else return stream.readF8le();
    }

    @Override
    public short readS2be() {
        return readS2();
    }

    @Override
    public int readS4be() {
        return readS4();
    }

    @Override
    public long readS8be() {
        return readS8();
    }

    @Override
    public short readS2le() {
        return readS2();
    }

    @Override
    public int readS4le() {
        return readS4();
    }

    @Override
    public long readS8le() {
        return readS8();
    }

    @Override
    public int readU2be() {
        return readU2();
    }

    @Override
    public long readU4be() {
        return readU4();
    }

    @Override
    public int readU2le() {
        return readU2();
    }

    @Override
    public long readU4le() {
        return readU4();
    }

    @Override
    public float readF4be() {
        return readF4();
    }

    @Override
    public double readF8be() {
        return readF8();
    }

    @Override
    public float readF4le() {
        return readF4();
    }

    @Override
    public double readF8le() {
        return readF8();
    }

    @Override
    public byte[] readBytes(long n) {
        return stream.readBytes(n);
    }

    @Override
    public byte[] readBytesFull() {
        return stream.readBytesFull();
    }

    @Override
    public byte[] readBytesTerm(int term, boolean includeTerm, boolean consumeTerm, boolean eosError) {
        return stream.readBytesTerm(term, includeTerm, consumeTerm, eosError);
    }
}
