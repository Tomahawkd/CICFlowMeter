package io.tomahawkd.cic.pcap;

import io.tomahawkd.cic.pcap.parse.PcapFileReader;
import io.tomahawkd.cic.pcap.parse.pcap.Pcap;
import io.tomahawkd.cic.pcap.parse.pcapng.Pcapng;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public enum PcapFileReaderProvider {

    INSTANCE;

    public PcapFileReader newReader(Path file) throws IOException {
        FileChannel fc = FileChannel.open(file, StandardOpenOption.READ);
        byte[] magicNumber = new byte[4];
        fc.read(ByteBuffer.wrap(magicNumber));
        fc.close();
        switch (PcapMagicNumber.getTypeBySignature(magicNumber)) {
            case PCAP: return Pcap.fromFile(file);
            case PCAPNG: return Pcapng.fromFile(file);
            case UNKNOWN: break;
        }

        throw new IllegalArgumentException("Type not found");
    }
}
