package io.tomahawkd.cic.pcap;

import io.tomahawkd.cic.config.CommandlineDelegate;
import io.tomahawkd.cic.pcap.parse.PcapFileReader;
import io.tomahawkd.cic.pcap.parse.jnetpcap.JnetpcapReader;
import io.tomahawkd.cic.pcap.parse.pcap.Pcap;
import io.tomahawkd.cic.pcap.parse.pcapng.Pcapng;
import io.tomahawkd.config.ConfigManager;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public enum PcapFileReaderProvider {

    INSTANCE;

    private PcapMagicNumber getMagicNumberFromFile(Path file) throws IOException {
        FileChannel fc = FileChannel.open(file, StandardOpenOption.READ);
        byte[] magicNumber = new byte[4];
        fc.read(ByteBuffer.wrap(magicNumber));
        fc.close();

        return PcapMagicNumber.getTypeBySignature(magicNumber);
    }

    public boolean isPcapFile(Path file) throws IOException {
        PcapMagicNumber sign = getMagicNumberFromFile(file);
        return sign == PcapMagicNumber.PCAP || sign == PcapMagicNumber.PCAPNG;
    }

    public PcapFileReader newReader(Path file) throws IOException {
        CommandlineDelegate delegate = ConfigManager.get().getDelegateByType(CommandlineDelegate.class);
        if (delegate != null && delegate.useOldParser()) {
            return new JnetpcapReader(file);
        }

        switch (getMagicNumberFromFile(file)) {
            case PCAP: return Pcap.fromFile(file);
            case PCAPNG: return Pcapng.fromFile(file);
            default: return new JnetpcapReader(file);
        }
    }
}
