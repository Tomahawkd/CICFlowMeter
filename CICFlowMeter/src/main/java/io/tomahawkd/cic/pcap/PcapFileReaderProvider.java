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

    public PcapFileReader newReader(Path file) throws IOException {
        CommandlineDelegate delegate = ConfigManager.get().getDelegateByType(CommandlineDelegate.class);
        if (delegate != null && delegate.useOldParser()) {
            return new JnetpcapReader(file);
        }

        FileChannel fc = FileChannel.open(file, StandardOpenOption.READ);
        byte[] magicNumber = new byte[4];
        fc.read(ByteBuffer.wrap(magicNumber));
        fc.close();
        switch (PcapMagicNumber.getTypeBySignature(magicNumber)) {
            case PCAP: return Pcap.fromFile(file);
            case PCAPNG: return Pcapng.fromFile(file);
            case UNKNOWN: break;
        }

        return new JnetpcapReader(file);
    }
}
