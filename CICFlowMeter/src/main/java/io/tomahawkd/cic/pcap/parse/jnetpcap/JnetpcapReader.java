package io.tomahawkd.cic.pcap.parse.jnetpcap;

import io.tomahawkd.cic.pcap.parse.AbstractPcapFileReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;

import java.nio.file.Path;

public class JnetpcapReader extends AbstractPcapFileReader {

    private static final Logger logger = LogManager.getLogger(JnetpcapReader.class);
    private final Pcap pcapReader;
    private PcapHeader hdr;
    private JBuffer buf;
    private boolean hasNext;

    public JnetpcapReader(Path file) {
        super(file);
        String filename = file.toAbsolutePath().toString();
        logger.debug("Read file {} with reader.", filename);
        StringBuilder errBuf = new StringBuilder(); // For any error msgs
        pcapReader = Pcap.openOffline(filename, errBuf);

        if (pcapReader == null) {
            logger.error("Error while opening file for capture: " + errBuf);
            System.exit(-1);
        } else {
            hdr = new PcapHeader(JMemory.POINTER);
            buf = new JBuffer(JMemory.POINTER);
            hasNext = true;
        }
    }

    public PcapPacketAdapter next() {
        try {
            int status;
            if ((status = pcapReader.nextEx(hdr, buf)) == Pcap.NEXT_EX_OK) {
                PcapPacket packet = new PcapPacket(hdr, buf);
                return new PcapPacketAdapter(packet);
            } else if (status == Pcap.NEXT_EX_EOF) {
                logger.info("Reach the EOF of the file {}", file);
                hasNext = false;
                return null;
            } else {
                logger.error("Unexpected Exception while reading pcap file {}", file);
                throw new IllegalStateException("Unexpected Exception");
            }
        } catch (PcapClosedException e) {
            throw e;
        } catch (IllegalStateException e) {
            return null;
        }
    }

    // the EOF is triggered by Pcap.NEXT_EX_EOF
    public boolean hasNext() {
        return hasNext;
    }
}
