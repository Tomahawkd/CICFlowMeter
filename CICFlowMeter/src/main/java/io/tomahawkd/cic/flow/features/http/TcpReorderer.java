package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

public class TcpReorderer {

    private static final Logger logger = LogManager.getLogger(TcpReorderer.class);

    private boolean inited = false;
    private long currentSeq = 0;
    private long nextExpectedSeq = 0;

    private final Map<Long, PacketInfo> futurePackets = new HashMap<>();

    private final TcpReassembler reassembler;

    public TcpReorderer(Consumer<PacketInfo> releaseListener) {
        this.reassembler = new TcpReassembler(releaseListener);
    }

    public void addPacket(PacketInfo info) {
        if (!inited) {
            inited = true;
            currentSeq = info.seq();

            if (info.getFlag(PacketInfo.FLAG_SYN)) {
                nextExpectedSeq = currentSeq + 1;
                logger.debug("Initialized Connection with Packet [{}]", info);
            } else {
                nextExpectedSeq = currentSeq + info.getPayloadBytes();
                logger.warn("Initialized flow without SYN flag using packet [{}].", info);
                reassembler.addPacket(info);
            }
            return;
        }

        // this is the last packet
        if (info.getFlag(PacketInfo.FLAG_RST)) {
            finalizeFlow();
            return;
        } else if (info.getFlag(PacketInfo.FLAG_FIN)) {
            if (info.getPayloadBytes() == 0) {
                currentSeq = nextExpectedSeq;
                nextExpectedSeq = nextExpectedSeq + 1;
                return;
            }
        }

        if (info.getPayloadBytes() == 0) {
            return;
        }

        if (info.seq() == nextExpectedSeq) {
            // push all expected seq packet to the assembler
            parseAndAdvanceSeq(info);
            // remove out-dated data
            futurePackets.entrySet().removeIf(entry -> entry.getKey() < currentSeq);

        } else if (info.seq() > nextExpectedSeq) {
            futurePackets.put(info.seq(), info);
        } else {
            if (info.seq() == currentSeq) {
                // TODO: retransmission count
                logger.debug("Got retransmission packet [{}], expecting {}", info, nextExpectedSeq);
            } else if (info.seq() == nextExpectedSeq - 1) {
                // Keep-Alive packet
                // https://datatracker.ietf.org/doc/html/rfc1122#page-102
                logger.debug("Received Keep-Alive packet [{}]", info);
            } else {
                logger.warn("Received a packet [{}] with seq {} less than expect {}", info, info.seq(), nextExpectedSeq);
            }
        }
    }

    private void parseAndAdvanceSeq(PacketInfo info) {
        PacketInfo temp = info;
        do {
            // push to assembler
            reassembler.addPacket(temp);

            // advance seq
            currentSeq = nextExpectedSeq;
            nextExpectedSeq += temp.getPayloadBytes();
        } while ((temp = futurePackets.remove(nextExpectedSeq)) != null);
    }

    public void finalizeFlow() {
        while (!futurePackets.isEmpty()) {
            reassembler.forceParse();
            Optional<Long> seqOpt = futurePackets.keySet().stream().min(Comparator.comparingLong(a -> a));
            if (!seqOpt.isPresent()) break;
            currentSeq = seqOpt.get();
            PacketInfo temp = futurePackets.remove(currentSeq);
            nextExpectedSeq = currentSeq + temp.getPayloadBytes();
            parseAndAdvanceSeq(temp);
        }

        reassembler.forceParse();
    }
}
