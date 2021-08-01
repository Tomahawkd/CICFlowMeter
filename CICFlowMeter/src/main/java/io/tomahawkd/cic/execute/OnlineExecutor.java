package io.tomahawkd.cic.execute;

import io.tomahawkd.cic.config.CommandlineDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import java.util.ArrayList;
import java.util.List;

@WithMode(ExecutionMode.ONLINE)
public class OnlineExecutor extends AbstractExecutor {

    private static final Logger logger = LogManager.getLogger(OnlineExecutor.class);

    public OnlineExecutor() {
        super();
    }

    @Override
    public void execute(CommandlineDelegate delegate) throws Exception {
        throw new IllegalStateException("Not Implement yet.");
    }

    private void readInterface() {
        StringBuilder errBuf = new StringBuilder();
        List<PcapIf> ifs = new ArrayList<>();
        if(Pcap.findAllDevs(ifs, errBuf)!=Pcap.OK) {
            logger.error("Error occurred: {}", errBuf.toString());
            throw new RuntimeException(errBuf.toString());
        }
    }
}
