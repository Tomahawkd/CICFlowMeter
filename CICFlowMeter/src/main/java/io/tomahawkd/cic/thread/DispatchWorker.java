package io.tomahawkd.cic.thread;

import io.tomahawkd.cic.packet.PacketInfo;

public interface DispatchWorker extends Runnable {

    boolean containsFlow(PacketInfo info);

    void accept(PacketInfo info);

    long getWorkload();

    long getFlowCount();

    void run();

    void close();

    void forceClose();
}
