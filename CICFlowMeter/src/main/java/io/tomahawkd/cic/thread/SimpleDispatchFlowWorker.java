package io.tomahawkd.cic.thread;

import io.tomahawkd.cic.flow.FlowGenerator;
import io.tomahawkd.cic.packet.PacketInfo;

import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicBoolean;

public class SimpleDispatchFlowWorker implements DispatchFlowWorker {

    private final FlowGenerator flowGenerator;
    private final AtomicBoolean working;

    private final Deque<PacketInfo> queue;

    public SimpleDispatchFlowWorker(FlowGenerator flowGenerator) {
        this.flowGenerator = flowGenerator;
        this.working = new AtomicBoolean(false);
        this.queue = new ConcurrentLinkedDeque<>();
    }

    @Override
    public boolean containsFlow(PacketInfo info) {
        synchronized (flowGenerator) {
            return flowGenerator.containsFlow(info);
        }
    }

    @Override
    public void accept(PacketInfo info) {
        if (!this.working.get()) return;
        queue.add(info);
    }

    @Override
    public long getWorkload() {
        return queue.size();
    }

    @Override
    public long getFlowCount() {
        synchronized (flowGenerator) {
            return flowGenerator.getFlowCount();
        }
    }

    @Override
    public void run() {
        this.working.set(true);

        while (true) {
            if (!queue.isEmpty()) {
                synchronized (this.flowGenerator) {
                    flowGenerator.addPacket(queue.pop());
                }
            }

            synchronized (this.working) {
                if (!this.working.get()) break;
            }
        }

        while (!queue.isEmpty()) {
            synchronized (this.flowGenerator) {
                flowGenerator.addPacket(queue.pop());
            }
        }

        synchronized (this.flowGenerator) {
            flowGenerator.dumpLabeledCurrentFlow();
        }
    }

    @Override
    public void close() {
        synchronized (this.working) {
            this.working.set(false);
        }
    }

    @Override
    public void forceClose() {
        this.queue.clear();
        close();
    }
}
