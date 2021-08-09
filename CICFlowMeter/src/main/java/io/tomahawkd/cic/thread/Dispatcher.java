package io.tomahawkd.cic.thread;

public interface Dispatcher {

    void start();

    void stop();

    void forceStop();

    boolean running();
}
