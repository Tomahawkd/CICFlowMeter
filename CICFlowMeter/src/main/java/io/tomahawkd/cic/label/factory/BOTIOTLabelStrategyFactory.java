package io.tomahawkd.cic.label.factory;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.label.LabelStrategy;
import io.tomahawkd.cic.source.LocalFile;

@LabelFactory(name = "BOTIOTLabelStrategyFactory", dataset = "BOT-IOT")
public class BOTIOTLabelStrategyFactory extends LabelStrategyFactory {

    @Override
    public LabelStrategy getStrategy(LocalFile file) {
        if (file.filenameContains("IoT_Dataset_HTTP_")) {
            return f -> {
                if (f.connectBetween("192.168.100.150", Flow.PORT_ANY, "192.168.100.6", 80) ||
                        f.connectBetween("192.168.100.149", Flow.PORT_ANY, "192.168.100.5", 80) ||
                        f.connectBetween("192.168.100.148", Flow.PORT_ANY, "192.168.100.3", 80) ||
                        f.connectBetween("192.168.100.147", Flow.PORT_ANY, "192.168.100.3", 80)) {
                    return "DOS";
                } else return "NORMAL";
            };
        }

        return LabelStrategy.NONE;
    }
}
