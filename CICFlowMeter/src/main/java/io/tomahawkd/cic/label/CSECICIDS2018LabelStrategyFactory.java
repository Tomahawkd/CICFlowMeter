package io.tomahawkd.cic.label;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.source.LocalFile;

@LabelFactory(name = "CSECICIDS2018LabelStrategyFactory", dataset = "CSE-CICIDS2018")
public class CSECICIDS2018LabelStrategyFactory extends LabelStrategyFactory {

    @Override
    public LabelStrategy getStrategy(LocalFile file) {
        if (file.filenameContains("Friday-16-02-2018-UCAP172.31.69.25")) {
            return f -> {
                if (f.connectBetween("13.59.126.31", Flow.PORT_ANY, "172.31.69.25", 21) ||
                    f.connectBetween("18.219.193.20", Flow.PORT_ANY, "172.31.69.25", 80)) {
                    return "SLOWDOS";
                } else return "NORMAL";
            };
        } else if (file.filenameContains("Thursday-15-02-2018-UCAP172.31.69.25")) {
            return f -> {
                if (f.connectBetween("18.219.211.138", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("18.217.165.70", Flow.PORT_ANY, "172.31.69.25", 80)) {
                    return "SLOWDOS";
                } else return "NORMAL";
            };
        } else if (file.filenameContains("Tuesday-20-02-2018-UCAP172.31.69.25")) {
            return f -> {
                if (f.connectBetween("18.218.115.60", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("18.219.9.1", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("18.219.32.43", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("18.218.55.126", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("52.14.136.135", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("18.219.5.43", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("18.216.200.189", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("18.218.229.235", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("18.218.11.51", Flow.PORT_ANY, "172.31.69.25", 80) ||
                        f.connectBetween("18.216.24.42", Flow.PORT_ANY, "172.31.69.25", 80)) {
                    return "DOS";
                } else return "NORMAL";
            };
        } else if (file.filenameContains("Wednesday-21-02-2018-UCAP172.31.69.28")) {
            return f -> {
                if (f.connectBetween("18.218.115.60", Flow.PORT_ANY, "172.31.69.28", 80) ||
                        f.connectBetween("18.219.9.1", Flow.PORT_ANY, "172.31.69.28", 80) ||
                        f.connectBetween("18.219.32.43", Flow.PORT_ANY, "172.31.69.28", 80) ||
                        f.connectBetween("18.218.55.126", Flow.PORT_ANY, "172.31.69.28", 80) ||
                        f.connectBetween("52.14.136.135", Flow.PORT_ANY, "172.31.69.28", 80) ||
                        f.connectBetween("18.219.5.43", Flow.PORT_ANY, "172.31.69.28", 80) ||
                        f.connectBetween("18.216.200.189", Flow.PORT_ANY, "172.31.69.28", 80) ||
                        f.connectBetween("18.218.229.235", Flow.PORT_ANY, "172.31.69.28", 80) ||
                        f.connectBetween("18.218.11.51", Flow.PORT_ANY, "172.31.69.28", 80) ||
                        f.connectBetween("18.216.24.42", Flow.PORT_ANY, "172.31.69.28", 80)) {
                    return "DOS";
                } else return "NORMAL";
            };
        }

        return LabelStrategy.NONE;
    }
}
