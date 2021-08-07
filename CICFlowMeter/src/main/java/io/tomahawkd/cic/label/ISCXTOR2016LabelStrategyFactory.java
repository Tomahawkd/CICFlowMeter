package io.tomahawkd.cic.label;

import io.tomahawkd.cic.source.LocalFile;

@LabelFactory(name = "ISCXTOR2016LabelStrategyFactory", dataset = "ISCXTor2016")
public class ISCXTOR2016LabelStrategyFactory extends LabelStrategyFactory {

    @Override
    public LabelStrategy getStrategy(LocalFile file) {
        if (file.filenameContains("browsing")) {
            return f -> "NORMAL";
        } else return LabelStrategy.NONE;
    }
}
