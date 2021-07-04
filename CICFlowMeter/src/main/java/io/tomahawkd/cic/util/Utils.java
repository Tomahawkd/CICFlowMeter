package io.tomahawkd.cic.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class Utils {
    protected static final Logger logger = LogManager.getLogger(Utils.class);
    public static final String LINE_SEP = System.lineSeparator();
    public final static String PCAP = "application/vnd.tcpdump.pcap";
    public static final String FLOW_SUFFIX = "_Flow.csv";

    public static long countLines(Path fileName) {
        File file = fileName.toFile();
        int linenumber = 0;
        FileReader fr;
        LineNumberReader lnr = null;
        try {
            fr = new FileReader(file);
            lnr = new LineNumberReader(fr);

            while (lnr.readLine() != null) {
                linenumber++;
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {

            if (lnr != null) {
                try {
                    lnr.close();
                } catch (IOException e) {
                    logger.debug(e.getMessage());
                }
            }
        }
        return linenumber;
    }

    public static void insertToFile(String header, List<String> rows, Path path) {
        if (path == null || rows == null || rows.size() <= 0) {
            String ex = String.format("path=%s", path);
            throw new IllegalArgumentException(ex);
        }

        FileOutputStream output = null;
        try {
            if (Files.exists(path)) {
                output = new FileOutputStream(path.toFile(), true);
            } else {
                Files.createFile(path);
                output = new FileOutputStream(path.toFile());
                if (header != null) {
                    output.write((header + LINE_SEP).getBytes());
                }
            }
            for (String row : rows) {
                output.write((row + LINE_SEP).getBytes());
            }
        } catch (IOException e) {
            logger.warn(e);
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.warn(e);
            }
        }
    }
}
