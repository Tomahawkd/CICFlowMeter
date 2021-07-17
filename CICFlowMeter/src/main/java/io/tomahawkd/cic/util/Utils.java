package io.tomahawkd.cic.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

public class Utils {
    protected static final Logger logger = LogManager.getLogger(Utils.class);
    public static final String LINE_SEP = System.lineSeparator();
    public final static String PCAP = "application/vnd.tcpdump.pcap";
    public static final String FLOW_SUFFIX = "_Flow.csv";

    public static long countLines(Path fileName) {
        File file = fileName.toFile();
        int linenumber = 0;
        try (LineNumberReader lnr = new LineNumberReader(new FileReader(file))) {
            while (lnr.readLine() != null) {
                linenumber++;
            }

        } catch (IOException e) {
            logger.warn(e.getMessage());
        }
        return linenumber;
    }

    public static void initFile(Path path, String header) throws IOException {
        if (Files.exists(path)) return;
        Files.createFile(path);
        try (FileOutputStream output = new FileOutputStream(path.toFile())) {
            output.write((header + LINE_SEP).getBytes());
        }
    }

    public static void insertToFile(String line, Path path) {
        if (path == null || line == null) {
            String ex = String.format("path=%s", path);
            throw new IllegalArgumentException(ex);
        }

        try (FileOutputStream output = new FileOutputStream(path.toFile(), true)) {
            output.write((line + LINE_SEP).getBytes());
        } catch (IOException e) {
            logger.warn(e);
        }
    }

    public static String convertToString(Object data) {
        Class<?> type = data.getClass();
        StringBuilder builder = new StringBuilder();
        if (type.isArray()) {
            return Arrays.toString((Object[]) data);
        } else if (data instanceof Map) {
            builder.append("{");
            ((Map<?, ?>) data).forEach((k, v) -> builder.append(k).append(": ").append(v).append(", "));
            builder.append("}");
        } else if (data instanceof Collection) {
            builder.append("[");
            ((Collection<?>) data).forEach(v -> builder.append(v).append(", "));
            builder.append("]");
        } else {
            return data.toString();
        }

        return builder.toString();
    }
}
