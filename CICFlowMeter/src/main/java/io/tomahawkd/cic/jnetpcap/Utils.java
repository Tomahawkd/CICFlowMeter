package io.tomahawkd.cic.jnetpcap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.List;

public class Utils {
    protected static final Logger logger = LogManager.getLogger(Utils.class);
    public static final String FILE_SEP = System.getProperty("file.separator");
    public static final String LINE_SEP = System.lineSeparator();
    public final static String PCAP = "application/vnd.tcpdump.pcap";
    public static final String FLOW_SUFFIX = "_Flow.csv";

    public static long countLines(String fileName) {
        File file = new File(fileName);
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

    public static void insertToFile(String header, List<String> rows, String savepath, String filename) {
        if (savepath == null || filename == null || rows == null || rows.size() <= 0) {
            String ex = String.format("savepath=%s,filename=%s", savepath, filename);
            throw new IllegalArgumentException(ex);
        }

        File fileSavPath = new File(savepath);
        if (!fileSavPath.exists()) {
            fileSavPath.mkdirs();
        }


        if (!savepath.endsWith(FILE_SEP)) {
            savepath += FILE_SEP;
        }

        File file = new File(savepath + filename);
        FileOutputStream output = null;

        try {
            if (file.exists()) {
                output = new FileOutputStream(file, true);
            } else {
                if (file.createNewFile()) output = new FileOutputStream(file);
                else throw new IOException("File " + file + " create failed.");

                if (header != null) {
                    output.write((header + LINE_SEP).getBytes());
                }
            }
            for (String row : rows) {
                output.write((row + LINE_SEP).getBytes());
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
    }
}
