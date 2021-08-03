package io.tomahawkd.cic.source;

public class LocalFiles {

    public static boolean exists(LocalFile file) {
        return file.exists();
    }

    public static boolean filenameContains(LocalFile file, CharSequence seq) {
        return file.filenameContains(seq);
    }
}
