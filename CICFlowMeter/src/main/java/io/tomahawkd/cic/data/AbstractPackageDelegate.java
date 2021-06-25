package io.tomahawkd.cic.data;

public abstract class AbstractPackageDelegate implements PackageDelegate {

    private final int id;

    public AbstractPackageDelegate(int id) {
        this.id = id;
    }

}
