package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;

public class Ipv4PackageDelegate extends AbstractPackageDelegate {


    public Ipv4PackageDelegate() {
        super(Ip4.ID);
    }

    @Override
    public boolean parse(PackageInfo dst, PcapPacket packet) {
        Ip4 ipv4 = new Ip4();
        if (!packet.hasHeader(ipv4)) {
            return false;
        }

        dst.addFeature(MetaFeature.SRC, ipv4.source());
        dst.addFeature(MetaFeature.DST, ipv4.destination());
        dst.addFeature(MetaFeature.IPV4, true);
        return true;
    }
}
