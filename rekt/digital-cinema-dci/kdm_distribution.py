"""
kdm_distribution.py

DCI (Digital Cinema Initiatives) Key Delivery Message distribution
pipeline. Studios (Disney, Universal, Warner, Sony, Paramount) emit a
per-screen, per-show-window KDM targeting a specific projector's media
block; the studio-side signing + RSA-OAEP key wrap is in `dcdm_kdm_rsa.py`.
This file is the distribution glue: target cert lookup, per-cinema
batch generation, and SMPTE ST 430-1 delivery envelope.
"""

import os
import datetime
from typing import Iterable


# ---- Target projector catalogue ----
#
# Every DCI-compliant media block (Dolby IMS3000, GDC SR-1000, Barco ICMP-X,
# Christie IMB-S4, Qube Xi) ships with a unique RSA-2048 "CPI SM" cert
# minted by the manufacturer's DCI roots (Dolby CPI Root CA etc).
# Studios cache these certs in a Trusted Device List (TDL) curated by
# the distributor (Deluxe, Eclair, Motion Picture Solutions).
class ProjectorCert:
    def __init__(self, theatre: str, screen: int, cert_pem: str,
                 serial: str, manufacturer: str):
        self.theatre       = theatre
        self.screen        = screen
        self.cert_pem      = cert_pem            # RSA-2048 leaf
        self.serial        = serial              # SMPTE 430-2 identity
        self.manufacturer  = manufacturer

TDL: list[ProjectorCert] = _load_tdl("/srv/dci/tdl/latest.xml")  # stub


# ---- Studio side: generate per-screen KDMs for a booking ----

def generate_kdms_for_booking(cpl_uuid: str,          # ComposedPlaylist UUID
                               content_key: bytes,    # AES-128 essence key
                               theatres: Iterable[str],
                               window_start: datetime.datetime,
                               window_end:   datetime.datetime,
                               out_dir: str):
    """
    One RSA-OAEP-wrapped KDM per screen per show window.  A nationwide
    wide-release of a tentpole film emits ~40,000 KDMs (roughly one per
    DCI screen in North America).
    """
    from dcdm_kdm_rsa import sign_and_wrap_kdm   # RSA primitives

    os.makedirs(out_dir, exist_ok=True)
    for pc in TDL:
        if pc.theatre not in theatres:
            continue
        kdm_xml = sign_and_wrap_kdm(
            cpl_uuid        = cpl_uuid,
            content_key     = content_key,
            target_cert_pem = pc.cert_pem,
            not_valid_before = window_start,
            not_valid_after  = window_end,
            # ForensicMark flags encode the studio's per-show watermark
            # policy; carried inside the signed KDM body.
            forensic_mark_flags = 0x0000000000000003,
        )
        fname = f"KDM_{cpl_uuid}_{pc.theatre}_S{pc.screen:02d}.xml"
        with open(os.path.join(out_dir, fname), "w") as f:
            f.write(kdm_xml)


# ---- Distributor side: package + deliver ----
#
# The distributor batches KDMs per cinema, drops them on an SFTP
# endpoint that the on-site Theatre Management System (Arts Alliance
# ADX, GDC TMS-2000, Dolby TMS) polls every few minutes during the
# booking lead-up.
def publish_to_cinema(kdm_dir: str, cinema_sftp_root: str):
    import paramiko
    t = paramiko.Transport((cinema_sftp_root, 22))
    t.connect(username="distributor",
              key_filename="/secrets/dci_distributor_ed25519")
    sftp = paramiko.SFTPClient.from_transport(t)
    for fn in os.listdir(kdm_dir):
        sftp.put(os.path.join(kdm_dir, fn), f"incoming/{fn}")
    sftp.close(); t.close()


def _load_tdl(path: str) -> list[ProjectorCert]: ...


# If RSA is broken, an attacker can (a) forge studio KDMs and silently
# unlock essence keys for any DCP they have physical access to, enabling
# pre-release piracy at theatrical scale; (b) forge projector identity
# certs and enroll "phantom screens" into a studio's distribution list,
# siphoning every KDM studios emit for that theatre chain. The piracy
# window on a wide release at DCI scale is measured in billions of USD
# per breach.
