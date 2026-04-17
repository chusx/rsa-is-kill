"""
as2_epcis_exchange.py

DSCSA / EU FMD trading-partner exchange: manufacturer → distributor
EPCIS event via AS2 (RFC 4130) with S/MIME-RSA sign+encrypt, and
dispenser → NMVS decommission via TLS mutual auth.

Runs inside serialization platforms (Tracelink, SAP ATTP, Systech),
wholesaler IT (McKesson, Cardinal, AmerisourceBergen), national
NMVO hubs, and FDA-ESG submission adapters.
"""
from __future__ import annotations

import hashlib
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from pyas2lib import Message, Partner, Organization

# ----- AS2 partnership registry (real deployments load from DB) -----

ORG = Organization(
    as2_name="PFIZER-MANUF",
    sign_key=Path("/secrets/pfizer-as2-rsa4096.p12").read_bytes(),
    sign_key_pass=b"",
)

MCKESSON = Partner(
    as2_name="MCKESSON-DIST",
    verify_cert=Path("/certs/mckesson-as2.crt").read_bytes(),
    encrypt_cert=Path("/certs/mckesson-as2.crt").read_bytes(),
    compress=True,
    sign=True,
    encrypt=True,
    mdn_mode="SYNC",
    mdn_sign="sha256",
)


# ----- EPCIS event construction + XMLDSig countersignature ------

def build_epcis_shipment(gtin: str, serials: list[str],
                          ship_to_gln: str, biz_tx: str) -> bytes:
    """Build EPCIS 2.0 ObjectEvent for a pharma shipment."""
    ev = ET.Element(
        "{urn:epcglobal:epcis:xsd:2}EPCISDocument",
        attrib={"schemaVersion": "2.0",
                "creationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ")}
    )
    body = ET.SubElement(ev, "EPCISBody")
    el = ET.SubElement(body, "EventList")
    oe = ET.SubElement(el, "ObjectEvent")
    ET.SubElement(oe, "eventTime").text = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    epcs = ET.SubElement(oe, "epcList")
    for sn in serials:
        ET.SubElement(epcs, "epc").text = f"urn:epc:id:sgtin:0614141.{gtin}.{sn}"
    ET.SubElement(oe, "action").text = "OBSERVE"
    ET.SubElement(oe, "bizStep").text = "urn:epcglobal:cbv:bizstep:shipping"
    ET.SubElement(oe, "disposition").text = "urn:epcglobal:cbv:disp:in_transit"
    bt = ET.SubElement(oe, "bizTransactionList")
    ET.SubElement(bt, "bizTransaction",
                  attrib={"type": "urn:epcglobal:cbv:btt:po"}).text = biz_tx
    return ET.tostring(ev, xml_declaration=True, encoding="utf-8")


def xmldsig_countersign(xml_bytes: bytes, pkcs12_path: str) -> bytes:
    """Add a detached XMLDSig-RSA-SHA256 signature over the EPCIS
    document.  Recalled-product investigations rely on the per-event
    signature, not just the AS2 wrapper."""
    with open(pkcs12_path, "rb") as f:
        priv, cert, _ = pkcs12.load_key_and_certificates(f.read(), password=b"")
    sig = priv.sign(
        xml_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return xml_bytes + b"\n<!-- RSA-SHA256 sig: " + sig.hex().encode() + b" -->"


# ----- AS2 send to trading partner -----

def send_as2(payload: bytes, to: Partner) -> dict:
    msg = Message(sender=ORG, receiver=to)
    msg.build(payload, content_type="application/xml",
              filename="epcis-shipment.xml",
              subject="DSCSA ObjectEvent — PO 4500127734")
    # msg.payload is now multipart/signed (S/MIME CMS SignedData,
    # RSA-SHA256 over the EPCIS doc) inside an encrypted AS2 envelope
    resp = requests.post(
        to.url,
        data=msg.payload.as_bytes(),
        headers=msg.headers,
        timeout=60,
    )
    resp.raise_for_status()
    mdn = Message.parse_mdn(resp.content, resp.headers)
    mdn.verify(to)   # RSA verify the signed MDN (receipt) from partner
    return {"mdn_status": mdn.status, "received_at": time.time()}


# ----- NMVS dispenser decommission (EU FMD) -----

def nmvs_decommission(product_code: str, serial: str, batch: str,
                       expiry: str, nmvs_url: str,
                       client_p12: str) -> dict:
    """Pharmacy checkout-time pack verify + decommission."""
    ctx = ssl.create_default_context()
    ctx.load_cert_chain(client_p12, password="")   # RSA-2048 pharmacy cert
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    body = {
        "productCode": product_code,
        "serialNumber": serial,
        "batch": batch,
        "expiryDate": expiry,
        "transactionState": "DISPENSED",
        "txGUID": hashlib.sha1(serial.encode()).hexdigest(),
    }
    # The EMVO hub responds with a signed JSON token; every dispenser
    # validates the signature against the NMVO CA pinned at go-live.
    r = requests.post(f"{nmvs_url}/packs/verify",
                      json=body, verify="/certs/nmvo-root.pem",
                      cert=("/certs/pharmacy.crt", "/certs/pharmacy.key"),
                      timeout=5)
    r.raise_for_status()
    return r.json()


if __name__ == "__main__":
    xml = build_epcis_shipment(
        gtin="00312345000010",
        serials=[f"SN{i:010d}" for i in range(100)],
        ship_to_gln="0860001234567",
        biz_tx="urn:epcglobal:cbv:bt:0614141073467:PO-45001277",
    )
    signed = xmldsig_countersign(xml, "/secrets/pfizer-as2-rsa4096.p12")
    r = send_as2(signed, MCKESSON)
    print("AS2 MDN:", r)

#
# ---- Breakage ----
#
# A factoring attack against:
#
# - The NMVO / NMVS CA: attacker mints pharmacy dispenser certs and
#   issues decommission-OK responses for counterfeit packs, OR mints
#   a forged hub cert and MITM's the dispenser-to-hub TLS — in either
#   case the scanner at the pharmacy counter gives a green "verified,
#   decommissioned" indicator for forged medicine.
#
# - Pfizer / Merck / Novartis AS2 keys: attacker injects forged EPCIS
#   events into McKesson / Cardinal Health / AmerisourceBergen ERP
#   chains-of-custody. Recall investigations and DEA ARCOS reporting
#   depend on these events as evidence; falsification lasts for the
#   retention window (6–10 years).
#
# - Serialization-platform vendor RSA root (Tracelink, SAP ATTP):
#   cross-manufacturer compromise; one forged key signs events
#   claiming to originate from any of 100+ pharma manufacturer
#   tenants hosted on the platform.
