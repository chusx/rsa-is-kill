"""
pacs_store_scu.py

DICOM Storage SCU that pushes signed radiology studies from a modality
(CT, MRI, PET, DR, mammography) to the hospital PACS, plus a verifier
that re-checks the Digital Signature Sequence (0400,0500) at the PACS
side before long-term archival.

Deployment: every modern enterprise PACS (GE Centricity / Universal
Viewer, Siemens syngo.via, Philips IntelliSpace, Sectra IDS7, Agfa
IMPAX, Hyland Acuo, DCM4CHEE). The RSA primitives used to emit and
verify the embedded DICOM Digital Signatures live alongside this file
in `dcmtk_rsa_signature_profile.cc`.
"""

import os
from pydicom import dcmread, Dataset
from pynetdicom import AE, evt, StoragePresentationContexts
from pynetdicom.sop_class import CTImageStorage, MRImageStorage


# ---- 1. Modality side: C-STORE SCU ----
#
# Every study emitted by the CT scanner is signed on the console
# workstation under the hospital's Tier-1 signing CA (Base RSA Digital
# Signature Profile, DICOM PS3.15 Annex C). The device cert is minted
# against the IHE ATNA + Audit Trail roots.

def push_study_to_pacs(study_dir: str,
                        pacs_host: str = "pacs.hospital.internal",
                        pacs_port: int = 11112,
                        calling_ae: str = "CT-SCANNER-04",
                        called_ae:  str = "ENT-PACS"):
    ae = AE(ae_title=calling_ae)
    ae.requested_contexts = StoragePresentationContexts

    # Associate over TLS (ATNA Secure Node profile). The TLS channel is
    # itself RSA-authenticated (see `dcmtk_rsa_signature_profile.cc`
    # for the layer-level wiring).
    assoc = ae.associate(pacs_host, pacs_port, ae_title=called_ae,
                          tls_args=(_tls_context(), pacs_host))
    if not assoc.is_established:
        raise RuntimeError("DICOM association rejected by PACS")

    for fn in sorted(os.listdir(study_dir)):
        if not fn.endswith(".dcm"):
            continue
        ds = dcmread(os.path.join(study_dir, fn))

        # Re-validate the local signature before sending, to avoid
        # propagating corrupted studies forward.
        if not _verify_digital_signature_seq(ds):
            raise RuntimeError(f"{fn}: local signature verify failed")

        status = assoc.send_c_store(ds)
        if status.Status != 0x0000:
            raise RuntimeError(f"C-STORE failed: {status.Status:04X}")
    assoc.release()


# ---- 2. PACS side: C-STORE SCP that re-verifies every incoming SOP ----

def _handle_store(event):
    ds: Dataset = event.dataset
    ds.file_meta = event.file_meta
    if not _verify_digital_signature_seq(ds):
        # A6xx = "Refused: Out of Resources" is the DICOM idiom; the
        # audit trail gets the real reason.
        _audit("signature_verify_failed",
               sop_instance=ds.SOPInstanceUID,
               modality=ds.Modality)
        return 0xA700
    _store_to_long_term(ds)
    return 0x0000


def run_pacs_scp():
    ae = AE(ae_title="ENT-PACS")
    for cx in StoragePresentationContexts:
        ae.add_supported_context(cx.abstract_syntax)
    handlers = [(evt.EVT_C_STORE, _handle_store)]
    ae.start_server(("0.0.0.0", 11112), evt_handlers=handlers,
                     ssl_cxt=_tls_context())


# ---- stubs: the real signing/verifying happens in the C++ module ----
def _verify_digital_signature_seq(ds: Dataset) -> bool: ...
def _tls_context(): ...
def _store_to_long_term(ds: Dataset) -> None: ...
def _audit(event: str, **kv) -> None: ...


# Hospital reality: a factoring break lets an attacker forge DICOM
# Digital Signatures, meaning they can either (a) inject fabricated
# studies — faked tumors, faked fractures — into a patient's PACS
# record, or (b) silently alter pixel data in a real study while
# preserving a valid signature. This has been demonstrated in academic
# work (Mirsky 2019 "CT-GAN") with MD5/broken-PKI assumptions; a real
# RSA break scales the attack to every PACS on the planet.
