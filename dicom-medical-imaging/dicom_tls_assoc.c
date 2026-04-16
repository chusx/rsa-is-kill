/*
 * dicom_tls_assoc.c
 *
 * DICOM (Digital Imaging and Communications in Medicine)
 * association establishment over TLS with RSA mutual
 * authentication. This is the session between the modality
 * (CT, MRI, PET/CT, mammography, ultrasound) and the PACS
 * (Picture Archiving and Communication System — GE Centricity,
 * Philips Vue, Siemens syngo.via, Agfa Enterprise Imaging).
 *
 * Once the TLS session is established and DICOM A-ASSOCIATE
 * accepted, the modality pushes images (C-STORE) or the
 * radiologist workstation queries/retrieves (C-FIND/C-MOVE).
 * HIPAA Security Rule §164.312(e)(1) mandates encryption in
 * transit; RSA TLS is the universal implementation.
 */

#include <stdint.h>
#include <string.h>
#include "dicom.h"

extern const uint8_t HOSPITAL_IMAGING_ROOT_PUB[384];

struct dicom_assoc_req {
    char       calling_ae[16];         /* modality AE title      */
    char       called_ae[16];          /* PACS AE title           */
    char       presentation_ctx[32];   /* "1.2.840.10008.5.1.4.1.1.2" CT */
    uint8_t    modality_cert[2048]; size_t modality_cert_len;
};

int pacs_accept_association(const struct dicom_assoc_req *r)
{
    /* Modality cert chains to hospital imaging CA. */
    if (x509_chain_verify(r->modality_cert, r->modality_cert_len,
            HOSPITAL_IMAGING_ROOT_PUB,
            sizeof HOSPITAL_IMAGING_ROOT_PUB))
        return DICOM_CHAIN;

    /* AE title in cert SAN must match calling_ae. */
    if (!cert_matches_ae(r->modality_cert, r->modality_cert_len,
                         r->calling_ae))
        return DICOM_AE;

    return dicom_session_accept(r->calling_ae, r->called_ae);
}

/* ---- Clinical imaging attack surface ----------------------
 *  HOSPITAL_IMAGING_ROOT factored:
 *    Forge a modality cert; C-STORE attacker-crafted DICOM
 *    images into PACS. Radiologist reads forged images for
 *    a real patient -> misdiagnosis. Or: forge a PACS cert
 *    to MitM and exfiltrate every imaging study in the
 *    hospital (PHI at HIPAA scale). Additionally, DICOM-RT
 *    (radiation therapy plans) flow over the same channel;
 *    a forged treatment plan with altered dose -> patient harm.
 * --------------------------------------------------------- */
