# ATSC 3.0 NextGen TV — signed application delivery, signed
# emergency-alert messages, DRM for broadcast-to-internet hybrid

**ATSC 3.0 ("NextGen TV")** is the replacement over-the-air digital
TV standard in the United States, Korea, and (in rollout) other
markets. Deployment: ~75% of US population coverage by 2024,
targeting 100% by 2027; Korea had full deployment from 2017. Every
modern TV sold in the US since 2023 includes an ATSC 3.0 tuner.

Unlike ATSC 1.0 (broadcast-only), ATSC 3.0 is IP-based and combines
broadcast + broadband ("hybrid"). This opens an attack surface that
did not exist in the analog / ATSC 1.0 era.

## RSA usage

### 1. Signed broadcast applications (A/344)
ATSC 3.0 broadcasts can push interactive applications (HTML/JS)
that run on the receiver. **ATSC A/344** specifies signed
applications — the broadcaster signs the app bundle with a cert
chained to an ATSC-recognised CA; receivers refuse to execute
un-signed or mis-signed apps. This prevents a malicious RF
injection from running hostile code on TVs.

### 2. Signed emergency-alert messages (A/331 / A/341 / A/332)
EAS (Emergency Alert System), WEA (Wireless Emergency Alerts), and
ATSC 3.0's **AEA (Advanced Emergency Alerts)** deliver life-safety
messages: AMBER, tornado, tsunami, presidential. On ATSC 3.0 the
AEA payload is authenticated via RSA signature over the alert
envelope.

### 3. DRM / content protection (A/362)
Premium programming (sports, movie broadcasts) uses DRM (Widevine,
PlayReady, Marlin). License-acquisition over broadband carries
RSA-based certs; device attestation (Widevine L1) has its own RSA
provisioning.

### 4. Broadcast-gateway PKI
The IP gateway at each broadcast station (Sinclair Broadcasting,
Nexstar, Tegna, CBS, ABC-owned stations) runs a signed-transport
stack. Station-to-STL (studio-transmitter link) uses signed link
messages.

### 5. Receiver firmware signing
TV OEMs (Samsung, LG, Sony, TCL, Hisense, Vizio) ship RSA-signed
firmware OTA. The tuner + Android TV / Tizen / webOS / Google TV
layers each sign their own stack. An ATSC 3.0 tuner firmware push
is a vehicle for interactive-app-key updates.

## Scale

- ~120M TV households in the US; ATSC 3.0 reaches ~60M+ of them
- ATSC 3.0 rollout in Korea, India (pilot), Jamaica, Trinidad, and
  in evaluation across Latin America
- Emergency alerts reach every ATSC 3.0 receiver in the broadcast
  footprint — a WEA / AEA signed-forgery has direct public-safety
  consequences
- 2018 Hawaii false-missile alert (non-ATSC-3.0) took 38 minutes
  to correct; imagine the scenario with cryptographic
  authentication of the false alert

## Breakage

A factoring attack against:

- **An ATSC 3.0 broadcast-application signing CA**: attacker
  injects a signed malicious interactive app into the RF path
  (a rogue RF transmitter near a station, or a station-side
  supply-chain compromise). App runs on every TV in the
  footprint — can do anything a browser can, including exfil
  via broadband companion link.
- **The AEA alert-signing root**: forged signed emergency alerts
  ("tsunami evacuate now", "shelter in place", "civil
  disturbance") delivered to every NextGen TV. Mass panic; real
  alerts distrusted thereafter ("crying-wolf erosion" of the
  most-trusted civil-warning channel).
- **A DRM provisioning root** (Widevine / PlayReady): mass
  premium-content piracy capability; operators face RIAA/MPAA
  fallout.
- **A station-gateway / STL signing key**: attacker impersonates
  a legitimate station on its assigned frequency; content
  hijack of the broadcast itself.
- **A TV-OEM firmware root**: Samsung/LG/Sony/TCL push that
  bricks or converts TVs into IoT attack infrastructure.

Broadcast-equipment lifecycle is 10–15 years; TV-receiver
lifecycle is 7–12 years. ATSC 3.0 trust-anchor replacement requires
coordination between the broadcaster consortium, ATSC, FCC, and
every TV OEM — no precedent for a full crypto rotation at this
scale in US broadcasting.
