# US freight + passenger railway — Positive Train Control signed
# messaging, locomotive onboard certs, wayside interlocking PKI

**Positive Train Control (PTC)** is the US-mandated train-control
overlay that enforces safe train separation and authority, required
by the Rail Safety Improvement Act of 2008 (RSIA) and finally
declared interoperable across all Class I carriers in 2020. PTC
prevents: train-to-train collisions, over-speed derailments,
incursion into established work zones, movement through mis-
aligned switches.

## Operators + vendors

- **Class I freight**: BNSF, Union Pacific, CSX, Norfolk Southern,
  Canadian National (CN), Canadian Pacific Kansas City (CPKC)
- **Passenger**: Amtrak, Metro-North, LIRR, NJ Transit, MBTA,
  Metra, SEPTA, MARC, VRE, Caltrain, Metrolink, Coaster, etc.
- **Vendors**: Wabtec (I-ETMS dominant), Hitachi Rail STS (formerly
  Ansaldo STS; ACSES on Amtrak NEC), Siemens Mobility, Alstom
  (TCAS/ETCS in international market)

~60,000 track-miles equipped; ~22,000 locomotives fitted.

## RSA usage

### 1. Onboard-locomotive computer (OBC) firmware + codebase signing
Wabtec I-ETMS Train Management Computer (TMC), Hitachi ACSES-II
onboard, Alstom PTC onboard — each runs a signed software load.
OEM + operator counter-signatures common.

### 2. Mobile-to-wayside / wayside-to-mobile message auth
PTC message integrity rides on a RSA / HMAC hybrid per
AAR S-9401, S-9402, S-9201. Class I railroads share an
**Interoperable Train Control (ITC)** messaging fabric; the
**Railroad PKI** under the AAR issues operator certs so a BNSF
locomotive operating on UP track accepts authority messages from
UP wayside.

### 3. Wayside Interface Unit (WIU) → Back Office Server (BOS)
WIUs at switches, signals, and highway crossings publish status
over 220 MHz PTC radio + TCP-IP backhaul. Signed messages carry
switch position, signal aspect, track-circuit state.

### 4. Dispatch → mobile movement authority
Signed movement-authority messages from the BOS tell an onboard
where it may travel. Enforced speed profiles ride the same
trust plane.

### 5. Grade-crossing predictor integrity
Signed messages from crossing predictors about gate-arm status;
failure to authenticate = train enforces stop.

### 6. Dispatcher-console + engineer-tablet authentication
Dispatcher consoles (GE/Wabtec Trident, Siemens Vicos) and
engineer ETS tablets authenticate to the BOS with per-device
certs.

### 7. Cross-carrier interoperability (AAR Railinc)
Railinc runs shared rail-industry services (car-location,
equipment registry, safety-critical EDI). These rely on RSA-
backed TLS mutual auth between carriers.

## Scale

- 140,000 miles of US rail (Class I, II, III combined); 60,000
  miles mandated to PTC
- ~22,000 PTC-equipped locomotives
- PTC messaging: ~1B authenticated messages/day fleet-wide
- Amtrak NEC + NEC commuter rail: ~750,000 daily passengers;
  ACSES-II authenticated signaling mandatory above 79 mph

## Breakage

A factoring attack against:

- **The AAR Railroad PKI root**: attacker injects signed
  movement-authority messages — granting an already-occupied
  authority, cancelling a legitimate authority mid-move,
  forging a switch-aligned message that doesn't match the
  field. The PTC safety case collapses. This is a precondition
  for a train-vs-train collision at track speed (Chatsworth
  2008-class event was the motivating incident for RSIA).
- **Wabtec I-ETMS OBC firmware root**: signed firmware pushed
  to thousands of locomotives that mis-parses the movement-
  authority database or silently disables enforcement. A
  nominal over-speed goes un-arrested.
- **Hitachi STS ACSES-II codebase signing key (passenger rail)**:
  equivalent impact on Amtrak NEC and connected commuter
  systems. The 2015 Frankford Junction derailment (Amtrak 188,
  8 killed) happened in a known over-speed location for which
  ACSES was not yet installed on that track direction;
  ACSES-II's compromise reverses the safety gain.
- **Grade-crossing predictor signing key**: authenticated
  "gate-down, track clear" messages can be forged to a train
  approaching a crossing that actually has a vehicle on it.
- **Railinc cross-carrier CA**: inter-carrier safety-critical
  EDI (dangerous-goods, hazmat-car-location) integrity
  compromised. EPA / DOT notifications for derailments / spills
  depend on these records.

Rail-industry equipment lifecycle is 30–50 years for locomotive
hulls; PTC electronics ~15–25 years. A fleet-wide PTC-signing-
root compromise requires a coordinated re-keying across every
Class I, every commuter railroad, every Amtrak installation, and
hundreds of short-line carriers that rideshare PTC messaging —
no US precedent for this scale of crypto rotation in a
safety-regulated transport domain.
