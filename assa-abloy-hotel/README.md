# Hotel / access-control — RFID keycard issuance, BLE mobile keys,
# PMS integration, signed lock firmware

Hospitality electronic-lock access control: every major hotel brand
runs one of:

- **ASSA ABLOY Hospitality** (Vingcard, Saflok, ILCO) — largest
  global, brands of Marriott, Hilton, Hyatt, IHG, Accor, Wyndham
- **Dormakaba** (Saflok, Ilco, Kaba) — large enterprise + US
- **Salto Systems** — boutique + mid-market
- **Kwikset / Schlage Residential + Commercial** (Allegion)
- **Brivo, Openpath (now Avigilon Alta), Kisi** — office access
- **HID Global** (cross-ref `hid-osdp-seos/`) — corporate / ID

Commercial access control extends to corporate, hospitals, multi-
family residential, student housing, co-working. Global installed
base of electronic locks: ~100M across hospitality, and ~500M if
residential/commercial deadbolts included.

## RSA usage

### 1. Lock firmware signing
Vingcard RFID / BLE locks, Saflok MT, Salto XS4, Schlage Encode /
NDE — every modern electronic hotel/commercial lock ships with
an RSA-signed firmware image. Many accept OTA updates carried via
the cleaning/staff key (itself authenticated).

### 2. Mobile-key / BLE credential signing
Hilton Digital Key, Marriott Mobile Key, Hyatt Key by SALTO KS,
OpenKey, ASSA ABLOY Mobile Access (VingCard) — the mobile
credential is a short-lived, signed token encoding (guest_id,
room, validity window, permissions). Issued by the hotel PMS +
hospitality-vendor cloud, signed with an RSA key bound to the
property.

### 3. Property Management System integration
PMS platforms (Oracle OPERA / Opera Cloud, Mews, Cloudbeds,
Infor HMS) issue cryptographically-bound keycard activation
records over TLS mutual auth to the lock-interface server (LIS).
Check-in → "encode room 1205 for guest X until Saturday 11am" —
signed transaction.

### 4. Staff credential provisioning
Housekeeping, maintenance, and management staff cards are issued
with role-scoped permissions (floor set, time-of-day, tour-mode).
Roll-out to locks via the "staff front-desk encoder" which itself
holds an RSA-authenticated session to the property CA.

### 5. Cloud-managed lock fleets
Salto KS, dormakaba EntriWorX, ASSA ABLOY Incedo, Latch / Latch+,
Brivo Access — SaaS access-control backends issue per-lock
cloud certs (RSA-2048) for fleet control + audit sync.

### 6. PACS + HR integration in commercial
For commercial (non-hotel) deployments, access-control integrates
with HR (Workday, SAP SuccessFactors) over mutually-authenticated
APIs — badge provisioning tied to employment status.

## Scale

- ~100M hotel electronic-lock doors worldwide
- Major-brand hotels issuing mobile keys: Marriott, Hilton,
  IHG, Hyatt, Accor, Choice — ~10M+ guest-nights/day with a
  mobile-key option
- High-value guest: finance execs, diplomats, attorneys carrying
  privileged material sleep behind these locks
- 2024 "Dormakaba Saflok Unsaflok" disclosure showed vulnerability
  in the factory-default key hierarchy affecting ~3M doors; the
  paper-fix was a field visit to every lock

## Breakage

A factoring attack against:

- **A hospitality vendor lock-firmware-signing root** (ASSA ABLOY
  VingCard, Dormakaba Saflok, Salto): signed firmware pushed via
  cleaning-card or cloud-sync that opens any door on command, or
  silently logs a skeleton-key value attackers can use with a
  standard test keycard. Universal hotel-room access across a
  brand portfolio.
- **A property mobile-key signing key**: attacker mints valid
  mobile keys for any room at a property without PMS
  involvement. Guest-room-intrusion threat is continuous —
  invisible entry + exit with no PMS-side audit trail.
- **A PMS-to-LIS integration CA**: forged check-in events issue
  real keycards (physical or mobile) for rooms the attacker
  never booked. Front-desk fraud + guest-safety exposure.
- **A cloud-managed fleet CA (Salto KS, Latch, Brivo)**:
  commercial-building entry at scale — office tower tenants,
  multifamily, hospital back-of-house. Attackers hold dynamic
  universal-unlock capability.
- **HR-integration signing (corporate)**: terminated employees
  retain access; fabricated employment records issue valid
  badges to outsiders.

Hospitality-lock lifecycle is 7–15 years; many branded-property
owners replace only at property-renovation cycle (10–20 years).
A vendor-root compromise means brand-portfolio-wide lock swap or
extensive field-firmware reflash — the Saflok 2024 incident
demonstrated how slow "visit every door" programmes actually are.
