# ros2-sros2-dds — RSA in AI-driven robotics security

**Standard:** ROS 2 (Robot Operating System 2), SROS2, DDS-Security 1.1 (OMG)
**Industry:** AI robotics — autonomous mobile robots, surgical robots, agricultural autonomy, warehouse automation, defense robotics
**Algorithm:** RSA-2048 (Identity + Permissions CAs), ECDSA-P256 alternate

## What it does

ROS 2 is the de facto operating layer for AI robotics. SROS2 (Secure ROS 2)
layers DDS-Security authentication, access-control, and cryptography on top
of ROS 2's pub/sub node graph.

DDS-Security defines three plugins and three PKIs:

1. **Authentication plugin** — validates that each participating node has a
   cert signed by the Identity CA.
2. **Access Control plugin** — checks that a node has permissions to publish
   on / subscribe to specific topics; permissions docs are signed XML signed
   by the Permissions CA.
3. **Cryptographic plugin** — AES-GCM + HMAC session crypto; bootstrap via
   authenticated Diffie-Hellman.

Both CAs are typically configured as RSA-2048 (the default in `sros2` CLI
tooling). Every robot deployment that enables security ships with an Identity
CA cert, a Permissions CA cert, per-node identity certs, and signed
permissions/governance XML documents.

Who uses SROS2 in production AI robotics:

- **Autonomous mobile robots** — Locus Robotics, Fetch/Zebra, Boston Dynamics
  (Spot SDK uses ROS 2 bridges), 6 River Systems
- **Agricultural autonomy** — John Deere See & Spray, Blue River, Carbon Robotics
- **Surgical robotics** — Intuitive Surgical research work, CMR Surgical, Medtronic
  Hugo research integrations
- **Autonomous trucking / delivery bots** — Nuro, Kiwibot, Starship Technologies
- **Defense AI** — Anduril Ghost series, Shield AI Hivemind (some deployments),
  research autonomy at DARPA OFFSET
- **Humanoid AI** — Figure, 1X, Agility Digit ground truth stacks
- **Research labs** — every major university AI robotics lab (MIT CSAIL,
  CMU RI, Stanford AI Lab) standardizes on ROS 2 for AI policy deployment

## Why it's stuck

- DDS-Security 1.1 mandates PKCS#7 signed governance + permissions docs,
  X.509 identity certs. RSA is the most widely deployed; ECDSA is permitted
  but less common in practice.
- Identity CAs and Permissions CAs in robot fleets are often manually managed
  per fleet; rotation is operationally expensive (requires provisioning new
  certs to every robot via maintenance visit).
- Robots have long physical lives. An AMR fielded in 2022 with RSA-2048
  identity will still be in production in 2030.
- Robot-to-robot and robot-to-operator mTLS bridges (e.g., ROS 2 Bridge,
  Foxglove Studio, rosbridge) inherit the same RSA CA.

## impact

- **Rogue AI-robot injection**: Forge an Identity CA signature → provision
  an attacker-controlled "robot" into a factory fleet, which then subscribes
  to control topics, sensor streams, and proprietary policy outputs. Data
  exfiltration of vision streams, LiDAR maps, proprietary AI policy actions.
- **Command injection into autonomous platforms**: Forge Permissions CA
  signatures on a permissions doc that authorizes an attacker node to
  publish on `/cmd_vel` (velocity command) or `/mission_plan`. Physical
  manipulation of robot motion — safety-critical implications (surgical,
  agricultural, autonomous trucking).
- **Surgical AI sabotage**: In hospital deployments using SROS2-secured
  ROS 2 bridges for surgical assistants, forged identity means an attacker
  can appear as a legitimate console to the arm.
- **Fleet-wide recall / DoS**: Revocation lists are signed by the CA. A
  forged CRL injected into a fleet can revoke legitimate robots' certs,
  grounding entire fleets.
- **Supply-chain weight injection**: Many AI robots receive policy model
  updates over ROS 2 topics with signed payloads. Forge the signing chain
  → push tampered policy models that misbehave on specific visual triggers
  (adversarial objects). Classic backdoored-policy attack with authenticated
  delivery.
- **Defense / autonomous weapon platforms**: SROS2 is evaluated for use in
  defense autonomy stacks; RSA compromise neutralizes every identity and
  permissions proof.

## Code

- `sros2_bootstrap.py` — generate an Identity CA + Permissions CA (RSA-2048),
  issue per-node identity certs, sign governance + permissions XML.
- `dds_security_plugin.c` — DDS-Security authentication plugin glue: RSA
  signature check on handshake, cert chain validation to Identity CA.
- `permissions.xml` — example signed DDS-Security permissions document
  granting publish/subscribe on specific topics.
