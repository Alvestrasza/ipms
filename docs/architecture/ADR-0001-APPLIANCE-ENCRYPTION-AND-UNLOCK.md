# ADR-0001: Appliance Encryption, Unlock, and Recovery Policy

- Status: Accepted policy; implementation and clean-install validation pending
- Decision date: 2026-08-30
- Applies to: IPMS Appliance, IPMS Scale-Out, and A-Corp-hosted IPMS
- Related issues: [#10](https://github.com/Alvestrasza/ipms/issues/10),
  [#11](https://github.com/Alvestrasza/ipms/issues/11)

## Context

IPMS stores infrastructure inventory, operational telemetry, connector
configuration, audit evidence, backup metadata, and potentially recoverable
secret material. Offline access to an Appliance disk, VM export, snapshot, or
backup must not expose that data.

Encryption at rest also creates an availability dependency: the Appliance
cannot start until an authorized mechanism releases a disk key. The design must
therefore cover normal boot, unattended restart, platform migration, disaster
recovery, hardware replacement, key rotation, backup, and permanent key loss.

An unlock key stored only on the same unencrypted OS volume does not provide an
independent trust boundary and is not an approved production design.

## Threat Model

The policy addresses:

- theft or unauthorized copying of a physical disk, virtual disk, snapshot, or
  VM export
- offline modification of an Appliance filesystem
- loss or replacement of a TPM, vTPM, Hyper-V host, or key protector
- compromise or outage of a network-bound unlock service
- theft of backup media or a LUKS header backup
- accidental key deletion, incorrect rotation, or operator lockout
- cross-tenant impact from key reuse in hosted or Scale-Out deployments

Block-device encryption does not protect data after the volume is unlocked. It
does not by itself protect against a compromised guest root account, memory
inspection, an authorized application process, or every hostile-hypervisor
scenario. Shielding, application authorization, tenant isolation, secret
management, audit, and backup encryption remain separate controls.

## Decision

### Encryption Format

IPMS uses LUKS2 for Linux block-device encryption.

- Every encrypted Appliance receives a newly generated, unique LUKS volume key.
- Encrypted VM images are never cloned after LUKS initialization.
- The persistent data mapping is named `ipms-data-crypt`.
- Destructive provisioning selects the physical target by a verified stable
  `/dev/disk/by-id/` path, never by a volatile `/dev/sdX` name alone.
- Runtime activation uses the LUKS UUID in `/etc/crypttab`.
- LUKS2 header backups are required after provisioning and every keyslot or
  token change.

The preferred fresh-install layering is:

```text
stable physical disk identity
    -> GPT partition
        -> LUKS2 container
            -> LVM volume group
                -> logical volumes
                    -> ext4 filesystems
```

This keeps all LVM metadata, free extents, and future logical volumes inside
the encrypted boundary.

### Operating-System and Data Volumes

Customer production and A-Corp-hosted deployments require encryption for both:

- the persistent IPMS data volume
- the operating-system volume containing logs, local configuration, temporary
  files, container state, and crash artifacts

The EFI System Partition and the minimum boot chain required by the selected
Ubuntu boot design may remain unencrypted. Secure Boot is required whenever
the platform supports it.

Until OS-volume encryption is implemented and validated for the selected
Ubuntu Server installation path, no connector secret, license signing secret,
tenant encryption key, backup key, or reusable disk-unlock key may be persisted
on the OS volume.

### Supported Deployment Profiles

| Profile | Data volume | OS volume | Normal unlock | Recovery | Approval |
| --- | --- | --- | --- | --- | --- |
| `development-unencrypted` | Unencrypted | Unencrypted | None | Backup only | Isolated DEV and disposable evaluation only |
| `manual-luks2` | LUKS2 | LUKS2 where installer support is validated | Console passphrase or recovery key | Independent recovery key plus encrypted header backup | Customer deployment without unattended restart |
| `tpm2-luks2` | LUKS2 | LUKS2 | TPM2/vTPM-sealed token | Independent recovery key plus encrypted header backup | Preferred standalone production profile after platform qualification |
| `network-luks2` | LUKS2 | LUKS2 | Approved network-bound unlock policy | Independent recovery key plus encrypted header backup | Hosted and Scale-Out profile after availability testing |

The current v0.1.0 reference Appliance uses
`development-unencrypted`. This is an explicit temporary exception, not a
customer default. It may not contain customer production data or reusable
production connector credentials.

The hardening bootstrap must continue to reject `customer` and `production`
profiles until at least one encrypted profile has completed clean-install,
reboot, recovery, backup, and migration acceptance.

## Unlock Profiles

### Manual LUKS2

Manual unlock is the safe fallback when no independently trusted hardware or
network service is available.

- It requires console interaction after every cold boot.
- It is incompatible with fully unattended recovery after power loss.
- It must never be weakened by adding a key file to the local unencrypted OS.
- A randomly generated recovery key is preferred over a human-selected short
  passphrase.

### TPM2 or vTPM

`systemd-cryptenroll` is the reference integration for enrolling TPM2 and
recovery tokens into LUKS2.

- TPM enrollment is always accompanied by an independent recovery keyslot.
- PCR policy is versioned and tested against Secure Boot, kernel, initramfs,
  firmware, and bootloader updates.
- A failed TPM policy must stop automatic unlock and require recovery; it must
  not fall back to a local plaintext key.
- After recovery boot, the operator validates the platform state before
  replacing the TPM enrollment.

For Hyper-V, a local key protector can support a local vTPM without a complete
Host Guardian Service deployment. This does not provide the same migration,
attestation, or hostile-fabric protection as a properly operated guarded
fabric. The local protector and its recovery material become critical backup
assets. Before host migration or recovery, key-protector portability must be
tested independently.

HGS-backed protection is the preferred Hyper-V design for Scale-Out or guarded
production fabrics. IPMS does not claim HGS-level protection when only a local
key protector is present.

### Network-Bound Unlock

Clevis with Tang is the reference candidate for network-bound LUKS2 unlock.
Production use requires:

- multiple independently operated Tang endpoints
- a threshold policy so one endpoint loss does not stop every Appliance
- pinned and pre-approved Tang advertisements during enrollment
- early-boot network, DNS, route, and time behavior tested under failure
- rate-limited monitoring and audit without exposing key material
- a manual recovery key that works when all network endpoints are unavailable

Automatic trust bypass flags are not permitted during production enrollment.

Vault Transit or another external KMS may wrap application, tenant, export, and
backup data-encryption keys. It is not automatically an early-boot disk unlock
mechanism. Any custom initramfs KMS integration requires a separate ADR,
availability model, credential bootstrap design, and recovery test.

## Recovery Material

Every encrypted volume has at least two independent unlock paths:

1. the selected normal unlock token
2. a randomly generated recovery key in a separate LUKS2 keyslot

Recovery material requirements:

- generated locally from a cryptographically secure source
- displayed or exported only once during the protected enrollment ceremony
- never passed as a process-list-visible command-line argument
- never written to Git, issue comments, logs, shell history, unattended
  installation files, or the Appliance database
- stored in an approved external secrets system with strong authentication,
  access logging, and separation from the Appliance
- protected by at least two authorized custodians or an equivalent audited
  break-glass process for customer and hosted production deployments
- backed up independently from the encrypted data and LUKS header
- tested through a scheduled recovery exercise

The encrypted LUKS2 header backup and the recovery key are separate assets.
Possession of both can permit offline decryption and must be controlled
accordingly.

If every valid keyslot, token, recovery key, and usable backup is lost, the data
is intentionally unrecoverable. IPMS must state this before enrollment and must
not imply that A-Corp can bypass LUKS cryptography.

## Key Rotation and Revocation

Rotation uses an add-test-remove sequence:

1. create a new keyslot or token
2. back up the updated LUKS2 header
3. validate normal unlock
4. validate the independent recovery path
5. reboot through the selected profile
6. revoke the old token or keyslot
7. back up the final header and audit the ceremony

Deleting the old key before the new and recovery paths are proven is forbidden.

TPM replacement, Hyper-V key-protector replacement, suspected recovery-key
exposure, custodian changes, and unlock-service trust changes all trigger
rotation.

## Backup Policy

- Backups use encryption independent from the live LUKS volume key.
- Copying an encrypted virtual disk is not sufficient backup evidence.
- Backup keys are stored outside the protected Appliance.
- Restore testing includes a target with different disk identifiers and, where
  applicable, a different TPM, vTPM, Hyper-V host, or network-unlock identity.
- VM configuration backups containing Hyper-V key-protector information are
  treated as sensitive key-management material.
- LUKS header backups are versioned and associated with the correct stable disk
  identity and Appliance record without publishing those values.

## Migration to Scale-Out

Standalone-to-Scale-Out migration does not copy the source LUKS volume key.

1. Provision every target node with a unique encrypted volume and recovery
   material.
2. Establish authenticated encrypted transport between source and target.
3. Export a versioned application-level migration package encrypted with a
   one-time data-encryption key.
4. Wrap that key for the destination key-management boundary.
5. Import and validate tenant counts, checksums, audit continuity, and service
   health.
6. Revoke the one-time key after the rollback window.
7. Retire and cryptographically erase the source only after acceptance.

Scale-Out nodes never share a cloned LUKS header, volume key, TPM enrollment, or
recovery key. Database replication and backups use their own transport and key
policies.

## Bootstrap Inputs

The installer may accept only non-secret policy selectors directly:

- deployment profile
- stable target disk identity
- mapping name and mount point
- normal unlock method
- TPM2 policy identifier or approved network-unlock policy identifier
- external recovery-material destination reference
- maintenance and recovery-test policy identifiers

Passphrases and recovery keys are supplied through protected interactive input,
an ephemeral file descriptor, or a platform credential mechanism. The
installer emits only redacted identifiers, keyslot numbers, token types,
checksums of public policy data, and pass/fail results.

## Validation Requirements

An encrypted profile is accepted only after all applicable checks pass:

- stable physical target identity verified before destructive work
- `cryptsetup luksDump` confirms LUKS2 and expected token/keyslot classes
- `/etc/crypttab` uses the LUKS UUID and contains no plaintext secret
- `/etc/fstab` references only the unlocked mapping or filesystems above it
- unattended normal boot succeeds when the selected profile promises it
- normal unlock fails safely when its TPM or network dependency is unavailable
- recovery unlock succeeds from the documented console path
- normal unlock can be rotated without losing recovery access
- header backup and restore are verified on a disposable target
- filesystem and application data survive reboot
- backup restore succeeds with different platform and disk identities
- logs and process lists contain no passphrase, recovery key, or volume key
- migration to a newly keyed target preserves data without copying the source
  LUKS key

## Current Reference Migration

The current development data volume is unencrypted and contains no accepted
customer production workload. The preferred transition is backup, rebuild, and
restore onto a newly created LUKS2 layout.

In-place LUKS2 encryption exists in cryptsetup, but it changes live storage
metadata and carries additional recovery requirements. It is not the default
IPMS conversion path. It may be used only after a separate backup, capacity
check, interruption test, rollback procedure, and explicit approval.

## Consequences

- The present isolated DEV Appliance may continue without encryption.
- Customer and production installers remain blocked until encrypted-profile
  implementation and recovery acceptance exist.
- Unattended boot requires an independent TPM2/vTPM or network trust service.
- Recovery operations become a required product workflow, not an informal
  password note.
- Hosted and Scale-Out designs require highly available external key services
  before they can claim unattended encrypted restart.
- Encryption does not replace tenant isolation, secret management, audit, or
  application-layer envelope encryption.

## Primary References

- [Ubuntu full disk encryption](https://documentation.ubuntu.com/security/security-features/storage/encryption-full-disk/)
- [Ubuntu storage encryption overview](https://documentation.ubuntu.com/security/security-features/storage/)
- [Ubuntu systemd-cryptenroll manual](https://manpages.ubuntu.com/manpages/questing/man1/systemd-cryptenroll.1.html)
- [Ubuntu autoinstall configuration reference](https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-reference.html)
- [cryptsetup LUKS manual](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)
- [cryptsetup re-encryption manual](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup-reencrypt.8.adoc)
- [Ubuntu Clevis LUKS binding manual](https://manpages.ubuntu.com/manpages/questing/man1/clevis-luks-bind.1.html)
- [Microsoft Hyper-V Generation 2 VM security](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/generation-2-virtual-machine-security-features)
- [Microsoft Hyper-V local key protector](https://learn.microsoft.com/en-us/powershell/module/hyper-v/set-vmkeyprotector?view=windowsserver2025-ps)
- [Microsoft Host Guardian Service management](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-manage-hgs)
- [Vault Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
