"""Compatibilidad con switches que solo hablan SSH "viejo" (SHA-1).

Paramiko 5 eliminó los algoritmos con SHA-1 que siguen usando muchos equipos en producción
(Cisco IOS clásico "SSH-2.0-Cisco-1.25", Catalyst 2960/3560/3750, Aruba/ProCurve antiguos,
OmniSwitch AOS 6...): diffie-hellman-group1-sha1, diffie-hellman-group14-sha1,
diffie-hellman-group-exchange-sha1 y el host key "ssh-rsa". PuTTY todavía los acepta, por eso
PuTTY entra y la app no.

Aquí se vuelven a registrar, **al final** de la lista de preferencia: un equipo moderno sigue
negociando lo más seguro y solo los equipos viejos usan estos. Funciona con cualquier versión de
Paramiko (si la versión instalada ya los trae, no se toca nada).
"""
from __future__ import annotations

import logging
from hashlib import sha1

log = logging.getLogger(__name__)

# RFC 2409 sección 6.2 (Oakley group 2, 1024 bits)
_GROUP1_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E"
    "3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5"
    "CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)

LEGACY_KEX = ("diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
              "diffie-hellman-group1-sha1")
LEGACY_HOSTKEYS = ("ssh-rsa",)

_done = False


def enable_legacy_algorithms() -> list[str]:
    """Registra los algoritmos legacy que falten. Devuelve los que agregó (idempotente)."""
    global _done
    if _done:
        return []
    _done = True
    added: list[str] = []
    try:
        from paramiko.transport import Transport
    except Exception:          # sin paramiko no hay nada que hacer
        return added

    kex_info = dict(Transport._kex_info)
    try:
        if "diffie-hellman-group14-sha1" not in kex_info:
            from paramiko.kex_group14 import KexGroup14SHA256

            class KexGroup14SHA1(KexGroup14SHA256):
                name = "diffie-hellman-group14-sha1"
                hash_algo = sha1

            class KexGroup1(KexGroup14SHA256):
                P = _GROUP1_P
                G = 2
                name = "diffie-hellman-group1-sha1"
                hash_algo = sha1

            kex_info[KexGroup14SHA1.name] = KexGroup14SHA1
            kex_info.setdefault(KexGroup1.name, KexGroup1)
            added += [KexGroup14SHA1.name, KexGroup1.name]
        if "diffie-hellman-group-exchange-sha1" not in kex_info:
            from paramiko.kex_gex import KexGexSHA256

            class KexGexSHA1(KexGexSHA256):
                name = "diffie-hellman-group-exchange-sha1"
                hash_algo = sha1
                min_bits = 1024           # los equipos viejos suelen ofrecer grupos de 1024

            kex_info[KexGexSHA1.name] = KexGexSHA1
            added.append(KexGexSHA1.name)
    except Exception as exc:   # cambio interno de Paramiko: se reporta y la app sigue
        log.warning("No se pudieron habilitar los KEX legacy: %s", exc)
    Transport._kex_info = kex_info

    try:
        from cryptography.hazmat.primitives import hashes
        from paramiko.rsakey import RSAKey
        if "ssh-rsa" not in Transport._key_info:
            RSAKey.HASHES = {**RSAKey.HASHES, "ssh-rsa": hashes.SHA1}
            Transport._key_info = {**Transport._key_info, "ssh-rsa": RSAKey}
            added.append("ssh-rsa")
    except Exception as exc:
        log.warning("No se pudo habilitar el host key ssh-rsa: %s", exc)

    def _append(attr: str, names) -> None:
        current = tuple(getattr(Transport, attr))
        extra = tuple(n for n in names if n not in current)
        if extra:
            setattr(Transport, attr, current + extra)

    _append("_preferred_kex", [k for k in LEGACY_KEX if k in Transport._kex_info])
    _append("_preferred_keys", [k for k in LEGACY_HOSTKEYS if k in Transport._key_info])
    if added:
        log.info("SSH legacy habilitado (solo como último recurso): %s", ", ".join(added))
    return added
