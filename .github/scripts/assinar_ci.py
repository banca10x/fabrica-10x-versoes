"""Assinatura Ed25519 feita no CI deste repositório público (instalador e manifesto do componente de download).

O formato é BYTE A BYTE o que o aplicativo confere (fabrica/app/atualizacao.py e fabrica/app/componente_download.py, repositório privado):
  instalador : mensagem = b"fabrica10x-setup\\n<nome do arquivo>\\n<sha256 em minúsculas>\\n"
  manifesto  : mensagem = b"fabrica10x-componente\\n" + bytes EXATOS do componente_download.json que sobe para a Release
  arquivo .sig = assinatura de 64 bytes em base64 + "\\n"

Comandos (o segredo só é lido pelos comandos de assinar, sempre da variável de ambiente, nunca de argumento, nunca impresso):
  assinar-instalador ARQ SAIDA      assina e já confere o resultado contra a chave pública embutida abaixo
  assinar-componente ARQ SAIDA      idem para o manifesto
  conferir-instalador ARQ SIG [--sha256-arquivo ARQ.sha256] [--fonte atualizacao.py]
  conferir-componente ARQ SIG
        só usam a chave pública: é a autoverificação que roda antes de publicar. Saem com código 1 se algo não bate.
Só depende de ``cryptography`` (versão fixada no workflow).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys
from pathlib import Path

# Mesma chave de CHAVE_PUBLICA_ED25519_HEX no código-fonte. Se o par de chaves for trocado, troque aqui E no aplicativo.
CHAVE_PUBLICA_HEX = "9cae36e30d86aded44bee40d2f9949e13b6a7d7baeeff915295b0e5f04d3f2d8"
VARIAVEL = "FABRICA_ASSINATURA_ED25519"


def _falha(msg: str, codigo: int = 1) -> "int":
    print(f"::error::{msg}", file=sys.stderr)
    return codigo


def mensagem_instalador(nome: str, sha256: str) -> bytes:
    return f"fabrica10x-setup\n{nome}\n{sha256.lower()}\n".encode("utf-8")


def mensagem_componente(corpo: bytes) -> bytes:
    return b"fabrica10x-componente\n" + corpo


def sha256_arquivo(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for bloco in iter(lambda: f.read(1024 * 1024), b""):
            h.update(bloco)
    return h.hexdigest()


def _chave_privada(chave_publica_hex: str = CHAVE_PUBLICA_HEX):
    """Semente = EXATAMENTE 64 caracteres hexadecimais. Ausente, malformada ou de outro par: erro sem ecoar o valor."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    bruto = os.environ.get(VARIAVEL, "")
    if not bruto:
        raise SystemExit(_falha(f"O segredo {VARIAVEL} está ausente. Crie o Environment 'assinatura' e coloque o segredo dentro dele (docs/LANCAMENTO.md)."))
    if not re.fullmatch(r"[0-9a-fA-F]{64}", bruto):   # sem strip: espaço ou quebra de linha sobrando reprova, como no passo de conferência do workflow
        raise SystemExit(_falha(f"O segredo {VARIAVEL} não tem 64 caracteres hexadecimais (semente Ed25519). Não vou assinar."))
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(bruto))
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    if pub != chave_publica_hex:
        raise SystemExit(_falha("O segredo de assinatura não é o par da chave pública embutida no aplicativo. Uma versão assinada assim seria recusada por todos os PCs."))
    return priv


def _verificar(assinatura_b64: bytes, mensagem: bytes, chave_publica_hex: str = CHAVE_PUBLICA_HEX) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        txt = assinatura_b64.decode("ascii").strip()
        bruto = base64.b64decode(txt, validate=True)
        if len(bruto) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(chave_publica_hex)).verify(bruto, mensagem)
        return True
    except (InvalidSignature, ValueError, UnicodeDecodeError):
        return False


def _gravar_sig(saida: Path, sig: bytes) -> None:
    saida.write_text(base64.b64encode(sig).decode("ascii") + "\n", encoding="ascii", newline="\n")


def assinar_instalador(arq: Path, saida: Path) -> int:
    priv = _chave_privada()
    sha = sha256_arquivo(arq)
    _gravar_sig(saida, priv.sign(mensagem_instalador(arq.name, sha)))
    rc = conferir_instalador(arq, saida, None, None)
    if rc != 0:
        saida.unlink(missing_ok=True)
    return rc


def assinar_componente(arq: Path, saida: Path) -> int:
    priv = _chave_privada()
    _gravar_sig(saida, priv.sign(mensagem_componente(arq.read_bytes())))
    rc = conferir_componente(arq, saida)
    if rc != 0:
        saida.unlink(missing_ok=True)
    return rc


def conferir_instalador(arq: Path, sig: Path, sha_arquivo: Path | None, fonte: Path | None) -> int:
    sha = sha256_arquivo(arq)
    if sha_arquivo is not None:
        m = re.match(r"([0-9a-f]{64})\b", sha_arquivo.read_text(encoding="utf-8").lstrip("﻿").strip().lower())
        if not m or m.group(1) != sha:
            return _falha(f"O {sha_arquivo.name} não corresponde ao hash real de {arq.name}.")
    if fonte is not None:
        m = re.search(r'^CHAVE_PUBLICA_ED25519_HEX\s*(?::[^=]+)?=\s*"([0-9a-fA-F]*)"', fonte.read_text(encoding="utf-8"), flags=re.M)
        embutida = m.group(1).lower() if m else ""
        if not embutida:
            print("::warning::Esta versão do código-fonte não tem chave pública embutida: o .sig sai, mas o aplicativo dela não o exige.")
        elif embutida != CHAVE_PUBLICA_HEX:
            return _falha("A chave pública embutida no código-fonte desta versão é diferente da chave de assinatura deste workflow. Não publico.")
    if not _verificar(sig.read_bytes(), mensagem_instalador(arq.name, sha)):
        return _falha(f"Autoverificação FALHOU: {sig.name} não confere com a chave pública do aplicativo para {arq.name}.")
    print(f"Autoverificação ok: {sig.name} confere com a chave pública do aplicativo (sha256 {sha}).")
    return 0


def conferir_componente(arq: Path, sig: Path) -> int:
    if not _verificar(sig.read_bytes(), mensagem_componente(arq.read_bytes())):
        return _falha(f"Autoverificação FALHOU: {sig.name} não confere com a chave pública do aplicativo para {arq.name}.")
    print(f"Autoverificação ok: {sig.name} confere com a chave pública do aplicativo.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for nome in ("assinar-instalador", "assinar-componente"):
        s = sub.add_parser(nome)
        s.add_argument("arquivo", type=Path)
        s.add_argument("saida", type=Path)
    ci = sub.add_parser("conferir-instalador")
    ci.add_argument("arquivo", type=Path)
    ci.add_argument("sig", type=Path)
    ci.add_argument("--sha256-arquivo", type=Path)
    ci.add_argument("--fonte", type=Path)
    cc = sub.add_parser("conferir-componente")
    cc.add_argument("arquivo", type=Path)
    cc.add_argument("sig", type=Path)
    a = p.parse_args(argv)
    if a.cmd == "assinar-instalador":
        return assinar_instalador(a.arquivo, a.saida)
    if a.cmd == "assinar-componente":
        return assinar_componente(a.arquivo, a.saida)
    if a.cmd == "conferir-instalador":
        return conferir_instalador(a.arquivo, a.sig, a.sha256_arquivo, a.fonte)
    return conferir_componente(a.arquivo, a.sig)


if __name__ == "__main__":
    raise SystemExit(main())
