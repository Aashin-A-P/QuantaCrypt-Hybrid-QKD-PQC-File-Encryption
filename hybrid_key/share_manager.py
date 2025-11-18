from dataclasses import dataclass
from typing import List, Literal, Tuple
from .secret_sharing import make_shamir_shares, reconstruct_shamir_secret

Channel = Literal["qkd_channel", "pqc_channel", "local_storage"]


@dataclass
class ShareRecord:
    index: int
    x: int
    data: bytes
    channel: Channel


def distribute_shares(
    hybrid_key: bytes,
    n: int,
    k: int
) -> List[ShareRecord]:
    """
    Split hybrid_key using Shamir (k-of-n) and
    tag each share with a conceptual channel.
    """
    raw_shares = make_shamir_shares(hybrid_key, n=n, k=k)

    channels_cycle: list[Channel] = [
        "qkd_channel",
        "pqc_channel",
        "local_storage",
    ]
    records: List[ShareRecord] = []

    for idx, (x, y) in enumerate(raw_shares):
        ch = channels_cycle[idx % len(channels_cycle)]
        records.append(
            ShareRecord(
                index=idx + 1,
                x=x,
                data=y,
                channel=ch,
            )
        )

    return records


def reconstruct_from_records(
    records: List[ShareRecord],
    k: int,
    out_length: int
) -> bytes:
    """
    Reconstruct the hybrid key using any k ShareRecord entries.
    """
    if len(records) < k:
        raise ValueError("Need at least k records to reconstruct")

    selected = records[:k]
    basic_shares: list[Tuple[int, bytes]] = [(r.x, r.data) for r in selected]
    return reconstruct_shamir_secret(basic_shares, k=k, out_length=out_length)
