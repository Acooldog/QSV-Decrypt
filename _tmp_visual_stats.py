from pathlib import Path
from src.Infrastructure.ffmpeg_tools import FfmpegTools
ff = FfmpegTools()
root = Path(r"O:\A_python\A_aqy\_log\2026-3-28\bbts_repair\家事法庭第3集-准高清720P-标准音效\segments")
checks = []
for seg in range(1,7):
    for suffix in [
        'dispatch_key_base64.full.decrypt.ts',
        'dispatch_key_base64.full.encrypt.ts',
        'dispatch_key_base64.w00.decrypt.ts',
        'dispatch_key_base64.w00.encrypt.ts',
        'selected.ts',
    ]:
        p = root / f'{seg:02d}.{suffix}' if not suffix.startswith('selected') else root / f'{seg:02d}.selected.ts'
        if p.exists():
            checks.append(p)
for p in checks:
    probe = ff.probe(p)
    dur = 0.0
    if probe.ok:
        for s in probe.raw.get('streams', []):
            if s.get('codec_type') == 'video':
                try:
                    dur = float(s.get('duration') or 0.0)
                except Exception:
                    dur = 0.0
                break
    ts = [max(0.5, dur * r) for r in (0.12, 0.5, 0.88)] if dur > 0 else [1.0,3.0,5.0]
    stats = ff.sample_gray_frame_stats(p, ts)
    if stats:
        ent = sum(x['entropy'] for x in stats)/len(stats)
        std = sum(x['stddev'] for x in stats)/len(stats)
        dom = max(x['dominant_ratio'] for x in stats)
    else:
        ent = std = dom = -1
    print(p.name, 'dur=', round(dur,3), 'ent=', round(ent,3), 'std=', round(std,3), 'dom=', round(dom,3), 'samples=', len(stats))
