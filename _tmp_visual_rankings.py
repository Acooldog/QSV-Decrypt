import hashlib, json
from pathlib import Path
from src.Infrastructure.ffmpeg_tools import FfmpegTools
ff = FfmpegTools()
root = Path(r"O:\A_python\A_aqy\_log\2026-3-28\bbts_repair\家事法庭第3集-准高清720P-标准音效\segments")
out = root.parent / 'visual_rankings.json'
all_out = {}
for seg in range(1, 7):
    prefix = f'{seg:02d}'
    files = sorted(root.glob(f'{prefix}*.ts'))
    groups = {}
    for f in files:
        h = hashlib.sha1(f.read_bytes()).hexdigest()
        groups.setdefault(h, f)
    rows = []
    for h, f in groups.items():
        probe = ff.probe(f)
        dur = 0.0
        if probe.ok:
            for s in probe.raw.get('streams', []):
                if s.get('codec_type') == 'video':
                    try:
                        dur = float(s.get('duration') or 0.0)
                    except Exception:
                        dur = 0.0
                    break
        ts = [max(0.5, dur * r) for r in (0.12, 0.5, 0.88)] if dur > 0 else [1.0, 3.0, 5.0]
        stats = ff.sample_gray_frame_stats(f, ts)
        ent = sum(x['entropy'] for x in stats)/len(stats) if stats else 0.0
        std = sum(x['stddev'] for x in stats)/len(stats) if stats else 0.0
        dom = max(x['dominant_ratio'] for x in stats) if stats else 1.0
        score = ent * 140.0 + std * 8.0 + (1.0 - dom) * 500.0
        rows.append({
            'name': f.name,
            'hash': h,
            'duration': dur,
            'entropy_avg': ent,
            'stddev_avg': std,
            'dominant_max': dom,
            'visual_score': score,
            'samples': len(stats),
        })
    rows.sort(key=lambda x: x['visual_score'], reverse=True)
    all_out[prefix] = rows[:12]
out.write_text(json.dumps(all_out, ensure_ascii=False, indent=2), encoding='utf-8')
print(out)
for seg, rows in all_out.items():
    print('SEG', seg)
    for row in rows[:5]:
        print(row['name'], round(row['visual_score'],3), round(row['entropy_avg'],3), round(row['stddev_avg'],3), round(row['dominant_max'],3))
