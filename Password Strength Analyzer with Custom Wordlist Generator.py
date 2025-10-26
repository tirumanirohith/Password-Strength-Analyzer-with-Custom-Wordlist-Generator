import sys
import os
import argparse
import itertools
import json
import math
import re
from datetime import datetime
from pathlib import Path
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except Exception:
    tk = None

# Optional zxcvbn integration
USE_ZXCVBN = False
try:
    from zxcvbn import zxcvbn  # pip install zxcvbn
    USE_ZXCVBN = True
except Exception:
    USE_ZXCVBN = False

### --------------------------
### Utilities & heuristics
### --------------------------

LEET_MAP = {
    'a': ['@', '4'],
    'b': ['8', '6'],
    'e': ['3'],
    'i': ['1', '!'],
    'l': ['1', '|'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'g': ['6', '9'],
    'z': ['2'],
}

COMMON_SUFFIXES = ['!', '@', '#', '123', '2020', '2021', '2022', '99', '007']
COMMON_PREFIXES = ['', '!', '@', '#', '_', '-']
SEPARATORS = ['', '.', '_', '-', '']

def safe_write_lines(path: Path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf8', errors='ignore') as f:
        for l in lines:
            f.write(l + '\n')

def dedupe_keep_order(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

### --------------------------
### Password strength
### --------------------------

def estimate_entropy_custom(pw: str):
    """
    Estimate entropy using character class sizes and length.
    Apply small penalties for obvious patterns.
    Returns (bits_entropy, score 0-4, explanation)
    """
    if not pw:
        return 0.0, 0, "Empty password"

    classes = {
        'lower': any(c.islower() for c in pw),
        'upper': any(c.isupper() for c in pw),
        'digits': any(c.isdigit() for c in pw),
        'symbols': any(not c.isalnum() for c in pw),
    }
    charset = 0
    if classes['lower']:
        charset += 26
    if classes['upper']:
        charset += 26
    if classes['digits']:
        charset += 10
    if classes['symbols']:
        charset += 32  # rough
    if charset == 0:
        charset = 1

    # basic entropy estimate
    bits = len(pw) * math.log2(charset)

    # simple pattern deductions
    deductions = 0.0
    explanation = []
    if re.fullmatch(r'(.)\1*', pw):
        # all same char e.g., "aaaaaa"
        deductions += 10
        explanation.append("repeated single char")
    if pw.lower() in COMMON_WORDS:
        deductions += 8
        explanation.append("common word")
    if re.search(r'(012|123|234|345|456|567|678|789|890)', pw):
        deductions += 6
        explanation.append("sequence of digits")
    if re.search(r'(abcd|bcde|cdef|defg|efgh|fghi|ghij)', pw.lower()):
        deductions += 6
        explanation.append("alphabet sequence")
    # subtract deductions but not below 0
    bits = max(0.0, bits - deductions)

    # map bits to 0-4 score similar-ish to zxcvbn
    if bits < 28:
        score = 0
    elif bits < 36:
        score = 1
    elif bits < 60:
        score = 2
    elif bits < 128:
        score = 3
    else:
        score = 4

    if not explanation:
        explanation = ["no obvious patterns found"]

    return round(bits, 2), score, '; '.join(explanation)

# small common words seed
COMMON_WORDS = set([
    'password','123456','qwerty','letmein','admin','welcome',
    'iloveyou','monkey','dragon','sunshine','princess','football'
])

def analyze_password(pw: str):
    """
    Return a dict with analysis.
    If zxcvbn is installed, use it and also include our fallback.
    """
    out = {}
    if USE_ZXCVBN:
        try:
            z = zxcvbn(pw)
            out['zxcvbn'] = {
                'score': z.get('score'),
                'entropy': z.get('entropy'),
                'crack_times_display': z.get('crack_times_display'),
                'match_sequence': z.get('sequence')
            }
        except Exception as e:
            out['zxcvbn_error'] = str(e)
    bits, score, explanation = estimate_entropy_custom(pw)
    out['custom'] = {
        'entropy_bits': bits,
        'score_0_to_4': score,
        'reason': explanation
    }
    return out

### --------------------------
### Wordlist generator
### --------------------------

def generate_leet_variants(s: str, max_variants=20):
    """Generate leetspeak variants (bounded)."""
    s = s.strip()
    if not s:
        return []
    variants = set([s])
    # for each character, optionally substitute with each replacement
    positions = []
    for i, ch in enumerate(s.lower()):
        if ch in LEET_MAP:
            positions.append((i, LEET_MAP[ch]))
    # limit expansions
    # build variants by trying to apply substitutions at up to n positions
    for r in range(1, min(len(positions)+1, 5)):  # limit combinatorial explosion
        for comb in itertools.combinations(positions, r):
            base = list(s)
            for pos, repls in comb:
                # try first replacement for each (to limit count)
                base[pos] = repls[0]
            variants.add(''.join(base))
            if len(variants) >= max_variants:
                break
        if len(variants) >= max_variants:
            break
    return list(variants)

def case_variants(s: str):
    """Return reasonable case variations: original, lower, upper, title, camel."""
    s = s.strip()
    out = {s, s.lower(), s.upper(), s.title()}
    # camel case (first lower rest Title)
    if len(s) > 1:
        out.add(s[0].lower() + s[1:].title())
    return list(out)

def append_years(words, start=1970, end=None, max_suffixes=60):
    if end is None:
        end = datetime.now().year
    suffixes = [str(y) for y in range(start, end+1)]
    if len(suffixes) > max_suffixes:
        suffixes = suffixes[-max_suffixes:]
    out = []
    for w in words:
        for sep in SEPARATORS:
            for suf in suffixes:
                out.append(f"{w}{sep}{suf}")
    return out

def surround_with_separators(words):
    out = []
    for w in words:
        for pre in COMMON_PREFIXES:
            for suf in COMMON_SUFFIXES:
                out.append(f"{pre}{w}{suf}")
    return out

def generate_wordlist_from_inputs(inputs: dict,
                                  include_leet=True,
                                  include_case=True,
                                  years=True,
                                  year_start=1970,
                                  year_end=None,
                                  extras=None,
                                  max_output=200000):
    """
    inputs: dict with keys like 'names', 'keywords', 'pets', 'dates' (strings)
    extras: list of extra raw words
    Returns: list of candidate passwords
    """
    base_words = []
    for k, v in inputs.items():
        if not v:
            continue
        if isinstance(v, (list, tuple)):
            for item in v:
                if item and isinstance(item, str):
                    base_words.append(item.strip())
        elif isinstance(v, str):
            base_words.extend([p.strip() for p in re.split(r'[,;\n]+', v) if p.strip()])

    if extras:
        base_words.extend([e for e in extras if e.strip()])

    base_words = [w for w in base_words if w]
    base_words = dedupe_keep_order(base_words)

    candidates = set()
    # add base words
    for w in base_words:
        candidates.add(w)

    # case variants
    if include_case:
        for w in list(candidates):
            for v in case_variants(w):
                candidates.add(v)

    # leet variants
    if include_leet:
        snapshot = list(candidates)
        for w in snapshot:
            for v in generate_leet_variants(w):
                candidates.add(v)

    # combine pairwise concatenations (name + keyword, keyword + year, etc.)
    words_list = list(candidates)
    for a in words_list:
        for b in words_list:
            if a == b:
                continue
            # small heuristic to avoid huge combinations: only combine if total len <= 30
            if len(a) + len(b) <= 30:
                candidates.add(a + b)
                # with separator
                for sep in SEPARATORS:
                    candidates.add(a + sep + b)

    # append years if requested
    if years:
        yend = year_end or datetime.now().year
        year_suffixes = [str(y) for y in range(year_start, yend+1)]
        # only keep recent slice if huge
        if len(year_suffixes) > 80:
            year_suffixes = year_suffixes[-80:]
        snapshot = list(candidates)
        for w in snapshot:
            for y in year_suffixes:
                # both prefix and suffix
                candidates.add(w + y)
                candidates.add(y + w)

    # surround with common prefix/suffix sets
    for w in list(candidates):
        for pre in COMMON_PREFIXES:
            for suf in COMMON_SUFFIXES:
                candidates.add(pre + w + suf)

    # add purely numeric variants from provided dates (e.g., 01012000)
    if 'dates' in inputs and inputs.get('dates'):
        ds = inputs.get('dates')
        for rawdate in re.split(r'[,;\n]+', ds):
            rawdate = rawdate.strip()
            numbers = re.findall(r'\d+', rawdate)
            for n in numbers:
                candidates.add(n)
                # add ddmmyyyy if length appropriate
                if len(n) >= 4:
                    candidates.add(n[-4:])  # year
    # ensure ordering and trimming
    out = dedupe_keep_order(list(candidates))
    if len(out) > max_output:
        out = out[:max_output]
    return out

### --------------------------
### CLI
### --------------------------

def cli_main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer + Custom Wordlist Generator")
    sub = parser.add_subparsers(dest='cmd', required=False)

    # analyze
    p_an = sub.add_parser('analyze', help='Analyze a single password')
    p_an.add_argument('password', help='Password to analyze')

    # generate
    p_gen = sub.add_parser('generate', help='Generate custom wordlist')
    p_gen.add_argument('--names', help='Comma-separated names (e.g., "alice,bob")', default='')
    p_gen.add_argument('--keywords', help='Comma-separated keywords (e.g., "gmail,football")', default='')
    p_gen.add_argument('--pets', help='Comma-separated pet names', default='')
    p_gen.add_argument('--dates', help='Comma-separated dates (e.g., "01-01-1990,2000")', default='')
    p_gen.add_argument('--extras', help='Comma-separated extra words', default='')
    p_gen.add_argument('--no-leet', action='store_true', help='Disable leetspeak variants')
    p_gen.add_argument('--no-years', action='store_true', help='Disable appending years')
    p_gen.add_argument('--year-start', type=int, default=1970)
    p_gen.add_argument('--year-end', type=int, default=None)
    p_gen.add_argument('--out', help='Output .txt path', default='wordlist.txt')
    p_gen.add_argument('--max', type=int, default=200000, help='Maximum number of lines in output')

    args = parser.parse_args()

    if not args.cmd:
        # run GUI if available, else show help
        if tk:
            run_gui()
            return
        else:
            parser.print_help()
            return

    if args.cmd == 'analyze':
        res = analyze_password(args.password)
        print(json.dumps(res, indent=2))
        return

    if args.cmd == 'generate':
        inputs = {
            'names': args.names,
            'keywords': args.keywords,
            'pets': args.pets,
            'dates': args.dates
        }
        extras = [e.strip() for e in args.extras.split(',') if e.strip()] if args.extras else []
        words = generate_wordlist_from_inputs(inputs,
                                             include_leet = not args.no_leet,
                                             include_case = True,
                                             years = not args.no_years,
                                             year_start = args.year_start,
                                             year_end = args.year_end,
                                             extras = extras,
                                             max_output = args.max)
        path = Path(args.out)
        safe_write_lines(path, words)
        print(f"Wrote {len(words)} lines to {path.resolve()}")
        return

### --------------------------
### Simple Tkinter GUI
### --------------------------

def run_gui():
    if not tk:
        print("Tkinter not available in this Python environment. Use CLI instead.")
        return

    root = tk.Tk()
    root.title("Password Analyzer & Wordlist Generator")
    root.geometry("720x520")

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill=tk.BOTH, expand=True)

    # Left: Analyzer
    analyzer = ttk.LabelFrame(frm, text="Password Analyzer", padding=10)
    analyzer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)

    pw_var = tk.StringVar()
    ttk.Label(analyzer, text="Enter password:").pack(anchor='w')
    pw_entry = ttk.Entry(analyzer, textvariable=pw_var, show='*', width=36)
    pw_entry.pack(anchor='w', pady=6)

    analyze_text = tk.Text(analyzer, height=10, width=50)
    analyze_text.pack(fill=tk.BOTH, expand=False)

    def do_analyze():
        pw = pw_var.get()
        if not pw:
            messagebox.showinfo("Info", "Enter a password to analyze.")
            return
        res = analyze_password(pw)
        analyze_text.delete('1.0', tk.END)
        analyze_text.insert(tk.END, json.dumps(res, indent=2))

    ttk.Button(analyzer, text="Analyze", command=do_analyze).pack(pady=6)

    # Right: Wordlist generator
    gen = ttk.LabelFrame(frm, text="Wordlist Generator", padding=10)
    gen.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=6, pady=6)

    def labeled_entry(parent, label_text, default=''):
        ttk.Label(parent, text=label_text).pack(anchor='w')
        v = tk.StringVar(value=default)
        e = ttk.Entry(parent, textvariable=v, width=36)
        e.pack(anchor='w', pady=3)
        return v

    names_v = labeled_entry(gen, "Names (comma-separated):")
    keywords_v = labeled_entry(gen, "Keywords (comma-separated):")
    pets_v = labeled_entry(gen, "Pet names (comma-separated):")
    dates_v = labeled_entry(gen, "Dates (comma-separated):")
    extras_v = labeled_entry(gen, "Extra words (comma-separated):")
    out_v = labeled_entry(gen, "Output filepath:", "wordlist.txt")

    options_frame = ttk.Frame(gen)
    options_frame.pack(fill=tk.X, pady=6)
    leet_var = tk.BooleanVar(value=True)
    years_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(options_frame, text="Include leet variants", variable=leet_var).pack(anchor='w')
    ttk.Checkbutton(options_frame, text="Append years", variable=years_var).pack(anchor='w')

    progress_label = ttk.Label(gen, text="")
    progress_label.pack(anchor='w', pady=6)

    def do_generate():
        inputs = {
            'names': names_v.get(),
            'keywords': keywords_v.get(),
            'pets': pets_v.get(),
            'dates': dates_v.get()
        }
        extras = [e.strip() for e in extras_v.get().split(',') if e.strip()]
        path = Path(out_v.get() or "wordlist.txt")
        progress_label.config(text="Generating...")
        root.update_idletasks()
        words = generate_wordlist_from_inputs(inputs,
                                             include_leet=leet_var.get(),
                                             include_case=True,
                                             years=years_var.get(),
                                             max_output=200000)
        safe_write_lines(path, words)
        progress_label.config(text=f"Wrote {len(words)} lines to {path.resolve()}")
        messagebox.showinfo("Done", f"Wrote {len(words)} lines to {path.resolve()}")

    ttk.Button(gen, text="Generate & Save", command=do_generate).pack(pady=6)

    # Footer: Help & Ethics
    help_text = ("Ethical reminder: Use only for your own accounts or \n"
                 "with explicit permission. This tool can assist defenders; \n"
                 "do not use it for unauthorized access.")
    ttk.Label(frm, text=help_text, foreground='red').pack(side=tk.BOTTOM, pady=6)

    root.mainloop()

### --------------------------
### Entry
### --------------------------

if __name__ == '__main__':
    # If run inside IDLE (or double-click) we prefer GUI
    # However CLI also available via args
    if len(sys.argv) == 1 and tk:
        run_gui()
    else:
        cli_main()
