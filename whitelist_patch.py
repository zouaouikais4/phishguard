"""
whitelist_patch.py — Add missing trusted domains to predict_url.py.
Run from your project root:
    python whitelist_patch.py
"""
import os

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src', 'predict_url.py')

OLD = "    # Tunisian sites\n    'tunisianet.com.tn', 'mytek.tn', 'topnet.tn', 'orange.tn',"

NEW = """    # Tunisian sites
    'tunisianet.com.tn', 'mytek.tn', 'topnet.tn', 'orange.tn',
    'ooredoo.tn', 'rnu.tn', 'fsb.rnu.tn', 'ucar.tn',
    # AI / tools
    'chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com',
    'fast.com', 'speedtest.net',
    # Package registries & dev tools
    'pypi.org', 'npmjs.com', 'crates.io', 'packagist.org',
    'docs.python.org', 'readthedocs.io', 'readthedocs.org',
    # Gaming / mods
    'nexusmods.com', 'curseforge.com', 'modrinth.com',
    # Shopping (extended)
    'aliexpress.com', 'alibaba.com', 'etsy.com', 'walmart.com',
    'att.com', 'verizon.com', 'tmobile.com',
    # Torrent / open source
    'qbittorrent.org', 'transmissionbt.com',
    # Tech companies
    'apple.com', 'microsoft.com', 'mozilla.org', 'opera.com',"""

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

if OLD not in content:
    print(f"⚠  Could not find patch target in {path}")
    print("   Add these domains manually to _TRUSTED_DOMAINS in src/predict_url.py:")
    print("   'chatgpt.com', 'fast.com', 'pypi.org', 'nexusmods.com',")
    print("   'aliexpress.com', 'att.com', 'docs.python.org'")
else:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content.replace(OLD, NEW, 1))
    print(f"✅ Whitelist updated in {path}")
    print("\nDomains added:")
    print("  chatgpt.com, fast.com, pypi.org, nexusmods.com,")
    print("  aliexpress.com, att.com, ooredoo.tn, rnu.tn + more")
    print("\nRestart the app:")
    print("  python app.py")
