"""
ipxo_geofeed_checker.py

Usage:
  python3 ipxo_geofeed_checker.py --geofeeds-dir ./geofeeds --subnets-file ./subnets.txt --out-dir ./out
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import logging
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

try:
    import urllib.request as _url
except Exception:
    _url = None

# SSL Certicate to implement
import ssl
try:
    import certifi  # type: ignore
    _CERT_BUNDLE = certifi.where()
except Exception:
    certifi = None
    _CERT_BUNDLE = None

IPXO_DEFAULT_URL = "https://geofeed.ipxo.com/geofeed.txt"
URL_RE = re.compile(r'^(https?://\S+)$', re.IGNORECASE) 


@dataclass(frozen=True)
class GeoRow:
    prefix: ipaddress._BaseNetwork
    country: str = ""
    region: str = ""
    city: str = ""
    postal: str = ""
    source: str = ""
    lineno: int = 0
    raw_fields: Tuple[str, ...] = ()

    @staticmethod
    def from_fields(fields: List[str], source: str, lineno: int) -> Optional["GeoRow"]:
        if not fields:
            return None
        try:
            net = ipaddress.ip_network(fields[0].strip(), strict=False)
        except Exception:
            return None
        
        f = fields + [""] * (5 - len(fields))
        return GeoRow(
            prefix=net,
            country=(f[1] or "").strip(),
            region=(f[2] or "").strip(),
            city=(f[3] or "").strip(),
            postal=(f[4] or "").strip(),
            source=source,
            lineno=lineno,
            raw_fields=tuple(fields)
        )


def open_text_file(path: Path) -> Iterator[Tuple[int, str]]:
    with path.open("rb") as fh:
        data = fh.read()
    text = None
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        raise UnicodeDecodeError("utf-8", b"", 0, 1, "Unable to decode file")
    for i, line in enumerate(io.StringIO(text), start=1):
        yield i, line.rstrip("\n")


def is_comment_or_blank(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#")


def parse_geofeed_line(line: str) -> List[str]:
    # Support semicolons, if no commas
    if ";" in line and "," not in line:
        line = line.replace(";", ",")
    reader = csv.reader([line])
    try:
        return next(reader, [])
    except Exception:
        return []


def parse_geofeed_file(path: Path) -> List[GeoRow]:
    rows: List[GeoRow] = []
    for lineno, line in open_text_file(path):
        if is_comment_or_blank(line):
            continue
        if looks_like_url_list_line(line):
            continue
        fields = parse_geofeed_line(line)
        row = GeoRow.from_fields(fields, source=str(path), lineno=lineno)
        if row:
            rows.append(row)
    return rows


def parse_geofeed_text(name: str, text: str) -> List[GeoRow]:
    rows: List[GeoRow] = []
    for lineno, line in enumerate(io.StringIO(text), start=1):
        if is_comment_or_blank(line):
            continue
        fields = parse_geofeed_line(line)
        row = GeoRow.from_fields(fields, source=name, lineno=lineno)
        if row:
            rows.append(row)
    return rows


def looks_like_url_list_line(line: str) -> bool:
    s = line.strip()
    if not s or s.startswith("#"):
        return False
    first = s.split()[0]
    return bool(URL_RE.match(first))


def fetch_url(url: str, timeout: int = 30) -> str:
    if _url is None:
        raise RuntimeError("urllib not available in this environment")
    req = _url.Request(url, headers={"User-Agent": "ipxo-geofeed-checker/1.2"})
    if _CERT_BUNDLE:
        ctx = ssl.create_default_context(cafile=_CERT_BUNDLE)
    else:
        ctx = ssl.create_default_context()
    with _url.urlopen(req, timeout=timeout, context=ctx) as resp:
        charset = "utf-8"
        ct = resp.headers.get_content_charset()
        if ct:
            charset = ct
        data = resp.read()
    return data.decode(charset, errors="replace")


def load_ipxo_geofeed(ipxo_url: Optional[str], ipxo_file: Optional[Path]) -> List[GeoRow]:
    if ipxo_file and ipxo_file.is_file():
        text = "".join(line + "\n" for _, line in open_text_file(ipxo_file))
        return parse_geofeed_text(str(ipxo_file), text)
    if ipxo_url:
        try:
            text = fetch_url(ipxo_url)
            return parse_geofeed_text(f"{ipxo_url}", text)
        except Exception as e:
            logging.warning("Failed to fetch IPXO geofeed from %s: %s", ipxo_url, e)
    return []


def scan_geofeeds_dir(geofeeds_dir: Path) -> List[GeoRow]:
    """Scan the directory for (a) local geofeed data files; (b) URL-list files and fetch those feeds."""
    rows: List[GeoRow] = []
    # 1) Parse local data files
    for path in sorted([p for p in geofeeds_dir.rglob("*") if p.is_file() and p.suffix.lower() in (".csv", ".txt")]):
        # Determine if this file is a URL list
        is_url_list = False
        url_count = 0
        local_count = 0
        urls_to_fetch: List[str] = []

        for lineno, line in open_text_file(path):
            if is_comment_or_blank(line):
                continue
            if looks_like_url_list_line(line):
                is_url_list = True
                url = line.strip().split()[0]
                urls_to_fetch.append(url)
                url_count += 1
            else:
                fields = parse_geofeed_line(line)
                row = GeoRow.from_fields(fields, source=str(path), lineno=lineno)
                if row:
                    rows.append(row)
                    local_count += 1

        if is_url_list:
            logging.info("Detected URL list in %s (%d URLs). Fetching…", path, url_count)
            for url in urls_to_fetch:
                try:
                    text = fetch_url(url)
                    fetched_rows = parse_geofeed_text(url, text)
                    rows.extend(fetched_rows)
                    logging.info("Fetched %s : %d rows", url, len(fetched_rows))
                except Exception as e:
                    logging.warning("Failed to fetch %s: %s", url, e)
        else:
            logging.info("Parsed %s : %d local rows", path, local_count)

    return rows


def write_csv(path: Path, header: List[str], rows: Iterable[Iterable[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def best_covering_country(ipxo_rows: List[GeoRow], target: ipaddress._BaseNetwork) -> Optional[str]:
    best = None
    for r in ipxo_rows:
        if r.prefix.version != target.version:
            continue
        if r.prefix.supernet_of(target) or r.prefix == target or r.prefix.subnet_of(target):
            if best is None or r.prefix.prefixlen > best.prefix.prefixlen:
                best = r
    return best.country if best else None


def build_lookup(rows: List[GeoRow]):
    v4, v6 = [], []
    for r in rows:
        (v4 if isinstance(r.prefix, ipaddress.IPv4Network) else v6).append(r)
    return v4, v6


def overlaps(a: ipaddress._BaseNetwork, b: ipaddress._BaseNetwork) -> bool:
    if a.version != b.version:
        return False
    return a.overlaps(b)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Compare IPXO subnets against external Geofeed files and URL lists.")
    ap.add_argument("--geofeeds-dir", required=True, help="Directory containing *.csv/*.txt geofeed files or URL lists")
    ap.add_argument("--subnets-file", required=True, help="Path to subnet.txt (CIDR per line)")
    ap.add_argument("--out-dir", default="out", help="Where to write reports (default: ./out)")
    ap.add_argument("--ipxo-url", default=IPXO_DEFAULT_URL, help=f"IPXO geofeed URL (default: {IPXO_DEFAULT_URL})")
    ap.add_argument("--ipxo-file", default="", help="Local file to use as IPXO geofeed (overrides --ipxo-url if present)")
    ap.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"])
    args = ap.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(message)s")

    geofeeds_dir = Path(args.geofeeds_dir)
    subnets_file = Path(args.subnets_file)
    out_dir = Path(args.out_dir)
    ipxo_file = Path(args.ipxo_file) if args.ipxo_file else None

    if not geofeeds_dir.is_dir():
        logging.error("Geofeeds dir does not exist or is not a directory: %s", geofeeds_dir)
        return 2
    if not subnets_file.is_file():
        logging.error("Subnets file does not exist: %s", subnets_file)
        return 2

    logging.info("Loading IPXO geofeed (local=%s, url=%s)", bool(ipxo_file), args.ipxo_url)
    ipxo_rows = load_ipxo_geofeed(args.ipxo_url, ipxo_file)
    logging.info("Loaded %d IPXO rows", len(ipxo_rows))

    logging.info("Scanning geofeeds under %s ...", geofeeds_dir)
    external_rows = scan_geofeeds_dir(geofeeds_dir)
    logging.info("Loaded %d external geofeed rows from %s", len(external_rows), geofeeds_dir)

    logging.info("Loading IPXO subnets from %s ...", subnets_file)
    ipxo_subnets = []
    with subnets_file.open("r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                ipxo_subnets.append(ipaddress.ip_network(s, strict=False))
            except Exception:
                logging.warning("Skipped invalid subnet in %s:%d -> %r", subnets_file, i, s)
    logging.info("Loaded %d subnets", len(ipxo_subnets))

    ipxo_v4, ipxo_v6 = build_lookup(ipxo_rows)
    ext_v4, ext_v6 = build_lookup(external_rows)

    matches_out = out_dir / "matches.csv"
    summary_out = out_dir / "summary_by_subnet.csv"
    log_out = out_dir / "run.log"

    out_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_out, encoding="utf-8")
    fh.setLevel(logging.getLogger().level)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.getLogger().addHandler(fh)

    matches = []
    summary = defaultdict(lambda: {"overlaps": 0, "sources": set(), "country_mismatch": 0})

    for ipxo_net in ipxo_subnets:
        ext_rows = ext_v4 if isinstance(ipxo_net, ipaddress.IPv4Network) else ext_v6
        ipxo_country_guess = best_covering_country(ipxo_rows, ipxo_net)
        for r in ext_rows:
            if overlaps(ipxo_net, r.prefix):
                mismatch = "NA"
                if ipxo_country_guess is not None:
                    mismatch = "YES" if (r.country and r.country.upper() != ipxo_country_guess.upper()) else "NO"
                matches.append([
                    str(ipxo_net),
                    str(r.prefix),
                    r.country,
                    r.region,
                    r.city,
                    r.postal,
                    r.source,
                    r.lineno,
                    ipxo_country_guess or "",
                    mismatch
                ])
                summary[str(ipxo_net)]["overlaps"] += 1
                summary[str(ipxo_net)]["sources"].add(str(r.source))
                if mismatch == "YES":
                    summary[str(ipxo_net)]["country_mismatch"] += 1

    write_csv(matches_out,
              header=["ipxo_subnet","external_prefix","external_country","external_region","external_city","external_postal",
                      "source","source_lineno","ipxo_country_guess","country_mismatch"],
              rows=matches)

    write_csv(summary_out,
              header=["ipxo_subnet","num_overlaps","num_unique_sources","num_country_mismatches"],
              rows=[[subnet, v["overlaps"], len(v["sources"]), v["country_mismatch"]]
                    for subnet, v in sorted(summary.items(), key=lambda kv: kv[0])])

    logging.info("Done. Wrote %s and %s", matches_out, summary_out)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
