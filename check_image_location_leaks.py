#!/usr/bin/env python3
"""
GitHub Image Location Leak Detector

This script scans GitHub issues and pull requests for images that contain
GPS/location metadata in their EXIF data. This helps identify privacy leaks
where users may have inadvertently shared their location through photos.

Usage:
    python3 check_image_location_leaks.py [--repo OWNER/REPO] [--output FILE]
    python3 check_image_location_leaks.py --issue 80  # Check specific issue
    python3 check_image_location_leaks.py --pr 123    # Check specific PR
    python3 check_image_location_leaks.py --since 2024-01-01  # Only check items created after date

Recommended: Use --since to avoid re-checking old issues/PRs that have already been reviewed.

Requirements:
    - gh CLI (GitHub CLI) installed and authenticated
    - Pillow library (pip install Pillow)
"""

import sys

import argparse
import json
import re
import subprocess
import time
from datetime import datetime
from html import escape
from io import BytesIO
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from typing import Optional
from dataclasses import dataclass, field

# Cache for reverse geocoding to avoid duplicate API calls
_geocode_cache = {}

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    print("Error: Pillow is required. Install with: pip3 install Pillow")
    sys.exit(1)


def reverse_geocode(lat: float, lon: float, verbose: bool = False) -> dict:
    """
    Reverse geocode coordinates to get city and country.
    Uses OpenStreetMap Nominatim API (free, no API key required).
    """
    # Round coordinates to reduce cache misses for nearby points
    cache_key = f"{lat:.4f},{lon:.4f}"

    if cache_key in _geocode_cache:
        if verbose:
            cached = _geocode_cache[cache_key]
            print(f"        [cache] Location: {cached.get('city', '')}, {cached.get('country', '')}", flush=True)
        return _geocode_cache[cache_key]

    try:
        if verbose:
            print(f"        [geocoding] Looking up {lat:.4f}, {lon:.4f}...", end=" ", flush=True)

        url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json&zoom=10"
        headers = {
            'User-Agent': 'GitHubImageLocationLeakDetector/1.0 (privacy-check-tool)'
        }
        req = Request(url, headers=headers)

        with urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))

        address = data.get('address', {})
        result = {
            'city': address.get('city') or address.get('town') or address.get('village') or address.get('municipality') or address.get('county', ''),
            'country': address.get('country', ''),
            'country_code': address.get('country_code', '').upper(),
            'display_name': data.get('display_name', '')
        }

        _geocode_cache[cache_key] = result

        if verbose:
            print(f"{result.get('city', '')}, {result.get('country', '')}", flush=True)

        # Be nice to the free API - rate limit
        time.sleep(1)

        return result
    except Exception as e:
        if verbose:
            print(f"Error: {e}", flush=True)
        result = {'city': '', 'country': '', 'country_code': '', 'error': str(e)}
        _geocode_cache[cache_key] = result
        return result


@dataclass
class GPSData:
    """Represents GPS data extracted from an image"""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    timestamp: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None

    def __bool__(self):
        return self.latitude is not None and self.longitude is not None

    def to_dict(self):
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "timestamp": self.timestamp,
            "city": self.city,
            "country": self.country,
            "country_code": self.country_code
        }

    def format_coords(self) -> str:
        if self.latitude is not None and self.longitude is not None:
            lat_dir = "N" if self.latitude >= 0 else "S"
            lon_dir = "E" if self.longitude >= 0 else "W"
            return f"{abs(self.latitude):.6f}°{lat_dir}, {abs(self.longitude):.6f}°{lon_dir}"
        return "Unknown"

    def format_location(self) -> str:
        """Format city, country as a string"""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.country:
            parts.append(self.country)
        return ", ".join(parts) if parts else "Unknown"

    def google_maps_link(self) -> str:
        if self.latitude is not None and self.longitude is not None:
            return f"https://maps.google.com/?q={self.latitude},{self.longitude}"
        return ""

    def fetch_location(self, verbose: bool = False):
        """Fetch city and country from coordinates using reverse geocoding"""
        if self.latitude is not None and self.longitude is not None:
            geo = reverse_geocode(self.latitude, self.longitude, verbose=verbose)
            self.city = geo.get('city', '')
            self.country = geo.get('country', '')
            self.country_code = geo.get('country_code', '')


@dataclass
class ImageResult:
    """Result of checking an image for location data"""
    url: str
    has_location: bool
    gps_data: Optional[GPSData] = None
    error: Optional[str] = None


@dataclass
class IssueOrPRResult:
    """Result for an issue or PR"""
    number: int
    title: str
    url: str
    type: str  # "issue" or "pr"
    author: str
    images_with_location: list = field(default_factory=list)
    images_checked: int = 0
    errors: list = field(default_factory=list)


def convert_to_degrees(value) -> Optional[float]:
    """Convert GPS coordinates to degrees. Returns None if conversion fails."""
    try:
        if isinstance(value, tuple) and len(value) >= 3:
            d, m, s = value[0], value[1], value[2]
            return float(d) + float(m) / 60.0 + float(s) / 3600.0
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def extract_gps_from_exif(exif_data: dict) -> Optional[GPSData]:
    """Extract GPS data from EXIF dictionary"""
    gps_info = {}

    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == "GPSInfo":
            for gps_tag_id, gps_value in value.items():
                gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                gps_info[gps_tag] = gps_value

    if not gps_info:
        return None

    gps_data = GPSData()

    # Extract latitude
    if "GPSLatitude" in gps_info and "GPSLatitudeRef" in gps_info:
        lat = convert_to_degrees(gps_info["GPSLatitude"])
        if lat is not None:
            if gps_info["GPSLatitudeRef"] in ("S", b"S"):
                lat = -lat
            gps_data.latitude = lat

    # Extract longitude
    if "GPSLongitude" in gps_info and "GPSLongitudeRef" in gps_info:
        lon = convert_to_degrees(gps_info["GPSLongitude"])
        if lon is not None:
            if gps_info["GPSLongitudeRef"] in ("W", b"W"):
                lon = -lon
            gps_data.longitude = lon

    # Extract altitude (may be stored as Rational)
    if "GPSAltitude" in gps_info:
        try:
            alt_val = gps_info["GPSAltitude"]
            # Handle Rational type (tuple) or direct numeric
            if isinstance(alt_val, tuple) and len(alt_val) == 2:
                alt = float(alt_val[0]) / float(alt_val[1]) if alt_val[1] != 0 else 0.0
            else:
                alt = float(alt_val)
            if gps_info.get("GPSAltitudeRef") in (b'\x01', 1):
                alt = -alt
            gps_data.altitude = alt
        except (TypeError, ValueError, ZeroDivisionError):
            pass

    # Extract timestamp
    if "GPSDateStamp" in gps_info:
        gps_data.timestamp = str(gps_info["GPSDateStamp"])
        if "GPSTimeStamp" in gps_info:
            ts = gps_info["GPSTimeStamp"]
            if isinstance(ts, tuple) and len(ts) >= 3:
                try:
                    # GPS time values may be Rational (tuple) or numeric
                    def to_int(val):
                        if isinstance(val, tuple) and len(val) == 2:
                            return int(float(val[0]) / float(val[1])) if val[1] != 0 else 0
                        return int(float(val))
                    h, m, s = to_int(ts[0]), to_int(ts[1]), to_int(ts[2])
                    gps_data.timestamp += f" {h:02d}:{m:02d}:{s:02d}"
                except (TypeError, ValueError, ZeroDivisionError):
                    pass

    return gps_data if gps_data else None


def check_image_for_gps(image_url: str, verbose: bool = False) -> ImageResult:
    """Download an image and check for GPS data"""
    try:
        if verbose:
            # Show short URL
            short_url = image_url.split('/')[-1][:20] + "..." if len(image_url) > 50 else image_url
            print(f"      Downloading {short_url}...", end=" ", flush=True)

        # Create request with headers to avoid 403
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        }
        req = Request(image_url, headers=headers)

        with urlopen(req, timeout=30) as response:
            image_data = response.read()

        if verbose:
            print(f"({len(image_data) // 1024}KB)", end=" ", flush=True)

        # Open image and extract EXIF
        with Image.open(BytesIO(image_data)) as image:
            # _getexif() is JPEG-specific; may not exist for other formats
            try:
                exif_data = image._getexif()
            except AttributeError:
                exif_data = None

        if not exif_data:
            if verbose:
                print("no EXIF", flush=True)
            return ImageResult(url=image_url, has_location=False)

        gps_data = extract_gps_from_exif(exif_data)

        if gps_data:
            if verbose:
                print("GPS FOUND!", flush=True)
            # Fetch location (city, country) via reverse geocoding
            gps_data.fetch_location(verbose=verbose)
            return ImageResult(url=image_url, has_location=True, gps_data=gps_data)
        else:
            if verbose:
                print("no GPS", flush=True)
            return ImageResult(url=image_url, has_location=False)

    except HTTPError as e:
        if verbose:
            print(f"HTTP error {e.code}", flush=True)
        return ImageResult(url=image_url, has_location=False, error=f"HTTP {e.code}")
    except URLError as e:
        if verbose:
            print(f"URL error: {e.reason}", flush=True)
        return ImageResult(url=image_url, has_location=False, error=f"URL Error: {e.reason}")
    except Exception as e:
        if verbose:
            print(f"Error: {e}", flush=True)
        return ImageResult(url=image_url, has_location=False, error=str(e))


def extract_image_urls(text: str) -> list:
    """Extract image URLs from markdown/HTML text"""
    urls = set()

    # GitHub user-attachments
    pattern1 = r'https://github\.com/user-attachments/assets/[a-f0-9-]+'
    urls.update(re.findall(pattern1, text))

    # Generic image URLs in markdown: ![alt](url)
    pattern2 = r'!\[.*?\]\((https?://[^\s\)]+\.(?:jpg|jpeg|png|gif|webp)(?:\?[^\s\)]*)?)[\)\s]'
    urls.update(re.findall(pattern2, text, re.IGNORECASE))

    # HTML img tags
    pattern3 = r'<img[^>]+src=["\']?(https?://[^\s"\'>\)]+)["\']?'
    urls.update(re.findall(pattern3, text, re.IGNORECASE))

    # Direct image links
    pattern4 = r'(https?://[^\s\)>\]"\']+\.(?:jpg|jpeg|png|gif|webp)(?:\?[^\s\)>\]"\']*)?)'
    urls.update(re.findall(pattern4, text, re.IGNORECASE))

    return list(urls)


def run_gh_command(args: list):
    """Run a GitHub CLI command and return JSON output (list or dict)"""
    cmd = ["gh"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        raise Exception("gh CLI not found. Please install GitHub CLI: https://cli.github.com/")
    except subprocess.TimeoutExpired:
        raise Exception("gh command timed out after 120 seconds")
    if result.returncode != 0:
        raise Exception(f"gh command failed: {result.stderr}")
    if not result.stdout.strip():
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse gh output as JSON: {e}")


def get_issues(repo: str, since: Optional[str] = None) -> list:
    """Fetch all issues from a repository, optionally filtered by creation date"""
    if since:
        print(f"Fetching issues from {repo} created after {since}...", flush=True)
    else:
        print(f"Fetching issues from {repo}...", flush=True)
    try:
        # gh issue list doesn't have pagination - use a high limit to get all
        cmd = [
            "issue", "list",
            "--repo", repo,
            "--state", "all",
            "--limit", "1000",
            "--json", "number,title,body,comments,author,url,createdAt"
        ]
        # Add date filter using GitHub search syntax
        if since:
            cmd.extend(["--search", f"created:>{since}"])

        result = run_gh_command(cmd)
        print(f"  Fetched {len(result) if result else 0} issues", flush=True)
        return result if result else []
    except Exception as e:
        print(f"Error fetching issues: {e}", flush=True)
        return []


def get_pull_requests(repo: str, since: Optional[str] = None) -> list:
    """Fetch all pull requests from a repository, optionally filtered by creation date"""
    if since:
        print(f"Fetching pull requests from {repo} created after {since}...", flush=True)
    else:
        print(f"Fetching pull requests from {repo}...", flush=True)
    prs = []

    try:
        cmd = [
            "pr", "list",
            "--repo", repo,
            "--state", "all",
            "--limit", "1000",
            "--json", "number,title,body,comments,author,url,createdAt"
        ]
        # Add date filter using GitHub search syntax
        if since:
            cmd.extend(["--search", f"created:>{since}"])

        result = run_gh_command(cmd)
        prs = result if result else []
        print(f"  Fetched {len(prs)} pull requests", flush=True)
    except Exception as e:
        print(f"Error fetching PRs: {e}", flush=True)

    return prs


def process_issue_or_pr(item: dict, item_type: str, verbose: bool = False) -> IssueOrPRResult:
    """Process a single issue or PR for location leaks"""
    number = item["number"]
    title = item.get("title", "")
    url = item.get("url", "")
    author = (item.get("author") or {}).get("login", "unknown")

    result = IssueOrPRResult(
        number=number,
        title=title,
        url=url,
        type=item_type,
        author=author
    )

    # Collect all text content
    all_text = item.get("body", "") or ""

    # Add comment bodies
    comments = item.get("comments") or []
    for comment in comments:
        comment_body = comment.get("body", "") or ""
        all_text += "\n" + comment_body

    # Extract image URLs
    image_urls = extract_image_urls(all_text)
    result.images_checked = len(image_urls)

    if verbose and image_urls:
        print(f"    Found {len(image_urls)} image(s) to check", flush=True)

    # Check each image
    for img_url in image_urls:
        img_result = check_image_for_gps(img_url, verbose=verbose)
        if img_result.error:
            result.errors.append(f"{img_url}: {img_result.error}")
        if img_result.has_location:
            result.images_with_location.append(img_result)

    return result


def generate_report(results: list, output_file: Optional[str] = None) -> str:
    """Generate a report of all findings"""
    flagged = [r for r in results if r.images_with_location]

    report_lines = [
        "=" * 70,
        "GITHUB IMAGE LOCATION LEAK REPORT",
        "=" * 70,
        "",
        f"Total issues/PRs scanned: {len(results)}",
        f"Issues/PRs with location leaks: {len(flagged)}",
        "",
    ]

    if flagged:
        report_lines.append("-" * 70)
        report_lines.append("FLAGGED ITEMS WITH LOCATION DATA:")
        report_lines.append("-" * 70)

        for item in flagged:
            report_lines.append("")
            report_lines.append(f"[{item.type.upper()} #{item.number}] {item.title}")
            report_lines.append(f"  URL: {item.url}")
            report_lines.append(f"  Author: @{item.author}")
            report_lines.append(f"  Images with location: {len(item.images_with_location)}")
            if item.errors:
                report_lines.append(f"  Errors: {len(item.errors)}")

            for img in item.images_with_location:
                report_lines.append(f"")
                report_lines.append(f"    Image: {img.url}")
                if img.gps_data:
                    report_lines.append(f"    Coordinates: {img.gps_data.format_coords()}")
                    if img.gps_data.altitude:
                        report_lines.append(f"    Altitude: {img.gps_data.altitude:.1f}m")
                    if img.gps_data.timestamp:
                        report_lines.append(f"    GPS Timestamp: {img.gps_data.timestamp}")
                    report_lines.append(f"    Maps: {img.gps_data.google_maps_link()}")
    else:
        report_lines.append("No location leaks detected!")

    report_lines.append("")
    report_lines.append("=" * 70)

    report = "\n".join(report_lines)

    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
        print(f"\nReport saved to: {output_file}")

    return report


def generate_json_report(results: list, output_file: str):
    """Generate a JSON report of findings"""
    flagged = [r for r in results if r.images_with_location]

    report = {
        "summary": {
            "total_scanned": len(results),
            "with_location_leaks": len(flagged)
        },
        "flagged_items": []
    }

    for item in flagged:
        item_data = {
            "type": item.type,
            "number": item.number,
            "title": item.title,
            "url": item.url,
            "author": item.author,
            "images": [],
            "errors": item.errors if item.errors else []
        }

        for img in item.images_with_location:
            img_data = {
                "url": img.url,
                "gps": img.gps_data.to_dict() if img.gps_data else None,
                "coordinates": img.gps_data.format_coords() if img.gps_data else None,
                "maps_link": img.gps_data.google_maps_link() if img.gps_data else None
            }
            item_data["images"].append(img_data)

        report["flagged_items"].append(item_data)

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"JSON report saved to: {output_file}")


def generate_html_report(results: list, output_file: str, repo: str):
    """Generate an HTML report with a table of findings"""
    flagged = [r for r in results if r.images_with_location]

    # Build table rows
    table_rows = []
    for item in flagged:
        for img in item.images_with_location:
            gps = img.gps_data
            row = {
                'type': item.type.upper(),
                'number': item.number,
                'title': escape(item.title),
                'url': item.url,
                'author': item.author,
                'image_url': img.url,
                'coordinates': gps.format_coords() if gps else '',
                'city': escape(gps.city or '') if gps else '',
                'country': escape(gps.country or '') if gps else '',
                'altitude': f"{gps.altitude:.1f}m" if gps and gps.altitude else '',
                'timestamp': escape(gps.timestamp or '') if gps else '',
                'maps_link': gps.google_maps_link() if gps else ''
            }
            table_rows.append(row)

    # Generate HTML
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Image Location Leak Report - {escape(repo)}</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        h1 {{
            color: #d32f2f;
            border-bottom: 3px solid #d32f2f;
            padding-bottom: 10px;
        }}
        .summary {{
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary h2 {{
            margin-top: 0;
            color: #666;
        }}
        .stat {{
            display: inline-block;
            margin-right: 30px;
            padding: 10px 20px;
            background: #f0f0f0;
            border-radius: 4px;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #d32f2f;
        }}
        .stat-label {{
            font-size: 14px;
            color: #666;
        }}
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 0 8px 8px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #d32f2f;
            color: white;
            padding: 12px 8px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
        }}
        td {{
            padding: 10px 8px;
            border-bottom: 1px solid #eee;
            font-size: 13px;
            vertical-align: top;
        }}
        tr:hover {{
            background: #f9f9f9;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        a {{
            color: #1976d2;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .type-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
        }}
        .type-issue {{
            background: #e3f2fd;
            color: #1565c0;
        }}
        .type-pr {{
            background: #f3e5f5;
            color: #7b1fa2;
        }}
        .location {{
            font-weight: 500;
        }}
        .country-flag {{
            font-size: 16px;
            margin-right: 4px;
        }}
        .image-preview {{
            max-width: 60px;
            max-height: 60px;
            border-radius: 4px;
            cursor: pointer;
        }}
        .maps-link {{
            display: inline-block;
            padding: 4px 8px;
            background: #4CAF50;
            color: white !important;
            border-radius: 4px;
            font-size: 11px;
        }}
        .maps-link:hover {{
            background: #388E3C;
            text-decoration: none;
        }}
        .no-leaks {{
            text-align: center;
            padding: 40px;
            background: #e8f5e9;
            border-radius: 8px;
            color: #2e7d32;
        }}
        .no-leaks h2 {{
            margin: 0;
        }}
        .timestamp {{
            font-size: 11px;
            color: #888;
        }}
        .footer {{
            margin-top: 20px;
            padding: 15px;
            text-align: center;
            color: #888;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>&#x1F6A8; GitHub Image Location Leak Report</h1>

        <div class="summary">
            <h2>Repository: <a href="https://github.com/{escape(repo)}">{escape(repo)}</a></h2>
            <div class="stat">
                <div class="stat-value">{len(results)}</div>
                <div class="stat-label">Issues/PRs Scanned</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(flagged)}</div>
                <div class="stat-label">With Location Leaks</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(table_rows)}</div>
                <div class="stat-label">Images with GPS Data</div>
            </div>
        </div>
'''

    if flagged:
        html += '''
        <div class="warning">
            <strong>&#x26A0;&#xFE0F; Privacy Warning:</strong> The following images contain embedded GPS coordinates that reveal the photographer's location.
            Consider notifying the authors so they can remove or replace these images with location data stripped.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>#</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Image</th>
                    <th>Location</th>
                    <th>Coordinates</th>
                    <th>Timestamp</th>
                    <th>Map</th>
                </tr>
            </thead>
            <tbody>
'''
        for row in table_rows:
            type_class = 'type-issue' if row['type'] == 'ISSUE' else 'type-pr'
            location = f"{row['city']}, {row['country']}" if row['city'] and row['country'] else row['country'] or row['city'] or 'Unknown'
            # Escape URLs for HTML attributes to prevent XSS
            safe_url = escape(row['url'])
            safe_image_url = escape(row['image_url'])
            safe_author = escape(row['author'])
            safe_maps_link = escape(row['maps_link'])

            html += f'''                <tr>
                    <td><span class="type-badge {type_class}">{row['type']}</span></td>
                    <td><a href="{safe_url}">#{row['number']}</a></td>
                    <td><a href="{safe_url}">{row['title'][:50]}{'...' if len(row['title']) > 50 else ''}</a></td>
                    <td><a href="https://github.com/{safe_author}">@{safe_author}</a></td>
                    <td><a href="{safe_image_url}" target="_blank"><img src="{safe_image_url}" class="image-preview" alt="Preview"></a></td>
                    <td class="location">{escape(location)}</td>
                    <td>{escape(row['coordinates'])}</td>
                    <td class="timestamp">{escape(row['timestamp'])}</td>
                    <td><a href="{safe_maps_link}" target="_blank" class="maps-link">&#x1F4CD; View</a></td>
                </tr>
'''

        html += '''            </tbody>
        </table>
'''
    else:
        html += '''
        <div class="no-leaks">
            <h2>&#x2705; No Location Leaks Detected</h2>
            <p>All scanned images are free of GPS metadata.</p>
        </div>
'''

    html += f'''
        <div class="footer">
            Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
            GitHub Image Location Leak Detector
        </div>
    </div>
</body>
</html>
'''

    with open(output_file, "w") as f:
        f.write(html)

    print(f"HTML report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="""
GitHub Image Location Leak Detector

Scans GitHub issues and pull requests for images containing GPS/location
metadata in their EXIF data. This helps identify privacy leaks where users
may have inadvertently shared their location through photos.

The script downloads each image, extracts EXIF data, and checks for GPS
coordinates. If found, it reverse-geocodes the location to city/country
and generates a report.
""",
        epilog="""
EXAMPLES:
  # Scan entire repository (may take time for large repos)
  python3 check_image_location_leaks.py --repo owner/repo --html report.html

  # Recommended: Scan only recent items (past 7 days) for regular checks
  python3 check_image_location_leaks.py --since 2024-01-14 --html report.html

  # Check a specific issue
  python3 check_image_location_leaks.py --issue 80 --verbose

  # Check a specific PR
  python3 check_image_location_leaks.py --pr 123 --verbose

  # Generate both HTML and JSON reports
  python3 check_image_location_leaks.py --html report.html --json report.json

  # Check only issues (skip PRs)
  python3 check_image_location_leaks.py --issues-only --since 2024-01-01

RECOMMENDED WORKFLOW:
  1. First run with --since to check recent items: --since YYYY-MM-DD
  2. Use --verbose to see progress when checking specific items
  3. Generate --html report for easy review with clickable links
  4. If leaks are found, notify authors to replace images with GPS stripped

REQUIREMENTS:
  - GitHub CLI (gh) installed and authenticated
  - Pillow library: pip3 install Pillow
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--repo", "-r",
        default="romasku/tuya-zigbee-switch",
        help="Repository in OWNER/REPO format (default: %(default)s)"
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save text report to FILE (default: print to stdout)"
    )
    parser.add_argument(
        "--json", "-j",
        dest="json_output",
        metavar="FILE",
        help="Save machine-readable JSON report to FILE"
    )
    parser.add_argument(
        "--html",
        dest="html_output",
        metavar="FILE",
        help="Save visual HTML report with table to FILE (recommended)"
    )
    parser.add_argument(
        "--issues-only",
        action="store_true",
        help="Only scan issues, skip pull requests"
    )
    parser.add_argument(
        "--prs-only",
        action="store_true",
        help="Only scan pull requests, skip issues"
    )
    parser.add_argument(
        "--issue", "-i",
        type=int,
        metavar="NUM",
        help="Check only issue #NUM (useful for testing or re-checking)"
    )
    parser.add_argument(
        "--pr", "-p",
        type=int,
        metavar="NUM",
        help="Check only PR #NUM (useful for testing or re-checking)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed progress: download status, EXIF extraction, geocoding"
    )
    parser.add_argument(
        "--since", "-s",
        metavar="DATE",
        help="Only check items created after DATE (YYYY-MM-DD). "
             "Recommended for regular checks to avoid re-scanning old items"
    )

    args = parser.parse_args()

    # Validate --since date format if provided
    if args.since:
        try:
            datetime.strptime(args.since, "%Y-%m-%d")
        except ValueError:
            print(f"Error: --since date must be in YYYY-MM-DD format, got: {args.since}")
            sys.exit(1)

    # Validate mutually exclusive arguments
    if args.issue and args.pr:
        print("Error: --issue and --pr cannot be used together")
        sys.exit(1)
    if args.issues_only and args.prs_only:
        print("Error: --issues-only and --prs-only cannot be used together")
        sys.exit(1)

    # Default to verbose for better visibility
    verbose = args.verbose

    results = []

    # Check specific issue if requested
    if args.issue:
        print(f"Fetching issue #{args.issue} from {args.repo}...", flush=True)
        try:
            issue = run_gh_command([
                "issue", "view", str(args.issue),
                "--repo", args.repo,
                "--json", "number,title,body,comments,author,url"
            ])
            print(f"  Checking issue #{issue['number']}...", end=" " if not verbose else "\n", flush=True)
            result = process_issue_or_pr(issue, "issue", verbose=verbose)
            results.append(result)

            if result.images_with_location:
                print(f"⚠️  LOCATION FOUND ({len(result.images_with_location)} images)", flush=True)
            elif result.images_checked > 0:
                print(f"✓ ({result.images_checked} images checked)", flush=True)
            else:
                print("- (no images)", flush=True)
        except Exception as e:
            print(f"Error fetching issue #{args.issue}: {e}", flush=True)

    # Check specific PR if requested
    elif args.pr:
        print(f"Fetching PR #{args.pr} from {args.repo}...", flush=True)
        try:
            pr = run_gh_command([
                "pr", "view", str(args.pr),
                "--repo", args.repo,
                "--json", "number,title,body,comments,author,url"
            ])
            print(f"  Checking PR #{pr['number']}...", end=" " if not verbose else "\n", flush=True)
            result = process_issue_or_pr(pr, "pr", verbose=verbose)
            results.append(result)

            if result.images_with_location:
                print(f"⚠️  LOCATION FOUND ({len(result.images_with_location)} images)", flush=True)
            elif result.images_checked > 0:
                print(f"✓ ({result.images_checked} images checked)", flush=True)
            else:
                print("- (no images)", flush=True)
        except Exception as e:
            print(f"Error fetching PR #{args.pr}: {e}", flush=True)

    else:
        # Fetch and process all issues
        if not args.prs_only:
            issues = get_issues(args.repo, since=args.since)

            for i, issue in enumerate(issues, 1):
                print(f"  [{i}/{len(issues)}] Issue #{issue['number']}...", end=" " if not verbose else "\n", flush=True)
                result = process_issue_or_pr(issue, "issue", verbose=verbose)
                results.append(result)

                if result.images_with_location:
                    print(f"⚠️  LOCATION FOUND ({len(result.images_with_location)} images)", flush=True)
                elif result.images_checked > 0:
                    print(f"✓ ({result.images_checked} images checked)", flush=True)
                else:
                    print("- (no images)", flush=True)

        # Fetch and process all PRs
        if not args.issues_only:
            prs = get_pull_requests(args.repo, since=args.since)

            for i, pr in enumerate(prs, 1):
                print(f"  [{i}/{len(prs)}] PR #{pr['number']}...", end=" " if not verbose else "\n", flush=True)
                result = process_issue_or_pr(pr, "pr", verbose=verbose)
                results.append(result)

                if result.images_with_location:
                    print(f"⚠️  LOCATION FOUND ({len(result.images_with_location)} images)", flush=True)
                elif result.images_checked > 0:
                    print(f"✓ ({result.images_checked} images checked)", flush=True)
                else:
                    print("- (no images)", flush=True)

    # Generate reports
    print()
    report = generate_report(results, args.output)
    print(report)

    if args.json_output:
        generate_json_report(results, args.json_output)

    if args.html_output:
        generate_html_report(results, args.html_output, args.repo)

    # Return exit code based on findings
    flagged_count = sum(1 for r in results if r.images_with_location)
    return 0 if flagged_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
