#!/usr/bin/env python3
"""Check that relative links in Markdown files resolve to existing files and anchors."""

import os
import re
import sys
from pathlib import Path

def slugify(text):
    """Convert a heading to a GitHub-style slug."""
    # Lowercase
    slug = text.lower()
    # Replace spaces with hyphens
    slug = re.sub(r'\s+', '-', slug)
    # Remove punctuation except hyphens
    slug = re.sub(r'[^\w\-]', '', slug)
    # Remove consecutive hyphens
    slug = re.sub(r'-+', '-', slug)
    # Remove leading/trailing hyphens
    slug = slug.strip('-')
    return slug

def extract_headings(content):
    """Extract all headings from markdown content as a dict of slug -> heading text."""
    headings = {}
    for match in re.finditer(r'^(#{1,6})\s+(.+)$', content, re.MULTILINE):
        heading_text = match.group(2).strip()
        slug = slugify(heading_text)
        headings[slug] = heading_text
    return headings

def extract_links(content, file_path):
    """Extract all markdown links from content and their locations."""
    links = []
    # Match [text](url) pattern
    for match in re.finditer(r'\]\(([^\)]+)\)', content):
        url = match.group(1)
        if not url.startswith('http://') and not url.startswith('https://') and not url.startswith('#'):
            # This is a relative link (possibly with an anchor)
            links.append((url, match.start()))
    return links

def check_file(file_path, root_dir):
    """Check all links in a markdown file."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        return [(f"Error reading {file_path}: {e}", None)]

    links = extract_links(content, file_path)
    errors = []

    for link, _ in links:
        # Split link and anchor
        if '#' in link:
            file_part, anchor = link.split('#', 1)
        else:
            file_part = link
            anchor = None

        # Resolve the file path relative to the markdown file's directory
        if file_part:
            markdown_dir = os.path.dirname(file_path)
            target_path = os.path.normpath(os.path.join(markdown_dir, file_part))

            # Check if file exists
            if not os.path.exists(target_path):
                errors.append((f"{file_path}: broken link ]('{link}') -> file not found: {target_path}", link))
                continue

            # If there's an anchor and the file is markdown, check if the anchor exists
            if anchor and target_path.endswith('.md'):
                try:
                    with open(target_path, 'r') as f:
                        target_content = f.read()
                    headings = extract_headings(target_content)
                    if anchor not in headings and anchor.lower() not in headings:
                        errors.append((f"{file_path}: broken anchor ]('{link}') -> anchor #{anchor} not found in {target_path}", link))
                except Exception as e:
                    errors.append((f"{file_path}: error reading {target_path}: {e}", link))
        else:
            # File part is empty, just an anchor on the same file
            if anchor:
                headings = extract_headings(content)
                if anchor not in headings and anchor.lower() not in headings:
                    errors.append((f"{file_path}: broken anchor ]('{link}') -> anchor #{anchor} not found", link))

    return errors

def main():
    root_dir = Path.cwd()

    # Find all markdown files
    md_files = list(root_dir.glob('**/*.md'))
    md_files = [f for f in md_files if '.git' not in f.parts]

    all_errors = []
    for md_file in sorted(md_files):
        errors = check_file(str(md_file), str(root_dir))
        all_errors.extend(errors)

    if all_errors:
        print("Markdown link check results:")
        print("=" * 80)
        for error_msg, link in all_errors:
            print(f"  {error_msg}")
        print("=" * 80)
        print(f"\nTotal broken links: {len(all_errors)}")
        return 1
    else:
        print("All markdown links are valid.")
        return 0

if __name__ == '__main__':
    sys.exit(main())
